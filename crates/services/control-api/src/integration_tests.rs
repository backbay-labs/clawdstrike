#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::TcpListener;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use futures::StreamExt;
use serde_json::Value;
use sqlx::row::Row;
use tower::ServiceExt;
use uuid::Uuid;

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
    _postgres: DockerContainer,
    _nats: DockerContainer,
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
    assert_eq!(payload.as_ref(), policy_yaml.as_bytes());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_migrations_is_safe_under_concurrent_startup() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let pg_port = free_local_port();
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
        &format!("{pg_port}:5432"),
        "postgres:16-alpine",
    ]);

    let database_url = format!("postgres://postgres:postgres@127.0.0.1:{pg_port}/cloud_api");
    wait_for_postgres(&database_url).await;

    let pool_a = create_pool(&database_url).await.expect("create pool a");
    let pool_b = create_pool(&database_url).await.expect("create pool b");

    let (left, right) = tokio::join!(run_migrations(&pool_a), run_migrations(&pool_b));
    left.expect("first migration runner should succeed");
    right.expect("second migration runner should succeed");

    let applied: i64 = sqlx::query_scalar::query_scalar("SELECT COUNT(*) FROM schema_migrations")
        .fetch_one(&pool_a)
        .await
        .expect("count applied migrations");
    assert_eq!(applied, 5);

    drop(postgres);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_migrations_backfills_markers_for_legacy_schema() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let pg_port = free_local_port();
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
        &format!("{pg_port}:5432"),
        "postgres:16-alpine",
    ]);

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
    assert_eq!(
        applied,
        vec![
            "001_init.sql",
            "002_adaptive_sdr_schema.sql",
            "003_adaptive_sdr_token_and_approval_flow.sql",
            "004_adaptive_sdr_active_policy.sql",
            "005_adaptive_sdr_approval_outbox.sql",
        ]
    );

    let enrollment_token_exists: bool = sqlx::query_scalar::query_scalar(
        r#"SELECT EXISTS (
               SELECT 1
               FROM information_schema.columns
               WHERE table_schema = 'public'
                 AND table_name = 'tenants'
                 AND column_name = 'enrollment_token'
           )"#,
    )
    .fetch_one(&db)
    .await
    .expect("check legacy enrollment token column");
    assert!(
        !enrollment_token_exists,
        "legacy tenants.enrollment_token must stay absent after backfill"
    );

    let active_policy_table_exists: bool = sqlx::query_scalar::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'tenant_active_policies')",
    )
    .fetch_one(&db)
    .await
    .expect("check tenant_active_policies");
    assert!(active_policy_table_exists);

    let approval_outbox_exists: bool = sqlx::query_scalar::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'approval_resolution_outbox')",
    )
    .fetch_one(&db)
    .await
    .expect("check approval_resolution_outbox");
    assert!(approval_outbox_exists);

    drop(postgres);
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
    assert_eq!(payload.as_ref(), policy_yaml.as_bytes());
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
            database_url: "postgres://unused".to_string(),
            nats_url: harness.nats_url.clone(),
            agent_nats_url: harness.nats_url.clone(),
            nats_provisioning_mode: "external".to_string(),
            nats_provisioner_base_url: Some("http://127.0.0.1:9".to_string()),
            nats_provisioner_api_token: None,
            nats_allow_insecure_mock_provisioner: false,
            jwt_secret: "jwt-secret".to_string(),
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

async fn setup_harness() -> Harness {
    let pg_port = free_local_port();
    let nats_port = free_local_port();

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
        &format!("{pg_port}:5432"),
        "postgres:16-alpine",
    ]);
    let nats = run_container(&[
        "run",
        "-d",
        "--rm",
        "-p",
        &format!("{nats_port}:4222"),
        "nats:2.10-alpine",
        "-js",
    ]);

    let database_url = format!("postgres://postgres:postgres@127.0.0.1:{pg_port}/cloud_api");
    let nats_url = format!("nats://127.0.0.1:{nats_port}");

    wait_for_postgres(&database_url).await;
    wait_for_nats(&nats_url).await;

    let db = create_pool(&database_url).await.expect("create pool");
    run_migrations(&db).await.expect("apply migrations");

    let nats_client = async_nats::connect(&nats_url).await.expect("connect nats");
    let signing_keypair = Arc::new(hush_core::Keypair::generate());

    let config = Config {
        listen_addr: "127.0.0.1:0".parse().expect("listen addr"),
        database_url: database_url.clone(),
        nats_url: nats_url.clone(),
        agent_nats_url: nats_url.clone(),
        nats_provisioning_mode: "mock".to_string(),
        nats_provisioner_base_url: None,
        nats_provisioner_api_token: None,
        nats_allow_insecure_mock_provisioner: true,
        jwt_secret: "jwt-secret".to_string(),
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
        stale_detector_enabled: false,
        stale_check_interval_secs: 60,
        stale_threshold_secs: 120,
        dead_threshold_secs: 300,
    };

    let provisioner = TenantProvisioner::new(
        db.clone(),
        config.agent_nats_url.clone(),
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
        signing_keypair: Some(signing_keypair),
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
        _postgres: postgres,
        _nats: nats,
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

fn docker_available() -> bool {
    Command::new("docker")
        .args(["info"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn run_container(args: &[&str]) -> DockerContainer {
    let output = Command::new("docker")
        .args(args)
        .output()
        .expect("docker run should execute");
    assert!(
        output.status.success(),
        "docker run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let id = String::from_utf8(output.stdout)
        .expect("container id utf8")
        .trim()
        .to_string();
    DockerContainer { id }
}

fn free_local_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local port");
    listener.local_addr().expect("local addr").port()
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
