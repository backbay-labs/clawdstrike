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
            "description": "integration-test",
            "break_glass": true,
            "break_glass_reason": "integration test seeds active policy before enrollment"
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
    sqlx::raw_sql::raw_sql(include_str!("../../migrations/001_init.sql"))
        .execute(&mut *tx)
        .await
        .expect("apply legacy 001");
    sqlx::raw_sql::raw_sql(include_str!(
        "../../migrations/002_adaptive_sdr_schema.sql"
    ))
        .execute(&mut *tx)
        .await
        .expect("apply legacy 002");
    sqlx::raw_sql::raw_sql(include_str!(
        "../../migrations/003_adaptive_sdr_token_and_approval_flow.sql"
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

    let proposed_policy_hash = proposal["preview"]["fleetRuleDiffValidation"]
        ["proposedPolicySha256"]
        .as_str()
        .expect("fleet validation proposed policy hash")
        .to_string();
    let mut impact_report = serde_json::json!({
        "impactId": "policy-impact-int-1",
        "analyzedAt": now,
        "mode": "current_vs_proposed_policy_event_impact",
        "source": "submitted",
        "currentPolicy": {
            "policyVersion": "proposal-test-current",
            "policyHash": "d".repeat(64),
            "policyEpoch": 1
        },
        "proposedPolicy": {
            "policyVersion": "proposal-test-proposed",
            "policyHash": proposed_policy_hash.clone(),
            "policyEpoch": 2
        },
        "proposedPolicyHash": proposed_policy_hash.clone(),
        "proposedPolicyEpoch": 2,
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
    let mut impact_report_two = serde_json::json!({
        "impactId": "policy-impact-int-2",
        "analyzedAt": now,
        "mode": "current_vs_proposed_policy_event_impact",
        "source": "submitted",
        "currentPolicy": {
            "policyVersion": "proposal-test-current",
            "policyHash": "d".repeat(64),
            "policyEpoch": 1
        },
        "proposedPolicy": {
            "policyVersion": "proposal-test-proposed",
            "policyHash": proposed_policy_hash.clone(),
            "policyEpoch": 2
        },
        "proposedPolicyHash": proposed_policy_hash.clone(),
        "proposedPolicyEpoch": 2,
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
    let policy_event_impact_id_for = |impact: &Value| {
        use clawdstrike_policy_event::edr::{
            endpoint_policy_event_impact_id, EndpointPolicyEventImpactIdInput,
        };

        endpoint_policy_event_impact_id(EndpointPolicyEventImpactIdInput {
            current_policy_hash: impact["currentPolicy"]["policyHash"]
                .as_str()
                .expect("current policy hash"),
            current_policy_epoch: impact["currentPolicy"]["policyEpoch"]
                .as_u64()
                .expect("current policy epoch"),
            proposed_policy_hash: impact["proposedPolicy"]["policyHash"]
                .as_str()
                .expect("proposed policy hash"),
            proposed_policy_epoch: impact["proposedPolicy"]["policyEpoch"]
                .as_u64()
                .expect("proposed policy epoch"),
            event_source: impact["source"].as_str().expect("event source"),
            event_stream_hash: impact["eventStreamHash"]
                .as_str()
                .expect("event stream hash"),
            current_result_hash: impact["currentResultHash"]
                .as_str()
                .expect("current result hash"),
            proposed_result_hash: impact["proposedResultHash"]
                .as_str()
                .expect("proposed result hash"),
            impact_hash: impact["impactHash"].as_str().expect("impact hash"),
            event_count: impact["eventCount"].as_u64().expect("event count"),
            changed_count: impact["changedCount"].as_u64().expect("changed count"),
            allow_to_block_count: impact["allowToBlockCount"]
                .as_u64()
                .expect("allow-to-block count"),
            track_posture: impact["trackPosture"].as_bool().expect("track posture"),
        })
    };
    let impact_id = policy_event_impact_id_for(&impact_report);
    let impact_id_two = policy_event_impact_id_for(&impact_report_two);
    impact_report["impactId"] = serde_json::json!(impact_id);
    impact_report_two["impactId"] = serde_json::json!(impact_id_two);
    let impact_id = impact_report["impactId"]
        .as_str()
        .expect("policy impact id")
        .to_string();
    let impact_id_two = impact_report_two["impactId"]
        .as_str()
        .expect("second policy impact id")
        .to_string();
    let impact_evidence_for = |impact: &Value| {
        [
            ("impactId", impact["impactId"].as_str().unwrap().to_string()),
            (
                "eventSource",
                impact["source"].as_str().unwrap().to_string(),
            ),
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
    let endpoint_sensor_state = |endpoint_agent_id: &str| {
        serde_json::json!({
            "providers": [{
                "providerId": format!("agent-api:{endpoint_agent_id}"),
                "providerKind": "agent_api",
                "installed": true,
                "active": true,
                "healthy": true,
                "degraded": false,
                "degradationReasons": [],
                "droppedEventCount": 0,
                "deadlineMissCount": 0,
                "fullDiskAccess": null,
                "lastSeen": now
            }]
        })
    };
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
        "sensorState": endpoint_sensor_state("endpoint-policy-1"),
        "decision": {
            "findingId": impact_id.clone(),
            "ruleId": "endpoint.policy_event_impact",
            "action": "observe",
            "passed": true
        },
        "graph": {
            "graphSliceId": impact_id,
            "processNodeId": "policy_event_stream",
            "nodeIds": ["policy_event_stream"],
            "edgeIds": []
        },
        "evidence": impact_evidence
    });
    let signed_endpoint_decision_receipt_value =
        |keypair: &hush_core::Keypair, receipt_id: &str, endpoint_decision: Value| {
            let canonical_endpoint_decision = hush_core::canonicalize_json(&endpoint_decision)
                .expect("canonicalize endpoint decision receipt metadata");
            let impact_receipt = hush_core::Receipt::new(
                hush_core::sha256(canonical_endpoint_decision.as_bytes()),
                hush_core::Verdict::pass(),
            )
            .with_id(receipt_id)
            .with_metadata(serde_json::json!({
                "endpointDecision": endpoint_decision
            }));
            let signed_receipt = hush_core::SignedReceipt::sign(impact_receipt, keypair)
                .expect("sign policy impact receipt");
            serde_json::to_value(&signed_receipt).expect("signed receipt to json")
        };
    let signed_impact_receipt_value = signed_endpoint_decision_receipt_value(
        &impact_receipt_keypair,
        "receipt-policy-impact-1",
        endpoint_decision.clone(),
    );
    let mut endpoint_decision_two = endpoint_decision.clone();
    endpoint_decision_two["signer"]["signerPublicKey"] =
        serde_json::json!(impact_receipt_keypair_two.public_key().to_hex());
    endpoint_decision_two["signer"]["signerIdentity"] =
        serde_json::json!("endpoint-policy-proposal-int-2");
    endpoint_decision_two["actor"]["endpointId"] = serde_json::json!("endpoint-policy-2");
    endpoint_decision_two["sensorState"] = endpoint_sensor_state("endpoint-policy-2");
    endpoint_decision_two["decision"]["findingId"] = serde_json::json!(impact_id_two.clone());
    endpoint_decision_two["graph"]["graphSliceId"] = serde_json::json!(impact_id_two);
    endpoint_decision_two["evidence"] = serde_json::json!(impact_evidence_for(&impact_report_two));
    let signed_impact_receipt_value_two = signed_endpoint_decision_receipt_value(
        &impact_receipt_keypair_two,
        "receipt-policy-impact-2",
        endpoint_decision_two,
    );
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
    let endpoint_one_request = endpoint_one_envelope["fact"]["payload"]["request"].clone();
    let endpoint_one_expected_receipt =
        endpoint_one_envelope["fact"]["payload"]["expectedReceipt"].clone();
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
    let endpoint_two_request = endpoint_two_envelope["fact"]["payload"]["request"].clone();
    let endpoint_two_expected_receipt =
        endpoint_two_envelope["fact"]["payload"]["expectedReceipt"].clone();
    let endpoint_two_ack_token = endpoint_two_envelope["fact"]["delivery"]["ackToken"]
        .as_str()
        .expect("endpoint-policy-2 ack token")
        .to_string();

    for (action_id, endpoint_agent_id, ack_token, request, expected_receipt, impact, receipt) in [
        (
            endpoint_one_action_id.clone(),
            "endpoint-policy-1",
            endpoint_one_ack_token,
            endpoint_one_request,
            endpoint_one_expected_receipt,
            impact_report.clone(),
            signed_impact_receipt_value.clone(),
        ),
        (
            endpoint_two_action_id.clone(),
            "endpoint-policy-2",
            endpoint_two_ack_token,
            endpoint_two_request,
            endpoint_two_expected_receipt,
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
                        "request": request,
                        "expectedReceipt": expected_receipt,
                        "impact": impact,
                        "receipt": receipt
                    }
                }
            })),
        )
        .await;
        assert_eq!(ack_resp.0, StatusCode::OK, "{:?}", ack_resp.1);
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
            "blocking_change_count": 0,
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
    assert_eq!(attach_impact_resp.1["impact"]["blockingChangeCount"], 0);
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

    let proof_only_create_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/policies/proposals".to_string(),
        Some(member_key),
        Some(serde_json::json!({
            "policy_yaml": "policy:\n  mode: proof-only-proposal\n",
            "description": "proof hash without verified simulation receipt"
        })),
    )
    .await;
    assert_eq!(proof_only_create_resp.0, StatusCode::OK);
    let proof_only_proposal_id = proof_only_create_resp.1["proposal"]["id"]
        .as_str()
        .expect("proof-only proposal id")
        .to_string();
    let proof_only_impact_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/policies/proposals/{proof_only_proposal_id}/impact"),
        Some(member_key),
        Some(serde_json::json!({
            "source": "manual_review",
            "summary": "Manual review attached only an opaque proof hash.",
            "changed_verdict_count": 0,
            "blocking_change_count": 0,
            "developer_breakage_score": 0.0,
            "affected_identity_count": 0,
            "affected_tool_count": 0,
            "recommendation": "approve",
            "proof_hashes": ["a".repeat(64)]
        })),
    )
    .await;
    assert_eq!(proof_only_impact_resp.0, StatusCode::OK);
    assert_eq!(
        proof_only_impact_resp.1["impact"]["simulationReceiptsVerifiedCount"],
        0
    );
    let proof_only_first_approve_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/policies/proposals/{proof_only_proposal_id}/approve-deploy"),
        Some(&harness.api_key),
        Some(serde_json::json!({ "note": "first proof-only approval" })),
    )
    .await;
    assert_eq!(proof_only_first_approve_resp.0, StatusCode::OK);
    assert_eq!(
        proof_only_first_approve_resp.1["proposal"]["status"],
        "pending"
    );
    let proof_only_final_approve_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/policies/proposals/{proof_only_proposal_id}/approve-deploy"),
        Some(admin2_key),
        Some(serde_json::json!({ "note": "should require verified receipt" })),
    )
    .await;
    assert_eq!(proof_only_final_approve_resp.0, StatusCode::CONFLICT);
    assert!(proof_only_final_approve_resp.1["error"]
        .as_str()
        .expect("proof-only deploy error")
        .contains("verified simulation receipt"));
    let active_after_proof_only =
        policy_distribution::fetch_active_policy_by_tenant_id(&harness.db, harness.tenant_id)
            .await
            .expect("fetch active policy after proof-only deploy block")
            .expect("active policy should remain present after proof-only deploy block");
    assert_eq!(active_after_proof_only.version, 2);

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
