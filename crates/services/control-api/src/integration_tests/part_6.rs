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
