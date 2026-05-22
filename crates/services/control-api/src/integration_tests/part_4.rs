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
                "actionType": "policy_rule_diff_validation",
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
                "actionType": "policy_rule_diff_validation",
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
            "targetKind": "principal",
            "targetId": fixture.principal_id.to_string(),
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
               'policy_rule_diff_validation',
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

fn policy_rule_diff_simulation_receipt_fixture(
    keypair: &hush_core::Keypair,
    target_id: &str,
) -> (Value, String, String) {
    use clawdstrike_policy_event::edr::{
        EndpointDecisionReceipt, EndpointPolicyEventImpactReceiptInput, EndpointPolicySnapshot,
        EndpointSensorState,
    };

    let policy_hash = hush_core::sha256(b"current-policy").to_hex_prefixed();
    let proposed_policy_hash = hush_core::sha256(b"proposed-policy").to_hex_prefixed();
    let event_stream_hash = hush_core::sha256(b"events").to_hex_prefixed();
    let current_result_hash = hush_core::sha256(b"current-results").to_hex_prefixed();
    let proposed_result_hash = hush_core::sha256(b"proposed-results").to_hex_prefixed();
    let impact_hash = hush_core::sha256(b"impact").to_hex_prefixed();
    let mut receipt =
        EndpointDecisionReceipt::for_policy_event_impact(EndpointPolicyEventImpactReceiptInput {
            local_sequence: 77,
            endpoint_id: target_id,
            signer_identity: &format!("local-edr:{target_id}"),
            policy: EndpointPolicySnapshot {
                policy_version: "test-policy".to_string(),
                policy_hash,
                policy_epoch: 1,
            },
            sensor_state: EndpointSensorState::single_active_agent(format!(
                "agent-api:{target_id}"
            )),
            impact_id: "ignored-by-builder",
            event_source: "submitted",
            event_stream_hash: &event_stream_hash,
            current_result_hash: &current_result_hash,
            proposed_result_hash: &proposed_result_hash,
            impact_hash: &impact_hash,
            proposed_policy_hash: &proposed_policy_hash,
            proposed_policy_epoch: 2,
            event_count: 2,
            changed_count: 1,
            allow_to_block_count: 1,
            track_posture: true,
        });
    receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());
    let impact_id = receipt
        .decision
        .finding_id
        .clone()
        .expect("policy event impact receipt id");
    let signed = receipt
        .sign_with(keypair)
        .expect("sign policy rule-diff simulation receipt");
    let receipt_id = signed
        .receipt
        .receipt_id
        .clone()
        .expect("signed policy rule-diff receipt id");
    let signed_value = serde_json::to_value(&signed).expect("signed receipt to json");
    (signed_value, receipt_id, impact_id)
}

fn policy_rule_diff_impact_payload_fixture(impact_id: &str) -> Value {
    serde_json::json!({
        "impactId": impact_id,
        "eventStreamHash": hush_core::sha256(b"events").to_hex_prefixed(),
        "currentResultHash": hush_core::sha256(b"current-results").to_hex_prefixed(),
        "proposedResultHash": hush_core::sha256(b"proposed-results").to_hex_prefixed(),
        "impactHash": hush_core::sha256(b"impact").to_hex_prefixed(),
        "proposedPolicy": {
            "policyHash": hush_core::sha256(b"proposed-policy").to_hex_prefixed(),
            "policyEpoch": 2
        },
        "eventCount": 2,
        "changedCount": 1,
        "allowToBlockCount": 1,
        "trackPosture": true
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_action_acks_reject_duplicate_delivery_acks() {
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
            "agent_id": "endpoint-1",
            "name": "Duplicate Ack Endpoint",
            "public_key": keypair.public_key().to_hex()
        })),
    )
    .await;
    assert_eq!(register_resp.0, StatusCode::OK);
    let (action_id, ack_token) = seed_ack_enabled_response_action(
        &harness.db,
        harness.tenant_id,
        "published",
        "published",
        None,
        Some(chrono::Utc::now() + chrono::Duration::minutes(10)),
    )
    .await;
    let (signed_receipt, _receipt_id, impact_id) =
        policy_rule_diff_simulation_receipt_fixture(&keypair, "endpoint-1");
    let impact_payload = policy_rule_diff_impact_payload_fixture(&impact_id);

    let first_ack = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/response-actions/{action_id}/acks"),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "targetKind": "endpoint",
            "targetId": "endpoint-1",
            "status": "acknowledged",
            "ackToken": &ack_token,
            "rawPayload": {
                "policyRuleDiffValidation": {
                    "proposalId": "proposal-test",
                    "validationPlanSha256": "sha256:plan",
                    "endpointAgentId": "endpoint-1",
                    "impact": impact_payload.clone(),
                    "receipt": signed_receipt
                }
            }
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
    let keypair = hush_core::Keypair::generate();
    let register_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/agents".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "agent_id": "endpoint-1",
            "name": "Response Ack Endpoint",
            "public_key": keypair.public_key().to_hex()
        })),
    )
    .await;
    assert_eq!(register_resp.0, StatusCode::OK);
    let (action_id, ack_token) = seed_ack_enabled_response_action(
        &harness.db,
        harness.tenant_id,
        "published",
        "published",
        None,
        Some(chrono::Utc::now() + chrono::Duration::minutes(10)),
    )
    .await;
    let (signed_receipt, receipt_id, impact_id) =
        policy_rule_diff_simulation_receipt_fixture(&keypair, "endpoint-1");
    let impact_payload = policy_rule_diff_impact_payload_fixture(&impact_id);

    let missing_receipt_resp = request_json(
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
                "policyRuleDiffValidation": {
                    "proposalId": "proposal-test",
                    "validationPlanSha256": "sha256:plan",
                    "endpointAgentId": "endpoint-1",
                    "impact": {
                        "impactId": "impact-test"
                    }
                }
            }
        })),
    )
    .await;
    assert_eq!(missing_receipt_resp.0, StatusCode::BAD_REQUEST);
    assert!(missing_receipt_resp.1["error"]
        .as_str()
        .expect("missing policy rule-diff receipt error")
        .contains("policyRuleDiffValidation acknowledgement must include receipt"));

    let invalid_receipt_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/response-actions/{action_id}/agent-acks"),
        None,
        Some(serde_json::json!({
            "targetKind": "endpoint",
            "targetId": "endpoint-1",
            "status": "acknowledged",
            "ackToken": &ack_token,
            "message": "forged receipt must be rejected before ack persistence",
            "resultingState": "collect_evidence:succeeded",
            "rawPayload": {
                "policyRuleDiffValidation": {
                    "proposalId": "proposal-test",
                    "validationPlanSha256": "sha256:plan",
                    "endpointAgentId": "endpoint-1",
                    "impact": {
                        "impactId": &impact_id
                    },
                    "receipt": {
                        "receipt": {
                            "receipt_id": "forged-policy-diff-receipt"
                        }
                    }
                }
            }
        })),
    )
    .await;
    assert_eq!(invalid_receipt_resp.0, StatusCode::BAD_REQUEST);
    assert!(invalid_receipt_resp.1["error"]
        .as_str()
        .expect("invalid policy rule-diff receipt error")
        .contains("policyRuleDiffValidation receipt is invalid"));

    let under_bound_impact_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/response-actions/{action_id}/agent-acks"),
        None,
        Some(serde_json::json!({
            "targetKind": "endpoint",
            "targetId": "endpoint-1",
            "status": "acknowledged",
            "ackToken": &ack_token,
            "message": "under-bound impact must be rejected before ack persistence",
            "resultingState": "collect_evidence:succeeded",
            "rawPayload": {
                "policyRuleDiffValidation": {
                    "proposalId": "proposal-test",
                    "validationPlanSha256": "sha256:plan",
                    "endpointAgentId": "endpoint-1",
                    "impact": {
                        "impactId": &impact_id
                    },
                    "receipt": signed_receipt.clone()
                }
            }
        })),
    )
    .await;
    assert_eq!(under_bound_impact_resp.0, StatusCode::BAD_REQUEST);
    assert!(under_bound_impact_resp.1["error"]
        .as_str()
        .expect("under-bound policy rule-diff impact error")
        .contains("policyRuleDiffValidation impact must include eventStreamHash"));

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
                "policyRuleDiffValidation": {
                    "proposalId": "proposal-test",
                    "validationPlanSha256": "sha256:plan",
                    "endpointAgentId": "endpoint-1",
                    "impact": impact_payload,
                    "receipt": signed_receipt
                }
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
        detail_resp.1["acknowledgements"][0]["raw_payload"]["policyRuleDiffValidation"]["receipt"]
            ["receipt"]["receipt_id"]
            .as_str()
            .expect("acknowledgement receipt is persisted"),
        receipt_id
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
            "actionType": "policy_rule_diff_validation",
            "target": {
                "kind": "endpoint",
                "id": endpoint_agent_id
            },
            "reason": "Validate endpoint policy diff",
            "requireAcknowledgement": true,
            "payload": {
                "operation": "policy_rule_diff_validation"
            }
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

