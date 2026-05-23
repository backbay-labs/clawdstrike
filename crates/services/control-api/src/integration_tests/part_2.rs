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
            cors: crate::config::CorsConfig::default(),
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

