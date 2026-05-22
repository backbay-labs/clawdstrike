    #[tokio::test]
    async fn agent_edr_policy_deltas_promote_staged_detection_to_signed_overlay() {
        let staged_detection_path = test_staged_detection_path();
        let policy_delta_dir = test_policy_delta_dir();
        let _ = std::fs::remove_file(&staged_detection_path);
        let _ = std::fs::remove_dir_all(&policy_delta_dir);
        let mut state = test_state();
        state.edr_staged_detection_ledger = Arc::new(Mutex::new(
            EndpointStagedDetectionLedger::open(&staged_detection_path)
                .unwrap_or_else(|e| panic!("failed to open staged detection ledger: {e}")),
        ));
        state.edr_policy_delta_store = Arc::new(Mutex::new(
            EndpointPolicyDeltaStore::open(&policy_delta_dir)
                .unwrap_or_else(|e| panic!("failed to open policy delta store: {e}")),
        ));
        {
            let settings = state.settings.read().await;
            std::fs::write(
                &settings.policy_path,
                "version: \"test-edr\"\npolicy_epoch: 1\nname: agent-api-test\n",
            )
            .unwrap_or_else(|e| panic!("failed to pin test policy epoch: {e}"));
        }
        let state = Arc::new(state);
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/staged-detections",
                get(agent_edr_staged_detections).post(agent_edr_stage_detection),
            )
            .route(
                "/api/v1/agent/edr/policy-deltas",
                get(agent_edr_policy_deltas).post(agent_edr_policy_delta),
            )
            .route(
                "/api/v1/agent/edr/policy-deltas/{policy_delta_id}/apply",
                post(agent_edr_policy_delta_apply),
            )
            .with_state(state.clone());

        let host = "delta.example.invalid";
        let port = 443;
        let observations = vec![
            EndpointObservation {
                observation_id: "policy-delta-network-1".to_string(),
                host_id: Some("host-policy-delta-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("session-policy-delta-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-policy-delta-1".to_string()),
                    image: Some("/usr/bin/python3".to_string()),
                    command_line: Some("python3 exfil.py".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::NetworkFlow {
                    host: host.to_string(),
                    port,
                    protocol: Some("https".to_string()),
                    url: Some(format!("https://{host}/upload")),
                },
                metadata: BTreeMap::from([
                    (
                        "agentId".to_string(),
                        serde_json::json!("agent-policy-delta-1"),
                    ),
                    (
                        "toolCallId".to_string(),
                        serde_json::json!("tool-call-policy-delta-1"),
                    ),
                ]),
                ..EndpointObservation::default()
            },
            EndpointObservation {
                observation_id: "policy-delta-tool-1".to_string(),
                host_id: Some("host-policy-delta-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("session-policy-delta-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-policy-delta-1".to_string()),
                    image: Some("/usr/bin/python3".to_string()),
                    command_line: Some("python3 exfil.py".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::ToolCall {
                    tool_name: "mcp.shell".to_string(),
                    parameters: serde_json::json!({
                        "command": "python3 exfil.py"
                    }),
                },
                metadata: BTreeMap::from([
                    (
                        "agentId".to_string(),
                        serde_json::json!("agent-policy-delta-1"),
                    ),
                    (
                        "toolCallId".to_string(),
                        serde_json::json!("tool-call-policy-delta-1"),
                    ),
                ]),
                ..EndpointObservation::default()
            },
        ];
        let body = serde_json::json!({
            "observations": observations,
            "honey_artifacts": []
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/findings")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build policy-delta findings: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("policy-delta findings failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let network_node_id = {
            let graph = state.edr_flight_recorder.lock().await.graph().clone();
            graph
                .nodes
                .iter()
                .find(|(_, node)| {
                    node.kind == CausalNodeKind::Network && node.label == format!("{host}:{port}")
                })
                .map(|(node_id, _)| node_id.clone())
                .unwrap_or_else(|| panic!("missing network graph node"))
        };

        let body = serde_json::json!({
            "rootNodeId": network_node_id,
            "maxDepth": 8,
            "selectedStage": "limited_block",
            "stagedBy": "operator:bob",
            "note": "attempt enforcement without cross-window readiness"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/staged-detections")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build ungated policy-delta stage request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("ungated policy-delta stage request failed: {e}"));
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read ungated stage response: {e}"));
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "ungated stage response: {}",
            String::from_utf8_lossy(&bytes)
        );
        assert!(
            String::from_utf8_lossy(&bytes).contains("promotionReady=true"),
            "ungated stage response: {}",
            String::from_utf8_lossy(&bytes)
        );

        let body = serde_json::json!({
            "rootNodeId": network_node_id,
            "maxDepth": 8,
            "selectedStage": "limited_block",
            "crossWindowImpactHash": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "crossWindowRecommendationHash": "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "stagedBy": "operator:bob",
            "note": "stage egress restriction"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/staged-detections")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build policy-delta stage request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("policy-delta stage request failed: {e}"));
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read unproven staged detection response: {e}"));
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "unproven stage response: {}",
            String::from_utf8_lossy(&bytes)
        );
        assert!(
            String::from_utf8_lossy(&bytes).contains("recent promotionReady=true"),
            "unproven stage response: {}",
            String::from_utf8_lossy(&bytes)
        );

        let current_policy = {
            let settings = state.settings.read().await.clone();
            endpoint_policy_snapshot_from_settings(&settings)
                .unwrap_or_else(|e| panic!("failed to snapshot current policy: {e}"))
        };

        state
            .edr_cross_window_promotion_validations
            .lock()
            .await
            .push_back(EdrCrossWindowPromotionValidation {
                recorded_at: chrono::Utc::now(),
                impact_hash:
                    "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_string(),
                recommendation_hash:
                    "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                        .to_string(),
                current_policy_hash: current_policy.policy_hash,
                current_policy_epoch: current_policy.policy_epoch,
                proposed_policy_hash: sha256(b"test-proposed-policy").to_hex_prefixed(),
                proposed_policy_epoch: 2,
                event_stream_hash: sha256(b"test-event-stream").to_hex_prefixed(),
                current_result_hash: sha256(b"test-current-result").to_hex_prefixed(),
                proposed_result_hash: sha256(b"test-proposed-result").to_hex_prefixed(),
                history_selector_hash: sha256(b"test-history-selector").to_hex_prefixed(),
                newest_event_at: Some(chrono::Utc::now()),
                max_age_seconds: Some(1800),
                recommended_stage: "limited_block".to_string(),
                root_node_id: network_node_id.clone(),
                action: EndpointDecisionAction::RestrictEgress,
                promotion_ready: true,
            });

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/staged-detections")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build proven policy-delta stage request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("proven policy-delta stage request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read staged detection response: {e}"));
        let staged_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode staged detection response: {e}"));
        let staged_detection_id = staged_payload["record"]["stagedDetectionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing staged detection id"));
        assert!(staged_payload["record"]["simulation"]["affectedIdentities"]
            .as_array()
            .unwrap_or_else(|| panic!("missing staged policy-delta affected identities"))
            .iter()
            .any(|identity| identity["identityKind"] == "user" && identity["value"] == "alice"));
        assert!(staged_payload["record"]["simulation"]["affectedTools"]
            .as_array()
            .unwrap_or_else(|| panic!("missing staged policy-delta affected tools"))
            .iter()
            .any(|tool| tool["toolName"] == "mcp.shell"
                && tool["toolCallId"] == "tool-call-policy-delta-1"));

        let body = serde_json::json!({
            "stagedDetectionId": staged_detection_id,
            "generatedBy": "operator:bob",
            "note": "promote egress rule into a policy delta"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/policy-deltas")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build policy delta request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("policy delta request failed: {e}"));
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read policy delta response: {e}"));
        assert_eq!(
            status,
            StatusCode::OK,
            "policy delta response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode policy delta response: {e}"));

        assert_eq!(payload["record"]["stage"], "limited_block");
        assert_eq!(payload["record"]["action"], "restrict_egress");
        assert_eq!(
            payload["record"]["artifact"]["schemaVersion"],
            EDR_POLICY_DELTA_SCHEMA_VERSION
        );
        assert_eq!(
            payload["record"]["artifact"]["stagedDetectionId"],
            staged_detection_id
        );
        assert!(payload["record"]["artifact"]["sourceAffectedIdentities"]
            .as_array()
            .unwrap_or_else(|| panic!("missing policy delta source affected identities"))
            .iter()
            .any(|identity| identity["identityKind"] == "user" && identity["value"] == "alice"));
        assert!(payload["record"]["artifact"]["sourceAffectedTools"]
            .as_array()
            .unwrap_or_else(|| panic!("missing policy delta source affected tools"))
            .iter()
            .any(|tool| tool["toolName"] == "mcp.shell"
                && tool["toolCallId"] == "tool-call-policy-delta-1"));
        assert_eq!(
            payload["record"]["artifact"]["rollout"]["crossWindowImpactHash"],
            "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
        assert_eq!(
            payload["record"]["artifact"]["rollout"]["crossWindowRecommendationHash"],
            "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        );
        assert_eq!(
            payload["record"]["artifact"]["policyPatch"]["endpoint_decision_engine"]
                ["generated_rules"][0]["cross_window_impact_hash"],
            "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
        assert!(
            payload["record"]["artifact"]["policyPatch"]["endpoint_decision_engine"]
                ["generated_rules"][0]["impact"]["affected_identity_context"]
                .as_array()
                .unwrap_or_else(|| panic!("missing policy patch affected identity context"))
                .iter()
                .any(|identity| identity["identityKind"] == "user" && identity["value"] == "alice")
        );
        assert!(
            payload["record"]["artifact"]["policyPatch"]["endpoint_decision_engine"]
                ["generated_rules"][0]["impact"]["affected_tool_context"]
                .as_array()
                .unwrap_or_else(|| panic!("missing policy patch affected tool context"))
                .iter()
                .any(|tool| tool["toolName"] == "mcp.shell"
                    && tool["toolCallId"] == "tool-call-policy-delta-1")
        );
        assert_eq!(
            payload["record"]["artifact"]["policyPatch"]["guards"]["egress_allowlist"]["block"][0],
            "delta.example.invalid:443"
        );
        assert!(payload["record"]["artifactHash"]
            .as_str()
            .unwrap_or_default()
            .starts_with("0x"));
        let artifact_path = payload["record"]["artifactPath"]
            .as_str()
            .unwrap_or_else(|| panic!("missing policy delta artifact path"));
        assert!(std::path::Path::new(artifact_path).is_file());
        let endpoint_decision =
            &payload["record"]["receipt"]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(endpoint_decision["receiptFamily"], "policy_delta");
        assert_eq!(
            endpoint_decision["decision"]["findingId"],
            payload["record"]["policyDeltaId"]
        );
        assert_eq!(
            endpoint_decision["decision"]["ruleId"],
            payload["record"]["ruleId"]
        );
        assert!(endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing policy delta receipt evidence"))
            .iter()
            .any(|item| item["key"] == "crossWindowImpactHash"));
        assert!(endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing policy delta receipt evidence"))
            .iter()
            .any(|item| item["key"] == "crossWindowRecommendationHash"));
        assert!(endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing policy delta receipt evidence"))
            .iter()
            .any(|item| item["key"] == "sourceAffectedIdentityContext"));
        assert!(endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing policy delta receipt evidence"))
            .iter()
            .any(|item| item["key"] == "sourceAffectedToolContext"));
        let mut policy_delta_record_value = payload["record"].clone();
        policy_delta_record_value["shadowPolicyDelta"] =
            serde_json::Value::String("must not be ignored".to_string());
        assert_unknown_field_rejected::<EdrPolicyDeltaRecord>(
            policy_delta_record_value,
            "shadowPolicyDelta",
        );
        let mut policy_delta_artifact_value = payload["record"]["artifact"].clone();
        policy_delta_artifact_value["shadowPolicyPatch"] =
            serde_json::Value::String("must not be ignored".to_string());
        assert_unknown_field_rejected::<EdrPolicyDeltaArtifact>(
            policy_delta_artifact_value,
            "shadowPolicyPatch",
        );
        let mut policy_delta_target_value = payload["record"]["artifact"]["targetPolicy"].clone();
        policy_delta_target_value["shadowPolicyEpoch"] =
            serde_json::Value::String("must not be ignored".to_string());
        assert_unknown_field_rejected::<EdrPolicyDeltaTargetPolicy>(
            policy_delta_target_value,
            "shadowPolicyEpoch",
        );
        let mut policy_delta_rollout_value = payload["record"]["artifact"]["rollout"].clone();
        policy_delta_rollout_value["shadowPromotionGate"] =
            serde_json::Value::String("must not be ignored".to_string());
        assert_unknown_field_rejected::<EdrPolicyDeltaRollout>(
            policy_delta_rollout_value,
            "shadowPromotionGate",
        );

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/edr/policy-deltas?stage=limited_block")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build policy delta list request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("policy delta list request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read policy delta list: {e}"));
        let list_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode policy delta list: {e}"));
        assert_eq!(list_payload["count"], 1);
        assert_eq!(
            list_payload["policyDeltas"][0]["artifactHash"],
            payload["record"]["artifactHash"]
        );

        let policy_delta_id = payload["record"]["policyDeltaId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing policy delta id"));
        let original_policy = {
            let settings = state.settings.read().await;
            std::fs::read_to_string(&settings.policy_path)
                .unwrap_or_else(|e| panic!("failed to read original policy: {e}"))
        };
        let original_record: EdrPolicyDeltaRecord =
            serde_json::from_value(payload["record"].clone())
                .unwrap_or_else(|e| panic!("failed to decode original policy delta record: {e}"));
        let mut tampered_record = original_record.clone();
        tampered_record.artifact.policy_patch = serde_json::json!({
            "endpoint_decision_engine": {
                "generated_rules": []
            }
        });
        let policy_delta_index =
            crate::edr::ledger::policy_delta::policy_delta_index_path(&policy_delta_dir);
        let mut policy_delta_index_contents = std::fs::read_to_string(&policy_delta_index)
            .unwrap_or_else(|e| panic!("failed to read policy delta index: {e}"));
        policy_delta_index_contents.push_str(
            &serde_json::to_string(&tampered_record)
                .unwrap_or_else(|e| panic!("failed to encode tampered policy delta record: {e}")),
        );
        policy_delta_index_contents.push('\n');
        std::fs::write(&policy_delta_index, policy_delta_index_contents)
            .unwrap_or_else(|e| panic!("failed to append tampered policy delta record: {e}"));
        let body = serde_json::json!({
            "dryRun": true,
            "appliedBy": "operator:bob"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/policy-deltas/{policy_delta_id}/apply"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build tampered policy delta apply: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("tampered policy delta apply failed: {e}"));
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read tampered policy delta apply error: {e}"));
        let error = String::from_utf8(bytes.to_vec())
            .unwrap_or_else(|e| panic!("tampered policy delta apply error is not utf8: {e}"));
        assert!(
            error.contains("artifact hash mismatch"),
            "unexpected tampered policy delta error: {error}"
        );
        let mut policy_delta_index_contents = std::fs::read_to_string(&policy_delta_index)
            .unwrap_or_else(|e| panic!("failed to reread policy delta index: {e}"));
        policy_delta_index_contents.push_str(
            &serde_json::to_string(&original_record)
                .unwrap_or_else(|e| panic!("failed to encode original policy delta record: {e}")),
        );
        policy_delta_index_contents.push('\n');
        std::fs::write(&policy_delta_index, policy_delta_index_contents)
            .unwrap_or_else(|e| panic!("failed to restore original policy delta record: {e}"));
        let body = serde_json::json!({
            "dryRun": true,
            "appliedBy": "operator:bob"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/policy-deltas/{policy_delta_id}/apply"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build policy delta dry-run apply: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("policy delta dry-run apply failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read policy delta dry-run apply: {e}"));
        let dry_run_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode policy delta dry-run apply: {e}"));
        assert_eq!(dry_run_payload["record"]["dryRun"], true);
        assert_eq!(dry_run_payload["record"]["applied"], false);
        assert_eq!(
            dry_run_payload["record"]["crossWindowImpactHash"],
            "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
        assert_eq!(
            dry_run_payload["record"]["crossWindowRecommendationHash"],
            "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        );
        assert!(dry_run_payload["receipt"].is_null());
        assert!(dry_run_payload["postApplyEnforcement"].is_null());
        let policy_after_dry_run = {
            let settings = state.settings.read().await;
            std::fs::read_to_string(&settings.policy_path)
                .unwrap_or_else(|e| panic!("failed to read dry-run policy: {e}"))
        };
        assert_eq!(policy_after_dry_run, original_policy);
        let expected_new_epoch = dry_run_payload["record"]["newPolicyEpoch"]
            .as_u64()
            .unwrap_or_else(|| panic!("missing dry-run new policy epoch"));
        let advanced_policy = format!(
            "version: test-edr\npolicy_epoch: {}\n",
            expected_new_epoch.saturating_add(10)
        );
        {
            let settings = state.settings.read().await;
            std::fs::write(&settings.policy_path, advanced_policy.as_bytes())
                .unwrap_or_else(|e| panic!("failed to write advanced policy: {e}"));
        }
        let body = serde_json::json!({
            "dryRun": true,
            "allowBasePolicyDrift": true,
            "appliedBy": "operator:bob"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/policy-deltas/{policy_delta_id}/apply"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build stale policy delta apply: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("stale policy delta apply request failed: {e}"));
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read stale policy delta apply error: {e}"));
        let error = String::from_utf8(bytes.to_vec())
            .unwrap_or_else(|e| panic!("stale policy delta apply error is not utf8: {e}"));
        assert!(error.contains("policy delta target epoch"));
        {
            let settings = state.settings.read().await;
            std::fs::write(&settings.policy_path, original_policy.as_bytes())
                .unwrap_or_else(|e| panic!("failed to restore original policy: {e}"));
        }
        let body = serde_json::json!({
            "dryRun": false,
            "verifyProtectionState": false,
            "reloadDaemonPolicy": false,
            "restartDaemon": false,
            "appliedBy": "operator:bob"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/policy-deltas/{policy_delta_id}/apply"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build unverified live policy delta apply request: {e}")
            });
        let response =
            app.clone().oneshot(req).await.unwrap_or_else(|e| {
                panic!("unverified live policy delta apply request failed: {e}")
            });
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read unverified live policy delta apply response: {e}")
            });
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "unexpected unverified live policy delta apply response: {}",
            String::from_utf8_lossy(&bytes)
        );
        assert!(String::from_utf8_lossy(&bytes).contains("verifyProtectionState"));
        let body = serde_json::json!({
            "dryRun": false,
            "appliedBy": "operator:bob",
            "note": "missing approval-bound actor must be rejected",
            "providerAckTimeoutMs": 1000
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/policy-deltas/{policy_delta_id}/apply"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build unauthored live policy delta apply request: {e}")
            });
        let response =
            app.clone().oneshot(req).await.unwrap_or_else(|e| {
                panic!("unauthored live policy delta apply request failed: {e}")
            });
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read unauthored live policy delta apply response: {e}")
            });
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "unexpected unauthored live policy delta apply response: {}",
            String::from_utf8_lossy(&bytes)
        );
        assert!(
            String::from_utf8_lossy(&bytes).contains("requires actor identity"),
            "unexpected unauthored live policy delta apply response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let (mock_daemon_policy_reload_port, _mock_daemon_policy_reload_handle) =
            spawn_mock_daemon_policy_reload().await;
        {
            let mut settings = state.settings.write().await;
            settings.daemon_port = mock_daemon_policy_reload_port;
        }
        let policy_delta_reload_path = state
            .edr_network_extension_egress_policy_path
            .display()
            .to_string();
        let (reload_tx, mut reload_rx) =
            tokio::sync::mpsc::channel::<crate::macos::host::MacosNetworkExtensionReloadRequest>(1);
        state
            .macos_host
            .install_network_extension_reload_channel(reload_tx)
            .await;
        let macos_host_for_ack = state.macos_host.clone();
        let policy_delta_reload_path_for_ack = policy_delta_reload_path.clone();
        tokio::spawn(async move {
            let request = reload_rx
                .recv()
                .await
                .unwrap_or_else(|| panic!("missing policy-delta NetworkExtension reload request"));
            assert_eq!(
                request.policy_snapshot_path,
                PathBuf::from(policy_delta_reload_path_for_ack.as_str())
            );
            assert_eq!(request.timeout_duration, Duration::from_millis(1000));
            let request_id = "policy-delta-reload-1".to_string();
            macos_host_for_ack
                .replace_status(CombinedSystemExtensionStatus {
                    install_state: SystemExtensionInstallState::Installed,
                    approval: SystemExtensionApproval::Approved,
                    endpoint_security: ProviderStatus {
                        runtime: ProviderRuntimeState::Active,
                        policy_epoch: Some(expected_new_epoch),
                        ..ProviderStatus::unknown()
                    },
                    network_extension: ProviderStatus {
                        runtime: ProviderRuntimeState::Active,
                        policy_epoch: Some(expected_new_epoch),
                        policy_synced: Some(true),
                        enforcement_ready: Some(true),
                        last_reload_observation: Some(
                            crate::macos::status::ProviderReloadObservation {
                                request_id: Some(request_id.clone()),
                                command: Some("reload_policy".to_string()),
                                policy_snapshot_path: Some(
                                    policy_delta_reload_path_for_ack.clone(),
                                ),
                                generation: Some(request.generation),
                                accepted: Some(true),
                                reloaded: Some(true),
                                error: None,
                            },
                        ),
                        ..ProviderStatus::unknown()
                    },
                    ..CombinedSystemExtensionStatus::default()
                })
                .await;
            request
                .reply_tx
                .send(Ok(crate::macos::host::MacosNetworkExtensionReloadResult {
                    requested: true,
                    saved: true,
                    request_id,
                    policy_snapshot_path: policy_delta_reload_path_for_ack,
                    generation: request.generation,
                }))
                .unwrap_or_else(|_| panic!("failed to send policy-delta reload response"));
        });

        let body = serde_json::json!({
            "dryRun": false,
            "appliedBy": "operator:bob",
            "actor": {
                "endpointId": "endpoint-policy-delta-1",
                "userId": "operator:bob",
                "sessionId": "session-policy-delta-apply-1",
                "agentId": "agent-api",
                "approvalId": "approval-policy-delta-1"
            },
            "note": "apply generated egress overlay",
            "providerAckTimeoutMs": 1000
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/policy-deltas/{policy_delta_id}/apply"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build policy delta apply: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("policy delta apply failed: {e}"));
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read policy delta apply: {e}"));
        assert_eq!(
            status,
            StatusCode::OK,
            "policy delta apply response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let apply_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode policy delta apply: {e}"));
        assert_eq!(apply_payload["record"]["dryRun"], false);
        assert_eq!(apply_payload["record"]["applied"], true);
        assert_eq!(
            apply_payload["record"]["crossWindowImpactHash"],
            "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
        assert_eq!(
            apply_payload["record"]["crossWindowRecommendationHash"],
            "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        );
        assert_eq!(
            apply_payload["receipt"]["receipt"]["metadata"]["endpointDecision"]["receiptFamily"],
            "policy_delta"
        );
        assert_eq!(
            apply_payload["preparedReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "policy_delta"
        );
        let applied_endpoint_decision =
            &apply_payload["receipt"]["receipt"]["metadata"]["endpointDecision"];
        let prepared_endpoint_decision =
            &apply_payload["preparedReceipt"]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(
            apply_payload["record"]["actor"]["approvalId"],
            "approval-policy-delta-1"
        );
        assert_eq!(
            applied_endpoint_decision["actor"]["approvalId"],
            "approval-policy-delta-1"
        );
        assert_eq!(
            prepared_endpoint_decision["actor"]["approvalId"],
            "approval-policy-delta-1"
        );
        assert!(applied_endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing applied policy delta receipt evidence"))
            .iter()
            .any(|item| item["key"] == "actorHash"));
        assert!(prepared_endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing prepared policy delta receipt evidence"))
            .iter()
            .any(|item| item["key"] == "actorHash"));
        assert_eq!(
            apply_payload["preparedReceipt"]["receipt"]["metadata"]["endpointDecision"]["decision"]
                ["title"],
            "Endpoint staged policy delta prepared"
        );
        let apply_ledger_path =
            crate::edr::ledger::policy_delta::policy_delta_apply_index_path(&policy_delta_dir);
        let apply_ledger = std::fs::read_to_string(&apply_ledger_path)
            .unwrap_or_else(|e| panic!("failed to read policy delta apply ledger: {e}"));
        assert!(
            apply_ledger.contains(policy_delta_id),
            "policy delta apply ledger missing {policy_delta_id}: {apply_ledger}"
        );
        assert!(
            apply_payload["receipt"]["receipt"]["metadata"]["endpointDecision"]["evidence"]
                .as_array()
                .unwrap_or_else(|| panic!("missing apply policy delta receipt evidence"))
                .iter()
                .any(|item| item["key"] == "crossWindowImpactHash")
        );
        assert!(
            apply_payload["receipt"]["receipt"]["metadata"]["endpointDecision"]["evidence"]
                .as_array()
                .unwrap_or_else(|| panic!("missing apply policy delta receipt evidence"))
                .iter()
                .any(|item| item["key"] == "crossWindowRecommendationHash")
        );
        assert!(
            apply_payload["receipt"]["receipt"]["metadata"]["endpointDecision"]["evidence"]
                .as_array()
                .unwrap_or_else(|| panic!("missing apply policy delta receipt evidence"))
                .iter()
                .any(|item| item["key"] == "sourceAffectedIdentityContext")
        );
        assert!(
            apply_payload["receipt"]["receipt"]["metadata"]["endpointDecision"]["evidence"]
                .as_array()
                .unwrap_or_else(|| panic!("missing apply policy delta receipt evidence"))
                .iter()
                .any(|item| item["key"] == "sourceAffectedToolContext")
        );
        assert_eq!(
            apply_payload["receipt"]["receipt"]["metadata"]["endpointDecision"]["decision"]
                ["findingId"],
            policy_delta_id
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["policySyncedToDisk"],
            true
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["daemonPolicyReload"]["requested"],
            true
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["daemonPolicyReload"]["reloaded"],
            true
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["networkExtensionPolicyReload"]["requested"],
            true
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["networkExtensionPolicyReload"]["saved"],
            true
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["networkExtensionPolicyReload"]["requestId"],
            "policy-delta-reload-1"
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["networkExtensionPolicyReload"]
                ["policySnapshotPath"],
            policy_delta_reload_path
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["networkExtensionPolicyReload"]
                ["providerReloadObserved"],
            true
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["networkExtensionPolicyReload"]
                ["providerReloadMatched"],
            true
        );
        let network_extension_policy =
            read_json_file(state.edr_network_extension_egress_policy_path.as_ref());
        assert!(network_extension_policy["restrictions"]
            .as_array()
            .unwrap_or_else(|| panic!("missing policy-delta NetworkExtension restrictions"))
            .iter()
            .any(
                |restriction| restriction["target"] == "delta.example.invalid:443"
                    && restriction["active"] == true
                    && restriction["executionId"]
                        .as_str()
                        .unwrap_or_default()
                        .starts_with("policy_egress-")
            ));
        assert_eq!(
            apply_payload["postApplyEnforcement"]["providerStatusRefresh"]["requested"],
            true
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["providerStatusRefresh"]["refreshed"],
            false
        );
        let provider_acks = apply_payload["postApplyEnforcement"]["providerPolicyAcknowledgements"]
            .as_array()
            .unwrap_or_else(|| panic!("missing provider policy acknowledgements"));
        assert_eq!(
            apply_payload["postApplyEnforcement"]["providerAcknowledgementPoll"]["requested"],
            true
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["providerAcknowledgementPoll"]["satisfied"],
            true
        );
        assert!(
            apply_payload["postApplyEnforcement"]["providerAcknowledgementPoll"]["attempts"]
                .as_u64()
                .unwrap_or(0)
                >= 1
        );
        assert!(provider_acks.iter().any(|ack| {
            ack["providerId"] == "macos.network_extension"
                && ack["acknowledged"] == true
                && ack["observedPolicyEpoch"] == apply_payload["record"]["newPolicyEpoch"]
        }));
        assert!(provider_acks.iter().any(|ack| {
            ack["providerId"] == "macos.endpoint_security"
                && ack["acknowledged"] == true
                && ack["observedPolicyEpoch"] == apply_payload["record"]["newPolicyEpoch"]
        }));
        assert_eq!(
            apply_payload["postApplyEnforcement"]["daemonRestartRequested"],
            false
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["daemonRestarted"],
            false
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["localPolicy"]["policyEpoch"],
            apply_payload["record"]["newPolicyEpoch"]
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["crossWindowImpactHash"],
            "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["crossWindowRecommendationHash"],
            "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        );
        assert_eq!(
            apply_payload["postApplyEnforcement"]["receipt"]["receipt"]["metadata"]
                ["endpointDecision"]["receiptFamily"],
            "sensor_state"
        );
        let enforcement_receipt_endpoint_decision = &apply_payload["postApplyEnforcement"]
            ["receipt"]["receipt"]["metadata"]["endpointDecision"];
        let enforcement_receipt_evidence = enforcement_receipt_endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing post-apply enforcement receipt evidence"));
        let true_hash = sha256(b"true").to_hex_prefixed();
        let false_hash = sha256(b"false").to_hex_prefixed();
        let expected_epoch_hash =
            sha256(expected_new_epoch.to_string().as_bytes()).to_hex_prefixed();
        let policy_delta_reload_path_hash =
            sha256(policy_delta_reload_path.as_bytes()).to_hex_prefixed();
        assert!(enforcement_receipt_evidence.iter().any(|item| {
            item["key"] == "policyDeltaApplyProviderAckPollSatisfied"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(enforcement_receipt_evidence.iter().any(|item| {
            item["key"] == "policyDeltaApplyProviderRefreshRequested"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(enforcement_receipt_evidence.iter().any(|item| {
            item["key"] == "policyDeltaApplyProviderRefreshRefreshed"
                && item["valueHash"].as_str() == Some(false_hash.as_str())
        }));
        assert!(enforcement_receipt_evidence.iter().any(|item| {
            item["key"] == "policyDeltaApplyNetworkExtensionReloadRequested"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(enforcement_receipt_evidence.iter().any(|item| {
            item["key"] == "policyDeltaApplyNetworkExtensionReloadSaved"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(enforcement_receipt_evidence.iter().any(|item| {
            item["key"] == "policyDeltaApplyNetworkExtensionReloadPolicySnapshotPath"
                && item["valueHash"].as_str() == Some(policy_delta_reload_path_hash.as_str())
        }));
        assert!(enforcement_receipt_evidence.iter().any(|item| {
            item["key"] == "policyDeltaApplyCrossWindowImpactHash"
                && item["valueHash"].as_str()
                    == Some(
                        sha256(
                            b"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                        )
                        .to_hex_prefixed()
                        .as_str(),
                    )
        }));
        assert!(enforcement_receipt_evidence.iter().any(|item| {
            item["key"] == "policyDeltaApplyCrossWindowRecommendationHash"
                && item["valueHash"].as_str()
                    == Some(
                        sha256(
                            b"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                        )
                        .to_hex_prefixed()
                        .as_str(),
                    )
        }));
        assert!(enforcement_receipt_evidence.iter().any(|item| {
            item["key"] == "providerAck.macos_network_extension.acknowledged"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(enforcement_receipt_evidence.iter().any(|item| {
            item["key"] == "providerAck.macos_network_extension.observedPolicyEpoch"
                && item["valueHash"].as_str() == Some(expected_epoch_hash.as_str())
        }));
        assert!(enforcement_receipt_evidence.iter().any(|item| {
            item["key"] == "providerAck.macos_network_extension.policySynced"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(enforcement_receipt_evidence.iter().any(|item| {
            item["key"] == "providerAck.macos_network_extension.enforcementReady"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        let backup_path = apply_payload["record"]["backupPath"]
            .as_str()
            .unwrap_or_else(|| panic!("missing policy delta backup path"));
        assert!(std::path::Path::new(backup_path).is_file());
        let applied_policy = {
            let settings = state.settings.read().await;
            std::fs::read_to_string(&settings.policy_path)
                .unwrap_or_else(|e| panic!("failed to read applied policy: {e}"))
        };
        assert!(applied_policy.contains("endpoint_decision_engine"));
        assert!(applied_policy.contains("delta.example.invalid:443"));
        let applied_snapshot = {
            let settings = state.settings.read().await;
            endpoint_policy_snapshot_from_policy_bytes(
                applied_policy.as_bytes(),
                &settings.policy_path,
            )
            .unwrap_or_else(|e| panic!("failed to snapshot applied policy: {e}"))
        };
        let previous_epoch = apply_payload["record"]["previousPolicyEpoch"]
            .as_u64()
            .unwrap_or_else(|| panic!("missing previous policy epoch"));
        let new_epoch = apply_payload["record"]["newPolicyEpoch"]
            .as_u64()
            .unwrap_or_else(|| panic!("missing new policy epoch"));
        assert_eq!(new_epoch, previous_epoch.saturating_add(1));
        assert_eq!(applied_snapshot.policy_epoch, new_epoch);

        let _ = std::fs::remove_file(staged_detection_path);
        let _ = std::fs::remove_dir_all(policy_delta_dir);
        let settings = state.settings.read().await;
        let _ = std::fs::remove_file(&settings.policy_path);
    }

    #[tokio::test]
    async fn agent_edr_response_action_dry_run_requires_graph_target_and_receipts() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[61u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state = test_state();
        state.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state);
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/evidence-bundles/{bundle_id}",
                get(agent_edr_evidence_bundle),
            )
            .route("/api/v1/agent/edr/receipts", get(agent_edr_receipts))
            .route(
                "/api/v1/agent/edr/response-executions",
                get(agent_edr_response_executions),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/cancel",
                post(agent_edr_response_execution_cancel),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/acknowledge",
                post(agent_edr_response_execution_acknowledge),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}",
                get(agent_edr_response_execution),
            )
            .with_state(Arc::clone(&state));
        let identity_metadata = BTreeMap::from([
            ("agentId".to_string(), serde_json::json!("agent-response-1")),
            (
                "workloadIdentity".to_string(),
                serde_json::json!("workload-response-1"),
            ),
            (
                "approvalId".to_string(),
                serde_json::json!("approval-response-1"),
            ),
        ]);
        let observations = vec![
            EndpointObservation {
                observation_id: "response-tool-1".to_string(),
                host_id: Some("host-response-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("session-response-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-response-1".to_string()),
                    image: Some("/usr/bin/python3".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::ToolCall {
                    tool_name: "mcp.shell".to_string(),
                    parameters: serde_json::json!({
                        "command": "python upload.py"
                    }),
                },
                metadata: identity_metadata.clone(),
                ..EndpointObservation::default()
            },
            EndpointObservation {
                observation_id: "response-network-1".to_string(),
                host_id: Some("host-response-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("session-response-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-response-1".to_string()),
                    image: Some("/usr/bin/python3".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::NetworkFlow {
                    host: "egress.example.invalid".to_string(),
                    port: 443,
                    protocol: Some("tcp".to_string()),
                    url: Some("https://egress.example.invalid/upload".to_string()),
                },
                metadata: identity_metadata,
                ..EndpointObservation::default()
            },
        ];
        let body = serde_json::json!({
            "observations": observations,
            "honey_artifacts": []
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/findings")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build edr findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("edr findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "action": "restrict_egress",
            "process": {
                "processGuid": "proc-response-1"
            },
            "ttlSeconds": 600,
            "reason": "contain process tree for 10 minutes",
            "dryRun": true
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build response action request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("response action request failed: {e}"));
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read response action response: {e}"));
        assert_eq!(
            status,
            StatusCode::OK,
            "unexpected response action response body: {}",
            String::from_utf8_lossy(&bytes)
        );
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode response action response: {e}"));

        assert_eq!(payload["plan"]["dryRun"], true);
        assert_eq!(payload["plan"]["ttlSeconds"], 600);
        assert_eq!(payload["plan"]["action"], "restrict_egress");
        assert!(payload["graph"]["nodes"]
            .as_object()
            .unwrap_or_else(|| panic!("missing response graph nodes"))
            .values()
            .any(|node| node["label"] == "egress.example.invalid:443"));
        assert_eq!(payload["affectedIdentityCount"].as_u64(), Some(6));
        assert_eq!(payload["affectedToolCount"].as_u64(), Some(1));
        assert_eq!(
            payload["affectedIdentities"]["hosts"][0]["id"],
            "host-response-1"
        );
        assert_eq!(payload["affectedIdentities"]["users"][0]["id"], "alice");
        assert_eq!(
            payload["affectedIdentities"]["sessions"][0]["id"],
            "session-response-1"
        );
        assert_eq!(
            payload["affectedIdentities"]["agents"][0]["id"],
            "agent-response-1"
        );
        assert_eq!(
            payload["affectedIdentities"]["workloads"][0]["id"],
            "workload-response-1"
        );
        assert_eq!(
            payload["affectedIdentities"]["approvals"][0]["id"],
            "approval-response-1"
        );
        assert_eq!(payload["affectedTools"][0]["toolName"], "mcp.shell");

        let signed: SignedReceipt = serde_json::from_value(payload["receipt"].clone())
            .unwrap_or_else(|e| panic!("failed to decode response receipt: {e}"));
        let endpoint_decision = signed
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing endpointDecision response metadata"));
        let public_key = endpoint_decision
            .get("signer")
            .and_then(|signer| signer.get("signerPublicKey"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("missing response receipt signer public key"));
        let public_key = hush_core::PublicKey::from_hex(public_key)
            .unwrap_or_else(|e| panic!("failed to parse response receipt public key: {e}"));
        let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(public_key));
        assert!(verification.valid);
        assert_eq!(endpoint_decision["receiptFamily"], "response_request");
        assert_eq!(
            endpoint_decision["decision"]["rollbackRef"],
            payload["plan"]["rollbackRef"]
        );
        assert_eq!(endpoint_decision["actor"]["agentId"], "agent-api");
        assert_eq!(
            endpoint_decision["actor"]["workloadId"],
            "endpoint-response-engine"
        );
        assert_eq!(endpoint_decision["actor"]["posture"], "unknown");

        let failing_observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-response-failure-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::FileAccess {
                operation: FileOperation::Write,
                path: "/tmp/clawdstrike-response-failure.txt".to_string(),
                source_url: None,
                content_preview: None,
            },
            ..EndpointObservation::default()
        };
        let body = serde_json::json!({
            "observations": [failing_observation],
            "honey_artifacts": []
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/findings")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build failing findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("failing findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "action": "restrict_egress",
            "process": {
                "processGuid": "proc-response-failure-1"
            },
            "ttlSeconds": 600,
            "reason": "attempt egress response on graph without network targets",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build failed response action request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("failed response action request failed: {e}"));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read failed response action error: {e}"));
        let error = String::from_utf8(bytes.to_vec())
            .unwrap_or_else(|e| panic!("failed response action error is not utf8: {e}"));
        assert!(error.contains("invalid egress restriction target"));
        assert!(error.contains("failed response execution recorded as"));

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/edr/response-executions?limit=10")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build failed execution list request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("failed execution list request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read failed execution list: {e}"));
        let executions_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode failed execution list: {e}"));
        assert_eq!(executions_payload["execution_count"], 1);
        assert_eq!(
            executions_payload["executions"][0]["execution"]["status"],
            "failed"
        );
        assert_eq!(
            executions_payload["executions"][0]["execution"]["actor"]["userId"],
            "operator:test"
        );

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/edr/receipts?family=response_execution&limit=10")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build failed receipt request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("failed receipt request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read failed receipt response: {e}"));
        let receipts_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode failed receipt response: {e}"));
        assert_eq!(receipts_payload["receipt_count"], 1);
        let failed_decision =
            &receipts_payload["receipts"][0]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(failed_decision["receiptFamily"], "response_execution");
        assert_eq!(
            failed_decision["decision"]["action"],
            serde_json::Value::String("restrict_egress".to_string())
        );
        assert_eq!(
            failed_decision["decision"]["title"],
            "Endpoint response action failed"
        );
        assert_eq!(
            failed_decision["decision"]["passed"],
            serde_json::Value::Bool(false)
        );
        let failed_hash = sha256(b"failed").to_hex_prefixed();
        assert!(failed_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing failed receipt evidence"))
            .iter()
            .any(|item| item["key"] == "executionStatus"
                && item["valueHash"].as_str() == Some(failed_hash.as_str())));
        let failed_execution_id = executions_payload["executions"][0]["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing failed execution id"));

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/receipts?family=response_execution&status=failed&executionId={failed_execution_id}&actorUserId=operator:test&limit=10"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build failed receipt search request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("failed receipt search request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read failed receipt search response: {e}"));
        let filtered_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode failed receipt search response: {e}"));
        assert_eq!(filtered_payload["receipt_count"], 1);
        let receipt_index_path = endpoint_receipt_index_path(&receipt_path);
        assert!(receipt_index_path.is_file());
        let receipt_index = read_endpoint_receipt_index(&receipt_index_path)
            .unwrap_or_else(|e| panic!("failed to read receipt index: {e}"));
        assert!(receipt_index.iter().any(|record| {
            record.family.as_deref() == Some("response_execution")
                && record.action.as_deref() == Some("restrict_egress")
                && record.execution_id.as_deref() == Some(failed_execution_id)
                && record.execution_status.as_deref() == Some("failed")
                && record.actor_user_id.as_deref() == Some("operator:test")
                && record.byte_len > 0
        }));
        std::fs::remove_file(&receipt_index_path)
            .unwrap_or_else(|e| panic!("failed to remove receipt index: {e}"));
        assert!(!receipt_index_path.exists());

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/receipts?family=response_execution&status=failed&executionId={failed_execution_id}&actorUserId=operator:test&limit=10"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build rebuilt receipt search request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("rebuilt receipt search request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read rebuilt receipt search response: {e}"));
        let rebuilt_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode rebuilt receipt search response: {e}"));
        assert_eq!(rebuilt_payload["receipt_count"], 1);
        assert!(receipt_index_path.is_file());
        std::fs::write(&receipt_index_path, b"")
            .unwrap_or_else(|e| panic!("failed to write empty receipt index: {e}"));

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/receipts?family=response_execution&status=failed&executionId={failed_execution_id}&actorUserId=operator:test&limit=10"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build empty-index receipt search request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("empty-index receipt search request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read empty-index receipt search response: {e}"));
        let empty_index_payload: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                panic!("failed to decode empty-index receipt search response: {e}")
            });
        assert_eq!(empty_index_payload["receipt_count"], 1);

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(
                "/api/v1/agent/edr/receipts?family=response_execution&status=succeeded&actorUserId=operator:test&limit=10",
            )
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build mismatched receipt search request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("mismatched receipt search request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read mismatched receipt search response: {e}"));
        let filtered_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode mismatched receipt search response: {e}"));
        assert_eq!(filtered_payload["receipt_count"], 0);

        let body = serde_json::json!({
            "action": "restrict_egress",
            "process": {
                "processGuid": "proc-response-1"
            },
            "ttlSeconds": 600,
            "reason": "attempt live response without actor identity",
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build actorless response action request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("actorless response action request failed: {e}"));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read actorless response action error: {e}"));
        let error = String::from_utf8(bytes.to_vec())
            .unwrap_or_else(|e| panic!("actorless response action error is not utf8: {e}"));
        assert!(error.contains("live response execution requires actor identity"));
        let _ = std::fs::remove_file(receipt_path);
    }

    #[tokio::test]
    async fn agent_edr_response_action_rejects_out_of_range_ttl() {
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .with_state(Arc::new(test_state()));

        for ttl_seconds in [0, EDR_MAX_RESPONSE_TTL_SECONDS + 1] {
            let body = serde_json::json!({
                "action": "collect_evidence",
                "rootNodeId": "process:ttl-validation",
                "ttlSeconds": ttl_seconds
            });
            let req = axum::http::Request::builder()
                .method("POST")
                .uri("/api/v1/agent/edr/response-action")
                .header(AUTHORIZATION, "Bearer test-token")
                .header(CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap_or_else(|e| panic!("failed to build ttl validation request: {e}"));
            let response = app
                .clone()
                .oneshot(req)
                .await
                .unwrap_or_else(|e| panic!("ttl validation request failed: {e}"));
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap_or_else(|e| panic!("failed to read ttl validation error: {e}"));
            let error = String::from_utf8(bytes.to_vec())
                .unwrap_or_else(|e| panic!("ttl validation error is not utf8: {e}"));
            assert!(error.contains("ttlSeconds must be between 1 and 3600 seconds"));
        }
    }

    #[tokio::test]
    async fn agent_edr_response_action_rejects_oversized_reason() {
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .with_state(Arc::new(test_state()));
        let oversized_reason = "x".repeat(EDR_MAX_RESPONSE_REASON_BYTES + 1);
        let body = serde_json::json!({
            "action": "collect_evidence",
            "rootNodeId": "process:reason-validation",
            "reason": oversized_reason
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build oversized reason request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("oversized reason request failed: {e}"));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read oversized reason error: {e}"));
        let error = String::from_utf8(bytes.to_vec())
            .unwrap_or_else(|e| panic!("oversized reason error is not utf8: {e}"));
        assert!(error.contains("response action reason must be at most 1024 bytes"));
    }

    #[tokio::test]
    async fn agent_edr_response_action_rejects_oversized_actor_identity() {
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .with_state(Arc::new(test_state()));
        let body = serde_json::json!({
            "action": "collect_evidence",
            "rootNodeId": "process:actor-validation",
            "actor": {
                "userId": "x".repeat(EDR_MAX_RESPONSE_ACTOR_FIELD_BYTES + 1)
            }
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build oversized actor request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("oversized actor request failed: {e}"));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read oversized actor error: {e}"));
        let error = String::from_utf8(bytes.to_vec())
            .unwrap_or_else(|e| panic!("oversized actor error is not utf8: {e}"));
        assert!(error.contains("actor.userId must be at most 256 bytes"));
    }

    #[tokio::test]
    async fn agent_edr_response_control_requests_reject_unknown_fields() {
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/cancel",
                post(agent_edr_response_execution_cancel),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/acknowledge",
                post(agent_edr_response_execution_acknowledge),
            )
            .with_state(Arc::new(test_state()));

        for (uri, body, field) in [
            (
                "/api/v1/agent/edr/response-action",
                serde_json::json!({
                    "action": "collect_evidence",
                    "rootNodeId": "process:missing",
                    "unexpectedField": true
                }),
                "unexpectedField",
            ),
            (
                "/api/v1/agent/edr/response-action",
                serde_json::json!({
                    "action": "collect_evidence",
                    "rootNodeId": "process:missing",
                    "actor": {
                        "unexpectedActorField": true
                    }
                }),
                "unexpectedActorField",
            ),
            (
                "/api/v1/agent/edr/response-action",
                serde_json::json!({
                    "action": "collect_evidence",
                    "process": {
                        "processGUID": "proc-misspelled-selector"
                    }
                }),
                "processGUID",
            ),
            (
                "/api/v1/agent/edr/response-executions/missing/cancel",
                serde_json::json!({
                    "reason": "cancel stale execution",
                    "unexpectedField": true
                }),
                "unexpectedField",
            ),
            (
                "/api/v1/agent/edr/response-executions/missing/rollback",
                serde_json::json!({
                    "reason": "rollback stale execution",
                    "unexpectedField": true
                }),
                "unexpectedField",
            ),
            (
                "/api/v1/agent/edr/response-executions/missing/acknowledge",
                serde_json::json!({
                    "acknowledgedBy": "operator:test",
                    "unexpectedField": true
                }),
                "unexpectedField",
            ),
            (
                "/api/v1/agent/edr/response-executions/missing/acknowledge",
                serde_json::json!({
                    "acknowledgedBy": "operator:test",
                    "controlApi": {
                        "unexpectedNestedField": true
                    }
                }),
                "unexpectedNestedField",
            ),
        ] {
            let req = axum::http::Request::builder()
                .method("POST")
                .uri(uri)
                .header(AUTHORIZATION, "Bearer test-token")
                .header(CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap_or_else(|e| {
                    panic!("failed to build unknown-field response control request: {e}")
                });
            let response =
                app.clone().oneshot(req).await.unwrap_or_else(|e| {
                    panic!("unknown-field response control request failed: {e}")
                });
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap_or_else(|e| {
                    panic!("failed to read unknown-field response control error: {e}")
                });
            let error = String::from_utf8(bytes.to_vec()).unwrap_or_else(|e| {
                panic!("unknown-field response control error is not utf8: {e}")
            });
            assert_eq!(
                status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "unexpected status for {uri}: {error}"
            );
            assert!(
                error.contains("unknown field") && error.contains(field),
                "unexpected unknown-field error for {uri}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn agent_edr_response_action_restrict_egress_fails_closed_when_provider_unready() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[62u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state = test_state();
        state.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state);
        state
            .macos_host
            .replace_status(CombinedSystemExtensionStatus {
                install_state: SystemExtensionInstallState::Installed,
                approval: SystemExtensionApproval::Approved,
                endpoint_security: ProviderStatus {
                    runtime: ProviderRuntimeState::Active,
                    ..ProviderStatus::unknown()
                },
                network_extension: ProviderStatus {
                    runtime: ProviderRuntimeState::Active,
                    policy_synced: Some(false),
                    enforcement_ready: Some(false),
                    last_error: Some(
                        "provider policy update pending: ghs_1234567890abcdef1234".to_string(),
                    ),
                    ..ProviderStatus::unknown()
                },
                ..CombinedSystemExtensionStatus::default()
            })
            .await;
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route("/api/v1/agent/edr/receipts", get(agent_edr_receipts))
            .route(
                "/api/v1/agent/edr/response-executions",
                get(agent_edr_response_executions),
            )
            .with_state(state.clone());

        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-restrict-egress-unready-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::NetworkFlow {
                host: "unready-egress.example.invalid".to_string(),
                port: 443,
                protocol: Some("tcp".to_string()),
                url: Some("https://unready-egress.example.invalid/upload".to_string()),
            },
            ..EndpointObservation::default()
        };
        let body = serde_json::json!({
            "observations": [observation],
            "honey_artifacts": []
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/findings")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build unready findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("unready findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "action": "restrict_egress",
            "process": {
                "processGuid": "proc-restrict-egress-unready-1"
            },
            "ttlSeconds": 600,
            "reason": "contain observed egress while provider is unready",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build unready response request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("unready response request failed: {e}"));
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read unready response error: {e}"));
        let error = String::from_utf8(bytes.to_vec())
            .unwrap_or_else(|e| panic!("unready response error is not utf8: {e}"));
        assert!(error.contains("network extension provider is not ready for restrict_egress"));
        assert!(error.contains("policy_not_synced"));
        assert!(error.contains("enforcement_not_ready"));
        assert!(error.contains("provider_last_error:provider policy update pending"));
        assert!(error.contains("[REDACTED]"));
        assert!(!error.contains("ghs_1234567890abcdef1234"));
        assert!(error.contains("failed response execution recorded as"));
        assert!(!state.edr_network_extension_egress_policy_path.exists());

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/edr/response-executions?limit=10")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build unready execution list request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("unready execution list request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read unready execution list: {e}"));
        let executions_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode unready execution list: {e}"));
        assert_eq!(executions_payload["execution_count"], 1);
        let execution = &executions_payload["executions"][0]["execution"];
        assert_eq!(execution["action"], "restrict_egress");
        assert_eq!(execution["status"], "failed");
        assert_eq!(execution["actor"]["userId"], "operator:test");
        assert!(execution["reason"]
            .as_str()
            .unwrap_or_else(|| panic!("missing unready execution reason"))
            .contains("policy_not_synced"));
        assert!(execution["reason"]
            .as_str()
            .unwrap_or_else(|| panic!("missing unready execution reason"))
            .contains("[REDACTED]"));
        assert!(!execution["reason"]
            .as_str()
            .unwrap_or_else(|| panic!("missing unready execution reason"))
            .contains("ghs_1234567890abcdef1234"));
        assert!(execution["summary"]
            .as_str()
            .unwrap_or_else(|| panic!("missing unready execution summary"))
            .contains("network extension provider is not ready for restrict_egress"));
        assert!(execution["summary"]
            .as_str()
            .unwrap_or_else(|| panic!("missing unready execution summary"))
            .contains("[REDACTED]"));
        assert!(!execution["summary"]
            .as_str()
            .unwrap_or_else(|| panic!("missing unready execution summary"))
            .contains("ghs_1234567890abcdef1234"));

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/edr/receipts?family=response_execution&limit=10")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build unready receipt list request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("unready receipt list request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read unready receipt list: {e}"));
        let receipts_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode unready receipt list: {e}"));
        assert_eq!(receipts_payload["receipt_count"], 1);
        let failed_decision =
            &receipts_payload["receipts"][0]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(failed_decision["receiptFamily"], "response_execution");
        assert_eq!(failed_decision["decision"]["action"], "restrict_egress");
        assert_eq!(failed_decision["decision"]["passed"], false);
        let failed_hash = sha256(b"failed").to_hex_prefixed();
        assert!(failed_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing unready failed receipt evidence"))
            .iter()
            .any(|item| item["key"] == "executionStatus"
                && item["valueHash"].as_str() == Some(failed_hash.as_str())));

        let _ = std::fs::remove_file(receipt_path);
    }

