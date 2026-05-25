    #[tokio::test]
    async fn agent_edr_findings_redacts_proxy_authorization_header_without_scheme_before_recording()
    {
        let flight_recorder_path = test_flight_recorder_path();
        let _ = std::fs::remove_file(&flight_recorder_path);
        let mut state = test_state();
        state.edr_flight_recorder = Arc::new(Mutex::new(
            EndpointFlightRecorder::open(&flight_recorder_path)
                .unwrap_or_else(|e| panic!("failed to open test flight recorder: {e}")),
        ));
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .with_state(Arc::new(state));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-proxy-auth-no-scheme-redaction-1".to_string()),
                image: Some("/usr/bin/curl".to_string()),
                command_line: Some(
                    "curl -H Proxy-Authorization: MY_RAW_SECRET https://api.example.invalid"
                        .to_string(),
                ),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::ProcessExec {
                image: "/usr/bin/curl".to_string(),
                args: vec![
                    "-H".to_string(),
                    "Proxy-Authorization:".to_string(),
                    "MY_RAW_SECRET".to_string(),
                    "https://api.example.invalid".to_string(),
                ],
                env: BTreeMap::new(),
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
            .unwrap_or_else(|e| {
                panic!("failed to build proxy authorization no-scheme findings request: {e}")
            });

        let response = app.oneshot(req).await.unwrap_or_else(|e| {
            panic!("proxy authorization no-scheme findings request failed: {e}")
        });
        assert_eq!(response.status(), StatusCode::OK);
        let recorded = std::fs::read_to_string(&flight_recorder_path)
            .unwrap_or_else(|e| panic!("failed to read flight recorder: {e}"));
        assert!(!recorded.contains("MY_RAW_SECRET"));
        let stored = recorded
            .lines()
            .find(|line| !line.trim().is_empty())
            .and_then(|line| serde_json::from_str::<EndpointObservation>(line).ok())
            .unwrap_or_else(|| panic!("missing stored endpoint observation"));
        assert_eq!(
            stored.process.command_line.as_deref(),
            Some("curl -H Proxy-Authorization: [REDACTED] https://api.example.invalid")
        );
        let EndpointEvent::ProcessExec { args, .. } = stored.event else {
            panic!("stored observation should remain process_exec");
        };
        assert_eq!(args[2], "[REDACTED]");

        let _ = std::fs::remove_file(flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_findings_redacts_single_arg_authorization_header_before_recording() {
        let flight_recorder_path = test_flight_recorder_path();
        let _ = std::fs::remove_file(&flight_recorder_path);
        let mut state = test_state();
        state.edr_flight_recorder = Arc::new(Mutex::new(
            EndpointFlightRecorder::open(&flight_recorder_path)
                .unwrap_or_else(|e| panic!("failed to open test flight recorder: {e}")),
        ));
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .with_state(Arc::new(state));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-single-arg-auth-header-redaction-1".to_string()),
                image: Some("/usr/bin/curl".to_string()),
                command_line: Some(
                    "curl -H Authorization:Bearer MY_RAW_SECRET https://api.example.invalid"
                        .to_string(),
                ),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::ProcessExec {
                image: "/usr/bin/curl".to_string(),
                args: vec![
                    "-H".to_string(),
                    "Authorization: Bearer MY_RAW_SECRET".to_string(),
                    "https://api.example.invalid".to_string(),
                ],
                env: BTreeMap::new(),
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
            .unwrap_or_else(|e| {
                panic!("failed to build single-arg authorization findings request: {e}")
            });

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("single-arg authorization findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let recorded = std::fs::read_to_string(&flight_recorder_path)
            .unwrap_or_else(|e| panic!("failed to read flight recorder: {e}"));
        assert!(!recorded.contains("MY_RAW_SECRET"));
        let stored = recorded
            .lines()
            .find(|line| !line.trim().is_empty())
            .and_then(|line| serde_json::from_str::<EndpointObservation>(line).ok())
            .unwrap_or_else(|| panic!("missing stored endpoint observation"));
        assert_eq!(
            stored.process.command_line.as_deref(),
            Some("curl -H Authorization: Bearer [REDACTED] https://api.example.invalid")
        );
        let EndpointEvent::ProcessExec { args, .. } = stored.event else {
            panic!("stored observation should remain process_exec");
        };
        assert_eq!(args[1], "Authorization: Bearer [REDACTED]");

        let _ = std::fs::remove_file(flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_findings_redacts_authorization_assignment_scheme_before_recording() {
        let flight_recorder_path = test_flight_recorder_path();
        let _ = std::fs::remove_file(&flight_recorder_path);
        let mut state = test_state();
        state.edr_flight_recorder = Arc::new(Mutex::new(
            EndpointFlightRecorder::open(&flight_recorder_path)
                .unwrap_or_else(|e| panic!("failed to open test flight recorder: {e}")),
        ));
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .with_state(Arc::new(state));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-auth-assignment-scheme-redaction-1".to_string()),
                image: Some("/usr/bin/curl".to_string()),
                command_line: Some(
                    "curl -H Authorization=Bearer MY_RAW_SECRET https://api.example.invalid"
                        .to_string(),
                ),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::ProcessExec {
                image: "/usr/bin/curl".to_string(),
                args: vec![
                    "-H".to_string(),
                    "Authorization=Bearer".to_string(),
                    "MY_RAW_SECRET".to_string(),
                    "https://api.example.invalid".to_string(),
                ],
                env: BTreeMap::new(),
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
            .unwrap_or_else(|e| {
                panic!("failed to build authorization assignment findings request: {e}")
            });

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("authorization assignment findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let recorded = std::fs::read_to_string(&flight_recorder_path)
            .unwrap_or_else(|e| panic!("failed to read flight recorder: {e}"));
        assert!(!recorded.contains("MY_RAW_SECRET"));
        let stored = recorded
            .lines()
            .find(|line| !line.trim().is_empty())
            .and_then(|line| serde_json::from_str::<EndpointObservation>(line).ok())
            .unwrap_or_else(|| panic!("missing stored endpoint observation"));
        assert_eq!(
            stored.process.command_line.as_deref(),
            Some("curl -H Authorization=Bearer [REDACTED] https://api.example.invalid")
        );
        let EndpointEvent::ProcessExec { args, .. } = stored.event else {
            panic!("stored observation should remain process_exec");
        };
        assert_eq!(args[1], "Authorization=Bearer");
        assert_eq!(args[2], "[REDACTED]");

        let _ = std::fs::remove_file(flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_findings_redacts_policy_decision_target_before_recording() {
        let flight_recorder_path = test_flight_recorder_path();
        let _ = std::fs::remove_file(&flight_recorder_path);
        let mut state = test_state();
        state.edr_flight_recorder = Arc::new(Mutex::new(
            EndpointFlightRecorder::open(&flight_recorder_path)
                .unwrap_or_else(|e| panic!("failed to open test flight recorder: {e}")),
        ));
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .with_state(Arc::new(state));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-policy-target-redaction-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::PolicyDecision {
                action: "tool_call".to_string(),
                target: Some(
                    "curl -H Authorization: Bearer MY_RAW_SECRET https://api.example.invalid"
                        .to_string(),
                ),
                decision: "block".to_string(),
                guard: Some("test_guard".to_string()),
                severity: Some("critical".to_string()),
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
            .unwrap_or_else(|e| {
                panic!("failed to build policy-decision-target findings request: {e}")
            });

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("policy-decision-target findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let recorded = std::fs::read_to_string(&flight_recorder_path)
            .unwrap_or_else(|e| panic!("failed to read flight recorder: {e}"));
        assert!(!recorded.contains("MY_RAW_SECRET"));
        let stored = recorded
            .lines()
            .find(|line| !line.trim().is_empty())
            .and_then(|line| serde_json::from_str::<EndpointObservation>(line).ok())
            .unwrap_or_else(|| panic!("missing stored endpoint observation"));
        let EndpointEvent::PolicyDecision { target, .. } = stored.event else {
            panic!("stored observation should remain policy_decision");
        };
        assert_eq!(
            target.as_deref(),
            Some("curl -H Authorization: Bearer [REDACTED] https://api.example.invalid")
        );

        let _ = std::fs::remove_file(flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_policy_events_convert_to_observations_findings_and_receipts() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[48u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state = test_state();
        state.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-policy-event-signer".to_string(),
            signer_public_key,
        }));
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/policy-events",
                post(agent_edr_policy_events),
            )
            .route("/api/v1/agent/edr/receipts", get(agent_edr_receipts))
            .with_state(Arc::new(state));
        let body = serde_json::json!({
            "events": [
                {
                    "eventId": "policy-secret-1",
                    "eventType": "secret_access",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "sessionId": "policy-session-1",
                    "data": {
                        "type": "secret",
                        "secretName": "NPM_TOKEN",
                        "scope": "npm_registry"
                    },
                    "metadata": {
                        "apiToken": "MY_RAW_SECRET",
                        "headers": {
                            "authorization": "Bearer MY_RAW_SECRET"
                        },
                        "process": {
                            "pid": 91,
                            "image": "/usr/local/bin/node",
                            "commandLine": "node install.js --token=MY_RAW_SECRET",
                            "processGuid": "proc-policy-events-1"
                        }
                    },
                    "context": {
                        "endpoint_id": "endpoint-policy-test",
                        "identity": {
                            "id": "alice"
                        },
                        "metadata": {
                            "runtimeAgentId": "agent-policy-route",
                            "approvalRequestId": "approval-policy-route",
                            "policyEpoch": 42
                        }
                    }
                },
                {
                    "eventId": "policy-cloud-1",
                    "eventType": "command_exec",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "sessionId": "policy-session-1",
                    "data": {
                        "type": "command",
                        "command": "/opt/homebrew/bin/aws",
                        "args": ["secretsmanager", "get-secret-value", "--secret-id", "prod/db", "--token", "MY_RAW_SECRET"]
                    },
                    "metadata": {
                        "hostId": "endpoint-policy-test",
                        "userId": "alice",
                        "apiToken": "MY_RAW_SECRET",
                        "process": {
                            "pid": 92,
                            "image": "/opt/homebrew/bin/aws",
                            "commandLine": "aws secretsmanager get-secret-value --secret-id prod/db --token=MY_RAW_SECRET",
                            "processGuid": "proc-policy-events-2"
                        }
                    }
                }
            ]
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/policy-events")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build policy-events EDR request: {e}"));

        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("policy-events EDR request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read policy-events EDR response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode policy-events EDR response: {e}"));

        assert_eq!(payload["policy_event_count"], 2);
        assert_eq!(payload["observation_count"], 2);
        assert_eq!(payload["finding_count"], 2);
        assert_eq!(payload["receipt_count"], 4);
        assert_eq!(
            payload["observation_receipts"].as_array().map(Vec::len),
            Some(2)
        );
        assert_eq!(
            payload["observations"][0]["event"]["type"],
            "credential_access"
        );
        assert_eq!(payload["observations"][0]["hostId"], "endpoint-policy-test");
        assert_eq!(payload["observations"][0]["userId"], "alice");
        assert_eq!(
            payload["observations"][0]["metadata"]["agentId"],
            "agent-policy-route"
        );
        assert_eq!(
            payload["observations"][0]["metadata"]["approvalId"],
            "approval-policy-route"
        );
        assert_eq!(payload["observations"][0]["metadata"]["policyEpoch"], 42);
        assert_eq!(
            payload["observations"][0]["metadata"]["apiToken"],
            "[REDACTED]"
        );
        assert_eq!(
            payload["observations"][0]["metadata"]["headers"]["authorization"],
            "[REDACTED]"
        );
        assert_eq!(
            payload["observations"][0]["process"]["commandLine"],
            "node install.js --token=[REDACTED]"
        );
        assert_eq!(payload["observations"][1]["event"]["args"][4], "--token");
        assert_eq!(payload["observations"][1]["event"]["args"][5], "[REDACTED]");
        assert_eq!(
            payload["observations"][1]["process"]["commandLine"],
            "aws secretsmanager get-secret-value --secret-id prod/db --token=[REDACTED]"
        );
        assert_eq!(
            payload["observations"][1]["metadata"]["apiToken"],
            "[REDACTED]"
        );
        assert!(!payload.to_string().contains("MY_RAW_SECRET"));
        let rule_ids = payload["findings"]
            .as_array()
            .unwrap_or_else(|| panic!("missing policy-event findings"))
            .iter()
            .filter_map(|finding| finding["ruleId"].as_str())
            .collect::<Vec<_>>();
        assert!(rule_ids.contains(&"supply_chain.developer_secret_access"));
        assert!(rule_ids.contains(&"supply_chain.cloud_cli_sensitive_operation"));

        let cloud_finding_id = payload["findings"]
            .as_array()
            .unwrap_or_else(|| panic!("missing policy-event findings"))
            .iter()
            .find(|finding| finding["ruleId"] == "supply_chain.cloud_cli_sensitive_operation")
            .and_then(|finding| finding["findingId"].as_str())
            .unwrap_or_else(|| panic!("missing cloud CLI policy-event finding id"));
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/receipts?family=detection&ruleId=supply_chain.cloud_cli_sensitive_operation&findingId={cloud_finding_id}&limit=10"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build policy-event receipt query: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("policy-event receipt query failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read policy-event receipt query response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("failed to decode policy-event receipt query response: {e}")
        });
        assert_eq!(payload["receipt_count"], 1);

        let _ = std::fs::remove_file(receipt_path);
    }

    #[tokio::test]
    async fn agent_edr_ingress_requests_reject_unknown_fields() {
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/policy-events",
                post(agent_edr_policy_events),
            )
            .route(
                "/api/v1/agent/edr/developer-activity",
                post(agent_edr_developer_activity),
            )
            .route(
                "/api/v1/agent/edr/package-manager/events",
                post(agent_edr_package_manager_events),
            )
            .route(
                "/api/v1/agent/edr/endpoint-security/events",
                post(agent_edr_endpoint_security_events),
            )
            .route(
                "/api/v1/agent/edr/network-extension/events",
                post(agent_edr_network_extension_events),
            )
            .with_state(Arc::new(test_state()));

        for (uri, body, field) in [
            (
                "/api/v1/agent/edr/findings",
                serde_json::json!({
                    "observations": [],
                    "shadowFindingEnvelope": true
                }),
                "shadowFindingEnvelope",
            ),
            (
                "/api/v1/agent/edr/policy-events",
                serde_json::json!({
                    "events": [],
                    "shadowPolicyEventEnvelope": true
                }),
                "shadowPolicyEventEnvelope",
            ),
            (
                "/api/v1/agent/edr/developer-activity",
                serde_json::json!({
                    "activities": [],
                    "shadowDeveloperEnvelope": true
                }),
                "shadowDeveloperEnvelope",
            ),
            (
                "/api/v1/agent/edr/developer-activity",
                serde_json::json!({
                    "activities": [
                        {
                            "kind": "mcp_tool",
                            "shadowActivityField": true
                        }
                    ]
                }),
                "shadowActivityField",
            ),
            (
                "/api/v1/agent/edr/package-manager/events",
                serde_json::json!({
                    "events": [
                        {
                            "manager": "npm",
                            "phase": "postinstall",
                            "script": "echo ok",
                            "shadowPackageField": true
                        }
                    ]
                }),
                "shadowPackageField",
            ),
            (
                "/api/v1/agent/edr/endpoint-security/events",
                serde_json::json!({
                    "events": [
                        {
                            "kind": "file_access",
                            "shadowEndpointSecurityField": true
                        }
                    ]
                }),
                "shadowEndpointSecurityField",
            ),
            (
                "/api/v1/agent/edr/network-extension/events",
                serde_json::json!({
                    "events": [
                        {
                            "port": 443,
                            "verdict": "allow",
                            "shadowNetworkExtensionField": true
                        }
                    ]
                }),
                "shadowNetworkExtensionField",
            ),
        ] {
            let req = axum::http::Request::builder()
                .method("POST")
                .uri(uri)
                .header(AUTHORIZATION, "Bearer test-token")
                .header(CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap_or_else(|e| {
                    panic!("failed to build unknown-field EDR ingress request: {e}")
                });
            let response = app
                .clone()
                .oneshot(req)
                .await
                .unwrap_or_else(|e| panic!("unknown-field EDR ingress request failed: {e}"));
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap_or_else(|e| panic!("failed to read unknown-field EDR ingress error: {e}"));
            let error = String::from_utf8(bytes.to_vec())
                .unwrap_or_else(|e| panic!("unknown-field EDR ingress error is not utf8: {e}"));
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

