    #[tokio::test]
    async fn agent_edr_response_action_disables_system_cron_dropin_with_rollback_and_proof() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[93u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-system-cron-dropin-persistence-signer".to_string(),
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
            "clawdstrike-cron-dropin-persistence-{}-{counter}/etc/cron.d",
            std::process::id()
        ));
        std::fs::create_dir_all(&cron_dir)
            .unwrap_or_else(|e| panic!("failed to create cron drop-in dir: {e}"));
        let source_path = cron_dir.join("evil-agent");
        std::fs::write(
            &source_path,
            b"*/2 * * * * alice /usr/bin/python3 /tmp/.cache/evil-agent.py\n",
        )
        .unwrap_or_else(|e| panic!("failed to write cron drop-in file: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-system-cron-dropin-1".to_string()),
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
            .unwrap_or_else(|e| panic!("failed to build cron drop-in findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("cron drop-in findings request failed: {e}"));
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
                .unwrap_or_else(|| panic!("missing cron drop-in file graph node"))
        };
        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": file_node_id,
            "ttlSeconds": 600,
            "reason": "disable suspicious system cron drop-in",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build cron drop-in response request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("cron drop-in response request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read cron drop-in response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode cron drop-in response: {e}"));

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
                .unwrap_or_else(|| panic!("missing cron drop-in artifact path")),
        );
        assert!(disabled_path.is_file());
        assert_eq!(
            std::fs::read(&disabled_path)
                .unwrap_or_else(|e| panic!("failed to read cron drop-in artifact: {e}")),
            b"*/2 * * * * alice /usr/bin/python3 /tmp/.cache/evil-agent.py\n"
        );

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing cron drop-in execution id"));
        let body = serde_json::json!({
            "reason": "restore system cron drop-in"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build cron drop-in rollback request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("cron drop-in rollback request failed: {e}"));
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
            .unwrap_or_else(|e| panic!("failed to build cron drop-in proof request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("cron drop-in proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read cron drop-in proof response: {e}"));
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected cron drop-in proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let proof_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode cron drop-in proof response: {e}"));
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
            .unwrap_or_else(|| panic!("missing cron drop-in proof transition receipts"));
        assert_eq!(transition_receipts.len(), 1);
        assert_eq!(
            transition_receipts[0]["receipt"]["metadata"]["endpointDecision"]["decision"]["title"],
            "Endpoint response action rolled back"
        );
        let rollback_receipts = proof_payload["rollbackReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing cron drop-in proof rollback receipts"));
        assert_eq!(rollback_receipts.len(), 1);
        assert_eq!(
            rollback_receipts[0]["receipt"]["metadata"]["endpointDecision"]["receiptFamily"],
            "response_rollback"
        );
        assert!(proof_payload["acknowledgementReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing cron drop-in proof acknowledgement receipts"))
            .is_empty());

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(cron_dir);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[tokio::test]
    async fn agent_edr_response_action_disables_systemd_user_service_with_rollback_and_proof() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[94u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-systemd-user-service-signer".to_string(),
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
        let systemd_user_dir = std::env::temp_dir().join(format!(
            "clawdstrike-systemd-user-persistence-{}-{counter}/home/alice/.config/systemd/user",
            std::process::id()
        ));
        std::fs::create_dir_all(&systemd_user_dir)
            .unwrap_or_else(|e| panic!("failed to create systemd user persistence dir: {e}"));
        let source_path = systemd_user_dir.join("evil-agent.service");
        std::fs::write(
            &source_path,
            b"[Service]\nExecStart=/tmp/.cache/evil-agent\n[Install]\nWantedBy=default.target\n",
        )
        .unwrap_or_else(|e| panic!("failed to write systemd user service: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-systemd-user-persistence-1".to_string()),
                image: Some("/usr/bin/systemctl".to_string()),
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
                panic!("failed to build systemd persistence findings request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("systemd persistence findings request failed: {e}"));
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
                .unwrap_or_else(|| panic!("missing systemd user service file graph node"))
        };
        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": file_node_id,
            "ttlSeconds": 600,
            "reason": "disable suspicious systemd user service",
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
                panic!("failed to build systemd persistence response request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("systemd persistence response request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read systemd persistence response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode systemd persistence response: {e}"));

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
                .unwrap_or_else(|| panic!("missing systemd persistence artifact path")),
        );
        assert!(disabled_path.is_file());
        assert_eq!(
            std::fs::read(&disabled_path)
                .unwrap_or_else(|e| panic!("failed to read systemd persistence artifact: {e}")),
            b"[Service]\nExecStart=/tmp/.cache/evil-agent\n[Install]\nWantedBy=default.target\n"
        );

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing systemd persistence execution id"));
        let body = serde_json::json!({
            "reason": "restore systemd user service"
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
                panic!("failed to build systemd persistence rollback request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("systemd persistence rollback request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        assert!(source_path.is_file());
        assert!(!disabled_path.exists());
        assert_response_rollback_proof(
            app,
            execution_id,
            &payload,
            &source_path,
            "systemd user service",
        )
        .await;

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(systemd_user_dir);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[tokio::test]
    async fn agent_edr_response_action_disables_systemd_system_service_with_rollback_and_proof() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[95u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-systemd-system-service-signer".to_string(),
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
        let systemd_system_dir = std::env::temp_dir().join(format!(
            "clawdstrike-systemd-system-persistence-{}-{counter}/etc/systemd/system",
            std::process::id()
        ));
        std::fs::create_dir_all(&systemd_system_dir)
            .unwrap_or_else(|e| panic!("failed to create systemd system persistence dir: {e}"));
        let source_path = systemd_system_dir.join("evil-agent.service");
        std::fs::write(
            &source_path,
            b"[Service]\nExecStart=/tmp/.cache/evil-agent\n[Install]\nWantedBy=multi-user.target\n",
        )
        .unwrap_or_else(|e| panic!("failed to write systemd system service: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-systemd-system-persistence-1".to_string()),
                image: Some("/usr/bin/systemctl".to_string()),
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
                panic!("failed to build systemd system persistence findings request: {e}")
            });
        let response =
            app.clone().oneshot(req).await.unwrap_or_else(|e| {
                panic!("systemd system persistence findings request failed: {e}")
            });
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
                .unwrap_or_else(|| panic!("missing systemd system service file graph node"))
        };
        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": file_node_id,
            "ttlSeconds": 600,
            "reason": "disable suspicious systemd system service",
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
                panic!("failed to build systemd system persistence response request: {e}")
            });
        let response =
            app.clone().oneshot(req).await.unwrap_or_else(|e| {
                panic!("systemd system persistence response request failed: {e}")
            });
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read systemd system persistence response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("failed to decode systemd system persistence response: {e}")
        });

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
                .unwrap_or_else(|| panic!("missing systemd system persistence artifact path")),
        );
        assert!(disabled_path.is_file());
        assert_eq!(
            std::fs::read(&disabled_path)
                .unwrap_or_else(|e| panic!("failed to read systemd system artifact: {e}")),
            b"[Service]\nExecStart=/tmp/.cache/evil-agent\n[Install]\nWantedBy=multi-user.target\n"
        );

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing systemd system persistence execution id"));
        let body = serde_json::json!({
            "reason": "restore systemd system service"
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
                panic!("failed to build systemd system persistence rollback request: {e}")
            });
        let response =
            app.clone().oneshot(req).await.unwrap_or_else(|e| {
                panic!("systemd system persistence rollback request failed: {e}")
            });
        assert_eq!(response.status(), StatusCode::OK);
        assert!(source_path.is_file());
        assert!(!disabled_path.exists());
        assert_response_rollback_proof(
            app,
            execution_id,
            &payload,
            &source_path,
            "systemd system service",
        )
        .await;

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(systemd_system_dir);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[tokio::test]
    async fn agent_edr_response_action_disables_systemd_system_dropin_with_rollback_and_proof() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[96u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-systemd-system-dropin-signer".to_string(),
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
        let systemd_dropin_dir = std::env::temp_dir().join(format!(
            "clawdstrike-systemd-dropin-persistence-{}-{counter}/etc/systemd/system/evil-agent.service.d",
            std::process::id()
        ));
        std::fs::create_dir_all(&systemd_dropin_dir)
            .unwrap_or_else(|e| panic!("failed to create systemd drop-in dir: {e}"));
        let source_path = systemd_dropin_dir.join("override.conf");
        std::fs::write(
            &source_path,
            b"[Service]\nEnvironment=LD_PRELOAD=/tmp/.cache/libevil.so\n",
        )
        .unwrap_or_else(|e| panic!("failed to write systemd drop-in: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-systemd-system-dropin-1".to_string()),
                image: Some("/usr/bin/systemctl".to_string()),
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
                panic!("failed to build systemd drop-in persistence findings request: {e}")
            });
        let response =
            app.clone().oneshot(req).await.unwrap_or_else(|e| {
                panic!("systemd drop-in persistence findings request failed: {e}")
            });
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
                .unwrap_or_else(|| panic!("missing systemd drop-in file graph node"))
        };
        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": file_node_id,
            "ttlSeconds": 600,
            "reason": "disable suspicious systemd drop-in",
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
                panic!("failed to build systemd drop-in persistence response request: {e}")
            });
        let response =
            app.clone().oneshot(req).await.unwrap_or_else(|e| {
                panic!("systemd drop-in persistence response request failed: {e}")
            });
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read systemd drop-in persistence response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("failed to decode systemd drop-in persistence response: {e}")
        });

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
                .unwrap_or_else(|| panic!("missing systemd drop-in persistence artifact path")),
        );
        assert!(disabled_path.is_file());
        assert_eq!(
            std::fs::read(&disabled_path)
                .unwrap_or_else(|e| panic!("failed to read systemd drop-in artifact: {e}")),
            b"[Service]\nEnvironment=LD_PRELOAD=/tmp/.cache/libevil.so\n"
        );

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing systemd drop-in persistence execution id"));
        let body = serde_json::json!({
            "reason": "restore systemd drop-in"
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
                panic!("failed to build systemd drop-in persistence rollback request: {e}")
            });
        let response =
            app.clone().oneshot(req).await.unwrap_or_else(|e| {
                panic!("systemd drop-in persistence rollback request failed: {e}")
            });
        assert_eq!(response.status(), StatusCode::OK);
        assert!(source_path.is_file());
        assert!(!disabled_path.exists());
        assert_response_rollback_proof(
            app,
            execution_id,
            &payload,
            &source_path,
            "systemd system drop-in",
        )
        .await;

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(systemd_dropin_dir);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[tokio::test]
    async fn agent_edr_response_action_disables_xdg_autostart_with_rollback_and_proof() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[97u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-xdg-autostart-signer".to_string(),
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
        let autostart_dir = std::env::temp_dir().join(format!(
            "clawdstrike-xdg-autostart-persistence-{}-{counter}/home/alice/.config/autostart",
            std::process::id()
        ));
        std::fs::create_dir_all(&autostart_dir)
            .unwrap_or_else(|e| panic!("failed to create XDG autostart dir: {e}"));
        let source_path = autostart_dir.join("evil-agent.desktop");
        std::fs::write(
            &source_path,
            b"[Desktop Entry]\nType=Application\nName=Updater\nExec=/tmp/.cache/evil-agent\n",
        )
        .unwrap_or_else(|e| panic!("failed to write XDG autostart file: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-xdg-autostart-1".to_string()),
                image: Some("/usr/bin/xdg-desktop-menu".to_string()),
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
            .unwrap_or_else(|e| panic!("failed to build XDG autostart findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("XDG autostart findings request failed: {e}"));
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
                .unwrap_or_else(|| panic!("missing XDG autostart file graph node"))
        };
        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": file_node_id,
            "ttlSeconds": 600,
            "reason": "disable suspicious XDG autostart entry",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build XDG autostart response request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("XDG autostart response request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read XDG autostart response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode XDG autostart response: {e}"));

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
                .unwrap_or_else(|| panic!("missing XDG autostart artifact path")),
        );
        assert!(disabled_path.is_file());
        assert_eq!(
            std::fs::read(&disabled_path)
                .unwrap_or_else(|e| panic!("failed to read XDG autostart artifact: {e}")),
            b"[Desktop Entry]\nType=Application\nName=Updater\nExec=/tmp/.cache/evil-agent\n"
        );

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing XDG autostart execution id"));
        let body = serde_json::json!({
            "reason": "restore XDG autostart entry"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build XDG autostart rollback request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("XDG autostart rollback request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        assert!(source_path.is_file());
        assert!(!disabled_path.exists());
        assert_response_rollback_proof(app, execution_id, &payload, &source_path, "XDG autostart")
            .await;

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(autostart_dir);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[tokio::test]
    async fn agent_edr_response_action_disables_plasma_env_script_with_rollback_and_proof() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[98u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-plasma-env-script-signer".to_string(),
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
        let plasma_env_dir = std::env::temp_dir().join(format!(
            "clawdstrike-plasma-env-persistence-{}-{counter}/home/alice/.config/plasma-workspace/env",
            std::process::id()
        ));
        std::fs::create_dir_all(&plasma_env_dir)
            .unwrap_or_else(|e| panic!("failed to create Plasma env dir: {e}"));
        let source_path = plasma_env_dir.join("evil-agent.sh");
        std::fs::write(
            &source_path,
            b"#!/bin/sh\nexport LD_PRELOAD=/tmp/.cache/libevil.so\n",
        )
        .unwrap_or_else(|e| panic!("failed to write Plasma env script: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-plasma-env-1".to_string()),
                image: Some("/usr/bin/kwriteconfig5".to_string()),
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
            .unwrap_or_else(|e| panic!("failed to build Plasma env findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("Plasma env findings request failed: {e}"));
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
                .unwrap_or_else(|| panic!("missing Plasma env file graph node"))
        };
        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": file_node_id,
            "ttlSeconds": 600,
            "reason": "disable suspicious Plasma env script",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build Plasma env response request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("Plasma env response request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read Plasma env response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode Plasma env response: {e}"));

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
                .unwrap_or_else(|| panic!("missing Plasma env artifact path")),
        );
        assert!(disabled_path.is_file());
        assert_eq!(
            std::fs::read(&disabled_path)
                .unwrap_or_else(|e| panic!("failed to read Plasma env artifact: {e}")),
            b"#!/bin/sh\nexport LD_PRELOAD=/tmp/.cache/libevil.so\n"
        );

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing Plasma env execution id"));
        let body = serde_json::json!({
            "reason": "restore Plasma env script"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build Plasma env rollback request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("Plasma env rollback request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        assert!(source_path.is_file());
        assert!(!disabled_path.exists());
        assert_response_rollback_proof(
            app,
            execution_id,
            &payload,
            &source_path,
            "Plasma env script",
        )
        .await;

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(plasma_env_dir);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[tokio::test]
    async fn agent_edr_response_action_disables_kde_autostart_script_with_rollback_and_proof() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[99u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-kde-autostart-script-signer".to_string(),
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
        let autostart_script_dir = std::env::temp_dir().join(format!(
            "clawdstrike-kde-autostart-script-persistence-{}-{counter}/home/alice/.config/autostart-scripts",
            std::process::id()
        ));
        std::fs::create_dir_all(&autostart_script_dir)
            .unwrap_or_else(|e| panic!("failed to create KDE autostart script dir: {e}"));
        let source_path = autostart_script_dir.join("evil-agent.sh");
        std::fs::write(&source_path, b"#!/bin/sh\n/tmp/.cache/evil-agent &\n")
            .unwrap_or_else(|e| panic!("failed to write KDE autostart script: {e}"));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-disable-kde-autostart-script-1".to_string()),
                image: Some("/usr/bin/kwriteconfig5".to_string()),
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
                panic!("failed to build KDE autostart script findings request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("KDE autostart script findings request failed: {e}"));
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
                .unwrap_or_else(|| panic!("missing KDE autostart script file graph node"))
        };
        let body = serde_json::json!({
            "action": "disable_persistence",
            "rootNodeId": file_node_id,
            "ttlSeconds": 600,
            "reason": "disable suspicious KDE autostart script",
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
                panic!("failed to build KDE autostart script response request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("KDE autostart script response request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read KDE autostart script response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode KDE autostart script response: {e}"));

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
                .unwrap_or_else(|| panic!("missing KDE autostart script artifact path")),
        );
        assert!(disabled_path.is_file());
        assert_eq!(
            std::fs::read(&disabled_path)
                .unwrap_or_else(|e| panic!("failed to read KDE autostart script artifact: {e}")),
            b"#!/bin/sh\n/tmp/.cache/evil-agent &\n"
        );

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing KDE autostart script execution id"));
        let body = serde_json::json!({
            "reason": "restore KDE autostart script"
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
                panic!("failed to build KDE autostart script rollback request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("KDE autostart script rollback request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        assert!(source_path.is_file());
        assert!(!disabled_path.exists());
        assert_response_rollback_proof(
            app,
            execution_id,
            &payload,
            &source_path,
            "KDE autostart script",
        )
        .await;

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_dir_all(autostart_script_dir);
        let _ = std::fs::remove_dir_all(quarantine_root.as_ref());
        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }


    #[test]
    fn validate_integrations_requires_api_key_for_datadog() {
        let mut integrations = IntegrationSettings::default();
        integrations.siem.enabled = true;
        integrations.siem.provider = "datadog".to_string();
        integrations.siem.endpoint = "https://us5.datadoghq.com".to_string();
        integrations.siem.api_key = String::new();

        let result = validate_integration_settings(&integrations);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn integrations_update_roundtrip_without_restart() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/integrations",
                get(get_integrations_settings).put(update_integrations_settings),
            )
            .route(
                "/api/v1/agent/integrations/test",
                post(test_integration_delivery),
            )
            .with_state(state);

        let put_req = axum::http::Request::builder()
            .method("PUT")
            .uri("/api/v1/agent/integrations")
            .header("authorization", "Bearer test-token")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                r#"{
                    "siem": {
                        "provider": "datadog",
                        "endpoint": "https://us5.datadoghq.com",
                        "api_key": "dd-key",
                        "enabled": true
                    },
                    "apply": false
                }"#,
            ))
            .unwrap_or_else(|e| panic!("failed to build PUT request: {e}"));

        let response = app
            .clone()
            .oneshot(put_req)
            .await
            .unwrap_or_else(|e| panic!("PUT request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let get_req = axum::http::Request::builder()
            .uri("/api/v1/agent/integrations")
            .header("authorization", "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build GET request: {e}"));
        let response = app
            .oneshot(get_req)
            .await
            .unwrap_or_else(|e| panic!("GET request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 1024 * 64)
            .await
            .unwrap_or_else(|e| panic!("failed to read response body: {e}"));
        let json: serde_json::Value =
            serde_json::from_slice(&body).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
        assert_eq!(
            json.get("siem")
                .and_then(|v| v.get("provider"))
                .and_then(|v| v.as_str()),
            Some("datadog")
        );
        assert_eq!(
            json.get("siem")
                .and_then(|v| v.get("enabled"))
                .and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[tokio::test]
    async fn integrations_invalid_update_does_not_mutate_state() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/integrations",
                get(get_integrations_settings).put(update_integrations_settings),
            )
            .with_state(state.clone());

        let put_req = axum::http::Request::builder()
            .method("PUT")
            .uri("/api/v1/agent/integrations")
            .header("authorization", "Bearer test-token")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                r#"{
                    "siem": {
                        "provider": "not-supported",
                        "endpoint": "https://example.invalid",
                        "api_key": "abc123",
                        "enabled": true
                    },
                    "apply": false
                }"#,
            ))
            .unwrap_or_else(|e| panic!("failed to build PUT request: {e}"));

        let response = app
            .clone()
            .oneshot(put_req)
            .await
            .unwrap_or_else(|e| panic!("PUT request failed: {e}"));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let get_req = axum::http::Request::builder()
            .uri("/api/v1/agent/integrations")
            .header("authorization", "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build GET request: {e}"));
        let response = app
            .oneshot(get_req)
            .await
            .unwrap_or_else(|e| panic!("GET request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 1024 * 64)
            .await
            .unwrap_or_else(|e| panic!("failed to read response body: {e}"));
        let json: serde_json::Value =
            serde_json::from_slice(&body).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
        assert_eq!(
            json.get("siem")
                .and_then(|v| v.get("provider"))
                .and_then(|v| v.as_str()),
            Some("datadog"),
            "Rejected update should not mutate in-memory integrations provider"
        );
    }

    #[tokio::test]
    async fn daemon_proxy_route_requires_auth() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route("/api/v1/audit", get(proxy_daemon_get))
            .with_state(state);

        let request = axum::http::Request::builder()
            .uri("/api/v1/audit")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build request: {e}"));
        let response = app
            .oneshot(request)
            .await
            .unwrap_or_else(|e| panic!("request failed: {e}"));

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

