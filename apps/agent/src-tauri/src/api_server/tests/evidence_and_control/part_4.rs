    #[tokio::test]
    async fn network_extension_egress_policy_proof_does_not_claim_enforcement_when_provider_unready(
    ) {
        let state = Arc::new(test_state());
        let now = chrono::Utc::now();
        write_network_extension_egress_policy_snapshot(
            state.edr_network_extension_egress_policy_path.as_ref(),
            &[EndpointEgressRestriction {
                restriction_id: "restriction-proof-unready".to_string(),
                execution_id: "execution-proof-unready".to_string(),
                action_id: "action-proof-unready".to_string(),
                graph_slice_id: "graph-proof-unready".to_string(),
                rollback_ref: "rollback-proof-unready".to_string(),
                target: "proof-unready.example.invalid:443".to_string(),
                target_hash: sha256(b"proof-unready.example.invalid:443").to_hex_prefixed(),
                active: true,
                created_at: now,
                expires_at: now + chrono::Duration::minutes(10),
                updated_at: now,
            }],
            now,
        )
        .unwrap_or_else(|err| panic!("failed to write NetworkExtension proof snapshot: {err}"));
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
                    last_error: Some("policy reload pending".to_string()),
                    ..ProviderStatus::unknown()
                },
                ..CombinedSystemExtensionStatus::default()
            })
            .await;
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/network-extension/egress-policy/proof",
                post(agent_edr_network_extension_egress_policy_proof),
            )
            .with_state(state.clone());
        let body = serde_json::json!({
            "refreshProviders": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/network-extension/egress-policy/proof")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build unready proof request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("unready proof request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read unready proof response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode unready proof response: {e}"));
        assert_eq!(payload["snapshotPresent"], true);
        assert_eq!(payload["snapshotDecodable"], true);
        assert_eq!(payload["enforcementReady"], false);
        assert_eq!(payload["liveEnforcementProven"], false);
        assert!(payload["liveEnforcementProofReasons"]
            .as_array()
            .unwrap_or_else(|| panic!("missing unready live-enforcement proof reasons"))
            .iter()
            .any(|reason| reason == "provider_not_enforcement_ready"));
        assert_eq!(payload["networkExtensionProvider"]["policy_synced"], false);
        assert_eq!(
            payload["networkExtensionProvider"]["enforcement_ready"],
            false
        );

        let false_hash = sha256(b"false").to_hex_prefixed();
        let evidence = payload["receipt"]["receipt"]["metadata"]["endpointDecision"]["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing unready proof receipt evidence"));
        assert!(evidence.iter().any(|item| {
            item["key"] == "networkExtensionEgressPolicyEnforcementReady"
                && item["valueHash"].as_str() == Some(false_hash.as_str())
        }));
        assert!(evidence.iter().any(|item| {
            item["key"] == "networkExtensionLiveEnforcementProven"
                && item["valueHash"].as_str() == Some(false_hash.as_str())
        }));
        assert!(evidence.iter().any(|item| {
            item["key"] == "networkExtensionPolicySynced"
                && item["valueHash"].as_str() == Some(false_hash.as_str())
        }));
    }

    #[tokio::test]
    async fn network_extension_egress_policy_proof_binds_observed_provider_reload() {
        let state = Arc::new(test_state());
        let now = chrono::Utc::now();
        write_network_extension_egress_policy_snapshot(
            state.edr_network_extension_egress_policy_path.as_ref(),
            &[EndpointEgressRestriction {
                restriction_id: "restriction-proof-reload".to_string(),
                execution_id: "execution-proof-reload".to_string(),
                action_id: "action-proof-reload".to_string(),
                graph_slice_id: "graph-proof-reload".to_string(),
                rollback_ref: "rollback-proof-reload".to_string(),
                target: "proof-reload.example.invalid:443".to_string(),
                target_hash: sha256(b"proof-reload.example.invalid:443").to_hex_prefixed(),
                active: true,
                created_at: now,
                expires_at: now + chrono::Duration::minutes(10),
                updated_at: now,
            }],
            now,
        )
        .unwrap_or_else(|err| panic!("failed to write NetworkExtension proof snapshot: {err}"));
        let policy_snapshot_path = state
            .edr_network_extension_egress_policy_path
            .display()
            .to_string();
        let network_extension_provider: ProviderStatus =
            serde_json::from_value(serde_json::json!({
                "runtime": { "state": "active" },
                "policy_synced": true,
                "enforcement_ready": true,
                "counters": {
                    "flows_observed": 14,
                    "flows_blocked": 4,
                    "remediation_requests": 2,
                    "dropped_verdicts": 0
                },
                "last_reload_observation": {
                    "request_id": "provider-reload-observed-1",
                    "command": "reload_policy",
                    "policy_snapshot_path": policy_snapshot_path,
                    "generation": 12345,
                    "accepted": true,
                    "reloaded": true
                }
            }))
            .unwrap_or_else(|err| {
                panic!("failed to decode provider status with reload observation: {err}")
            });
        state
            .macos_host
            .replace_status(CombinedSystemExtensionStatus {
                install_state: SystemExtensionInstallState::Installed,
                approval: SystemExtensionApproval::Approved,
                endpoint_security: ProviderStatus {
                    runtime: ProviderRuntimeState::Active,
                    ..ProviderStatus::unknown()
                },
                network_extension: network_extension_provider,
                ..CombinedSystemExtensionStatus::default()
            })
            .await;
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/network-extension/egress-policy/proof",
                post(agent_edr_network_extension_egress_policy_proof),
            )
            .with_state(state.clone());
        let body = serde_json::json!({
            "refreshProviders": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/network-extension/egress-policy/proof")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build observed reload proof request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("observed reload proof request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read observed reload proof response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode observed reload proof response: {e}"));

        assert_eq!(payload["providerReloadObserved"], true);
        assert_eq!(
            payload["providerReloadRequestId"],
            "provider-reload-observed-1"
        );
        assert_eq!(payload["providerReloadGeneration"], 12345);
        assert_eq!(payload["providerReloadReloaded"], true);
        assert_eq!(
            payload["providerReloadPolicySnapshotPath"],
            policy_snapshot_path
        );
        assert_eq!(
            payload["networkExtensionProvider"]["last_reload_observation"]["request_id"],
            "provider-reload-observed-1"
        );

        let true_hash = sha256(b"true").to_hex_prefixed();
        let request_id_hash = sha256(b"provider-reload-observed-1").to_hex_prefixed();
        let generation_hash = sha256(b"12345").to_hex_prefixed();
        let proof_receipt_evidence = payload["receipt"]["receipt"]["metadata"]["endpointDecision"]
            ["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing observed reload proof receipt evidence"));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionReloadObserved"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionReloadObservedRequestId"
                && item["valueHash"].as_str() == Some(request_id_hash.as_str())
        }));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionReloadObservedGeneration"
                && item["valueHash"].as_str() == Some(generation_hash.as_str())
        }));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionReloadObservedReloaded"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
    }

    #[tokio::test]
    async fn agent_edr_response_action_restricts_egress_policy_check_until_rollback() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[58u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state_value = test_state();
        state_value.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-restrict-egress-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state_value);
        {
            let mut settings = state.settings.write().await;
            settings.enabled = false;
        }
        let mut network_counters = BTreeMap::new();
        network_counters.insert("flows_observed".to_string(), 11);
        network_counters.insert("flows_blocked".to_string(), 3);
        network_counters.insert("remediation_requests".to_string(), 1);
        network_counters.insert("dropped_verdicts".to_string(), 0);
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
                    counters: network_counters,
                    policy_epoch: Some(99),
                    policy_synced: Some(true),
                    enforcement_ready: Some(true),
                    ..ProviderStatus::unknown()
                },
                ..CombinedSystemExtensionStatus::default()
            })
            .await;
        let (reload_tx, mut reload_rx) =
            tokio::sync::mpsc::channel::<crate::macos::host::MacosNetworkExtensionReloadRequest>(4);
        state
            .macos_host
            .install_network_extension_reload_channel(reload_tx)
            .await;
        let reload_generation_probe = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let reload_count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let reload_policy_path = state
            .edr_network_extension_egress_policy_path
            .display()
            .to_string();
        {
            let reload_generation_probe = reload_generation_probe.clone();
            let reload_count = reload_count.clone();
            let reload_policy_path = reload_policy_path.clone();
            let macos_host = state.macos_host.clone();
            tokio::spawn(async move {
                while let Some(request) = reload_rx.recv().await {
                    let count = reload_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    if count == 1 {
                        reload_generation_probe
                            .store(request.generation, std::sync::atomic::Ordering::SeqCst);
                    }
                    macos_host
                        .replace_status(CombinedSystemExtensionStatus {
                            install_state: SystemExtensionInstallState::Installed,
                            approval: SystemExtensionApproval::Approved,
                            endpoint_security: ProviderStatus {
                                runtime: ProviderRuntimeState::Active,
                                ..ProviderStatus::unknown()
                            },
                            network_extension: ProviderStatus {
                                runtime: ProviderRuntimeState::Active,
                                counters: BTreeMap::from([
                                    ("flows_observed".to_string(), 11),
                                    ("flows_blocked".to_string(), 3),
                                    ("remediation_requests".to_string(), 1),
                                    ("dropped_verdicts".to_string(), 0),
                                ]),
                                policy_epoch: Some(99),
                                policy_synced: Some(true),
                                enforcement_ready: Some(true),
                                last_reload_observation: Some(
                                    crate::macos::status::ProviderReloadObservation {
                                        request_id: Some(format!("restrict-egress-reload-{count}")),
                                        command: Some("reload_policy".to_string()),
                                        policy_snapshot_path: Some(reload_policy_path.clone()),
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
                    let _ = request.reply_tx.send(Ok(
                        crate::macos::host::MacosNetworkExtensionReloadResult {
                            requested: true,
                            saved: true,
                            request_id: format!("restrict-egress-reload-{count}"),
                            policy_snapshot_path: reload_policy_path.clone(),
                            generation: request.generation,
                        },
                    ));
                }
            });
        }
        let app = Router::new()
            .route("/api/v1/agent/policy-check", post(agent_policy_check))
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/network-extension/egress-policy/proof",
                post(agent_edr_network_extension_egress_policy_proof),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/expire",
                post(agent_edr_response_execution_expire),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/cancel",
                post(agent_edr_response_execution_cancel),
            )
            .with_state(state.clone());
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-restrict-egress-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::NetworkFlow {
                host: "egress.example.invalid".to_string(),
                port: 443,
                protocol: Some("tcp".to_string()),
                url: Some("https://egress.example.invalid/upload".to_string()),
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
            .unwrap_or_else(|e| panic!("failed to build restrict-egress findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("restrict-egress findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = serde_json::json!({
            "action": "restrict_egress",
            "process": {
                "processGuid": "proc-restrict-egress-1"
            },
            "ttlSeconds": 600,
            "reason": "restrict observed egress",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build restrict-egress response request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("restrict-egress response request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read restrict-egress response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode restrict-egress response: {e}"));
        assert_eq!(payload["execution"]["action"], "restrict_egress");
        assert_eq!(payload["execution"]["status"], "succeeded");
        assert_eq!(
            payload["execution"]["effects"][0]["effectType"],
            "restrict_egress"
        );
        assert_eq!(
            payload["execution"]["effects"][0]["artifact"],
            "egress.example.invalid:443"
        );
        let network_extension_policy =
            read_json_file(state.edr_network_extension_egress_policy_path.as_ref());
        assert_eq!(network_extension_policy["schemaVersion"], 1);
        assert_eq!(
            network_extension_policy["restrictions"][0]["target"],
            "egress.example.invalid:443"
        );
        assert_eq!(
            network_extension_policy["restrictions"][0]["executionId"],
            payload["execution"]["executionId"]
        );
        let execution_receipt: SignedReceipt =
            serde_json::from_value(payload["executionReceipt"].clone()).unwrap_or_else(|e| {
                panic!("failed to decode restrict-egress execution receipt: {e}")
            });
        let endpoint_decision = execution_receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing restrict-egress endpointDecision metadata"));
        let true_hash = sha256(b"true").to_hex_prefixed();
        let false_hash = sha256(b"false").to_hex_prefixed();
        let blocked_count_hash = sha256(b"3").to_hex_prefixed();
        let reload_generation = reload_generation_probe.load(std::sync::atomic::Ordering::SeqCst);
        assert!(reload_generation > 0);
        let reload_request_id_hash = sha256(b"restrict-egress-reload-1").to_hex_prefixed();
        let reload_generation_hash =
            sha256(reload_generation.to_string().as_bytes()).to_hex_prefixed();
        let receipt_evidence = endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing restrict-egress receipt evidence"));
        assert!(receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionPolicySynced"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionEnforcementReady"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionFlowsBlocked"
                && item["valueHash"].as_str() == Some(blocked_count_hash.as_str())
        }));
        assert!(receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionReloadRequested"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionReloadSaved"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionReloadRequestId"
                && item["valueHash"].as_str() == Some(reload_request_id_hash.as_str())
        }));
        assert!(receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionReloadGeneration"
                && item["valueHash"].as_str() == Some(reload_generation_hash.as_str())
        }));
        assert!(endpoint_decision["sensorState"]["providers"]
            .as_array()
            .unwrap_or_else(|| panic!("missing receipt sensor providers"))
            .iter()
            .any(
                |provider| provider["providerId"] == "macos.network_extension"
                    && provider["healthy"] == true
            ));
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
                    counters: BTreeMap::from([
                        ("flows_observed".to_string(), 11),
                        ("flows_blocked".to_string(), 3),
                        ("remediation_requests".to_string(), 1),
                        ("dropped_verdicts".to_string(), 0),
                    ]),
                    policy_epoch: Some(99),
                    policy_synced: Some(true),
                    enforcement_ready: Some(true),
                    last_reload_observation: Some(
                        crate::macos::status::ProviderReloadObservation {
                            request_id: Some("restrict-egress-reload-1".to_string()),
                            command: Some("reload_policy".to_string()),
                            policy_snapshot_path: Some(reload_policy_path.clone()),
                            generation: Some(reload_generation),
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
        let body = serde_json::json!({
            "refreshProviders": false,
            "executionId": payload["execution"]["executionId"]
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/network-extension/egress-policy/proof")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build NetworkExtension proof request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("NetworkExtension proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read NetworkExtension proof response: {e}"));
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected NetworkExtension proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let proof_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode NetworkExtension proof response: {e}"));
        assert_eq!(proof_payload["snapshotPresent"], true);
        assert_eq!(proof_payload["snapshotDecodable"], true);
        assert_eq!(proof_payload["restrictionCount"], 1);
        assert_eq!(proof_payload["activeRestrictionCount"], 1);
        assert_eq!(proof_payload["enforcementReady"], true);
        assert_eq!(proof_payload["liveEnforcementProven"], true);
        assert_eq!(
            proof_payload["liveEnforcementProofReasons"]
                .as_array()
                .unwrap_or_else(|| panic!("missing live-enforcement proof reasons"))
                .len(),
            0
        );
        assert_eq!(proof_payload["flowCounterObserved"], true);
        assert_eq!(proof_payload["observedFlowCount"], 11);
        assert_eq!(proof_payload["blockedFlowCount"], 3);
        assert_eq!(proof_payload["remediationRequestCount"], 1);
        assert_eq!(proof_payload["droppedVerdictCount"], 0);
        assert_eq!(
            proof_payload["providerReloadDelivery"]["executionId"],
            payload["execution"]["executionId"]
        );
        assert_eq!(proof_payload["providerReloadDelivery"]["observed"], true);
        assert_eq!(proof_payload["providerReloadDelivery"]["matched"], true);
        assert_eq!(
            proof_payload["providerReloadDelivery"]["requestIdMatches"],
            true
        );
        assert_eq!(
            proof_payload["providerReloadDelivery"]["generationMatches"],
            true
        );
        assert_eq!(
            proof_payload["providerReloadDelivery"]["policySnapshotPathMatches"],
            true
        );
        assert_eq!(
            proof_payload["providerReloadDelivery"]["providerReloaded"],
            true
        );
        assert_eq!(
            proof_payload["networkExtensionProvider"]["policy_synced"],
            true
        );
        let proof_snapshot_hash = proof_payload["snapshotHash"]
            .as_str()
            .unwrap_or_else(|| panic!("missing NetworkExtension proof snapshot hash"));
        assert!(proof_snapshot_hash.starts_with("0x"));
        assert_eq!(proof_payload["providerStatusRefresh"]["requested"], false);
        assert_eq!(
            proof_payload["receipt"]["receipt"]["metadata"]["endpointDecision"]["receiptFamily"],
            "sensor_state"
        );
        let proof_endpoint_decision =
            &proof_payload["receipt"]["receipt"]["metadata"]["endpointDecision"];
        let proof_receipt_evidence = proof_endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing NetworkExtension proof receipt evidence"));
        let one_hash = sha256(b"1").to_hex_prefixed();
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionEgressPolicySnapshotHash"
                && item["valueHash"].as_str() == Some(proof_snapshot_hash)
        }));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionEgressPolicySnapshotPresent"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionEgressPolicySnapshotDecodable"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionEgressPolicyActiveRestrictionCount"
                && item["valueHash"].as_str() == Some(one_hash.as_str())
        }));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionEgressPolicyProviderRefreshRequested"
                && item["valueHash"].as_str() == Some(false_hash.as_str())
        }));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionFlowCounterObserved"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionLiveEnforcementProven"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionLiveEnforcementProofReasons"
                && item["valueHash"].as_str() == Some(sha256(b"").to_hex_prefixed().as_str())
        }));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionPolicySynced"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionReloadDeliveryMatched"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));
        assert!(proof_receipt_evidence.iter().any(|item| {
            item["key"] == "networkExtensionReloadDeliveryRequestIdMatches"
                && item["valueHash"].as_str() == Some(true_hash.as_str())
        }));

        let policy_body = serde_json::json!({
            "action_type": "egress",
            "target": "https://egress.example.invalid/upload"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/policy-check")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(policy_body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build restricted policy-check request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("restricted policy-check request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read restricted policy-check response: {e}"));
        let policy_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode restricted policy-check response: {e}"));
        assert_eq!(policy_payload["allowed"], false);
        assert_eq!(policy_payload["guard"], "edr_restrict_egress");
        assert_eq!(
            policy_payload["details"]["executionId"],
            payload["execution"]["executionId"]
        );

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing restrict-egress execution id"));
        let body = serde_json::json!({
            "reason": "restore restricted egress"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build restrict-egress rollback request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("restrict-egress rollback request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read restrict-egress rollback response: {e}"));
        let rollback_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode restrict-egress rollback response: {e}"));
        assert_eq!(
            rollback_payload["rollback"]["effects"][0]["effectType"],
            "restore_egress"
        );
        let network_extension_policy =
            read_json_file(state.edr_network_extension_egress_policy_path.as_ref());
        assert_eq!(
            network_extension_policy["restrictions"]
                .as_array()
                .unwrap_or_else(|| panic!("missing NetworkExtension policy restrictions"))
                .len(),
            0
        );

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/policy-check")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(policy_body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build restored policy-check request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("restored policy-check request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read restored policy-check response: {e}"));
        let restored_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode restored policy-check response: {e}"));
        assert_eq!(restored_payload["allowed"], true);
        assert_eq!(restored_payload["guard"], "enforcement_disabled");

        let body = serde_json::json!({
            "action": "restrict_egress",
            "process": {
                "processGuid": "proc-restrict-egress-1"
            },
            "ttlSeconds": 600,
            "reason": "restrict observed egress again",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build second restrict-egress request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("second restrict-egress request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read second restrict-egress response: {e}"));
        let second_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode second restrict-egress response: {e}"));
        let second_execution_id = second_payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing second restrict-egress execution id"));

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/policy-check")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(policy_body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build second restricted policy-check request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("second restricted policy-check request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read second restricted policy-check: {e}"));
        let restricted_again: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode second restricted policy-check: {e}"));
        assert_eq!(restricted_again["allowed"], false);
        assert_eq!(restricted_again["guard"], "edr_restrict_egress");

        let body = serde_json::json!({
            "reason": "cancel restricted egress"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{second_execution_id}/cancel"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build restrict-egress cancel request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("restrict-egress cancel request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/policy-check")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(policy_body.to_string()))
            .unwrap_or_else(|e| {
                panic!("failed to build cancel-restored policy-check request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("cancel-restored policy-check request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read cancel-restored policy-check response: {e}")
            });
        let cancel_restored: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                panic!("failed to decode cancel-restored policy-check response: {e}")
            });
        assert_eq!(cancel_restored["allowed"], true);
        assert_eq!(cancel_restored["guard"], "enforcement_disabled");
        let network_extension_policy =
            read_json_file(state.edr_network_extension_egress_policy_path.as_ref());
        assert_eq!(
            network_extension_policy["restrictions"]
                .as_array()
                .unwrap_or_else(|| panic!("missing NetworkExtension policy restrictions"))
                .len(),
            0
        );

        let body = serde_json::json!({
            "action": "restrict_egress",
            "process": {
                "processGuid": "proc-restrict-egress-1"
            },
            "ttlSeconds": 1,
            "reason": "restrict observed egress until expiration",
            "actor": response_action_actor_input(),
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-action")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build expiring restrict-egress request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("expiring restrict-egress request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read expiring restrict-egress response: {e}"));
        let expiring_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode expiring restrict-egress response: {e}"));
        let expiring_action_id = expiring_payload["execution"]["actionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing expiring restrict-egress action id"));
        {
            let ledger = state.edr_egress_restriction_ledger.lock().await;
            assert!(!ledger.active_for_action(expiring_action_id).is_empty());
        }

        tokio::time::sleep(Duration::from_millis(1100)).await;

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-executions/expire")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build restrict-egress expiration request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("restrict-egress expiration request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read restrict-egress expiration response: {e}"));
        let expiration_payload: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                panic!("failed to decode restrict-egress expiration response: {e}")
            });
        assert_eq!(expiration_payload["expired_count"], 0);
        assert_eq!(
            expiration_payload["rollback_transitions"][0]["execution"]["action"],
            "restrict_egress"
        );
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
        {
            let ledger = state.edr_egress_restriction_ledger.lock().await;
            assert!(ledger.active_for_action(expiring_action_id).is_empty());
        }
        let network_extension_policy =
            read_json_file(state.edr_network_extension_egress_policy_path.as_ref());
        assert_eq!(
            network_extension_policy["restrictions"]
                .as_array()
                .unwrap_or_else(|| panic!("missing NetworkExtension policy restrictions"))
                .len(),
            0
        );
        let _ = std::fs::remove_file(receipt_path);
    }

    #[tokio::test]
    async fn agent_edr_response_action_executes_collect_evidence_with_execution_receipt() {
        let receipt_path = test_receipt_path();
        let execution_path = test_response_execution_path();
        let keypair = Keypair::from_seed(&[64u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state = test_state();
        state.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-response-proof-signer".to_string(),
            signer_public_key,
        }));
        state.edr_response_execution_ledger = Arc::new(Mutex::new(
            EndpointResponseExecutionLedger::open(execution_path.clone())
                .unwrap_or_else(|e| panic!("failed to open response execution proof ledger: {e}")),
        ));
        let state = Arc::new(state);
        let app_state = Arc::clone(&state);
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
            .route(
                "/api/v1/agent/edr/evidence-bundles/{bundle_id}/archive",
                get(agent_edr_evidence_bundle_archive),
            )
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
            .with_state(app_state);
        let identity_metadata = BTreeMap::from([
            ("agentId".to_string(), serde_json::json!("agent-collect-1")),
            (
                "workloadIdentity".to_string(),
                serde_json::json!("workload-collect-1"),
            ),
            (
                "approvalId".to_string(),
                serde_json::json!("approval-collect-1"),
            ),
        ]);
        let observations = vec![
            EndpointObservation {
                observation_id: "collect-tool-1".to_string(),
                host_id: Some("host-collect-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("session-collect-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-collect-evidence-1".to_string()),
                    image: Some("/usr/bin/python3".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::ToolCall {
                    tool_name: "mcp.shell".to_string(),
                    parameters: serde_json::json!({
                        "command": "python collect.py"
                    }),
                },
                metadata: identity_metadata.clone(),
                ..EndpointObservation::default()
            },
            EndpointObservation {
                observation_id: "collect-network-1".to_string(),
                host_id: Some("host-collect-1".to_string()),
                user_id: Some("alice".to_string()),
                session_id: Some("session-collect-1".to_string()),
                process: EndpointProcess {
                    process_guid: Some("proc-collect-evidence-1".to_string()),
                    image: Some("/usr/bin/python3".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::NetworkFlow {
                    host: "evidence.example.invalid".to_string(),
                    port: 443,
                    protocol: Some("tcp".to_string()),
                    url: Some("https://evidence.example.invalid/upload".to_string()),
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
            "action": "collect_evidence",
            "process": {
                "processGuid": "proc-collect-evidence-1"
            },
            "ttlSeconds": 600,
            "reason": "collect evidence bundle for graph target",
            "actor": response_action_actor_input(),
            "dryRun": false
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

        assert_eq!(payload["plan"]["dryRun"], false);
        assert_eq!(payload["plan"]["action"], "collect_evidence");
        assert_eq!(payload["execution"]["status"], "succeeded");
        assert_eq!(
            payload["execution"]["actionId"],
            payload["plan"]["actionId"]
        );
        assert_eq!(
            payload["execution"]["rollbackRef"],
            payload["plan"]["rollbackRef"]
        );
        assert_eq!(payload["execution"]["actor"]["userId"], "operator:test");
        assert_eq!(
            payload["execution"]["actor"]["approvalId"],
            "approval-response-action"
        );
        assert_eq!(payload["affectedIdentityCount"].as_u64(), Some(6));
        assert_eq!(payload["affectedToolCount"].as_u64(), Some(1));
        assert_eq!(
            payload["affectedIdentities"]["hosts"][0]["id"],
            "host-collect-1"
        );
        assert_eq!(payload["affectedIdentities"]["users"][0]["id"], "alice");
        assert_eq!(
            payload["affectedIdentities"]["sessions"][0]["id"],
            "session-collect-1"
        );
        assert_eq!(
            payload["affectedIdentities"]["agents"][0]["id"],
            "agent-collect-1"
        );
        assert_eq!(
            payload["affectedIdentities"]["workloads"][0]["id"],
            "workload-collect-1"
        );
        assert_eq!(
            payload["affectedIdentities"]["approvals"][0]["id"],
            "approval-collect-1"
        );
        assert_eq!(payload["affectedTools"][0]["toolName"], "mcp.shell");
        assert!(
            payload["execution"]["evidenceBundle"]["nodeCount"]
                .as_u64()
                .unwrap_or_default()
                >= 2
        );
        assert!(payload["execution"]["evidenceBundle"]["contentHash"]
            .as_str()
            .unwrap_or_default()
            .starts_with("0x"));
        let bundle_id = payload["execution"]["evidenceBundle"]["bundleId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing execution evidence bundle id"));
        assert_eq!(payload["evidenceBundleArtifact"]["bundleId"], bundle_id);
        assert_eq!(
            payload["evidenceBundleArtifact"]["contentHash"],
            payload["execution"]["evidenceBundle"]["contentHash"]
        );
        assert!(
            payload["evidenceBundleArtifact"]["byteCount"]
                .as_u64()
                .unwrap_or_default()
                > 0
        );

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!("/api/v1/agent/edr/evidence-bundles/{bundle_id}"))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build evidence bundle request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("evidence bundle request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read evidence bundle response: {e}"));
        let bundle_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode evidence bundle response: {e}"));
        assert_eq!(bundle_payload["bundle"]["bundleId"], bundle_id);
        assert_eq!(
            bundle_payload["bundle"]["contentHash"],
            payload["execution"]["evidenceBundle"]["contentHash"]
        );
        assert!(bundle_payload["graph"]["nodes"]
            .as_object()
            .unwrap_or_else(|| panic!("missing evidence bundle graph nodes"))
            .values()
            .any(|node| node["label"] == "evidence.example.invalid:443"));

        let execution_id = payload["execution"]["executionId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing response execution id"));
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build execution lookup request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("execution lookup request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read execution lookup response: {e}"));
        let execution_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode execution lookup response: {e}"));
        assert_eq!(
            execution_payload["execution"]["execution"]["executionId"],
            execution_id
        );
        assert_eq!(
            execution_payload["execution"]["rollbackRef"],
            payload["execution"]["rollbackRef"]
        );
        assert_eq!(
            execution_payload["execution"]["execution"]["ttlSeconds"],
            serde_json::Value::from(600)
        );
        assert_eq!(
            execution_payload["execution"]["execution"]["actor"]["userId"],
            "operator:test"
        );
        assert_eq!(
            execution_payload["execution"]["execution"]["actor"]["approvalId"],
            "approval-response-action"
        );
        assert_eq!(
            execution_payload["execution"]["affectedIdentityCount"].as_u64(),
            Some(6)
        );
        assert_eq!(
            execution_payload["execution"]["affectedToolCount"].as_u64(),
            Some(1)
        );
        assert_eq!(
            execution_payload["execution"]["affectedIdentities"]["hosts"][0]["id"],
            "host-collect-1"
        );
        assert_eq!(
            execution_payload["execution"]["affectedTools"][0]["toolName"],
            "mcp.shell"
        );

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/edr/response-executions?limit=10")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build execution list request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("execution list request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read execution list response: {e}"));
        let executions_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode execution list response: {e}"));
        assert_eq!(executions_payload["execution_count"], 1);
        assert_eq!(
            executions_payload["executions"][0]["execution"]["executionId"],
            execution_id
        );
        assert_eq!(
            executions_payload["executions"][0]["affectedIdentityCount"].as_u64(),
            Some(6)
        );
        assert_eq!(
            executions_payload["executions"][0]["affectedToolCount"].as_u64(),
            Some(1)
        );

        let request_receipt: SignedReceipt = serde_json::from_value(payload["receipt"].clone())
            .unwrap_or_else(|e| panic!("failed to decode response request receipt: {e}"));
        let request_decision = request_receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing response request endpointDecision metadata"));
        assert_eq!(request_decision["receiptFamily"], "response_request");
        assert_eq!(request_decision["actor"]["userId"], "operator:test");
        assert_eq!(
            request_decision["actor"]["sessionId"],
            "session-response-action"
        );
        assert_eq!(request_decision["actor"]["agentId"], "agent-api:test");
        assert_eq!(
            request_decision["actor"]["approvalId"],
            "approval-response-action"
        );

        let execution_receipt: SignedReceipt =
            serde_json::from_value(payload["executionReceipt"].clone())
                .unwrap_or_else(|e| panic!("failed to decode response execution receipt: {e}"));
        let execution_decision = execution_receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing response execution endpointDecision metadata"));
        let public_key = execution_decision
            .get("signer")
            .and_then(|signer| signer.get("signerPublicKey"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("missing execution receipt signer public key"));
        let public_key = hush_core::PublicKey::from_hex(public_key)
            .unwrap_or_else(|e| panic!("failed to parse execution receipt public key: {e}"));
        let verification =
            execution_receipt.verify(&hush_core::receipt::PublicKeySet::new(public_key));
        assert!(verification.valid);
        assert_eq!(execution_decision["receiptFamily"], "response_execution");
        let execution_providers = execution_decision["sensorState"]["providers"]
            .as_array()
            .unwrap_or_else(|| panic!("missing response execution sensor providers"));
        assert!(execution_providers
            .iter()
            .any(|provider| provider["providerId"] == "agent-api"));
        assert!(execution_providers
            .iter()
            .any(|provider| provider["providerId"] == "macos.endpoint_security"));
        assert!(execution_providers
            .iter()
            .any(|provider| provider["providerId"] == "macos.network_extension"));
        assert_eq!(execution_decision["actor"]["userId"], "operator:test");
        assert_eq!(
            execution_decision["actor"]["sessionId"],
            "session-response-action"
        );
        assert_eq!(execution_decision["actor"]["agentId"], "agent-api:test");
        assert_eq!(
            execution_decision["actor"]["approvalId"],
            "approval-response-action"
        );
        assert_eq!(
            execution_decision["decision"]["findingId"],
            payload["execution"]["executionId"]
        );

        let bundle_receipt: SignedReceipt =
            serde_json::from_value(payload["evidenceBundleReceipt"].clone())
                .unwrap_or_else(|e| panic!("failed to decode evidence bundle receipt: {e}"));
        let bundle_decision = bundle_receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing evidence bundle endpointDecision metadata"));
        let public_key = bundle_decision
            .get("signer")
            .and_then(|signer| signer.get("signerPublicKey"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("missing evidence bundle receipt signer public key"));
        let public_key = hush_core::PublicKey::from_hex(public_key)
            .unwrap_or_else(|e| panic!("failed to parse evidence bundle receipt public key: {e}"));
        let verification =
            bundle_receipt.verify(&hush_core::receipt::PublicKeySet::new(public_key));
        assert!(verification.valid);
        assert_eq!(bundle_decision["receiptFamily"], "evidence_bundle_manifest");
        assert_eq!(
            bundle_decision["decision"]["findingId"],
            payload["execution"]["evidenceBundle"]["bundleId"]
        );
        assert_eq!(
            bundle_decision["graph"]["graphSliceId"],
            payload["execution"]["evidenceBundle"]["graphSliceId"]
        );

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/evidence-bundles/{bundle_id}/archive"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build collect-evidence archive request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("collect-evidence archive request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read collect-evidence archive response: {e}"));
        let collect_archive_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode collect-evidence archive response: {e}"));
        assert_eq!(collect_archive_payload["verification"]["verified"], true);
        assert_eq!(
            collect_archive_payload["verification"]["requiredReceiptFamiliesPresent"],
            true
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptsBindBundleId"],
            true
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptsBindActor"],
            true
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptsBindPolicy"],
            true
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptsBindSensorState"],
            true
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptsBindEndpointDecision"],
            true
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptsBindEndpointIdentity"],
            true
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptEndpointIds"]
                .as_array()
                .unwrap_or_else(|| panic!("missing collect archive endpoint identity list"))
                .len(),
            1
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptsBindRootNode"],
            true
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptRootNodeIds"]
                .as_array()
                .unwrap_or_else(|| panic!("missing collect archive root-node list"))
                .len(),
            1
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptSignersConsistent"],
            true
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptIdsUnique"],
            true
        );
        let collect_present_receipt_families = collect_archive_payload["verification"]
            ["presentReceiptFamilies"]
            .as_array()
            .unwrap_or_else(|| panic!("missing collect archive present receipt-family list"));
        let collect_required_receipt_families = collect_archive_payload["verification"]
            ["requiredReceiptFamilies"]
            .as_array()
            .unwrap_or_else(|| panic!("missing collect archive required receipt-family list"));
        for required_family in [
            "response_request",
            "response_execution",
            "evidence_bundle_manifest",
        ] {
            assert!(collect_present_receipt_families
                .iter()
                .any(|family| family == required_family));
            assert!(collect_required_receipt_families
                .iter()
                .any(|family| family == required_family));
            assert_eq!(
                collect_archive_payload["verification"]["receiptFamilyCounts"][required_family],
                1
            );
        }
        assert_eq!(
            collect_archive_payload["verification"]["receiptFamilyCardinalityValid"],
            true
        );
        assert_eq!(
            collect_archive_payload["verification"]["missingRequiredReceiptFamilies"],
            serde_json::json!([])
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptLocalSequencesPresent"],
            true
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptLocalSequencesUnique"],
            true
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptLocalSequences"]
                .as_array()
                .unwrap_or_else(|| panic!("missing collect archive local sequence list"))
                .len(),
            collect_archive_payload["verification"]["receiptCount"]
                .as_u64()
                .unwrap_or_default() as usize
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptTimestampsParse"],
            true
        );
        assert_eq!(
            collect_archive_payload["verification"]["receiptChronologyConsistent"],
            true
        );
        let collect_archive_families = collect_archive_payload["archive"]["receipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing collect-evidence archive receipts"))
            .iter()
            .filter_map(|receipt| {
                receipt["receipt"]["metadata"]["endpointDecision"]["receiptFamily"].as_str()
            })
            .collect::<BTreeSet<_>>();
        assert!(collect_archive_families.contains("response_request"));
        assert!(collect_archive_families.contains("response_execution"));
        assert!(collect_archive_families.contains("evidence_bundle_manifest"));
        let collect_archive: EdrEvidenceBundleArchive = serde_json::from_value(
            collect_archive_payload["archive"].clone(),
        )
        .unwrap_or_else(|e| {
            panic!("failed to decode collect-evidence archive for receipt-family checks: {e}")
        });
        for missing_family in [
            "response_request",
            "response_execution",
            "evidence_bundle_manifest",
        ] {
            let mut missing_family_archive = collect_archive.clone();
            missing_family_archive.receipts.retain(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"]) != Some(missing_family)
            });
            let missing_family_verification =
                evidence_bundle_archive_verification(&missing_family_archive).unwrap_or_else(|e| {
                    panic!("failed to verify archive missing {missing_family}: {e}")
                });
            assert_eq!(missing_family_verification.verified, false);
            assert_eq!(
                missing_family_verification.required_receipt_families_present,
                false
            );
            assert_eq!(
                missing_family_verification.missing_required_receipt_families,
                vec![missing_family.to_string()]
            );
            assert_eq!(missing_family_verification.receipt_families_valid, true);
            assert!(
                missing_family_verification
                    .receipt_failures
                    .iter()
                    .any(|failure| failure == &format!("missing_required_family:{missing_family}")),
                "missing required-family failure for {missing_family}: {:?}",
                missing_family_verification.receipt_failures
            );
        }
        let mut duplicate_family_archive = collect_archive.clone();
        let duplicate_family_request_receipt_index = duplicate_family_archive
            .receipts
            .iter()
            .position(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"])
                    == Some("response_request")
            })
            .unwrap_or_else(|| panic!("missing duplicate-family request receipt index"));
        let duplicate_family_next_sequence = duplicate_family_archive
            .receipts
            .iter()
            .filter_map(receipt_local_sequence)
            .max()
            .unwrap_or_default()
            .saturating_add(1);
        let duplicate_family_keypair = Keypair::from_seed(&[64u8; 32]);
        let mut duplicate_family_decision: EndpointDecisionReceipt = serde_json::from_value(
            duplicate_family_archive.receipts[duplicate_family_request_receipt_index]
                .receipt
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.get("endpointDecision"))
                .cloned()
                .unwrap_or_else(|| panic!("missing duplicate-family endpointDecision metadata")),
        )
        .unwrap_or_else(|e| panic!("failed to decode duplicate-family endpoint decision: {e}"));
        duplicate_family_decision.local_sequence = duplicate_family_next_sequence;
        duplicate_family_decision.signer.signer_public_key =
            Some(duplicate_family_keypair.public_key().to_hex());
        duplicate_family_archive.receipts.push(
            duplicate_family_decision
                .sign_with(&duplicate_family_keypair)
                .unwrap_or_else(|e| panic!("failed to sign duplicate-family receipt: {e}")),
        );
        let duplicate_family_verification =
            evidence_bundle_archive_verification(&duplicate_family_archive)
                .unwrap_or_else(|e| panic!("failed to verify duplicate-family archive: {e}"));
        assert_eq!(duplicate_family_verification.verified, false);
        assert_eq!(duplicate_family_verification.receipt_ids_unique, true);
        assert_eq!(
            duplicate_family_verification.receipt_local_sequences_unique,
            true
        );
        assert_eq!(duplicate_family_verification.receipt_signatures_valid, true);
        assert_eq!(
            duplicate_family_verification.receipt_family_cardinality_valid,
            false
        );
        assert_eq!(
            duplicate_family_verification
                .receipt_family_counts
                .get("response_request"),
            Some(&2)
        );
        assert!(
            duplicate_family_verification
                .receipt_failures
                .iter()
                .any(|failure| failure == "duplicate_receipt_family:response_request:2"),
            "missing duplicate family failure: {:?}",
            duplicate_family_verification.receipt_failures
        );
        let mut duplicate_sequence_archive = collect_archive.clone();
        let duplicate_sequence_request_receipt_index = duplicate_sequence_archive
            .receipts
            .iter()
            .position(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"])
                    == Some("response_request")
            })
            .unwrap_or_else(|| panic!("missing duplicate-sequence request receipt index"));
        let duplicate_sequence_execution_sequence = duplicate_sequence_archive
            .receipts
            .iter()
            .find(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"])
                    == Some("response_execution")
            })
            .and_then(receipt_local_sequence)
            .unwrap_or_else(|| panic!("missing duplicate-sequence execution local sequence"));
        let duplicate_sequence_keypair = Keypair::from_seed(&[64u8; 32]);
        let mut duplicate_sequence_endpoint_decision: EndpointDecisionReceipt =
            serde_json::from_value(
                duplicate_sequence_archive.receipts[duplicate_sequence_request_receipt_index]
                    .receipt
                    .metadata
                    .as_ref()
                    .and_then(|metadata| metadata.get("endpointDecision"))
                    .cloned()
                    .unwrap_or_else(|| {
                        panic!("missing duplicate-sequence request endpointDecision metadata")
                    }),
            )
            .unwrap_or_else(|e| {
                panic!("failed to decode duplicate-sequence endpoint decision: {e}")
            });
        duplicate_sequence_endpoint_decision.local_sequence = duplicate_sequence_execution_sequence;
        duplicate_sequence_endpoint_decision
            .signer
            .signer_public_key = Some(duplicate_sequence_keypair.public_key().to_hex());
        duplicate_sequence_archive.receipts[duplicate_sequence_request_receipt_index] =
            duplicate_sequence_endpoint_decision
                .sign_with(&duplicate_sequence_keypair)
                .unwrap_or_else(|e| panic!("failed to sign duplicate-sequence receipt: {e}"));
        let duplicate_sequence_verification =
            evidence_bundle_archive_verification(&duplicate_sequence_archive)
                .unwrap_or_else(|e| panic!("failed to verify duplicate-sequence archive: {e}"));
        assert_eq!(duplicate_sequence_verification.verified, false);
        assert_eq!(duplicate_sequence_verification.receipt_ids_unique, true);
        assert_eq!(
            duplicate_sequence_verification.receipt_local_sequences_present,
            true
        );
        assert_eq!(
            duplicate_sequence_verification.receipt_local_sequences_unique,
            false
        );
        assert_eq!(
            duplicate_sequence_verification.receipt_signatures_valid,
            true
        );
        assert_eq!(
            duplicate_sequence_verification.receipt_signers_consistent,
            true
        );
        assert!(
            duplicate_sequence_verification
                .receipt_failures
                .iter()
                .any(|failure| failure.starts_with("duplicate_receipt_local_sequence:")),
            "missing duplicate local-sequence failure: {:?}",
            duplicate_sequence_verification.receipt_failures
        );
        let mut inverted_timestamp_archive = collect_archive.clone();
        let inverted_timestamp_manifest_receipt_index = inverted_timestamp_archive
            .receipts
            .iter()
            .position(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"])
                    == Some("evidence_bundle_manifest")
            })
            .unwrap_or_else(|| panic!("missing inverted-timestamp manifest receipt index"));
        inverted_timestamp_archive.receipts[inverted_timestamp_manifest_receipt_index]
            .receipt
            .timestamp = "1970-01-01T00:00:00Z".to_string();
        let inverted_timestamp_verification =
            evidence_bundle_archive_verification(&inverted_timestamp_archive)
                .unwrap_or_else(|e| panic!("failed to verify inverted-timestamp archive: {e}"));
        assert_eq!(inverted_timestamp_verification.verified, false);
        assert_eq!(
            inverted_timestamp_verification.receipt_timestamps_parse,
            true
        );
        assert_eq!(
            inverted_timestamp_verification.receipt_chronology_consistent,
            false
        );
        assert_eq!(
            inverted_timestamp_verification.receipt_signatures_valid,
            false
        );
        assert!(
            inverted_timestamp_verification
                .receipt_failures
                .iter()
                .any(|failure| failure.starts_with("receipt_chronology_inversion:")),
            "missing timestamp chronology inversion failure: {:?}",
            inverted_timestamp_verification.receipt_failures
        );
        let mut mixed_endpoint_archive = collect_archive.clone();
        let mixed_endpoint_manifest_receipt_index = mixed_endpoint_archive
            .receipts
            .iter()
            .position(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"])
                    == Some("evidence_bundle_manifest")
            })
            .unwrap_or_else(|| panic!("missing mixed-endpoint archive manifest receipt index"));
        let mixed_endpoint_keypair = Keypair::from_seed(&[64u8; 32]);
        let mut mixed_endpoint_decision: EndpointDecisionReceipt = serde_json::from_value(
            mixed_endpoint_archive.receipts[mixed_endpoint_manifest_receipt_index]
                .receipt
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.get("endpointDecision"))
                .cloned()
                .unwrap_or_else(|| {
                    panic!("missing mixed-endpoint manifest endpointDecision metadata")
                }),
        )
        .unwrap_or_else(|e| panic!("failed to decode mixed-endpoint endpoint decision: {e}"));
        mixed_endpoint_decision.actor.endpoint_id = "endpoint-agent-archive-other".to_string();
        mixed_endpoint_decision.signer.signer_public_key =
            Some(mixed_endpoint_keypair.public_key().to_hex());
        mixed_endpoint_archive.receipts[mixed_endpoint_manifest_receipt_index] =
            mixed_endpoint_decision
                .sign_with(&mixed_endpoint_keypair)
                .unwrap_or_else(|e| panic!("failed to sign mixed-endpoint receipt: {e}"));
        let mixed_endpoint_verification =
            evidence_bundle_archive_verification(&mixed_endpoint_archive)
                .unwrap_or_else(|e| panic!("failed to verify mixed-endpoint archive: {e}"));
        assert_eq!(mixed_endpoint_verification.verified, false);
        assert_eq!(mixed_endpoint_verification.receipt_ids_unique, true);
        assert_eq!(mixed_endpoint_verification.receipt_signatures_valid, true);
        assert_eq!(mixed_endpoint_verification.receipt_signers_consistent, true);
        assert_eq!(mixed_endpoint_verification.receipts_bind_actor, true);
        assert_eq!(
            mixed_endpoint_verification.receipts_bind_endpoint_identity,
            false
        );
        assert_eq!(mixed_endpoint_verification.receipt_endpoint_ids.len(), 2);
        assert!(
            mixed_endpoint_verification
                .receipt_failures
                .iter()
                .any(|failure| failure == "receipt_endpoint_identity_mismatch:2"),
            "missing endpoint identity continuity failure: {:?}",
            mixed_endpoint_verification.receipt_failures
        );
        let mut mixed_root_archive = collect_archive.clone();
        let mixed_root_manifest_receipt_index = mixed_root_archive
            .receipts
            .iter()
            .position(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"])
                    == Some("evidence_bundle_manifest")
            })
            .unwrap_or_else(|| panic!("missing mixed-root archive manifest receipt index"));
        let original_root_node_id = receipt_endpoint_decision_str(
            &mixed_root_archive.receipts[mixed_root_manifest_receipt_index],
            &["graph", "processNodeId"],
        )
        .unwrap_or_else(|| panic!("missing mixed-root original process node id"));
        let mixed_root_node_id = mixed_root_archive
            .graph
            .nodes
            .keys()
            .find(|node_id| node_id.as_str() != original_root_node_id)
            .cloned()
            .unwrap_or_else(|| panic!("missing alternate root node for mixed-root archive"));
        let mixed_root_keypair = Keypair::from_seed(&[64u8; 32]);
        let mut mixed_root_decision: EndpointDecisionReceipt = serde_json::from_value(
            mixed_root_archive.receipts[mixed_root_manifest_receipt_index]
                .receipt
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.get("endpointDecision"))
                .cloned()
                .unwrap_or_else(|| panic!("missing mixed-root manifest endpointDecision metadata")),
        )
        .unwrap_or_else(|e| panic!("failed to decode mixed-root endpoint decision: {e}"));
        let mixed_root_graph =
            EndpointGraphReference::for_subgraph(mixed_root_node_id, &mixed_root_archive.graph);
        let mixed_root_graph_slice_id = mixed_root_graph
            .graph_slice_id
            .clone()
            .unwrap_or_else(|| panic!("missing mixed-root graph slice id"));
        mixed_root_decision.graph = mixed_root_graph;
        let graph_slice_evidence = mixed_root_decision
            .evidence
            .iter_mut()
            .find(|item| item.key == "graphSliceId")
            .unwrap_or_else(|| panic!("missing mixed-root manifest graphSliceId evidence"));
        *graph_slice_evidence =
            EndpointReceiptEvidence::hashed("graphSliceId", &mixed_root_graph_slice_id);
        mixed_root_decision.signer.signer_public_key =
            Some(mixed_root_keypair.public_key().to_hex());
        mixed_root_archive.receipts[mixed_root_manifest_receipt_index] = mixed_root_decision
            .sign_with(&mixed_root_keypair)
            .unwrap_or_else(|e| panic!("failed to sign mixed-root receipt: {e}"));
        let mixed_root_verification = evidence_bundle_archive_verification(&mixed_root_archive)
            .unwrap_or_else(|e| panic!("failed to verify mixed-root archive: {e}"));
        assert_eq!(mixed_root_verification.verified, false);
        assert_eq!(mixed_root_verification.receipt_ids_unique, true);
        assert_eq!(mixed_root_verification.receipt_signatures_valid, true);
        assert_eq!(mixed_root_verification.receipt_signers_consistent, true);
        assert_eq!(
            mixed_root_verification.receipts_bind_endpoint_decision,
            true
        );
        assert_eq!(
            mixed_root_verification.receipts_bind_endpoint_identity,
            true
        );
        assert_eq!(mixed_root_verification.receipts_bind_root_node, false);
        assert_eq!(mixed_root_verification.receipt_root_node_ids.len(), 2);
        assert!(
            mixed_root_verification
                .receipt_failures
                .iter()
                .any(|failure| failure == "receipt_root_node_continuity_mismatch:2"),
            "missing root-node continuity failure: {:?}",
            mixed_root_verification.receipt_failures
        );
        let mut mixed_signer_archive = collect_archive.clone();
        let request_receipt_index = mixed_signer_archive
            .receipts
            .iter()
            .position(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"])
                    == Some("response_request")
            })
            .unwrap_or_else(|| panic!("missing mixed-signer archive request receipt index"));
        let mixed_signer_keypair = Keypair::from_seed(&[72u8; 32]);
        let mut mixed_signer_endpoint_decision: EndpointDecisionReceipt = serde_json::from_value(
            mixed_signer_archive.receipts[request_receipt_index]
                .receipt
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.get("endpointDecision"))
                .cloned()
                .unwrap_or_else(|| {
                    panic!("missing mixed-signer request endpointDecision metadata")
                }),
        )
        .unwrap_or_else(|e| panic!("failed to decode mixed-signer endpoint decision: {e}"));
        mixed_signer_endpoint_decision.signer.signer_public_key =
            Some(mixed_signer_keypair.public_key().to_hex());
        mixed_signer_archive.receipts[request_receipt_index] = mixed_signer_endpoint_decision
            .sign_with(&mixed_signer_keypair)
            .unwrap_or_else(|e| panic!("failed to sign mixed-signer receipt: {e}"));
        let mixed_signer_verification = evidence_bundle_archive_verification(&mixed_signer_archive)
            .unwrap_or_else(|e| panic!("failed to verify mixed-signer archive: {e}"));
        assert_eq!(mixed_signer_verification.verified, false);
        assert_eq!(mixed_signer_verification.receipt_ids_unique, true);
        assert_eq!(mixed_signer_verification.receipt_signatures_valid, true);
        assert_eq!(mixed_signer_verification.receipt_signers_consistent, false);
        assert!(
            mixed_signer_verification
                .receipt_failures
                .iter()
                .any(|failure| failure == "receipt_signer_continuity_mismatch:2"),
            "missing signer continuity failure: {:?}",
            mixed_signer_verification.receipt_failures
        );
        let mut wrong_count_archive = collect_archive.clone();
        let manifest_receipt_index = wrong_count_archive
            .receipts
            .iter()
            .position(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"])
                    == Some("evidence_bundle_manifest")
            })
            .unwrap_or_else(|| panic!("missing wrong-count archive manifest receipt index"));
        let wrong_node_count_hash = sha256(b"0").to_hex_prefixed();
        let manifest_metadata = wrong_count_archive.receipts[manifest_receipt_index]
            .receipt
            .metadata
            .as_mut()
            .and_then(|metadata| metadata.get_mut("endpointDecision"))
            .unwrap_or_else(|| panic!("missing wrong-count manifest endpointDecision metadata"));
        let manifest_evidence = manifest_metadata
            .get_mut("evidence")
            .and_then(Value::as_array_mut)
            .unwrap_or_else(|| panic!("missing wrong-count manifest evidence"));
        let node_count_evidence = manifest_evidence
            .iter_mut()
            .find(|item| item.get("key").and_then(Value::as_str) == Some("nodeCount"))
            .unwrap_or_else(|| panic!("missing wrong-count manifest nodeCount evidence"));
        node_count_evidence["valueHash"] = Value::String(wrong_node_count_hash);
        let wrong_count_verification = evidence_bundle_archive_verification(&wrong_count_archive)
            .unwrap_or_else(|e| panic!("failed to verify wrong-count manifest archive: {e}"));
        assert_eq!(wrong_count_verification.verified, false);
        assert_eq!(wrong_count_verification.receipt_signatures_valid, false);
        assert_eq!(wrong_count_verification.receipts_bind_bundle_id, true);
        assert_eq!(wrong_count_verification.receipts_bind_graph_slice, true);
        assert_eq!(wrong_count_verification.receipts_bind_content_hash, true);
        assert_eq!(
            wrong_count_verification.required_receipt_families_present,
            true
        );
        assert_eq!(wrong_count_verification.graph_counts_match, false);
        assert!(
            wrong_count_verification
                .receipt_failures
                .iter()
                .any(|failure| failure.contains(":node_count_mismatch:")),
            "missing node-count mismatch failure: {:?}",
            wrong_count_verification.receipt_failures
        );
        assert!(
            wrong_count_verification
                .receipt_failures
                .iter()
                .any(|failure| failure.contains(":signature_invalid")),
            "missing signature failure for tampered manifest receipt: {:?}",
            wrong_count_verification.receipt_failures
        );
        let mut wrong_execution_hash_archive = collect_archive.clone();
        let execution_receipt_index = wrong_execution_hash_archive
            .receipts
            .iter()
            .position(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"])
                    == Some("response_execution")
            })
            .unwrap_or_else(|| panic!("missing wrong-content archive execution receipt index"));
        let wrong_content_hash = sha256(b"wrong-content-hash").to_hex_prefixed();
        let execution_metadata = wrong_execution_hash_archive.receipts[execution_receipt_index]
            .receipt
            .metadata
            .as_mut()
            .and_then(|metadata| metadata.get_mut("endpointDecision"))
            .unwrap_or_else(|| panic!("missing wrong-content execution endpointDecision metadata"));
        let execution_evidence = execution_metadata
            .get_mut("evidence")
            .and_then(Value::as_array_mut)
            .unwrap_or_else(|| panic!("missing wrong-content execution evidence"));
        let bundle_content_hash_evidence = execution_evidence
            .iter_mut()
            .find(|item| {
                item.get("key").and_then(Value::as_str) == Some("evidenceBundleContentHash")
            })
            .unwrap_or_else(|| {
                panic!("missing wrong-content execution evidenceBundleContentHash evidence")
            });
        bundle_content_hash_evidence["valueHash"] = Value::String(wrong_content_hash);
        let wrong_execution_hash_verification = evidence_bundle_archive_verification(
            &wrong_execution_hash_archive,
        )
        .unwrap_or_else(|e| panic!("failed to verify wrong-content execution archive: {e}"));
        assert_eq!(wrong_execution_hash_verification.verified, false);
        assert_eq!(
            wrong_execution_hash_verification.receipt_signatures_valid,
            false
        );
        assert_eq!(
            wrong_execution_hash_verification.receipts_bind_bundle_id,
            true
        );
        assert_eq!(
            wrong_execution_hash_verification.receipts_bind_graph_slice,
            true
        );
        assert_eq!(
            wrong_execution_hash_verification.receipts_bind_content_hash,
            false
        );
        assert!(
            wrong_execution_hash_verification
                .receipt_failures
                .iter()
                .any(|failure| failure.contains(":content_hash_mismatch:")),
            "missing execution content-hash mismatch failure: {:?}",
            wrong_execution_hash_verification.receipt_failures
        );
        let mut wrong_actor_archive = collect_archive.clone();
        let request_receipt_index = wrong_actor_archive
            .receipts
            .iter()
            .position(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"])
                    == Some("response_request")
            })
            .unwrap_or_else(|| panic!("missing wrong-actor archive request receipt index"));
        let wrong_actor_hash = sha256(b"wrong-actor-hash").to_hex_prefixed();
        let request_metadata = wrong_actor_archive.receipts[request_receipt_index]
            .receipt
            .metadata
            .as_mut()
            .and_then(|metadata| metadata.get_mut("endpointDecision"))
            .unwrap_or_else(|| panic!("missing wrong-actor request endpointDecision metadata"));
        let request_evidence = request_metadata
            .get_mut("evidence")
            .and_then(Value::as_array_mut)
            .unwrap_or_else(|| panic!("missing wrong-actor request evidence"));
        let actor_hash_evidence = request_evidence
            .iter_mut()
            .find(|item| item.get("key").and_then(Value::as_str) == Some("actorHash"))
            .unwrap_or_else(|| panic!("missing wrong-actor request actorHash evidence"));
        actor_hash_evidence["valueHash"] = Value::String(wrong_actor_hash);
        let wrong_actor_verification = evidence_bundle_archive_verification(&wrong_actor_archive)
            .unwrap_or_else(|e| panic!("failed to verify wrong-actor archive: {e}"));
        assert_eq!(wrong_actor_verification.verified, false);
        assert_eq!(wrong_actor_verification.receipt_signatures_valid, false);
        assert_eq!(wrong_actor_verification.receipts_bind_actor, false);
        assert_eq!(wrong_actor_verification.receipts_bind_bundle_id, true);
        assert_eq!(wrong_actor_verification.receipts_bind_graph_slice, true);
        assert_eq!(wrong_actor_verification.receipts_bind_content_hash, true);
        assert!(
            wrong_actor_verification
                .receipt_failures
                .iter()
                .any(|failure| failure.contains(":actor_hash_mismatch:")),
            "missing actor hash mismatch failure: {:?}",
            wrong_actor_verification.receipt_failures
        );
        let mut wrong_policy_archive = collect_archive.clone();
        let request_receipt_index = wrong_policy_archive
            .receipts
            .iter()
            .position(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"])
                    == Some("response_request")
            })
            .unwrap_or_else(|| panic!("missing wrong-policy archive request receipt index"));
        let request_metadata = wrong_policy_archive.receipts[request_receipt_index]
            .receipt
            .metadata
            .as_mut()
            .and_then(|metadata| metadata.get_mut("endpointDecision"))
            .unwrap_or_else(|| panic!("missing wrong-policy request endpointDecision metadata"));
        request_metadata["policy"]["policyHash"] =
            Value::String("0x0000000000000000000000000000000000000000".to_string());
        let wrong_policy_verification = evidence_bundle_archive_verification(&wrong_policy_archive)
            .unwrap_or_else(|e| panic!("failed to verify wrong-policy archive: {e}"));
        assert_eq!(wrong_policy_verification.verified, false);
        assert_eq!(wrong_policy_verification.receipt_signatures_valid, false);
        assert_eq!(wrong_policy_verification.receipts_bind_policy, false);
        assert_eq!(wrong_policy_verification.receipts_bind_sensor_state, true);
        assert_eq!(wrong_policy_verification.receipts_bind_actor, true);
        assert!(
            wrong_policy_verification
                .receipt_failures
                .iter()
                .any(|failure| failure.contains("policy_continuity_mismatch")),
            "missing policy continuity failure: {:?}",
            wrong_policy_verification.receipt_failures
        );
        let mut wrong_sensor_archive = collect_archive.clone();
        let request_receipt_index = wrong_sensor_archive
            .receipts
            .iter()
            .position(|receipt| {
                receipt_endpoint_decision_str(receipt, &["receiptFamily"])
                    == Some("response_request")
            })
            .unwrap_or_else(|| panic!("missing wrong-sensor archive request receipt index"));
        let request_metadata = wrong_sensor_archive.receipts[request_receipt_index]
            .receipt
            .metadata
            .as_mut()
            .and_then(|metadata| metadata.get_mut("endpointDecision"))
            .unwrap_or_else(|| panic!("missing wrong-sensor request endpointDecision metadata"));
        request_metadata["sensorState"]["providers"] = Value::Array(Vec::new());
        let wrong_sensor_verification = evidence_bundle_archive_verification(&wrong_sensor_archive)
            .unwrap_or_else(|e| panic!("failed to verify wrong-sensor archive: {e}"));
        assert_eq!(wrong_sensor_verification.verified, false);
        assert_eq!(wrong_sensor_verification.receipt_signatures_valid, false);
        assert_eq!(wrong_sensor_verification.receipts_bind_sensor_state, false);
        assert_eq!(wrong_sensor_verification.receipts_bind_policy, true);
        assert_eq!(wrong_sensor_verification.receipts_bind_actor, true);
        assert!(
            wrong_sensor_verification
                .receipt_failures
                .iter()
                .any(|failure| failure.contains(":sensor_state_missing_providers")),
            "missing sensor-state provider failure: {:?}",
            wrong_sensor_verification.receipt_failures
        );

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build execution proof request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("execution proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read execution proof response: {e}"));
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected execution proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let proof_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode execution proof response: {e}"));
        assert_eq!(
            proof_payload["execution"]["execution"]["executionId"],
            execution_id
        );
        assert_eq!(
            proof_payload["requestReceipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_request"
        );
        assert_eq!(
            proof_payload["requestReceipt"]["receipt"]["metadata"]["endpointDecision"]["decision"]
                ["findingId"],
            payload["plan"]["actionId"]
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
            proof_payload["evidenceBundleArtifact"]["contentHash"],
            payload["execution"]["evidenceBundle"]["contentHash"]
        );
        assert!(
            proof_payload["evidenceBundleArtifact"]["byteCount"]
                .as_u64()
                .unwrap_or_default()
                > 0
        );
        let proof_providers = proof_payload["providerState"]["providers"]
            .as_array()
            .unwrap_or_else(|| panic!("missing proof provider state"));
        assert!(proof_providers
            .iter()
            .any(|provider| provider["providerId"] == "agent-api"));
        assert!(proof_providers
            .iter()
            .any(|provider| provider["providerId"] == "macos.endpoint_security"));
        assert!(proof_providers
            .iter()
            .any(|provider| provider["providerId"] == "macos.network_extension"));
        assert_eq!(
            proof_payload["graph"]["graphSliceId"],
            bundle_decision["graph"]["graphSliceId"]
        );
        assert_eq!(proof_payload["affectedIdentityCount"].as_u64(), Some(6));
        assert_eq!(proof_payload["affectedToolCount"].as_u64(), Some(1));
        assert_eq!(
            proof_payload["affectedIdentities"]["hosts"][0]["id"],
            "host-collect-1"
        );
        assert_eq!(
            proof_payload["affectedIdentities"]["users"][0]["id"],
            "alice"
        );
        assert_eq!(
            proof_payload["affectedIdentities"]["sessions"][0]["id"],
            "session-collect-1"
        );
        assert_eq!(
            proof_payload["affectedIdentities"]["agents"][0]["id"],
            "agent-collect-1"
        );
        assert_eq!(
            proof_payload["affectedIdentities"]["workloads"][0]["id"],
            "workload-collect-1"
        );
        assert_eq!(
            proof_payload["affectedIdentities"]["approvals"][0]["id"],
            "approval-collect-1"
        );
        assert_eq!(proof_payload["affectedTools"][0]["toolName"], "mcp.shell");

        let original_execution = {
            let ledger = state.edr_response_execution_ledger.lock().await;
            ledger
                .get(execution_id)
                .unwrap_or_else(|e| panic!("failed to read original response execution: {e}"))
                .unwrap_or_else(|| panic!("missing original response execution"))
        };
        let mut actor_mismatched_execution = original_execution.clone();
        actor_mismatched_execution
            .actor
            .as_mut()
            .unwrap_or_else(|| panic!("missing response execution actor"))
            .user_id = Some("operator:other".to_string());
        {
            let mut ledger = state.edr_response_execution_ledger.lock().await;
            ledger
                .append(&actor_mismatched_execution)
                .unwrap_or_else(|e| panic!("failed to append actor-mismatched execution: {e}"));
        }
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| {
                panic!("failed to build actor-mismatched execution proof request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("actor-mismatched execution proof request failed: {e}"));
        let mismatch_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read actor-mismatched execution proof response: {e}")
            });
        assert_eq!(
            mismatch_status,
            StatusCode::CONFLICT,
            "unexpected actor-mismatched execution proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        assert!(String::from_utf8_lossy(&bytes).contains("actor"));
        {
            let mut ledger = state.edr_response_execution_ledger.lock().await;
            ledger
                .append(&original_execution)
                .unwrap_or_else(|e| panic!("failed to restore original response execution: {e}"));
        }

        let body = serde_json::json!({
            "acknowledgedBy": "operator:test",
            "note": "operator reviewed collect evidence outcome"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/acknowledge"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build execution acknowledgement request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("execution acknowledgement request failed: {e}"));
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read execution acknowledgement response: {e}"));
        assert_eq!(
            status,
            StatusCode::OK,
            "unexpected execution acknowledgement response body: {}",
            String::from_utf8_lossy(&bytes)
        );
        let acknowledgement_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode execution acknowledgement response: {e}"));
        assert_eq!(
            acknowledgement_payload["receipt"]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "response_acknowledgement"
        );

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| {
                panic!("failed to build acknowledged execution proof request: {e}")
            });
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("acknowledged execution proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| {
                panic!("failed to read acknowledged execution proof response: {e}")
            });
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected acknowledged execution proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let acknowledged_proof_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| {
                panic!("failed to decode acknowledged execution proof response: {e}")
            });
        let acknowledgement_receipts = acknowledged_proof_payload["acknowledgementReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing acknowledged proof acknowledgement receipts"));
        assert_eq!(acknowledgement_receipts.len(), 1);
        let acknowledgement_decision =
            &acknowledgement_receipts[0]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(
            acknowledgement_decision["receiptFamily"],
            "response_acknowledgement"
        );
        assert_eq!(
            acknowledgement_decision["decision"]["action"],
            payload["execution"]["action"]
        );
        assert_eq!(
            acknowledgement_decision["decision"]["rollbackRef"],
            payload["execution"]["rollbackRef"]
        );
        let acknowledgement_evidence = acknowledgement_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing acknowledgement receipt evidence"));
        assert!(acknowledgement_evidence
            .iter()
            .any(|item| item["key"] == "acknowledgementId"));
        assert!(acknowledgement_evidence
            .iter()
            .any(|item| item["key"] == "executionId"));
        assert!(acknowledgement_evidence
            .iter()
            .any(|item| item["key"] == "responseActionId"));

        let body = serde_json::json!({
            "reason": "operator closed the local response window"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/cancel"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build execution cancel request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("execution cancel request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read execution cancel response: {e}"));
        let cancel_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode execution cancel response: {e}"));
        assert_eq!(
            cancel_payload["execution"]["execution"]["status"],
            "cancelled"
        );
        assert_eq!(
            cancel_payload["execution"]["rollbackRef"],
            payload["execution"]["rollbackRef"]
        );

        let cancel_receipt: SignedReceipt =
            serde_json::from_value(cancel_payload["receipt"].clone())
                .unwrap_or_else(|e| panic!("failed to decode cancellation receipt: {e}"));
        let cancel_decision = cancel_receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing cancellation endpointDecision metadata"));
        let public_key = cancel_decision
            .get("signer")
            .and_then(|signer| signer.get("signerPublicKey"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("missing cancellation receipt signer public key"));
        let public_key = hush_core::PublicKey::from_hex(public_key)
            .unwrap_or_else(|e| panic!("failed to parse cancellation receipt public key: {e}"));
        let verification =
            cancel_receipt.verify(&hush_core::receipt::PublicKeySet::new(public_key));
        assert!(verification.valid);
        assert_eq!(cancel_decision["receiptFamily"], "response_execution");
        assert_eq!(cancel_decision["actor"]["userId"], "operator:test");
        assert_eq!(
            cancel_decision["actor"]["approvalId"],
            "approval-response-action"
        );
        assert_eq!(
            cancel_decision["decision"]["title"],
            "Endpoint response action cancelled"
        );
        assert_eq!(
            cancel_decision["decision"]["rollbackRef"],
            payload["execution"]["rollbackRef"]
        );
        assert_eq!(
            cancel_decision["decision"]["passed"],
            serde_json::Value::Bool(false)
        );

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build cancelled execution proof request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("cancelled execution proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read cancelled execution proof response: {e}"));
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected cancelled execution proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let cancelled_proof_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode cancelled execution proof response: {e}"));
        let transition_receipts = cancelled_proof_payload["transitionReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing cancelled proof transition receipts"));
        assert_eq!(transition_receipts.len(), 1);
        let transition_decision =
            &transition_receipts[0]["receipt"]["metadata"]["endpointDecision"];
        assert_eq!(transition_decision["receiptFamily"], "response_execution");
        assert_eq!(
            transition_decision["decision"]["title"],
            "Endpoint response action cancelled"
        );
        assert_eq!(
            transition_decision["decision"]["rollbackRef"],
            payload["execution"]["rollbackRef"]
        );
        assert_eq!(
            cancelled_proof_payload["rollbackReceipts"]
                .as_array()
                .unwrap_or_else(|| panic!("missing cancelled proof rollback receipts"))
                .len(),
            0
        );
        assert_eq!(
            cancelled_proof_payload["acknowledgementReceipts"]
                .as_array()
                .unwrap_or_else(|| panic!("missing cancelled proof acknowledgement receipts"))
                .len(),
            1
        );

        let _ = std::fs::remove_file(receipt_path);
        let _ = std::fs::remove_file(execution_path);
    }

