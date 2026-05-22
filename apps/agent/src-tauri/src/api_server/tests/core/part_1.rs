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

