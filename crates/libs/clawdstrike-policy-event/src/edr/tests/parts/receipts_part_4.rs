#[test]
fn endpoint_collect_evidence_acknowledgement_receipt_rejects_effects() {
    let event = observation(EndpointEvent::NetworkFlow {
        host: "ack-effect.example".to_string(),
        port: 443,
        protocol: Some("tcp".to_string()),
        url: Some("https://ack-effect.example/upload".to_string()),
    });
    let mut graph_recorder = CausalGraphRecorder::new();
    graph_recorder.record_observation(&event);
    let process_node_id = event.process.stable_node_id();
    let subgraph = graph_recorder
        .graph()
        .causal_subgraph_from(&process_node_id, 3)
        .unwrap();
    let plan = EndpointResponsePlan::collect_evidence_execution(
        &process_node_id,
        &subgraph,
        600,
        "collect evidence graph slice",
    );
    let execution = EndpointResponseExecutionReport::collect_evidence(&plan, &subgraph)
        .unwrap_or_else(|err| panic!("failed to collect evidence report: {err}"));
    let acknowledgement = EndpointResponseAcknowledgementReport::from_execution(
        &execution,
        "operator:test",
        Some("reviewed collect evidence".to_string()),
        execution.completed_at + chrono::Duration::seconds(5),
    );
    let receipt = EndpointDecisionReceipt::for_response_acknowledgement(
        EndpointResponseAcknowledgementReceiptInput {
            local_sequence: 38,
            endpoint_id: "endpoint-1",
            signer_identity: "local-edr:endpoint-1",
            actor: response_actor("endpoint-1"),
            policy: EndpointPolicySnapshot {
                policy_version: "test-policy@1".to_string(),
                policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                policy_epoch: 7,
            },
            sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
            acknowledgement: &acknowledgement,
            graph: &subgraph,
        },
    );

    receipt.validate().unwrap();
    assert_eq!(
        receipt.decision.action,
        EndpointDecisionAction::CollectEvidence
    );
    assert!(!receipt
        .evidence
        .iter()
        .any(|item| item.key.starts_with("acknowledgementEffect:")));

    let mut injected_effect = receipt;
    injected_effect
        .evidence
        .push(EndpointReceiptEvidence::hashed(
            "acknowledgementEffect:effect:fake",
            "collect_evidence:fake_effect",
        ));
    if let Some(effect_count_evidence) = injected_effect
        .evidence
        .iter_mut()
        .find(|item| item.key == "effectCount")
    {
        *effect_count_evidence = EndpointReceiptEvidence::hashed("effectCount", "1");
    }
    let response_action_id = response_action_id_from_signed_response_fields(
        injected_effect.graph.process_node_id.as_deref().unwrap(),
        injected_effect.graph.graph_slice_id.as_deref().unwrap(),
        &injected_effect.decision.action,
        injected_effect.decision.ttl_seconds.unwrap(),
    );
    let acknowledgement_id = response_acknowledgement_id_from_signed_evidence(
        &injected_effect.evidence,
        response_action_id.as_str(),
        injected_effect.decision.rollback_ref.as_deref().unwrap(),
        injected_effect.actor.agent_id.as_deref().unwrap(),
    )
    .unwrap();
    injected_effect.decision.finding_id = Some(acknowledgement_id.clone());
    if let Some(acknowledgement_id_evidence) = injected_effect
        .evidence
        .iter_mut()
        .find(|item| item.key == "acknowledgementId")
    {
        *acknowledgement_id_evidence =
            EndpointReceiptEvidence::hashed("acknowledgementId", acknowledgement_id);
    }
    assert!(injected_effect
        .validate()
        .unwrap_err()
        .to_string()
        .contains("collect evidence acknowledgement effect evidence"));
}

#[test]
fn endpoint_response_acknowledgement_receipt_requires_effects_for_successful_non_collect() {
    let event = observation(EndpointEvent::FileAccess {
        operation: FileOperation::Write,
        path: "/tmp/clawdstrike-ack-malware.sh".to_string(),
        source_url: None,
        content_preview: None,
    });
    let mut graph_recorder = CausalGraphRecorder::new();
    graph_recorder.record_observation(&event);
    let file_node_id = graph_recorder
        .graph()
        .nodes
        .values()
        .find(|node| node.kind == CausalNodeKind::File)
        .map(|node| node.node_id.clone())
        .unwrap_or_else(|| panic!("missing file node"));
    let subgraph = graph_recorder
        .graph()
        .causal_subgraph_from(&file_node_id, 3)
        .unwrap();
    let plan = EndpointResponsePlan::quarantine_file_execution(
        &file_node_id,
        &subgraph,
        600,
        "quarantine suspicious file",
    );
    let execution = EndpointResponseExecutionReport::quarantine_file(
        &plan,
        &subgraph,
        "/tmp/clawdstrike-ack-malware.sh",
        "/tmp/clawdstrike-quarantine/clawdstrike-ack-malware.sh.quarantine",
        "0xabc123",
        128,
    )
    .unwrap_or_else(|err| panic!("failed to build quarantine execution report: {err}"));
    let acknowledgement = EndpointResponseAcknowledgementReport::from_execution(
        &execution,
        "operator:test",
        Some("reviewed quarantine".to_string()),
        execution.completed_at + chrono::Duration::seconds(5),
    );
    let receipt = EndpointDecisionReceipt::for_response_acknowledgement(
        EndpointResponseAcknowledgementReceiptInput {
            local_sequence: 39,
            endpoint_id: "endpoint-1",
            signer_identity: "local-edr:endpoint-1",
            actor: response_actor("endpoint-1"),
            policy: EndpointPolicySnapshot {
                policy_version: "test-policy@1".to_string(),
                policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                policy_epoch: 7,
            },
            sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
            acknowledgement: &acknowledgement,
            graph: &subgraph,
        },
    );

    receipt.validate().unwrap();
    assert_eq!(
        receipt.decision.action,
        EndpointDecisionAction::QuarantineFile
    );
    assert!(receipt.decision.passed);
    assert_eq!(acknowledgement.effects.len(), 1);
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key.starts_with("acknowledgementEffect:")));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key.starts_with("acknowledgementEffectType:")));

    let mut missing_effect_type = receipt.clone();
    missing_effect_type
        .evidence
        .retain(|item| !item.key.starts_with("acknowledgementEffectType:"));
    assert!(missing_effect_type
        .validate()
        .unwrap_err()
        .to_string()
        .contains("acknowledgement effect type evidence"));

    let mut mismatched_effect_type = receipt.clone();
    if let Some(effect_type_evidence) = mismatched_effect_type
        .evidence
        .iter_mut()
        .find(|item| item.key.starts_with("acknowledgementEffectType:"))
    {
        let key = effect_type_evidence.key.clone();
        *effect_type_evidence = EndpointReceiptEvidence::hashed(key, "disable_persistence");
    }
    assert!(mismatched_effect_type
        .validate()
        .unwrap_err()
        .to_string()
        .contains("acknowledgement effect type evidence hash"));

    let mut dropped_effect_evidence = receipt;
    dropped_effect_evidence
        .evidence
        .retain(|item| !item.key.starts_with("acknowledgementEffect:"));
    if let Some(effect_count_evidence) = dropped_effect_evidence
        .evidence
        .iter_mut()
        .find(|item| item.key == "effectCount")
    {
        *effect_count_evidence = EndpointReceiptEvidence::hashed("effectCount", "0");
    }
    assert!(dropped_effect_evidence
        .validate()
        .unwrap_err()
        .to_string()
        .contains("acknowledgement effect evidence"));
}

#[test]
fn endpoint_response_acknowledgement_receipt_binds_effect_digest() {
    let event = observation(EndpointEvent::FileAccess {
        operation: FileOperation::Write,
        path: "/tmp/clawdstrike-ack-effect-malware.sh".to_string(),
        source_url: None,
        content_preview: None,
    });
    let mut graph_recorder = CausalGraphRecorder::new();
    graph_recorder.record_observation(&event);
    let file_node_id = graph_recorder
        .graph()
        .nodes
        .values()
        .find(|node| node.kind == CausalNodeKind::File)
        .map(|node| node.node_id.clone())
        .unwrap_or_else(|| panic!("missing file node"));
    let subgraph = graph_recorder
        .graph()
        .causal_subgraph_from(&file_node_id, 3)
        .unwrap();
    let plan = EndpointResponsePlan::quarantine_file_execution(
        &file_node_id,
        &subgraph,
        600,
        "quarantine suspicious file",
    );
    let execution = EndpointResponseExecutionReport::quarantine_file(
        &plan,
        &subgraph,
        "/tmp/clawdstrike-ack-effect-malware.sh",
        "/tmp/clawdstrike-quarantine/clawdstrike-ack-effect-malware.sh.quarantine",
        "0xabc123",
        128,
    )
    .unwrap_or_else(|err| panic!("failed to build quarantine execution report: {err}"));
    let acknowledgement = EndpointResponseAcknowledgementReport::from_execution(
        &execution,
        "operator:test",
        Some("reviewed quarantine effect".to_string()),
        execution.completed_at + chrono::Duration::seconds(5),
    );
    let receipt = EndpointDecisionReceipt::for_response_acknowledgement(
        EndpointResponseAcknowledgementReceiptInput {
            local_sequence: 40,
            endpoint_id: "endpoint-1",
            signer_identity: "local-edr:endpoint-1",
            actor: response_actor("endpoint-1"),
            policy: EndpointPolicySnapshot {
                policy_version: "test-policy@1".to_string(),
                policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                policy_epoch: 7,
            },
            sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
            acknowledgement: &acknowledgement,
            graph: &subgraph,
        },
    );

    receipt.validate().unwrap();
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key.starts_with("acknowledgementEffect:")));

    let mut substituted_effect = receipt;
    if let Some(effect_evidence) = substituted_effect
        .evidence
        .iter_mut()
        .find(|item| item.key.starts_with("acknowledgementEffect:"))
    {
        let effect_key = effect_evidence.key.clone();
        *effect_evidence = EndpointReceiptEvidence::hashed(effect_key, "quarantine_file:other");
    }
    assert!(substituted_effect
        .validate()
        .unwrap_err()
        .to_string()
        .contains("acknowledgement execution id evidence hash"));
}

#[test]
fn endpoint_response_execution_expiration_receipt_binds_ttl_and_rollback() {
    let event = observation(EndpointEvent::NetworkFlow {
        host: "expire.example".to_string(),
        port: 443,
        protocol: Some("tcp".to_string()),
        url: Some("https://expire.example/upload".to_string()),
    });
    let mut graph_recorder = CausalGraphRecorder::new();
    graph_recorder.record_observation(&event);
    let process_node_id = event.process.stable_node_id();
    let subgraph = graph_recorder
        .graph()
        .causal_subgraph_from(&process_node_id, 3)
        .unwrap();
    let plan = EndpointResponsePlan::collect_evidence_execution(
        &process_node_id,
        &subgraph,
        1,
        "collect evidence graph slice",
    );
    let execution = EndpointResponseExecutionReport::collect_evidence(&plan, &subgraph)
        .unwrap_or_else(|err| panic!("failed to collect evidence report: {err}"));
    let expired = EndpointResponseExecutionReport::expired_from(&execution, execution.expires_at());
    let keypair = hush_core::Keypair::from_seed(&[19u8; 32]);
    let mut receipt =
        EndpointDecisionReceipt::for_response_execution(EndpointResponseExecutionReceiptInput {
            local_sequence: 19,
            endpoint_id: "endpoint-1",
            signer_identity: "local-edr:endpoint-1",
            actor: response_actor("endpoint-1"),
            policy: EndpointPolicySnapshot {
                policy_version: "test-policy@1".to_string(),
                policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                policy_epoch: 7,
            },
            sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
            execution: &expired,
            graph: &subgraph,
        });
    receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

    let signed = receipt.sign_with(&keypair).unwrap();
    let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

    assert!(verification.valid);
    assert_eq!(
        receipt.receipt_family,
        EndpointDecisionReceiptFamily::ResponseExecution
    );
    assert_eq!(receipt.decision.finding_id, Some(expired.execution_id));
    assert_eq!(
        receipt.decision.action,
        EndpointDecisionAction::CollectEvidence
    );
    assert!(!receipt.decision.passed);
    assert_eq!(
        receipt.decision.rollback_ref.as_deref(),
        Some(plan.rollback_ref.as_str())
    );
    assert_eq!(receipt.decision.ttl_seconds, Some(1));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "executionStatus"));
}

#[test]
fn endpoint_response_execution_cancellation_receipt_binds_reason_ttl_and_rollback() {
    let event = observation(EndpointEvent::NetworkFlow {
        host: "cancel.example".to_string(),
        port: 443,
        protocol: Some("tcp".to_string()),
        url: Some("https://cancel.example/upload".to_string()),
    });
    let mut graph_recorder = CausalGraphRecorder::new();
    graph_recorder.record_observation(&event);
    let process_node_id = event.process.stable_node_id();
    let subgraph = graph_recorder
        .graph()
        .causal_subgraph_from(&process_node_id, 3)
        .unwrap();
    let plan = EndpointResponsePlan::collect_evidence_execution(
        &process_node_id,
        &subgraph,
        600,
        "collect evidence graph slice",
    );
    let execution = EndpointResponseExecutionReport::collect_evidence(&plan, &subgraph)
        .unwrap_or_else(|err| panic!("failed to collect evidence report: {err}"));
    let cancelled = EndpointResponseExecutionReport::cancelled_from(
        &execution,
        "operator closed the local response window",
        execution.completed_at + chrono::Duration::seconds(15),
    );
    let keypair = hush_core::Keypair::from_seed(&[23u8; 32]);
    let mut receipt =
        EndpointDecisionReceipt::for_response_execution(EndpointResponseExecutionReceiptInput {
            local_sequence: 23,
            endpoint_id: "endpoint-1",
            signer_identity: "local-edr:endpoint-1",
            actor: response_actor("endpoint-1"),
            policy: EndpointPolicySnapshot {
                policy_version: "test-policy@1".to_string(),
                policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                policy_epoch: 7,
            },
            sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
            execution: &cancelled,
            graph: &subgraph,
        });
    receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

    let signed = receipt.sign_with(&keypair).unwrap();
    let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

    assert!(verification.valid);
    assert_eq!(
        receipt.receipt_family,
        EndpointDecisionReceiptFamily::ResponseExecution
    );
    assert_eq!(receipt.decision.finding_id, Some(cancelled.execution_id));
    assert_eq!(
        receipt.decision.action,
        EndpointDecisionAction::CollectEvidence
    );
    assert!(!receipt.decision.passed);
    assert_eq!(
        receipt.decision.rollback_ref.as_deref(),
        Some(plan.rollback_ref.as_str())
    );
    assert_eq!(receipt.decision.ttl_seconds, Some(600));
    assert_eq!(
        receipt.decision.title.as_deref(),
        Some("Endpoint response action cancelled")
    );
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "executionStatus"));
    assert!(receipt.evidence.iter().any(|item| item.key == "reason"));

    let mut relabeled_cancellation_id = receipt.clone();
    relabeled_cancellation_id.decision.finding_id =
        Some("response_execution_cancelled:other".to_string());
    if let Some(execution_id_evidence) = relabeled_cancellation_id
        .evidence
        .iter_mut()
        .find(|item| item.key == "executionId")
    {
        *execution_id_evidence =
            EndpointReceiptEvidence::hashed("executionId", "response_execution_cancelled:other");
    }
    assert!(relabeled_cancellation_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("execution id evidence hash"));
}

#[test]
fn endpoint_graph_slice_receipt_binds_exported_subgraph() {
    let event = observation(EndpointEvent::FileAccess {
        operation: FileOperation::Read,
        path: "/Users/alice/.npmrc".to_string(),
        source_url: None,
        content_preview: None,
    });
    let mut graph_recorder = CausalGraphRecorder::new();
    graph_recorder.record_observation(&event);
    let process_node_id = event.process.stable_node_id();
    let subgraph = graph_recorder
        .graph()
        .causal_subgraph_from(&process_node_id, 3)
        .unwrap();
    let keypair = hush_core::Keypair::from_seed(&[17u8; 32]);
    let mut receipt = EndpointDecisionReceipt::for_graph_slice(EndpointGraphSliceReceiptInput {
        local_sequence: 16,
        endpoint_id: "endpoint-1",
        signer_identity: "local-edr:endpoint-1",
        policy: EndpointPolicySnapshot {
            policy_version: "test-policy@1".to_string(),
            policy_hash: sha256(b"test-policy").to_hex_prefixed(),
            policy_epoch: 7,
        },
        sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
        root_node_id: &process_node_id,
        slice_kind: "causal_subgraph",
        graph: &subgraph,
    });
    receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

    let signed = receipt.sign_with(&keypair).unwrap();
    let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

    assert!(verification.valid);
    assert_eq!(
        receipt.receipt_family,
        EndpointDecisionReceiptFamily::GraphSlice
    );
    assert_eq!(
        receipt.decision.finding_id.as_deref(),
        receipt.graph.graph_slice_id.as_deref()
    );
    assert_eq!(
        receipt.graph.process_node_id.as_deref(),
        Some(process_node_id.as_str())
    );
    assert!(receipt.evidence.iter().any(|item| item.key == "sliceKind"));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "contentHash"));

    let mut mismatched_content_hash = receipt.clone();
    if let Some(content_hash_evidence) = mismatched_content_hash
        .evidence
        .iter_mut()
        .find(|item| item.key == "contentHash")
    {
        *content_hash_evidence = EndpointReceiptEvidence::hashed("contentHash", "sha256:other");
    }
    assert!(mismatched_content_hash
        .validate()
        .unwrap_err()
        .to_string()
        .contains("graph slice content hash evidence hash"));

    let mut mismatched_root_evidence = receipt.clone();
    if let Some(root_node_evidence) = mismatched_root_evidence
        .evidence
        .iter_mut()
        .find(|item| item.key == "rootNodeId")
    {
        *root_node_evidence = EndpointReceiptEvidence::hashed("rootNodeId", "node:other");
    }
    assert!(mismatched_root_evidence
        .validate()
        .unwrap_err()
        .to_string()
        .contains("graph slice root node evidence hash"));

    let mut mismatched_node_count = receipt.clone();
    if let Some(node_count_evidence) = mismatched_node_count
        .evidence
        .iter_mut()
        .find(|item| item.key == "nodeCount")
    {
        *node_count_evidence = EndpointReceiptEvidence::hashed("nodeCount", "0");
    }
    assert!(mismatched_node_count
        .validate()
        .unwrap_err()
        .to_string()
        .contains("graph slice node count evidence hash"));

    let mut mismatched_root_reference = receipt.clone();
    mismatched_root_reference.graph.process_node_id = Some("node:other".to_string());
    if let Some(root_node_evidence) = mismatched_root_reference
        .evidence
        .iter_mut()
        .find(|item| item.key == "rootNodeId")
    {
        *root_node_evidence = EndpointReceiptEvidence::hashed("rootNodeId", "node:other");
    }
    assert!(mismatched_root_reference
        .validate()
        .unwrap_err()
        .to_string()
        .contains("graph slice graph root reference"));

    let mut mismatched_graph_slice_reference = receipt.clone();
    mismatched_graph_slice_reference.graph.graph_slice_id = Some("graph_slice:other".to_string());
    if let Some(graph_slice_evidence) = mismatched_graph_slice_reference
        .evidence
        .iter_mut()
        .find(|item| item.key == "graphSliceId")
    {
        *graph_slice_evidence =
            EndpointReceiptEvidence::hashed("graphSliceId", "graph_slice:other");
    }
    assert!(mismatched_graph_slice_reference
        .validate()
        .unwrap_err()
        .to_string()
        .contains("graph slice graph slice reference"));
}

#[test]
fn endpoint_policy_delta_receipt_binds_delta_artifact_and_graph() {
    let keypair = hush_core::Keypair::from_seed(&[31u8; 32]);
    let artifact_hash = sha256(b"policy-delta-artifact").to_hex_prefixed();
    let action = EndpointDecisionAction::Warn;
    let generated_at = "2026-05-17T12:00:00Z";
    let source_affected_identity_context = r#"[{"identityKind":"user","sourceNodeId":"node:user:alice","sourceNodeKind":"user","value":"alice"}]"#;
    let source_affected_tool_context = r#"[{"sourceNodeId":"node:tool:mcp.shell","toolCallId":"tool-call-1","toolName":"mcp.shell"}]"#;
    let policy_delta_id = endpoint_policy_delta_id(EndpointPolicyDeltaIdInput {
        endpoint_id: "endpoint-1",
        rule_id: "endpoint.policy_delta.test",
        action: &action,
        staged_detection_id: "staged_detection:test",
        stage: "audit",
        generated_at,
        simulation_id: "simulation:test",
        graph_slice_id: "graph_slice:test",
        root_node_id: "node:test",
        source_affected_identity_context,
        source_affected_tool_context,
    });
    let mut receipt = EndpointDecisionReceipt::for_policy_delta(EndpointPolicyDeltaReceiptInput {
        local_sequence: 31,
        endpoint_id: "endpoint-1",
        signer_identity: "local-edr:endpoint-1",
        actor: None,
        policy: EndpointPolicySnapshot {
            policy_version: "test-policy@1".to_string(),
            policy_hash: sha256(b"test-policy").to_hex_prefixed(),
            policy_epoch: 7,
        },
        sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
        operation: "generated",
        policy_delta_id: policy_delta_id.as_str(),
        staged_detection_id: "staged_detection:test",
        rule_id: "endpoint.policy_delta.test",
        stage: "audit",
        generated_at,
        action: action.clone(),
        artifact_hash: artifact_hash.as_str(),
        simulation_id: "simulation:test",
        graph_slice_id: "graph_slice:test",
        root_node_id: "node:test",
        source_affected_identity_context,
        source_affected_tool_context,
        cross_window_impact_hash: None,
        cross_window_recommendation_hash: None,
        previous_policy_hash: None,
        new_policy_hash: None,
        backup_path: None,
    });
    receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

    let signed = receipt.sign_with(&keypair).unwrap();
    let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

    assert!(verification.valid);
    assert_eq!(
        receipt.receipt_family,
        EndpointDecisionReceiptFamily::PolicyDelta
    );
    assert_eq!(
        receipt.decision.finding_id.as_deref(),
        Some(policy_delta_id.as_str())
    );

    let previous_policy_hash = sha256(b"test-policy").to_hex_prefixed();
    let prepared_policy_hash = sha256(b"test-policy-v2").to_hex_prefixed();
    let prepared_receipt =
        EndpointDecisionReceipt::for_policy_delta(EndpointPolicyDeltaReceiptInput {
            local_sequence: 33,
            endpoint_id: "endpoint-1",
            signer_identity: "local-edr:endpoint-1",
            actor: None,
            policy: EndpointPolicySnapshot {
                policy_version: "test-policy@2".to_string(),
                policy_hash: prepared_policy_hash.clone(),
                policy_epoch: 8,
            },
            sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
            operation: "prepared",
            policy_delta_id: policy_delta_id.as_str(),
            staged_detection_id: "staged_detection:test",
            rule_id: "endpoint.policy_delta.test",
            stage: "audit",
            generated_at,
            action,
            artifact_hash: artifact_hash.as_str(),
            simulation_id: "simulation:test",
            graph_slice_id: "graph_slice:test",
            root_node_id: "node:test",
            source_affected_identity_context,
            source_affected_tool_context,
            cross_window_impact_hash: None,
            cross_window_recommendation_hash: None,
            previous_policy_hash: Some(previous_policy_hash.as_str()),
            new_policy_hash: Some(prepared_policy_hash.as_str()),
            backup_path: Some("/tmp/policy.yaml.backup"),
        });
    assert!(prepared_receipt.validate().is_ok());
    assert_eq!(
        prepared_receipt.decision.title.as_deref(),
        Some("Endpoint staged policy delta prepared")
    );

    let terminate_delta_id = endpoint_policy_delta_id(EndpointPolicyDeltaIdInput {
        endpoint_id: "endpoint-1",
        rule_id: "endpoint.policy_delta.terminate",
        action: &EndpointDecisionAction::TerminateProcessTree,
        staged_detection_id: "staged_detection:terminate",
        stage: "limited_block",
        generated_at,
        simulation_id: "simulation:terminate",
        graph_slice_id: "graph_slice:terminate",
        root_node_id: "node:terminate",
        source_affected_identity_context,
        source_affected_tool_context,
    });
    let terminate_receipt =
        EndpointDecisionReceipt::for_policy_delta(EndpointPolicyDeltaReceiptInput {
            local_sequence: 32,
            endpoint_id: "endpoint-1",
            signer_identity: "local-edr:endpoint-1",
            actor: None,
            policy: EndpointPolicySnapshot {
                policy_version: "test-policy@1".to_string(),
                policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                policy_epoch: 7,
            },
            sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
            operation: "generated",
            policy_delta_id: terminate_delta_id.as_str(),
            staged_detection_id: "staged_detection:terminate",
            rule_id: "endpoint.policy_delta.terminate",
            stage: "limited_block",
            generated_at,
            action: EndpointDecisionAction::TerminateProcessTree,
            artifact_hash: artifact_hash.as_str(),
            simulation_id: "simulation:terminate",
            graph_slice_id: "graph_slice:terminate",
            root_node_id: "node:terminate",
            source_affected_identity_context,
            source_affected_tool_context,
            cross_window_impact_hash: None,
            cross_window_recommendation_hash: None,
            previous_policy_hash: None,
            new_policy_hash: None,
            backup_path: None,
        });
    assert!(terminate_receipt
        .validate()
        .unwrap_err()
        .to_string()
        .contains("rollback-capable policy action"));

    let mut mismatched_delta_id = receipt.clone();
    if let Some(delta_id_evidence) = mismatched_delta_id
        .evidence
        .iter_mut()
        .find(|item| item.key == "policyDeltaId")
    {
        *delta_id_evidence = EndpointReceiptEvidence::hashed("policyDeltaId", "policy_delta:other");
    }
    assert!(mismatched_delta_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy delta id evidence hash"));

    let mut relabeled_delta_id = receipt.clone();
    relabeled_delta_id.decision.finding_id = Some("policy_delta:other".to_string());
    if let Some(delta_id_evidence) = relabeled_delta_id
        .evidence
        .iter_mut()
        .find(|item| item.key == "policyDeltaId")
    {
        *delta_id_evidence = EndpointReceiptEvidence::hashed("policyDeltaId", "policy_delta:other");
    }
    assert!(relabeled_delta_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy delta id"));

    let mut relabeled_generated_as_applied = receipt.clone();
    relabeled_generated_as_applied.decision.title =
        Some("Endpoint staged policy delta applied".to_string());
    if let Some(operation_evidence) = relabeled_generated_as_applied
        .evidence
        .iter_mut()
        .find(|item| item.key == "operation")
    {
        *operation_evidence = EndpointReceiptEvidence::hashed("operation", "applied");
    }
    assert!(relabeled_generated_as_applied
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy delta applied"));

    let mut missing_artifact_hash = receipt.clone();
    missing_artifact_hash
        .evidence
        .retain(|item| item.key != "artifactHash");
    assert!(missing_artifact_hash
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy delta artifact hash evidence"));

    let mut missing_source_identity_context = receipt.clone();
    missing_source_identity_context
        .evidence
        .retain(|item| item.key != "sourceAffectedIdentityContext");
    assert!(missing_source_identity_context
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy delta source affected identity context evidence"));

    let mut relabeled_source_tool_context = receipt.clone();
    if let Some(tool_context_evidence) = relabeled_source_tool_context
        .evidence
        .iter_mut()
        .find(|item| item.key == "sourceAffectedToolContext")
    {
        *tool_context_evidence = EndpointReceiptEvidence::hashed("sourceAffectedToolContext", "[]");
    }
    assert!(relabeled_source_tool_context
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy delta id"));

    let mut mismatched_graph_slice = receipt.clone();
    if let Some(graph_slice_evidence) = mismatched_graph_slice
        .evidence
        .iter_mut()
        .find(|item| item.key == "graphSliceId")
    {
        *graph_slice_evidence =
            EndpointReceiptEvidence::hashed("graphSliceId", "graph_slice:other");
    }
    assert!(mismatched_graph_slice
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy delta graph slice evidence hash"));

    let mut mismatched_root_reference = receipt.clone();
    mismatched_root_reference.graph.process_node_id = Some("node:other".to_string());
    if let Some(root_node_evidence) = mismatched_root_reference
        .evidence
        .iter_mut()
        .find(|item| item.key == "rootNodeId")
    {
        *root_node_evidence = EndpointReceiptEvidence::hashed("rootNodeId", "node:other");
    }
    assert!(mismatched_root_reference
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy delta root node reference"));
}

#[test]
fn endpoint_evidence_bundle_manifest_receipt_binds_graph_slice_hash() {
    let event = observation(EndpointEvent::NetworkFlow {
        host: "bundle.example".to_string(),
        port: 443,
        protocol: Some("tcp".to_string()),
        url: Some("https://bundle.example/upload".to_string()),
    });
    let mut graph_recorder = CausalGraphRecorder::new();
    graph_recorder.record_observation(&event);
    let process_node_id = event.process.stable_node_id();
    let subgraph = graph_recorder
        .graph()
        .causal_subgraph_from(&process_node_id, 3)
        .unwrap();
    let plan = EndpointResponsePlan::collect_evidence_execution(
        &process_node_id,
        &subgraph,
        600,
        "collect evidence graph slice",
    );
    let execution = EndpointResponseExecutionReport::collect_evidence(&plan, &subgraph)
        .unwrap_or_else(|err| panic!("failed to collect evidence report: {err}"));
    let keypair = hush_core::Keypair::from_seed(&[16u8; 32]);
    let mut receipt = EndpointDecisionReceipt::for_evidence_bundle_manifest(
        EndpointEvidenceBundleManifestReceiptInput {
            local_sequence: 15,
            endpoint_id: "endpoint-1",
            signer_identity: "local-edr:endpoint-1",
            policy: EndpointPolicySnapshot {
                policy_version: "test-policy@1".to_string(),
                policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                policy_epoch: 7,
            },
            sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
            root_node_id: &process_node_id,
            bundle: &execution.evidence_bundle,
            graph: &subgraph,
        },
    );
    receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

    let signed = receipt.sign_with(&keypair).unwrap();
    let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

    assert!(verification.valid);
    assert_eq!(
        receipt.receipt_family,
        EndpointDecisionReceiptFamily::EvidenceBundleManifest
    );
    assert_eq!(
        receipt.decision.finding_id.as_deref(),
        Some(execution.evidence_bundle.bundle_id.as_str())
    );
    assert_eq!(
        receipt.graph.process_node_id.as_deref(),
        Some(process_node_id.as_str())
    );
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "contentHash"));

    let mut mismatched_bundle_id = receipt.clone();
    if let Some(bundle_id_evidence) = mismatched_bundle_id
        .evidence
        .iter_mut()
        .find(|item| item.key == "evidenceBundleId")
    {
        *bundle_id_evidence =
            EndpointReceiptEvidence::hashed("evidenceBundleId", "evidence_bundle:other");
    }
    assert!(mismatched_bundle_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("evidence bundle id evidence hash"));

    let mut mismatched_node_count = receipt.clone();
    if let Some(node_count_evidence) = mismatched_node_count
        .evidence
        .iter_mut()
        .find(|item| item.key == "nodeCount")
    {
        *node_count_evidence = EndpointReceiptEvidence::hashed("nodeCount", "0");
    }
    assert!(mismatched_node_count
        .validate()
        .unwrap_err()
        .to_string()
        .contains("evidence bundle node count evidence hash"));

    let mut mismatched_content_hash = receipt.clone();
    if let Some(content_hash_evidence) = mismatched_content_hash
        .evidence
        .iter_mut()
        .find(|item| item.key == "contentHash")
    {
        *content_hash_evidence = EndpointReceiptEvidence::hashed("contentHash", "sha256:other");
    }
    assert!(mismatched_content_hash
        .validate()
        .unwrap_err()
        .to_string()
        .contains("evidence bundle content hash evidence hash"));

    let mut mismatched_root_reference = receipt.clone();
    mismatched_root_reference.graph.process_node_id = Some("node:other".to_string());
    assert!(mismatched_root_reference
        .validate()
        .unwrap_err()
        .to_string()
        .contains("evidence bundle graph root reference"));

    let mut mismatched_graph_slice_reference = receipt.clone();
    mismatched_graph_slice_reference.graph.graph_slice_id = Some("graph_slice:other".to_string());
    if let Some(graph_slice_evidence) = mismatched_graph_slice_reference
        .evidence
        .iter_mut()
        .find(|item| item.key == "graphSliceId")
    {
        *graph_slice_evidence =
            EndpointReceiptEvidence::hashed("graphSliceId", "graph_slice:other");
    }
    assert!(mismatched_graph_slice_reference
        .validate()
        .unwrap_err()
        .to_string()
        .contains("evidence bundle graph slice reference"));
}

