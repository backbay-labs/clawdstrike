#[test]
fn endpoint_policy_event_replay_receipt_binds_stream_graph_reference() {
    let keypair = hush_core::Keypair::from_seed(&[47u8; 32]);
    let event_stream_hash = sha256(b"event-stream").to_hex_prefixed();
    let result_hash = sha256(b"replay-result").to_hex_prefixed();
    let policy = EndpointPolicySnapshot {
        policy_version: "test-policy@1".to_string(),
        policy_hash: sha256(b"test-policy").to_hex_prefixed(),
        policy_epoch: 7,
    };
    let replay_id = endpoint_policy_event_replay_id(EndpointPolicyEventReplayIdInput {
        policy_hash: policy.policy_hash.as_str(),
        policy_epoch: policy.policy_epoch,
        event_source: "submitted",
        event_stream_hash: &event_stream_hash,
        result_hash: &result_hash,
        event_count: 3,
        allowed_count: 1,
        warn_count: 1,
        blocked_count: 1,
        track_posture: true,
    });
    let mut receipt =
        EndpointDecisionReceipt::for_policy_event_replay(EndpointPolicyEventReplayReceiptInput {
            local_sequence: 47,
            endpoint_id: "endpoint-1",
            signer_identity: "local-edr:endpoint-1",
            policy,
            sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
            replay_id: replay_id.as_str(),
            event_source: "submitted",
            event_stream_hash: &event_stream_hash,
            result_hash: &result_hash,
            event_count: 3,
            allowed_count: 1,
            warn_count: 1,
            blocked_count: 1,
            track_posture: true,
        });
    receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

    let signed = receipt.sign_with(&keypair).unwrap();
    let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

    assert!(verification.valid);
    assert_eq!(
        receipt.receipt_family,
        EndpointDecisionReceiptFamily::Simulation
    );
    assert_eq!(
        receipt.decision.rule_id.as_deref(),
        Some("endpoint.policy_event_replay")
    );
    assert_eq!(
        receipt.graph.graph_slice_id.as_deref(),
        Some(replay_id.as_str())
    );
    assert_eq!(
        receipt.graph.process_node_id.as_deref(),
        Some("policy_event_stream")
    );

    let mut mismatched_graph_slice = receipt.clone();
    mismatched_graph_slice.graph.graph_slice_id = Some("policy_event_replay:other".to_string());
    assert!(mismatched_graph_slice
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy event replay graph slice reference"));

    let mut relabeled_replay_id = receipt.clone();
    relabeled_replay_id.decision.finding_id = Some("policy_event_replay:other".to_string());
    relabeled_replay_id.graph.graph_slice_id = Some("policy_event_replay:other".to_string());
    if let Some(replay_id_evidence) = relabeled_replay_id
        .evidence
        .iter_mut()
        .find(|item| item.key == "replayId")
    {
        *replay_id_evidence =
            EndpointReceiptEvidence::hashed("replayId", "policy_event_replay:other");
    }
    assert!(relabeled_replay_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy event replay id"));

    let mut mismatched_stream_node = receipt.clone();
    mismatched_stream_node.graph.process_node_id = Some("node:process-other".to_string());
    assert!(mismatched_stream_node
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy event replay stream node reference"));

    let mut missing_stream_graph_node = receipt.clone();
    missing_stream_graph_node.graph.node_ids.clear();
    assert!(missing_stream_graph_node
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy event replay stream node reference"));

    let mut missing_result_hash = receipt.clone();
    missing_result_hash
        .evidence
        .retain(|item| item.key != "resultHash");
    assert!(missing_result_hash
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy event replay result hash evidence"));

    let mut non_boolean_posture = receipt.clone();
    if let Some(posture_evidence) = non_boolean_posture
        .evidence
        .iter_mut()
        .find(|item| item.key == "trackPosture")
    {
        *posture_evidence = EndpointReceiptEvidence::hashed("trackPosture", "maybe");
    }
    assert!(non_boolean_posture
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy event replay posture evidence"));
}

#[test]
fn endpoint_policy_event_impact_receipt_binds_stream_graph_reference() {
    let keypair = hush_core::Keypair::from_seed(&[48u8; 32]);
    let event_stream_hash = sha256(b"event-stream").to_hex_prefixed();
    let current_result_hash = sha256(b"current-result").to_hex_prefixed();
    let proposed_result_hash = sha256(b"proposed-result").to_hex_prefixed();
    let impact_hash = sha256(b"impact").to_hex_prefixed();
    let proposed_policy_hash = sha256(b"proposed-policy").to_hex_prefixed();
    let policy = EndpointPolicySnapshot {
        policy_version: "test-policy@1".to_string(),
        policy_hash: sha256(b"test-policy").to_hex_prefixed(),
        policy_epoch: 7,
    };
    let impact_id = endpoint_policy_event_impact_id(EndpointPolicyEventImpactIdInput {
        current_policy_hash: policy.policy_hash.as_str(),
        current_policy_epoch: policy.policy_epoch,
        proposed_policy_hash: &proposed_policy_hash,
        proposed_policy_epoch: 8,
        event_source: "submitted",
        event_stream_hash: &event_stream_hash,
        current_result_hash: &current_result_hash,
        proposed_result_hash: &proposed_result_hash,
        impact_hash: &impact_hash,
        event_count: 3,
        changed_count: 2,
        allow_to_block_count: 1,
        track_posture: true,
    });
    let mut receipt =
        EndpointDecisionReceipt::for_policy_event_impact(EndpointPolicyEventImpactReceiptInput {
            local_sequence: 48,
            endpoint_id: "endpoint-1",
            signer_identity: "local-edr:endpoint-1",
            policy,
            sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
            impact_id: impact_id.as_str(),
            event_source: "submitted",
            event_stream_hash: &event_stream_hash,
            current_result_hash: &current_result_hash,
            proposed_result_hash: &proposed_result_hash,
            impact_hash: &impact_hash,
            proposed_policy_hash: &proposed_policy_hash,
            proposed_policy_epoch: 8,
            event_count: 3,
            changed_count: 2,
            allow_to_block_count: 1,
            track_posture: true,
        });
    receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

    let signed = receipt.sign_with(&keypair).unwrap();
    let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

    assert!(verification.valid);
    assert_eq!(
        receipt.receipt_family,
        EndpointDecisionReceiptFamily::Simulation
    );
    assert_eq!(
        receipt.decision.rule_id.as_deref(),
        Some("endpoint.policy_event_impact")
    );
    assert_eq!(
        receipt.graph.graph_slice_id.as_deref(),
        Some(impact_id.as_str())
    );
    assert_eq!(
        receipt.graph.process_node_id.as_deref(),
        Some("policy_event_stream")
    );

    let mut mismatched_graph_slice = receipt.clone();
    mismatched_graph_slice.graph.graph_slice_id = Some("policy_event_impact:other".to_string());
    assert!(mismatched_graph_slice
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy event impact graph slice reference"));

    let mut relabeled_impact_id = receipt.clone();
    relabeled_impact_id.decision.finding_id = Some("policy_event_impact:other".to_string());
    relabeled_impact_id.graph.graph_slice_id = Some("policy_event_impact:other".to_string());
    if let Some(impact_id_evidence) = relabeled_impact_id
        .evidence
        .iter_mut()
        .find(|item| item.key == "impactId")
    {
        *impact_id_evidence =
            EndpointReceiptEvidence::hashed("impactId", "policy_event_impact:other");
    }
    assert!(relabeled_impact_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy event impact id"));

    let mut mismatched_stream_node = receipt.clone();
    mismatched_stream_node.graph.process_node_id = Some("node:process-other".to_string());
    assert!(mismatched_stream_node
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy event impact stream node reference"));

    let mut missing_stream_graph_node = receipt.clone();
    missing_stream_graph_node.graph.node_ids.clear();
    assert!(missing_stream_graph_node
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy event impact stream node reference"));

    let mut missing_impact_hash = receipt.clone();
    missing_impact_hash
        .evidence
        .retain(|item| item.key != "impactHash");
    assert!(missing_impact_hash
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy event impact hash evidence"));

    let mut non_boolean_posture = receipt.clone();
    if let Some(posture_evidence) = non_boolean_posture
        .evidence
        .iter_mut()
        .find(|item| item.key == "trackPosture")
    {
        *posture_evidence = EndpointReceiptEvidence::hashed("trackPosture", "maybe");
    }
    assert!(non_boolean_posture
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy event impact posture evidence"));
}

#[test]
fn endpoint_response_metadata_deserialization_rejects_unknown_fields() {
    let event = observation(EndpointEvent::NetworkFlow {
        host: "egress.example.invalid".to_string(),
        port: 443,
        protocol: Some("tcp".to_string()),
        url: Some("https://egress.example.invalid/upload".to_string()),
    });
    let mut graph_recorder = CausalGraphRecorder::new();
    graph_recorder.record_observation(&event);
    let process_node_id = event.process.stable_node_id();
    let subgraph = graph_recorder
        .graph()
        .causal_subgraph_from(&process_node_id, 3)
        .unwrap();
    let plan = EndpointResponsePlan::restrict_egress_execution(
        &process_node_id,
        &subgraph,
        600,
        "restrict observed egress",
    );
    assert_unknown_field_rejected::<EndpointResponsePlan>(
        serde_json::to_value(&plan).unwrap(),
        "shadowTtlSeconds",
    );

    let targets = vec!["egress.example.invalid:443".to_string()];
    let mut execution =
        EndpointResponseExecutionReport::restrict_egress(&plan, &subgraph, &targets).unwrap();
    execution.actor = Some(response_actor("endpoint-1"));
    assert_unknown_field_rejected::<EndpointResponseExecutionReport>(
        serde_json::to_value(&execution).unwrap(),
        "shadowExecutionStatus",
    );
    assert_unknown_field_rejected::<EndpointEvidenceBundleReference>(
        serde_json::to_value(&execution.evidence_bundle).unwrap(),
        "shadowBundleHash",
    );
    assert_unknown_field_rejected::<EndpointResponseExecutionEffect>(
        serde_json::to_value(&execution.effects[0]).unwrap(),
        "shadowEffectTarget",
    );

    let rollback = EndpointResponseRollbackReport::restrict_egress(
        &execution,
        "restore egress",
        execution.completed_at + chrono::Duration::seconds(1),
    )
    .unwrap();
    assert_unknown_field_rejected::<EndpointResponseRollbackReport>(
        serde_json::to_value(&rollback).unwrap(),
        "shadowRollbackStatus",
    );

    let control = EndpointResponseControlCorrelation {
        response_action_id: execution.action_id.clone(),
        delivery_id: Some("delivery:test".to_string()),
        target_kind: "endpoint".to_string(),
        target_id: "endpoint-1".to_string(),
        ack_token_hash: sha256(b"ack-token").to_hex_prefixed(),
        ack_status: "acknowledged".to_string(),
        resulting_state: Some("contained".to_string()),
    };
    assert_unknown_field_rejected::<EndpointResponseControlCorrelation>(
        serde_json::to_value(&control).unwrap(),
        "shadowAckToken",
    );

    let acknowledgement = EndpointResponseAcknowledgementReport::from_execution(
        &execution,
        "operator:test",
        Some("operator acknowledged response".to_string()),
        execution.completed_at + chrono::Duration::seconds(2),
    )
    .with_control_correlation(Some(control));
    assert_unknown_field_rejected::<EndpointResponseAcknowledgementReport>(
        serde_json::to_value(&acknowledgement).unwrap(),
        "shadowAcknowledgedBy",
    );
}

#[test]
fn endpoint_response_request_receipt_requires_ttl_rollback_and_graph_target() {
    let event = observation(EndpointEvent::NetworkFlow {
        host: "egress.example".to_string(),
        port: 443,
        protocol: Some("tcp".to_string()),
        url: Some("https://egress.example/upload".to_string()),
    });
    let mut graph_recorder = CausalGraphRecorder::new();
    graph_recorder.record_observation(&event);
    let process_node_id = event.process.stable_node_id();
    let subgraph = graph_recorder
        .graph()
        .causal_subgraph_from(&process_node_id, 3)
        .unwrap();
    let plan = EndpointResponsePlan::dry_run(
        EndpointDecisionAction::RestrictEgress,
        &process_node_id,
        &subgraph,
        600,
        "contain process tree",
    );
    let keypair = hush_core::Keypair::from_seed(&[11u8; 32]);
    let mut receipt = EndpointDecisionReceipt::for_response_request(EndpointResponseReceiptInput {
        local_sequence: 10,
        endpoint_id: "endpoint-1",
        signer_identity: "local-edr:endpoint-1",
        actor: response_actor("endpoint-1"),
        policy: EndpointPolicySnapshot {
            policy_version: "test-policy@1".to_string(),
            policy_hash: sha256(b"test-policy").to_hex_prefixed(),
            policy_epoch: 7,
        },
        sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
        plan: &plan,
        graph: &subgraph,
    });
    receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

    let signed = receipt.sign_with(&keypair).unwrap();
    let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

    assert!(verification.valid);
    assert_eq!(
        receipt.receipt_family,
        EndpointDecisionReceiptFamily::ResponseRequest
    );
    assert_eq!(receipt.decision.ttl_seconds, Some(600));
    assert_eq!(
        receipt.decision.rollback_ref.as_deref(),
        Some(plan.rollback_ref.as_str())
    );
    assert_eq!(
        receipt.graph.process_node_id.as_deref(),
        Some(process_node_id.as_str())
    );
    assert_eq!(receipt.decision.confidence, Some(1.0));
    assert_eq!(
        receipt.actor.session_id.as_deref(),
        Some("session-response")
    );
    assert_eq!(receipt.actor.posture.as_deref(), Some("restricted"));
    assert!(receipt.evidence.iter().any(|item| item.key == "actorHash"));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "contentHash"));

    let terminate_dry_run_plan = EndpointResponsePlan::dry_run(
        EndpointDecisionAction::TerminateProcessTree,
        &process_node_id,
        &subgraph,
        600,
        "model terminate process tree only",
    );
    let mut terminate_dry_run_receipt =
        EndpointDecisionReceipt::for_response_request(EndpointResponseReceiptInput {
            local_sequence: 11,
            endpoint_id: "endpoint-1",
            signer_identity: "local-edr:endpoint-1",
            actor: response_actor("endpoint-1"),
            policy: EndpointPolicySnapshot {
                policy_version: "test-policy@1".to_string(),
                policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                policy_epoch: 7,
            },
            sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
            plan: &terminate_dry_run_plan,
            graph: &subgraph,
        });
    terminate_dry_run_receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());
    let signed_terminate_dry_run = terminate_dry_run_receipt.sign_with(&keypair).unwrap();
    assert!(
        signed_terminate_dry_run
            .verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()))
            .valid
    );
    assert_eq!(
        terminate_dry_run_receipt.decision.action,
        EndpointDecisionAction::TerminateProcessTree
    );

    let mut terminate_live_plan = terminate_dry_run_plan.clone();
    terminate_live_plan.dry_run = false;
    let terminate_live_ttl = terminate_live_plan.ttl_seconds.to_string();
    terminate_live_plan.action_id = stable_id(
        "response_action",
        [
            terminate_live_plan.root_node_id.as_str(),
            terminate_live_plan.graph_slice_id.as_str(),
            terminate_live_plan.action.as_str(),
            "execute",
            terminate_live_ttl.as_str(),
        ],
    );
    terminate_live_plan.rollback_ref = format!("rollback:{}", terminate_live_plan.action_id);
    let mut terminate_live_receipt =
        EndpointDecisionReceipt::for_response_request(EndpointResponseReceiptInput {
            local_sequence: 12,
            endpoint_id: "endpoint-1",
            signer_identity: "local-edr:endpoint-1",
            actor: response_actor("endpoint-1"),
            policy: EndpointPolicySnapshot {
                policy_version: "test-policy@1".to_string(),
                policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                policy_epoch: 7,
            },
            sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
            plan: &terminate_live_plan,
            graph: &subgraph,
        });
    terminate_live_receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());
    let err = terminate_live_receipt.sign_with(&keypair).unwrap_err();
    assert!(err.to_string().contains("dry-run response requests"));

    let mut missing_actor_context = receipt.clone();
    missing_actor_context.actor.host_id = None;
    missing_actor_context.actor.user_id = None;
    missing_actor_context.actor.session_id = None;
    missing_actor_context.actor.posture = None;
    missing_actor_context.actor.agent_id = None;
    missing_actor_context.actor.workload_id = None;
    missing_actor_context.actor.approval_id = None;
    assert!(missing_actor_context
        .validate()
        .unwrap_err()
        .to_string()
        .contains("response actor context"));

    let mut missing_actor_hash = receipt.clone();
    missing_actor_hash
        .evidence
        .retain(|item| item.key != "actorHash");
    assert!(missing_actor_hash
        .validate()
        .unwrap_err()
        .to_string()
        .contains("response actor evidence"));

    let mut mismatched_actor_hash = receipt.clone();
    if let Some(actor_hash_evidence) = mismatched_actor_hash
        .evidence
        .iter_mut()
        .find(|item| item.key == "actorHash")
    {
        *actor_hash_evidence = EndpointReceiptEvidence::hashed("actorHash", "actor:other");
    }
    assert!(mismatched_actor_hash
        .validate()
        .unwrap_err()
        .to_string()
        .contains("response actor evidence hash"));

    let mut missing_ttl = receipt.clone();
    missing_ttl.decision.ttl_seconds = None;
    assert!(missing_ttl
        .validate()
        .unwrap_err()
        .to_string()
        .contains("ttl"));

    let mut missing_rollback = receipt.clone();
    missing_rollback.decision.rollback_ref = None;
    assert!(missing_rollback
        .validate()
        .unwrap_err()
        .to_string()
        .contains("rollback"));

    let mut missing_confidence = receipt.clone();
    missing_confidence.decision.confidence = None;
    assert!(missing_confidence
        .validate()
        .unwrap_err()
        .to_string()
        .contains("confidence"));

    let mut missing_ttl_evidence = receipt.clone();
    missing_ttl_evidence
        .evidence
        .retain(|item| item.key != "ttlSeconds");
    assert!(missing_ttl_evidence
        .validate()
        .unwrap_err()
        .to_string()
        .contains("response ttl evidence"));

    let mut missing_rollback_evidence = receipt.clone();
    missing_rollback_evidence
        .evidence
        .retain(|item| item.key != "rollbackRef");
    assert!(missing_rollback_evidence
        .validate()
        .unwrap_err()
        .to_string()
        .contains("response rollback evidence"));

    let mut missing_content_hash_evidence = receipt.clone();
    missing_content_hash_evidence
        .evidence
        .retain(|item| item.key != "contentHash");
    assert!(missing_content_hash_evidence
        .validate()
        .unwrap_err()
        .to_string()
        .contains("response graph content hash evidence"));

    let mut mismatched_ttl_evidence = receipt.clone();
    if let Some(ttl_evidence) = mismatched_ttl_evidence
        .evidence
        .iter_mut()
        .find(|item| item.key == "ttlSeconds")
    {
        *ttl_evidence = EndpointReceiptEvidence::hashed("ttlSeconds", "601");
    }
    assert!(mismatched_ttl_evidence
        .validate()
        .unwrap_err()
        .to_string()
        .contains("response ttl evidence hash"));

    let mut mismatched_rollback_evidence = receipt.clone();
    if let Some(rollback_evidence) = mismatched_rollback_evidence
        .evidence
        .iter_mut()
        .find(|item| item.key == "rollbackRef")
    {
        *rollback_evidence = EndpointReceiptEvidence::hashed("rollbackRef", "rollback:other");
    }
    assert!(mismatched_rollback_evidence
        .validate()
        .unwrap_err()
        .to_string()
        .contains("response rollback evidence hash"));

    let mut mismatched_content_hash_evidence = receipt.clone();
    if let Some(content_hash_evidence) = mismatched_content_hash_evidence
        .evidence
        .iter_mut()
        .find(|item| item.key == "contentHash")
    {
        *content_hash_evidence = EndpointReceiptEvidence::hashed("contentHash", "sha256:other");
    }
    assert!(mismatched_content_hash_evidence
        .validate()
        .unwrap_err()
        .to_string()
        .contains("response graph content hash evidence hash"));

    let mut relabeled_action_contract = receipt.clone();
    relabeled_action_contract.decision.finding_id = Some("response_action:other".to_string());
    relabeled_action_contract.decision.rollback_ref =
        Some("rollback:response_action:other".to_string());
    if let Some(response_action_id_evidence) = relabeled_action_contract
        .evidence
        .iter_mut()
        .find(|item| item.key == "responseActionId")
    {
        *response_action_id_evidence =
            EndpointReceiptEvidence::hashed("responseActionId", "response_action:other");
    }
    if let Some(rollback_evidence) = relabeled_action_contract
        .evidence
        .iter_mut()
        .find(|item| item.key == "rollbackRef")
    {
        *rollback_evidence =
            EndpointReceiptEvidence::hashed("rollbackRef", "rollback:response_action:other");
    }
    assert!(relabeled_action_contract
        .validate()
        .unwrap_err()
        .to_string()
        .contains("response action id evidence hash"));

    let mut mismatched_dry_run_evidence = receipt.clone();
    if let Some(dry_run_evidence) = mismatched_dry_run_evidence
        .evidence
        .iter_mut()
        .find(|item| item.key == "dryRun")
    {
        *dry_run_evidence = EndpointReceiptEvidence::hashed("dryRun", "false");
    }
    assert!(mismatched_dry_run_evidence
        .validate()
        .unwrap_err()
        .to_string()
        .contains("response dry-run evidence hash"));

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
        .contains("response graph root reference"));

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
        .contains("response graph slice reference"));

    let mut empty_reason_evidence = receipt.clone();
    if let Some(reason_evidence) = empty_reason_evidence
        .evidence
        .iter_mut()
        .find(|item| item.key == "reason")
    {
        *reason_evidence = EndpointReceiptEvidence::hashed("reason", "");
    }
    assert!(empty_reason_evidence
        .validate()
        .unwrap_err()
        .to_string()
        .contains("response reason evidence"));

    let mut non_response_action = receipt;
    non_response_action.decision.action = EndpointDecisionAction::Observe;
    assert!(non_response_action
        .validate()
        .unwrap_err()
        .to_string()
        .contains("response action"));
}

#[test]
fn endpoint_restrict_egress_execution_receipt_binds_targets_and_rollback() {
    let event = observation(EndpointEvent::NetworkFlow {
        host: "egress.example.invalid".to_string(),
        port: 443,
        protocol: Some("tcp".to_string()),
        url: Some("https://egress.example.invalid/upload".to_string()),
    });
    let mut graph_recorder = CausalGraphRecorder::new();
    graph_recorder.record_observation(&event);
    let process_node_id = event.process.stable_node_id();
    let subgraph = graph_recorder
        .graph()
        .causal_subgraph_from(&process_node_id, 3)
        .unwrap();
    let targets = vec!["egress.example.invalid:443".to_string()];
    let plan = EndpointResponsePlan::restrict_egress_execution(
        &process_node_id,
        &subgraph,
        600,
        "restrict observed egress",
    );
    let execution =
        EndpointResponseExecutionReport::restrict_egress(&plan, &subgraph, &targets).unwrap();

    assert_eq!(execution.action, EndpointDecisionAction::RestrictEgress);
    assert_eq!(execution.status, EndpointResponseExecutionStatus::Succeeded);
    assert_eq!(execution.effects[0].effect_type, "restrict_egress");
    assert_eq!(
        execution.effects[0].target,
        "egress:egress.example.invalid:443"
    );
    assert_eq!(
        execution.effects[0].artifact.as_deref(),
        Some("egress.example.invalid:443")
    );
    assert_eq!(execution.effects[0].byte_count, Some(1));

    let rollback = EndpointResponseRollbackReport::restrict_egress(
        &execution,
        "restore egress",
        execution.completed_at + chrono::Duration::seconds(1),
    )
    .unwrap();
    assert_eq!(rollback.action, EndpointDecisionAction::RestrictEgress);
    assert_eq!(rollback.effects[0].effect_type, "restore_egress");
    assert_eq!(
        rollback.effects[0].content_hash,
        execution.effects[0].content_hash
    );
    assert_eq!(rollback.effects[0].byte_count, Some(1));
}

#[test]
fn endpoint_policy_decision_receipt_signs_allow_and_block() {
    let keypair = hush_core::Keypair::from_seed(&[18u8; 32]);
    let policy = EndpointPolicySnapshot {
        policy_version: "test-policy@1".to_string(),
        policy_hash: sha256(b"test-policy").to_hex_prefixed(),
        policy_epoch: 7,
    };
    let sensor_state = EndpointSensorState::single_active_agent("agent-api:test");
    let actor = EndpointDecisionActor {
        endpoint_id: "endpoint-1".to_string(),
        session_id: Some("session-1".to_string()),
        agent_id: Some("agent:codex".to_string()),
        workload_id: Some("local-agent".to_string()),
        ..EndpointDecisionActor::default()
    };
    let details = serde_json::json!({
        "reason": "developer_tool_allowed"
    });
    let allowed_observation = observation(EndpointEvent::PolicyDecision {
        action: "mcp_tool".to_string(),
        target: Some("openclaw.list".to_string()),
        decision: "allowed".to_string(),
        guard: Some("developer_tool_allowlist".to_string()),
        severity: Some("info".to_string()),
    });
    let blocked_observation = observation(EndpointEvent::PolicyDecision {
        action: "egress".to_string(),
        target: Some("evil.example:443".to_string()),
        decision: "blocked".to_string(),
        guard: Some("deny_unknown_egress".to_string()),
        severity: Some("high".to_string()),
    });
    let mut graph_recorder = CausalGraphRecorder::new();
    graph_recorder.record_observation(&allowed_observation);
    graph_recorder.record_observation(&blocked_observation);
    let graph = graph_recorder.graph();
    let mut allowed_receipt =
        EndpointDecisionReceipt::for_policy_decision(EndpointPolicyDecisionReceiptInput {
            local_sequence: 17,
            signer_identity: "local-edr:endpoint-1",
            actor: actor.clone(),
            policy: policy.clone(),
            sensor_state: sensor_state.clone(),
            observation: &allowed_observation,
            graph,
            action_type: "mcp_tool",
            target: "openclaw.list",
            allowed: true,
            guard: Some("developer_tool_allowlist"),
            severity: Some(DetectionSeverity::Info),
            severity_label: Some("info"),
            message: Some("allowed by developer tool allowlist"),
            details: Some(&details),
        });
    allowed_receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

    let signed = allowed_receipt.sign_with(&keypair).unwrap();
    let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));
    assert!(verification.valid);
    assert_eq!(
        allowed_receipt.receipt_family,
        EndpointDecisionReceiptFamily::PolicyDecision
    );
    assert_eq!(
        allowed_receipt.decision.action,
        EndpointDecisionAction::Allow
    );
    assert!(allowed_receipt.decision.passed);
    assert_eq!(
        allowed_receipt.actor.agent_id.as_deref(),
        Some("agent:codex")
    );
    assert!(allowed_receipt
        .evidence
        .iter()
        .any(|item| item.key == "actorHash"));
    assert!(allowed_receipt
        .evidence
        .iter()
        .any(|item| item.key == "actorSessionId"));
    assert!(allowed_receipt
        .evidence
        .iter()
        .any(|item| item.key == "policyEpoch"));

    let mut mismatched_allowed = allowed_receipt.clone();
    if let Some(allowed_evidence) = mismatched_allowed
        .evidence
        .iter_mut()
        .find(|item| item.key == "allowed")
    {
        *allowed_evidence = EndpointReceiptEvidence::hashed("allowed", "false");
    }
    assert!(mismatched_allowed
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy decision allowed evidence hash"));

    let mut mismatched_action_type = allowed_receipt.clone();
    if let Some(action_type_evidence) = mismatched_action_type
        .evidence
        .iter_mut()
        .find(|item| item.key == "actionType")
    {
        *action_type_evidence = EndpointReceiptEvidence::hashed("actionType", "egress");
    }
    assert!(mismatched_action_type
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy decision action type evidence hash"));

    let mut missing_target = allowed_receipt.clone();
    missing_target.evidence.retain(|item| item.key != "target");
    assert!(missing_target
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy decision target evidence"));

    let mut missing_graph = allowed_receipt.clone();
    missing_graph.graph = EndpointGraphReference::default();
    assert!(missing_graph
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy decision graph slice"));

    let mut tampered_actor_hash = allowed_receipt.clone();
    tampered_actor_hash.actor.agent_id = Some("agent:other".to_string());
    assert!(tampered_actor_hash
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy decision actor hash evidence hash"));

    let mut tampered_actor_session = allowed_receipt.clone();
    tampered_actor_session.actor.session_id = Some("session-other".to_string());
    if let Some(actor_hash_evidence) = tampered_actor_session
        .evidence
        .iter_mut()
        .find(|item| item.key == "actorHash")
    {
        *actor_hash_evidence = EndpointReceiptEvidence::hashed(
            "actorHash",
            endpoint_decision_actor_content_hash(&tampered_actor_session.actor),
        );
    }
    assert!(tampered_actor_session
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy decision actor session evidence hash"));

    let mut tampered_policy_epoch = allowed_receipt.clone();
    tampered_policy_epoch.policy.policy_epoch += 1;
    assert!(tampered_policy_epoch
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy decision policy epoch evidence hash"));

    let mut relabeled_policy_decision_id = allowed_receipt.clone();
    relabeled_policy_decision_id.decision.finding_id = Some("policy_decision:other".to_string());
    assert!(relabeled_policy_decision_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy decision id"));

    let mut blocked_receipt =
        EndpointDecisionReceipt::for_policy_decision(EndpointPolicyDecisionReceiptInput {
            local_sequence: 18,
            signer_identity: "local-edr:endpoint-1",
            actor,
            policy,
            sensor_state,
            observation: &blocked_observation,
            graph,
            action_type: "egress",
            target: "evil.example:443",
            allowed: false,
            guard: Some("deny_unknown_egress"),
            severity: Some(DetectionSeverity::High),
            severity_label: Some("high"),
            message: Some("unknown egress blocked"),
            details: None,
        });
    blocked_receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

    let signed = blocked_receipt.sign_with(&keypair).unwrap();
    let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));
    assert!(verification.valid);
    assert_eq!(
        blocked_receipt.decision.action,
        EndpointDecisionAction::Block
    );
    assert!(!blocked_receipt.decision.passed);
    assert!(blocked_receipt
        .evidence
        .iter()
        .any(|item| item.key == "target"));
}

#[test]
fn endpoint_collect_evidence_execution_receipt_binds_bundle_and_graph() {
    let event = observation(EndpointEvent::NetworkFlow {
        host: "evidence.example".to_string(),
        port: 443,
        protocol: Some("tcp".to_string()),
        url: Some("https://evidence.example/upload".to_string()),
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
    let keypair = hush_core::Keypair::from_seed(&[13u8; 32]);
    let mut receipt =
        EndpointDecisionReceipt::for_response_execution(EndpointResponseExecutionReceiptInput {
            local_sequence: 12,
            endpoint_id: "endpoint-1",
            signer_identity: "local-edr:endpoint-1",
            actor: response_actor("endpoint-1"),
            policy: EndpointPolicySnapshot {
                policy_version: "test-policy@1".to_string(),
                policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                policy_epoch: 7,
            },
            sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
            execution: &execution,
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
    assert_eq!(
        receipt.decision.finding_id.as_deref(),
        Some(execution.execution_id.as_str())
    );
    assert_eq!(
        receipt.decision.rollback_ref.as_deref(),
        Some(plan.rollback_ref.as_str())
    );
    assert_eq!(receipt.decision.ttl_seconds, Some(600));
    assert_eq!(
        receipt.graph.process_node_id.as_deref(),
        Some(process_node_id.as_str())
    );

    let mut missing_bundle_content_hash = receipt.clone();
    missing_bundle_content_hash
        .evidence
        .retain(|item| item.key != "evidenceBundleContentHash");
    assert!(missing_bundle_content_hash
        .validate()
        .unwrap_err()
        .to_string()
        .contains("execution evidence bundle content hash evidence"));

    let mut mismatched_bundle_content_hash = receipt.clone();
    if let Some(bundle_content_hash_evidence) = mismatched_bundle_content_hash
        .evidence
        .iter_mut()
        .find(|item| item.key == "evidenceBundleContentHash")
    {
        *bundle_content_hash_evidence =
            EndpointReceiptEvidence::hashed("evidenceBundleContentHash", "sha256:other");
    }
    assert!(mismatched_bundle_content_hash
        .validate()
        .unwrap_err()
        .to_string()
        .contains("execution evidence bundle content hash evidence hash"));

    let mut empty_bundle_id = receipt.clone();
    if let Some(bundle_id_evidence) = empty_bundle_id
        .evidence
        .iter_mut()
        .find(|item| item.key == "evidenceBundleId")
    {
        *bundle_id_evidence = EndpointReceiptEvidence::hashed("evidenceBundleId", "");
    }
    assert!(empty_bundle_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("execution evidence bundle id evidence"));

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
        .contains("execution evidence bundle id evidence hash"));

    let mut relabeled_execution_id = receipt.clone();
    relabeled_execution_id.decision.finding_id = Some("response_execution:other".to_string());
    if let Some(execution_id_evidence) = relabeled_execution_id
        .evidence
        .iter_mut()
        .find(|item| item.key == "executionId")
    {
        *execution_id_evidence =
            EndpointReceiptEvidence::hashed("executionId", "response_execution:other");
    }
    assert!(relabeled_execution_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("execution id evidence hash"));

    let mut empty_response_action_id = receipt.clone();
    if let Some(response_action_id) = empty_response_action_id
        .evidence
        .iter_mut()
        .find(|item| item.key == "responseActionId")
    {
        *response_action_id = EndpointReceiptEvidence::hashed("responseActionId", "");
    }
    assert!(empty_response_action_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("response action id evidence"));

    let mut mismatched_response_action_id = receipt.clone();
    if let Some(response_action_id) = mismatched_response_action_id
        .evidence
        .iter_mut()
        .find(|item| item.key == "responseActionId")
    {
        *response_action_id =
            EndpointReceiptEvidence::hashed("responseActionId", "response_action:other");
    }
    assert!(mismatched_response_action_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("response action id evidence hash"));

    let mut relabeled_action_contract = receipt.clone();
    relabeled_action_contract.decision.rollback_ref =
        Some("rollback:noop:response_action:other".to_string());
    if let Some(response_action_id) = relabeled_action_contract
        .evidence
        .iter_mut()
        .find(|item| item.key == "responseActionId")
    {
        *response_action_id =
            EndpointReceiptEvidence::hashed("responseActionId", "response_action:other");
    }
    if let Some(rollback_evidence) = relabeled_action_contract
        .evidence
        .iter_mut()
        .find(|item| item.key == "rollbackRef")
    {
        *rollback_evidence =
            EndpointReceiptEvidence::hashed("rollbackRef", "rollback:noop:response_action:other");
    }
    assert!(relabeled_action_contract
        .validate()
        .unwrap_err()
        .to_string()
        .contains("response action id evidence hash"));

    let fake_effect =
        EndpointResponseExecutionEffect::revoke_grant("local_api_auth_token", "sha256:fake");
    let injected_execution_id = response_execution_id_from_effects(
        plan.action_id.as_str(),
        execution.evidence_bundle.bundle_id.as_str(),
        std::slice::from_ref(&fake_effect),
    )
    .unwrap();
    let mut collect_evidence_with_effect = receipt.clone();
    collect_evidence_with_effect.decision.finding_id = Some(injected_execution_id.clone());
    if let Some(execution_id_evidence) = collect_evidence_with_effect
        .evidence
        .iter_mut()
        .find(|item| item.key == "executionId")
    {
        *execution_id_evidence =
            EndpointReceiptEvidence::hashed("executionId", &injected_execution_id);
    }
    if let Some(effect_count_evidence) = collect_evidence_with_effect
        .evidence
        .iter_mut()
        .find(|item| item.key == "effectCount")
    {
        *effect_count_evidence = EndpointReceiptEvidence::hashed("effectCount", "1");
    }
    collect_evidence_with_effect
        .evidence
        .push(EndpointReceiptEvidence::hashed(
            format!("executionEffect:{}", fake_effect.effect_id),
            response_effect_evidence_value(&fake_effect),
        ));
    assert!(collect_evidence_with_effect
        .validate()
        .unwrap_err()
        .to_string()
        .contains("collect evidence execution effect evidence"));

    let mut mismatched_dry_run = receipt;
    if let Some(dry_run_evidence) = mismatched_dry_run
        .evidence
        .iter_mut()
        .find(|item| item.key == "dryRun")
    {
        *dry_run_evidence = EndpointReceiptEvidence::hashed("dryRun", "true");
    }
    assert!(mismatched_dry_run
        .validate()
        .unwrap_err()
        .to_string()
        .contains("execution dry-run evidence hash"));

    let mut execution_with_conflicting_actor = execution.clone();
    let mut other_actor = response_actor("endpoint-1");
    other_actor.agent_id = Some("agent-api:other".to_string());
    execution_with_conflicting_actor.actor = Some(other_actor);
    let mismatched_execution_actor =
        EndpointDecisionReceipt::for_response_execution(EndpointResponseExecutionReceiptInput {
            local_sequence: 12,
            endpoint_id: "endpoint-1",
            signer_identity: "local-edr:endpoint-1",
            actor: response_actor("endpoint-1"),
            policy: EndpointPolicySnapshot {
                policy_version: "test-policy@1".to_string(),
                policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                policy_epoch: 7,
            },
            sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
            execution: &execution_with_conflicting_actor,
            graph: &subgraph,
        });
    assert!(mismatched_execution_actor
        .validate()
        .unwrap_err()
        .to_string()
        .contains("execution actor evidence"));
}

