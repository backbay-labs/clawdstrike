#[test]
fn endpoint_failed_response_execution_receipt_binds_status_reason_and_graph() {
    let event = observation(EndpointEvent::FileAccess {
        operation: FileOperation::Write,
        path: "/tmp/clawdstrike-non-network-target.txt".to_string(),
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
    let plan = EndpointResponsePlan::restrict_egress_execution(
        &process_node_id,
        &subgraph,
        600,
        "restrict graph egress",
    );
    let execution = EndpointResponseExecutionReport::failed(&plan, &subgraph, "no network targets")
        .unwrap_or_else(|err| panic!("failed to build failure report: {err}"));
    let keypair = hush_core::Keypair::from_seed(&[31u8; 32]);
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
    assert_eq!(execution.status, EndpointResponseExecutionStatus::Failed);
    assert!(execution.reason.contains("no network targets"));
    assert!(!receipt.decision.passed);
    assert_eq!(
        receipt.decision.title.as_deref(),
        Some("Endpoint response action failed")
    );
    assert_eq!(
        receipt.graph.process_node_id.as_deref(),
        Some(process_node_id.as_str())
    );
    assert!(receipt.evidence.iter().any(|item| {
        item.key == "executionStatus" && item.value_hash == sha256(b"failed").to_hex_prefixed()
    }));

    let mut mismatched_execution_status = receipt.clone();
    if let Some(status_evidence) = mismatched_execution_status
        .evidence
        .iter_mut()
        .find(|item| item.key == "executionStatus")
    {
        *status_evidence = EndpointReceiptEvidence::hashed("executionStatus", "succeeded");
    }
    assert!(mismatched_execution_status
        .validate()
        .unwrap_err()
        .to_string()
        .contains("execution status evidence hash"));

    let mut mismatched_execution_id = receipt.clone();
    if let Some(execution_id_evidence) = mismatched_execution_id
        .evidence
        .iter_mut()
        .find(|item| item.key == "executionId")
    {
        *execution_id_evidence =
            EndpointReceiptEvidence::hashed("executionId", "response_execution:other");
    }
    assert!(mismatched_execution_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("execution id evidence hash"));

    let mut missing_execution_status = receipt;
    missing_execution_status
        .evidence
        .retain(|item| item.key != "executionStatus");
    assert!(missing_execution_status
        .validate()
        .unwrap_err()
        .to_string()
        .contains("execution status evidence"));
}

#[test]
fn endpoint_quarantine_file_execution_receipt_binds_effect_and_graph() {
    let event = observation(EndpointEvent::FileAccess {
        operation: FileOperation::Write,
        path: "/tmp/clawdstrike-test-malware.sh".to_string(),
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
        "/tmp/clawdstrike-test-malware.sh",
        "/tmp/clawdstrike-quarantine/clawdstrike-test-malware.sh.quarantine",
        "0xabc123",
        128,
    )
    .unwrap_or_else(|err| panic!("failed to build quarantine execution report: {err}"));
    let keypair = hush_core::Keypair::from_seed(&[29u8; 32]);
    let mut receipt =
        EndpointDecisionReceipt::for_response_execution(EndpointResponseExecutionReceiptInput {
            local_sequence: 29,
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
        receipt.decision.action,
        EndpointDecisionAction::QuarantineFile
    );
    assert!(receipt.decision.passed);
    assert_eq!(
        receipt.decision.rollback_ref.as_deref(),
        Some(plan.rollback_ref.as_str())
    );
    assert_eq!(execution.effects.len(), 1);
    assert_eq!(execution.effects[0].effect_type, "quarantine_file");
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "effectCount"));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key.starts_with("executionEffect:")));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key.starts_with("executionEffectType:")));

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

    let mut mismatched_effect_count = receipt.clone();
    if let Some(effect_count_evidence) = mismatched_effect_count
        .evidence
        .iter_mut()
        .find(|item| item.key == "effectCount")
    {
        *effect_count_evidence = EndpointReceiptEvidence::hashed("effectCount", "0");
    }
    assert!(mismatched_effect_count
        .validate()
        .unwrap_err()
        .to_string()
        .contains("execution effect count evidence hash"));

    let mut missing_effect_type = receipt.clone();
    missing_effect_type
        .evidence
        .retain(|item| !item.key.starts_with("executionEffectType:"));
    assert!(missing_effect_type
        .validate()
        .unwrap_err()
        .to_string()
        .contains("execution effect type evidence"));

    let mut mismatched_effect_type = receipt.clone();
    if let Some(effect_type_evidence) = mismatched_effect_type
        .evidence
        .iter_mut()
        .find(|item| item.key.starts_with("executionEffectType:"))
    {
        let key = effect_type_evidence.key.clone();
        *effect_type_evidence = EndpointReceiptEvidence::hashed(key, "disable_persistence");
    }
    assert!(mismatched_effect_type
        .validate()
        .unwrap_err()
        .to_string()
        .contains("execution effect type evidence hash"));

    let mut dropped_effect_evidence = receipt;
    dropped_effect_evidence
        .evidence
        .retain(|item| !item.key.starts_with("executionEffect:"));
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
        .contains("execution effect evidence"));
}

#[test]
fn endpoint_disable_persistence_execution_receipt_binds_effect_and_graph() {
    let event = observation(EndpointEvent::LaunchPersistence {
        path: "/tmp/Library/LaunchAgents/com.example.agent.plist".to_string(),
        label: Some("com.example.agent".to_string()),
        operation: FileOperation::Create,
    });
    let mut graph_recorder = CausalGraphRecorder::new();
    graph_recorder.record_observation(&event);
    let persistence_node_id = graph_recorder
        .graph()
        .nodes
        .values()
        .find(|node| node.kind == CausalNodeKind::File)
        .map(|node| node.node_id.clone())
        .unwrap_or_else(|| panic!("missing persistence file node"));
    let subgraph = graph_recorder
        .graph()
        .causal_subgraph_from(&persistence_node_id, 3)
        .unwrap();
    let plan = EndpointResponsePlan::disable_persistence_execution(
        &persistence_node_id,
        &subgraph,
        600,
        "disable launch agent persistence",
    );
    let execution = EndpointResponseExecutionReport::disable_persistence(
        &plan,
        &subgraph,
        "/tmp/Library/LaunchAgents/com.example.agent.plist",
        "/tmp/clawdstrike-quarantine/com.example.agent.plist.disabled-persistence",
        "0xabc456",
        512,
    )
    .unwrap_or_else(|err| panic!("failed to build persistence execution report: {err}"));
    let keypair = hush_core::Keypair::from_seed(&[33u8; 32]);
    let mut receipt =
        EndpointDecisionReceipt::for_response_execution(EndpointResponseExecutionReceiptInput {
            local_sequence: 33,
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
        receipt.decision.action,
        EndpointDecisionAction::DisablePersistence
    );
    assert!(receipt.decision.passed);
    assert_eq!(
        receipt.decision.rollback_ref.as_deref(),
        Some(plan.rollback_ref.as_str())
    );
    assert_eq!(execution.effects.len(), 1);
    assert_eq!(execution.effects[0].effect_type, "disable_persistence");
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key.starts_with("executionEffect:")));
}

#[test]
fn endpoint_revoke_grant_execution_receipt_binds_revoked_hash_and_graph() {
    let event = observation(EndpointEvent::CredentialAccess {
        kind: CredentialKind::ApiToken,
        path: Some("/Users/alice/.config/clawdstrike/agent-local-token".to_string()),
        name: Some("clawdstrike_agent_auth".to_string()),
    });
    let mut graph_recorder = CausalGraphRecorder::new();
    graph_recorder.record_observation(&event);
    let process_node_id = event.process.stable_node_id();
    let subgraph = graph_recorder
        .graph()
        .causal_subgraph_from(&process_node_id, 3)
        .unwrap();
    let plan = EndpointResponsePlan::revoke_grant_execution(
        &process_node_id,
        &subgraph,
        600,
        "revoke touched local agent API credential",
    );
    let revoked_grant_hash = sha256(b"old-local-token").to_hex_prefixed();
    let execution = EndpointResponseExecutionReport::revoke_grant(
        &plan,
        &subgraph,
        "local_api_auth_token",
        &revoked_grant_hash,
    )
    .unwrap_or_else(|err| panic!("failed to build revoke grant execution report: {err}"));
    let keypair = hush_core::Keypair::from_seed(&[39u8; 32]);
    let mut receipt =
        EndpointDecisionReceipt::for_response_execution(EndpointResponseExecutionReceiptInput {
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
            execution: &execution,
            graph: &subgraph,
        });
    receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

    let signed = receipt.sign_with(&keypair).unwrap();
    let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

    assert!(verification.valid);
    assert_eq!(receipt.decision.action, EndpointDecisionAction::RevokeGrant);
    assert!(receipt.decision.passed);
    assert_eq!(
        receipt.decision.rollback_ref.as_deref(),
        Some(plan.rollback_ref.as_str())
    );
    assert_eq!(execution.effects.len(), 1);
    assert_eq!(execution.effects[0].effect_type, "revoke_grant");
    assert_eq!(execution.effects[0].target, "local_api_auth_token");
    assert_eq!(
        execution.effects[0].content_hash.as_deref(),
        Some(revoked_grant_hash.as_str())
    );
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key.starts_with("executionEffect:")));
}

#[test]
fn endpoint_suspend_process_tree_receipts_bind_pid_set_and_resume_effect() {
    let event = EndpointObservation {
        process: EndpointProcess {
            pid: Some(4242),
            process_guid: Some("proc-suspend-root".to_string()),
            image: Some("/usr/bin/python3".to_string()),
            command_line: Some("python worker.py".to_string()),
            ..EndpointProcess::default()
        },
        event: EndpointEvent::ProcessExec {
            image: "/usr/bin/python3".to_string(),
            args: vec!["worker.py".to_string()],
            env: BTreeMap::new(),
        },
        ..EndpointObservation::default()
    };
    let mut graph_recorder = CausalGraphRecorder::new();
    graph_recorder.record_observation(&event);
    let process_node_id = event.process.stable_node_id();
    let subgraph = graph_recorder
        .graph()
        .causal_subgraph_from(&process_node_id, 3)
        .unwrap();
    let plan = EndpointResponsePlan::suspend_process_tree_execution(
        &process_node_id,
        &subgraph,
        600,
        "contain process tree for 10 minutes",
    );
    let execution =
        EndpointResponseExecutionReport::suspend_process_tree(&plan, &subgraph, 4242, &[4242])
            .unwrap_or_else(|err| panic!("failed to build suspend execution report: {err}"));
    let keypair = hush_core::Keypair::from_seed(&[41u8; 32]);
    let mut receipt =
        EndpointDecisionReceipt::for_response_execution(EndpointResponseExecutionReceiptInput {
            local_sequence: 41,
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
        receipt.decision.action,
        EndpointDecisionAction::SuspendProcessTree
    );
    assert!(receipt.decision.passed);
    assert_eq!(execution.effects.len(), 1);
    assert_eq!(execution.effects[0].effect_type, "suspend_process_tree");
    assert_eq!(execution.effects[0].target, "pid:4242");
    assert_eq!(execution.effects[0].artifact.as_deref(), Some("4242"));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key.starts_with("executionEffect:")));

    let rollback = EndpointResponseRollbackReport::suspend_process_tree(
        &execution,
        "resume contained process tree",
        execution.completed_at + chrono::Duration::seconds(10),
    )
    .unwrap_or_else(|err| panic!("failed to build suspend rollback report: {err}"));
    assert_eq!(rollback.action, EndpointDecisionAction::SuspendProcessTree);
    assert_eq!(rollback.effects.len(), 1);
    assert_eq!(rollback.effects[0].effect_type, "resume_process_tree");
    assert_eq!(
        rollback.effects[0].content_hash,
        execution.effects[0].content_hash
    );
}

#[test]
fn endpoint_terminate_process_tree_execution_report_is_rejected() {
    let event = EndpointObservation {
        process: EndpointProcess {
            pid: Some(4343),
            process_guid: Some("proc-terminate-root".to_string()),
            image: Some("/usr/bin/python3".to_string()),
            command_line: Some("python worker.py".to_string()),
            ..EndpointProcess::default()
        },
        event: EndpointEvent::ProcessExec {
            image: "/usr/bin/python3".to_string(),
            args: vec!["worker.py".to_string()],
            env: BTreeMap::new(),
        },
        ..EndpointObservation::default()
    };
    let mut graph_recorder = CausalGraphRecorder::new();
    graph_recorder.record_observation(&event);
    let process_node_id = event.process.stable_node_id();
    let subgraph = graph_recorder
        .graph()
        .causal_subgraph_from(&process_node_id, 3)
        .unwrap();
    let plan = EndpointResponsePlan::dry_run(
        EndpointDecisionAction::TerminateProcessTree,
        &process_node_id,
        &subgraph,
        60,
        "model terminate process tree only",
    );
    let report_error =
        EndpointResponseExecutionReport::terminate_process_tree(&plan, &subgraph, 4343, &[4343])
            .unwrap_err()
            .to_string();
    assert!(report_error.contains("not rollback-capable"));

    let graph_value = serde_json::to_value(&subgraph)
        .unwrap_or_else(|err| panic!("failed to serialize terminate graph: {err}"));
    let canonical_graph = canonicalize_json(&graph_value)
        .unwrap_or_else(|err| panic!("failed to canonicalize terminate graph: {err}"));
    let graph_content_hash = sha256(canonical_graph.as_bytes()).to_hex_prefixed();
    let effect = EndpointResponseExecutionEffect::terminate_process_tree(4343, &[4343]);
    let completed_at = Utc::now();
    let execution = EndpointResponseExecutionReport {
        execution_id: "response_execution:forged_terminate".to_string(),
        action_id: plan.action_id.clone(),
        action: EndpointDecisionAction::TerminateProcessTree,
        status: EndpointResponseExecutionStatus::Succeeded,
        dry_run: false,
        root_node_id: plan.root_node_id.clone(),
        graph_slice_id: plan.graph_slice_id.clone(),
        ttl_seconds: plan.ttl_seconds,
        rollback_ref: plan.rollback_ref.clone(),
        reason: plan.reason.clone(),
        started_at: completed_at,
        completed_at,
        evidence_bundle: EndpointEvidenceBundleReference {
            bundle_id: "evidence_bundle:forged_terminate".to_string(),
            graph_slice_id: plan.graph_slice_id.clone(),
            content_hash: graph_content_hash,
            node_count: subgraph.nodes.len(),
            edge_count: subgraph.edges.len(),
            created_at: completed_at,
        },
        actor: None,
        effects: vec![effect],
        summary: "forged terminate process tree execution".to_string(),
    };
    let keypair = hush_core::Keypair::from_seed(&[43u8; 32]);
    let mut receipt =
        EndpointDecisionReceipt::for_response_execution(EndpointResponseExecutionReceiptInput {
            local_sequence: 43,
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

    let err = receipt.sign_with(&keypair).unwrap_err().to_string();
    assert!(err.contains("dry-run response requests"));
    assert_eq!(
        receipt.decision.action,
        EndpointDecisionAction::TerminateProcessTree
    );
    assert!(receipt.decision.passed);
    assert_eq!(execution.effects.len(), 1);
    assert_eq!(execution.effects[0].effect_type, "terminate_process_tree");
    assert_eq!(execution.effects[0].target, "pid:4343");
    assert_eq!(execution.effects[0].artifact.as_deref(), Some("4343"));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key.starts_with("executionEffect:")));
}

#[test]
fn endpoint_response_rollback_receipt_binds_restore_effect() {
    let event = observation(EndpointEvent::FileAccess {
        operation: FileOperation::Write,
        path: "/tmp/clawdstrike-test-rollback.sh".to_string(),
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
        "/tmp/clawdstrike-test-rollback.sh",
        "/tmp/clawdstrike-quarantine/clawdstrike-test-rollback.sh.quarantine",
        "0xdef456",
        256,
    )
    .unwrap_or_else(|err| panic!("failed to build quarantine execution report: {err}"));
    let rollback = EndpointResponseRollbackReport::quarantine_file(
        &execution,
        "restore quarantined test file",
        execution.completed_at + chrono::Duration::seconds(30),
    )
    .unwrap_or_else(|err| panic!("failed to build rollback report: {err}"));
    let keypair = hush_core::Keypair::from_seed(&[31u8; 32]);
    let mut receipt =
        EndpointDecisionReceipt::for_response_rollback(EndpointResponseRollbackReceiptInput {
            local_sequence: 31,
            endpoint_id: "endpoint-1",
            signer_identity: "local-edr:endpoint-1",
            actor: response_actor("endpoint-1"),
            policy: EndpointPolicySnapshot {
                policy_version: "test-policy@1".to_string(),
                policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                policy_epoch: 7,
            },
            sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
            rollback: &rollback,
            graph: &subgraph,
        });
    receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

    let signed = receipt.sign_with(&keypair).unwrap();
    let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

    assert!(verification.valid);
    assert_eq!(
        receipt.receipt_family,
        EndpointDecisionReceiptFamily::ResponseRollback
    );
    assert_eq!(receipt.decision.finding_id, Some(rollback.rollback_id));
    assert_eq!(
        receipt.decision.action,
        EndpointDecisionAction::QuarantineFile
    );
    assert!(receipt.decision.passed);
    assert_eq!(
        receipt.decision.rollback_ref.as_deref(),
        Some(plan.rollback_ref.as_str())
    );
    assert_eq!(rollback.effects.len(), 1);
    assert_eq!(rollback.effects[0].effect_type, "restore_quarantine_file");
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "rollbackStatus"));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key.starts_with("rollbackEffect:")));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key.starts_with("rollbackEffectType:")));

    let mut mismatched_rollback_status = receipt.clone();
    if let Some(status_evidence) = mismatched_rollback_status
        .evidence
        .iter_mut()
        .find(|item| item.key == "rollbackStatus")
    {
        *status_evidence = EndpointReceiptEvidence::hashed("rollbackStatus", "failed");
    }
    assert!(mismatched_rollback_status
        .validate()
        .unwrap_err()
        .to_string()
        .contains("rollback status evidence hash"));

    let mut mismatched_rollback_id = receipt.clone();
    if let Some(rollback_id_evidence) = mismatched_rollback_id
        .evidence
        .iter_mut()
        .find(|item| item.key == "rollbackId")
    {
        *rollback_id_evidence =
            EndpointReceiptEvidence::hashed("rollbackId", "response_rollback:other");
    }
    assert!(mismatched_rollback_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("rollback id evidence hash"));

    let mut mismatched_execution_id = receipt.clone();
    if let Some(execution_id_evidence) = mismatched_execution_id
        .evidence
        .iter_mut()
        .find(|item| item.key == "executionId")
    {
        *execution_id_evidence =
            EndpointReceiptEvidence::hashed("executionId", "response_execution:other");
    }
    assert!(mismatched_execution_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("rollback execution id evidence hash"));

    let mut empty_rollback_effect = receipt.clone();
    if let Some(effect_evidence) = empty_rollback_effect
        .evidence
        .iter_mut()
        .find(|item| item.key.starts_with("rollbackEffect:"))
    {
        let effect_key = effect_evidence.key.clone();
        *effect_evidence = EndpointReceiptEvidence::hashed(effect_key, "");
    }
    let response_action_id = empty_rollback_effect
        .decision
        .rollback_ref
        .as_deref()
        .and_then(|rollback_ref| rollback_ref.strip_prefix("rollback:"))
        .unwrap();
    let rollback_id = response_rollback_id_from_signed_evidence(
        &empty_rollback_effect.evidence,
        response_action_id,
        empty_rollback_effect
            .decision
            .rollback_ref
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    empty_rollback_effect.decision.finding_id = Some(rollback_id.clone());
    if let Some(rollback_id_evidence) = empty_rollback_effect
        .evidence
        .iter_mut()
        .find(|item| item.key == "rollbackId")
    {
        *rollback_id_evidence = EndpointReceiptEvidence::hashed("rollbackId", rollback_id);
    }
    assert!(empty_rollback_effect
        .validate()
        .unwrap_err()
        .to_string()
        .contains("rollback effect evidence"));

    let mut missing_rollback_effect_type = receipt.clone();
    missing_rollback_effect_type
        .evidence
        .retain(|item| !item.key.starts_with("rollbackEffectType:"));
    assert!(missing_rollback_effect_type
        .validate()
        .unwrap_err()
        .to_string()
        .contains("rollback effect type evidence"));

    let mut mismatched_rollback_effect_type = receipt.clone();
    if let Some(effect_type_evidence) = mismatched_rollback_effect_type
        .evidence
        .iter_mut()
        .find(|item| item.key.starts_with("rollbackEffectType:"))
    {
        let key = effect_type_evidence.key.clone();
        *effect_type_evidence = EndpointReceiptEvidence::hashed(key, "resume_process_tree");
    }
    assert!(mismatched_rollback_effect_type
        .validate()
        .unwrap_err()
        .to_string()
        .contains("rollback effect type evidence hash"));

    let mut missing_execution_id = receipt.clone();
    missing_execution_id
        .evidence
        .retain(|item| item.key != "executionId");
    assert!(missing_execution_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("rollback execution id evidence"));

    let mut missing_rollback_status = receipt;
    missing_rollback_status
        .evidence
        .retain(|item| item.key != "rollbackStatus");
    assert!(missing_rollback_status
        .validate()
        .unwrap_err()
        .to_string()
        .contains("rollback status evidence"));
}

#[test]
fn endpoint_response_acknowledgement_receipt_binds_execution_status_and_actor() {
    let event = observation(EndpointEvent::NetworkFlow {
        host: "ack.example".to_string(),
        port: 443,
        protocol: Some("tcp".to_string()),
        url: Some("https://ack.example/upload".to_string()),
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
        Some("reviewed local response outcome".to_string()),
        execution.completed_at + chrono::Duration::seconds(5),
    )
    .with_control_correlation(Some(EndpointResponseControlCorrelation {
        response_action_id: "11111111-1111-4111-8111-111111111111".to_string(),
        delivery_id: Some("22222222-2222-4222-8222-222222222222".to_string()),
        target_kind: "endpoint".to_string(),
        target_id: "endpoint-1".to_string(),
        ack_token_hash: sha256(b"control-ack-token").to_hex_prefixed(),
        ack_status: "acknowledged".to_string(),
        resulting_state: Some("succeeded".to_string()),
    }));
    let keypair = hush_core::Keypair::from_seed(&[37u8; 32]);
    let mut receipt = EndpointDecisionReceipt::for_response_acknowledgement(
        EndpointResponseAcknowledgementReceiptInput {
            local_sequence: 37,
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
    receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

    let signed = receipt.sign_with(&keypair).unwrap();
    let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

    assert!(verification.valid);
    assert_eq!(
        receipt.receipt_family,
        EndpointDecisionReceiptFamily::ResponseAcknowledgement
    );
    assert_eq!(
        receipt.decision.finding_id,
        Some(acknowledgement.acknowledgement_id)
    );
    assert_eq!(receipt.actor.agent_id.as_deref(), Some("operator:test"));
    assert_eq!(
        receipt.decision.rollback_ref.as_deref(),
        Some(plan.rollback_ref.as_str())
    );
    assert_eq!(receipt.decision.ttl_seconds, Some(600));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "acknowledgedStatus"));
    assert!(receipt.evidence.iter().any(|item| item.key == "rootNodeId"));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "graphSliceId"));
    assert!(receipt.evidence.iter().any(|item| item.key == "note"));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "controlResponseActionId"));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "controlDeliveryId"));
    assert!(receipt.evidence.iter().any(|item| {
        item.key == "controlAckTokenHash"
            && item.redaction_class == EndpointEvidenceRedactionClass::HashOnly
            && item.raw_value.is_none()
    }));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "controlAckStatus"));

    let mut mismatched_acknowledgement_id = receipt.clone();
    if let Some(acknowledgement_id_evidence) = mismatched_acknowledgement_id
        .evidence
        .iter_mut()
        .find(|item| item.key == "acknowledgementId")
    {
        *acknowledgement_id_evidence =
            EndpointReceiptEvidence::hashed("acknowledgementId", "response_acknowledgement:other");
    }
    assert!(mismatched_acknowledgement_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("acknowledgement id evidence hash"));

    let mut mismatched_acknowledged_status = receipt.clone();
    if let Some(status_evidence) = mismatched_acknowledged_status
        .evidence
        .iter_mut()
        .find(|item| item.key == "acknowledgedStatus")
    {
        *status_evidence = EndpointReceiptEvidence::hashed("acknowledgedStatus", "failed");
    }
    assert!(mismatched_acknowledged_status
        .validate()
        .unwrap_err()
        .to_string()
        .contains("acknowledgement status evidence hash"));

    let mut mismatched_acknowledged_by = receipt.clone();
    if let Some(acknowledged_by_evidence) = mismatched_acknowledged_by
        .evidence
        .iter_mut()
        .find(|item| item.key == "acknowledgedBy")
    {
        *acknowledged_by_evidence =
            EndpointReceiptEvidence::hashed("acknowledgedBy", "operator:other");
    }
    assert!(mismatched_acknowledged_by
        .validate()
        .unwrap_err()
        .to_string()
        .contains("acknowledged-by evidence hash"));

    let mut empty_note = receipt.clone();
    if let Some(note_evidence) = empty_note
        .evidence
        .iter_mut()
        .find(|item| item.key == "note")
    {
        *note_evidence = EndpointReceiptEvidence::hashed("note", "");
    }
    assert!(empty_note
        .validate()
        .unwrap_err()
        .to_string()
        .contains("acknowledgement note evidence"));

    let mut missing_control_target = receipt.clone();
    missing_control_target
        .evidence
        .retain(|item| item.key != "controlTargetId");
    assert!(missing_control_target
        .validate()
        .unwrap_err()
        .to_string()
        .contains("control acknowledgement target id evidence"));

    let mut empty_control_ack_token = receipt.clone();
    if let Some(token_hash) = empty_control_ack_token
        .evidence
        .iter_mut()
        .find(|item| item.key == "controlAckTokenHash")
    {
        token_hash.value_hash = sha256(b"").to_hex_prefixed();
    }
    assert!(empty_control_ack_token
        .validate()
        .unwrap_err()
        .to_string()
        .contains("control acknowledgement token hash"));

    let mut relabeled_control_target = receipt.clone();
    if let Some(control_target) = relabeled_control_target
        .evidence
        .iter_mut()
        .find(|item| item.key == "controlTargetId")
    {
        *control_target = EndpointReceiptEvidence::hashed("controlTargetId", "endpoint-other");
    }
    assert!(relabeled_control_target
        .validate()
        .unwrap_err()
        .to_string()
        .contains("acknowledgement execution id evidence hash"));

    let invalid_control_status_acknowledgement =
        EndpointResponseAcknowledgementReport::from_execution(
            &execution,
            "operator:test",
            Some("invalid control acknowledgement status".to_string()),
            execution.completed_at + chrono::Duration::seconds(6),
        )
        .with_control_correlation(Some(EndpointResponseControlCorrelation {
            response_action_id: "11111111-1111-4111-8111-111111111111".to_string(),
            delivery_id: Some("22222222-2222-4222-8222-222222222222".to_string()),
            target_kind: "endpoint".to_string(),
            target_id: "endpoint-1".to_string(),
            ack_token_hash: sha256(b"control-ack-token").to_hex_prefixed(),
            ack_status: "queued".to_string(),
            resulting_state: Some("queued".to_string()),
        }));
    let invalid_control_status_receipt = EndpointDecisionReceipt::for_response_acknowledgement(
        EndpointResponseAcknowledgementReceiptInput {
            local_sequence: 137,
            endpoint_id: "endpoint-1",
            signer_identity: "local-edr:endpoint-1",
            actor: response_actor("endpoint-1"),
            policy: EndpointPolicySnapshot {
                policy_version: "test-policy@1".to_string(),
                policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                policy_epoch: 7,
            },
            sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
            acknowledgement: &invalid_control_status_acknowledgement,
            graph: &subgraph,
        },
    );
    assert!(invalid_control_status_receipt
        .validate()
        .unwrap_err()
        .to_string()
        .contains("control acknowledgement status evidence"));

    let invalid_control_target_kind_acknowledgement =
        EndpointResponseAcknowledgementReport::from_execution(
            &execution,
            "operator:test",
            Some("invalid control acknowledgement target kind".to_string()),
            execution.completed_at + chrono::Duration::seconds(7),
        )
        .with_control_correlation(Some(EndpointResponseControlCorrelation {
            response_action_id: "11111111-1111-4111-8111-111111111111".to_string(),
            delivery_id: Some("22222222-2222-4222-8222-222222222222".to_string()),
            target_kind: "deployment".to_string(),
            target_id: "endpoint-1".to_string(),
            ack_token_hash: sha256(b"control-ack-token").to_hex_prefixed(),
            ack_status: "acknowledged".to_string(),
            resulting_state: Some("succeeded".to_string()),
        }));
    let invalid_control_target_kind_receipt = EndpointDecisionReceipt::for_response_acknowledgement(
        EndpointResponseAcknowledgementReceiptInput {
            local_sequence: 138,
            endpoint_id: "endpoint-1",
            signer_identity: "local-edr:endpoint-1",
            actor: response_actor("endpoint-1"),
            policy: EndpointPolicySnapshot {
                policy_version: "test-policy@1".to_string(),
                policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                policy_epoch: 7,
            },
            sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
            acknowledgement: &invalid_control_target_kind_acknowledgement,
            graph: &subgraph,
        },
    );
    assert!(invalid_control_target_kind_receipt
        .validate()
        .unwrap_err()
        .to_string()
        .contains("control acknowledgement target kind evidence"));

    let mut mismatched_execution_id = receipt.clone();
    if let Some(execution_id_evidence) = mismatched_execution_id
        .evidence
        .iter_mut()
        .find(|item| item.key == "executionId")
    {
        *execution_id_evidence =
            EndpointReceiptEvidence::hashed("executionId", "response_execution:other");
    }
    assert!(mismatched_execution_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("acknowledgement execution id evidence hash"));

    let mut missing_execution_id = receipt.clone();
    missing_execution_id
        .evidence
        .retain(|item| item.key != "executionId");
    assert!(missing_execution_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("acknowledgement execution id evidence"));

    let mut missing_acknowledged_status = receipt;
    missing_acknowledged_status
        .evidence
        .retain(|item| item.key != "acknowledgedStatus");
    assert!(missing_acknowledged_status
        .validate()
        .unwrap_err()
        .to_string()
        .contains("acknowledgement status evidence"));
}

