use super::*;

pub(crate) async fn emit_edr_detection_receipts(
    state: &AgentApiState,
    observations: &[EndpointObservation],
    findings: &[DetectionFinding],
    graph: &CausalGraph,
) -> Result<Vec<SignedReceipt>> {
    if findings.is_empty() {
        return Ok(Vec::new());
    }

    let settings = state.settings.read().await.clone();
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipts = ledger.sign_detection_receipts(
        &settings,
        policy,
        sensor_state,
        observations,
        findings,
        graph,
    )?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(state, &receipts, "detection").await;
    Ok(receipts)
}

pub(crate) async fn emit_edr_provider_observation_receipts(
    state: &AgentApiState,
    observations: &[EndpointObservation],
    upload_path: &str,
) -> Result<Vec<SignedReceipt>> {
    if observations.is_empty() {
        return Ok(Vec::new());
    }

    let settings = state.settings.read().await.clone();
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let graph = graph_for_observations(observations);
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipts = ledger.sign_observation_receipts(&settings, policy, observations, &graph)?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(state, &receipts, upload_path).await;
    Ok(receipts)
}

pub(crate) fn graph_for_observations(observations: &[EndpointObservation]) -> CausalGraph {
    let mut recorder = CausalGraphRecorder::new();
    for observation in observations {
        recorder.record_observation(observation);
    }
    recorder.into_graph()
}

pub(crate) async fn emit_edr_sensor_state_receipt(
    state: &AgentApiState,
    policy: EndpointPolicySnapshot,
    sensor_state: EndpointSensorState,
    reason: &str,
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt = ledger.sign_sensor_state_receipt(&settings, policy, sensor_state, reason)?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "sensor_state",
    )
    .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_sensor_state_receipt_with_evidence(
    state: &AgentApiState,
    policy: EndpointPolicySnapshot,
    sensor_state: EndpointSensorState,
    reason: &str,
    additional_evidence: &[EndpointReceiptEvidence],
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt = ledger.sign_sensor_state_receipt_with_evidence(
        &settings,
        policy,
        sensor_state,
        reason,
        additional_evidence,
    )?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "sensor_state",
    )
    .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_telemetry_privacy_receipt(
    state: &AgentApiState,
    report: &EndpointTelemetryPrivacyReport,
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt = ledger.sign_telemetry_privacy_receipt(&settings, policy, sensor_state, report)?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "privacy_report",
    )
    .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_provider_degradation_receipts(
    state: &AgentApiState,
    policy: EndpointPolicySnapshot,
    sensor_state: EndpointSensorState,
) -> Result<Vec<SignedReceipt>> {
    let settings = state.settings.read().await.clone();
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipts = ledger.sign_provider_degradation_receipts(&settings, policy, sensor_state)?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(state, &receipts, "provider_degradation").await;
    Ok(receipts)
}

pub(crate) async fn emit_edr_policy_decision_receipt(
    state: &AgentApiState,
    input: &PolicyCheckInput,
    decision: &PolicyCheckOutput,
    session_id: Option<&str>,
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let session_state = state.session_manager.state().await;
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let receipt_observation =
        policy_check_receipt_observation(&settings, input, decision, &session_state, session_id);
    record_edr_observations(state, std::slice::from_ref(&receipt_observation))
        .await
        .map_err(|(_, err)| anyhow::anyhow!(err))?;
    let graph = state.edr_flight_recorder.lock().await.graph().clone();
    let actor = EndpointDecisionActor {
        endpoint_id: endpoint_id_for_settings(&settings),
        session_id: session_id
            .map(ToString::to_string)
            .or_else(|| session_state.session_id.clone()),
        posture: Some(session_state.posture),
        agent_id: input
            .runtime_agent_id
            .clone()
            .or_else(|| input.endpoint_agent_id.clone())
            .or_else(|| input.agent_id.clone()),
        workload_id: input.runtime_agent_kind.clone(),
        ..EndpointDecisionActor::default()
    };
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt = ledger.sign_policy_decision_receipt(PolicyDecisionReceiptSigningInput {
        actor,
        policy,
        sensor_state,
        observation: &receipt_observation,
        graph: &graph,
        action_type: input.action_type.as_str(),
        target: input.target.as_str(),
        decision,
    })?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "policy_decision",
    )
    .await;
    Ok(receipt)
}

pub(crate) fn policy_check_receipt_observation(
    settings: &Settings,
    input: &PolicyCheckInput,
    decision: &PolicyCheckOutput,
    session_state: &SessionState,
    session_id: Option<&str>,
) -> EndpointObservation {
    let now = chrono::Utc::now();
    let endpoint_id = endpoint_id_for_settings(settings);
    let allowed_text = if decision.allowed {
        "allowed"
    } else {
        "blocked"
    };
    let observed_at = now.to_rfc3339();
    let observation_id = local_stable_id(
        "policy_decision_observation",
        [
            endpoint_id.as_str(),
            input.action_type.as_str(),
            input.target.as_str(),
            allowed_text,
            observed_at.as_str(),
        ],
    );
    let process_guid = local_stable_id("process", [endpoint_id.as_str(), "agent-api-policy-check"]);
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "receiptSource".to_string(),
        serde_json::json!("agent_policy_check"),
    );
    metadata.insert(
        "policyCheckActionType".to_string(),
        serde_json::json!(input.action_type),
    );
    metadata.insert(
        "policyCheckTargetHash".to_string(),
        serde_json::json!(sha256(input.target.as_bytes()).to_hex_prefixed()),
    );
    if let Some(runtime_agent_id) = input
        .runtime_agent_id
        .as_deref()
        .or(input.endpoint_agent_id.as_deref())
        .or(input.agent_id.as_deref())
    {
        metadata.insert("agentId".to_string(), serde_json::json!(runtime_agent_id));
    }
    if let Some(runtime_agent_kind) = input.runtime_agent_kind.as_deref() {
        metadata.insert(
            "workloadId".to_string(),
            serde_json::json!(runtime_agent_kind),
        );
    }

    EndpointObservation {
        observation_id,
        timestamp: now,
        host_id: Some(endpoint_id),
        user_id: None,
        session_id: session_id
            .map(ToString::to_string)
            .or_else(|| session_state.session_id.clone()),
        process: EndpointProcess {
            process_guid: Some(process_guid),
            image: Some("agent-api".to_string()),
            command_line: Some("agent-api policy-check".to_string()),
            ..EndpointProcess::default()
        },
        event: EndpointEvent::PolicyDecision {
            action: input.action_type.clone(),
            target: Some(input.target.clone()),
            decision: allowed_text.to_string(),
            guard: decision.guard.clone(),
            severity: decision.severity.clone(),
        },
        metadata,
    }
}

pub(crate) struct ProviderPolicyDecisionReceiptCandidate {
    actor: EndpointDecisionActor,
    sensor_state: EndpointSensorState,
    observation: EndpointObservation,
    action_type: String,
    target: String,
    decision: PolicyCheckOutput,
}

pub(crate) async fn emit_edr_provider_policy_decision_receipts(
    state: &AgentApiState,
    observations: &[EndpointObservation],
    upload_path: &str,
) -> Result<Vec<SignedReceipt>> {
    let settings = state.settings.read().await.clone();
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let mut candidates = Vec::new();

    for observation in observations {
        let EndpointEvent::PolicyDecision {
            action,
            target,
            decision,
            guard,
            severity,
        } = &observation.event
        else {
            continue;
        };
        let Some(action_type) = trimmed_owned(Some(action.as_str())) else {
            continue;
        };
        let Some(target) = target
            .as_deref()
            .and_then(|value| trimmed_owned(Some(value)))
        else {
            continue;
        };
        let Some(allowed) = provider_policy_decision_allowed(decision) else {
            tracing::warn!(
                observation_id = %observation.observation_id,
                decision = decision.as_str(),
                "Skipping provider policy-decision receipt with unrecognized decision value"
            );
            continue;
        };
        let provider = provider_policy_decision_provider_state(observation);
        let details = provider_policy_decision_details(observation, &provider);
        candidates.push(ProviderPolicyDecisionReceiptCandidate {
            actor: EndpointDecisionActor::from_observation(
                endpoint_id_for_observation(&settings, observation),
                observation,
            ),
            sensor_state: EndpointSensorState {
                providers: vec![provider],
            },
            observation: observation.clone(),
            action_type,
            target,
            decision: PolicyCheckOutput {
                allowed,
                guard: guard
                    .clone()
                    .and_then(|value| trimmed_owned(Some(value.as_str()))),
                severity: severity
                    .clone()
                    .and_then(|value| trimmed_owned(Some(value.as_str()))),
                message: Some(if allowed {
                    "Provider policy decision allowed".to_string()
                } else {
                    "Provider policy decision blocked".to_string()
                }),
                details: Some(details),
            },
        });
    }

    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    let mut receipts = Vec::with_capacity(candidates.len());
    let graph = state.edr_flight_recorder.lock().await.graph().clone();
    let mut ledger = state.edr_receipt_ledger.lock().await;
    for candidate in candidates {
        receipts.push(
            ledger.sign_policy_decision_receipt(PolicyDecisionReceiptSigningInput {
                actor: candidate.actor,
                policy: policy.clone(),
                sensor_state: candidate.sensor_state,
                observation: &candidate.observation,
                graph: &graph,
                action_type: candidate.action_type.as_str(),
                target: candidate.target.as_str(),
                decision: &candidate.decision,
            })?,
        );
    }
    drop(ledger);
    post_control_endpoint_receipts_best_effort(state, &receipts, upload_path).await;
    Ok(receipts)
}

pub(crate) fn provider_policy_decision_allowed(decision: &str) -> Option<bool> {
    match decision.trim().to_ascii_lowercase().as_str() {
        "allow" | "allowed" | "pass" | "passed" | "permit" | "permitted" => Some(true),
        "block" | "blocked" | "deny" | "denied" | "drop" | "dropped" => Some(false),
        _ => None,
    }
}

pub(crate) fn provider_policy_decision_provider_state(
    observation: &EndpointObservation,
) -> EndpointProviderState {
    let collector_kind = observation_metadata_string(observation, "collectorKind");
    let provider_id = observation_metadata_string(observation, "providerId")
        .unwrap_or_else(|| "provider.policy_decision".to_string());
    let provider_kind = match collector_kind.as_deref() {
        Some("endpoint_security") => EndpointProviderKind::EndpointSecurity,
        Some("network_extension") => EndpointProviderKind::NetworkExtension,
        Some("darwin_bridge") => EndpointProviderKind::DarwinBridge,
        Some("policy_engine") => EndpointProviderKind::PolicyEngine,
        Some("agent_api") => EndpointProviderKind::AgentApi,
        _ => EndpointProviderKind::Other,
    };

    EndpointProviderState {
        provider_id,
        provider_kind,
        installed: true,
        active: true,
        healthy: true,
        degraded: false,
        degradation_reasons: Vec::new(),
        dropped_event_count: 0,
        deadline_miss_count: 0,
        full_disk_access: None,
        last_seen: Some(observation.timestamp),
    }
}

pub(crate) fn provider_policy_decision_details(
    observation: &EndpointObservation,
    provider: &EndpointProviderState,
) -> serde_json::Value {
    serde_json::json!({
        "source": "provider_policy_decision_observation",
        "observationId": observation.observation_id.as_str(),
        "providerId": provider.provider_id.as_str(),
        "providerKind": &provider.provider_kind,
        "collectorKind": observation_metadata_string(observation, "collectorKind"),
        "process": {
            "pid": observation.process.pid,
            "ppid": observation.process.ppid,
            "processGuid": observation.process.process_guid.as_deref(),
            "parentProcessGuid": observation.process.parent_process_guid.as_deref(),
            "image": observation.process.image.as_deref(),
            "commandLine": observation.process.command_line.as_deref(),
        },
        "metadata": &observation.metadata,
    })
}

pub(crate) fn observation_metadata_string(
    observation: &EndpointObservation,
    key: &str,
) -> Option<String> {
    observation
        .metadata
        .get(key)
        .and_then(serde_json::Value::as_str)
        .and_then(|value| trimmed_owned(Some(value)))
}

pub(crate) async fn emit_edr_graph_slice_receipt(
    state: &AgentApiState,
    root_node_id: &str,
    slice_kind: &str,
    graph: &CausalGraph,
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt = ledger.sign_graph_slice_receipt(
        &settings,
        policy,
        sensor_state,
        root_node_id,
        slice_kind,
        graph,
    )?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "graph_slice",
    )
    .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_simulation_receipt(
    state: &AgentApiState,
    simulation: &EndpointPolicySimulationReport,
    graph: &CausalGraph,
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    emit_edr_simulation_receipt_with_policy(state, &settings, policy, simulation, graph).await
}

pub(crate) async fn emit_edr_simulation_receipt_with_policy(
    state: &AgentApiState,
    settings: &Settings,
    policy: EndpointPolicySnapshot,
    simulation: &EndpointPolicySimulationReport,
    graph: &CausalGraph,
) -> Result<SignedReceipt> {
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt =
        ledger.sign_simulation_receipt(settings, policy, sensor_state, simulation, graph)?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(state, std::slice::from_ref(&receipt), "simulation")
        .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_policy_event_replay_receipt(
    state: &AgentApiState,
    settings: &Settings,
    replay: &EdrPolicyEventReplayReport,
) -> Result<SignedReceipt> {
    let policy = replay.policy.clone();
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt =
        ledger.sign_policy_event_replay_receipt(settings, policy, sensor_state, replay)?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "policy_event_replay",
    )
    .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_policy_event_impact_receipt(
    state: &AgentApiState,
    settings: &Settings,
    impact: &EdrPolicyEventImpactReport,
) -> Result<SignedReceipt> {
    let policy = impact.current_policy.clone();
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt =
        ledger.sign_policy_event_impact_receipt(settings, policy, sensor_state, impact)?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "policy_event_impact",
    )
    .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_deception_materialization_receipt(
    state: &AgentApiState,
    plan: &DeceptionPlan,
    report: &DeceptionMaterializationReport,
    registered_artifact_count: usize,
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt = ledger.sign_deception_materialization_receipt(
        &settings,
        policy,
        sensor_state,
        plan,
        report,
        registered_artifact_count,
    )?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "deception_materialization",
    )
    .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_deception_cleanup_receipt(
    state: &AgentApiState,
    plan: &DeceptionPlan,
    report: &DeceptionCleanupReport,
    deregistered_artifact_count: usize,
    remaining_registered_artifact_count: usize,
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt = ledger.sign_deception_cleanup_receipt(DeceptionCleanupReceiptSigningInput {
        settings: &settings,
        policy,
        sensor_state,
        plan,
        report,
        deregistered_artifact_count,
        remaining_registered_artifact_count,
    })?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "deception_cleanup",
    )
    .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_deception_rotation_receipt(
    state: &AgentApiState,
    old_plan: &DeceptionPlan,
    new_plan: &DeceptionPlan,
    report: &DeceptionRotationReport,
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt = ledger.sign_deception_rotation_receipt(DeceptionRotationReceiptSigningInput {
        settings: &settings,
        policy,
        sensor_state,
        old_plan,
        new_plan,
        report,
    })?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "deception_rotation",
    )
    .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_response_receipt(
    state: &AgentApiState,
    actor: EndpointDecisionActor,
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt =
        ledger.sign_response_receipt(&settings, actor, policy, sensor_state, plan, graph)?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "response_request",
    )
    .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_response_execution_receipt(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    graph: &CausalGraph,
    actor: Option<EndpointDecisionActor>,
    extra_evidence: &[EndpointReceiptEvidence],
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let actor = if let Some(actor) = actor {
        actor
    } else {
        let session_state = state.session_manager.state().await;
        endpoint_response_actor_from_session(&settings, &session_state, "agent-api")
    };
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let macos_host = state.macos_host.snapshot().await;
    let sensor_state = endpoint_sensor_state_from_macos_host(&macos_host);
    let mut additional_evidence = if execution.action == EndpointDecisionAction::RestrictEgress {
        network_extension_response_execution_evidence(&macos_host.network_extension)
    } else {
        Vec::new()
    };
    additional_evidence.extend(extra_evidence.iter().cloned());
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt = ledger.sign_response_execution_receipt(ResponseExecutionReceiptSigningInput {
        settings: &settings,
        actor,
        policy,
        sensor_state,
        execution,
        graph,
        additional_evidence: &additional_evidence,
    })?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "response_execution",
    )
    .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_response_rollback_receipt(
    state: &AgentApiState,
    rollback: &EndpointResponseRollbackReport,
    graph: &CausalGraph,
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let session_state = state.session_manager.state().await;
    let actor = endpoint_response_actor_from_session(&settings, &session_state, "agent-api");
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt = ledger.sign_response_rollback_receipt(
        &settings,
        actor,
        policy,
        sensor_state,
        rollback,
        graph,
    )?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "response_rollback",
    )
    .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_response_acknowledgement_receipt(
    state: &AgentApiState,
    acknowledgement: &EndpointResponseAcknowledgementReport,
    graph: &CausalGraph,
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let session_state = state.session_manager.state().await;
    let actor = endpoint_response_actor_from_session(
        &settings,
        &session_state,
        acknowledgement.acknowledged_by.as_str(),
    );
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt = ledger.sign_response_acknowledgement_receipt(
        &settings,
        actor,
        policy,
        sensor_state,
        acknowledgement,
        graph,
    )?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "response_acknowledgement",
    )
    .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_evidence_bundle_manifest_receipt(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    graph: &CausalGraph,
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt = ledger.sign_evidence_bundle_manifest_receipt(
        &settings,
        policy,
        sensor_state,
        execution,
        graph,
    )?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "evidence_bundle_manifest",
    )
    .await;
    Ok(receipt)
}

pub(crate) fn receipt_matches_filter(
    receipt: &SignedReceipt,
    filter: EdrReceiptFilter<'_>,
) -> bool {
    if let Some(expected) = filter.receipt_id {
        if !receipt
            .receipt
            .receipt_id
            .as_deref()
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.family {
        if !receipt_family(receipt)
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.action {
        if !receipt_endpoint_decision_str(receipt, &["decision", "action"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.finding_id {
        if !receipt_endpoint_decision_str(receipt, &["decision", "findingId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.rule_id {
        if !receipt_endpoint_decision_str(receipt, &["decision", "ruleId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.graph_slice_id {
        if !receipt_endpoint_decision_str(receipt, &["graph", "graphSliceId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.root_node_id {
        if !receipt_endpoint_decision_str(receipt, &["graph", "processNodeId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.execution_id {
        if !receipt_endpoint_decision_str(receipt, &["decision", "findingId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
            && !receipt_evidence_hash_matches(receipt, "executionId", expected)
        {
            return false;
        }
    }
    if let Some(expected) = filter.status {
        if !receipt_evidence_hash_matches(receipt, "executionStatus", expected) {
            return false;
        }
    }
    if let Some(expected) = filter.actor_endpoint_id {
        if !receipt_endpoint_decision_str(receipt, &["actor", "endpointId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.actor_user_id {
        if !receipt_endpoint_decision_str(receipt, &["actor", "userId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.actor_session_id {
        if !receipt_endpoint_decision_str(receipt, &["actor", "sessionId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.actor_agent_id {
        if !receipt_endpoint_decision_str(receipt, &["actor", "agentId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.actor_workload_id {
        if !receipt_endpoint_decision_str(receipt, &["actor", "workloadId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.actor_approval_id {
        if !receipt_endpoint_decision_str(receipt, &["actor", "approvalId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.local_sequence {
        if receipt_local_sequence(receipt) != Some(expected) {
            return false;
        }
    }
    true
}

pub(crate) fn receipt_evidence_hash_matches(
    receipt: &SignedReceipt,
    key: &str,
    raw_value: &str,
) -> bool {
    let expected_hash = sha256(raw_value.as_bytes()).to_hex_prefixed();
    receipt_evidence_hash_value(receipt, key) == Some(expected_hash.as_str())
}

pub(crate) fn receipt_evidence_hash_value<'a>(
    receipt: &'a SignedReceipt,
    key: &str,
) -> Option<&'a str> {
    receipt_endpoint_decision_value(receipt, &["evidence"])
        .and_then(serde_json::Value::as_array)
        .and_then(|items| {
            items.iter().find_map(|item| {
                if item.get("key").and_then(serde_json::Value::as_str) == Some(key) {
                    item.get("valueHash").and_then(serde_json::Value::as_str)
                } else {
                    None
                }
            })
        })
}

pub(crate) fn verify_response_execution_proof_contract(
    execution: &EndpointResponseExecutionReport,
    request_receipt: &SignedReceipt,
    execution_receipt: &SignedReceipt,
    evidence_bundle_receipt: &SignedReceipt,
    transition_receipts: &[SignedReceipt],
    rollback_receipts: &[SignedReceipt],
    acknowledgement_receipts: &[SignedReceipt],
) -> Result<(), (StatusCode, String)> {
    require_proof_receipt_decision_str(
        request_receipt,
        "response request receipt",
        &["decision", "action"],
        execution.action.as_str(),
    )?;
    require_proof_receipt_decision_str(
        request_receipt,
        "response request receipt",
        &["decision", "rollbackRef"],
        execution.rollback_ref.as_str(),
    )?;
    for (key, raw_value) in [
        ("responseActionId", execution.action_id.as_str()),
        ("rootNodeId", execution.root_node_id.as_str()),
        ("graphSliceId", execution.graph_slice_id.as_str()),
        ("rollbackRef", execution.rollback_ref.as_str()),
        ("dryRun", "false"),
    ] {
        require_proof_receipt_evidence_hash(
            request_receipt,
            "response request receipt",
            key,
            raw_value,
        )?;
    }
    require_proof_receipt_evidence_hash(
        request_receipt,
        "response request receipt",
        "ttlSeconds",
        execution.ttl_seconds.to_string().as_str(),
    )?;

    verify_response_execution_receipt_contract(
        execution,
        execution_receipt,
        "response execution receipt",
        ResponseExecutionProofReceiptKind::Primary,
    )?;

    require_proof_receipt_decision_str(
        evidence_bundle_receipt,
        "evidence bundle manifest receipt",
        &["decision", "findingId"],
        execution.evidence_bundle.bundle_id.as_str(),
    )?;
    for (key, raw_value) in [
        (
            "evidenceBundleId",
            execution.evidence_bundle.bundle_id.as_str(),
        ),
        (
            "graphSliceId",
            execution.evidence_bundle.graph_slice_id.as_str(),
        ),
        (
            "contentHash",
            execution.evidence_bundle.content_hash.as_str(),
        ),
    ] {
        require_proof_receipt_evidence_hash(
            evidence_bundle_receipt,
            "evidence bundle manifest receipt",
            key,
            raw_value,
        )?;
    }
    require_proof_receipt_evidence_hash(
        evidence_bundle_receipt,
        "evidence bundle manifest receipt",
        "nodeCount",
        execution.evidence_bundle.node_count.to_string().as_str(),
    )?;
    require_proof_receipt_evidence_hash(
        evidence_bundle_receipt,
        "evidence bundle manifest receipt",
        "edgeCount",
        execution.evidence_bundle.edge_count.to_string().as_str(),
    )?;
    for receipt in transition_receipts {
        verify_response_execution_receipt_contract(
            execution,
            receipt,
            "response execution transition receipt",
            ResponseExecutionProofReceiptKind::TerminalTransition,
        )?;
    }
    for receipt in rollback_receipts {
        verify_response_lifecycle_receipt_contract(
            execution,
            receipt,
            "response rollback receipt",
        )?;
        require_proof_receipt_evidence_hash(
            receipt,
            "response rollback receipt",
            "executionId",
            execution.execution_id.as_str(),
        )?;
        let rollback_effects = expected_response_rollback_effects(execution)?;
        verify_response_effects_proof_contract(
            receipt,
            "response rollback receipt",
            "rollbackEffect",
            &rollback_effects,
        )?;
    }
    for receipt in acknowledgement_receipts {
        verify_response_lifecycle_receipt_contract(
            execution,
            receipt,
            "response acknowledgement receipt",
        )?;
        require_proof_receipt_evidence_hash(
            receipt,
            "response acknowledgement receipt",
            "executionId",
            execution.execution_id.as_str(),
        )?;
        require_proof_receipt_evidence_hash(
            receipt,
            "response acknowledgement receipt",
            "acknowledgedStatus",
            execution.status.as_str(),
        )?;
        verify_response_effects_proof_contract(
            receipt,
            "response acknowledgement receipt",
            "acknowledgementEffect",
            &execution.effects,
        )?;
    }
    Ok(())
}

pub(crate) fn verify_response_execution_proof_evidence_bundle(
    execution: &EndpointResponseExecutionReport,
    stored: &StoredEndpointEvidenceBundle,
) -> Result<(), (StatusCode, String)> {
    for (label, expected, actual) in [
        (
            "bundle_id",
            execution.evidence_bundle.bundle_id.as_str(),
            stored.bundle.bundle_id.as_str(),
        ),
        (
            "graph_slice_id",
            execution.evidence_bundle.graph_slice_id.as_str(),
            stored.bundle.graph_slice_id.as_str(),
        ),
        (
            "content_hash",
            execution.evidence_bundle.content_hash.as_str(),
            stored.bundle.content_hash.as_str(),
        ),
    ] {
        if expected != actual {
            return Err(response_proof_contract_conflict(format!(
                "evidence bundle artifact {label} does not match response execution proof contract"
            )));
        }
    }
    if execution.evidence_bundle.node_count != stored.bundle.node_count
        || execution.evidence_bundle.node_count != stored.graph.nodes.len()
    {
        return Err(response_proof_contract_conflict(
            "evidence bundle artifact node count does not match response execution proof contract",
        ));
    }
    if execution.evidence_bundle.edge_count != stored.bundle.edge_count
        || execution.evidence_bundle.edge_count != stored.graph.edges.len()
    {
        return Err(response_proof_contract_conflict(
            "evidence bundle artifact edge count does not match response execution proof contract",
        ));
    }
    let canonical_graph = canonical_evidence_graph(&stored.graph).map_err(internal_error)?;
    if canonical_graph.content_hash != execution.evidence_bundle.content_hash {
        return Err(response_proof_contract_conflict(
            "evidence bundle artifact content hash does not match response execution proof contract",
        ));
    }
    if stored.byte_count != canonical_graph.byte_count {
        return Err(response_proof_contract_conflict(
            "evidence bundle artifact byte count does not match response execution proof contract",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(crate) enum ResponseExecutionProofReceiptKind {
    Primary,
    TerminalTransition,
}

pub(crate) fn verify_response_execution_receipt_contract(
    execution: &EndpointResponseExecutionReport,
    receipt: &SignedReceipt,
    label: &str,
    kind: ResponseExecutionProofReceiptKind,
) -> Result<(), (StatusCode, String)> {
    verify_response_lifecycle_receipt_contract(execution, receipt, label)?;
    match kind {
        ResponseExecutionProofReceiptKind::Primary => {
            require_proof_receipt_decision_str(
                receipt,
                label,
                &["decision", "findingId"],
                execution.execution_id.as_str(),
            )?;
            require_proof_receipt_evidence_hash(
                receipt,
                label,
                "executionId",
                execution.execution_id.as_str(),
            )?;
            require_proof_receipt_evidence_hash(
                receipt,
                label,
                "executionStatus",
                execution.status.as_str(),
            )?;
        }
        ResponseExecutionProofReceiptKind::TerminalTransition => {
            if receipt_endpoint_decision_str(receipt, &["decision", "findingId"])
                == Some(execution.execution_id.as_str())
            {
                return Err((
                    StatusCode::CONFLICT,
                    format!("{label} does not match response execution proof contract"),
                ));
            }
            if !receipt_evidence_hash_matches(receipt, "executionStatus", "expired")
                && !receipt_evidence_hash_matches(receipt, "executionStatus", "cancelled")
                && !receipt_evidence_hash_matches(receipt, "executionStatus", "rollback_failed")
                && !receipt_evidence_hash_matches(receipt, "executionStatus", "rolled_back")
            {
                return Err((
                    StatusCode::CONFLICT,
                    format!(
                        "{label} executionStatus does not match response execution proof contract"
                    ),
                ));
            }
        }
    }
    for (key, raw_value) in [
        (
            "evidenceBundleId",
            execution.evidence_bundle.bundle_id.as_str(),
        ),
        (
            "evidenceBundleContentHash",
            execution.evidence_bundle.content_hash.as_str(),
        ),
    ] {
        require_proof_receipt_evidence_hash(receipt, label, key, raw_value)?;
    }
    require_proof_receipt_evidence_hash(
        receipt,
        label,
        "dryRun",
        execution.dry_run.to_string().as_str(),
    )?;
    verify_response_effects_proof_contract(receipt, label, "executionEffect", &execution.effects)?;
    Ok(())
}

pub(crate) fn verify_response_lifecycle_receipt_contract(
    execution: &EndpointResponseExecutionReport,
    receipt: &SignedReceipt,
    label: &str,
) -> Result<(), (StatusCode, String)> {
    require_proof_receipt_decision_str(
        receipt,
        label,
        &["decision", "action"],
        execution.action.as_str(),
    )?;
    require_proof_receipt_decision_str(
        receipt,
        label,
        &["decision", "rollbackRef"],
        execution.rollback_ref.as_str(),
    )?;
    for (key, raw_value) in [
        ("responseActionId", execution.action_id.as_str()),
        ("rootNodeId", execution.root_node_id.as_str()),
        ("graphSliceId", execution.graph_slice_id.as_str()),
        ("rollbackRef", execution.rollback_ref.as_str()),
    ] {
        require_proof_receipt_evidence_hash(receipt, label, key, raw_value)?;
    }
    require_proof_receipt_evidence_hash(
        receipt,
        label,
        "ttlSeconds",
        execution.ttl_seconds.to_string().as_str(),
    )?;
    Ok(())
}

pub(crate) fn response_effect_proof_contract_value(
    effect: &EndpointResponseExecutionEffect,
) -> Result<String, (StatusCode, String)> {
    let value = serde_json::to_value(effect)
        .map_err(|err| internal_error(anyhow::anyhow!("serialize response effect: {err}")))?;
    canonicalize_json(&value)
        .map_err(|err| internal_error(anyhow::anyhow!("canonicalize response effect: {err}")))
}

pub(crate) fn verify_response_effects_proof_contract(
    receipt: &SignedReceipt,
    label: &str,
    prefix: &str,
    effects: &[EndpointResponseExecutionEffect],
) -> Result<(), (StatusCode, String)> {
    require_proof_receipt_evidence_hash(
        receipt,
        label,
        "effectCount",
        effects.len().to_string().as_str(),
    )?;
    for effect in effects {
        let effect_value = response_effect_proof_contract_value(effect)?;
        require_proof_receipt_evidence_hash(
            receipt,
            label,
            format!("{prefix}:{}", effect.effect_id).as_str(),
            effect_value.as_str(),
        )?;
        require_proof_receipt_evidence_hash(
            receipt,
            label,
            format!("{prefix}Type:{}", effect.effect_id).as_str(),
            effect.effect_type.as_str(),
        )?;
    }
    Ok(())
}

pub(crate) fn expected_response_rollback_effects(
    execution: &EndpointResponseExecutionReport,
) -> Result<Vec<EndpointResponseExecutionEffect>, (StatusCode, String)> {
    match execution.action {
        EndpointDecisionAction::RestrictEgress => {
            let effect = require_execution_effect_for_rollback(execution, "restrict_egress")?;
            let primary_target =
                effect
                    .target
                    .strip_prefix("egress:")
                    .ok_or_else(|| {
                        response_proof_contract_conflict(
                            "response rollback receipt target does not match response execution proof contract",
                        )
                    })?;
            let targets = response_proof_contract_string_artifact(effect)?;
            let rollback_effect =
                EndpointResponseExecutionEffect::restore_egress(primary_target, &targets);
            verify_rollback_effect_matches_execution_effect(&rollback_effect, effect)?;
            Ok(vec![rollback_effect])
        }
        EndpointDecisionAction::QuarantineFile => {
            let effect = require_execution_effect_for_rollback(execution, "quarantine_file")?;
            let artifact = response_proof_contract_required_effect_field(
                effect.artifact.as_deref(),
                "response rollback receipt artifact does not match response execution proof contract",
            )?;
            let content_hash = response_proof_contract_required_effect_field(
                effect.content_hash.as_deref(),
                "response rollback receipt content hash does not match response execution proof contract",
            )?;
            let byte_count = effect.byte_count.ok_or_else(|| {
                response_proof_contract_conflict(
                    "response rollback receipt byte count does not match response execution proof contract",
                )
            })?;
            Ok(vec![
                EndpointResponseExecutionEffect::restore_quarantine_file(
                    effect.target.as_str(),
                    artifact,
                    content_hash,
                    byte_count,
                ),
            ])
        }
        EndpointDecisionAction::DisablePersistence => {
            let effect = require_execution_effect_for_rollback(execution, "disable_persistence")?;
            let artifact = response_proof_contract_required_effect_field(
                effect.artifact.as_deref(),
                "response rollback receipt artifact does not match response execution proof contract",
            )?;
            let content_hash = response_proof_contract_required_effect_field(
                effect.content_hash.as_deref(),
                "response rollback receipt content hash does not match response execution proof contract",
            )?;
            let byte_count = effect.byte_count.ok_or_else(|| {
                response_proof_contract_conflict(
                    "response rollback receipt byte count does not match response execution proof contract",
                )
            })?;
            Ok(vec![
                EndpointResponseExecutionEffect::restore_persistence_file(
                    effect.target.as_str(),
                    artifact,
                    content_hash,
                    byte_count,
                ),
            ])
        }
        EndpointDecisionAction::SuspendProcessTree => {
            let effect = require_execution_effect_for_rollback(execution, "suspend_process_tree")?;
            let root_pid = effect
                .target
                .strip_prefix("pid:")
                .ok_or_else(|| {
                    response_proof_contract_conflict(
                        "response rollback receipt target does not match response execution proof contract",
                    )
                })?
                .parse::<u32>()
                .map_err(|_| {
                    response_proof_contract_conflict(
                        "response rollback receipt target does not match response execution proof contract",
                    )
                })?;
            let artifact = response_proof_contract_required_effect_field(
                effect.artifact.as_deref(),
                "response rollback receipt artifact does not match response execution proof contract",
            )?;
            let rollback_effect =
                EndpointResponseExecutionEffect::resume_process_tree_from_artifact(
                    root_pid, artifact,
                );
            verify_rollback_effect_matches_execution_effect(&rollback_effect, effect)?;
            Ok(vec![rollback_effect])
        }
        _ => Err(response_proof_contract_conflict(
            "response rollback receipt is not valid for this response execution action",
        )),
    }
}

pub(crate) fn require_execution_effect_for_rollback<'a>(
    execution: &'a EndpointResponseExecutionReport,
    effect_type: &str,
) -> Result<&'a EndpointResponseExecutionEffect, (StatusCode, String)> {
    execution
        .effects
        .iter()
        .find(|effect| effect.effect_type == effect_type)
        .ok_or_else(|| {
            response_proof_contract_conflict(
                "response rollback receipt effect does not match response execution proof contract",
            )
        })
}

pub(crate) fn response_proof_contract_string_artifact(
    effect: &EndpointResponseExecutionEffect,
) -> Result<Vec<String>, (StatusCode, String)> {
    let artifact = response_proof_contract_required_effect_field(
        effect.artifact.as_deref(),
        "response rollback receipt artifact does not match response execution proof contract",
    )?;
    let values = artifact
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if values.is_empty() {
        return Err(response_proof_contract_conflict(
            "response rollback receipt artifact does not match response execution proof contract",
        ));
    }
    Ok(values)
}

pub(crate) fn response_proof_contract_required_effect_field<'a>(
    value: Option<&'a str>,
    message: &'static str,
) -> Result<&'a str, (StatusCode, String)> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| response_proof_contract_conflict(message))
}

pub(crate) fn verify_rollback_effect_matches_execution_effect(
    rollback_effect: &EndpointResponseExecutionEffect,
    execution_effect: &EndpointResponseExecutionEffect,
) -> Result<(), (StatusCode, String)> {
    if rollback_effect.target == execution_effect.target
        && rollback_effect.artifact == execution_effect.artifact
        && rollback_effect.content_hash == execution_effect.content_hash
        && rollback_effect.byte_count == execution_effect.byte_count
    {
        return Ok(());
    }
    Err(response_proof_contract_conflict(
        "response rollback receipt effect does not match response execution proof contract",
    ))
}

pub(crate) fn response_proof_contract_conflict(message: impl Into<String>) -> (StatusCode, String) {
    (StatusCode::CONFLICT, message.into())
}

pub(crate) fn require_proof_receipt_decision_str(
    receipt: &SignedReceipt,
    label: &str,
    path: &[&str],
    expected: &str,
) -> Result<(), (StatusCode, String)> {
    if receipt_endpoint_decision_str(receipt, path) == Some(expected) {
        return Ok(());
    }
    Err((
        StatusCode::CONFLICT,
        format!("{label} does not match response execution proof contract"),
    ))
}

pub(crate) fn require_proof_receipt_evidence_hash(
    receipt: &SignedReceipt,
    label: &str,
    key: &str,
    raw_value: &str,
) -> Result<(), (StatusCode, String)> {
    if receipt_evidence_hash_matches(receipt, key, raw_value) {
        return Ok(());
    }
    Err((
        StatusCode::CONFLICT,
        format!("{label} {key} does not match response execution proof contract"),
    ))
}

pub(crate) fn verify_response_execution_proof_actor_continuity(
    execution: &EndpointResponseExecutionReport,
    request_receipt: &SignedReceipt,
    execution_receipt: &SignedReceipt,
    transition_receipts: &[SignedReceipt],
) -> Result<(), (StatusCode, String)> {
    let actor = execution.actor.as_ref().ok_or_else(|| {
        (
            StatusCode::CONFLICT,
            format!(
                "response execution proof actor validation failed for {}: execution ledger is missing actor identity",
                execution.execution_id
            ),
        )
    })?;
    let actor_hash =
        canonical_json_hash(actor, "response execution proof actor").map_err(internal_error)?;
    verify_response_execution_proof_receipt_actor(
        "response request receipt",
        request_receipt,
        actor,
        &actor_hash,
        &["actorHash"],
    )?;
    verify_response_execution_proof_receipt_actor(
        "response execution receipt",
        execution_receipt,
        actor,
        &actor_hash,
        &["actorHash", "executionActorHash"],
    )?;
    for receipt in transition_receipts {
        verify_response_execution_proof_receipt_actor(
            "response execution transition receipt",
            receipt,
            actor,
            &actor_hash,
            &["actorHash", "executionActorHash"],
        )?;
    }
    Ok(())
}

pub(crate) fn verify_response_execution_proof_receipt_actor(
    label: &str,
    receipt: &SignedReceipt,
    expected_actor: &EndpointDecisionActor,
    expected_actor_hash: &str,
    required_hash_keys: &[&str],
) -> Result<(), (StatusCode, String)> {
    let receipt_actor = receipt_endpoint_decision_actor(receipt).map_err(|reason| {
        (
            StatusCode::CONFLICT,
            format!("{label} failed actor validation: {reason}"),
        )
    })?;
    if &receipt_actor != expected_actor {
        return Err((
            StatusCode::CONFLICT,
            format!("{label} actor does not match response execution ledger actor"),
        ));
    }
    for key in required_hash_keys {
        if !receipt_evidence_hash_matches(receipt, key, expected_actor_hash) {
            return Err((
                StatusCode::CONFLICT,
                format!("{label} {key} does not match response execution ledger actor"),
            ));
        }
    }
    Ok(())
}

pub(crate) struct ResponseExecutionLifecycleReceipts {
    pub(crate) transition_receipts: Vec<SignedReceipt>,
    pub(crate) rollback_receipts: Vec<SignedReceipt>,
    pub(crate) acknowledgement_receipts: Vec<SignedReceipt>,
}

pub(crate) fn response_execution_lifecycle_receipts(
    ledger: &EndpointReceiptLedger,
    execution: &EndpointResponseExecutionReport,
) -> Result<ResponseExecutionLifecycleReceipts, (StatusCode, String)> {
    let mut transition_receipts = Vec::new();
    let mut rollback_receipts = Vec::new();
    let mut acknowledgement_receipts = Vec::new();

    for receipt in ledger.all().map_err(internal_error)? {
        match receipt_family(&receipt) {
            Some("response_execution")
                if response_lifecycle_receipt_matches_execution(&receipt, execution)
                    && response_execution_receipt_is_terminal_transition(&receipt)
                    && receipt_endpoint_decision_str(&receipt, &["decision", "findingId"])
                        != Some(execution.execution_id.as_str()) =>
            {
                verify_proof_receipt_signature(
                    &receipt,
                    "response execution transition receipt",
                    &ledger.signer_public_key,
                )?;
                transition_receipts.push(receipt);
            }
            Some("response_rollback")
                if response_lifecycle_receipt_matches_execution(&receipt, execution)
                    && receipt_evidence_hash_matches(
                        &receipt,
                        "executionId",
                        execution.execution_id.as_str(),
                    ) =>
            {
                verify_proof_receipt_signature(
                    &receipt,
                    "response rollback receipt",
                    &ledger.signer_public_key,
                )?;
                rollback_receipts.push(receipt);
            }
            Some("response_acknowledgement")
                if response_lifecycle_receipt_matches_execution(&receipt, execution)
                    && receipt_evidence_hash_matches(
                        &receipt,
                        "executionId",
                        execution.execution_id.as_str(),
                    ) =>
            {
                verify_proof_receipt_signature(
                    &receipt,
                    "response acknowledgement receipt",
                    &ledger.signer_public_key,
                )?;
                acknowledgement_receipts.push(receipt);
            }
            _ => {}
        }
    }

    transition_receipts.sort_by(endpoint_receipt_proof_order);
    rollback_receipts.sort_by(endpoint_receipt_proof_order);
    acknowledgement_receipts.sort_by(endpoint_receipt_proof_order);
    Ok(ResponseExecutionLifecycleReceipts {
        transition_receipts,
        rollback_receipts,
        acknowledgement_receipts,
    })
}

pub(crate) fn response_lifecycle_receipt_matches_execution(
    receipt: &SignedReceipt,
    execution: &EndpointResponseExecutionReport,
) -> bool {
    receipt_endpoint_decision_str(receipt, &["decision", "action"])
        == Some(execution.action.as_str())
        && receipt_endpoint_decision_str(receipt, &["decision", "rollbackRef"])
            == Some(execution.rollback_ref.as_str())
        && receipt_evidence_hash_matches(receipt, "responseActionId", &execution.action_id)
        && receipt_evidence_hash_matches(receipt, "rootNodeId", &execution.root_node_id)
        && receipt_evidence_hash_matches(receipt, "graphSliceId", &execution.graph_slice_id)
}

pub(crate) fn response_execution_receipt_is_terminal_transition(receipt: &SignedReceipt) -> bool {
    receipt_evidence_hash_matches(receipt, "executionStatus", "expired")
        || receipt_evidence_hash_matches(receipt, "executionStatus", "cancelled")
        || receipt_evidence_hash_matches(receipt, "executionStatus", "rollback_failed")
        || receipt_evidence_hash_matches(receipt, "executionStatus", "rolled_back")
}

pub(crate) fn endpoint_receipt_proof_order(
    left: &SignedReceipt,
    right: &SignedReceipt,
) -> std::cmp::Ordering {
    left.receipt
        .timestamp
        .cmp(&right.receipt.timestamp)
        .then_with(|| left.receipt.receipt_id.cmp(&right.receipt.receipt_id))
}

pub(crate) fn latest_required_receipt(
    ledger: &EndpointReceiptLedger,
    family: &str,
    finding_id: &str,
    label: &str,
) -> Result<SignedReceipt, (StatusCode, String)> {
    let filter = EdrReceiptFilter {
        receipt_id: None,
        family: Some(family),
        action: None,
        finding_id: Some(finding_id),
        rule_id: None,
        graph_slice_id: None,
        root_node_id: None,
        execution_id: None,
        status: None,
        actor_endpoint_id: None,
        actor_user_id: None,
        actor_session_id: None,
        actor_agent_id: None,
        actor_workload_id: None,
        actor_approval_id: None,
        local_sequence: None,
    };
    let mut receipts = ledger.read_recent(1, filter).map_err(internal_error)?;
    let receipt = receipts.pop().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("{label} not found for response execution proof target {finding_id}"),
        )
    })?;
    verify_proof_receipt_signature(&receipt, label, &ledger.signer_public_key)?;
    Ok(receipt)
}

pub(crate) fn latest_required_receipt_by_execution_id(
    ledger: &EndpointReceiptLedger,
    family: &str,
    execution_id: &str,
    label: &str,
) -> Result<SignedReceipt, (StatusCode, String)> {
    let filter = EdrReceiptFilter {
        receipt_id: None,
        family: Some(family),
        action: None,
        finding_id: None,
        rule_id: None,
        graph_slice_id: None,
        root_node_id: None,
        execution_id: Some(execution_id),
        status: None,
        actor_endpoint_id: None,
        actor_user_id: None,
        actor_session_id: None,
        actor_agent_id: None,
        actor_workload_id: None,
        actor_approval_id: None,
        local_sequence: None,
    };
    let mut receipts = ledger.read_recent(1, filter).map_err(internal_error)?;
    let receipt = receipts.pop().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("{label} not found for response execution proof target {execution_id}"),
        )
    })?;
    verify_proof_receipt_signature(&receipt, label, &ledger.signer_public_key)?;
    Ok(receipt)
}

pub(crate) fn verify_proof_receipt_signature(
    receipt: &SignedReceipt,
    label: &str,
    expected_signer_public_key: &str,
) -> Result<(), (StatusCode, String)> {
    verify_endpoint_receipt_signature(receipt, label, expected_signer_public_key).map_err(
        |reason| {
            (
                StatusCode::CONFLICT,
                format!("{label} failed signature verification: {reason}"),
            )
        },
    )
}

pub(crate) fn verify_endpoint_receipt_signature(
    receipt: &SignedReceipt,
    label: &str,
    expected_signer_public_key: &str,
) -> Result<(), String> {
    let public_key = receipt_endpoint_decision_str(receipt, &["signer", "signerPublicKey"])
        .ok_or_else(|| format!("{label} is missing signer public key"))?;
    if public_key != expected_signer_public_key {
        return Err(format!("{label} signer public key is not trusted"));
    }
    let public_key = hush_core::PublicKey::from_hex(public_key)
        .map_err(|err| format!("{label} signer public key is invalid: {err}"))?;
    let verification = receipt.verify(&hush_core::receipt::PublicKeySet::new(public_key));
    if !verification.valid {
        return Err(format!("{label} signature is invalid"));
    }
    let endpoint_decision_value = receipt
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("endpointDecision"))
        .ok_or_else(|| format!("{label} is missing endpoint decision metadata"))?;
    let canonical_endpoint_decision =
        canonicalize_json(endpoint_decision_value).map_err(|err| {
            format!("{label} endpoint decision metadata is not canonicalizable: {err}")
        })?;
    let expected_content_hash = sha256(canonical_endpoint_decision.as_bytes());
    if receipt.receipt.content_hash != expected_content_hash {
        return Err(format!(
            "{label} endpoint decision metadata content hash does not match receipt content hash"
        ));
    }
    let endpoint_decision: EndpointDecisionReceipt =
        serde_json::from_value(endpoint_decision_value.clone())
            .map_err(|err| format!("{label} endpoint decision metadata is invalid: {err}"))?;
    endpoint_decision
        .validate()
        .map_err(|err| format!("{label} endpoint decision metadata is invalid: {err}"))?;
    let expected_receipt_id = endpoint_decision.receipt_id();
    if receipt.receipt.receipt_id.as_deref() != Some(expected_receipt_id.as_str()) {
        return Err(format!(
            "{label} endpoint decision metadata receipt id does not match receipt id"
        ));
    }
    Ok(())
}

pub(crate) fn control_store_receipt_from_endpoint_receipt(
    receipt: &SignedReceipt,
) -> Result<ControlStoreReceiptRequest, String> {
    let public_key = receipt_endpoint_decision_str(receipt, &["signer", "signerPublicKey"])
        .ok_or_else(|| "endpoint receipt is missing signer public key".to_string())?;
    verify_endpoint_receipt_signature(receipt, "endpoint receipt upload candidate", public_key)?;
    let policy_name = receipt
        .receipt
        .provenance
        .as_ref()
        .and_then(|provenance| non_empty(provenance.ruleset.as_deref()))
        .or_else(|| receipt_endpoint_decision_str(receipt, &["policy", "policyVersion"]))
        .ok_or_else(|| "endpoint receipt is missing policy name".to_string())?;
    let guard = receipt
        .receipt
        .verdict
        .gate_id
        .as_deref()
        .and_then(|value| non_empty(Some(value)))
        .or_else(|| receipt_family(receipt))
        .unwrap_or("endpoint_decision");
    let endpoint_decision = receipt
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("endpointDecision"))
        .ok_or_else(|| "endpoint receipt is missing endpoint decision metadata".to_string())?;
    let evidence = endpoint_decision
        .get("evidence")
        .and_then(|value| {
            value
                .as_array()
                .filter(|items| !items.is_empty())
                .map(|_| value)
        })
        .cloned();
    let signed_receipt = serde_json::to_value(receipt)
        .map_err(|err| format!("serialize endpoint receipt for upload: {err}"))?;

    Ok(ControlStoreReceiptRequest {
        timestamp: receipt.receipt.timestamp.clone(),
        verdict: control_store_receipt_verdict(receipt).to_string(),
        guard: guard.to_string(),
        policy_name: policy_name.to_string(),
        signature: receipt.signatures.signer.to_hex(),
        public_key: public_key.to_string(),
        chain_hash: None,
        evidence,
        metadata: Some(serde_json::json!({
            "source": "clawdstrike-agent",
            "receiptId": receipt.receipt.receipt_id.as_deref(),
            "receiptFamily": receipt_family(receipt),
            "localSequence": receipt_local_sequence(receipt),
            "endpointId": receipt_endpoint_decision_str(receipt, &["actor", "endpointId"]),
            "policyHash": receipt_endpoint_decision_str(receipt, &["policy", "policyHash"]),
        })),
        signed_receipt,
    })
}

pub(crate) fn control_store_receipt_verdict(receipt: &SignedReceipt) -> &'static str {
    if receipt.receipt.verdict.passed {
        "allow"
    } else if receipt_endpoint_decision_str(receipt, &["decision", "action"]) == Some("warn") {
        "warn"
    } else {
        "deny"
    }
}

pub(crate) fn receipt_compaction_record(
    receipt: &SignedReceipt,
    age_seconds: u64,
    removed: bool,
    reason: String,
) -> EdrReceiptCompactionRecord {
    EdrReceiptCompactionRecord {
        receipt_id: receipt.receipt.receipt_id.clone(),
        timestamp: receipt.receipt.timestamp.clone(),
        age_seconds,
        family: receipt_family(receipt).map(ToString::to_string),
        action: receipt_endpoint_decision_str(receipt, &["decision", "action"])
            .map(ToString::to_string),
        finding_id: receipt_endpoint_decision_str(receipt, &["decision", "findingId"])
            .map(ToString::to_string),
        rule_id: receipt_endpoint_decision_str(receipt, &["decision", "ruleId"])
            .map(ToString::to_string),
        graph_slice_id: receipt_endpoint_decision_str(receipt, &["graph", "graphSliceId"])
            .map(ToString::to_string),
        root_node_id: receipt_endpoint_decision_str(receipt, &["graph", "processNodeId"])
            .map(ToString::to_string),
        local_sequence: receipt_local_sequence(receipt),
        removed,
        reason,
    }
}

pub(crate) fn receipt_age_seconds(
    receipt: &SignedReceipt,
    now: chrono::DateTime<chrono::Utc>,
) -> u64 {
    chrono::DateTime::parse_from_rfc3339(&receipt.receipt.timestamp)
        .map(|timestamp| {
            now.signed_duration_since(timestamp.with_timezone(&chrono::Utc))
                .num_seconds()
                .max(0) as u64
        })
        .unwrap_or(0)
}

pub(crate) fn receipt_local_sequence(receipt: &SignedReceipt) -> Option<u64> {
    receipt
        .receipt
        .metadata
        .as_ref()?
        .get("endpointDecision")?
        .get("localSequence")?
        .as_u64()
}

pub(crate) fn receipt_family(receipt: &SignedReceipt) -> Option<&str> {
    receipt_endpoint_decision_str(receipt, &["receiptFamily"])
}

pub(crate) fn receipt_endpoint_decision_graph(
    receipt: &SignedReceipt,
) -> Result<EndpointGraphReference> {
    let graph = receipt_endpoint_decision_value(receipt, &["graph"])
        .ok_or_else(|| anyhow::anyhow!("endpoint receipt is missing graph reference"))?;
    serde_json::from_value(graph.clone()).context("decode endpoint receipt graph reference")
}

pub(crate) fn receipt_endpoint_decision_sensor_state(
    receipt: &SignedReceipt,
) -> Result<EndpointSensorState> {
    let sensor_state = receipt_endpoint_decision_value(receipt, &["sensorState"])
        .ok_or_else(|| anyhow::anyhow!("endpoint receipt is missing sensor state"))?;
    serde_json::from_value(sensor_state.clone()).context("decode endpoint receipt sensor state")
}

pub(crate) fn receipt_endpoint_decision_policy(
    receipt: &SignedReceipt,
) -> Result<EndpointPolicySnapshot> {
    let policy = receipt_endpoint_decision_value(receipt, &["policy"])
        .ok_or_else(|| anyhow::anyhow!("endpoint receipt is missing policy snapshot"))?;
    serde_json::from_value(policy.clone()).context("decode endpoint receipt policy snapshot")
}

pub(crate) fn receipt_endpoint_decision_actor(
    receipt: &SignedReceipt,
) -> Result<EndpointDecisionActor> {
    let actor = receipt_endpoint_decision_value(receipt, &["actor"])
        .ok_or_else(|| anyhow::anyhow!("endpoint receipt is missing actor"))?;
    serde_json::from_value(actor.clone()).context("decode endpoint receipt actor")
}

pub(crate) fn receipt_endpoint_decision_str<'a>(
    receipt: &'a SignedReceipt,
    path: &[&str],
) -> Option<&'a str> {
    receipt_endpoint_decision_value(receipt, path)?.as_str()
}

pub(crate) fn receipt_endpoint_decision_value<'a>(
    receipt: &'a SignedReceipt,
    path: &[&str],
) -> Option<&'a Value> {
    let mut value = receipt.receipt.metadata.as_ref()?.get("endpointDecision")?;
    for key in path {
        value = value.get(*key)?;
    }
    Some(value)
}

pub(crate) fn protected_observation_ids_for_receipts(
    receipts: &[SignedReceipt],
    graph: &CausalGraph,
) -> BTreeSet<String> {
    let mut observation_ids = BTreeSet::new();
    let mut graph_node_ids = BTreeSet::new();
    let mut graph_edge_ids = BTreeSet::new();

    for receipt in receipts {
        let Some(endpoint_decision) = receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
        else {
            continue;
        };

        if let Some(observation_id) = endpoint_decision
            .get("decision")
            .and_then(|decision| decision.get("observationId"))
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            observation_ids.insert(observation_id.to_string());
        }

        let Some(graph_ref) = endpoint_decision.get("graph") else {
            continue;
        };
        if let Some(node_id) = graph_ref
            .get("processNodeId")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            graph_node_ids.insert(node_id.to_string());
        }
        if let Some(node_ids) = graph_ref
            .get("nodeIds")
            .and_then(serde_json::Value::as_array)
        {
            graph_node_ids.extend(
                node_ids
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string),
            );
        }
        if let Some(edge_ids) = graph_ref
            .get("edgeIds")
            .and_then(serde_json::Value::as_array)
        {
            graph_edge_ids.extend(
                edge_ids
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string),
            );
        }
    }

    for edge in &graph.edges {
        if graph_edge_ids.contains(&edge.edge_id)
            || graph_node_ids.contains(&edge.from)
            || graph_node_ids.contains(&edge.to)
        {
            observation_ids.insert(edge.observation_id.clone());
        }
    }

    observation_ids
}

pub(crate) fn detection_severity_from_policy_label(
    value: Option<&str>,
) -> Option<DetectionSeverity> {
    match value?.trim().to_ascii_lowercase().as_str() {
        "info" => Some(DetectionSeverity::Info),
        "low" => Some(DetectionSeverity::Low),
        "medium" => Some(DetectionSeverity::Medium),
        "high" => Some(DetectionSeverity::High),
        "critical" => Some(DetectionSeverity::Critical),
        _ => None,
    }
}

const EDR_RAW_ARTIFACT_POLICY_PATHS: &[(&[&str], &str)] = &[
    (
        &["edr", "telemetry", "raw_artifact_upload"],
        "edr.telemetry.raw_artifact_upload",
    ),
    (
        &["edr", "telemetry", "rawArtifactUpload"],
        "edr.telemetry.rawArtifactUpload",
    ),
    (
        &["endpoint_telemetry", "raw_artifact_upload"],
        "endpoint_telemetry.raw_artifact_upload",
    ),
    (
        &["endpointTelemetry", "rawArtifactUpload"],
        "endpointTelemetry.rawArtifactUpload",
    ),
];

const EDR_POLICY_EPOCH_YAML_PATHS: &[&[&str]] = &[
    &["policy_epoch"],
    &["policyEpoch"],
    &["epoch"],
    &["policy", "epoch"],
    &["policy", "policy_epoch"],
    &["policy", "policyEpoch"],
    &["metadata", "policy_epoch"],
    &["metadata", "policyEpoch"],
    &["bundle", "epoch"],
    &["bundle", "policy_epoch"],
    &["bundle", "policyEpoch"],
];

pub(crate) fn edr_privacy_policy_decision(
    settings: &Settings,
    requested_privacy_mode: EndpointTelemetryPrivacyMode,
    raw_artifact_approval: Option<&EdrRawArtifactApproval>,
) -> Result<EdrPrivacyPolicyDecision> {
    let raw_policy = edr_raw_artifact_upload_policy(settings)?;
    let raw_artifact_upload_requested = requested_privacy_mode.permits_raw_artifacts();
    let raw_artifact_approval_required = raw_artifact_upload_requested && raw_policy.allowed;
    let denied_reason = if raw_artifact_upload_requested && !raw_policy.allowed {
        Some(
            "raw_artifact_permitted was requested, but the local policy does not allow raw artifact upload"
                .to_string(),
        )
    } else if raw_artifact_approval_required && raw_artifact_approval.is_none() {
        Some(
            "raw_artifact_permitted was requested and local policy allows raw artifact upload, but rawArtifactApprovalId and rawArtifactApprovalReason are required"
                .to_string(),
        )
    } else {
        None
    };
    let effective_privacy_mode = if denied_reason.is_some() {
        EndpointTelemetryPrivacyMode::HashesFeatures
    } else {
        requested_privacy_mode.clone()
    };
    let effective_raw_artifact_approval = effective_privacy_mode
        .permits_raw_artifacts()
        .then_some(raw_artifact_approval)
        .flatten();

    Ok(EdrPrivacyPolicyDecision {
        requested_privacy_mode,
        effective_privacy_mode,
        raw_artifact_upload_requested,
        raw_artifact_upload_allowed: raw_policy.allowed,
        raw_artifact_approval_required,
        raw_artifact_approval_provided: raw_artifact_approval.is_some(),
        raw_artifact_approval_id: effective_raw_artifact_approval
            .map(|approval| approval.approval_id.clone()),
        raw_artifact_approval_reason_hash: effective_raw_artifact_approval
            .map(|approval| approval.reason_hash.clone()),
        policy_source: raw_policy.source,
        denied_reason,
    })
}

pub(crate) fn validate_raw_artifact_approval(
    input: &EdrPrivacyReportInput,
) -> Result<Option<EdrRawArtifactApproval>, (StatusCode, String)> {
    validate_raw_artifact_approval_fields(
        input.raw_artifact_approval_id.as_deref(),
        input.raw_artifact_approval_reason.as_deref(),
    )
}

pub(crate) fn validate_raw_artifact_approval_fields(
    approval_id: Option<&str>,
    approval_reason: Option<&str>,
) -> Result<Option<EdrRawArtifactApproval>, (StatusCode, String)> {
    let approval_id = trimmed_owned(approval_id);
    let approval_reason = trimmed_owned(approval_reason);
    if let Some(approval_id) = approval_id.as_deref() {
        if approval_id.len() > EDR_MAX_RAW_ARTIFACT_APPROVAL_ID_BYTES {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "rawArtifactApprovalId must be at most {EDR_MAX_RAW_ARTIFACT_APPROVAL_ID_BYTES} bytes"
                ),
            ));
        }
    }
    if let Some(reason) = approval_reason.as_deref() {
        if reason.len() > EDR_MAX_RAW_ARTIFACT_APPROVAL_REASON_BYTES {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "rawArtifactApprovalReason must be at most {EDR_MAX_RAW_ARTIFACT_APPROVAL_REASON_BYTES} bytes"
                ),
            ));
        }
    }

    match (approval_id, approval_reason) {
        (Some(approval_id), Some(approval_reason)) => Ok(Some(EdrRawArtifactApproval {
            approval_id,
            reason_hash: sha256(approval_reason.as_bytes()).to_hex_prefixed(),
        })),
        (None, None) => Ok(None),
        _ => Err((
            StatusCode::BAD_REQUEST,
            "rawArtifactApprovalId and rawArtifactApprovalReason must be provided together"
                .to_string(),
        )),
    }
}

pub(crate) fn raw_artifact_approval_resource_for_privacy_report() -> String {
    format!("{EDR_RAW_ARTIFACT_UPLOAD_GUARD}:privacy_report")
}

pub(crate) fn raw_artifact_approval_resource_for_evidence_bundle_fleet_publish(
    bundle_id: &str,
) -> String {
    format!(
        "{EDR_RAW_ARTIFACT_UPLOAD_GUARD}:evidence_bundle_fleet_publish:{}",
        bundle_id.trim()
    )
}

pub(crate) fn raw_artifact_approval_resource_for_control_archive_backfill(
    bundle_id: Option<&str>,
) -> String {
    match bundle_id.and_then(|value| trimmed_owned(Some(value))) {
        Some(bundle_id) => {
            format!("{EDR_RAW_ARTIFACT_UPLOAD_GUARD}:control_archive_backfill:{bundle_id}")
        }
        None => format!("{EDR_RAW_ARTIFACT_UPLOAD_GUARD}:control_archive_backfill_batch"),
    }
}

pub(crate) async fn validate_resolved_raw_artifact_approval(
    state: &AgentApiState,
    raw_artifact_approval: Option<EdrRawArtifactApproval>,
    expected_resource: &str,
) -> Result<Option<EdrRawArtifactApproval>, (StatusCode, String)> {
    let Some(raw_artifact_approval) = raw_artifact_approval else {
        return Ok(None);
    };
    let approval_status = state
        .approval_queue
        .get_status(&raw_artifact_approval.approval_id)
        .await
        .ok_or_else(|| {
            (
                StatusCode::CONFLICT,
                "rawArtifactApprovalId does not reference a local approval request".to_string(),
            )
        })?;
    if approval_status.status != ApprovalStatus::Resolved {
        return Err((
            StatusCode::CONFLICT,
            "rawArtifactApprovalId must reference a resolved local approval request".to_string(),
        ));
    }
    match approval_status.resolution {
        Some(
            ApprovalResolution::AllowOnce
            | ApprovalResolution::AllowSession
            | ApprovalResolution::AllowAlways,
        ) => {}
        Some(ApprovalResolution::Deny) | None => {
            return Err((
                StatusCode::CONFLICT,
                "rawArtifactApprovalId must reference an allowed local approval request"
                    .to_string(),
            ));
        }
    }
    if !approval_status.resolved_by_trusted_authority {
        return Err((
            StatusCode::CONFLICT,
            "rawArtifactApprovalId must be resolved by a trusted UI or signed control-plane authority"
                .to_string(),
        ));
    }
    if approval_status.guard != EDR_RAW_ARTIFACT_UPLOAD_GUARD {
        return Err((
            StatusCode::CONFLICT,
            "rawArtifactApprovalId must reference an endpoint.telemetry.raw_artifact_upload approval"
                .to_string(),
        ));
    }
    if approval_status.resource != expected_resource {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "rawArtifactApprovalId must reference resource {expected_resource} for this raw artifact upload"
            ),
        ));
    }
    let expected_reason_hash = sha256(approval_status.reason.as_bytes()).to_hex_prefixed();
    if raw_artifact_approval.reason_hash != expected_reason_hash {
        return Err((
            StatusCode::CONFLICT,
            "rawArtifactApprovalReason does not match the resolved approval request".to_string(),
        ));
    }
    state
        .approval_queue
        .consume_allow_once(&raw_artifact_approval.approval_id)
        .await
        .map_err(|err| {
            (
                StatusCode::CONFLICT,
                format!("rawArtifactApprovalId could not be consumed: {err}"),
            )
        })?;
    Ok(Some(raw_artifact_approval))
}

pub(crate) fn edr_raw_artifact_upload_policy(
    settings: &Settings,
) -> Result<EdrRawArtifactUploadPolicy> {
    let bytes = fs::read(&settings.policy_path).with_context(|| {
        format!(
            "read local policy for endpoint telemetry privacy {}",
            settings.policy_path.display()
        )
    })?;
    let policy_prefix = format!("policy:{}#", settings.policy_path.display());
    let value = match serde_yaml::from_slice::<serde_yaml::Value>(&bytes) {
        Ok(value) => value,
        Err(_) => {
            return Ok(EdrRawArtifactUploadPolicy {
                allowed: false,
                source: format!("{policy_prefix}default-deny-invalid-yaml"),
            });
        }
    };

    for (path, label) in EDR_RAW_ARTIFACT_POLICY_PATHS {
        if let Some(allowed) = yaml_bool_at_path(&value, path) {
            return Ok(EdrRawArtifactUploadPolicy {
                allowed,
                source: format!("{policy_prefix}{label}"),
            });
        }
    }

    Ok(EdrRawArtifactUploadPolicy {
        allowed: false,
        source: format!("{policy_prefix}default-deny"),
    })
}

pub(crate) fn yaml_bool_at_path(value: &serde_yaml::Value, path: &[&str]) -> Option<bool> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    yaml_bool_value(current)
}

pub(crate) fn yaml_bool_value(value: &serde_yaml::Value) -> Option<bool> {
    match value {
        serde_yaml::Value::Bool(value) => Some(*value),
        serde_yaml::Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "true" | "allow" | "allowed" | "enabled" | "yes" => Some(true),
            "false" | "deny" | "denied" | "disabled" | "no" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

pub(crate) fn endpoint_policy_snapshot_from_settings(
    settings: &Settings,
) -> Result<EndpointPolicySnapshot> {
    let bytes = fs::read(&settings.policy_path).with_context(|| {
        format!(
            "read local policy for endpoint receipt {}",
            settings.policy_path.display()
        )
    })?;
    endpoint_policy_snapshot_from_policy_bytes(&bytes, &settings.policy_path)
}

pub(crate) fn endpoint_policy_snapshot_from_policy_bytes(
    bytes: &[u8],
    policy_path: &FsPath,
) -> Result<EndpointPolicySnapshot> {
    let policy_hash = sha256(bytes).to_hex_prefixed();
    let policy_version =
        policy_version_from_yaml(bytes).unwrap_or_else(|| format!("local-policy:{policy_hash}"));
    let policy_epoch = policy_epoch_from_yaml(bytes)
        .or_else(|| policy_epoch_from_file(policy_path))
        .unwrap_or(1)
        .max(1);
    Ok(EndpointPolicySnapshot {
        policy_version,
        policy_hash,
        policy_epoch,
    })
}

pub(crate) fn endpoint_policy_snapshot_from_memory_policy_bytes(
    bytes: &[u8],
) -> Result<EndpointPolicySnapshot> {
    let policy_hash = sha256(bytes).to_hex_prefixed();
    let policy_version =
        policy_version_from_yaml(bytes).unwrap_or_else(|| format!("local-policy:{policy_hash}"));
    let policy_epoch = policy_epoch_from_yaml(bytes).ok_or_else(|| {
        anyhow::anyhow!("proposedPolicyYaml must declare a positive policy_epoch")
    })?;
    Ok(EndpointPolicySnapshot {
        policy_version,
        policy_hash,
        policy_epoch,
    })
}

pub(crate) fn policy_version_from_yaml(bytes: &[u8]) -> Option<String> {
    let value = serde_yaml::from_slice::<serde_yaml::Value>(bytes).ok()?;
    value
        .get("version")
        .and_then(serde_yaml::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub(crate) fn policy_epoch_from_yaml(bytes: &[u8]) -> Option<u64> {
    let value = serde_yaml::from_slice::<serde_yaml::Value>(bytes).ok()?;
    EDR_POLICY_EPOCH_YAML_PATHS
        .iter()
        .filter_map(|path| yaml_u64_at_path(&value, path))
        .find(|epoch| *epoch > 0)
}

pub(crate) fn yaml_u64_at_path(value: &serde_yaml::Value, path: &[&str]) -> Option<u64> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    yaml_u64_value(current)
}

pub(crate) fn yaml_u64_value(value: &serde_yaml::Value) -> Option<u64> {
    match value {
        serde_yaml::Value::Number(value) => value.as_u64(),
        serde_yaml::Value::String(value) => value.trim().parse::<u64>().ok(),
        _ => None,
    }
}

pub(crate) fn policy_epoch_from_file(path: &FsPath) -> Option<u64> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    let since_epoch = modified.duration_since(std::time::UNIX_EPOCH).ok()?;
    Some(since_epoch.as_secs())
}

pub(crate) fn endpoint_id_for_observation(
    settings: &Settings,
    observation: &EndpointObservation,
) -> String {
    settings
        .enrollment
        .agent_uuid
        .clone()
        .or_else(|| settings.local_agent_id.clone())
        .or_else(|| observation.host_id.clone())
        .unwrap_or_else(crate::settings::hostname_best_effort)
}

pub(crate) fn endpoint_id_for_settings(settings: &Settings) -> String {
    settings
        .enrollment
        .agent_uuid
        .clone()
        .or_else(|| settings.local_agent_id.clone())
        .unwrap_or_else(crate::settings::hostname_best_effort)
}

pub(crate) fn endpoint_response_actor_from_session(
    settings: &Settings,
    session_state: &SessionState,
    agent_id: &str,
) -> EndpointDecisionActor {
    EndpointDecisionActor {
        endpoint_id: endpoint_id_for_settings(settings),
        session_id: session_state.session_id.clone(),
        posture: Some(session_state.posture.clone()),
        agent_id: Some(agent_id.to_string()),
        workload_id: Some("endpoint-response-engine".to_string()),
        ..EndpointDecisionActor::default()
    }
}

pub(crate) fn endpoint_response_actor_from_action_input(
    settings: &Settings,
    session_state: &SessionState,
    agent_id: &str,
    input: Option<&EdrResponseActionActorInput>,
) -> EndpointDecisionActor {
    let mut actor = endpoint_response_actor_from_session(settings, session_state, agent_id);
    let Some(input) = input else {
        return actor;
    };

    if let Some(endpoint_id) = trimmed_owned(Some(input.endpoint_id.as_str())) {
        actor.endpoint_id = endpoint_id;
    }
    if let Some(host_id) = trimmed_owned(input.host_id.as_deref()) {
        actor.host_id = Some(host_id);
    }
    if let Some(user_id) = trimmed_owned(input.user_id.as_deref()) {
        actor.user_id = Some(user_id);
    }
    if let Some(session_id) = trimmed_owned(input.session_id.as_deref()) {
        actor.session_id = Some(session_id);
    }
    if let Some(posture) = trimmed_owned(input.posture.as_deref()) {
        actor.posture = Some(posture);
    }
    if let Some(agent_id) = trimmed_owned(input.agent_id.as_deref()) {
        actor.agent_id = Some(agent_id);
    }
    if let Some(workload_id) = trimmed_owned(input.workload_id.as_deref()) {
        actor.workload_id = Some(workload_id);
    }
    if let Some(approval_id) = trimmed_owned(input.approval_id.as_deref()) {
        actor.approval_id = Some(approval_id);
    }
    actor
}

pub(crate) fn endpoint_sensor_state_from_macos_host(
    status: &CombinedSystemExtensionStatus,
) -> EndpointSensorState {
    EndpointSensorState {
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
                last_seen: Some(chrono::Utc::now()),
            },
            endpoint_provider_state_from_macos_provider(
                "macos.endpoint_security",
                EndpointProviderKind::EndpointSecurity,
                status,
                &status.endpoint_security,
            ),
            endpoint_provider_state_from_macos_provider(
                "macos.network_extension",
                EndpointProviderKind::NetworkExtension,
                status,
                &status.network_extension,
            ),
        ],
    }
}

pub(crate) fn endpoint_provider_recoveries(
    previous_status: Option<&CombinedSystemExtensionStatus>,
    current_sensor_state: &EndpointSensorState,
) -> Vec<EdrProviderRecovery> {
    let Some(previous_status) = previous_status else {
        return Vec::new();
    };
    let previous_sensor_state = endpoint_sensor_state_from_macos_host(previous_status);
    let previous_providers = previous_sensor_state
        .providers
        .into_iter()
        .map(|provider| (provider.provider_id.clone(), provider))
        .collect::<BTreeMap<_, _>>();
    let mut recoveries = current_sensor_state
        .providers
        .iter()
        .filter_map(|current| {
            let previous = previous_providers.get(&current.provider_id)?;
            if !previous.installed
                || !previous.degraded
                || current.degraded
                || !current.healthy
                || !current.active
            {
                return None;
            }
            Some(EdrProviderRecovery {
                provider_id: current.provider_id.clone(),
                provider_kind: current.provider_kind.clone(),
                previous_active: previous.active,
                previous_healthy: previous.healthy,
                previous_degraded: previous.degraded,
                previous_degradation_reasons: previous.degradation_reasons.clone(),
                current_active: current.active,
                current_healthy: current.healthy,
                current_degraded: current.degraded,
                recovered_at: current.last_seen,
            })
        })
        .collect::<Vec<_>>();
    recoveries.sort_by(|left, right| left.provider_id.cmp(&right.provider_id));
    recoveries
}

pub(crate) fn provider_recovery_receipt_evidence(
    recoveries: &[EdrProviderRecovery],
) -> Vec<EndpointReceiptEvidence> {
    if recoveries.is_empty() {
        return Vec::new();
    }
    let recovered_ids = recoveries
        .iter()
        .map(|recovery| recovery.provider_id.as_str())
        .collect::<Vec<_>>()
        .join(",");
    vec![
        EndpointReceiptEvidence::hashed("providerRecoveryCount", recoveries.len().to_string()),
        EndpointReceiptEvidence::hashed("providerRecoveredIds", recovered_ids),
    ]
}

pub(crate) fn network_extension_response_execution_evidence(
    provider: &ProviderStatus,
) -> Vec<EndpointReceiptEvidence> {
    let mut evidence = vec![
        EndpointReceiptEvidence::hashed(
            "networkExtensionRuntime",
            provider_runtime_evidence_value(&provider.runtime),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionPolicySynced",
            optional_bool_evidence_value(provider.policy_synced),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEnforcementReady",
            optional_bool_evidence_value(provider.enforcement_ready),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionPolicyEpoch",
            optional_u64_evidence_value(provider.policy_epoch),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionFlowsObserved",
            provider_counter(provider, &["flows_observed"]).to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionFlowsBlocked",
            provider_counter(provider, &["flows_blocked"]).to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionRemediationRequests",
            provider_counter(provider, &["remediation_requests"]).to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionDroppedVerdicts",
            provider_counter(provider, &["dropped_verdicts"]).to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadObserved",
            provider.last_reload_observation.is_some().to_string(),
        ),
    ];
    if let Some(observation) = provider.last_reload_observation.as_ref() {
        if let Some(command) = observation
            .command
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            evidence.push(EndpointReceiptEvidence::hashed(
                "networkExtensionReloadObservedCommand",
                command,
            ));
        }
        if let Some(request_id) = observation
            .request_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            evidence.push(EndpointReceiptEvidence::hashed(
                "networkExtensionReloadObservedRequestId",
                request_id,
            ));
        }
        if let Some(policy_snapshot_path) = observation
            .policy_snapshot_path
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            evidence.push(EndpointReceiptEvidence::hashed(
                "networkExtensionReloadObservedPolicySnapshotPath",
                policy_snapshot_path,
            ));
        }
        if let Some(generation) = observation.generation {
            evidence.push(EndpointReceiptEvidence::hashed(
                "networkExtensionReloadObservedGeneration",
                generation.to_string(),
            ));
        }
        if let Some(accepted) = observation.accepted {
            evidence.push(EndpointReceiptEvidence::hashed(
                "networkExtensionReloadObservedAccepted",
                accepted.to_string(),
            ));
        }
        if let Some(reloaded) = observation.reloaded {
            evidence.push(EndpointReceiptEvidence::hashed(
                "networkExtensionReloadObservedReloaded",
                reloaded.to_string(),
            ));
        }
        if let Some(error) = observation
            .error
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            evidence.push(EndpointReceiptEvidence::hashed(
                "networkExtensionReloadObservedError",
                error,
            ));
        }
    }
    if let Some(last_error) = provider
        .last_error
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        evidence.push(EndpointReceiptEvidence::hashed(
            "networkExtensionLastError",
            last_error,
        ));
    }
    evidence
}

pub(crate) struct NetworkExtensionFlowCounterSummary {
    pub(crate) flow_counter_observed: bool,
    pub(crate) observed_flow_count: u64,
    pub(crate) blocked_flow_count: u64,
    pub(crate) remediation_request_count: u64,
    pub(crate) dropped_verdict_count: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NetworkExtensionReloadRequestProof {
    pub(crate) requested: bool,
    pub(crate) saved: bool,
    pub(crate) request_id: Option<String>,
    pub(crate) policy_snapshot_path: String,
    pub(crate) generation: u64,
    pub(crate) provider_reload_observed: bool,
    pub(crate) provider_reload_matched: bool,
    pub(crate) provider_reload_request_id_matches: bool,
    pub(crate) provider_reload_generation_matches: bool,
    pub(crate) provider_reload_policy_snapshot_path_matches: bool,
    pub(crate) provider_reloaded: Option<bool>,
    pub(crate) provider_policy_synced: Option<bool>,
    pub(crate) provider_enforcement_ready: Option<bool>,
    pub(crate) provider_reload_elapsed_ms: u64,
    pub(crate) provider_reload_attempts: u64,
    pub(crate) error: Option<String>,
}

pub(crate) fn network_extension_flow_counter_summary(
    provider: &ProviderStatus,
) -> NetworkExtensionFlowCounterSummary {
    let observed_flow_count = provider_counter(provider, &["flows_observed"]);
    let blocked_flow_count = provider_counter(provider, &["flows_blocked"]);
    let remediation_request_count = provider_counter(provider, &["remediation_requests"]);
    let dropped_verdict_count = provider_counter(provider, &["dropped_verdicts"]);
    NetworkExtensionFlowCounterSummary {
        flow_counter_observed: observed_flow_count > 0 || blocked_flow_count > 0,
        observed_flow_count,
        blocked_flow_count,
        remediation_request_count,
        dropped_verdict_count,
    }
}

pub(crate) struct NetworkExtensionLiveEnforcementProof {
    pub(crate) proven: bool,
    pub(crate) reasons: Vec<String>,
}

pub(crate) struct NetworkExtensionLiveEnforcementProofInput<'a> {
    pub(crate) snapshot_present: bool,
    pub(crate) snapshot_decodable: bool,
    pub(crate) active_restriction_count: usize,
    pub(crate) enforcement_ready: bool,
    pub(crate) flow_counters: &'a NetworkExtensionFlowCounterSummary,
    pub(crate) execution_id_provided: bool,
    pub(crate) provider_reload_delivery: Option<&'a EdrNetworkExtensionReloadDeliveryProof>,
}

pub(crate) fn network_extension_live_enforcement_proof(
    input: NetworkExtensionLiveEnforcementProofInput<'_>,
) -> NetworkExtensionLiveEnforcementProof {
    let mut reasons = Vec::new();
    if !input.snapshot_present {
        reasons.push("snapshot_missing".to_string());
    }
    if !input.snapshot_decodable {
        reasons.push("snapshot_not_decodable".to_string());
    }
    if input.active_restriction_count == 0 {
        reasons.push("no_active_restrictions".to_string());
    }
    if !input.enforcement_ready {
        reasons.push("provider_not_enforcement_ready".to_string());
    }
    if !input.flow_counters.flow_counter_observed {
        reasons.push("flow_counters_not_observed".to_string());
    }
    if input.flow_counters.blocked_flow_count == 0 {
        reasons.push("blocked_flow_counter_zero".to_string());
    }
    if input.flow_counters.dropped_verdict_count > 0 {
        reasons.push("dropped_verdicts_observed".to_string());
    }
    if !input.execution_id_provided {
        reasons.push("execution_id_required".to_string());
    }
    match input.provider_reload_delivery {
        Some(delivery) if delivery.matched => {}
        Some(_) => reasons.push("reload_delivery_not_matched".to_string()),
        None => reasons.push("reload_delivery_missing".to_string()),
    }
    reasons.sort();
    reasons.dedup();

    NetworkExtensionLiveEnforcementProof {
        proven: reasons.is_empty(),
        reasons,
    }
}

pub(crate) fn network_extension_reload_request_evidence(
    proof: &NetworkExtensionReloadRequestProof,
) -> Vec<EndpointReceiptEvidence> {
    let mut evidence = vec![
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadRequested",
            proof.requested.to_string(),
        ),
        EndpointReceiptEvidence::hashed("networkExtensionReloadSaved", proof.saved.to_string()),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadGeneration",
            proof.generation.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadPolicySnapshotPath",
            proof.policy_snapshot_path.as_str(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderObserved",
            proof.provider_reload_observed.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderMatched",
            proof.provider_reload_matched.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderRequestIdMatches",
            proof.provider_reload_request_id_matches.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderGenerationMatches",
            proof.provider_reload_generation_matches.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderPolicySnapshotPathMatches",
            proof
                .provider_reload_policy_snapshot_path_matches
                .to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderAttempts",
            proof.provider_reload_attempts.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderElapsedMs",
            proof.provider_reload_elapsed_ms.to_string(),
        ),
    ];
    if let Some(reloaded) = proof.provider_reloaded {
        evidence.push(EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderReloaded",
            reloaded.to_string(),
        ));
    }
    if let Some(policy_synced) = proof.provider_policy_synced {
        evidence.push(EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderPolicySynced",
            policy_synced.to_string(),
        ));
    }
    if let Some(enforcement_ready) = proof.provider_enforcement_ready {
        evidence.push(EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderEnforcementReady",
            enforcement_ready.to_string(),
        ));
    }
    if let Some(request_id) = proof.request_id.as_deref() {
        evidence.push(EndpointReceiptEvidence::hashed(
            "networkExtensionReloadRequestId",
            request_id,
        ));
    }
    if let Some(error) = proof.error.as_deref() {
        evidence.push(EndpointReceiptEvidence::hashed(
            "networkExtensionReloadError",
            error,
        ));
    }
    evidence
}

pub(crate) async fn network_extension_reload_delivery_for_execution(
    state: &AgentApiState,
    execution_id: Option<&str>,
    provider: &ProviderStatus,
) -> Result<Option<EdrNetworkExtensionReloadDeliveryProof>, (StatusCode, String)> {
    let Some(execution_id) = execution_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let execution = {
        let ledger = state.edr_response_execution_ledger.lock().await;
        ledger
            .get(execution_id)
            .map_err(internal_error)?
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!("response execution not found: {execution_id}"),
                )
            })?
    };
    if execution.action != EndpointDecisionAction::RestrictEgress {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "response execution {} is {}, not restrict_egress",
                execution.execution_id,
                execution.action.as_str()
            ),
        ));
    }
    let execution_receipt = {
        let ledger = state.edr_receipt_ledger.lock().await;
        latest_required_receipt(
            &ledger,
            "response_execution",
            execution.execution_id.as_str(),
            "response execution receipt",
        )
        .or_else(|err| {
            if err.0 == StatusCode::NOT_FOUND {
                latest_required_receipt_by_execution_id(
                    &ledger,
                    "response_execution",
                    execution.execution_id.as_str(),
                    "response execution receipt",
                )
            } else {
                Err(err)
            }
        })?
    };

    let observation = provider.last_reload_observation.as_ref();
    let request_id_matches = observation
        .and_then(|observation| observation.request_id.as_deref())
        .is_some_and(|request_id| {
            receipt_evidence_hash_matches(
                &execution_receipt,
                "networkExtensionReloadRequestId",
                request_id,
            )
        });
    let generation_matches = observation
        .and_then(|observation| observation.generation)
        .is_some_and(|generation| {
            receipt_evidence_hash_matches(
                &execution_receipt,
                "networkExtensionReloadGeneration",
                generation.to_string().as_str(),
            )
        });
    let policy_snapshot_path_matches = observation
        .and_then(|observation| observation.policy_snapshot_path.as_deref())
        .is_some_and(|policy_snapshot_path| {
            receipt_evidence_hash_matches(
                &execution_receipt,
                "networkExtensionReloadPolicySnapshotPath",
                policy_snapshot_path,
            )
        });
    let requested = receipt_evidence_hash_matches(
        &execution_receipt,
        "networkExtensionReloadRequested",
        "true",
    );
    let saved =
        receipt_evidence_hash_matches(&execution_receipt, "networkExtensionReloadSaved", "true");
    let provider_reloaded = observation.and_then(|observation| observation.reloaded);
    let matched = requested
        && saved
        && request_id_matches
        && generation_matches
        && policy_snapshot_path_matches
        && provider_reloaded == Some(true);

    Ok(Some(EdrNetworkExtensionReloadDeliveryProof {
        execution_id: execution.execution_id,
        observed: observation.is_some(),
        matched,
        request_id_matches,
        generation_matches,
        policy_snapshot_path_matches,
        provider_reloaded,
    }))
}

pub(crate) struct NetworkExtensionEgressPolicyProofEvidenceInput<'a> {
    pub(crate) provider_policy_path: &'a FsPath,
    pub(crate) snapshot_present: bool,
    pub(crate) snapshot_decodable: bool,
    pub(crate) snapshot_hash: Option<&'a str>,
    pub(crate) generated_at: Option<&'a chrono::DateTime<chrono::Utc>>,
    pub(crate) restriction_count: usize,
    pub(crate) active_restriction_count: usize,
    pub(crate) expired_restriction_count: usize,
    pub(crate) enforcement_ready: bool,
    pub(crate) live_enforcement_proven: bool,
    pub(crate) live_enforcement_proof_reasons: &'a [String],
    pub(crate) flow_counter_observed: bool,
    pub(crate) provider: &'a ProviderStatus,
    pub(crate) provider_status_refresh: &'a EdrProviderStatusRefreshResult,
    pub(crate) provider_reload_delivery: Option<&'a EdrNetworkExtensionReloadDeliveryProof>,
}

pub(crate) fn network_extension_egress_policy_proof_evidence(
    input: NetworkExtensionEgressPolicyProofEvidenceInput<'_>,
) -> Vec<EndpointReceiptEvidence> {
    let mut evidence = vec![
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyPath",
            input.provider_policy_path.display().to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicySnapshotPresent",
            input.snapshot_present.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicySnapshotDecodable",
            input.snapshot_decodable.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyRestrictionCount",
            input.restriction_count.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyActiveRestrictionCount",
            input.active_restriction_count.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyExpiredRestrictionCount",
            input.expired_restriction_count.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyEnforcementReady",
            input.enforcement_ready.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionLiveEnforcementProven",
            input.live_enforcement_proven.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionLiveEnforcementProofReasons",
            input.live_enforcement_proof_reasons.join(","),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionFlowCounterObserved",
            input.flow_counter_observed.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyProviderRefreshRequested",
            input.provider_status_refresh.requested.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyProviderRefreshRefreshed",
            input.provider_status_refresh.refreshed.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyProviderRefreshTimeoutMs",
            input.provider_status_refresh.timeout_ms.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyProviderRefreshElapsedMs",
            input.provider_status_refresh.elapsed_ms.to_string(),
        ),
    ];
    if let Some(snapshot_hash) = input.snapshot_hash.filter(|value| !value.trim().is_empty()) {
        evidence.push(EndpointReceiptEvidence {
            key: "networkExtensionEgressPolicySnapshotHash".to_string(),
            value_hash: snapshot_hash.to_string(),
            redaction_class: EndpointEvidenceRedactionClass::HashOnly,
            raw_value: None,
        });
    }
    if let Some(generated_at) = input.generated_at {
        evidence.push(EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyGeneratedAt",
            generated_at.to_rfc3339(),
        ));
    }
    if let Some(error) = input.provider_status_refresh.error.as_deref() {
        evidence.push(EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyProviderRefreshError",
            error,
        ));
    }
    if let Some(delivery) = input.provider_reload_delivery {
        evidence.extend([
            EndpointReceiptEvidence::hashed(
                "networkExtensionReloadDeliveryExecutionId",
                delivery.execution_id.as_str(),
            ),
            EndpointReceiptEvidence::hashed(
                "networkExtensionReloadDeliveryObserved",
                delivery.observed.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "networkExtensionReloadDeliveryMatched",
                delivery.matched.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "networkExtensionReloadDeliveryRequestIdMatches",
                delivery.request_id_matches.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "networkExtensionReloadDeliveryGenerationMatches",
                delivery.generation_matches.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "networkExtensionReloadDeliveryPolicySnapshotPathMatches",
                delivery.policy_snapshot_path_matches.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "networkExtensionReloadDeliveryProviderReloaded",
                optional_bool_evidence_value(delivery.provider_reloaded),
            ),
        ]);
    }
    evidence.extend(network_extension_response_execution_evidence(
        input.provider,
    ));
    evidence
}

pub(crate) fn provider_runtime_evidence_value(runtime: &ProviderRuntimeState) -> String {
    match runtime {
        ProviderRuntimeState::Unknown => "unknown".to_string(),
        ProviderRuntimeState::Inactive => "inactive".to_string(),
        ProviderRuntimeState::Active => "active".to_string(),
        ProviderRuntimeState::Degraded { reason } => {
            format!("degraded:{}", sanitize_provider_status_reason(reason))
        }
    }
}

pub(crate) fn optional_bool_evidence_value(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "unknown",
    }
}

pub(crate) fn optional_u64_evidence_value(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub(crate) fn endpoint_provider_state_from_macos_provider(
    provider_id: &str,
    provider_kind: EndpointProviderKind,
    host_status: &CombinedSystemExtensionStatus,
    provider: &ProviderStatus,
) -> EndpointProviderState {
    let installed = host_status.install_state == SystemExtensionInstallState::Installed
        || provider
            .provider_state
            .as_ref()
            .map(|state| state.installed)
            .unwrap_or(false);
    let active = matches!(provider.runtime, ProviderRuntimeState::Active)
        || provider
            .provider_state
            .as_ref()
            .map(|state| state.active)
            .unwrap_or(false);
    let dropped_event_count = provider_counter(
        provider,
        &["dropped_event_count", "dropped_events", "dropped"],
    );
    let deadline_miss_count =
        provider_counter(provider, &["deadline_miss_count", "deadline_misses"]);
    let full_disk_access = provider_full_disk_access(&provider_kind, provider);
    let provider_attestation_degraded = provider.provider_state.as_ref().is_some_and(|state| {
        !state.installed
            || !state.active
            || !state.healthy
            || matches!(
                state.availability,
                ProviderAvailability::Unavailable
                    | ProviderAvailability::Inactive
                    | ProviderAvailability::Degraded
            )
            || !state.degraded_reasons.is_empty()
    });
    let degraded = matches!(
        provider.runtime,
        ProviderRuntimeState::Unknown
            | ProviderRuntimeState::Inactive
            | ProviderRuntimeState::Degraded { .. }
    ) || !installed
        || !active
        || host_status.approval == SystemExtensionApproval::ApprovalBlocked
        || provider_attestation_degraded
        || dropped_event_count > 0
        || deadline_miss_count > 0
        || full_disk_access == Some(false)
        || provider.policy_synced == Some(false)
        || provider.enforcement_ready == Some(false)
        || provider.last_error.is_some();
    let mut degradation_reasons = macos_provider_degradation_reasons(
        host_status,
        provider,
        dropped_event_count,
        deadline_miss_count,
        full_disk_access,
    );
    if degraded && degradation_reasons.is_empty() {
        degradation_reasons.push("provider degraded without a specific reason".to_string());
    }
    let healthy = active && !degraded;

    EndpointProviderState {
        provider_id: provider_id.to_string(),
        provider_kind,
        installed,
        active,
        healthy,
        degraded,
        degradation_reasons,
        dropped_event_count,
        deadline_miss_count,
        full_disk_access,
        last_seen: provider_last_seen(provider).or_else(|| active.then(chrono::Utc::now)),
    }
}

pub(crate) fn macos_provider_degradation_reasons(
    host_status: &CombinedSystemExtensionStatus,
    provider: &ProviderStatus,
    dropped_event_count: u64,
    deadline_miss_count: u64,
    full_disk_access: Option<bool>,
) -> Vec<String> {
    let mut reasons = Vec::new();
    match provider.runtime.clone() {
        ProviderRuntimeState::Degraded { reason } if !reason.trim().is_empty() => {
            reasons.push(sanitize_provider_status_reason(&reason));
        }
        ProviderRuntimeState::Unknown => reasons.push("provider runtime unknown".to_string()),
        ProviderRuntimeState::Inactive => reasons.push("provider runtime inactive".to_string()),
        _ => {}
    }
    if host_status.install_state == SystemExtensionInstallState::NotInstalled {
        reasons.push("system extension not installed".to_string());
    }
    if host_status.approval == SystemExtensionApproval::ApprovalBlocked {
        reasons.push("system extension approval blocked".to_string());
    }
    if let Some(last_error) = provider
        .last_error
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        reasons.push(sanitize_provider_status_reason(last_error));
    }
    if provider.policy_synced == Some(false) {
        reasons.push("provider policy not synced".to_string());
    }
    if provider.enforcement_ready == Some(false) {
        reasons.push("provider enforcement not ready".to_string());
    }
    if let Some(provider_state) = &provider.provider_state {
        if !provider_state.installed {
            reasons.push("provider attestation reports not installed".to_string());
        }
        if !provider_state.active {
            reasons.push("provider attestation reports inactive".to_string());
        }
        if !provider_state.healthy {
            reasons.push("provider attestation reports unhealthy".to_string());
        }
        match provider_state.availability {
            ProviderAvailability::Unavailable => {
                reasons.push("provider attestation reports unavailable".to_string());
            }
            ProviderAvailability::Inactive => {
                reasons.push("provider attestation reports inactive".to_string());
            }
            ProviderAvailability::Active => {}
            ProviderAvailability::Degraded => {
                reasons.push("provider attestation reports degraded".to_string());
            }
        }
        reasons.extend(
            provider_state
                .degraded_reasons
                .iter()
                .map(|reason| sanitize_provider_status_reason(reason)),
        );
    }
    if dropped_event_count > 0 {
        reasons.push("provider dropped enforcement events".to_string());
    }
    if deadline_miss_count > 0 {
        reasons.push("provider authorization deadline misses".to_string());
    }
    if full_disk_access == Some(false) {
        reasons.push("missing_full_disk_access".to_string());
    }
    reasons.sort();
    reasons.dedup();
    reasons
}

pub(crate) fn provider_full_disk_access(
    provider_kind: &EndpointProviderKind,
    provider: &ProviderStatus,
) -> Option<bool> {
    if provider_kind != &EndpointProviderKind::EndpointSecurity {
        return None;
    }
    if provider_reports_missing_full_disk_access(provider) {
        Some(false)
    } else {
        None
    }
}

pub(crate) fn provider_reports_missing_full_disk_access(provider: &ProviderStatus) -> bool {
    matches!(
        &provider.runtime,
        ProviderRuntimeState::Degraded { reason } if is_missing_full_disk_access_signal(reason)
    ) || provider.provider_state.as_ref().is_some_and(|state| {
        state
            .degraded_reasons
            .iter()
            .any(|reason| is_missing_full_disk_access_signal(reason))
    }) || provider
        .evidence_paths
        .iter()
        .any(|artifact| is_missing_full_disk_access_signal(&artifact.kind))
}

pub(crate) fn is_missing_full_disk_access_signal(value: &str) -> bool {
    let normalized = value
        .trim()
        .chars()
        .map(|ch| match ch {
            ' ' | '-' => '_',
            _ => ch.to_ascii_lowercase(),
        })
        .collect::<String>();
    normalized == "missing_full_disk_access"
}

pub(crate) fn provider_counter(provider: &ProviderStatus, keys: &[&str]) -> u64 {
    keys.iter()
        .find_map(|key| provider.counters.get(*key).copied())
        .unwrap_or(0)
}

pub(crate) fn provider_last_seen(
    provider: &ProviderStatus,
) -> Option<chrono::DateTime<chrono::Utc>> {
    provider
        .last_healthy_timestamp
        .as_deref()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
}

pub(crate) fn next_receipt_sequence(path: &FsPath) -> Result<u64> {
    Ok(read_endpoint_receipt_ledger(path)?
        .iter()
        .filter_map(receipt_local_sequence)
        .max()
        .unwrap_or(0)
        .saturating_add(1)
        .max(1))
}

pub(crate) fn read_endpoint_receipt_ledger(path: &FsPath) -> Result<Vec<SignedReceipt>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("read endpoint receipt ledger {}", path.display()));
        }
    };
    let mut receipts = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let receipt: SignedReceipt = serde_json::from_str(line).with_context(|| {
            format!(
                "parse endpoint receipt ledger line {} from {}",
                index + 1,
                path.display()
            )
        })?;
        receipts.push(receipt);
    }
    Ok(receipts)
}

pub(crate) fn endpoint_receipt_index_path(path: &FsPath) -> PathBuf {
    let mut filename = path
        .file_name()
        .map(|value| value.to_os_string())
        .unwrap_or_else(|| "decision-receipts.jsonl".into());
    filename.push(".index.jsonl");
    path.with_file_name(filename)
}

pub(crate) fn read_endpoint_receipt_index(
    path: &FsPath,
) -> Result<Vec<EndpointReceiptIndexRecord>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("read endpoint receipt index {}", path.display()));
        }
    };
    let mut records = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record: EndpointReceiptIndexRecord = serde_json::from_str(line).with_context(|| {
            format!(
                "parse endpoint receipt index line {} from {}",
                index + 1,
                path.display()
            )
        })?;
        records.push(record);
    }
    Ok(records)
}

pub(crate) fn read_recent_indexed_endpoint_receipts(
    path: &FsPath,
    limit: usize,
    filter: EdrReceiptFilter<'_>,
) -> Result<Option<Vec<SignedReceipt>>> {
    let index_path = endpoint_receipt_index_path(path);
    if !index_path.exists() {
        if !path.exists() {
            return Ok(None);
        }
        rebuild_endpoint_receipt_index(path)?;
    }
    let mut records = read_endpoint_receipt_index_or_rebuild(path, &index_path)?;
    if records.is_empty() {
        if endpoint_receipt_ledger_len(path)? > 0 {
            rebuild_endpoint_receipt_index(path)?;
            records = read_endpoint_receipt_index(&index_path)?;
            if !records.is_empty() {
                return read_recent_indexed_endpoint_receipts_from_records(
                    path, limit, filter, records,
                )
                .map(Some);
            }
        }
        return Ok(Some(Vec::new()));
    }
    if !endpoint_receipt_index_is_current(path, &records)? {
        rebuild_endpoint_receipt_index(path)?;
        records = read_endpoint_receipt_index(&index_path)?;
        if records.is_empty() {
            return Ok(Some(Vec::new()));
        }
    }
    read_recent_indexed_endpoint_receipts_from_records(path, limit, filter, records).map(Some)
}

pub(crate) fn read_endpoint_receipt_index_or_rebuild(
    path: &FsPath,
    index_path: &FsPath,
) -> Result<Vec<EndpointReceiptIndexRecord>> {
    match read_endpoint_receipt_index(index_path) {
        Ok(records) => Ok(records),
        Err(index_error) => {
            let index_error = index_error.to_string();
            rebuild_endpoint_receipt_index(path).with_context(|| {
                format!("rebuild endpoint receipt index after index read failed: {index_error}")
            })?;
            read_endpoint_receipt_index(index_path).with_context(|| {
                format!("read endpoint receipt index after rebuilding corrupt index: {index_error}")
            })
        }
    }
}

pub(crate) fn read_recent_indexed_endpoint_receipts_from_records(
    path: &FsPath,
    limit: usize,
    filter: EdrReceiptFilter<'_>,
    records: Vec<EndpointReceiptIndexRecord>,
) -> Result<Vec<SignedReceipt>> {
    let records = match validate_endpoint_receipt_index_records(path, records) {
        Ok(records) => records,
        Err(index_error) => {
            let index_error = index_error.to_string();
            let rebuild_error_context =
                format!("rebuild endpoint receipt index after validation failed: {index_error}");
            rebuild_endpoint_receipt_index(path).with_context(|| rebuild_error_context)?;
            read_endpoint_receipt_index(&endpoint_receipt_index_path(path)).with_context(|| {
                format!("read endpoint receipt index after rebuilding stale index: {index_error}")
            })?
        }
    };
    let selected = select_endpoint_receipt_index_records(records, limit, filter);
    match read_endpoint_receipts_by_index(path, &selected) {
        Ok(receipts) => Ok(receipts),
        Err(index_error) => {
            let index_error = index_error.to_string();
            let rebuild_error_context =
                format!("rebuild endpoint receipt index after indexed read failed: {index_error}");
            rebuild_endpoint_receipt_index(path).with_context(|| rebuild_error_context)?;
            let rebuilt_records = read_endpoint_receipt_index(&endpoint_receipt_index_path(path))?;
            let selected = select_endpoint_receipt_index_records(rebuilt_records, limit, filter);
            let read_error_context = format!(
                "read endpoint receipts after rebuilding corrupt receipt index: {index_error}"
            );
            read_endpoint_receipts_by_index(path, &selected).with_context(|| read_error_context)
        }
    }
}

pub(crate) fn validate_endpoint_receipt_index_records(
    path: &FsPath,
    records: Vec<EndpointReceiptIndexRecord>,
) -> Result<Vec<EndpointReceiptIndexRecord>> {
    read_endpoint_receipts_by_index(path, &records)?;
    Ok(records)
}

pub(crate) fn select_endpoint_receipt_index_records(
    records: Vec<EndpointReceiptIndexRecord>,
    limit: usize,
    filter: EdrReceiptFilter<'_>,
) -> Vec<EndpointReceiptIndexRecord> {
    records
        .into_iter()
        .filter(|record| receipt_index_matches_filter(record, filter))
        .rev()
        .take(limit)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
}

pub(crate) fn endpoint_receipt_ledger_len(path: &FsPath) -> Result<u64> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(err) => {
            Err(err).with_context(|| format!("stat endpoint receipt ledger {}", path.display()))
        }
    }
}

pub(crate) fn endpoint_receipt_index_is_current(
    path: &FsPath,
    records: &[EndpointReceiptIndexRecord],
) -> Result<bool> {
    let ledger_len = endpoint_receipt_ledger_len(path)?;
    let Some(last) = records.last() else {
        return Ok(ledger_len == 0);
    };
    let last_record_end = last.byte_offset.saturating_add(last.byte_len);
    Ok(ledger_len == last_record_end || ledger_len == last_record_end.saturating_add(1))
}

pub(crate) fn read_endpoint_receipts_by_index(
    path: &FsPath,
    records: &[EndpointReceiptIndexRecord],
) -> Result<Vec<SignedReceipt>> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("open endpoint receipt ledger {}", path.display()))?;
    let mut receipts = Vec::with_capacity(records.len());
    for record in records {
        file.seek(SeekFrom::Start(record.byte_offset))
            .with_context(|| format!("seek endpoint receipt ledger {}", path.display()))?;
        let mut bytes = vec![0u8; record.byte_len as usize];
        file.read_exact(&mut bytes)
            .with_context(|| format!("read endpoint receipt ledger {}", path.display()))?;
        let receipt: SignedReceipt = serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "parse endpoint receipt {} at byte offset {} from {}",
                record
                    .receipt_id
                    .as_deref()
                    .unwrap_or("<missing-receipt-id>"),
                record.byte_offset,
                path.display()
            )
        })?;
        validate_endpoint_receipt_index_record(path, record, &receipt)?;
        receipts.push(receipt);
    }
    Ok(receipts)
}

pub(crate) fn validate_endpoint_receipt_index_record(
    path: &FsPath,
    record: &EndpointReceiptIndexRecord,
    receipt: &SignedReceipt,
) -> Result<()> {
    let actual = endpoint_receipt_index_record(receipt, record.byte_offset, record.byte_len);
    if actual != *record {
        return Err(anyhow::anyhow!(
            "endpoint receipt index metadata mismatch at {} byte offset {}: expected receipt {:?} family {:?}, found receipt {:?} family {:?}",
            path.display(),
            record.byte_offset,
            record.receipt_id,
            record.family,
            actual.receipt_id,
            actual.family
        ));
    }
    Ok(())
}

pub(crate) fn rebuild_endpoint_receipt_index(path: &FsPath) -> Result<()> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let _ = fs::remove_file(endpoint_receipt_index_path(path));
            return Ok(());
        }
        Err(err) => {
            return Err(err)
                .with_context(|| format!("read endpoint receipt ledger {}", path.display()));
        }
    };
    let mut records = Vec::new();
    let mut byte_offset = 0u64;
    for segment in contents.split_inclusive('\n') {
        let line_without_newline = segment.trim_end_matches('\n');
        let line = line_without_newline.trim();
        if !line.is_empty() {
            let receipt: SignedReceipt = serde_json::from_str(line).with_context(|| {
                format!(
                    "parse endpoint receipt ledger at byte offset {} from {}",
                    byte_offset,
                    path.display()
                )
            })?;
            records.push(endpoint_receipt_index_record(
                &receipt,
                byte_offset,
                line_without_newline.len() as u64,
            ));
        }
        byte_offset = byte_offset.saturating_add(segment.len() as u64);
    }
    let mut contents = String::new();
    for record in &records {
        let line =
            serde_json::to_string(record).context("serialize endpoint receipt index record")?;
        contents.push_str(&line);
        contents.push('\n');
    }
    let index_path = endpoint_receipt_index_path(path);
    crate::security::fs::write_private_atomic(
        &index_path,
        contents.as_bytes(),
        "endpoint receipt index",
    )
}

pub(crate) fn endpoint_receipt_index_record(
    receipt: &SignedReceipt,
    byte_offset: u64,
    byte_len: u64,
) -> EndpointReceiptIndexRecord {
    let family = receipt_family(receipt).map(ToString::to_string);
    let finding_id =
        receipt_endpoint_decision_str(receipt, &["decision", "findingId"]).map(ToString::to_string);
    EndpointReceiptIndexRecord {
        receipt_id: receipt.receipt.receipt_id.clone(),
        timestamp: receipt.receipt.timestamp.clone(),
        family: family.clone(),
        action: receipt_endpoint_decision_str(receipt, &["decision", "action"])
            .map(ToString::to_string),
        finding_id: finding_id.clone(),
        rule_id: receipt_endpoint_decision_str(receipt, &["decision", "ruleId"])
            .map(ToString::to_string),
        graph_slice_id: receipt_endpoint_decision_str(receipt, &["graph", "graphSliceId"])
            .map(ToString::to_string),
        root_node_id: receipt_endpoint_decision_str(receipt, &["graph", "processNodeId"])
            .map(ToString::to_string),
        execution_id: (family.as_deref() == Some("response_execution"))
            .then(|| finding_id.clone())
            .flatten(),
        execution_status: response_execution_status_from_receipt(receipt),
        actor_endpoint_id: receipt_endpoint_decision_str(receipt, &["actor", "endpointId"])
            .map(ToString::to_string),
        actor_user_id: receipt_endpoint_decision_str(receipt, &["actor", "userId"])
            .map(ToString::to_string),
        actor_session_id: receipt_endpoint_decision_str(receipt, &["actor", "sessionId"])
            .map(ToString::to_string),
        actor_agent_id: receipt_endpoint_decision_str(receipt, &["actor", "agentId"])
            .map(ToString::to_string),
        actor_workload_id: receipt_endpoint_decision_str(receipt, &["actor", "workloadId"])
            .map(ToString::to_string),
        actor_approval_id: receipt_endpoint_decision_str(receipt, &["actor", "approvalId"])
            .map(ToString::to_string),
        local_sequence: receipt_local_sequence(receipt),
        byte_offset,
        byte_len,
    }
}

pub(crate) fn response_execution_status_from_receipt(receipt: &SignedReceipt) -> Option<String> {
    [
        "succeeded",
        "failed",
        "partial",
        "rollback_pending",
        "rollback_failed",
        "expired",
        "cancelled",
        "rolled_back",
    ]
    .into_iter()
    .find(|status| receipt_evidence_hash_matches(receipt, "executionStatus", status))
    .map(ToString::to_string)
}

pub(crate) fn receipt_index_matches_filter(
    record: &EndpointReceiptIndexRecord,
    filter: EdrReceiptFilter<'_>,
) -> bool {
    string_filter_matches(record.receipt_id.as_deref(), filter.receipt_id)
        && string_filter_matches(record.family.as_deref(), filter.family)
        && string_filter_matches(record.action.as_deref(), filter.action)
        && string_filter_matches(record.finding_id.as_deref(), filter.finding_id)
        && string_filter_matches(record.rule_id.as_deref(), filter.rule_id)
        && string_filter_matches(record.graph_slice_id.as_deref(), filter.graph_slice_id)
        && string_filter_matches(record.root_node_id.as_deref(), filter.root_node_id)
        && string_filter_matches(record.execution_id.as_deref(), filter.execution_id)
        && string_filter_matches(record.execution_status.as_deref(), filter.status)
        && string_filter_matches(
            record.actor_endpoint_id.as_deref(),
            filter.actor_endpoint_id,
        )
        && string_filter_matches(record.actor_user_id.as_deref(), filter.actor_user_id)
        && string_filter_matches(record.actor_session_id.as_deref(), filter.actor_session_id)
        && string_filter_matches(record.actor_agent_id.as_deref(), filter.actor_agent_id)
        && string_filter_matches(
            record.actor_workload_id.as_deref(),
            filter.actor_workload_id,
        )
        && string_filter_matches(
            record.actor_approval_id.as_deref(),
            filter.actor_approval_id,
        )
        && filter
            .local_sequence
            .map_or(true, |expected| record.local_sequence == Some(expected))
}

pub(crate) fn string_filter_matches(actual: Option<&str>, expected: Option<&str>) -> bool {
    expected.map_or(true, |expected| actual == Some(expected))
}

pub(crate) fn load_or_create_edr_receipt_signer_with_requirement(
    require_enrolled_signer: bool,
) -> Result<(Keypair, String)> {
    if let Some(key_hex) = crate::enrollment::load_enrollment_key_hex()
        .with_context(|| "load enrollment key for endpoint receipt signer")?
    {
        let keypair = Keypair::from_hex(key_hex.trim())
            .with_context(|| "parse enrollment key for endpoint receipt signer")?;
        let signer_identity = format!("agent-enrollment:{}", keypair.public_key().to_hex());
        return Ok((keypair, signer_identity));
    }

    if require_enrolled_signer {
        anyhow::bail!(
            "endpoint receipt signer requires an enrolled agent key; refusing local EDR signer fallback"
        );
    }

    let path = default_edr_receipt_signing_key_path();
    if path.exists() {
        let key_hex = fs::read_to_string(&path)
            .with_context(|| format!("read endpoint receipt signing key {}", path.display()))?;
        let keypair = Keypair::from_hex(key_hex.trim())
            .with_context(|| "parse endpoint receipt signing key")?;
        let signer_identity = format!("local-edr:{}", keypair.public_key().to_hex());
        return Ok((keypair, signer_identity));
    }

    let keypair = Keypair::generate();
    crate::security::fs::write_private_atomic(
        &path,
        format!("{}\n", keypair.to_hex()).as_bytes(),
        "endpoint receipt signing key",
    )?;
    let signer_identity = format!("local-edr:{}", keypair.public_key().to_hex());
    Ok((keypair, signer_identity))
}
