//! Policy-decision receipt emission, including provider-sourced policy
//! decision receipts and their construction helpers.

use super::super::*;

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
