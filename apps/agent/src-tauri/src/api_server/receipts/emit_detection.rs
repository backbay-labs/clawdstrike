//! Detection, observation, sensor-state, telemetry-privacy, and provider
//! degradation receipt emission helpers.

use super::super::*;

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
