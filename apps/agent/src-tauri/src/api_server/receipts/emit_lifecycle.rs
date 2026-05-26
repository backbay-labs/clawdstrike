//! Receipt emission helpers for causal graph slices, policy simulations,
//! and policy event replay/impact reports.

use super::super::*;

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
