//! Receipt emission helpers for response request, execution, rollback,
//! acknowledgement, and evidence bundle manifest events.

use super::super::*;

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
