//! Receipt emission helpers for deception artifact materialization,
//! cleanup, and rotation lifecycle events.

use super::super::*;

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
