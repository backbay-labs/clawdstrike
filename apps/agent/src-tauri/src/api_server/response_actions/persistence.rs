//! Ledger persistence and receipt-emission helpers for response executions.
//!
//! These functions append execution and rollback reports to the response
//! execution ledger, durably record the matching signed receipts, and produce
//! stable IDs for synthetic transition entries (partial, rollback pending,
//! rollback failed) used by the live executor.

use super::*;

pub(crate) async fn persist_edr_response_execution(
    state: &AgentApiState,
    execution: EndpointResponseExecutionReport,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
) -> Result<
    (
        EndpointResponseExecutionReport,
        StoredEndpointEvidenceBundle,
        SignedReceipt,
        SignedReceipt,
    ),
    (StatusCode, String),
> {
    persist_edr_response_execution_with_evidence(state, execution, graph, actor, &[]).await
}

pub(crate) async fn emit_pre_effect_response_execution_receipt(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
    phase: &str,
) -> Result<SignedReceipt, (StatusCode, String)> {
    let mut prepared = execution.clone();
    prepared.status = EndpointResponseExecutionStatus::Partial;
    prepared.completed_at = chrono::Utc::now();
    prepared.summary = format!(
        "Durably recorded {} response execution intent before local side effects.",
        execution.action.as_str()
    );
    let reason_hash = sha256(prepared.reason.as_bytes()).to_hex_prefixed();
    prepared.execution_id = response_execution_transition_id(
        "response_execution_partial",
        prepared.action_id.as_str(),
        prepared.evidence_bundle.bundle_id.as_str(),
        prepared.rollback_ref.as_str(),
        reason_hash.as_str(),
    );
    let evidence = [EndpointReceiptEvidence::hashed("executionPhase", phase)];
    state
        .edr_response_execution_ledger
        .lock()
        .await
        .append(&prepared)
        .map_err(internal_error)?;
    emit_edr_response_execution_receipt(state, &prepared, graph, Some(actor), &evidence)
        .await
        .map_err(internal_error)
}

pub(crate) async fn record_edr_response_rollback_intent(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    reason: &str,
    graph: &CausalGraph,
) -> Result<(EndpointResponseExecutionReport, SignedReceipt), (StatusCode, String)> {
    let pending = EndpointResponseExecutionReport::rollback_pending_from(
        execution,
        reason,
        chrono::Utc::now(),
    );
    {
        let mut ledger = state.edr_response_execution_ledger.lock().await;
        ledger.append(&pending).map_err(internal_error)?;
    }
    let receipt = emit_edr_response_execution_receipt(
        state,
        &pending,
        graph,
        pending.actor.clone(),
        &[EndpointReceiptEvidence::hashed(
            "rollbackIntentForExecutionId",
            execution.execution_id.as_str(),
        )],
    )
    .await
    .map_err(internal_error)?;
    Ok((pending, receipt))
}

pub(crate) async fn record_edr_response_rollback_failure(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    reason: &str,
    failure: &str,
    graph: &CausalGraph,
) -> Result<(EndpointResponseExecutionReport, SignedReceipt), (StatusCode, String)> {
    let failed = EndpointResponseExecutionReport::rollback_failed_from(
        execution,
        reason,
        failure,
        chrono::Utc::now(),
    );
    {
        let mut ledger = state.edr_response_execution_ledger.lock().await;
        ledger.append(&failed).map_err(internal_error)?;
    }
    let receipt = emit_edr_response_execution_receipt(
        state,
        &failed,
        graph,
        failed.actor.clone(),
        &[EndpointReceiptEvidence::hashed(
            "rollbackFailureForExecutionId",
            execution.execution_id.as_str(),
        )],
    )
    .await
    .map_err(internal_error)?;
    Ok((failed, receipt))
}

pub(super) fn response_execution_transition_id(
    prefix: &str,
    response_action_id: &str,
    evidence_bundle_id: &str,
    rollback_ref: &str,
    reason_hash: &str,
) -> String {
    edr_fnv_stable_id(
        prefix,
        [
            response_action_id,
            evidence_bundle_id,
            rollback_ref,
            reason_hash,
        ],
    )
}

fn edr_fnv_stable_id<'a>(prefix: &str, parts: impl IntoIterator<Item = &'a str>) -> String {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = FNV_OFFSET;
    for part in parts {
        for byte in part.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("{prefix}:{hash:016x}")
}

pub(crate) async fn persist_edr_response_execution_with_evidence(
    state: &AgentApiState,
    mut execution: EndpointResponseExecutionReport,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
    additional_evidence: &[EndpointReceiptEvidence],
) -> Result<
    (
        EndpointResponseExecutionReport,
        StoredEndpointEvidenceBundle,
        SignedReceipt,
        SignedReceipt,
    ),
    (StatusCode, String),
> {
    execution.actor = Some(actor.clone());
    let stored_bundle = state
        .edr_evidence_bundle_store
        .lock()
        .await
        .store(&execution.evidence_bundle, graph)
        .map_err(internal_error)?;
    let (execution_receipt, evidence_bundle_receipt) = append_and_receipt_edr_response_execution(
        state,
        &execution,
        graph,
        Some(actor),
        additional_evidence,
    )
    .await?;
    Ok((
        execution,
        stored_bundle,
        execution_receipt,
        evidence_bundle_receipt,
    ))
}

pub(crate) async fn append_and_receipt_edr_response_execution(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    graph: &CausalGraph,
    actor: Option<EndpointDecisionActor>,
    additional_evidence: &[EndpointReceiptEvidence],
) -> Result<(SignedReceipt, SignedReceipt), (StatusCode, String)> {
    state
        .edr_response_execution_ledger
        .lock()
        .await
        .append(execution)
        .map_err(internal_error)?;
    let receipt =
        emit_edr_response_execution_receipt(state, execution, graph, actor, additional_evidence)
            .await
            .map_err(internal_error)?;
    let bundle_receipt = emit_edr_evidence_bundle_manifest_receipt(state, execution, graph)
        .await
        .map_err(internal_error)?;
    Ok((receipt, bundle_receipt))
}

pub(crate) async fn append_edr_response_acknowledgement(
    state: &AgentApiState,
    acknowledgement: &EndpointResponseAcknowledgementReport,
) -> Result<Option<String>, (StatusCode, String)> {
    let mut ledger = state.edr_response_acknowledgement_ledger.lock().await;
    let path = ledger.path().map(|path| path.display().to_string());
    ledger.append(acknowledgement).map_err(internal_error)?;
    Ok(path)
}
