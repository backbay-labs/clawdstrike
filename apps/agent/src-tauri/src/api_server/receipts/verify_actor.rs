//! Actor-continuity proof contract verifiers — ensure the same actor
//! identity is present and hash-bound across all response receipts for an
//! execution.

use super::super::*;

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
