//! Shared response lifecycle receipt validators used by execution,
//! rollback, and acknowledgement contract checks.

use super::super::*;

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
