//! Lifecycle receipt lookup: scan the receipt ledger for transition,
//! rollback, and acknowledgement receipts associated with a given response
//! execution, plus the latest required receipt lookups used by proof
//! validation routes.

use super::super::*;

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
