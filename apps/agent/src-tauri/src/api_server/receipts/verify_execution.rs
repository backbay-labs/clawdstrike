//! Response execution proof contract verifiers.
//!
//! Validates that a set of receipts (request, execution, evidence bundle,
//! transitions, rollbacks, acknowledgements) collectively prove the
//! semantics of a stored `EndpointResponseExecutionReport`.

use super::super::*;

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
