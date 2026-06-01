use super::super::*;

pub(crate) fn require_response_request_receipt_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
    root_node_id: &str,
    graph_slice_id: &str,
    graph_content_hash: Option<&str>,
    ttl_seconds: u64,
    rollback_ref: &str,
) -> Result<()> {
    let dry_run = response_request_dry_run_from_decision(decision)?;
    let response_action_id = decision
        .finding_id
        .as_deref()
        .ok_or_else(|| anyhow!("response action id is required"))?;
    require_response_action_id_matches_signed_response_fields(
        response_action_id,
        root_node_id,
        graph_slice_id,
        &decision.action,
        ttl_seconds,
        if dry_run { "dry_run" } else { "execute" },
    )?;
    let expected_rollback_ref =
        expected_response_rollback_ref(&decision.action, dry_run, response_action_id);
    if rollback_ref != expected_rollback_ref {
        return Err(anyhow!(
            "response rollback evidence hash must match signed response action fields"
        ));
    }
    require_response_receipt_evidence_fields(
        evidence,
        response_action_id,
        root_node_id,
        graph_slice_id,
        graph_content_hash,
        ttl_seconds,
        rollback_ref,
    )
}

pub(crate) fn require_response_request_dry_run_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let expected_dry_run = if response_request_dry_run_from_decision(decision)? {
        "true"
    } else {
        "false"
    };
    require_evidence_value_hash(
        evidence,
        "dryRun",
        expected_dry_run,
        "response dry-run evidence",
    )
}

pub(crate) fn response_request_dry_run_from_decision(
    decision: &EndpointDecisionRecord,
) -> Result<bool> {
    let title = decision
        .title
        .as_deref()
        .ok_or_else(|| anyhow!("response request title is required"))?;
    match title {
        "Endpoint response action dry run planned" => Ok(true),
        "Endpoint response action planned" => Ok(false),
        _ => Err(anyhow!("response request title is invalid")),
    }
}
