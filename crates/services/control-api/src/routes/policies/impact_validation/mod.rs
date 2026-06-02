//! Proposal impact validation and deployability checks.

use super::*;

mod simulation_receipt;

pub(crate) use simulation_receipt::*;

pub(crate) async fn attach_policy_proposal_impact(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(req): Json<AttachPolicyProposalImpactRequest>,
) -> Result<Json<PolicyProposalResponse>, ApiError> {
    ensure_policy_author(&auth)?;

    let proposal = fetch_policy_proposal_row(&state, auth.tenant_id, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if proposal.status != "pending" {
        return Err(ApiError::NotFound);
    }
    let impact = validate_policy_proposal_impact(req)?;
    validate_policy_proposal_impact_matches_proposal(&proposal, &impact)?;
    let attached_by = auth.actor_id();
    let row = sqlx::query::query(
        r#"UPDATE policy_proposals
           SET impact = $3,
               impact_attached_by = $4,
               impact_attached_at = now(),
               updated_at = now()
           WHERE tenant_id = $1
             AND id = $2
             AND status = 'pending'
           RETURNING *"#,
    )
    .bind(auth.tenant_id)
    .bind(id)
    .bind(&impact)
    .bind(&attached_by)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

    Ok(Json(proposal_response_from_row(row, &auth.slug)?))
}

pub(crate) fn ensure_policy_proposal_deployable_impact(
    proposal: &PolicyProposalRow,
) -> Result<(), ApiError> {
    let Some(impact) = proposal.impact.as_ref() else {
        return Err(ApiError::Conflict(format!(
            "policy proposal {} requires verified simulation impact before deployment",
            proposal.id
        )));
    };
    let verified_receipt_count = impact
        .get("simulationReceiptsVerifiedCount")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    if verified_receipt_count == 0 {
        return Err(ApiError::Conflict(format!(
            "policy proposal {} requires at least one verified simulation receipt before deployment",
            proposal.id
        )));
    }
    let recommendation = impact
        .get("recommendation")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if matches!(recommendation, "revise" | "reject") {
        return Err(ApiError::Conflict(format!(
            "policy proposal {} cannot deploy while verified simulation impact recommends {recommendation}",
            proposal.id
        )));
    }
    let blocking_change_count = impact
        .get("blockingChangeCount")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    if blocking_change_count > 0 {
        return Err(ApiError::Conflict(format!(
            "policy proposal {} cannot deploy with {blocking_change_count} verified blocking simulation change(s)",
            proposal.id
        )));
    }
    Ok(())
}

pub(crate) fn validate_policy_proposal_impact_matches_proposal(
    proposal: &PolicyProposalRow,
    impact: &serde_json::Value,
) -> Result<(), ApiError> {
    let Some(receipts) = impact
        .get("simulationReceipts")
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(());
    };
    if receipts.is_empty() {
        return Ok(());
    }

    let expected_policy_hash = sha256(proposal.checksum_sha256.as_bytes()).to_hex_prefixed();
    let expected_policy_epoch =
        sha256(proposal.proposed_policy_version.to_string().as_bytes()).to_hex_prefixed();

    for receipt in receipts {
        let proposed_policy_hash =
            policy_proposal_receipt_evidence_hash(receipt, "proposedPolicyHash").ok_or_else(
                || {
                    ApiError::BadRequest(
                        "simulation_receipt evidence must include proposedPolicyHash".to_string(),
                    )
                },
            )?;
        if !proposed_policy_hash.eq_ignore_ascii_case(&expected_policy_hash) {
            return Err(ApiError::BadRequest(
                "simulation_receipt proposedPolicyHash must match the policy proposal".to_string(),
            ));
        }

        let proposed_policy_epoch =
            policy_proposal_receipt_evidence_hash(receipt, "proposedPolicyEpoch").ok_or_else(
                || {
                    ApiError::BadRequest(
                        "simulation_receipt evidence must include proposedPolicyEpoch".to_string(),
                    )
                },
            )?;
        if !proposed_policy_epoch.eq_ignore_ascii_case(&expected_policy_epoch) {
            return Err(ApiError::BadRequest(
                "simulation_receipt proposedPolicyEpoch must match the policy proposal".to_string(),
            ));
        }
    }

    Ok(())
}

pub(crate) fn policy_proposal_receipt_evidence_hash<'a>(
    receipt: &'a serde_json::Value,
    key: &str,
) -> Option<&'a str> {
    if let Some(hash) = receipt
        .get("evidenceValueHashes")
        .and_then(serde_json::Value::as_object)
        .and_then(|hashes| hashes.get(key))
        .and_then(serde_json::Value::as_str)
    {
        return Some(hash);
    }

    let evidence = receipt
        .pointer("/signedReceipt/receipt/metadata/endpointDecision/evidence")
        .or_else(|| receipt.pointer("/receipt/metadata/endpointDecision/evidence"))?
        .as_array()?;
    evidence.iter().find_map(|item| {
        let item_key = item.get("key").and_then(serde_json::Value::as_str)?;
        if item_key == key {
            item.get("valueHash").and_then(serde_json::Value::as_str)
        } else {
            None
        }
    })
}

pub(crate) fn validate_policy_proposal_impact(
    req: AttachPolicyProposalImpactRequest,
) -> Result<serde_json::Value, ApiError> {
    let source = require_non_empty_policy_impact_field("source", req.source)?;
    if !matches!(
        source.as_str(),
        "local_history" | "fleet_history" | "manual_review"
    ) {
        return Err(ApiError::BadRequest(
            "impact source must be one of: local_history, fleet_history, manual_review".to_string(),
        ));
    }

    let summary = require_non_empty_policy_impact_field("summary", req.summary)?;
    let recommendation =
        require_non_empty_policy_impact_field("recommendation", req.recommendation)?;
    if !matches!(
        recommendation.as_str(),
        "approve" | "revise" | "reject" | "observe_only"
    ) {
        return Err(ApiError::BadRequest(
            "impact recommendation must be one of: approve, revise, reject, observe_only"
                .to_string(),
        ));
    }

    validate_non_negative_policy_impact_count("changed_verdict_count", req.changed_verdict_count)?;
    validate_non_negative_policy_impact_count("blocking_change_count", req.blocking_change_count)?;
    validate_non_negative_policy_impact_count(
        "affected_identity_count",
        req.affected_identity_count,
    )?;
    validate_non_negative_policy_impact_count("affected_tool_count", req.affected_tool_count)?;
    if !req.developer_breakage_score.is_finite()
        || !(0.0..=100.0).contains(&req.developer_breakage_score)
    {
        return Err(ApiError::BadRequest(
            "developer_breakage_score must be a finite value from 0 through 100".to_string(),
        ));
    }

    let simulation_receipt_id = req
        .simulation_receipt_id
        .map(|value| require_non_empty_policy_impact_field("simulation_receipt_id", value))
        .transpose()?;
    let verified_simulation_receipt = validate_policy_proposal_simulation_receipt(
        req.simulation_receipt,
        req.simulation_receipt_public_key,
    )?;
    let verified_batch_simulation_receipts =
        validate_policy_proposal_simulation_receipt_attachments(req.simulation_receipts)?;
    let provided_simulation_receipt_sha256 = req
        .simulation_receipt_sha256
        .map(|value| normalize_policy_impact_sha256("simulation_receipt_sha256", &value))
        .transpose()?;
    let simulation_receipt_sha256 = match (
        provided_simulation_receipt_sha256,
        verified_simulation_receipt.as_ref(),
    ) {
        (Some(provided), Some(verified)) if provided != verified.signed_receipt_sha256 => {
            return Err(ApiError::BadRequest(
                "simulation_receipt_sha256 must match the canonical signed receipt hash"
                    .to_string(),
            ));
        }
        (Some(provided), _) => Some(provided),
        (None, Some(verified)) => Some(verified.signed_receipt_sha256.clone()),
        (None, None) => None,
    };

    if let (Some(provided_receipt_id), Some(verified)) = (
        simulation_receipt_id.as_deref(),
        verified_simulation_receipt.as_ref(),
    ) {
        if let Some(verified_receipt_id) = verified.receipt_id.as_deref() {
            if provided_receipt_id != verified_receipt_id {
                return Err(ApiError::BadRequest(
                    "simulation_receipt_id must match the signed receipt receipt_id".to_string(),
                ));
            }
        }
    }

    validate_unique_policy_proposal_simulation_receipts(
        verified_simulation_receipt.as_ref(),
        &verified_batch_simulation_receipts,
    )?;

    let proof_hashes = req
        .proof_hashes
        .into_iter()
        .map(|hash| normalize_policy_impact_sha256("proof_hashes", &hash))
        .collect::<Result<Vec<_>, _>>()?;

    if simulation_receipt_sha256.is_none()
        && verified_batch_simulation_receipts.is_empty()
        && proof_hashes.is_empty()
    {
        return Err(ApiError::BadRequest(
            "impact evidence must include simulation_receipt_sha256, simulation_receipts, or at least one proof_hashes entry"
                .to_string(),
        ));
    }

    let simulation_receipt_summaries = policy_proposal_simulation_receipt_summaries(
        &verified_simulation_receipt,
        &verified_batch_simulation_receipts,
    );
    let simulation_receipt_endpoint_ids =
        distinct_policy_proposal_receipt_values(simulation_receipt_summaries.iter(), "endpointId");
    let simulation_receipt_signed_sha256s = simulation_receipt_summaries
        .iter()
        .filter_map(|receipt| receipt.get("signedReceiptSha256"))
        .filter_map(serde_json::Value::as_str)
        .map(str::to_string)
        .collect::<Vec<_>>();

    let mut impact = serde_json::json!({
        "schemaVersion": 1,
        "source": source,
        "summary": summary,
        "simulationReceiptId": simulation_receipt_id,
        "simulationReceiptSha256": simulation_receipt_sha256,
        "changedVerdictCount": req.changed_verdict_count,
        "blockingChangeCount": req.blocking_change_count,
        "developerBreakageScore": req.developer_breakage_score,
        "affectedIdentityCount": req.affected_identity_count,
        "affectedToolCount": req.affected_tool_count,
        "recommendation": recommendation,
        "proofHashes": proof_hashes,
        "simulationReceiptsVerifiedCount": simulation_receipt_summaries.len(),
        "simulationReceiptSignedSha256s": simulation_receipt_signed_sha256s,
        "simulationReceiptDistinctEndpointCount": simulation_receipt_endpoint_ids.len(),
        "simulationReceiptEndpointIds": simulation_receipt_endpoint_ids,
        "simulationReceipts": simulation_receipt_summaries,
    });

    if let Some(verified) = verified_simulation_receipt {
        impact["simulationReceiptVerified"] = serde_json::json!(true);
        impact["simulationReceiptSignedSha256"] = serde_json::json!(verified.signed_receipt_sha256);
        impact["simulationReceiptPublicKey"] = serde_json::json!(verified.public_key);
        impact["simulationReceiptFamily"] =
            serde_json::json!(POLICY_PROPOSAL_SIMULATION_RECEIPT_FAMILY);
        impact["simulationReceiptRuleId"] = serde_json::json!(POLICY_PROPOSAL_SIMULATION_RULE_ID);
        impact["simulationReceiptEndpointId"] = serde_json::json!(verified.endpoint_id);
        impact["simulationReceiptPolicyEpoch"] = serde_json::json!(verified.policy_epoch);
        impact["simulationReceiptImpactId"] = serde_json::json!(verified.impact_id);
        impact["simulationReceiptGraphSliceId"] = serde_json::json!(verified.graph_slice_id);
        impact["simulationReceiptEvidenceKeys"] = serde_json::json!(verified.evidence_keys);
        impact["simulationReceipt"] = verified.signed_receipt;
    }

    Ok(impact)
}
