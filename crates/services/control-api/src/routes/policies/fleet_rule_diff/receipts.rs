//! Fleet rule-diff acknowledgement-receipt collection and impact validation.

use crate::routes::policies::*;

pub(crate) async fn collect_policy_rule_diff_ack_receipts(
    db: &PgPool,
    tenant_id: Uuid,
    proposal_id: Uuid,
    validation_plan_sha256: Option<&str>,
    expected_proposed_policy_sha256: &str,
    expected_proposed_policy_epoch: u64,
    response_action_ids: &[Uuid],
) -> Result<Vec<CollectedPolicyRuleDiffReceipt>, ApiError> {
    let rows = sqlx::query::query(
        r#"SELECT ack.action_id,
                  ack.target_id,
                  ack.observed_at,
                  ack.raw_payload,
                  agents.public_key
           FROM response_action_acks ack
           JOIN response_actions action
             ON action.tenant_id = ack.tenant_id
            AND action.id = ack.action_id
           JOIN agents
             ON agents.tenant_id = ack.tenant_id
            AND agents.agent_id = ack.target_id
           WHERE ack.tenant_id = $1
             AND ack.action_id = ANY($2)
             AND ack.status = 'acknowledged'
             AND action.action_type = 'policy_rule_diff_validation'
           ORDER BY ack.observed_at ASC, ack.id ASC"#,
    )
    .bind(tenant_id)
    .bind(response_action_ids)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    let mut collected = Vec::with_capacity(rows.len());
    for row in rows {
        let response_action_id: Uuid = row.try_get("action_id").map_err(ApiError::Database)?;
        let endpoint_agent_id: String = row.try_get("target_id").map_err(ApiError::Database)?;
        let observed_at: DateTime<Utc> = row.try_get("observed_at").map_err(ApiError::Database)?;
        let raw_payload: serde_json::Value =
            row.try_get("raw_payload").map_err(ApiError::Database)?;
        let public_key: String = row.try_get("public_key").map_err(ApiError::Database)?;
        let payload = policy_rule_diff_payload(&raw_payload)?;
        validate_policy_rule_diff_payload_correlation(
            payload,
            proposal_id,
            validation_plan_sha256,
            &endpoint_agent_id,
        )?;
        let receipt = payload.get("receipt").cloned().ok_or_else(|| {
            ApiError::BadRequest(
                "policyRuleDiffValidation acknowledgement must include receipt".to_string(),
            )
        })?;
        let impact = payload.get("impact").cloned().ok_or_else(|| {
            ApiError::BadRequest(
                "policyRuleDiffValidation acknowledgement must include impact".to_string(),
            )
        })?;
        let verified =
            validate_policy_proposal_simulation_receipt_value(receipt.clone(), public_key.clone())?;
        let receipt_endpoint_id = verified.endpoint_id.as_deref().ok_or_else(|| {
            ApiError::BadRequest(
                "policyRuleDiffValidation receipt must include endpointId".to_string(),
            )
        })?;
        if receipt_endpoint_id != endpoint_agent_id {
            return Err(ApiError::BadRequest(
                "policyRuleDiffValidation receipt endpointId must match the response-action target"
                    .to_string(),
            ));
        }
        validate_policy_rule_diff_impact_against_receipt(
            &impact,
            &verified,
            expected_proposed_policy_sha256,
            expected_proposed_policy_epoch,
        )?;
        collected.push(CollectedPolicyRuleDiffReceipt {
            response_action_id,
            endpoint_agent_id,
            observed_at,
            impact,
            receipt,
            public_key,
        });
    }
    Ok(latest_policy_rule_diff_receipts_by_endpoint(collected))
}

pub(crate) fn policy_rule_diff_payload(
    raw_payload: &serde_json::Value,
) -> Result<&serde_json::Value, ApiError> {
    raw_payload
        .get("policyRuleDiffValidation")
        .or_else(|| raw_payload.get("policy_rule_diff_validation"))
        .ok_or_else(|| {
            ApiError::BadRequest(
                "acknowledgement raw_payload must include policyRuleDiffValidation".to_string(),
            )
        })
}

pub(crate) fn validate_policy_rule_diff_payload_correlation(
    payload: &serde_json::Value,
    proposal_id: Uuid,
    validation_plan_sha256: Option<&str>,
    endpoint_agent_id: &str,
) -> Result<(), ApiError> {
    let payload_proposal_id = payload
        .get("proposalId")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ApiError::BadRequest(
                "policyRuleDiffValidation acknowledgement must include proposalId".to_string(),
            )
        })?;
    if payload_proposal_id != proposal_id.to_string() {
        return Err(ApiError::BadRequest(
            "policyRuleDiffValidation proposalId does not match the policy proposal".to_string(),
        ));
    }
    if let Some(expected_plan_sha256) = validation_plan_sha256 {
        let payload_plan_sha256 = payload
            .get("validationPlanSha256")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ApiError::BadRequest(
                    "policyRuleDiffValidation acknowledgement must include validationPlanSha256"
                        .to_string(),
                )
            })?;
        if payload_plan_sha256 != expected_plan_sha256 {
            return Err(ApiError::BadRequest(
                "policyRuleDiffValidation validationPlanSha256 does not match the proposal plan"
                    .to_string(),
            ));
        }
    }
    let payload_endpoint_agent_id = payload
        .get("endpointAgentId")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ApiError::BadRequest(
                "policyRuleDiffValidation acknowledgement must include endpointAgentId".to_string(),
            )
        })?;
    if payload_endpoint_agent_id != endpoint_agent_id {
        return Err(ApiError::BadRequest(
            "policyRuleDiffValidation endpointAgentId does not match the response-action target"
                .to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_policy_rule_diff_impact_against_receipt(
    impact: &serde_json::Value,
    verified: &VerifiedPolicyProposalSimulationReceipt,
    expected_proposed_policy_sha256: &str,
    expected_proposed_policy_epoch: u64,
) -> Result<(), ApiError> {
    if let (Some(receipt_impact_id), Some(impact_id)) = (
        verified.impact_id.as_deref(),
        impact.get("impactId").and_then(serde_json::Value::as_str),
    ) {
        if receipt_impact_id != impact_id {
            return Err(ApiError::BadRequest(
                "policyRuleDiffValidation impactId must match the signed receipt findingId"
                    .to_string(),
            ));
        }
    }

    for key in [
        "impactId",
        "eventStreamHash",
        "currentResultHash",
        "proposedResultHash",
        "impactHash",
        "proposedPolicyHash",
        "proposedPolicyEpoch",
        "eventCount",
        "changedCount",
        "allowToBlockCount",
        "trackPosture",
    ] {
        let raw_value = policy_rule_diff_impact_evidence_value(impact, key)?;
        let expected_hash = sha256(raw_value.as_bytes()).to_hex_prefixed();
        let actual_hash = verified.evidence_value_hashes.get(key).ok_or_else(|| {
            ApiError::BadRequest(format!(
                "policyRuleDiffValidation receipt evidence is missing {key}"
            ))
        })?;
        if actual_hash != &expected_hash {
            return Err(ApiError::BadRequest(format!(
                "policyRuleDiffValidation impact {key} does not match signed receipt evidence"
            )));
        }
    }
    let proposed_policy_hash = impact
        .pointer("/proposedPolicy/policyHash")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ApiError::BadRequest(
                "policyRuleDiffValidation impact must include proposedPolicy.policyHash"
                    .to_string(),
            )
        })?;
    let proposed_policy_hash =
        normalize_policy_impact_sha256("proposedPolicy.policyHash", proposed_policy_hash)?;
    let expected_proposed_policy_sha256 = normalize_policy_impact_sha256(
        "policy proposal proposedPolicy.policyHash",
        expected_proposed_policy_sha256,
    )?;
    if proposed_policy_hash != expected_proposed_policy_sha256 {
        return Err(ApiError::BadRequest(
            "policyRuleDiffValidation proposedPolicy.policyHash does not match the policy proposal"
                .to_string(),
        ));
    }
    let proposed_policy_epoch = impact
        .pointer("/proposedPolicy/policyEpoch")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            ApiError::BadRequest(
                "policyRuleDiffValidation impact must include proposedPolicy.policyEpoch"
                    .to_string(),
            )
        })?;
    if proposed_policy_epoch != expected_proposed_policy_epoch {
        return Err(ApiError::BadRequest(
            "policyRuleDiffValidation proposedPolicy.policyEpoch does not match the policy proposal"
                .to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn policy_rule_diff_impact_evidence_value(
    impact: &serde_json::Value,
    key: &str,
) -> Result<String, ApiError> {
    match key {
        "proposedPolicyHash" => impact
            .pointer("/proposedPolicy/policyHash")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        "proposedPolicyEpoch" => impact
            .pointer("/proposedPolicy/policyEpoch")
            .and_then(serde_json::Value::as_u64)
            .map(|value| value.to_string()),
        "eventCount" | "changedCount" | "allowToBlockCount" => impact
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .map(|value| value.to_string()),
        "trackPosture" => impact
            .get(key)
            .and_then(serde_json::Value::as_bool)
            .map(|value| value.to_string()),
        _ => impact
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
    }
    .ok_or_else(|| {
        ApiError::BadRequest(format!(
            "policyRuleDiffValidation impact must include evidence field {key}"
        ))
    })
}

pub(crate) fn build_collected_policy_rule_diff_impact_request(
    collected: &[CollectedPolicyRuleDiffReceipt],
    validation_plan_sha256: Option<&str>,
) -> Result<AttachPolicyProposalImpactRequest, ApiError> {
    let event_count = collected.iter().try_fold(0u64, |total, receipt| {
        Ok::<_, ApiError>(total.saturating_add(required_policy_rule_diff_impact_u64(
            &receipt.impact,
            "eventCount",
        )?))
    })?;
    let changed_count = collected.iter().try_fold(0u64, |total, receipt| {
        Ok::<_, ApiError>(total.saturating_add(required_policy_rule_diff_impact_u64(
            &receipt.impact,
            "changedCount",
        )?))
    })?;
    let allow_to_block_count = collected.iter().try_fold(0u64, |total, receipt| {
        Ok::<_, ApiError>(total.saturating_add(required_policy_rule_diff_impact_u64(
            &receipt.impact,
            "allowToBlockCount",
        )?))
    })?;
    let endpoint_count = collected
        .iter()
        .map(|receipt| receipt.endpoint_agent_id.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let developer_breakage_score = if event_count == 0 {
        0.0
    } else {
        ((changed_count as f64 / event_count as f64) * 100.0).clamp(0.0, 100.0)
    };
    let recommendation = if allow_to_block_count > 0 {
        "revise"
    } else if changed_count > 0 {
        "observe_only"
    } else {
        "approve"
    };
    let summary = format!(
        "Collected {} signed endpoint rule-diff validation receipt(s) across {} endpoint(s); {} of {} replayed event(s) changed verdict and {} changed from allow to block.",
        collected.len(),
        endpoint_count,
        changed_count,
        event_count,
        allow_to_block_count
    );
    let proof_hashes = validation_plan_sha256
        .map(|hash| vec![hash.to_string()])
        .unwrap_or_default();

    let mut attachments = collected
        .iter()
        .map(|receipt| PolicyProposalSimulationReceiptAttachment {
            receipt_id: receipt
                .receipt
                .pointer("/receipt/receipt_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            receipt_sha256: None,
            receipt: receipt.receipt.clone(),
            public_key: receipt.public_key.clone(),
        })
        .collect::<Vec<_>>();
    attachments.sort_by(|left, right| left.receipt_id.as_deref().cmp(&right.receipt_id.as_deref()));

    Ok(AttachPolicyProposalImpactRequest {
        source: "fleet_history".to_string(),
        summary,
        simulation_receipt_id: None,
        simulation_receipt_sha256: None,
        simulation_receipt: None,
        simulation_receipt_public_key: None,
        simulation_receipts: attachments,
        changed_verdict_count: changed_count.min(i64::MAX as u64) as i64,
        blocking_change_count: allow_to_block_count.min(i64::MAX as u64) as i64,
        developer_breakage_score,
        affected_identity_count: endpoint_count.min(i64::MAX as usize) as i64,
        affected_tool_count: collected.len().min(i64::MAX as usize) as i64,
        recommendation: recommendation.to_string(),
        proof_hashes,
    })
}

pub(crate) fn required_policy_rule_diff_impact_u64(
    impact: &serde_json::Value,
    field: &str,
) -> Result<u64, ApiError> {
    impact
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            ApiError::BadRequest(format!(
                "policyRuleDiffValidation impact must include numeric {field}"
            ))
        })
}
