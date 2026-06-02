//! Policy-rule-diff acknowledgement receipt and error-payload validation.

use crate::routes::response_actions::*;
pub(crate) async fn validate_policy_rule_diff_ack_receipt(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    context: &AckContext,
    ack: &AckSubmission,
) -> Result<(), ApiError> {
    validate_policy_rule_diff_ack_payload(ack)?;
    if !matches!(ack.ack_status, "acknowledged") {
        return Ok(());
    }

    let payload = policy_rule_diff_ack_payload_value(ack)?;
    let signed_receipt_value = payload.get("receipt").cloned().ok_or_else(|| {
        ApiError::BadRequest(
            "policyRuleDiffValidation acknowledgement must include receipt".to_string(),
        )
    })?;
    validate_policy_rule_diff_ack_matches_action_payload(
        payload,
        &context.action.payload,
        &ack.target_id,
    )?;
    let public_key =
        load_endpoint_ack_public_key(tx, context.action.tenant_id, &ack.target_id).await?;
    let verified = verify_endpoint_decision_signed_receipt_value(
        signed_receipt_value,
        &public_key,
        "policyRuleDiffValidation receipt",
    )?;

    if verified.endpoint_decision.receipt_family != EndpointDecisionReceiptFamily::Simulation {
        return Err(ApiError::BadRequest(
            "policyRuleDiffValidation receipt endpointDecision.receiptFamily must be simulation"
                .to_string(),
        ));
    }
    if verified.endpoint_decision.decision.rule_id.as_deref()
        != Some("endpoint.policy_event_impact")
    {
        return Err(ApiError::BadRequest(
            "policyRuleDiffValidation receipt endpointDecision.decision.ruleId must be endpoint.policy_event_impact"
                .to_string(),
        ));
    }
    if verified.endpoint_decision.actor.endpoint_id != ack.target_id {
        return Err(ApiError::BadRequest(
            "policyRuleDiffValidation receipt endpoint id must match target_id".to_string(),
        ));
    }

    let impact_id = payload
        .pointer("/impact/impactId")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ApiError::BadRequest(
                "policyRuleDiffValidation impact must include impactId".to_string(),
            )
        })?;
    let receipt_impact_id = verified
        .endpoint_decision
        .decision
        .finding_id
        .as_deref()
        .ok_or_else(|| {
            ApiError::BadRequest(
                "policyRuleDiffValidation receipt endpointDecision.decision.findingId is required"
                    .to_string(),
            )
        })?;
    if impact_id != receipt_impact_id {
        return Err(ApiError::BadRequest(
            "policyRuleDiffValidation impactId must match the signed receipt findingId".to_string(),
        ));
    }
    validate_policy_rule_diff_ack_impact_evidence(payload, &verified)
}

pub(crate) fn validate_policy_rule_diff_ack_matches_action_payload(
    payload: &Value,
    action_payload: &Value,
    target_id: &str,
) -> Result<(), ApiError> {
    if let Some(expected_proposal_id) = action_payload.get("proposalId").and_then(Value::as_str) {
        let actual_proposal_id = payload
            .get("proposalId")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ApiError::BadRequest(
                    "policyRuleDiffValidation acknowledgement must include proposalId".to_string(),
                )
            })?;
        if actual_proposal_id != expected_proposal_id {
            return Err(ApiError::BadRequest(
                "policyRuleDiffValidation proposalId does not match the dispatched response action"
                    .to_string(),
            ));
        }
    }

    if let Some(expected_plan_sha256) = action_payload
        .get("validationPlanSha256")
        .and_then(Value::as_str)
    {
        let actual_plan_sha256 = payload
            .get("validationPlanSha256")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ApiError::BadRequest(
                    "policyRuleDiffValidation acknowledgement must include validationPlanSha256"
                        .to_string(),
                )
            })?;
        if actual_plan_sha256 != expected_plan_sha256 {
            return Err(ApiError::BadRequest(
                "policyRuleDiffValidation validationPlanSha256 does not match the dispatched response action"
                    .to_string(),
            ));
        }
    }

    let actual_endpoint_agent_id = payload
        .get("endpointAgentId")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ApiError::BadRequest(
                "policyRuleDiffValidation acknowledgement must include endpointAgentId".to_string(),
            )
        })?;
    if actual_endpoint_agent_id != target_id {
        return Err(ApiError::BadRequest(
            "policyRuleDiffValidation endpointAgentId does not match target_id".to_string(),
        ));
    }
    if let Some(expected_endpoint_agent_id) = action_payload
        .get("endpointAgentId")
        .and_then(Value::as_str)
    {
        if actual_endpoint_agent_id != expected_endpoint_agent_id {
            return Err(ApiError::BadRequest(
                "policyRuleDiffValidation endpointAgentId does not match the dispatched response action"
                    .to_string(),
            ));
        }
    }

    if let Some(expected_request) = action_payload.get("request") {
        let actual_request = payload.get("request").ok_or_else(|| {
            ApiError::BadRequest(
                "policyRuleDiffValidation acknowledgement must include request".to_string(),
            )
        })?;
        let expected_request = canonicalize_json(expected_request).map_err(|err| {
            ApiError::BadRequest(format!(
                "policyRuleDiffValidation dispatched request is not canonicalizable JSON: {err}"
            ))
        })?;
        let actual_request = canonicalize_json(actual_request).map_err(|err| {
            ApiError::BadRequest(format!(
                "policyRuleDiffValidation acknowledgement request is not canonicalizable JSON: {err}"
            ))
        })?;
        if actual_request != expected_request {
            return Err(ApiError::BadRequest(
                "policyRuleDiffValidation request does not match the dispatched response action"
                    .to_string(),
            ));
        }
    }

    if let Some(expected_receipt) = action_payload.get("expectedReceipt") {
        let actual_expected_receipt = payload.get("expectedReceipt").ok_or_else(|| {
            ApiError::BadRequest(
                "policyRuleDiffValidation acknowledgement must include expectedReceipt".to_string(),
            )
        })?;
        let expected_canonical = canonicalize_json(expected_receipt).map_err(|err| {
            ApiError::BadRequest(format!(
                "policyRuleDiffValidation dispatched expectedReceipt is not canonicalizable JSON: {err}"
            ))
        })?;
        let actual_canonical = canonicalize_json(actual_expected_receipt).map_err(|err| {
            ApiError::BadRequest(format!(
                "policyRuleDiffValidation acknowledgement expectedReceipt is not canonicalizable JSON: {err}"
            ))
        })?;
        if actual_canonical != expected_canonical {
            return Err(ApiError::BadRequest(
                "policyRuleDiffValidation expectedReceipt does not match the dispatched response action"
                    .to_string(),
            ));
        }
        validate_policy_rule_diff_ack_expected_policy_identity(payload, expected_receipt)?;
    }

    Ok(())
}

fn validate_policy_rule_diff_ack_expected_policy_identity(
    payload: &Value,
    expected_receipt: &Value,
) -> Result<(), ApiError> {
    let Some(expected_policy_hash) = expected_receipt
        .get("proposedPolicyHash")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(());
    };
    let Some(expected_policy_epoch) = expected_receipt
        .get("proposedPolicyEpoch")
        .and_then(Value::as_u64)
    else {
        return Ok(());
    };

    let actual_expected_receipt = payload.get("expectedReceipt").ok_or_else(|| {
        ApiError::BadRequest(
            "policyRuleDiffValidation acknowledgement must include expectedReceipt".to_string(),
        )
    })?;
    let actual_expected_policy_hash = actual_expected_receipt
        .get("proposedPolicyHash")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ApiError::BadRequest(
                "policyRuleDiffValidation expectedReceipt must include proposedPolicyHash"
                    .to_string(),
            )
        })?;
    if actual_expected_policy_hash != expected_policy_hash {
        return Err(ApiError::BadRequest(
            "policyRuleDiffValidation expectedReceipt proposedPolicyHash does not match the dispatched response action"
                .to_string(),
        ));
    }
    let actual_expected_policy_epoch = actual_expected_receipt
        .get("proposedPolicyEpoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            ApiError::BadRequest(
                "policyRuleDiffValidation expectedReceipt must include proposedPolicyEpoch"
                    .to_string(),
            )
        })?;
    if actual_expected_policy_epoch != expected_policy_epoch {
        return Err(ApiError::BadRequest(
            "policyRuleDiffValidation expectedReceipt proposedPolicyEpoch does not match the dispatched response action"
                .to_string(),
        ));
    }

    let impact = payload.get("impact").ok_or_else(|| {
        ApiError::BadRequest(
            "policyRuleDiffValidation acknowledgement must include impact".to_string(),
        )
    })?;
    let impact_policy_hash = impact
        .get("proposedPolicyHash")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ApiError::BadRequest(
                "policyRuleDiffValidation impact must include proposedPolicyHash".to_string(),
            )
        })?;
    if impact_policy_hash != expected_policy_hash {
        return Err(ApiError::BadRequest(
            "policyRuleDiffValidation impact proposedPolicyHash does not match expectedReceipt"
                .to_string(),
        ));
    }
    let impact_policy_epoch = impact
        .get("proposedPolicyEpoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            ApiError::BadRequest(
                "policyRuleDiffValidation impact must include proposedPolicyEpoch".to_string(),
            )
        })?;
    if impact_policy_epoch != expected_policy_epoch {
        return Err(ApiError::BadRequest(
            "policyRuleDiffValidation impact proposedPolicyEpoch does not match expectedReceipt"
                .to_string(),
        ));
    }

    Ok(())
}

fn policy_rule_diff_error_payload_value(ack: &AckSubmission) -> Result<&Value, ApiError> {
    ack.raw_payload
        .get("policyRuleDiffValidationError")
        .or_else(|| ack.raw_payload.get("policy_rule_diff_validation_error"))
        .ok_or_else(|| {
            ApiError::BadRequest(
                "acknowledgement raw_payload must include policyRuleDiffValidationError"
                    .to_string(),
            )
        })
}

pub(crate) fn validate_policy_rule_diff_error_payload_matches_action(
    ack: &AckSubmission,
    action_payload: &Value,
    target_id: &str,
) -> Result<(), ApiError> {
    let payload = policy_rule_diff_error_payload_value(ack)?;
    if !payload.is_object() {
        return Err(ApiError::BadRequest(
            "policyRuleDiffValidationError must be an object".to_string(),
        ));
    }

    require_policy_rule_diff_error_str_matches_action(
        payload,
        action_payload,
        "proposalId",
        "proposalId",
    )?;
    require_policy_rule_diff_error_str_matches_action(
        payload,
        action_payload,
        "validationPlanSha256",
        "validationPlanSha256",
    )?;
    let endpoint_agent_id = required_policy_rule_diff_error_str(payload, "endpointAgentId")?;
    if endpoint_agent_id != target_id {
        return Err(ApiError::BadRequest(
            "policyRuleDiffValidationError endpointAgentId does not match target_id".to_string(),
        ));
    }
    let expected_endpoint_agent_id =
        required_policy_rule_diff_action_str(action_payload, "endpointAgentId")?;
    if endpoint_agent_id != expected_endpoint_agent_id {
        return Err(ApiError::BadRequest(
            "policyRuleDiffValidationError endpointAgentId does not match the dispatched response action"
                .to_string(),
        ));
    }

    let expected_request = action_payload.get("request").ok_or_else(|| {
        ApiError::BadRequest(
            "policyRuleDiffValidation dispatched response action must include request".to_string(),
        )
    })?;
    let actual_request = payload.get("request").ok_or_else(|| {
        ApiError::BadRequest("policyRuleDiffValidationError must include request".to_string())
    })?;
    let expected_request = canonicalize_json(expected_request).map_err(|err| {
        ApiError::BadRequest(format!(
            "policyRuleDiffValidation dispatched request is not canonicalizable JSON: {err}"
        ))
    })?;
    let actual_request = canonicalize_json(actual_request).map_err(|err| {
        ApiError::BadRequest(format!(
            "policyRuleDiffValidationError request is not canonicalizable JSON: {err}"
        ))
    })?;
    if actual_request != expected_request {
        return Err(ApiError::BadRequest(
            "policyRuleDiffValidationError request does not match the dispatched response action"
                .to_string(),
        ));
    }

    let message = payload
        .get("message")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ApiError::BadRequest(
                "policyRuleDiffValidationError must include a non-empty message".to_string(),
            )
        })?;
    if let Some(ack_message) = ack
        .message
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if message != ack_message {
            return Err(ApiError::BadRequest(
                "policyRuleDiffValidationError message must match acknowledgement message"
                    .to_string(),
            ));
        }
    }

    Ok(())
}

fn require_policy_rule_diff_error_str_matches_action(
    payload: &Value,
    action_payload: &Value,
    payload_key: &str,
    action_key: &str,
) -> Result<(), ApiError> {
    let actual = required_policy_rule_diff_error_str(payload, payload_key)?;
    let expected = required_policy_rule_diff_action_str(action_payload, action_key)?;
    if actual != expected {
        return Err(ApiError::BadRequest(format!(
            "policyRuleDiffValidationError {payload_key} does not match the dispatched response action"
        )));
    }
    Ok(())
}

fn required_policy_rule_diff_error_str<'a>(
    payload: &'a Value,
    key: &str,
) -> Result<&'a str, ApiError> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ApiError::BadRequest(format!("policyRuleDiffValidationError must include {key}"))
        })
}

fn required_policy_rule_diff_action_str<'a>(
    payload: &'a Value,
    key: &str,
) -> Result<&'a str, ApiError> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ApiError::BadRequest(format!(
                "policyRuleDiffValidation dispatched response action must include {key}"
            ))
        })
}

fn validate_policy_rule_diff_ack_impact_evidence(
    payload: &Value,
    verified: &VerifiedEndpointDecisionReceipt,
) -> Result<(), ApiError> {
    let impact = payload.get("impact").ok_or_else(|| {
        ApiError::BadRequest(
            "policyRuleDiffValidation acknowledgement must include impact".to_string(),
        )
    })?;
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
        let raw_value = policy_rule_diff_ack_impact_evidence_value(impact, key)?;
        require_policy_rule_diff_ack_receipt_evidence_hash(
            &verified.endpoint_decision_value,
            key,
            &raw_value,
        )?;
    }
    Ok(())
}

fn policy_rule_diff_ack_impact_evidence_value(
    impact: &Value,
    key: &str,
) -> Result<String, ApiError> {
    let value = match key {
        "proposedPolicyHash" => impact
            .pointer("/proposedPolicy/policyHash")
            .and_then(Value::as_str)
            .map(str::to_string),
        "proposedPolicyEpoch" => impact
            .pointer("/proposedPolicy/policyEpoch")
            .and_then(Value::as_u64)
            .map(|value| value.to_string()),
        "eventCount" | "changedCount" | "allowToBlockCount" => impact
            .get(key)
            .and_then(Value::as_u64)
            .map(|value| value.to_string()),
        "trackPosture" => impact
            .get(key)
            .and_then(Value::as_bool)
            .map(|value| value.to_string()),
        _ => impact.get(key).and_then(Value::as_str).map(str::to_string),
    };
    value.ok_or_else(|| {
        ApiError::BadRequest(format!(
            "policyRuleDiffValidation impact must include {key}"
        ))
    })
}

fn require_policy_rule_diff_ack_receipt_evidence_hash(
    endpoint_decision: &Value,
    key: &str,
    raw_value: &str,
) -> Result<(), ApiError> {
    let expected_hash = sha256(raw_value.as_bytes()).to_hex_prefixed();
    let evidence_hash = endpoint_decision
        .get("evidence")
        .and_then(Value::as_array)
        .and_then(|items| {
            items.iter().find_map(|item| {
                if item.get("key").and_then(Value::as_str) == Some(key) {
                    item.get("valueHash").and_then(Value::as_str)
                } else {
                    None
                }
            })
        })
        .ok_or_else(|| {
            ApiError::BadRequest(format!(
                "policyRuleDiffValidation receipt evidence is missing {key}"
            ))
        })?;
    if evidence_hash != expected_hash {
        return Err(ApiError::BadRequest(format!(
            "policyRuleDiffValidation impact {key} does not match signed receipt evidence"
        )));
    }
    Ok(())
}

fn policy_rule_diff_ack_payload_value(ack: &AckSubmission) -> Result<&Value, ApiError> {
    ack.raw_payload
        .get("policyRuleDiffValidation")
        .or_else(|| ack.raw_payload.get("policy_rule_diff_validation"))
        .ok_or_else(|| {
            ApiError::BadRequest(
                "acknowledgement raw_payload must include policyRuleDiffValidation".to_string(),
            )
        })
}

pub(crate) fn validate_policy_rule_diff_ack_payload(ack: &AckSubmission) -> Result<(), ApiError> {
    if !matches!(ack.ack_status, "acknowledged") {
        return Ok(());
    }

    let payload = policy_rule_diff_ack_payload_value(ack)?;

    if payload.get("receipt").is_none() {
        return Err(ApiError::BadRequest(
            "policyRuleDiffValidation acknowledgement must include receipt".to_string(),
        ));
    }
    if payload.get("impact").is_none() {
        return Err(ApiError::BadRequest(
            "policyRuleDiffValidation acknowledgement must include impact".to_string(),
        ));
    }

    Ok(())
}
