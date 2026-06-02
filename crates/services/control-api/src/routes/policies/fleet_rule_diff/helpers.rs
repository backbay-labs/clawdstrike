//! Fleet rule-diff dispatch reservation, plan selection, and receipt aggregation helpers.

use crate::routes::policies::*;

pub(crate) fn selected_policy_rule_diff_endpoint_requests(
    validation_plan: &serde_json::Value,
    endpoint_filter: &BTreeSet<String>,
) -> Result<Vec<serde_json::Value>, ApiError> {
    let endpoint_requests = validation_plan
        .get("endpointRequests")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            ApiError::BadRequest(
                "fleet rule-diff validation plan endpointRequests must be an array".to_string(),
            )
        })?;
    let mut selected = Vec::new();
    for request in endpoint_requests {
        let endpoint_agent_id = request
            .get("endpointAgentId")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                ApiError::BadRequest(
                    "fleet rule-diff endpoint request is missing endpointAgentId".to_string(),
                )
            })?;
        if endpoint_filter.is_empty() || endpoint_filter.contains(endpoint_agent_id) {
            selected.push(request.clone());
        }
    }
    Ok(selected)
}

pub(crate) fn reserve_policy_rule_diff_dispatch(
    mut preview: serde_json::Value,
    validation_plan_sha256: Option<&str>,
    endpoint_requests: &[serde_json::Value],
) -> Result<serde_json::Value, ApiError> {
    let requested_endpoint_ids = endpoint_requests
        .iter()
        .map(|request| {
            request
                .get("endpointAgentId")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string)
                .ok_or_else(|| {
                    ApiError::BadRequest(
                        "fleet rule-diff endpoint request is missing endpointAgentId".to_string(),
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let validation = preview
        .get_mut("fleetRuleDiffValidation")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| {
            ApiError::BadRequest(
                "proposal preview does not include fleetRuleDiffValidation".to_string(),
            )
        })?;
    validation.insert(
        "dispatchReservation".to_string(),
        serde_json::json!({
            "schemaVersion": 1,
            "validationPlanSha256": validation_plan_sha256,
            "reservedAt": Utc::now(),
            "requestedEndpointCount": requested_endpoint_ids.len(),
            "requestedEndpointIds": requested_endpoint_ids,
        }),
    );
    validation.insert(
        "status".to_string(),
        serde_json::Value::String("dispatching".to_string()),
    );
    Ok(preview)
}

pub(crate) fn append_policy_rule_diff_dispatches(
    mut preview: serde_json::Value,
    validation_plan_sha256: Option<&str>,
    dispatches: &[serde_json::Value],
) -> Result<serde_json::Value, ApiError> {
    let validation = preview
        .get_mut("fleetRuleDiffValidation")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| {
            ApiError::BadRequest(
                "proposal preview does not include fleetRuleDiffValidation".to_string(),
            )
        })?;
    let existing = validation
        .entry("dispatches")
        .or_insert_with(|| serde_json::json!([]));
    let existing = existing.as_array_mut().ok_or_else(|| {
        ApiError::BadRequest("fleetRuleDiffValidation.dispatches must be an array".to_string())
    })?;
    existing.extend(dispatches.iter().cloned());
    validation.insert(
        "lastDispatch".to_string(),
        serde_json::json!({
            "validationPlanSha256": validation_plan_sha256,
            "dispatchedAt": Utc::now(),
            "dispatchedActionCount": dispatches.len(),
        }),
    );
    validation.insert(
        "status".to_string(),
        serde_json::Value::String("dispatch_requested".to_string()),
    );
    Ok(preview)
}

pub(crate) fn append_policy_rule_diff_collection(
    mut preview: serde_json::Value,
    validation_plan_sha256: Option<&str>,
    collection: &serde_json::Value,
) -> Result<serde_json::Value, ApiError> {
    let validation = preview
        .get_mut("fleetRuleDiffValidation")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| {
            ApiError::BadRequest(
                "proposal preview does not include fleetRuleDiffValidation".to_string(),
            )
        })?;
    validation.insert(
        "lastCollection".to_string(),
        serde_json::json!({
            "validationPlanSha256": validation_plan_sha256,
            "collection": collection,
        }),
    );
    validation.insert(
        "status".to_string(),
        serde_json::Value::String("receipts_collected".to_string()),
    );
    Ok(preview)
}

pub(crate) fn policy_rule_diff_dispatch_response_action_ids(
    preview: &serde_json::Value,
) -> Result<Vec<Uuid>, ApiError> {
    let Some(dispatches) = preview
        .pointer("/fleetRuleDiffValidation/dispatches")
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(Vec::new());
    };
    let mut latest_by_endpoint = BTreeMap::<String, Uuid>::new();
    for dispatch in dispatches {
        let endpoint_agent_id = dispatch
            .get("endpointAgentId")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                ApiError::BadRequest(
                    "fleetRuleDiffValidation.dispatches endpointAgentId must be a string"
                        .to_string(),
                )
            })?;
        let response_action_id = dispatch.get("responseActionId").ok_or_else(|| {
            ApiError::BadRequest(
                "fleetRuleDiffValidation.dispatches must include responseActionId".to_string(),
            )
        })?;
        let response_action_id = response_action_id.as_str().ok_or_else(|| {
            ApiError::BadRequest(
                "fleetRuleDiffValidation.dispatches responseActionId must be a string".to_string(),
            )
        })?;
        let response_action_id = Uuid::parse_str(response_action_id).map_err(|_| {
            ApiError::BadRequest(
                "fleetRuleDiffValidation.dispatches responseActionId must be a UUID".to_string(),
            )
        })?;
        latest_by_endpoint.insert(endpoint_agent_id.to_string(), response_action_id);
    }
    Ok(latest_by_endpoint.into_values().collect())
}

pub(crate) fn policy_rule_diff_expected_proposed_policy(
    preview: &serde_json::Value,
) -> Result<(String, u64), ApiError> {
    let validation = preview.get("fleetRuleDiffValidation").ok_or_else(|| {
        ApiError::BadRequest(
            "proposal preview does not include fleetRuleDiffValidation".to_string(),
        )
    })?;
    let proposed_policy_sha256 = validation
        .get("proposedPolicySha256")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ApiError::BadRequest(
                "fleetRuleDiffValidation must include proposedPolicySha256".to_string(),
            )
        })?;
    let proposed_policy_version = validation
        .get("proposedPolicyVersion")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            ApiError::BadRequest(
                "fleetRuleDiffValidation must include proposedPolicyVersion".to_string(),
            )
        })?;
    Ok((proposed_policy_sha256.to_string(), proposed_policy_version))
}

pub(crate) struct CollectedPolicyRuleDiffReceipt {
    pub(crate) response_action_id: Uuid,
    pub(crate) endpoint_agent_id: String,
    pub(crate) observed_at: DateTime<Utc>,
    pub(crate) impact: serde_json::Value,
    pub(crate) receipt: serde_json::Value,
    pub(crate) public_key: String,
}

pub(crate) fn latest_policy_rule_diff_receipts_by_endpoint(
    receipts: Vec<CollectedPolicyRuleDiffReceipt>,
) -> Vec<CollectedPolicyRuleDiffReceipt> {
    let mut latest_by_endpoint = BTreeMap::<String, CollectedPolicyRuleDiffReceipt>::new();
    for receipt in receipts {
        match latest_by_endpoint.entry(receipt.endpoint_agent_id.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(receipt);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let current = entry.get();
                if receipt.observed_at > current.observed_at
                    || (receipt.observed_at == current.observed_at
                        && receipt.response_action_id > current.response_action_id)
                {
                    entry.insert(receipt);
                }
            }
        }
    }

    let mut receipts = latest_by_endpoint.into_values().collect::<Vec<_>>();
    receipts.sort_by(|left, right| {
        left.observed_at
            .cmp(&right.observed_at)
            .then_with(|| left.endpoint_agent_id.cmp(&right.endpoint_agent_id))
            .then_with(|| left.response_action_id.cmp(&right.response_action_id))
    });
    receipts
}
