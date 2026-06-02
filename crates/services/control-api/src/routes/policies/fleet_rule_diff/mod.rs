//! Fleet rule-diff dispatch/collect handlers.

use super::*;

mod helpers;
mod receipts;

pub(crate) use helpers::*;
pub(crate) use receipts::*;

pub(crate) async fn dispatch_policy_proposal_fleet_rule_diff_validation(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(req): Json<DispatchPolicyProposalFleetRuleDiffRequest>,
) -> Result<Json<DispatchPolicyProposalFleetRuleDiffResponse>, ApiError> {
    ensure_policy_deployer(&auth)?;

    let endpoint_filter = req
        .endpoint_agent_ids
        .into_iter()
        .map(|value| require_non_empty_policy_impact_field("endpoint_agent_ids", value))
        .collect::<Result<BTreeSet<_>, _>>()?;

    let mut reservation_tx = state.db.begin().await.map_err(ApiError::Database)?;
    let locked_proposal =
        fetch_policy_proposal_row_for_update(&mut reservation_tx, auth.tenant_id, id)
            .await?
            .ok_or(ApiError::NotFound)?;
    if locked_proposal.status != "pending" {
        return Err(ApiError::NotFound);
    }
    let validation_plan = locked_proposal
        .preview
        .get("fleetRuleDiffValidation")
        .ok_or_else(|| {
            ApiError::BadRequest(
                "proposal does not include a fleet rule-diff validation plan".to_string(),
            )
        })?;
    let validation_plan_sha256 = validation_plan
        .get("planSha256")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let endpoint_requests =
        selected_policy_rule_diff_endpoint_requests(validation_plan, &endpoint_filter)?;
    if endpoint_requests.is_empty() {
        return Err(ApiError::BadRequest(
            "fleet rule-diff validation plan has no selected endpoints to dispatch".to_string(),
        ));
    }

    let reason = req
        .reason
        .map(|value| require_non_empty_policy_impact_field("reason", value))
        .transpose()?
        .unwrap_or_else(|| {
            format!(
                "collect signed fleet rule-diff validation receipts for policy proposal {}",
                locked_proposal.id
            )
        });

    let reservation_preview = reserve_policy_rule_diff_dispatch(
        locked_proposal.preview.clone(),
        validation_plan_sha256.as_deref(),
        &endpoint_requests,
    )?;
    let reserved_row = sqlx::query::query(
        r#"UPDATE policy_proposals
           SET preview = $3,
               updated_at = now()
           WHERE tenant_id = $1
             AND id = $2
             AND status = 'pending'
           RETURNING *"#,
    )
    .bind(auth.tenant_id)
    .bind(id)
    .bind(&reservation_preview)
    .fetch_optional(&mut *reservation_tx)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;
    reservation_tx.commit().await.map_err(ApiError::Database)?;
    let mut proposal = policy_proposal_from_row(reserved_row).map_err(ApiError::Database)?;

    let mut dispatches = Vec::with_capacity(endpoint_requests.len());
    for endpoint_request in &endpoint_requests {
        let endpoint_agent_id = endpoint_request
            .get("endpointAgentId")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ApiError::BadRequest(
                    "fleet rule-diff endpoint request is missing endpointAgentId".to_string(),
                )
            })?;
        let payload = serde_json::json!({
            "operation": "policy_rule_diff_validation",
            "proposalId": proposal.id,
            "tenantId": proposal.tenant_id,
            "validationPlanSha256": validation_plan_sha256,
            "endpointAgentId": endpoint_agent_id,
            "request": endpoint_request.get("request").cloned().unwrap_or_else(|| serde_json::json!({})),
            "expectedReceipt": endpoint_request.get("expectedReceipt").cloned().unwrap_or_else(|| serde_json::json!({})),
            "ackRawPayloadContract": {
                "policyRuleDiffValidation": {
                    "proposalId": proposal.id,
                    "validationPlanSha256": validation_plan_sha256,
                    "endpointAgentId": endpoint_agent_id,
                    "impact": "EdrPolicyEventImpactReport",
                    "receipt": "SignedReceipt"
                }
            }
        });
        let action = response_actions::create_and_publish_internal_action(
            &state,
            &auth,
            CreateResponseActionRequest {
                action_type: "policy_rule_diff_validation".to_string(),
                target: ResponseTargetInput {
                    kind: "endpoint".to_string(),
                    id: endpoint_agent_id.to_string(),
                },
                reason: reason.clone(),
                expires_at: req.expires_at,
                case_id: None,
                source_detection_id: None,
                source_approval_id: None,
                require_acknowledgement: Some(true),
                payload: Some(payload),
            },
        )
        .await?;
        let delivery = action.deliveries.first();
        let dispatch = serde_json::json!({
            "responseActionId": action.action.id,
            "endpointAgentId": endpoint_agent_id,
            "actionStatus": action.action.status,
            "deliveryStatus": delivery.map(|delivery| delivery.status.as_str()),
            "deliverySubject": delivery.and_then(|delivery| delivery.delivery_subject.as_deref()),
            "publishedAt": delivery.and_then(|delivery| delivery.published_at),
            "dispatchedAt": Utc::now(),
        });
        let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
        let latest_proposal = fetch_policy_proposal_row_for_update(&mut tx, auth.tenant_id, id)
            .await?
            .ok_or(ApiError::NotFound)?;
        let preview = append_policy_rule_diff_dispatches(
            latest_proposal.preview,
            validation_plan_sha256.as_deref(),
            std::slice::from_ref(&dispatch),
        )?;
        let row = sqlx::query::query(
            r#"UPDATE policy_proposals
               SET preview = $3,
                   updated_at = now()
               WHERE tenant_id = $1
                 AND id = $2
                 AND status = 'pending'
               RETURNING *"#,
        )
        .bind(auth.tenant_id)
        .bind(id)
        .bind(&preview)
        .fetch_optional(&mut *tx)
        .await
        .map_err(ApiError::Database)?
        .ok_or(ApiError::NotFound)?;
        tx.commit().await.map_err(ApiError::Database)?;
        proposal = policy_proposal_from_row(row).map_err(ApiError::Database)?;
        dispatches.push(dispatch);
    }

    Ok(Json(DispatchPolicyProposalFleetRuleDiffResponse {
        proposal: proposal.into_response(&auth.slug),
        validation_plan_sha256,
        requested_endpoint_count: endpoint_requests.len(),
        dispatched_action_count: dispatches.len(),
        dispatches,
    }))
}

pub(crate) async fn collect_policy_proposal_fleet_rule_diff_validation(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(req): Json<CollectPolicyProposalFleetRuleDiffRequest>,
) -> Result<Json<CollectPolicyProposalFleetRuleDiffResponse>, ApiError> {
    ensure_policy_author(&auth)?;

    let proposal = fetch_policy_proposal_row(&state, auth.tenant_id, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if proposal.status != "pending" {
        return Err(ApiError::NotFound);
    }

    let validation_plan_sha256 = proposal
        .preview
        .pointer("/fleetRuleDiffValidation/planSha256")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let latest_response_action_ids =
        policy_rule_diff_dispatch_response_action_ids(&proposal.preview)?;
    let response_action_ids = if req.response_action_ids.is_empty() {
        latest_response_action_ids
    } else {
        let latest_response_action_ids = latest_response_action_ids
            .into_iter()
            .collect::<BTreeSet<_>>();
        for response_action_id in &req.response_action_ids {
            if !latest_response_action_ids.contains(response_action_id) {
                return Err(ApiError::BadRequest(
                    "responseActionIds must reference the latest fleet rule-diff dispatch for each endpoint"
                        .to_string(),
                ));
            }
        }
        req.response_action_ids
    };
    if response_action_ids.is_empty() {
        return Err(ApiError::BadRequest(
            "no fleet rule-diff validation response actions are available to collect".to_string(),
        ));
    }
    let (expected_proposed_policy_sha256, expected_proposed_policy_epoch) =
        policy_rule_diff_expected_proposed_policy(&proposal.preview)?;

    let collected = collect_policy_rule_diff_ack_receipts(
        &state.db,
        auth.tenant_id,
        proposal.id,
        validation_plan_sha256.as_deref(),
        &expected_proposed_policy_sha256,
        expected_proposed_policy_epoch,
        &response_action_ids,
    )
    .await?;
    if collected.is_empty() {
        return Err(ApiError::BadRequest(
            "no acknowledged fleet rule-diff validation receipts are available to collect"
                .to_string(),
        ));
    }

    let impact_request = build_collected_policy_rule_diff_impact_request(
        &collected,
        validation_plan_sha256.as_deref(),
    )?;
    let mut impact = validate_policy_proposal_impact(impact_request)?;
    impact["fleetRuleDiffCollection"] = serde_json::json!({
        "schemaVersion": 1,
        "validationPlanSha256": validation_plan_sha256,
        "responseActionIds": response_action_ids,
        "collectedAt": Utc::now(),
        "collectedReceiptCount": collected.len(),
        "acknowledgements": collected
            .iter()
            .map(|receipt| {
                serde_json::json!({
                    "responseActionId": receipt.response_action_id,
                    "endpointAgentId": receipt.endpoint_agent_id,
                    "observedAt": receipt.observed_at,
                })
            })
            .collect::<Vec<_>>(),
        "collectedEndpointIds": collected
            .iter()
            .map(|receipt| receipt.endpoint_agent_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>(),
    });

    let attached_by = auth.actor_id();
    let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
    let latest_proposal = fetch_policy_proposal_row_for_update(&mut tx, auth.tenant_id, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if latest_proposal.status != "pending" {
        return Err(ApiError::NotFound);
    }
    let preview = append_policy_rule_diff_collection(
        latest_proposal.preview,
        validation_plan_sha256.as_deref(),
        &impact["fleetRuleDiffCollection"],
    )?;
    let row = sqlx::query::query(
        r#"UPDATE policy_proposals
           SET impact = $3,
               impact_attached_by = $4,
               impact_attached_at = now(),
               preview = $5,
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
    .bind(&preview)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;
    tx.commit().await.map_err(ApiError::Database)?;

    let collected_endpoint_count = collected
        .iter()
        .map(|receipt| receipt.endpoint_agent_id.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    Ok(Json(CollectPolicyProposalFleetRuleDiffResponse {
        proposal: proposal_response_from_row(row, &auth.slug)?,
        validation_plan_sha256,
        collected_receipt_count: collected.len(),
        collected_endpoint_count,
        response_action_ids,
    }))
}
