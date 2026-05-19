use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use hush_core::receipt::PublicKeySet;
use hush_core::{canonicalize_json, sha256, PublicKey, SignedReceipt};
use serde::{Deserialize, Serialize};
use sqlx::row::Row;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

use crate::auth::AuthenticatedTenant;
use crate::db::PgPool;
use crate::error::ApiError;
use crate::routes::response_actions::{self, CreateResponseActionRequest, ResponseTargetInput};
use crate::services::policy_distribution;
use crate::state::AppState;

const POLICY_PROPOSAL_HISTORY_LOOKBACK_HOURS: i64 = 168;
const POLICY_PROPOSAL_HISTORY_LIMIT: i64 = 1000;
const POLICY_PROPOSAL_FLEET_VALIDATION_ENDPOINT_LIMIT: usize = 25;
const POLICY_PROPOSAL_FLEET_VALIDATION_EVENT_ID_LIMIT: usize = 25;
const MAX_POLICY_PROPOSAL_SIMULATION_RECEIPT_BYTES: usize = 256 * 1024;
const MAX_POLICY_PROPOSAL_SIMULATION_RECEIPTS: usize = 64;
const POLICY_PROPOSAL_SIMULATION_RECEIPT_FAMILY: &str = "simulation";
const POLICY_PROPOSAL_SIMULATION_RULE_ID: &str = "endpoint.policy_event_impact";
const POLICY_PROPOSAL_SIMULATION_PROCESS_NODE_ID: &str = "policy_event_stream";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/policies/deploy", post(deploy_policy))
        .route("/policies/preview", post(preview_policy))
        .route(
            "/policies/proposals",
            get(list_policy_proposals).post(create_policy_proposal),
        )
        .route("/policies/proposals/{id}", get(get_policy_proposal))
        .route(
            "/policies/proposals/{id}/approve-deploy",
            post(approve_policy_proposal),
        )
        .route(
            "/policies/proposals/{id}/impact",
            post(attach_policy_proposal_impact),
        )
        .route(
            "/policies/proposals/{id}/fleet-rule-diff/dispatch",
            post(dispatch_policy_proposal_fleet_rule_diff_validation),
        )
        .route(
            "/policies/proposals/{id}/fleet-rule-diff/collect",
            post(collect_policy_proposal_fleet_rule_diff_validation),
        )
        .route(
            "/policies/proposals/{id}/reject",
            post(reject_policy_proposal),
        )
        .route("/policies/active", get(get_active_policy))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployPolicyRequest {
    pub policy_yaml: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeployPolicyResponse {
    pub deployment_id: Uuid,
    pub tenant_slug: String,
    pub nats_subject: String,
    pub agent_count: i64,
    pub kv_write_failures: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewPolicyRequest {
    pub policy_yaml: String,
    pub description: Option<String>,
    pub agent_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PreviewPolicyResponse {
    pub preview_id: Uuid,
    pub tenant_slug: String,
    pub status: String,
    pub would_deploy_version: i64,
    pub policy_yaml_sha256: String,
    pub distribution_policy_yaml: String,
    pub distribution_policy_sha256: String,
    pub deploy_allowed: bool,
    pub requires_deploy_approval: bool,
    pub agent_effective_policy: Option<PreviewEffectivePolicyResponse>,
}

#[derive(Debug, Serialize)]
pub struct PreviewEffectivePolicyResponse {
    pub agent_id: String,
    pub principal_id: Option<Uuid>,
    pub lifecycle_state: String,
    pub liveness_state: Option<String>,
    pub policy_epoch: i64,
    pub compiled_policy_yaml: String,
    pub compiled_policy_sha256: String,
    pub source_attachments: Vec<PreviewPolicyAttachmentResponse>,
    pub applied_overlays: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PreviewPolicyAttachmentResponse {
    pub attachment_id: Uuid,
    pub target_kind: String,
    pub target_id: Uuid,
    pub priority: i32,
    pub policy_ref: Option<String>,
    pub checksum_sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePolicyProposalRequest {
    pub policy_yaml: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewPolicyProposalRequest {
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachPolicyProposalImpactRequest {
    pub source: String,
    pub summary: String,
    pub simulation_receipt_id: Option<String>,
    pub simulation_receipt_sha256: Option<String>,
    pub simulation_receipt: Option<serde_json::Value>,
    pub simulation_receipt_public_key: Option<String>,
    #[serde(default)]
    pub simulation_receipts: Vec<PolicyProposalSimulationReceiptAttachment>,
    pub changed_verdict_count: i64,
    pub blocking_change_count: i64,
    pub developer_breakage_score: f64,
    pub affected_identity_count: i64,
    pub affected_tool_count: i64,
    pub recommendation: String,
    #[serde(default)]
    pub proof_hashes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyProposalSimulationReceiptAttachment {
    pub receipt_id: Option<String>,
    pub receipt_sha256: Option<String>,
    pub receipt: serde_json::Value,
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DispatchPolicyProposalFleetRuleDiffRequest {
    #[serde(default)]
    pub endpoint_agent_ids: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CollectPolicyProposalFleetRuleDiffRequest {
    #[serde(default)]
    pub response_action_ids: Vec<Uuid>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DispatchPolicyProposalFleetRuleDiffResponse {
    pub proposal: PolicyProposalResponse,
    pub validation_plan_sha256: Option<String>,
    pub requested_endpoint_count: usize,
    pub dispatched_action_count: usize,
    pub dispatches: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectPolicyProposalFleetRuleDiffResponse {
    pub proposal: PolicyProposalResponse,
    pub validation_plan_sha256: Option<String>,
    pub collected_receipt_count: usize,
    pub collected_endpoint_count: usize,
    pub response_action_ids: Vec<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct CreatePolicyProposalResponse {
    pub proposal: PolicyProposalResponse,
}

#[derive(Debug, Serialize)]
pub struct ApprovePolicyProposalResponse {
    pub proposal: PolicyProposalResponse,
    pub deployment: Option<DeployPolicyResponse>,
    pub approvals_remaining: i32,
}

#[derive(Debug, Serialize)]
pub struct PolicyProposalResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub tenant_slug: String,
    pub policy_yaml: String,
    pub checksum_sha256: String,
    pub description: Option<String>,
    pub status: String,
    pub base_active_policy_version: i64,
    pub proposed_policy_version: i64,
    pub preview: serde_json::Value,
    pub required_approvals: i32,
    pub approval_count: i32,
    pub approvals_remaining: i32,
    pub approved_by: Vec<String>,
    pub approval_notes: serde_json::Value,
    pub impact: Option<serde_json::Value>,
    pub impact_attached_by: Option<String>,
    pub impact_attached_at: Option<DateTime<Utc>>,
    pub deployed_policy_version: Option<i64>,
    pub deployment_id: Option<Uuid>,
    pub submitted_by: String,
    pub reviewed_by: Option<String>,
    pub review_note: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub deployed_at: Option<DateTime<Utc>>,
}

struct PolicyProposalRow {
    id: Uuid,
    tenant_id: Uuid,
    policy_yaml: String,
    checksum_sha256: String,
    description: Option<String>,
    status: String,
    base_active_policy_version: i64,
    proposed_policy_version: i64,
    preview: serde_json::Value,
    required_approvals: i32,
    approved_by: Vec<String>,
    approval_notes: serde_json::Value,
    impact: Option<serde_json::Value>,
    impact_attached_by: Option<String>,
    impact_attached_at: Option<DateTime<Utc>>,
    deployed_policy_version: Option<i64>,
    deployment_id: Option<Uuid>,
    submitted_by: String,
    reviewed_by: Option<String>,
    review_note: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    reviewed_at: Option<DateTime<Utc>>,
    deployed_at: Option<DateTime<Utc>>,
}

struct PolicyDeploymentOutcome {
    deployment_id: Uuid,
    nats_subject: String,
    agent_count: i64,
    kv_write_failures: i64,
}

async fn deploy_policy(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(req): Json<DeployPolicyRequest>,
) -> Result<Json<DeployPolicyResponse>, ApiError> {
    if auth.role == "viewer" || auth.role == "member" {
        return Err(ApiError::Forbidden);
    }

    // Validate the policy YAML before it becomes tenant distribution state.
    policy_distribution::validate_policy_document(&req.policy_yaml)
        .map_err(ApiError::BadRequest)?;

    // Persist tenant-level active policy so enroll/recovery paths can converge later.
    let active_policy = policy_distribution::upsert_active_policy(
        &state.db,
        auth.tenant_id,
        &req.policy_yaml,
        req.description.as_deref(),
    )
    .await
    .map_err(ApiError::Database)?;
    let deployment = distribute_active_policy_to_fleet(
        &state,
        auth.tenant_id,
        &auth.slug,
        &active_policy,
        Uuid::new_v4(),
    )
    .await?;

    tracing::info!(
        deployment_id = %deployment.deployment_id,
        tenant = %auth.slug,
        policy_version = active_policy.version,
        agents = deployment.agent_count,
        kv_write_failures = deployment.kv_write_failures,
        "Policy deployed to tenant fleet"
    );

    Ok(Json(DeployPolicyResponse {
        deployment_id: deployment.deployment_id,
        tenant_slug: auth.slug,
        nats_subject: deployment.nats_subject,
        agent_count: deployment.agent_count,
        kv_write_failures: deployment.kv_write_failures,
    }))
}

async fn preview_policy(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(req): Json<PreviewPolicyRequest>,
) -> Result<Json<PreviewPolicyResponse>, ApiError> {
    if auth.role == "viewer" {
        return Err(ApiError::Forbidden);
    }

    let candidate = policy_distribution::preview_active_policy_candidate(
        &state.db,
        auth.tenant_id,
        &req.policy_yaml,
        req.description.as_deref(),
    )
    .await
    .map_err(policy_preview_error)?;
    let distribution_policy_yaml =
        policy_distribution::distribution_policy_yaml(&candidate).map_err(ApiError::Internal)?;
    let distribution_policy_sha256 =
        policy_distribution::policy_yaml_checksum_sha256(&distribution_policy_yaml);
    let agent_effective_policy = if let Some(agent_id) = req.agent_id.as_deref() {
        let Some(effective_policy) =
            policy_distribution::preview_effective_policy_candidate_for_agent(
                &state.db,
                auth.tenant_id,
                agent_id,
                &candidate,
            )
            .await
            .map_err(policy_preview_error)?
        else {
            return Err(ApiError::NotFound);
        };
        Some(PreviewEffectivePolicyResponse::from(effective_policy))
    } else {
        None
    };
    let deploy_allowed = auth.role == "admin" || auth.role == "owner";

    Ok(Json(PreviewPolicyResponse {
        preview_id: Uuid::new_v4(),
        tenant_slug: auth.slug,
        status: "valid".to_string(),
        would_deploy_version: candidate.version,
        policy_yaml_sha256: candidate.checksum_sha256,
        distribution_policy_yaml,
        distribution_policy_sha256,
        deploy_allowed,
        requires_deploy_approval: !deploy_allowed,
        agent_effective_policy,
    }))
}

async fn create_policy_proposal(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(req): Json<CreatePolicyProposalRequest>,
) -> Result<Json<CreatePolicyProposalResponse>, ApiError> {
    ensure_policy_author(&auth)?;

    let candidate = policy_distribution::preview_active_policy_candidate(
        &state.db,
        auth.tenant_id,
        &req.policy_yaml,
        req.description.as_deref(),
    )
    .await
    .map_err(policy_preview_error)?;
    let base_active_policy_version = candidate.version - 1;
    let current_active =
        policy_distribution::fetch_active_policy_by_tenant_id(&state.db, auth.tenant_id)
            .await
            .map_err(ApiError::Database)?;
    let preview = build_policy_proposal_preview(
        &state.db,
        auth.tenant_id,
        &candidate,
        current_active.as_ref(),
    )
    .await?;
    let submitted_by = auth.actor_id();

    let row = sqlx::query::query(
        r#"INSERT INTO policy_proposals (
               tenant_id,
               policy_yaml,
               checksum_sha256,
               description,
               base_active_policy_version,
               proposed_policy_version,
               preview,
               submitted_by
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           RETURNING *"#,
    )
    .bind(auth.tenant_id)
    .bind(&candidate.policy_yaml)
    .bind(&candidate.checksum_sha256)
    .bind(candidate.description.as_deref())
    .bind(base_active_policy_version)
    .bind(candidate.version)
    .bind(&preview)
    .bind(&submitted_by)
    .fetch_one(&state.db)
    .await
    .map_err(ApiError::Database)?;

    Ok(Json(CreatePolicyProposalResponse {
        proposal: proposal_response_from_row(row, &auth.slug)?,
    }))
}

async fn list_policy_proposals(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
) -> Result<Json<Vec<PolicyProposalResponse>>, ApiError> {
    let rows = sqlx::query::query(
        r#"SELECT *
           FROM policy_proposals
           WHERE tenant_id = $1
           ORDER BY created_at DESC, id DESC"#,
    )
    .bind(auth.tenant_id)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::Database)?;

    let proposals = rows
        .into_iter()
        .map(|row| proposal_response_from_row(row, &auth.slug))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(proposals))
}

async fn get_policy_proposal(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<PolicyProposalResponse>, ApiError> {
    let row = fetch_policy_proposal_row(&state, auth.tenant_id, id)
        .await?
        .ok_or(ApiError::NotFound)?;

    Ok(Json(row.into_response(&auth.slug)))
}

async fn attach_policy_proposal_impact(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(req): Json<AttachPolicyProposalImpactRequest>,
) -> Result<Json<PolicyProposalResponse>, ApiError> {
    ensure_policy_author(&auth)?;

    let impact = validate_policy_proposal_impact(req)?;
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

async fn dispatch_policy_proposal_fleet_rule_diff_validation(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(req): Json<DispatchPolicyProposalFleetRuleDiffRequest>,
) -> Result<Json<DispatchPolicyProposalFleetRuleDiffResponse>, ApiError> {
    ensure_policy_deployer(&auth)?;

    let proposal = fetch_policy_proposal_row(&state, auth.tenant_id, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if proposal.status != "pending" {
        return Err(ApiError::NotFound);
    }

    let endpoint_filter = req
        .endpoint_agent_ids
        .into_iter()
        .map(|value| require_non_empty_policy_impact_field("endpoint_agent_ids", value))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let validation_plan = proposal
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
                proposal.id
            )
        });

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
        dispatches.push(serde_json::json!({
            "responseActionId": action.action.id,
            "endpointAgentId": endpoint_agent_id,
            "actionStatus": action.action.status,
            "deliveryStatus": delivery.map(|delivery| delivery.status.as_str()),
            "deliverySubject": delivery.and_then(|delivery| delivery.delivery_subject.as_deref()),
            "publishedAt": delivery.and_then(|delivery| delivery.published_at),
            "dispatchedAt": Utc::now(),
        }));
    }

    let preview = append_policy_rule_diff_dispatches(
        proposal.preview.clone(),
        validation_plan_sha256.as_deref(),
        &dispatches,
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
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

    Ok(Json(DispatchPolicyProposalFleetRuleDiffResponse {
        proposal: proposal_response_from_row(row, &auth.slug)?,
        validation_plan_sha256,
        requested_endpoint_count: endpoint_requests.len(),
        dispatched_action_count: dispatches.len(),
        dispatches,
    }))
}

async fn collect_policy_proposal_fleet_rule_diff_validation(
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
    let response_action_ids = if req.response_action_ids.is_empty() {
        policy_rule_diff_dispatch_response_action_ids(&proposal.preview)?
    } else {
        req.response_action_ids
    };
    if response_action_ids.is_empty() {
        return Err(ApiError::BadRequest(
            "no fleet rule-diff validation response actions are available to collect".to_string(),
        ));
    }

    let collected = collect_policy_rule_diff_ack_receipts(
        &state.db,
        auth.tenant_id,
        proposal.id,
        validation_plan_sha256.as_deref(),
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
    );
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

    let preview = append_policy_rule_diff_collection(
        proposal.preview.clone(),
        validation_plan_sha256.as_deref(),
        &impact["fleetRuleDiffCollection"],
    )?;
    let attached_by = auth.actor_id();
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
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

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

fn selected_policy_rule_diff_endpoint_requests(
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

fn append_policy_rule_diff_dispatches(
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

fn append_policy_rule_diff_collection(
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

fn policy_rule_diff_dispatch_response_action_ids(
    preview: &serde_json::Value,
) -> Result<Vec<Uuid>, ApiError> {
    let Some(dispatches) = preview
        .pointer("/fleetRuleDiffValidation/dispatches")
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(Vec::new());
    };
    dispatches
        .iter()
        .filter_map(|dispatch| dispatch.get("responseActionId"))
        .map(|value| {
            let id = value.as_str().ok_or_else(|| {
                ApiError::BadRequest(
                    "fleetRuleDiffValidation.dispatches responseActionId must be a string"
                        .to_string(),
                )
            })?;
            Uuid::parse_str(id).map_err(|_| {
                ApiError::BadRequest(
                    "fleetRuleDiffValidation.dispatches responseActionId must be a UUID"
                        .to_string(),
                )
            })
        })
        .collect()
}

struct CollectedPolicyRuleDiffReceipt {
    response_action_id: Uuid,
    endpoint_agent_id: String,
    observed_at: DateTime<Utc>,
    impact: serde_json::Value,
    receipt: serde_json::Value,
    public_key: String,
}

async fn collect_policy_rule_diff_ack_receipts(
    db: &PgPool,
    tenant_id: Uuid,
    proposal_id: Uuid,
    validation_plan_sha256: Option<&str>,
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
        if let Some(receipt_endpoint_id) = verified.endpoint_id.as_deref() {
            if receipt_endpoint_id != endpoint_agent_id {
                return Err(ApiError::BadRequest(
                    "policyRuleDiffValidation receipt endpointId must match the response-action target"
                        .to_string(),
                ));
            }
        }
        validate_policy_rule_diff_impact_against_receipt(&impact, &verified)?;
        collected.push(CollectedPolicyRuleDiffReceipt {
            response_action_id,
            endpoint_agent_id,
            observed_at,
            impact,
            receipt,
            public_key,
        });
    }
    Ok(collected)
}

fn policy_rule_diff_payload(
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

fn validate_policy_rule_diff_payload_correlation(
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

fn validate_policy_rule_diff_impact_against_receipt(
    impact: &serde_json::Value,
    verified: &VerifiedPolicyProposalSimulationReceipt,
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
    Ok(())
}

fn policy_rule_diff_impact_evidence_value(
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

fn build_collected_policy_rule_diff_impact_request(
    collected: &[CollectedPolicyRuleDiffReceipt],
    validation_plan_sha256: Option<&str>,
) -> AttachPolicyProposalImpactRequest {
    let event_count = collected
        .iter()
        .map(|receipt| impact_u64(&receipt.impact, "eventCount"))
        .sum::<u64>();
    let changed_count = collected
        .iter()
        .map(|receipt| impact_u64(&receipt.impact, "changedCount"))
        .sum::<u64>();
    let allow_to_block_count = collected
        .iter()
        .map(|receipt| impact_u64(&receipt.impact, "allowToBlockCount"))
        .sum::<u64>();
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

    AttachPolicyProposalImpactRequest {
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
    }
}

fn impact_u64(impact: &serde_json::Value, field: &str) -> u64 {
    impact
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

async fn reject_policy_proposal(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(req): Json<ReviewPolicyProposalRequest>,
) -> Result<Json<PolicyProposalResponse>, ApiError> {
    ensure_policy_deployer(&auth)?;

    let reviewed_by = auth.actor_id();
    let row = sqlx::query::query(
        r#"UPDATE policy_proposals
           SET status = 'rejected',
               reviewed_by = $3,
               review_note = $4,
               reviewed_at = now(),
               updated_at = now()
           WHERE tenant_id = $1
             AND id = $2
             AND status = 'pending'
           RETURNING *"#,
    )
    .bind(auth.tenant_id)
    .bind(id)
    .bind(&reviewed_by)
    .bind(req.note.as_deref())
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

    Ok(Json(proposal_response_from_row(row, &auth.slug)?))
}

async fn approve_policy_proposal(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(req): Json<ReviewPolicyProposalRequest>,
) -> Result<Json<ApprovePolicyProposalResponse>, ApiError> {
    ensure_policy_deployer(&auth)?;

    let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
    let proposal = fetch_policy_proposal_row_for_update(&mut tx, auth.tenant_id, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if proposal.status != "pending" {
        return Err(ApiError::NotFound);
    }

    let current_active = policy_distribution::fetch_active_policy_by_tenant_id_with_executor(
        &mut *tx,
        auth.tenant_id,
    )
    .await
    .map_err(ApiError::Database)?;
    let current_version = current_active
        .as_ref()
        .map(|policy| policy.version)
        .unwrap_or(0);
    if current_version != proposal.base_active_policy_version {
        return Err(ApiError::Conflict(format!(
            "policy proposal {} was based on active policy version {}, but current active policy version is {}; resubmit the proposal",
            proposal.id, proposal.base_active_policy_version, current_version
        )));
    }

    let reviewed_by = auth.actor_id();
    if reviewed_by == proposal.submitted_by {
        return Err(ApiError::Conflict(format!(
            "policy proposal {} must be approved by someone other than its submitter",
            proposal.id
        )));
    }
    if proposal
        .approved_by
        .iter()
        .any(|approver| approver == &reviewed_by)
    {
        return Err(ApiError::Conflict(format!(
            "policy proposal {} has already been approved by this actor",
            proposal.id
        )));
    }

    let mut approved_by = proposal.approved_by.clone();
    approved_by.push(reviewed_by.clone());
    let approval_notes = append_policy_proposal_approval_note(
        &proposal.approval_notes,
        &reviewed_by,
        req.note.as_deref(),
    );
    let approvals_remaining = proposal.required_approvals - approved_by.len() as i32;
    if approvals_remaining > 0 {
        let row = sqlx::query::query(
            r#"UPDATE policy_proposals
               SET approved_by = $3,
                   approval_notes = $4,
                   updated_at = now()
               WHERE tenant_id = $1
                 AND id = $2
                 AND status = 'pending'
               RETURNING *"#,
        )
        .bind(auth.tenant_id)
        .bind(id)
        .bind(&approved_by)
        .bind(&approval_notes)
        .fetch_optional(&mut *tx)
        .await
        .map_err(ApiError::Database)?
        .ok_or_else(|| {
            ApiError::Conflict(format!(
                "policy proposal {} was changed before approval could be recorded",
                proposal.id
            ))
        })?;
        tx.commit().await.map_err(ApiError::Database)?;

        return Ok(Json(ApprovePolicyProposalResponse {
            proposal: proposal_response_from_row(row, &auth.slug)?,
            deployment: None,
            approvals_remaining,
        }));
    }

    let active_policy = policy_distribution::upsert_active_policy_with_executor(
        &mut *tx,
        auth.tenant_id,
        &proposal.policy_yaml,
        proposal.description.as_deref(),
    )
    .await
    .map_err(ApiError::Database)?;
    let deployment_id = Uuid::new_v4();

    let row = sqlx::query::query(
        r#"UPDATE policy_proposals
           SET status = 'deployed',
               approved_by = $7,
               approval_notes = $8,
               reviewed_by = $3,
               review_note = $4,
               reviewed_at = now(),
               deployed_at = now(),
               deployed_policy_version = $5,
               deployment_id = $6,
               updated_at = now()
           WHERE tenant_id = $1
             AND id = $2
             AND status = 'pending'
           RETURNING *"#,
    )
    .bind(auth.tenant_id)
    .bind(id)
    .bind(&reviewed_by)
    .bind(req.note.as_deref())
    .bind(active_policy.version)
    .bind(deployment_id)
    .bind(&approved_by)
    .bind(&approval_notes)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::Database)?
    .ok_or_else(|| {
        ApiError::Conflict(format!(
            "policy proposal {} was changed before deployment could be recorded",
            proposal.id
        ))
    })?;
    tx.commit().await.map_err(ApiError::Database)?;
    let deployment = distribute_active_policy_to_fleet(
        &state,
        auth.tenant_id,
        &auth.slug,
        &active_policy,
        deployment_id,
    )
    .await?;

    Ok(Json(ApprovePolicyProposalResponse {
        proposal: proposal_response_from_row(row, &auth.slug)?,
        deployment: Some(DeployPolicyResponse {
            deployment_id: deployment.deployment_id,
            tenant_slug: auth.slug,
            nats_subject: deployment.nats_subject,
            agent_count: deployment.agent_count,
            kv_write_failures: deployment.kv_write_failures,
        }),
        approvals_remaining: 0,
    }))
}

async fn get_active_policy(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
) -> Result<Json<serde_json::Value>, ApiError> {
    let active = policy_distribution::fetch_active_policy_by_tenant_id(&state.db, auth.tenant_id)
        .await
        .map_err(ApiError::Database)?;

    if let Some(policy) = active {
        return Ok(Json(serde_json::json!({
            "tenant": auth.slug,
            "status": "active",
            "version": policy.version,
            "checksum_sha256": policy.checksum_sha256,
            "description": policy.description,
            "updated_at": policy.updated_at,
            "policy_yaml": policy.policy_yaml,
        })));
    }

    Ok(Json(serde_json::json!({
        "tenant": auth.slug,
        "status": "no active policy",
    })))
}

async fn distribute_active_policy_to_fleet(
    state: &AppState,
    tenant_id: Uuid,
    tenant_slug: &str,
    active_policy: &policy_distribution::ActiveTenantPolicy,
    deployment_id: Uuid,
) -> Result<PolicyDeploymentOutcome, ApiError> {
    // Enumerate all non-revoked agents (active + inactive lifecycle states).
    // This avoids only targeting currently-active agents during deploy.
    let agent_rows = sqlx::query::query(
        r#"SELECT agent_id
           FROM agents
           WHERE tenant_id = $1
             AND status IN ('active', 'inactive', 'stale', 'dead')
           ORDER BY created_at ASC"#,
    )
    .bind(tenant_id)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::Database)?;

    let agent_ids: Vec<String> = agent_rows
        .into_iter()
        .map(|row| row.try_get("agent_id"))
        .collect::<Result<_, _>>()
        .map_err(ApiError::Database)?;
    let agent_count = agent_ids.len() as i64;

    // Write policy into each agent-scoped KV bucket used by PolicySync.
    let mut kv_write_failures = 0_i64;
    for agent_id in &agent_ids {
        if let Err(err) = policy_distribution::reconcile_effective_policy_for_agent(
            &state.db,
            &state.nats,
            tenant_id,
            agent_id,
        )
        .await
        {
            kv_write_failures += 1;
            tracing::warn!(
                error = %err,
                tenant = %tenant_slug,
                agent_id = %agent_id,
                "Failed to push deployed policy to agent KV bucket"
            );
        }
    }

    // Best-effort compatibility broadcast for legacy subscribers.
    let subject = policy_distribution::policy_update_subject(tenant_slug);
    let distribution_policy_yaml =
        policy_distribution::distribution_policy_yaml(active_policy).map_err(ApiError::Internal)?;
    if let Err(err) = state
        .nats
        .publish(
            subject.clone(),
            distribution_policy_yaml.into_bytes().into(),
        )
        .await
    {
        tracing::warn!(
            error = %err,
            subject = %subject,
            "Legacy policy update publish failed (KV writes succeeded)"
        );
    }

    Ok(PolicyDeploymentOutcome {
        deployment_id,
        nats_subject: subject,
        agent_count,
        kv_write_failures,
    })
}

async fn fetch_policy_proposal_row(
    state: &AppState,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<Option<PolicyProposalRow>, ApiError> {
    let row = sqlx::query::query(
        r#"SELECT *
           FROM policy_proposals
           WHERE tenant_id = $1
             AND id = $2"#,
    )
    .bind(tenant_id)
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::Database)?;

    row.map(policy_proposal_from_row)
        .transpose()
        .map_err(ApiError::Database)
}

async fn fetch_policy_proposal_row_for_update(
    tx: &mut sqlx::transaction::Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<Option<PolicyProposalRow>, ApiError> {
    let row = sqlx::query::query(
        r#"SELECT *
           FROM policy_proposals
           WHERE tenant_id = $1
             AND id = $2
           FOR UPDATE"#,
    )
    .bind(tenant_id)
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(ApiError::Database)?;

    row.map(policy_proposal_from_row)
        .transpose()
        .map_err(ApiError::Database)
}

fn proposal_response_from_row(
    row: sqlx_postgres::PgRow,
    tenant_slug: &str,
) -> Result<PolicyProposalResponse, ApiError> {
    Ok(policy_proposal_from_row(row)
        .map_err(ApiError::Database)?
        .into_response(tenant_slug))
}

fn policy_proposal_from_row(
    row: sqlx_postgres::PgRow,
) -> Result<PolicyProposalRow, sqlx::error::Error> {
    Ok(PolicyProposalRow {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        policy_yaml: row.try_get("policy_yaml")?,
        checksum_sha256: row.try_get("checksum_sha256")?,
        description: row.try_get("description")?,
        status: row.try_get("status")?,
        base_active_policy_version: row.try_get("base_active_policy_version")?,
        proposed_policy_version: row.try_get("proposed_policy_version")?,
        preview: row.try_get("preview")?,
        required_approvals: row.try_get("required_approvals")?,
        approved_by: row.try_get("approved_by")?,
        approval_notes: row.try_get("approval_notes")?,
        impact: row.try_get("impact")?,
        impact_attached_by: row.try_get("impact_attached_by")?,
        impact_attached_at: row.try_get("impact_attached_at")?,
        deployed_policy_version: row.try_get("deployed_policy_version")?,
        deployment_id: row.try_get("deployment_id")?,
        submitted_by: row.try_get("submitted_by")?,
        reviewed_by: row.try_get("reviewed_by")?,
        review_note: row.try_get("review_note")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        reviewed_at: row.try_get("reviewed_at")?,
        deployed_at: row.try_get("deployed_at")?,
    })
}

impl PolicyProposalRow {
    fn into_response(self, tenant_slug: &str) -> PolicyProposalResponse {
        let approval_count = self.approved_by.len() as i32;
        let approvals_remaining = (self.required_approvals - approval_count).max(0);
        PolicyProposalResponse {
            id: self.id,
            tenant_id: self.tenant_id,
            tenant_slug: tenant_slug.to_string(),
            policy_yaml: self.policy_yaml,
            checksum_sha256: self.checksum_sha256,
            description: self.description,
            status: self.status,
            base_active_policy_version: self.base_active_policy_version,
            proposed_policy_version: self.proposed_policy_version,
            preview: self.preview,
            required_approvals: self.required_approvals,
            approval_count,
            approvals_remaining,
            approved_by: self.approved_by,
            approval_notes: self.approval_notes,
            impact: self.impact,
            impact_attached_by: self.impact_attached_by,
            impact_attached_at: self.impact_attached_at,
            deployed_policy_version: self.deployed_policy_version,
            deployment_id: self.deployment_id,
            submitted_by: self.submitted_by,
            reviewed_by: self.reviewed_by,
            review_note: self.review_note,
            created_at: self.created_at,
            updated_at: self.updated_at,
            reviewed_at: self.reviewed_at,
            deployed_at: self.deployed_at,
        }
    }
}

fn ensure_policy_author(auth: &AuthenticatedTenant) -> Result<(), ApiError> {
    if auth.role == "viewer" {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

fn ensure_policy_deployer(auth: &AuthenticatedTenant) -> Result<(), ApiError> {
    if auth.role == "admin" || auth.role == "owner" {
        return Ok(());
    }
    Err(ApiError::Forbidden)
}

fn append_policy_proposal_approval_note(
    existing: &serde_json::Value,
    actor_id: &str,
    note: Option<&str>,
) -> serde_json::Value {
    let mut notes = existing.as_object().cloned().unwrap_or_default();
    notes.insert(
        actor_id.to_string(),
        serde_json::json!({
            "note": note,
            "recordedAt": Utc::now().to_rfc3339(),
        }),
    );
    serde_json::Value::Object(notes)
}

struct VerifiedPolicyProposalSimulationReceipt {
    signed_receipt: serde_json::Value,
    signed_receipt_sha256: String,
    public_key: String,
    receipt_id: Option<String>,
    endpoint_id: Option<String>,
    policy_epoch: Option<u64>,
    impact_id: Option<String>,
    graph_slice_id: Option<String>,
    evidence_keys: Vec<String>,
    evidence_value_hashes: BTreeMap<String, String>,
}

impl VerifiedPolicyProposalSimulationReceipt {
    fn to_impact_receipt_summary(&self) -> serde_json::Value {
        serde_json::json!({
            "receiptId": self.receipt_id,
            "signedReceiptSha256": self.signed_receipt_sha256,
            "publicKey": self.public_key,
            "receiptFamily": POLICY_PROPOSAL_SIMULATION_RECEIPT_FAMILY,
            "ruleId": POLICY_PROPOSAL_SIMULATION_RULE_ID,
            "endpointId": self.endpoint_id,
            "policyEpoch": self.policy_epoch,
            "impactId": self.impact_id,
            "graphSliceId": self.graph_slice_id,
            "evidenceKeys": self.evidence_keys,
            "signedReceipt": self.signed_receipt,
        })
    }
}

fn validate_policy_proposal_impact(
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

fn validate_policy_proposal_simulation_receipt(
    simulation_receipt: Option<serde_json::Value>,
    simulation_receipt_public_key: Option<String>,
) -> Result<Option<VerifiedPolicyProposalSimulationReceipt>, ApiError> {
    let Some(signed_receipt_value) = simulation_receipt else {
        if simulation_receipt_public_key.is_some() {
            return Err(ApiError::BadRequest(
                "simulation_receipt is required when simulation_receipt_public_key is provided"
                    .to_string(),
            ));
        }
        return Ok(None);
    };
    let public_key_hex = simulation_receipt_public_key
        .map(|value| require_non_empty_policy_impact_field("simulation_receipt_public_key", value))
        .transpose()?
        .ok_or_else(|| {
            ApiError::BadRequest(
                "simulation_receipt_public_key is required when simulation_receipt is provided"
                    .to_string(),
            )
        })?;
    validate_policy_proposal_simulation_receipt_value(signed_receipt_value, public_key_hex)
        .map(Some)
}

fn validate_policy_proposal_simulation_receipt_attachments(
    attachments: Vec<PolicyProposalSimulationReceiptAttachment>,
) -> Result<Vec<VerifiedPolicyProposalSimulationReceipt>, ApiError> {
    if attachments.len() > MAX_POLICY_PROPOSAL_SIMULATION_RECEIPTS {
        return Err(ApiError::BadRequest(format!(
            "simulation_receipts must include no more than {MAX_POLICY_PROPOSAL_SIMULATION_RECEIPTS} receipts"
        )));
    }

    attachments
        .into_iter()
        .enumerate()
        .map(|(index, attachment)| {
            let expected_receipt_id = attachment
                .receipt_id
                .map(|value| {
                    require_non_empty_policy_impact_field(
                        &format!("simulation_receipts[{index}].receipt_id"),
                        value,
                    )
                })
                .transpose()?;
            let expected_receipt_sha256 = attachment
                .receipt_sha256
                .map(|value| {
                    normalize_policy_impact_sha256(
                        &format!("simulation_receipts[{index}].receipt_sha256"),
                        &value,
                    )
                })
                .transpose()?;
            let public_key = require_non_empty_policy_impact_field(
                &format!("simulation_receipts[{index}].public_key"),
                attachment.public_key,
            )?;
            let verified =
                validate_policy_proposal_simulation_receipt_value(attachment.receipt, public_key)?;
            validate_policy_proposal_simulation_receipt_expectations(
                &verified,
                expected_receipt_id.as_deref(),
                expected_receipt_sha256.as_deref(),
            )?;
            Ok(verified)
        })
        .collect()
}

fn validate_policy_proposal_simulation_receipt_value(
    signed_receipt_value: serde_json::Value,
    public_key_hex: String,
) -> Result<VerifiedPolicyProposalSimulationReceipt, ApiError> {
    let public_key = PublicKey::from_hex(&public_key_hex).map_err(|_| {
        ApiError::BadRequest(
            "simulation_receipt_public_key must be a valid Ed25519 public key hex".to_string(),
        )
    })?;
    let canonical_signed_receipt = canonicalize_json(&signed_receipt_value).map_err(|err| {
        ApiError::BadRequest(format!(
            "simulation_receipt is not canonicalizable JSON: {err}"
        ))
    })?;
    if canonical_signed_receipt.len() > MAX_POLICY_PROPOSAL_SIMULATION_RECEIPT_BYTES {
        return Err(ApiError::BadRequest(format!(
            "simulation_receipt must be no larger than {MAX_POLICY_PROPOSAL_SIMULATION_RECEIPT_BYTES} bytes"
        )));
    }
    let signed_receipt: SignedReceipt = serde_json::from_value(signed_receipt_value.clone())
        .map_err(|err| ApiError::BadRequest(format!("invalid simulation_receipt: {err}")))?;
    let verification = signed_receipt.verify(&PublicKeySet::new(public_key.clone()));
    if !verification.valid {
        return Err(ApiError::BadRequest(format!(
            "simulation_receipt failed verification: {}",
            verification.errors.join("; ")
        )));
    }

    let endpoint_decision = signed_receipt
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("endpointDecision"))
        .ok_or_else(|| {
            ApiError::BadRequest(
                "simulation_receipt must include receipt.metadata.endpointDecision".to_string(),
            )
        })?;
    let receipt_family = required_endpoint_decision_string(endpoint_decision, "/receiptFamily")?;
    if receipt_family != POLICY_PROPOSAL_SIMULATION_RECEIPT_FAMILY {
        return Err(ApiError::BadRequest(
            "simulation_receipt endpointDecision.receiptFamily must be simulation".to_string(),
        ));
    }
    let rule_id = required_endpoint_decision_string(endpoint_decision, "/decision/ruleId")?;
    if rule_id != POLICY_PROPOSAL_SIMULATION_RULE_ID {
        return Err(ApiError::BadRequest(
            "simulation_receipt endpointDecision.decision.ruleId must be endpoint.policy_event_impact"
                .to_string(),
        ));
    }
    let process_node_id =
        required_endpoint_decision_string(endpoint_decision, "/graph/processNodeId")?;
    if process_node_id != POLICY_PROPOSAL_SIMULATION_PROCESS_NODE_ID {
        return Err(ApiError::BadRequest(
            "simulation_receipt endpointDecision.graph.processNodeId must be policy_event_stream"
                .to_string(),
        ));
    }

    if let Some(signer_public_key) = endpoint_decision
        .pointer("/signer/signerPublicKey")
        .and_then(serde_json::Value::as_str)
    {
        let metadata_public_key = PublicKey::from_hex(signer_public_key).map_err(|_| {
            ApiError::BadRequest(
                "simulation_receipt endpointDecision.signer.signerPublicKey must be a valid Ed25519 public key hex"
                    .to_string(),
            )
        })?;
        if metadata_public_key.to_hex() != public_key.to_hex() {
            return Err(ApiError::BadRequest(
                "simulation_receipt endpointDecision.signer.signerPublicKey must match simulation_receipt_public_key"
                    .to_string(),
            ));
        }
    }

    let evidence_value_hashes = endpoint_decision_evidence_value_hashes(endpoint_decision)?;
    let evidence_keys = evidence_value_hashes
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    for required_key in [
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
        if !evidence_keys.contains(required_key) {
            return Err(ApiError::BadRequest(format!(
                "simulation_receipt endpointDecision.evidence must include {required_key}"
            )));
        }
    }

    let signed_receipt_sha256 = sha256(canonical_signed_receipt.as_bytes()).to_hex();
    Ok(VerifiedPolicyProposalSimulationReceipt {
        signed_receipt: signed_receipt_value,
        signed_receipt_sha256,
        public_key: public_key.to_hex(),
        receipt_id: signed_receipt.receipt.receipt_id.clone(),
        endpoint_id: endpoint_decision
            .pointer("/actor/endpointId")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        policy_epoch: endpoint_decision
            .pointer("/policy/policyEpoch")
            .and_then(serde_json::Value::as_u64),
        impact_id: endpoint_decision
            .pointer("/decision/findingId")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        graph_slice_id: endpoint_decision
            .pointer("/graph/graphSliceId")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        evidence_value_hashes,
        evidence_keys: evidence_keys.into_iter().collect(),
    })
}

fn validate_policy_proposal_simulation_receipt_expectations(
    verified: &VerifiedPolicyProposalSimulationReceipt,
    expected_receipt_id: Option<&str>,
    expected_receipt_sha256: Option<&str>,
) -> Result<(), ApiError> {
    if let (Some(expected), Some(actual)) = (expected_receipt_id, verified.receipt_id.as_deref()) {
        if expected != actual {
            return Err(ApiError::BadRequest(
                "simulation_receipts receipt_id must match the signed receipt receipt_id"
                    .to_string(),
            ));
        }
    }
    if let Some(expected) = expected_receipt_sha256 {
        if expected != verified.signed_receipt_sha256 {
            return Err(ApiError::BadRequest(
                "simulation_receipts receipt_sha256 must match the canonical signed receipt hash"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_unique_policy_proposal_simulation_receipts(
    single_receipt: Option<&VerifiedPolicyProposalSimulationReceipt>,
    batch_receipts: &[VerifiedPolicyProposalSimulationReceipt],
) -> Result<(), ApiError> {
    let mut seen = BTreeSet::new();
    for receipt in single_receipt.into_iter().chain(batch_receipts.iter()) {
        if !seen.insert(receipt.signed_receipt_sha256.as_str()) {
            return Err(ApiError::BadRequest(
                "simulation receipts must not repeat the same signed receipt hash".to_string(),
            ));
        }
    }
    Ok(())
}

fn policy_proposal_simulation_receipt_summaries(
    single_receipt: &Option<VerifiedPolicyProposalSimulationReceipt>,
    batch_receipts: &[VerifiedPolicyProposalSimulationReceipt],
) -> Vec<serde_json::Value> {
    single_receipt
        .iter()
        .chain(batch_receipts.iter())
        .map(VerifiedPolicyProposalSimulationReceipt::to_impact_receipt_summary)
        .collect()
}

fn distinct_policy_proposal_receipt_values<'a>(
    receipts: impl Iterator<Item = &'a serde_json::Value>,
    field: &str,
) -> Vec<String> {
    receipts
        .filter_map(|receipt| receipt.get(field))
        .filter_map(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn required_endpoint_decision_string<'a>(
    endpoint_decision: &'a serde_json::Value,
    pointer: &str,
) -> Result<&'a str, ApiError> {
    endpoint_decision
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ApiError::BadRequest(format!(
                "simulation_receipt endpointDecision{pointer} must be a non-empty string"
            ))
        })
}

fn endpoint_decision_evidence_keys(
    endpoint_decision: &serde_json::Value,
) -> Result<BTreeSet<String>, ApiError> {
    Ok(endpoint_decision_evidence_value_hashes(endpoint_decision)?
        .keys()
        .cloned()
        .collect())
}

fn endpoint_decision_evidence_value_hashes(
    endpoint_decision: &serde_json::Value,
) -> Result<BTreeMap<String, String>, ApiError> {
    let evidence = endpoint_decision
        .get("evidence")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            ApiError::BadRequest(
                "simulation_receipt endpointDecision.evidence must be an array".to_string(),
            )
        })?;
    let mut hashes = BTreeMap::new();
    for item in evidence {
        let key = item
            .get("key")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                ApiError::BadRequest(
                    "simulation_receipt endpointDecision.evidence entries must include a non-empty key"
                        .to_string(),
                )
            })?;
        let value_hash = item
            .get("valueHash")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                ApiError::BadRequest(
                    "simulation_receipt endpointDecision.evidence entries must include a non-empty valueHash"
                        .to_string(),
                )
            })?;
        hashes.insert(key.to_string(), value_hash.to_string());
    }
    Ok(hashes)
}

fn require_non_empty_policy_impact_field(field: &str, value: String) -> Result<String, ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest(format!("{field} must not be empty")));
    }
    Ok(trimmed.to_string())
}

fn validate_non_negative_policy_impact_count(field: &str, value: i64) -> Result<(), ApiError> {
    if value < 0 {
        return Err(ApiError::BadRequest(format!(
            "{field} must be greater than or equal to 0"
        )));
    }
    Ok(())
}

fn normalize_policy_impact_sha256(field: &str, value: &str) -> Result<String, ApiError> {
    let trimmed = value.trim();
    let digest = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if digest.len() != 64 || !digest.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest(format!(
            "{field} must be a SHA-256 hex digest"
        )));
    }
    Ok(digest.to_ascii_lowercase())
}

async fn build_policy_proposal_preview(
    db: &PgPool,
    tenant_id: Uuid,
    candidate: &policy_distribution::ActiveTenantPolicy,
    active_policy: Option<&policy_distribution::ActiveTenantPolicy>,
) -> Result<serde_json::Value, ApiError> {
    let distribution_policy_yaml =
        policy_distribution::distribution_policy_yaml(candidate).map_err(ApiError::Internal)?;
    let distribution_policy_sha256 =
        policy_distribution::policy_yaml_checksum_sha256(&distribution_policy_yaml);
    let proposed_value = serde_yaml::from_str::<serde_yaml::Value>(&candidate.policy_yaml)
        .map_err(|err| {
            ApiError::Internal(format!("proposal candidate policy is invalid YAML: {err}"))
        })?;
    let base_value = match active_policy {
        Some(policy) => Some(
            serde_yaml::from_str::<serde_yaml::Value>(&policy.policy_yaml).map_err(|err| {
                ApiError::Internal(format!("active tenant policy is invalid YAML: {err}"))
            })?,
        ),
        None => None,
    };
    let change_summary = top_level_policy_change_summary(base_value.as_ref(), &proposed_value);
    let fleet_history_impact = build_policy_proposal_fleet_history_impact(db, tenant_id).await?;
    let fleet_rule_diff_validation = build_policy_proposal_fleet_rule_diff_validation_plan(
        db,
        tenant_id,
        candidate,
        active_policy,
    )
    .await?;
    let simulation_status = fleet_history_impact
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");

    Ok(serde_json::json!({
        "baseActivePolicyVersion": active_policy.map(|policy| policy.version).unwrap_or(0),
        "basePolicySha256": active_policy.map(|policy| policy.checksum_sha256.as_str()),
        "proposedPolicyVersion": candidate.version,
        "proposedPolicySha256": candidate.checksum_sha256,
        "distributionPolicySha256": distribution_policy_sha256,
        "distributionPolicyEpoch": candidate.version,
        "topLevelChanges": change_summary,
        "simulationStatus": simulation_status,
        "simulationReason": "control-plane estimate from recent fleet hunt history; exact endpoint policy-event replay receipts are still required for rule-diff proof",
        "fleetHistoryImpact": fleet_history_impact,
        "fleetRuleDiffValidation": fleet_rule_diff_validation
    }))
}

async fn build_policy_proposal_fleet_history_impact(
    db: &PgPool,
    tenant_id: Uuid,
) -> Result<serde_json::Value, ApiError> {
    let since = Utc::now() - chrono::Duration::hours(POLICY_PROPOSAL_HISTORY_LOOKBACK_HOURS);
    let rows = sqlx::query::query(
        r#"SELECT verdict,
                  action_type,
                  endpoint_agent_id,
                  runtime_agent_id,
                  principal_id,
                  session_id,
                  detection_ids
           FROM hunt_events
           WHERE tenant_id = $1
             AND timestamp >= $2
           ORDER BY timestamp DESC, event_id DESC
           LIMIT $3"#,
    )
    .bind(tenant_id)
    .bind(since)
    .bind(POLICY_PROPOSAL_HISTORY_LIMIT)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    let mut verdict_counts = BTreeMap::<String, i64>::new();
    let mut action_type_counts = BTreeMap::<String, i64>::new();
    let mut detection_counts = BTreeMap::<String, i64>::new();
    let mut affected_identities = BTreeSet::<String>::new();
    let mut affected_tools = BTreeSet::<String>::new();
    let mut affected_endpoints = BTreeSet::<String>::new();
    let mut candidate_breakage_count = 0_i64;
    let mut blocking_event_count = 0_i64;

    for row in rows {
        let verdict: String = row.try_get("verdict").map_err(ApiError::Database)?;
        let normalized_verdict = normalize_policy_proposal_history_verdict(&verdict);
        *verdict_counts
            .entry(normalized_verdict.to_string())
            .or_insert(0) += 1;
        match normalized_verdict {
            "allow" | "warn" => candidate_breakage_count += 1,
            "block" => blocking_event_count += 1,
            _ => {}
        }

        let action_type = row
            .try_get::<Option<String>, _>("action_type")
            .map_err(ApiError::Database)?
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "unknown".to_string());
        *action_type_counts.entry(action_type.clone()).or_insert(0) += 1;
        affected_tools.insert(format!("action:{action_type}"));

        if let Some(endpoint_id) = row
            .try_get::<Option<String>, _>("endpoint_agent_id")
            .map_err(ApiError::Database)?
            .filter(|value| !value.trim().is_empty())
        {
            affected_endpoints.insert(endpoint_id);
        }
        if let Some(runtime_id) = row
            .try_get::<Option<String>, _>("runtime_agent_id")
            .map_err(ApiError::Database)?
            .filter(|value| !value.trim().is_empty())
        {
            affected_tools.insert(format!("runtime:{runtime_id}"));
        }
        if let Some(principal_id) = row
            .try_get::<Option<String>, _>("principal_id")
            .map_err(ApiError::Database)?
            .filter(|value| !value.trim().is_empty())
        {
            affected_identities.insert(format!("principal:{principal_id}"));
        }
        if let Some(session_id) = row
            .try_get::<Option<String>, _>("session_id")
            .map_err(ApiError::Database)?
            .filter(|value| !value.trim().is_empty())
        {
            affected_identities.insert(format!("session:{session_id}"));
        }

        let detection_ids: Vec<String> =
            row.try_get("detection_ids").map_err(ApiError::Database)?;
        for detection_id in detection_ids
            .into_iter()
            .filter(|value| !value.trim().is_empty())
        {
            *detection_counts.entry(detection_id).or_insert(0) += 1;
        }
    }

    let events_sampled = verdict_counts.values().sum::<i64>();
    let status = if events_sampled == 0 {
        "no_fleet_history"
    } else {
        "estimated_from_fleet_history"
    };
    let developer_breakage_score = if events_sampled == 0 {
        0
    } else {
        ((candidate_breakage_count * 100) / events_sampled).clamp(0, 100)
    };
    let recommendation = if events_sampled == 0 {
        "collect_history"
    } else if candidate_breakage_count == 0 {
        "approve_with_observation"
    } else if developer_breakage_score >= 50 {
        "simulate_on_endpoints"
    } else {
        "stage_with_audit"
    };

    let mut impact = serde_json::json!({
        "schemaVersion": 1,
        "source": "control_api_hunt_events",
        "status": status,
        "lookbackHours": POLICY_PROPOSAL_HISTORY_LOOKBACK_HOURS,
        "selectionLimit": POLICY_PROPOSAL_HISTORY_LIMIT,
        "eventsSampled": events_sampled,
        "candidateBreakageCount": candidate_breakage_count,
        "blockingEventCount": blocking_event_count,
        "developerBreakageScore": developer_breakage_score,
        "affectedIdentityCount": affected_identities.len(),
        "affectedToolCount": affected_tools.len(),
        "affectedEndpointCount": affected_endpoints.len(),
        "verdictCounts": verdict_counts,
        "topActionTypes": top_policy_proposal_history_counts(&action_type_counts, 5),
        "topDetectionIds": top_policy_proposal_history_counts(&detection_counts, 5),
        "recommendation": recommendation,
        "limitations": "estimated from normalized hunt_events only; exact proposal impact still requires endpoint policy-event history replay"
    });
    let hash_input = serde_json::to_string(&impact)
        .map_err(|err| ApiError::Internal(format!("serialize fleet history impact: {err}")))?;
    impact["historySha256"] = serde_json::Value::String(
        policy_distribution::policy_yaml_checksum_sha256(&hash_input),
    );

    Ok(impact)
}

struct PolicyProposalFleetRuleDiffEndpointSelection {
    endpoint_agent_id: String,
    event_count: i64,
    candidate_breakage_count: i64,
    blocking_event_count: i64,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    event_ids: Vec<String>,
    action_type_counts: BTreeMap<String, i64>,
    detection_counts: BTreeMap<String, i64>,
    principal_ids: BTreeSet<String>,
    runtime_agent_ids: BTreeSet<String>,
    session_ids: BTreeSet<String>,
}

impl PolicyProposalFleetRuleDiffEndpointSelection {
    fn new(endpoint_agent_id: String, timestamp: DateTime<Utc>) -> Self {
        Self {
            endpoint_agent_id,
            event_count: 0,
            candidate_breakage_count: 0,
            blocking_event_count: 0,
            first_seen: timestamp,
            last_seen: timestamp,
            event_ids: Vec::new(),
            action_type_counts: BTreeMap::new(),
            detection_counts: BTreeMap::new(),
            principal_ids: BTreeSet::new(),
            runtime_agent_ids: BTreeSet::new(),
            session_ids: BTreeSet::new(),
        }
    }

    fn observe(
        &mut self,
        event_id: String,
        timestamp: DateTime<Utc>,
        verdict: &str,
        action_type: Option<String>,
        runtime_agent_id: Option<String>,
        principal_id: Option<String>,
        session_id: Option<String>,
        detection_ids: Vec<String>,
    ) {
        self.event_count += 1;
        if timestamp < self.first_seen {
            self.first_seen = timestamp;
        }
        if timestamp > self.last_seen {
            self.last_seen = timestamp;
        }
        if self.event_ids.len() < POLICY_PROPOSAL_FLEET_VALIDATION_EVENT_ID_LIMIT {
            self.event_ids.push(event_id);
        }

        match normalize_policy_proposal_history_verdict(verdict) {
            "allow" | "warn" => self.candidate_breakage_count += 1,
            "block" => self.blocking_event_count += 1,
            _ => {}
        }

        if let Some(action_type) = action_type.filter(|value| !value.trim().is_empty()) {
            *self.action_type_counts.entry(action_type).or_insert(0) += 1;
        }
        if let Some(runtime_agent_id) = runtime_agent_id.filter(|value| !value.trim().is_empty()) {
            self.runtime_agent_ids.insert(runtime_agent_id);
        }
        if let Some(principal_id) = principal_id.filter(|value| !value.trim().is_empty()) {
            self.principal_ids.insert(principal_id);
        }
        if let Some(session_id) = session_id.filter(|value| !value.trim().is_empty()) {
            self.session_ids.insert(session_id);
        }
        for detection_id in detection_ids
            .into_iter()
            .filter(|value| !value.trim().is_empty())
        {
            *self.detection_counts.entry(detection_id).or_insert(0) += 1;
        }
    }
}

async fn build_policy_proposal_fleet_rule_diff_validation_plan(
    db: &PgPool,
    tenant_id: Uuid,
    candidate: &policy_distribution::ActiveTenantPolicy,
    active_policy: Option<&policy_distribution::ActiveTenantPolicy>,
) -> Result<serde_json::Value, ApiError> {
    let since = Utc::now() - chrono::Duration::hours(POLICY_PROPOSAL_HISTORY_LOOKBACK_HOURS);
    let rows = sqlx::query::query(
        r#"SELECT event_id,
                  timestamp,
                  verdict,
                  action_type,
                  endpoint_agent_id,
                  runtime_agent_id,
                  principal_id,
                  session_id,
                  detection_ids
           FROM hunt_events
           WHERE tenant_id = $1
             AND timestamp >= $2
             AND endpoint_agent_id IS NOT NULL
           ORDER BY timestamp DESC, event_id DESC
           LIMIT $3"#,
    )
    .bind(tenant_id)
    .bind(since)
    .bind(POLICY_PROPOSAL_HISTORY_LIMIT)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    let mut endpoints = BTreeMap::<String, PolicyProposalFleetRuleDiffEndpointSelection>::new();
    for row in rows {
        let endpoint_agent_id = row
            .try_get::<Option<String>, _>("endpoint_agent_id")
            .map_err(ApiError::Database)?
            .filter(|value| !value.trim().is_empty());
        let Some(endpoint_agent_id) = endpoint_agent_id else {
            continue;
        };
        let timestamp: DateTime<Utc> = row.try_get("timestamp").map_err(ApiError::Database)?;
        let event_id: String = row.try_get("event_id").map_err(ApiError::Database)?;
        let verdict: String = row.try_get("verdict").map_err(ApiError::Database)?;
        let action_type = row
            .try_get::<Option<String>, _>("action_type")
            .map_err(ApiError::Database)?;
        let runtime_agent_id = row
            .try_get::<Option<String>, _>("runtime_agent_id")
            .map_err(ApiError::Database)?;
        let principal_id = row
            .try_get::<Option<String>, _>("principal_id")
            .map_err(ApiError::Database)?;
        let session_id = row
            .try_get::<Option<String>, _>("session_id")
            .map_err(ApiError::Database)?;
        let detection_ids: Vec<String> =
            row.try_get("detection_ids").map_err(ApiError::Database)?;
        endpoints
            .entry(endpoint_agent_id.clone())
            .or_insert_with(|| {
                PolicyProposalFleetRuleDiffEndpointSelection::new(
                    endpoint_agent_id.clone(),
                    timestamp,
                )
            })
            .observe(
                event_id,
                timestamp,
                &verdict,
                action_type,
                runtime_agent_id,
                principal_id,
                session_id,
                detection_ids,
            );
    }

    let mut endpoint_selections = endpoints.into_values().collect::<Vec<_>>();
    endpoint_selections.sort_by(|left, right| {
        right
            .candidate_breakage_count
            .cmp(&left.candidate_breakage_count)
            .then_with(|| right.event_count.cmp(&left.event_count))
            .then_with(|| left.endpoint_agent_id.cmp(&right.endpoint_agent_id))
    });
    endpoint_selections.truncate(POLICY_PROPOSAL_FLEET_VALIDATION_ENDPOINT_LIMIT);

    let endpoint_requests = endpoint_selections
        .iter()
        .map(|selection| {
            serde_json::json!({
                "endpointAgentId": selection.endpoint_agent_id,
                "eventCount": selection.event_count,
                "candidateBreakageCount": selection.candidate_breakage_count,
                "blockingEventCount": selection.blocking_event_count,
                "firstSeen": selection.first_seen,
                "lastSeen": selection.last_seen,
                "sampleEventIds": selection.event_ids,
                "topActionTypes": top_policy_proposal_history_counts(&selection.action_type_counts, 5),
                "topDetectionIds": top_policy_proposal_history_counts(&selection.detection_counts, 5),
                "principalIds": selection.principal_ids,
                "runtimeAgentIds": selection.runtime_agent_ids,
                "sessionIds": selection.session_ids,
                "request": {
                    "method": "POST",
                    "path": "/api/v1/agent/edr/policy-events/impact/history",
                    "body": {
                        "since": selection.first_seen,
                        "until": selection.last_seen,
                        "limit": selection.event_count.min(POLICY_PROPOSAL_HISTORY_LIMIT),
                        "agentId": selection.endpoint_agent_id,
                        "trackPosture": true,
                        "validationWindowSeconds": 3600,
                        "proposedPolicyYaml": candidate.policy_yaml,
                    }
                },
                "expectedReceipt": {
                    "receiptFamily": POLICY_PROPOSAL_SIMULATION_RECEIPT_FAMILY,
                    "ruleId": POLICY_PROPOSAL_SIMULATION_RULE_ID,
                    "graphProcessNodeId": POLICY_PROPOSAL_SIMULATION_PROCESS_NODE_ID,
                    "requiredEvidenceKeys": [
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
                        "trackPosture"
                    ]
                }
            })
        })
        .collect::<Vec<_>>();
    let selected_event_count = endpoint_selections
        .iter()
        .map(|selection| selection.event_count)
        .sum::<i64>();
    let status = if endpoint_requests.is_empty() {
        "no_endpoint_history"
    } else {
        "ready_for_endpoint_receipt_collection"
    };
    let mut plan = serde_json::json!({
        "schemaVersion": 1,
        "source": "control_api_hunt_events",
        "status": status,
        "lookbackHours": POLICY_PROPOSAL_HISTORY_LOOKBACK_HOURS,
        "selectionLimit": POLICY_PROPOSAL_HISTORY_LIMIT,
        "endpointLimit": POLICY_PROPOSAL_FLEET_VALIDATION_ENDPOINT_LIMIT,
        "selectedEndpointCount": endpoint_requests.len(),
        "selectedEventCount": selected_event_count,
        "currentPolicyVersion": active_policy.map(|policy| policy.version).unwrap_or(0),
        "currentPolicySha256": active_policy.map(|policy| policy.checksum_sha256.as_str()),
        "proposedPolicyVersion": candidate.version,
        "proposedPolicySha256": candidate.checksum_sha256,
        "receiptAttachmentField": "simulation_receipts",
        "endpointRequests": endpoint_requests,
        "limitations": "control-plane selection plan only; endpoint agents must execute local history impact replay and return signed receipts"
    });
    let hash_input = serde_json::to_string(&plan)
        .map_err(|err| ApiError::Internal(format!("serialize fleet validation plan: {err}")))?;
    plan["planSha256"] = serde_json::Value::String(
        policy_distribution::policy_yaml_checksum_sha256(&hash_input),
    );
    Ok(plan)
}

fn normalize_policy_proposal_history_verdict(verdict: &str) -> &'static str {
    match verdict.trim().to_ascii_lowercase().as_str() {
        "allow" | "allowed" | "forward" | "forwarded" => "allow",
        "warn" | "warning" => "warn",
        "block" | "blocked" | "deny" | "denied" => "block",
        _ => "other",
    }
}

fn top_policy_proposal_history_counts(
    counts: &BTreeMap<String, i64>,
    limit: usize,
) -> Vec<serde_json::Value> {
    let mut entries = counts.iter().collect::<Vec<_>>();
    entries.sort_by(|(left_key, left_count), (right_key, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_key.cmp(right_key))
    });
    entries
        .into_iter()
        .take(limit)
        .map(|(value, count)| {
            serde_json::json!({
                "value": value,
                "count": count,
            })
        })
        .collect()
}

fn top_level_policy_change_summary(
    base_value: Option<&serde_yaml::Value>,
    proposed_value: &serde_yaml::Value,
) -> serde_json::Value {
    let base_keys = yaml_mapping_keys(base_value);
    let proposed_keys = yaml_mapping_keys(Some(proposed_value));

    let added = sorted_difference(&proposed_keys, &base_keys);
    let removed = sorted_difference(&base_keys, &proposed_keys);
    let common = base_keys
        .intersection(&proposed_keys)
        .cloned()
        .collect::<BTreeSet<_>>();
    let changed = common
        .into_iter()
        .filter(|key| {
            yaml_mapping_value(base_value, key) != yaml_mapping_value(Some(proposed_value), key)
        })
        .collect::<Vec<_>>();
    let unchanged_count = proposed_keys
        .iter()
        .filter(|key| {
            base_keys.contains(*key)
                && yaml_mapping_value(base_value, key)
                    == yaml_mapping_value(Some(proposed_value), key)
        })
        .count();

    serde_json::json!({
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchangedCount": unchanged_count,
    })
}

fn yaml_mapping_keys(value: Option<&serde_yaml::Value>) -> BTreeSet<String> {
    let Some(serde_yaml::Value::Mapping(map)) = value else {
        return BTreeSet::new();
    };
    map.keys().map(yaml_key_label).collect()
}

fn yaml_mapping_value<'a>(
    value: Option<&'a serde_yaml::Value>,
    key_label: &str,
) -> Option<&'a serde_yaml::Value> {
    let Some(serde_yaml::Value::Mapping(map)) = value else {
        return None;
    };
    map.iter()
        .find(|(key, _)| yaml_key_label(key) == key_label)
        .map(|(_, value)| value)
}

fn yaml_key_label(key: &serde_yaml::Value) -> String {
    key.as_str()
        .map(str::to_string)
        .unwrap_or_else(|| serde_yaml::to_string(key).unwrap_or_else(|_| format!("{key:?}")))
}

fn sorted_difference(left: &BTreeSet<String>, right: &BTreeSet<String>) -> Vec<String> {
    left.difference(right).cloned().collect()
}

impl From<policy_distribution::EffectiveAgentPolicy> for PreviewEffectivePolicyResponse {
    fn from(policy: policy_distribution::EffectiveAgentPolicy) -> Self {
        Self {
            agent_id: policy.agent_id,
            principal_id: policy.principal_id,
            lifecycle_state: policy.lifecycle_state,
            liveness_state: policy.liveness_state,
            policy_epoch: policy.policy_epoch,
            compiled_policy_yaml: policy.policy_yaml,
            compiled_policy_sha256: policy.checksum_sha256,
            source_attachments: policy
                .source_attachments
                .into_iter()
                .map(PreviewPolicyAttachmentResponse::from)
                .collect(),
            applied_overlays: policy.applied_overlays,
        }
    }
}

impl From<policy_distribution::EffectivePolicyAttachment> for PreviewPolicyAttachmentResponse {
    fn from(attachment: policy_distribution::EffectivePolicyAttachment) -> Self {
        Self {
            attachment_id: attachment.attachment_id,
            target_kind: attachment.target_kind,
            target_id: attachment.target_id,
            priority: attachment.priority,
            policy_ref: attachment.policy_ref,
            checksum_sha256: attachment.checksum_sha256,
        }
    }
}

fn policy_preview_error(err: String) -> ApiError {
    if err.contains("invalid policy YAML") || err.contains("policy YAML root must be a mapping") {
        return ApiError::BadRequest(err);
    }
    if err.contains("unresolved policy_ref") {
        return ApiError::Conflict(err);
    }
    ApiError::Internal(err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_subject_uses_tenant_prefix_contract() {
        assert_eq!(
            policy_distribution::policy_update_subject("acme"),
            "tenant-acme.clawdstrike.policy.update"
        );
    }

    #[test]
    fn policy_sync_bucket_matches_agent_contract() {
        assert_eq!(
            policy_distribution::policy_sync_bucket("tenant-acme.clawdstrike", "agent-123"),
            "tenant-acme-clawdstrike-policy-sync-agent-123"
        );
    }

    #[test]
    fn policy_sync_key_is_stable() {
        assert_eq!(policy_distribution::POLICY_SYNC_KEY, "policy.yaml");
    }
}
