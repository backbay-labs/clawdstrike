//! Fleet response-action routes and delivery ledger helpers.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use clawdstrike_policy_event::edr::{EndpointDecisionReceipt, EndpointDecisionReceiptFamily};
use hush_core::receipt::PublicKeySet;
use hush_core::{canonicalize_json, sha256, PublicKey, SignedReceipt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::row::Row;
use sqlx::transaction::Transaction;
use uuid::Uuid;

use crate::auth::AuthenticatedTenant;
use crate::error::ApiError;
use crate::models::delegation_graph::RevokeGrantRequest;
use crate::services::delegation_graph as delegation_graph_service;
use crate::services::principal_resolution;
use crate::services::tenant_provisioner::tenant_subject_prefix;
use crate::state::AppState;

const ACK_DEADLINE_MINUTES: i64 = 10;
const ACTION_TYPE_MAX_BYTES: usize = 64;
const TARGET_KIND_MAX_BYTES: usize = 64;
const ACTION_TARGET_ID_MAX_BYTES: usize = 256;
const ACTION_REASON_MAX_BYTES: usize = 2048;
const ACTION_PAYLOAD_MAX_BYTES: usize = 65_536;
const ACK_STATUS_MAX_BYTES: usize = 64;
const ACK_TARGET_ID_MAX_BYTES: usize = 256;
const ACK_TOKEN_MAX_BYTES: usize = 1024;
const ACK_MESSAGE_MAX_BYTES: usize = 2048;
const ACK_RESULTING_STATE_MAX_BYTES: usize = 256;
const ACK_RAW_PAYLOAD_MAX_BYTES: usize = 65_536;
const ACK_SIGNED_RECEIPT_MAX_BYTES: usize = 256 * 1024;
const ACK_OBSERVED_AT_FUTURE_SKEW_SECONDS: i64 = 300;
const ACK_OBSERVED_AT_MAX_AGE_SECONDS: i64 = 3600;
const RESPONSE_TARGET_KIND_ALLOWLIST: &str =
    "endpoint, runtime, session, principal, grant, swarm, project";
const RESPONSE_ACTION_TYPE_ALLOWLIST: &str = "transition_posture, request_policy_reload, \
terminate_session, kill_switch, quarantine_principal, revoke_grant, revoke_principal, \
policy_rule_diff_validation";
const ACK_STATUS_ALLOWLIST: &str = "acknowledged, rejected, failed, expired, rolled_back";

mod access;
mod ack;
mod create;
mod delivery;
mod dto;
mod execute;
mod fetch;
mod publish;

pub(crate) use access::*;
pub(crate) use ack::*;
pub(crate) use create::*;
pub(crate) use delivery::*;
pub(crate) use dto::*;
pub use dto::{CreateResponseActionRequest, ResponseTargetInput};
pub(crate) use execute::*;
pub(crate) use fetch::*;
pub(crate) use publish::*;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/response-actions", post(create_action).get(list_actions))
        .route("/response-actions/{id}", get(get_action))
        .route("/response-actions/{id}/approve", post(approve_action))
        .route("/response-actions/{id}/cancel", post(cancel_action))
        .route("/response-actions/{id}/retry", post(retry_action))
        .route("/response-actions/{id}/acks", post(record_ack))
}

pub fn public_ack_router() -> Router<AppState> {
    Router::new().route("/response-actions/{id}/agent-acks", post(record_agent_ack))
}

async fn create_action(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(input): Json<CreateResponseActionRequest>,
) -> Result<Json<ResponseActionRecord>, ApiError> {
    ensure_write_access(&auth)?;
    let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
    let draft = prepare_create_action(&mut tx, &auth, input).await?;
    let action = insert_action(&mut tx, &auth, draft).await?;
    link_action_to_source_detection(
        &mut tx,
        auth.tenant_id,
        action.id,
        action.source_detection_id,
    )
    .await?;
    tx.commit().await.map_err(ApiError::Database)?;

    Ok(Json(action))
}

pub async fn create_and_publish_internal_action(
    state: &AppState,
    auth: &AuthenticatedTenant,
    input: CreateResponseActionRequest,
) -> Result<ResponseActionDetail, ApiError> {
    ensure_write_access(auth)?;
    let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
    let draft = prepare_create_action(&mut tx, auth, input).await?;
    let action = insert_action(&mut tx, auth, draft).await?;
    link_action_to_source_detection(
        &mut tx,
        auth.tenant_id,
        action.id,
        action.source_detection_id,
    )
    .await?;
    tx.commit().await.map_err(ApiError::Database)?;

    publish_action(state, &auth.slug, auth.tenant_id, action.id, false)
        .await
        .map(|Json(detail)| detail)
}

async fn list_actions(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
) -> Result<Json<Vec<ResponseActionRecord>>, ApiError> {
    let rows = sqlx::query::query(
        r#"SELECT *
           FROM response_actions
           WHERE tenant_id = $1
           ORDER BY requested_at DESC, id DESC"#,
    )
    .bind(auth.tenant_id)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::Database)?;

    let actions = rows
        .into_iter()
        .map(ResponseActionRecord::from_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::Database)?;
    Ok(Json(actions))
}

async fn get_action(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<ResponseActionDetail>, ApiError> {
    let action = fetch_action(&state, auth.tenant_id, id).await?;
    let deliveries = fetch_deliveries(&state, auth.tenant_id, id).await?;
    let acknowledgements = fetch_acks(&state, auth.tenant_id, id).await?;

    Ok(Json(ResponseActionDetail {
        action,
        deliveries,
        acknowledgements,
    }))
}

async fn approve_action(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<ResponseActionDetail>, ApiError> {
    ensure_write_access(&auth)?;
    publish_action(&state, &auth.slug, auth.tenant_id, id, false).await
}

async fn retry_action(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<ResponseActionDetail>, ApiError> {
    ensure_write_access(&auth)?;
    publish_action(&state, &auth.slug, auth.tenant_id, id, true).await
}

async fn cancel_action(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<ResponseActionRecord>, ApiError> {
    ensure_write_access(&auth)?;

    let row = sqlx::query::query(
        r#"UPDATE response_actions
           SET status = 'cancelled',
               updated_at = now()
           WHERE id = $1
             AND tenant_id = $2
             AND status IN ('queued', 'approved', 'published', 'failed')
           RETURNING *"#,
    )
    .bind(id)
    .bind(auth.tenant_id)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

    sqlx::query::query(
        r#"UPDATE response_action_deliveries
           SET status = 'cancelled',
               updated_at = now()
           WHERE action_id = $1
             AND tenant_id = $2
             AND status IN ('queued', 'approved', 'published', 'failed')"#,
    )
    .bind(id)
    .bind(auth.tenant_id)
    .execute(&state.db)
    .await
    .map_err(ApiError::Database)?;

    Ok(Json(
        ResponseActionRecord::from_row(row).map_err(ApiError::Database)?,
    ))
}

async fn record_ack(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(input): Json<RecordResponseAckRequest>,
) -> Result<Json<ResponseActionDetail>, ApiError> {
    ensure_api_key_executor(&auth)?;
    let ack = parse_ack_submission(input)?;

    let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
    let context = match load_ack_context(&mut tx, auth.tenant_id, id, &ack).await? {
        Some(context) => context,
        None => {
            tx.commit().await.map_err(ApiError::Database)?;
            return Err(ApiError::Conflict(
                "acknowledgement window has expired".to_string(),
            ));
        }
    };
    validate_endpoint_ack_signed_receipt(&mut tx, &context, &ack).await?;
    persist_ack_submission(&mut tx, &context, &ack).await?;
    tx.commit().await.map_err(ApiError::Database)?;
    get_action(State(state), auth, Path(id)).await
}

async fn record_agent_ack(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(input): Json<RecordResponseAckRequest>,
) -> Result<Json<RecordAgentAckResponse>, ApiError> {
    let ack = parse_ack_submission(input)?;

    let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
    let tenant_id = load_ack_action_tenant_id(&mut tx, id).await?;
    let context = match load_ack_context(&mut tx, tenant_id, id, &ack).await? {
        Some(context) => context,
        None => {
            tx.commit().await.map_err(ApiError::Database)?;
            return Err(ApiError::Conflict(
                "acknowledgement window has expired".to_string(),
            ));
        }
    };
    validate_endpoint_ack_signed_receipt(&mut tx, &context, &ack).await?;
    persist_ack_submission(&mut tx, &context, &ack).await?;
    tx.commit().await.map_err(ApiError::Database)?;

    Ok(Json(RecordAgentAckResponse {
        accepted: true,
        action_id: id,
        target_kind: ack.target_kind.as_str().to_string(),
        target_id: ack.target_id,
        status: ack.ack_status.to_string(),
        observed_at: ack.observed_at,
    }))
}

#[cfg(test)]
mod tests;
