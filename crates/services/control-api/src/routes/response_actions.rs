//! Fleet response-action routes and delivery ledger helpers.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::row::Row;
use sqlx::transaction::Transaction;
use uuid::Uuid;

use crate::auth::AuthenticatedTenant;
use crate::error::ApiError;
use crate::services::tenant_provisioner::tenant_subject_prefix;
use crate::state::AppState;

const ACK_DEADLINE_MINUTES: i64 = 10;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/response-actions", post(create_action).get(list_actions))
        .route("/response-actions/{id}", get(get_action))
        .route("/response-actions/{id}/approve", post(approve_action))
        .route("/response-actions/{id}/cancel", post(cancel_action))
        .route("/response-actions/{id}/retry", post(retry_action))
        .route("/response-actions/{id}/acks", post(record_ack))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseTargetKind {
    Endpoint,
    Runtime,
    Session,
    Principal,
    Grant,
    Swarm,
    Project,
}

impl ResponseTargetKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Endpoint => "endpoint",
            Self::Runtime => "runtime",
            Self::Session => "session",
            Self::Principal => "principal",
            Self::Grant => "grant",
            Self::Swarm => "swarm",
            Self::Project => "project",
        }
    }

    fn from_str(value: &str) -> Result<Self, ApiError> {
        match value {
            "endpoint" => Ok(Self::Endpoint),
            "runtime" => Ok(Self::Runtime),
            "session" => Ok(Self::Session),
            "principal" => Ok(Self::Principal),
            "grant" => Ok(Self::Grant),
            "swarm" => Ok(Self::Swarm),
            "project" => Ok(Self::Project),
            other => Err(ApiError::BadRequest(format!(
                "unsupported target kind '{other}'"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseActionType {
    TransitionPosture,
    RequestPolicyReload,
    TerminateSession,
    KillSwitch,
    QuarantinePrincipal,
    RevokeGrant,
    RevokePrincipal,
}

impl ResponseActionType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::TransitionPosture => "transition_posture",
            Self::RequestPolicyReload => "request_policy_reload",
            Self::TerminateSession => "terminate_session",
            Self::KillSwitch => "kill_switch",
            Self::QuarantinePrincipal => "quarantine_principal",
            Self::RevokeGrant => "revoke_grant",
            Self::RevokePrincipal => "revoke_principal",
        }
    }

    fn from_str(value: &str) -> Result<Self, ApiError> {
        match value {
            "transition_posture" => Ok(Self::TransitionPosture),
            "request_policy_reload" => Ok(Self::RequestPolicyReload),
            "terminate_session" => Ok(Self::TerminateSession),
            "kill_switch" => Ok(Self::KillSwitch),
            "quarantine_principal" => Ok(Self::QuarantinePrincipal),
            "revoke_grant" => Ok(Self::RevokeGrant),
            "revoke_principal" => Ok(Self::RevokePrincipal),
            other => Err(ApiError::BadRequest(format!(
                "unsupported action type '{other}'"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseTarget {
    pub kind: ResponseTargetKind,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestedBy {
    pub actor_type: String,
    pub actor_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseActionRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub action_type: String,
    pub target: ResponseTarget,
    pub requested_by: RequestedBy,
    pub requested_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub reason: String,
    pub case_id: Option<String>,
    pub source_detection_id: Option<String>,
    pub source_approval_id: Option<Uuid>,
    pub require_acknowledgement: bool,
    pub payload: Value,
    pub status: String,
    pub metadata: Value,
}

impl ResponseActionRecord {
    fn from_row(row: crate::db::PgRow) -> Result<Self, sqlx::Error> {
        let target_kind: String = row.try_get("target_kind")?;
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            action_type: row.try_get("action_type")?,
            target: ResponseTarget {
                kind: ResponseTargetKind::from_str(&target_kind)
                    .map_err(|err| sqlx::Error::Protocol(err.to_string()))?,
                id: row.try_get("target_id")?,
            },
            requested_by: RequestedBy {
                actor_type: row.try_get("requested_by_type")?,
                actor_id: row.try_get("requested_by_id")?,
            },
            requested_at: row.try_get("requested_at")?,
            expires_at: row.try_get("expires_at")?,
            reason: row.try_get("reason")?,
            case_id: row.try_get("case_id")?,
            source_detection_id: row.try_get("source_detection_id")?,
            source_approval_id: row.try_get("source_approval_id")?,
            require_acknowledgement: row.try_get("require_acknowledgement")?,
            payload: row.try_get("payload")?,
            status: row.try_get("status")?,
            metadata: row.try_get("metadata")?,
        })
    }

    fn to_transport_payload(&self) -> Value {
        json!({
            "actionId": self.id,
            "tenantId": self.tenant_id,
            "actionType": self.action_type,
            "target": {
                "kind": self.target.kind.as_str(),
                "id": self.target.id,
            },
            "requestedBy": {
                "actorType": self.requested_by.actor_type,
                "actorId": self.requested_by.actor_id,
            },
            "requestedAt": self.requested_at.to_rfc3339(),
            "expiresAt": self.expires_at.map(|value| value.to_rfc3339()),
            "reason": self.reason,
            "caseId": self.case_id,
            "sourceDetectionId": self.source_detection_id,
            "sourceApprovalId": self.source_approval_id,
            "requireAcknowledgement": self.require_acknowledgement,
            "payload": self.payload,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseActionDelivery {
    pub id: Uuid,
    pub action_id: Uuid,
    pub tenant_id: Uuid,
    pub target_kind: String,
    pub target_id: String,
    pub executor_kind: String,
    pub delivery_subject: Option<String>,
    pub status: String,
    pub attempt_count: i32,
    pub published_at: Option<DateTime<Utc>>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub acknowledgement_deadline: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub metadata: Value,
}

impl ResponseActionDelivery {
    fn from_row(row: crate::db::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            action_id: row.try_get("action_id")?,
            tenant_id: row.try_get("tenant_id")?,
            target_kind: row.try_get("target_kind")?,
            target_id: row.try_get("target_id")?,
            executor_kind: row.try_get("executor_kind")?,
            delivery_subject: row.try_get("delivery_subject")?,
            status: row.try_get("status")?,
            attempt_count: row.try_get("attempt_count")?,
            published_at: row.try_get("published_at")?,
            acknowledged_at: row.try_get("acknowledged_at")?,
            acknowledgement_deadline: row.try_get("acknowledgement_deadline")?,
            last_error: row.try_get("last_error")?,
            metadata: row.try_get("metadata")?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseActionAckRecord {
    pub id: Uuid,
    pub action_id: Uuid,
    pub tenant_id: Uuid,
    pub target_kind: String,
    pub target_id: String,
    pub observed_at: DateTime<Utc>,
    pub status: String,
    pub message: Option<String>,
    pub resulting_state: Option<String>,
    pub raw_payload: Value,
}

impl ResponseActionAckRecord {
    fn from_row(row: crate::db::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            action_id: row.try_get("action_id")?,
            tenant_id: row.try_get("tenant_id")?,
            target_kind: row.try_get("target_kind")?,
            target_id: row.try_get("target_id")?,
            observed_at: row.try_get("observed_at")?,
            status: row.try_get("status")?,
            message: row.try_get("message")?,
            resulting_state: row.try_get("resulting_state")?,
            raw_payload: row.try_get("raw_payload")?,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct ResponseActionDetail {
    pub action: ResponseActionRecord,
    pub deliveries: Vec<ResponseActionDelivery>,
    pub acknowledgements: Vec<ResponseActionAckRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateResponseActionRequest {
    pub action_type: String,
    pub target: ResponseTargetInput,
    pub reason: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub case_id: Option<String>,
    pub source_detection_id: Option<String>,
    pub source_approval_id: Option<Uuid>,
    pub require_acknowledgement: Option<bool>,
    pub payload: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct ResponseTargetInput {
    pub kind: String,
    pub id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordResponseAckRequest {
    pub target_kind: String,
    pub target_id: String,
    pub status: String,
    pub observed_at: Option<DateTime<Utc>>,
    pub message: Option<String>,
    pub resulting_state: Option<String>,
    pub raw_payload: Option<Value>,
}

async fn create_action(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(input): Json<CreateResponseActionRequest>,
) -> Result<Json<ResponseActionRecord>, ApiError> {
    if auth.role == "viewer" {
        return Err(ApiError::Forbidden);
    }

    let action_type = ResponseActionType::from_str(&input.action_type)?;
    let target_kind = ResponseTargetKind::from_str(&input.target.kind)?;
    validate_create_request(&input, &action_type, &target_kind)?;

    let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
    let row = sqlx::query::query(
        r#"INSERT INTO response_actions (
               tenant_id,
               action_type,
               target_kind,
               target_id,
               requested_by_type,
               requested_by_id,
               expires_at,
               reason,
               case_id,
               source_detection_id,
               source_approval_id,
               require_acknowledgement,
               payload,
               metadata
           )
           VALUES ($1, $2, $3, $4, 'user', $5, $6, $7, $8, $9, $10, $11, $12, $13)
           RETURNING *"#,
    )
    .bind(auth.tenant_id)
    .bind(action_type.as_str())
    .bind(target_kind.as_str())
    .bind(input.target.id.trim())
    .bind("api_key")
    .bind(input.expires_at)
    .bind(input.reason.trim())
    .bind(input.case_id.as_deref())
    .bind(input.source_detection_id.as_deref())
    .bind(input.source_approval_id)
    .bind(input.require_acknowledgement.unwrap_or(true))
    .bind(input.payload.unwrap_or_else(|| json!({})))
    .bind(json!({
        "requested_by_slug": auth.slug,
    }))
    .fetch_one(&mut *tx)
    .await
    .map_err(ApiError::Database)?;

    let action = ResponseActionRecord::from_row(row).map_err(ApiError::Database)?;
    link_action_to_source_detection(
        &mut tx,
        auth.tenant_id,
        action.id,
        action.source_detection_id.as_deref(),
    )
    .await?;
    tx.commit().await.map_err(ApiError::Database)?;

    Ok(Json(action))
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
    if auth.role == "viewer" {
        return Err(ApiError::Forbidden);
    }
    publish_action(&state, &auth.slug, auth.tenant_id, id, false).await
}

async fn retry_action(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<ResponseActionDetail>, ApiError> {
    if auth.role == "viewer" {
        return Err(ApiError::Forbidden);
    }
    publish_action(&state, &auth.slug, auth.tenant_id, id, true).await
}

async fn cancel_action(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<ResponseActionRecord>, ApiError> {
    if auth.role == "viewer" {
        return Err(ApiError::Forbidden);
    }

    let row = sqlx::query::query(
        r#"UPDATE response_actions
           SET status = 'cancelled',
               updated_at = now()
           WHERE id = $1
             AND tenant_id = $2
             AND status IN ('queued', 'approved', 'published', 'failed', 'expired')
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
             AND status IN ('queued', 'approved', 'published', 'failed', 'expired')"#,
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
    if auth.role == "viewer" {
        return Err(ApiError::Forbidden);
    }

    let observed_at = input.observed_at.unwrap_or_else(Utc::now);
    let ack_status = normalize_ack_status(&input.status)?;
    let target_kind = ResponseTargetKind::from_str(input.target_kind.trim())?;
    let target_id = input.target_id.trim();
    if target_id.is_empty() {
        return Err(ApiError::BadRequest("target_id is required".to_string()));
    }
    let raw_payload = input.raw_payload.unwrap_or_else(|| {
        json!({
            "status": ack_status,
            "message": input.message.clone(),
            "resulting_state": input.resulting_state.clone(),
        })
    });

    let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
    let action = sqlx::query::query(
        "SELECT * FROM response_actions WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
    )
    .bind(id)
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;
    let action = ResponseActionRecord::from_row(action).map_err(ApiError::Database)?;

    let delivery = sqlx::query::query(
        r#"SELECT id
           FROM response_action_deliveries
           WHERE action_id = $1
             AND tenant_id = $2
             AND target_kind = $3
             AND target_id = $4
           FOR UPDATE"#,
    )
    .bind(action.id)
    .bind(action.tenant_id)
    .bind(target_kind.as_str())
    .bind(target_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::Database)?
    .ok_or_else(|| {
        ApiError::BadRequest("acknowledgement target does not match a known delivery".to_string())
    })?;
    let delivery_id: Uuid = delivery.try_get("id").map_err(ApiError::Database)?;

    sqlx::query::query(
        r#"INSERT INTO response_action_acks (
               action_id,
               tenant_id,
               target_kind,
               target_id,
               observed_at,
               status,
               message,
               resulting_state,
               raw_payload
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
    )
    .bind(action.id)
    .bind(action.tenant_id)
    .bind(target_kind.as_str())
    .bind(target_id)
    .bind(observed_at)
    .bind(ack_status)
    .bind(input.message.as_deref())
    .bind(input.resulting_state.as_deref())
    .bind(raw_payload)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::Database)?;

    sqlx::query::query(
        r#"UPDATE response_action_deliveries
           SET status = $4,
               acknowledged_at = $3,
               updated_at = now(),
               last_error = CASE WHEN $4 IN ('failed', 'rejected', 'expired') THEN COALESCE($5, last_error) ELSE last_error END
           WHERE id = $6
             AND action_id = $1
             AND tenant_id = $2"#,
    )
    .bind(action.id)
    .bind(action.tenant_id)
    .bind(observed_at)
    .bind(ack_status)
    .bind(input.message.as_deref())
    .bind(delivery_id)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::Database)?;

    sqlx::query::query(
        r#"UPDATE response_actions
           SET status = $3,
               updated_at = now()
           WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(action.id)
    .bind(action.tenant_id)
    .bind(ack_status)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::Database)?;

    tx.commit().await.map_err(ApiError::Database)?;
    get_action(State(state), auth, Path(id)).await
}

async fn publish_action(
    state: &AppState,
    tenant_slug: &str,
    tenant_id: Uuid,
    action_id: Uuid,
    allow_retry: bool,
) -> Result<Json<ResponseActionDetail>, ApiError> {
    let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
    let row = sqlx::query::query(
        "SELECT * FROM response_actions WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
    )
    .bind(action_id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;
    let action = ResponseActionRecord::from_row(row).map_err(ApiError::Database)?;
    ensure_publishable(&action.status, allow_retry)?;

    if action
        .expires_at
        .is_some_and(|expires_at| expires_at <= Utc::now())
    {
        sqlx::query::query(
            "UPDATE response_actions SET status = 'expired', updated_at = now() WHERE id = $1",
        )
        .bind(action.id)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::Database)?;
        tx.commit().await.map_err(ApiError::Database)?;
        return Ok(Json(
            fetch_action_detail(state, tenant_id, action_id).await?,
        ));
    }

    let plan = delivery_plan(&action, tenant_slug);
    let delivery_row = sqlx::query::query(
        r#"INSERT INTO response_action_deliveries (
               action_id,
               tenant_id,
               target_kind,
               target_id,
               executor_kind,
               delivery_subject,
               status,
               attempt_count,
               acknowledgement_deadline,
               metadata
           )
           VALUES ($1, $2, $3, $4, $5, $6, 'approved', 0, $7, $8)
           ON CONFLICT (action_id, target_kind, target_id) DO UPDATE
           SET executor_kind = EXCLUDED.executor_kind,
               delivery_subject = EXCLUDED.delivery_subject,
               acknowledgement_deadline = EXCLUDED.acknowledgement_deadline,
               status = 'approved',
               updated_at = now()
           RETURNING *"#,
    )
    .bind(action.id)
    .bind(action.tenant_id)
    .bind(plan.target_kind.clone())
    .bind(plan.target_id.clone())
    .bind(plan.executor_kind.clone())
    .bind(plan.delivery_subject.clone())
    .bind(plan.acknowledgement_deadline)
    .bind(plan.metadata.clone())
    .fetch_one(&mut *tx)
    .await
    .map_err(ApiError::Database)?;
    let delivery = ResponseActionDelivery::from_row(delivery_row).map_err(ApiError::Database)?;

    sqlx::query::query(
        "UPDATE response_actions SET status = 'approved', updated_at = now() WHERE id = $1",
    )
    .bind(action.id)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::Database)?;
    tx.commit().await.map_err(ApiError::Database)?;

    let publish_result: Result<(), ApiError> =
        if let Some(subject) = delivery.delivery_subject.clone() {
            let payload_bytes = build_signed_response_action_payload_bytes(
                action.to_transport_payload(),
                state.config.approval_signing_enabled,
                state.signing_keypair.as_deref(),
            )?;
            let js = async_nats::jetstream::new(state.nats.clone());
            js.publish(subject, payload_bytes.into())
                .await
                .map_err(|err| ApiError::Nats(err.to_string()))?
                .await
                .map_err(|err| ApiError::Nats(err.to_string()))?;
            Ok(())
        } else {
            Ok(())
        };

    match publish_result {
        Ok(()) => {
            let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
            sqlx::query::query(
                r#"UPDATE response_actions
                   SET status = 'published',
                       updated_at = now()
                   WHERE id = $1 AND tenant_id = $2"#,
            )
            .bind(action.id)
            .bind(action.tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::Database)?;
            sqlx::query::query(
                r#"UPDATE response_action_deliveries
                   SET status = 'published',
                       attempt_count = attempt_count + 1,
                       published_at = now(),
                       last_error = NULL,
                       updated_at = now()
                   WHERE id = $1"#,
            )
            .bind(delivery.id)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::Database)?;
            tx.commit().await.map_err(ApiError::Database)?;
        }
        Err(err) => {
            let err_string = err.to_string();
            let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
            sqlx::query::query(
                r#"UPDATE response_actions
                   SET status = 'failed',
                       metadata = jsonb_set(metadata, '{last_error}', to_jsonb($3::text), true),
                       updated_at = now()
                   WHERE id = $1 AND tenant_id = $2"#,
            )
            .bind(action.id)
            .bind(action.tenant_id)
            .bind(&err_string)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::Database)?;
            sqlx::query::query(
                r#"UPDATE response_action_deliveries
                   SET status = 'failed',
                       attempt_count = attempt_count + 1,
                       last_error = $2,
                       updated_at = now()
                   WHERE id = $1"#,
            )
            .bind(delivery.id)
            .bind(&err_string)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::Database)?;
            tx.commit().await.map_err(ApiError::Database)?;
        }
    }

    Ok(Json(
        fetch_action_detail(state, tenant_id, action_id).await?,
    ))
}

fn validate_create_request(
    input: &CreateResponseActionRequest,
    action_type: &ResponseActionType,
    target_kind: &ResponseTargetKind,
) -> Result<(), ApiError> {
    if input.reason.trim().is_empty() {
        return Err(ApiError::BadRequest("reason is required".to_string()));
    }
    if input.target.id.trim().is_empty() {
        return Err(ApiError::BadRequest("target.id is required".to_string()));
    }
    if let Some(expires_at) = input.expires_at {
        if expires_at <= Utc::now() {
            return Err(ApiError::BadRequest(
                "expires_at must be in the future".to_string(),
            ));
        }
    }

    match (action_type, target_kind) {
        (ResponseActionType::TransitionPosture, ResponseTargetKind::Endpoint)
        | (ResponseActionType::TransitionPosture, ResponseTargetKind::Runtime)
        | (ResponseActionType::TransitionPosture, ResponseTargetKind::Session)
        | (ResponseActionType::RequestPolicyReload, ResponseTargetKind::Endpoint)
        | (ResponseActionType::RequestPolicyReload, ResponseTargetKind::Runtime)
        | (ResponseActionType::TerminateSession, ResponseTargetKind::Session)
        | (ResponseActionType::KillSwitch, ResponseTargetKind::Endpoint)
        | (ResponseActionType::KillSwitch, ResponseTargetKind::Runtime)
        | (ResponseActionType::KillSwitch, ResponseTargetKind::Session)
        | (ResponseActionType::QuarantinePrincipal, ResponseTargetKind::Principal)
        | (ResponseActionType::QuarantinePrincipal, ResponseTargetKind::Project)
        | (ResponseActionType::QuarantinePrincipal, ResponseTargetKind::Swarm)
        | (ResponseActionType::RevokeGrant, ResponseTargetKind::Grant)
        | (ResponseActionType::RevokePrincipal, ResponseTargetKind::Principal) => Ok(()),
        _ => Err(ApiError::BadRequest(format!(
            "action '{}' is not valid for target kind '{}'",
            input.action_type, input.target.kind
        ))),
    }
}

fn normalize_ack_status(status: &str) -> Result<&'static str, ApiError> {
    match status.trim() {
        "acknowledged" => Ok("acknowledged"),
        "rejected" => Ok("rejected"),
        "failed" => Ok("failed"),
        "expired" => Ok("expired"),
        other => Err(ApiError::BadRequest(format!(
            "unsupported ack status '{other}'"
        ))),
    }
}

fn ensure_publishable(current_status: &str, allow_retry: bool) -> Result<(), ApiError> {
    match (current_status, allow_retry) {
        ("queued", false) | ("approved", false) => Ok(()),
        ("failed", true) | ("expired", true) | ("approved", true) | ("published", true) => Ok(()),
        ("cancelled", _) => Err(ApiError::BadRequest(
            "cancelled actions cannot be published".to_string(),
        )),
        ("acknowledged", _) => Err(ApiError::BadRequest(
            "acknowledged actions cannot be republished".to_string(),
        )),
        (status, true) => Err(ApiError::BadRequest(format!(
            "status '{status}' cannot be retried"
        ))),
        (status, false) => Err(ApiError::BadRequest(format!(
            "status '{status}' cannot be approved"
        ))),
    }
}

#[derive(Debug, Clone)]
struct DeliveryPlan {
    target_kind: String,
    target_id: String,
    executor_kind: String,
    delivery_subject: Option<String>,
    acknowledgement_deadline: Option<DateTime<Utc>>,
    metadata: Value,
}

fn delivery_plan(action: &ResponseActionRecord, tenant_slug: &str) -> DeliveryPlan {
    let subject_prefix = tenant_subject_prefix(tenant_slug);
    let ack_deadline = action
        .require_acknowledgement
        .then(|| Utc::now() + Duration::minutes(ACK_DEADLINE_MINUTES));

    match action.target.kind {
        ResponseTargetKind::Endpoint
        | ResponseTargetKind::Runtime
        | ResponseTargetKind::Session => DeliveryPlan {
            target_kind: action.target.kind.as_str().to_string(),
            target_id: action.target.id.clone(),
            executor_kind: match action.target.kind {
                ResponseTargetKind::Endpoint => "endpoint_agent".to_string(),
                ResponseTargetKind::Runtime => "runtime_agent".to_string(),
                ResponseTargetKind::Session => "session_api".to_string(),
                _ => "endpoint_agent".to_string(),
            },
            delivery_subject: Some(format!(
                "{subject_prefix}.response.command.{}.{}",
                action.target.kind.as_str(),
                action.target.id
            )),
            acknowledgement_deadline: ack_deadline,
            metadata: json!({
                "compat_mirror_subject": legacy_posture_subject(action, &subject_prefix),
            }),
        },
        _ => DeliveryPlan {
            target_kind: action.target.kind.as_str().to_string(),
            target_id: action.target.id.clone(),
            executor_kind: "cloud_only".to_string(),
            delivery_subject: None,
            acknowledgement_deadline: ack_deadline,
            metadata: json!({ "cloud_only": true }),
        },
    }
}

fn legacy_posture_subject(action: &ResponseActionRecord, subject_prefix: &str) -> Option<String> {
    if matches!(
        action.action_type.as_str(),
        "transition_posture" | "request_policy_reload" | "kill_switch"
    ) && matches!(action.target.kind, ResponseTargetKind::Endpoint)
    {
        Some(format!(
            "{subject_prefix}.posture.command.{}",
            action.target.id
        ))
    } else {
        None
    }
}

fn build_signed_response_action_payload_bytes(
    payload: Value,
    signing_enabled: bool,
    signing_keypair: Option<&hush_core::Keypair>,
) -> Result<Vec<u8>, ApiError> {
    if signing_enabled {
        let keypair = signing_keypair.ok_or_else(|| {
            ApiError::Internal("response signing is enabled but keypair is not loaded".to_string())
        })?;
        let envelope =
            spine::build_signed_envelope(keypair, 0, None, payload, spine::now_rfc3339()).map_err(
                |err| ApiError::Internal(format!("failed to sign response action: {err}")),
            )?;
        return serde_json::to_vec(&envelope).map_err(|err| {
            ApiError::Internal(format!(
                "failed to serialize signed response action envelope: {err}"
            ))
        });
    }

    Ok(serde_json::to_vec(&payload).unwrap_or_default())
}

async fn fetch_action(
    state: &AppState,
    tenant_id: Uuid,
    action_id: Uuid,
) -> Result<ResponseActionRecord, ApiError> {
    let row = sqlx::query::query("SELECT * FROM response_actions WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(action_id)
        .fetch_optional(&state.db)
        .await
        .map_err(ApiError::Database)?
        .ok_or(ApiError::NotFound)?;
    ResponseActionRecord::from_row(row).map_err(ApiError::Database)
}

async fn fetch_deliveries(
    state: &AppState,
    tenant_id: Uuid,
    action_id: Uuid,
) -> Result<Vec<ResponseActionDelivery>, ApiError> {
    let rows = sqlx::query::query(
        r#"SELECT *
           FROM response_action_deliveries
           WHERE tenant_id = $1 AND action_id = $2
           ORDER BY created_at DESC, id DESC"#,
    )
    .bind(tenant_id)
    .bind(action_id)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::Database)?;

    rows.into_iter()
        .map(ResponseActionDelivery::from_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::Database)
}

async fn fetch_acks(
    state: &AppState,
    tenant_id: Uuid,
    action_id: Uuid,
) -> Result<Vec<ResponseActionAckRecord>, ApiError> {
    let rows = sqlx::query::query(
        r#"SELECT *
           FROM response_action_acks
           WHERE tenant_id = $1 AND action_id = $2
           ORDER BY observed_at DESC, id DESC"#,
    )
    .bind(tenant_id)
    .bind(action_id)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::Database)?;

    rows.into_iter()
        .map(ResponseActionAckRecord::from_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::Database)
}

async fn fetch_action_detail(
    state: &AppState,
    tenant_id: Uuid,
    action_id: Uuid,
) -> Result<ResponseActionDetail, ApiError> {
    let action = fetch_action(state, tenant_id, action_id).await?;
    let deliveries = fetch_deliveries(state, tenant_id, action_id).await?;
    let acknowledgements = fetch_acks(state, tenant_id, action_id).await?;
    Ok(ResponseActionDetail {
        action,
        deliveries,
        acknowledgements,
    })
}

async fn link_action_to_source_detection(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    action_id: Uuid,
    source_detection_id: Option<&str>,
) -> Result<(), ApiError> {
    let Some(source_detection_id) = source_detection_id else {
        return Ok(());
    };
    let Ok(finding_id) = Uuid::parse_str(source_detection_id) else {
        return Ok(());
    };

    sqlx::query::query(
        r#"UPDATE detection_findings
           SET response_action_ids = CASE
                   WHEN COALESCE(response_action_ids, '[]'::jsonb)
                        @> jsonb_build_array($3::text) THEN COALESCE(response_action_ids, '[]'::jsonb)
                   ELSE COALESCE(response_action_ids, '[]'::jsonb) || jsonb_build_array($3::text)
               END
           WHERE tenant_id = $1
             AND id = $2"#,
    )
    .bind(tenant_id)
    .bind(finding_id)
    .bind(action_id.to_string())
    .execute(&mut **tx)
    .await
    .map_err(ApiError::Database)?;

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn delivery_plan_uses_response_subject_for_endpoint_actions() {
        let action = ResponseActionRecord {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            action_type: "transition_posture".to_string(),
            target: ResponseTarget {
                kind: ResponseTargetKind::Endpoint,
                id: "agent-123".to_string(),
            },
            requested_by: RequestedBy {
                actor_type: "user".to_string(),
                actor_id: "alice".to_string(),
            },
            requested_at: Utc::now(),
            expires_at: None,
            reason: "test".to_string(),
            case_id: None,
            source_detection_id: None,
            source_approval_id: None,
            require_acknowledgement: true,
            payload: json!({"toState": "restricted"}),
            status: "queued".to_string(),
            metadata: json!({}),
        };

        let plan = delivery_plan(&action, "acme");
        assert_eq!(
            plan.delivery_subject.as_deref(),
            Some("tenant-acme.clawdstrike.response.command.endpoint.agent-123")
        );
        assert_eq!(
            plan.metadata["compat_mirror_subject"],
            "tenant-acme.clawdstrike.posture.command.agent-123"
        );
    }

    #[test]
    fn cloud_only_targets_skip_transport_subject() {
        let action = ResponseActionRecord {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            action_type: "revoke_principal".to_string(),
            target: ResponseTarget {
                kind: ResponseTargetKind::Principal,
                id: "principal-1".to_string(),
            },
            requested_by: RequestedBy {
                actor_type: "user".to_string(),
                actor_id: "alice".to_string(),
            },
            requested_at: Utc::now(),
            expires_at: None,
            reason: "test".to_string(),
            case_id: None,
            source_detection_id: None,
            source_approval_id: None,
            require_acknowledgement: false,
            payload: json!({}),
            status: "queued".to_string(),
            metadata: json!({}),
        };

        let plan = delivery_plan(&action, "acme");
        assert!(plan.delivery_subject.is_none());
        assert_eq!(plan.executor_kind, "cloud_only");
    }

    #[test]
    fn create_validation_rejects_invalid_action_target_pairs() {
        let input = CreateResponseActionRequest {
            action_type: "request_policy_reload".to_string(),
            target: ResponseTargetInput {
                kind: "principal".to_string(),
                id: "p-1".to_string(),
            },
            reason: "reload".to_string(),
            expires_at: None,
            case_id: None,
            source_detection_id: None,
            source_approval_id: None,
            require_acknowledgement: Some(true),
            payload: None,
        };
        let err = validate_create_request(
            &input,
            &ResponseActionType::RequestPolicyReload,
            &ResponseTargetKind::Principal,
        )
        .unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }
}
