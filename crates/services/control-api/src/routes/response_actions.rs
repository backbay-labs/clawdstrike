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
use crate::models::delegation_graph::RevokeGrantRequest;
use crate::services::delegation_graph as delegation_graph_service;
use crate::services::principal_resolution;
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
    pub case_id: Option<Uuid>,
    pub source_detection_id: Option<Uuid>,
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
    pub case_id: Option<Uuid>,
    pub source_detection_id: Option<Uuid>,
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
    pub ack_token: String,
    pub status: String,
    pub observed_at: Option<DateTime<Utc>>,
    pub message: Option<String>,
    pub resulting_state: Option<String>,
    pub raw_payload: Option<Value>,
}

struct ValidatedCreateAction {
    action_type: ResponseActionType,
    target_kind: ResponseTargetKind,
    resolved_target_id: String,
    reason: String,
    expires_at: Option<DateTime<Utc>>,
    case_id: Option<Uuid>,
    source_detection_id: Option<Uuid>,
    source_approval_id: Option<Uuid>,
    require_acknowledgement: bool,
    payload: Value,
    metadata: Value,
}

struct AckSubmission {
    target_kind: ResponseTargetKind,
    target_id: String,
    ack_token: String,
    ack_status: &'static str,
    observed_at: DateTime<Utc>,
    message: Option<String>,
    resulting_state: Option<String>,
    raw_payload: Value,
}

struct AckContext {
    action: ResponseActionRecord,
    delivery_id: Uuid,
}

struct PublishContext {
    action: ResponseActionRecord,
    delivery: ResponseActionDelivery,
}

struct PrincipalLifecycleTarget {
    principal_id: Uuid,
    stable_ref: String,
}

enum PublishPreparation {
    Ready(Box<PublishContext>),
    Expired,
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
    persist_ack_submission(&mut tx, &context, &ack).await?;
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
    match prepare_publish(state, tenant_slug, tenant_id, action_id, allow_retry).await? {
        PublishPreparation::Expired => {}
        PublishPreparation::Ready(context) => {
            let execution = execute_delivery(state, &context).await;
            apply_delivery_execution(state, &context, execution).await?;
        }
    }

    Ok(Json(
        fetch_action_detail(state, tenant_id, action_id).await?,
    ))
}

fn ensure_write_access(auth: &AuthenticatedTenant) -> Result<(), ApiError> {
    if !matches!(auth.role.as_str(), "owner" | "admin") {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

fn ensure_api_key_executor(auth: &AuthenticatedTenant) -> Result<(), ApiError> {
    if auth.role == "viewer" || !auth.is_api_key() {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

async fn prepare_create_action(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    auth: &AuthenticatedTenant,
    input: CreateResponseActionRequest,
) -> Result<ValidatedCreateAction, ApiError> {
    let action_type = ResponseActionType::from_str(&input.action_type)?;
    let target_kind = ResponseTargetKind::from_str(&input.target.kind)?;
    let require_acknowledgement = input.require_acknowledgement.unwrap_or(false);
    validate_create_request(&input, &action_type, &target_kind, require_acknowledgement)?;

    let resolved_target_id =
        resolve_action_target_id(tx, auth.tenant_id, &target_kind, input.target.id.trim()).await?;
    validate_action_links(
        tx,
        auth.tenant_id,
        input.case_id,
        input.source_detection_id,
        input.source_approval_id,
    )
    .await?;

    Ok(ValidatedCreateAction {
        action_type,
        target_kind,
        resolved_target_id,
        reason: input.reason.trim().to_string(),
        expires_at: input.expires_at,
        case_id: input.case_id,
        source_detection_id: input.source_detection_id,
        source_approval_id: input.source_approval_id,
        require_acknowledgement,
        payload: input.payload.unwrap_or_else(|| json!({})),
        metadata: json!({
            "requested_by_slug": auth.slug,
        }),
    })
}

async fn insert_action(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    auth: &AuthenticatedTenant,
    draft: ValidatedCreateAction,
) -> Result<ResponseActionRecord, ApiError> {
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
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
           RETURNING *"#,
    )
    .bind(auth.tenant_id)
    .bind(draft.action_type.as_str())
    .bind(draft.target_kind.as_str())
    .bind(&draft.resolved_target_id)
    .bind(auth.actor_type())
    .bind(auth.actor_id())
    .bind(draft.expires_at)
    .bind(&draft.reason)
    .bind(draft.case_id)
    .bind(draft.source_detection_id)
    .bind(draft.source_approval_id)
    .bind(draft.require_acknowledgement)
    .bind(draft.payload)
    .bind(draft.metadata)
    .fetch_one(&mut **tx)
    .await
    .map_err(ApiError::Database)?;

    ResponseActionRecord::from_row(row).map_err(ApiError::Database)
}

fn parse_ack_submission(input: RecordResponseAckRequest) -> Result<AckSubmission, ApiError> {
    let ack_status = normalize_ack_status(&input.status)?;
    let target_kind = ResponseTargetKind::from_str(input.target_kind.trim())?;
    let target_id = input.target_id.trim();
    if target_id.is_empty() {
        return Err(ApiError::BadRequest("target_id is required".to_string()));
    }

    let ack_token = input.ack_token.trim();
    if ack_token.is_empty() {
        return Err(ApiError::BadRequest("ack_token is required".to_string()));
    }

    let observed_at = input.observed_at.unwrap_or_else(Utc::now);
    let raw_payload = input.raw_payload.unwrap_or_else(|| {
        json!({
            "status": ack_status,
            "message": input.message.clone(),
            "resulting_state": input.resulting_state.clone(),
        })
    });

    Ok(AckSubmission {
        target_kind,
        target_id: target_id.to_string(),
        ack_token: ack_token.to_string(),
        ack_status,
        observed_at,
        message: input.message,
        resulting_state: input.resulting_state,
        raw_payload,
    })
}

async fn load_ack_context(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    action_id: Uuid,
    ack: &AckSubmission,
) -> Result<Option<AckContext>, ApiError> {
    let action = sqlx::query::query(
        "SELECT * FROM response_actions WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
    )
    .bind(action_id)
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;
    let action = ResponseActionRecord::from_row(action).map_err(ApiError::Database)?;
    if !action.require_acknowledgement {
        return Err(ApiError::BadRequest(
            "acknowledgements are not enabled for this action".to_string(),
        ));
    }

    let delivery = sqlx::query::query(
        r#"SELECT id, status, acknowledgement_deadline, metadata
           FROM response_action_deliveries
           WHERE action_id = $1
             AND tenant_id = $2
             AND target_kind = $3
             AND target_id = $4
           FOR UPDATE"#,
    )
    .bind(action.id)
    .bind(action.tenant_id)
    .bind(ack.target_kind.as_str())
    .bind(&ack.target_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(ApiError::Database)?
    .ok_or_else(|| {
        ApiError::BadRequest("acknowledgement target does not match a known delivery".to_string())
    })?;
    let delivery_id: Uuid = delivery.try_get("id").map_err(ApiError::Database)?;
    let delivery_status: String = delivery.try_get("status").map_err(ApiError::Database)?;
    let acknowledgement_deadline: Option<DateTime<Utc>> = delivery
        .try_get("acknowledgement_deadline")
        .map_err(ApiError::Database)?;
    let delivery_metadata: Value = delivery.try_get("metadata").map_err(ApiError::Database)?;
    let expected_ack_token = delivery_metadata
        .get("ack_token")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ApiError::BadRequest("delivery is not acknowledgement-enabled".to_string())
        })?;
    if expected_ack_token != ack.ack_token {
        return Err(ApiError::Forbidden);
    }
    let ack_exists = sqlx::query_scalar::query_scalar::<_, bool>(
        r#"SELECT EXISTS(
                   SELECT 1
                   FROM response_action_acks
                   WHERE delivery_id = $1
               )"#,
    )
    .bind(delivery_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(ApiError::Database)?;
    if ack_exists {
        return Err(ApiError::Conflict(
            "delivery acknowledgement has already been recorded".to_string(),
        ));
    }

    if ensure_ack_window_open(
        tx,
        &action,
        delivery_id,
        &delivery_status,
        acknowledgement_deadline,
        Utc::now(),
    )
    .await?
    {
        return Ok(None);
    }

    Ok(Some(AckContext {
        action,
        delivery_id,
    }))
}

async fn ensure_ack_window_open(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    action: &ResponseActionRecord,
    delivery_id: Uuid,
    delivery_status: &str,
    acknowledgement_deadline: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<bool, ApiError> {
    if action.status != "published" {
        return Err(ApiError::Conflict(format!(
            "action status '{}' cannot accept acknowledgements",
            action.status
        )));
    }

    if delivery_status != "published" {
        return Err(ApiError::Conflict(format!(
            "delivery status '{}' cannot accept acknowledgements",
            delivery_status
        )));
    }

    let window_expired = action
        .expires_at
        .is_some_and(|expires_at| expires_at <= now)
        || acknowledgement_deadline.is_some_and(|deadline| deadline <= now);
    if !window_expired {
        return Ok(false);
    }

    expire_ack_window(tx, action, delivery_id).await?;
    Ok(true)
}

async fn expire_ack_window(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    action: &ResponseActionRecord,
    delivery_id: Uuid,
) -> Result<(), ApiError> {
    sqlx::query::query(
        r#"UPDATE response_actions
           SET status = 'expired',
               updated_at = now()
           WHERE id = $1
             AND tenant_id = $2
             AND status = 'published'"#,
    )
    .bind(action.id)
    .bind(action.tenant_id)
    .execute(&mut **tx)
    .await
    .map_err(ApiError::Database)?;

    sqlx::query::query(
        r#"UPDATE response_action_deliveries
           SET status = 'expired',
               updated_at = now(),
               last_error = COALESCE(last_error, 'acknowledgement window expired')
           WHERE id = $1
             AND action_id = $2
             AND tenant_id = $3
             AND status = 'published'"#,
    )
    .bind(delivery_id)
    .bind(action.id)
    .bind(action.tenant_id)
    .execute(&mut **tx)
    .await
    .map_err(ApiError::Database)?;

    Ok(())
}

async fn persist_ack_submission(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    context: &AckContext,
    ack: &AckSubmission,
) -> Result<(), ApiError> {
    sqlx::query::query(
        r#"INSERT INTO response_action_acks (
               delivery_id,
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
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
    )
    .bind(context.delivery_id)
    .bind(context.action.id)
    .bind(context.action.tenant_id)
    .bind(ack.target_kind.as_str())
    .bind(&ack.target_id)
    .bind(ack.observed_at)
    .bind(ack.ack_status)
    .bind(ack.message.as_deref())
    .bind(ack.resulting_state.as_deref())
    .bind(&ack.raw_payload)
    .execute(&mut **tx)
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
    .bind(context.action.id)
    .bind(context.action.tenant_id)
    .bind(ack.observed_at)
    .bind(ack.ack_status)
    .bind(ack.message.as_deref())
    .bind(context.delivery_id)
    .execute(&mut **tx)
    .await
    .map_err(ApiError::Database)?;

    sqlx::query::query(
        r#"UPDATE response_actions
           SET status = $3,
               updated_at = now()
           WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(context.action.id)
    .bind(context.action.tenant_id)
    .bind(ack.ack_status)
    .execute(&mut **tx)
    .await
    .map_err(ApiError::Database)?;

    Ok(())
}

async fn prepare_publish(
    state: &AppState,
    tenant_slug: &str,
    tenant_id: Uuid,
    action_id: Uuid,
    allow_retry: bool,
) -> Result<PublishPreparation, ApiError> {
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
        return Ok(PublishPreparation::Expired);
    }

    let delivery = upsert_delivery_plan(&mut tx, &action, tenant_slug).await?;
    sqlx::query::query(
        "UPDATE response_actions SET status = 'approved', updated_at = now() WHERE id = $1",
    )
    .bind(action.id)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::Database)?;
    tx.commit().await.map_err(ApiError::Database)?;

    Ok(PublishPreparation::Ready(Box::new(PublishContext {
        action,
        delivery,
    })))
}

async fn upsert_delivery_plan(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    action: &ResponseActionRecord,
    tenant_slug: &str,
) -> Result<ResponseActionDelivery, ApiError> {
    let plan = delivery_plan(action, tenant_slug);
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
               metadata = EXCLUDED.metadata,
               status = 'approved',
               updated_at = now()
           RETURNING *"#,
    )
    .bind(action.id)
    .bind(action.tenant_id)
    .bind(plan.target_kind)
    .bind(plan.target_id)
    .bind(plan.executor_kind)
    .bind(plan.delivery_subject)
    .bind(plan.acknowledgement_deadline)
    .bind(plan.metadata)
    .fetch_one(&mut **tx)
    .await
    .map_err(ApiError::Database)?;
    ResponseActionDelivery::from_row(delivery_row).map_err(ApiError::Database)
}

async fn execute_delivery(
    state: &AppState,
    context: &PublishContext,
) -> Result<DeliveryExecution, ApiError> {
    if let Some(subject) = context.delivery.delivery_subject.clone() {
        let payload_bytes = build_delivery_payload_bytes(
            &context.action,
            &context.delivery,
            state.config.approval_signing_enabled,
            state.signing_keypair.as_deref(),
        )?;
        state
            .nats
            .publish(subject, payload_bytes.into())
            .await
            .map_err(|err| ApiError::Nats(err.to_string()))?;

        if let Some(compat_subject) = context
            .delivery
            .metadata
            .get("compat_mirror_subject")
            .and_then(Value::as_str)
        {
            let compat_payload = legacy_posture_command_payload(&context.action)?;
            let compat_payload_bytes = build_signed_payload_bytes(
                compat_payload,
                state.config.approval_signing_enabled,
                state.signing_keypair.as_deref(),
            )?;
            state
                .nats
                .publish(compat_subject.to_string(), compat_payload_bytes.into())
                .await
                .map_err(|err| ApiError::Nats(err.to_string()))?;
        }

        return Ok(DeliveryExecution::Published);
    }

    execute_cloud_only_action(state, &context.action).await
}

async fn apply_delivery_execution(
    state: &AppState,
    context: &PublishContext,
    execution: Result<DeliveryExecution, ApiError>,
) -> Result<(), ApiError> {
    match execution {
        Ok(DeliveryExecution::Published) => {
            let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
            sqlx::query::query(
                r#"UPDATE response_actions
                   SET status = 'published',
                       updated_at = now()
                   WHERE id = $1 AND tenant_id = $2"#,
            )
            .bind(context.action.id)
            .bind(context.action.tenant_id)
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
            .bind(context.delivery.id)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::Database)?;
            tx.commit().await.map_err(ApiError::Database)?;
        }
        Ok(DeliveryExecution::Acknowledged {
            observed_at,
            message,
            resulting_state,
            raw_payload,
        }) => {
            let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
            sqlx::query::query(
                r#"INSERT INTO response_action_acks (
                       delivery_id,
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
                   VALUES ($1, $2, $3, $4, $5, $6, 'acknowledged', $7, $8, $9)"#,
            )
            .bind(context.delivery.id)
            .bind(context.action.id)
            .bind(context.action.tenant_id)
            .bind(&context.delivery.target_kind)
            .bind(&context.delivery.target_id)
            .bind(observed_at)
            .bind(message.as_deref())
            .bind(resulting_state.as_deref())
            .bind(raw_payload)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::Database)?;
            sqlx::query::query(
                r#"UPDATE response_actions
                   SET status = 'acknowledged',
                       updated_at = now()
                   WHERE id = $1 AND tenant_id = $2"#,
            )
            .bind(context.action.id)
            .bind(context.action.tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::Database)?;
            sqlx::query::query(
                r#"UPDATE response_action_deliveries
                   SET status = 'acknowledged',
                       attempt_count = attempt_count + 1,
                       published_at = COALESCE(published_at, $2),
                       acknowledged_at = $2,
                       last_error = NULL,
                       updated_at = now()
                   WHERE id = $1"#,
            )
            .bind(context.delivery.id)
            .bind(observed_at)
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
            .bind(context.action.id)
            .bind(context.action.tenant_id)
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
            .bind(context.delivery.id)
            .bind(&err_string)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::Database)?;
            tx.commit().await.map_err(ApiError::Database)?;
        }
    }

    Ok(())
}

fn validate_create_request(
    input: &CreateResponseActionRequest,
    action_type: &ResponseActionType,
    target_kind: &ResponseTargetKind,
    require_acknowledgement: bool,
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
    if matches!(action_type, ResponseActionType::TransitionPosture)
        && transition_posture_value(input.payload.as_ref().unwrap_or(&Value::Null)).is_none()
    {
        return Err(ApiError::BadRequest(
            "transition_posture actions require payload.toState or payload.posture".to_string(),
        ));
    }
    if require_acknowledgement {
        return Err(ApiError::BadRequest(
            "response acknowledgements are not supported for the current executor set".to_string(),
        ));
    }

    match (action_type, target_kind) {
        (ResponseActionType::TransitionPosture, ResponseTargetKind::Endpoint)
        | (ResponseActionType::RequestPolicyReload, ResponseTargetKind::Endpoint)
        | (ResponseActionType::KillSwitch, ResponseTargetKind::Endpoint)
        | (ResponseActionType::QuarantinePrincipal, ResponseTargetKind::Principal)
        | (ResponseActionType::RevokeGrant, ResponseTargetKind::Grant)
        | (ResponseActionType::RevokePrincipal, ResponseTargetKind::Principal) => Ok(()),
        _ => Err(ApiError::BadRequest(format!(
            "action '{}' is not valid for target kind '{}'",
            input.action_type, input.target.kind
        ))),
    }
}

async fn resolve_action_target_id(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    target_kind: &ResponseTargetKind,
    target_id: &str,
) -> Result<String, ApiError> {
    let resolved = match target_kind {
        ResponseTargetKind::Endpoint => {
            if let Some(row) = sqlx::query::query(
                "SELECT agent_id FROM agents WHERE tenant_id = $1 AND agent_id = $2",
            )
            .bind(tenant_id)
            .bind(target_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(ApiError::Database)?
            {
                row.try_get("agent_id").map_err(ApiError::Database)?
            } else if let Ok(agent_row_id) = Uuid::parse_str(target_id) {
                let row = sqlx::query::query(
                    "SELECT agent_id FROM agents WHERE tenant_id = $1 AND id = $2",
                )
                .bind(tenant_id)
                .bind(agent_row_id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(ApiError::Database)?
                .ok_or(ApiError::NotFound)?;
                row.try_get("agent_id").map_err(ApiError::Database)?
            } else {
                return Err(ApiError::NotFound);
            }
        }
        ResponseTargetKind::Principal => {
            principal_resolution::resolve_principal_identifier(&mut **tx, tenant_id, target_id)
                .await?
                .id
                .to_string()
        }
        ResponseTargetKind::Grant => {
            let grant_id = Uuid::parse_str(target_id).map_err(|_| {
                ApiError::BadRequest("grant targets must use a UUID grant id".to_string())
            })?;
            let exists =
                sqlx::query::query("SELECT 1 FROM fleet_grants WHERE tenant_id = $1 AND id = $2")
                    .bind(tenant_id)
                    .bind(grant_id)
                    .fetch_optional(&mut **tx)
                    .await
                    .map_err(ApiError::Database)?
                    .is_some();
            if !exists {
                return Err(ApiError::NotFound);
            }
            grant_id.to_string()
        }
        ResponseTargetKind::Runtime
        | ResponseTargetKind::Session
        | ResponseTargetKind::Swarm
        | ResponseTargetKind::Project => {
            return Err(ApiError::BadRequest(format!(
                "target kind '{}' does not have a registered executor",
                target_kind.as_str()
            )));
        }
    };

    Ok(resolved)
}

async fn validate_action_links(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    case_id: Option<Uuid>,
    source_detection_id: Option<Uuid>,
    source_approval_id: Option<Uuid>,
) -> Result<(), ApiError> {
    if let Some(case_id) = case_id {
        let exists = sqlx::query_scalar::query_scalar::<_, bool>(
            r#"SELECT EXISTS(
                   SELECT 1
                   FROM fleet_cases
                   WHERE tenant_id = $1 AND id = $2
               )"#,
        )
        .bind(tenant_id)
        .bind(case_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(ApiError::Database)?;
        if !exists {
            return Err(ApiError::NotFound);
        }
    }

    if let Some(finding_id) = source_detection_id {
        let exists = sqlx::query_scalar::query_scalar::<_, bool>(
            r#"SELECT EXISTS(
                   SELECT 1
                   FROM detection_findings
                   WHERE tenant_id = $1 AND id = $2
               )"#,
        )
        .bind(tenant_id)
        .bind(finding_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(ApiError::Database)?;
        if !exists {
            return Err(ApiError::NotFound);
        }
    }

    if let Some(approval_id) = source_approval_id {
        let exists = sqlx::query_scalar::query_scalar::<_, bool>(
            r#"SELECT EXISTS(
                   SELECT 1
                   FROM approvals
                   WHERE tenant_id = $1 AND id = $2
               )"#,
        )
        .bind(tenant_id)
        .bind(approval_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(ApiError::Database)?;
        if !exists {
            return Err(ApiError::NotFound);
        }
    }

    Ok(())
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

enum DeliveryExecution {
    Published,
    Acknowledged {
        observed_at: DateTime<Utc>,
        message: Option<String>,
        resulting_state: Option<String>,
        raw_payload: Value,
    },
}

fn delivery_plan(action: &ResponseActionRecord, tenant_slug: &str) -> DeliveryPlan {
    let subject_prefix = tenant_subject_prefix(tenant_slug);
    let ack_deadline = action
        .require_acknowledgement
        .then(|| Utc::now() + Duration::minutes(ACK_DEADLINE_MINUTES));
    let ack_token = action
        .require_acknowledgement
        .then(|| Uuid::new_v4().to_string());

    match action.target.kind {
        ResponseTargetKind::Endpoint
        | ResponseTargetKind::Runtime
        | ResponseTargetKind::Session => {
            let canonical_subject = canonical_response_subject(action, &subject_prefix);
            let legacy_subject = legacy_posture_subject(action, &subject_prefix);

            DeliveryPlan {
                target_kind: action.target.kind.as_str().to_string(),
                target_id: action.target.id.clone(),
                executor_kind: match action.target.kind {
                    ResponseTargetKind::Endpoint => "endpoint_agent".to_string(),
                    ResponseTargetKind::Runtime => "runtime_agent".to_string(),
                    ResponseTargetKind::Session => "session_api".to_string(),
                    _ => "endpoint_agent".to_string(),
                },
                delivery_subject: Some(canonical_subject.clone()),
                acknowledgement_deadline: ack_deadline,
                metadata: json!({
                    "ack_token": ack_token,
                    "canonical_subject": canonical_subject,
                    "compat_mirror_subject": legacy_subject,
                    "protocol": "response_action_v1",
                }),
            }
        }
        _ => DeliveryPlan {
            target_kind: action.target.kind.as_str().to_string(),
            target_id: action.target.id.clone(),
            executor_kind: "cloud_only".to_string(),
            delivery_subject: None,
            acknowledgement_deadline: ack_deadline,
            metadata: json!({
                "ack_token": ack_token,
                "cloud_only": true,
                "protocol": "cloud_only",
            }),
        },
    }
}

fn canonical_response_subject(action: &ResponseActionRecord, subject_prefix: &str) -> String {
    format!(
        "{subject_prefix}.response.command.{}.{}",
        action.target.kind.as_str(),
        action.target.id
    )
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

fn build_delivery_payload_bytes(
    action: &ResponseActionRecord,
    delivery: &ResponseActionDelivery,
    signing_enabled: bool,
    signing_keypair: Option<&hush_core::Keypair>,
) -> Result<Vec<u8>, ApiError> {
    let payload = action_transport_payload(action, delivery);
    build_signed_payload_bytes(payload, signing_enabled, signing_keypair)
}

fn action_transport_payload(
    action: &ResponseActionRecord,
    delivery: &ResponseActionDelivery,
) -> Value {
    let ack_token = delivery.metadata.get("ack_token").and_then(Value::as_str);

    let mut payload = action.to_transport_payload();
    payload["delivery"] = json!({
        "subject": delivery.delivery_subject,
        "targetKind": delivery.target_kind,
        "targetId": delivery.target_id,
        "ackToken": ack_token,
    });
    payload
}

async fn execute_cloud_only_action(
    state: &AppState,
    action: &ResponseActionRecord,
) -> Result<DeliveryExecution, ApiError> {
    match (
        ResponseActionType::from_str(&action.action_type)?,
        &action.target.kind,
    ) {
        (ResponseActionType::RevokeGrant, ResponseTargetKind::Grant) => {
            let grant_id = Uuid::parse_str(&action.target.id).map_err(|_| {
                ApiError::BadRequest("grant targets must use a UUID grant id".to_string())
            })?;
            let response = delegation_graph_service::revoke_grant(
                &state.db,
                action.tenant_id,
                grant_id,
                RevokeGrantRequest {
                    reason: action.reason.clone(),
                    revoke_descendants: Some(true),
                    revoked_by: Some(action.requested_by.actor_id.clone()),
                    response_action_id: Some(action.id.to_string()),
                    response_action_label: Some(action.action_type.clone()),
                    response_action_state: Some("acknowledged".to_string()),
                    response_action_metadata: Some(json!({
                        "response_action_id": action.id.to_string(),
                        "action_type": action.action_type.as_str(),
                    })),
                },
            )
            .await?;

            Ok(DeliveryExecution::Acknowledged {
                observed_at: Utc::now(),
                message: Some("grant revoked".to_string()),
                resulting_state: Some("revoked".to_string()),
                raw_payload: json!({
                    "grantId": grant_id,
                    "revokedGrantIds": response.revoked_grant_ids,
                    "status": "acknowledged",
                }),
            })
        }
        (ResponseActionType::QuarantinePrincipal, ResponseTargetKind::Principal) => {
            execute_principal_lifecycle_action(state, action, "quarantined").await
        }
        (ResponseActionType::RevokePrincipal, ResponseTargetKind::Principal) => {
            execute_principal_lifecycle_action(state, action, "revoked").await
        }
        _ => Err(ApiError::BadRequest(format!(
            "action '{}' does not have an executable control-plane handler",
            action.action_type
        ))),
    }
}

async fn execute_principal_lifecycle_action(
    state: &AppState,
    action: &ResponseActionRecord,
    lifecycle_state: &str,
) -> Result<DeliveryExecution, ApiError> {
    let target = update_principal_lifecycle_target(
        &state.db,
        action.tenant_id,
        &action.target.id,
        lifecycle_state,
    )
    .await?;
    sync_principal_graph_state(&state.db, action.tenant_id, &target, lifecycle_state).await?;
    let revoked_grant_ids = delegation_graph_service::revoke_principal_grants(
        &state.db,
        action.tenant_id,
        delegation_graph_service::RevokePrincipalGrantsRequest {
            principal_id: target.principal_id,
            principal_stable_ref: target.stable_ref.clone(),
            reason: action.reason.clone(),
            revoked_by: Some(action.requested_by.actor_id.clone()),
            response_action_id: Some(action.id.to_string()),
            response_action_label: Some(action.action_type.clone()),
            response_action_state: Some("acknowledged".to_string()),
            response_action_metadata: Some(json!({
                "response_action_id": action.id.to_string(),
                "action_type": action.action_type.as_str(),
            })),
        },
    )
    .await?;

    Ok(DeliveryExecution::Acknowledged {
        observed_at: Utc::now(),
        message: Some(format!("principal transitioned to {lifecycle_state}")),
        resulting_state: Some(lifecycle_state.to_string()),
        raw_payload: json!({
            "principalId": target.principal_id,
            "stableRef": target.stable_ref,
            "status": "acknowledged",
            "lifecycleState": lifecycle_state,
            "revokedGrantIds": revoked_grant_ids,
        }),
    })
}

async fn update_principal_lifecycle_target(
    db: &crate::db::PgPool,
    tenant_id: Uuid,
    target_id: &str,
    lifecycle_state: &str,
) -> Result<PrincipalLifecycleTarget, ApiError> {
    let principal_id = Uuid::parse_str(target_id.trim()).map_err(|_| {
        ApiError::Internal("principal response targets must be canonical UUID ids".to_string())
    })?;
    let row = sqlx::query::query(
        r#"UPDATE principals
           SET lifecycle_state = $3,
               updated_at = now()
           WHERE tenant_id = $1
             AND id = $2
           RETURNING id, stable_ref"#,
    )
    .bind(tenant_id)
    .bind(principal_id)
    .bind(lifecycle_state)
    .fetch_optional(db)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

    Ok(PrincipalLifecycleTarget {
        principal_id: row.try_get("id").map_err(ApiError::Database)?,
        stable_ref: row.try_get("stable_ref").map_err(ApiError::Database)?,
    })
}

async fn sync_principal_graph_state(
    db: &crate::db::PgPool,
    tenant_id: Uuid,
    target: &PrincipalLifecycleTarget,
    lifecycle_state: &str,
) -> Result<(), ApiError> {
    let node_ids = vec![
        format!("principal:{}", target.principal_id),
        format!("principal:{}", target.stable_ref),
    ];
    sqlx::query::query(
        r#"UPDATE delegation_graph_nodes
           SET state = $3,
               updated_at = now()
           WHERE tenant_id = $1
             AND id = ANY($2)"#,
    )
    .bind(tenant_id)
    .bind(&node_ids)
    .bind(lifecycle_state)
    .execute(db)
    .await
    .map_err(ApiError::Database)?;
    Ok(())
}

fn legacy_posture_command_payload(action: &ResponseActionRecord) -> Result<Value, ApiError> {
    match action.action_type.as_str() {
        "transition_posture" => {
            let posture = transition_posture_value(&action.payload).ok_or_else(|| {
                ApiError::BadRequest(
                    "transition_posture actions require payload.toState or payload.posture"
                        .to_string(),
                )
            })?;
            Ok(json!({
                "command": "set_posture",
                "posture": posture,
            }))
        }
        "request_policy_reload" => Ok(json!({
            "command": "request_policy_reload",
        })),
        "kill_switch" => Ok(json!({
            "command": "kill_switch",
            "reason": action.reason,
        })),
        other => Err(ApiError::BadRequest(format!(
            "action '{other}' does not support legacy posture transport"
        ))),
    }
}

fn build_signed_payload_bytes(
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

fn transition_posture_value(payload: &Value) -> Option<String> {
    payload
        .get("toState")
        .and_then(Value::as_str)
        .or_else(|| payload.get("to_state").and_then(Value::as_str))
        .or_else(|| payload.get("posture").and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn scrub_delivery_metadata(mut metadata: Value) -> Value {
    if let Some(object) = metadata.as_object_mut() {
        object.remove("ack_token");
    }
    metadata
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
        .map(|delivery| {
            let mut delivery = delivery?;
            delivery.metadata = scrub_delivery_metadata(delivery.metadata);
            Ok(delivery)
        })
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
    source_detection_id: Option<Uuid>,
) -> Result<(), ApiError> {
    let Some(finding_id) = source_detection_id else {
        return Ok(());
    };

    let result = sqlx::query::query(
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

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

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
        assert_eq!(
            plan.metadata["canonical_subject"],
            "tenant-acme.clawdstrike.response.command.endpoint.agent-123"
        );
        assert!(plan.metadata["ack_token"].is_string());
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
            require_acknowledgement: Some(false),
            payload: None,
        };
        let err = validate_create_request(
            &input,
            &ResponseActionType::RequestPolicyReload,
            &ResponseTargetKind::Principal,
            false,
        )
        .unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn transition_posture_requires_target_state_in_payload() {
        let input = CreateResponseActionRequest {
            action_type: "transition_posture".to_string(),
            target: ResponseTargetInput {
                kind: "endpoint".to_string(),
                id: "agent-1".to_string(),
            },
            reason: "contain".to_string(),
            expires_at: None,
            case_id: None,
            source_detection_id: None,
            source_approval_id: None,
            require_acknowledgement: Some(false),
            payload: Some(json!({})),
        };

        let err = validate_create_request(
            &input,
            &ResponseActionType::TransitionPosture,
            &ResponseTargetKind::Endpoint,
            false,
        )
        .unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn create_validation_rejects_acknowledgement_until_executor_support_exists() {
        let input = CreateResponseActionRequest {
            action_type: "request_policy_reload".to_string(),
            target: ResponseTargetInput {
                kind: "endpoint".to_string(),
                id: "agent-1".to_string(),
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
            &ResponseTargetKind::Endpoint,
            true,
        )
        .unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn create_validation_rejects_unsupported_runtime_targets() {
        let input = CreateResponseActionRequest {
            action_type: "kill_switch".to_string(),
            target: ResponseTargetInput {
                kind: "runtime".to_string(),
                id: "runtime-1".to_string(),
            },
            reason: "contain".to_string(),
            expires_at: None,
            case_id: None,
            source_detection_id: None,
            source_approval_id: None,
            require_acknowledgement: Some(false),
            payload: None,
        };

        let err = validate_create_request(
            &input,
            &ResponseActionType::KillSwitch,
            &ResponseTargetKind::Runtime,
            false,
        )
        .unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn scrub_delivery_metadata_hides_ack_token() {
        let scrubbed = scrub_delivery_metadata(json!({
            "ack_token": "secret",
            "compat_mirror_subject": "tenant-acme.clawdstrike.posture.command.agent-123",
        }));

        assert!(scrubbed.get("ack_token").is_none());
        assert_eq!(
            scrubbed["compat_mirror_subject"],
            "tenant-acme.clawdstrike.posture.command.agent-123"
        );
    }
}
