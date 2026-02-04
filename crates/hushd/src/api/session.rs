//! Session management endpoints.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::auth::AuthenticatedActor;
use crate::auth::Scope;
use crate::authz::require_api_key_scope_or_user_permission;
use crate::rbac::{Action, ResourceType};
use crate::session::CreateSessionOptions;
use crate::state::AppState;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionResponse {
    pub session: clawdstrike::SessionContext,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetSessionResponse {
    pub session: clawdstrike::SessionContext,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TerminateSessionRequest {
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminateSessionResponse {
    pub success: bool,
}

/// POST /api/v1/session
pub async fn create_session(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    body: Option<Json<CreateSessionOptions>>,
) -> Result<Json<CreateSessionResponse>, (StatusCode, String)> {
    let Some(axum::extract::Extension(actor)) = actor else {
        return Err((StatusCode::UNAUTHORIZED, "unauthenticated".to_string()));
    };

    let AuthenticatedActor::User(principal) = actor else {
        return Err((
            StatusCode::FORBIDDEN,
            "api_key_cannot_create_user_session".to_string(),
        ));
    };

    let options = body.map(|Json(v)| v);
    let session = state
        .sessions
        .create_session(principal, options)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(CreateSessionResponse { session }))
}

/// GET /api/v1/session/:id
pub async fn get_session(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<Json<GetSessionResponse>, (StatusCode, String)> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Read,
        ResourceType::Session,
        Action::Read,
    )?;

    let session = state
        .sessions
        .get_session(&session_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "session_not_found".to_string()))?;

    Ok(Json(GetSessionResponse { session }))
}

/// DELETE /api/v1/session/:id
pub async fn terminate_session(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    body: Option<Json<TerminateSessionRequest>>,
) -> Result<Json<TerminateSessionResponse>, (StatusCode, String)> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Admin,
        ResourceType::Session,
        Action::Delete,
    )?;

    let reason = body.and_then(|Json(v)| v.reason);
    let deleted = state
        .sessions
        .terminate_session(&session_id, reason.as_deref())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if !deleted {
        return Err((StatusCode::NOT_FOUND, "session_not_found".to_string()));
    }

    Ok(Json(TerminateSessionResponse { success: true }))
}
