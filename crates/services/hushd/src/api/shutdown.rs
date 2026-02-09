//! Shutdown endpoint

use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;

use crate::auth::{AuthenticatedActor, Scope};
use crate::authz::require_api_key_scope_or_user_permission;
use crate::rbac::{Action, ResourceType};
use crate::state::AppState;

#[derive(Clone, Debug, Serialize)]
pub struct ShutdownResponse {
    pub status: String,
}

/// POST /api/v1/shutdown
pub async fn shutdown(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<Json<ShutdownResponse>, (StatusCode, String)> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Admin,
        ResourceType::All,
        Action::All,
    )?;

    state.request_shutdown();
    Ok(Json(ShutdownResponse {
        status: "shutting_down".to_string(),
    }))
}
