//! Shutdown endpoint

use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;

use crate::state::AppState;

#[derive(Clone, Debug, Serialize)]
pub struct ShutdownResponse {
    pub status: String,
}

/// POST /api/v1/shutdown
pub async fn shutdown(
    State(state): State<AppState>,
) -> Result<Json<ShutdownResponse>, (StatusCode, String)> {
    state.request_shutdown();
    Ok(Json(ShutdownResponse {
        status: "shutting_down".to_string(),
    }))
}
