//! Health check endpoint

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_secs: i64,
    pub session_id: String,
    pub audit_count: usize,
}

/// GET /health
pub async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let audit_count = state.ledger.count().unwrap_or(0);

    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs: state.uptime_secs(),
        session_id: state.session_id.clone(),
        audit_count,
    })
}
