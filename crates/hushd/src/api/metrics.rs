//! Prometheus-style metrics endpoint

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
};

use crate::state::AppState;

/// GET /metrics
pub async fn metrics(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let dropped = state.audit_forwarder.as_ref().map(|f| f.dropped_total());
    let body = state.metrics.render(state.uptime_secs(), dropped);
    Ok(([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response())
}
