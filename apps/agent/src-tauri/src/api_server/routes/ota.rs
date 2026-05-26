//! OTA (over-the-air update) status and trigger endpoints.

use super::super::*;
use crate::updater::OtaStatus;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use std::sync::Arc;

pub(crate) async fn get_ota_status(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<OtaStatus>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    Ok(Json(state.updater.status().await))
}

pub(crate) async fn trigger_ota_check(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<OtaStatus>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    state
        .updater
        .check_now()
        .await
        .map(Json)
        .map_err(internal_error)
}

pub(crate) async fn trigger_ota_apply(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<OtaStatus>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    state
        .updater
        .apply_now()
        .await
        .map(Json)
        .map_err(internal_error)
}
