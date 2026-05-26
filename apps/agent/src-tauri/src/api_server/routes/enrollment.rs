//! Enrollment HTTP handlers.

use super::super::*;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
pub(crate) struct EnrollAgentInput {
    pub(crate) control_api_url: String,
    pub(crate) enrollment_token: String,
}

pub(crate) async fn enroll_agent(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EnrollAgentInput>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    let manager = crate::enrollment::EnrollmentManager::new(state.settings.clone());
    match manager
        .enroll(&input.control_api_url, &input.enrollment_token)
        .await
    {
        Ok(result) => {
            tracing::info!(
                agent_uuid = %result.agent_uuid,
                "Enrollment complete — agent restart required to activate NATS enterprise features"
            );
            Ok(Json(serde_json::json!({
                "status": "enrolled",
                "agent_uuid": result.agent_uuid,
                "tenant_id": result.tenant_id,
                "restart_required": true,
                "message": "Restart the agent to activate enterprise features (policy sync, telemetry, posture commands)",
            })))
        }
        Err(err) => Err((
            StatusCode::BAD_REQUEST,
            format!("Enrollment failed: {}", err),
        )),
    }
}

pub(crate) async fn enrollment_status(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    let settings = state.settings.read().await;
    let enrollment = &settings.enrollment;
    Ok(Json(serde_json::json!({
        "enrolled": enrollment.enrolled,
        "agent_uuid": enrollment.agent_uuid,
        "tenant_id": enrollment.tenant_id,
        "enrollment_in_progress": enrollment.enrollment_in_progress,
    })))
}
