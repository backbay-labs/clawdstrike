//! Local agent policy-check endpoint.

use super::super::*;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use std::sync::Arc;

pub(crate) async fn agent_policy_check(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<crate::policy::PolicyCheckInput>,
) -> Result<Json<AgentPolicyCheckResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let session_id = state.session_manager.session_id().await;
    let receipt_input = input.clone();
    let output = match active_egress_restriction_for_policy_check(&state, &receipt_input).await {
        Some(restriction) => policy_output_for_active_egress_restriction(&restriction),
        None => {
            crate::policy::evaluate_policy_check(
                state.settings.clone(),
                &state.http_client,
                input,
                session_id.clone(),
                Some(state.audit_queue.clone()),
            )
            .await
        }
    };
    let receipt =
        emit_edr_policy_decision_receipt(&state, &receipt_input, &output, session_id.as_deref())
            .await
            .map_err(internal_error)?;
    Ok(Json(AgentPolicyCheckResponse {
        decision: output,
        receipt,
    }))
}
