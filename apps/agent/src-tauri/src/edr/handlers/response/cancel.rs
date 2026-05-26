//! POST /agent/edr/response-executions/{id}/cancel — cancel collect_evidence / restrict_egress.
#[allow(unused_imports, clippy::wildcard_imports)]
use crate::api_server::*;
#[allow(unused_imports)]
use axum::extract::{Path, State};
#[allow(unused_imports)]
use axum::http::{HeaderMap, StatusCode};
#[allow(unused_imports)]
use axum::Json;
#[allow(unused_imports)]
use clawdstrike_policy_event::edr::*;
#[allow(unused_imports)]
use std::sync::Arc;

pub(crate) async fn agent_edr_response_execution_cancel(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(execution_id): Path<String>,
    Json(input): Json<EdrResponseExecutionCancelInput>,
) -> Result<Json<EdrResponseExecutionCancelResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let execution_id = execution_id.trim();
    if execution_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "response execution id must not be empty".to_string(),
        ));
    }
    let reason = validate_response_reason(
        "response execution cancel",
        input.reason.as_deref(),
        "local response execution cancelled",
    )?;

    let now = chrono::Utc::now();
    let (path, execution) = {
        let ledger = state.edr_response_execution_ledger.lock().await;
        let path = ledger.path().map(|path| path.display().to_string());
        let execution = ledger
            .get(execution_id)
            .map_err(internal_error)?
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!("response execution not found: {execution_id}"),
                )
            })?;
        (path, execution)
    };
    if !matches!(
        execution.action,
        EndpointDecisionAction::CollectEvidence | EndpointDecisionAction::RestrictEgress
    ) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "response execution {execution_id} cannot be cancelled safely; use rollback for rollback-capable local side-effect actions"
            ),
        ));
    }
    if !matches!(
        execution.status,
        EndpointResponseExecutionStatus::Succeeded
            | EndpointResponseExecutionStatus::Partial
            | EndpointResponseExecutionStatus::RollbackPending
            | EndpointResponseExecutionStatus::RollbackFailed
    ) {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "response execution {execution_id} cannot be cancelled from status {}",
                execution.status.as_str()
            ),
        ));
    }
    if now > execution.expires_at() {
        return Err((
            StatusCode::CONFLICT,
            format!("response execution {execution_id} TTL already expired"),
        ));
    }

    let graph = {
        let mut store = state.edr_evidence_bundle_store.lock().await;
        store
            .load(&execution.evidence_bundle.bundle_id)
            .map_err(internal_error)?
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!(
                        "evidence bundle for response execution not found: {}",
                        execution.evidence_bundle.bundle_id
                    ),
                )
            })?
            .graph
    };

    let cancelled = {
        let mut ledger = state.edr_response_execution_ledger.lock().await;
        ledger
            .cancel(&execution, &reason, now)
            .map_err(internal_error)?
            .ok_or_else(|| {
                (
                    StatusCode::CONFLICT,
                    format!("response execution {execution_id} already has a terminal transition"),
                )
            })?
    };
    if cancelled.action == EndpointDecisionAction::RestrictEgress {
        deactivate_egress_restrictions_if_active(&state, &cancelled.action_id, now).await?;
    }
    let receipt = emit_edr_response_execution_receipt(
        &state,
        &cancelled,
        &graph,
        cancelled.actor.clone(),
        &[],
    )
    .await
    .map_err(internal_error)?;

    Ok(Json(EdrResponseExecutionCancelResponse {
        path,
        execution: EdrResponseExecutionRecord::from_execution(cancelled),
        receipt,
    }))
}
