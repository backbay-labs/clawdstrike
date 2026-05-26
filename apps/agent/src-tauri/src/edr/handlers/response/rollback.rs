//! POST /agent/edr/response-executions/{id}/rollback — rollback of side-effect actions.
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

pub(crate) async fn agent_edr_response_execution_rollback(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(execution_id): Path<String>,
    Json(input): Json<EdrResponseExecutionRollbackInput>,
) -> Result<Json<EdrResponseExecutionRollbackResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let execution_id = execution_id.trim();
    if execution_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "response execution id must not be empty".to_string(),
        ));
    }
    let reason = validate_response_reason(
        "response execution rollback",
        input.reason.as_deref(),
        "local response execution rollback",
    )?;

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
        EndpointDecisionAction::RestrictEgress
            | EndpointDecisionAction::QuarantineFile
            | EndpointDecisionAction::DisablePersistence
            | EndpointDecisionAction::SuspendProcessTree
    ) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "response execution {execution_id} is not a rollback-capable restrict_egress, quarantine_file, disable_persistence, or suspend_process_tree execution"
            ),
        ));
    }
    if !matches!(
        execution.status,
        EndpointResponseExecutionStatus::Succeeded | EndpointResponseExecutionStatus::Partial
    ) {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "response execution {execution_id} cannot be rolled back from status {}",
                execution.status.as_str()
            ),
        ));
    }
    {
        let ledger = state.edr_response_execution_ledger.lock().await;
        if ledger
            .has_terminal_transition_for(&execution)
            .map_err(internal_error)?
        {
            return Err((
                StatusCode::CONFLICT,
                format!("response execution {execution_id} already has a terminal transition"),
            ));
        }
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

    let (_rollback_intent, _rollback_intent_receipt) =
        record_edr_response_rollback_intent(&state, &execution, &reason, &graph).await?;

    let rollback_result = match execution.action {
        EndpointDecisionAction::RestrictEgress => {
            execute_restrict_egress_rollback(&state, &execution, &reason).await
        }
        EndpointDecisionAction::QuarantineFile => {
            execute_quarantine_file_rollback(&state, &execution, &reason)
        }
        EndpointDecisionAction::DisablePersistence => {
            execute_disable_persistence_rollback(&state, &execution, &reason)
        }
        EndpointDecisionAction::SuspendProcessTree => {
            execute_suspend_process_tree_rollback(&execution, &reason)
        }
        _ => unreachable!("rollback-capable action was validated above"),
    };
    let rollback = match rollback_result {
        Ok(rollback) => rollback,
        Err((status, err)) => {
            let record_message = sanitize_response_execution_failure(&err);
            let record_result = record_edr_response_rollback_failure(
                &state,
                &execution,
                &reason,
                record_message.as_str(),
                &graph,
            )
            .await;
            let suffix = match record_result {
                Ok((failed, receipt)) => {
                    let receipt = receipt
                        .receipt
                        .receipt_id
                        .unwrap_or_else(|| "unknown".to_string());
                    format!(
                        "; rollback failure recorded as {} with receipt {}",
                        failed.execution_id, receipt
                    )
                }
                Err((_, record_err)) => {
                    format!("; rollback failure recording also failed: {record_err}")
                }
            };
            return Err((
                status,
                format!("failed to roll back response execution {execution_id}: {err}{suffix}"),
            ));
        }
    };
    let receipt = emit_edr_response_rollback_receipt(&state, &rollback, &graph)
        .await
        .map_err(internal_error)?;
    let rollback_transition = {
        let mut ledger = state.edr_response_execution_ledger.lock().await;
        ledger
            .roll_back(&execution, &reason, rollback.completed_at)
            .map_err(internal_error)?
            .ok_or_else(|| {
                (
                    StatusCode::CONFLICT,
                    format!("response execution {execution_id} already has a terminal transition"),
                )
            })?
    };
    let transition_receipt = emit_edr_response_execution_receipt(
        &state,
        &rollback_transition,
        &graph,
        rollback_transition.actor.clone(),
        &[],
    )
    .await
    .map_err(internal_error)?;

    Ok(Json(EdrResponseExecutionRollbackResponse {
        path,
        execution: EdrResponseExecutionRecord::from_execution(execution),
        rollback_transition: EdrResponseExecutionRecord::from_execution(rollback_transition),
        rollback,
        receipt,
        transition_receipt,
    }))
}
