//! POST /agent/edr/response-executions/expire — TTL sweep with rollback orchestration.
#[allow(unused_imports, clippy::wildcard_imports)]
use crate::api_server::*;
#[allow(unused_imports)]
use axum::extract::State;
#[allow(unused_imports)]
use axum::http::{HeaderMap, StatusCode};
#[allow(unused_imports)]
use axum::Json;
#[allow(unused_imports)]
use clawdstrike_policy_event::edr::*;
#[allow(unused_imports)]
use std::collections::HashMap;
#[allow(unused_imports)]
use std::sync::Arc;

pub(crate) async fn agent_edr_response_execution_expire(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<EdrResponseExecutionExpireResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let response = expire_edr_response_executions(&state).await?;
    Ok(Json(response))
}

pub(crate) async fn expire_edr_response_executions(
    state: &Arc<AgentApiState>,
) -> Result<EdrResponseExecutionExpireResponse, (StatusCode, String)> {
    let now = chrono::Utc::now();
    let (path, pending) = {
        let ledger = state.edr_response_execution_ledger.lock().await;
        let path = ledger.path().map(|path| path.display().to_string());
        let pending = ledger
            .pending_expiring_executions(now)
            .map_err(internal_error)?;
        (path, pending)
    };

    let mut graphs = HashMap::with_capacity(pending.len());
    for execution in &pending {
        let graph = {
            let mut store = state.edr_evidence_bundle_store.lock().await;
            store
                .load(&execution.evidence_bundle.bundle_id)
                .map_err(internal_error)?
                .ok_or_else(|| {
                    (
                        StatusCode::NOT_FOUND,
                        format!(
                            "evidence bundle for expired response execution not found: {}",
                            execution.evidence_bundle.bundle_id
                        ),
                    )
                })?
                .graph
        };
        graphs.insert(execution.evidence_bundle.bundle_id.clone(), graph);
    }

    let mut rollbacks = Vec::new();
    let mut rollback_receipts = Vec::new();
    let mut rollback_transitions = Vec::new();
    let mut rollback_transition_receipts = Vec::new();
    for execution in pending
        .iter()
        .filter(|execution| response_execution_expires_with_rollback(&execution.action))
    {
        let graph = graphs
            .get(&execution.evidence_bundle.bundle_id)
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!(
                        "evidence bundle for expired response execution not found: {}",
                        execution.evidence_bundle.bundle_id
                    ),
                )
            })?;
        let reason = format!("response execution {} TTL expired", execution.execution_id);
        let (_rollback_intent, _rollback_intent_receipt) =
            record_edr_response_rollback_intent(state, execution, &reason, graph).await?;
        let rollback = match execute_response_expiration_rollback(state, execution).await {
            Ok(rollback) => rollback,
            Err((status, err)) => {
                let record_message = sanitize_response_execution_failure(&err);
                let record_result = record_edr_response_rollback_failure(
                    state,
                    execution,
                    &reason,
                    record_message.as_str(),
                    graph,
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
                    format!(
                        "failed to roll back expired response execution {}: {err}{suffix}",
                        execution.execution_id
                    ),
                ));
            }
        };
        let receipt = emit_edr_response_rollback_receipt(state, &rollback, graph)
            .await
            .map_err(internal_error)?;
        let rollback_transition = {
            let mut ledger = state.edr_response_execution_ledger.lock().await;
            ledger
                .roll_back(execution, &reason, rollback.completed_at)
                .map_err(internal_error)?
                .ok_or_else(|| {
                    (
                        StatusCode::CONFLICT,
                        format!(
                            "response execution {} already has a terminal transition",
                            execution.execution_id
                        ),
                    )
                })?
        };
        let transition_receipt = emit_edr_response_execution_receipt(
            state,
            &rollback_transition,
            graph,
            rollback_transition.actor.clone(),
            &[],
        )
        .await
        .map_err(internal_error)?;
        rollbacks.push(rollback);
        rollback_receipts.push(receipt);
        rollback_transitions.push(EdrResponseExecutionRecord::from_execution(
            rollback_transition,
        ));
        rollback_transition_receipts.push(transition_receipt);
    }

    let expired = {
        let mut ledger = state.edr_response_execution_ledger.lock().await;
        ledger.expire_due(now).map_err(internal_error)?
    };
    deactivate_expired_egress_restrictions(state, &expired, now).await?;

    let mut records = Vec::with_capacity(expired.len());
    let mut receipts = Vec::with_capacity(expired.len());
    for execution in expired {
        let graph = graphs
            .get(&execution.evidence_bundle.bundle_id)
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!(
                        "evidence bundle for expired response execution not found: {}",
                        execution.evidence_bundle.bundle_id
                    ),
                )
            })?;
        let receipt = emit_edr_response_execution_receipt(
            state,
            &execution,
            graph,
            execution.actor.clone(),
            &[],
        )
        .await
        .map_err(internal_error)?;
        receipts.push(receipt);
        records.push(EdrResponseExecutionRecord::from_execution(execution));
    }

    Ok(EdrResponseExecutionExpireResponse {
        path,
        expired_count: records.len(),
        executions: records,
        receipts,
        rollback_count: rollbacks.len(),
        rollbacks,
        rollback_receipts,
        rollback_transitions,
        rollback_transition_receipts,
    })
}
