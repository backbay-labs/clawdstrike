//! GET /agent/edr/response-executions[/{id}[/proof]].
#[allow(unused_imports, clippy::wildcard_imports)]
use crate::api_server::*;
#[allow(unused_imports)]
use axum::extract::{Path, Query, State};
#[allow(unused_imports)]
use axum::http::{HeaderMap, StatusCode};
#[allow(unused_imports)]
use axum::Json;
#[allow(unused_imports)]
use clawdstrike_policy_event::edr::*;
#[allow(unused_imports)]
use std::sync::Arc;

pub(crate) async fn agent_edr_response_executions(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Query(query): Query<EdrResponseExecutionQuery>,
) -> Result<Json<EdrResponseExecutionsResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let limit = bounded_request_limit(
        "limit",
        query.limit,
        EDR_DEFAULT_RESPONSE_EXECUTION_QUERY_LIMIT,
        EDR_MAX_RESPONSE_EXECUTION_QUERY_LIMIT,
    )?;
    let (path, executions) = {
        let ledger = state.edr_response_execution_ledger.lock().await;
        let path = ledger.path().map(|path| path.display().to_string());
        let executions = ledger.read_recent(limit).map_err(internal_error)?;
        (path, executions)
    };
    let executions =
        response_execution_records_with_attribution(state.as_ref(), executions).await?;
    Ok(Json(EdrResponseExecutionsResponse {
        path,
        execution_count: executions.len(),
        executions,
    }))
}

pub(crate) async fn agent_edr_response_execution(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(execution_id): Path<String>,
) -> Result<Json<EdrResponseExecutionResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let execution_id = execution_id.trim();
    if execution_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "response execution id must not be empty".to_string(),
        ));
    }

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
    let execution = response_execution_record_with_attribution(state.as_ref(), execution).await?;

    Ok(Json(EdrResponseExecutionResponse { path, execution }))
}

pub(crate) async fn agent_edr_response_execution_proof(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(execution_id): Path<String>,
) -> Result<Json<EdrResponseExecutionProofResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let execution_id = execution_id.trim();
    if execution_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "response execution id must not be empty".to_string(),
        ));
    }

    let (execution_path, execution, has_terminal_transition) = {
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
        let has_terminal_transition = ledger
            .has_terminal_transition_for(&execution)
            .map_err(internal_error)?;
        (path, execution, has_terminal_transition)
    };
    ensure_response_execution_proof_ttl_state(
        execution.execution_id.as_str(),
        execution.expires_at(),
        has_terminal_transition,
        chrono::Utc::now(),
    )?;

    let (
        receipt_path,
        request_receipt,
        execution_receipt,
        evidence_bundle_receipt,
        transition_receipts,
        rollback_receipts,
        acknowledgement_receipts,
    ) = {
        let ledger = state.edr_receipt_ledger.lock().await;
        let path = ledger.path().map(|path| path.display().to_string());
        let request_receipt = latest_required_receipt(
            &ledger,
            "response_request",
            execution.action_id.as_str(),
            "response request receipt",
        )?;
        let execution_receipt = latest_required_receipt(
            &ledger,
            "response_execution",
            execution.execution_id.as_str(),
            "response execution receipt",
        )
        .or_else(|err| {
            if err.0 == StatusCode::NOT_FOUND {
                latest_required_receipt_by_execution_id(
                    &ledger,
                    "response_execution",
                    execution.execution_id.as_str(),
                    "response execution receipt",
                )
            } else {
                Err(err)
            }
        })?;
        let evidence_bundle_receipt = latest_required_receipt(
            &ledger,
            "evidence_bundle_manifest",
            execution.evidence_bundle.bundle_id.as_str(),
            "evidence bundle manifest receipt",
        )?;
        let lifecycle_receipts = response_execution_lifecycle_receipts(&ledger, &execution)?;
        verify_response_execution_proof_actor_continuity(
            &execution,
            &request_receipt,
            &execution_receipt,
            &lifecycle_receipts.transition_receipts,
        )?;
        verify_response_execution_proof_contract(
            &execution,
            &request_receipt,
            &execution_receipt,
            &evidence_bundle_receipt,
            &lifecycle_receipts.transition_receipts,
            &lifecycle_receipts.rollback_receipts,
            &lifecycle_receipts.acknowledgement_receipts,
        )?;
        (
            path,
            request_receipt,
            execution_receipt,
            evidence_bundle_receipt,
            lifecycle_receipts.transition_receipts,
            lifecycle_receipts.rollback_receipts,
            lifecycle_receipts.acknowledgement_receipts,
        )
    };
    let graph = receipt_endpoint_decision_graph(&execution_receipt).map_err(internal_error)?;
    let provider_state =
        receipt_endpoint_decision_sensor_state(&execution_receipt).map_err(internal_error)?;
    let (evidence_bundle_artifact, affected_identities, affected_tools) = {
        let mut store = state.edr_evidence_bundle_store.lock().await;
        let stored = store
            .load(&execution.evidence_bundle.bundle_id)
            .map_err(internal_error)?
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!(
                        "evidence bundle for response execution proof not found: {}",
                        execution.evidence_bundle.bundle_id
                    ),
                )
            })?;
        verify_response_execution_proof_evidence_bundle(&execution, &stored)?;
        let affected_identities = affected_identities_for_causal_impact(&stored.graph);
        let affected_tools = affected_tools_for_causal_impact(&stored.graph);
        (
            crate::edr::dto::evidence_bundle_artifact_from_stored(&stored),
            affected_identities,
            affected_tools,
        )
    };
    let affected_identity_count = affected_identities.count();
    let affected_tool_count = affected_tools.len();

    Ok(Json(EdrResponseExecutionProofResponse {
        execution_path,
        receipt_path,
        execution: EdrResponseExecutionRecord::from_execution(execution),
        graph,
        affected_identity_count,
        affected_tool_count,
        affected_identities,
        affected_tools,
        provider_state,
        evidence_bundle_artifact,
        request_receipt,
        execution_receipt,
        evidence_bundle_receipt,
        transition_receipts,
        rollback_receipts,
        acknowledgement_receipts,
    }))
}

pub(super) fn ensure_response_execution_proof_ttl_state(
    execution_id: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
    has_terminal_transition: bool,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), (StatusCode, String)> {
    if now > expires_at && !has_terminal_transition {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "response execution {execution_id} TTL expired without terminal expiry or rollback receipt"
            ),
        ));
    }
    Ok(())
}
