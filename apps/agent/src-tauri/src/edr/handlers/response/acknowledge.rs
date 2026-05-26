//! POST /agent/edr/response-executions/{id}/acknowledge plus GET response acknowledgements.
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

pub(crate) async fn agent_edr_response_execution_acknowledge(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(execution_id): Path<String>,
    Json(input): Json<EdrResponseExecutionAcknowledgeInput>,
) -> Result<Json<EdrResponseExecutionAcknowledgeResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let execution_id = execution_id.trim();
    if execution_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "response execution id must not be empty".to_string(),
        ));
    }
    let acknowledged_by = input
        .acknowledged_by
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("local-agent");
    if acknowledged_by.len() > 256 {
        return Err((
            StatusCode::BAD_REQUEST,
            "response acknowledgement actor must be at most 256 bytes".to_string(),
        ));
    }
    let note = input
        .note
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    if note.as_deref().is_some_and(|value| value.len() > 2048) {
        return Err((
            StatusCode::BAD_REQUEST,
            "response acknowledgement note must be at most 2048 bytes".to_string(),
        ));
    }

    let execution = {
        let ledger = state.edr_response_execution_ledger.lock().await;
        ledger
            .get(execution_id)
            .map_err(internal_error)?
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!("response execution not found: {execution_id}"),
                )
            })?
    };
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
    let control_correlation =
        endpoint_response_control_correlation(input.control.as_ref(), &execution)?;
    let acknowledgement = EndpointResponseAcknowledgementReport::from_execution(
        &execution,
        acknowledged_by,
        note,
        chrono::Utc::now(),
    )
    .with_control_correlation(control_correlation);
    let path = append_edr_response_acknowledgement(&state, &acknowledgement).await?;
    let receipt = emit_edr_response_acknowledgement_receipt(&state, &acknowledgement, &graph)
        .await
        .map_err(internal_error)?;
    let control_postback = match input.control.as_ref() {
        Some(control) => {
            post_control_response_acknowledgement(&state, control, &acknowledgement, &receipt)
                .await?
        }
        None => None,
    };

    Ok(Json(EdrResponseExecutionAcknowledgeResponse {
        path,
        execution: EdrResponseExecutionRecord::from_execution(execution),
        acknowledgement,
        receipt,
        control_postback,
    }))
}

pub(crate) async fn agent_edr_response_acknowledgements(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Query(query): Query<EdrResponseAcknowledgementQuery>,
) -> Result<Json<EdrResponseAcknowledgementsResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let limit = bounded_request_limit("limit", query.limit, 50, EDR_MAX_STORED_FINDINGS)?;
    let ledger = state.edr_response_acknowledgement_ledger.lock().await;
    let path = ledger.path().map(|path| path.display().to_string());
    let acknowledgements = ledger
        .read_recent(limit)
        .map_err(internal_error)?
        .into_iter()
        .map(EdrResponseAcknowledgementRecord::from_acknowledgement)
        .collect::<Vec<_>>();
    Ok(Json(EdrResponseAcknowledgementsResponse {
        path,
        count: acknowledgements.len(),
        acknowledgements,
    }))
}
