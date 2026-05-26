//! Detection candidate generation and staged-detection lifecycle handlers.
#[allow(unused_imports, clippy::wildcard_imports)]
use crate::api_server::*;
#[allow(unused_imports)]
use axum::extract::{Query, State};
#[allow(unused_imports)]
use axum::http::{HeaderMap, StatusCode};
#[allow(unused_imports)]
use axum::Json;
#[allow(unused_imports)]
use clawdstrike_policy_event::edr::*;
#[allow(unused_imports)]
use std::sync::Arc;

pub(crate) async fn agent_edr_detection_candidate(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrDetectionCandidateInput>,
) -> Result<Json<EdrDetectionCandidateResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    build_edr_detection_candidate(&state, input).await.map(Json)
}

pub(crate) async fn agent_edr_stage_detection(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrStageDetectionInput>,
) -> Result<Json<EdrStageDetectionResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let candidate_response = build_edr_detection_candidate(&state, input.candidate_input()).await?;
    let stage = input
        .stage
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(candidate_response.recommended_stage.as_str());
    let stage_entry = detection_stage_entry(stage, &candidate_response.stage_plan)?;
    let staged_by = input
        .staged_by
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("local-agent");
    if staged_by.len() > 256 {
        return Err((
            StatusCode::BAD_REQUEST,
            "staged_by must be at most 256 bytes".to_string(),
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
            "staged detection note must be at most 2048 bytes".to_string(),
        ));
    }
    let cross_window_impact_hash =
        normalize_staged_detection_hash("crossWindowImpactHash", input.cross_window_impact_hash)?;
    let cross_window_recommendation_hash = normalize_staged_detection_hash(
        "crossWindowRecommendationHash",
        input.cross_window_recommendation_hash,
    )?;
    let settings = state.settings.read().await.clone();
    let policy = endpoint_policy_snapshot_from_settings(&settings).map_err(internal_error)?;
    let cross_window_validation = recent_cross_window_promotion_validation(
        state.as_ref(),
        stage,
        candidate_response.candidate.root_node_id.as_str(),
        &candidate_response.candidate.action,
        &policy,
        cross_window_impact_hash.as_deref(),
        cross_window_recommendation_hash.as_deref(),
    )
    .await?;
    validate_detection_stage_promotion_readiness(
        stage,
        stage_entry,
        cross_window_validation.as_ref(),
    )?;

    let staged_at = chrono::Utc::now();
    let staged_at_text = staged_at.to_rfc3339();
    let staged_detection_id = local_stable_id(
        "staged_detection",
        [
            candidate_response.candidate.rule_id.as_str(),
            candidate_response.candidate.graph_slice_id.as_str(),
            stage,
            staged_at_text.as_str(),
        ],
    );
    let record = EdrStagedDetectionRecord {
        staged_detection_id,
        staged_at,
        staged_by: staged_by.to_string(),
        stage: stage.to_string(),
        cross_window_impact_hash,
        cross_window_recommendation_hash,
        note,
        policy,
        candidate: candidate_response.candidate,
        recommended_stage: candidate_response.recommended_stage,
        stage_plan: candidate_response.stage_plan,
        simulation: candidate_response.simulation,
        simulation_receipt: candidate_response.receipt,
    };
    let path = {
        let mut ledger = state.edr_staged_detection_ledger.lock().await;
        ledger.append(&record).map_err(internal_error)?;
        ledger.path().map(|path| path.display().to_string())
    };

    Ok(Json(EdrStageDetectionResponse {
        path,
        record,
        graph: candidate_response.graph,
    }))
}

pub(crate) async fn agent_edr_staged_detections(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Query(query): Query<EdrStagedDetectionsQuery>,
) -> Result<Json<EdrStagedDetectionsResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let limit = bounded_request_limit("limit", query.limit, 50, EDR_MAX_STORED_FINDINGS)?;
    let stage = query_value(&query.stage).map(ToString::to_string);
    let rule_id = query_value(&query.rule_id).map(ToString::to_string);
    let ledger = state.edr_staged_detection_ledger.lock().await;
    let path = ledger.path().map(|path| path.display().to_string());
    let staged_detections = ledger
        .read_recent(limit, stage.as_deref(), rule_id.as_deref())
        .map_err(internal_error)?;
    Ok(Json(EdrStagedDetectionsResponse {
        path,
        count: staged_detections.len(),
        staged_detections,
    }))
}
