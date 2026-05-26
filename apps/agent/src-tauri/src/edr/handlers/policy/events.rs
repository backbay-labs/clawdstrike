//! Policy event replay and impact analysis handlers.
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
use std::sync::Arc;

pub(crate) async fn agent_edr_policy_events_replay(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrPolicyEventReplayInput>,
) -> Result<Json<EdrPolicyEventReplayResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    replay_policy_events_under_current_policy(
        &state,
        input.events,
        "submitted",
        input.track_posture.unwrap_or(false),
    )
    .await
    .map(Json)
}

pub(crate) async fn agent_edr_policy_events_replay_jsonl(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    body: String,
) -> Result<Json<EdrPolicyEventReplayResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let events = parse_policy_event_jsonl(&body)?;
    replay_policy_events_under_current_policy(&state, events, "submitted", false)
        .await
        .map(Json)
}

pub(crate) async fn agent_edr_policy_events_replay_history(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrPolicyEventHistoryReplayInput>,
) -> Result<Json<EdrPolicyEventHistoryReplayResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let track_posture = input.track_posture.unwrap_or(false);
    let selection = select_policy_event_history_from_flight_recorder(&state, input).await?;
    let replay = replay_policy_events_under_current_policy(
        &state,
        selection.events,
        "endpoint_flight_recorder",
        track_posture,
    )
    .await?;

    Ok(Json(EdrPolicyEventHistoryReplayResponse {
        history: selection.report,
        replay: replay.replay,
        result: replay.result,
        receipt: replay.receipt,
    }))
}

pub(crate) async fn agent_edr_policy_events_impact(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrPolicyEventImpactInput>,
) -> Result<Json<EdrPolicyEventImpactResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    analyze_policy_event_impact_under_proposed_policy(
        &state,
        input.events,
        "submitted",
        input.proposed_policy_yaml,
        input.track_posture.unwrap_or(false),
    )
    .await
    .map(Json)
}

pub(crate) async fn agent_edr_policy_events_impact_history(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrPolicyEventHistoryImpactInput>,
) -> Result<Json<EdrPolicyEventHistoryImpactResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let causal_context_depth = bounded_graph_depth(
        "causalContextDepth",
        input
            .causal_context_depth
            .or(Some(EDR_DEFAULT_POLICY_EVENT_IMPACT_CAUSAL_DEPTH)),
    )?;
    let validation_window_seconds =
        normalize_policy_event_history_validation_window_seconds(input.validation_window_seconds)?;
    if validation_window_seconds.is_some() && input.max_age_seconds.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "history impact validationWindowSeconds requires maxAgeSeconds so promotion evidence is tied to recent endpoint history".to_string(),
        ));
    }
    let selector = input.replay_selector_input();
    let track_posture = input.track_posture.unwrap_or(false);
    let selection = select_policy_event_history_from_flight_recorder(&state, selector).await?;
    let impact = analyze_policy_event_impact_under_proposed_policy(
        &state,
        selection.events.clone(),
        "endpoint_flight_recorder",
        input.proposed_policy_yaml,
        track_posture,
    )
    .await?;
    let graph = state.edr_flight_recorder.lock().await.graph().clone();
    let cross_window_impact = validation_window_seconds.map(|window_seconds| {
        build_policy_event_history_cross_window_impact(
            &selection,
            &impact.impact,
            &impact.changes,
            window_seconds,
        )
    });
    let promotion_stage = cross_window_impact
        .as_ref()
        .map(|impact| impact.recommended_stage.as_str());
    let cross_window_hashes = cross_window_impact.as_ref().map(|impact| {
        (
            impact.impact_hash.as_str(),
            impact.recommendation_hash.as_str(),
        )
    });
    let mut causal_impact = build_policy_event_history_causal_impact(
        &selection,
        &impact.changes,
        &graph,
        causal_context_depth,
        promotion_stage,
        cross_window_hashes,
    );
    if let Some(cross_window_impact) = &cross_window_impact {
        remember_cross_window_promotion_validation(
            &state,
            cross_window_impact,
            &causal_impact,
            &impact.impact,
            &selection.report,
        )
        .await;
    }
    if let Some((receipt_root_node_id, receipt_graph)) = causal_impact_receipt_graph(&causal_impact)
    {
        causal_impact.receipt = Some(
            emit_edr_graph_slice_receipt(
                &state,
                &receipt_root_node_id,
                "policy_event_history_impact",
                &receipt_graph,
            )
            .await
            .map_err(internal_error)?,
        );
    }

    Ok(Json(EdrPolicyEventHistoryImpactResponse {
        history: selection.report,
        causal_impact,
        cross_window_impact,
        impact: impact.impact,
        summary: impact.summary,
        drivers: impact.drivers,
        changes: impact.changes,
        current_result: impact.current_result,
        proposed_result: impact.proposed_result,
        receipt: impact.receipt,
    }))
}
