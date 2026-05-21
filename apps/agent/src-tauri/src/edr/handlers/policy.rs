//! Policy simulation, replay, and delta handlers.
#[allow(unused_imports, clippy::wildcard_imports)]
use crate::api_server::*;
#[allow(unused_imports)]
use anyhow::Context;
#[allow(unused_imports)]
use axum::extract::{Path, Query, State};
#[allow(unused_imports)]
use axum::http::{HeaderMap, StatusCode};
#[allow(unused_imports)]
use axum::Json;
#[allow(unused_imports)]
use clawdstrike_policy_event::edr::*;
#[allow(unused_imports)]
use clawdstrike_policy_event::event::PolicyEvent;
#[allow(unused_imports)]
use hush_core::sha256;
#[allow(unused_imports)]
use hush_core::SignedReceipt;
#[allow(unused_imports)]
use serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use serde_json::Value;
#[allow(unused_imports)]
use std::collections::{BTreeMap, BTreeSet, HashMap};
#[allow(unused_imports)]
use std::fs;
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

pub(crate) async fn agent_edr_policy_simulation(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrPolicySimulationInput>,
) -> Result<Json<EdrPolicySimulationResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let action = input.action.unwrap_or(EndpointDecisionAction::Block);
    if !supported_edr_simulation_action(&action) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "unsupported endpoint policy simulation action: {}",
                action.as_str()
            ),
        ));
    }

    let root_node_id =
        resolve_graph_root_from_selector(input.root_node_id.as_deref(), input.process.as_ref())?;
    let max_depth = bounded_graph_depth("maxDepth", input.max_depth)?;
    let rule_id = input
        .rule_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("endpoint.policy_simulation.block")
        .to_string();
    let description = input
        .description
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);

    let graph = state.edr_flight_recorder.lock().await.graph().clone();
    let subgraph = edr_policy_simulation_graph_slice(&graph, root_node_id.as_str(), max_depth)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("policy simulation target not found in causal graph: {root_node_id}"),
            )
        })?;
    let simulation = EndpointPolicySimulationReport::for_rule(
        EndpointPolicySimulationRule {
            rule_id,
            action,
            description,
        },
        &root_node_id,
        &subgraph,
    );
    let receipt = emit_edr_simulation_receipt(&state, &simulation, &subgraph)
        .await
        .map_err(internal_error)?;

    Ok(Json(EdrPolicySimulationResponse {
        simulation,
        graph: subgraph,
        receipt,
    }))
}

pub(crate) async fn agent_edr_policy_replay(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrPolicyReplayInput>,
) -> Result<Json<EdrPolicyReplayResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let root_node_id =
        resolve_graph_root_from_selector(input.root_node_id.as_deref(), input.process.as_ref())?;
    let max_depth = bounded_graph_depth("maxDepth", input.max_depth)?;
    let (graph, flight_recorder_observation_count) = {
        let recorder = state.edr_flight_recorder.lock().await;
        (recorder.graph().clone(), recorder.observation_count())
    };
    let subgraph = edr_policy_simulation_graph_slice(&graph, root_node_id.as_str(), max_depth)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("policy replay target not found in causal graph: {root_node_id}"),
            )
        })?;
    let root_node = subgraph.nodes.get(&root_node_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("policy replay root not found in graph slice: {root_node_id}"),
        )
    })?;
    let action = input
        .action
        .unwrap_or_else(|| default_detection_candidate_action(root_node));
    if !supported_edr_simulation_action(&action) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "unsupported endpoint policy replay action: {}",
                action.as_str()
            ),
        ));
    }

    let settings = state.settings.read().await.clone();
    let policy = endpoint_policy_snapshot_from_settings(&settings).map_err(internal_error)?;
    let rule_id = input
        .rule_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| policy_replay_rule_id(&policy, root_node, &action));
    let description = input
        .description
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| policy_replay_description(&policy, root_node, &action));
    let simulation = EndpointPolicySimulationReport::for_rule(
        EndpointPolicySimulationRule {
            rule_id,
            action: action.clone(),
            description: Some(description),
        },
        &root_node_id,
        &subgraph,
    );
    let receipt = emit_edr_simulation_receipt_with_policy(
        &state,
        &settings,
        policy.clone(),
        &simulation,
        &subgraph,
    )
    .await
    .map_err(internal_error)?;
    let replay = build_policy_replay_report(
        policy,
        root_node,
        flight_recorder_observation_count,
        &simulation,
        &subgraph,
    );

    Ok(Json(EdrPolicyReplayResponse {
        replay,
        simulation,
        graph: subgraph,
        receipt,
    }))
}

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

pub(crate) async fn agent_edr_policy_delta(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrPolicyDeltaInput>,
) -> Result<Json<EdrPolicyDeltaResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let generated_by = input
        .generated_by
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("local-agent");
    if generated_by.len() > 256 {
        return Err((
            StatusCode::BAD_REQUEST,
            "generated_by must be at most 256 bytes".to_string(),
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
            "policy delta note must be at most 2048 bytes".to_string(),
        ));
    }

    let staged_detection_id = query_value(&input.staged_detection_id).map(ToString::to_string);
    let rule_id = query_value(&input.rule_id).map(ToString::to_string);
    let stage = query_value(&input.stage).map(ToString::to_string);
    let staged = {
        let ledger = state.edr_staged_detection_ledger.lock().await;
        let records = ledger.all().map_err(internal_error)?;
        select_staged_detection_for_policy_delta(
            records,
            staged_detection_id.as_deref(),
            rule_id.as_deref(),
            stage.as_deref(),
        )?
    };
    let stage_entry = staged_detection_stage_entry(&staged)?;
    let settings = state.settings.read().await.clone();
    let endpoint_id = endpoint_id_for_settings(&settings);
    let generated_at = chrono::Utc::now();
    let generated_at_text = generated_at.to_rfc3339();
    let source_affected_identity_context =
        policy_delta_source_context_evidence_value(&staged.simulation.affected_identities);
    let source_affected_tool_context =
        policy_delta_source_context_evidence_value(&staged.simulation.affected_tools);
    let policy_delta_id = endpoint_policy_delta_id(EndpointPolicyDeltaIdInput {
        endpoint_id: endpoint_id.as_str(),
        rule_id: staged.candidate.rule_id.as_str(),
        action: &stage_entry.action,
        staged_detection_id: staged.staged_detection_id.as_str(),
        stage: staged.stage.as_str(),
        generated_at: generated_at_text.as_str(),
        simulation_id: staged.simulation.simulation_id.as_str(),
        graph_slice_id: staged.candidate.graph_slice_id.as_str(),
        root_node_id: staged.candidate.root_node_id.as_str(),
        source_affected_identity_context: source_affected_identity_context.as_str(),
        source_affected_tool_context: source_affected_tool_context.as_str(),
    });
    let artifact = build_edr_policy_delta_artifact(
        &staged,
        stage_entry,
        policy_delta_id,
        generated_at,
        generated_by,
        note,
    )?;
    let artifact_hash = policy_delta_artifact_hash(&artifact).map_err(internal_error)?;
    let sensor_state = endpoint_sensor_state_from_macos_host(&state.macos_host.snapshot().await);
    let receipt = {
        let mut ledger = state.edr_receipt_ledger.lock().await;
        ledger
            .sign_policy_delta_receipt(
                &settings,
                staged.policy.clone(),
                sensor_state,
                EdrPolicyDeltaReceiptSigningInput {
                    artifact: &artifact,
                    artifact_hash: &artifact_hash,
                    operation: "generated",
                    previous_policy_hash: None,
                    new_policy_hash: None,
                    backup_path: None,
                },
            )
            .map_err(internal_error)?
    };
    let mut record = EdrPolicyDeltaRecord {
        policy_delta_id: artifact.policy_delta_id.clone(),
        generated_at: artifact.generated_at,
        generated_by: artifact.generated_by.clone(),
        rule_id: artifact.candidate.rule_id.clone(),
        stage: artifact.rollout.stage.clone(),
        action: artifact.rollout.action.clone(),
        artifact_hash,
        artifact_path: None,
        artifact,
        receipt,
    };
    let path = {
        let mut store = state.edr_policy_delta_store.lock().await;
        store.append(&mut record).map_err(internal_error)?;
        store.path().map(|path| path.display().to_string())
    };

    Ok(Json(EdrPolicyDeltaResponse { path, record }))
}

pub(crate) async fn agent_edr_policy_deltas(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Query(query): Query<EdrPolicyDeltasQuery>,
) -> Result<Json<EdrPolicyDeltasResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let limit = bounded_request_limit("limit", query.limit, 50, EDR_MAX_STORED_FINDINGS)?;
    let stage = query_value(&query.stage).map(ToString::to_string);
    let rule_id = query_value(&query.rule_id).map(ToString::to_string);
    let store = state.edr_policy_delta_store.lock().await;
    let path = store.path().map(|path| path.display().to_string());
    let policy_deltas = store
        .read_recent(limit, stage.as_deref(), rule_id.as_deref())
        .map_err(internal_error)?;
    Ok(Json(EdrPolicyDeltasResponse {
        path,
        count: policy_deltas.len(),
        policy_deltas,
    }))
}

pub(crate) async fn agent_edr_policy_delta_apply(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(policy_delta_id): Path<String>,
    Json(input): Json<EdrPolicyDeltaApplyInput>,
) -> Result<Json<EdrPolicyDeltaApplyResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let policy_delta_id = policy_delta_id.trim();
    if policy_delta_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "policy delta id must not be empty".to_string(),
        ));
    }
    let dry_run = input.dry_run.unwrap_or(true);
    let allow_base_policy_drift = input.allow_base_policy_drift.unwrap_or(false);
    let reload_daemon_policy = input.reload_daemon_policy.unwrap_or(!dry_run);
    let restart_daemon = input.restart_daemon.unwrap_or(false);
    let verify_protection_state = input.verify_protection_state.unwrap_or(!dry_run);
    let provider_ack_timeout_ms = if dry_run || !verify_protection_state {
        0
    } else {
        bounded_provider_timeout_ms("providerAckTimeoutMs", input.provider_ack_timeout_ms)?
    };
    if dry_run && input.reload_daemon_policy.unwrap_or(false) {
        return Err((
            StatusCode::BAD_REQUEST,
            "reloadDaemonPolicy cannot be true for dryRun".to_string(),
        ));
    }
    if dry_run && restart_daemon {
        return Err((
            StatusCode::BAD_REQUEST,
            "restartDaemon cannot be true for dryRun".to_string(),
        ));
    }
    if dry_run && input.verify_protection_state.unwrap_or(false) {
        return Err((
            StatusCode::BAD_REQUEST,
            "verifyProtectionState cannot be true for dryRun".to_string(),
        ));
    }
    if dry_run && input.provider_ack_timeout_ms.unwrap_or(0) > 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "providerAckTimeoutMs cannot be set for dryRun".to_string(),
        ));
    }
    if !dry_run && !verify_protection_state {
        return Err((
            StatusCode::BAD_REQUEST,
            "verifyProtectionState must be true for live policy delta apply".to_string(),
        ));
    }
    if !dry_run && !reload_daemon_policy && !restart_daemon {
        return Err((
            StatusCode::BAD_REQUEST,
            "live policy delta apply requires reloadDaemonPolicy or restartDaemon".to_string(),
        ));
    }
    let applied_by = input
        .applied_by
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("local-agent");
    if applied_by.len() > 256 {
        return Err((
            StatusCode::BAD_REQUEST,
            "applied_by must be at most 256 bytes".to_string(),
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
            "policy delta apply note must be at most 2048 bytes".to_string(),
        ));
    }

    let policy_delta = {
        let store = state.edr_policy_delta_store.lock().await;
        store
            .read_by_id(policy_delta_id)
            .map_err(internal_error)?
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!("policy delta not found: {policy_delta_id}"),
                )
            })?
    };
    verify_policy_delta_record_before_apply(state.as_ref(), &policy_delta).await?;
    let settings = state.settings.read().await.clone();
    let policy_path = settings.policy_path.clone();
    let current_bytes = fs::read(&policy_path).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("read local policy {}: {err}", policy_path.display()),
        )
    })?;
    let previous_snapshot =
        endpoint_policy_snapshot_from_policy_bytes(&current_bytes, &policy_path)
            .map_err(internal_error)?;
    if !dry_run && policy_epoch_from_yaml(&current_bytes).is_none() {
        return Err((
            StatusCode::CONFLICT,
            "live policy delta apply requires the current policy to declare a positive policy_epoch"
                .to_string(),
        ));
    }
    let expected_base_policy_hash = policy_delta.artifact.target_policy.base_policy_hash.clone();
    if previous_snapshot.policy_hash != expected_base_policy_hash && !allow_base_policy_drift {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "policy delta base hash mismatch: expected {}, current {}",
                expected_base_policy_hash, previous_snapshot.policy_hash
            ),
        ));
    }

    let new_bytes =
        apply_policy_delta_patch_to_policy(&current_bytes, &policy_delta.artifact.policy_patch)
            .map_err(internal_error)?;
    let new_snapshot = endpoint_policy_snapshot_from_policy_bytes(&new_bytes, &policy_path)
        .map_err(internal_error)?;
    if !dry_run && policy_epoch_from_yaml(&new_bytes).is_none() {
        return Err((
            StatusCode::CONFLICT,
            "live policy delta apply requires the target policy to declare a positive policy_epoch"
                .to_string(),
        ));
    }
    if new_snapshot.policy_epoch <= previous_snapshot.policy_epoch {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "policy delta target epoch {} is not newer than current policy epoch {}",
                new_snapshot.policy_epoch, previous_snapshot.policy_epoch
            ),
        ));
    }
    let applied_at = chrono::Utc::now();
    let backup_path = if dry_run {
        None
    } else {
        let backup_path = policy_delta_backup_path(&policy_path, policy_delta_id, applied_at);
        if let Some(parent) = backup_path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("create policy backup directory {}: {err}", parent.display()),
                )
            })?;
        }
        fs::copy(&policy_path, &backup_path).map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "backup local policy {} to {}: {err}",
                    policy_path.display(),
                    backup_path.display()
                ),
            )
        })?;
        Some(backup_path.display().to_string())
    };

    let mut record = EdrPolicyDeltaApplyRecord {
        policy_delta_id: policy_delta.policy_delta_id.clone(),
        applied_at,
        apply_status: Some(if dry_run { "dry_run" } else { "prepared" }.to_string()),
        failure_reason: None,
        applied_by: applied_by.to_string(),
        note,
        dry_run,
        applied: false,
        allow_base_policy_drift,
        cross_window_impact_hash: policy_delta
            .artifact
            .rollout
            .cross_window_impact_hash
            .clone(),
        cross_window_recommendation_hash: policy_delta
            .artifact
            .rollout
            .cross_window_recommendation_hash
            .clone(),
        policy_path: policy_path.display().to_string(),
        backup_path: backup_path.clone(),
        expected_base_policy_hash,
        previous_policy_hash: previous_snapshot.policy_hash.clone(),
        new_policy_hash: new_snapshot.policy_hash.clone(),
        previous_policy_epoch: previous_snapshot.policy_epoch,
        new_policy_epoch: new_snapshot.policy_epoch,
    };

    let prepared_receipt = if dry_run {
        None
    } else {
        let sensor_state =
            endpoint_sensor_state_from_macos_host(&state.macos_host.snapshot().await);
        let mut ledger = state.edr_receipt_ledger.lock().await;
        Some(
            ledger
                .sign_policy_delta_receipt(
                    &settings,
                    new_snapshot.clone(),
                    sensor_state,
                    EdrPolicyDeltaReceiptSigningInput {
                        artifact: &policy_delta.artifact,
                        artifact_hash: &policy_delta.artifact_hash,
                        operation: "prepared",
                        previous_policy_hash: Some(previous_snapshot.policy_hash.as_str()),
                        new_policy_hash: Some(new_snapshot.policy_hash.as_str()),
                        backup_path: backup_path.as_deref(),
                    },
                )
                .map_err(internal_error)?,
        )
    };

    if !dry_run {
        append_policy_delta_apply_record(state.as_ref(), &record).await?;
    }

    if !dry_run {
        crate::security::fs::write_private_atomic(
            &policy_path,
            &new_bytes,
            "endpoint policy delta applied policy",
        )
        .map_err(internal_error)?;
        record.apply_status = Some("policy_written".to_string());
        record.applied = true;
    }

    let receipt = if dry_run {
        None
    } else {
        let sensor_state =
            endpoint_sensor_state_from_macos_host(&state.macos_host.snapshot().await);
        let mut ledger = state.edr_receipt_ledger.lock().await;
        match ledger.sign_policy_delta_receipt(
            &settings,
            new_snapshot.clone(),
            sensor_state,
            EdrPolicyDeltaReceiptSigningInput {
                artifact: &policy_delta.artifact,
                artifact_hash: &policy_delta.artifact_hash,
                operation: "applied",
                previous_policy_hash: Some(previous_snapshot.policy_hash.as_str()),
                new_policy_hash: Some(new_snapshot.policy_hash.as_str()),
                backup_path: backup_path.as_deref(),
            },
        ) {
            Ok(receipt) => Some(receipt),
            Err(err) => {
                rollback_policy_delta_apply_after_failure(
                    state.as_ref(),
                    &mut record,
                    &policy_path,
                    "applied receipt signing failed",
                )
                .await?;
                return Err(internal_error(err));
            }
        }
    };
    let post_apply_enforcement =
        if !dry_run && (verify_protection_state || reload_daemon_policy || restart_daemon) {
            match build_policy_delta_apply_enforcement_proof(
                &state,
                PolicyDeltaApplyEnforcementProofInput {
                    settings: &settings,
                    local_policy: new_snapshot.clone(),
                    cross_window_impact_hash: policy_delta
                        .artifact
                        .rollout
                        .cross_window_impact_hash
                        .as_deref(),
                    cross_window_recommendation_hash: policy_delta
                        .artifact
                        .rollout
                        .cross_window_recommendation_hash
                        .as_deref(),
                    daemon_policy_reload_requested: reload_daemon_policy,
                    daemon_restart_requested: restart_daemon,
                    provider_ack_timeout_ms,
                },
            )
            .await
            {
                Ok(proof) => Some(proof),
                Err(err) => {
                    rollback_policy_delta_apply_after_failure(
                        state.as_ref(),
                        &mut record,
                        &policy_path,
                        "post-apply enforcement proof failed",
                    )
                    .await?;
                    return Err(internal_error(err));
                }
            }
        } else {
            None
        };

    if !dry_run {
        record.apply_status = Some("complete".to_string());
        record.failure_reason = None;
        record.applied = true;
        if let Err((status, message)) =
            append_policy_delta_apply_record(state.as_ref(), &record).await
        {
            let rollback_reason = "complete apply record append failed";
            return match rollback_policy_delta_apply_after_failure(
                state.as_ref(),
                &mut record,
                &policy_path,
                rollback_reason,
            )
            .await
            {
                Ok(()) => Err((
                    status,
                    format!("{message}; policy rollback completed after durable apply record failure"),
                )),
                Err((rollback_status, rollback_message)) => Err((
                    rollback_status,
                    format!(
                        "{message}; rollback after durable apply record failure failed: {rollback_message}"
                    ),
                )),
            };
        }
    }

    Ok(Json(EdrPolicyDeltaApplyResponse {
        record,
        policy_delta,
        prepared_receipt,
        receipt,
        post_apply_enforcement,
    }))
}

async fn append_policy_delta_apply_record(
    state: &AgentApiState,
    record: &EdrPolicyDeltaApplyRecord,
) -> Result<(), (StatusCode, String)> {
    let mut store = state.edr_policy_delta_store.lock().await;
    store.append_apply(record).map_err(internal_error)
}

async fn rollback_policy_delta_apply_after_failure(
    state: &AgentApiState,
    record: &mut EdrPolicyDeltaApplyRecord,
    policy_path: &std::path::Path,
    reason: &str,
) -> Result<(), (StatusCode, String)> {
    let rollback_result = restore_policy_delta_backup(policy_path, record.backup_path.as_deref());
    record.applied = false;
    match &rollback_result {
        Ok(()) => {
            record.apply_status = Some("failed_rolled_back".to_string());
            record.failure_reason = Some(reason.to_string());
        }
        Err((_, rollback_error)) => {
            record.apply_status = Some("failed_rollback_failed".to_string());
            record.failure_reason = Some(format!("{reason}; rollback failed: {rollback_error}"));
        }
    }
    append_policy_delta_apply_record(state, record).await?;
    rollback_result
}

fn restore_policy_delta_backup(
    policy_path: &std::path::Path,
    backup_path: Option<&str>,
) -> Result<(), (StatusCode, String)> {
    let backup_path = backup_path.map(std::path::PathBuf::from).ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "cannot rollback policy delta apply without a backup path".to_string(),
        )
    })?;
    let backup_bytes = fs::read(&backup_path)
        .with_context(|| format!("read policy delta backup {}", backup_path.display()))
        .map_err(internal_error)?;
    crate::security::fs::write_private_atomic(
        policy_path,
        &backup_bytes,
        "endpoint policy delta rollback policy",
    )
    .map_err(internal_error)
}
