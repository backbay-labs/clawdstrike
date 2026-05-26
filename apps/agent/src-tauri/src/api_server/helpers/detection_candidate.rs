//! Staged detection candidate builders and promotion-readiness validators.

use super::super::*;
use axum::http::StatusCode;
use clawdstrike_fs_policy_paths::path_is_bounded_persistence_target;
use clawdstrike_policy_event::edr::{
    CausalNodeKind, EndpointDecisionAction, EndpointPolicySimulationReport,
    EndpointPolicySimulationRule, EndpointPolicySnapshot,
};
use std::path::PathBuf;
use std::sync::Arc;

pub(crate) async fn build_edr_detection_candidate(
    state: &AgentApiState,
    input: EdrDetectionCandidateInput,
) -> Result<EdrDetectionCandidateResponse, (StatusCode, String)> {
    let root_node_id =
        resolve_graph_root_from_selector(input.root_node_id.as_deref(), input.process.as_ref())?;
    let max_depth = bounded_graph_depth("maxDepth", input.max_depth)?;
    let graph = state.edr_flight_recorder.lock().await.graph().clone();
    let subgraph = edr_policy_simulation_graph_slice(&graph, root_node_id.as_str(), max_depth)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("detection candidate target not found in causal graph: {root_node_id}"),
            )
        })?;
    let root_node = subgraph.nodes.get(&root_node_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("detection candidate root not found in graph slice: {root_node_id}"),
        )
    })?;
    let action = input
        .action
        .unwrap_or_else(|| default_detection_candidate_action(root_node));
    if !supported_edr_simulation_action(&action) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "unsupported endpoint detection candidate action: {}",
                action.as_str()
            ),
        ));
    }
    let rule_id = detection_candidate_rule_id(root_node, &action);
    let description = input
        .description
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| detection_candidate_description(root_node, &action));
    let rule = EndpointPolicySimulationRule {
        rule_id: rule_id.clone(),
        action: action.clone(),
        description: Some(description.clone()),
    };
    let simulation = EndpointPolicySimulationReport::for_rule(rule, &root_node_id, &subgraph);
    let receipt = emit_edr_simulation_receipt(state, &simulation, &subgraph)
        .await
        .map_err(internal_error)?;
    let recommended_stage = recommended_detection_stage(&simulation, &root_node.kind);
    let stage_plan =
        detection_candidate_stage_plan(&simulation, &root_node.kind, &recommended_stage);
    let candidate = EdrDetectionCandidate {
        rule_id,
        action,
        description,
        root_node_id: root_node_id.clone(),
        root_label: root_node.label.clone(),
        root_kind: root_node.kind.clone(),
        graph_slice_id: simulation.graph_slice_id.clone(),
    };

    Ok(EdrDetectionCandidateResponse {
        candidate,
        recommended_stage,
        stage_plan,
        simulation,
        graph: subgraph,
        receipt,
    })
}

pub(crate) fn normalize_staged_detection_hash(
    field: &str,
    value: Option<String>,
) -> Result<Option<String>, (StatusCode, String)> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() != 66 || !value.starts_with("0x") {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{field} must be a 0x-prefixed SHA-256 hex digest"),
        ));
    }
    if !value[2..].chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{field} must be a 0x-prefixed SHA-256 hex digest"),
        ));
    }
    Ok(Some(value.to_ascii_lowercase()))
}

pub(crate) async fn remember_cross_window_promotion_validation(
    state: &Arc<AgentApiState>,
    impact: &EdrPolicyEventHistoryCrossWindowImpact,
    causal_impact: &EdrPolicyEventHistoryCausalImpact,
    policy_impact: &EdrPolicyEventImpactReport,
    history: &EdrPolicyEventHistoryReport,
) {
    if !impact.promotion_ready {
        return;
    }
    let recorded_at = chrono::Utc::now();
    let history_selector_hash = policy_event_history_selector_hash(history);
    let mut validations = state.edr_cross_window_promotion_validations.lock().await;
    for suggestion in &causal_impact.promotion_suggestions {
        if suggestion.selected_stage != impact.recommended_stage {
            continue;
        }
        validations.push_back(EdrCrossWindowPromotionValidation {
            recorded_at,
            impact_hash: impact.impact_hash.clone(),
            recommendation_hash: impact.recommendation_hash.clone(),
            current_policy_hash: policy_impact.current_policy.policy_hash.clone(),
            current_policy_epoch: policy_impact.current_policy.policy_epoch,
            proposed_policy_hash: policy_impact.proposed_policy.policy_hash.clone(),
            proposed_policy_epoch: policy_impact.proposed_policy.policy_epoch,
            event_stream_hash: policy_impact.event_stream_hash.clone(),
            current_result_hash: policy_impact.current_result_hash.clone(),
            proposed_result_hash: policy_impact.proposed_result_hash.clone(),
            history_selector_hash: history_selector_hash.clone(),
            newest_event_at: history.newest_timestamp,
            max_age_seconds: history.max_age_seconds,
            recommended_stage: impact.recommended_stage.clone(),
            root_node_id: suggestion.target_node_id.clone(),
            action: suggestion.action.clone(),
            promotion_ready: true,
        });
    }
    while validations.len() > EDR_CROSS_WINDOW_PROMOTION_VALIDATION_CACHE_LIMIT {
        let _ = validations.pop_front();
    }
}

pub(crate) async fn recent_cross_window_promotion_validation(
    state: &AgentApiState,
    stage: &str,
    root_node_id: &str,
    action: &EndpointDecisionAction,
    current_policy: &EndpointPolicySnapshot,
    cross_window_impact_hash: Option<&str>,
    cross_window_recommendation_hash: Option<&str>,
) -> Result<Option<EdrCrossWindowPromotionValidation>, (StatusCode, String)> {
    let (Some(cross_window_impact_hash), Some(cross_window_recommendation_hash)) =
        (cross_window_impact_hash, cross_window_recommendation_hash)
    else {
        return Ok(None);
    };
    let now = chrono::Utc::now();
    let validations = state.edr_cross_window_promotion_validations.lock().await;
    Ok(validations
        .iter()
        .rev()
        .find(|validation| {
            validation.promotion_ready
                && validation.recommended_stage == stage
                && validation.root_node_id == root_node_id
                && validation.action == *action
                && validation.impact_hash == cross_window_impact_hash
                && validation.recommendation_hash == cross_window_recommendation_hash
                && validation.current_policy_hash == current_policy.policy_hash
                && validation.current_policy_epoch == current_policy.policy_epoch
                && !validation.proposed_policy_hash.is_empty()
                && validation.proposed_policy_epoch > 0
                && !validation.event_stream_hash.is_empty()
                && !validation.current_result_hash.is_empty()
                && !validation.proposed_result_hash.is_empty()
                && !validation.history_selector_hash.is_empty()
                && validation.newest_event_at.is_some()
                && validation.max_age_seconds.is_some_and(|max_age_seconds| {
                    validation.newest_event_at.is_some_and(|newest_event_at| {
                        now.signed_duration_since(newest_event_at)
                            .num_seconds()
                            .max(0) as u64
                            <= max_age_seconds
                    })
                })
                && now
                    .signed_duration_since(validation.recorded_at)
                    .num_seconds()
                    <= EDR_CROSS_WINDOW_PROMOTION_VALIDATION_MAX_AGE_SECONDS
        })
        .cloned())
}

pub(crate) fn detection_stage_entry<'a>(
    stage: &str,
    stage_plan: &'a [EdrDetectionCandidateStage],
) -> Result<&'a EdrDetectionCandidateStage, (StatusCode, String)> {
    if let Some(candidate) = stage_plan.iter().find(|candidate| candidate.stage == stage) {
        return Ok(candidate);
    }
    Err((
        StatusCode::BAD_REQUEST,
        format!(
            "stage must be one of: {}",
            detection_stage_names(stage_plan)
        ),
    ))
}

pub(crate) fn validate_detection_stage_promotion_readiness(
    stage: &str,
    stage_entry: &EdrDetectionCandidateStage,
    cross_window_validation: Option<&EdrCrossWindowPromotionValidation>,
) -> Result<(), (StatusCode, String)> {
    if !policy_delta_stage_is_enforcing(stage, &stage_entry.action) {
        return Ok(());
    }
    if cross_window_validation.is_some() {
        return Ok(());
    }
    Err((
        StatusCode::BAD_REQUEST,
        format!(
            "{stage} is an enforcing endpoint policy stage for action {}; provide crossWindowImpactHash and crossWindowRecommendationHash from a recent promotionReady=true policy-events impact history response before staging enforcement",
            stage_entry.action.as_str()
        ),
    ))
}

pub(crate) fn default_detection_candidate_action(
    node: &clawdstrike_policy_event::edr::CausalNode,
) -> EndpointDecisionAction {
    match node.kind {
        CausalNodeKind::Network => EndpointDecisionAction::RestrictEgress,
        CausalNodeKind::File | CausalNodeKind::BrowserDownload => {
            let path = PathBuf::from(node.label.trim());
            if path_is_bounded_persistence_target(&path) {
                EndpointDecisionAction::DisablePersistence
            } else {
                EndpointDecisionAction::QuarantineFile
            }
        }
        CausalNodeKind::BrowserExtension => EndpointDecisionAction::DisablePersistence,
        _ => EndpointDecisionAction::Block,
    }
}

pub(crate) fn detection_candidate_rule_id(
    node: &clawdstrike_policy_event::edr::CausalNode,
    action: &EndpointDecisionAction,
) -> String {
    format!(
        "endpoint.generated.{}.{}.{}",
        action.as_str(),
        causal_node_kind_name(&node.kind),
        rule_id_fragment(&node.label)
    )
}

pub(crate) fn detection_candidate_description(
    node: &clawdstrike_policy_event::edr::CausalNode,
    action: &EndpointDecisionAction,
) -> String {
    format!(
        "Generated staged endpoint detection candidate to {} {} node {} from local causal graph impact simulation.",
        action.as_str(),
        causal_node_kind_name(&node.kind),
        node.label
    )
}

pub(crate) fn detection_candidate_stage_plan(
    simulation: &EndpointPolicySimulationReport,
    root_kind: &CausalNodeKind,
    recommended_stage: &str,
) -> Vec<EdrDetectionCandidateStage> {
    let mut stages = vec![
        (
            "observe",
            EndpointDecisionAction::Observe,
            "record graph slices and receipts without user-visible enforcement",
        ),
        (
            "audit",
            EndpointDecisionAction::Alert,
            "review grouped causal evidence and simulation impact before notifying users",
        ),
        (
            "warn",
            EndpointDecisionAction::Warn,
            "warn affected users when developer breakage score is acceptable for workflow testing",
        ),
    ];
    if policy_delta_stage_materializes_guard(root_kind, &simulation.action) {
        stages.push((
            "limited_block",
            simulation.action.clone(),
            "enable bounded enforcement for matching graph roots with rollback or recovery path",
        ));
    }
    stages
        .into_iter()
        .map(
            |(stage, action, promotion_gate)| EdrDetectionCandidateStage {
                stage: stage.to_string(),
                action,
                promotion_gate: promotion_gate.to_string(),
                recommended: stage == recommended_stage,
            },
        )
        .collect()
}

pub(crate) fn recommended_detection_stage(
    simulation: &EndpointPolicySimulationReport,
    root_kind: &CausalNodeKind,
) -> String {
    if !simulation.would_block {
        return "observe".to_string();
    }
    if !policy_delta_stage_materializes_guard(root_kind, &simulation.action) {
        return "audit".to_string();
    }
    match simulation.developer_breakage_score {
        0..=45 => "limited_block",
        46..=70 => "warn",
        _ => "audit",
    }
    .to_string()
}
