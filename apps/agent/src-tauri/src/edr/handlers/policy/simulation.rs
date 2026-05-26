//! Policy simulation and policy-replay (live-policy preview) handlers.
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
