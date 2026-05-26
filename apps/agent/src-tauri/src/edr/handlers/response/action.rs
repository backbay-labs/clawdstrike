//! POST /agent/edr/response-action — dry-run or live response action submission.
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

pub(crate) async fn agent_edr_response_action(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrResponseActionInput>,
) -> Result<Json<EdrResponseActionResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let dry_run = input.dry_run.unwrap_or(true);
    if !dry_run
        && !matches!(
            input.action,
            EndpointDecisionAction::CollectEvidence
                | EndpointDecisionAction::RestrictEgress
                | EndpointDecisionAction::QuarantineFile
                | EndpointDecisionAction::DisablePersistence
                | EndpointDecisionAction::RevokeGrant
                | EndpointDecisionAction::SuspendProcessTree
        )
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "only collect_evidence, restrict_egress, quarantine_file, disable_persistence, revoke_grant, and suspend_process_tree can execute locally in this safe response-engine slice"
                .to_string(),
        ));
    }
    if !supported_edr_response_action(&input.action) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "unsupported endpoint response action for dry-run executor: {}",
                input.action.as_str()
            ),
        ));
    }
    validate_response_action_actor_fields(input.actor.as_ref())?;
    if !dry_run {
        validate_response_action_actor(input.actor.as_ref())?;
    }

    let root_node_id =
        resolve_graph_root_from_selector(input.root_node_id.as_deref(), input.process.as_ref())?;
    let ttl_seconds = validate_response_action_ttl_seconds(input.ttl_seconds)?;
    let reason = validate_response_reason(
        "response action",
        input.reason.as_deref(),
        default_response_action_reason(&input.action, dry_run),
    )?;

    let graph = state.edr_flight_recorder.lock().await.graph().clone();
    let subgraph = graph
        .causal_subgraph_from(root_node_id.as_str(), EDR_MAX_CAUSAL_SUBGRAPH_DEPTH)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("response action target not found in causal graph: {root_node_id}"),
            )
        })?;
    let actor = {
        let settings = state.settings.read().await.clone();
        let session_state = state.session_manager.state().await;
        endpoint_response_actor_from_action_input(
            &settings,
            &session_state,
            "agent-api",
            input.actor.as_ref(),
        )
    };
    let plan = if dry_run {
        EndpointResponsePlan::dry_run(
            input.action.clone(),
            root_node_id,
            &subgraph,
            ttl_seconds,
            reason.clone(),
        )
    } else {
        match input.action {
            EndpointDecisionAction::CollectEvidence => {
                EndpointResponsePlan::collect_evidence_execution(
                    root_node_id,
                    &subgraph,
                    ttl_seconds,
                    reason.clone(),
                )
            }
            EndpointDecisionAction::RestrictEgress => {
                EndpointResponsePlan::restrict_egress_execution(
                    root_node_id,
                    &subgraph,
                    ttl_seconds,
                    reason.clone(),
                )
            }
            EndpointDecisionAction::QuarantineFile => {
                EndpointResponsePlan::quarantine_file_execution(
                    root_node_id,
                    &subgraph,
                    ttl_seconds,
                    reason.clone(),
                )
            }
            EndpointDecisionAction::DisablePersistence => {
                EndpointResponsePlan::disable_persistence_execution(
                    root_node_id,
                    &subgraph,
                    ttl_seconds,
                    reason.clone(),
                )
            }
            EndpointDecisionAction::RevokeGrant => EndpointResponsePlan::revoke_grant_execution(
                root_node_id,
                &subgraph,
                ttl_seconds,
                reason.clone(),
            ),
            EndpointDecisionAction::SuspendProcessTree => {
                EndpointResponsePlan::suspend_process_tree_execution(
                    root_node_id,
                    &subgraph,
                    ttl_seconds,
                    reason.clone(),
                )
            }
            _ => unreachable!("non-dry-run response action was validated above"),
        }
    };
    let receipt = emit_edr_response_receipt(&state, actor.clone(), &plan, &subgraph)
        .await
        .map_err(internal_error)?;
    let (execution, evidence_bundle_artifact, execution_receipt, evidence_bundle_receipt) =
        if dry_run {
            (None, None, None, None)
        } else {
            let (execution, stored_bundle, receipt, bundle_receipt) =
                match execute_edr_response_action(&state, &plan, &subgraph, actor.clone()).await {
                    Ok(result) => result,
                    Err((status, message)) => {
                        let message = sanitize_response_execution_failure(&message);
                        let failure = record_failed_edr_response_execution(
                            &state,
                            &plan,
                            &subgraph,
                            actor,
                            message.as_str(),
                        )
                        .await;
                        return Err(response_action_failure_error(status, message, failure));
                    }
                };
            (
                Some(execution),
                Some(crate::edr::dto::evidence_bundle_artifact_from_stored(
                    &stored_bundle,
                )),
                Some(receipt),
                Some(bundle_receipt),
            )
        };
    let affected_identities = affected_identities_for_causal_impact(&subgraph);
    let affected_identity_count = affected_identities.count();
    let affected_tools = affected_tools_for_causal_impact(&subgraph);
    let affected_tool_count = affected_tools.len();

    Ok(Json(EdrResponseActionResponse {
        plan,
        graph: subgraph,
        affected_identity_count,
        affected_tool_count,
        affected_identities,
        affected_tools,
        receipt,
        execution,
        evidence_bundle_artifact,
        execution_receipt,
        evidence_bundle_receipt,
    }))
}
