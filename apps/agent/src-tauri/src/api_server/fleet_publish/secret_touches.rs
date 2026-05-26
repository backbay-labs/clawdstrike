//! Agent-secret-touch graph slice collection and fleet publish helpers.

use super::super::*;
use axum::http::StatusCode;
use clawdstrike_policy_event::edr::EndpointObservation;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) async fn publish_agent_secret_touches_to_fleet(
    context: &FleetHuntPublishContext,
    touches: &[EdrAgentSecretTouch],
) -> Result<Vec<EdrPublishedHuntEvent>, (StatusCode, String)> {
    let mut events = Vec::new();
    for touch in touches {
        let event = fleet_hunt_event_for_agent_secret_touch(
            touch,
            &context.tenant_id,
            &context.endpoint_agent_id,
        );
        let event_id = event
            .get("eventId")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let raw_ref = event
            .get("evidence")
            .and_then(|evidence| evidence.get("rawRef"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let payload = serde_json::to_vec(&event)
            .map_err(|err| internal_error(anyhow::anyhow!("serialize hunt event: {err}")))?;
        context
            .publisher
            .publish_hunt_event(&payload)
            .await
            .map_err(|err| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("failed to publish hunt event to NATS: {err}"),
                )
            })?;
        events.push(EdrPublishedHuntEvent {
            event_id,
            raw_ref,
            credential_node_id: touch.credential_node_id.clone(),
        });
    }
    Ok(events)
}

pub(crate) async fn publish_current_agent_secret_touches_to_fleet_best_effort(
    state: &AgentApiState,
    observations: &[EndpointObservation],
) {
    let credential_observations = observations
        .iter()
        .filter(|observation| is_credential_access_observation(observation))
        .collect::<Vec<_>>();
    if credential_observations.is_empty() {
        return;
    }
    publish_unpublished_agent_secret_touches_to_fleet_best_effort(
        state,
        Some(&credential_observations),
        "current_ingestion",
    )
    .await;
}

pub(crate) async fn publish_persisted_agent_secret_touches_to_fleet_best_effort(
    state: &AgentApiState,
) {
    publish_unpublished_agent_secret_touches_to_fleet_best_effort(
        state,
        None,
        "flight_recorder_sync",
    )
    .await;
}

async fn publish_unpublished_agent_secret_touches_to_fleet_best_effort(
    state: &AgentApiState,
    credential_observations: Option<&[&EndpointObservation]>,
    source: &'static str,
) {
    if state.fleet_hunt_publisher.is_none() {
        return;
    }
    let publish_context = match fleet_hunt_publish_context(state).await {
        Ok(context) => context,
        Err((_, err)) => {
            tracing::debug!(error = %err, source, "Skipping automatic fleet hunt publish");
            return;
        }
    };
    let (touches_to_publish, keys_by_credential_node) =
        match collect_unpublished_agent_secret_touches_for_fleet(
            state,
            credential_observations,
            EDR_MAX_AUTO_FLEET_AGENT_SECRET_TOUCHES_PER_BATCH,
        )
        .await
        {
            Ok(result) => result,
            Err((_, err)) => {
                tracing::warn!(
                    error = %err,
                    source,
                    "Failed to collect agent-secret-touch graph slices for automatic fleet publish"
                );
                return;
            }
        };
    if touches_to_publish.is_empty() {
        return;
    }

    match publish_agent_secret_touches_to_fleet(&publish_context, &touches_to_publish).await {
        Ok(published_events) => {
            let mut published = state
                .edr_auto_published_agent_secret_touch_keys
                .lock()
                .await;
            for event in &published_events {
                if let Some(keys) = keys_by_credential_node.get(&event.credential_node_id) {
                    published.extend(keys.iter().cloned());
                }
            }
            tracing::info!(
                published_count = published_events.len(),
                source,
                "Published agent-secret-touch hunt events to fleet"
            );
        }
        Err((_, err)) => {
            tracing::warn!(
                error = %err,
                source,
                "Failed to publish agent-secret-touch hunt events to fleet"
            );
        }
    }
}

async fn collect_unpublished_agent_secret_touches_for_fleet(
    state: &AgentApiState,
    credential_observations: Option<&[&EndpointObservation]>,
    limit: usize,
) -> Result<(Vec<EdrAgentSecretTouch>, BTreeMap<String, BTreeSet<String>>), (StatusCode, String)> {
    use clawdstrike_policy_event::edr::CausalNodeKind;
    let limit = limit.clamp(1, EDR_MAX_STORED_FINDINGS);
    let published = state
        .edr_auto_published_agent_secret_touch_keys
        .lock()
        .await
        .clone();
    let observation_ids = credential_observations.map(|observations| {
        observations
            .iter()
            .map(|observation| observation.observation_id.as_str())
            .collect::<BTreeSet<_>>()
    });
    let graph = state.edr_flight_recorder.lock().await.graph().clone();
    let mut touches = Vec::new();
    let mut keys_by_credential_node = BTreeMap::new();

    for credential in graph
        .nodes
        .values()
        .filter(|node| node.kind == CausalNodeKind::Credential)
    {
        if let Some(observations) = credential_observations {
            if !observations.iter().any(|observation| {
                credential_node_matches_observation_credential(credential, observation)
            }) {
                continue;
            }
        }

        let Some(context) =
            graph.causal_context_around(&credential.node_id, EDR_MAX_CAUSAL_SUBGRAPH_DEPTH, 1)
        else {
            continue;
        };
        let (agent_node_ids, agent_labels) = graph_agent_context(&context);
        if agent_node_ids.is_empty() {
            continue;
        }
        let publish_keys = agent_secret_touch_publish_keys(
            &credential.node_id,
            &context,
            observation_ids.as_ref(),
        )
        .into_iter()
        .filter(|key| !published.contains(key))
        .collect::<BTreeSet<_>>();
        if publish_keys.is_empty() {
            continue;
        }

        let process_node_ids = context
            .nodes
            .values()
            .filter(|node| node.kind == CausalNodeKind::Process)
            .map(|node| node.node_id.clone())
            .collect::<Vec<_>>();
        let receipt = emit_edr_graph_slice_receipt(
            state,
            &credential.node_id,
            "agent_secret_touch",
            &context,
        )
        .await
        .map_err(internal_error)?;
        keys_by_credential_node.insert(credential.node_id.clone(), publish_keys);
        touches.push(EdrAgentSecretTouch {
            credential_node_id: credential.node_id.clone(),
            credential_label: credential.label.clone(),
            credential_kind: node_attribute_string(&credential.attributes, "credentialKind"),
            path: node_attribute_string(&credential.attributes, "path"),
            name: node_attribute_string(&credential.attributes, "name"),
            agent_node_ids,
            agent_labels,
            process_node_ids,
            graph: context,
            receipt,
        });
        if touches.len() >= limit {
            break;
        }
    }

    Ok((touches, keys_by_credential_node))
}

pub(crate) async fn collect_agent_secret_touches(
    state: &AgentApiState,
    input: EdrAgentSecretTouchesInput,
) -> Result<EdrAgentSecretTouchesResponse, (StatusCode, String)> {
    collect_agent_secret_touches_with_filter(state, input, |_| true).await
}

async fn collect_agent_secret_touches_with_filter<F>(
    state: &AgentApiState,
    input: EdrAgentSecretTouchesInput,
    mut include_credential: F,
) -> Result<EdrAgentSecretTouchesResponse, (StatusCode, String)>
where
    F: FnMut(&clawdstrike_policy_event::edr::CausalNode) -> bool,
{
    use clawdstrike_policy_event::edr::CausalNodeKind;
    let session_id = input
        .session_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    let credential_kind = input
        .credential_kind
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase());
    let require_agent_context = input.require_agent_context.unwrap_or(true);
    let upstream_depth = bounded_graph_depth("upstreamDepth", input.upstream_depth)?;
    let downstream_depth =
        bounded_graph_depth("downstreamDepth", input.downstream_depth.or(Some(1)))?;
    let limit = bounded_request_limit("limit", input.limit, 50, EDR_MAX_STORED_FINDINGS)?;

    let graph = state.edr_flight_recorder.lock().await.graph().clone();
    let mut touches = Vec::new();
    for credential in graph
        .nodes
        .values()
        .filter(|node| node.kind == CausalNodeKind::Credential)
    {
        if !include_credential(credential) {
            continue;
        }
        if let Some(expected_kind) = credential_kind.as_deref() {
            let actual_kind = node_attribute_string(&credential.attributes, "credentialKind")
                .unwrap_or_default()
                .to_ascii_lowercase();
            if actual_kind != expected_kind {
                continue;
            }
        }

        let Some(context) =
            graph.causal_context_around(&credential.node_id, upstream_depth, downstream_depth)
        else {
            continue;
        };
        if let Some(session_id) = session_id.as_deref() {
            if !graph_context_has_attribute(&context, "sessionId", session_id) {
                continue;
            }
        }

        let (agent_node_ids, agent_labels) = graph_agent_context(&context);
        if require_agent_context && agent_node_ids.is_empty() {
            continue;
        }
        let process_node_ids = context
            .nodes
            .values()
            .filter(|node| node.kind == CausalNodeKind::Process)
            .map(|node| node.node_id.clone())
            .collect::<Vec<_>>();
        let receipt = emit_edr_graph_slice_receipt(
            state,
            &credential.node_id,
            "agent_secret_touch",
            &context,
        )
        .await
        .map_err(internal_error)?;
        touches.push(EdrAgentSecretTouch {
            credential_node_id: credential.node_id.clone(),
            credential_label: credential.label.clone(),
            credential_kind: node_attribute_string(&credential.attributes, "credentialKind"),
            path: node_attribute_string(&credential.attributes, "path"),
            name: node_attribute_string(&credential.attributes, "name"),
            agent_node_ids,
            agent_labels,
            process_node_ids,
            graph: context,
            receipt,
        });
        if touches.len() >= limit {
            break;
        }
    }

    Ok(EdrAgentSecretTouchesResponse {
        touch_count: touches.len(),
        touches,
    })
}
