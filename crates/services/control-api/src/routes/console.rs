use std::collections::{HashMap, HashSet};
use std::convert::Infallible;

use axum::extract::{Path, Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::get;
use axum::{Json, Router};
use futures::StreamExt;
use tokio_stream::wrappers::ReceiverStream;

use crate::auth::AuthenticatedTenant;
use crate::error::ApiError;
use crate::models::console::{
    ConsoleGraphNode, ConsoleGraphNodeKind, ConsoleGraphView, ConsolePrincipalDetail,
    ConsolePrincipalListQuery, ConsoleResponseActionListQuery, ConsoleTimelineQuery,
};
use crate::models::delegation_graph::DelegationGraphSnapshot;
use crate::services::console as console_service;
use crate::services::delegation_graph as delegation_graph_service;
use crate::services::tenant_provisioner::tenant_subject_prefix;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/console/overview", get(get_overview))
        .route("/console/principals", get(list_principals))
        .route("/console/principals/{id}", get(get_principal_detail))
        .route(
            "/console/principals/{id}/timeline",
            get(get_principal_timeline),
        )
        .route("/console/principals/{id}/graph", get(get_principal_graph))
        .route("/console/timeline", get(list_timeline))
        .route("/console/response-actions", get(list_response_actions))
        .route("/console/stream", get(console_stream))
}

fn stream_subject(slug: &str) -> String {
    format!("{}.spine.envelope.>", tenant_subject_prefix(slug))
}

async fn get_overview(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
) -> Result<Json<crate::models::console::FleetConsoleOverview>, ApiError> {
    Ok(Json(
        console_service::overview(&state.db, auth.tenant_id).await?,
    ))
}

async fn list_principals(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Query(query): Query<ConsolePrincipalListQuery>,
) -> Result<Json<Vec<crate::models::console::ConsolePrincipalListItem>>, ApiError> {
    Ok(Json(
        console_service::list_principals(&state.db, auth.tenant_id, &query).await?,
    ))
}

async fn get_principal_detail(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<String>,
) -> Result<Json<crate::models::console::ConsolePrincipalDetail>, ApiError> {
    Ok(Json(
        console_service::get_principal_detail(&state.db, auth.tenant_id, &id).await?,
    ))
}

async fn list_timeline(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Query(query): Query<ConsoleTimelineQuery>,
) -> Result<Json<Vec<crate::models::console::ConsoleTimelineEvent>>, ApiError> {
    Ok(Json(
        console_service::list_timeline_events(&state.db, auth.tenant_id, None, &query).await?,
    ))
}

async fn get_principal_timeline(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<String>,
    Query(query): Query<ConsoleTimelineQuery>,
) -> Result<Json<Vec<crate::models::console::ConsoleTimelineEvent>>, ApiError> {
    Ok(Json(
        console_service::list_timeline_events(&state.db, auth.tenant_id, Some(&id), &query).await?,
    ))
}

async fn list_response_actions(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Query(query): Query<ConsoleResponseActionListQuery>,
) -> Result<Json<Vec<crate::models::console::ConsoleResponseActionListItem>>, ApiError> {
    Ok(Json(
        console_service::list_response_actions(&state.db, auth.tenant_id, &query).await?,
    ))
}

async fn get_principal_graph(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<String>,
) -> Result<Json<ConsoleGraphView>, ApiError> {
    let detail = console_service::get_principal_detail(&state.db, auth.tenant_id, &id).await?;
    let snapshot = delegation_graph_service::principal_graph_snapshot(
        &state.db,
        auth.tenant_id,
        &detail.principal.principal_id,
        true,
    )
    .await?;

    Ok(Json(normalize_graph_snapshot(snapshot, &detail)))
}

async fn console_stream(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
) -> Result<Sse<impl futures::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let subject = stream_subject(&auth.slug);
    let subscriber = state
        .nats
        .subscribe(subject)
        .await
        .map_err(|error| ApiError::Nats(error.to_string()))?;

    let tenant_id = auth.tenant_id;
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(256);

    tokio::spawn(async move {
        let mut subscriber = subscriber;
        while let Some(message) = subscriber.next().await {
            let payload = serde_json::from_slice::<serde_json::Value>(&message.payload)
                .unwrap_or_else(|_| {
                    serde_json::json!({
                        "raw": String::from_utf8_lossy(&message.payload).to_string()
                    })
                });
            let normalized = console_service::normalize_console_stream_event(payload, tenant_id);
            let event = Event::default()
                .event(normalized.kind.as_str())
                .json_data(&normalized)
                .unwrap_or_else(|_| Event::default().data("{\"error\":\"serialization failed\"}"));

            if tx.send(Ok(event)).await.is_err() {
                break;
            }
        }
    });

    Ok(Sse::new(ReceiverStream::new(rx)).keep_alive(KeepAlive::default()))
}

fn normalize_graph_snapshot(
    snapshot: DelegationGraphSnapshot,
    detail: &ConsolePrincipalDetail,
) -> ConsoleGraphView {
    let fallback = console_service::build_principal_graph_from_detail(detail);
    let mut id_map = HashMap::<String, String>::new();
    let mut nodes = Vec::new();
    let mut seen_nodes = HashSet::new();

    for node in snapshot.nodes {
        let Some(kind) = map_graph_node_kind(&node.kind) else {
            continue;
        };
        let normalized_id = strip_node_prefix(&node.id);
        id_map.insert(node.id.clone(), normalized_id.clone());

        let normalized_node = ConsoleGraphNode {
            id: normalized_id,
            kind,
            label: node.label,
            state: node.state,
        };

        if seen_nodes.insert(normalized_node.id.clone()) {
            nodes.push(normalized_node);
        }
    }

    if seen_nodes.insert(detail.principal.principal_id.clone()) {
        nodes.push(ConsoleGraphNode {
            id: detail.principal.principal_id.clone(),
            kind: ConsoleGraphNodeKind::Principal,
            label: detail.principal.display_name.clone(),
            state: Some(detail.principal.lifecycle_state.clone()),
        });
    }

    let mut edges = Vec::new();
    let mut seen_edges = HashSet::new();
    let mut hidden_event_inbound = HashMap::<String, Vec<String>>::new();
    let mut hidden_event_outbound = HashMap::<String, Vec<(String, String)>>::new();
    for edge in snapshot.edges {
        let from = id_map.get(&edge.from).cloned();
        let to = id_map.get(&edge.to).cloned();

        match (from, to) {
            (Some(from), Some(to)) => {
                if !seen_nodes.contains(&from) || !seen_nodes.contains(&to) {
                    continue;
                }
                if seen_edges.insert((from.clone(), to.clone(), edge.kind.clone())) {
                    edges.push(crate::models::console::ConsoleGraphEdge {
                        id: edge.id.to_string(),
                        from,
                        to,
                        kind: edge.kind,
                    });
                }
            }
            (Some(from), None) if edge.to.starts_with("event:") => {
                hidden_event_inbound.entry(edge.to).or_default().push(from);
            }
            (None, Some(to)) if edge.from.starts_with("event:") => {
                hidden_event_outbound
                    .entry(edge.from)
                    .or_default()
                    .push((to, edge.kind));
            }
            _ => {}
        }
    }

    for (event_id, inbound_nodes) in hidden_event_inbound {
        let Some(outbound_nodes) = hidden_event_outbound.get(&event_id) else {
            continue;
        };
        for from in inbound_nodes {
            for (to, kind) in outbound_nodes {
                if !seen_nodes.contains(&from) || !seen_nodes.contains(to) {
                    continue;
                }
                if seen_edges.insert((from.clone(), to.clone(), kind.clone())) {
                    edges.push(crate::models::console::ConsoleGraphEdge {
                        id: format!("{event_id}:{from}:{to}:{kind}"),
                        from: from.clone(),
                        to: to.clone(),
                        kind: kind.clone(),
                    });
                }
            }
        }
    }

    if edges.is_empty() && nodes.len() <= 1 {
        return fallback;
    }

    ConsoleGraphView {
        root_principal_id: detail.principal.principal_id.clone(),
        nodes,
        edges,
        generated_at: snapshot.generated_at,
    }
}

fn map_graph_node_kind(value: &str) -> Option<ConsoleGraphNodeKind> {
    match value {
        "principal" => Some(ConsoleGraphNodeKind::Principal),
        "session" => Some(ConsoleGraphNodeKind::Session),
        "grant" => Some(ConsoleGraphNodeKind::Grant),
        "approval" => Some(ConsoleGraphNodeKind::Approval),
        "response_action" => Some(ConsoleGraphNodeKind::ResponseAction),
        _ => None,
    }
}

fn strip_node_prefix(value: &str) -> String {
    match value.split_once(':') {
        Some((
            "principal" | "session" | "grant" | "approval" | "event" | "response_action",
            rest,
        )) => rest.to_string(),
        _ => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::stream_subject;

    #[test]
    fn console_stream_subject_uses_tenant_envelope_scope() {
        assert_eq!(
            stream_subject("acme"),
            "tenant-acme.clawdstrike.spine.envelope.>"
        );
    }
}
