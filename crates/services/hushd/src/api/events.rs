//! Server-Sent Events (SSE) streaming endpoint

use std::collections::HashSet;
use std::convert::Infallible;

use axum::{
    extract::{Query, State},
    response::sse::{Event, Sse},
};
use futures::stream::Stream;
use serde::Deserialize;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::api::v1::V1Error;
use crate::auth::{AuthenticatedActor, Scope};
use crate::authz::require_api_key_scope_or_user_permission;
use crate::rbac::{Action, ResourceType};
use crate::state::{AppState, DaemonEvent};

#[derive(Clone, Debug, Deserialize, Default)]
pub struct EventsQuery {
    /// Comma-separated event types.
    pub event_types: Option<String>,
    pub session_id: Option<String>,
    pub endpoint_agent_id: Option<String>,
    pub runtime_agent_id: Option<String>,
    pub runtime_agent_kind: Option<String>,
}

fn normalized_opt(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn event_data_str<'a>(data: &'a serde_json::Value, keys: &[&str]) -> Option<&'a str> {
    let obj = data.as_object()?;
    keys.iter()
        .filter_map(|key| obj.get(*key))
        .find_map(|value| value.as_str())
}

fn matches_sse_filters(
    event: &DaemonEvent,
    event_types: &HashSet<String>,
    session_id: Option<&str>,
    endpoint_agent_id: Option<&str>,
    runtime_agent_id: Option<&str>,
    runtime_agent_kind: Option<&str>,
) -> bool {
    if !event_types.is_empty() && !event_types.contains(&event.event_type.to_ascii_lowercase()) {
        return false;
    }

    if let Some(expected) = session_id {
        if event_data_str(&event.data, &["session_id", "sessionId"]) != Some(expected) {
            return false;
        }
    }

    if let Some(expected) = endpoint_agent_id {
        let found = event_data_str(
            &event.data,
            &[
                "endpoint_agent_id",
                "endpointAgentId",
                "agent_id",
                "agentId",
            ],
        );
        if found != Some(expected) {
            return false;
        }
    }

    if let Some(expected) = runtime_agent_id {
        let found = event_data_str(&event.data, &["runtime_agent_id", "runtimeAgentId"]);
        if found != Some(expected) {
            return false;
        }
    }

    if let Some(expected) = runtime_agent_kind {
        let found = event_data_str(&event.data, &["runtime_agent_kind", "runtimeAgentKind"]);
        if !found
            .map(|value| value.eq_ignore_ascii_case(expected))
            .unwrap_or(false)
        {
            return false;
        }
    }

    true
}

/// GET /api/v1/events
pub async fn stream_events(
    State(state): State<AppState>,
    Query(query): Query<EventsQuery>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, V1Error> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Read,
        ResourceType::AuditLog,
        Action::Read,
    )?;

    let rx = state.event_tx.subscribe();
    let event_types = query
        .event_types
        .as_deref()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.to_ascii_lowercase())
                .collect::<HashSet<_>>()
        })
        .unwrap_or_default();
    let session_id = normalized_opt(query.session_id.as_deref());
    let endpoint_agent_id = normalized_opt(query.endpoint_agent_id.as_deref());
    let runtime_agent_id = normalized_opt(query.runtime_agent_id.as_deref());
    let runtime_agent_kind = normalized_opt(query.runtime_agent_kind.as_deref());

    let stream = BroadcastStream::new(rx).filter_map(move |result| {
        let event_types = event_types.clone();
        let session_id = session_id.clone();
        let endpoint_agent_id = endpoint_agent_id.clone();
        let runtime_agent_id = runtime_agent_id.clone();
        let runtime_agent_kind = runtime_agent_kind.clone();
        result.ok().and_then(move |event: DaemonEvent| {
            if !matches_sse_filters(
                &event,
                &event_types,
                session_id.as_deref(),
                endpoint_agent_id.as_deref(),
                runtime_agent_id.as_deref(),
                runtime_agent_kind.as_deref(),
            ) {
                return None;
            }

            Some(Ok(Event::default()
                .event(event.event_type)
                .json_data(event.data)
                .unwrap_or_else(|_| Event::default().data("error"))))
        })
    });

    Ok(Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(std::time::Duration::from_secs(30))
            .text("keep-alive"),
    ))
}
