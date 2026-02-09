//! Server-Sent Events (SSE) streaming endpoint

use std::convert::Infallible;

use axum::{
    extract::State,
    http::StatusCode,
    response::sse::{Event, Sse},
};
use futures::stream::Stream;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::auth::{AuthenticatedActor, Scope};
use crate::authz::require_api_key_scope_or_user_permission;
use crate::rbac::{Action, ResourceType};
use crate::state::{AppState, DaemonEvent};

/// GET /api/v1/events
pub async fn stream_events(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, (StatusCode, String)> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Read,
        ResourceType::AuditLog,
        Action::Read,
    )?;

    let rx = state.event_tx.subscribe();

    let stream = BroadcastStream::new(rx).filter_map(|result| {
        result.ok().map(|event: DaemonEvent| {
            Ok(Event::default()
                .event(event.event_type)
                .json_data(event.data)
                .unwrap_or_else(|_| Event::default().data("error")))
        })
    });

    Ok(Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(std::time::Duration::from_secs(30))
            .text("keep-alive"),
    ))
}
