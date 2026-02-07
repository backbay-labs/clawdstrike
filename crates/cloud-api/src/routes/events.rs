use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::get;
use axum::Router;
use futures::StreamExt;
use std::convert::Infallible;
use tokio_stream::wrappers::ReceiverStream;

use crate::auth::AuthenticatedTenant;
use crate::error::ApiError;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/events/stream", get(event_stream))
}

async fn event_stream(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
) -> Result<Sse<impl futures::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    // Subscribe to tenant-scoped NATS subjects
    let subject = format!("tenant-{}.clawdstrike.spine.envelope.>", auth.slug);
    let subscriber = state
        .nats
        .subscribe(subject)
        .await
        .map_err(|e| ApiError::Nats(e.to_string()))?;

    // Bridge NATS subscription into an SSE stream via a channel
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(256);

    tokio::spawn(async move {
        let mut sub = subscriber;
        while let Some(msg) = sub.next().await {
            let data = String::from_utf8_lossy(&msg.payload).to_string();
            let event = Event::default().data(data);
            if tx.send(Ok(event)).await.is_err() {
                break;
            }
        }
    });

    let stream = ReceiverStream::new(rx);
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}
