//! Fleet hunt-event outbox: identity resolution, enqueue, retry, and best-effort drain.

use super::super::*;
use anyhow::Result;
use axum::http::StatusCode;
use hush_core::sha256;
use std::sync::Arc;
use tokio::sync::broadcast;

pub(crate) struct FleetHuntPublishContext {
    pub(crate) publisher: Arc<dyn FleetHuntEventPublisher>,
    pub(crate) tenant_id: String,
    pub(crate) endpoint_agent_id: String,
}

pub(crate) struct FleetHuntEventIdentity {
    pub(crate) publisher: Option<Arc<dyn FleetHuntEventPublisher>>,
    pub(crate) tenant_id: String,
    pub(crate) endpoint_agent_id: String,
}

pub(crate) async fn fleet_hunt_publish_context(
    state: &AgentApiState,
) -> Result<FleetHuntPublishContext, (StatusCode, String)> {
    let publisher = state
        .fleet_hunt_publisher
        .as_ref()
        .cloned()
        .ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "fleet hunt publisher is unavailable because NATS is not connected".to_string(),
            )
        })?;
    let settings = state.settings.read().await;
    let tenant_id = settings.nats.tenant_id.clone().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "fleet hunt publisher is unavailable because nats.tenant_id is not configured"
                .to_string(),
        )
    })?;
    let endpoint_agent_id = settings
        .nats
        .agent_id
        .clone()
        .unwrap_or_else(|| publisher.agent_id().to_string());
    Ok(FleetHuntPublishContext {
        publisher,
        tenant_id,
        endpoint_agent_id,
    })
}

pub(crate) async fn fleet_hunt_event_identity(
    state: &AgentApiState,
) -> Result<FleetHuntEventIdentity, (StatusCode, String)> {
    let publisher = state.fleet_hunt_publisher.as_ref().cloned();
    let settings = state.settings.read().await;
    let tenant_id = settings.nats.tenant_id.clone().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "fleet hunt event identity is unavailable because nats.tenant_id is not configured"
                .to_string(),
        )
    })?;
    let endpoint_agent_id = settings
        .nats
        .agent_id
        .clone()
        .or_else(|| {
            publisher
                .as_ref()
                .map(|publisher| publisher.agent_id().to_string())
        })
        .ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "fleet hunt event identity is unavailable because nats.agent_id is not configured"
                    .to_string(),
            )
        })?;
    Ok(FleetHuntEventIdentity {
        publisher,
        tenant_id,
        endpoint_agent_id,
    })
}

pub(crate) async fn enqueue_fleet_hunt_event_outbox(
    state: &AgentApiState,
    event: serde_json::Value,
    error: Option<&str>,
) -> Result<(String, chrono::DateTime<chrono::Utc>), (StatusCode, String)> {
    let event_id = event
        .get("eventId")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "fleet hunt event is missing eventId".to_string(),
            )
        })?
        .to_string();
    let raw_ref = event
        .get("evidence")
        .and_then(|evidence| evidence.get("rawRef"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "fleet hunt event is missing evidence.rawRef".to_string(),
            )
        })?
        .to_string();
    let now = chrono::Utc::now();
    let attempt_count = 1;
    let outbox_id = sha256(format!("{event_id}:{raw_ref}").as_bytes()).to_hex_prefixed();
    let next_attempt_at =
        now + chrono::Duration::seconds(control_ack_retry_backoff_seconds(attempt_count));
    let event = EndpointFleetHuntEventOutboxEntry {
        outbox_id: outbox_id.clone(),
        event_id,
        raw_ref,
        event,
        attempt_count,
        next_attempt_at,
        last_attempt_at: Some(now),
        last_error_hash: error.map(|error| sha256(error.as_bytes()).to_hex_prefixed()),
        created_at: now,
        updated_at: now,
    };
    state
        .edr_fleet_hunt_event_outbox
        .lock()
        .await
        .append(event)
        .map_err(internal_error)?;
    Ok((outbox_id, next_attempt_at))
}

pub(crate) struct FleetHuntEventRetryAttemptOutcome {
    pub(crate) delivered: bool,
    pub(crate) error_hash: Option<String>,
}

async fn send_fleet_hunt_event_outbox_retry(
    publisher: &dyn FleetHuntEventPublisher,
    event: &EndpointFleetHuntEventOutboxEntry,
) -> FleetHuntEventRetryAttemptOutcome {
    let payload = match serde_json::to_vec(&event.event) {
        Ok(payload) => payload,
        Err(err) => {
            let error = truncate_delivery_error(&format!("serialize fleet hunt event: {err}"));
            return FleetHuntEventRetryAttemptOutcome {
                delivered: false,
                error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
            };
        }
    };

    match publisher.publish_hunt_event(&payload).await {
        Ok(()) => FleetHuntEventRetryAttemptOutcome {
            delivered: true,
            error_hash: None,
        },
        Err(err) => {
            let error = truncate_delivery_error(&err.to_string());
            FleetHuntEventRetryAttemptOutcome {
                delivered: false,
                error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
            }
        }
    }
}

pub(crate) async fn drain_fleet_hunt_event_outbox(
    state: &AgentApiState,
    publisher: Arc<dyn FleetHuntEventPublisher>,
    limit: usize,
    force: bool,
) -> Result<EdrFleetHuntEventRetryResponse, (StatusCode, String)> {
    let limit = limit.clamp(1, 100);
    let now = chrono::Utc::now();
    let (path, pending_before, due) = {
        let outbox = state.edr_fleet_hunt_event_outbox.lock().await;
        (
            outbox.path().map(|path| path.display().to_string()),
            outbox.pending_count(),
            outbox.due(now, limit, force),
        )
    };

    let mut attempts = Vec::new();
    let mut delivered = 0usize;
    let mut failed = 0usize;
    for event in due {
        let outcome = send_fleet_hunt_event_outbox_retry(publisher.as_ref(), &event).await;
        let attempted_count = event.attempt_count.saturating_add(1);
        if outcome.delivered {
            delivered += 1;
            let mut outbox = state.edr_fleet_hunt_event_outbox.lock().await;
            outbox
                .mark_delivered(&event.outbox_id)
                .map_err(internal_error)?;
            attempts.push(EdrFleetHuntEventRetryAttemptRecord {
                outbox_id: event.outbox_id,
                event_id: event.event_id,
                raw_ref: event.raw_ref,
                delivered: true,
                attempt_count: attempted_count,
                next_attempt_at: None,
                error_hash: None,
            });
        } else {
            failed += 1;
            let mut outbox = state.edr_fleet_hunt_event_outbox.lock().await;
            let updated = outbox
                .mark_failed(
                    &event.outbox_id,
                    chrono::Utc::now(),
                    outcome.error_hash.clone(),
                )
                .map_err(internal_error)?
                .unwrap_or_else(|| event.clone());
            attempts.push(EdrFleetHuntEventRetryAttemptRecord {
                outbox_id: event.outbox_id,
                event_id: event.event_id,
                raw_ref: event.raw_ref,
                delivered: false,
                attempt_count: updated.attempt_count,
                next_attempt_at: Some(updated.next_attempt_at),
                error_hash: outcome.error_hash,
            });
        }
    }

    let pending = state
        .edr_fleet_hunt_event_outbox
        .lock()
        .await
        .pending_count();
    Ok(EdrFleetHuntEventRetryResponse {
        path,
        attempted: attempts.len(),
        delivered,
        failed,
        skipped: pending_before.saturating_sub(attempts.len()),
        pending,
        attempts,
    })
}

pub(crate) async fn drain_due_fleet_hunt_event_outbox_best_effort(
    state: &AgentApiState,
    source: &'static str,
) {
    let Some(publisher) = state.fleet_hunt_publisher.as_ref().cloned() else {
        return;
    };
    match drain_fleet_hunt_event_outbox(
        state,
        publisher,
        EDR_MAX_AUTO_FLEET_HUNT_EVENT_OUTBOX_RETRIES_PER_BATCH,
        false,
    )
    .await
    {
        Ok(response) if response.attempted > 0 => {
            tracing::info!(
                attempted = response.attempted,
                delivered = response.delivered,
                failed = response.failed,
                pending = response.pending,
                source,
                "Drained queued fleet hunt events"
            );
        }
        Ok(_) => {}
        Err((_, err)) => {
            tracing::warn!(
                error = %err,
                source,
                "Failed to drain queued fleet hunt events"
            );
        }
    }
}

pub(crate) async fn fleet_agent_secret_touch_sync_loop(
    state: Arc<AgentApiState>,
    shutdown_rx: &mut broadcast::Receiver<()>,
) {
    drain_due_fleet_hunt_event_outbox_best_effort(state.as_ref(), "fleet_sync_startup").await;
    publish_persisted_agent_secret_touches_to_fleet_best_effort(state.as_ref()).await;
    let mut interval = tokio::time::interval(EDR_FLEET_AGENT_SECRET_TOUCH_SYNC_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval.tick().await;
    loop {
        tokio::select! {
            _ = interval.tick() => {
                drain_due_fleet_hunt_event_outbox_best_effort(
                    state.as_ref(),
                    "fleet_sync_interval",
                )
                .await;
                publish_persisted_agent_secret_touches_to_fleet_best_effort(state.as_ref()).await;
            }
            shutdown = shutdown_rx.recv() => {
                if shutdown.is_err() {
                    tracing::debug!("Fleet agent-secret-touch sync shutdown channel closed");
                }
                break;
            }
        }
    }
}
