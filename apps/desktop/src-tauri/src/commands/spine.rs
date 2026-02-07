//! Spine event subscription commands
//!
//! Provides Tauri commands to subscribe/unsubscribe to NATS spine events.
//! When connected, signed envelopes are deserialized and their `fact` payloads
//! are emitted to the frontend via Tauri's event system (`spine_event` channel).
//!
//! When NATS is not available, the commands return gracefully so the frontend
//! can fall back to demo mode.

use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Runtime, State};

use crate::state::AppState;

/// Spine subscription status stored in AppState
pub struct SpineSubscription {
    pub active: bool,
    pub nats_url: Option<String>,
    pub cancel: Option<tokio::sync::watch::Sender<bool>>,
}

impl Default for SpineSubscription {
    fn default() -> Self {
        Self {
            active: false,
            nats_url: None,
            cancel: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SpineSubscribeResult {
    pub connected: bool,
    pub message: String,
}

/// Subscribe to spine events via NATS.
///
/// This starts a background task that connects to the NATS server and subscribes
/// to `clawdstrike.spine.envelope.>`. Each message is deserialized as a signed
/// envelope, and the full envelope JSON is forwarded to the frontend as a
/// `spine_event` Tauri event.
///
/// If the NATS connection fails, returns a result indicating the failure so the
/// frontend can fall back to demo mode.
#[tauri::command]
pub async fn subscribe_spine_events<R: Runtime>(
    app: AppHandle<R>,
    nats_url: String,
    state: State<'_, AppState>,
) -> Result<SpineSubscribeResult, String> {
    let mut sub = state.spine_subscription.write().await;

    // If already subscribed to the same URL, return early
    if sub.active {
        if sub.nats_url.as_deref() == Some(&nats_url) {
            return Ok(SpineSubscribeResult {
                connected: true,
                message: "Already subscribed".to_string(),
            });
        }
        // Cancel existing subscription before reconnecting
        if let Some(cancel) = sub.cancel.take() {
            let _ = cancel.send(true);
        }
    }

    // Attempt NATS connection before spawning the background task.
    // This lets us report connection errors synchronously.
    let client = async_nats::connect(&nats_url).await.map_err(|e| {
        tracing::warn!("Failed to connect to NATS at {}: {}", nats_url, e);
        format!("NATS connection failed: {e}")
    })?;

    let nats_sub = client
        .subscribe("clawdstrike.spine.envelope.>")
        .await
        .map_err(|e| {
            tracing::warn!("Failed to subscribe to spine envelopes: {}", e);
            format!("NATS subscribe failed: {e}")
        })?;

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    sub.active = true;
    sub.nats_url = Some(nats_url.clone());
    sub.cancel = Some(cancel_tx);

    tracing::info!("Connected to NATS at {}, subscribing to spine envelopes", nats_url);

    // Spawn background task for NATS subscription
    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        spine_event_loop(app_handle, nats_sub, cancel_rx).await;
    });

    Ok(SpineSubscribeResult {
        connected: true,
        message: "Subscription started".to_string(),
    })
}

/// Unsubscribe from spine events.
#[tauri::command]
pub async fn unsubscribe_spine_events(
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut sub = state.spine_subscription.write().await;

    if let Some(cancel) = sub.cancel.take() {
        let _ = cancel.send(true);
    }
    sub.active = false;
    sub.nats_url = None;

    Ok(())
}

/// Get current spine subscription status.
#[tauri::command]
pub async fn spine_status(
    state: State<'_, AppState>,
) -> Result<SpineSubscribeResult, String> {
    let sub = state.spine_subscription.read().await;

    Ok(SpineSubscribeResult {
        connected: sub.active,
        message: if sub.active {
            format!("Connected to {}", sub.nats_url.as_deref().unwrap_or("unknown"))
        } else {
            "Not connected".to_string()
        },
    })
}

/// Background event loop that reads NATS messages and emits them to the frontend.
///
/// Each message payload is expected to be a JSON signed envelope. The full
/// envelope (including `fact`, `issuer`, `envelope_hash`, etc.) is emitted
/// as the `spine_event` Tauri event so the frontend normalizer can pick it apart.
async fn spine_event_loop<R: Runtime>(
    app: AppHandle<R>,
    mut subscription: async_nats::Subscriber,
    mut cancel: tokio::sync::watch::Receiver<bool>,
) {
    tracing::info!("Spine event loop started");

    loop {
        tokio::select! {
            _ = cancel.changed() => {
                if *cancel.borrow() {
                    tracing::info!("Spine event loop cancelled");
                    break;
                }
            }
            msg = subscription.next() => {
                let Some(msg) = msg else {
                    tracing::warn!("NATS subscription stream ended");
                    break;
                };

                // Parse the envelope JSON from the message payload
                let envelope: serde_json::Value = match serde_json::from_slice(&msg.payload) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(
                            subject = %msg.subject,
                            "Failed to parse spine envelope: {}",
                            e
                        );
                        continue;
                    }
                };

                // Extract the `fact` object from the envelope to determine
                // what kind of event this is, but emit the full envelope so
                // the frontend normalizer has access to all fields.
                let payload = build_frontend_payload(&envelope, &msg.subject);

                if let Err(e) = app.emit("spine_event", &payload) {
                    tracing::warn!("Failed to emit spine_event to frontend: {}", e);
                }
            }
        }
    }

    tracing::info!("Spine event loop exited");
}

/// Build the payload to send to the frontend from a signed envelope.
///
/// The frontend's `normalizeSpinePayload` expects either:
/// - Tetragon-style: `{ process_exec | process_kprobe | process_exit, ... }`
/// - Hubble-style: `{ source, destination, verdict, ... }`
/// - Hushd-style: `{ type, data, ... }`
///
/// The spine envelope wraps these in a `fact` field with a `schema` identifier.
/// We extract the inner fact data and merge it with envelope metadata so the
/// frontend normalizer can identify the event type.
fn build_frontend_payload(
    envelope: &serde_json::Value,
    subject: &async_nats::Subject,
) -> serde_json::Value {
    let fact = envelope.get("fact").cloned().unwrap_or(serde_json::Value::Null);

    // Start with the fact object (which contains the actual event data)
    let mut payload = if let serde_json::Value::Object(map) = fact {
        serde_json::Value::Object(map)
    } else {
        // If fact isn't an object, wrap the whole envelope
        return envelope.clone();
    };

    // Merge envelope-level metadata the frontend normalizer can use
    if let Some(obj) = payload.as_object_mut() {
        // Carry over envelope metadata for richer normalization
        if let Some(issued_at) = envelope.get("issued_at") {
            obj.entry("time").or_insert_with(|| issued_at.clone());
            obj.entry("timestamp").or_insert_with(|| issued_at.clone());
        }
        if let Some(issuer) = envelope.get("issuer") {
            obj.entry("issuer").or_insert_with(|| issuer.clone());
        }
        if let Some(hash) = envelope.get("envelope_hash") {
            obj.entry("envelope_hash").or_insert_with(|| hash.clone());
        }
        // Store the NATS subject for debugging
        obj.entry("_nats_subject")
            .or_insert_with(|| serde_json::Value::String(subject.to_string()));
    }

    payload
}
