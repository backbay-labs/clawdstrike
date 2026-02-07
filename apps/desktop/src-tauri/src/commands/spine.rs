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
use tokio::sync::RwLock;

use crate::state::AppState;

/// Default NATS URL when none is provided by the frontend.
pub const DEFAULT_NATS_URL: &str = "nats://localhost:4222";

/// Spine subscription status stored in AppState
pub struct SpineSubscription {
    pub active: bool,
    pub nats_url: Option<String>,
    pub cancel: Option<tokio::sync::watch::Sender<bool>>,
    pub event_count: u64,
    pub last_event_at: Option<String>,
    pub last_error: Option<String>,
}

impl Default for SpineSubscription {
    fn default() -> Self {
        Self {
            active: false,
            nats_url: None,
            cancel: None,
            event_count: 0,
            last_event_at: None,
            last_error: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SpineSubscribeResult {
    pub connected: bool,
    pub message: String,
}

/// Richer connection status returned by `get_spine_connection_status`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SpineConnectionStatusResult {
    pub connected: bool,
    pub nats_url: Option<String>,
    pub event_count: u64,
    pub last_event_at: Option<String>,
    pub last_error: Option<String>,
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
    nats_url: Option<String>,
    state: State<'_, AppState>,
) -> Result<SpineSubscribeResult, String> {
    let nats_url = match nats_url.as_deref() {
        Some(url) if !url.is_empty() => url.to_string(),
        _ => DEFAULT_NATS_URL.to_string(),
    };

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

    // Reset counters for new subscription
    sub.event_count = 0;
    sub.last_event_at = None;
    sub.last_error = None;

    // Attempt NATS connection before spawning the background task.
    // This lets us report connection errors synchronously.
    let client = match async_nats::connect(&nats_url).await {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("NATS connection failed: {e}");
            tracing::warn!("Failed to connect to NATS at {}: {}", nats_url, e);
            sub.last_error = Some(msg.clone());
            return Err(msg);
        }
    };

    let nats_sub = match client
        .subscribe("clawdstrike.spine.envelope.>")
        .await
    {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("NATS subscribe failed: {e}");
            tracing::warn!("Failed to subscribe to spine envelopes: {}", e);
            sub.last_error = Some(msg.clone());
            return Err(msg);
        }
    };

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    sub.active = true;
    sub.nats_url = Some(nats_url.clone());
    sub.cancel = Some(cancel_tx);

    tracing::info!("Connected to NATS at {}, subscribing to spine envelopes", nats_url);

    // Spawn background task for NATS subscription
    let app_handle = app.clone();
    let spine_sub = state.spine_subscription.clone();
    tauri::async_runtime::spawn(async move {
        spine_event_loop(app_handle, nats_sub, cancel_rx, spine_sub).await;
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
    sub.event_count = 0;
    sub.last_event_at = None;
    sub.last_error = None;

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

/// Get detailed spine connection status including event counts and errors.
#[tauri::command]
pub async fn get_spine_connection_status(
    state: State<'_, AppState>,
) -> Result<SpineConnectionStatusResult, String> {
    let sub = state.spine_subscription.read().await;

    Ok(SpineConnectionStatusResult {
        connected: sub.active,
        nats_url: sub.nats_url.clone(),
        event_count: sub.event_count,
        last_event_at: sub.last_event_at.clone(),
        last_error: sub.last_error.clone(),
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
    spine_sub: std::sync::Arc<RwLock<SpineSubscription>>,
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
                    // Record the stream ending as an error
                    let mut sub = spine_sub.write().await;
                    sub.active = false;
                    sub.last_error = Some("NATS subscription stream ended unexpectedly".to_string());
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

                // Verify envelope signature before forwarding to the frontend.
                // Fail-closed: skip any envelope that cannot be verified.
                match spine::verify_envelope(&envelope) {
                    Ok(true) => {}
                    Ok(false) => {
                        tracing::warn!(
                            subject = %msg.subject,
                            "Spine envelope signature verification failed, skipping"
                        );
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!(
                            subject = %msg.subject,
                            "Spine envelope verification error: {}, skipping",
                            e
                        );
                        continue;
                    }
                }

                // Update event counters
                {
                    let mut sub = spine_sub.write().await;
                    sub.event_count += 1;
                    sub.last_event_at = Some(chrono::Utc::now().to_rfc3339());
                }

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
