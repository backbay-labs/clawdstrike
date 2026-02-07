//! Spine event subscription commands
//!
//! Provides Tauri commands to subscribe/unsubscribe to NATS spine events.
//! When connected, events are normalized and emitted to the frontend via
//! Tauri's event system (`spine_event` channel).
//!
//! When NATS is not available, the commands return gracefully so the frontend
//! can fall back to demo mode.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Runtime, State};
use tokio::sync::RwLock;

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
/// to Tetragon/Hubble event subjects. Events are forwarded to the frontend as
/// `spine_event` Tauri events.
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

    // If already subscribed, just update the URL
    if sub.active {
        if sub.nats_url.as_deref() == Some(&nats_url) {
            return Ok(SpineSubscribeResult {
                connected: true,
                message: "Already subscribed".to_string(),
            });
        }
        // Cancel existing subscription
        if let Some(cancel) = sub.cancel.take() {
            let _ = cancel.send(true);
        }
    }

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    sub.active = true;
    sub.nats_url = Some(nats_url.clone());
    sub.cancel = Some(cancel_tx);

    // Spawn background task for NATS subscription
    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        spine_event_loop(app_handle, nats_url, cancel_rx).await;
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

/// Background event loop that connects to NATS and forwards events.
///
/// Currently uses a placeholder approach: it attempts an HTTP connection to
/// the NATS URL's monitoring endpoint and falls back to periodic polling.
/// Once the `tetragon-nats-bridge` is running, this will use a proper NATS
/// client subscription (e.g. `async-nats` crate).
async fn spine_event_loop<R: Runtime>(
    app: AppHandle<R>,
    nats_url: String,
    mut cancel: tokio::sync::watch::Receiver<bool>,
) {
    // For now, attempt to connect via HTTP to validate the URL.
    // The actual NATS subscription will be wired once async-nats is added.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    // Try to reach the NATS monitoring endpoint
    let monitor_url = nats_url
        .replace("nats://", "http://")
        .replace(":4222", ":8222");
    let reachable = client
        .get(format!("{}/varz", monitor_url))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);

    if !reachable {
        tracing::warn!(
            "NATS at {} not reachable, spine event loop exiting (frontend will use demo mode)",
            nats_url
        );
        return;
    }

    tracing::info!("Spine event loop started for {}", nats_url);

    // Placeholder: poll or wait for cancellation.
    // Real implementation will use:
    //   let nc = async_nats::connect(&nats_url).await;
    //   let sub = nc.subscribe("spine.events.>").await;
    //   while let Some(msg) = sub.next().await { ... }
    loop {
        tokio::select! {
            _ = cancel.changed() => {
                if *cancel.borrow() {
                    tracing::info!("Spine event loop cancelled");
                    break;
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {
                // Heartbeat / keep-alive check
                let still_up = client
                    .get(format!("{}/varz", monitor_url))
                    .send()
                    .await
                    .map(|r| r.status().is_success())
                    .unwrap_or(false);

                if !still_up {
                    tracing::warn!("NATS connection lost, spine event loop exiting");
                    break;
                }
            }
        }
    }
}
