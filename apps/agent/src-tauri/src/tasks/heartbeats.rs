//! Periodic heartbeat loops.
//!
//! These two long-running tokio tasks keep hushd and the upstream NATS
//! telemetry stream aware that this endpoint is still alive. They are
//! extracted from `main.rs` so that the orchestrator can stay focused on
//! wiring components together.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, RwLock};

use crate::daemon::{self, DaemonManager};
use crate::macos::MacosHostService;
use crate::runtime_registry::resolve_effective_endpoint_agent_id;
use crate::session::SessionManager;
use crate::settings::{self, Settings};
use crate::telemetry_publisher;

/// Periodic NATS heartbeat loop that publishes session state to the telemetry stream.
pub async fn nats_heartbeat_loop(
    telemetry: Arc<telemetry_publisher::TelemetryPublisher>,
    session_manager: Arc<SessionManager>,
    policy_cache: Arc<daemon::PolicyCache>,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    let heartbeat_interval = Duration::from_secs(30);
    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                tracing::debug!("NATS heartbeat loop shutting down");
                break;
            }
            _ = tokio::time::sleep(heartbeat_interval) => {
                let state = session_manager.state().await;
                let hostname = settings::hostname_best_effort();
                let last_policy_version = policy_cache.cached_policy_version().await;
                let heartbeat = serde_json::json!({
                    "agent_id": telemetry.agent_id(),
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "session_id": state.session_id,
                    "posture": state.posture,
                    "budget_used": state.budget_used,
                    "budget_limit": state.budget_limit,
                    "mode": "connected",
                    "last_policy_version": last_policy_version,
                    "hostname": hostname,
                    "version": env!("CARGO_PKG_VERSION"),
                });
                let payload = serde_json::to_vec(&heartbeat).unwrap_or_default();
                telemetry.publish_heartbeat(&payload).await;
            }
        }
    }
}

/// Periodic local heartbeat loop that updates hushd endpoint/runtime liveness state.
pub async fn local_heartbeat_loop(
    settings: Arc<RwLock<Settings>>,
    session_manager: Arc<SessionManager>,
    policy_cache: Arc<daemon::PolicyCache>,
    daemon_manager: Arc<DaemonManager>,
    macos_host: Arc<MacosHostService>,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let interval = Duration::from_secs(30);

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                tracing::debug!("Local heartbeat loop shutting down");
                break;
            }
            _ = tokio::time::sleep(interval) => {
                let (daemon_url, api_key, endpoint_agent_id, runtime_identities) = {
                    let mut guard = settings.write().await;
                    let endpoint_agent_id =
                        resolve_effective_endpoint_agent_id(&mut guard, None);
                    let staleness_threshold = chrono::Utc::now() - chrono::Duration::minutes(5);
                    let runtime_identities = guard
                        .runtime_registry
                        .runtimes
                        .iter()
                        .filter(|runtime| {
                            chrono::DateTime::parse_from_rfc3339(&runtime.last_seen_at)
                                .map(|ts| ts >= staleness_threshold)
                                .unwrap_or(false)
                        })
                        .map(|runtime| {
                            (
                                runtime.runtime_agent_id.clone(),
                                runtime.runtime_agent_kind.clone(),
                                runtime.endpoint_agent_id.clone(),
                            )
                        })
                        .collect::<Vec<_>>();
                    (guard.daemon_url(), guard.api_key.clone(), endpoint_agent_id, runtime_identities)
                };

                let session_state = session_manager.state().await;
                let daemon_status = daemon_manager.status().await;
                let policy_version = policy_cache.cached_policy_version().await;
                let macos_host_status = macos_host.snapshot().await;
                let heartbeat_base = serde_json::json!({
                    "endpoint_agent_id": endpoint_agent_id,
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "session_id": session_state.session_id,
                    "posture": session_state.posture,
                    "policy_version": policy_version,
                    "daemon_version": daemon_status.version,
                    "macos_host": macos_host_status,
                });

                let send_heartbeat = |payload: serde_json::Value| {
                    let client = client.clone();
                    let daemon_url = daemon_url.clone();
                    let api_key = api_key.clone();
                    async move {
                        let mut request = client
                            .post(format!("{}/api/v1/agent/heartbeat", daemon_url))
                            .json(&payload);
                        if let Some(key) = api_key.as_deref() {
                            request = request.header("Authorization", format!("Bearer {}", key));
                        }
                        request.send().await
                    }
                };

                match send_heartbeat(heartbeat_base.clone()).await {
                    Ok(response) if response.status().is_success() => {
                        for (runtime_agent_id, runtime_agent_kind, runtime_endpoint_agent_id) in runtime_identities {
                            let runtime_heartbeat = serde_json::json!({
                                "endpoint_agent_id": if runtime_endpoint_agent_id.trim().is_empty() {
                                    heartbeat_base
                                        .get("endpoint_agent_id")
                                        .and_then(serde_json::Value::as_str)
                                        .unwrap_or_default()
                                } else {
                                    runtime_endpoint_agent_id.as_str()
                                },
                                "runtime_agent_id": runtime_agent_id,
                                "runtime_agent_kind": runtime_agent_kind,
                                "timestamp": heartbeat_base.get("timestamp").cloned(),
                                "session_id": heartbeat_base.get("session_id").cloned(),
                                "posture": heartbeat_base.get("posture").cloned(),
                                "policy_version": heartbeat_base.get("policy_version").cloned(),
                                "daemon_version": heartbeat_base.get("daemon_version").cloned(),
                            });
                            match send_heartbeat(runtime_heartbeat.clone()).await {
                                Ok(runtime_response) if runtime_response.status().is_success() => {}
                                Ok(runtime_response) => {
                                    tracing::debug!(
                                        status = %runtime_response.status(),
                                        runtime_agent_id = %runtime_heartbeat
                                            .get("runtime_agent_id")
                                            .and_then(serde_json::Value::as_str)
                                            .unwrap_or(""),
                                        "Runtime heartbeat POST returned non-success status"
                                    );
                                }
                                Err(err) => {
                                    tracing::debug!(error = %err, "Failed to send runtime heartbeat");
                                }
                            }
                        }
                    }
                    Ok(response) => {
                        tracing::debug!(
                            status = %response.status(),
                            "Local heartbeat POST returned non-success status"
                        );
                    }
                    Err(err) => {
                        tracing::debug!(error = %err, "Failed to send local heartbeat");
                    }
                }
            }
        }
    }
}
