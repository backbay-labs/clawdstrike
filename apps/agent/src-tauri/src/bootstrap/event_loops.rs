//! Long-running event-consumer loops spawned by `run_agent`.
//!
//! These functions take their dependencies by clone and spawn one tokio
//! task each. They were extracted from `run_agent` to keep the orchestrator
//! readable. Each task respects the global shutdown broadcast.

use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Runtime};
use tokio::sync::{broadcast, RwLock};

use crate::approval::{self, ApprovalQueue};
use crate::approval_outbox;
use crate::daemon::{AuditQueue, DaemonManager, DaemonState, PolicyCache};
use crate::events::EventManager;
use crate::notifications::{self, show_policy_reload_notification, NotificationManager};
use crate::session::SessionManager;
use crate::settings::Settings;
use crate::tray::TrayManager;

use super::log_audit_flush_failure;

/// Spawn the periodic audit-outbox flush loop. Runs every 5s if the queue has items.
pub(super) fn spawn_periodic_audit_flush(
    audit_queue: Arc<AuditQueue>,
    settings: Arc<RwLock<Settings>>,
    mut periodic_shutdown: broadcast::Receiver<()>,
) {
    tokio::spawn(async move {
        let flush_interval = Duration::from_secs(5);
        loop {
            tokio::select! {
                _ = periodic_shutdown.recv() => {
                    tracing::debug!("Periodic audit-outbox flush loop shutting down");
                    break;
                }
                _ = tokio::time::sleep(flush_interval) => {
                    if audit_queue.len().await == 0 {
                        continue;
                    }
                    let (daemon_url, api_key) = {
                        let guard = settings.read().await;
                        (guard.daemon_url(), guard.api_key.clone())
                    };
                    match audit_queue.flush(&daemon_url, api_key.as_deref()).await {
                        Ok(outcome) if outcome.partial_rejection => {
                            tracing::warn!(
                                count = outcome.accepted,
                                duplicates = outcome.duplicates,
                                rejected = outcome.rejected,
                                "Durable audit outbox flush partially succeeded; rejected entries remain queued"
                            );
                        }
                        Ok(outcome) if outcome.accepted > 0 => {
                            tracing::debug!(count = outcome.accepted, "Flushed durable audit outbox");
                        }
                        Ok(_) => {}
                        Err(err) => log_audit_flush_failure(&err, "Durable audit outbox flush failed"),
                    }
                }
            }
        }
    });
}

/// Subscribe to daemon state transitions and re-establish the session +
/// resync caches when the daemon comes back up.
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_daemon_state_watcher<R: Runtime>(
    daemon_manager: Arc<DaemonManager>,
    tray_manager: Arc<TrayManager<R>>,
    audit_queue: Arc<AuditQueue>,
    policy_cache: Arc<PolicyCache>,
    settings: Arc<RwLock<Settings>>,
    session_manager: Arc<SessionManager>,
    shutdown_tx: broadcast::Sender<()>,
) {
    let mut daemon_rx = daemon_manager.subscribe();
    tokio::spawn(async move {
        while let Ok(state) = daemon_rx.recv().await {
            tray_manager.set_daemon_state(state.clone()).await;

            // On reconnect: re-establish session, flush queued audit events, resync policy cache.
            if state == DaemonState::Running {
                let (daemon_url, api_key) = {
                    let guard = settings.read().await;
                    (guard.daemon_url(), guard.api_key.clone())
                };

                // Re-establish session (previous session may have expired on daemon restart).
                match session_manager
                    .create_session(&daemon_url, api_key.as_deref())
                    .await
                {
                    Ok(session_id) => {
                        tracing::info!(session_id = %session_id, "Session re-established after daemon reconnect");
                        let session_state = session_manager.state().await;
                        tray_manager
                            .set_session_info(Some(session_state.summary()))
                            .await;
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            "Failed to re-establish session after daemon reconnect (retrying in background)"
                        );
                        session_manager.start_ensure_session(
                            daemon_url.clone(),
                            api_key.clone(),
                            shutdown_tx.subscribe(),
                        );
                    }
                }

                if audit_queue.len().await > 0 {
                    match audit_queue.flush(&daemon_url, api_key.as_deref()).await {
                        Ok(outcome) if outcome.partial_rejection => {
                            tracing::warn!(
                                count = outcome.accepted,
                                duplicates = outcome.duplicates,
                                rejected = outcome.rejected,
                                "Flushed queued audit events after reconnect with rejected entries still queued"
                            )
                        }
                        Ok(outcome) => {
                            tracing::info!(
                                count = outcome.accepted,
                                "Flushed queued audit events after reconnect"
                            )
                        }
                        Err(err) => log_audit_flush_failure(
                            &err,
                            "Failed to flush audit queue after reconnect",
                        ),
                    }
                }
                if let Err(err) = policy_cache
                    .sync_from_daemon(&daemon_url, api_key.as_deref())
                    .await
                {
                    tracing::debug!(error = %err, "Policy cache resync after reconnect failed");
                }
            }
        }
    });
}

/// Spawn the event-manager driver task and the tray/notification consumer.
pub(super) fn spawn_policy_event_consumer<R: Runtime>(
    app: AppHandle<R>,
    event_manager: Arc<EventManager>,
    tray_manager: Arc<TrayManager<R>>,
    settings: Arc<RwLock<Settings>>,
    shutdown_tx: &broadcast::Sender<()>,
) {
    let event_shutdown = shutdown_tx.subscribe();
    let event_mgr = event_manager.clone();
    tokio::spawn(async move {
        event_mgr.start(event_shutdown).await;
    });

    let mut events_rx = event_manager.subscribe();
    let notification_manager = NotificationManager::new(app.clone(), settings.clone());
    let tray_for_events = tray_manager.clone();
    tokio::spawn(async move {
        loop {
            match events_rx.recv().await {
                Ok(event) => {
                    tray_for_events.add_event(event.clone()).await;
                    notification_manager.notify(&event).await;
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(
                        skipped,
                        "Policy event consumer lagged; skipping dropped events"
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    tracing::info!("Policy event channel closed");
                    break;
                }
            }
        }
    });
}

/// Subscribe to daemon-level SSE events (policy updates, violations,
/// posture transitions, heartbeats) and reflect them in the tray and
/// in-process state.
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_daemon_sse_consumer<R: Runtime>(
    app: AppHandle<R>,
    event_manager: Arc<EventManager>,
    tray_manager: Arc<TrayManager<R>>,
    policy_cache: Arc<PolicyCache>,
    session_manager: Arc<SessionManager>,
    settings: Arc<RwLock<Settings>>,
) {
    let mut daemon_events_rx = event_manager.subscribe_daemon_events();
    let notification_manager_for_sse = NotificationManager::new(app.clone(), settings.clone());
    tokio::spawn(async move {
        use crate::events::DaemonEvent;

        loop {
            let event = match daemon_events_rx.recv().await {
                Ok(event) => event,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(
                        skipped,
                        "Daemon event consumer lagged; skipping dropped events"
                    );
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    tracing::info!("Daemon event channel closed");
                    break;
                }
            };

            match event {
                DaemonEvent::PolicyUpdated { version } => {
                    tracing::info!(version = ?version, "Received policy_updated event from hushd");
                    let (daemon_url, api_key) = {
                        let guard = settings.read().await;
                        (guard.daemon_url(), guard.api_key.clone())
                    };
                    if let Err(err) = policy_cache
                        .sync_from_daemon(&daemon_url, api_key.as_deref())
                        .await
                    {
                        tracing::warn!(error = %err, "Failed to refresh policy cache after update event");
                    } else {
                        show_policy_reload_notification(&app, true);
                    }
                }
                DaemonEvent::Violation {
                    guard,
                    message: _,
                    severity,
                    target,
                    session_id,
                    agent_id,
                } => {
                    tracing::info!(
                        guard = ?guard,
                        severity = ?severity,
                        target = ?target,
                        session_id = ?session_id,
                        agent_id = ?agent_id,
                        "Received violation event from hushd"
                    );
                    // Notification is handled via PolicyEvent → NotificationManager
                    // for consistent severity filtering and attribution.
                }
                DaemonEvent::SessionPostureTransition {
                    session_id,
                    from,
                    to,
                } => {
                    let new_posture = to.unwrap_or_else(|| "unknown".to_string());
                    let old_posture = from.unwrap_or_else(|| "unknown".to_string());
                    tracing::info!(
                        from = %old_posture,
                        to = %new_posture,
                        "Session posture transition"
                    );

                    // Keep the exposed session state in sync with SSE posture updates so the agent
                    // health endpoint doesn't lag behind the tray display until the next heartbeat.
                    let _ = session_manager
                        .update_posture_from_daemon_event(
                            session_id.as_deref(),
                            new_posture.clone(),
                        )
                        .await;

                    let session_state = session_manager.state().await;
                    let summary = if session_state.session_id.is_some() {
                        session_state.summary()
                    } else {
                        format!("Posture: {}", new_posture)
                    };
                    tray_manager.set_session_info(Some(summary)).await;

                    notification_manager_for_sse
                        .notify_posture_transition(&old_posture, &new_posture)
                        .await;
                }
                DaemonEvent::AgentHeartbeat {
                    endpoint_agent_id,
                    runtime_agent_id,
                    runtime_agent_kind,
                    session_id,
                    posture,
                    policy_version,
                    daemon_version,
                    timestamp,
                } => {
                    tracing::debug!(
                        endpoint_agent_id = ?endpoint_agent_id,
                        runtime_agent_id = ?runtime_agent_id,
                        runtime_agent_kind = ?runtime_agent_kind,
                        session_id = ?session_id,
                        posture = ?posture,
                        policy_version = ?policy_version,
                        daemon_version = ?daemon_version,
                        timestamp = ?timestamp,
                        "Received agent heartbeat event from hushd"
                    );
                }
            }
        }
    });
}

/// Spawn the approval-event consumer that drives notifications, the tray
/// badge, and the durable cloud outbox enqueue.
pub(super) fn spawn_approval_event_consumer<R: Runtime>(
    app: AppHandle<R>,
    approval_queue: Arc<ApprovalQueue>,
    tray_manager: Arc<TrayManager<R>>,
    approval_request_outbox: Option<Arc<approval_outbox::ApprovalRequestOutbox>>,
    shutdown_tx: &broadcast::Sender<()>,
) {
    approval_queue.start_cleanup(shutdown_tx.subscribe());
    let mut approval_events_rx = approval_queue.subscribe();
    let approval_queue_for_events = approval_queue.clone();
    tokio::spawn(async move {
        loop {
            let event = match approval_events_rx.recv().await {
                Ok(event) => event,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(
                        skipped,
                        "Approval event consumer lagged; skipping dropped events"
                    );
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    tracing::info!("Approval event channel closed");
                    break;
                }
            };

            match &event {
                approval::ApprovalEvent::NewRequest { request } => {
                    if let Some(outbox) = approval_request_outbox.as_ref() {
                        if let Err(err) = outbox.enqueue(request).await {
                            tracing::warn!(
                                error = %err,
                                request_id = %request.id,
                                "Failed to persist approval request to durable outbox"
                            );
                        }
                    }
                    let title = format!("Approval Required: {}", request.tool);
                    let body = format!("{}\n{}", request.resource, request.reason);
                    notifications::show_notification(&app, &title, &body);
                    let count = approval_queue_for_events.pending_count().await;
                    tray_manager.set_approval_badge(count).await;
                }
                approval::ApprovalEvent::Resolved { .. }
                | approval::ApprovalEvent::Expired { .. } => {
                    let count = approval_queue_for_events.pending_count().await;
                    tray_manager.set_approval_badge(count).await;
                }
            }
        }
    });
}
