//! Top-level orchestrator entry point.
//!
//! `run_agent` is the body of the long-running background task spawned by
//! `fn main` after the tauri builder is configured. The orchestrator
//! delegates each subsystem to a sibling submodule and then waits for the
//! shutdown broadcast before tearing everything down in order.

use std::sync::Arc;
use tauri::{AppHandle, Runtime};
use tokio::sync::{broadcast, RwLock};

use crate::api_server::{AgentApiServer, AgentApiServerDeps};
use crate::approval::ApprovalQueue;
use crate::brokerd::BrokerdManager;
use crate::daemon::{AuditQueue, DaemonManager, DaemonState, PolicyCache};
use crate::events::EventManager;
use crate::integrations::McpServer;
use crate::macos::{start_status_collector, MacosHostService};
use crate::notifications::show_startup_notification;
use crate::openclaw::OpenClawManager;
use crate::response_action_commands;
use crate::session::SessionManager;
use crate::settings::Settings;
use crate::tasks::heartbeats::local_heartbeat_loop;
use crate::tray::TrayManager;
use crate::updater::HushdUpdater;
use crate::ShutdownComplete;

use super::event_loops::{
    spawn_approval_event_consumer, spawn_daemon_sse_consumer, spawn_daemon_state_watcher,
    spawn_periodic_audit_flush, spawn_policy_event_consumer,
};
use super::listeners::register_tauri_listeners;
use super::log_audit_flush_failure;
use super::nats::setup_nats;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_agent<R: Runtime>(
    app: AppHandle<R>,
    daemon_manager: Arc<DaemonManager>,
    brokerd_manager: Arc<BrokerdManager>,
    event_manager: Arc<EventManager>,
    openclaw_manager: OpenClawManager,
    session_manager: Arc<SessionManager>,
    approval_queue: Arc<ApprovalQueue>,
    policy_cache: Arc<PolicyCache>,
    audit_queue: Arc<AuditQueue>,
    updater: Arc<HushdUpdater>,
    macos_host: Arc<MacosHostService>,
    tray_manager: Arc<TrayManager<R>>,
    settings: Arc<RwLock<Settings>>,
    shutdown_tx: broadcast::Sender<()>,
    agent_api_token: String,
    shutdown_complete: Arc<ShutdownComplete>,
) {
    let (daemon_url, api_key) = {
        let guard = settings.read().await;
        (guard.daemon_url(), guard.api_key.clone())
    };

    // Periodic liveness reporters. They no-op until a session is established.
    session_manager.start_heartbeat(daemon_url.clone(), api_key.clone(), shutdown_tx.subscribe());
    start_status_collector(app.clone(), macos_host.clone(), shutdown_tx.subscribe());
    {
        let local_hb_shutdown = shutdown_tx.subscribe();
        let settings_for_local_hb = settings.clone();
        let session_for_local_hb = session_manager.clone();
        let policy_cache_for_local_hb = policy_cache.clone();
        let daemon_for_local_hb = daemon_manager.clone();
        let macos_host_for_local_hb = macos_host.clone();
        tokio::spawn(async move {
            local_heartbeat_loop(
                settings_for_local_hb,
                session_for_local_hb,
                policy_cache_for_local_hb,
                daemon_for_local_hb,
                macos_host_for_local_hb,
                local_hb_shutdown,
            )
            .await;
        });
    }
    updater.start_background(shutdown_tx.subscribe());

    start_daemon(
        &app,
        &daemon_manager,
        &brokerd_manager,
        &session_manager,
        &policy_cache,
        &audit_queue,
        &tray_manager,
        &daemon_url,
        api_key.as_deref(),
        &shutdown_tx,
    )
    .await;

    let nats_bootstrap = setup_nats(
        &daemon_manager,
        &session_manager,
        &approval_queue,
        &policy_cache,
        &settings,
        &shutdown_tx,
        &tray_manager,
    )
    .await;

    spawn_periodic_audit_flush(
        audit_queue.clone(),
        settings.clone(),
        shutdown_tx.subscribe(),
    );

    spawn_daemon_state_watcher(
        daemon_manager.clone(),
        tray_manager.clone(),
        audit_queue.clone(),
        policy_cache.clone(),
        settings.clone(),
        session_manager.clone(),
        shutdown_tx.clone(),
    );

    spawn_policy_event_consumer(
        app.clone(),
        event_manager.clone(),
        tray_manager.clone(),
        settings.clone(),
        &shutdown_tx,
    );

    spawn_daemon_sse_consumer(
        app.clone(),
        event_manager.clone(),
        tray_manager.clone(),
        policy_cache.clone(),
        session_manager.clone(),
        settings.clone(),
    );

    spawn_approval_event_consumer(
        app.clone(),
        approval_queue.clone(),
        tray_manager.clone(),
        nats_bootstrap.approval_request_outbox.clone(),
        &shutdown_tx,
    );

    let (mcp_port, api_port) = {
        let guard = settings.read().await;
        (guard.mcp_port, guard.agent_api_port)
    };

    let mcp_server = McpServer::new(
        mcp_port,
        settings.clone(),
        session_manager.clone(),
        agent_api_token.clone(),
    );
    let mcp_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        if let Err(e) = mcp_server.start(mcp_shutdown).await {
            tracing::error!("MCP server error: {}", e);
        }
    });

    let response_action_local_api_token = agent_api_token.clone();
    let api_server = match AgentApiServer::try_new(
        api_port,
        AgentApiServerDeps {
            settings: settings.clone(),
            daemon_manager: daemon_manager.clone(),
            session_manager: session_manager.clone(),
            approval_queue: approval_queue.clone(),
            audit_queue: audit_queue.clone(),
            macos_host: macos_host.clone(),
            openclaw: openclaw_manager.clone(),
            updater: updater.clone(),
            fleet_hunt_publisher: nats_bootstrap.fleet_hunt_publisher,
            auth_token: agent_api_token,
        },
    ) {
        Ok(api_server) => api_server,
        Err(err) => {
            tracing::error!(
                error = %err,
                "Failed to initialize durable Agent API EDR state; exiting instead of running with transient evidence"
            );
            app.exit(1);
            return;
        }
    };
    let control_ack_retry_sink = api_server.control_ack_postback_retry_sink();
    let api_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        if let Err(err) = api_server.start(api_shutdown).await {
            tracing::error!("Agent API server error: {}", err);
        }
    });
    if let Some(nats) = nats_bootstrap.response_action_nats {
        let handler = response_action_commands::ResponseActionCommandHandler::new(
            nats,
            settings.clone(),
            response_action_local_api_token,
            Some(control_ack_retry_sink),
        );
        let response_action_shutdown = shutdown_tx.subscribe();
        tokio::spawn(async move {
            handler.start(response_action_shutdown).await;
        });
    }

    register_tauri_listeners(
        &app,
        settings.clone(),
        daemon_manager.clone(),
        tray_manager.clone(),
    );

    let mut shutdown_rx = shutdown_tx.subscribe();
    let _ = shutdown_rx.recv().await;

    openclaw_manager.shutdown().await;

    // Terminate session before stopping daemon.
    {
        let (daemon_url, api_key) = {
            let guard = settings.read().await;
            (guard.daemon_url(), guard.api_key.clone())
        };
        if let Err(err) = session_manager
            .terminate_session(&daemon_url, api_key.as_deref())
            .await
        {
            tracing::warn!(error = %err, "Failed to terminate session during shutdown");
        }
    }

    if let Err(err) = brokerd_manager.stop().await {
        tracing::error!(error = %err, "Error during brokerd shutdown");
    }
    if let Err(err) = daemon_manager.stop().await {
        tracing::error!("Error during daemon shutdown: {}", err);
    }
    shutdown_complete.mark_done();
    tracing::info!("Agent shutdown complete");
}

#[allow(clippy::too_many_arguments)]
async fn start_daemon<R: Runtime>(
    app: &AppHandle<R>,
    daemon_manager: &Arc<DaemonManager>,
    brokerd_manager: &Arc<BrokerdManager>,
    session_manager: &Arc<SessionManager>,
    policy_cache: &Arc<PolicyCache>,
    audit_queue: &Arc<AuditQueue>,
    tray_manager: &Arc<TrayManager<R>>,
    daemon_url: &str,
    api_key: Option<&str>,
    shutdown_tx: &broadcast::Sender<()>,
) {
    tracing::info!("Starting hushd daemon...");
    if let Err(e) = daemon_manager.start().await {
        tracing::error!("Failed to start daemon: {}", e);
        tray_manager.set_daemon_state(DaemonState::Stopped).await;
        tray_manager
            .set_session_info(Some(
                "Daemon failed to start (check hushd install)".to_string(),
            ))
            .await;
        return;
    }
    tray_manager.set_daemon_state(DaemonState::Running).await;
    show_startup_notification(app);

    if let Err(err) = brokerd_manager.start().await {
        tracing::error!(error = %err, "Failed to start brokerd sidecar");
    }

    // Create session with hushd.
    match session_manager.create_session(daemon_url, api_key).await {
        Ok(session_id) => {
            tracing::info!(session_id = %session_id, "Session established with hushd");
            let session_state = session_manager.state().await;
            tray_manager
                .set_session_info(Some(session_state.summary()))
                .await;
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                "Failed to create session with hushd; posture-enabled policies may deny actions until a session is established (retrying in background)"
            );
            session_manager.start_ensure_session(
                daemon_url.to_string(),
                api_key.map(ToString::to_string),
                shutdown_tx.subscribe(),
            );
            let session_state = session_manager.state().await;
            tray_manager
                .set_session_info(Some(session_state.summary()))
                .await;
        }
    }

    // Initial policy cache sync after successful daemon startup.
    if let Err(err) = policy_cache.sync_from_daemon(daemon_url, api_key).await {
        tracing::warn!(error = %err, "Initial policy cache sync failed");
    }

    // Start periodic policy cache sync.
    policy_cache.start_periodic_sync(
        daemon_url.to_string(),
        api_key.map(ToString::to_string),
        shutdown_tx.subscribe(),
    );

    // Flush any queued audit events from a previous offline period.
    if audit_queue.len().await > 0 {
        match audit_queue.flush(daemon_url, api_key).await {
            Ok(outcome) if outcome.partial_rejection => tracing::warn!(
                count = outcome.accepted,
                duplicates = outcome.duplicates,
                rejected = outcome.rejected,
                "Flushed queued audit events on startup with rejected entries still queued"
            ),
            Ok(outcome) => tracing::info!(
                count = outcome.accepted,
                "Flushed queued audit events on startup"
            ),
            Err(err) => log_audit_flush_failure(&err, "Failed to flush queued audit events"),
        }
    }
}
