//! Clawdstrike Agent - Security enforcement runtime for AI coding tools.
//!
//! A lightweight tray application that:
//! - Spawns and manages the hushd daemon
//! - Provides status and notifications via system tray
//! - Integrates with Claude hooks, MCP, and OpenClaw transport

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod agent_auth;
mod api_server;
mod approval;
mod daemon;
mod decision;
mod events;
mod integrations;
mod notifications;
mod openclaw;
mod policy;
mod session;
mod settings;
mod tray;

use agent_auth::ensure_local_api_token;
use api_server::AgentApiServer;
use approval::ApprovalQueue;
use daemon::{
    find_hushd_binary, AuditQueue, DaemonConfig, DaemonManager, DaemonState, PolicyCache,
};
use events::EventManager;
use integrations::{ClaudeCodeIntegration, McpServer};
use notifications::{
    show_hooks_installed_notification, show_policy_reload_notification, show_startup_notification,
    show_toggle_notification, NotificationManager,
};
use openclaw::OpenClawManager;
use session::SessionManager;
use settings::{ensure_default_policy, Settings};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Listener, Manager, RunEvent, Runtime};
use tokio::sync::{broadcast, Notify, RwLock};
use tray::{setup_tray, TrayManager};

/// Bundled default policy.
const DEFAULT_POLICY: &str = include_str!("../resources/default-policy.yaml");

/// Application state shared across components.
struct AppState {
    settings: Arc<RwLock<Settings>>,
    daemon_manager: Arc<DaemonManager>,
    event_manager: Arc<EventManager>,
    openclaw_manager: OpenClawManager,
    session_manager: Arc<SessionManager>,
    approval_queue: Arc<ApprovalQueue>,
    policy_cache: Arc<PolicyCache>,
    audit_queue: Arc<AuditQueue>,
    shutdown_tx: broadcast::Sender<()>,
    agent_api_token: String,
    shutdown_complete: Arc<ShutdownComplete>,
}

struct ShutdownComplete {
    done: AtomicBool,
    notify: Notify,
}

impl ShutdownComplete {
    fn new() -> Self {
        Self {
            done: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    fn mark_done(&self) {
        self.done.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    async fn wait(&self) {
        while !self.done.load(Ordering::SeqCst) {
            self.notify.notified().await;
        }
    }
}

fn main() {
    // Initialize logging.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("clawdstrike_agent=info".parse().unwrap_or_default())
                .add_directive("hushd=info".parse().unwrap_or_default()),
        )
        .init();

    tracing::info!("Starting Clawdstrike Agent v{}", env!("CARGO_PKG_VERSION"));

    let settings = match Settings::load() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to load settings: {}. Using defaults.", e);
            Settings::default()
        }
    };

    if let Err(e) = ensure_default_policy(DEFAULT_POLICY) {
        tracing::warn!("Failed to ensure default policy: {}", e);
    }

    let agent_api_token = match ensure_local_api_token() {
        Ok(token) => token,
        Err(err) => {
            tracing::error!("Failed to initialize local API token: {}", err);
            return;
        }
    };

    let hushd_path = settings
        .hushd_binary_path
        .clone()
        .or_else(find_hushd_binary)
        .unwrap_or_else(|| {
            tracing::error!(
                "Could not find hushd binary. Please install hushd or set hushd_binary_path."
            );
            std::path::PathBuf::from("hushd")
        });

    let daemon_config = DaemonConfig {
        binary_path: hushd_path,
        port: settings.daemon_port,
        policy_path: settings.policy_path.clone(),
    };

    let settings = Arc::new(RwLock::new(settings));
    let (daemon_url, daemon_api_key) = {
        let guard = settings.blocking_read();
        (guard.daemon_url(), guard.api_key.clone())
    };
    let daemon_manager = Arc::new(DaemonManager::new(daemon_config));
    let event_manager = Arc::new(EventManager::new(daemon_url, daemon_api_key));
    let openclaw_manager = OpenClawManager::new(settings.clone());
    let session_manager = Arc::new(SessionManager::new());
    let approval_queue = Arc::new(ApprovalQueue::new());
    let policy_cache = Arc::new(PolicyCache::new());
    let audit_queue = Arc::new(AuditQueue::new());
    let (shutdown_tx, _) = broadcast::channel::<()>(4);
    let shutdown_complete = Arc::new(ShutdownComplete::new());

    let app_state = AppState {
        settings: settings.clone(),
        daemon_manager,
        event_manager,
        openclaw_manager: openclaw_manager.clone(),
        session_manager,
        approval_queue,
        policy_cache,
        audit_queue,
        shutdown_tx: shutdown_tx.clone(),
        agent_api_token,
        shutdown_complete: shutdown_complete.clone(),
    };

    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .manage(app_state.settings.clone())
        .manage(app_state.daemon_manager.clone())
        .manage(app_state.event_manager.clone())
        .manage(app_state.openclaw_manager.clone())
        .manage(app_state.session_manager.clone())
        .manage(app_state.approval_queue.clone())
        .manage(app_state.policy_cache.clone())
        .manage(app_state.audit_queue.clone())
        .manage(app_state.shutdown_tx.clone())
        .manage(app_state.shutdown_complete.clone())
        .setup(move |app| {
            let app_handle = app.handle().clone();

            let tray = setup_tray(&app_handle)?;
            let tray_manager = Arc::new(TrayManager::new(app_handle.clone(), tray));
            app.manage(tray_manager.clone());

            let daemon_manager = app_state.daemon_manager.clone();
            let event_manager = app_state.event_manager.clone();
            let openclaw_manager = app_state.openclaw_manager.clone();
            let session_manager = app_state.session_manager.clone();
            let approval_queue = app_state.approval_queue.clone();
            let policy_cache = app_state.policy_cache.clone();
            let audit_queue = app_state.audit_queue.clone();
            let settings = app_state.settings.clone();
            let shutdown_tx = app_state.shutdown_tx.clone();
            let agent_api_token = app_state.agent_api_token.clone();
            let shutdown_complete = app_state.shutdown_complete.clone();

            tauri::async_runtime::spawn(async move {
                run_agent(
                    app_handle,
                    daemon_manager,
                    event_manager,
                    openclaw_manager,
                    session_manager,
                    approval_queue,
                    policy_cache,
                    audit_queue,
                    tray_manager,
                    settings,
                    shutdown_tx,
                    agent_api_token,
                    shutdown_complete,
                )
                .await;
            });

            Ok(())
        });

    let app = match builder.build(tauri::generate_context!()) {
        Ok(app) => app,
        Err(err) => {
            tracing::error!("Failed to build tauri application: {}", err);
            return;
        }
    };

    app.run(|app_handle, event| {
        if let RunEvent::ExitRequested { .. } = event {
            if let Some(shutdown_tx) = app_handle.try_state::<broadcast::Sender<()>>() {
                let _ = shutdown_tx.send(());
            }
            if let Some(shutdown_complete) = app_handle.try_state::<Arc<ShutdownComplete>>() {
                let latch = shutdown_complete.inner().clone();
                tauri::async_runtime::block_on(async move {
                    let _ = tokio::time::timeout(Duration::from_secs(8), latch.wait()).await;
                });
            }
        }
    });
}

#[allow(clippy::too_many_arguments)]
async fn run_agent<R: Runtime>(
    app: AppHandle<R>,
    daemon_manager: Arc<DaemonManager>,
    event_manager: Arc<EventManager>,
    openclaw_manager: OpenClawManager,
    session_manager: Arc<SessionManager>,
    approval_queue: Arc<ApprovalQueue>,
    policy_cache: Arc<PolicyCache>,
    audit_queue: Arc<AuditQueue>,
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

    // Start heartbeat loop once. It no-ops until a session is established, and it reads the
    // current session ID from shared state each tick (so daemon reconnect replacements do not
    // require restarting the loop).
    session_manager.start_heartbeat(
        daemon_url.clone(),
        api_key.clone(),
        shutdown_tx.subscribe(),
    );

    tracing::info!("Starting hushd daemon...");
    if let Err(e) = daemon_manager.start().await {
        tracing::error!("Failed to start daemon: {}", e);
        tray_manager.set_daemon_state(DaemonState::Stopped).await;
    } else {
        tray_manager.set_daemon_state(DaemonState::Running).await;
        show_startup_notification(&app);

        // Create session with hushd.
        match session_manager
            .create_session(&daemon_url, api_key.as_deref())
            .await
        {
            Ok(session_id) => {
                tracing::info!(session_id = %session_id, "Session established with hushd");
                // Update tray with session info.
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
                    daemon_url.clone(),
                    api_key.clone(),
                    shutdown_tx.subscribe(),
                );
                let session_state = session_manager.state().await;
                tray_manager
                    .set_session_info(Some(session_state.summary()))
                    .await;
            }
        }

        // Initial policy cache sync after successful daemon startup.
        if let Err(err) = policy_cache
            .sync_from_daemon(&daemon_url, api_key.as_deref())
            .await
        {
            tracing::warn!(error = %err, "Initial policy cache sync failed");
        }

        // Start periodic policy cache sync.
        policy_cache.start_periodic_sync(
            daemon_url.clone(),
            api_key.clone(),
            shutdown_tx.subscribe(),
        );

        // Flush any queued audit events from a previous offline period.
        if audit_queue.len().await > 0 {
            match audit_queue.flush(&daemon_url, api_key.as_deref()).await {
                Ok(count) => tracing::info!(count, "Flushed queued audit events on startup"),
                Err(err) => tracing::warn!(error = %err, "Failed to flush queued audit events"),
            }
        }
    }

    let mut daemon_rx = daemon_manager.subscribe();
    let tray_for_daemon = tray_manager.clone();
    let audit_queue_for_daemon = audit_queue.clone();
    let policy_cache_for_daemon = policy_cache.clone();
    let settings_for_daemon = settings.clone();
    let session_for_daemon = session_manager.clone();
    let shutdown_for_daemon = shutdown_tx.clone();
    tokio::spawn(async move {
        while let Ok(state) = daemon_rx.recv().await {
            tray_for_daemon.set_daemon_state(state.clone()).await;

            // On reconnect: re-establish session, flush queued audit events, resync policy cache.
            if state == DaemonState::Running {
                let (daemon_url, api_key) = {
                    let guard = settings_for_daemon.read().await;
                    (guard.daemon_url(), guard.api_key.clone())
                };

                // Re-establish session (previous session may have expired on daemon restart).
                match session_for_daemon
                    .create_session(&daemon_url, api_key.as_deref())
                    .await
                {
                    Ok(session_id) => {
                        tracing::info!(session_id = %session_id, "Session re-established after daemon reconnect");
                        let session_state = session_for_daemon.state().await;
                        tray_for_daemon
                            .set_session_info(Some(session_state.summary()))
                            .await;
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            "Failed to re-establish session after daemon reconnect (retrying in background)"
                        );
                        session_for_daemon.start_ensure_session(
                            daemon_url.clone(),
                            api_key.clone(),
                            shutdown_for_daemon.subscribe(),
                        );
                    }
                }

                if audit_queue_for_daemon.len().await > 0 {
                    match audit_queue_for_daemon
                        .flush(&daemon_url, api_key.as_deref())
                        .await
                    {
                        Ok(count) => {
                            tracing::info!(count, "Flushed queued audit events after reconnect")
                        }
                        Err(err) => {
                            tracing::warn!(error = %err, "Failed to flush audit queue after reconnect")
                        }
                    }
                }
                if let Err(err) = policy_cache_for_daemon
                    .sync_from_daemon(&daemon_url, api_key.as_deref())
                    .await
                {
                    tracing::debug!(error = %err, "Policy cache resync after reconnect failed");
                }
            }
        }
    });

    let event_shutdown = shutdown_tx.subscribe();
    let event_mgr = event_manager.clone();
    tokio::spawn(async move {
        event_mgr.start(event_shutdown).await;
    });

    let mut events_rx = event_manager.subscribe();
    let notification_manager = NotificationManager::new(app.clone(), settings.clone());
    let tray_for_events = tray_manager.clone();
    tokio::spawn(async move {
        while let Ok(event) = events_rx.recv().await {
            tray_for_events.add_event(event.clone()).await;
            notification_manager.notify(&event).await;
        }
    });

    // Subscribe to daemon-level SSE events (policy updates, violations, posture transitions).
    let mut daemon_events_rx = event_manager.subscribe_daemon_events();
    let policy_cache_for_sse = policy_cache.clone();
    let session_manager_for_sse = session_manager.clone();
    let tray_for_sse = tray_manager.clone();
    let app_for_sse = app.clone();
    let settings_for_sse = settings.clone();
    tokio::spawn(async move {
        use crate::events::DaemonEvent;

        while let Ok(event) = daemon_events_rx.recv().await {
            match event {
                DaemonEvent::PolicyUpdated { version } => {
                    tracing::info!(version = ?version, "Received policy_updated event from hushd");
                    let (daemon_url, api_key) = {
                        let guard = settings_for_sse.read().await;
                        (guard.daemon_url(), guard.api_key.clone())
                    };
                    if let Err(err) = policy_cache_for_sse
                        .sync_from_daemon(&daemon_url, api_key.as_deref())
                        .await
                    {
                        tracing::warn!(error = %err, "Failed to refresh policy cache after update event");
                    } else {
                        show_policy_reload_notification(&app_for_sse, true);
                    }
                }
                DaemonEvent::Violation {
                    guard,
                    message,
                    severity,
                    target,
                } => {
                    tracing::info!(
                        guard = ?guard,
                        severity = ?severity,
                        target = ?target,
                        "Received violation event from hushd"
                    );
                    let title = format!(
                        "Security Violation{}",
                        guard
                            .as_ref()
                            .map(|g| format!(" ({})", g))
                            .unwrap_or_default()
                    );
                    let body = message
                        .unwrap_or_else(|| target.unwrap_or_else(|| "Unknown target".to_string()));
                    notifications::show_notification(&app_for_sse, &title, &body);
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
                    let _ = session_manager_for_sse
                        .update_posture_from_daemon_event(session_id.as_deref(), new_posture.clone())
                        .await;

                    let session_state = session_manager_for_sse.state().await;
                    let summary = if session_state.session_id.is_some() {
                        session_state.summary()
                    } else {
                        format!("Posture: {}", new_posture)
                    };
                    tray_for_sse.set_session_info(Some(summary)).await;

                    let body = format!("Posture changed from {} to {}", old_posture, new_posture);
                    notifications::show_notification(&app_for_sse, "Posture Transition", &body);
                }
            }
        }
    });

    // Start approval queue cleanup loop and event handler.
    approval_queue.start_cleanup(shutdown_tx.subscribe());
    let mut approval_events_rx = approval_queue.subscribe();
    let tray_for_approvals = tray_manager.clone();
    let app_for_approvals = app.clone();
    let approval_queue_for_events = approval_queue.clone();
    tokio::spawn(async move {
        while let Ok(event) = approval_events_rx.recv().await {
            match &event {
                approval::ApprovalEvent::NewRequest { request } => {
                    let title = format!("Approval Required: {}", request.tool);
                    let body = format!("{}\n{}", request.resource, request.reason);
                    notifications::show_notification(&app_for_approvals, &title, &body);
                    let count = approval_queue_for_events.pending_count().await;
                    tray_for_approvals.set_approval_badge(count).await;
                }
                approval::ApprovalEvent::Resolved { .. }
                | approval::ApprovalEvent::Expired { .. } => {
                    let count = approval_queue_for_events.pending_count().await;
                    tray_for_approvals.set_approval_badge(count).await;
                }
            }
        }
    });

    let (mcp_port, api_port) = {
        let guard = settings.read().await;
        (guard.mcp_port, guard.agent_api_port)
    };

    let mcp_server = McpServer::new(mcp_port, settings.clone(), session_manager.clone());
    let mcp_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        if let Err(e) = mcp_server.start(mcp_shutdown).await {
            tracing::error!("MCP server error: {}", e);
        }
    });

    let api_server = AgentApiServer::new(
        api_port,
        settings.clone(),
        daemon_manager.clone(),
        session_manager.clone(),
        approval_queue.clone(),
        openclaw_manager.clone(),
        agent_api_token,
    );
    let api_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        if let Err(err) = api_server.start(api_shutdown).await {
            tracing::error!("Agent API server error: {}", err);
        }
    });

    let app_for_events = app.clone();
    let settings_for_events = settings.clone();
    let tray_for_toggle = tray_manager.clone();
    let daemon_for_reload = daemon_manager.clone();

    let toggle_handler = app.listen("toggle_enabled", move |_| {
        let settings = settings_for_events.clone();
        let tray = tray_for_toggle.clone();
        let app = app_for_events.clone();

        tauri::async_runtime::spawn(async move {
            let mut s = settings.write().await;
            s.enabled = !s.enabled;
            let enabled = s.enabled;
            if let Err(err) = s.save() {
                tracing::error!("Failed to save settings: {}", err);
            }
            drop(s);

            tray.set_enabled(enabled).await;
            show_toggle_notification(&app, enabled);
        });
    });

    let app_for_hooks = app.clone();
    let hooks_handler = app.listen("install_hooks", move |_| {
        let app = app_for_hooks.clone();

        tauri::async_runtime::spawn(async move {
            let integration = ClaudeCodeIntegration::new();
            if !integration.is_installed() {
                tracing::warn!("Claude Code not detected (~/.claude not found)");
                show_hooks_installed_notification(&app, false);
                return;
            }

            match integration.install_hooks() {
                Ok(_) => {
                    tracing::info!("Claude Code hooks installed successfully");
                    show_hooks_installed_notification(&app, true);
                }
                Err(err) => {
                    tracing::error!("Failed to install hooks: {}", err);
                    show_hooks_installed_notification(&app, false);
                }
            }
        });
    });

    let app_for_reload = app.clone();
    let reload_handler = app.listen("reload_policy", move |_| {
        let app = app_for_reload.clone();
        let daemon = daemon_for_reload.clone();

        tauri::async_runtime::spawn(async move {
            match reload_daemon_policy(&daemon).await {
                Ok(_) => {
                    tracing::info!("Policy reloaded successfully");
                    show_policy_reload_notification(&app, true);
                }
                Err(err) => {
                    tracing::error!("Failed to reload policy: {}", err);
                    show_policy_reload_notification(&app, false);
                }
            }
        });
    });

    let _handlers = (toggle_handler, hooks_handler, reload_handler);

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

    if let Err(err) = daemon_manager.stop().await {
        tracing::error!("Error during daemon shutdown: {}", err);
    }
    shutdown_complete.mark_done();
    tracing::info!("Agent shutdown complete");
}

async fn reload_daemon_policy(daemon: &DaemonManager) -> anyhow::Result<()> {
    let status = daemon.status().await;
    if status.state != "running" {
        anyhow::bail!("Daemon is not running");
    }
    daemon.restart().await
}
