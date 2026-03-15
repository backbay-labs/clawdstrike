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
mod approval_outbox;
mod approval_sync;
mod brokerd;
mod daemon;
mod decision;
mod enrollment;
mod events;
mod integrations;
mod nats_client;
mod nats_subjects;
mod notifications;
mod openclaw;
mod policy;
mod policy_sync;
mod posture_commands;
mod runtime_registry;
mod security;
mod session;
mod settings;
mod telemetry_publisher;
mod tray;
mod updater;

use agent_auth::ensure_local_api_token;
use api_server::{AgentApiServer, AgentApiServerDeps};
use approval::ApprovalQueue;
use brokerd::{find_brokerd_binary, prepare_managed_brokerd_binary, BrokerdConfig, BrokerdManager};
use daemon::{
    find_hushd_binary, prepare_managed_hushd_binary, AuditFlushProgressError, AuditQueue,
    DaemonConfig, DaemonManager, DaemonState, PolicyCache,
};
use events::EventManager;
use integrations::{ClaudeCodeIntegration, McpServer, OpenClawPluginIntegration};
use notifications::{
    show_hooks_installed_notification, show_openclaw_plugin_installed_notification,
    show_policy_reload_notification, show_startup_notification, show_toggle_notification,
    NotificationManager,
};
use openclaw::OpenClawManager;
use runtime_registry::resolve_effective_endpoint_agent_id;
use session::SessionManager;
use settings::{ensure_default_policy, NatsSettings, Settings};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Listener, Manager, RunEvent, Runtime};
use tokio::sync::{broadcast, Notify, RwLock};
use tray::{setup_tray, TrayManager};
use updater::HushdUpdater;

/// Bundled default policy.
const DEFAULT_POLICY: &str = include_str!("../resources/default-policy.yaml");

/// Application state shared across components.
struct AppState {
    settings: Arc<RwLock<Settings>>,
    daemon_manager: Arc<DaemonManager>,
    brokerd_manager: Arc<BrokerdManager>,
    event_manager: Arc<EventManager>,
    openclaw_manager: OpenClawManager,
    session_manager: Arc<SessionManager>,
    approval_queue: Arc<ApprovalQueue>,
    policy_cache: Arc<PolicyCache>,
    audit_queue: Arc<AuditQueue>,
    updater: Arc<HushdUpdater>,
    shutdown_tx: broadcast::Sender<()>,
    agent_api_token: String,
    shutdown_complete: Arc<ShutdownComplete>,
}

fn log_audit_flush_failure(err: &anyhow::Error, message: &'static str) {
    if let Some(progress) = err.downcast_ref::<AuditFlushProgressError>() {
        tracing::warn!(
            error = %progress.message,
            count = progress.outcome.accepted,
            duplicates = progress.outcome.duplicates,
            rejected = progress.outcome.rejected,
            "{} after partial progress",
            message
        );
    } else {
        tracing::warn!(error = %err, "{}", message);
    }
}

#[derive(Clone)]
pub struct AgentApiAuthToken(pub String);

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
    if let Err(err) = crate::enrollment::migrate_legacy_enrollment_key_file() {
        tracing::warn!(
            error = %err,
            "Failed to migrate legacy enrollment key into keyring-backed storage"
        );
    }

    let agent_api_token = match ensure_local_api_token() {
        Ok(token) => token,
        Err(err) => {
            tracing::error!("Failed to initialize local API token: {}", err);
            return;
        }
    };

    let bundled_hushd_path = if settings.hushd_binary_path.is_none() {
        match prepare_managed_hushd_binary() {
            Ok(path) => path,
            Err(err) => {
                tracing::warn!(error = %err, "Failed to prepare bundled hushd binary");
                None
            }
        }
    } else {
        None
    };

    let hushd_path = settings
        .hushd_binary_path
        .clone()
        .or(bundled_hushd_path)
        .or_else(find_hushd_binary)
        .unwrap_or_else(|| {
            tracing::error!(
                "Could not find hushd binary. Install hushd or set hushd_binary_path in agent settings."
            );
            std::path::PathBuf::from("hushd")
        });
    tracing::info!(path = %hushd_path.display(), "Using hushd binary path");

    let bundled_brokerd_path = if settings.brokerd.enabled && settings.brokerd.binary_path.is_none()
    {
        match prepare_managed_brokerd_binary() {
            Ok(path) => path,
            Err(err) => {
                tracing::warn!(error = %err, "Failed to prepare bundled brokerd binary");
                None
            }
        }
    } else {
        None
    };
    let brokerd_path = settings
        .brokerd
        .binary_path
        .clone()
        .or(bundled_brokerd_path)
        .or_else(find_brokerd_binary)
        .unwrap_or_else(|| std::path::PathBuf::from("clawdstrike-brokerd"));
    if settings.brokerd.enabled {
        tracing::info!(path = %brokerd_path.display(), "Using brokerd binary path");
    }

    let settings = Arc::new(RwLock::new(settings));
    let (daemon_url, daemon_api_key) = {
        let guard = settings.blocking_read();
        (guard.daemon_url(), guard.api_key.clone())
    };
    let daemon_config = {
        let guard = settings.blocking_read();
        DaemonConfig {
            binary_path: hushd_path,
            port: guard.daemon_port,
            policy_path: guard.policy_path.clone(),
            settings: Some(settings.clone()),
        }
    };
    let daemon_manager = Arc::new(DaemonManager::new(daemon_config));
    let brokerd_config = {
        let guard = settings.blocking_read();
        BrokerdConfig {
            enabled: guard.brokerd.enabled,
            binary_path: brokerd_path,
            port: guard.brokerd.port,
            hushd_base_url: guard.daemon_url(),
            hushd_token: guard.api_key.clone(),
            admin_token: guard.brokerd.admin_token.clone(),
            secret_backend: guard.brokerd.secret_backend.clone(),
            allow_http_loopback: guard.brokerd.allow_http_loopback,
            allow_private_upstream_hosts: guard.brokerd.allow_private_upstream_hosts,
            allow_invalid_upstream_tls: guard.brokerd.allow_invalid_upstream_tls,
        }
    };
    let brokerd_manager = Arc::new(BrokerdManager::new(brokerd_config));
    let event_manager = Arc::new(EventManager::new(daemon_url, daemon_api_key));
    let openclaw_manager = OpenClawManager::new(settings.clone());
    let session_manager = Arc::new(SessionManager::new());
    let approval_queue = Arc::new(ApprovalQueue::new());
    let policy_cache = Arc::new(PolicyCache::new());
    let audit_queue = Arc::new(AuditQueue::new());
    let updater = Arc::new(HushdUpdater::new(settings.clone(), daemon_manager.clone()));
    let (shutdown_tx, _) = broadcast::channel::<()>(4);
    let shutdown_complete = Arc::new(ShutdownComplete::new());

    let app_state = AppState {
        settings: settings.clone(),
        daemon_manager,
        brokerd_manager,
        event_manager,
        openclaw_manager: openclaw_manager.clone(),
        session_manager,
        approval_queue,
        policy_cache,
        audit_queue,
        updater,
        shutdown_tx: shutdown_tx.clone(),
        agent_api_token,
        shutdown_complete: shutdown_complete.clone(),
    };

    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .manage(app_state.settings.clone())
        .manage(app_state.daemon_manager.clone())
        .manage(app_state.brokerd_manager.clone())
        .manage(app_state.event_manager.clone())
        .manage(app_state.openclaw_manager.clone())
        .manage(app_state.session_manager.clone())
        .manage(app_state.approval_queue.clone())
        .manage(app_state.policy_cache.clone())
        .manage(app_state.audit_queue.clone())
        .manage(app_state.updater.clone())
        .manage(app_state.shutdown_tx.clone())
        .manage(app_state.shutdown_complete.clone())
        .manage(AgentApiAuthToken(app_state.agent_api_token.clone()))
        .setup(move |app| {
            let app_handle = app.handle().clone();

            let tray = setup_tray(&app_handle)?;
            let tray_manager = Arc::new(TrayManager::new(app_handle.clone(), tray));
            app.manage(tray_manager.clone());

            let daemon_manager = app_state.daemon_manager.clone();
            let brokerd_manager = app_state.brokerd_manager.clone();
            let event_manager = app_state.event_manager.clone();
            let openclaw_manager = app_state.openclaw_manager.clone();
            let session_manager = app_state.session_manager.clone();
            let approval_queue = app_state.approval_queue.clone();
            let policy_cache = app_state.policy_cache.clone();
            let audit_queue = app_state.audit_queue.clone();
            let updater = app_state.updater.clone();
            let settings = app_state.settings.clone();
            let shutdown_tx = app_state.shutdown_tx.clone();
            let agent_api_token = app_state.agent_api_token.clone();
            let shutdown_complete = app_state.shutdown_complete.clone();

            tauri::async_runtime::spawn(async move {
                run_agent(
                    app_handle,
                    daemon_manager,
                    brokerd_manager,
                    event_manager,
                    openclaw_manager,
                    session_manager,
                    approval_queue,
                    policy_cache,
                    audit_queue,
                    updater,
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

fn validate_nats_security_settings(nats: &NatsSettings) -> std::result::Result<(), String> {
    if !nats.require_signed_approval_responses {
        return Err(
            "NATS approval sync requires signed responses; unsigned mode is disabled".to_string(),
        );
    }

    let trusted_issuer = nats
        .approval_response_trusted_issuer
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if trusted_issuer.is_none() {
        return Err(
            "NATS is enabled but no trusted approval response issuer is configured".to_string(),
        );
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_agent<R: Runtime>(
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
    session_manager.start_heartbeat(daemon_url.clone(), api_key.clone(), shutdown_tx.subscribe());
    {
        let settings_for_local_hb = settings.clone();
        let session_for_local_hb = session_manager.clone();
        let policy_cache_for_local_hb = policy_cache.clone();
        let daemon_for_local_hb = daemon_manager.clone();
        let local_hb_shutdown = shutdown_tx.subscribe();
        tokio::spawn(async move {
            local_heartbeat_loop(
                settings_for_local_hb,
                session_for_local_hb,
                policy_cache_for_local_hb,
                daemon_for_local_hb,
                local_hb_shutdown,
            )
            .await;
        });
    }
    updater.start_background(shutdown_tx.subscribe());

    tracing::info!("Starting hushd daemon...");
    if let Err(e) = daemon_manager.start().await {
        tracing::error!("Failed to start daemon: {}", e);
        tray_manager.set_daemon_state(DaemonState::Stopped).await;
        tray_manager
            .set_session_info(Some(
                "Daemon failed to start (check hushd install)".to_string(),
            ))
            .await;
    } else {
        tray_manager.set_daemon_state(DaemonState::Running).await;
        show_startup_notification(&app);

        if let Err(err) = brokerd_manager.start().await {
            tracing::error!(error = %err, "Failed to start brokerd sidecar");
        }

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

    // --- NATS enterprise connectivity (adaptive SDR) ---
    // If NATS is enabled (either via static config or enrollment), connect and start
    // policy sync, telemetry publishing, and posture command handling.
    let mut approval_request_outbox: Option<Arc<approval_outbox::ApprovalRequestOutbox>> = None;
    let nats_enabled = {
        let guard = settings.read().await;
        guard.nats.enabled
    };
    if nats_enabled {
        let nats_settings = {
            let guard = settings.read().await;
            guard.nats.clone()
        };
        if let Err(err) = validate_nats_security_settings(&nats_settings) {
            tracing::error!(
                error = %err,
                "Enterprise NATS connectivity disabled due to unsafe configuration"
            );
            tray_manager
                .set_session_info(Some(format!("NATS disabled: {}", err)))
                .await;
        } else {
            match nats_client::NatsClient::connect(&nats_settings).await {
                Ok(nats) => {
                    let nats = Arc::new(nats);

                    // Policy sync: watch KV for policy updates and reload hushd.
                    let policy_path = {
                        let guard = settings.read().await;
                        guard.policy_path.clone()
                    };
                    let policy_sync = policy_sync::PolicySync::new(nats.clone(), policy_path);
                    let (policy_update_tx, mut policy_update_rx) =
                        tokio::sync::mpsc::channel::<()>(16);
                    let policy_sync_shutdown = shutdown_tx.subscribe();
                    tokio::spawn(async move {
                        policy_sync
                            .start(policy_sync_shutdown, Some(policy_update_tx))
                            .await;
                    });

                    // On policy file change from NATS sync, signal hushd reload.
                    let daemon_for_nats = daemon_manager.clone();
                    tokio::spawn(async move {
                        while policy_update_rx.recv().await.is_some() {
                            tracing::info!("Policy updated via NATS sync; reloading hushd");
                            if let Err(err) = daemon_for_nats.restart().await {
                                tracing::warn!(
                                    error = %err,
                                    "Failed to reload hushd after NATS policy sync"
                                );
                            }
                        }
                    });

                    // Telemetry publisher.
                    let telemetry =
                        Arc::new(telemetry_publisher::TelemetryPublisher::new(nats.clone()));
                    tracing::info!("NATS telemetry publisher initialized");

                    // Posture command handler.
                    let posture_handler = posture_commands::PostureCommandHandler::new(
                        nats.clone(),
                        session_manager.clone(),
                        daemon_manager.clone(),
                        settings.clone(),
                    );
                    let posture_shutdown = shutdown_tx.subscribe();
                    tokio::spawn(async move {
                        posture_handler.start(posture_shutdown).await;
                    });

                    // Approval sync: ingest cloud decisions and apply them to local queue.
                    let approval_sync = approval_sync::ApprovalSync::new(
                        nats.clone(),
                        approval_queue.clone(),
                        nats_settings.require_signed_approval_responses,
                        nats_settings.approval_response_trusted_issuer.clone(),
                    );
                    let approval_sync_shutdown = shutdown_tx.subscribe();
                    tokio::spawn(async move {
                        approval_sync.start(approval_sync_shutdown).await;
                    });

                    // Durable approval-request outbox (agent -> cloud).
                    let outbox = Arc::new(approval_outbox::ApprovalRequestOutbox::load_default());
                    if outbox.len().await > 0 {
                        match outbox.flush_due(nats.as_ref()).await {
                            Ok(sent) if sent > 0 => {
                                tracing::info!(
                                    sent,
                                    "Flushed persisted approval-request outbox on startup"
                                );
                            }
                            Ok(_) => {}
                            Err(err) => {
                                tracing::warn!(
                                    error = %err,
                                    "Failed to flush approval-request outbox on startup"
                                );
                            }
                        }
                    }
                    outbox.clone().start(nats.clone(), shutdown_tx.subscribe());
                    approval_request_outbox = Some(outbox);

                    // Publish periodic NATS heartbeats alongside the existing HTTP heartbeats.
                    let telemetry_for_heartbeat = telemetry.clone();
                    let session_for_nats_hb = session_manager.clone();
                    let policy_cache_for_nats_hb = policy_cache.clone();
                    let nats_hb_shutdown = shutdown_tx.subscribe();
                    tokio::spawn(async move {
                        nats_heartbeat_loop(
                            telemetry_for_heartbeat,
                            session_for_nats_hb,
                            policy_cache_for_nats_hb,
                            nats_hb_shutdown,
                        )
                        .await;
                    });
                }
                Err(err) => {
                    tracing::error!(
                        error = %err,
                        "Failed to connect to NATS; enterprise features disabled"
                    );
                    if is_nats_auth_failure(&err.to_string()) {
                        tracing::warn!(
                            "NATS connect failed with authentication/authorization error; preserving enrollment identity and existing NATS config for automatic recovery"
                        );
                    }
                }
            }
        }
    }

    // Periodic durable audit-outbox flush (independent of daemon lifecycle notifications).
    {
        let audit_queue_for_periodic = audit_queue.clone();
        let settings_for_periodic = settings.clone();
        let mut periodic_shutdown = shutdown_tx.subscribe();
        tokio::spawn(async move {
            let flush_interval = Duration::from_secs(5);
            loop {
                tokio::select! {
                    _ = periodic_shutdown.recv() => {
                        tracing::debug!("Periodic audit-outbox flush loop shutting down");
                        break;
                    }
                    _ = tokio::time::sleep(flush_interval) => {
                        if audit_queue_for_periodic.len().await == 0 {
                            continue;
                        }
                        let (daemon_url, api_key) = {
                            let guard = settings_for_periodic.read().await;
                            (guard.daemon_url(), guard.api_key.clone())
                        };
                        match audit_queue_for_periodic.flush(&daemon_url, api_key.as_deref()).await {
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

    // Subscribe to daemon-level SSE events (policy updates, violations, posture transitions).
    let mut daemon_events_rx = event_manager.subscribe_daemon_events();
    let policy_cache_for_sse = policy_cache.clone();
    let session_manager_for_sse = session_manager.clone();
    let tray_for_sse = tray_manager.clone();
    let app_for_sse = app.clone();
    let settings_for_sse = settings.clone();
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
                    let _ = session_manager_for_sse
                        .update_posture_from_daemon_event(
                            session_id.as_deref(),
                            new_posture.clone(),
                        )
                        .await;

                    let session_state = session_manager_for_sse.state().await;
                    let summary = if session_state.session_id.is_some() {
                        session_state.summary()
                    } else {
                        format!("Posture: {}", new_posture)
                    };
                    tray_for_sse.set_session_info(Some(summary)).await;

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

    // Start approval queue cleanup loop and event handler.
    approval_queue.start_cleanup(shutdown_tx.subscribe());
    let mut approval_events_rx = approval_queue.subscribe();
    let tray_for_approvals = tray_manager.clone();
    let app_for_approvals = app.clone();
    let approval_queue_for_events = approval_queue.clone();
    let approval_outbox_for_events = approval_request_outbox.clone();
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
                    if let Some(outbox) = approval_outbox_for_events.as_ref() {
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

    let api_server = AgentApiServer::new(
        api_port,
        AgentApiServerDeps {
            settings: settings.clone(),
            daemon_manager: daemon_manager.clone(),
            session_manager: session_manager.clone(),
            approval_queue: approval_queue.clone(),
            audit_queue: audit_queue.clone(),
            openclaw: openclaw_manager.clone(),
            updater: updater.clone(),
            auth_token: agent_api_token,
        },
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

    let app_for_openclaw = app.clone();
    let openclaw_handler = app.listen("install_openclaw_plugin", move |_| {
        let app = app_for_openclaw.clone();

        tauri::async_runtime::spawn(async move {
            let integration = OpenClawPluginIntegration::new();
            if !integration.is_cli_available() {
                tracing::warn!("OpenClaw CLI not detected on PATH");
                show_openclaw_plugin_installed_notification(&app, false);
                return;
            }

            match integration.install_plugin().await {
                Ok(_) => {
                    tracing::info!("OpenClaw plugin installed successfully");
                    show_openclaw_plugin_installed_notification(&app, true);
                }
                Err(err) => {
                    tracing::error!("Failed to install OpenClaw plugin: {}", err);
                    show_openclaw_plugin_installed_notification(&app, false);
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

    let _handlers = (
        toggle_handler,
        hooks_handler,
        openclaw_handler,
        reload_handler,
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

async fn reload_daemon_policy(daemon: &DaemonManager) -> anyhow::Result<()> {
    let status = daemon.status().await;
    if status.state != "running" {
        anyhow::bail!("Daemon is not running");
    }
    daemon.restart().await
}

fn is_nats_auth_failure(error_message: &str) -> bool {
    let lower = error_message.to_ascii_lowercase();
    if lower.contains("certificate authentication failed")
        || lower.contains("authentication handshake timeout")
    {
        return false;
    }

    [
        "authorization violation",
        "permissions violation",
        "authentication failed",
        "authorization failed",
        "invalid credentials",
        "invalid token",
        "invalid jwt",
        "user authentication expired",
        "authentication error",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

/// Periodic NATS heartbeat loop that publishes session state to the telemetry stream.
async fn nats_heartbeat_loop(
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
async fn local_heartbeat_loop(
    settings: Arc<RwLock<Settings>>,
    session_manager: Arc<SessionManager>,
    policy_cache: Arc<daemon::PolicyCache>,
    daemon_manager: Arc<DaemonManager>,
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
                let heartbeat_base = serde_json::json!({
                    "endpoint_agent_id": endpoint_agent_id,
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "session_id": session_state.session_id,
                    "posture": session_state.posture,
                    "policy_version": policy_version,
                    "daemon_version": daemon_status.version,
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

#[cfg(test)]
mod tests {
    use super::is_nats_auth_failure;

    #[test]
    fn nats_auth_error_detection_matches_expected_strings() {
        assert!(is_nats_auth_failure("Authorization Violation"));
        assert!(is_nats_auth_failure("user authentication expired"));
        assert!(is_nats_auth_failure("authentication failed"));
        assert!(!is_nats_auth_failure("connection refused"));
        assert!(!is_nats_auth_failure("dial tcp timeout"));
        assert!(!is_nats_auth_failure("authentication handshake timeout"));
        assert!(!is_nats_auth_failure(
            "tls: certificate authentication failed during renegotiation"
        ));
    }
}
