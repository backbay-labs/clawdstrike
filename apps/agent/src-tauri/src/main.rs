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
mod bootstrap;
mod brokerd;
mod daemon;
mod decision;
mod edr;
mod enrollment;
mod events;
mod integrations;
mod macos;
mod nats_client;
mod nats_subjects;
mod notifications;
mod openclaw;
mod policy;
mod policy_sync;
mod posture_commands;
mod response_action_commands;
mod runtime_registry;
mod security;
mod session;
mod settings;
mod tasks;
mod telemetry_publisher;
mod tray;
mod updater;

use agent_auth::ensure_local_api_token;
use approval::ApprovalQueue;
use bootstrap::run_agent;
use brokerd::{find_brokerd_binary, prepare_managed_brokerd_binary, BrokerdConfig, BrokerdManager};
use daemon::{
    find_hushd_binary, prepare_managed_hushd_binary, AuditQueue, DaemonConfig, DaemonManager,
    PolicyCache,
};
use events::EventManager;
use macos::MacosHostService;
use openclaw::OpenClawManager;
use session::SessionManager;
use settings::{ensure_default_policy, Settings};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::{Manager, RunEvent};
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
    macos_host: Arc<MacosHostService>,
    shutdown_tx: broadcast::Sender<()>,
    agent_api_token: String,
    shutdown_complete: Arc<ShutdownComplete>,
}

#[derive(Clone)]
pub struct AgentApiAuthToken(pub String);

pub struct ShutdownComplete {
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

    pub(crate) fn mark_done(&self) {
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
    let macos_host = Arc::new(MacosHostService::new());
    tauri::async_runtime::block_on(macos_host.bootstrap_placeholder_state());
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
        macos_host,
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
        .manage(app_state.macos_host.clone())
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
            let macos_host = app_state.macos_host.clone();
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
                    macos_host,
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
