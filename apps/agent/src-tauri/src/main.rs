//! Clawdstrike Agent - Security enforcement runtime for AI coding tools
//!
//! A lightweight tray application that:
//! - Spawns and manages the hushd daemon
//! - Provides status and notifications via system tray
//! - Integrates with AI tools (Claude Code hooks, MCP server)

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod daemon;
mod events;
mod integrations;
mod notifications;
mod settings;
mod tray;

use daemon::{find_hushd_binary, DaemonConfig, DaemonManager, DaemonState};
use events::EventManager;
use integrations::{ClaudeCodeIntegration, McpServer};
use notifications::{
    show_hooks_installed_notification, show_policy_reload_notification,
    show_startup_notification, show_toggle_notification, NotificationManager,
};
use settings::{ensure_default_policy, get_data_dir, Settings};
use tray::{setup_tray, TrayManager};

use std::sync::Arc;
use tauri::{AppHandle, Listener, Manager, RunEvent, Runtime};
use tokio::sync::{broadcast, RwLock};

/// Bundled default policy
const DEFAULT_POLICY: &str = include_str!("../resources/default-policy.yaml");

/// Application state shared across components
struct AppState {
    settings: Arc<RwLock<Settings>>,
    daemon_manager: Arc<DaemonManager>,
    event_manager: Arc<EventManager>,
    shutdown_tx: broadcast::Sender<()>,
}

fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("clawdstrike_agent=info".parse().unwrap_or_default())
                .add_directive("hushd=info".parse().unwrap_or_default()),
        )
        .init();

    tracing::info!("Starting Clawdstrike Agent v{}", env!("CARGO_PKG_VERSION"));

    // Load settings
    let settings = match Settings::load() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to load settings: {}. Using defaults.", e);
            Settings::default()
        }
    };

    // Ensure default policy exists
    if let Err(e) = ensure_default_policy(DEFAULT_POLICY) {
        tracing::warn!("Failed to ensure default policy: {}", e);
    }

    // Find hushd binary
    let hushd_path = settings
        .hushd_binary_path
        .clone()
        .or_else(find_hushd_binary);

    let hushd_path = match hushd_path {
        Some(p) => p,
        None => {
            tracing::error!("Could not find hushd binary. Please install hushd or set the path in settings.");
            // Continue anyway - daemon will fail to start but app will still run
            std::path::PathBuf::from("hushd")
        }
    };

    // Create daemon config
    let daemon_config = DaemonConfig {
        binary_path: hushd_path,
        port: settings.daemon_port,
        policy_path: settings.policy_path.clone(),
        audit_db_path: get_data_dir().join("audit.db"),
        api_key: settings.api_key.clone(),
    };

    // Create shutdown channel
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    // Create managers
    let daemon_manager = Arc::new(DaemonManager::new(daemon_config));
    let event_manager = Arc::new(EventManager::new(
        settings.daemon_url(),
        settings.api_key.clone(),
    ));

    let app_state = AppState {
        settings: Arc::new(RwLock::new(settings)),
        daemon_manager,
        event_manager,
        shutdown_tx: shutdown_tx.clone(),
    };

    // Build and run Tauri app
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .manage(app_state.settings.clone())
        .manage(app_state.daemon_manager.clone())
        .manage(app_state.event_manager.clone())
        .setup(move |app| {
            let app_handle = app.handle().clone();

            // Setup tray
            let tray = setup_tray(&app_handle)?;
            let tray_manager = Arc::new(TrayManager::new(app_handle.clone(), tray));

            // Store tray manager in app state
            app.manage(tray_manager.clone());

            // Clone what we need for async tasks
            let daemon_manager = app_state.daemon_manager.clone();
            let event_manager = app_state.event_manager.clone();
            let settings = app_state.settings.clone();
            let shutdown_tx = app_state.shutdown_tx.clone();

            // Start async tasks
            tauri::async_runtime::spawn(async move {
                run_agent(
                    app_handle,
                    daemon_manager,
                    event_manager,
                    tray_manager,
                    settings,
                    shutdown_tx,
                )
                .await;
            });

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            if let RunEvent::ExitRequested { api, .. } = event {
                // Get shutdown sender
                if let Some(daemon_manager) = app_handle.try_state::<Arc<DaemonManager>>() {
                    tracing::info!("Shutting down daemon...");
                    let dm = daemon_manager.inner().clone();
                    tauri::async_runtime::block_on(async move {
                        if let Err(e) = dm.stop().await {
                            tracing::error!("Error stopping daemon: {}", e);
                        }
                    });
                }
            }
        });
}

async fn run_agent<R: Runtime>(
    app: AppHandle<R>,
    daemon_manager: Arc<DaemonManager>,
    event_manager: Arc<EventManager>,
    tray_manager: Arc<TrayManager<R>>,
    settings: Arc<RwLock<Settings>>,
    shutdown_tx: broadcast::Sender<()>,
) {
    // Start the daemon
    tracing::info!("Starting hushd daemon...");
    if let Err(e) = daemon_manager.start().await {
        tracing::error!("Failed to start daemon: {}", e);
        // Update tray to show error
        tray_manager.set_daemon_state(DaemonState::Stopped).await;
    } else {
        tray_manager.set_daemon_state(DaemonState::Running).await;
        show_startup_notification(&app);
    }

    // Subscribe to daemon state changes
    let mut daemon_rx = daemon_manager.subscribe();
    let tray_for_daemon = tray_manager.clone();
    tokio::spawn(async move {
        while let Ok(state) = daemon_rx.recv().await {
            tray_for_daemon.set_daemon_state(state).await;
        }
    });

    // Start event manager
    let event_shutdown = shutdown_tx.subscribe();
    let event_mgr = event_manager.clone();
    tokio::spawn(async move {
        event_mgr.start(event_shutdown).await;
    });

    // Subscribe to events for tray and notifications
    let mut events_rx = event_manager.subscribe();
    let notification_manager = NotificationManager::new(app.clone(), settings.clone());
    let tray_for_events = tray_manager.clone();
    tokio::spawn(async move {
        while let Ok(event) = events_rx.recv().await {
            // Update tray
            tray_for_events.add_event(event.clone()).await;
            // Show notification
            notification_manager.notify(&event).await;
        }
    });

    // Start MCP server
    let settings_guard = settings.read().await;
    let mcp_server = McpServer::new(
        settings_guard.mcp_port,
        settings_guard.daemon_url(),
        settings_guard.api_key.clone(),
    );
    drop(settings_guard);

    let mcp_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        if let Err(e) = mcp_server.start(mcp_shutdown).await {
            tracing::error!("MCP server error: {}", e);
        }
    });

    // Listen for app events
    let app_for_events = app.clone();
    let settings_for_events = settings.clone();
    let tray_for_toggle = tray_manager.clone();
    let daemon_for_reload = daemon_manager.clone();

    // Handle toggle_enabled event
    let toggle_handler = app.listen("toggle_enabled", move |_| {
        let settings = settings_for_events.clone();
        let tray = tray_for_toggle.clone();
        let app = app_for_events.clone();

        tauri::async_runtime::spawn(async move {
            let mut s = settings.write().await;
            s.enabled = !s.enabled;
            let enabled = s.enabled;
            if let Err(e) = s.save() {
                tracing::error!("Failed to save settings: {}", e);
            }
            drop(s);

            tray.set_enabled(enabled).await;
            show_toggle_notification(&app, enabled);
        });
    });

    // Handle install_hooks event
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
                Err(e) => {
                    tracing::error!("Failed to install hooks: {}", e);
                    show_hooks_installed_notification(&app, false);
                }
            }
        });
    });

    // Handle reload_policy event
    let app_for_reload = app.clone();
    let reload_handler = app.listen("reload_policy", move |_| {
        let app = app_for_reload.clone();
        let daemon = daemon_for_reload.clone();

        tauri::async_runtime::spawn(async move {
            // Signal daemon to reload policy via SIGHUP or API call
            match reload_daemon_policy(&daemon).await {
                Ok(_) => {
                    tracing::info!("Policy reloaded successfully");
                    show_policy_reload_notification(&app, true);
                }
                Err(e) => {
                    tracing::error!("Failed to reload policy: {}", e);
                    show_policy_reload_notification(&app, false);
                }
            }
        });
    });

    // Keep the handlers alive
    let _handlers = (toggle_handler, hooks_handler, reload_handler);

    // Wait for shutdown
    let mut shutdown_rx = shutdown_tx.subscribe();
    let _ = shutdown_rx.recv().await;
    tracing::info!("Agent shutdown complete");
}

async fn reload_daemon_policy(daemon: &DaemonManager) -> anyhow::Result<()> {
    // Try to call the policy reload endpoint
    let status = daemon.status().await;
    if status.state != "running" {
        anyhow::bail!("Daemon is not running");
    }

    // For now, just restart the daemon to pick up new policy
    daemon.restart().await
}
