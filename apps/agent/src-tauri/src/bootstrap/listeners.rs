//! Tauri front-end event listeners.
//!
//! The frontend (or the tray menu) raises emit events for actions like
//! "toggle enforcement", "install Claude hooks", etc. These functions
//! register the listeners that translate those events into agent-side
//! operations.

use std::sync::Arc;
use tauri::{AppHandle, Listener, Runtime};
use tokio::sync::RwLock;

use crate::daemon::DaemonManager;
use crate::integrations::{ClaudeCodeIntegration, OpenClawPluginIntegration};
use crate::notifications::{
    show_hooks_installed_notification, show_openclaw_plugin_installed_notification,
    show_policy_reload_notification, show_toggle_notification,
};
use crate::settings::Settings;
use crate::tray::TrayManager;

/// Register the four Tauri listeners (`toggle_enabled`, `install_hooks`,
/// `install_openclaw_plugin`, `reload_policy`) that the tray and the
/// frontend emit.
pub(super) fn register_tauri_listeners<R: Runtime>(
    app: &AppHandle<R>,
    settings: Arc<RwLock<Settings>>,
    daemon_manager: Arc<DaemonManager>,
    tray_manager: Arc<TrayManager<R>>,
) {
    register_toggle_listener(app, settings, tray_manager);
    register_hooks_listener(app);
    register_openclaw_listener(app);
    register_reload_listener(app, daemon_manager);
}

fn register_toggle_listener<R: Runtime>(
    app: &AppHandle<R>,
    settings: Arc<RwLock<Settings>>,
    tray_manager: Arc<TrayManager<R>>,
) {
    let app_for_events = app.clone();
    let _ = app.listen("toggle_enabled", move |_| {
        let settings = settings.clone();
        let tray = tray_manager.clone();
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
}

fn register_hooks_listener<R: Runtime>(app: &AppHandle<R>) {
    let app_for_hooks = app.clone();
    let _ = app.listen("install_hooks", move |_| {
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
}

fn register_openclaw_listener<R: Runtime>(app: &AppHandle<R>) {
    let app_for_openclaw = app.clone();
    let _ = app.listen("install_openclaw_plugin", move |_| {
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
}

fn register_reload_listener<R: Runtime>(app: &AppHandle<R>, daemon_manager: Arc<DaemonManager>) {
    let app_for_reload = app.clone();
    let _ = app.listen("reload_policy", move |_| {
        let app = app_for_reload.clone();
        let daemon = daemon_manager.clone();

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
}

async fn reload_daemon_policy(daemon: &DaemonManager) -> anyhow::Result<()> {
    let status = daemon.status().await;
    if status.state != "running" {
        anyhow::bail!("Daemon is not running");
    }
    daemon.restart().await
}
