//! System tray management for Clawdstrike Agent.
//!
//! - [`menu`]: tray menu construction (pure builders).
//! - [`manager`]: `TrayManager` actor + `TrayState` mutations.
//! - [`menu_handlers`]: click routing for menu and tray icon events.
//! - [`dashboard_url`]: pure URL validation/resolution helpers used by
//!   the menu handlers when launching the local web UI.

mod dashboard_url;
mod manager;
mod menu;
mod menu_handlers;

pub use manager::{TrayManager, TrayState};

use tauri::tray::{TrayIcon, TrayIconBuilder};
use tauri::{AppHandle, Runtime};

use menu::build_menu;
use menu_handlers::{handle_menu_event, handle_tray_event};

/// Menu item IDs.
#[allow(dead_code)]
pub mod menu_ids {
    pub const STATUS: &str = "status";
    pub const SESSION_INFO: &str = "session_info";
    pub const UI_BOOTSTRAP_HINT: &str = "ui_bootstrap_hint";
    pub const COPY_UI_BOOTSTRAP_CODE: &str = "copy_ui_bootstrap_code";
    pub const REGENERATE_UI_BOOTSTRAP_CODE: &str = "regenerate_ui_bootstrap_code";
    pub const TOGGLE_ENABLED: &str = "toggle_enabled";
    pub const EVENT_PREFIX: &str = "event_";
    pub const OPEN_WEB_UI: &str = "open_web_ui";
    pub const INSTALL_HOOKS: &str = "install_hooks";
    pub const INTEGRATIONS_INSTALL_HOOKS: &str = "integrations_install_hooks";
    pub const INTEGRATIONS_INSTALL_OPENCLAW: &str = "integrations_install_openclaw";
    pub const INTEGRATIONS_CONFIGURE_SIEM: &str = "integrations_configure_siem";
    pub const INTEGRATIONS_CONFIGURE_WEBHOOKS: &str = "integrations_configure_webhooks";
    pub const RELOAD_POLICY: &str = "reload_policy";
    pub const CREATE_DIAGNOSTICS_BUNDLE: &str = "create_diagnostics_bundle";
    pub const QUIT: &str = "quit";
}

/// Create and setup the tray icon.
pub fn setup_tray<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<TrayIcon<R>> {
    let state = TrayState::default();
    let menu = build_menu(app, &state)?;

    let tray = TrayIconBuilder::new()
        .icon(
            app.default_window_icon()
                .cloned()
                .ok_or_else(|| tauri::Error::AssetNotFound("Default icon not found".to_string()))?,
        )
        .tooltip("Clawdstrike Agent")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(handle_menu_event)
        .on_tray_icon_event(handle_tray_event)
        .build(app)?;
    tray.set_show_menu_on_left_click(true)?;

    Ok(tray)
}
