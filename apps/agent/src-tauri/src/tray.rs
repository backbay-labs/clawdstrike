//! System tray management for Clawdstrike Agent
//!
//! Handles the tray icon, menu, and status updates.

use crate::daemon::DaemonState;
use crate::events::PolicyEvent;
use std::sync::Arc;
use tauri::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Runtime};
use tokio::sync::RwLock;

/// Menu item IDs
#[allow(dead_code)]
pub mod menu_ids {
    pub const STATUS: &str = "status";
    pub const TOGGLE_ENABLED: &str = "toggle_enabled";
    pub const RECENT_EVENTS: &str = "recent_events";
    pub const EVENT_PREFIX: &str = "event_";
    pub const OPEN_DESKTOP: &str = "open_desktop";
    pub const SETTINGS: &str = "settings";
    pub const INSTALL_HOOKS: &str = "install_hooks";
    pub const RELOAD_POLICY: &str = "reload_policy";
    pub const QUIT: &str = "quit";
}

/// Tray state for dynamic updates
pub struct TrayState {
    pub daemon_state: DaemonState,
    pub enabled: bool,
    pub recent_events: Vec<PolicyEvent>,
    pub blocks_today: u32,
}

impl Default for TrayState {
    fn default() -> Self {
        Self {
            daemon_state: DaemonState::Stopped,
            enabled: true,
            recent_events: Vec::new(),
            blocks_today: 0,
        }
    }
}

/// Build the tray menu
pub fn build_menu<R: Runtime>(app: &AppHandle<R>, state: &TrayState) -> tauri::Result<Menu<R>> {
    let status_text = format_status_text(state);
    let toggle_text = if state.enabled {
        "Disable Enforcement"
    } else {
        "Enable Enforcement"
    };

    // Status (non-clickable, just informational)
    let status_item = MenuItem::with_id(app, menu_ids::STATUS, &status_text, false, None::<&str>)?;

    // Toggle enabled
    let toggle_item = MenuItem::with_id(app, menu_ids::TOGGLE_ENABLED, toggle_text, true, None::<&str>)?;

    // Recent events submenu
    let events_submenu = build_events_submenu(app, state)?;

    // Separator using predefined
    let sep1 = PredefinedMenuItem::separator(app)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let sep3 = PredefinedMenuItem::separator(app)?;

    // Actions
    let install_hooks = MenuItem::with_id(app, menu_ids::INSTALL_HOOKS, "Install Claude Code Hooks", true, None::<&str>)?;
    let reload_policy = MenuItem::with_id(app, menu_ids::RELOAD_POLICY, "Reload Policy", true, None::<&str>)?;
    let open_desktop = MenuItem::with_id(app, menu_ids::OPEN_DESKTOP, "Open SDR Desktop", true, None::<&str>)?;

    // Quit
    let quit_item = MenuItem::with_id(app, menu_ids::QUIT, "Quit", true, None::<&str>)?;

    // Build menu
    let menu = Menu::with_items(
        app,
        &[
            &status_item,
            &toggle_item,
            &sep1,
            &events_submenu,
            &sep2,
            &install_hooks,
            &reload_policy,
            &open_desktop,
            &sep3,
            &quit_item,
        ],
    )?;

    Ok(menu)
}

fn build_events_submenu<R: Runtime>(
    app: &AppHandle<R>,
    state: &TrayState,
) -> tauri::Result<Submenu<R>> {
    let title = format!("Recent Events ({})", state.recent_events.len());

    let items: Vec<MenuItem<R>> = if state.recent_events.is_empty() {
        vec![MenuItem::with_id(
            app,
            "no_events",
            "No recent events",
            false,
            None::<&str>,
        )?]
    } else {
        state
            .recent_events
            .iter()
            .take(10)
            .enumerate()
            .filter_map(|(i, event)| {
                let id = format!("{}{}", menu_ids::EVENT_PREFIX, i);
                let label = format_event_label(event);
                MenuItem::with_id(app, &id, &label, false, None::<&str>).ok()
            })
            .collect()
    };

    let item_refs: Vec<&dyn tauri::menu::IsMenuItem<R>> = items
        .iter()
        .map(|item| item as &dyn tauri::menu::IsMenuItem<R>)
        .collect();

    Submenu::with_items(app, &title, true, &item_refs)
}

fn format_status_text(state: &TrayState) -> String {
    let status_icon = match state.daemon_state {
        DaemonState::Running if state.enabled => "🟢",
        DaemonState::Running => "🟡",
        DaemonState::Starting | DaemonState::Restarting => "🟡",
        DaemonState::Unhealthy => "🟠",
        DaemonState::Stopped => "🔴",
    };

    let status_text = match state.daemon_state {
        DaemonState::Running if state.enabled => "Running",
        DaemonState::Running => "Running (disabled)",
        DaemonState::Starting => "Starting...",
        DaemonState::Restarting => "Restarting...",
        DaemonState::Unhealthy => "Unhealthy",
        DaemonState::Stopped => "Stopped",
    };

    if state.blocks_today > 0 {
        format!("{} {} ({} blocks today)", status_icon, status_text, state.blocks_today)
    } else {
        format!("{} {}", status_icon, status_text)
    }
}

fn format_event_label(event: &PolicyEvent) -> String {
    let icon = match event.decision.as_str() {
        "block" | "BLOCK" => "🚫",
        "warn" | "WARN" => "⚠️",
        "allow" | "ALLOW" => "✅",
        _ => "❓",
    };

    let target = event.target.as_deref().unwrap_or("unknown");
    let short_target = if target.len() > 30 {
        format!("...{}", &target[target.len() - 27..])
    } else {
        target.to_string()
    };

    format!("{} {} - {}", icon, event.action_type, short_target)
}

/// Create and setup the tray icon
pub fn setup_tray<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<TrayIcon<R>> {
    let state = TrayState::default();
    let menu = build_menu(app, &state)?;

    let tray = TrayIconBuilder::new()
        .icon(app.default_window_icon().cloned().ok_or_else(|| {
            tauri::Error::AssetNotFound("Default icon not found".to_string())
        })?)
        .tooltip("Clawdstrike Agent")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(handle_menu_event)
        .on_tray_icon_event(handle_tray_event)
        .build(app)?;

    Ok(tray)
}

/// Handle menu item clicks
fn handle_menu_event<R: Runtime>(app: &AppHandle<R>, event: MenuEvent) {
    let id = event.id().as_ref();

    match id {
        menu_ids::TOGGLE_ENABLED => {
            tracing::info!("Toggle enabled clicked");
            let _ = app.emit("toggle_enabled", ());
        }
        menu_ids::INSTALL_HOOKS => {
            tracing::info!("Install hooks clicked");
            let _ = app.emit("install_hooks", ());
        }
        menu_ids::RELOAD_POLICY => {
            tracing::info!("Reload policy clicked");
            let _ = app.emit("reload_policy", ());
        }
        menu_ids::OPEN_DESKTOP => {
            tracing::info!("Open desktop clicked");
            // Try to open SDR Desktop app
            #[cfg(target_os = "macos")]
            {
                let _ = std::process::Command::new("open")
                    .arg("-a")
                    .arg("SDR Desktop")
                    .spawn();
            }
            #[cfg(target_os = "linux")]
            {
                let _ = std::process::Command::new("sdr-desktop").spawn();
            }
        }
        menu_ids::QUIT => {
            tracing::info!("Quit clicked");
            app.exit(0);
        }
        _ => {
            tracing::debug!("Unknown menu item clicked: {}", id);
        }
    }
}

/// Handle tray icon events (click, etc)
fn handle_tray_event<R: Runtime>(_tray: &TrayIcon<R>, event: TrayIconEvent) {
    if let TrayIconEvent::Click {
        button: MouseButton::Left,
        button_state: MouseButtonState::Up,
        ..
    } = event
    {
        // Left click shows menu (already handled by show_menu_on_left_click)
        tracing::debug!("Tray icon clicked");
    }
}

/// Update the tray menu with new state
pub fn update_tray_menu<R: Runtime>(
    app: &AppHandle<R>,
    tray: &TrayIcon<R>,
    state: &TrayState,
) -> tauri::Result<()> {
    let menu = build_menu(app, state)?;
    tray.set_menu(Some(menu))?;

    // Update tooltip
    let tooltip = format_status_text(state);
    tray.set_tooltip(Some(&tooltip))?;

    Ok(())
}

/// Tray manager that handles state and updates
pub struct TrayManager<R: Runtime> {
    app: AppHandle<R>,
    tray: TrayIcon<R>,
    state: Arc<RwLock<TrayState>>,
}

impl<R: Runtime> TrayManager<R> {
    pub fn new(app: AppHandle<R>, tray: TrayIcon<R>) -> Self {
        Self {
            app,
            tray,
            state: Arc::new(RwLock::new(TrayState::default())),
        }
    }

    /// Update daemon state
    pub async fn set_daemon_state(&self, daemon_state: DaemonState) {
        let mut state = self.state.write().await;
        state.daemon_state = daemon_state;
        drop(state);
        self.refresh_menu().await;
    }

    /// Update enabled state
    pub async fn set_enabled(&self, enabled: bool) {
        let mut state = self.state.write().await;
        state.enabled = enabled;
        drop(state);
        self.refresh_menu().await;
    }

    /// Add a new event
    pub async fn add_event(&self, event: PolicyEvent) {
        let mut state = self.state.write().await;

        // Count blocks
        if event.decision.to_lowercase() == "block" {
            state.blocks_today += 1;
        }

        // Add to recent events (keep last 10)
        state.recent_events.insert(0, event);
        if state.recent_events.len() > 10 {
            state.recent_events.truncate(10);
        }

        drop(state);
        self.refresh_menu().await;
    }

    /// Refresh the menu with current state
    async fn refresh_menu(&self) {
        let state = self.state.read().await;
        if let Err(e) = update_tray_menu(&self.app, &self.tray, &state) {
            tracing::error!("Failed to update tray menu: {}", e);
        }
    }

    /// Get current state
    pub async fn state(&self) -> TrayState {
        self.state.read().await.clone()
    }
}

impl Clone for TrayState {
    fn clone(&self) -> Self {
        Self {
            daemon_state: self.daemon_state.clone(),
            enabled: self.enabled,
            recent_events: self.recent_events.clone(),
            blocks_today: self.blocks_today,
        }
    }
}
