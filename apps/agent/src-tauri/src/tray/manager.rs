//! Tray-state actor.
//!
//! [`TrayManager`] is a small Tauri-bound actor that owns the live
//! `TrayState` and re-renders the menu whenever something changes.
//! Each setter exposes a single mutation and triggers a refresh.

use std::sync::Arc;
use tauri::tray::TrayIcon;
use tauri::{AppHandle, Runtime};
use tokio::sync::RwLock;

use crate::daemon::DaemonState;
use crate::events::PolicyEvent;

use super::menu::{build_menu, format_status_text};

/// Tray state for dynamic updates.
#[derive(Clone)]
pub struct TrayState {
    pub daemon_state: DaemonState,
    pub enabled: bool,
    pub recent_events: Vec<PolicyEvent>,
    pub blocks_today: u32,
    pub session_info: Option<String>,
    pub ui_bootstrap_hint: Option<String>,
    pub ui_bootstrap_code: Option<String>,
    pub pending_approvals: usize,
}

impl Default for TrayState {
    fn default() -> Self {
        Self {
            daemon_state: DaemonState::Stopped,
            enabled: true,
            recent_events: Vec::new(),
            blocks_today: 0,
            session_info: None,
            ui_bootstrap_hint: None,
            ui_bootstrap_code: None,
            pending_approvals: 0,
        }
    }
}

/// Update the tray menu with new state.
pub(super) fn update_tray_menu<R: Runtime>(
    app: &AppHandle<R>,
    tray: &TrayIcon<R>,
    state: &TrayState,
) -> tauri::Result<()> {
    let menu = build_menu(app, state)?;
    tray.set_menu(Some(menu))?;

    let tooltip = format_status_text(state);
    tray.set_tooltip(Some(&tooltip))?;

    Ok(())
}

/// Tray manager that handles state and updates.
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

    /// Update daemon state.
    pub async fn set_daemon_state(&self, daemon_state: DaemonState) {
        let mut state = self.state.write().await;
        state.daemon_state = daemon_state;
        drop(state);
        self.refresh_menu().await;
    }

    /// Update enabled state.
    pub async fn set_enabled(&self, enabled: bool) {
        let mut state = self.state.write().await;
        state.enabled = enabled;
        drop(state);
        self.refresh_menu().await;
    }

    /// Update session info displayed in the tray menu.
    pub async fn set_session_info(&self, info: Option<String>) {
        let mut state = self.state.write().await;
        state.session_info = info;
        drop(state);
        self.refresh_menu().await;
    }

    /// Set an ephemeral Web UI bootstrap hint and copyable code.
    pub async fn set_ui_bootstrap_hint(&self, hint: Option<String>, code: Option<String>) {
        let mut state = self.state.write().await;
        state.ui_bootstrap_hint = hint;
        state.ui_bootstrap_code = code;
        drop(state);
        self.refresh_menu().await;
    }

    /// Clear bootstrap hint/code only if the active code still matches.
    pub async fn clear_ui_bootstrap_hint_if_code_matches(&self, expected_code: &str) {
        let mut state = self.state.write().await;
        if state.ui_bootstrap_code.as_deref() == Some(expected_code) {
            state.ui_bootstrap_hint = None;
            state.ui_bootstrap_code = None;
        }
        drop(state);
        self.refresh_menu().await;
    }

    /// Return the active one-time Web UI bootstrap code, if present.
    pub async fn current_ui_bootstrap_code(&self) -> Option<String> {
        self.state.read().await.ui_bootstrap_code.clone()
    }

    /// Update the pending approvals badge count.
    pub async fn set_approval_badge(&self, count: usize) {
        let mut state = self.state.write().await;
        state.pending_approvals = count;
        drop(state);
        self.refresh_menu().await;
    }

    /// Add a new event.
    pub async fn add_event(&self, event: PolicyEvent) {
        let mut state = self.state.write().await;

        if event.normalized_decision().is_blocked() {
            state.blocks_today += 1;
        }

        state.recent_events.insert(0, event);
        if state.recent_events.len() > 10 {
            state.recent_events.truncate(10);
        }

        drop(state);
        self.refresh_menu().await;
    }

    /// Refresh the menu with current state.
    async fn refresh_menu(&self) {
        let state = self.state.read().await;
        if let Err(err) = update_tray_menu(&self.app, &self.tray, &state) {
            tracing::error!(error = %err, "Failed to update tray menu");
        }
    }
}
