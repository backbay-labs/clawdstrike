//! Tray menu construction.
//!
//! Pure menu-builder functions used by `setup_tray` and `update_tray_menu`.
//! These do not touch state directly; callers pass in a `TrayState` and
//! receive a `Menu<R>` ready to be installed on the tray icon.

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::{AppHandle, Runtime};

use crate::decision::NormalizedDecision;
use crate::events::PolicyEvent;

use super::manager::TrayState;
use super::menu_ids;

/// Build the tray menu.
pub(super) fn build_menu<R: Runtime>(
    app: &AppHandle<R>,
    state: &TrayState,
) -> tauri::Result<Menu<R>> {
    let status_text = format_status_text(state);
    let toggle_text = if state.enabled {
        "Disable Enforcement"
    } else {
        "Enable Enforcement"
    };

    let status_item = MenuItem::with_id(app, menu_ids::STATUS, &status_text, false, None::<&str>)?;

    let session_text = state.session_info.as_deref().unwrap_or("Session: inactive");
    let session_item = MenuItem::with_id(
        app,
        menu_ids::SESSION_INFO,
        session_text,
        false,
        None::<&str>,
    )?;
    let ui_bootstrap_hint_label = state
        .ui_bootstrap_hint
        .clone()
        .unwrap_or_else(|| "Web UI code: not active".to_string());
    let ui_bootstrap_hint_item = MenuItem::with_id(
        app,
        menu_ids::UI_BOOTSTRAP_HINT,
        &ui_bootstrap_hint_label,
        state.ui_bootstrap_code.is_some(),
        None::<&str>,
    )?;
    let ui_bootstrap_copy_label = match state.ui_bootstrap_code.as_deref() {
        Some(code) => format!("Copy Web UI Code ({code})"),
        None => "Copy Web UI Code".to_string(),
    };
    let ui_bootstrap_copy_item = MenuItem::with_id(
        app,
        menu_ids::COPY_UI_BOOTSTRAP_CODE,
        &ui_bootstrap_copy_label,
        state.ui_bootstrap_code.is_some(),
        None::<&str>,
    )?;
    let ui_bootstrap_regenerate_item = MenuItem::with_id(
        app,
        menu_ids::REGENERATE_UI_BOOTSTRAP_CODE,
        "Regenerate Web UI Code",
        true,
        None::<&str>,
    )?;

    let toggle_item = MenuItem::with_id(
        app,
        menu_ids::TOGGLE_ENABLED,
        toggle_text,
        true,
        None::<&str>,
    )?;

    let events_submenu = build_events_submenu(app, state)?;

    let sep1 = PredefinedMenuItem::separator(app)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let sep3 = PredefinedMenuItem::separator(app)?;

    let integrations_submenu = build_integrations_submenu(app)?;
    let reload_policy = MenuItem::with_id(
        app,
        menu_ids::RELOAD_POLICY,
        "Reload Policy",
        true,
        None::<&str>,
    )?;
    let create_diagnostics_bundle = MenuItem::with_id(
        app,
        menu_ids::CREATE_DIAGNOSTICS_BUNDLE,
        "Create Diagnostics Bundle",
        true,
        None::<&str>,
    )?;
    let open_web_ui = MenuItem::with_id(
        app,
        menu_ids::OPEN_WEB_UI,
        "Open Web UI",
        true,
        None::<&str>,
    )?;
    let quit_item = MenuItem::with_id(app, menu_ids::QUIT, "Quit", true, None::<&str>)?;

    let mut items: Vec<&dyn tauri::menu::IsMenuItem<R>> = vec![
        &status_item,
        &session_item,
        &ui_bootstrap_hint_item,
        &ui_bootstrap_copy_item,
        &ui_bootstrap_regenerate_item,
    ];
    items.extend([
        &toggle_item as &dyn tauri::menu::IsMenuItem<R>,
        &sep1,
        &events_submenu,
        &sep2,
        &integrations_submenu,
        &reload_policy,
        &create_diagnostics_bundle,
        &open_web_ui,
        &sep3,
        &quit_item,
    ]);

    let menu = Menu::with_items(app, &items)?;

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

fn build_integrations_submenu<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<Submenu<R>> {
    let install_hooks = MenuItem::with_id(
        app,
        menu_ids::INTEGRATIONS_INSTALL_HOOKS,
        "Install Claude Code Hooks",
        true,
        None::<&str>,
    )?;
    let install_openclaw = MenuItem::with_id(
        app,
        menu_ids::INTEGRATIONS_INSTALL_OPENCLAW,
        "Install OpenClaw Plugin",
        true,
        None::<&str>,
    )?;
    let separator = PredefinedMenuItem::separator(app)?;
    let configure_siem = MenuItem::with_id(
        app,
        menu_ids::INTEGRATIONS_CONFIGURE_SIEM,
        "Configure SIEM Export",
        true,
        None::<&str>,
    )?;
    let configure_webhooks = MenuItem::with_id(
        app,
        menu_ids::INTEGRATIONS_CONFIGURE_WEBHOOKS,
        "Configure Webhooks",
        true,
        None::<&str>,
    )?;

    Submenu::with_items(
        app,
        "Integrations",
        true,
        &[
            &install_hooks as &dyn tauri::menu::IsMenuItem<R>,
            &install_openclaw,
            &separator,
            &configure_siem,
            &configure_webhooks,
        ],
    )
}

pub(super) fn format_status_text(state: &TrayState) -> String {
    use crate::daemon::DaemonState;
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

    let mut parts = Vec::new();
    if state.blocks_today > 0 {
        parts.push(format!("{} blocks today", state.blocks_today));
    }
    if state.pending_approvals > 0 {
        parts.push(format!("{} pending approvals", state.pending_approvals));
    }

    if parts.is_empty() {
        format!("{} {}", status_icon, status_text)
    } else {
        format!("{} {} ({})", status_icon, status_text, parts.join(", "))
    }
}

fn format_event_label(event: &PolicyEvent) -> String {
    let icon = match event.normalized_decision() {
        NormalizedDecision::Blocked => "🚫",
        NormalizedDecision::Warn => "⚠️",
        NormalizedDecision::Allowed => "✅",
        NormalizedDecision::Unknown => "❓",
    };

    let target = event.target.as_deref().unwrap_or("unknown");
    let short_target = if target.len() > 30 {
        format!("...{}", &target[target.len() - 27..])
    } else {
        target.to_string()
    };

    let attribution = if let Some(ref aid) = event.agent_id {
        let truncated: String = aid.chars().take(8).collect();
        format!(" [{}]", truncated)
    } else if let Some(ref sid) = event.session_id {
        let truncated: String = sid.chars().take(8).collect();
        format!(" [s:{}]", truncated)
    } else {
        String::new()
    };

    format!(
        "{} {} - {}{}",
        icon, event.action_type, short_target, attribution
    )
}
