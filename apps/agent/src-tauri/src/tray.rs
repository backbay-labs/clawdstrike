//! System tray management for Clawdstrike Agent.

use crate::agent_auth::read_local_api_token;
use crate::daemon::DaemonState;
use crate::decision::NormalizedDecision;
use crate::events::PolicyEvent;
use crate::notifications::show_notification;
use crate::settings::Settings;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tauri::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use tauri::Manager;
use tauri::{AppHandle, Emitter, Runtime};
use tokio::net::{lookup_host, TcpStream};
use tokio::sync::RwLock;
use tokio::time::{sleep, timeout};

#[derive(Debug, Serialize)]
struct UiBootstrapStartRequest {
    next_path: String,
}

#[derive(Debug, Deserialize)]
struct UiBootstrapStartResponse {
    session_id: String,
    user_code: String,
    expires_in_seconds: u64,
}

#[derive(Debug, Deserialize)]
struct DiagnosticsBundleResponse {
    bundle_path: String,
    generated_at: String,
}

#[derive(Debug)]
struct DashboardLaunchTarget {
    url: String,
    bootstrap_code: Option<String>,
    bootstrap_ttl_seconds: Option<u64>,
}

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

/// Build the tray menu.
pub fn build_menu<R: Runtime>(app: &AppHandle<R>, state: &TrayState) -> tauri::Result<Menu<R>> {
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

fn validate_dashboard_url(candidate: &str) -> Option<String> {
    let trimmed = candidate.trim();
    if trimmed.is_empty() {
        return None;
    }

    let parsed = reqwest::Url::parse(trimmed).ok()?;
    let scheme = parsed.scheme();
    if (scheme == "http" || scheme == "https") && parsed.host_str().is_some() {
        Some(parsed.to_string())
    } else {
        None
    }
}

fn default_local_dashboard_url(agent_api_port: u16) -> String {
    format!("http://127.0.0.1:{}/ui", agent_api_port)
}

fn is_local_dashboard_url(candidate: &str) -> bool {
    let parsed = match reqwest::Url::parse(candidate) {
        Ok(url) => url,
        Err(_) => return false,
    };
    let host = parsed
        .host_str()
        .unwrap_or_default()
        .trim_start_matches('[')
        .trim_end_matches(']');
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn is_loopback_host(parsed: &reqwest::Url) -> bool {
    let host = parsed
        .host_str()
        .unwrap_or_default()
        .trim_start_matches('[')
        .trim_end_matches(']');
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn is_local_agent_ui_url(parsed: &reqwest::Url, expected_port: u16) -> bool {
    if !matches!(parsed.scheme(), "http" | "https") {
        return false;
    }
    if !is_loopback_host(parsed) {
        return false;
    }
    if parsed.port_or_known_default() != Some(expected_port) {
        return false;
    }
    parsed.path().starts_with("/ui")
}

fn ui_next_path(parsed: &reqwest::Url) -> String {
    let mut out = parsed.path().to_string();
    if let Some(query) = parsed.query() {
        out.push('?');
        out.push_str(query);
    }
    if out.is_empty() || !out.starts_with("/ui") {
        "/ui".to_string()
    } else {
        out
    }
}

fn redact_url_for_log(url: &str) -> String {
    let mut parsed = match reqwest::Url::parse(url) {
        Ok(value) => value,
        Err(_) => return "<invalid-url>".to_string(),
    };
    parsed.set_query(None);
    parsed.set_fragment(None);
    parsed.to_string()
}

async fn request_local_ui_bootstrap(
    agent_api_port: u16,
    auth_token: &str,
    next_path: String,
) -> Option<UiBootstrapStartResponse> {
    let endpoint = format!(
        "http://127.0.0.1:{}/api/v1/ui/bootstrap/start",
        agent_api_port
    );
    let request = UiBootstrapStartRequest { next_path };
    let response = reqwest::Client::new()
        .post(&endpoint)
        .bearer_auth(auth_token)
        .json(&request)
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.json::<UiBootstrapStartResponse>().await.ok()
}

async fn build_dashboard_launch_target(
    url: &str,
    settings: &Settings,
    auth_token: Option<&str>,
) -> Option<DashboardLaunchTarget> {
    let parsed = reqwest::Url::parse(url).ok()?;

    if !is_loopback_host(&parsed) {
        return Some(DashboardLaunchTarget {
            url: parsed.to_string(),
            bootstrap_code: None,
            bootstrap_ttl_seconds: None,
        });
    }

    if !is_local_agent_ui_url(&parsed, settings.agent_api_port) {
        return Some(DashboardLaunchTarget {
            url: parsed.to_string(),
            bootstrap_code: None,
            bootstrap_ttl_seconds: None,
        });
    }

    let auth_token = auth_token
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let bootstrap =
        request_local_ui_bootstrap(settings.agent_api_port, auth_token, ui_next_path(&parsed))
            .await?;

    let mut bootstrap_url = parsed;
    bootstrap_url.set_path("/ui/bootstrap");
    bootstrap_url.set_query(Some(&format!("session_id={}", bootstrap.session_id)));
    bootstrap_url.set_fragment(None);
    Some(DashboardLaunchTarget {
        url: bootstrap_url.to_string(),
        bootstrap_code: Some(bootstrap.user_code),
        bootstrap_ttl_seconds: Some(bootstrap.expires_in_seconds),
    })
}

fn load_current_local_api_token() -> Option<String> {
    match read_local_api_token() {
        Ok(token) => Some(token),
        Err(err) => {
            tracing::warn!(error = %err, "Failed to read current local API auth token");
            None
        }
    }
}

fn is_legacy_local_dev_dashboard_url(candidate: &str) -> bool {
    let parsed = match reqwest::Url::parse(candidate) {
        Ok(url) => url,
        Err(_) => return false,
    };
    let host = parsed.host_str().unwrap_or_default();
    parsed.scheme() == "http"
        && matches!(host, "localhost" | "127.0.0.1")
        && parsed.port_or_known_default() == Some(3100)
        && (parsed.path() == "/" || parsed.path().is_empty())
}

async fn url_is_reachable(candidate: &str) -> bool {
    let parsed = match reqwest::Url::parse(candidate) {
        Ok(url) => url,
        Err(_) => return false,
    };
    let host = match parsed.host_str() {
        Some(host) => host,
        None => return false,
    };
    let port = match parsed.port_or_known_default() {
        Some(port) => port,
        None => return false,
    };
    let timeout_duration = Duration::from_millis(150);
    let addresses = match lookup_host((host, port)).await {
        Ok(addresses) => addresses,
        Err(_) => return false,
    };
    for address in addresses.take(4) {
        if let Ok(Ok(_)) = timeout(timeout_duration, TcpStream::connect(address)).await {
            return true;
        }
    }
    false
}

async fn resolve_dashboard_url(settings: &Settings) -> Option<String> {
    let fallback = default_local_dashboard_url(settings.agent_api_port);
    let configured = if settings.dashboard_url.trim().is_empty() {
        fallback.clone()
    } else {
        settings.dashboard_url.clone()
    };

    let validated = validate_dashboard_url(&configured)?;
    if is_local_dashboard_url(&validated) && !url_is_reachable(&validated).await {
        if is_legacy_local_dev_dashboard_url(&validated) {
            tracing::warn!(
                configured_url = %validated,
                fallback_url = %fallback,
                "Dashboard URL points to localhost:3100, but no service is listening; using local agent UI fallback"
            );
        } else {
            tracing::warn!(
                configured_url = %validated,
                fallback_url = %fallback,
                "Configured local dashboard URL is unreachable; using local agent UI fallback"
            );
        }
        return validate_dashboard_url(&fallback);
    }
    Some(validated)
}

fn build_dashboard_settings_url(base_url: &str, section: &str) -> Option<String> {
    let section = section.trim().trim_matches('/');
    if section.is_empty() {
        return None;
    }

    let mut parsed = reqwest::Url::parse(base_url).ok()?;
    parsed.set_query(None);
    parsed.set_fragment(None);

    let base_path = parsed.path().trim_end_matches('/');
    let target_path = if base_path.is_empty() || base_path == "/" {
        format!("/settings/{}", section)
    } else if base_path.ends_with("/settings") {
        format!("{}/{}", base_path, section)
    } else {
        format!("{}/settings/{}", base_path, section)
    };
    parsed.set_path(&target_path);
    Some(parsed.to_string())
}

fn open_dashboard_url(url: &str) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("explorer.exe").arg(url).spawn();
    }
}

fn copy_text_to_clipboard(text: &str) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    #[cfg(target_os = "macos")]
    {
        let mut child = Command::new("pbcopy")
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|err| format!("failed to spawn pbcopy: {err}"))?;
        let Some(mut stdin) = child.stdin.take() else {
            return Err("pbcopy stdin unavailable".to_string());
        };
        stdin
            .write_all(text.as_bytes())
            .map_err(|err| format!("failed to write clipboard content: {err}"))?;
        drop(stdin);
        let status = child
            .wait()
            .map_err(|err| format!("failed to wait for pbcopy: {err}"))?;
        if !status.success() {
            return Err(format!("pbcopy exited with status {status}"));
        }
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    {
        let mut child = Command::new("cmd")
            .args(["/C", "clip"])
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|err| format!("failed to spawn clip: {err}"))?;
        let Some(mut stdin) = child.stdin.take() else {
            return Err("clip stdin unavailable".to_string());
        };
        stdin
            .write_all(text.as_bytes())
            .map_err(|err| format!("failed to write clipboard content: {err}"))?;
        drop(stdin);
        let status = child
            .wait()
            .map_err(|err| format!("failed to wait for clip: {err}"))?;
        if !status.success() {
            return Err(format!("clip exited with status {status}"));
        }
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        for (binary, args) in [
            ("wl-copy", Vec::<&str>::new()),
            ("xclip", vec!["-selection", "clipboard"]),
        ] {
            let mut child = match Command::new(binary)
                .args(&args)
                .stdin(Stdio::piped())
                .spawn()
            {
                Ok(child) => child,
                Err(_) => continue,
            };
            if let Some(mut stdin) = child.stdin.take() {
                if stdin.write_all(text.as_bytes()).is_err() {
                    continue;
                }
            } else {
                continue;
            }
            if let Ok(status) = child.wait() {
                if status.success() {
                    return Ok(());
                }
            }
        }
        return Err("no supported clipboard utility found (tried wl-copy, xclip)".to_string());
    }

    #[allow(unreachable_code)]
    Err("clipboard copy is not supported on this platform".to_string())
}

fn present_ui_bootstrap_code<R: Runtime>(app: &AppHandle<R>, code: &str, ttl_seconds: u64) {
    let ttl_seconds = ttl_seconds.max(1);
    show_notification(
        app,
        "Web UI One-Time Code",
        &format!("Enter code {code} in your browser within {ttl_seconds}s."),
    );

    let Some(tray_manager_state) = app.try_state::<Arc<TrayManager<R>>>() else {
        tracing::warn!(
            "Tray manager state unavailable; one-time code is only shown in system notification"
        );
        return;
    };
    let tray_manager = tray_manager_state.inner().clone();
    let code_for_clear = code.to_string();
    let clear_after = ttl_seconds.min(300);
    let hint = format!("Web UI code: {code_for_clear} (valid for {clear_after}s) · click to copy");
    tauri::async_runtime::spawn(async move {
        tray_manager
            .set_ui_bootstrap_hint(Some(hint), Some(code_for_clear.clone()))
            .await;
        sleep(Duration::from_secs(clear_after)).await;
        tray_manager
            .clear_ui_bootstrap_hint_if_code_matches(&code_for_clear)
            .await;
    });
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

/// Handle menu item clicks.
fn handle_menu_event<R: Runtime>(app: &AppHandle<R>, event: MenuEvent) {
    let id = event.id().as_ref();

    match id {
        menu_ids::TOGGLE_ENABLED => {
            tracing::info!("Toggle enabled clicked");
            let _ = app.emit("toggle_enabled", ());
        }
        menu_ids::INTEGRATIONS_INSTALL_HOOKS => {
            tracing::info!("Install hooks clicked (via Integrations menu)");
            let _ = app.emit("install_hooks", ());
        }
        menu_ids::INTEGRATIONS_INSTALL_OPENCLAW => {
            tracing::info!("Install OpenClaw plugin clicked");
            let _ = app.emit("install_openclaw_plugin", ());
        }
        menu_ids::INTEGRATIONS_CONFIGURE_SIEM => {
            tracing::info!("Configure SIEM export clicked");
            let settings: Arc<RwLock<Settings>> =
                app.state::<Arc<RwLock<Settings>>>().inner().clone();
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                let settings_snapshot = settings.read().await.clone();
                let Some(url) = resolve_dashboard_url(&settings_snapshot).await else {
                    tracing::warn!("Dashboard URL is invalid; refusing to open SIEM config");
                    return;
                };
                let Some(raw_target) = build_dashboard_settings_url(&url, "siem") else {
                    tracing::warn!("Failed to build SIEM settings URL; refusing to open");
                    return;
                };
                let auth_token = load_current_local_api_token();
                let Some(target) = build_dashboard_launch_target(
                    &raw_target,
                    &settings_snapshot,
                    auth_token.as_deref(),
                )
                .await
                else {
                    tracing::warn!("Failed to create secure SIEM dashboard launch target");
                    return;
                };
                if let Some(code) = target.bootstrap_code.as_deref() {
                    let ttl = target.bootstrap_ttl_seconds.unwrap_or(60);
                    present_ui_bootstrap_code(&app_handle, code, ttl);
                }
                tracing::debug!(url = %redact_url_for_log(&target.url), "Opening SIEM config");
                open_dashboard_url(&target.url);
            });
        }
        menu_ids::INTEGRATIONS_CONFIGURE_WEBHOOKS => {
            tracing::info!("Configure webhooks clicked");
            let settings: Arc<RwLock<Settings>> =
                app.state::<Arc<RwLock<Settings>>>().inner().clone();
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                let settings_snapshot = settings.read().await.clone();
                let Some(url) = resolve_dashboard_url(&settings_snapshot).await else {
                    tracing::warn!("Dashboard URL is invalid; refusing to open webhook config");
                    return;
                };
                let Some(raw_target) = build_dashboard_settings_url(&url, "webhooks") else {
                    tracing::warn!("Failed to build webhook settings URL; refusing to open");
                    return;
                };
                let auth_token = load_current_local_api_token();
                let Some(target) = build_dashboard_launch_target(
                    &raw_target,
                    &settings_snapshot,
                    auth_token.as_deref(),
                )
                .await
                else {
                    tracing::warn!("Failed to create secure webhook dashboard launch target");
                    return;
                };
                if let Some(code) = target.bootstrap_code.as_deref() {
                    let ttl = target.bootstrap_ttl_seconds.unwrap_or(60);
                    present_ui_bootstrap_code(&app_handle, code, ttl);
                }
                tracing::debug!(
                    url = %redact_url_for_log(&target.url),
                    "Opening webhook config"
                );
                open_dashboard_url(&target.url);
            });
        }
        menu_ids::RELOAD_POLICY => {
            tracing::info!("Reload policy clicked");
            let _ = app.emit("reload_policy", ());
        }
        menu_ids::CREATE_DIAGNOSTICS_BUNDLE => {
            tracing::info!("Create diagnostics bundle clicked");
            let settings: Arc<RwLock<Settings>> =
                app.state::<Arc<RwLock<Settings>>>().inner().clone();
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                let settings_snapshot = settings.read().await.clone();
                let auth_token = load_current_local_api_token();
                let Some(token) = auth_token
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                else {
                    show_notification(
                        &app_handle,
                        "Diagnostics Failed",
                        "Agent auth token unavailable.",
                    );
                    return;
                };

                let client = reqwest::Client::new();
                let url = format!(
                    "http://127.0.0.1:{}/api/v1/agent/diagnostics/bundle",
                    settings_snapshot.agent_api_port
                );
                let response = client
                    .post(&url)
                    .header("Authorization", format!("Bearer {token}"))
                    .header("Content-Type", "application/json")
                    .body("{}")
                    .send()
                    .await;
                match response {
                    Ok(resp) if resp.status().is_success() => {
                        match resp.json::<DiagnosticsBundleResponse>().await {
                            Ok(payload) => {
                                open_dashboard_url(&payload.bundle_path);
                                show_notification(
                                    &app_handle,
                                    "Diagnostics Bundle Created",
                                    &format!("Bundle generated at {}", payload.generated_at),
                                );
                            }
                            Err(err) => {
                                tracing::warn!(error = %err, "Failed to parse diagnostics response");
                                show_notification(
                                    &app_handle,
                                    "Diagnostics Failed",
                                    "Bundle created, but response parsing failed.",
                                );
                            }
                        }
                    }
                    Ok(resp) => {
                        let status = resp.status();
                        let body = resp.text().await.unwrap_or_default();
                        tracing::warn!(
                            status = %status,
                            body = %body,
                            "Diagnostics bundle request failed"
                        );
                        show_notification(
                            &app_handle,
                            "Diagnostics Failed",
                            "Agent API rejected diagnostics bundle request.",
                        );
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "Diagnostics bundle request errored");
                        show_notification(
                            &app_handle,
                            "Diagnostics Failed",
                            "Could not reach local agent API.",
                        );
                    }
                }
            });
        }
        menu_ids::UI_BOOTSTRAP_HINT | menu_ids::COPY_UI_BOOTSTRAP_CODE => {
            tracing::info!("Copy Web UI code clicked");
            let app_handle = app.clone();
            let Some(tray_manager_state) = app.try_state::<Arc<TrayManager<R>>>() else {
                tracing::warn!("Tray manager state unavailable; cannot copy Web UI code");
                return;
            };
            let tray_manager = tray_manager_state.inner().clone();
            tauri::async_runtime::spawn(async move {
                let Some(code) = tray_manager.current_ui_bootstrap_code().await else {
                    tracing::warn!("No active Web UI bootstrap code available to copy");
                    show_notification(
                        &app_handle,
                        "Web UI Code Unavailable",
                        "Generate a one-time code first.",
                    );
                    return;
                };
                match copy_text_to_clipboard(&code) {
                    Ok(()) => {
                        show_notification(
                            &app_handle,
                            "Web UI Code Copied",
                            &format!("Copied code {code} to clipboard."),
                        );
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "Failed to copy Web UI bootstrap code");
                        show_notification(
                            &app_handle,
                            "Web UI Copy Failed",
                            "Could not copy the code to clipboard.",
                        );
                    }
                }
            });
        }
        menu_ids::REGENERATE_UI_BOOTSTRAP_CODE => {
            tracing::info!("Regenerate Web UI code clicked");
            let settings: Arc<RwLock<Settings>> =
                app.state::<Arc<RwLock<Settings>>>().inner().clone();
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                let settings_snapshot = settings.read().await.clone();
                let auth_token = load_current_local_api_token();
                let Some(token) = auth_token
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                else {
                    show_notification(
                        &app_handle,
                        "Web UI Code Failed",
                        "Agent auth token unavailable.",
                    );
                    return;
                };

                let Some(bootstrap) = request_local_ui_bootstrap(
                    settings_snapshot.agent_api_port,
                    token,
                    "/ui".to_string(),
                )
                .await
                else {
                    show_notification(
                        &app_handle,
                        "Web UI Code Failed",
                        "Could not generate a new one-time code.",
                    );
                    return;
                };

                present_ui_bootstrap_code(
                    &app_handle,
                    &bootstrap.user_code,
                    bootstrap.expires_in_seconds,
                );
            });
        }
        menu_ids::OPEN_WEB_UI => {
            tracing::info!("Open Web UI clicked");
            let settings: Arc<RwLock<Settings>> =
                app.state::<Arc<RwLock<Settings>>>().inner().clone();
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                let settings_snapshot = settings.read().await.clone();
                let Some(raw_url) = resolve_dashboard_url(&settings_snapshot).await else {
                    tracing::warn!("Dashboard URL is invalid; refusing to open Web UI");
                    return;
                };
                let auth_token = load_current_local_api_token();
                let Some(target) = build_dashboard_launch_target(
                    &raw_url,
                    &settings_snapshot,
                    auth_token.as_deref(),
                )
                .await
                else {
                    tracing::warn!("Failed to create secure Web UI launch target");
                    return;
                };
                if let Some(code) = target.bootstrap_code.as_deref() {
                    let ttl = target.bootstrap_ttl_seconds.unwrap_or(60);
                    present_ui_bootstrap_code(&app_handle, code, ttl);
                }
                tracing::debug!(url = %redact_url_for_log(&target.url), "Opening Web UI");
                open_dashboard_url(&target.url);
            });
        }
        menu_ids::QUIT => {
            tracing::info!("Quit clicked");
            app.exit(0);
        }
        _ => tracing::debug!(id = %id, "Unknown menu item clicked"),
    }
}

/// Handle tray icon events.
fn handle_tray_event<R: Runtime>(_tray: &TrayIcon<R>, event: TrayIconEvent) {
    if let TrayIconEvent::Click {
        button: MouseButton::Left,
        button_state: MouseButtonState::Up,
        ..
    } = event
    {
        tracing::debug!("Tray icon clicked");
    }
}

/// Update the tray menu with new state.
pub fn update_tray_menu<R: Runtime>(
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

#[cfg(test)]
mod tests {
    use super::{
        build_dashboard_settings_url, default_local_dashboard_url,
        is_legacy_local_dev_dashboard_url, is_local_agent_ui_url, is_local_dashboard_url,
        redact_url_for_log, ui_next_path, validate_dashboard_url,
    };

    #[test]
    fn validate_dashboard_url_accepts_http_https_with_host() {
        assert_eq!(
            validate_dashboard_url("https://example.com/path?q=1").as_deref(),
            Some("https://example.com/path?q=1")
        );
        assert_eq!(
            validate_dashboard_url("http://localhost:3100").as_deref(),
            Some("http://localhost:3100/")
        );
    }

    #[test]
    fn validate_dashboard_url_rejects_non_network_or_hostless_urls() {
        assert!(validate_dashboard_url("urn:isbn:0451450523").is_none());
        assert!(validate_dashboard_url("javascript:alert(1)").is_none());
        assert!(validate_dashboard_url("file:///tmp/test").is_none());
        assert!(validate_dashboard_url("not a url").is_none());
    }

    #[test]
    fn local_dashboard_url_uses_agent_api_port() {
        assert_eq!(
            default_local_dashboard_url(9878),
            "http://127.0.0.1:9878/ui"
        );
    }

    #[test]
    fn local_dashboard_url_detection_is_precise() {
        assert!(is_local_dashboard_url("http://127.0.0.1:4200"));
        assert!(is_local_dashboard_url("https://localhost:3100/path"));
        assert!(is_local_dashboard_url("https://[::1]:3100/path"));
        assert!(!is_local_dashboard_url("https://example.com/settings"));
    }

    #[test]
    fn local_agent_ui_validation_pins_expected_origin() {
        let allowed = reqwest::Url::parse("http://127.0.0.1:9878/ui/settings/siem")
            .unwrap_or_else(|_| panic!("failed to parse allowed test url"));
        let allowed_https = reqwest::Url::parse("https://127.0.0.1:9878/ui/settings/siem")
            .unwrap_or_else(|_| panic!("failed to parse allowed-https test url"));
        let wrong_port = reqwest::Url::parse("http://127.0.0.1:9999/ui")
            .unwrap_or_else(|_| panic!("failed to parse wrong-port test url"));
        let wrong_scheme = reqwest::Url::parse("ftp://127.0.0.1:9878/ui")
            .unwrap_or_else(|_| panic!("failed to parse wrong-scheme test url"));
        let wrong_path = reqwest::Url::parse("http://127.0.0.1:9878/api")
            .unwrap_or_else(|_| panic!("failed to parse wrong-path test url"));
        let remote_host = reqwest::Url::parse("http://example.com:9878/ui")
            .unwrap_or_else(|_| panic!("failed to parse remote-host test url"));

        assert!(is_local_agent_ui_url(&allowed, 9878));
        assert!(is_local_agent_ui_url(&allowed_https, 9878));
        assert!(!is_local_agent_ui_url(&wrong_port, 9878));
        assert!(!is_local_agent_ui_url(&wrong_scheme, 9878));
        assert!(!is_local_agent_ui_url(&wrong_path, 9878));
        assert!(!is_local_agent_ui_url(&remote_host, 9878));
    }

    #[test]
    fn ui_next_path_and_log_redaction_strip_sensitive_url_parts() {
        let parsed = reqwest::Url::parse("http://127.0.0.1:9878/ui/settings/siem?x=1")
            .unwrap_or_else(|_| panic!("failed to parse next-path test url"));
        assert_eq!(ui_next_path(&parsed), "/ui/settings/siem?x=1".to_string());
        assert_eq!(
            redact_url_for_log("http://127.0.0.1:9878/ui/bootstrap?session_id=abc#fragment"),
            "http://127.0.0.1:9878/ui/bootstrap"
        );
    }

    #[test]
    fn build_dashboard_settings_url_uses_path_routes() {
        assert_eq!(
            build_dashboard_settings_url("http://127.0.0.1:3100", "siem").as_deref(),
            Some("http://127.0.0.1:3100/settings/siem")
        );
        assert_eq!(
            build_dashboard_settings_url("https://dashboard.example.com/app/", "webhooks")
                .as_deref(),
            Some("https://dashboard.example.com/app/settings/webhooks")
        );
        assert_eq!(
            build_dashboard_settings_url("https://dashboard.example.com/settings", "siem")
                .as_deref(),
            Some("https://dashboard.example.com/settings/siem")
        );
        assert_eq!(
            build_dashboard_settings_url("http://127.0.0.1:9878/ui", "webhooks").as_deref(),
            Some("http://127.0.0.1:9878/ui/settings/webhooks")
        );
    }

    #[test]
    fn legacy_local_dev_dashboard_url_detection_is_precise() {
        assert!(is_legacy_local_dev_dashboard_url("http://localhost:3100"));
        assert!(is_legacy_local_dev_dashboard_url("http://127.0.0.1:3100/"));
        assert!(!is_legacy_local_dev_dashboard_url("http://localhost:4200"));
        assert!(!is_legacy_local_dev_dashboard_url("https://localhost:3100"));
        assert!(!is_legacy_local_dev_dashboard_url(
            "http://example.com:3100"
        ));
    }
}
