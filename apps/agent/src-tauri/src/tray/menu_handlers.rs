//! Click handlers for the tray menu.
//!
//! Each handler is wired up via `setup_tray` (`on_menu_event`). Most
//! handlers emit a tauri event for the bootstrap layer to react to;
//! the dashboard-related ones perform their own HTTP calls because they
//! need a one-time bootstrap code minted via the local agent API.

use std::sync::Arc;
use std::time::Duration;
use tauri::menu::MenuEvent;
use tauri::tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, Runtime};
use tokio::sync::RwLock;
use tokio::time::sleep;

use crate::agent_auth::read_local_api_token;
use crate::notifications::show_notification;
use crate::settings::Settings;

use super::dashboard_url::{
    build_dashboard_launch_target, build_dashboard_settings_url, redact_url_for_log,
    request_local_ui_bootstrap, resolve_dashboard_url, DashboardLaunchTarget,
};
use super::manager::TrayManager;
use super::menu_ids;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct DiagnosticsBundleResponse {
    bundle_path: String,
    generated_at: String,
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

async fn open_dashboard_settings_section<R: Runtime>(
    app_handle: AppHandle<R>,
    settings: Arc<RwLock<Settings>>,
    section: &'static str,
    failure_log: &'static str,
    open_log: &'static str,
) {
    let settings_snapshot = settings.read().await.clone();
    let Some(url) = resolve_dashboard_url(&settings_snapshot).await else {
        tracing::warn!("Dashboard URL is invalid; refusing to open {}", section);
        return;
    };
    let Some(raw_target) = build_dashboard_settings_url(&url, section) else {
        tracing::warn!("Failed to build {} settings URL; refusing to open", section);
        return;
    };
    let auth_token = load_current_local_api_token();
    let Some(target) =
        build_dashboard_launch_target(&raw_target, &settings_snapshot, auth_token.as_deref()).await
    else {
        tracing::warn!("{}", failure_log);
        return;
    };
    if let Some(code) = target.bootstrap_code.as_deref() {
        let ttl = target.bootstrap_ttl_seconds.unwrap_or(60);
        present_ui_bootstrap_code(&app_handle, code, ttl);
    }
    tracing::debug!(url = %redact_url_for_log(&target.url), "{}", open_log);
    open_dashboard_url(&target.url);
}

/// Handle menu item clicks.
pub(super) fn handle_menu_event<R: Runtime>(app: &AppHandle<R>, event: MenuEvent) {
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
            tauri::async_runtime::spawn(open_dashboard_settings_section(
                app_handle,
                settings,
                "siem",
                "Failed to create secure SIEM dashboard launch target",
                "Opening SIEM config",
            ));
        }
        menu_ids::INTEGRATIONS_CONFIGURE_WEBHOOKS => {
            tracing::info!("Configure webhooks clicked");
            let settings: Arc<RwLock<Settings>> =
                app.state::<Arc<RwLock<Settings>>>().inner().clone();
            let app_handle = app.clone();
            tauri::async_runtime::spawn(open_dashboard_settings_section(
                app_handle,
                settings,
                "webhooks",
                "Failed to create secure webhook dashboard launch target",
                "Opening webhook config",
            ));
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
                create_diagnostics_bundle(&app_handle, &settings).await;
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
                copy_active_bootstrap_code(&app_handle, tray_manager).await;
            });
        }
        menu_ids::REGENERATE_UI_BOOTSTRAP_CODE => {
            tracing::info!("Regenerate Web UI code clicked");
            let settings: Arc<RwLock<Settings>> =
                app.state::<Arc<RwLock<Settings>>>().inner().clone();
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                regenerate_bootstrap_code(&app_handle, &settings).await;
            });
        }
        menu_ids::OPEN_WEB_UI => {
            tracing::info!("Open Web UI clicked");
            let settings: Arc<RwLock<Settings>> =
                app.state::<Arc<RwLock<Settings>>>().inner().clone();
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                open_main_web_ui(&app_handle, &settings).await;
            });
        }
        menu_ids::QUIT => {
            tracing::info!("Quit clicked");
            app.exit(0);
        }
        _ => tracing::debug!(id = %id, "Unknown menu item clicked"),
    }
}

async fn create_diagnostics_bundle<R: Runtime>(
    app_handle: &AppHandle<R>,
    settings: &Arc<RwLock<Settings>>,
) {
    let settings_snapshot = settings.read().await.clone();
    let auth_token = load_current_local_api_token();
    let Some(token) = auth_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        show_notification(
            app_handle,
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
                        app_handle,
                        "Diagnostics Bundle Created",
                        &format!("Bundle generated at {}", payload.generated_at),
                    );
                }
                Err(err) => {
                    tracing::warn!(error = %err, "Failed to parse diagnostics response");
                    show_notification(
                        app_handle,
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
                app_handle,
                "Diagnostics Failed",
                "Agent API rejected diagnostics bundle request.",
            );
        }
        Err(err) => {
            tracing::warn!(error = %err, "Diagnostics bundle request errored");
            show_notification(
                app_handle,
                "Diagnostics Failed",
                "Could not reach local agent API.",
            );
        }
    }
}

async fn copy_active_bootstrap_code<R: Runtime>(
    app_handle: &AppHandle<R>,
    tray_manager: Arc<TrayManager<R>>,
) {
    let Some(code) = tray_manager.current_ui_bootstrap_code().await else {
        tracing::warn!("No active Web UI bootstrap code available to copy");
        show_notification(
            app_handle,
            "Web UI Code Unavailable",
            "Generate a one-time code first.",
        );
        return;
    };
    match copy_text_to_clipboard(&code) {
        Ok(()) => {
            show_notification(
                app_handle,
                "Web UI Code Copied",
                &format!("Copied code {code} to clipboard."),
            );
        }
        Err(err) => {
            tracing::warn!(error = %err, "Failed to copy Web UI bootstrap code");
            show_notification(
                app_handle,
                "Web UI Copy Failed",
                "Could not copy the code to clipboard.",
            );
        }
    }
}

async fn regenerate_bootstrap_code<R: Runtime>(
    app_handle: &AppHandle<R>,
    settings: &Arc<RwLock<Settings>>,
) {
    let settings_snapshot = settings.read().await.clone();
    let auth_token = load_current_local_api_token();
    let Some(token) = auth_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        show_notification(
            app_handle,
            "Web UI Code Failed",
            "Agent auth token unavailable.",
        );
        return;
    };

    let Some(bootstrap) =
        request_local_ui_bootstrap(settings_snapshot.agent_api_port, token, "/ui".to_string())
            .await
    else {
        show_notification(
            app_handle,
            "Web UI Code Failed",
            "Could not generate a new one-time code.",
        );
        return;
    };

    present_ui_bootstrap_code(
        app_handle,
        &bootstrap.user_code,
        bootstrap.expires_in_seconds,
    );
}

async fn open_main_web_ui<R: Runtime>(app_handle: &AppHandle<R>, settings: &Arc<RwLock<Settings>>) {
    let settings_snapshot = settings.read().await.clone();
    let Some(raw_url) = resolve_dashboard_url(&settings_snapshot).await else {
        tracing::warn!("Dashboard URL is invalid; refusing to open Web UI");
        return;
    };
    let auth_token = load_current_local_api_token();
    let Some(target): Option<DashboardLaunchTarget> =
        build_dashboard_launch_target(&raw_url, &settings_snapshot, auth_token.as_deref()).await
    else {
        tracing::warn!("Failed to create secure Web UI launch target");
        return;
    };
    if let Some(code) = target.bootstrap_code.as_deref() {
        let ttl = target.bootstrap_ttl_seconds.unwrap_or(60);
        present_ui_bootstrap_code(app_handle, code, ttl);
    }
    tracing::debug!(url = %redact_url_for_log(&target.url), "Opening Web UI");
    open_dashboard_url(&target.url);
}

/// Handle tray icon events.
pub(super) fn handle_tray_event<R: Runtime>(_tray: &TrayIcon<R>, event: TrayIconEvent) {
    if let TrayIconEvent::Click {
        button: MouseButton::Left,
        button_state: MouseButtonState::Up,
        ..
    } = event
    {
        tracing::debug!("Tray icon clicked");
    }
}
