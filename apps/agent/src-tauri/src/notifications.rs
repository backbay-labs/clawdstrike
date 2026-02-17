//! Desktop notifications for Clawdstrike Agent.

use crate::decision::NormalizedDecision;
use crate::events::PolicyEvent;
use crate::settings::Settings;
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(target_os = "macos")]
use std::sync::Once;
use tauri::path::BaseDirectory;
use tauri::Manager;
use tauri::{AppHandle, Runtime};
#[cfg(not(target_os = "macos"))]
use tauri_plugin_notification::NotificationExt;
use tokio::sync::RwLock;

const BRAND_PREFIX: &str = "Clawdstrike // ";
const NOTIFICATION_ICON_RESOURCES: &[&str] = &["icons/icon.icns", "icons/icon.png"];
const NOTIFICATION_ICON_DEV_FILES: &[&str] = &["icons/icon.icns", "icons/icon.png"];
#[cfg(target_os = "macos")]
static MAC_NOTIFICATION_SOURCE_INIT: Once = Once::new();

/// Severity levels for notifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info = 0,
    Warn = 1,
    Block = 2,
}

impl Severity {
    pub fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "block" | "high" | "critical" => Self::Block,
            "warn" | "warning" | "medium" => Self::Warn,
            _ => Self::Info,
        }
    }

    pub fn from_decision(decision: &str) -> Self {
        match NormalizedDecision::from_str(decision) {
            NormalizedDecision::Blocked => Self::Block,
            NormalizedDecision::Warn => Self::Warn,
            _ => Self::Info,
        }
    }
}

/// Notification manager.
pub struct NotificationManager<R: Runtime> {
    app: AppHandle<R>,
    settings: Arc<RwLock<Settings>>,
}

impl<R: Runtime> NotificationManager<R> {
    /// Create a new notification manager.
    pub fn new(app: AppHandle<R>, settings: Arc<RwLock<Settings>>) -> Self {
        Self { app, settings }
    }

    async fn should_notify(&self, event_severity: Severity) -> bool {
        let settings = self.settings.read().await;
        if !settings.notifications_enabled {
            return false;
        }
        let min_severity = Severity::from_str(&settings.notification_severity);
        event_severity >= min_severity
    }

    /// Show notification for a policy event.
    pub async fn notify(&self, event: &PolicyEvent) {
        let event_severity = Severity::from_decision(&event.decision);
        if !self.should_notify(event_severity).await {
            return;
        }

        let (title, body) = format_notification(event);
        show_branded_notification(&self.app, &title, &body);
    }

    /// Show notification for posture transitions.
    pub async fn notify_posture_transition(&self, from: &str, to: &str) {
        let notifications_enabled = self.settings.read().await.notifications_enabled;
        if !notifications_enabled {
            return;
        }

        let body = format!("Posture changed from {} to {}", from, to);
        show_branded_notification(&self.app, "Posture Transition", &body);
    }
}

fn branded_title(title: &str) -> String {
    format!("{BRAND_PREFIX}{title}")
}

fn resolve_notification_icon_path<R: Runtime>(app: &AppHandle<R>) -> Option<String> {
    for rel in NOTIFICATION_ICON_RESOURCES {
        if let Ok(path) = app.path().resolve(rel, BaseDirectory::Resource) {
            if path.is_file() {
                return Some(path.to_string_lossy().into_owned());
            }
        }
    }

    for rel in NOTIFICATION_ICON_DEV_FILES {
        let dev_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
        if dev_path.is_file() {
            return Some(dev_path.to_string_lossy().into_owned());
        }
    }

    None
}

#[cfg(target_os = "macos")]
fn mac_notification_bundle_id<R: Runtime>(app: &AppHandle<R>) -> String {
    // When launched from raw CLI binary, notifications are attributed to Terminal.
    // Forcing an uninstalled bundle id logs warnings and can trigger odd OS UX paths.
    let running_from_app_bundle = std::env::current_exe()
        .ok()
        .map(|p| p.to_string_lossy().contains(".app/Contents/MacOS/"))
        .unwrap_or(false);
    if running_from_app_bundle {
        app.config().identifier.clone()
    } else {
        "com.apple.Terminal".to_string()
    }
}

fn show_branded_notification<R: Runtime>(app: &AppHandle<R>, title: &str, body: &str) {
    #[cfg(target_os = "macos")]
    {
        MAC_NOTIFICATION_SOURCE_INIT.call_once(|| {
            // Avoid mac-notification-sys probing "use_default", which can open a chooser dialog.
            let bundle_id = mac_notification_bundle_id(app);
            if let Err(err) = mac_notification_sys::set_application(&bundle_id) {
                tracing::warn!(
                    error = %err,
                    bundle_id,
                    "Failed to set macOS notification source bundle id"
                );
            }
        });

        let branded = branded_title(title);
        let mut notification = mac_notification_sys::Notification::new();
        notification
            .title(&branded)
            .message(body)
            .asynchronous(true);

        let icon_path = resolve_notification_icon_path(app);
        if let Some(path) = icon_path.as_deref() {
            notification.app_icon(path);
        }

        if let Err(err) = notification.send() {
            tracing::error!(error = %err, "Failed to show notification");
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        let mut builder = app
            .notification()
            .builder()
            .title(branded_title(title))
            .body(body);

        if let Some(icon_path) = resolve_notification_icon_path(app) {
            builder = builder.icon(icon_path);
        }

        if let Err(err) = builder.show() {
            tracing::error!(error = %err, "Failed to show notification");
        }
    }
}

/// Format a policy event into notification title and body.
fn format_notification(event: &PolicyEvent) -> (String, String) {
    let icon = match NormalizedDecision::from_str(&event.decision) {
        NormalizedDecision::Blocked => "🚫",
        NormalizedDecision::Warn => "⚠️",
        _ => "ℹ️",
    };

    let title = format!(
        "{} {} {}",
        icon,
        event.decision.to_uppercase(),
        event.action_type
    );

    let target = event.target.as_deref().unwrap_or("unknown target");

    let mut body = if let Some(ref message) = event.message {
        format!("{}\n{}", target, message)
    } else if let Some(ref guard) = event.guard {
        format!("{}\nGuard: {}", target, guard)
    } else {
        target.to_string()
    };

    if let Some(agent_id) = event
        .agent_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        body.push_str(&format!("\nAgent: {agent_id}"));
    }

    if let Some(session_id) = event
        .session_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        body.push_str(&format!("\nSession: {session_id}"));
    }

    (title, body)
}

/// Simple notification helper for one-off notifications.
pub fn show_notification<R: Runtime>(app: &AppHandle<R>, title: &str, body: &str) {
    show_branded_notification(app, title, body);
}

/// Show a notification that the agent has started.
pub fn show_startup_notification<R: Runtime>(app: &AppHandle<R>) {
    show_notification(app, "Agent Started", "Security enforcement is now active");
}

/// Show a notification that enforcement was toggled.
pub fn show_toggle_notification<R: Runtime>(app: &AppHandle<R>, enabled: bool) {
    let (title, body) = if enabled {
        (
            "Enforcement Enabled",
            "Security policy enforcement is now active",
        )
    } else {
        (
            "Enforcement Disabled",
            "Security policy enforcement is paused",
        )
    };
    show_notification(app, title, body);
}

/// Show a notification for policy reload.
pub fn show_policy_reload_notification<R: Runtime>(app: &AppHandle<R>, success: bool) {
    let (title, body) = if success {
        ("Policy Reloaded", "Security policy has been updated")
    } else {
        (
            "Policy Reload Failed",
            "Failed to reload security policy. Check logs for details.",
        )
    };
    show_notification(app, title, body);
}

/// Show a notification for Claude Code hooks installation.
pub fn show_hooks_installed_notification<R: Runtime>(app: &AppHandle<R>, success: bool) {
    let (title, body) = if success {
        (
            "Claude Code Hooks Installed",
            "Policy checks are now integrated with Claude Code",
        )
    } else {
        (
            "Hook Installation Failed",
            "Failed to install Claude Code hooks. Check logs for details.",
        )
    };
    show_notification(app, title, body);
}

/// Show a notification for OpenClaw plugin installation.
pub fn show_openclaw_plugin_installed_notification<R: Runtime>(app: &AppHandle<R>, success: bool) {
    let (title, body) = if success {
        (
            "OpenClaw Plugin Installed",
            "Clawdstrike security plugin is now active in OpenClaw",
        )
    } else {
        (
            "OpenClaw Plugin Installation Failed",
            "Failed to install OpenClaw plugin. Check logs for details.",
        )
    };
    show_notification(app, title, body);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::PolicyEvent;

    #[test]
    fn test_severity_from_str() {
        assert_eq!(Severity::from_str("block"), Severity::Block);
        assert_eq!(Severity::from_str("BLOCK"), Severity::Block);
        assert_eq!(Severity::from_str("warn"), Severity::Warn);
        assert_eq!(Severity::from_str("info"), Severity::Info);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Block > Severity::Warn);
        assert!(Severity::Warn > Severity::Info);
    }

    #[test]
    fn test_format_notification() {
        let event = PolicyEvent {
            id: "123".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            action_type: "file_access".to_string(),
            target: Some("/etc/passwd".to_string()),
            decision: "blocked".to_string(),
            guard: Some("fs_blocklist".to_string()),
            severity: Some("high".to_string()),
            message: None,
            details: serde_json::Value::Null,
            session_id: Some("s-123".to_string()),
            agent_id: Some("a-456".to_string()),
        };

        let (title, body) = format_notification(&event);
        assert!(title.contains("BLOCKED"));
        assert!(title.contains("file_access"));
        assert!(body.contains("/etc/passwd"));
        assert!(body.contains("Agent: a-456"));
        assert!(body.contains("Session: s-123"));
    }

    #[test]
    fn test_branded_title() {
        assert_eq!(
            branded_title("Policy Reloaded"),
            "Clawdstrike // Policy Reloaded"
        );
    }
}
