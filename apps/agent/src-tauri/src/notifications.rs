//! Desktop notifications for Clawdstrike Agent.

use crate::decision::NormalizedDecision;
use crate::events::PolicyEvent;
use crate::settings::Settings;
use std::sync::Arc;
use tauri::{AppHandle, Runtime};
use tauri_plugin_notification::NotificationExt;
use tokio::sync::RwLock;

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

    /// Show notification for a policy event.
    pub async fn notify(&self, event: &PolicyEvent) {
        let settings = self.settings.read().await;

        if !settings.notifications_enabled {
            return;
        }

        let min_severity = Severity::from_str(&settings.notification_severity);
        let event_severity = Severity::from_decision(&event.decision);
        if event_severity < min_severity {
            return;
        }

        drop(settings);

        let (title, body) = format_notification(event);
        if let Err(err) = self
            .app
            .notification()
            .builder()
            .title(&title)
            .body(&body)
            .show()
        {
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

    let body = if let Some(ref message) = event.message {
        format!("{}\n{}", target, message)
    } else if let Some(ref guard) = event.guard {
        format!("{}\nGuard: {}", target, guard)
    } else {
        target.to_string()
    };

    (title, body)
}

/// Simple notification helper for one-off notifications.
pub fn show_notification<R: Runtime>(app: &AppHandle<R>, title: &str, body: &str) {
    if let Err(err) = app.notification().builder().title(title).body(body).show() {
        tracing::error!(error = %err, "Failed to show notification");
    }
}

/// Show a notification that the agent has started.
pub fn show_startup_notification<R: Runtime>(app: &AppHandle<R>) {
    show_notification(
        app,
        "Clawdstrike Agent Started",
        "Security enforcement is now active",
    );
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
        };

        let (title, body) = format_notification(&event);
        assert!(title.contains("BLOCKED"));
        assert!(title.contains("file_access"));
        assert!(body.contains("/etc/passwd"));
    }
}
