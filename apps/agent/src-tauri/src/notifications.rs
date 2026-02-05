//! Desktop notifications for Clawdstrike Agent
//!
//! Shows notifications when policy events occur.

use crate::events::PolicyEvent;
use crate::settings::Settings;
use std::sync::Arc;
use tauri::{AppHandle, Runtime};
use tauri_plugin_notification::NotificationExt;
use tokio::sync::{broadcast, RwLock};

/// Severity levels for notifications
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info = 0,
    Warn = 1,
    Block = 2,
}

impl Severity {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "block" | "high" | "critical" => Severity::Block,
            "warn" | "warning" | "medium" => Severity::Warn,
            _ => Severity::Info,
        }
    }

    pub fn from_decision(decision: &str) -> Self {
        match decision.to_lowercase().as_str() {
            "block" => Severity::Block,
            "warn" => Severity::Warn,
            _ => Severity::Info,
        }
    }
}

/// Notification manager
pub struct NotificationManager<R: Runtime> {
    app: AppHandle<R>,
    settings: Arc<RwLock<Settings>>,
    min_severity: Arc<RwLock<Severity>>,
}

impl<R: Runtime> NotificationManager<R> {
    /// Create a new notification manager
    pub fn new(app: AppHandle<R>, settings: Arc<RwLock<Settings>>) -> Self {
        Self {
            app,
            settings,
            min_severity: Arc::new(RwLock::new(Severity::Block)),
        }
    }

    /// Update settings
    pub async fn update_settings(&self, settings: &Settings) {
        let severity = Severity::from_str(&settings.notification_severity);
        *self.min_severity.write().await = severity;
    }

    /// Show notification for a policy event
    pub async fn notify(&self, event: &PolicyEvent) {
        let settings = self.settings.read().await;

        // Check if notifications are enabled
        if !settings.notifications_enabled {
            return;
        }

        // Check severity threshold
        let event_severity = Severity::from_decision(&event.decision);
        let min_severity = *self.min_severity.read().await;

        if event_severity < min_severity {
            return;
        }

        drop(settings);

        // Build notification
        let (title, body) = format_notification(event);

        // Send via Tauri notification plugin
        if let Err(e) = self
            .app
            .notification()
            .builder()
            .title(&title)
            .body(&body)
            .show()
        {
            tracing::error!("Failed to show notification: {}", e);
        }
    }

    /// Start listening for events and showing notifications
    pub async fn start(&self, mut events_rx: broadcast::Receiver<PolicyEvent>) {
        while let Ok(event) = events_rx.recv().await {
            self.notify(&event).await;
        }
    }
}

/// Format a policy event into notification title and body
fn format_notification(event: &PolicyEvent) -> (String, String) {
    let icon = match event.decision.to_lowercase().as_str() {
        "block" => "🚫",
        "warn" => "⚠️",
        _ => "ℹ️",
    };

    let title = format!(
        "{} {} {}",
        icon,
        event.decision.to_uppercase(),
        event.action_type
    );

    let target = event
        .target
        .as_deref()
        .unwrap_or("unknown target");

    let body = if let Some(ref message) = event.message {
        format!("{}\n{}", target, message)
    } else if let Some(ref guard) = event.guard {
        format!("{}\nBlocked by: {}", target, guard)
    } else {
        target.to_string()
    };

    (title, body)
}

/// Simple notification helper for one-off notifications
pub fn show_notification<R: Runtime>(app: &AppHandle<R>, title: &str, body: &str) {
    if let Err(e) = app.notification().builder().title(title).body(body).show() {
        tracing::error!("Failed to show notification: {}", e);
    }
}

/// Show a notification that the agent has started
pub fn show_startup_notification<R: Runtime>(app: &AppHandle<R>) {
    show_notification(
        app,
        "Clawdstrike Agent Started",
        "Security enforcement is now active",
    );
}

/// Show a notification that enforcement was toggled
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

/// Show a notification for policy reload
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

/// Show a notification for Claude Code hooks installation
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
            decision: "block".to_string(),
            guard: Some("fs_blocklist".to_string()),
            severity: Some("high".to_string()),
            message: None,
            details: serde_json::Value::Null,
        };

        let (title, body) = format_notification(&event);
        assert!(title.contains("BLOCK"));
        assert!(title.contains("file_access"));
        assert!(body.contains("/etc/passwd"));
    }
}
