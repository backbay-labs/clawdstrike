//! Settings management for Clawdstrike Agent.
//!
//! Persistent configuration stored in ~/.config/clawdstrike/agent.json.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Non-secret OpenClaw gateway metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenClawGatewayMetadata {
    pub id: String,
    pub label: String,
    pub gateway_url: String,
}

/// OpenClaw settings stored in agent config.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OpenClawSettings {
    #[serde(default)]
    pub gateways: Vec<OpenClawGatewayMetadata>,
    #[serde(default)]
    pub active_gateway_id: Option<String>,
}

/// Agent settings persisted to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// Path to the policy file.
    #[serde(default = "default_policy_path")]
    pub policy_path: PathBuf,

    /// Port for the hushd daemon HTTP API.
    #[serde(default = "default_daemon_port")]
    pub daemon_port: u16,

    /// Port for the MCP server.
    #[serde(default = "default_mcp_port")]
    pub mcp_port: u16,

    /// Port for the local authenticated agent API.
    #[serde(default = "default_agent_api_port")]
    pub agent_api_port: u16,

    /// Whether enforcement is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Whether to start the agent at login.
    #[serde(default = "default_auto_start")]
    pub auto_start: bool,

    /// Whether to show desktop notifications.
    #[serde(default = "default_notifications_enabled")]
    pub notifications_enabled: bool,

    /// Minimum severity for notifications (block, warn, info).
    #[serde(default = "default_notification_severity")]
    pub notification_severity: String,

    /// Whether to play sound on notifications.
    #[serde(default)]
    pub notification_sound: bool,

    /// Debug-only: include hushd error bodies in tool-visible policy-check JSON.
    ///
    /// This can leak internal details; keep disabled in normal operation.
    #[serde(default)]
    pub debug_include_daemon_error_body: bool,

    /// Path to hushd binary (if not using bundled).
    #[serde(default)]
    pub hushd_binary_path: Option<PathBuf>,

    /// API key for hushd (if authentication is enabled).
    #[serde(default)]
    pub api_key: Option<String>,

    /// Non-secret OpenClaw metadata.
    #[serde(default)]
    pub openclaw: OpenClawSettings,
}

fn default_policy_path() -> PathBuf {
    get_config_dir().join("policy.yaml")
}

fn default_daemon_port() -> u16 {
    9876
}

fn default_mcp_port() -> u16 {
    9877
}

fn default_agent_api_port() -> u16 {
    9878
}

fn default_enabled() -> bool {
    true
}

fn default_auto_start() -> bool {
    true
}

fn default_notifications_enabled() -> bool {
    true
}

fn default_notification_severity() -> String {
    "block".to_string()
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            policy_path: default_policy_path(),
            daemon_port: default_daemon_port(),
            mcp_port: default_mcp_port(),
            agent_api_port: default_agent_api_port(),
            enabled: default_enabled(),
            auto_start: default_auto_start(),
            notifications_enabled: default_notifications_enabled(),
            notification_severity: default_notification_severity(),
            notification_sound: false,
            debug_include_daemon_error_body: false,
            hushd_binary_path: None,
            api_key: None,
            openclaw: OpenClawSettings::default(),
        }
    }
}

impl Settings {
    /// Load settings from disk, or create defaults if not found.
    pub fn load() -> Result<Self> {
        let path = get_settings_path();

        if path.exists() {
            let contents = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read settings from {:?}", path))?;
            let settings: Settings =
                serde_json::from_str(&contents).with_context(|| "Failed to parse settings JSON")?;
            Ok(settings)
        } else {
            let settings = Settings::default();
            settings.save()?;
            Ok(settings)
        }
    }

    /// Save settings to disk.
    pub fn save(&self) -> Result<()> {
        let path = get_settings_path();

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory {:?}", parent))?;
        }

        let contents =
            serde_json::to_string_pretty(self).with_context(|| "Failed to serialize settings")?;
        std::fs::write(&path, contents)
            .with_context(|| format!("Failed to write settings to {:?}", path))?;

        Ok(())
    }

    /// Get the daemon URL based on current settings.
    pub fn daemon_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.daemon_port)
    }
}

/// Get the configuration directory for clawdstrike.
pub fn get_config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("clawdstrike")
}

/// Get the path to the settings file.
pub fn get_settings_path() -> PathBuf {
    get_config_dir().join("agent.json")
}

/// Get the path to the local API auth token file.
pub fn get_agent_token_path() -> PathBuf {
    get_config_dir().join("agent-local-token")
}

/// Ensure the default policy file exists, copying from bundled if needed.
pub fn ensure_default_policy(bundled_policy: &str) -> Result<PathBuf> {
    let policy_path = default_policy_path();

    if !policy_path.exists() {
        if let Some(parent) = policy_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory {:?}", parent))?;
        }

        std::fs::write(&policy_path, bundled_policy)
            .with_context(|| format!("Failed to write default policy to {:?}", policy_path))?;

        tracing::info!(path = ?policy_path, "Created default policy");
    }

    Ok(policy_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_settings() {
        let settings = Settings::default();
        assert_eq!(settings.daemon_port, 9876);
        assert_eq!(settings.mcp_port, 9877);
        assert_eq!(settings.agent_api_port, 9878);
        assert!(settings.enabled);
        assert!(settings.notifications_enabled);
        assert!(!settings.debug_include_daemon_error_body);
    }

    #[test]
    fn test_daemon_url() {
        let settings = Settings::default();
        assert_eq!(settings.daemon_url(), "http://127.0.0.1:9876");
        assert_eq!(settings.agent_api_port, 9878);
    }
}
