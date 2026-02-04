//! Settings management for Clawdstrike Agent
//!
//! Persistent configuration stored in ~/.config/clawdstrike/agent.json

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Agent settings persisted to disk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// Path to the policy file
    #[serde(default = "default_policy_path")]
    pub policy_path: PathBuf,

    /// Port for the hushd daemon HTTP API
    #[serde(default = "default_daemon_port")]
    pub daemon_port: u16,

    /// Port for the MCP server
    #[serde(default = "default_mcp_port")]
    pub mcp_port: u16,

    /// Whether enforcement is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Whether to start the agent at login
    #[serde(default = "default_auto_start")]
    pub auto_start: bool,

    /// Whether to show desktop notifications
    #[serde(default = "default_notifications_enabled")]
    pub notifications_enabled: bool,

    /// Minimum severity for notifications (block, warn, info)
    #[serde(default = "default_notification_severity")]
    pub notification_severity: String,

    /// Whether to play sound on notifications
    #[serde(default)]
    pub notification_sound: bool,

    /// Path to hushd binary (if not using bundled)
    #[serde(default)]
    pub hushd_binary_path: Option<PathBuf>,

    /// API key for hushd (if authentication is enabled)
    #[serde(default)]
    pub api_key: Option<String>,
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
            enabled: default_enabled(),
            auto_start: default_auto_start(),
            notifications_enabled: default_notifications_enabled(),
            notification_severity: default_notification_severity(),
            notification_sound: false,
            hushd_binary_path: None,
            api_key: None,
        }
    }
}

impl Settings {
    /// Load settings from disk, or create defaults if not found
    pub fn load() -> Result<Self> {
        let path = get_settings_path();

        if path.exists() {
            let contents = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read settings from {:?}", path))?;
            let settings: Settings = serde_json::from_str(&contents)
                .with_context(|| "Failed to parse settings JSON")?;
            Ok(settings)
        } else {
            let settings = Settings::default();
            settings.save()?;
            Ok(settings)
        }
    }

    /// Save settings to disk
    pub fn save(&self) -> Result<()> {
        let path = get_settings_path();

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory {:?}", parent))?;
        }

        let contents = serde_json::to_string_pretty(self)
            .with_context(|| "Failed to serialize settings")?;
        std::fs::write(&path, contents)
            .with_context(|| format!("Failed to write settings to {:?}", path))?;

        Ok(())
    }

    /// Get the daemon URL based on current settings
    pub fn daemon_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.daemon_port)
    }

    /// Get the MCP server URL based on current settings
    pub fn mcp_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.mcp_port)
    }
}

/// Get the configuration directory for clawdstrike
pub fn get_config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("clawdstrike")
}

/// Get the path to the settings file
pub fn get_settings_path() -> PathBuf {
    get_config_dir().join("agent.json")
}

/// Get the data directory for clawdstrike
pub fn get_data_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("clawdstrike")
}

/// Ensure the default policy file exists, copying from bundled if needed
pub fn ensure_default_policy(bundled_policy: &str) -> Result<PathBuf> {
    let policy_path = default_policy_path();

    if !policy_path.exists() {
        // Ensure parent directory exists
        if let Some(parent) = policy_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory {:?}", parent))?;
        }

        // Copy bundled policy
        std::fs::write(&policy_path, bundled_policy)
            .with_context(|| format!("Failed to write default policy to {:?}", policy_path))?;

        tracing::info!("Created default policy at {:?}", policy_path);
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
        assert!(settings.enabled);
        assert!(settings.notifications_enabled);
    }

    #[test]
    fn test_daemon_url() {
        let settings = Settings::default();
        assert_eq!(settings.daemon_url(), "http://127.0.0.1:9876");
    }
}
