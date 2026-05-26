//! Top-level `Settings` struct, load/save, and defaults wiring.

use super::brokerd::BrokerdSettings;
use super::control_api::ControlApiSettings;
use super::defaults::{
    default_agent_api_port, default_auto_start, default_daemon_port, default_dashboard_url,
    default_dashboard_url_for_port, default_enabled, default_mcp_port,
    default_notification_severity, default_notifications_enabled, default_ota_channel,
    default_ota_check_interval_minutes, default_ota_enabled, default_ota_mode, default_policy_path,
};
use super::enrollment::EnrollmentState;
use super::integrations::IntegrationSettings;
use super::local_api::LocalApiSecuritySettings;
use super::nats::NatsSettings;
use super::openclaw::OpenClawSettings;
use super::paths::{get_settings_path, write_settings_file};
use super::runtime_registry::RuntimeRegistrySettings;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    #[serde(skip)]
    pub(crate) settings_path_override: Option<PathBuf>,

    #[serde(default = "default_policy_path")]
    pub policy_path: PathBuf,

    #[serde(default = "default_daemon_port")]
    pub daemon_port: u16,

    #[serde(default = "default_mcp_port")]
    pub mcp_port: u16,

    #[serde(default = "default_agent_api_port")]
    pub agent_api_port: u16,

    #[serde(default = "default_enabled")]
    pub enabled: bool,

    #[serde(default = "default_auto_start")]
    pub auto_start: bool,

    #[serde(default = "default_notifications_enabled")]
    pub notifications_enabled: bool,

    #[serde(default = "default_notification_severity")]
    pub notification_severity: String,

    #[serde(default)]
    pub notification_sound: bool,

    /// Can leak internal details; keep disabled in normal operation.
    #[serde(default)]
    pub debug_include_daemon_error_body: bool,

    #[serde(default)]
    pub hushd_binary_path: Option<PathBuf>,

    #[serde(default)]
    pub api_key: Option<String>,

    #[serde(default)]
    pub brokerd: BrokerdSettings,

    #[serde(default)]
    pub openclaw: OpenClawSettings,

    #[serde(default = "default_dashboard_url")]
    pub dashboard_url: String,

    #[serde(default)]
    pub local_agent_id: Option<String>,

    #[serde(default)]
    pub integrations: IntegrationSettings,

    #[serde(default)]
    pub runtime_registry: RuntimeRegistrySettings,

    #[serde(default)]
    pub control_api: ControlApiSettings,

    #[serde(default)]
    pub local_api_security: LocalApiSecuritySettings,

    #[serde(default = "default_ota_enabled")]
    pub ota_enabled: bool,

    #[serde(default = "default_ota_mode")]
    pub ota_mode: String,

    #[serde(default = "default_ota_channel")]
    pub ota_channel: String,

    #[serde(default)]
    pub ota_manifest_url: Option<String>,

    #[serde(default)]
    pub ota_allow_fallback_to_default: bool,

    #[serde(default = "default_ota_check_interval_minutes")]
    pub ota_check_interval_minutes: u32,

    #[serde(default)]
    pub ota_pinned_public_keys: Vec<String>,

    #[serde(default)]
    pub ota_last_check_at: Option<String>,

    #[serde(default)]
    pub ota_last_result: Option<String>,

    #[serde(default)]
    pub ota_current_hushd_version: Option<String>,

    #[serde(default)]
    pub nats: NatsSettings,

    #[serde(default)]
    pub enrollment: EnrollmentState,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            settings_path_override: None,
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
            brokerd: BrokerdSettings::default(),
            openclaw: OpenClawSettings::default(),
            dashboard_url: default_dashboard_url(),
            local_agent_id: None,
            integrations: IntegrationSettings::default(),
            runtime_registry: RuntimeRegistrySettings::default(),
            control_api: ControlApiSettings::default(),
            local_api_security: LocalApiSecuritySettings::default(),
            ota_enabled: default_ota_enabled(),
            ota_mode: default_ota_mode(),
            ota_channel: default_ota_channel(),
            ota_manifest_url: None,
            ota_allow_fallback_to_default: false,
            ota_check_interval_minutes: default_ota_check_interval_minutes(),
            ota_pinned_public_keys: Vec::new(),
            ota_last_check_at: None,
            ota_last_result: None,
            ota_current_hushd_version: None,
            nats: NatsSettings::default(),
            enrollment: EnrollmentState::default(),
        }
    }
}

impl Settings {
    pub fn load() -> Result<Self> {
        let path = get_settings_path();

        if path.exists() {
            let contents = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read settings from {:?}", path))?;
            let settings_json: serde_json::Value =
                serde_json::from_str(&contents).context("Failed to parse settings JSON")?;
            let mut settings: Settings = serde_json::from_value(settings_json.clone())
                .context("Failed to parse settings JSON")?;
            let dashboard_url_present = settings_json
                .as_object()
                .map(|obj| obj.contains_key("dashboard_url"))
                .unwrap_or(false);
            backfill_dashboard_url_if_missing(&mut settings, dashboard_url_present);
            Ok(settings)
        } else {
            let settings = Settings::default();
            settings.save()?;
            Ok(settings)
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = self
            .settings_path_override
            .clone()
            .unwrap_or_else(get_settings_path);

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory {:?}", parent))?;
        }

        let contents =
            serde_json::to_string_pretty(self).context("Failed to serialize settings")?;
        write_settings_file(&path, &contents)?;

        Ok(())
    }

    pub fn daemon_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.daemon_port)
    }
}

pub(super) fn backfill_dashboard_url_if_missing(
    settings: &mut Settings,
    dashboard_url_present: bool,
) {
    if !dashboard_url_present || settings.dashboard_url.trim().is_empty() {
        settings.dashboard_url = default_dashboard_url_for_port(settings.agent_api_port);
    }
}
