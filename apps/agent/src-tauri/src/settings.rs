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

/// SIEM integration settings configured from the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemIntegrationSettings {
    #[serde(default = "default_siem_provider")]
    pub provider: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub enabled: bool,
}

impl Default for SiemIntegrationSettings {
    fn default() -> Self {
        Self {
            provider: default_siem_provider(),
            endpoint: String::new(),
            api_key: String::new(),
            enabled: false,
        }
    }
}

fn default_siem_provider() -> String {
    "datadog".to_string()
}

/// Webhook integration settings configured from the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WebhookIntegrationSettings {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub enabled: bool,
}

/// Integration settings configured from dashboard pages.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntegrationSettings {
    #[serde(default)]
    pub siem: SiemIntegrationSettings,
    #[serde(default)]
    pub webhooks: WebhookIntegrationSettings,
}

/// NATS connectivity settings for enterprise cloud management.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatsSettings {
    /// Whether NATS enterprise connectivity is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// NATS server URL (e.g., "nats://nats.example.com:4222").
    #[serde(default)]
    pub nats_url: Option<String>,
    /// Path to a `.creds` file for NATS authentication.
    #[serde(default)]
    pub creds_file: Option<String>,
    /// Bearer token for NATS authentication.
    #[serde(default)]
    pub token: Option<String>,
    /// NKey seed for NATS authentication.
    #[serde(default)]
    pub nkey_seed: Option<String>,
    /// Tenant identifier for NATS subject namespacing.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Agent identifier for NATS subject namespacing.
    #[serde(default)]
    pub agent_id: Option<String>,
    /// NATS account identifier assigned during enrollment.
    #[serde(default)]
    pub nats_account: Option<String>,
    /// Subject prefix for NATS topics assigned during enrollment.
    #[serde(default)]
    pub subject_prefix: Option<String>,
    /// Whether approval responses must be Spine-signed envelopes.
    #[serde(default = "default_require_signed_approval_responses")]
    pub require_signed_approval_responses: bool,
    /// Trusted Spine issuer for approval responses from cloud.
    #[serde(default)]
    pub approval_response_trusted_issuer: Option<String>,
}

impl Default for NatsSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            nats_url: None,
            creds_file: None,
            token: None,
            nkey_seed: None,
            tenant_id: None,
            agent_id: None,
            nats_account: None,
            subject_prefix: None,
            require_signed_approval_responses: default_require_signed_approval_responses(),
            approval_response_trusted_issuer: None,
        }
    }
}

/// Enrollment state for cloud-managed agents.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnrollmentState {
    /// Whether the agent has completed enrollment.
    #[serde(default)]
    pub enrolled: bool,
    /// Server-assigned agent UUID from the Control API.
    #[serde(default)]
    pub agent_uuid: Option<String>,
    /// Tenant ID assigned during enrollment.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Flag indicating enrollment is currently in progress (for crash recovery).
    #[serde(default)]
    pub enrollment_in_progress: bool,
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

    /// URL for the local web dashboard.
    #[serde(default = "default_dashboard_url")]
    pub dashboard_url: String,

    /// Integration settings synchronized from the local dashboard.
    #[serde(default)]
    pub integrations: IntegrationSettings,

    /// Enable automatic hushd OTA checks and updates.
    #[serde(default = "default_ota_enabled")]
    pub ota_enabled: bool,

    /// OTA behavior mode: "auto" or "manual".
    #[serde(default = "default_ota_mode")]
    pub ota_mode: String,

    /// OTA release channel ("stable" or "beta").
    #[serde(default = "default_ota_channel")]
    pub ota_channel: String,

    /// Optional override URL for signed OTA manifest.
    #[serde(default)]
    pub ota_manifest_url: Option<String>,

    /// Whether manifest override is allowed to fall back to default URL.
    #[serde(default)]
    pub ota_allow_fallback_to_default: bool,

    /// Periodic OTA check interval in minutes.
    #[serde(default = "default_ota_check_interval_minutes")]
    pub ota_check_interval_minutes: u32,

    /// Additional trusted OTA signer keys (hex-encoded Ed25519 public keys).
    #[serde(default)]
    pub ota_pinned_public_keys: Vec<String>,

    /// RFC3339 timestamp of the last OTA check attempt.
    #[serde(default)]
    pub ota_last_check_at: Option<String>,

    /// Human-readable summary of the last OTA action result.
    #[serde(default)]
    pub ota_last_result: Option<String>,

    /// Current hushd version observed/applied by OTA.
    #[serde(default)]
    pub ota_current_hushd_version: Option<String>,

    /// NATS enterprise connectivity settings.
    #[serde(default)]
    pub nats: NatsSettings,

    /// Enrollment state for cloud-managed agents.
    #[serde(default)]
    pub enrollment: EnrollmentState,
}

fn default_policy_path() -> PathBuf {
    get_config_dir().join("policy.yaml")
}

fn default_require_signed_approval_responses() -> bool {
    true
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

fn default_dashboard_url() -> String {
    default_dashboard_url_for_port(default_agent_api_port())
}

fn default_dashboard_url_for_port(agent_api_port: u16) -> String {
    format!("http://127.0.0.1:{}/ui", agent_api_port)
}

fn default_ota_enabled() -> bool {
    true
}

fn default_ota_mode() -> String {
    "auto".to_string()
}

fn default_ota_channel() -> String {
    "stable".to_string()
}

fn default_ota_check_interval_minutes() -> u32 {
    360
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
            dashboard_url: default_dashboard_url(),
            integrations: IntegrationSettings::default(),
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
    /// Load settings from disk, or create defaults if not found.
    pub fn load() -> Result<Self> {
        let path = get_settings_path();

        if path.exists() {
            let contents = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read settings from {:?}", path))?;
            let settings_json: serde_json::Value =
                serde_json::from_str(&contents).with_context(|| "Failed to parse settings JSON")?;
            let mut settings: Settings = serde_json::from_value(settings_json.clone())
                .with_context(|| "Failed to parse settings JSON")?;
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

    /// Save settings to disk.
    pub fn save(&self) -> Result<()> {
        let path = get_settings_path();

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory {:?}", parent))?;
        }

        let contents =
            serde_json::to_string_pretty(self).with_context(|| "Failed to serialize settings")?;
        write_settings_file(&path, &contents)?;

        Ok(())
    }

    /// Get the daemon URL based on current settings.
    pub fn daemon_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.daemon_port)
    }
}

fn backfill_dashboard_url_if_missing(settings: &mut Settings, dashboard_url_present: bool) {
    if !dashboard_url_present || settings.dashboard_url.trim().is_empty() {
        settings.dashboard_url = default_dashboard_url_for_port(settings.agent_api_port);
    }
}

fn write_settings_file(path: &PathBuf, contents: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("Failed to create settings file {:?}", path))?;
        file.write_all(contents.as_bytes())
            .with_context(|| format!("Failed to write settings to {:?}", path))?;
        enforce_private_mode(path, "settings file")?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
            .with_context(|| format!("Failed to write settings to {:?}", path))?;
    }

    Ok(())
}

#[cfg(unix)]
pub(crate) fn enforce_private_mode(path: &std::path::Path, target: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::metadata(path)
        .with_context(|| format!("Failed to read {target} metadata {:?}", path))?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("Failed to set {target} permissions on {:?}", path))?;
    }
    Ok(())
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

/// Best-effort hostname retrieval via `libc::gethostname`.
pub fn hostname_best_effort() -> String {
    #[cfg(unix)]
    {
        let mut buf = vec![0u8; 256];
        let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut _, buf.len()) };
        if ret == 0 {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            buf.truncate(end);
            return String::from_utf8_lossy(&buf).into_owned();
        }
    }
    "unknown".to_string()
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
        assert!(settings.ota_enabled);
        assert_eq!(settings.ota_mode, "auto");
        assert_eq!(settings.ota_channel, "stable");
        assert_eq!(settings.ota_check_interval_minutes, 360);
        assert_eq!(settings.integrations.siem.provider, "datadog");
        assert!(!settings.integrations.siem.enabled);
        assert!(!settings.integrations.webhooks.enabled);
    }

    #[test]
    fn backfills_dashboard_url_from_loaded_agent_port_when_missing() {
        let mut settings = Settings::default();
        settings.agent_api_port = 21111;
        settings.dashboard_url = String::new();

        backfill_dashboard_url_if_missing(&mut settings, false);

        assert_eq!(settings.dashboard_url, "http://127.0.0.1:21111/ui");
    }

    #[test]
    fn preserves_dashboard_url_when_explicitly_present() {
        let mut settings = Settings::default();
        settings.agent_api_port = 21111;
        settings.dashboard_url = "http://localhost:3100".to_string();

        backfill_dashboard_url_if_missing(&mut settings, true);

        assert_eq!(settings.dashboard_url, "http://localhost:3100");
    }

    #[test]
    fn test_daemon_url() {
        let settings = Settings::default();
        assert_eq!(settings.daemon_url(), "http://127.0.0.1:9876");
        assert_eq!(settings.agent_api_port, 9878);
    }

    #[cfg(unix)]
    #[test]
    fn write_settings_file_uses_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let unique = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => duration.as_nanos(),
            Err(_) => 0,
        };
        let dir = std::env::temp_dir().join(format!("clawdstrike-settings-perms-{unique}"));
        if let Err(err) = std::fs::create_dir_all(&dir) {
            panic!("failed to create temp dir for settings permissions test: {err}");
        }
        let path = dir.join("agent.json");

        if let Err(err) = write_settings_file(&path, "{\"nats\":{\"token\":\"secret\"}}") {
            panic!("failed to write settings file: {err}");
        }

        let metadata = match std::fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) => panic!("failed to read settings metadata: {err}"),
        };
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_settings_file_hardens_existing_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let unique = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => duration.as_nanos(),
            Err(_) => 0,
        };
        let dir = std::env::temp_dir().join(format!("clawdstrike-settings-perms-existing-{unique}"));
        if let Err(err) = std::fs::create_dir_all(&dir) {
            panic!("failed to create temp dir for settings permissions test: {err}");
        }
        let path = dir.join("agent.json");
        if let Err(err) = std::fs::write(&path, "{}") {
            panic!("failed to seed settings file: {err}");
        }
        if let Err(err) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)) {
            panic!("failed to seed settings file mode: {err}");
        }

        if let Err(err) = write_settings_file(&path, "{\"nats\":{\"token\":\"secret\"}}") {
            panic!("failed to write settings file: {err}");
        }

        let metadata = match std::fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) => panic!("failed to read settings metadata: {err}"),
        };
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }
}
