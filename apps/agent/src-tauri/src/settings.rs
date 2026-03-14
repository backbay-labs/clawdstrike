//! Settings management for Clawdstrike Agent.
//!
//! Persistent configuration stored in ~/.config/clawdstrike/agent.json.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenClawGatewayMetadata {
    pub id: String,
    pub label: String,
    pub gateway_url: String,
    #[serde(default)]
    pub pinned_ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OpenClawSettings {
    #[serde(default)]
    pub gateways: Vec<OpenClawGatewayMetadata>,
    #[serde(default)]
    pub active_gateway_id: Option<String>,
}

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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WebhookIntegrationSettings {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntegrationSettings {
    #[serde(default)]
    pub siem: SiemIntegrationSettings,
    #[serde(default)]
    pub webhooks: WebhookIntegrationSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeAgentRegistration {
    pub runtime_agent_id: String,
    pub runtime_agent_kind: String,
    pub endpoint_agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_runtime_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub first_seen_at: String,
    pub last_seen_at: String,
    #[serde(default)]
    pub policy_event_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeRegistrySettings {
    #[serde(default)]
    pub runtimes: Vec<RuntimeAgentRegistration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalApiSecuritySettings {
    #[serde(default = "default_local_api_token_rotation_interval_hours")]
    pub token_rotation_interval_hours: u32,
    #[serde(default = "default_local_api_token_grace_minutes")]
    pub token_grace_minutes: u32,
    #[serde(default)]
    pub mtls_enabled: bool,
    #[serde(default = "default_local_api_mtls_port")]
    pub mtls_port: u16,
    #[serde(default)]
    pub mtls_server_cert_path: Option<PathBuf>,
    #[serde(default)]
    pub mtls_server_key_path: Option<PathBuf>,
    #[serde(default)]
    pub mtls_client_ca_path: Option<PathBuf>,
}

impl Default for LocalApiSecuritySettings {
    fn default() -> Self {
        Self {
            token_rotation_interval_hours: default_local_api_token_rotation_interval_hours(),
            token_grace_minutes: default_local_api_token_grace_minutes(),
            mtls_enabled: false,
            mtls_port: default_local_api_mtls_port(),
            mtls_server_cert_path: None,
            mtls_server_key_path: None,
            mtls_client_ca_path: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatsSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub nats_url: Option<String>,
    #[serde(default)]
    pub creds_file: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub nkey_seed: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub nats_account: Option<String>,
    #[serde(default)]
    pub subject_prefix: Option<String>,
    #[serde(default = "default_require_signed_approval_responses")]
    pub require_signed_approval_responses: bool,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnrollmentState {
    #[serde(default)]
    pub enrolled: bool,
    #[serde(default)]
    pub agent_uuid: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub enrollment_in_progress: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerdSecretBackendSettings {
    #[serde(default = "default_broker_secret_backend_kind")]
    pub kind: String,
    #[serde(default = "default_broker_secret_file_path")]
    pub file_path: PathBuf,
    #[serde(default = "default_broker_secret_env_prefix")]
    pub env_prefix: String,
    #[serde(default)]
    pub http_base_url: Option<String>,
    #[serde(default)]
    pub http_bearer_token: Option<String>,
    #[serde(default = "default_broker_secret_http_path_prefix")]
    pub http_path_prefix: String,
}

impl Default for BrokerdSecretBackendSettings {
    fn default() -> Self {
        Self {
            kind: default_broker_secret_backend_kind(),
            file_path: default_broker_secret_file_path(),
            env_prefix: default_broker_secret_env_prefix(),
            http_base_url: None,
            http_bearer_token: None,
            http_path_prefix: default_broker_secret_http_path_prefix(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerdSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_broker_port")]
    pub port: u16,
    #[serde(default)]
    pub binary_path: Option<PathBuf>,
    #[serde(default)]
    pub allow_http_loopback: bool,
    #[serde(default)]
    pub allow_private_upstream_hosts: bool,
    #[serde(default)]
    pub allow_invalid_upstream_tls: bool,
    #[serde(default)]
    pub secret_backend: BrokerdSecretBackendSettings,
    /// Optional bearer token required for admin and mutation endpoints on
    /// the local brokerd instance.  When absent, brokerd skips auth.
    #[serde(default)]
    pub admin_token: Option<String>,
}

impl Default for BrokerdSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            port: default_broker_port(),
            binary_path: None,
            allow_http_loopback: false,
            allow_private_upstream_hosts: false,
            allow_invalid_upstream_tls: false,
            secret_backend: BrokerdSecretBackendSettings::default(),
            admin_token: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
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

fn default_local_api_token_rotation_interval_hours() -> u32 {
    168
}

fn default_local_api_token_grace_minutes() -> u32 {
    15
}

fn default_local_api_mtls_port() -> u16 {
    9880
}

fn default_broker_port() -> u16 {
    9889
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

fn default_broker_secret_backend_kind() -> String {
    "file".to_string()
}

fn default_broker_secret_file_path() -> PathBuf {
    get_config_dir().join("broker-secrets.json")
}

fn default_broker_secret_env_prefix() -> String {
    "CLAWDSTRIKE_SECRET_".to_string()
}

fn default_broker_secret_http_path_prefix() -> String {
    "/v1/secrets".to_string()
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
            brokerd: BrokerdSettings::default(),
            openclaw: OpenClawSettings::default(),
            dashboard_url: default_dashboard_url(),
            local_agent_id: None,
            integrations: IntegrationSettings::default(),
            runtime_registry: RuntimeRegistrySettings::default(),
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
        let path = get_settings_path();

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

fn backfill_dashboard_url_if_missing(settings: &mut Settings, dashboard_url_present: bool) {
    if !dashboard_url_present || settings.dashboard_url.trim().is_empty() {
        settings.dashboard_url = default_dashboard_url_for_port(settings.agent_api_port);
    }
}

fn write_settings_file(path: &std::path::Path, contents: &str) -> Result<()> {
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

pub fn get_config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("clawdstrike")
}

pub fn get_settings_path() -> PathBuf {
    get_config_dir().join("agent.json")
}

pub fn get_agent_token_path() -> PathBuf {
    get_config_dir().join("agent-local-token")
}

pub fn hostname_best_effort() -> String {
    hostname::get()
        .ok()
        .and_then(|value| value.into_string().ok())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

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
        let mut settings = Settings {
            agent_api_port: 21111,
            dashboard_url: String::new(),
            ..Settings::default()
        };

        backfill_dashboard_url_if_missing(&mut settings, false);

        assert_eq!(settings.dashboard_url, "http://127.0.0.1:21111/ui");
    }

    #[test]
    fn preserves_dashboard_url_when_explicitly_present() {
        let mut settings = Settings {
            agent_api_port: 21111,
            dashboard_url: "http://localhost:3100".to_string(),
            ..Settings::default()
        };

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
        let dir =
            std::env::temp_dir().join(format!("clawdstrike-settings-perms-existing-{unique}"));
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
