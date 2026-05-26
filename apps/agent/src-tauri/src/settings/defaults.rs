//! Default values for fields with `#[serde(default = "...")]` annotations.

use super::paths::get_config_dir;
use std::path::PathBuf;

pub(super) fn default_policy_path() -> PathBuf {
    get_config_dir().join("policy.yaml")
}

pub(super) fn default_require_signed_approval_responses() -> bool {
    true
}

pub(super) fn default_daemon_port() -> u16 {
    9876
}

pub(super) fn default_mcp_port() -> u16 {
    9877
}

pub(super) fn default_agent_api_port() -> u16 {
    9878
}

pub(super) fn default_local_api_token_rotation_interval_hours() -> u32 {
    168
}

pub(super) fn default_local_api_token_grace_minutes() -> u32 {
    15
}

pub(super) fn default_local_api_mtls_port() -> u16 {
    9880
}

pub(super) fn default_broker_port() -> u16 {
    9889
}

pub(super) fn default_enabled() -> bool {
    true
}

pub(super) fn default_auto_start() -> bool {
    true
}

pub(super) fn default_notifications_enabled() -> bool {
    true
}

pub(super) fn default_notification_severity() -> String {
    "block".to_string()
}

pub(super) fn default_dashboard_url() -> String {
    default_dashboard_url_for_port(default_agent_api_port())
}

pub(super) fn default_dashboard_url_for_port(agent_api_port: u16) -> String {
    format!("http://127.0.0.1:{}/ui", agent_api_port)
}

pub(super) fn default_broker_secret_backend_kind() -> String {
    "file".to_string()
}

pub(super) fn default_broker_secret_file_path() -> PathBuf {
    get_config_dir().join("broker-secrets.json")
}

pub(super) fn default_broker_secret_env_prefix() -> String {
    "CLAWDSTRIKE_SECRET_".to_string()
}

pub(super) fn default_broker_secret_http_path_prefix() -> String {
    "/v1/secrets".to_string()
}

pub(super) fn default_ota_enabled() -> bool {
    true
}

pub(super) fn default_ota_mode() -> String {
    "auto".to_string()
}

pub(super) fn default_ota_channel() -> String {
    "stable".to_string()
}

pub(super) fn default_ota_check_interval_minutes() -> u32 {
    360
}
