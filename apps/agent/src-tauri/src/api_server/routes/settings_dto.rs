//! Request/response DTOs for the agent settings and integrations endpoints.

use super::super::*;
use crate::daemon::DaemonStatus;
use crate::macos::status::CombinedSystemExtensionStatus;
use crate::settings::IntegrationSettings;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize)]
pub(crate) struct AgentHealthResponse {
    pub(crate) status: &'static str,
    pub(crate) daemon: DaemonStatus,
    pub(crate) session: crate::session::SessionState,
    pub(crate) macos_host: CombinedSystemExtensionStatus,
    pub(crate) edr: EdrHealthSummary,
    pub(crate) openclaw: serde_json::Value,
    pub(crate) runtime_agents: usize,
    pub(crate) last_policy_version: Option<String>,
    pub(crate) endpoint_agent_id: String,
    pub(crate) last_heartbeat_at: Option<String>,
    pub(crate) heartbeat_age_secs: Option<i64>,
    pub(crate) endpoint_online: Option<bool>,
    pub(crate) policy_drift: Option<bool>,
    pub(crate) daemon_drift: Option<bool>,
    pub(crate) stale: Option<bool>,
    pub(crate) version: &'static str,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DaemonAgentStatusResponse {
    pub(crate) endpoints: Vec<DaemonEndpointStatus>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DaemonEndpointStatus {
    #[serde(default)]
    pub(crate) last_heartbeat_at: Option<String>,
    #[serde(default)]
    pub(crate) seconds_since_heartbeat: Option<i64>,
    #[serde(default)]
    pub(crate) online: Option<bool>,
    #[serde(default)]
    pub(crate) drift: Option<DaemonEndpointDrift>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DaemonEndpointDrift {
    #[serde(default)]
    pub(crate) policy_drift: Option<bool>,
    #[serde(default)]
    pub(crate) daemon_drift: Option<bool>,
    #[serde(default)]
    pub(crate) stale: Option<bool>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AgentSettingsResponse {
    pub(crate) daemon_port: u16,
    pub(crate) mcp_port: u16,
    pub(crate) agent_api_port: u16,
    pub(crate) enabled: bool,
    pub(crate) auto_start: bool,
    pub(crate) notifications_enabled: bool,
    pub(crate) notification_severity: String,
    pub(crate) dashboard_url: String,
    pub(crate) debug_include_daemon_error_body: bool,
    pub(crate) openclaw_active_gateway_id: Option<String>,
    pub(crate) ota_enabled: bool,
    pub(crate) ota_mode: String,
    pub(crate) ota_channel: String,
    pub(crate) ota_manifest_url: Option<String>,
    pub(crate) ota_allow_fallback_to_default: bool,
    pub(crate) ota_check_interval_minutes: u32,
    pub(crate) ota_pinned_public_keys: Vec<String>,
    pub(crate) ota_last_check_at: Option<String>,
    pub(crate) ota_last_result: Option<String>,
    pub(crate) ota_current_hushd_version: Option<String>,
    pub(crate) control_api: ControlApiSettingsResponse,
    pub(crate) local_api_security: LocalApiSecurityResponse,
}

#[derive(Debug, Serialize)]
pub(crate) struct ControlApiSettingsResponse {
    pub(crate) enabled: bool,
    pub(crate) url: Option<String>,
    pub(crate) api_key_configured: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct LocalApiSecurityResponse {
    pub(crate) token_rotation_interval_hours: u32,
    pub(crate) token_grace_minutes: u32,
    pub(crate) mtls_enabled: bool,
    pub(crate) mtls_port: u16,
    pub(crate) mtls_server_cert_path: Option<String>,
    pub(crate) mtls_server_key_path: Option<String>,
    pub(crate) mtls_client_ca_path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RuntimeRegisterInput {
    pub(crate) runtime_agent_kind: String,
    #[serde(default)]
    pub(crate) runtime_agent_id: Option<String>,
    #[serde(default)]
    pub(crate) endpoint_agent_id: Option<String>,
    #[serde(default)]
    pub(crate) display_name: Option<String>,
    #[serde(default)]
    pub(crate) metadata: Option<Value>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RuntimeRegisterResponse {
    pub(crate) endpoint_agent_id: String,
    pub(crate) runtime_agent_id: String,
    pub(crate) runtime_agent_kind: String,
    pub(crate) external_runtime_id: Option<String>,
    pub(crate) first_seen_at: String,
    pub(crate) last_seen_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentSettingsUpdate {
    pub(crate) enabled: Option<bool>,
    pub(crate) auto_start: Option<bool>,
    pub(crate) notifications_enabled: Option<bool>,
    pub(crate) notification_severity: Option<String>,
    pub(crate) dashboard_url: Option<String>,
    pub(crate) debug_include_daemon_error_body: Option<bool>,
    pub(crate) ota_enabled: Option<bool>,
    pub(crate) ota_mode: Option<String>,
    pub(crate) ota_channel: Option<String>,
    pub(crate) ota_manifest_url: Option<Option<String>>,
    pub(crate) ota_allow_fallback_to_default: Option<bool>,
    pub(crate) ota_check_interval_minutes: Option<u32>,
    pub(crate) ota_pinned_public_keys: Option<Vec<String>>,
    pub(crate) ota_last_check_at: Option<Option<String>>,
    pub(crate) ota_last_result: Option<Option<String>>,
    pub(crate) ota_current_hushd_version: Option<Option<String>>,
    pub(crate) control_api: Option<ControlApiSettingsUpdate>,
    #[serde(default, deserialize_with = "deserialize_optional_string_field")]
    pub(crate) openclaw_active_gateway_id: Option<Option<String>>,
    pub(crate) local_api_security: Option<LocalApiSecurityUpdate>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ControlApiSettingsUpdate {
    pub(crate) enabled: Option<bool>,
    pub(crate) url: Option<Option<String>>,
    pub(crate) api_key: Option<Option<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalApiSecurityUpdate {
    pub(crate) token_rotation_interval_hours: Option<u32>,
    pub(crate) token_grace_minutes: Option<u32>,
    pub(crate) mtls_enabled: Option<bool>,
    pub(crate) mtls_port: Option<u16>,
    pub(crate) mtls_server_cert_path: Option<Option<String>>,
    pub(crate) mtls_server_key_path: Option<Option<String>>,
    pub(crate) mtls_client_ca_path: Option<Option<String>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GatewayPatchInput {
    pub(crate) label: Option<String>,
    pub(crate) gateway_url: Option<String>,
    pub(crate) token: Option<String>,
    pub(crate) device_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ActiveGatewayUpdateInput {
    pub(crate) active_gateway_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct IntegrationsSettingsUpdateInput {
    #[serde(default)]
    pub(crate) siem: Option<SiemIntegrationUpdateInput>,
    #[serde(default)]
    pub(crate) webhooks: Option<WebhookIntegrationUpdateInput>,
    #[serde(default = "default_apply_integrations_changes")]
    pub(crate) apply: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SiemIntegrationUpdateInput {
    pub(crate) provider: Option<String>,
    pub(crate) endpoint: Option<String>,
    pub(crate) api_key: Option<String>,
    pub(crate) enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct WebhookIntegrationUpdateInput {
    pub(crate) url: Option<String>,
    pub(crate) secret: Option<String>,
    pub(crate) enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub(crate) struct IntegrationsApplyResponse {
    pub(crate) integrations: IntegrationSettings,
    pub(crate) restarted: bool,
    pub(crate) daemon: DaemonStatus,
    pub(crate) exporter_status: Option<Value>,
    pub(crate) warning: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct IntegrationTestInput {
    pub(crate) target: String,
    #[serde(default)]
    pub(crate) max_retries: Option<u8>,
}

#[derive(Debug, Serialize)]
pub(crate) struct IntegrationTestResponse {
    pub(crate) target: String,
    pub(crate) endpoint: String,
    pub(crate) delivered: bool,
    pub(crate) status_code: Option<u16>,
    pub(crate) attempts: u8,
    pub(crate) retry_count: u8,
    pub(crate) latency_ms: u64,
    pub(crate) last_error: Option<String>,
    pub(crate) tested_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct RotateLocalApiTokenResponse {
    pub(crate) rotated: bool,
    pub(crate) previous_token_valid_for_seconds: u64,
}

#[derive(Debug, Deserialize, Default)]
pub(crate) struct DiagnosticsBundleInput {
    #[serde(default)]
    pub(crate) include_logs: Option<bool>,
    #[serde(default)]
    pub(crate) log_lines: Option<usize>,
}

#[derive(Debug, Serialize)]
pub(crate) struct DiagnosticsBundleResponse {
    pub(crate) bundle_path: String,
    pub(crate) generated_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct AgentPolicyCheckResponse {
    #[serde(flatten)]
    pub(crate) decision: crate::policy::PolicyCheckOutput,
    pub(crate) receipt: hush_core::SignedReceipt,
}
