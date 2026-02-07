//! Configuration for clawdstriked daemon

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::auth::{ApiKey, AuthStore, Scope};
use crate::siem::dlq::DeadLetterQueueConfig;
use crate::siem::exporter::ExporterConfig as SiemExporterConfig;
use crate::siem::exporters::alerting::AlertingConfig;
use crate::siem::exporters::datadog::DatadogConfig;
use crate::siem::exporters::elastic::ElasticConfig;
use crate::siem::exporters::splunk::SplunkConfig;
use crate::siem::exporters::sumo_logic::SumoLogicConfig;
use crate::siem::exporters::webhooks::WebhookExporterConfig;
use crate::siem::filter::EventFilter;
use crate::siem::threat_intel::config::ThreatIntelConfig;

pub(crate) fn expand_env_refs(value: &str) -> anyhow::Result<String> {
    let mut out = String::new();
    let mut rest = value;

    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| anyhow::anyhow!("Unclosed env var reference in value: {}", value))?;
        let name = &after[..end];
        if name.is_empty() {
            return Err(anyhow::anyhow!(
                "Empty env var reference in value: {}",
                value
            ));
        }
        let resolved = std::env::var(name)
            .map_err(|_| anyhow::anyhow!("Missing environment variable: {}", name))?;
        out.push_str(&resolved);
        rest = &after[end + 1..];
    }

    out.push_str(rest);
    Ok(out)
}

fn expand_secret_ref(value: &str) -> anyhow::Result<String> {
    let expanded = expand_env_refs(value)?;
    let expanded = expanded.trim().to_string();

    let path = if let Some(rest) = expanded.strip_prefix("file:") {
        rest.trim()
    } else if let Some(rest) = expanded.strip_prefix('@') {
        rest.trim()
    } else {
        return Ok(expanded);
    };

    let bytes = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("Failed to read secret file {}: {e}", path))?;
    let s = String::from_utf8(bytes)
        .map_err(|e| anyhow::anyhow!("Secret file {} is not valid UTF-8: {e}", path))?;
    Ok(s.trim().to_string())
}

/// TLS configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Path to certificate file
    pub cert_path: PathBuf,
    /// Path to private key file
    pub key_path: PathBuf,
}

/// Configuration for a single API key
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiKeyConfig {
    /// Human-readable name for the key
    pub name: String,
    /// The actual API key (will be hashed, never stored plaintext)
    pub key: String,
    /// Scopes granted to this key (check, read, admin, *)
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Optional expiration time (ISO 8601 format)
    #[serde(default)]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Authentication configuration
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// Whether authentication is required for API endpoints
    #[serde(default)]
    pub enabled: bool,
    /// API keys
    #[serde(default)]
    pub api_keys: Vec<ApiKeyConfig>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    /// OIDC (JWT) identity configuration
    #[serde(default)]
    pub oidc: Option<OidcConfig>,
    /// Okta-specific configuration (optional)
    #[serde(default)]
    pub okta: Option<OktaConfig>,
    /// Auth0-specific configuration (optional)
    #[serde(default)]
    pub auth0: Option<Auth0Config>,
    /// SAML configuration (optional)
    #[serde(default)]
    pub saml: Option<SamlConfig>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OktaConfig {
    #[serde(default)]
    pub webhooks: Option<OktaWebhookConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OktaWebhookConfig {
    /// Shared secret token for verifying Okta event hooks (`Authorization: Bearer <token>`).
    pub verification_key: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Auth0Config {
    #[serde(default)]
    pub log_stream: Option<Auth0LogStreamConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Auth0LogStreamConfig {
    /// Shared bearer token for verifying Auth0 log stream webhooks (`Authorization: Bearer <token>`).
    pub authorization: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlConfig {
    /// Service Provider entity ID (audience)
    pub entity_id: String,
    /// IdP signing certificate (PEM), used to validate assertion signatures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idp_signing_cert_pem: Option<String>,
    /// Whether to validate assertion signature.
    ///
    /// When enabled, `idp_signing_cert_pem` must be set.
    #[serde(default)]
    pub validate_signature: bool,
    /// Whether to validate assertion conditions (NotBefore/NotOnOrAfter/AudienceRestriction).
    #[serde(default = "default_validate_saml_conditions")]
    pub validate_conditions: bool,
    /// Attribute mapping configuration
    #[serde(default)]
    pub attribute_mapping: SamlAttributeMapping,
    /// Maximum assertion age (seconds)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_assertion_age_secs: Option<u64>,
}

fn default_validate_saml_conditions() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAttributeMapping {
    /// Attribute name for user ID (defaults to NameID when unset)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub teams: Option<String>,
    #[serde(default)]
    pub additional_attributes: Vec<String>,
}

impl Default for SamlAttributeMapping {
    fn default() -> Self {
        Self {
            user_id: None,
            email: Some("email".to_string()),
            display_name: Some("displayName".to_string()),
            organization_id: None,
            roles: Some("roles".to_string()),
            teams: Some("teams".to_string()),
            additional_attributes: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RbacConfig {
    /// Whether RBAC is enabled for user principals.
    #[serde(default = "default_rbac_enabled")]
    pub enabled: bool,
    /// Mapping from identity groups/roles/teams to RBAC roles.
    #[serde(default)]
    pub group_mapping: GroupMappingConfig,
}

fn default_rbac_enabled() -> bool {
    true
}

impl Default for RbacConfig {
    fn default() -> Self {
        Self {
            enabled: default_rbac_enabled(),
            group_mapping: GroupMappingConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyScopingConfig {
    /// Whether identity-based policy scoping is enabled.
    #[serde(default = "default_policy_scoping_enabled")]
    pub enabled: bool,
    /// Engine cache settings (policy-hash -> compiled guards).
    #[serde(default)]
    pub cache: PolicyScopingCacheConfig,
    /// Escalation prevention settings (optional hardening).
    #[serde(default)]
    pub escalation_prevention: PolicyScopingEscalationPreventionConfig,
}

fn default_policy_scoping_enabled() -> bool {
    true
}

impl Default for PolicyScopingConfig {
    fn default() -> Self {
        Self {
            enabled: default_policy_scoping_enabled(),
            cache: PolicyScopingCacheConfig::default(),
            escalation_prevention: PolicyScopingEscalationPreventionConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyScopingCacheConfig {
    #[serde(default = "default_policy_scoping_cache_enabled")]
    pub enabled: bool,
    #[serde(default = "default_policy_scoping_cache_ttl_seconds")]
    pub ttl_seconds: u64,
    #[serde(default = "default_policy_scoping_cache_max_entries")]
    pub max_entries: usize,
}

fn default_policy_scoping_cache_enabled() -> bool {
    true
}

fn default_policy_scoping_cache_ttl_seconds() -> u64 {
    60
}

fn default_policy_scoping_cache_max_entries() -> usize {
    1000
}

impl Default for PolicyScopingCacheConfig {
    fn default() -> Self {
        Self {
            enabled: default_policy_scoping_cache_enabled(),
            ttl_seconds: default_policy_scoping_cache_ttl_seconds(),
            max_entries: default_policy_scoping_cache_max_entries(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyScopingEscalationPreventionConfig {
    /// Whether escalation prevention checks are enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Fields that scoped policies are not allowed to relax/override.
    #[serde(default)]
    pub locked_fields: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupMappingConfig {
    /// Direct mapping: identity group -> RBAC roles
    #[serde(default)]
    pub direct: std::collections::HashMap<String, Vec<String>>,
    /// Pattern mapping (glob/regex): group pattern -> RBAC roles
    #[serde(default)]
    pub patterns: Vec<GroupPattern>,
    /// Include all identity groups as roles (optionally prefixed)
    #[serde(default)]
    pub include_all_groups: bool,
    /// Prefix for auto-generated roles from identity groups
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_prefix: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupPattern {
    pub pattern: String,
    pub roles: Vec<String>,
    #[serde(default)]
    pub is_regex: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// OIDC issuer URL
    pub issuer: String,

    /// Expected audience (client ID)
    #[serde(deserialize_with = "deserialize_string_or_vec")]
    pub audience: Vec<String>,

    /// JWKS URI (auto-discovered if not provided)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    /// Clock tolerance for expiration checks (seconds)
    #[serde(default = "default_clock_tolerance_secs")]
    pub clock_tolerance_secs: u64,

    /// Maximum token age (seconds)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_secs: Option<u64>,

    /// Required claims (must exist and be non-empty)
    #[serde(default)]
    pub required_claims: Vec<String>,

    /// Claim mapping to Clawdstrike identity
    #[serde(default)]
    pub claim_mapping: OidcClaimMapping,

    /// JWKS cache TTL (seconds)
    #[serde(default = "default_jwks_cache_ttl_secs")]
    pub jwks_cache_ttl_secs: u64,

    /// Replay protection settings (OIDC `jti` tracking).
    #[serde(default)]
    pub replay_protection: OidcReplayProtectionConfig,
}

fn default_clock_tolerance_secs() -> u64 {
    30
}

fn default_jwks_cache_ttl_secs() -> u64 {
    3600
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcReplayProtectionConfig {
    /// Whether replay protection is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Whether `jti` is required when replay protection is enabled.
    #[serde(default)]
    pub require_jti: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcClaimMapping {
    /// Claim for user ID (default: "sub")
    #[serde(default = "default_claim_sub")]
    pub user_id: String,

    /// Claim for email (default: "email")
    #[serde(default = "default_claim_email")]
    pub email: String,

    /// Claim for display name (default: "name")
    #[serde(default = "default_claim_name")]
    pub display_name: String,

    /// Claim for organization ID
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,

    /// Claim for roles (default: "roles")
    #[serde(default = "default_claim_roles")]
    pub roles: String,

    /// Claim for teams
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub teams: Option<String>,

    /// Additional claims to extract
    #[serde(default)]
    pub additional_claims: Vec<String>,
}

fn default_claim_sub() -> String {
    "sub".to_string()
}

fn default_claim_email() -> String {
    "email".to_string()
}

fn default_claim_name() -> String {
    "name".to_string()
}

fn default_claim_roles() -> String {
    "roles".to_string()
}

impl Default for OidcClaimMapping {
    fn default() -> Self {
        Self {
            user_id: default_claim_sub(),
            email: default_claim_email(),
            display_name: default_claim_name(),
            organization_id: None,
            roles: default_claim_roles(),
            teams: None,
            additional_claims: Vec::new(),
        }
    }
}

fn deserialize_string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrVec {
        String(String),
        Vec(Vec<String>),
    }

    match StringOrVec::deserialize(deserializer)? {
        StringOrVec::String(value) => Ok(vec![value]),
        StringOrVec::Vec(values) => Ok(values),
    }
}

/// Rate limiting configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Whether rate limiting is enabled
    #[serde(default = "default_rate_limit_enabled")]
    pub enabled: bool,
    /// Maximum requests per second per IP
    #[serde(default = "default_requests_per_second")]
    pub requests_per_second: u32,
    /// Burst size (number of requests allowed in a burst)
    #[serde(default = "default_burst_size")]
    pub burst_size: u32,
    /// Trusted proxy IP addresses (X-Forwarded-For only trusted from these)
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Whether to trust X-Forwarded-For from any source (INSECURE - use trusted_proxies instead)
    #[serde(default)]
    pub trust_xff_from_any: bool,

    /// Identity-based rate limiting for authenticated users.
    #[serde(default)]
    pub identity: IdentityRateLimitConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityRateLimitConfig {
    /// Whether identity-based rate limiting is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Sliding window size (seconds).
    #[serde(default = "default_identity_rate_window_secs")]
    pub window_secs: u64,
    /// Max requests per window per user (0 = unlimited).
    #[serde(default = "default_identity_rate_max_user")]
    pub max_requests_per_window_user: u32,
    /// Max requests per window per org (0 = unlimited).
    #[serde(default = "default_identity_rate_max_org")]
    pub max_requests_per_window_org: u32,
    /// Check action types this limiter applies to. Empty = all check actions.
    #[serde(default)]
    pub apply_to_actions: Vec<String>,
}

fn default_identity_rate_window_secs() -> u64 {
    3600
}

fn default_identity_rate_max_user() -> u32 {
    1000
}

fn default_identity_rate_max_org() -> u32 {
    10_000
}

impl Default for IdentityRateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            window_secs: default_identity_rate_window_secs(),
            max_requests_per_window_user: default_identity_rate_max_user(),
            max_requests_per_window_org: default_identity_rate_max_org(),
            apply_to_actions: vec!["shell".to_string()],
        }
    }
}

fn default_rate_limit_enabled() -> bool {
    true
}

fn default_requests_per_second() -> u32 {
    100
}

fn default_burst_size() -> u32 {
    50
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: default_rate_limit_enabled(),
            requests_per_second: default_requests_per_second(),
            burst_size: default_burst_size(),
            trusted_proxies: Vec::new(),
            trust_xff_from_any: false,
            identity: IdentityRateLimitConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionHardeningConfig {
    /// Rotate (terminate) existing user sessions when creating a new session.
    #[serde(default)]
    pub rotate_on_create: bool,
    /// Bind sessions to a user-agent hash.
    #[serde(default)]
    pub bind_user_agent: bool,
    /// Bind sessions to the source IP.
    #[serde(default)]
    pub bind_source_ip: bool,
    /// Bind sessions to request geo country (requires `request.geo_location.country`).
    #[serde(default)]
    pub bind_country: bool,
}

fn default_remote_max_fetch_bytes() -> usize {
    1_048_576 // 1 MiB
}

fn default_remote_max_cache_bytes() -> usize {
    100_000_000 // 100 MB
}

/// Remote `extends` configuration (disabled unless allowlisted).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteExtendsConfig {
    /// Allowed hosts for remote policy resolution.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// Optional cache directory override.
    #[serde(default)]
    pub cache_dir: Option<PathBuf>,
    /// Require HTTPS for remote policy resolution.
    #[serde(default = "default_remote_extends_https_only")]
    pub https_only: bool,
    /// Allow resolving to private/loopback/link-local IPs (INSECURE).
    #[serde(default)]
    pub allow_private_ips: bool,
    /// Allow redirects to a different host than the original request.
    #[serde(default)]
    pub allow_cross_host_redirects: bool,
    /// Maximum bytes to fetch for a single remote policy.
    #[serde(default = "default_remote_max_fetch_bytes")]
    pub max_fetch_bytes: usize,
    /// Maximum total bytes for the cache directory.
    #[serde(default = "default_remote_max_cache_bytes")]
    pub max_cache_bytes: usize,
}

impl Default for RemoteExtendsConfig {
    fn default() -> Self {
        Self {
            allowed_hosts: Vec::new(),
            cache_dir: None,
            https_only: default_remote_extends_https_only(),
            allow_private_ips: false,
            allow_cross_host_redirects: false,
            max_fetch_bytes: default_remote_max_fetch_bytes(),
            max_cache_bytes: default_remote_max_cache_bytes(),
        }
    }
}

fn default_remote_extends_https_only() -> bool {
    true
}

/// Audit ledger encryption key source.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuditEncryptionKeySource {
    /// Load key bytes from a file containing a hex string (32 bytes / 64 hex chars).
    #[default]
    File,
    /// Load key bytes from an environment variable containing a hex string (32 bytes / 64 hex chars).
    Env,
    /// Load key bytes from a TPM-sealed blob (JSON written by `hush keygen --tpm-seal`).
    TpmSealedBlob,
}

/// Audit ledger encryption configuration.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEncryptionConfig {
    /// Enable encryption at rest for the audit metadata blob.
    #[serde(default)]
    pub enabled: bool,

    /// Key source for encryption.
    #[serde(default)]
    pub key_source: AuditEncryptionKeySource,

    /// File containing the hex-encoded key (required for `file` key_source).
    #[serde(default)]
    pub key_path: Option<PathBuf>,

    /// Environment variable name containing the hex-encoded key (required for `env` key_source).
    #[serde(default)]
    pub key_env: Option<String>,

    /// Path to a TPM-sealed blob JSON file (required for `tpm_sealed_blob` key_source).
    #[serde(default)]
    pub tpm_sealed_blob_path: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    #[serde(default)]
    pub encryption: AuditEncryptionConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditSinkConfig {
    /// Print each audit event as JSONL to stdout.
    StdoutJsonl,
    /// Append each audit event as JSONL to a file.
    FileJsonl { path: PathBuf },
    /// POST each audit event to a webhook endpoint.
    Webhook {
        url: String,
        #[serde(default)]
        headers: Option<std::collections::HashMap<String, String>>,
    },
    /// Send audit events as OTLP logs over HTTP.
    OtlpHttp {
        endpoint: String,
        #[serde(default)]
        headers: Option<std::collections::HashMap<String, String>>,
        #[serde(default)]
        service_name: Option<String>,
        #[serde(default)]
        service_version: Option<String>,
        #[serde(default)]
        resource_attributes: Option<std::collections::HashMap<String, String>>,
    },
    /// Send audit events to Splunk HTTP Event Collector.
    SplunkHec {
        url: String,
        token: String,
        #[serde(default)]
        index: Option<String>,
        #[serde(default)]
        sourcetype: Option<String>,
        #[serde(default)]
        source: Option<String>,
    },
    /// Index audit events into Elasticsearch.
    Elastic {
        url: String,
        #[serde(default)]
        api_key: Option<String>,
        #[serde(default)]
        index: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditForwardConfig {
    /// Whether forwarding is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// In-memory queue size for forwarding.
    #[serde(default = "default_audit_forward_queue_size")]
    pub queue_size: usize,
    /// Per-sink send timeout (milliseconds).
    #[serde(default = "default_audit_forward_timeout_ms")]
    pub timeout_ms: u64,
    /// Configured sinks.
    #[serde(default)]
    pub sinks: Vec<AuditSinkConfig>,
}

fn default_audit_forward_queue_size() -> usize {
    8192
}

fn default_audit_forward_timeout_ms() -> u64 {
    2_000
}

impl Default for AuditForwardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            queue_size: default_audit_forward_queue_size(),
            timeout_ms: default_audit_forward_timeout_ms(),
            sinks: Vec::new(),
        }
    }
}

impl AuditForwardConfig {
    pub fn resolve_env_refs(&self) -> anyhow::Result<Self> {
        let mut out = self.clone();

        let mut sinks = Vec::with_capacity(out.sinks.len());
        for (idx, sink) in out.sinks.into_iter().enumerate() {
            let sink = match sink {
                AuditSinkConfig::StdoutJsonl => AuditSinkConfig::StdoutJsonl,
                AuditSinkConfig::FileJsonl { path } => AuditSinkConfig::FileJsonl { path },
                AuditSinkConfig::Webhook { url, headers } => {
                    let url = expand_env_refs(&url).map_err(|e| {
                        anyhow::anyhow!("Invalid audit_forward.sinks[{}].url value: {}", idx, e)
                    })?;
                    let headers = headers
                        .map(|h| {
                            h.into_iter()
                                .map(|(k, v)| Ok((k, expand_env_refs(&v)?)))
                                .collect::<anyhow::Result<std::collections::HashMap<_, _>>>()
                        })
                        .transpose()
                        .map_err(|e| {
                            anyhow::anyhow!(
                                "Invalid audit_forward.sinks[{}].headers value: {}",
                                idx,
                                e
                            )
                        })?;
                    AuditSinkConfig::Webhook { url, headers }
                }
                AuditSinkConfig::OtlpHttp {
                    endpoint,
                    headers,
                    service_name,
                    service_version,
                    resource_attributes,
                } => {
                    let endpoint = expand_env_refs(&endpoint).map_err(|e| {
                        anyhow::anyhow!(
                            "Invalid audit_forward.sinks[{}].endpoint value: {}",
                            idx,
                            e
                        )
                    })?;
                    let headers = headers
                        .map(|h| {
                            h.into_iter()
                                .map(|(k, v)| Ok((k, expand_env_refs(&v)?)))
                                .collect::<anyhow::Result<std::collections::HashMap<_, _>>>()
                        })
                        .transpose()
                        .map_err(|e| {
                            anyhow::anyhow!(
                                "Invalid audit_forward.sinks[{}].headers value: {}",
                                idx,
                                e
                            )
                        })?;
                    let service_name = service_name
                        .map(|v| expand_env_refs(&v))
                        .transpose()
                        .map_err(|e| {
                            anyhow::anyhow!(
                                "Invalid audit_forward.sinks[{}].service_name value: {}",
                                idx,
                                e
                            )
                        })?;
                    let service_version = service_version
                        .map(|v| expand_env_refs(&v))
                        .transpose()
                        .map_err(|e| {
                            anyhow::anyhow!(
                                "Invalid audit_forward.sinks[{}].service_version value: {}",
                                idx,
                                e
                            )
                        })?;
                    let resource_attributes = resource_attributes
                        .map(|attrs| {
                            attrs
                                .into_iter()
                                .map(|(k, v)| Ok((k, expand_env_refs(&v)?)))
                                .collect::<anyhow::Result<std::collections::HashMap<_, _>>>()
                        })
                        .transpose()
                        .map_err(|e| {
                            anyhow::anyhow!(
                                "Invalid audit_forward.sinks[{}].resource_attributes value: {}",
                                idx,
                                e
                            )
                        })?;

                    AuditSinkConfig::OtlpHttp {
                        endpoint,
                        headers,
                        service_name,
                        service_version,
                        resource_attributes,
                    }
                }
                AuditSinkConfig::SplunkHec {
                    url,
                    token,
                    index,
                    sourcetype,
                    source,
                } => {
                    let url = expand_env_refs(&url).map_err(|e| {
                        anyhow::anyhow!("Invalid audit_forward.sinks[{}].url value: {}", idx, e)
                    })?;
                    let token = expand_env_refs(&token).map_err(|e| {
                        anyhow::anyhow!("Invalid audit_forward.sinks[{}].token value: {}", idx, e)
                    })?;
                    AuditSinkConfig::SplunkHec {
                        url,
                        token,
                        index,
                        sourcetype,
                        source,
                    }
                }
                AuditSinkConfig::Elastic {
                    url,
                    api_key,
                    index,
                } => {
                    let url = expand_env_refs(&url).map_err(|e| {
                        anyhow::anyhow!("Invalid audit_forward.sinks[{}].url value: {}", idx, e)
                    })?;
                    let api_key =
                        api_key
                            .map(|k| expand_env_refs(&k))
                            .transpose()
                            .map_err(|e| {
                                anyhow::anyhow!(
                                    "Invalid audit_forward.sinks[{}].api_key value: {}",
                                    idx,
                                    e
                                )
                            })?;
                    AuditSinkConfig::Elastic {
                        url,
                        api_key,
                        index,
                    }
                }
            };

            sinks.push(sink);
        }
        out.sinks = sinks;

        Ok(out)
    }
}
/// Daemon configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Listen address (e.g., "0.0.0.0:8080")
    #[serde(default = "default_listen")]
    pub listen: String,

    /// Path to policy YAML file
    #[serde(default)]
    pub policy_path: Option<PathBuf>,

    /// Ruleset name (if policy_path not set)
    #[serde(default = "default_ruleset")]
    pub ruleset: String,

    /// Path to SQLite audit database
    #[serde(default = "default_audit_db")]
    pub audit_db: PathBuf,

    /// Path to SQLite control database (sessions/RBAC/scoped policies).
    ///
    /// If unset, defaults to `audit_db` to keep deployments single-file.
    #[serde(default)]
    pub control_db: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Optional TLS configuration
    #[serde(default)]
    pub tls: Option<TlsConfig>,

    /// Path to signing key file
    #[serde(default)]
    pub signing_key: Option<PathBuf>,

    /// Trusted public keys for verifying incoming signed policy bundles (hex, 32 bytes).
    ///
    /// Supports `${VAR}` environment variable references.
    #[serde(default)]
    pub policy_bundle_trusted_pubkeys: Vec<String>,

    /// Enable CORS for browser access
    #[serde(default = "default_cors")]
    pub cors_enabled: bool,

    /// Maximum audit log entries to keep (0 = unlimited)
    #[serde(default)]
    pub max_audit_entries: usize,

    /// Audit ledger configuration.
    #[serde(default)]
    pub audit: AuditConfig,

    /// Audit forwarding configuration (optional).
    #[serde(default)]
    pub audit_forward: AuditForwardConfig,

    /// API authentication configuration
    #[serde(default)]
    pub auth: AuthConfig,

    /// Identity configuration (OIDC/SAML/etc)
    #[serde(default)]
    pub identity: IdentityConfig,

    /// RBAC configuration
    #[serde(default)]
    pub rbac: RbacConfig,

    /// Policy scoping configuration
    #[serde(default)]
    pub policy_scoping: PolicyScopingConfig,

    /// Session hardening configuration (binding/rotation).
    #[serde(default)]
    pub session: SessionHardeningConfig,

    /// Rate limiting configuration
    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    /// Threat intelligence (STIX/TAXII) configuration
    #[serde(default)]
    pub threat_intel: ThreatIntelConfig,

    /// SIEM/SOAR export configuration
    #[serde(default)]
    pub siem: SiemSoarConfig,

    /// Remote `extends` configuration (disabled unless allowlisted).
    #[serde(default)]
    pub remote_extends: RemoteExtendsConfig,
}

fn default_listen() -> String {
    "127.0.0.1:9876".to_string()
}

fn default_ruleset() -> String {
    "default".to_string()
}

fn default_audit_db() -> PathBuf {
    let base = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("clawdstriked").join("audit.db")
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_cors() -> bool {
    false
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            policy_path: None,
            ruleset: default_ruleset(),
            audit_db: default_audit_db(),
            control_db: None,
            log_level: default_log_level(),
            tls: None,
            signing_key: None,
            policy_bundle_trusted_pubkeys: Vec::new(),
            cors_enabled: default_cors(),
            max_audit_entries: 0,
            audit: AuditConfig::default(),
            audit_forward: AuditForwardConfig::default(),
            auth: AuthConfig::default(),
            identity: IdentityConfig::default(),
            rbac: RbacConfig::default(),
            policy_scoping: PolicyScopingConfig::default(),
            session: SessionHardeningConfig::default(),
            rate_limit: RateLimitConfig::default(),
            threat_intel: ThreatIntelConfig::default(),
            siem: SiemSoarConfig::default(),
            remote_extends: RemoteExtendsConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiemSoarConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub labels: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub privacy: SiemPrivacyConfig,
    #[serde(default)]
    pub exporters: SiemExportersConfig,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiemPrivacyConfig {
    #[serde(default)]
    pub drop_metadata: bool,
    #[serde(default)]
    pub drop_labels: bool,
    /// Field paths to remove (best-effort, limited to known fields).
    #[serde(default)]
    pub deny_fields: Vec<String>,
    /// Field paths to redact to a static replacement (best-effort, limited to known fields).
    #[serde(default)]
    pub redact_fields: Vec<String>,
    #[serde(default = "default_redaction_replacement")]
    pub redaction_replacement: String,
}

fn default_redaction_replacement() -> String {
    "[REDACTED]".to_string()
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiemExportersConfig {
    #[serde(default)]
    pub splunk: Option<ExporterSettings<SplunkConfig>>,
    #[serde(default)]
    pub elastic: Option<ExporterSettings<ElasticConfig>>,
    #[serde(default)]
    pub datadog: Option<ExporterSettings<DatadogConfig>>,
    #[serde(default)]
    pub sumo_logic: Option<ExporterSettings<SumoLogicConfig>>,
    #[serde(default)]
    pub alerting: Option<ExporterSettings<AlertingConfig>>,
    #[serde(default)]
    pub webhooks: Option<ExporterSettings<WebhookExporterConfig>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExporterSettings<T> {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub runtime: SiemExporterConfig,
    #[serde(default)]
    pub filter: EventFilter,
    #[serde(default)]
    pub dlq: Option<DeadLetterQueueConfig>,
    #[serde(default = "default_exporter_queue_capacity")]
    pub queue_capacity: usize,
    #[serde(flatten)]
    pub config: T,
}

fn default_exporter_queue_capacity() -> usize {
    10_000
}

impl Config {
    /// Load configuration from file
    pub fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())?;

        // Support both YAML and TOML based on extension
        let mut config: Config = if path
            .as_ref()
            .extension()
            .is_some_and(|e| e == "yaml" || e == "yml")
        {
            serde_yaml::from_str(&content)?
        } else {
            toml::from_str(&content)?
        };

        config.expand_env_refs()?;
        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        for (idx, proxy) in self.rate_limit.trusted_proxies.iter().enumerate() {
            proxy.parse::<IpAddr>().map_err(|e| {
                anyhow::anyhow!(
                    "Invalid rate_limit.trusted_proxies[{}] value {}: {}",
                    idx,
                    proxy,
                    e
                )
            })?;
        }

        if self.audit_forward.enabled {
            if self.audit_forward.queue_size == 0 {
                return Err(anyhow::anyhow!("audit_forward.queue_size must be > 0"));
            }
            if self.audit_forward.timeout_ms == 0 {
                return Err(anyhow::anyhow!("audit_forward.timeout_ms must be > 0"));
            }
        }

        if self.audit.encryption.enabled {
            match self.audit.encryption.key_source {
                AuditEncryptionKeySource::File => {
                    if self.audit.encryption.key_path.is_none() {
                        return Err(anyhow::anyhow!(
                            "audit.encryption.key_path is required when audit.encryption.key_source = file"
                        ));
                    }
                }
                AuditEncryptionKeySource::Env => {
                    if self.audit.encryption.key_env.is_none() {
                        return Err(anyhow::anyhow!(
                            "audit.encryption.key_env is required when audit.encryption.key_source = env"
                        ));
                    }
                }
                AuditEncryptionKeySource::TpmSealedBlob => {
                    if self.audit.encryption.tpm_sealed_blob_path.is_none() {
                        return Err(anyhow::anyhow!(
                            "audit.encryption.tpm_sealed_blob_path is required when audit.encryption.key_source = tpm_sealed_blob"
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn expand_env_refs(&mut self) -> anyhow::Result<()> {
        // Threat intel auth.
        for server in &mut self.threat_intel.servers {
            if let Some(auth) = &mut server.auth {
                if let Some(v) = &auth.username {
                    auth.username = Some(expand_secret_ref(v)?);
                }
                if let Some(v) = &auth.password {
                    auth.password = Some(expand_secret_ref(v)?);
                }
                if let Some(v) = &auth.api_key {
                    auth.api_key = Some(expand_secret_ref(v)?);
                }
            }
        }

        // SIEM exporter credentials.
        if let Some(splunk) = &mut self.siem.exporters.splunk {
            splunk.config.hec_url = expand_env_refs(&splunk.config.hec_url)?;
            splunk.config.hec_token = expand_secret_ref(&splunk.config.hec_token)?;
        }
        if let Some(elastic) = &mut self.siem.exporters.elastic {
            elastic.config.base_url = expand_env_refs(&elastic.config.base_url)?;
            if let Some(v) = &elastic.config.auth.api_key {
                elastic.config.auth.api_key = Some(expand_secret_ref(v)?);
            }
            if let Some(v) = &elastic.config.auth.username {
                elastic.config.auth.username = Some(expand_secret_ref(v)?);
            }
            if let Some(v) = &elastic.config.auth.password {
                elastic.config.auth.password = Some(expand_secret_ref(v)?);
            }
        }
        if let Some(datadog) = &mut self.siem.exporters.datadog {
            datadog.config.api_key = expand_secret_ref(&datadog.config.api_key)?;
            if let Some(v) = &datadog.config.app_key {
                datadog.config.app_key = Some(expand_secret_ref(v)?);
            }
        }
        if let Some(sumo) = &mut self.siem.exporters.sumo_logic {
            sumo.config.http_source_url = expand_secret_ref(&sumo.config.http_source_url)?;
        }
        if let Some(alerting) = &mut self.siem.exporters.alerting {
            if let Some(pd) = &mut alerting.config.pagerduty {
                pd.routing_key = expand_secret_ref(&pd.routing_key)?;
            }
            if let Some(og) = &mut alerting.config.opsgenie {
                og.api_key = expand_secret_ref(&og.api_key)?;
            }
        }
        if let Some(webhooks) = &mut self.siem.exporters.webhooks {
            if let Some(slack) = &mut webhooks.config.slack {
                slack.webhook_url = expand_secret_ref(&slack.webhook_url)?;
            }
            if let Some(teams) = &mut webhooks.config.teams {
                teams.webhook_url = expand_secret_ref(&teams.webhook_url)?;
            }
            for hook in &mut webhooks.config.webhooks {
                hook.url = expand_env_refs(&hook.url)?;
                for (_k, v) in hook.headers.iter_mut() {
                    *v = expand_env_refs(v)?;
                }
                if let Some(v) = &hook.content_type {
                    hook.content_type = Some(expand_env_refs(v)?);
                }
                if let Some(v) = &hook.body_template {
                    hook.body_template = Some(expand_env_refs(v)?);
                }
                if let Some(auth) = &mut hook.auth {
                    if let Some(v) = &auth.token {
                        auth.token = Some(expand_secret_ref(v)?);
                    }
                    if let Some(v) = &auth.username {
                        auth.username = Some(expand_secret_ref(v)?);
                    }
                    if let Some(v) = &auth.password {
                        auth.password = Some(expand_secret_ref(v)?);
                    }
                    if let Some(v) = &auth.header_value {
                        auth.header_value = Some(expand_secret_ref(v)?);
                    }
                }
            }
        }

        Ok(())
    }

    pub fn audit_encryption_key(&self) -> anyhow::Result<Option<[u8; 32]>> {
        if !self.audit.encryption.enabled {
            return Ok(None);
        }

        let bytes = match self.audit.encryption.key_source {
            AuditEncryptionKeySource::File => {
                let path = self.audit.encryption.key_path.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("audit.encryption.key_path is required for file key_source")
                })?;
                std::fs::read_to_string(path)
                    .map_err(|e| anyhow::anyhow!("Failed to read audit encryption key: {}", e))?
            }
            AuditEncryptionKeySource::Env => {
                let name = self.audit.encryption.key_env.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("audit.encryption.key_env is required for env key_source")
                })?;
                expand_env_refs(&format!("${{{}}}", name))?
            }
            AuditEncryptionKeySource::TpmSealedBlob => {
                let path = self
                    .audit
                    .encryption
                    .tpm_sealed_blob_path
                    .as_ref()
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "audit.encryption.tpm_sealed_blob_path is required for tpm_sealed_blob key_source"
                        )
                    })?;
                let raw = std::fs::read_to_string(path).map_err(|e| {
                    anyhow::anyhow!("Failed to read TPM sealed audit key blob: {}", e)
                })?;
                let blob: hush_core::TpmSealedBlob = serde_json::from_str(raw.trim())
                    .map_err(|e| anyhow::anyhow!("Invalid TPM sealed blob JSON: {}", e))?;
                let unsealed = blob
                    .unseal()
                    .map_err(|e| anyhow::anyhow!("TPM unseal failed: {}", e))?;
                if unsealed.len() != 32 {
                    return Err(anyhow::anyhow!(
                        "Audit encryption key must be 32 bytes, got {}",
                        unsealed.len()
                    ));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&unsealed);
                return Ok(Some(arr));
            }
        };

        let hex_str = bytes.trim().strip_prefix("0x").unwrap_or(bytes.trim());
        let decoded = hex::decode(hex_str)
            .map_err(|e| anyhow::anyhow!("Invalid audit encryption key hex: {}", e))?;
        if decoded.len() != 32 {
            return Err(anyhow::anyhow!(
                "Audit encryption key must be 32 bytes (64 hex chars), got {} bytes",
                decoded.len()
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&decoded);
        Ok(Some(arr))
    }

    pub fn load_trusted_policy_bundle_keys(&self) -> anyhow::Result<Vec<hush_core::PublicKey>> {
        let mut keys = Vec::new();
        for (idx, key) in self.policy_bundle_trusted_pubkeys.iter().enumerate() {
            let key = expand_env_refs(key).map_err(|e| {
                anyhow::anyhow!(
                    "Invalid policy_bundle_trusted_pubkeys[{}] value: {}",
                    idx,
                    e
                )
            })?;
            let pk = hush_core::PublicKey::from_hex(key.trim()).map_err(|e| {
                anyhow::anyhow!(
                    "Invalid policy_bundle_trusted_pubkeys[{}] public key: {}",
                    idx,
                    e
                )
            })?;
            keys.push(pk);
        }
        Ok(keys)
    }

    /// Load from default locations or create default
    pub fn load_default() -> anyhow::Result<Self> {
        let paths = [
            PathBuf::from("/etc/clawdstriked/config.yaml"),
            PathBuf::from("/etc/clawdstriked/config.toml"),
            dirs::config_dir()
                .map(|d| d.join("clawdstriked/config.yaml"))
                .unwrap_or_default(),
            dirs::config_dir()
                .map(|d| d.join("clawdstriked/config.toml"))
                .unwrap_or_default(),
            PathBuf::from("./clawdstriked.yaml"),
            PathBuf::from("./clawdstriked.toml"),
        ];

        let mut errors: Vec<(PathBuf, anyhow::Error)> = Vec::new();
        for path in paths {
            if path.exists() {
                match Self::from_file(&path) {
                    Ok(config) => {
                        if let Err(err) = config.validate() {
                            errors.push((path, err));
                        } else {
                            tracing::info!(path = %path.display(), "Loaded config");
                            return Ok(config);
                        }
                    }
                    Err(err) => {
                        errors.push((path, err));
                    }
                }
            }
        }

        if !errors.is_empty() {
            let mut msg =
                String::from("Failed to load clawdstriked config from existing file(s):\n");
            for (path, err) in errors {
                msg.push_str(&format!("  - {}: {err}\n", path.display()));
            }
            return Err(anyhow::anyhow!(msg));
        }

        Ok(Self::default())
    }

    /// Get the tracing level filter
    pub fn tracing_level(&self) -> tracing::Level {
        match self.log_level.to_lowercase().as_str() {
            "trace" => tracing::Level::TRACE,
            "debug" => tracing::Level::DEBUG,
            "info" => tracing::Level::INFO,
            "warn" | "warning" => tracing::Level::WARN,
            "error" => tracing::Level::ERROR,
            _ => tracing::Level::INFO,
        }
    }

    /// Load API keys from config into an AuthStore.
    ///
    /// Supports `${VAR}` environment variable references inside `auth.api_keys[].key`.
    pub async fn load_auth_store(&self) -> anyhow::Result<AuthStore> {
        let store = AuthStore::new();

        let has_pepper = std::env::var("CLAWDSTRIKE_AUTH_PEPPER")
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        let has_api_keys = !self.auth.api_keys.is_empty();
        if self.auth.enabled && has_api_keys && !has_pepper {
            return Err(anyhow::anyhow!(
                "Auth is enabled but CLAWDSTRIKE_AUTH_PEPPER is not set; refusing to start without a pepper"
            ));
        }

        for (idx, key_config) in self.auth.api_keys.iter().enumerate() {
            // Parse scopes
            let scopes = if key_config.scopes.is_empty() {
                // Default to check+read if no scopes specified.
                let mut default_scopes = std::collections::HashSet::new();
                default_scopes.insert(Scope::Check);
                default_scopes.insert(Scope::Read);
                default_scopes
            } else {
                let mut scopes = std::collections::HashSet::new();
                for scope_str in &key_config.scopes {
                    let scope = scope_str.parse::<Scope>().map_err(|()| {
                        anyhow::anyhow!(
                            "Invalid auth.api_keys[{}].scopes entry: {}",
                            idx,
                            scope_str
                        )
                    })?;
                    scopes.insert(scope);
                }
                scopes
            };

            let key = expand_env_refs(&key_config.key)
                .map_err(|e| anyhow::anyhow!("Invalid auth.api_keys[{}].key value: {}", idx, e))?;

            let api_key = ApiKey {
                id: uuid::Uuid::new_v4().to_string(),
                key_hash: AuthStore::hash_key(&key),
                name: key_config.name.clone(),
                tier: None,
                scopes,
                created_at: chrono::Utc::now(),
                expires_at: key_config.expires_at,
            };

            store.add_key(api_key).await;
        }

        if self.auth.enabled && self.auth.api_keys.is_empty() {
            tracing::warn!("Auth is enabled but no API keys configured");
        }

        Ok(store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.listen, "127.0.0.1:9876");
        assert_eq!(config.ruleset, "default");
        assert!(!config.cors_enabled);
        assert!(!config.audit.encryption.enabled);
        assert!(!config.audit_forward.enabled);
    }

    #[test]
    fn test_config_from_toml() {
        let toml = r#"
listen = "0.0.0.0:8080"
ruleset = "strict"
log_level = "debug"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.listen, "0.0.0.0:8080");
        assert_eq!(config.ruleset, "strict");
        assert_eq!(config.log_level, "debug");
    }

    #[test]
    fn test_tracing_level() {
        let config = Config {
            log_level: "trace".to_string(),
            ..Default::default()
        };
        assert_eq!(config.tracing_level(), tracing::Level::TRACE);

        let config = Config {
            log_level: "debug".to_string(),
            ..Default::default()
        };
        assert_eq!(config.tracing_level(), tracing::Level::DEBUG);

        let config = Config {
            log_level: "invalid".to_string(),
            ..Default::default()
        };
        assert_eq!(config.tracing_level(), tracing::Level::INFO);
    }

    #[test]
    fn test_auth_config_default() {
        let config = Config::default();
        assert!(!config.auth.enabled);
        assert!(config.auth.api_keys.is_empty());
    }

    #[test]
    fn test_config_with_auth_from_toml() {
        let toml = r#"
listen = "0.0.0.0:8080"
ruleset = "strict"

[auth]
enabled = true

[[auth.api_keys]]
name = "test-key"
key = "secret-key-123"
scopes = ["check", "read"]

[[auth.api_keys]]
name = "admin-key"
key = "admin-secret"
scopes = ["*"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.auth.enabled);
        assert_eq!(config.auth.api_keys.len(), 2);
        assert_eq!(config.auth.api_keys[0].name, "test-key");
        assert_eq!(config.auth.api_keys[0].scopes, vec!["check", "read"]);
        assert_eq!(config.auth.api_keys[1].name, "admin-key");
        assert_eq!(config.auth.api_keys[1].scopes, vec!["*"]);
    }

    #[tokio::test]
    async fn test_load_auth_store() -> anyhow::Result<()> {
        std::env::set_var("CLAWDSTRIKE_AUTH_PEPPER", "test-pepper");

        let toml = r#"
listen = "127.0.0.1:9876"

[auth]
enabled = true

[[auth.api_keys]]
name = "test"
key = "my-secret-key"
scopes = ["check"]
"#;
        let config: Config = toml::from_str(toml)?;
        let store = config.load_auth_store().await?;

        // Should be able to validate with the raw key
        let key = store.validate_key("my-secret-key").await?;
        assert_eq!(key.name, "test");
        assert!(key.has_scope(crate::auth::Scope::Check));
        assert!(!key.has_scope(crate::auth::Scope::Admin));
        Ok(())
    }

    #[tokio::test]
    async fn test_load_auth_store_default_scopes() -> anyhow::Result<()> {
        std::env::set_var("CLAWDSTRIKE_AUTH_PEPPER", "test-pepper");

        let toml = r#"
listen = "127.0.0.1:9876"

[auth]
enabled = true

[[auth.api_keys]]
name = "default-scopes"
key = "my-key"
scopes = []
"#;
        let config: Config = toml::from_str(toml)?;
        let store = config.load_auth_store().await?;

        let key = store.validate_key("my-key").await?;
        // Empty scopes should default to check+read
        assert!(key.has_scope(crate::auth::Scope::Check));
        assert!(key.has_scope(crate::auth::Scope::Read));
        assert!(!key.has_scope(crate::auth::Scope::Admin));
        Ok(())
    }

    #[tokio::test]
    async fn test_load_auth_store_expands_env_refs() -> anyhow::Result<()> {
        std::env::set_var("CLAWDSTRIKE_AUTH_PEPPER", "test-pepper");
        std::env::set_var("CLAWDSTRIKE_TEST_API_KEY", "secret-from-env");

        let yaml = r#"
listen: "127.0.0.1:9876"
auth:
  enabled: true
  api_keys:
    - name: "env"
      key: "${CLAWDSTRIKE_TEST_API_KEY}"
      scopes: ["check"]
"#;

        let config: Config = serde_yaml::from_str(yaml)?;
        let store = config.load_auth_store().await?;
        let key = store.validate_key("secret-from-env").await?;
        assert_eq!(key.name, "env");
        Ok(())
    }

    #[tokio::test]
    async fn test_load_auth_store_allows_auth_enabled_without_api_keys_and_without_pepper(
    ) -> anyhow::Result<()> {
        std::env::remove_var("CLAWDSTRIKE_AUTH_PEPPER");

        let toml = r#"
listen = "127.0.0.1:9876"

[auth]
enabled = true
"#;

        let config: Config = toml::from_str(toml)?;
        let _store = config.load_auth_store().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_load_auth_store_requires_pepper_when_api_keys_are_configured() {
        std::env::remove_var("CLAWDSTRIKE_AUTH_PEPPER");

        let toml = r#"
listen = "127.0.0.1:9876"

[auth]
enabled = true

[[auth.api_keys]]
name = "test"
key = "my-secret-key"
scopes = ["check"]
"#;

        let config: Config = toml::from_str(toml).expect("parse config");
        match config.load_auth_store().await {
            Ok(_) => panic!("missing pepper should fail when api_keys are configured"),
            Err(err) => {
                assert!(
                    err.to_string().contains("CLAWDSTRIKE_AUTH_PEPPER"),
                    "unexpected error: {err}"
                );
            }
        }
    }

    #[test]
    fn test_rate_limit_config_default() {
        let config = Config::default();
        assert!(config.rate_limit.enabled);
        assert_eq!(config.rate_limit.requests_per_second, 100);
        assert_eq!(config.rate_limit.burst_size, 50);
    }

    #[test]
    fn test_config_with_rate_limit_from_toml() {
        let toml = r#"
listen = "0.0.0.0:8080"

[rate_limit]
enabled = true
requests_per_second = 50
burst_size = 25
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.rate_limit.enabled);
        assert_eq!(config.rate_limit.requests_per_second, 50);
        assert_eq!(config.rate_limit.burst_size, 25);
    }

    #[test]
    fn test_config_rate_limit_disabled_from_toml() {
        let toml = r#"
listen = "0.0.0.0:8080"

[rate_limit]
enabled = false
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(!config.rate_limit.enabled);
    }

    #[test]
    fn test_audit_forward_otlp_env_resolution() {
        std::env::set_var("OTLP_ENDPOINT", "https://collector.example:4318");
        std::env::set_var("OTLP_AUTH", "Bearer abc");
        std::env::set_var("OTLP_SERVICE", "hushd-test");

        let cfg = AuditForwardConfig {
            enabled: true,
            queue_size: 128,
            timeout_ms: 2_000,
            sinks: vec![AuditSinkConfig::OtlpHttp {
                endpoint: "${OTLP_ENDPOINT}".to_string(),
                headers: Some(
                    [("Authorization".to_string(), "${OTLP_AUTH}".to_string())]
                        .into_iter()
                        .collect(),
                ),
                service_name: Some("${OTLP_SERVICE}".to_string()),
                service_version: None,
                resource_attributes: None,
            }],
        };

        let resolved = cfg.resolve_env_refs().expect("resolve");
        match &resolved.sinks[0] {
            AuditSinkConfig::OtlpHttp {
                endpoint,
                headers,
                service_name,
                ..
            } => {
                assert_eq!(endpoint, "https://collector.example:4318");
                assert_eq!(
                    headers
                        .as_ref()
                        .and_then(|h| h.get("Authorization"))
                        .map(String::as_str),
                    Some("Bearer abc")
                );
                assert_eq!(service_name.as_deref(), Some("hushd-test"));
            }
            _ => panic!("expected otlp sink"),
        }
    }
}
