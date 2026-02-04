//! Configuration for hushd daemon

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

fn expand_env_refs(value: &str) -> anyhow::Result<String> {
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
pub struct TlsConfig {
    /// Path to certificate file
    pub cert_path: PathBuf,
    /// Path to private key file
    pub key_path: PathBuf,
}

/// Configuration for a single API key
#[derive(Clone, Debug, Serialize, Deserialize)]
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
pub struct AuthConfig {
    /// Whether authentication is required for API endpoints
    #[serde(default)]
    pub enabled: bool,
    /// API keys
    #[serde(default)]
    pub api_keys: Vec<ApiKeyConfig>,
}

/// Rate limiting configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
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
        }
    }
}
/// Daemon configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
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

    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Optional TLS configuration
    #[serde(default)]
    pub tls: Option<TlsConfig>,

    /// Path to signing key file
    #[serde(default)]
    pub signing_key: Option<PathBuf>,

    /// Enable CORS for browser access
    #[serde(default = "default_cors")]
    pub cors_enabled: bool,

    /// Maximum audit log entries to keep (0 = unlimited)
    #[serde(default)]
    pub max_audit_entries: usize,

    /// API authentication configuration
    #[serde(default)]
    pub auth: AuthConfig,

    /// Rate limiting configuration
    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    /// Threat intelligence (STIX/TAXII) configuration
    #[serde(default)]
    pub threat_intel: ThreatIntelConfig,

    /// SIEM/SOAR export configuration
    #[serde(default)]
    pub siem: SiemSoarConfig,
}

fn default_listen() -> String {
    "127.0.0.1:9876".to_string()
}

fn default_ruleset() -> String {
    "default".to_string()
}

fn default_audit_db() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("hushd")
        .join("audit.db")
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_cors() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            policy_path: None,
            ruleset: default_ruleset(),
            audit_db: default_audit_db(),
            log_level: default_log_level(),
            tls: None,
            signing_key: None,
            cors_enabled: default_cors(),
            max_audit_entries: 0,
            auth: AuthConfig::default(),
            rate_limit: RateLimitConfig::default(),
            threat_intel: ThreatIntelConfig::default(),
            siem: SiemSoarConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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

    /// Load from default locations or create default
    pub fn load_default() -> anyhow::Result<Self> {
        // Try standard config locations
        let paths = [
            PathBuf::from("/etc/hushd/config.yaml"),
            PathBuf::from("/etc/hushd/config.toml"),
            dirs::config_dir()
                .map(|d| d.join("hushd/config.yaml"))
                .unwrap_or_default(),
            dirs::config_dir()
                .map(|d| d.join("hushd/config.toml"))
                .unwrap_or_default(),
            PathBuf::from("./hushd.yaml"),
            PathBuf::from("./hushd.toml"),
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
            let mut msg = String::from("Failed to load hushd config from existing file(s):\n");
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

        let has_pepper = std::env::var("HUSHD_AUTH_PEPPER")
            .ok()
            .as_deref()
            .is_some_and(|v| !v.is_empty());
        if self.auth.enabled && !has_pepper {
            tracing::warn!(
                "Auth is enabled but HUSHD_AUTH_PEPPER is not set; API key hashing will use raw SHA-256"
            );
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
        assert!(config.cors_enabled);
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
        std::env::set_var("HUSHD_TEST_API_KEY", "secret-from-env");

        let yaml = r#"
listen: "127.0.0.1:9876"
auth:
  enabled: true
  api_keys:
    - name: "env"
      key: "${HUSHD_TEST_API_KEY}"
      scopes: ["check"]
"#;

        let config: Config = serde_yaml::from_str(yaml)?;
        let store = config.load_auth_store().await?;
        let key = store.validate_key("secret-from-env").await?;
        assert_eq!(key.name, "env");
        Ok(())
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
}
