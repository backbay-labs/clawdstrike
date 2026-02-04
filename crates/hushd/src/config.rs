//! Configuration for hushd daemon

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::auth::{ApiKey, AuthStore, Scope};

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

    /// Audit forwarding configuration (optional).
    #[serde(default)]
    pub audit_forward: AuditForwardConfig,

    /// API authentication configuration
    #[serde(default)]
    pub auth: AuthConfig,

    /// Rate limiting configuration
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
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
            policy_bundle_trusted_pubkeys: Vec::new(),
            cors_enabled: default_cors(),
            max_audit_entries: 0,
            audit_forward: AuditForwardConfig::default(),
            auth: AuthConfig::default(),
            rate_limit: RateLimitConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from file
    pub fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())?;

        // Support both YAML and TOML based on extension
        let config = if path
            .as_ref()
            .extension()
            .is_some_and(|e| e == "yaml" || e == "yml")
        {
            serde_yaml::from_str(&content)?
        } else {
            toml::from_str(&content)?
        };

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
        Ok(())
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
