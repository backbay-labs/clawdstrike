use std::path::PathBuf;

use hush_core::PublicKey;

#[derive(Clone, Debug)]
pub enum SecretBackendConfig {
    File {
        path: PathBuf,
    },
    Env {
        prefix: String,
    },
    Http {
        base_url: String,
        bearer_token: Option<String>,
        path_prefix: String,
    },
}

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: String,
    pub hushd_base_url: String,
    pub hushd_token: Option<String>,
    pub secret_backend: SecretBackendConfig,
    pub trusted_hushd_public_keys: Vec<PublicKey>,
    pub request_timeout_secs: u64,
    pub binding_proof_ttl_secs: u64,
    pub allow_http_loopback: bool,
    pub allow_private_upstream_hosts: bool,
    pub allow_invalid_upstream_tls: bool,
    /// Optional bearer token required for admin and mutation endpoints.
    /// When `None`, authentication is skipped (backward compatible).
    pub admin_token: Option<String>,
}

fn env_bool(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let listen = std::env::var("CLAWDSTRIKE_BROKERD_LISTEN")
            .unwrap_or_else(|_| "127.0.0.1:9889".to_string());
        let hushd_base_url = std::env::var("CLAWDSTRIKE_BROKERD_HUSHD_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:9876".to_string());
        let hushd_token = std::env::var("CLAWDSTRIKE_BROKERD_HUSHD_TOKEN")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let secret_backend = match std::env::var("CLAWDSTRIKE_BROKERD_SECRET_BACKEND")
            .unwrap_or_else(|_| "file".to_string())
            .as_str()
        {
            "file" => SecretBackendConfig::File {
                path: std::env::var("CLAWDSTRIKE_BROKERD_SECRET_FILE")
                    .map(PathBuf::from)
                    .map_err(|_| anyhow::anyhow!("CLAWDSTRIKE_BROKERD_SECRET_FILE is required"))?,
            },
            "env" => SecretBackendConfig::Env {
                prefix: std::env::var("CLAWDSTRIKE_BROKERD_SECRET_ENV_PREFIX")
                    .unwrap_or_else(|_| "CLAWDSTRIKE_SECRET_".to_string()),
            },
            "http" => SecretBackendConfig::Http {
                base_url: std::env::var("CLAWDSTRIKE_BROKERD_SECRET_HTTP_URL").map_err(|_| {
                    anyhow::anyhow!("CLAWDSTRIKE_BROKERD_SECRET_HTTP_URL is required")
                })?,
                bearer_token: std::env::var("CLAWDSTRIKE_BROKERD_SECRET_HTTP_TOKEN")
                    .ok()
                    .filter(|value| !value.trim().is_empty()),
                path_prefix: std::env::var("CLAWDSTRIKE_BROKERD_SECRET_HTTP_PATH_PREFIX")
                    .unwrap_or_else(|_| "/v1/secrets".to_string()),
            },
            other => {
                return Err(anyhow::anyhow!(
                    "unsupported CLAWDSTRIKE_BROKERD_SECRET_BACKEND: {other}"
                ))
            }
        };
        let request_timeout_secs = std::env::var("CLAWDSTRIKE_BROKERD_REQUEST_TIMEOUT_SECS")
            .ok()
            .map(|value| value.parse::<u64>())
            .transpose()?
            .unwrap_or(30);
        let binding_proof_ttl_secs = std::env::var("CLAWDSTRIKE_BROKERD_BINDING_PROOF_TTL_SECS")
            .ok()
            .map(|value| value.parse::<u64>())
            .transpose()?
            .unwrap_or(60);
        let allow_http_loopback = env_bool("CLAWDSTRIKE_BROKERD_ALLOW_HTTP_LOOPBACK");
        let allow_private_upstream_hosts =
            env_bool("CLAWDSTRIKE_BROKERD_ALLOW_PRIVATE_UPSTREAM_HOSTS");
        let allow_invalid_upstream_tls = env_bool("CLAWDSTRIKE_BROKERD_ALLOW_INVALID_TLS");
        let admin_token = std::env::var("CLAWDSTRIKE_BROKERD_ADMIN_TOKEN")
            .ok()
            .filter(|value| !value.trim().is_empty());

        let trusted_hushd_public_keys = std::env::var("CLAWDSTRIKE_BROKERD_HUSHD_PUBKEYS")
            .map_err(|_| anyhow::anyhow!("CLAWDSTRIKE_BROKERD_HUSHD_PUBKEYS is required"))?
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(PublicKey::from_hex)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| anyhow::anyhow!("invalid trusted hushd public key: {error}"))?;

        if trusted_hushd_public_keys.is_empty() {
            return Err(anyhow::anyhow!(
                "CLAWDSTRIKE_BROKERD_HUSHD_PUBKEYS must contain at least one key"
            ));
        }

        if binding_proof_ttl_secs == 0 {
            return Err(anyhow::anyhow!(
                "CLAWDSTRIKE_BROKERD_BINDING_PROOF_TTL_SECS must be greater than zero"
            ));
        }

        Ok(Self {
            listen,
            hushd_base_url,
            hushd_token,
            secret_backend,
            trusted_hushd_public_keys,
            request_timeout_secs,
            binding_proof_ttl_secs,
            allow_http_loopback,
            allow_private_upstream_hosts,
            allow_invalid_upstream_tls,
            admin_token,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use hush_core::Keypair;
    use std::sync::Mutex;

    // Config::from_env reads process-global env vars, so tests that mutate
    // environment variables must be serialised.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Clear all CLAWDSTRIKE_BROKERD_* vars so each test starts from a clean slate.
    fn clear_env() {
        for (key, _) in std::env::vars() {
            if key.starts_with("CLAWDSTRIKE_BROKERD_") {
                std::env::remove_var(&key);
            }
        }
    }

    /// Set the minimum required env vars for a valid config (file backend).
    fn set_minimum_env() {
        let keypair = Keypair::generate();
        std::env::set_var(
            "CLAWDSTRIKE_BROKERD_HUSHD_PUBKEYS",
            keypair.public_key().to_hex(),
        );
        std::env::set_var("CLAWDSTRIKE_BROKERD_SECRET_FILE", "/tmp/test-secrets.json");
    }

    #[test]
    fn from_env_defaults_with_file_backend() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        set_minimum_env();

        let config = Config::from_env().expect("should parse");
        assert_eq!(config.listen, "127.0.0.1:9889");
        assert_eq!(config.hushd_base_url, "http://127.0.0.1:9876");
        assert!(config.hushd_token.is_none());
        assert_eq!(config.request_timeout_secs, 30);
        assert_eq!(config.binding_proof_ttl_secs, 60);
        assert!(!config.allow_http_loopback);
        assert!(!config.allow_private_upstream_hosts);
        assert!(!config.allow_invalid_upstream_tls);
        assert!(!config.trusted_hushd_public_keys.is_empty());
        match &config.secret_backend {
            SecretBackendConfig::File { path } => {
                assert_eq!(path.to_str().unwrap(), "/tmp/test-secrets.json");
            }
            other => panic!("expected File backend, got: {other:?}"),
        }
    }

    #[test]
    fn from_env_custom_listen_and_hushd_url() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        set_minimum_env();
        std::env::set_var("CLAWDSTRIKE_BROKERD_LISTEN", "0.0.0.0:7777");
        std::env::set_var("CLAWDSTRIKE_BROKERD_HUSHD_URL", "http://hushd:9876");

        let config = Config::from_env().expect("should parse");
        assert_eq!(config.listen, "0.0.0.0:7777");
        assert_eq!(config.hushd_base_url, "http://hushd:9876");
    }

    #[test]
    fn from_env_hushd_token_set() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        set_minimum_env();
        std::env::set_var("CLAWDSTRIKE_BROKERD_HUSHD_TOKEN", "my-secret-token");

        let config = Config::from_env().expect("should parse");
        assert_eq!(config.hushd_token.as_deref(), Some("my-secret-token"));
    }

    #[test]
    fn from_env_hushd_token_empty_becomes_none() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        set_minimum_env();
        std::env::set_var("CLAWDSTRIKE_BROKERD_HUSHD_TOKEN", "   ");

        let config = Config::from_env().expect("should parse");
        assert!(config.hushd_token.is_none());
    }

    #[test]
    fn from_env_env_backend() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        let keypair = Keypair::generate();
        std::env::set_var(
            "CLAWDSTRIKE_BROKERD_HUSHD_PUBKEYS",
            keypair.public_key().to_hex(),
        );
        std::env::set_var("CLAWDSTRIKE_BROKERD_SECRET_BACKEND", "env");

        let config = Config::from_env().expect("should parse");
        match &config.secret_backend {
            SecretBackendConfig::Env { prefix } => {
                assert_eq!(prefix, "CLAWDSTRIKE_SECRET_");
            }
            other => panic!("expected Env backend, got: {other:?}"),
        }
    }

    #[test]
    fn from_env_env_backend_custom_prefix() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        let keypair = Keypair::generate();
        std::env::set_var(
            "CLAWDSTRIKE_BROKERD_HUSHD_PUBKEYS",
            keypair.public_key().to_hex(),
        );
        std::env::set_var("CLAWDSTRIKE_BROKERD_SECRET_BACKEND", "env");
        std::env::set_var("CLAWDSTRIKE_BROKERD_SECRET_ENV_PREFIX", "MY_PREFIX_");

        let config = Config::from_env().expect("should parse");
        match &config.secret_backend {
            SecretBackendConfig::Env { prefix } => {
                assert_eq!(prefix, "MY_PREFIX_");
            }
            other => panic!("expected Env backend, got: {other:?}"),
        }
    }

    #[test]
    fn from_env_http_backend() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        let keypair = Keypair::generate();
        std::env::set_var(
            "CLAWDSTRIKE_BROKERD_HUSHD_PUBKEYS",
            keypair.public_key().to_hex(),
        );
        std::env::set_var("CLAWDSTRIKE_BROKERD_SECRET_BACKEND", "http");
        std::env::set_var(
            "CLAWDSTRIKE_BROKERD_SECRET_HTTP_URL",
            "https://vault.example.com",
        );

        let config = Config::from_env().expect("should parse");
        match &config.secret_backend {
            SecretBackendConfig::Http {
                base_url,
                bearer_token,
                path_prefix,
            } => {
                assert_eq!(base_url, "https://vault.example.com");
                assert!(bearer_token.is_none());
                assert_eq!(path_prefix, "/v1/secrets");
            }
            other => panic!("expected Http backend, got: {other:?}"),
        }
    }

    #[test]
    fn from_env_http_backend_with_token_and_prefix() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        let keypair = Keypair::generate();
        std::env::set_var(
            "CLAWDSTRIKE_BROKERD_HUSHD_PUBKEYS",
            keypair.public_key().to_hex(),
        );
        std::env::set_var("CLAWDSTRIKE_BROKERD_SECRET_BACKEND", "http");
        std::env::set_var(
            "CLAWDSTRIKE_BROKERD_SECRET_HTTP_URL",
            "https://vault.example.com",
        );
        std::env::set_var("CLAWDSTRIKE_BROKERD_SECRET_HTTP_TOKEN", "vault-token");
        std::env::set_var("CLAWDSTRIKE_BROKERD_SECRET_HTTP_PATH_PREFIX", "/v2/managed");

        let config = Config::from_env().expect("should parse");
        match &config.secret_backend {
            SecretBackendConfig::Http {
                base_url,
                bearer_token,
                path_prefix,
            } => {
                assert_eq!(base_url, "https://vault.example.com");
                assert_eq!(bearer_token.as_deref(), Some("vault-token"));
                assert_eq!(path_prefix, "/v2/managed");
            }
            other => panic!("expected Http backend, got: {other:?}"),
        }
    }

    #[test]
    fn from_env_http_backend_empty_token_becomes_none() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        let keypair = Keypair::generate();
        std::env::set_var(
            "CLAWDSTRIKE_BROKERD_HUSHD_PUBKEYS",
            keypair.public_key().to_hex(),
        );
        std::env::set_var("CLAWDSTRIKE_BROKERD_SECRET_BACKEND", "http");
        std::env::set_var(
            "CLAWDSTRIKE_BROKERD_SECRET_HTTP_URL",
            "https://vault.example.com",
        );
        std::env::set_var("CLAWDSTRIKE_BROKERD_SECRET_HTTP_TOKEN", "  ");

        let config = Config::from_env().expect("should parse");
        match &config.secret_backend {
            SecretBackendConfig::Http { bearer_token, .. } => {
                assert!(bearer_token.is_none());
            }
            other => panic!("expected Http backend, got: {other:?}"),
        }
    }

    #[test]
    fn from_env_http_backend_missing_url_errors() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        let keypair = Keypair::generate();
        std::env::set_var(
            "CLAWDSTRIKE_BROKERD_HUSHD_PUBKEYS",
            keypair.public_key().to_hex(),
        );
        std::env::set_var("CLAWDSTRIKE_BROKERD_SECRET_BACKEND", "http");

        let err = Config::from_env().unwrap_err();
        assert!(err
            .to_string()
            .contains("CLAWDSTRIKE_BROKERD_SECRET_HTTP_URL"));
    }

    #[test]
    fn from_env_unsupported_backend_errors() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        let keypair = Keypair::generate();
        std::env::set_var(
            "CLAWDSTRIKE_BROKERD_HUSHD_PUBKEYS",
            keypair.public_key().to_hex(),
        );
        std::env::set_var("CLAWDSTRIKE_BROKERD_SECRET_BACKEND", "redis");

        let err = Config::from_env().unwrap_err();
        assert!(err.to_string().contains("redis"));
    }

    #[test]
    fn from_env_file_backend_missing_path_errors() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        let keypair = Keypair::generate();
        std::env::set_var(
            "CLAWDSTRIKE_BROKERD_HUSHD_PUBKEYS",
            keypair.public_key().to_hex(),
        );
        std::env::set_var("CLAWDSTRIKE_BROKERD_SECRET_BACKEND", "file");

        let err = Config::from_env().unwrap_err();
        assert!(err.to_string().contains("CLAWDSTRIKE_BROKERD_SECRET_FILE"));
    }

    #[test]
    fn from_env_missing_pubkeys_errors() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        std::env::set_var("CLAWDSTRIKE_BROKERD_SECRET_FILE", "/tmp/test-secrets.json");

        let err = Config::from_env().unwrap_err();
        assert!(err
            .to_string()
            .contains("CLAWDSTRIKE_BROKERD_HUSHD_PUBKEYS"));
    }

    #[test]
    fn from_env_empty_pubkeys_errors() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        std::env::set_var("CLAWDSTRIKE_BROKERD_HUSHD_PUBKEYS", "  ,  , ");
        std::env::set_var("CLAWDSTRIKE_BROKERD_SECRET_FILE", "/tmp/test-secrets.json");

        let err = Config::from_env().unwrap_err();
        assert!(err.to_string().contains("must contain at least one key"));
    }

    #[test]
    fn from_env_invalid_pubkey_errors() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        std::env::set_var("CLAWDSTRIKE_BROKERD_HUSHD_PUBKEYS", "not-a-hex-key");
        std::env::set_var("CLAWDSTRIKE_BROKERD_SECRET_FILE", "/tmp/test-secrets.json");

        let err = Config::from_env().unwrap_err();
        assert!(err.to_string().contains("invalid trusted hushd public key"));
    }

    #[test]
    fn from_env_multiple_pubkeys() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        let k1 = Keypair::generate();
        let k2 = Keypair::generate();
        std::env::set_var(
            "CLAWDSTRIKE_BROKERD_HUSHD_PUBKEYS",
            format!("{},{}", k1.public_key().to_hex(), k2.public_key().to_hex()),
        );
        std::env::set_var("CLAWDSTRIKE_BROKERD_SECRET_FILE", "/tmp/test-secrets.json");

        let config = Config::from_env().expect("should parse");
        assert_eq!(config.trusted_hushd_public_keys.len(), 2);
    }

    #[test]
    fn from_env_custom_timeout() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        set_minimum_env();
        std::env::set_var("CLAWDSTRIKE_BROKERD_REQUEST_TIMEOUT_SECS", "120");

        let config = Config::from_env().expect("should parse");
        assert_eq!(config.request_timeout_secs, 120);
    }

    #[test]
    fn from_env_invalid_timeout_errors() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        set_minimum_env();
        std::env::set_var("CLAWDSTRIKE_BROKERD_REQUEST_TIMEOUT_SECS", "nope");

        let err = Config::from_env().unwrap_err();
        assert!(err.to_string().contains("invalid digit"));
    }

    #[test]
    fn from_env_custom_binding_proof_ttl() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        set_minimum_env();
        std::env::set_var("CLAWDSTRIKE_BROKERD_BINDING_PROOF_TTL_SECS", "300");

        let config = Config::from_env().expect("should parse");
        assert_eq!(config.binding_proof_ttl_secs, 300);
    }

    #[test]
    fn from_env_zero_binding_proof_ttl_errors() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        set_minimum_env();
        std::env::set_var("CLAWDSTRIKE_BROKERD_BINDING_PROOF_TTL_SECS", "0");

        let err = Config::from_env().unwrap_err();
        assert!(err.to_string().contains("greater than zero"));
    }

    #[test]
    fn from_env_boolean_flags_truthy_values() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        set_minimum_env();

        for truthy in &["1", "true", "TRUE", "yes", "YES"] {
            std::env::set_var("CLAWDSTRIKE_BROKERD_ALLOW_HTTP_LOOPBACK", truthy);
            std::env::set_var("CLAWDSTRIKE_BROKERD_ALLOW_PRIVATE_UPSTREAM_HOSTS", truthy);
            std::env::set_var("CLAWDSTRIKE_BROKERD_ALLOW_INVALID_TLS", truthy);

            let config = Config::from_env().expect("should parse");
            assert!(
                config.allow_http_loopback,
                "allow_http_loopback should be true for '{truthy}'"
            );
            assert!(
                config.allow_private_upstream_hosts,
                "allow_private_upstream_hosts should be true for '{truthy}'"
            );
            assert!(
                config.allow_invalid_upstream_tls,
                "allow_invalid_upstream_tls should be true for '{truthy}'"
            );
        }
    }

    #[test]
    fn from_env_boolean_flags_falsy_values() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();
        set_minimum_env();

        for falsy in &["0", "false", "no", "anything-else"] {
            std::env::set_var("CLAWDSTRIKE_BROKERD_ALLOW_HTTP_LOOPBACK", falsy);
            std::env::set_var("CLAWDSTRIKE_BROKERD_ALLOW_PRIVATE_UPSTREAM_HOSTS", falsy);
            std::env::set_var("CLAWDSTRIKE_BROKERD_ALLOW_INVALID_TLS", falsy);

            let config = Config::from_env().expect("should parse");
            assert!(
                !config.allow_http_loopback,
                "allow_http_loopback should be false for '{falsy}'"
            );
            assert!(
                !config.allow_private_upstream_hosts,
                "allow_private_upstream_hosts should be false for '{falsy}'"
            );
            assert!(
                !config.allow_invalid_upstream_tls,
                "allow_invalid_upstream_tls should be false for '{falsy}'"
            );
        }
    }
}
