//! Configuration for the registry service, loaded from environment variables.

use std::path::PathBuf;

/// Registry service configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// Listen host. Defaults to localhost (127.0.0.1); set to 0.0.0.0 explicitly
    /// to accept connections from any interface.
    pub host: String,
    /// Listen port (default: 3100).
    pub port: u16,
    /// Root data directory for SQLite, blobs, index, and keys.
    pub data_dir: PathBuf,
    /// API key for publisher authentication on non-OIDC authenticated routes.
    pub api_key: String,
    /// Explicit insecure override to allow unauthenticated access when
    /// `api_key` is empty. Defaults to false.
    pub allow_insecure_no_auth: bool,
    /// Max upload size in bytes (default: 50 MB).
    pub max_upload_bytes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 3100,
            data_dir: PathBuf::from("."),
            api_key: String::new(),
            allow_insecure_no_auth: false,
            max_upload_bytes: 50 * 1024 * 1024,
        }
    }
}

impl Config {
    /// Refuse to start when the API key is unset unless the operator has
    /// explicitly opted into insecure mode via `allow_insecure_no_auth`.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.api_key.trim().is_empty() && !self.allow_insecure_no_auth {
            anyhow::bail!(
                "CLAWDSTRIKE_REGISTRY_API_KEY is unset; refuse to start. \
                 Set the API key, or set CLAWDSTRIKE_REGISTRY_ALLOW_INSECURE_NO_AUTH=true to opt in."
            );
        }
        Ok(())
    }

    /// Load configuration from environment variables.
    pub fn from_env() -> anyhow::Result<Self> {
        let host = std::env::var("CLAWDSTRIKE_REGISTRY_HOST").unwrap_or_else(|_| "127.0.0.1".into());
        let port: u16 = std::env::var("CLAWDSTRIKE_REGISTRY_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3100);

        let data_dir = std::env::var("CLAWDSTRIKE_REGISTRY_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                dirs::home_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join(".clawdstrike")
                    .join("registry")
            });

        let api_key = std::env::var("CLAWDSTRIKE_REGISTRY_API_KEY").unwrap_or_default();
        let allow_insecure_no_auth = parse_bool_env("CLAWDSTRIKE_REGISTRY_ALLOW_INSECURE_NO_AUTH")?;

        // Fail-closed: refuse to start without an API key unless the operator
        // has explicitly opted in via CLAWDSTRIKE_REGISTRY_ALLOW_INSECURE_NO_AUTH.
        if api_key.trim().is_empty() {
            if !allow_insecure_no_auth {
                anyhow::bail!(
                    "CLAWDSTRIKE_REGISTRY_API_KEY is unset or empty; refusing to start. \
                     Set CLAWDSTRIKE_REGISTRY_API_KEY=<token> or, for local development only, \
                     set CLAWDSTRIKE_REGISTRY_ALLOW_INSECURE_NO_AUTH=true to disable auth."
                );
            }
            tracing::warn!(
                "Registry API key is unset and CLAWDSTRIKE_REGISTRY_ALLOW_INSECURE_NO_AUTH=true; \
                 starting with authenticated routes wide open. DO NOT use this in production."
            );
        }

        let max_upload_bytes: usize = std::env::var("CLAWDSTRIKE_REGISTRY_MAX_UPLOAD_BYTES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(50 * 1024 * 1024);

        let config = Self {
            host,
            port,
            data_dir,
            api_key,
            allow_insecure_no_auth,
            max_upload_bytes,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("db.sqlite")
    }

    pub fn blob_dir(&self) -> PathBuf {
        self.data_dir.join("blobs")
    }

    pub fn index_dir(&self) -> PathBuf {
        self.data_dir.join("index")
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.data_dir.join("keys")
    }
}

fn parse_bool_env(name: &str) -> anyhow::Result<bool> {
    match std::env::var(name) {
        Ok(raw) => {
            let normalized = raw.trim().to_ascii_lowercase();
            match normalized.as_str() {
                "1" | "true" | "yes" | "on" => Ok(true),
                "0" | "false" | "no" | "off" => Ok(false),
                _ => Err(anyhow::anyhow!(
                    "invalid boolean value for {name}: '{raw}' (expected true/false)"
                )),
            }
        }
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(e) => Err(anyhow::anyhow!("failed to read {name}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_paths() {
        let config = Config {
            host: "0.0.0.0".into(),
            port: 3100,
            data_dir: PathBuf::from("/tmp/registry"),
            api_key: String::new(),
            allow_insecure_no_auth: false,
            max_upload_bytes: 50 * 1024 * 1024,
        };
        assert_eq!(config.db_path(), PathBuf::from("/tmp/registry/db.sqlite"));
        assert_eq!(config.blob_dir(), PathBuf::from("/tmp/registry/blobs"));
        assert_eq!(config.index_dir(), PathBuf::from("/tmp/registry/index"));
        assert_eq!(config.keys_dir(), PathBuf::from("/tmp/registry/keys"));
    }

    #[test]
    fn validate_rejects_empty_api_key_without_insecure_opt_in() {
        let config = Config {
            api_key: String::new(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_allows_empty_api_key_when_insecure_opt_in_set() {
        let config = Config {
            api_key: String::new(),
            allow_insecure_no_auth: true,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_accepts_non_empty_api_key() {
        let config = Config {
            api_key: "secret".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn default_host_binds_localhost() {
        let config = Config::default();
        assert_eq!(config.host, "127.0.0.1");
    }

    #[test]
    fn parse_bool_env_defaults_to_false_when_missing() {
        let unique = format!(
            "CLAWDSTRIKE_REGISTRY_BOOL_TEST_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        assert!(matches!(parse_bool_env(&unique), Ok(false)));
    }

    /// Serialize env-var manipulation across tests so concurrent tests don't
    /// race on shared CLAWDSTRIKE_REGISTRY_* state.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_clean_env<F: FnOnce() -> R, R>(f: F) -> R {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let keys = [
            "CLAWDSTRIKE_REGISTRY_API_KEY",
            "CLAWDSTRIKE_REGISTRY_ALLOW_INSECURE_NO_AUTH",
            "CLAWDSTRIKE_REGISTRY_HOST",
            "CLAWDSTRIKE_REGISTRY_PORT",
            "CLAWDSTRIKE_REGISTRY_DATA_DIR",
            "CLAWDSTRIKE_REGISTRY_MAX_UPLOAD_BYTES",
        ];
        let saved: Vec<(&str, Option<String>)> = keys
            .iter()
            .map(|k| (*k, std::env::var(k).ok()))
            .collect();
        for (k, _) in &saved {
            std::env::remove_var(k);
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        for (k, original) in &saved {
            match original {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        match result {
            Ok(value) => value,
            Err(e) => std::panic::resume_unwind(e),
        }
    }

    #[test]
    fn from_env_refuses_to_start_without_api_key() {
        with_clean_env(|| {
            let err = Config::from_env().expect_err("must reject empty api key by default");
            let msg = err.to_string();
            assert!(
                msg.contains("CLAWDSTRIKE_REGISTRY_API_KEY"),
                "error message must point operator at the missing env var: {msg}"
            );
        });
    }

    #[test]
    fn from_env_allows_empty_api_key_when_insecure_flag_set() {
        with_clean_env(|| {
            std::env::set_var("CLAWDSTRIKE_REGISTRY_ALLOW_INSECURE_NO_AUTH", "true");
            // Provide a data dir so we don't depend on home dir resolution.
            std::env::set_var("CLAWDSTRIKE_REGISTRY_DATA_DIR", "/tmp/registry-test");
            let config = Config::from_env().expect("should load with explicit insecure opt-in");
            assert!(config.api_key.is_empty());
            assert!(config.allow_insecure_no_auth);
        });
    }

    #[test]
    fn from_env_succeeds_with_api_key_set() {
        with_clean_env(|| {
            std::env::set_var("CLAWDSTRIKE_REGISTRY_API_KEY", "secret-token");
            std::env::set_var("CLAWDSTRIKE_REGISTRY_DATA_DIR", "/tmp/registry-test");
            let config = Config::from_env().expect("should load");
            assert_eq!(config.api_key, "secret-token");
            assert!(!config.allow_insecure_no_auth);
        });
    }
}
