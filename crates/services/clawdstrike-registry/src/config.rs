//! Configuration for the registry service, loaded from environment variables.

use std::path::PathBuf;

/// Registry service configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// Listen host (default: 0.0.0.0).
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

impl Config {
    /// Load configuration from environment variables.
    pub fn from_env() -> anyhow::Result<Self> {
        let host = std::env::var("CLAWDSTRIKE_REGISTRY_HOST").unwrap_or_else(|_| "0.0.0.0".into());
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

        Ok(Self {
            host,
            port,
            data_dir,
            api_key,
            allow_insecure_no_auth,
            max_upload_bytes,
        })
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
