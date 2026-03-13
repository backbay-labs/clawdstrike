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
        let allow_http_loopback = std::env::var("CLAWDSTRIKE_BROKERD_ALLOW_HTTP_LOOPBACK")
            .ok()
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        let allow_private_upstream_hosts =
            std::env::var("CLAWDSTRIKE_BROKERD_ALLOW_PRIVATE_UPSTREAM_HOSTS")
                .ok()
                .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
                .unwrap_or(false);
        let allow_invalid_upstream_tls = std::env::var("CLAWDSTRIKE_BROKERD_ALLOW_INVALID_TLS")
            .ok()
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);

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
        })
    }
}
