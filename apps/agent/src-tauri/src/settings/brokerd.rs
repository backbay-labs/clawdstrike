//! Local brokerd sidecar settings and secret backend configuration.

use super::defaults::{
    default_broker_port, default_broker_secret_backend_kind, default_broker_secret_env_prefix,
    default_broker_secret_file_path, default_broker_secret_http_path_prefix,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
