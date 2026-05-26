//! Local API security settings (token rotation + optional mTLS).

use super::defaults::{
    default_local_api_mtls_port, default_local_api_token_grace_minutes,
    default_local_api_token_rotation_interval_hours,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalApiSecuritySettings {
    #[serde(default = "default_local_api_token_rotation_interval_hours")]
    pub token_rotation_interval_hours: u32,
    #[serde(default = "default_local_api_token_grace_minutes")]
    pub token_grace_minutes: u32,
    #[serde(default)]
    pub mtls_enabled: bool,
    #[serde(default = "default_local_api_mtls_port")]
    pub mtls_port: u16,
    #[serde(default)]
    pub mtls_server_cert_path: Option<PathBuf>,
    #[serde(default)]
    pub mtls_server_key_path: Option<PathBuf>,
    #[serde(default)]
    pub mtls_client_ca_path: Option<PathBuf>,
}

impl Default for LocalApiSecuritySettings {
    fn default() -> Self {
        Self {
            token_rotation_interval_hours: default_local_api_token_rotation_interval_hours(),
            token_grace_minutes: default_local_api_token_grace_minutes(),
            mtls_enabled: false,
            mtls_port: default_local_api_mtls_port(),
            mtls_server_cert_path: None,
            mtls_server_key_path: None,
            mtls_client_ca_path: None,
        }
    }
}
