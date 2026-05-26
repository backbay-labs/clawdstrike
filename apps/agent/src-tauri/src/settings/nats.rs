//! NATS connection settings.

use super::defaults::default_require_signed_approval_responses;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatsSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub nats_url: Option<String>,
    #[serde(default)]
    pub creds_file: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub nkey_seed: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub nats_account: Option<String>,
    #[serde(default)]
    pub subject_prefix: Option<String>,
    #[serde(default = "default_require_signed_approval_responses")]
    pub require_signed_approval_responses: bool,
    #[serde(default)]
    pub approval_response_trusted_issuer: Option<String>,
}

impl Default for NatsSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            nats_url: None,
            creds_file: None,
            token: None,
            nkey_seed: None,
            tenant_id: None,
            agent_id: None,
            nats_account: None,
            subject_prefix: None,
            require_signed_approval_responses: default_require_signed_approval_responses(),
            approval_response_trusted_issuer: None,
        }
    }
}
