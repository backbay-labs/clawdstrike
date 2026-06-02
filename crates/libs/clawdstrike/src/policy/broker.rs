//! Broker egress policy schema (`broker:` block).

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BrokerMethod {
    GET,
    POST,
    PUT,
    PATCH,
    DELETE,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub providers: Vec<BrokerProviderPolicy>,
}

impl BrokerConfig {
    pub fn merge_with(&self, child: &Self) -> Self {
        let mut providers = self.providers.clone();
        for child_provider in &child.providers {
            if let Some(position) = providers
                .iter()
                .position(|provider| provider.name == child_provider.name)
            {
                providers[position] = child_provider.clone();
            } else {
                providers.push(child_provider.clone());
            }
        }

        Self {
            enabled: child.enabled,
            providers,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerProviderPolicy {
    pub name: String,
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default)]
    pub exact_paths: Vec<String>,
    #[serde(default)]
    pub methods: Vec<BrokerMethod>,
    pub secret_ref: String,
    #[serde(default)]
    pub allowed_headers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_body_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_body_sha256: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_response: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_intent_preview: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_executions: Option<u32>,
    #[serde(default)]
    pub approval_required_risk_levels: Vec<String>,
    #[serde(default)]
    pub approval_required_data_classes: Vec<String>,
}
