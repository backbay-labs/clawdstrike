//! SIEM, webhook, and other integration settings.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemIntegrationSettings {
    #[serde(default = "default_siem_provider")]
    pub provider: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub enabled: bool,
}

impl Default for SiemIntegrationSettings {
    fn default() -> Self {
        Self {
            provider: default_siem_provider(),
            endpoint: String::new(),
            api_key: String::new(),
            enabled: false,
        }
    }
}

fn default_siem_provider() -> String {
    "datadog".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WebhookIntegrationSettings {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntegrationSettings {
    #[serde(default)]
    pub siem: SiemIntegrationSettings,
    #[serde(default)]
    pub webhooks: WebhookIntegrationSettings,
}
