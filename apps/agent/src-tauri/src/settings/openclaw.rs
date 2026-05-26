//! OpenClaw gateway settings.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenClawGatewayMetadata {
    pub id: String,
    pub label: String,
    pub gateway_url: String,
    #[serde(default)]
    pub pinned_ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OpenClawSettings {
    #[serde(default)]
    pub gateways: Vec<OpenClawGatewayMetadata>,
    #[serde(default)]
    pub active_gateway_id: Option<String>,
}
