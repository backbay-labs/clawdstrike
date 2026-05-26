//! Public-facing OpenClaw gateway DTOs.

use super::protocol::GatewayEventFrame;
use super::secret_store::SecretStoreMode;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GatewayConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayRuntimeSnapshot {
    pub status: GatewayConnectionStatus,
    pub last_error: Option<String>,
    pub connected_at_ms: Option<u64>,
    pub last_message_at_ms: Option<u64>,
    #[serde(default)]
    pub presence: Vec<Value>,
    #[serde(default)]
    pub nodes: Vec<Value>,
    #[serde(default)]
    pub devices: Option<Value>,
    #[serde(default)]
    pub exec_approval_queue: Vec<Value>,
}

impl Default for GatewayRuntimeSnapshot {
    fn default() -> Self {
        Self {
            status: GatewayConnectionStatus::Disconnected,
            last_error: None,
            connected_at_ms: None,
            last_message_at_ms: None,
            presence: Vec::new(),
            nodes: Vec::new(),
            devices: None,
            exec_approval_queue: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayView {
    pub id: String,
    pub label: String,
    pub gateway_url: String,
    pub has_token: bool,
    pub has_device_token: bool,
    pub runtime: GatewayRuntimeSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayListResponse {
    pub active_gateway_id: Option<String>,
    pub gateways: Vec<GatewayView>,
    pub secret_store_mode: SecretStoreMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayUpsertRequest {
    pub id: Option<String>,
    pub label: String,
    pub gateway_url: String,
    pub token: Option<String>,
    pub device_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportGatewayRequest {
    pub gateways: Vec<GatewayUpsertRequest>,
    pub active_gateway_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportGatewayResponse {
    pub imported: usize,
    pub skipped: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayRequestInput {
    pub gateway_id: String,
    pub method: String,
    pub params: Option<Value>,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayDiscoverInput {
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OpenClawAgentEvent {
    Status {
        gateway_id: String,
        runtime: GatewayRuntimeSnapshot,
    },
    GatewayEvent {
        gateway_id: String,
        frame: GatewayEventFrame,
    },
}
