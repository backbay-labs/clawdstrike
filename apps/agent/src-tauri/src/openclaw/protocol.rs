//! OpenClaw gateway protocol frame types.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum GatewayFrame {
    Req(GatewayRequestFrame),
    Res(GatewayResponseFrame),
    Event(GatewayEventFrame),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayRequestFrame {
    pub id: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayResponseFrame {
    pub id: String,
    pub ok: bool,
    #[serde(default)]
    pub payload: Option<Value>,
    #[serde(default)]
    pub error: Option<GatewayResponseError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayResponseError {
    #[serde(default)]
    pub code: Option<String>,
    pub message: String,
    #[serde(default)]
    pub details: Option<Value>,
    #[serde(default)]
    pub retryable: Option<bool>,
    #[serde(default)]
    pub retry_after_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayEventFrame {
    pub event: String,
    #[serde(default)]
    pub payload: Option<Value>,
    #[serde(default)]
    pub seq: Option<i64>,
    #[serde(default)]
    pub state_version: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayConnectParams {
    pub min_protocol: u32,
    pub max_protocol: u32,
    pub client: GatewayClientIdentity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<GatewayAuth>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<GatewayDeviceProof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayClientIdentity {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayAuth {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayDeviceProof {
    pub id: String,
    pub public_key: String,
    pub signature: String,
    pub signed_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

pub fn create_request_id(prefix: &str) -> String {
    format!("{}:{}", prefix, uuid::Uuid::new_v4())
}

pub fn parse_gateway_frame(text: &str) -> Option<GatewayFrame> {
    match serde_json::from_str::<GatewayFrame>(text) {
        Ok(frame) => Some(frame),
        Err(err) => {
            tracing::warn!(error = %err, "failed to parse gateway frame");
            None
        }
    }
}
