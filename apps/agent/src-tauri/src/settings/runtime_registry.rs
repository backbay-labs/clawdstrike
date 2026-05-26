//! Per-runtime registration entries observed by the agent.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeAgentRegistration {
    pub runtime_agent_id: String,
    pub runtime_agent_kind: String,
    pub endpoint_agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_runtime_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub first_seen_at: String,
    pub last_seen_at: String,
    #[serde(default)]
    pub policy_event_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeRegistrySettings {
    #[serde(default)]
    pub runtimes: Vec<RuntimeAgentRegistration>,
}
