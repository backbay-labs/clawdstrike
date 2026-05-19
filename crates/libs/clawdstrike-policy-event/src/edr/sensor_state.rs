use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointProviderKind {
    #[default]
    AgentApi,
    EndpointSecurity,
    NetworkExtension,
    DarwinBridge,
    PolicyEngine,
    ResponseExecutor,
    Other,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointProviderState {
    pub provider_id: String,
    pub provider_kind: EndpointProviderKind,
    pub installed: bool,
    pub active: bool,
    pub healthy: bool,
    pub degraded: bool,
    pub degradation_reasons: Vec<String>,
    pub dropped_event_count: u64,
    pub deadline_miss_count: u64,
    pub full_disk_access: Option<bool>,
    pub last_seen: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointSensorState {
    pub providers: Vec<EndpointProviderState>,
}

impl EndpointSensorState {
    #[must_use]
    pub fn single_active_agent(provider_id: impl Into<String>) -> Self {
        Self {
            providers: vec![EndpointProviderState {
                provider_id: provider_id.into(),
                provider_kind: EndpointProviderKind::AgentApi,
                installed: true,
                active: true,
                healthy: true,
                degraded: false,
                degradation_reasons: Vec::new(),
                dropped_event_count: 0,
                deadline_miss_count: 0,
                full_disk_access: None,
                last_seen: Some(Utc::now()),
            }],
        }
    }
}

