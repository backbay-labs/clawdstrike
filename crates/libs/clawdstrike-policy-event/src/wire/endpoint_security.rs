//! Endpoint Security (ES) system extension event DTOs.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::edr::{
    DetectionFinding, EndpointObservation, EndpointProcess, HoneyArtifact,
};
use hush_core::SignedReceipt;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrEndpointSecurityEventsInput {
    #[serde(default)]
    pub events: Vec<EdrEndpointSecurityEvent>,
    #[serde(default, alias = "honey_artifacts")]
    pub honey_artifacts: Vec<HoneyArtifact>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrEndpointSecurityEvent {
    #[serde(default, alias = "id", alias = "eventId")]
    pub event_id: Option<String>,
    pub kind: EdrEndpointSecurityEventKind,
    #[serde(default, alias = "observedAt", alias = "timestamp")]
    pub observed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, alias = "hostId")]
    pub host_id: Option<String>,
    #[serde(default, alias = "userId")]
    pub user_id: Option<String>,
    #[serde(default, alias = "sessionId")]
    pub session_id: Option<String>,
    #[serde(default)]
    pub process: Option<EndpointProcess>,
    #[serde(default)]
    pub metadata: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub ppid: Option<u32>,
    #[serde(default, alias = "processGuid")]
    pub process_guid: Option<String>,
    #[serde(default, alias = "parentProcessGuid")]
    pub parent_process_guid: Option<String>,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default, alias = "commandLine")]
    pub command_line: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default, alias = "targetPath")]
    pub path: Option<String>,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default, alias = "deadlineMissed")]
    pub deadline_missed: Option<bool>,
    #[serde(default, alias = "deadlineMs")]
    pub deadline_ms: Option<u64>,
    #[serde(default, alias = "droppedEvents")]
    pub dropped_event_count: Option<u64>,
    #[serde(default, alias = "deadlineMisses")]
    pub deadline_miss_count: Option<u64>,
    #[serde(default)]
    pub full_disk_access: Option<bool>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EdrEndpointSecurityEventKind {
    ProcessExec,
    FileAccess,
    AuthOpen,
    EventLoss,
}

impl EdrEndpointSecurityEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProcessExec => "process_exec",
            Self::FileAccess => "file_access",
            Self::AuthOpen => "auth_open",
            Self::EventLoss => "event_loss",
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrEndpointSecurityEventsResponse {
    pub event_count: usize,
    pub observation_count: usize,
    pub finding_count: usize,
    pub receipt_count: usize,
    pub observations: Vec<EndpointObservation>,
    pub findings: Vec<DetectionFinding>,
    pub receipts: Vec<SignedReceipt>,
    pub observation_receipts: Vec<SignedReceipt>,
    pub policy_decision_receipts: Vec<SignedReceipt>,
    pub degraded_provider_receipts: Vec<SignedReceipt>,
}
