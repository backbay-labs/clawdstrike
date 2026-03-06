use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleDetectionListItem {
    pub detection_id: String,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleResponseActionListItem {
    pub action_id: String,
    pub action_type: String,
    pub status: String,
    pub target_kind: String,
    pub target_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_display_name: Option<String>,
    pub requested_at: DateTime<Utc>,
    pub requested_by: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_detection_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleCounts {
    pub principals: i64,
    pub endpoint_agents: i64,
    pub runtime_agents: i64,
    pub swarms: i64,
    pub projects: i64,
    pub quarantined_principals: i64,
    pub stale_principals: i64,
    pub active_response_actions: i64,
    pub open_detections: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsolePostureSummaryItem {
    pub lifecycle_state: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleLivenessSummaryItem {
    pub liveness_state: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetConsoleOverview {
    pub tenant_id: String,
    pub generated_at: DateTime<Utc>,
    pub counts: ConsoleCounts,
    pub posture_summary: Vec<ConsolePostureSummaryItem>,
    pub liveness_summary: Vec<ConsoleLivenessSummaryItem>,
    pub recent_response_actions: Vec<ConsoleResponseActionListItem>,
    pub recent_detections: Vec<ConsoleDetectionListItem>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsolePrincipalListItem {
    pub principal_id: String,
    pub principal_type: String,
    pub display_name: String,
    pub stable_ref: String,
    pub lifecycle_state: String,
    pub liveness_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_posture: Option<String>,
    pub trust_level: String,
    pub swarm_names: Vec<String>,
    pub project_names: Vec<String>,
    pub capability_group_names: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    pub open_response_action_count: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleMembership {
    pub target_kind: String,
    pub target_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleEffectivePolicy {
    pub checksum_sha256: String,
    pub resolution_version: i64,
    pub overlays: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleActiveGrant {
    pub grant_id: String,
    pub subject_principal_id: String,
    pub expires_at: DateTime<Utc>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleRecentSession {
    pub session_id: String,
    pub started_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub posture: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsolePolicySourceAttachment {
    pub attachment_id: String,
    pub target_kind: String,
    pub target_id: String,
    pub priority: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsolePrincipalDetail {
    pub principal: ConsolePrincipalListItem,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    pub memberships: Vec<ConsoleMembership>,
    pub effective_policy: ConsoleEffectivePolicy,
    pub active_grants: Vec<ConsoleActiveGrant>,
    pub recent_sessions: Vec<ConsoleRecentSession>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiled_policy_yaml: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_attachments: Option<Vec<ConsolePolicySourceAttachment>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleTimelineEvent {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub tenant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed: Option<bool>,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConsoleGraphNodeKind {
    Principal,
    Session,
    Grant,
    Approval,
    ResponseAction,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleGraphNode {
    pub id: String,
    pub kind: ConsoleGraphNodeKind,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleGraphEdge {
    pub id: String,
    pub from: String,
    pub to: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleGraphView {
    pub root_principal_id: String,
    pub nodes: Vec<ConsoleGraphNode>,
    pub edges: Vec<ConsoleGraphEdge>,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConsoleStreamEventKind {
    PrincipalStateChanged,
    EffectivePolicyUpdated,
    ResponseActionUpdated,
    DetectionCreated,
    TimelineEvent,
    GraphUpdated,
}

impl ConsoleStreamEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrincipalStateChanged => "principal_state_changed",
            Self::EffectivePolicyUpdated => "effective_policy_updated",
            Self::ResponseActionUpdated => "response_action_updated",
            Self::DetectionCreated => "detection_created",
            Self::TimelineEvent => "timeline_event",
            Self::GraphUpdated => "graph_updated",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleStreamEvent {
    pub id: String,
    pub kind: ConsoleStreamEventKind,
    pub tenant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_action_id: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub payload: Value,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ConsolePrincipalListQuery {
    pub q: Option<String>,
    pub lifecycle_state: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ConsoleTimelineQuery {
    pub principal_id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ConsoleResponseActionListQuery {
    pub status: Option<String>,
    pub target_kind: Option<String>,
    pub limit: Option<u32>,
}
