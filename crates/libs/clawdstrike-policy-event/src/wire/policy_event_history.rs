//! Policy event history query and replay DTOs.
//!
//! Selectors, reports, and impact-window payloads used by the
//! `/edr/policy_events/history/*` endpoints. `matches_index_entry` impls on
//! the filter structs depend on agent-private helpers; those impls live in
//! the agent and are not extracted here.
//!
//! Deep causal-context subtypes (chains, drivers, promotion suggestions) live
//! in [`super::policy_event_history_causal`] to keep this file under the wire
//! crate's 500-line budget.

use serde::{Deserialize, Serialize};

use crate::edr::EndpointObservation;
use crate::event::PolicyEvent;
use crate::simulate::SimulationResult;
use hush_core::SignedReceipt;

use super::policy_event_history_causal::EdrPolicyEventHistoryCausalImpact;
use super::policy_events::{
    EdrPolicyEventImpactDriver, EdrPolicyEventImpactEntry, EdrPolicyEventImpactReport,
    EdrPolicyEventImpactSummary, EdrPolicyEventReplayReport,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrPolicyEventHistoryReplayInput {
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub since: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub until: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub max_age_seconds: Option<u64>,
    #[serde(default)]
    pub track_posture: Option<bool>,
    #[serde(default)]
    pub event_kinds: Vec<String>,
    #[serde(default, alias = "host_id")]
    pub host_id: Option<String>,
    #[serde(default, alias = "user_id")]
    pub user_id: Option<String>,
    #[serde(default, alias = "session_id")]
    pub session_id: Option<String>,
    #[serde(default, alias = "process_guid")]
    pub process_guid: Option<String>,
    #[serde(default, alias = "parent_process_guid")]
    pub parent_process_guid: Option<String>,
    #[serde(default, alias = "agent_id")]
    pub agent_id: Option<String>,
    #[serde(default, alias = "workload_id")]
    pub workload_id: Option<String>,
    #[serde(default, alias = "approval_id")]
    pub approval_id: Option<String>,
    #[serde(default, alias = "tool_name")]
    pub tool_name: Option<String>,
    #[serde(default, alias = "tool_call_id")]
    pub tool_call_id: Option<String>,
    #[serde(default, alias = "credential_kind")]
    pub credential_kind: Option<String>,
    #[serde(default, alias = "process_image_hash")]
    pub process_image_hash: Option<String>,
    #[serde(default, alias = "process_command_line_hash")]
    pub process_command_line_hash: Option<String>,
    #[serde(
        default,
        alias = "event_target",
        alias = "target",
        alias = "resourceTarget",
        alias = "resource_target"
    )]
    pub event_target: Option<String>,
    #[serde(
        default,
        alias = "event_target_hash",
        alias = "targetHash",
        alias = "target_hash",
        alias = "resourceTargetHash",
        alias = "resource_target_hash"
    )]
    pub event_target_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrPolicyEventHistoryImpactInput {
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub since: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub until: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub max_age_seconds: Option<u64>,
    #[serde(default)]
    pub track_posture: Option<bool>,
    #[serde(default)]
    pub event_kinds: Vec<String>,
    #[serde(default, alias = "host_id")]
    pub host_id: Option<String>,
    #[serde(default, alias = "user_id")]
    pub user_id: Option<String>,
    #[serde(default, alias = "session_id")]
    pub session_id: Option<String>,
    #[serde(default, alias = "process_guid")]
    pub process_guid: Option<String>,
    #[serde(default, alias = "parent_process_guid")]
    pub parent_process_guid: Option<String>,
    #[serde(default, alias = "agent_id")]
    pub agent_id: Option<String>,
    #[serde(default, alias = "workload_id")]
    pub workload_id: Option<String>,
    #[serde(default, alias = "approval_id")]
    pub approval_id: Option<String>,
    #[serde(default, alias = "tool_name")]
    pub tool_name: Option<String>,
    #[serde(default, alias = "tool_call_id")]
    pub tool_call_id: Option<String>,
    #[serde(default, alias = "credential_kind")]
    pub credential_kind: Option<String>,
    #[serde(default, alias = "process_image_hash")]
    pub process_image_hash: Option<String>,
    #[serde(default, alias = "process_command_line_hash")]
    pub process_command_line_hash: Option<String>,
    #[serde(
        default,
        alias = "event_target",
        alias = "target",
        alias = "resourceTarget",
        alias = "resource_target"
    )]
    pub event_target: Option<String>,
    #[serde(
        default,
        alias = "event_target_hash",
        alias = "targetHash",
        alias = "target_hash",
        alias = "resourceTargetHash",
        alias = "resource_target_hash"
    )]
    pub event_target_hash: Option<String>,
    #[serde(default)]
    pub causal_context_depth: Option<usize>,
    #[serde(default)]
    pub validation_window_seconds: Option<u64>,
    #[serde(alias = "proposedPolicyYaml")]
    pub proposed_policy_yaml: String,
}

impl EdrPolicyEventHistoryReplayInput {
    pub fn identity_filters(&self) -> EdrPolicyEventHistoryIdentityFilters {
        EdrPolicyEventHistoryIdentityFilters {
            host_id: self.host_id.clone(),
            user_id: self.user_id.clone(),
            session_id: self.session_id.clone(),
            process_guid: self.process_guid.clone(),
            parent_process_guid: self.parent_process_guid.clone(),
            agent_id: self.agent_id.clone(),
            workload_id: self.workload_id.clone(),
            approval_id: self.approval_id.clone(),
            tool_name: self.tool_name.clone(),
            tool_call_id: self.tool_call_id.clone(),
            credential_kind: self.credential_kind.clone(),
        }
    }

    pub fn process_filters(&self) -> EdrPolicyEventHistoryProcessFilters {
        EdrPolicyEventHistoryProcessFilters {
            process_image_hash: self.process_image_hash.clone(),
            process_command_line_hash: self.process_command_line_hash.clone(),
        }
    }

    pub fn target_filters(&self) -> EdrPolicyEventHistoryTargetFilters {
        EdrPolicyEventHistoryTargetFilters {
            event_target: self.event_target.clone(),
            event_target_hash: self.event_target_hash.clone(),
        }
    }
}

impl EdrPolicyEventHistoryImpactInput {
    pub fn replay_selector_input(&self) -> EdrPolicyEventHistoryReplayInput {
        EdrPolicyEventHistoryReplayInput {
            limit: self.limit,
            since: self.since,
            until: self.until,
            max_age_seconds: self.max_age_seconds,
            track_posture: self.track_posture,
            event_kinds: self.event_kinds.clone(),
            host_id: self.host_id.clone(),
            user_id: self.user_id.clone(),
            session_id: self.session_id.clone(),
            process_guid: self.process_guid.clone(),
            parent_process_guid: self.parent_process_guid.clone(),
            agent_id: self.agent_id.clone(),
            workload_id: self.workload_id.clone(),
            approval_id: self.approval_id.clone(),
            tool_name: self.tool_name.clone(),
            tool_call_id: self.tool_call_id.clone(),
            credential_kind: self.credential_kind.clone(),
            process_image_hash: self.process_image_hash.clone(),
            process_command_line_hash: self.process_command_line_hash.clone(),
            event_target: self.event_target.clone(),
            event_target_hash: self.event_target_hash.clone(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventHistoryIdentityFilters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_guid: Option<String>,
    #[serde(
        default,
        alias = "parent_process_guid",
        skip_serializing_if = "Option::is_none"
    )]
    pub parent_process_guid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    #[serde(default, alias = "tool_name", skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(
        default,
        alias = "tool_call_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub tool_call_id: Option<String>,
    #[serde(
        default,
        alias = "credential_kind",
        skip_serializing_if = "Option::is_none"
    )]
    pub credential_kind: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventHistoryProcessFilters {
    #[serde(
        default,
        alias = "process_image_hash",
        skip_serializing_if = "Option::is_none"
    )]
    pub process_image_hash: Option<String>,
    #[serde(
        default,
        alias = "process_command_line_hash",
        skip_serializing_if = "Option::is_none"
    )]
    pub process_command_line_hash: Option<String>,
}

impl EdrPolicyEventHistoryProcessFilters {
    pub fn is_empty(&self) -> bool {
        self.process_image_hash.is_none() && self.process_command_line_hash.is_none()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventHistoryTargetFilters {
    #[serde(
        default,
        alias = "event_target",
        alias = "target",
        alias = "resourceTarget",
        alias = "resource_target",
        skip_serializing_if = "Option::is_none"
    )]
    pub event_target: Option<String>,
    #[serde(
        default,
        alias = "event_target_hash",
        alias = "targetHash",
        alias = "target_hash",
        alias = "resourceTargetHash",
        alias = "resource_target_hash",
        skip_serializing_if = "Option::is_none"
    )]
    pub event_target_hash: Option<String>,
}

impl EdrPolicyEventHistoryTargetFilters {
    pub fn is_empty(&self) -> bool {
        self.event_target.is_none() && self.event_target_hash.is_none()
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventHistoryReport {
    pub source: String,
    pub projection_mode: String,
    pub selection_mode: String,
    pub path: Option<String>,
    pub index_path: Option<String>,
    pub total_observation_count: usize,
    pub matched_observation_count: usize,
    pub selected_observation_count: usize,
    pub policy_event_count: usize,
    pub limit: usize,
    pub since: Option<chrono::DateTime<chrono::Utc>>,
    pub until: Option<chrono::DateTime<chrono::Utc>>,
    pub max_age_seconds: Option<u64>,
    pub event_kinds: Vec<String>,
    pub identity_filters: EdrPolicyEventHistoryIdentityFilters,
    #[serde(skip_serializing_if = "EdrPolicyEventHistoryProcessFilters::is_empty")]
    pub process_filters: EdrPolicyEventHistoryProcessFilters,
    #[serde(skip_serializing_if = "EdrPolicyEventHistoryTargetFilters::is_empty")]
    pub target_filters: EdrPolicyEventHistoryTargetFilters,
    pub oldest_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub newest_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub event_stream_hash: String,
    pub summary: String,
}

#[derive(Debug)]
pub struct EdrPolicyEventHistorySelection {
    pub report: EdrPolicyEventHistoryReport,
    pub events: Vec<PolicyEvent>,
    pub observations: Vec<EndpointObservation>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventHistoryReplayResponse {
    pub history: EdrPolicyEventHistoryReport,
    pub replay: EdrPolicyEventReplayReport,
    pub result: SimulationResult,
    pub receipt: SignedReceipt,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventHistoryImpactResponse {
    pub history: EdrPolicyEventHistoryReport,
    pub causal_impact: EdrPolicyEventHistoryCausalImpact,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cross_window_impact: Option<EdrPolicyEventHistoryCrossWindowImpact>,
    pub impact: EdrPolicyEventImpactReport,
    pub summary: EdrPolicyEventImpactSummary,
    pub drivers: Vec<EdrPolicyEventImpactDriver>,
    pub changes: Vec<EdrPolicyEventImpactEntry>,
    pub current_result: SimulationResult,
    pub proposed_result: SimulationResult,
    pub receipt: SignedReceipt,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventHistoryCrossWindowImpact {
    pub window_seconds: u64,
    pub window_count: usize,
    pub changed_window_count: usize,
    pub blocking_window_count: usize,
    pub total_event_count: u64,
    pub total_changed_count: u64,
    pub total_blocking_change_count: u64,
    pub impact_hash: String,
    pub event_stream_hash: String,
    pub current_policy_hash: String,
    pub current_policy_epoch: u64,
    pub proposed_policy_hash: String,
    pub proposed_policy_epoch: u64,
    pub current_result_hash: String,
    pub proposed_result_hash: String,
    pub history_selector_hash: String,
    pub repeatability: String,
    pub recommended_stage: String,
    pub promotion_ready: bool,
    pub recommendation_hash: String,
    pub recommendation_reason: String,
    pub windows: Vec<EdrPolicyEventHistoryImpactWindow>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventHistoryImpactWindow {
    pub window_index: i64,
    pub window_start: chrono::DateTime<chrono::Utc>,
    pub window_end: chrono::DateTime<chrono::Utc>,
    pub event_count: u64,
    pub changed_count: u64,
    pub blocking_change_count: u64,
    pub sample_event_ids: Vec<String>,
}

#[derive(Debug, Default)]
pub struct EdrPolicyEventHistoryImpactWindowAccumulator {
    pub window_start: Option<chrono::DateTime<chrono::Utc>>,
    pub window_end: Option<chrono::DateTime<chrono::Utc>>,
    pub event_count: u64,
    pub changed_count: u64,
    pub blocking_change_count: u64,
    pub sample_event_ids: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventHistoryAffectedIdentities {
    pub hosts: Vec<EdrPolicyEventHistoryAffectedIdentity>,
    pub users: Vec<EdrPolicyEventHistoryAffectedIdentity>,
    pub sessions: Vec<EdrPolicyEventHistoryAffectedIdentity>,
    pub agents: Vec<EdrPolicyEventHistoryAffectedIdentity>,
    pub workloads: Vec<EdrPolicyEventHistoryAffectedIdentity>,
    pub approvals: Vec<EdrPolicyEventHistoryAffectedIdentity>,
}

impl EdrPolicyEventHistoryAffectedIdentities {
    pub fn count(&self) -> usize {
        self.hosts.len()
            + self.users.len()
            + self.sessions.len()
            + self.agents.len()
            + self.workloads.len()
            + self.approvals.len()
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventHistoryAffectedIdentity {
    pub node_id: String,
    pub label: String,
    pub id: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventHistoryAffectedTool {
    pub node_id: String,
    pub label: String,
    pub tool_name: String,
}
