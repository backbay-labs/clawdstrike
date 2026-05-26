//! EDR API request/response DTOs.
//!
//! These types are deserialized from incoming HTTP requests and serialized
//! into outgoing HTTP responses for the endpoint decision engine API. They
//! intentionally stay close to the wire shape; conversion to/from internal
//! types happens in `edr::conversion` and the API handlers in
//! `edr::handlers`.
//!
//! The bulk of these DTOs are extracted into
//! [`clawdstrike_policy_event::wire`](clawdstrike_policy_event::wire) and
//! re-exported here so existing `use crate::edr::dto::*` paths keep working.
//! Visibility was widened from `pub(crate)` to `pub` during the extraction.
//!
//! A handful of DTOs reference agent-private types (daemon status, network
//! extension reload proofs, control postback routes, stored evidence bundles)
//! and stay here. Helpers that previously hung off wire types as `impl`
//! methods (e.g. `matches_index_entry`, `hydrate_attribution`, `from_stored`)
//! are now plain functions in this module so callers do not violate Rust's
//! orphan rule.

#![allow(dead_code)]

pub use clawdstrike_policy_event::wire::*;

use serde::Serialize;

use clawdstrike_policy_event::edr::{
    CausalGraph, EndpointFlightRecorderHistoryIndexEntry, EndpointPolicySnapshot,
    EndpointSensorState,
};
use hush_core::SignedReceipt;

use crate::api_server::{
    affected_identities_for_causal_impact, affected_tools_for_causal_impact,
    identity_filter_matches, ControlResponseAckPostbackRoute, NetworkExtensionReloadRequestProof,
    StoredEndpointEvidenceBundle,
};
use crate::daemon::DaemonStatus;
use crate::macos::status::ProviderStatus;

// ---------------------------------------------------------------------------
// Helper functions on wire DTOs that reach into agent-private helpers.
//
// These used to be `impl` methods on wire DTOs but Rust's orphan rule prevents
// extension impls in a downstream crate; refactored to free functions.
// ---------------------------------------------------------------------------

pub(crate) fn edr_policy_event_history_identity_filters_matches_index_entry(
    filters: &EdrPolicyEventHistoryIdentityFilters,
    entry: &EndpointFlightRecorderHistoryIndexEntry,
) -> bool {
    identity_filter_matches(&filters.host_id, entry.host_id.as_deref())
        && identity_filter_matches(&filters.user_id, entry.user_id.as_deref())
        && identity_filter_matches(&filters.session_id, entry.session_id.as_deref())
        && identity_filter_matches(&filters.process_guid, entry.process_guid.as_deref())
        && identity_filter_matches(
            &filters.parent_process_guid,
            entry.parent_process_guid.as_deref(),
        )
        && identity_filter_matches(&filters.agent_id, entry.agent_id.as_deref())
        && identity_filter_matches(&filters.workload_id, entry.workload_id.as_deref())
        && identity_filter_matches(&filters.approval_id, entry.approval_id.as_deref())
        && identity_filter_matches(&filters.tool_name, entry.tool_name.as_deref())
        && identity_filter_matches(&filters.tool_call_id, entry.tool_call_id.as_deref())
        && identity_filter_matches(&filters.credential_kind, entry.credential_kind.as_deref())
}

pub(crate) fn edr_policy_event_history_process_filters_matches_index_entry(
    filters: &EdrPolicyEventHistoryProcessFilters,
    entry: &EndpointFlightRecorderHistoryIndexEntry,
) -> bool {
    identity_filter_matches(&filters.process_image_hash, entry.process_image_hash.as_deref())
        && identity_filter_matches(
            &filters.process_command_line_hash,
            entry.process_command_line_hash.as_deref(),
        )
}

pub(crate) fn edr_policy_event_history_target_filters_matches_index_entry(
    filters: &EdrPolicyEventHistoryTargetFilters,
    entry: &EndpointFlightRecorderHistoryIndexEntry,
) -> bool {
    identity_filter_matches(&filters.event_target, entry.event_target.as_deref())
        && identity_filter_matches(&filters.event_target_hash, entry.event_target_hash.as_deref())
}

pub(crate) fn hydrate_response_execution_record_attribution(
    record: &mut EdrResponseExecutionRecord,
    graph: &CausalGraph,
) {
    let affected_identities = affected_identities_for_causal_impact(graph);
    let affected_identity_count = affected_identities.count();
    let affected_tools = affected_tools_for_causal_impact(graph);
    record.affected_identity_count = Some(affected_identity_count);
    record.affected_tool_count = Some(affected_tools.len());
    record.affected_identities = Some(affected_identities);
    record.affected_tools = Some(affected_tools);
}

pub(crate) fn evidence_bundle_artifact_from_stored(
    stored: &StoredEndpointEvidenceBundle,
) -> EdrEvidenceBundleArtifact {
    EdrEvidenceBundleArtifact {
        bundle_id: stored.bundle.bundle_id.clone(),
        path: stored.path.clone(),
        byte_count: stored.byte_count,
        content_hash: stored.bundle.content_hash.clone(),
    }
}

// ---------------------------------------------------------------------------
// DTOs that reference agent-private types and therefore cannot move to the
// shared wire crate.
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyDeltaApplyResponse {
    pub(crate) record: EdrPolicyDeltaApplyRecord,
    pub(crate) policy_delta: EdrPolicyDeltaRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) prepared_receipt: Option<SignedReceipt>,
    pub(crate) receipt: Option<SignedReceipt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) post_apply_enforcement: Option<EdrPolicyDeltaApplyEnforcementProof>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyDeltaApplyEnforcementProof {
    pub(crate) policy_synced_to_disk: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cross_window_impact_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cross_window_recommendation_hash: Option<String>,
    pub(crate) local_policy: EndpointPolicySnapshot,
    pub(crate) daemon_policy_reload: EdrDaemonPolicyReloadResult,
    pub(crate) network_extension_policy_reload: NetworkExtensionReloadRequestProof,
    pub(crate) provider_status_refresh: EdrProviderStatusRefreshResult,
    pub(crate) provider_acknowledgement_poll: EdrProviderAcknowledgementPoll,
    pub(crate) provider_policy_acknowledgements: Vec<EdrProviderPolicyAcknowledgement>,
    pub(crate) daemon_restart_requested: bool,
    pub(crate) daemon_restarted: bool,
    pub(crate) daemon_restart_error: Option<String>,
    pub(crate) daemon: DaemonStatus,
    pub(crate) daemon_policy_version: Option<String>,
    pub(crate) sensor_state: EndpointSensorState,
    pub(crate) receipt: SignedReceipt,
    pub(crate) degraded_provider_receipts: Vec<SignedReceipt>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrNetworkExtensionEgressPolicyProofResponse {
    pub(crate) provider_policy_path: String,
    pub(crate) snapshot_present: bool,
    pub(crate) snapshot_decodable: bool,
    pub(crate) snapshot_hash: Option<String>,
    pub(crate) generated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub(crate) restriction_count: usize,
    pub(crate) active_restriction_count: usize,
    pub(crate) expired_restriction_count: usize,
    pub(crate) enforcement_ready: bool,
    pub(crate) live_enforcement_proven: bool,
    pub(crate) live_enforcement_proof_reasons: Vec<String>,
    pub(crate) flow_counter_observed: bool,
    pub(crate) observed_flow_count: u64,
    pub(crate) blocked_flow_count: u64,
    pub(crate) remediation_request_count: u64,
    pub(crate) dropped_verdict_count: u64,
    pub(crate) provider_reload_observed: bool,
    pub(crate) provider_reload_request_id: Option<String>,
    pub(crate) provider_reload_generation: Option<u64>,
    pub(crate) provider_reload_policy_snapshot_path: Option<String>,
    pub(crate) provider_reload_accepted: Option<bool>,
    pub(crate) provider_reload_reloaded: Option<bool>,
    pub(crate) provider_reload_error: Option<String>,
    pub(crate) provider_reload_delivery: Option<EdrNetworkExtensionReloadDeliveryProof>,
    pub(crate) read_error: Option<String>,
    pub(crate) provider_status_refresh: EdrProviderStatusRefreshResult,
    pub(crate) network_extension_provider: ProviderStatus,
    pub(crate) sensor_state: EndpointSensorState,
    pub(crate) receipt: SignedReceipt,
    pub(crate) degraded_provider_receipts: Vec<SignedReceipt>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrControlAckPostbackRetryResponse {
    pub(crate) path: Option<String>,
    pub(crate) attempted: usize,
    pub(crate) delivered: usize,
    pub(crate) failed: usize,
    pub(crate) skipped: usize,
    pub(crate) pending: usize,
    pub(crate) attempts: Vec<EdrControlAckPostbackRetryAttemptRecord>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrControlAckPostbackRetryAttemptRecord {
    pub(crate) retry_id: String,
    pub(crate) response_action_id: String,
    pub(crate) control_api_url: String,
    pub(crate) route: ControlResponseAckPostbackRoute,
    pub(crate) delivered: bool,
    pub(crate) attempt_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) next_attempt_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) http_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) response_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) error_hash: Option<String>,
}
