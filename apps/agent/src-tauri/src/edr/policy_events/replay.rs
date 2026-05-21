//! Pure helpers for policy event replay report construction.

use crate::edr::dto::EdrPolicyEventReplayReport;
use clawdstrike_policy_event::edr::{
    endpoint_policy_event_replay_id, EndpointPolicyEventReplayIdInput, EndpointPolicySnapshot,
};
use clawdstrike_policy_event::simulate::SimulationResult;

pub(crate) fn build_policy_event_replay_report(
    policy: EndpointPolicySnapshot,
    source: &str,
    event_count: usize,
    track_posture: bool,
    event_stream_hash: String,
    result_hash: String,
    result: &SimulationResult,
) -> EdrPolicyEventReplayReport {
    let replay_id = endpoint_policy_event_replay_id(EndpointPolicyEventReplayIdInput {
        policy_hash: policy.policy_hash.as_str(),
        policy_epoch: policy.policy_epoch,
        event_source: source,
        event_stream_hash: event_stream_hash.as_str(),
        result_hash: result_hash.as_str(),
        event_count: event_count as u64,
        allowed_count: result.summary.allowed,
        warn_count: result.summary.warn,
        blocked_count: result.summary.blocked,
        track_posture,
    });
    let summary = format!(
        "Replayed {} PolicyEvent records under current endpoint policy {} epoch {}; {} allowed, {} warned, {} blocked.",
        result.summary.total,
        policy.policy_version,
        policy.policy_epoch,
        result.summary.allowed,
        result.summary.warn,
        result.summary.blocked
    );

    EdrPolicyEventReplayReport {
        replay_id,
        replayed_at: chrono::Utc::now(),
        mode: "current_policy_event_stream_replay".to_string(),
        source: source.to_string(),
        policy,
        event_count: event_count as u64,
        allowed_count: result.summary.allowed,
        warn_count: result.summary.warn,
        blocked_count: result.summary.blocked,
        track_posture,
        event_stream_hash,
        result_hash,
        summary,
    }
}
