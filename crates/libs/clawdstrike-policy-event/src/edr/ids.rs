use super::receipt::inputs::{
    EndpointPolicyDeltaIdInput, EndpointPolicyEventImpactIdInput, EndpointPolicyEventReplayIdInput,
};
use super::{evidence_hash_for_value, stable_id};

pub fn endpoint_policy_event_replay_id(input: EndpointPolicyEventReplayIdInput<'_>) -> String {
    let policy_epoch = input.policy_epoch.to_string();
    let event_source = evidence_hash_for_value(input.event_source);
    let event_stream_hash = evidence_hash_for_value(input.event_stream_hash);
    let result_hash = evidence_hash_for_value(input.result_hash);
    let event_count = evidence_hash_for_value(input.event_count.to_string());
    let allowed_count = evidence_hash_for_value(input.allowed_count.to_string());
    let warn_count = evidence_hash_for_value(input.warn_count.to_string());
    let blocked_count = evidence_hash_for_value(input.blocked_count.to_string());
    let track_posture = evidence_hash_for_value(input.track_posture.to_string());
    stable_id(
        "policy_event_replay",
        [
            input.policy_hash,
            policy_epoch.as_str(),
            event_source.as_str(),
            event_stream_hash.as_str(),
            result_hash.as_str(),
            event_count.as_str(),
            allowed_count.as_str(),
            warn_count.as_str(),
            blocked_count.as_str(),
            track_posture.as_str(),
        ],
    )
}

#[must_use]
pub fn endpoint_policy_event_impact_id(input: EndpointPolicyEventImpactIdInput<'_>) -> String {
    let current_policy_epoch = input.current_policy_epoch.to_string();
    let proposed_policy_epoch = evidence_hash_for_value(input.proposed_policy_epoch.to_string());
    let proposed_policy_hash = evidence_hash_for_value(input.proposed_policy_hash);
    let event_source = evidence_hash_for_value(input.event_source);
    let event_stream_hash = evidence_hash_for_value(input.event_stream_hash);
    let current_result_hash = evidence_hash_for_value(input.current_result_hash);
    let proposed_result_hash = evidence_hash_for_value(input.proposed_result_hash);
    let impact_hash = evidence_hash_for_value(input.impact_hash);
    let event_count = evidence_hash_for_value(input.event_count.to_string());
    let changed_count = evidence_hash_for_value(input.changed_count.to_string());
    let allow_to_block_count = evidence_hash_for_value(input.allow_to_block_count.to_string());
    let track_posture = evidence_hash_for_value(input.track_posture.to_string());
    stable_id(
        "policy_event_impact",
        [
            input.current_policy_hash,
            current_policy_epoch.as_str(),
            proposed_policy_hash.as_str(),
            proposed_policy_epoch.as_str(),
            event_source.as_str(),
            event_stream_hash.as_str(),
            current_result_hash.as_str(),
            proposed_result_hash.as_str(),
            impact_hash.as_str(),
            event_count.as_str(),
            changed_count.as_str(),
            allow_to_block_count.as_str(),
            track_posture.as_str(),
        ],
    )
}

#[must_use]
pub fn endpoint_policy_delta_id(input: EndpointPolicyDeltaIdInput<'_>) -> String {
    let staged_detection_id = evidence_hash_for_value(input.staged_detection_id);
    let stage = evidence_hash_for_value(input.stage);
    let generated_at = evidence_hash_for_value(input.generated_at);
    let simulation_id = evidence_hash_for_value(input.simulation_id);
    let graph_slice_id = evidence_hash_for_value(input.graph_slice_id);
    let root_node_id = evidence_hash_for_value(input.root_node_id);
    let source_affected_identity_context =
        evidence_hash_for_value(input.source_affected_identity_context);
    let source_affected_tool_context = evidence_hash_for_value(input.source_affected_tool_context);
    stable_id(
        "policy_delta",
        [
            input.endpoint_id,
            input.rule_id,
            input.action.as_str(),
            staged_detection_id.as_str(),
            stage.as_str(),
            generated_at.as_str(),
            simulation_id.as_str(),
            graph_slice_id.as_str(),
            root_node_id.as_str(),
            source_affected_identity_context.as_str(),
            source_affected_tool_context.as_str(),
        ],
    )
}
