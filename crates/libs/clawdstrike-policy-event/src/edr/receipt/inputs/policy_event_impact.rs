use super::super::super::{actor::EndpointPolicySnapshot, sensor_state::EndpointSensorState};
pub struct EndpointPolicyEventImpactReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub impact_id: &'a str,
    pub event_source: &'a str,
    pub event_stream_hash: &'a str,
    pub current_result_hash: &'a str,
    pub proposed_result_hash: &'a str,
    pub impact_hash: &'a str,
    pub proposed_policy_hash: &'a str,
    pub proposed_policy_epoch: u64,
    pub event_count: u64,
    pub changed_count: u64,
    pub allow_to_block_count: u64,
    pub track_posture: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct EndpointPolicyEventImpactIdInput<'a> {
    pub current_policy_hash: &'a str,
    pub current_policy_epoch: u64,
    pub proposed_policy_hash: &'a str,
    pub proposed_policy_epoch: u64,
    pub event_source: &'a str,
    pub event_stream_hash: &'a str,
    pub current_result_hash: &'a str,
    pub proposed_result_hash: &'a str,
    pub impact_hash: &'a str,
    pub event_count: u64,
    pub changed_count: u64,
    pub allow_to_block_count: u64,
    pub track_posture: bool,
}
