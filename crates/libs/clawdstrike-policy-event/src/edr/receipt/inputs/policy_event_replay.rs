use super::super::super::{actor::EndpointPolicySnapshot, sensor_state::EndpointSensorState};
pub struct EndpointPolicyEventReplayReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub replay_id: &'a str,
    pub event_source: &'a str,
    pub event_stream_hash: &'a str,
    pub result_hash: &'a str,
    pub event_count: u64,
    pub allowed_count: u64,
    pub warn_count: u64,
    pub blocked_count: u64,
    pub track_posture: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct EndpointPolicyEventReplayIdInput<'a> {
    pub policy_hash: &'a str,
    pub policy_epoch: u64,
    pub event_source: &'a str,
    pub event_stream_hash: &'a str,
    pub result_hash: &'a str,
    pub event_count: u64,
    pub allowed_count: u64,
    pub warn_count: u64,
    pub blocked_count: u64,
    pub track_posture: bool,
}
