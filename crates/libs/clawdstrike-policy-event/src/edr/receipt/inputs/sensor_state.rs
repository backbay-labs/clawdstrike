use super::super::super::{actor::EndpointPolicySnapshot, sensor_state::EndpointSensorState};
pub struct EndpointSensorStateReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub reason: &'a str,
}
