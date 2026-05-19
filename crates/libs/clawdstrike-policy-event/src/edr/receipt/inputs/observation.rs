use super::super::super::{
    actor::EndpointPolicySnapshot,
    causal::CausalGraph,
    event::EndpointObservation,
    sensor_state::EndpointSensorState,
};
pub struct EndpointObservationReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub observation: &'a EndpointObservation,
    pub graph: &'a CausalGraph,
}

