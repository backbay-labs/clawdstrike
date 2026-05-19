use super::super::super::{
    actor::EndpointPolicySnapshot,
    causal::CausalGraph,
    sensor_state::EndpointSensorState,
    simulation::EndpointPolicySimulationReport,
};
pub struct EndpointSimulationReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub simulation: &'a EndpointPolicySimulationReport,
    pub graph: &'a CausalGraph,
}

