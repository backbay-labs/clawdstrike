use super::super::super::{
    actor::EndpointPolicySnapshot, causal::CausalGraph, sensor_state::EndpointSensorState,
};
pub struct EndpointGraphSliceReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub root_node_id: &'a str,
    pub slice_kind: &'a str,
    pub graph: &'a CausalGraph,
}
