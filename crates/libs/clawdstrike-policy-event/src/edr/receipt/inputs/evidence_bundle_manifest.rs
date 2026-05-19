use super::super::super::{
    actor::EndpointPolicySnapshot,
    causal::CausalGraph,
    receipt::evidence::EndpointEvidenceBundleReference,
    sensor_state::EndpointSensorState,
};
pub struct EndpointEvidenceBundleManifestReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub root_node_id: &'a str,
    pub bundle: &'a EndpointEvidenceBundleReference,
    pub graph: &'a CausalGraph,
}

