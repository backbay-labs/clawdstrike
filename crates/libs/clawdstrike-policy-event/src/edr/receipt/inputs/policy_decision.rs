use super::super::super::{
    actor::{EndpointDecisionActor, EndpointPolicySnapshot},
    causal::graph::CausalGraph,
    detection::DetectionSeverity,
    event::EndpointObservation,
    sensor_state::EndpointSensorState,
};
pub struct EndpointPolicyDecisionReceiptInput<'a> {
    pub local_sequence: u64,
    pub signer_identity: &'a str,
    pub actor: EndpointDecisionActor,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub observation: &'a EndpointObservation,
    pub graph: &'a CausalGraph,
    pub action_type: &'a str,
    pub target: &'a str,
    pub allowed: bool,
    pub guard: Option<&'a str>,
    pub severity: Option<DetectionSeverity>,
    pub severity_label: Option<&'a str>,
    pub message: Option<&'a str>,
    pub details: Option<&'a serde_json::Value>,
}
