use super::super::super::{
    actor::{EndpointDecisionActor, EndpointPolicySnapshot},
    detection::DetectionSeverity,
    sensor_state::EndpointSensorState,
};
pub struct EndpointPolicyDecisionReceiptInput<'a> {
    pub local_sequence: u64,
    pub signer_identity: &'a str,
    pub actor: EndpointDecisionActor,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub action_type: &'a str,
    pub target: &'a str,
    pub allowed: bool,
    pub guard: Option<&'a str>,
    pub severity: Option<DetectionSeverity>,
    pub severity_label: Option<&'a str>,
    pub message: Option<&'a str>,
    pub details: Option<&'a serde_json::Value>,
}

