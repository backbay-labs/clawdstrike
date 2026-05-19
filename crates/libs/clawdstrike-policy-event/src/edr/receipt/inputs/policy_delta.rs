use super::super::super::{
    action::EndpointDecisionAction, actor::EndpointPolicySnapshot,
    sensor_state::EndpointSensorState,
};
pub struct EndpointPolicyDeltaReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub operation: &'a str,
    pub policy_delta_id: &'a str,
    pub staged_detection_id: &'a str,
    pub rule_id: &'a str,
    pub stage: &'a str,
    pub generated_at: &'a str,
    pub action: EndpointDecisionAction,
    pub artifact_hash: &'a str,
    pub simulation_id: &'a str,
    pub graph_slice_id: &'a str,
    pub root_node_id: &'a str,
    pub source_affected_identity_context: &'a str,
    pub source_affected_tool_context: &'a str,
    pub cross_window_impact_hash: Option<&'a str>,
    pub cross_window_recommendation_hash: Option<&'a str>,
    pub previous_policy_hash: Option<&'a str>,
    pub new_policy_hash: Option<&'a str>,
    pub backup_path: Option<&'a str>,
}

#[derive(Clone, Copy, Debug)]
pub struct EndpointPolicyDeltaIdInput<'a> {
    pub endpoint_id: &'a str,
    pub rule_id: &'a str,
    pub action: &'a EndpointDecisionAction,
    pub staged_detection_id: &'a str,
    pub stage: &'a str,
    pub generated_at: &'a str,
    pub simulation_id: &'a str,
    pub graph_slice_id: &'a str,
    pub root_node_id: &'a str,
    pub source_affected_identity_context: &'a str,
    pub source_affected_tool_context: &'a str,
}
