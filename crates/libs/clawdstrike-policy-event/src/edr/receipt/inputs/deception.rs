use super::super::super::{
    actor::EndpointPolicySnapshot,
    deception::{DeceptionCleanupReport, DeceptionMaterializationReport, DeceptionPlan, DeceptionRotationReport},
    sensor_state::EndpointSensorState,
};
pub struct EndpointDeceptionMaterializationReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub plan: &'a DeceptionPlan,
    pub report: &'a DeceptionMaterializationReport,
    pub registered_artifact_count: usize,
}

pub struct EndpointDeceptionCleanupReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub plan: &'a DeceptionPlan,
    pub report: &'a DeceptionCleanupReport,
    pub deregistered_artifact_count: usize,
    pub remaining_registered_artifact_count: usize,
}

pub struct EndpointDeceptionRotationReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub old_plan: &'a DeceptionPlan,
    pub new_plan: &'a DeceptionPlan,
    pub report: &'a DeceptionRotationReport,
}

