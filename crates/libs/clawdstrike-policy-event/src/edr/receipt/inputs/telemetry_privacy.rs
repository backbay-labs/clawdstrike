use super::super::super::{
    actor::EndpointPolicySnapshot,
    privacy::EndpointTelemetryPrivacyReport,
    sensor_state::EndpointSensorState,
};
pub struct EndpointTelemetryPrivacyReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub report: &'a EndpointTelemetryPrivacyReport,
}

