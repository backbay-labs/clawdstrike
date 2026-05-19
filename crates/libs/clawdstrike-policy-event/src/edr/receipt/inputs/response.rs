use super::super::super::{
    actor::{EndpointDecisionActor, EndpointPolicySnapshot},
    causal::CausalGraph,
    receipt::evidence::EndpointEvidenceBundleReference,
    response::{
        EndpointResponseAcknowledgementReport, EndpointResponseControlCorrelation,
        EndpointResponseExecutionReport, EndpointResponsePlan, EndpointResponseRollbackReport,
    },
    sensor_state::EndpointSensorState,
};
pub struct EndpointResponseReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub actor: EndpointDecisionActor,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub plan: &'a EndpointResponsePlan,
    pub graph: &'a CausalGraph,
}

pub struct EndpointResponseExecutionReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub actor: EndpointDecisionActor,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub execution: &'a EndpointResponseExecutionReport,
    pub graph: &'a CausalGraph,
}

pub struct EndpointResponseRollbackReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub actor: EndpointDecisionActor,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub rollback: &'a EndpointResponseRollbackReport,
    pub graph: &'a CausalGraph,
}

pub struct EndpointResponseAcknowledgementReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub actor: EndpointDecisionActor,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub acknowledgement: &'a EndpointResponseAcknowledgementReport,
    pub graph: &'a CausalGraph,
}
