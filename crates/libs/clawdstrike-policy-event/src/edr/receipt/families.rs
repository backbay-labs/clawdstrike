use serde::{Deserialize, Serialize};

pub const ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION: &str = "clawdstrike.endpoint_decision.v1";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointDecisionReceiptFamily {
    SensorState,
    ProviderDegradation,
    Observation,
    PolicyDecision,
    PolicyDelta,
    GraphSlice,
    #[default]
    Detection,
    Simulation,
    ResponseRequest,
    ResponseExecution,
    ResponseRollback,
    ResponseAcknowledgement,
    DeceptionMaterialization,
    DeceptionCleanup,
    DeceptionRotation,
    EvidenceBundleManifest,
    PrivacyReport,
}
