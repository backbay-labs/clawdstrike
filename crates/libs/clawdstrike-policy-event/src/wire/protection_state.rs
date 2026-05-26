//! Protection state and provider recovery DTOs.

use serde::Serialize;

use crate::edr::{EndpointPolicySnapshot, EndpointProviderKind, EndpointSensorState};
use hush_core::SignedReceipt;

#[derive(Debug, Serialize)]
pub struct EdrProtectionStateResponse {
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub receipt: SignedReceipt,
    pub degraded_provider_receipts: Vec<SignedReceipt>,
    pub provider_recoveries: Vec<EdrProviderRecovery>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrProviderRecovery {
    pub provider_id: String,
    pub provider_kind: EndpointProviderKind,
    pub previous_active: bool,
    pub previous_healthy: bool,
    pub previous_degraded: bool,
    pub previous_degradation_reasons: Vec<String>,
    pub current_active: bool,
    pub current_healthy: bool,
    pub current_degraded: bool,
    pub recovered_at: Option<chrono::DateTime<chrono::Utc>>,
}
