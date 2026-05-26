//! Daemon and provider acknowledgement / refresh DTOs.

use serde::Serialize;

use crate::edr::EndpointProviderKind;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrDaemonPolicyReloadResult {
    pub requested: bool,
    pub reloaded: bool,
    pub status_code: Option<u16>,
    pub policy_hash: Option<String>,
    pub message: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrProviderPolicyAcknowledgement {
    pub provider_id: String,
    pub provider_kind: EndpointProviderKind,
    pub active: bool,
    pub observed_policy_epoch: Option<u64>,
    pub expected_policy_epoch: u64,
    pub policy_epoch_matches: Option<bool>,
    pub policy_synced: Option<bool>,
    pub enforcement_ready: Option<bool>,
    pub acknowledged: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrProviderAcknowledgementPoll {
    pub requested: bool,
    pub timeout_ms: u64,
    pub elapsed_ms: u64,
    pub attempts: u64,
    pub satisfied: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrProviderStatusRefreshResult {
    pub requested: bool,
    pub refreshed: bool,
    pub timeout_ms: u64,
    pub elapsed_ms: u64,
    pub error: Option<String>,
}
