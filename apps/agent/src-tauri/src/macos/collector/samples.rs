//! Wire-format types decoded from the macOS system-extension status helpers.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::macos::status::{
    EvidenceArtifact, ProviderAttestationState, ProviderReloadObservation, ProviderStatus,
    SystemExtensionApproval, SystemExtensionInstallState,
};

#[derive(Debug, Deserialize)]
pub(super) struct EndpointSecurityStatusSample {
    pub(super) host_status: EndpointSecurityHostStatus,
    #[serde(default)]
    pub(super) provider_state: Option<ProviderAttestationState>,
    #[serde(default)]
    pub(super) counters: BTreeMap<String, u64>,
    #[serde(default)]
    pub(super) evidence_paths: Vec<EvidenceArtifact>,
    #[serde(default)]
    pub(super) policy_epoch: Option<u64>,
    #[serde(default)]
    pub(super) last_error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct EndpointSecurityHostStatus {
    pub(super) install_state: SystemExtensionInstallState,
    pub(super) approval: SystemExtensionApproval,
    pub(super) endpoint_security: ProviderStatus,
}

#[derive(Debug, Deserialize)]
pub(super) struct NetworkExtensionStatusSample {
    pub(super) install_state: SystemExtensionInstallState,
    pub(super) approval: SystemExtensionApproval,
    pub(super) host_status: ProviderStatus,
    #[serde(default, rename = "attestation_state")]
    pub(super) provider_state: Option<ProviderAttestationState>,
    #[serde(default)]
    pub(super) counters: BTreeMap<String, u64>,
    #[serde(default)]
    pub(super) evidence_paths: Vec<EvidenceArtifact>,
    #[serde(default)]
    pub(super) policy_epoch: Option<u64>,
    #[serde(default)]
    pub(super) policy_synced: Option<bool>,
    #[serde(default)]
    pub(super) enforcement_ready: Option<bool>,
    #[serde(default)]
    pub(super) last_error: Option<String>,
    #[serde(default)]
    pub(super) last_reload_observation: Option<ProviderReloadObservation>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct NetworkExtensionReloadToolResponse {
    pub(super) request_id: String,
    pub(super) command: String,
    pub(super) policy_snapshot_path: String,
    pub(super) generation: u64,
    pub(super) saved: bool,
}

pub(super) struct ProviderStatusEnrichment {
    pub(super) provider_state: Option<ProviderAttestationState>,
    pub(super) counters: BTreeMap<String, u64>,
    pub(super) evidence_paths: Vec<EvidenceArtifact>,
    pub(super) policy_epoch: Option<u64>,
    pub(super) policy_synced: Option<bool>,
    pub(super) enforcement_ready: Option<bool>,
    pub(super) last_error: Option<String>,
    pub(super) last_reload_observation: Option<ProviderReloadObservation>,
}
