use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const MACOS_STATUS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemExtensionInstallState {
    #[default]
    Unknown,
    NotInstalled,
    Installed,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemExtensionApproval {
    #[default]
    Unknown,
    Approved,
    ApprovalBlocked,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemExtensionActivationState {
    #[default]
    Unknown,
    NotRequested,
    Pending,
    Active,
    Failed,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MdmProfileState {
    #[default]
    Unknown,
    Missing,
    Installed,
    Stale,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProviderRuntimeState {
    #[default]
    Unknown,
    Inactive,
    Active,
    Degraded { reason: String },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderApprovalStatus {
    NotRequired,
    Approved,
    Blocked,
    Missing,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderAvailability {
    #[default]
    Unavailable,
    Inactive,
    Active,
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProviderAttestationState {
    pub provider: String,
    pub installed: bool,
    pub approval_status: ProviderApprovalStatus,
    pub active: bool,
    pub healthy: bool,
    pub availability: ProviderAvailability,
    pub degraded_reasons: Vec<String>,
    pub last_healthy_timestamp: Option<String>,
}

impl Default for ProviderAttestationState {
    fn default() -> Self {
        Self {
            provider: "unknown".to_string(),
            installed: false,
            approval_status: ProviderApprovalStatus::Unknown,
            active: false,
            healthy: false,
            availability: ProviderAvailability::Unavailable,
            degraded_reasons: Vec::new(),
            last_healthy_timestamp: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceArtifact {
    pub kind: String,
    pub path: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProviderStatus {
    pub runtime: ProviderRuntimeState,
    pub provider_state: Option<ProviderAttestationState>,
    pub counters: BTreeMap<String, u64>,
    pub policy_epoch: Option<u64>,
    pub last_healthy_timestamp: Option<String>,
    pub last_error: Option<String>,
    pub evidence_paths: Vec<EvidenceArtifact>,
}

impl Default for ProviderStatus {
    fn default() -> Self {
        Self::unknown()
    }
}

impl ProviderStatus {
    pub fn unknown() -> Self {
        Self {
            runtime: ProviderRuntimeState::Unknown,
            provider_state: None,
            counters: BTreeMap::new(),
            policy_epoch: None,
            last_healthy_timestamp: None,
            last_error: None,
            evidence_paths: Vec::new(),
        }
    }

    #[cfg(test)]
    pub fn inactive() -> Self {
        Self {
            runtime: ProviderRuntimeState::Inactive,
            ..Self::unknown()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CombinedSystemExtensionStatus {
    pub schema_version: u32,
    pub install_state: SystemExtensionInstallState,
    pub approval: SystemExtensionApproval,
    pub activation_state: SystemExtensionActivationState,
    pub mdm_profile_state: MdmProfileState,
    pub endpoint_security: ProviderStatus,
    pub network_extension: ProviderStatus,
}

impl Default for CombinedSystemExtensionStatus {
    fn default() -> Self {
        Self {
            schema_version: MACOS_STATUS_SCHEMA_VERSION,
            install_state: SystemExtensionInstallState::Unknown,
            approval: SystemExtensionApproval::Unknown,
            activation_state: SystemExtensionActivationState::Unknown,
            mdm_profile_state: MdmProfileState::Unknown,
            endpoint_security: ProviderStatus::unknown(),
            network_extension: ProviderStatus::unknown(),
        }
    }
}

#[cfg(test)]
impl CombinedSystemExtensionStatus {
    pub fn is_degraded(&self) -> bool {
        matches!(
            self.endpoint_security.runtime,
            ProviderRuntimeState::Degraded { .. }
        ) || matches!(
            self.network_extension.runtime,
            ProviderRuntimeState::Degraded { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn default_status_starts_unknown() {
        let status = CombinedSystemExtensionStatus::default();

        assert_eq!(status.schema_version, MACOS_STATUS_SCHEMA_VERSION);
        assert_eq!(status.install_state, SystemExtensionInstallState::Unknown);
        assert_eq!(status.approval, SystemExtensionApproval::Unknown);
        assert_eq!(
            status.activation_state,
            SystemExtensionActivationState::Unknown
        );
        assert_eq!(status.mdm_profile_state, MdmProfileState::Unknown);
        assert_eq!(status.endpoint_security, ProviderStatus::unknown());
        assert_eq!(status.network_extension, ProviderStatus::unknown());
        assert!(!status.is_degraded());
    }

    #[test]
    fn degraded_state_is_detected_from_either_provider() {
        let status = CombinedSystemExtensionStatus {
            endpoint_security: ProviderStatus {
                runtime: ProviderRuntimeState::Degraded {
                    reason: "approval blocked".to_string(),
                },
                ..ProviderStatus::unknown()
            },
            ..CombinedSystemExtensionStatus::default()
        };

        assert!(status.is_degraded());
    }

    #[test]
    fn status_serializes_explicit_host_readout_states() {
        let status = CombinedSystemExtensionStatus {
            install_state: SystemExtensionInstallState::Installed,
            approval: SystemExtensionApproval::ApprovalBlocked,
            activation_state: SystemExtensionActivationState::Failed,
            mdm_profile_state: MdmProfileState::Missing,
            endpoint_security: ProviderStatus::inactive(),
            network_extension: ProviderStatus {
                runtime: ProviderRuntimeState::Degraded {
                    reason: "provider handshake stalled".to_string(),
                },
                policy_epoch: Some(7),
                last_error: Some("provider handshake stalled".to_string()),
                evidence_paths: vec![EvidenceArtifact {
                    kind: "activation".to_string(),
                    path: "fixtures/macos/network-extension/content-filter-provider-unavailable.json"
                        .to_string(),
                    detail: "provider failed to activate".to_string(),
                }],
                ..ProviderStatus::unknown()
            },
            ..CombinedSystemExtensionStatus::default()
        };

        let value = match serde_json::to_value(status) {
            Ok(value) => value,
            Err(error) => panic!("status should serialize: {error}"),
        };

        assert_eq!(
            value,
            json!({
                "schema_version": 1,
                "install_state": "installed",
                "approval": "approval_blocked",
                "activation_state": "failed",
                "mdm_profile_state": "missing",
                "endpoint_security": {
                    "runtime": {
                        "state": "inactive"
                    },
                    "provider_state": null,
                    "counters": {},
                    "policy_epoch": null,
                    "last_healthy_timestamp": null,
                    "last_error": null,
                    "evidence_paths": []
                },
                "network_extension": {
                    "runtime": {
                        "state": "degraded",
                        "reason": "provider handshake stalled"
                    },
                    "provider_state": null,
                    "counters": {},
                    "policy_epoch": 7,
                    "last_healthy_timestamp": null,
                    "last_error": "provider handshake stalled",
                    "evidence_paths": [{
                        "kind": "activation",
                        "path": "fixtures/macos/network-extension/content-filter-provider-unavailable.json",
                        "detail": "provider failed to activate"
                    }]
                }
            })
        );
    }

    #[test]
    fn legacy_status_without_new_fields_still_deserializes() {
        let parsed_result: Result<CombinedSystemExtensionStatus, _> = serde_json::from_value(json!({
            "install_state": "installed",
            "approval": "approved",
            "endpoint_security": {
                "runtime": {
                    "state": "active"
                }
            },
            "network_extension": {
                "runtime": {
                    "state": "unknown"
                }
            }
        }));
        let parsed = match parsed_result {
            Ok(parsed) => parsed,
            Err(error) => panic!("legacy status should deserialize: {error}"),
        };

        assert_eq!(parsed.schema_version, MACOS_STATUS_SCHEMA_VERSION);
        assert_eq!(
            parsed.activation_state,
            SystemExtensionActivationState::Unknown
        );
        assert_eq!(parsed.mdm_profile_state, MdmProfileState::Unknown);
        assert_eq!(parsed.endpoint_security.counters.len(), 0);
    }
}
