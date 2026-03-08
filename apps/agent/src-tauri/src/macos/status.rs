use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemExtensionInstallState {
    Unknown,
    NotInstalled,
    Installed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemExtensionApproval {
    Unknown,
    Approved,
    ApprovalBlocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProviderRuntimeState {
    Unknown,
    Inactive,
    Active,
    Degraded { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderStatus {
    pub runtime: ProviderRuntimeState,
}

impl ProviderStatus {
    pub fn unknown() -> Self {
        Self {
            runtime: ProviderRuntimeState::Unknown,
        }
    }

    #[cfg(test)]
    pub fn inactive() -> Self {
        Self {
            runtime: ProviderRuntimeState::Inactive,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CombinedSystemExtensionStatus {
    pub install_state: SystemExtensionInstallState,
    pub approval: SystemExtensionApproval,
    pub endpoint_security: ProviderStatus,
    pub network_extension: ProviderStatus,
}

impl Default for CombinedSystemExtensionStatus {
    fn default() -> Self {
        Self {
            install_state: SystemExtensionInstallState::Unknown,
            approval: SystemExtensionApproval::Unknown,
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

        assert_eq!(status.install_state, SystemExtensionInstallState::Unknown);
        assert_eq!(status.approval, SystemExtensionApproval::Unknown);
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
            endpoint_security: ProviderStatus::inactive(),
            network_extension: ProviderStatus {
                runtime: ProviderRuntimeState::Degraded {
                    reason: "provider handshake stalled".to_string(),
                },
            },
        };

        let value = match serde_json::to_value(status) {
            Ok(value) => value,
            Err(error) => panic!("status should serialize: {error}"),
        };

        assert_eq!(
            value,
            json!({
                "install_state": "installed",
                "approval": "approval_blocked",
                "endpoint_security": {
                    "runtime": {
                        "state": "inactive"
                    }
                },
                "network_extension": {
                    "runtime": {
                        "state": "degraded",
                        "reason": "provider handshake stalled"
                    }
                }
            })
        );
    }
}
