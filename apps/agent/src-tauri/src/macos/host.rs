use tokio::sync::RwLock;

use super::status::CombinedSystemExtensionStatus;

#[derive(Debug, Default)]
pub struct MacosHostService {
    status: RwLock<CombinedSystemExtensionStatus>,
}

impl MacosHostService {
    pub fn new() -> Self {
        Self {
            status: RwLock::new(CombinedSystemExtensionStatus::default()),
        }
    }

    pub async fn snapshot(&self) -> CombinedSystemExtensionStatus {
        self.status.read().await.clone()
    }

    pub async fn reset_unknown_state(&self) {
        self.replace_status(CombinedSystemExtensionStatus::default())
            .await;
    }

    pub async fn bootstrap_placeholder_state(&self) {
        self.reset_unknown_state().await;
    }

    pub(crate) async fn replace_status(&self, status: CombinedSystemExtensionStatus) {
        *self.status.write().await = status;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos::status::{
        ProviderRuntimeState, ProviderStatus, SystemExtensionApproval, SystemExtensionInstallState,
    };

    #[tokio::test]
    async fn service_exposes_default_snapshot() {
        let service = MacosHostService::new();
        service.bootstrap_placeholder_state().await;

        assert_eq!(
            service.snapshot().await,
            CombinedSystemExtensionStatus::default()
        );
    }

    #[tokio::test]
    async fn service_updates_status_transitions() {
        let service = MacosHostService::new();
        service.bootstrap_placeholder_state().await;

        service
            .replace_status(CombinedSystemExtensionStatus {
                install_state: SystemExtensionInstallState::Installed,
                approval: SystemExtensionApproval::ApprovalBlocked,
                endpoint_security: ProviderStatus {
                    runtime: ProviderRuntimeState::Degraded {
                        reason: "missing full disk access".to_string(),
                    },
                },
                network_extension: ProviderStatus {
                    runtime: ProviderRuntimeState::Active,
                },
            })
            .await;

        let snapshot = service.snapshot().await;
        assert_eq!(
            snapshot.install_state,
            SystemExtensionInstallState::Installed
        );
        assert_eq!(snapshot.approval, SystemExtensionApproval::ApprovalBlocked);
        assert_eq!(
            snapshot.endpoint_security,
            ProviderStatus {
                runtime: ProviderRuntimeState::Degraded {
                    reason: "missing full disk access".to_string(),
                },
            }
        );
        assert_eq!(
            snapshot.network_extension,
            ProviderStatus {
                runtime: ProviderRuntimeState::Active,
            }
        );
        assert!(snapshot.is_degraded());
    }
}
