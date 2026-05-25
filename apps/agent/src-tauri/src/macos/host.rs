use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, RwLock};

use super::status::CombinedSystemExtensionStatus;

pub(crate) type MacosHostRefreshRequest = oneshot::Sender<CombinedSystemExtensionStatus>;
pub(crate) type MacosNetworkExtensionReloadReply =
    oneshot::Sender<Result<MacosNetworkExtensionReloadResult, MacosNetworkExtensionReloadError>>;

pub(crate) struct MacosNetworkExtensionReloadRequest {
    pub policy_snapshot_path: PathBuf,
    pub generation: u64,
    pub timeout_duration: Duration,
    pub reply_tx: MacosNetworkExtensionReloadReply,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosNetworkExtensionReloadResult {
    pub requested: bool,
    pub saved: bool,
    pub request_id: String,
    pub policy_snapshot_path: String,
    pub generation: u64,
}

#[derive(Debug, Default)]
pub struct MacosHostService {
    status: RwLock<MacosHostStatusState>,
    refresh_tx: RwLock<Option<mpsc::Sender<MacosHostRefreshRequest>>>,
    network_extension_reload_tx: RwLock<Option<mpsc::Sender<MacosNetworkExtensionReloadRequest>>>,
}

#[derive(Debug, Default)]
struct MacosHostStatusState {
    current: CombinedSystemExtensionStatus,
    previous: Option<CombinedSystemExtensionStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosHostStatusTransition {
    pub previous: Option<CombinedSystemExtensionStatus>,
    pub current: CombinedSystemExtensionStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosHostRefreshError {
    Unavailable,
    SendFailed,
    TimedOut,
    Cancelled,
}

impl std::fmt::Display for MacosHostRefreshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => f.write_str("macOS host refresh collector unavailable"),
            Self::SendFailed => f.write_str("macOS host refresh collector stopped"),
            Self::TimedOut => f.write_str("macOS host refresh timed out"),
            Self::Cancelled => f.write_str("macOS host refresh was cancelled"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacosNetworkExtensionReloadError {
    Unavailable,
    SendFailed,
    TimedOut,
    Cancelled,
    HelperFailed(String),
    InvalidResponse(String),
}

impl std::fmt::Display for MacosNetworkExtensionReloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => f.write_str("macOS NetworkExtension reload helper unavailable"),
            Self::SendFailed => f.write_str("macOS NetworkExtension reload helper stopped"),
            Self::TimedOut => f.write_str("macOS NetworkExtension reload timed out"),
            Self::Cancelled => f.write_str("macOS NetworkExtension reload was cancelled"),
            Self::HelperFailed(error) => {
                write!(f, "macOS NetworkExtension reload helper failed: {error}")
            }
            Self::InvalidResponse(error) => {
                write!(
                    f,
                    "macOS NetworkExtension reload helper returned invalid response: {error}"
                )
            }
        }
    }
}

impl MacosHostService {
    pub fn new() -> Self {
        Self {
            status: RwLock::new(MacosHostStatusState::default()),
            refresh_tx: RwLock::new(None),
            network_extension_reload_tx: RwLock::new(None),
        }
    }

    pub async fn snapshot(&self) -> CombinedSystemExtensionStatus {
        self.status.read().await.current.clone()
    }

    pub async fn snapshot_transition(&self) -> MacosHostStatusTransition {
        let state = self.status.read().await;
        MacosHostStatusTransition {
            previous: state.previous.clone(),
            current: state.current.clone(),
        }
    }

    pub async fn reset_unknown_state(&self) {
        self.replace_status(CombinedSystemExtensionStatus::default())
            .await;
    }

    pub async fn bootstrap_placeholder_state(&self) {
        self.reset_unknown_state().await;
    }

    pub(crate) async fn replace_status(&self, status: CombinedSystemExtensionStatus) {
        let mut state = self.status.write().await;
        state.previous = Some(state.current.clone());
        state.current = status;
    }

    pub(crate) async fn install_refresh_channel(&self, tx: mpsc::Sender<MacosHostRefreshRequest>) {
        *self.refresh_tx.write().await = Some(tx);
    }

    pub(crate) async fn install_network_extension_reload_channel(
        &self,
        tx: mpsc::Sender<MacosNetworkExtensionReloadRequest>,
    ) {
        *self.network_extension_reload_tx.write().await = Some(tx);
    }

    pub async fn request_refresh(
        &self,
        timeout_duration: Duration,
    ) -> Result<CombinedSystemExtensionStatus, MacosHostRefreshError> {
        let tx = self
            .refresh_tx
            .read()
            .await
            .clone()
            .ok_or(MacosHostRefreshError::Unavailable)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(reply_tx)
            .await
            .map_err(|_| MacosHostRefreshError::SendFailed)?;
        match tokio::time::timeout(timeout_duration, reply_rx).await {
            Ok(Ok(status)) => Ok(status),
            Ok(Err(_)) => Err(MacosHostRefreshError::Cancelled),
            Err(_) => Err(MacosHostRefreshError::TimedOut),
        }
    }

    pub async fn request_network_extension_reload(
        &self,
        policy_snapshot_path: PathBuf,
        generation: u64,
        timeout_duration: Duration,
    ) -> Result<MacosNetworkExtensionReloadResult, MacosNetworkExtensionReloadError> {
        let tx = self
            .network_extension_reload_tx
            .read()
            .await
            .clone()
            .ok_or(MacosNetworkExtensionReloadError::Unavailable)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(MacosNetworkExtensionReloadRequest {
            policy_snapshot_path,
            generation,
            timeout_duration,
            reply_tx,
        })
        .await
        .map_err(|_| MacosNetworkExtensionReloadError::SendFailed)?;
        match tokio::time::timeout(timeout_duration, reply_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(MacosNetworkExtensionReloadError::Cancelled),
            Err(_) => Err(MacosNetworkExtensionReloadError::TimedOut),
        }
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

        let installed_status = CombinedSystemExtensionStatus {
            install_state: SystemExtensionInstallState::Installed,
            approval: SystemExtensionApproval::ApprovalBlocked,
            endpoint_security: ProviderStatus {
                runtime: ProviderRuntimeState::Degraded {
                    reason: "missing full disk access".to_string(),
                },
                ..ProviderStatus::unknown()
            },
            network_extension: ProviderStatus {
                runtime: ProviderRuntimeState::Active,
                ..ProviderStatus::unknown()
            },
            ..CombinedSystemExtensionStatus::default()
        };
        service.replace_status(installed_status.clone()).await;

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
                ..ProviderStatus::unknown()
            }
        );
        assert_eq!(
            snapshot.network_extension,
            ProviderStatus {
                runtime: ProviderRuntimeState::Active,
                ..ProviderStatus::unknown()
            }
        );
        assert!(snapshot.is_degraded());

        let transition = service.snapshot_transition().await;
        assert_eq!(
            transition.previous,
            Some(CombinedSystemExtensionStatus::default())
        );
        assert_eq!(transition.current, installed_status);
    }

    #[tokio::test]
    async fn service_reports_missing_refresh_collector() {
        let service = MacosHostService::new();
        let err = match service.request_refresh(Duration::from_millis(1)).await {
            Ok(_) => panic!("refresh unexpectedly succeeded without a collector"),
            Err(err) => err,
        };

        assert_eq!(err, MacosHostRefreshError::Unavailable);
    }

    #[tokio::test]
    async fn service_refresh_uses_registered_collector_channel() {
        let service = MacosHostService::new();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        service.install_refresh_channel(tx).await;

        tokio::spawn(async move {
            let request = rx
                .recv()
                .await
                .unwrap_or_else(|| panic!("missing refresh request"));
            let _ = request.send(CombinedSystemExtensionStatus {
                install_state: SystemExtensionInstallState::Installed,
                approval: SystemExtensionApproval::Approved,
                endpoint_security: ProviderStatus {
                    runtime: ProviderRuntimeState::Active,
                    ..ProviderStatus::unknown()
                },
                network_extension: ProviderStatus {
                    runtime: ProviderRuntimeState::Active,
                    ..ProviderStatus::unknown()
                },
                ..CombinedSystemExtensionStatus::default()
            });
        });

        let snapshot = service
            .request_refresh(Duration::from_secs(1))
            .await
            .unwrap_or_else(|err| panic!("refresh failed: {err}"));

        assert_eq!(
            snapshot.install_state,
            SystemExtensionInstallState::Installed
        );
        assert_eq!(snapshot.approval, SystemExtensionApproval::Approved);
    }
}
