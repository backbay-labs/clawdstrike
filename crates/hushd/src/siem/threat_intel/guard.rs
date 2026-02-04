use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use clawdstrike::guards::{Guard, GuardAction, GuardContext, GuardResult, Severity};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use crate::siem::threat_intel::config::ThreatIntelActions;
use crate::siem::threat_intel::service::ThreatIntelState;

pub struct ThreatIntelGuard {
    name: String,
    state: Arc<RwLock<ThreatIntelState>>,
    actions: ThreatIntelActions,
}

impl ThreatIntelGuard {
    pub fn new(state: Arc<RwLock<ThreatIntelState>>, actions: ThreatIntelActions) -> Self {
        Self {
            name: "threat_intel".to_string(),
            state,
            actions,
        }
    }
}

#[async_trait]
impl Guard for ThreatIntelGuard {
    fn name(&self) -> &str {
        &self.name
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        match action {
            GuardAction::NetworkEgress(_, _) => self.actions.block_egress,
            GuardAction::FileAccess(_)
            | GuardAction::FileWrite(_, _)
            | GuardAction::Patch(_, _) => self.actions.block_paths,
            _ => false,
        }
    }

    async fn check(&self, action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        match action {
            GuardAction::NetworkEgress(host, port) => {
                if !self.actions.block_egress {
                    return GuardResult::allow(self.name());
                }

                let state = self.state.read().await;
                let blocked = if let Ok(ip) = host.parse::<IpAddr>() {
                    state.is_ip_blocked(ip)
                } else {
                    state.is_domain_blocked(host)
                };

                if blocked {
                    GuardResult::block(
                        self.name(),
                        Severity::Error,
                        format!("Egress to {} blocked by threat intelligence", host),
                    )
                    .with_details(serde_json::json!({
                        "host": host,
                        "port": port,
                        "source": "stix/taxii",
                    }))
                } else {
                    GuardResult::allow(self.name())
                }
            }
            GuardAction::FileAccess(path) | GuardAction::Patch(path, _) => {
                if !self.actions.block_paths {
                    return GuardResult::allow(self.name());
                }

                let base = path.rsplit('/').next().unwrap_or(path);
                let state = self.state.read().await;
                let blocked = state.is_file_name_blocked(base);
                if blocked {
                    GuardResult::block(
                        self.name(),
                        Severity::Error,
                        format!("File access to {} blocked by threat intelligence", path),
                    )
                    .with_details(serde_json::json!({
                        "path": path,
                        "file_name": base,
                        "source": "stix/taxii",
                    }))
                } else {
                    GuardResult::allow(self.name())
                }
            }
            GuardAction::FileWrite(path, bytes) => {
                if !self.actions.block_paths {
                    return GuardResult::allow(self.name());
                }

                let base = path.rsplit('/').next().unwrap_or(path);
                let state = self.state.read().await;

                if state.is_file_name_blocked(base) {
                    return GuardResult::block(
                        self.name(),
                        Severity::Error,
                        format!("File write to {} blocked by threat intelligence", path),
                    )
                    .with_details(serde_json::json!({
                        "path": path,
                        "file_name": base,
                        "source": "stix/taxii",
                    }));
                }

                if !state.file_sha256.is_empty() {
                    let hash = Sha256::digest(bytes);
                    let hex = hex::encode(hash);
                    if state.is_file_sha256_blocked(&hex) {
                        return GuardResult::block(
                            self.name(),
                            Severity::Critical,
                            format!("File write blocked by threat intelligence (sha256={})", hex),
                        )
                        .with_details(serde_json::json!({
                            "path": path,
                            "sha256": hex,
                            "source": "stix/taxii",
                        }));
                    }
                }

                GuardResult::allow(self.name())
            }
            _ => GuardResult::allow(self.name()),
        }
    }
}
