use std::collections::BTreeMap;

use chrono::Utc;
use clawdstrike_broker_protocol::{
    BrokerApprovalState, BrokerCapability, BrokerCapabilityState, BrokerCapabilityStatus,
    BrokerExecutionEvidence, BrokerIntentPreview, BrokerProvider, BrokerProviderFreezeStatus,
    HttpMethod,
};
use tokio::sync::RwLock;

#[derive(Clone, Debug)]
pub struct BrokerPreviewRecord {
    pub preview: BrokerIntentPreview,
    pub url: String,
    pub method: HttpMethod,
    pub secret_ref_id: String,
    pub policy_hash: String,
}

#[derive(Default)]
pub struct BrokerStateStore {
    capabilities: RwLock<BTreeMap<String, BrokerCapabilityStatus>>,
    executions: RwLock<BTreeMap<String, Vec<BrokerExecutionEvidence>>>,
    frozen_providers: RwLock<BTreeMap<String, BrokerProviderFreezeStatus>>,
    previews: RwLock<BTreeMap<String, BrokerPreviewRecord>>,
}

impl BrokerStateStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn register_capability(&self, capability: &BrokerCapability, url: String) {
        let status = BrokerCapabilityStatus {
            capability_id: capability.capability_id.clone(),
            provider: capability.secret_ref.provider.clone(),
            state: BrokerCapabilityState::Active,
            issued_at: capability.issued_at,
            expires_at: capability.expires_at,
            policy_hash: capability.policy_hash.clone(),
            session_id: capability.session_id.clone(),
            endpoint_agent_id: capability.endpoint_agent_id.clone(),
            runtime_agent_id: capability.runtime_agent_id.clone(),
            runtime_agent_kind: capability.runtime_agent_kind.clone(),
            origin_fingerprint: capability.origin_fingerprint.clone(),
            secret_ref_id: capability.secret_ref.id.clone(),
            url: url.clone(),
            method: capability.destination.method.clone(),
            state_reason: None,
            revoked_at: None,
            execution_count: 0,
            last_executed_at: None,
            last_status_code: None,
            last_outcome: None,
            intent_preview: capability.intent_preview.clone(),
            minted_identity: None,
            lineage: capability.lineage.clone(),
            suspicion_reason: None,
        };

        self.capabilities
            .write()
            .await
            .insert(status.capability_id.clone(), status);
        if let Some(preview) = &capability.intent_preview {
            let record = BrokerPreviewRecord {
                preview: preview.clone(),
                url,
                method: capability.destination.method.clone(),
                secret_ref_id: capability.secret_ref.id.clone(),
                policy_hash: capability.policy_hash.clone(),
            };
            self.previews
                .write()
                .await
                .insert(record.preview.preview_id.clone(), record);
        }
        self.executions
            .write()
            .await
            .entry(capability.capability_id.clone())
            .or_default();
    }

    pub async fn record_evidence(&self, evidence: &BrokerExecutionEvidence) {
        let mut capabilities = self.capabilities.write().await;
        if let Some(status) = capabilities.get_mut(&evidence.capability_id) {
            if matches!(
                evidence.phase,
                clawdstrike_broker_protocol::BrokerExecutionPhase::Completed
            ) {
                status.execution_count = status.execution_count.saturating_add(1);
                status.last_executed_at = Some(evidence.executed_at);
                status.last_status_code = evidence.status_code;
                status.last_outcome = evidence.outcome.clone();
            }
            if let Some(minted_identity) = &evidence.minted_identity {
                status.minted_identity = Some(minted_identity.clone());
            }
            if let Some(lineage) = &evidence.lineage {
                status.lineage = Some(lineage.clone());
            }
            if let Some(suspicion_reason) = &evidence.suspicion_reason {
                status.suspicion_reason = Some(suspicion_reason.clone());
            }
            if status.intent_preview.is_none() {
                if let Some(preview_id) = &evidence.preview_id {
                    status.intent_preview = self
                        .previews
                        .read()
                        .await
                        .get(preview_id)
                        .map(|record| record.preview.clone());
                }
            }
        }
        drop(capabilities);

        self.executions
            .write()
            .await
            .entry(evidence.capability_id.clone())
            .or_default()
            .push(evidence.clone());
    }

    pub async fn get_capability_status(
        &self,
        capability_id: &str,
    ) -> Option<BrokerCapabilityStatus> {
        let capabilities = self.capabilities.read().await;
        let status = capabilities.get(capability_id)?.clone();
        drop(capabilities);
        Some(self.apply_runtime_state(status).await)
    }

    pub async fn get_capability_detail(
        &self,
        capability_id: &str,
    ) -> Option<(BrokerCapabilityStatus, Vec<BrokerExecutionEvidence>)> {
        let status = self.get_capability_status(capability_id).await?;
        let executions = self
            .executions
            .read()
            .await
            .get(capability_id)
            .cloned()
            .unwrap_or_default();
        Some((status, executions))
    }

    pub async fn list_capabilities(&self) -> Vec<BrokerCapabilityStatus> {
        let capabilities = self.capabilities.read().await;
        let statuses = capabilities.values().cloned().collect::<Vec<_>>();
        drop(capabilities);

        let mut hydrated = Vec::with_capacity(statuses.len());
        for status in statuses {
            hydrated.push(self.apply_runtime_state(status).await);
        }
        hydrated.sort_by(|left, right| right.issued_at.cmp(&left.issued_at));
        hydrated
    }

    pub async fn store_preview(&self, record: BrokerPreviewRecord) -> BrokerIntentPreview {
        let preview = record.preview.clone();
        self.previews
            .write()
            .await
            .insert(preview.preview_id.clone(), record);
        preview
    }

    pub async fn get_preview(&self, preview_id: &str) -> Option<BrokerIntentPreview> {
        self.previews
            .read()
            .await
            .get(preview_id)
            .map(|record| record.preview.clone())
    }

    pub async fn get_preview_record(&self, preview_id: &str) -> Option<BrokerPreviewRecord> {
        self.previews.read().await.get(preview_id).cloned()
    }

    pub async fn list_previews(&self) -> Vec<BrokerIntentPreview> {
        let mut previews = self
            .previews
            .read()
            .await
            .values()
            .map(|record| record.preview.clone())
            .collect::<Vec<_>>();
        previews.sort_by(|left, right| right.created_at.cmp(&left.created_at));
        previews
    }

    pub async fn approve_preview(
        &self,
        preview_id: &str,
        approver: Option<String>,
    ) -> Option<BrokerIntentPreview> {
        let mut previews = self.previews.write().await;
        let record = previews.get_mut(preview_id)?;
        record.preview.approval_state = BrokerApprovalState::Approved;
        record.preview.approved_at = Some(Utc::now());
        record.preview.approver = approver;
        Some(record.preview.clone())
    }

    pub async fn revoke_capability(
        &self,
        capability_id: &str,
        reason: Option<String>,
    ) -> Option<BrokerCapabilityStatus> {
        let mut capabilities = self.capabilities.write().await;
        let status = capabilities.get_mut(capability_id)?;
        status.state = BrokerCapabilityState::Revoked;
        status.state_reason = reason;
        status.revoked_at = Some(Utc::now());
        Some(status.clone())
    }

    pub async fn revoke_all_active(&self, reason: Option<String>) -> usize {
        let mut capabilities = self.capabilities.write().await;
        let now = Utc::now();
        let mut revoked: usize = 0;
        for status in capabilities.values_mut() {
            if matches!(status.state, BrokerCapabilityState::Revoked) || status.expires_at <= now {
                continue;
            }
            status.state = BrokerCapabilityState::Revoked;
            status.state_reason = reason.clone();
            status.revoked_at = Some(now);
            revoked = revoked.saturating_add(1);
        }
        revoked
    }

    pub async fn freeze_provider(
        &self,
        provider: BrokerProvider,
        reason: String,
    ) -> BrokerProviderFreezeStatus {
        let freeze = BrokerProviderFreezeStatus {
            provider: provider.clone(),
            frozen_at: Utc::now(),
            reason,
        };
        self.frozen_providers
            .write()
            .await
            .insert(provider_key(&provider), freeze.clone());
        freeze
    }

    pub async fn unfreeze_provider(
        &self,
        provider: &BrokerProvider,
    ) -> Option<BrokerProviderFreezeStatus> {
        self.frozen_providers
            .write()
            .await
            .remove(&provider_key(provider))
    }

    pub async fn list_frozen_providers(&self) -> Vec<BrokerProviderFreezeStatus> {
        let mut providers = self
            .frozen_providers
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        providers.sort_by(|left, right| right.frozen_at.cmp(&left.frozen_at));
        providers
    }

    pub async fn is_provider_frozen(&self, provider: &BrokerProvider) -> bool {
        self.frozen_providers
            .read()
            .await
            .contains_key(&provider_key(provider))
    }

    async fn apply_runtime_state(
        &self,
        mut status: BrokerCapabilityStatus,
    ) -> BrokerCapabilityStatus {
        if status.expires_at <= Utc::now() {
            status.state = BrokerCapabilityState::Expired;
            if status.state_reason.is_none() {
                status.state_reason = Some("capability_expired".to_string());
            }
            return status;
        }

        if matches!(status.state, BrokerCapabilityState::Revoked) {
            return status;
        }

        if let Some(frozen) = self
            .frozen_providers
            .read()
            .await
            .get(&provider_key(&status.provider))
            .cloned()
        {
            status.state = BrokerCapabilityState::Frozen;
            status.state_reason = Some(frozen.reason);
        }

        status
    }
}

fn provider_key(provider: &BrokerProvider) -> String {
    serde_json::to_string(provider).unwrap_or_else(|_| "unknown".to_string())
}
