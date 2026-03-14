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
            provider: capability.secret_ref.provider,
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
            method: capability.destination.method,
            state_reason: None,
            revoked_at: None,
            execution_count: 0,
            max_executions: capability.request_constraints.max_executions,
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
                method: capability.destination.method,
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
                status.last_outcome = evidence.outcome;
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
        let status = self.capabilities.read().await.get(capability_id)?.clone();
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
        let mut revoked = 0usize;
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
        let key = provider_key(&provider);
        let freeze = BrokerProviderFreezeStatus {
            provider,
            frozen_at: Utc::now(),
            reason,
        };
        self.frozen_providers
            .write()
            .await
            .insert(key, freeze.clone());
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

        if let Some(reason) = self
            .frozen_providers
            .read()
            .await
            .get(&provider_key(&status.provider))
            .map(|frozen| frozen.reason.clone())
        {
            status.state = BrokerCapabilityState::Frozen;
            status.state_reason = Some(reason);
        }

        status
    }
}

fn provider_key(provider: &BrokerProvider) -> String {
    serde_json::to_string(provider).unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use chrono::Duration;
    use clawdstrike_broker_protocol::{
        BrokerApprovalState, BrokerCapabilityState, BrokerDelegationLineage, BrokerDestination,
        BrokerExecutionOutcome, BrokerExecutionPhase, BrokerIntentPreview, BrokerIntentRiskLevel,
        BrokerMintedIdentity, BrokerMintedIdentityKind, BrokerProvider, BrokerRequestConstraints,
        CredentialRef, HttpMethod, UrlScheme,
    };
    use std::collections::BTreeMap;

    fn make_capability(id: &str, ttl_secs: i64) -> BrokerCapability {
        let now = Utc::now();
        BrokerCapability {
            capability_id: id.to_string(),
            issued_at: now,
            expires_at: now + Duration::seconds(ttl_secs),
            policy_hash: format!("hash-{id}"),
            session_id: Some(format!("sess-{id}")),
            endpoint_agent_id: Some("agent:endpoint".to_string()),
            runtime_agent_id: Some("agent:runner".to_string()),
            runtime_agent_kind: Some("delegate".to_string()),
            origin_fingerprint: Some("fp-test".to_string()),
            secret_ref: CredentialRef {
                id: "openai/dev".to_string(),
                provider: BrokerProvider::Openai,
                tenant_id: None,
                environment: Some("dev".to_string()),
                labels: BTreeMap::new(),
            },
            proof_binding: None,
            destination: BrokerDestination {
                scheme: UrlScheme::Https,
                host: "api.openai.com".to_string(),
                port: Some(443),
                method: HttpMethod::POST,
                exact_paths: vec!["/v1/responses".to_string()],
            },
            request_constraints: BrokerRequestConstraints::default(),
            evidence_required: true,
            intent_preview: None,
            lineage: None,
        }
    }

    fn make_expired_capability(id: &str) -> BrokerCapability {
        let now = Utc::now();
        BrokerCapability {
            capability_id: id.to_string(),
            issued_at: now - Duration::seconds(120),
            expires_at: now - Duration::seconds(60),
            policy_hash: "hash-expired".to_string(),
            session_id: None,
            endpoint_agent_id: None,
            runtime_agent_id: None,
            runtime_agent_kind: None,
            origin_fingerprint: None,
            secret_ref: CredentialRef {
                id: "openai/dev".to_string(),
                provider: BrokerProvider::Openai,
                tenant_id: None,
                environment: None,
                labels: BTreeMap::new(),
            },
            proof_binding: None,
            destination: BrokerDestination {
                scheme: UrlScheme::Https,
                host: "api.openai.com".to_string(),
                port: None,
                method: HttpMethod::GET,
                exact_paths: vec!["/v1/models".to_string()],
            },
            request_constraints: BrokerRequestConstraints::default(),
            evidence_required: false,
            intent_preview: None,
            lineage: None,
        }
    }

    fn make_evidence(
        exec_id: &str,
        cap_id: &str,
        phase: BrokerExecutionPhase,
    ) -> BrokerExecutionEvidence {
        BrokerExecutionEvidence {
            execution_id: exec_id.to_string(),
            capability_id: cap_id.to_string(),
            provider: BrokerProvider::Openai,
            phase,
            executed_at: Utc::now(),
            secret_ref_id: "openai/dev".to_string(),
            url: "https://api.openai.com/v1/responses".to_string(),
            method: HttpMethod::POST,
            request_body_sha256: Some("req-hash".to_string()),
            response_body_sha256: Some("resp-hash".to_string()),
            status_code: Some(200),
            bytes_sent: 128,
            bytes_received: 256,
            stream_chunk_count: None,
            provider_metadata: BTreeMap::from([(
                "operation".to_string(),
                "responses.create".to_string(),
            )]),
            outcome: Some(BrokerExecutionOutcome::Success),
            minted_identity: None,
            preview_id: None,
            lineage: None,
            suspicion_reason: None,
        }
    }

    fn make_preview(preview_id: &str) -> BrokerIntentPreview {
        BrokerIntentPreview {
            preview_id: preview_id.to_string(),
            provider: BrokerProvider::Openai,
            operation: "responses.create".to_string(),
            summary: "Create a response".to_string(),
            created_at: Utc::now(),
            risk_level: BrokerIntentRiskLevel::Low,
            data_classes: vec![],
            resources: vec![],
            egress_host: "api.openai.com".to_string(),
            estimated_cost_usd_micros: None,
            approval_required: false,
            approval_state: BrokerApprovalState::NotRequired,
            approved_at: None,
            approver: None,
            body_sha256: None,
        }
    }

    fn make_preview_record(preview_id: &str) -> BrokerPreviewRecord {
        BrokerPreviewRecord {
            preview: make_preview(preview_id),
            url: "https://api.openai.com/v1/responses".to_string(),
            method: HttpMethod::POST,
            secret_ref_id: "openai/dev".to_string(),
            policy_hash: "policy-hash-1".to_string(),
        }
    }

    // ── new / default ──────────────────────────────────────────────────

    #[tokio::test]
    async fn new_store_is_empty() {
        let store = BrokerStateStore::new();
        assert!(store.list_capabilities().await.is_empty());
        assert!(store.list_previews().await.is_empty());
        assert!(store.list_frozen_providers().await.is_empty());
    }

    #[tokio::test]
    async fn default_store_is_empty() {
        let store = BrokerStateStore::default();
        assert!(store.list_capabilities().await.is_empty());
    }

    // ── register_capability ────────────────────────────────────────────

    #[tokio::test]
    async fn register_and_retrieve_capability() {
        let store = BrokerStateStore::new();
        let cap = make_capability("cap-1", 300);
        store
            .register_capability(&cap, "https://api.openai.com/v1/responses".to_string())
            .await;

        let status = store.get_capability_status("cap-1").await.unwrap();
        assert_eq!(status.capability_id, "cap-1");
        assert_eq!(status.provider, BrokerProvider::Openai);
        assert!(matches!(status.state, BrokerCapabilityState::Active));
        assert_eq!(status.policy_hash, "hash-cap-1");
        assert_eq!(status.session_id, Some("sess-cap-1".to_string()));
        assert_eq!(status.endpoint_agent_id, Some("agent:endpoint".to_string()));
        assert_eq!(status.runtime_agent_id, Some("agent:runner".to_string()));
        assert_eq!(status.runtime_agent_kind, Some("delegate".to_string()));
        assert_eq!(status.origin_fingerprint, Some("fp-test".to_string()));
        assert_eq!(status.secret_ref_id, "openai/dev");
        assert_eq!(status.url, "https://api.openai.com/v1/responses");
        assert_eq!(status.method, HttpMethod::POST);
        assert!(status.state_reason.is_none());
        assert!(status.revoked_at.is_none());
        assert_eq!(status.execution_count, 0);
        assert!(status.last_executed_at.is_none());
        assert!(status.last_status_code.is_none());
        assert!(status.last_outcome.is_none());
        assert!(status.intent_preview.is_none());
        assert!(status.minted_identity.is_none());
        assert!(status.lineage.is_none());
        assert!(status.suspicion_reason.is_none());
    }

    #[tokio::test]
    async fn register_capability_with_intent_preview_stores_preview() {
        let store = BrokerStateStore::new();
        let preview = make_preview("prev-1");
        let mut cap = make_capability("cap-prev", 300);
        cap.intent_preview = Some(preview.clone());

        store
            .register_capability(&cap, "https://api.openai.com/v1/responses".to_string())
            .await;

        let stored_preview = store.get_preview("prev-1").await.unwrap();
        assert_eq!(stored_preview.preview_id, "prev-1");
        assert_eq!(stored_preview.operation, "responses.create");

        let status = store.get_capability_status("cap-prev").await.unwrap();
        assert!(status.intent_preview.is_some());
        assert_eq!(status.intent_preview.unwrap().preview_id, "prev-1");
    }

    #[tokio::test]
    async fn register_initializes_empty_execution_list() {
        let store = BrokerStateStore::new();
        let cap = make_capability("cap-exec-init", 300);
        store
            .register_capability(&cap, "https://example.com".to_string())
            .await;

        let (status, executions) = store.get_capability_detail("cap-exec-init").await.unwrap();
        assert_eq!(status.capability_id, "cap-exec-init");
        assert!(executions.is_empty());
    }

    #[tokio::test]
    async fn get_missing_capability_returns_none() {
        let store = BrokerStateStore::new();
        assert!(store.get_capability_status("nonexistent").await.is_none());
    }

    #[tokio::test]
    async fn get_missing_detail_returns_none() {
        let store = BrokerStateStore::new();
        assert!(store.get_capability_detail("nonexistent").await.is_none());
    }

    // ── record_evidence ────────────────────────────────────────────────

    #[tokio::test]
    async fn record_completed_evidence_updates_stats() {
        let store = BrokerStateStore::new();
        let cap = make_capability("cap-ev", 300);
        store
            .register_capability(&cap, "https://example.com".to_string())
            .await;

        let evidence = make_evidence("exec-1", "cap-ev", BrokerExecutionPhase::Completed);
        store.record_evidence(&evidence).await;

        let status = store.get_capability_status("cap-ev").await.unwrap();
        assert_eq!(status.execution_count, 1);
        assert!(status.last_executed_at.is_some());
        assert_eq!(status.last_status_code, Some(200));
        assert_eq!(status.last_outcome, Some(BrokerExecutionOutcome::Success));
    }

    #[tokio::test]
    async fn record_started_evidence_does_not_update_stats() {
        let store = BrokerStateStore::new();
        let cap = make_capability("cap-started", 300);
        store
            .register_capability(&cap, "https://example.com".to_string())
            .await;

        let evidence = make_evidence("exec-start", "cap-started", BrokerExecutionPhase::Started);
        store.record_evidence(&evidence).await;

        let status = store.get_capability_status("cap-started").await.unwrap();
        assert_eq!(status.execution_count, 0);
        assert!(status.last_executed_at.is_none());
        assert!(status.last_status_code.is_none());
        assert!(status.last_outcome.is_none());
    }

    #[tokio::test]
    async fn record_multiple_completed_increments_count() {
        let store = BrokerStateStore::new();
        let cap = make_capability("cap-multi", 300);
        store
            .register_capability(&cap, "https://example.com".to_string())
            .await;

        for i in 0..3 {
            let evidence = make_evidence(
                &format!("exec-{i}"),
                "cap-multi",
                BrokerExecutionPhase::Completed,
            );
            store.record_evidence(&evidence).await;
        }

        let status = store.get_capability_status("cap-multi").await.unwrap();
        assert_eq!(status.execution_count, 3);
    }

    #[tokio::test]
    async fn record_evidence_sets_minted_identity() {
        let store = BrokerStateStore::new();
        let cap = make_capability("cap-mint", 300);
        store
            .register_capability(&cap, "https://example.com".to_string())
            .await;

        let now = Utc::now();
        let mut evidence = make_evidence("exec-mint", "cap-mint", BrokerExecutionPhase::Completed);
        evidence.minted_identity = Some(BrokerMintedIdentity {
            kind: BrokerMintedIdentityKind::GithubAppInstallation,
            subject: "installation:42".to_string(),
            issued_at: now,
            expires_at: now + Duration::seconds(300),
            metadata: BTreeMap::from([("installation_id".to_string(), "42".to_string())]),
        });
        store.record_evidence(&evidence).await;

        let status = store.get_capability_status("cap-mint").await.unwrap();
        let minted = status.minted_identity.unwrap();
        assert_eq!(minted.subject, "installation:42");
        assert!(matches!(
            minted.kind,
            BrokerMintedIdentityKind::GithubAppInstallation
        ));
    }

    #[tokio::test]
    async fn record_evidence_sets_lineage() {
        let store = BrokerStateStore::new();
        let cap = make_capability("cap-lineage", 300);
        store
            .register_capability(&cap, "https://example.com".to_string())
            .await;

        let mut evidence = make_evidence(
            "exec-lineage",
            "cap-lineage",
            BrokerExecutionPhase::Completed,
        );
        evidence.lineage = Some(BrokerDelegationLineage {
            token_jti: "jti-1".to_string(),
            parent_token_jti: None,
            chain: vec![],
            depth: 0,
            issuer: "agent:planner".to_string(),
            subject: "agent:runner".to_string(),
            purpose: Some("tool-call".to_string()),
        });
        store.record_evidence(&evidence).await;

        let status = store.get_capability_status("cap-lineage").await.unwrap();
        let lineage = status.lineage.unwrap();
        assert_eq!(lineage.issuer, "agent:planner");
        assert_eq!(lineage.subject, "agent:runner");
        assert_eq!(lineage.purpose, Some("tool-call".to_string()));
    }

    #[tokio::test]
    async fn record_evidence_sets_suspicion_reason() {
        let store = BrokerStateStore::new();
        let cap = make_capability("cap-sus", 300);
        store
            .register_capability(&cap, "https://example.com".to_string())
            .await;

        let mut evidence = make_evidence("exec-sus", "cap-sus", BrokerExecutionPhase::Completed);
        evidence.suspicion_reason = Some("anomalous_egress_pattern".to_string());
        store.record_evidence(&evidence).await;

        let status = store.get_capability_status("cap-sus").await.unwrap();
        assert_eq!(
            status.suspicion_reason,
            Some("anomalous_egress_pattern".to_string())
        );
    }

    #[tokio::test]
    async fn record_evidence_backfills_preview_from_preview_id() {
        let store = BrokerStateStore::new();
        let cap = make_capability("cap-backfill", 300);
        store
            .register_capability(&cap, "https://example.com".to_string())
            .await;

        // Store a preview separately
        let record = make_preview_record("prev-backfill");
        store.store_preview(record).await;

        // Record evidence that references the preview
        let mut evidence =
            make_evidence("exec-bf", "cap-backfill", BrokerExecutionPhase::Completed);
        evidence.preview_id = Some("prev-backfill".to_string());
        store.record_evidence(&evidence).await;

        let status = store.get_capability_status("cap-backfill").await.unwrap();
        let preview = status.intent_preview.unwrap();
        assert_eq!(preview.preview_id, "prev-backfill");
    }

    #[tokio::test]
    async fn record_evidence_does_not_overwrite_existing_preview() {
        let store = BrokerStateStore::new();
        let original_preview = make_preview("orig-prev");
        let mut cap = make_capability("cap-no-overwrite", 300);
        cap.intent_preview = Some(original_preview);
        store
            .register_capability(&cap, "https://example.com".to_string())
            .await;

        // Store a different preview
        let record = make_preview_record("other-prev");
        store.store_preview(record).await;

        // Evidence references the other preview, but should NOT overwrite
        let mut evidence = make_evidence(
            "exec-no-ow",
            "cap-no-overwrite",
            BrokerExecutionPhase::Completed,
        );
        evidence.preview_id = Some("other-prev".to_string());
        store.record_evidence(&evidence).await;

        let status = store
            .get_capability_status("cap-no-overwrite")
            .await
            .unwrap();
        assert_eq!(status.intent_preview.unwrap().preview_id, "orig-prev");
    }

    #[tokio::test]
    async fn record_evidence_for_unknown_capability_still_stores_execution() {
        let store = BrokerStateStore::new();
        let evidence = make_evidence(
            "exec-orphan",
            "cap-unknown",
            BrokerExecutionPhase::Completed,
        );
        store.record_evidence(&evidence).await;

        // The capability status should still be None
        assert!(store.get_capability_status("cap-unknown").await.is_none());
    }

    // ── get_capability_detail ──────────────────────────────────────────

    #[tokio::test]
    async fn get_capability_detail_returns_status_and_executions() {
        let store = BrokerStateStore::new();
        let cap = make_capability("cap-detail", 300);
        store
            .register_capability(&cap, "https://example.com".to_string())
            .await;

        let e1 = make_evidence("exec-d1", "cap-detail", BrokerExecutionPhase::Started);
        let e2 = make_evidence("exec-d2", "cap-detail", BrokerExecutionPhase::Completed);
        store.record_evidence(&e1).await;
        store.record_evidence(&e2).await;

        let (status, executions) = store.get_capability_detail("cap-detail").await.unwrap();
        assert_eq!(status.capability_id, "cap-detail");
        assert_eq!(status.execution_count, 1); // Only completed counts
        assert_eq!(executions.len(), 2);
        assert_eq!(executions[0].execution_id, "exec-d1");
        assert_eq!(executions[1].execution_id, "exec-d2");
    }

    // ── list_capabilities ──────────────────────────────────────────────

    #[tokio::test]
    async fn list_capabilities_sorted_by_issued_at_descending() {
        let store = BrokerStateStore::new();

        let mut cap1 = make_capability("cap-old", 300);
        cap1.issued_at = Utc::now() - Duration::seconds(100);
        store
            .register_capability(&cap1, "https://example.com".to_string())
            .await;

        let mut cap2 = make_capability("cap-new", 300);
        cap2.issued_at = Utc::now();
        store
            .register_capability(&cap2, "https://example.com".to_string())
            .await;

        let list = store.list_capabilities().await;
        assert_eq!(list.len(), 2);
        // Newest first
        assert_eq!(list[0].capability_id, "cap-new");
        assert_eq!(list[1].capability_id, "cap-old");
    }

    #[tokio::test]
    async fn list_capabilities_applies_runtime_state() {
        let store = BrokerStateStore::new();

        // Register an expired capability
        let expired = make_expired_capability("cap-exp-list");
        store
            .register_capability(&expired, "https://example.com".to_string())
            .await;

        let list = store.list_capabilities().await;
        assert_eq!(list.len(), 1);
        assert!(matches!(list[0].state, BrokerCapabilityState::Expired));
    }

    // ── preview CRUD ───────────────────────────────────────────────────

    #[tokio::test]
    async fn store_and_get_preview() {
        let store = BrokerStateStore::new();
        let record = make_preview_record("prev-crud");
        let returned = store.store_preview(record).await;
        assert_eq!(returned.preview_id, "prev-crud");

        let fetched = store.get_preview("prev-crud").await.unwrap();
        assert_eq!(fetched.preview_id, "prev-crud");
        assert_eq!(fetched.operation, "responses.create");
    }

    #[tokio::test]
    async fn get_preview_record_returns_full_record() {
        let store = BrokerStateStore::new();
        let record = make_preview_record("prev-rec");
        store.store_preview(record).await;

        let fetched = store.get_preview_record("prev-rec").await.unwrap();
        assert_eq!(fetched.preview.preview_id, "prev-rec");
        assert_eq!(fetched.url, "https://api.openai.com/v1/responses");
        assert_eq!(fetched.method, HttpMethod::POST);
        assert_eq!(fetched.secret_ref_id, "openai/dev");
        assert_eq!(fetched.policy_hash, "policy-hash-1");
    }

    #[tokio::test]
    async fn get_missing_preview_returns_none() {
        let store = BrokerStateStore::new();
        assert!(store.get_preview("nonexistent").await.is_none());
    }

    #[tokio::test]
    async fn get_missing_preview_record_returns_none() {
        let store = BrokerStateStore::new();
        assert!(store.get_preview_record("nonexistent").await.is_none());
    }

    #[tokio::test]
    async fn list_previews_sorted_by_created_at_descending() {
        let store = BrokerStateStore::new();

        let mut r1 = make_preview_record("prev-old");
        r1.preview.created_at = Utc::now() - Duration::seconds(100);
        store.store_preview(r1).await;

        let mut r2 = make_preview_record("prev-new");
        r2.preview.created_at = Utc::now();
        store.store_preview(r2).await;

        let list = store.list_previews().await;
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].preview_id, "prev-new");
        assert_eq!(list[1].preview_id, "prev-old");
    }

    // ── approve_preview ────────────────────────────────────────────────

    #[tokio::test]
    async fn approve_preview_sets_state_and_approver() {
        let store = BrokerStateStore::new();
        let mut record = make_preview_record("prev-approve");
        record.preview.approval_state = BrokerApprovalState::Pending;
        record.preview.approval_required = true;
        store.store_preview(record).await;

        let approved = store
            .approve_preview("prev-approve", Some("admin@example.com".to_string()))
            .await
            .unwrap();
        assert!(matches!(
            approved.approval_state,
            BrokerApprovalState::Approved
        ));
        assert!(approved.approved_at.is_some());
        assert_eq!(approved.approver, Some("admin@example.com".to_string()));
    }

    #[tokio::test]
    async fn approve_preview_with_no_approver() {
        let store = BrokerStateStore::new();
        let record = make_preview_record("prev-no-approver");
        store.store_preview(record).await;

        let approved = store
            .approve_preview("prev-no-approver", None)
            .await
            .unwrap();
        assert!(matches!(
            approved.approval_state,
            BrokerApprovalState::Approved
        ));
        assert!(approved.approver.is_none());
    }

    #[tokio::test]
    async fn approve_missing_preview_returns_none() {
        let store = BrokerStateStore::new();
        assert!(store.approve_preview("nonexistent", None).await.is_none());
    }

    // ── revoke_capability ──────────────────────────────────────────────

    #[tokio::test]
    async fn revoke_capability_sets_state_and_reason() {
        let store = BrokerStateStore::new();
        let cap = make_capability("cap-revoke", 300);
        store
            .register_capability(&cap, "https://example.com".to_string())
            .await;

        let revoked = store
            .revoke_capability("cap-revoke", Some("incident response".to_string()))
            .await
            .unwrap();
        assert!(matches!(revoked.state, BrokerCapabilityState::Revoked));
        assert_eq!(revoked.state_reason, Some("incident response".to_string()));
        assert!(revoked.revoked_at.is_some());
    }

    #[tokio::test]
    async fn revoke_capability_with_no_reason() {
        let store = BrokerStateStore::new();
        let cap = make_capability("cap-revoke-nr", 300);
        store
            .register_capability(&cap, "https://example.com".to_string())
            .await;

        let revoked = store
            .revoke_capability("cap-revoke-nr", None)
            .await
            .unwrap();
        assert!(matches!(revoked.state, BrokerCapabilityState::Revoked));
        assert!(revoked.state_reason.is_none());
        assert!(revoked.revoked_at.is_some());
    }

    #[tokio::test]
    async fn revoke_missing_capability_returns_none() {
        let store = BrokerStateStore::new();
        assert!(store.revoke_capability("nonexistent", None).await.is_none());
    }

    #[tokio::test]
    async fn revoked_capability_persists_through_runtime_state() {
        let store = BrokerStateStore::new();
        let cap = make_capability("cap-rev-persist", 300);
        store
            .register_capability(&cap, "https://example.com".to_string())
            .await;

        store
            .revoke_capability("cap-rev-persist", Some("test".to_string()))
            .await;

        // get_capability_status applies runtime state; revoked should be preserved
        let status = store
            .get_capability_status("cap-rev-persist")
            .await
            .unwrap();
        assert!(matches!(status.state, BrokerCapabilityState::Revoked));
    }

    // ── revoke_all_active ──────────────────────────────────────────────

    #[tokio::test]
    async fn revoke_all_active_revokes_active_capabilities() {
        let store = BrokerStateStore::new();

        let cap1 = make_capability("cap-ra1", 300);
        let cap2 = make_capability("cap-ra2", 300);
        store
            .register_capability(&cap1, "https://example.com".to_string())
            .await;
        store
            .register_capability(&cap2, "https://example.com".to_string())
            .await;

        let count = store
            .revoke_all_active(Some("panic button".to_string()))
            .await;
        assert_eq!(count, 2);

        let s1 = store.get_capability_status("cap-ra1").await.unwrap();
        let s2 = store.get_capability_status("cap-ra2").await.unwrap();
        assert!(matches!(s1.state, BrokerCapabilityState::Revoked));
        assert!(matches!(s2.state, BrokerCapabilityState::Revoked));
        assert_eq!(s1.state_reason, Some("panic button".to_string()));
        assert_eq!(s2.state_reason, Some("panic button".to_string()));
    }

    #[tokio::test]
    async fn revoke_all_active_skips_already_revoked() {
        let store = BrokerStateStore::new();

        let cap1 = make_capability("cap-skip-rev", 300);
        let cap2 = make_capability("cap-active", 300);
        store
            .register_capability(&cap1, "https://example.com".to_string())
            .await;
        store
            .register_capability(&cap2, "https://example.com".to_string())
            .await;

        store
            .revoke_capability("cap-skip-rev", Some("already revoked".to_string()))
            .await;

        let count = store.revoke_all_active(Some("bulk".to_string())).await;
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn revoke_all_active_skips_expired() {
        let store = BrokerStateStore::new();

        let expired = make_expired_capability("cap-expired-skip");
        let active = make_capability("cap-active-rev", 300);
        store
            .register_capability(&expired, "https://example.com".to_string())
            .await;
        store
            .register_capability(&active, "https://example.com".to_string())
            .await;

        let count = store.revoke_all_active(Some("bulk".to_string())).await;
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn revoke_all_active_returns_zero_when_nothing_active() {
        let store = BrokerStateStore::new();
        let count = store.revoke_all_active(None).await;
        assert_eq!(count, 0);
    }

    // ── freeze / unfreeze provider ─────────────────────────────────────

    #[tokio::test]
    async fn freeze_and_list_provider() {
        let store = BrokerStateStore::new();
        let freeze = store
            .freeze_provider(BrokerProvider::Openai, "maintenance".to_string())
            .await;
        assert_eq!(freeze.provider, BrokerProvider::Openai);
        assert_eq!(freeze.reason, "maintenance");

        let frozen = store.list_frozen_providers().await;
        assert_eq!(frozen.len(), 1);
        assert_eq!(frozen[0].provider, BrokerProvider::Openai);
    }

    #[tokio::test]
    async fn is_provider_frozen_returns_correct_state() {
        let store = BrokerStateStore::new();
        assert!(!store.is_provider_frozen(&BrokerProvider::Openai).await);

        store
            .freeze_provider(BrokerProvider::Openai, "outage".to_string())
            .await;
        assert!(store.is_provider_frozen(&BrokerProvider::Openai).await);
        assert!(!store.is_provider_frozen(&BrokerProvider::Github).await);
    }

    #[tokio::test]
    async fn unfreeze_provider_removes_freeze() {
        let store = BrokerStateStore::new();
        store
            .freeze_provider(BrokerProvider::Github, "incident".to_string())
            .await;
        assert!(store.is_provider_frozen(&BrokerProvider::Github).await);

        let removed = store.unfreeze_provider(&BrokerProvider::Github).await;
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().reason, "incident");
        assert!(!store.is_provider_frozen(&BrokerProvider::Github).await);
    }

    #[tokio::test]
    async fn unfreeze_unfrozen_provider_returns_none() {
        let store = BrokerStateStore::new();
        let removed = store.unfreeze_provider(&BrokerProvider::Slack).await;
        assert!(removed.is_none());
    }

    #[tokio::test]
    async fn freeze_multiple_providers() {
        let store = BrokerStateStore::new();
        store
            .freeze_provider(BrokerProvider::Openai, "a".to_string())
            .await;
        store
            .freeze_provider(BrokerProvider::Github, "b".to_string())
            .await;
        store
            .freeze_provider(BrokerProvider::Slack, "c".to_string())
            .await;

        let frozen = store.list_frozen_providers().await;
        assert_eq!(frozen.len(), 3);
        // Sorted by frozen_at descending (newest first)
        assert_eq!(frozen[0].provider, BrokerProvider::Slack);
    }

    #[tokio::test]
    async fn refreeze_provider_updates_entry() {
        let store = BrokerStateStore::new();
        store
            .freeze_provider(BrokerProvider::Openai, "first".to_string())
            .await;
        store
            .freeze_provider(BrokerProvider::Openai, "second".to_string())
            .await;

        let frozen = store.list_frozen_providers().await;
        assert_eq!(frozen.len(), 1);
        assert_eq!(frozen[0].reason, "second");
    }

    // ── apply_runtime_state ────────────────────────────────────────────

    #[tokio::test]
    async fn expired_capability_shows_expired_state() {
        let store = BrokerStateStore::new();
        let expired = make_expired_capability("cap-exp");
        store
            .register_capability(&expired, "https://example.com".to_string())
            .await;

        let status = store.get_capability_status("cap-exp").await.unwrap();
        assert!(matches!(status.state, BrokerCapabilityState::Expired));
        assert_eq!(status.state_reason, Some("capability_expired".to_string()));
    }

    #[tokio::test]
    async fn expired_capability_preserves_existing_state_reason() {
        let store = BrokerStateStore::new();
        let expired = make_expired_capability("cap-exp-reason");
        store
            .register_capability(&expired, "https://example.com".to_string())
            .await;

        // Set a reason before it would be checked as expired
        store
            .revoke_capability("cap-exp-reason", Some("revoked before expiry".to_string()))
            .await;

        let status = store.get_capability_status("cap-exp-reason").await.unwrap();
        // Expired takes precedence over revoked in apply_runtime_state
        assert!(matches!(status.state, BrokerCapabilityState::Expired));
        // Existing state_reason is preserved (not overwritten)
        assert_eq!(
            status.state_reason,
            Some("revoked before expiry".to_string())
        );
    }

    #[tokio::test]
    async fn frozen_provider_affects_active_capability_state() {
        let store = BrokerStateStore::new();
        let cap = make_capability("cap-freeze-effect", 300);
        store
            .register_capability(&cap, "https://example.com".to_string())
            .await;

        store
            .freeze_provider(BrokerProvider::Openai, "provider outage".to_string())
            .await;

        let status = store
            .get_capability_status("cap-freeze-effect")
            .await
            .unwrap();
        assert!(matches!(status.state, BrokerCapabilityState::Frozen));
        assert_eq!(status.state_reason, Some("provider outage".to_string()));
    }

    #[tokio::test]
    async fn frozen_provider_does_not_affect_revoked_capability() {
        let store = BrokerStateStore::new();
        let cap = make_capability("cap-rev-freeze", 300);
        store
            .register_capability(&cap, "https://example.com".to_string())
            .await;

        store
            .revoke_capability("cap-rev-freeze", Some("revoked".to_string()))
            .await;
        store
            .freeze_provider(BrokerProvider::Openai, "outage".to_string())
            .await;

        let status = store.get_capability_status("cap-rev-freeze").await.unwrap();
        // Revoked is returned as-is (before freeze check)
        assert!(matches!(status.state, BrokerCapabilityState::Revoked));
    }

    #[tokio::test]
    async fn frozen_provider_does_not_affect_different_provider() {
        let store = BrokerStateStore::new();
        let mut cap = make_capability("cap-github", 300);
        cap.secret_ref.provider = BrokerProvider::Github;
        store
            .register_capability(&cap, "https://api.github.com".to_string())
            .await;

        store
            .freeze_provider(BrokerProvider::Openai, "openai down".to_string())
            .await;

        let status = store.get_capability_status("cap-github").await.unwrap();
        assert!(matches!(status.state, BrokerCapabilityState::Active));
    }

    #[tokio::test]
    async fn unfreeze_restores_active_state() {
        let store = BrokerStateStore::new();
        let cap = make_capability("cap-unfreeze", 300);
        store
            .register_capability(&cap, "https://example.com".to_string())
            .await;

        store
            .freeze_provider(BrokerProvider::Openai, "temp".to_string())
            .await;

        let frozen_status = store.get_capability_status("cap-unfreeze").await.unwrap();
        assert!(matches!(frozen_status.state, BrokerCapabilityState::Frozen));

        store.unfreeze_provider(&BrokerProvider::Openai).await;

        let active_status = store.get_capability_status("cap-unfreeze").await.unwrap();
        assert!(matches!(active_status.state, BrokerCapabilityState::Active));
    }

    // ── provider_key ───────────────────────────────────────────────────

    #[test]
    fn provider_key_produces_consistent_keys() {
        assert_eq!(
            provider_key(&BrokerProvider::Openai),
            provider_key(&BrokerProvider::Openai)
        );
        assert_ne!(
            provider_key(&BrokerProvider::Openai),
            provider_key(&BrokerProvider::Github)
        );
    }

    // ── combined / integration-style scenarios ─────────────────────────

    #[tokio::test]
    async fn full_lifecycle_register_execute_revoke() {
        let store = BrokerStateStore::new();

        // 1. Register
        let cap = make_capability("cap-lifecycle", 300);
        store
            .register_capability(&cap, "https://api.openai.com/v1/responses".to_string())
            .await;

        // 2. Verify active
        let status = store.get_capability_status("cap-lifecycle").await.unwrap();
        assert!(matches!(status.state, BrokerCapabilityState::Active));
        assert_eq!(status.execution_count, 0);

        // 3. Record started phase
        let started = make_evidence(
            "exec-lc-start",
            "cap-lifecycle",
            BrokerExecutionPhase::Started,
        );
        store.record_evidence(&started).await;

        // 4. Record completed phase
        let completed = make_evidence(
            "exec-lc-done",
            "cap-lifecycle",
            BrokerExecutionPhase::Completed,
        );
        store.record_evidence(&completed).await;

        // 5. Verify updated stats
        let (status, executions) = store.get_capability_detail("cap-lifecycle").await.unwrap();
        assert_eq!(status.execution_count, 1);
        assert_eq!(executions.len(), 2);
        assert_eq!(status.last_status_code, Some(200));

        // 6. Revoke
        store
            .revoke_capability("cap-lifecycle", Some("end of session".to_string()))
            .await;
        let final_status = store.get_capability_status("cap-lifecycle").await.unwrap();
        assert!(matches!(final_status.state, BrokerCapabilityState::Revoked));
        assert_eq!(final_status.execution_count, 1);
    }

    #[tokio::test]
    async fn preview_lifecycle_store_approve_link_to_capability() {
        let store = BrokerStateStore::new();

        // 1. Store preview
        let mut record = make_preview_record("prev-lifecycle");
        record.preview.approval_required = true;
        record.preview.approval_state = BrokerApprovalState::Pending;
        store.store_preview(record).await;

        // 2. Verify pending
        let preview = store.get_preview("prev-lifecycle").await.unwrap();
        assert!(matches!(
            preview.approval_state,
            BrokerApprovalState::Pending
        ));

        // 3. Approve
        let approved = store
            .approve_preview("prev-lifecycle", Some("ops-lead".to_string()))
            .await
            .unwrap();
        assert!(matches!(
            approved.approval_state,
            BrokerApprovalState::Approved
        ));
        assert_eq!(approved.approver, Some("ops-lead".to_string()));

        // 4. Register capability and link via evidence
        let cap = make_capability("cap-prev-link", 300);
        store
            .register_capability(&cap, "https://example.com".to_string())
            .await;

        let mut evidence = make_evidence(
            "exec-prev-link",
            "cap-prev-link",
            BrokerExecutionPhase::Completed,
        );
        evidence.preview_id = Some("prev-lifecycle".to_string());
        store.record_evidence(&evidence).await;

        let status = store.get_capability_status("cap-prev-link").await.unwrap();
        let linked_preview = status.intent_preview.unwrap();
        assert_eq!(linked_preview.preview_id, "prev-lifecycle");
        // The preview should have the approved state from when it was stored
        assert!(matches!(
            linked_preview.approval_state,
            BrokerApprovalState::Approved
        ));
    }

    #[tokio::test]
    async fn freeze_then_revoke_all_then_unfreeze() {
        let store = BrokerStateStore::new();

        let cap1 = make_capability("cap-fr1", 300);
        let cap2 = make_capability("cap-fr2", 300);
        store
            .register_capability(&cap1, "https://example.com".to_string())
            .await;
        store
            .register_capability(&cap2, "https://example.com".to_string())
            .await;

        // Freeze provider
        store
            .freeze_provider(BrokerProvider::Openai, "freeze".to_string())
            .await;

        // Both should appear frozen
        let s1 = store.get_capability_status("cap-fr1").await.unwrap();
        assert!(matches!(s1.state, BrokerCapabilityState::Frozen));

        // Revoke all active (frozen caps are technically Active in storage, just shown as frozen)
        let count = store.revoke_all_active(Some("panic".to_string())).await;
        assert_eq!(count, 2);

        // Unfreeze provider
        store.unfreeze_provider(&BrokerProvider::Openai).await;

        // Both should still be revoked (revoke is permanent in the store)
        let s1 = store.get_capability_status("cap-fr1").await.unwrap();
        let s2 = store.get_capability_status("cap-fr2").await.unwrap();
        assert!(matches!(s1.state, BrokerCapabilityState::Revoked));
        assert!(matches!(s2.state, BrokerCapabilityState::Revoked));
    }

    #[tokio::test]
    async fn multiple_providers_isolated() {
        let store = BrokerStateStore::new();

        let mut cap_openai = make_capability("cap-oa", 300);
        cap_openai.secret_ref.provider = BrokerProvider::Openai;

        let mut cap_github = make_capability("cap-gh", 300);
        cap_github.secret_ref.provider = BrokerProvider::Github;

        store
            .register_capability(&cap_openai, "https://api.openai.com".to_string())
            .await;
        store
            .register_capability(&cap_github, "https://api.github.com".to_string())
            .await;

        // Freeze only OpenAI
        store
            .freeze_provider(BrokerProvider::Openai, "openai frozen".to_string())
            .await;

        let oa = store.get_capability_status("cap-oa").await.unwrap();
        let gh = store.get_capability_status("cap-gh").await.unwrap();
        assert!(matches!(oa.state, BrokerCapabilityState::Frozen));
        assert!(matches!(gh.state, BrokerCapabilityState::Active));
    }
}
