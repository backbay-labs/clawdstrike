use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use clawdstrike_broker_protocol::{
    BrokerCapability, BrokerExecutionEvidence, BrokerExecutionOutcome, BrokerExecutionPhase,
    BrokerProvider, HttpMethod,
};
use serde::Serialize;
use tokio::sync::RwLock;

const MAX_CAPABILITIES: usize = 512;
const MAX_EXECUTIONS: usize = 2_048;
const MAX_TIMELINE_EVENTS: usize = 4_096;

#[derive(Clone, Default)]
pub struct OperatorState {
    inner: Arc<RwLock<OperatorStateInner>>,
}

#[derive(Default)]
struct OperatorStateInner {
    frozen: bool,
    revoked_capability_ids: BTreeSet<String>,
    capabilities: BTreeMap<String, CapabilityRecord>,
    executions: BTreeMap<String, ExecutionRecord>,
    timeline: VecDeque<ExecutionTimelineEvent>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CapabilityRecord {
    pub capability_id: String,
    pub provider: BrokerProvider,
    pub secret_ref_id: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub session_id: Option<String>,
    pub endpoint_agent_id: Option<String>,
    pub runtime_agent_id: Option<String>,
    pub runtime_agent_kind: Option<String>,
    pub origin_fingerprint: Option<String>,
    pub destination_scheme: String,
    pub destination_host: String,
    pub destination_port: Option<u16>,
    pub destination_method: HttpMethod,
    pub destination_paths: Vec<String>,
    pub evidence_required: bool,
    pub revoked: bool,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExecutionRecord {
    pub execution_id: String,
    pub capability_id: String,
    pub provider: BrokerProvider,
    pub phase: BrokerExecutionPhase,
    pub outcome: Option<BrokerExecutionOutcome>,
    pub executed_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub secret_ref_id: String,
    pub url: String,
    pub method: HttpMethod,
    pub request_body_sha256: Option<String>,
    pub response_body_sha256: Option<String>,
    pub status_code: Option<u16>,
    pub bytes_sent: usize,
    pub bytes_received: usize,
    pub stream_chunk_count: Option<u64>,
    pub provider_metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExecutionTimelineEvent {
    pub execution_id: String,
    pub capability_id: String,
    pub provider: BrokerProvider,
    pub phase: BrokerExecutionPhase,
    pub occurred_at: DateTime<Utc>,
    pub url: String,
    pub status_code: Option<u16>,
    pub outcome: Option<BrokerExecutionOutcome>,
    pub bytes_received: usize,
    pub stream_chunk_count: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct OperatorSnapshot {
    pub frozen: bool,
    pub revoked_capability_ids: Vec<String>,
    pub capabilities: Vec<CapabilityRecord>,
    pub executions: Vec<ExecutionRecord>,
    pub timeline: Vec<ExecutionTimelineEvent>,
}

impl OperatorState {
    pub async fn snapshot(&self) -> OperatorSnapshot {
        let inner = self.inner.read().await;
        OperatorSnapshot {
            frozen: inner.frozen,
            revoked_capability_ids: inner.revoked_capability_ids.iter().cloned().collect(),
            capabilities: inner.capabilities.values().cloned().collect(),
            executions: inner.executions.values().cloned().collect(),
            timeline: inner.timeline.iter().cloned().collect(),
        }
    }

    pub async fn is_frozen(&self) -> bool {
        self.inner.read().await.frozen
    }

    pub async fn set_frozen(&self, frozen: bool) {
        self.inner.write().await.frozen = frozen;
    }

    pub async fn revoke_capability(&self, capability_id: &str) -> bool {
        let mut inner = self.inner.write().await;
        let inserted = inner
            .revoked_capability_ids
            .insert(capability_id.to_string());
        if let Some(record) = inner.capabilities.get_mut(capability_id) {
            record.revoked = true;
            record.last_seen_at = Utc::now();
            return true;
        }
        inserted
    }

    pub async fn is_capability_revoked(&self, capability_id: &str) -> bool {
        self.inner
            .read()
            .await
            .revoked_capability_ids
            .contains(capability_id)
    }

    pub async fn register_capability(&self, capability: &BrokerCapability) {
        let mut inner = self.inner.write().await;
        let revoked = inner
            .revoked_capability_ids
            .contains(capability.capability_id.as_str());
        let capability_id = capability.capability_id.clone();
        inner.capabilities.insert(
            capability_id.clone(),
            CapabilityRecord {
                capability_id,
                provider: capability.secret_ref.provider,
                secret_ref_id: capability.secret_ref.id.clone(),
                issued_at: capability.issued_at,
                expires_at: capability.expires_at,
                session_id: capability.session_id.clone(),
                endpoint_agent_id: capability.endpoint_agent_id.clone(),
                runtime_agent_id: capability.runtime_agent_id.clone(),
                runtime_agent_kind: capability.runtime_agent_kind.clone(),
                origin_fingerprint: capability.origin_fingerprint.clone(),
                destination_scheme: capability.destination.scheme.as_str().to_string(),
                destination_host: capability.destination.host.clone(),
                destination_port: capability.destination.port,
                destination_method: capability.destination.method,
                destination_paths: capability.destination.exact_paths.clone(),
                evidence_required: capability.evidence_required,
                revoked,
                last_seen_at: Utc::now(),
            },
        );
        trim_oldest(&mut inner.capabilities, MAX_CAPABILITIES);
    }

    pub async fn record_execution(&self, evidence: &BrokerExecutionEvidence) {
        let mut inner = self.inner.write().await;
        let completed_at = match evidence.phase {
            BrokerExecutionPhase::Completed => Some(evidence.executed_at),
            BrokerExecutionPhase::Started => None,
        };
        let executed_at = inner
            .executions
            .get(&evidence.execution_id)
            .map(|record| record.executed_at)
            .unwrap_or(evidence.executed_at);

        let execution_id = evidence.execution_id.clone();
        let capability_id = evidence.capability_id.clone();
        let provider = evidence.provider;
        let phase = evidence.phase;
        let outcome = evidence.outcome;
        let url = evidence.url.clone();

        inner.timeline.push_back(ExecutionTimelineEvent {
            execution_id: execution_id.clone(),
            capability_id: capability_id.clone(),
            provider,
            phase,
            occurred_at: evidence.executed_at,
            url: url.clone(),
            status_code: evidence.status_code,
            outcome,
            bytes_received: evidence.bytes_received,
            stream_chunk_count: evidence.stream_chunk_count,
        });
        while inner.timeline.len() > MAX_TIMELINE_EVENTS {
            let _ = inner.timeline.pop_front();
        }

        inner.executions.insert(
            execution_id.clone(),
            ExecutionRecord {
                execution_id,
                capability_id,
                provider,
                phase,
                outcome,
                executed_at,
                completed_at,
                secret_ref_id: evidence.secret_ref_id.clone(),
                url,
                method: evidence.method,
                request_body_sha256: evidence.request_body_sha256.clone(),
                response_body_sha256: evidence.response_body_sha256.clone(),
                status_code: evidence.status_code,
                bytes_sent: evidence.bytes_sent,
                bytes_received: evidence.bytes_received,
                stream_chunk_count: evidence.stream_chunk_count,
                provider_metadata: evidence.provider_metadata.clone(),
            },
        );
        trim_oldest(&mut inner.executions, MAX_EXECUTIONS);
    }
}

fn trim_oldest<T>(map: &mut BTreeMap<String, T>, max_len: usize) {
    while map.len() > max_len {
        if map.pop_first().is_none() {
            break;
        }
    }
}

trait SchemeName {
    fn as_str(&self) -> &'static str;
}

impl SchemeName for clawdstrike_broker_protocol::UrlScheme {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}
