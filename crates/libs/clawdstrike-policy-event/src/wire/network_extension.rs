//! Network Extension (NE) content filter event DTOs.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::edr::{
    DetectionFinding, EndpointObservation, EndpointProcess, HoneyArtifact,
};
use hush_core::SignedReceipt;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrNetworkExtensionEventsInput {
    #[serde(default)]
    pub events: Vec<EdrNetworkExtensionFlowEvent>,
    #[serde(default, alias = "honey_artifacts")]
    pub honey_artifacts: Vec<HoneyArtifact>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrNetworkExtensionFlowEvent {
    #[serde(default, alias = "id", alias = "eventId")]
    pub event_id: Option<String>,
    #[serde(default, alias = "observedAt", alias = "timestamp")]
    pub observed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, alias = "hostId")]
    pub host_id: Option<String>,
    #[serde(default, alias = "userId")]
    pub user_id: Option<String>,
    #[serde(default, alias = "sessionId")]
    pub session_id: Option<String>,
    #[serde(default)]
    pub process: Option<EndpointProcess>,
    #[serde(default)]
    pub metadata: BTreeMap<String, serde_json::Value>,
    #[serde(default, alias = "flowId")]
    pub flow_id: Option<String>,
    #[serde(default, alias = "sourceApp")]
    pub source_app: Option<String>,
    #[serde(default, alias = "sourceAppPath")]
    pub source_app_path: Option<String>,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default, alias = "processGuid")]
    pub process_guid: Option<String>,
    #[serde(default, alias = "parentProcessGuid")]
    pub parent_process_guid: Option<String>,
    #[serde(default, alias = "remoteHost", alias = "targetHost")]
    pub host: Option<String>,
    pub port: u16,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default, alias = "dnsQuery")]
    pub dns_query: Option<String>,
    #[serde(default, alias = "dnsRecordType")]
    pub dns_record_type: Option<String>,
    #[serde(default, alias = "dnsAnswers")]
    pub dns_answers: Vec<String>,
    #[serde(default, alias = "dnsResolver")]
    pub dns_resolver: Option<String>,
    #[serde(default, alias = "dnsStatus")]
    pub dns_status: Option<String>,
    pub verdict: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default, alias = "policySnapshotPath")]
    pub policy_snapshot_path: Option<String>,
    #[serde(default, alias = "policySnapshotHash")]
    pub policy_snapshot_hash: Option<String>,
    #[serde(default)]
    pub generation: Option<u64>,
    #[serde(default, alias = "remediationRequests")]
    pub remediation_requests: Option<u64>,
    #[serde(default, alias = "blockedFlows")]
    pub blocked_flows: Option<u64>,
    #[serde(default, alias = "allowedFlows")]
    pub allowed_flows: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrNetworkExtensionEventsResponse {
    pub event_count: usize,
    pub observation_count: usize,
    pub finding_count: usize,
    pub receipt_count: usize,
    pub observations: Vec<EndpointObservation>,
    pub findings: Vec<DetectionFinding>,
    pub receipts: Vec<SignedReceipt>,
    pub observation_receipts: Vec<SignedReceipt>,
    pub policy_decision_receipts: Vec<SignedReceipt>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdrNetworkExtensionEgressPolicyProofInput {
    #[serde(default, alias = "refreshProviders")]
    pub refresh_providers: Option<bool>,
    #[serde(default, alias = "providerRefreshTimeoutMs")]
    pub provider_refresh_timeout_ms: Option<u64>,
    #[serde(default, alias = "executionId")]
    pub execution_id: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrNetworkExtensionReloadDeliveryProof {
    pub execution_id: String,
    pub observed: bool,
    pub matched: bool,
    pub request_id_matches: bool,
    pub generation_matches: bool,
    pub policy_snapshot_path_matches: bool,
    pub provider_reloaded: Option<bool>,
}
