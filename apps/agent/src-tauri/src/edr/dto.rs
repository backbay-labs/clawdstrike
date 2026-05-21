//! EDR API request/response DTOs.
//!
//! These types are deserialized from incoming HTTP requests and serialized
//! into outgoing HTTP responses for the endpoint decision engine API. They
//! intentionally stay close to the wire shape; conversion to/from internal
//! types happens in `edr::conversion` and the API handlers in
//! `edr::handlers`.

#![allow(dead_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use chrono;

use clawdstrike_policy_event::edr::{
    CausalGraph, CausalNodeKind, CredentialKind, DeceptionCleanupReport,
    DeceptionMaterializationReport, DeceptionPlan, DeceptionRotationReport, DetectionFinding,
    EndpointDecisionAction, EndpointEvidenceBundleReference,
    EndpointFlightRecorderCompactionRecord, EndpointObservation,
    EndpointPolicySimulationIdentityContext, EndpointPolicySimulationReport,
    EndpointPolicySimulationToolContext, EndpointPolicySnapshot, EndpointProcess,
    EndpointProviderKind, EndpointResponseAcknowledgementReport, EndpointResponseExecutionReport,
    EndpointResponsePlan, EndpointResponseRollbackReport, EndpointSensorState,
    EndpointSimulationImpactLevel, EndpointTelemetryPrivacyMode, EndpointTelemetryPrivacyReport,
    HoneyArtifact, PackageManager,
};
use clawdstrike_policy_event::event::PolicyEvent;
use clawdstrike_policy_event::simulate::DecisionInfo;
use hush_core::SignedReceipt;

use std::path::PathBuf;

use clawdstrike_policy_event::edr::{
    EndpointFlightRecorderHistoryIndexEntry, EndpointGraphReference,
};
use clawdstrike_policy_event::simulate::SimulationResult;

use crate::api_server::{
    affected_identities_for_causal_impact, affected_tools_for_causal_impact,
    identity_filter_matches, ControlResponseAckPostbackRoute, NetworkExtensionReloadRequestProof,
    StoredEndpointEvidenceBundle,
};
use crate::daemon::DaemonStatus;
use crate::macos::status::ProviderStatus;

#[derive(Debug, Serialize)]
pub(crate) struct EdrHealthSummary {
    pub(crate) observation_count: usize,
    pub(crate) graph_node_count: usize,
    pub(crate) graph_edge_count: usize,
    pub(crate) recent_finding_count: usize,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdrFindingsInput {
    #[serde(default)]
    pub(crate) observations: Vec<EndpointObservation>,
    #[serde(default, alias = "honeyArtifacts")]
    pub(crate) honey_artifacts: Vec<HoneyArtifact>,
}
#[derive(Debug)]
pub(crate) struct EdrEvaluatedFindings {
    pub(crate) findings: Vec<DetectionFinding>,
    pub(crate) receipts: Vec<SignedReceipt>,
}
#[derive(Debug, Serialize)]
pub(crate) struct EdrFindingsResponse {
    pub(crate) observation_count: usize,
    pub(crate) finding_count: usize,
    pub(crate) receipt_count: usize,
    pub(crate) findings: Vec<DetectionFinding>,
    pub(crate) receipts: Vec<SignedReceipt>,
    pub(crate) observation_receipts: Vec<SignedReceipt>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdrPolicyEventsInput {
    #[serde(default)]
    pub(crate) events: Vec<PolicyEvent>,
    #[serde(default, alias = "honeyArtifacts")]
    pub(crate) honey_artifacts: Vec<HoneyArtifact>,
}
#[derive(Debug, Serialize)]
pub(crate) struct EdrPolicyEventsResponse {
    pub(crate) policy_event_count: usize,
    pub(crate) observation_count: usize,
    pub(crate) finding_count: usize,
    pub(crate) receipt_count: usize,
    pub(crate) observations: Vec<EndpointObservation>,
    pub(crate) findings: Vec<DetectionFinding>,
    pub(crate) receipts: Vec<SignedReceipt>,
    pub(crate) observation_receipts: Vec<SignedReceipt>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrDeveloperActivityInput {
    #[serde(default)]
    pub(crate) activities: Vec<EdrDeveloperActivity>,
    #[serde(default, alias = "honey_artifacts")]
    pub(crate) honey_artifacts: Vec<HoneyArtifact>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrDeveloperActivity {
    #[serde(default, alias = "id", alias = "activityId")]
    pub(crate) activity_id: Option<String>,
    pub(crate) kind: EdrDeveloperActivityKind,
    #[serde(default, alias = "observedAt", alias = "timestamp")]
    pub(crate) observed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, alias = "hostId")]
    pub(crate) host_id: Option<String>,
    #[serde(default, alias = "userId")]
    pub(crate) user_id: Option<String>,
    #[serde(default, alias = "sessionId")]
    pub(crate) session_id: Option<String>,
    #[serde(default, alias = "agentId")]
    pub(crate) agent_id: Option<String>,
    #[serde(default, alias = "workloadId")]
    pub(crate) workload_id: Option<String>,
    #[serde(default, alias = "approvalId")]
    pub(crate) approval_id: Option<String>,
    #[serde(default, alias = "toolCallId", alias = "tool_call_id")]
    pub(crate) tool_call_id: Option<String>,
    #[serde(default)]
    pub(crate) process: Option<EndpointProcess>,
    #[serde(default, alias = "processGuid", alias = "process_guid")]
    pub(crate) process_guid: Option<String>,
    #[serde(default, alias = "parentProcessGuid", alias = "parent_process_guid")]
    pub(crate) parent_process_guid: Option<String>,
    #[serde(default)]
    pub(crate) pid: Option<u32>,
    #[serde(default)]
    pub(crate) ppid: Option<u32>,
    #[serde(default, alias = "processImage", alias = "process_image")]
    pub(crate) process_image: Option<String>,
    #[serde(default, alias = "processCommandLine", alias = "process_command_line")]
    pub(crate) process_command_line: Option<String>,
    #[serde(default, alias = "processCwd", alias = "process_cwd")]
    pub(crate) process_cwd: Option<String>,
    #[serde(default)]
    pub(crate) metadata: BTreeMap<String, serde_json::Value>,
    #[serde(default, alias = "toolName")]
    pub(crate) tool_name: Option<String>,
    #[serde(default)]
    pub(crate) parameters: Option<serde_json::Value>,
    #[serde(default)]
    pub(crate) action: Option<String>,
    #[serde(default)]
    pub(crate) target: Option<String>,
    #[serde(default)]
    pub(crate) query: Option<String>,
    #[serde(default, alias = "recordType")]
    pub(crate) record_type: Option<String>,
    #[serde(default)]
    pub(crate) answers: Vec<String>,
    #[serde(default)]
    pub(crate) resolver: Option<String>,
    #[serde(default)]
    pub(crate) status: Option<String>,
    #[serde(default)]
    pub(crate) manager: Option<PackageManager>,
    #[serde(default)]
    pub(crate) package: Option<String>,
    #[serde(default)]
    pub(crate) phase: Option<String>,
    #[serde(default)]
    pub(crate) script: Option<String>,
    #[serde(default, alias = "workingDirectory")]
    pub(crate) working_directory: Option<String>,
    #[serde(default)]
    pub(crate) provider: Option<String>,
    #[serde(default)]
    pub(crate) operation: Option<String>,
    #[serde(default)]
    pub(crate) args: Vec<String>,
    #[serde(default)]
    pub(crate) image: Option<String>,
    #[serde(default, alias = "commandLine")]
    pub(crate) command_line: Option<String>,
    #[serde(default)]
    pub(crate) host: Option<String>,
    #[serde(default)]
    pub(crate) port: Option<u16>,
    #[serde(default)]
    pub(crate) protocol: Option<String>,
    #[serde(default)]
    pub(crate) method: Option<String>,
    #[serde(default)]
    pub(crate) url: Option<String>,
    #[serde(default)]
    pub(crate) path: Option<String>,
    #[serde(default, alias = "contentHash")]
    pub(crate) content_hash: Option<String>,
    #[serde(
        default,
        alias = "byteCount",
        alias = "downloadByteCount",
        alias = "download_byte_count",
        alias = "fileSize",
        alias = "file_size",
        alias = "transferSize",
        alias = "transfer_size"
    )]
    pub(crate) byte_count: Option<u64>,
    #[serde(default, alias = "patchBytes")]
    pub(crate) patch_bytes: Option<u64>,
    #[serde(default, alias = "patchHash")]
    pub(crate) patch_hash: Option<String>,
    #[serde(default)]
    pub(crate) mechanism: Option<String>,
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default, alias = "credentialKind")]
    pub(crate) credential_kind: Option<CredentialKind>,
    #[serde(default)]
    pub(crate) browser: Option<String>,
    #[serde(default, alias = "sourceUrl")]
    pub(crate) source_url: Option<String>,
    #[serde(default, alias = "extensionId")]
    pub(crate) extension_id: Option<String>,
    #[serde(default)]
    pub(crate) source: Option<String>,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EdrDeveloperActivityKind {
    McpTool,
    BrowserAutomation,
    BrowserDownload,
    BrowserExtension,
    DnsLookup,
    NetworkEgress,
    FileRead,
    FileWrite,
    PatchApply,
    PersistenceChange,
    PackageScript,
    CloudCli,
    ShellCommand,
    RepoSecret,
    CiToken,
    LocalApiKey,
    BrowserCookie,
}
impl EdrDeveloperActivityKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::McpTool => "mcp_tool",
            Self::BrowserAutomation => "browser_automation",
            Self::BrowserDownload => "browser_download",
            Self::BrowserExtension => "browser_extension",
            Self::DnsLookup => "dns_lookup",
            Self::NetworkEgress => "network_egress",
            Self::FileRead => "file_read",
            Self::FileWrite => "file_write",
            Self::PatchApply => "patch_apply",
            Self::PersistenceChange => "persistence_change",
            Self::PackageScript => "package_script",
            Self::CloudCli => "cloud_cli",
            Self::ShellCommand => "shell_command",
            Self::RepoSecret => "repo_secret",
            Self::CiToken => "ci_token",
            Self::LocalApiKey => "local_api_key",
            Self::BrowserCookie => "browser_cookie",
        }
    }
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrDeveloperActivityResponse {
    pub(crate) activity_count: usize,
    pub(crate) observation_count: usize,
    pub(crate) finding_count: usize,
    pub(crate) receipt_count: usize,
    pub(crate) observations: Vec<EndpointObservation>,
    pub(crate) findings: Vec<DetectionFinding>,
    pub(crate) receipts: Vec<SignedReceipt>,
    pub(crate) observation_receipts: Vec<SignedReceipt>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrPackageManagerEventsInput {
    #[serde(default)]
    pub(crate) events: Vec<EdrPackageManagerEvent>,
    #[serde(default, alias = "honey_artifacts")]
    pub(crate) honey_artifacts: Vec<HoneyArtifact>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrPackageManagerEvent {
    #[serde(default, alias = "id", alias = "eventId")]
    pub(crate) event_id: Option<String>,
    #[serde(default, alias = "observedAt", alias = "timestamp")]
    pub(crate) observed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, alias = "hostId")]
    pub(crate) host_id: Option<String>,
    #[serde(default, alias = "userId")]
    pub(crate) user_id: Option<String>,
    #[serde(default, alias = "sessionId")]
    pub(crate) session_id: Option<String>,
    #[serde(default, alias = "agentId")]
    pub(crate) agent_id: Option<String>,
    #[serde(default, alias = "workloadId")]
    pub(crate) workload_id: Option<String>,
    #[serde(default, alias = "approvalId")]
    pub(crate) approval_id: Option<String>,
    #[serde(default, alias = "toolCallId", alias = "tool_call_id")]
    pub(crate) tool_call_id: Option<String>,
    #[serde(default)]
    pub(crate) process: Option<EndpointProcess>,
    #[serde(default)]
    pub(crate) metadata: BTreeMap<String, serde_json::Value>,
    pub(crate) manager: PackageManager,
    #[serde(default)]
    pub(crate) package: Option<String>,
    pub(crate) phase: String,
    pub(crate) script: String,
    #[serde(default, alias = "workingDirectory")]
    pub(crate) working_directory: Option<String>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPackageManagerEventsResponse {
    pub(crate) event_count: usize,
    pub(crate) observation_count: usize,
    pub(crate) finding_count: usize,
    pub(crate) receipt_count: usize,
    pub(crate) observations: Vec<EndpointObservation>,
    pub(crate) findings: Vec<DetectionFinding>,
    pub(crate) receipts: Vec<SignedReceipt>,
    pub(crate) observation_receipts: Vec<SignedReceipt>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrEndpointSecurityEventsInput {
    #[serde(default)]
    pub(crate) events: Vec<EdrEndpointSecurityEvent>,
    #[serde(default, alias = "honey_artifacts")]
    pub(crate) honey_artifacts: Vec<HoneyArtifact>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrEndpointSecurityEvent {
    #[serde(default, alias = "id", alias = "eventId")]
    pub(crate) event_id: Option<String>,
    pub(crate) kind: EdrEndpointSecurityEventKind,
    #[serde(default, alias = "observedAt", alias = "timestamp")]
    pub(crate) observed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, alias = "hostId")]
    pub(crate) host_id: Option<String>,
    #[serde(default, alias = "userId")]
    pub(crate) user_id: Option<String>,
    #[serde(default, alias = "sessionId")]
    pub(crate) session_id: Option<String>,
    #[serde(default)]
    pub(crate) process: Option<EndpointProcess>,
    #[serde(default)]
    pub(crate) metadata: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub(crate) pid: Option<u32>,
    #[serde(default)]
    pub(crate) ppid: Option<u32>,
    #[serde(default, alias = "processGuid")]
    pub(crate) process_guid: Option<String>,
    #[serde(default, alias = "parentProcessGuid")]
    pub(crate) parent_process_guid: Option<String>,
    #[serde(default)]
    pub(crate) image: Option<String>,
    #[serde(default)]
    pub(crate) args: Vec<String>,
    #[serde(default, alias = "commandLine")]
    pub(crate) command_line: Option<String>,
    #[serde(default)]
    pub(crate) cwd: Option<String>,
    #[serde(default, alias = "targetPath")]
    pub(crate) path: Option<String>,
    #[serde(default)]
    pub(crate) operation: Option<String>,
    #[serde(default)]
    pub(crate) decision: Option<String>,
    #[serde(default)]
    pub(crate) reason: Option<String>,
    #[serde(default, alias = "deadlineMissed")]
    pub(crate) deadline_missed: Option<bool>,
    #[serde(default, alias = "deadlineMs")]
    pub(crate) deadline_ms: Option<u64>,
    #[serde(default, alias = "droppedEvents")]
    pub(crate) dropped_event_count: Option<u64>,
    #[serde(default, alias = "deadlineMisses")]
    pub(crate) deadline_miss_count: Option<u64>,
    #[serde(default)]
    pub(crate) full_disk_access: Option<bool>,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EdrEndpointSecurityEventKind {
    ProcessExec,
    FileAccess,
    AuthOpen,
    EventLoss,
}
impl EdrEndpointSecurityEventKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ProcessExec => "process_exec",
            Self::FileAccess => "file_access",
            Self::AuthOpen => "auth_open",
            Self::EventLoss => "event_loss",
        }
    }
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrEndpointSecurityEventsResponse {
    pub(crate) event_count: usize,
    pub(crate) observation_count: usize,
    pub(crate) finding_count: usize,
    pub(crate) receipt_count: usize,
    pub(crate) observations: Vec<EndpointObservation>,
    pub(crate) findings: Vec<DetectionFinding>,
    pub(crate) receipts: Vec<SignedReceipt>,
    pub(crate) observation_receipts: Vec<SignedReceipt>,
    pub(crate) policy_decision_receipts: Vec<SignedReceipt>,
    pub(crate) degraded_provider_receipts: Vec<SignedReceipt>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrNetworkExtensionEventsInput {
    #[serde(default)]
    pub(crate) events: Vec<EdrNetworkExtensionFlowEvent>,
    #[serde(default, alias = "honey_artifacts")]
    pub(crate) honey_artifacts: Vec<HoneyArtifact>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrNetworkExtensionFlowEvent {
    #[serde(default, alias = "id", alias = "eventId")]
    pub(crate) event_id: Option<String>,
    #[serde(default, alias = "observedAt", alias = "timestamp")]
    pub(crate) observed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, alias = "hostId")]
    pub(crate) host_id: Option<String>,
    #[serde(default, alias = "userId")]
    pub(crate) user_id: Option<String>,
    #[serde(default, alias = "sessionId")]
    pub(crate) session_id: Option<String>,
    #[serde(default)]
    pub(crate) process: Option<EndpointProcess>,
    #[serde(default)]
    pub(crate) metadata: BTreeMap<String, serde_json::Value>,
    #[serde(default, alias = "flowId")]
    pub(crate) flow_id: Option<String>,
    #[serde(default, alias = "sourceApp")]
    pub(crate) source_app: Option<String>,
    #[serde(default, alias = "sourceAppPath")]
    pub(crate) source_app_path: Option<String>,
    #[serde(default)]
    pub(crate) pid: Option<u32>,
    #[serde(default, alias = "processGuid")]
    pub(crate) process_guid: Option<String>,
    #[serde(default, alias = "parentProcessGuid")]
    pub(crate) parent_process_guid: Option<String>,
    #[serde(default, alias = "remoteHost", alias = "targetHost")]
    pub(crate) host: Option<String>,
    pub(crate) port: u16,
    #[serde(default)]
    pub(crate) protocol: Option<String>,
    #[serde(default)]
    pub(crate) url: Option<String>,
    #[serde(default, alias = "dnsQuery")]
    pub(crate) dns_query: Option<String>,
    #[serde(default, alias = "dnsRecordType")]
    pub(crate) dns_record_type: Option<String>,
    #[serde(default, alias = "dnsAnswers")]
    pub(crate) dns_answers: Vec<String>,
    #[serde(default, alias = "dnsResolver")]
    pub(crate) dns_resolver: Option<String>,
    #[serde(default, alias = "dnsStatus")]
    pub(crate) dns_status: Option<String>,
    pub(crate) verdict: String,
    #[serde(default)]
    pub(crate) reason: Option<String>,
    #[serde(default, alias = "policySnapshotPath")]
    pub(crate) policy_snapshot_path: Option<String>,
    #[serde(default, alias = "policySnapshotHash")]
    pub(crate) policy_snapshot_hash: Option<String>,
    #[serde(default)]
    pub(crate) generation: Option<u64>,
    #[serde(default, alias = "remediationRequests")]
    pub(crate) remediation_requests: Option<u64>,
    #[serde(default, alias = "blockedFlows")]
    pub(crate) blocked_flows: Option<u64>,
    #[serde(default, alias = "allowedFlows")]
    pub(crate) allowed_flows: Option<u64>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrNetworkExtensionEventsResponse {
    pub(crate) event_count: usize,
    pub(crate) observation_count: usize,
    pub(crate) finding_count: usize,
    pub(crate) receipt_count: usize,
    pub(crate) observations: Vec<EndpointObservation>,
    pub(crate) findings: Vec<DetectionFinding>,
    pub(crate) receipts: Vec<SignedReceipt>,
    pub(crate) observation_receipts: Vec<SignedReceipt>,
    pub(crate) policy_decision_receipts: Vec<SignedReceipt>,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrPolicyEventReplayInput {
    #[serde(default)]
    pub(crate) events: Vec<PolicyEvent>,
    #[serde(default)]
    pub(crate) track_posture: Option<bool>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventReplayReport {
    pub(crate) replay_id: String,
    pub(crate) replayed_at: chrono::DateTime<chrono::Utc>,
    pub(crate) mode: String,
    pub(crate) policy: EndpointPolicySnapshot,
    pub(crate) event_count: u64,
    pub(crate) allowed_count: u64,
    pub(crate) warn_count: u64,
    pub(crate) blocked_count: u64,
    pub(crate) track_posture: bool,
    pub(crate) event_stream_hash: String,
    pub(crate) result_hash: String,
    pub(crate) summary: String,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventReplayResponse {
    pub(crate) replay: EdrPolicyEventReplayReport,
    pub(crate) result: SimulationResult,
    pub(crate) receipt: SignedReceipt,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrPolicyEventImpactInput {
    #[serde(default)]
    pub(crate) events: Vec<PolicyEvent>,
    #[serde(alias = "proposedPolicyYaml")]
    pub(crate) proposed_policy_yaml: String,
    #[serde(default)]
    pub(crate) track_posture: Option<bool>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventImpactSummary {
    pub(crate) total: u64,
    pub(crate) changed: u64,
    pub(crate) allow_to_warn: u64,
    pub(crate) allow_to_block: u64,
    pub(crate) warn_to_allow: u64,
    pub(crate) warn_to_block: u64,
    pub(crate) block_to_allow: u64,
    pub(crate) block_to_warn: u64,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventImpactEntry {
    pub(crate) event_id: String,
    pub(crate) current_outcome: String,
    pub(crate) proposed_outcome: String,
    pub(crate) changed: bool,
    pub(crate) current_decision: DecisionInfo,
    pub(crate) proposed_decision: DecisionInfo,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventImpactDriver {
    pub(crate) current_outcome: String,
    pub(crate) proposed_outcome: String,
    pub(crate) current_guard: Option<String>,
    pub(crate) proposed_guard: Option<String>,
    pub(crate) current_reason_code: String,
    pub(crate) proposed_reason_code: String,
    pub(crate) count: u64,
    pub(crate) sample_event_ids: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct EdrPolicyEventImpactDriverKey {
    pub(crate) current_outcome: String,
    pub(crate) proposed_outcome: String,
    pub(crate) current_guard: Option<String>,
    pub(crate) proposed_guard: Option<String>,
    pub(crate) current_reason_code: String,
    pub(crate) proposed_reason_code: String,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventImpactReport {
    pub(crate) impact_id: String,
    pub(crate) analyzed_at: chrono::DateTime<chrono::Utc>,
    pub(crate) mode: String,
    pub(crate) current_policy: EndpointPolicySnapshot,
    pub(crate) proposed_policy: EndpointPolicySnapshot,
    pub(crate) event_count: u64,
    pub(crate) changed_count: u64,
    pub(crate) allow_to_block_count: u64,
    pub(crate) track_posture: bool,
    pub(crate) event_stream_hash: String,
    pub(crate) current_result_hash: String,
    pub(crate) proposed_result_hash: String,
    pub(crate) impact_hash: String,
    pub(crate) summary: String,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventImpactResponse {
    pub(crate) impact: EdrPolicyEventImpactReport,
    pub(crate) summary: EdrPolicyEventImpactSummary,
    pub(crate) drivers: Vec<EdrPolicyEventImpactDriver>,
    pub(crate) changes: Vec<EdrPolicyEventImpactEntry>,
    pub(crate) current_result: SimulationResult,
    pub(crate) proposed_result: SimulationResult,
    pub(crate) receipt: SignedReceipt,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrPolicyEventHistoryReplayInput {
    #[serde(default)]
    pub(crate) limit: Option<usize>,
    #[serde(default)]
    pub(crate) since: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub(crate) until: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub(crate) max_age_seconds: Option<u64>,
    #[serde(default)]
    pub(crate) track_posture: Option<bool>,
    #[serde(default)]
    pub(crate) event_kinds: Vec<String>,
    #[serde(default, alias = "host_id")]
    pub(crate) host_id: Option<String>,
    #[serde(default, alias = "user_id")]
    pub(crate) user_id: Option<String>,
    #[serde(default, alias = "session_id")]
    pub(crate) session_id: Option<String>,
    #[serde(default, alias = "process_guid")]
    pub(crate) process_guid: Option<String>,
    #[serde(default, alias = "parent_process_guid")]
    pub(crate) parent_process_guid: Option<String>,
    #[serde(default, alias = "agent_id")]
    pub(crate) agent_id: Option<String>,
    #[serde(default, alias = "workload_id")]
    pub(crate) workload_id: Option<String>,
    #[serde(default, alias = "approval_id")]
    pub(crate) approval_id: Option<String>,
    #[serde(default, alias = "tool_name")]
    pub(crate) tool_name: Option<String>,
    #[serde(default, alias = "tool_call_id")]
    pub(crate) tool_call_id: Option<String>,
    #[serde(default, alias = "credential_kind")]
    pub(crate) credential_kind: Option<String>,
    #[serde(default, alias = "process_image_hash")]
    pub(crate) process_image_hash: Option<String>,
    #[serde(default, alias = "process_command_line_hash")]
    pub(crate) process_command_line_hash: Option<String>,
    #[serde(
        default,
        alias = "event_target",
        alias = "target",
        alias = "resourceTarget",
        alias = "resource_target"
    )]
    pub(crate) event_target: Option<String>,
    #[serde(
        default,
        alias = "event_target_hash",
        alias = "targetHash",
        alias = "target_hash",
        alias = "resourceTargetHash",
        alias = "resource_target_hash"
    )]
    pub(crate) event_target_hash: Option<String>,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrPolicyEventHistoryImpactInput {
    #[serde(default)]
    pub(crate) limit: Option<usize>,
    #[serde(default)]
    pub(crate) since: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub(crate) until: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub(crate) max_age_seconds: Option<u64>,
    #[serde(default)]
    pub(crate) track_posture: Option<bool>,
    #[serde(default)]
    pub(crate) event_kinds: Vec<String>,
    #[serde(default, alias = "host_id")]
    pub(crate) host_id: Option<String>,
    #[serde(default, alias = "user_id")]
    pub(crate) user_id: Option<String>,
    #[serde(default, alias = "session_id")]
    pub(crate) session_id: Option<String>,
    #[serde(default, alias = "process_guid")]
    pub(crate) process_guid: Option<String>,
    #[serde(default, alias = "parent_process_guid")]
    pub(crate) parent_process_guid: Option<String>,
    #[serde(default, alias = "agent_id")]
    pub(crate) agent_id: Option<String>,
    #[serde(default, alias = "workload_id")]
    pub(crate) workload_id: Option<String>,
    #[serde(default, alias = "approval_id")]
    pub(crate) approval_id: Option<String>,
    #[serde(default, alias = "tool_name")]
    pub(crate) tool_name: Option<String>,
    #[serde(default, alias = "tool_call_id")]
    pub(crate) tool_call_id: Option<String>,
    #[serde(default, alias = "credential_kind")]
    pub(crate) credential_kind: Option<String>,
    #[serde(default, alias = "process_image_hash")]
    pub(crate) process_image_hash: Option<String>,
    #[serde(default, alias = "process_command_line_hash")]
    pub(crate) process_command_line_hash: Option<String>,
    #[serde(
        default,
        alias = "event_target",
        alias = "target",
        alias = "resourceTarget",
        alias = "resource_target"
    )]
    pub(crate) event_target: Option<String>,
    #[serde(
        default,
        alias = "event_target_hash",
        alias = "targetHash",
        alias = "target_hash",
        alias = "resourceTargetHash",
        alias = "resource_target_hash"
    )]
    pub(crate) event_target_hash: Option<String>,
    #[serde(default)]
    pub(crate) causal_context_depth: Option<usize>,
    #[serde(default)]
    pub(crate) validation_window_seconds: Option<u64>,
    #[serde(alias = "proposedPolicyYaml")]
    pub(crate) proposed_policy_yaml: String,
}
impl EdrPolicyEventHistoryReplayInput {
    pub(crate) fn identity_filters(&self) -> EdrPolicyEventHistoryIdentityFilters {
        EdrPolicyEventHistoryIdentityFilters {
            host_id: self.host_id.clone(),
            user_id: self.user_id.clone(),
            session_id: self.session_id.clone(),
            process_guid: self.process_guid.clone(),
            parent_process_guid: self.parent_process_guid.clone(),
            agent_id: self.agent_id.clone(),
            workload_id: self.workload_id.clone(),
            approval_id: self.approval_id.clone(),
            tool_name: self.tool_name.clone(),
            tool_call_id: self.tool_call_id.clone(),
            credential_kind: self.credential_kind.clone(),
        }
    }

    pub(crate) fn process_filters(&self) -> EdrPolicyEventHistoryProcessFilters {
        EdrPolicyEventHistoryProcessFilters {
            process_image_hash: self.process_image_hash.clone(),
            process_command_line_hash: self.process_command_line_hash.clone(),
        }
    }

    pub(crate) fn target_filters(&self) -> EdrPolicyEventHistoryTargetFilters {
        EdrPolicyEventHistoryTargetFilters {
            event_target: self.event_target.clone(),
            event_target_hash: self.event_target_hash.clone(),
        }
    }
}
impl EdrPolicyEventHistoryImpactInput {
    pub(crate) fn replay_selector_input(&self) -> EdrPolicyEventHistoryReplayInput {
        EdrPolicyEventHistoryReplayInput {
            limit: self.limit,
            since: self.since,
            until: self.until,
            max_age_seconds: self.max_age_seconds,
            track_posture: self.track_posture,
            event_kinds: self.event_kinds.clone(),
            host_id: self.host_id.clone(),
            user_id: self.user_id.clone(),
            session_id: self.session_id.clone(),
            process_guid: self.process_guid.clone(),
            parent_process_guid: self.parent_process_guid.clone(),
            agent_id: self.agent_id.clone(),
            workload_id: self.workload_id.clone(),
            approval_id: self.approval_id.clone(),
            tool_name: self.tool_name.clone(),
            tool_call_id: self.tool_call_id.clone(),
            credential_kind: self.credential_kind.clone(),
            process_image_hash: self.process_image_hash.clone(),
            process_command_line_hash: self.process_command_line_hash.clone(),
            event_target: self.event_target.clone(),
            event_target_hash: self.event_target_hash.clone(),
        }
    }
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventHistoryIdentityFilters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) host_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) process_guid: Option<String>,
    #[serde(
        default,
        alias = "parent_process_guid",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) parent_process_guid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) workload_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) approval_id: Option<String>,
    #[serde(default, alias = "tool_name", skip_serializing_if = "Option::is_none")]
    pub(crate) tool_name: Option<String>,
    #[serde(
        default,
        alias = "tool_call_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) tool_call_id: Option<String>,
    #[serde(
        default,
        alias = "credential_kind",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) credential_kind: Option<String>,
}
impl EdrPolicyEventHistoryIdentityFilters {
    pub(crate) fn matches_index_entry(
        &self,
        entry: &EndpointFlightRecorderHistoryIndexEntry,
    ) -> bool {
        identity_filter_matches(&self.host_id, entry.host_id.as_deref())
            && identity_filter_matches(&self.user_id, entry.user_id.as_deref())
            && identity_filter_matches(&self.session_id, entry.session_id.as_deref())
            && identity_filter_matches(&self.process_guid, entry.process_guid.as_deref())
            && identity_filter_matches(
                &self.parent_process_guid,
                entry.parent_process_guid.as_deref(),
            )
            && identity_filter_matches(&self.agent_id, entry.agent_id.as_deref())
            && identity_filter_matches(&self.workload_id, entry.workload_id.as_deref())
            && identity_filter_matches(&self.approval_id, entry.approval_id.as_deref())
            && identity_filter_matches(&self.tool_name, entry.tool_name.as_deref())
            && identity_filter_matches(&self.tool_call_id, entry.tool_call_id.as_deref())
            && identity_filter_matches(&self.credential_kind, entry.credential_kind.as_deref())
    }
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventHistoryProcessFilters {
    #[serde(
        default,
        alias = "process_image_hash",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) process_image_hash: Option<String>,
    #[serde(
        default,
        alias = "process_command_line_hash",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) process_command_line_hash: Option<String>,
}
impl EdrPolicyEventHistoryProcessFilters {
    pub(crate) fn is_empty(&self) -> bool {
        self.process_image_hash.is_none() && self.process_command_line_hash.is_none()
    }

    pub(crate) fn matches_index_entry(
        &self,
        entry: &EndpointFlightRecorderHistoryIndexEntry,
    ) -> bool {
        identity_filter_matches(
            &self.process_image_hash,
            entry.process_image_hash.as_deref(),
        ) && identity_filter_matches(
            &self.process_command_line_hash,
            entry.process_command_line_hash.as_deref(),
        )
    }
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventHistoryTargetFilters {
    #[serde(
        default,
        alias = "event_target",
        alias = "target",
        alias = "resourceTarget",
        alias = "resource_target",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) event_target: Option<String>,
    #[serde(
        default,
        alias = "event_target_hash",
        alias = "targetHash",
        alias = "target_hash",
        alias = "resourceTargetHash",
        alias = "resource_target_hash",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) event_target_hash: Option<String>,
}
impl EdrPolicyEventHistoryTargetFilters {
    pub(crate) fn is_empty(&self) -> bool {
        self.event_target.is_none() && self.event_target_hash.is_none()
    }

    pub(crate) fn matches_index_entry(
        &self,
        entry: &EndpointFlightRecorderHistoryIndexEntry,
    ) -> bool {
        identity_filter_matches(&self.event_target, entry.event_target.as_deref())
            && identity_filter_matches(&self.event_target_hash, entry.event_target_hash.as_deref())
    }
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventHistoryReport {
    pub(crate) source: String,
    pub(crate) projection_mode: String,
    pub(crate) selection_mode: String,
    pub(crate) path: Option<String>,
    pub(crate) index_path: Option<String>,
    pub(crate) total_observation_count: usize,
    pub(crate) matched_observation_count: usize,
    pub(crate) selected_observation_count: usize,
    pub(crate) policy_event_count: usize,
    pub(crate) limit: usize,
    pub(crate) since: Option<chrono::DateTime<chrono::Utc>>,
    pub(crate) until: Option<chrono::DateTime<chrono::Utc>>,
    pub(crate) max_age_seconds: Option<u64>,
    pub(crate) event_kinds: Vec<String>,
    pub(crate) identity_filters: EdrPolicyEventHistoryIdentityFilters,
    #[serde(skip_serializing_if = "EdrPolicyEventHistoryProcessFilters::is_empty")]
    pub(crate) process_filters: EdrPolicyEventHistoryProcessFilters,
    #[serde(skip_serializing_if = "EdrPolicyEventHistoryTargetFilters::is_empty")]
    pub(crate) target_filters: EdrPolicyEventHistoryTargetFilters,
    pub(crate) oldest_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub(crate) newest_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub(crate) event_stream_hash: String,
    pub(crate) summary: String,
}
#[derive(Debug)]
pub(crate) struct EdrPolicyEventHistorySelection {
    pub(crate) report: EdrPolicyEventHistoryReport,
    pub(crate) events: Vec<PolicyEvent>,
    pub(crate) observations: Vec<EndpointObservation>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventHistoryReplayResponse {
    pub(crate) history: EdrPolicyEventHistoryReport,
    pub(crate) replay: EdrPolicyEventReplayReport,
    pub(crate) result: SimulationResult,
    pub(crate) receipt: SignedReceipt,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventHistoryImpactResponse {
    pub(crate) history: EdrPolicyEventHistoryReport,
    pub(crate) causal_impact: EdrPolicyEventHistoryCausalImpact,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cross_window_impact: Option<EdrPolicyEventHistoryCrossWindowImpact>,
    pub(crate) impact: EdrPolicyEventImpactReport,
    pub(crate) summary: EdrPolicyEventImpactSummary,
    pub(crate) drivers: Vec<EdrPolicyEventImpactDriver>,
    pub(crate) changes: Vec<EdrPolicyEventImpactEntry>,
    pub(crate) current_result: SimulationResult,
    pub(crate) proposed_result: SimulationResult,
    pub(crate) receipt: SignedReceipt,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventHistoryCrossWindowImpact {
    pub(crate) window_seconds: u64,
    pub(crate) window_count: usize,
    pub(crate) changed_window_count: usize,
    pub(crate) blocking_window_count: usize,
    pub(crate) total_event_count: u64,
    pub(crate) total_changed_count: u64,
    pub(crate) total_blocking_change_count: u64,
    pub(crate) impact_hash: String,
    pub(crate) repeatability: String,
    pub(crate) recommended_stage: String,
    pub(crate) promotion_ready: bool,
    pub(crate) recommendation_hash: String,
    pub(crate) recommendation_reason: String,
    pub(crate) windows: Vec<EdrPolicyEventHistoryImpactWindow>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventHistoryImpactWindow {
    pub(crate) window_index: i64,
    pub(crate) window_start: chrono::DateTime<chrono::Utc>,
    pub(crate) window_end: chrono::DateTime<chrono::Utc>,
    pub(crate) event_count: u64,
    pub(crate) changed_count: u64,
    pub(crate) blocking_change_count: u64,
    pub(crate) sample_event_ids: Vec<String>,
}
#[derive(Debug, Default)]
pub(crate) struct EdrPolicyEventHistoryImpactWindowAccumulator {
    pub(crate) window_start: Option<chrono::DateTime<chrono::Utc>>,
    pub(crate) window_end: Option<chrono::DateTime<chrono::Utc>>,
    pub(crate) event_count: u64,
    pub(crate) changed_count: u64,
    pub(crate) blocking_change_count: u64,
    pub(crate) sample_event_ids: Vec<String>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventHistoryCausalImpact {
    pub(crate) changed_event_count: u64,
    pub(crate) context_count: usize,
    pub(crate) chain_count: usize,
    pub(crate) chain_driver_count: usize,
    pub(crate) promotion_suggestion_count: usize,
    pub(crate) affected_identity_count: usize,
    pub(crate) affected_tool_count: usize,
    pub(crate) blocking_change_count: u64,
    pub(crate) developer_breakage_score: u8,
    pub(crate) impact_level: EndpointSimulationImpactLevel,
    pub(crate) breakage_driver_count: usize,
    pub(crate) omitted_context_count: usize,
    pub(crate) missing_graph_context_count: usize,
    pub(crate) context_depth: usize,
    pub(crate) node_count: usize,
    pub(crate) edge_count: usize,
    pub(crate) node_kinds: BTreeMap<String, u64>,
    pub(crate) affected_identities: EdrPolicyEventHistoryAffectedIdentities,
    pub(crate) affected_tools: Vec<EdrPolicyEventHistoryAffectedTool>,
    pub(crate) top_breakage_drivers: Vec<EdrPolicyEventHistoryBreakageDriver>,
    pub(crate) contexts: Vec<EdrPolicyEventHistoryCausalContext>,
    pub(crate) chain_drivers: Vec<EdrPolicyEventHistoryCausalChainDriver>,
    pub(crate) promotion_suggestions: Vec<EdrPolicyEventHistoryPromotionSuggestion>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) receipt: Option<SignedReceipt>,
}
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventHistoryAffectedIdentities {
    pub(crate) hosts: Vec<EdrPolicyEventHistoryAffectedIdentity>,
    pub(crate) users: Vec<EdrPolicyEventHistoryAffectedIdentity>,
    pub(crate) sessions: Vec<EdrPolicyEventHistoryAffectedIdentity>,
    pub(crate) agents: Vec<EdrPolicyEventHistoryAffectedIdentity>,
    pub(crate) workloads: Vec<EdrPolicyEventHistoryAffectedIdentity>,
    pub(crate) approvals: Vec<EdrPolicyEventHistoryAffectedIdentity>,
}
impl EdrPolicyEventHistoryAffectedIdentities {
    pub(crate) fn count(&self) -> usize {
        self.hosts.len()
            + self.users.len()
            + self.sessions.len()
            + self.agents.len()
            + self.workloads.len()
            + self.approvals.len()
    }
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventHistoryAffectedIdentity {
    pub(crate) node_id: String,
    pub(crate) label: String,
    pub(crate) id: String,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventHistoryAffectedTool {
    pub(crate) node_id: String,
    pub(crate) label: String,
    pub(crate) tool_name: String,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventHistoryBreakageDriver {
    pub(crate) node_id: String,
    pub(crate) kind: CausalNodeKind,
    pub(crate) label: String,
    pub(crate) workflow_category: String,
    pub(crate) breakage_score: u8,
    pub(crate) reason: String,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventHistoryCausalContext {
    pub(crate) event_id: String,
    pub(crate) current_outcome: String,
    pub(crate) proposed_outcome: String,
    pub(crate) current_guard: Option<String>,
    pub(crate) proposed_guard: Option<String>,
    pub(crate) current_reason_code: String,
    pub(crate) proposed_reason_code: String,
    pub(crate) root_node_id: String,
    pub(crate) root_label: String,
    pub(crate) node_count: usize,
    pub(crate) edge_count: usize,
    pub(crate) chain_count: usize,
    pub(crate) chains: Vec<EdrPolicyEventHistoryCausalChain>,
    pub(crate) node_kinds: BTreeMap<String, u64>,
    pub(crate) graph: CausalGraph,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventHistoryCausalChain {
    pub(crate) target_node_id: String,
    pub(crate) target_label: String,
    pub(crate) target_kind: String,
    pub(crate) path_node_count: usize,
    pub(crate) path_edge_count: usize,
    pub(crate) nodes: Vec<EdrPolicyEventHistoryCausalChainNode>,
    pub(crate) edge_kinds: Vec<String>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventHistoryCausalChainNode {
    pub(crate) node_id: String,
    pub(crate) kind: String,
    pub(crate) label: String,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventHistoryCausalChainDriver {
    pub(crate) driver_id: String,
    pub(crate) current_outcome: String,
    pub(crate) proposed_outcome: String,
    pub(crate) current_guard: Option<String>,
    pub(crate) proposed_guard: Option<String>,
    pub(crate) current_reason_code: String,
    pub(crate) proposed_reason_code: String,
    pub(crate) target_kind: String,
    pub(crate) action: EndpointDecisionAction,
    pub(crate) edge_kinds: Vec<String>,
    pub(crate) count: u64,
    pub(crate) sample_event_ids: Vec<String>,
    pub(crate) sample_target_node_ids: Vec<String>,
    pub(crate) sample_target_labels: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct EdrPolicyEventHistoryCausalChainDriverKey {
    pub(crate) current_outcome: String,
    pub(crate) proposed_outcome: String,
    pub(crate) current_guard: Option<String>,
    pub(crate) proposed_guard: Option<String>,
    pub(crate) current_reason_code: String,
    pub(crate) proposed_reason_code: String,
    pub(crate) target_kind: String,
    pub(crate) action: String,
    pub(crate) edge_kinds: Vec<String>,
}
#[derive(Debug, Default)]
pub(crate) struct EdrPolicyEventHistoryCausalChainDriverBucket {
    pub(crate) count: u64,
    pub(crate) sample_event_ids: Vec<String>,
    pub(crate) sample_target_node_ids: Vec<String>,
    pub(crate) sample_target_labels: Vec<String>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventHistoryPromotionSuggestion {
    pub(crate) suggestion_id: String,
    pub(crate) event_id: String,
    pub(crate) target_node_id: String,
    pub(crate) target_label: String,
    pub(crate) target_kind: String,
    pub(crate) action: EndpointDecisionAction,
    pub(crate) selected_stage: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cross_window_impact_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cross_window_recommendation_hash: Option<String>,
    pub(crate) reason: String,
    pub(crate) candidate_endpoint: String,
    pub(crate) candidate_request: EdrPolicyEventHistoryPromotionCandidateRequest,
    pub(crate) stage_endpoint: String,
    pub(crate) stage_request: EdrPolicyEventHistoryPromotionStageRequest,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventHistoryPromotionCandidateRequest {
    pub(crate) root_node_id: String,
    pub(crate) action: EndpointDecisionAction,
    pub(crate) max_depth: usize,
    pub(crate) description: String,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyEventHistoryPromotionStageRequest {
    pub(crate) root_node_id: String,
    pub(crate) action: EndpointDecisionAction,
    pub(crate) max_depth: usize,
    pub(crate) selected_stage: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cross_window_impact_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cross_window_recommendation_hash: Option<String>,
    pub(crate) staged_by: String,
    pub(crate) note: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdrPrivacyReportInput {
    #[serde(default)]
    pub(crate) observations: Vec<EndpointObservation>,
    #[serde(default, alias = "privacyMode")]
    pub(crate) privacy_mode: Option<EndpointTelemetryPrivacyMode>,
    #[serde(default, alias = "rawArtifactApprovalId")]
    pub(crate) raw_artifact_approval_id: Option<String>,
    #[serde(default, alias = "rawArtifactApprovalReason")]
    pub(crate) raw_artifact_approval_reason: Option<String>,
}
#[derive(Debug, Serialize)]
pub(crate) struct EdrPrivacyReportResponse {
    pub(crate) report: EndpointTelemetryPrivacyReport,
    pub(crate) privacy_policy: EdrPrivacyPolicyDecision,
    pub(crate) receipt: SignedReceipt,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPrivacyPolicyDecision {
    pub(crate) requested_privacy_mode: EndpointTelemetryPrivacyMode,
    pub(crate) effective_privacy_mode: EndpointTelemetryPrivacyMode,
    pub(crate) raw_artifact_upload_requested: bool,
    pub(crate) raw_artifact_upload_allowed: bool,
    pub(crate) raw_artifact_approval_required: bool,
    pub(crate) raw_artifact_approval_provided: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) raw_artifact_approval_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) raw_artifact_approval_reason_hash: Option<String>,
    pub(crate) policy_source: String,
    pub(crate) denied_reason: Option<String>,
}
#[derive(Clone, Debug)]
pub(crate) struct EdrRawArtifactApproval {
    pub(crate) approval_id: String,
    pub(crate) reason_hash: String,
}
#[derive(Clone, Debug)]
pub(crate) struct EdrRawArtifactUploadPolicy {
    pub(crate) allowed: bool,
    pub(crate) source: String,
}
#[derive(Debug, Deserialize)]
pub(crate) struct EdrFindingGroupsQuery {
    #[serde(default)]
    pub(crate) limit: Option<usize>,
    #[serde(default, alias = "maxDepth")]
    pub(crate) max_depth: Option<usize>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrFindingGroup {
    pub(crate) group_id: String,
    pub(crate) root_node_id: String,
    pub(crate) root_label: String,
    pub(crate) finding_count: usize,
    pub(crate) node_count: usize,
    pub(crate) edge_count: usize,
    pub(crate) rule_ids: Vec<String>,
    pub(crate) finding_ids: Vec<String>,
    pub(crate) findings: Vec<DetectionFinding>,
    pub(crate) affected_identity_count: usize,
    pub(crate) affected_tool_count: usize,
    pub(crate) affected_identities: EdrPolicyEventHistoryAffectedIdentities,
    pub(crate) affected_tools: Vec<EdrPolicyEventHistoryAffectedTool>,
    pub(crate) graph: CausalGraph,
    pub(crate) receipt: SignedReceipt,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrFindingGroupsResponse {
    pub(crate) group_count: usize,
    pub(crate) finding_count: usize,
    pub(crate) groups: Vec<EdrFindingGroup>,
}
#[derive(Debug, Deserialize)]
pub(crate) struct EdrCausalGraphInput {
    #[serde(default)]
    pub(crate) observations: Vec<EndpointObservation>,
}
#[derive(Debug, Serialize)]
pub(crate) struct EdrCausalGraphResponse {
    pub(crate) observation_count: usize,
    pub(crate) node_count: usize,
    pub(crate) edge_count: usize,
    pub(crate) graph: CausalGraph,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdrCausalSubgraphInput {
    #[serde(default, alias = "rootNodeId")]
    pub(crate) root_node_id: Option<String>,
    #[serde(default)]
    pub(crate) process: Option<EdrGraphRootProcessSelectorInput>,
    #[serde(default, alias = "maxDepth")]
    pub(crate) max_depth: Option<usize>,
}
#[derive(Debug, Serialize)]
pub(crate) struct EdrCausalSubgraphResponse {
    pub(crate) root_node_id: String,
    pub(crate) max_depth: usize,
    pub(crate) node_count: usize,
    pub(crate) edge_count: usize,
    pub(crate) affected_identity_count: usize,
    pub(crate) affected_tool_count: usize,
    pub(crate) affected_identities: EdrPolicyEventHistoryAffectedIdentities,
    pub(crate) affected_tools: Vec<EdrPolicyEventHistoryAffectedTool>,
    pub(crate) graph: CausalGraph,
    pub(crate) receipt: SignedReceipt,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdrCausalContextInput {
    #[serde(default, alias = "rootNodeId")]
    pub(crate) root_node_id: Option<String>,
    #[serde(default)]
    pub(crate) process: Option<EdrGraphRootProcessSelectorInput>,
    #[serde(default, alias = "upstreamDepth")]
    pub(crate) upstream_depth: Option<usize>,
    #[serde(default, alias = "downstreamDepth")]
    pub(crate) downstream_depth: Option<usize>,
}
#[derive(Debug, Serialize)]
pub(crate) struct EdrCausalContextResponse {
    pub(crate) root_node_id: String,
    pub(crate) upstream_depth: usize,
    pub(crate) downstream_depth: usize,
    #[serde(rename = "contextExpansionStrategy")]
    pub(crate) context_expansion_strategy: String,
    #[serde(rename = "edgeIndexSource")]
    pub(crate) edge_index_source: String,
    #[serde(rename = "edgeIndexPath", skip_serializing_if = "Option::is_none")]
    pub(crate) edge_index_path: Option<PathBuf>,
    #[serde(rename = "edgeIndexCount")]
    pub(crate) edge_index_count: usize,
    pub(crate) node_count: usize,
    pub(crate) edge_count: usize,
    pub(crate) affected_identity_count: usize,
    pub(crate) affected_tool_count: usize,
    pub(crate) affected_identities: EdrPolicyEventHistoryAffectedIdentities,
    pub(crate) affected_tools: Vec<EdrPolicyEventHistoryAffectedTool>,
    pub(crate) graph: CausalGraph,
    pub(crate) receipt: SignedReceipt,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdrGraphSearchInput {
    #[serde(default, alias = "nodeKind", alias = "kind")]
    pub(crate) node_kind: Option<CausalNodeKind>,
    #[serde(default, alias = "labelContains")]
    pub(crate) label_contains: Option<String>,
    #[serde(
        default,
        alias = "filePath",
        alias = "credentialPath",
        alias = "targetPath"
    )]
    pub(crate) path: Option<String>,
    #[serde(
        default,
        alias = "pathPrefix",
        alias = "filePathPrefix",
        alias = "credentialPathPrefix",
        alias = "targetPathPrefix"
    )]
    pub(crate) path_prefix: Option<String>,
    #[serde(
        default,
        alias = "pathPattern",
        alias = "filePathPattern",
        alias = "credentialPathPattern",
        alias = "targetPathPattern"
    )]
    pub(crate) path_pattern: Option<String>,
    #[serde(default, alias = "attributeKey")]
    pub(crate) attribute_key: Option<String>,
    #[serde(default, alias = "attributeValue")]
    pub(crate) attribute_value: Option<String>,
    #[serde(default, alias = "toolName")]
    pub(crate) tool_name: Option<String>,
    #[serde(default, alias = "hostId")]
    pub(crate) host_id: Option<String>,
    #[serde(default, alias = "sessionId")]
    pub(crate) session_id: Option<String>,
    #[serde(default, alias = "userId")]
    pub(crate) user_id: Option<String>,
    #[serde(default, alias = "agentId")]
    pub(crate) agent_id: Option<String>,
    #[serde(default, alias = "workloadId")]
    pub(crate) workload_id: Option<String>,
    #[serde(default, alias = "approvalId")]
    pub(crate) approval_id: Option<String>,
    #[serde(default, alias = "upstreamDepth")]
    pub(crate) upstream_depth: Option<usize>,
    #[serde(default, alias = "downstreamDepth")]
    pub(crate) downstream_depth: Option<usize>,
    #[serde(default)]
    pub(crate) limit: Option<usize>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrGraphSearchMatch {
    pub(crate) root_node_id: String,
    pub(crate) root_label: String,
    pub(crate) root_kind: CausalNodeKind,
    pub(crate) node_count: usize,
    pub(crate) edge_count: usize,
    pub(crate) affected_identity_count: usize,
    pub(crate) affected_tool_count: usize,
    pub(crate) affected_identities: EdrPolicyEventHistoryAffectedIdentities,
    pub(crate) affected_tools: Vec<EdrPolicyEventHistoryAffectedTool>,
    pub(crate) graph: CausalGraph,
    pub(crate) receipt: SignedReceipt,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrGraphSearchQueryPlan {
    pub(crate) strategy: String,
    pub(crate) indexed: bool,
    pub(crate) index_source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) index_path: Option<PathBuf>,
    pub(crate) edge_index_source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) edge_index_path: Option<PathBuf>,
    pub(crate) edge_index_count: usize,
    pub(crate) context_expansion_strategy: String,
    pub(crate) indexed_keys: Vec<String>,
    pub(crate) candidate_count: usize,
    pub(crate) scanned_node_count: usize,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrGraphSearchResponse {
    pub(crate) match_count: usize,
    pub(crate) total_match_count: usize,
    pub(crate) upstream_depth: usize,
    pub(crate) downstream_depth: usize,
    pub(crate) query_plan: EdrGraphSearchQueryPlan,
    pub(crate) matches: Vec<EdrGraphSearchMatch>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdrGraphSliceExportInput {
    #[serde(default, alias = "rootNodeId")]
    pub(crate) root_node_id: Option<String>,
    #[serde(default)]
    pub(crate) process: Option<EdrGraphRootProcessSelectorInput>,
    #[serde(default, alias = "sliceKind")]
    pub(crate) slice_kind: Option<String>,
    #[serde(default, alias = "maxDepth")]
    pub(crate) max_depth: Option<usize>,
    #[serde(default, alias = "upstreamDepth")]
    pub(crate) upstream_depth: Option<usize>,
    #[serde(default, alias = "downstreamDepth")]
    pub(crate) downstream_depth: Option<usize>,
    #[serde(default)]
    pub(crate) reason: Option<String>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrGraphSliceExportResponse {
    pub(crate) root_node_id: String,
    pub(crate) slice_kind: String,
    pub(crate) node_count: usize,
    pub(crate) edge_count: usize,
    pub(crate) affected_identity_count: usize,
    pub(crate) affected_tool_count: usize,
    pub(crate) affected_identities: EdrPolicyEventHistoryAffectedIdentities,
    pub(crate) affected_tools: Vec<EdrPolicyEventHistoryAffectedTool>,
    pub(crate) graph: CausalGraph,
    pub(crate) bundle: EndpointEvidenceBundleReference,
    pub(crate) artifact: EdrEvidenceBundleArtifact,
    pub(crate) receipt: SignedReceipt,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdrAgentSecretTouchesInput {
    #[serde(default, alias = "sessionId")]
    pub(crate) session_id: Option<String>,
    #[serde(default, alias = "credentialKind")]
    pub(crate) credential_kind: Option<String>,
    #[serde(default, alias = "requireAgentContext")]
    pub(crate) require_agent_context: Option<bool>,
    #[serde(default, alias = "upstreamDepth")]
    pub(crate) upstream_depth: Option<usize>,
    #[serde(default, alias = "downstreamDepth")]
    pub(crate) downstream_depth: Option<usize>,
    #[serde(default)]
    pub(crate) limit: Option<usize>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrAgentSecretTouch {
    pub(crate) credential_node_id: String,
    pub(crate) credential_label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) credential_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    pub(crate) agent_node_ids: Vec<String>,
    pub(crate) agent_labels: Vec<String>,
    pub(crate) process_node_ids: Vec<String>,
    pub(crate) graph: CausalGraph,
    pub(crate) receipt: SignedReceipt,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrAgentSecretTouchesResponse {
    pub(crate) touch_count: usize,
    pub(crate) touches: Vec<EdrAgentSecretTouch>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPublishedHuntEvent {
    pub(crate) event_id: String,
    pub(crate) raw_ref: String,
    pub(crate) credential_node_id: String,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrEvidenceBundleFleetPublishResponse {
    pub(crate) bundle_id: String,
    pub(crate) archive_id: String,
    pub(crate) archive_hash: String,
    pub(crate) published: bool,
    pub(crate) queued: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) control_upload: Option<EdrEvidenceBundleControlUploadReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) outbox_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) next_retry_at: Option<chrono::DateTime<chrono::Utc>>,
    pub(crate) event_id: String,
    pub(crate) raw_ref: String,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrEvidenceBundleControlUploadReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) control_api_url: Option<String>,
    pub(crate) attempted: bool,
    pub(crate) accepted: bool,
    pub(crate) raw_artifact_upload_allowed: bool,
    pub(crate) raw_artifact_approval_required: bool,
    pub(crate) raw_artifact_approval_provided: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) raw_artifact_approval_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) raw_artifact_approval_reason_hash: Option<String>,
    pub(crate) policy_source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) skipped_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) http_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) response_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
    pub(crate) retry_queued: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) retry_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) next_retry_at: Option<chrono::DateTime<chrono::Utc>>,
}
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrRawArtifactApprovalInput {
    #[serde(default)]
    pub(crate) raw_artifact_approval_id: Option<String>,
    #[serde(default)]
    pub(crate) raw_artifact_approval_reason: Option<String>,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrControlArchiveUploadRetryInput {
    #[serde(default)]
    pub(crate) force: bool,
    #[serde(default)]
    pub(crate) limit: Option<usize>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrControlArchiveUploadRetryAttemptRecord {
    pub(crate) retry_id: String,
    pub(crate) archive_id: String,
    pub(crate) archive_hash: String,
    pub(crate) raw_ref: String,
    pub(crate) bundle_id: String,
    pub(crate) control_api_url: String,
    pub(crate) delivered: bool,
    pub(crate) attempt_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) next_attempt_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) http_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) response_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error_hash: Option<String>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrControlArchiveUploadRetryResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) path: Option<String>,
    pub(crate) attempted: usize,
    pub(crate) delivered: usize,
    pub(crate) failed: usize,
    pub(crate) skipped: usize,
    pub(crate) pending: usize,
    pub(crate) attempts: Vec<EdrControlArchiveUploadRetryAttemptRecord>,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrControlReceiptUploadRetryInput {
    #[serde(default)]
    pub(crate) force: bool,
    #[serde(default)]
    pub(crate) limit: Option<usize>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrControlReceiptUploadRetryAttemptRecord {
    pub(crate) retry_id: String,
    pub(crate) receipt_id: Option<String>,
    pub(crate) receipt_hash: String,
    pub(crate) control_api_url: String,
    pub(crate) delivered: bool,
    pub(crate) attempt_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) next_attempt_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) http_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) response_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error_hash: Option<String>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrControlReceiptUploadRetryResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) path: Option<String>,
    pub(crate) attempted: usize,
    pub(crate) delivered: usize,
    pub(crate) failed: usize,
    pub(crate) skipped: usize,
    pub(crate) pending: usize,
    pub(crate) attempts: Vec<EdrControlReceiptUploadRetryAttemptRecord>,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrControlArchiveUploadBackfillInput {
    #[serde(default)]
    pub(crate) bundle_id: Option<String>,
    #[serde(default)]
    pub(crate) limit: Option<usize>,
    #[serde(default)]
    pub(crate) raw_artifact_approval_id: Option<String>,
    #[serde(default)]
    pub(crate) raw_artifact_approval_reason: Option<String>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrControlArchiveUploadBackfillRecord {
    pub(crate) bundle_id: String,
    pub(crate) archive_id: String,
    pub(crate) archive_hash: String,
    pub(crate) raw_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) control_upload: Option<EdrEvidenceBundleControlUploadReport>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrControlArchiveUploadBackfillResponse {
    pub(crate) attempted: usize,
    pub(crate) delivered: usize,
    pub(crate) failed: usize,
    pub(crate) skipped: usize,
    pub(crate) records: Vec<EdrControlArchiveUploadBackfillRecord>,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrFleetHuntEventRetryInput {
    #[serde(default)]
    pub(crate) force: bool,
    #[serde(default)]
    pub(crate) limit: Option<usize>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrFleetHuntEventRetryAttemptRecord {
    pub(crate) outbox_id: String,
    pub(crate) event_id: String,
    pub(crate) raw_ref: String,
    pub(crate) delivered: bool,
    pub(crate) attempt_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) next_attempt_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error_hash: Option<String>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrFleetHuntEventRetryResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) path: Option<String>,
    pub(crate) attempted: usize,
    pub(crate) delivered: usize,
    pub(crate) failed: usize,
    pub(crate) skipped: usize,
    pub(crate) pending: usize,
    pub(crate) attempts: Vec<EdrFleetHuntEventRetryAttemptRecord>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrAgentSecretTouchesFleetPublishResponse {
    pub(crate) touch_count: usize,
    pub(crate) published_count: usize,
    pub(crate) events: Vec<EdrPublishedHuntEvent>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdrPolicySimulationInput {
    #[serde(default, alias = "rootNodeId")]
    pub(crate) root_node_id: Option<String>,
    #[serde(default)]
    pub(crate) process: Option<EdrGraphRootProcessSelectorInput>,
    #[serde(default, alias = "ruleId")]
    pub(crate) rule_id: Option<String>,
    #[serde(default)]
    pub(crate) description: Option<String>,
    #[serde(default)]
    pub(crate) action: Option<EndpointDecisionAction>,
    #[serde(default, alias = "maxDepth")]
    pub(crate) max_depth: Option<usize>,
}
#[derive(Debug, Serialize)]
pub(crate) struct EdrPolicySimulationResponse {
    pub(crate) simulation: EndpointPolicySimulationReport,
    pub(crate) graph: CausalGraph,
    pub(crate) receipt: SignedReceipt,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdrPolicyReplayInput {
    #[serde(default, alias = "rootNodeId")]
    pub(crate) root_node_id: Option<String>,
    #[serde(default)]
    pub(crate) process: Option<EdrGraphRootProcessSelectorInput>,
    #[serde(default)]
    pub(crate) action: Option<EndpointDecisionAction>,
    #[serde(default, alias = "ruleId")]
    pub(crate) rule_id: Option<String>,
    #[serde(default)]
    pub(crate) description: Option<String>,
    #[serde(default, alias = "maxDepth")]
    pub(crate) max_depth: Option<usize>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyReplayReport {
    pub(crate) replay_id: String,
    pub(crate) replayed_at: chrono::DateTime<chrono::Utc>,
    pub(crate) mode: String,
    pub(crate) policy: EndpointPolicySnapshot,
    pub(crate) root_node_id: String,
    pub(crate) root_label: String,
    pub(crate) root_kind: CausalNodeKind,
    pub(crate) action: EndpointDecisionAction,
    pub(crate) graph_slice_id: String,
    pub(crate) observation_count: usize,
    pub(crate) node_count: usize,
    pub(crate) edge_count: usize,
    pub(crate) flight_recorder_observation_count: usize,
    pub(crate) would_enforce: bool,
    pub(crate) developer_breakage_score: u8,
    pub(crate) impact_level: EndpointSimulationImpactLevel,
    pub(crate) summary: String,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyReplayResponse {
    pub(crate) replay: EdrPolicyReplayReport,
    pub(crate) simulation: EndpointPolicySimulationReport,
    pub(crate) graph: CausalGraph,
    pub(crate) receipt: SignedReceipt,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdrDetectionCandidateInput {
    #[serde(default, alias = "rootNodeId")]
    pub(crate) root_node_id: Option<String>,
    #[serde(default)]
    pub(crate) process: Option<EdrGraphRootProcessSelectorInput>,
    #[serde(default)]
    pub(crate) action: Option<EndpointDecisionAction>,
    #[serde(default)]
    pub(crate) description: Option<String>,
    #[serde(default, alias = "maxDepth")]
    pub(crate) max_depth: Option<usize>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrDetectionCandidate {
    pub(crate) rule_id: String,
    pub(crate) action: EndpointDecisionAction,
    pub(crate) description: String,
    pub(crate) root_node_id: String,
    pub(crate) root_label: String,
    pub(crate) root_kind: CausalNodeKind,
    pub(crate) graph_slice_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrDetectionCandidateStage {
    pub(crate) stage: String,
    pub(crate) action: EndpointDecisionAction,
    pub(crate) promotion_gate: String,
    pub(crate) recommended: bool,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrDetectionCandidateResponse {
    pub(crate) candidate: EdrDetectionCandidate,
    pub(crate) recommended_stage: String,
    pub(crate) stage_plan: Vec<EdrDetectionCandidateStage>,
    pub(crate) simulation: EndpointPolicySimulationReport,
    pub(crate) graph: CausalGraph,
    pub(crate) receipt: SignedReceipt,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdrStageDetectionInput {
    #[serde(default, alias = "rootNodeId")]
    pub(crate) root_node_id: Option<String>,
    #[serde(default)]
    pub(crate) process: Option<EdrGraphRootProcessSelectorInput>,
    #[serde(default)]
    pub(crate) action: Option<EndpointDecisionAction>,
    #[serde(default)]
    pub(crate) description: Option<String>,
    #[serde(default, alias = "maxDepth")]
    pub(crate) max_depth: Option<usize>,
    #[serde(default, alias = "selectedStage")]
    pub(crate) stage: Option<String>,
    #[serde(default, alias = "crossWindowImpactHash")]
    pub(crate) cross_window_impact_hash: Option<String>,
    #[serde(default, alias = "crossWindowRecommendationHash")]
    pub(crate) cross_window_recommendation_hash: Option<String>,
    #[serde(default, alias = "stagedBy")]
    pub(crate) staged_by: Option<String>,
    #[serde(default)]
    pub(crate) note: Option<String>,
}
impl EdrStageDetectionInput {
    pub(crate) fn candidate_input(&self) -> EdrDetectionCandidateInput {
        EdrDetectionCandidateInput {
            root_node_id: self.root_node_id.clone(),
            process: self.process.clone(),
            action: self.action.clone(),
            description: self.description.clone(),
            max_depth: self.max_depth,
        }
    }
}
#[derive(Debug, Deserialize)]
pub(crate) struct EdrStagedDetectionsQuery {
    #[serde(default)]
    pub(crate) limit: Option<usize>,
    #[serde(default)]
    pub(crate) stage: Option<String>,
    #[serde(default, alias = "ruleId")]
    pub(crate) rule_id: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrStagedDetectionRecord {
    pub(crate) staged_detection_id: String,
    pub(crate) staged_at: chrono::DateTime<chrono::Utc>,
    pub(crate) staged_by: String,
    pub(crate) stage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cross_window_impact_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cross_window_recommendation_hash: Option<String>,
    pub(crate) note: Option<String>,
    pub(crate) policy: EndpointPolicySnapshot,
    pub(crate) candidate: EdrDetectionCandidate,
    pub(crate) recommended_stage: String,
    pub(crate) stage_plan: Vec<EdrDetectionCandidateStage>,
    pub(crate) simulation: EndpointPolicySimulationReport,
    pub(crate) simulation_receipt: SignedReceipt,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrStageDetectionResponse {
    pub(crate) path: Option<String>,
    pub(crate) record: EdrStagedDetectionRecord,
    pub(crate) graph: CausalGraph,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrStagedDetectionsResponse {
    pub(crate) path: Option<String>,
    pub(crate) count: usize,
    pub(crate) staged_detections: Vec<EdrStagedDetectionRecord>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdrPolicyDeltaInput {
    #[serde(default, alias = "stagedDetectionId")]
    pub(crate) staged_detection_id: Option<String>,
    #[serde(default, alias = "ruleId")]
    pub(crate) rule_id: Option<String>,
    #[serde(default)]
    pub(crate) stage: Option<String>,
    #[serde(default, alias = "generatedBy", alias = "promotedBy")]
    pub(crate) generated_by: Option<String>,
    #[serde(default)]
    pub(crate) note: Option<String>,
}
#[derive(Debug, Deserialize)]
pub(crate) struct EdrPolicyDeltasQuery {
    #[serde(default)]
    pub(crate) limit: Option<usize>,
    #[serde(default)]
    pub(crate) stage: Option<String>,
    #[serde(default, alias = "ruleId")]
    pub(crate) rule_id: Option<String>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdrPolicyDeltaApplyInput {
    #[serde(default, alias = "dryRun")]
    pub(crate) dry_run: Option<bool>,
    #[serde(default, alias = "allowBasePolicyDrift")]
    pub(crate) allow_base_policy_drift: Option<bool>,
    #[serde(default, alias = "reloadDaemonPolicy")]
    pub(crate) reload_daemon_policy: Option<bool>,
    #[serde(default, alias = "restartDaemon")]
    pub(crate) restart_daemon: Option<bool>,
    #[serde(default, alias = "verifyProtectionState")]
    pub(crate) verify_protection_state: Option<bool>,
    #[serde(default, alias = "providerAckTimeoutMs")]
    pub(crate) provider_ack_timeout_ms: Option<u64>,
    #[serde(default, alias = "appliedBy", alias = "promotedBy")]
    pub(crate) applied_by: Option<String>,
    #[serde(default)]
    pub(crate) note: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrPolicyDeltaTargetPolicy {
    pub(crate) base_policy_version: String,
    pub(crate) base_policy_hash: String,
    pub(crate) base_policy_epoch: u64,
    pub(crate) target_policy_epoch: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrPolicyDeltaRollout {
    pub(crate) stage: String,
    pub(crate) action: EndpointDecisionAction,
    pub(crate) recommended_stage: String,
    pub(crate) promotion_gate: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cross_window_impact_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cross_window_recommendation_hash: Option<String>,
    pub(crate) developer_breakage_score: u8,
    pub(crate) impact_level: String,
    pub(crate) would_block: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrPolicyDeltaArtifact {
    pub(crate) schema_version: String,
    pub(crate) policy_delta_id: String,
    pub(crate) generated_at: chrono::DateTime<chrono::Utc>,
    pub(crate) generated_by: String,
    pub(crate) note: Option<String>,
    pub(crate) staged_detection_id: String,
    pub(crate) source_simulation_id: String,
    pub(crate) source_simulation_receipt_id: Option<String>,
    #[serde(default)]
    pub(crate) source_affected_identities: Vec<EndpointPolicySimulationIdentityContext>,
    #[serde(default)]
    pub(crate) source_affected_tools: Vec<EndpointPolicySimulationToolContext>,
    pub(crate) candidate: EdrDetectionCandidate,
    pub(crate) target_policy: EdrPolicyDeltaTargetPolicy,
    pub(crate) rollout: EdrPolicyDeltaRollout,
    pub(crate) policy_patch: Value,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrPolicyDeltaRecord {
    pub(crate) policy_delta_id: String,
    pub(crate) generated_at: chrono::DateTime<chrono::Utc>,
    pub(crate) generated_by: String,
    pub(crate) rule_id: String,
    pub(crate) stage: String,
    pub(crate) action: EndpointDecisionAction,
    pub(crate) artifact_hash: String,
    pub(crate) artifact_path: Option<String>,
    pub(crate) artifact: EdrPolicyDeltaArtifact,
    pub(crate) receipt: SignedReceipt,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyDeltaResponse {
    pub(crate) path: Option<String>,
    pub(crate) record: EdrPolicyDeltaRecord,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyDeltasResponse {
    pub(crate) path: Option<String>,
    pub(crate) count: usize,
    pub(crate) policy_deltas: Vec<EdrPolicyDeltaRecord>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyDeltaApplyRecord {
    pub(crate) policy_delta_id: String,
    pub(crate) applied_at: chrono::DateTime<chrono::Utc>,
    pub(crate) applied_by: String,
    pub(crate) note: Option<String>,
    pub(crate) dry_run: bool,
    pub(crate) applied: bool,
    pub(crate) allow_base_policy_drift: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cross_window_impact_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cross_window_recommendation_hash: Option<String>,
    pub(crate) policy_path: String,
    pub(crate) backup_path: Option<String>,
    pub(crate) expected_base_policy_hash: String,
    pub(crate) previous_policy_hash: String,
    pub(crate) new_policy_hash: String,
    pub(crate) previous_policy_epoch: u64,
    pub(crate) new_policy_epoch: u64,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyDeltaApplyResponse {
    pub(crate) record: EdrPolicyDeltaApplyRecord,
    pub(crate) policy_delta: EdrPolicyDeltaRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) prepared_receipt: Option<SignedReceipt>,
    pub(crate) receipt: Option<SignedReceipt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) post_apply_enforcement: Option<EdrPolicyDeltaApplyEnforcementProof>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrPolicyDeltaApplyEnforcementProof {
    pub(crate) policy_synced_to_disk: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cross_window_impact_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cross_window_recommendation_hash: Option<String>,
    pub(crate) local_policy: EndpointPolicySnapshot,
    pub(crate) daemon_policy_reload: EdrDaemonPolicyReloadResult,
    pub(crate) network_extension_policy_reload: NetworkExtensionReloadRequestProof,
    pub(crate) provider_status_refresh: EdrProviderStatusRefreshResult,
    pub(crate) provider_acknowledgement_poll: EdrProviderAcknowledgementPoll,
    pub(crate) provider_policy_acknowledgements: Vec<EdrProviderPolicyAcknowledgement>,
    pub(crate) daemon_restart_requested: bool,
    pub(crate) daemon_restarted: bool,
    pub(crate) daemon_restart_error: Option<String>,
    pub(crate) daemon: DaemonStatus,
    pub(crate) daemon_policy_version: Option<String>,
    pub(crate) sensor_state: EndpointSensorState,
    pub(crate) receipt: SignedReceipt,
    pub(crate) degraded_provider_receipts: Vec<SignedReceipt>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrDaemonPolicyReloadResult {
    pub(crate) requested: bool,
    pub(crate) reloaded: bool,
    pub(crate) status_code: Option<u16>,
    pub(crate) policy_hash: Option<String>,
    pub(crate) message: Option<String>,
    pub(crate) error: Option<String>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrProviderPolicyAcknowledgement {
    pub(crate) provider_id: String,
    pub(crate) provider_kind: EndpointProviderKind,
    pub(crate) active: bool,
    pub(crate) observed_policy_epoch: Option<u64>,
    pub(crate) expected_policy_epoch: u64,
    pub(crate) policy_epoch_matches: Option<bool>,
    pub(crate) policy_synced: Option<bool>,
    pub(crate) enforcement_ready: Option<bool>,
    pub(crate) acknowledged: bool,
    pub(crate) reasons: Vec<String>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrProviderAcknowledgementPoll {
    pub(crate) requested: bool,
    pub(crate) timeout_ms: u64,
    pub(crate) elapsed_ms: u64,
    pub(crate) attempts: u64,
    pub(crate) satisfied: bool,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrProviderStatusRefreshResult {
    pub(crate) requested: bool,
    pub(crate) refreshed: bool,
    pub(crate) timeout_ms: u64,
    pub(crate) elapsed_ms: u64,
    pub(crate) error: Option<String>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdrNetworkExtensionEgressPolicyProofInput {
    #[serde(default, alias = "refreshProviders")]
    pub(crate) refresh_providers: Option<bool>,
    #[serde(default, alias = "providerRefreshTimeoutMs")]
    pub(crate) provider_refresh_timeout_ms: Option<u64>,
    #[serde(default, alias = "executionId")]
    pub(crate) execution_id: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrNetworkExtensionReloadDeliveryProof {
    pub(crate) execution_id: String,
    pub(crate) observed: bool,
    pub(crate) matched: bool,
    pub(crate) request_id_matches: bool,
    pub(crate) generation_matches: bool,
    pub(crate) policy_snapshot_path_matches: bool,
    pub(crate) provider_reloaded: Option<bool>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrNetworkExtensionEgressPolicyProofResponse {
    pub(crate) provider_policy_path: String,
    pub(crate) snapshot_present: bool,
    pub(crate) snapshot_decodable: bool,
    pub(crate) snapshot_hash: Option<String>,
    pub(crate) generated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub(crate) restriction_count: usize,
    pub(crate) active_restriction_count: usize,
    pub(crate) expired_restriction_count: usize,
    pub(crate) enforcement_ready: bool,
    pub(crate) live_enforcement_proven: bool,
    pub(crate) live_enforcement_proof_reasons: Vec<String>,
    pub(crate) flow_counter_observed: bool,
    pub(crate) observed_flow_count: u64,
    pub(crate) blocked_flow_count: u64,
    pub(crate) remediation_request_count: u64,
    pub(crate) dropped_verdict_count: u64,
    pub(crate) provider_reload_observed: bool,
    pub(crate) provider_reload_request_id: Option<String>,
    pub(crate) provider_reload_generation: Option<u64>,
    pub(crate) provider_reload_policy_snapshot_path: Option<String>,
    pub(crate) provider_reload_accepted: Option<bool>,
    pub(crate) provider_reload_reloaded: Option<bool>,
    pub(crate) provider_reload_error: Option<String>,
    pub(crate) provider_reload_delivery: Option<EdrNetworkExtensionReloadDeliveryProof>,
    pub(crate) read_error: Option<String>,
    pub(crate) provider_status_refresh: EdrProviderStatusRefreshResult,
    pub(crate) network_extension_provider: ProviderStatus,
    pub(crate) sensor_state: EndpointSensorState,
    pub(crate) receipt: SignedReceipt,
    pub(crate) degraded_provider_receipts: Vec<SignedReceipt>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdrResponseActionInput {
    pub(crate) action: EndpointDecisionAction,
    #[serde(default, alias = "rootNodeId")]
    pub(crate) root_node_id: Option<String>,
    #[serde(default)]
    pub(crate) process: Option<EdrGraphRootProcessSelectorInput>,
    #[serde(default)]
    pub(crate) actor: Option<EdrResponseActionActorInput>,
    #[serde(default, alias = "ttlSeconds")]
    pub(crate) ttl_seconds: Option<u64>,
    #[serde(default)]
    pub(crate) reason: Option<String>,
    #[serde(default, alias = "dryRun")]
    pub(crate) dry_run: Option<bool>,
}
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrGraphRootProcessSelectorInput {
    pub(crate) pid: Option<u32>,
    pub(crate) ppid: Option<u32>,
    pub(crate) process_guid: Option<String>,
    pub(crate) parent_process_guid: Option<String>,
    pub(crate) image: Option<String>,
    pub(crate) command_line: Option<String>,
    pub(crate) cwd: Option<String>,
}
#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrResponseActionActorInput {
    pub(crate) endpoint_id: String,
    pub(crate) host_id: Option<String>,
    pub(crate) user_id: Option<String>,
    pub(crate) session_id: Option<String>,
    pub(crate) posture: Option<String>,
    pub(crate) agent_id: Option<String>,
    pub(crate) workload_id: Option<String>,
    pub(crate) approval_id: Option<String>,
}
#[derive(Debug, Serialize)]
pub(crate) struct EdrResponseActionResponse {
    pub(crate) plan: EndpointResponsePlan,
    pub(crate) graph: CausalGraph,
    #[serde(rename = "affectedIdentityCount")]
    pub(crate) affected_identity_count: usize,
    #[serde(rename = "affectedToolCount")]
    pub(crate) affected_tool_count: usize,
    #[serde(rename = "affectedIdentities")]
    pub(crate) affected_identities: EdrPolicyEventHistoryAffectedIdentities,
    #[serde(rename = "affectedTools")]
    pub(crate) affected_tools: Vec<EdrPolicyEventHistoryAffectedTool>,
    pub(crate) receipt: SignedReceipt,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) execution: Option<EndpointResponseExecutionReport>,
    #[serde(
        rename = "evidenceBundleArtifact",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) evidence_bundle_artifact: Option<EdrEvidenceBundleArtifact>,
    #[serde(rename = "executionReceipt", skip_serializing_if = "Option::is_none")]
    pub(crate) execution_receipt: Option<SignedReceipt>,
    #[serde(
        rename = "evidenceBundleReceipt",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) evidence_bundle_receipt: Option<SignedReceipt>,
}
#[derive(Debug, Deserialize)]
pub(crate) struct EdrResponseExecutionQuery {
    #[serde(default)]
    pub(crate) limit: Option<usize>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrResponseExecutionRecord {
    pub(crate) execution: EndpointResponseExecutionReport,
    pub(crate) expires_at: chrono::DateTime<chrono::Utc>,
    pub(crate) expired: bool,
    pub(crate) rollback_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) affected_identity_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) affected_tool_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) affected_identities: Option<EdrPolicyEventHistoryAffectedIdentities>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) affected_tools: Option<Vec<EdrPolicyEventHistoryAffectedTool>>,
}
impl EdrResponseExecutionRecord {
    pub(crate) fn from_execution(execution: EndpointResponseExecutionReport) -> Self {
        let expires_at = execution.expires_at();
        let expired = chrono::Utc::now() > expires_at;
        let rollback_ref = execution.rollback_ref.clone();
        Self {
            execution,
            expires_at,
            expired,
            rollback_ref,
            affected_identity_count: None,
            affected_tool_count: None,
            affected_identities: None,
            affected_tools: None,
        }
    }

    pub(crate) fn hydrate_attribution(&mut self, graph: &CausalGraph) {
        let affected_identities = affected_identities_for_causal_impact(graph);
        let affected_identity_count = affected_identities.count();
        let affected_tools = affected_tools_for_causal_impact(graph);
        self.affected_identity_count = Some(affected_identity_count);
        self.affected_tool_count = Some(affected_tools.len());
        self.affected_identities = Some(affected_identities);
        self.affected_tools = Some(affected_tools);
    }
}
#[derive(Debug, Serialize)]
pub(crate) struct EdrResponseExecutionsResponse {
    pub(crate) path: Option<String>,
    pub(crate) execution_count: usize,
    pub(crate) executions: Vec<EdrResponseExecutionRecord>,
}
#[derive(Debug, Serialize)]
pub(crate) struct EdrResponseExecutionResponse {
    pub(crate) path: Option<String>,
    pub(crate) execution: EdrResponseExecutionRecord,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrResponseExecutionProofResponse {
    pub(crate) execution_path: Option<String>,
    pub(crate) receipt_path: Option<String>,
    pub(crate) execution: EdrResponseExecutionRecord,
    pub(crate) graph: EndpointGraphReference,
    pub(crate) affected_identity_count: usize,
    pub(crate) affected_tool_count: usize,
    pub(crate) affected_identities: EdrPolicyEventHistoryAffectedIdentities,
    pub(crate) affected_tools: Vec<EdrPolicyEventHistoryAffectedTool>,
    pub(crate) provider_state: EndpointSensorState,
    pub(crate) evidence_bundle_artifact: EdrEvidenceBundleArtifact,
    pub(crate) request_receipt: SignedReceipt,
    pub(crate) execution_receipt: SignedReceipt,
    pub(crate) evidence_bundle_receipt: SignedReceipt,
    pub(crate) transition_receipts: Vec<SignedReceipt>,
    pub(crate) rollback_receipts: Vec<SignedReceipt>,
    pub(crate) acknowledgement_receipts: Vec<SignedReceipt>,
}
#[derive(Debug, Serialize)]
pub(crate) struct EdrResponseExecutionExpireResponse {
    pub(crate) path: Option<String>,
    pub(crate) expired_count: usize,
    pub(crate) executions: Vec<EdrResponseExecutionRecord>,
    pub(crate) receipts: Vec<SignedReceipt>,
    pub(crate) rollback_count: usize,
    pub(crate) rollbacks: Vec<EndpointResponseRollbackReport>,
    pub(crate) rollback_receipts: Vec<SignedReceipt>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdrResponseExecutionCancelInput {
    #[serde(default)]
    pub(crate) reason: Option<String>,
}
#[derive(Debug, Serialize)]
pub(crate) struct EdrResponseExecutionCancelResponse {
    pub(crate) path: Option<String>,
    pub(crate) execution: EdrResponseExecutionRecord,
    pub(crate) receipt: SignedReceipt,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdrResponseExecutionRollbackInput {
    #[serde(default)]
    pub(crate) reason: Option<String>,
}
#[derive(Debug, Serialize)]
pub(crate) struct EdrResponseExecutionRollbackResponse {
    pub(crate) path: Option<String>,
    pub(crate) execution: EdrResponseExecutionRecord,
    pub(crate) rollback_transition: EdrResponseExecutionRecord,
    pub(crate) rollback: EndpointResponseRollbackReport,
    pub(crate) receipt: SignedReceipt,
    pub(crate) transition_receipt: SignedReceipt,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdrResponseExecutionAcknowledgeInput {
    #[serde(default, alias = "acknowledgedBy")]
    pub(crate) acknowledged_by: Option<String>,
    #[serde(default)]
    pub(crate) note: Option<String>,
    #[serde(default, alias = "controlApi", alias = "controlCorrelation")]
    pub(crate) control: Option<EdrResponseControlAcknowledgementInput>,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrResponseControlAcknowledgementInput {
    #[serde(default, alias = "responseActionID")]
    pub(crate) response_action_id: Option<String>,
    #[serde(default, alias = "deliveryID")]
    pub(crate) delivery_id: Option<String>,
    #[serde(default)]
    pub(crate) target_kind: Option<String>,
    #[serde(default)]
    pub(crate) target_id: Option<String>,
    #[serde(default)]
    pub(crate) ack_token: Option<String>,
    #[serde(default)]
    pub(crate) status: Option<String>,
    #[serde(default)]
    pub(crate) resulting_state: Option<String>,
    #[serde(default, alias = "url", alias = "baseUrl", alias = "controlApiUrl")]
    pub(crate) control_api_url: Option<String>,
    #[serde(
        default,
        alias = "apiKey",
        alias = "bearerToken",
        alias = "controlApiKey",
        alias = "controlApiToken",
        alias = "controlApiBearerToken"
    )]
    pub(crate) control_api_token: Option<String>,
}
#[derive(Debug, Serialize)]
pub(crate) struct EdrResponseExecutionAcknowledgeResponse {
    pub(crate) path: Option<String>,
    pub(crate) execution: EdrResponseExecutionRecord,
    pub(crate) acknowledgement: EndpointResponseAcknowledgementReport,
    pub(crate) receipt: SignedReceipt,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "controlPostback"
    )]
    pub(crate) control_postback: Option<EdrResponseControlPostbackReport>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrResponseControlPostbackReport {
    pub(crate) control_api_url: String,
    pub(crate) response_action_id: String,
    pub(crate) accepted: bool,
    pub(crate) retry_queued: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) retry_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) next_retry_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) http_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) response_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) error_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}
#[derive(Debug, Deserialize)]
pub(crate) struct EdrResponseAcknowledgementQuery {
    pub(crate) limit: Option<usize>,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrControlAckPostbackRetryInput {
    #[serde(default)]
    pub(crate) force: bool,
    #[serde(default)]
    pub(crate) limit: Option<usize>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrControlAckPostbackRetryResponse {
    pub(crate) path: Option<String>,
    pub(crate) attempted: usize,
    pub(crate) delivered: usize,
    pub(crate) failed: usize,
    pub(crate) skipped: usize,
    pub(crate) pending: usize,
    pub(crate) attempts: Vec<EdrControlAckPostbackRetryAttemptRecord>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrControlAckPostbackRetryAttemptRecord {
    pub(crate) retry_id: String,
    pub(crate) response_action_id: String,
    pub(crate) control_api_url: String,
    pub(crate) route: ControlResponseAckPostbackRoute,
    pub(crate) delivered: bool,
    pub(crate) attempt_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) next_attempt_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) http_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) response_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) error_hash: Option<String>,
}
#[derive(Debug, Serialize)]
pub(crate) struct EdrResponseAcknowledgementRecord {
    pub(crate) acknowledgement: EndpointResponseAcknowledgementReport,
}
impl EdrResponseAcknowledgementRecord {
    pub(crate) fn from_acknowledgement(
        acknowledgement: EndpointResponseAcknowledgementReport,
    ) -> Self {
        Self { acknowledgement }
    }
}
#[derive(Debug, Serialize)]
pub(crate) struct EdrResponseAcknowledgementsResponse {
    pub(crate) path: Option<String>,
    pub(crate) count: usize,
    pub(crate) acknowledgements: Vec<EdrResponseAcknowledgementRecord>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrEvidenceBundleArtifact {
    pub(crate) bundle_id: String,
    pub(crate) path: Option<String>,
    pub(crate) byte_count: usize,
    pub(crate) content_hash: String,
}
impl EdrEvidenceBundleArtifact {
    pub(crate) fn from_stored(stored: &StoredEndpointEvidenceBundle) -> Self {
        Self {
            bundle_id: stored.bundle.bundle_id.clone(),
            path: stored.path.clone(),
            byte_count: stored.byte_count,
            content_hash: stored.bundle.content_hash.clone(),
        }
    }
}
#[derive(Debug, Serialize)]
pub(crate) struct EdrEvidenceBundleResponse {
    pub(crate) bundle: EndpointEvidenceBundleReference,
    pub(crate) path: Option<String>,
    pub(crate) byte_count: usize,
    pub(crate) graph: CausalGraph,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrEvidenceBundleArchive {
    pub(crate) bundle: EndpointEvidenceBundleReference,
    pub(crate) artifact: EdrEvidenceBundleArtifact,
    pub(crate) graph: CausalGraph,
    pub(crate) receipts: Vec<SignedReceipt>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrEvidenceBundleArchiveResponse {
    pub(crate) archive_id: String,
    pub(crate) generated_at: chrono::DateTime<chrono::Utc>,
    pub(crate) archive_hash: String,
    pub(crate) receipt_count: usize,
    pub(crate) verification: EdrEvidenceBundleArchiveVerification,
    pub(crate) archive: EdrEvidenceBundleArchive,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrEvidenceBundleArchiveVerification {
    pub(crate) verified: bool,
    pub(crate) graph_content_hash: String,
    pub(crate) content_hash_matches: bool,
    pub(crate) artifact_matches_bundle: bool,
    #[serde(default)]
    pub(crate) artifact_byte_count_matches: bool,
    #[serde(default)]
    pub(crate) receipts_bind_bundle_id: bool,
    #[serde(default)]
    pub(crate) receipts_bind_actor: bool,
    #[serde(default)]
    pub(crate) receipts_bind_policy: bool,
    #[serde(default)]
    pub(crate) receipts_bind_sensor_state: bool,
    #[serde(default)]
    pub(crate) receipts_bind_endpoint_decision: bool,
    #[serde(default)]
    pub(crate) receipt_endpoint_ids: Vec<String>,
    #[serde(default)]
    pub(crate) receipts_bind_endpoint_identity: bool,
    #[serde(default)]
    pub(crate) receipt_root_node_ids: Vec<String>,
    #[serde(default)]
    pub(crate) receipts_bind_root_node: bool,
    pub(crate) graph_counts_match: bool,
    pub(crate) receipt_count: usize,
    #[serde(default)]
    pub(crate) receipt_ids_unique: bool,
    #[serde(default)]
    pub(crate) receipt_local_sequences: Vec<u64>,
    #[serde(default)]
    pub(crate) receipt_local_sequences_present: bool,
    #[serde(default)]
    pub(crate) receipt_local_sequences_unique: bool,
    #[serde(default)]
    pub(crate) receipt_timestamps_parse: bool,
    #[serde(default)]
    pub(crate) receipt_chronology_consistent: bool,
    pub(crate) receipt_families_valid: bool,
    #[serde(default)]
    pub(crate) present_receipt_families: Vec<String>,
    #[serde(default)]
    pub(crate) receipt_family_counts: BTreeMap<String, usize>,
    #[serde(default)]
    pub(crate) receipt_family_cardinality_valid: bool,
    #[serde(default)]
    pub(crate) required_receipt_families: Vec<String>,
    #[serde(default)]
    pub(crate) required_receipt_families_present: bool,
    #[serde(default)]
    pub(crate) missing_required_receipt_families: Vec<String>,
    pub(crate) receipt_signatures_valid: bool,
    #[serde(default)]
    pub(crate) receipt_signers_consistent: bool,
    pub(crate) receipts_bind_graph_slice: bool,
    pub(crate) receipts_bind_content_hash: bool,
    pub(crate) receipt_failure_count: usize,
    pub(crate) receipt_failures: Vec<String>,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrEvidenceBundleArchiveVerifyInput {
    #[serde(default)]
    pub(crate) archive_id: Option<String>,
    #[serde(default)]
    pub(crate) generated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub(crate) archive_hash: String,
    #[serde(default)]
    pub(crate) receipt_count: Option<usize>,
    #[serde(default)]
    pub(crate) verification: Option<EdrEvidenceBundleArchiveVerification>,
    #[serde(default)]
    pub(crate) trusted_signer_public_key: Option<String>,
    pub(crate) archive: EdrEvidenceBundleArchive,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrEvidenceBundleArchiveVerifyResponse {
    pub(crate) verified: bool,
    pub(crate) expected_archive_id: String,
    pub(crate) archive_id_matches: bool,
    pub(crate) expected_archive_hash: String,
    pub(crate) archive_hash: String,
    pub(crate) archive_hash_matches: bool,
    pub(crate) receipt_count_matches: bool,
    pub(crate) verification_matches: bool,
    pub(crate) generated_at_covers_receipts: bool,
    pub(crate) newest_receipt_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub(crate) trusted_signer_public_key: Option<String>,
    pub(crate) signer_trust_matches: bool,
    pub(crate) verification: EdrEvidenceBundleArchiveVerification,
}
#[derive(Debug, Deserialize)]
pub(crate) struct EdrEvidenceBundleQuery {
    #[serde(default)]
    pub(crate) limit: Option<usize>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrEvidenceBundleRecord {
    pub(crate) bundle: EndpointEvidenceBundleReference,
    pub(crate) path: Option<String>,
    pub(crate) byte_count: usize,
    pub(crate) age_seconds: u64,
    pub(crate) protected_by_active_response: bool,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrEvidenceBundlesResponse {
    pub(crate) root: Option<String>,
    pub(crate) bundle_count: usize,
    pub(crate) protected_count: usize,
    pub(crate) bundles: Vec<EdrEvidenceBundleRecord>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdrEvidenceBundleCompactionInput {
    #[serde(default, alias = "maxBundles")]
    pub(crate) max_bundles: Option<usize>,
    #[serde(default, alias = "minAgeSeconds")]
    pub(crate) min_age_seconds: Option<u64>,
    #[serde(default, alias = "dryRun")]
    pub(crate) dry_run: Option<bool>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrEvidenceBundleCompactionRecord {
    pub(crate) bundle_id: String,
    pub(crate) graph_slice_id: String,
    pub(crate) path: Option<String>,
    pub(crate) byte_count: usize,
    pub(crate) age_seconds: u64,
    pub(crate) protected_by_active_response: bool,
    pub(crate) removed: bool,
    pub(crate) reason: String,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrEvidenceBundleCompactionResponse {
    pub(crate) root: Option<String>,
    pub(crate) dry_run: bool,
    pub(crate) max_bundles: Option<usize>,
    pub(crate) min_age_seconds: u64,
    pub(crate) bundle_count: usize,
    pub(crate) candidate_count: usize,
    pub(crate) removed_count: usize,
    pub(crate) protected_count: usize,
    pub(crate) records: Vec<EdrEvidenceBundleCompactionRecord>,
}
#[derive(Debug, Serialize)]
pub(crate) struct EdrFlightRecorderResponse {
    pub(crate) path: Option<String>,
    pub(crate) observation_count: usize,
    pub(crate) node_count: usize,
    pub(crate) edge_count: usize,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdrFlightRecorderCompactionInput {
    #[serde(default, alias = "maxObservations")]
    pub(crate) max_observations: Option<usize>,
    #[serde(default, alias = "minAgeSeconds")]
    pub(crate) min_age_seconds: Option<u64>,
    #[serde(default, alias = "dryRun")]
    pub(crate) dry_run: Option<bool>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrFlightRecorderCompactionResponse {
    pub(crate) path: Option<String>,
    pub(crate) dry_run: bool,
    pub(crate) max_observations: Option<usize>,
    pub(crate) min_age_seconds: u64,
    pub(crate) observation_count: usize,
    pub(crate) candidate_count: usize,
    pub(crate) removed_count: usize,
    pub(crate) retained_count: usize,
    pub(crate) protected_count: usize,
    pub(crate) node_count: usize,
    pub(crate) edge_count: usize,
    pub(crate) records: Vec<EndpointFlightRecorderCompactionRecord>,
}
#[derive(Debug, Deserialize)]
pub(crate) struct EdrReceiptQuery {
    #[serde(default, alias = "receiptId")]
    pub(crate) receipt_id: Option<String>,
    #[serde(default)]
    pub(crate) family: Option<String>,
    #[serde(default)]
    pub(crate) limit: Option<usize>,
    #[serde(default)]
    pub(crate) action: Option<String>,
    #[serde(default, alias = "findingId")]
    pub(crate) finding_id: Option<String>,
    #[serde(default, alias = "ruleId")]
    pub(crate) rule_id: Option<String>,
    #[serde(default, alias = "graphSliceId")]
    pub(crate) graph_slice_id: Option<String>,
    #[serde(default, alias = "rootNodeId")]
    pub(crate) root_node_id: Option<String>,
    #[serde(default, alias = "executionId")]
    pub(crate) execution_id: Option<String>,
    #[serde(default)]
    pub(crate) status: Option<String>,
    #[serde(default, alias = "actorEndpointId")]
    pub(crate) actor_endpoint_id: Option<String>,
    #[serde(default, alias = "actorUserId")]
    pub(crate) actor_user_id: Option<String>,
    #[serde(default, alias = "actorSessionId")]
    pub(crate) actor_session_id: Option<String>,
    #[serde(default, alias = "actorAgentId")]
    pub(crate) actor_agent_id: Option<String>,
    #[serde(default, alias = "actorWorkloadId")]
    pub(crate) actor_workload_id: Option<String>,
    #[serde(default, alias = "actorApprovalId")]
    pub(crate) actor_approval_id: Option<String>,
    #[serde(default, alias = "localSequence")]
    pub(crate) local_sequence: Option<u64>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdrReceiptUploadInput {
    #[serde(default, alias = "receiptId")]
    pub(crate) receipt_id: Option<String>,
    #[serde(default)]
    pub(crate) family: Option<String>,
    #[serde(default)]
    pub(crate) limit: Option<usize>,
    #[serde(default)]
    pub(crate) action: Option<String>,
    #[serde(default, alias = "findingId")]
    pub(crate) finding_id: Option<String>,
    #[serde(default, alias = "ruleId")]
    pub(crate) rule_id: Option<String>,
    #[serde(default, alias = "graphSliceId")]
    pub(crate) graph_slice_id: Option<String>,
    #[serde(default, alias = "rootNodeId")]
    pub(crate) root_node_id: Option<String>,
    #[serde(default, alias = "executionId")]
    pub(crate) execution_id: Option<String>,
    #[serde(default)]
    pub(crate) status: Option<String>,
    #[serde(default, alias = "actorEndpointId")]
    pub(crate) actor_endpoint_id: Option<String>,
    #[serde(default, alias = "actorUserId")]
    pub(crate) actor_user_id: Option<String>,
    #[serde(default, alias = "actorSessionId")]
    pub(crate) actor_session_id: Option<String>,
    #[serde(default, alias = "actorAgentId")]
    pub(crate) actor_agent_id: Option<String>,
    #[serde(default, alias = "actorWorkloadId")]
    pub(crate) actor_workload_id: Option<String>,
    #[serde(default, alias = "actorApprovalId")]
    pub(crate) actor_approval_id: Option<String>,
    #[serde(default, alias = "localSequence")]
    pub(crate) local_sequence: Option<u64>,
    #[serde(default, alias = "dryRun")]
    pub(crate) dry_run: Option<bool>,
}
#[derive(Debug, Serialize)]
pub(crate) struct EdrReceiptsResponse {
    pub(crate) path: Option<String>,
    pub(crate) receipt_count: usize,
    pub(crate) receipts: Vec<SignedReceipt>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrReceiptUploadResponse {
    pub(crate) path: Option<String>,
    pub(crate) dry_run: bool,
    pub(crate) control_api_url: Option<String>,
    pub(crate) selected_count: usize,
    pub(crate) attempted: bool,
    pub(crate) accepted: bool,
    pub(crate) uploaded_count: usize,
    pub(crate) http_status: Option<u16>,
    pub(crate) response_hash: Option<String>,
    pub(crate) error_hash: Option<String>,
    pub(crate) skipped_reason: Option<String>,
    pub(crate) records: Vec<EdrReceiptUploadRecord>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrReceiptUploadRecord {
    pub(crate) receipt_id: Option<String>,
    pub(crate) timestamp: String,
    pub(crate) family: Option<String>,
    pub(crate) verdict: String,
    pub(crate) guard: String,
    pub(crate) policy_name: String,
    pub(crate) local_sequence: Option<u64>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdrReceiptCompactionInput {
    #[serde(default, alias = "maxReceipts")]
    pub(crate) max_receipts: Option<usize>,
    #[serde(default, alias = "minAgeSeconds")]
    pub(crate) min_age_seconds: Option<u64>,
    #[serde(default, alias = "dryRun")]
    pub(crate) dry_run: Option<bool>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrReceiptCompactionRecord {
    pub(crate) receipt_id: Option<String>,
    pub(crate) timestamp: String,
    pub(crate) age_seconds: u64,
    pub(crate) family: Option<String>,
    pub(crate) action: Option<String>,
    pub(crate) finding_id: Option<String>,
    pub(crate) rule_id: Option<String>,
    pub(crate) graph_slice_id: Option<String>,
    pub(crate) root_node_id: Option<String>,
    pub(crate) local_sequence: Option<u64>,
    pub(crate) removed: bool,
    pub(crate) reason: String,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrReceiptCompactionResponse {
    pub(crate) path: Option<String>,
    pub(crate) dry_run: bool,
    pub(crate) max_receipts: Option<usize>,
    pub(crate) min_age_seconds: u64,
    pub(crate) receipt_count: usize,
    pub(crate) candidate_count: usize,
    pub(crate) removed_count: usize,
    pub(crate) retained_count: usize,
    pub(crate) records: Vec<EdrReceiptCompactionRecord>,
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct EdrReceiptFilter<'a> {
    pub(crate) receipt_id: Option<&'a str>,
    pub(crate) family: Option<&'a str>,
    pub(crate) action: Option<&'a str>,
    pub(crate) finding_id: Option<&'a str>,
    pub(crate) rule_id: Option<&'a str>,
    pub(crate) graph_slice_id: Option<&'a str>,
    pub(crate) root_node_id: Option<&'a str>,
    pub(crate) execution_id: Option<&'a str>,
    pub(crate) status: Option<&'a str>,
    pub(crate) actor_endpoint_id: Option<&'a str>,
    pub(crate) actor_user_id: Option<&'a str>,
    pub(crate) actor_session_id: Option<&'a str>,
    pub(crate) actor_agent_id: Option<&'a str>,
    pub(crate) actor_workload_id: Option<&'a str>,
    pub(crate) actor_approval_id: Option<&'a str>,
    pub(crate) local_sequence: Option<u64>,
}
#[derive(Debug, Serialize)]
pub(crate) struct EdrProtectionStateResponse {
    pub(crate) policy: EndpointPolicySnapshot,
    pub(crate) sensor_state: EndpointSensorState,
    pub(crate) receipt: SignedReceipt,
    pub(crate) degraded_provider_receipts: Vec<SignedReceipt>,
    pub(crate) provider_recoveries: Vec<EdrProviderRecovery>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrProviderRecovery {
    pub(crate) provider_id: String,
    pub(crate) provider_kind: EndpointProviderKind,
    pub(crate) previous_active: bool,
    pub(crate) previous_healthy: bool,
    pub(crate) previous_degraded: bool,
    pub(crate) previous_degradation_reasons: Vec<String>,
    pub(crate) current_active: bool,
    pub(crate) current_healthy: bool,
    pub(crate) current_degraded: bool,
    pub(crate) recovered_at: Option<chrono::DateTime<chrono::Utc>>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdrDeceptionPlanInput {
    pub(crate) root: String,
    pub(crate) endpoint_id: String,
}
#[derive(Debug, Serialize)]
pub(crate) struct EdrDeceptionPlanResponse {
    pub(crate) artifact_count: usize,
    pub(crate) plan: DeceptionPlan,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdrMaterializeDeceptionPlanInput {
    pub(crate) plan: DeceptionPlan,
}
#[derive(Debug, Serialize)]
pub(crate) struct EdrMaterializeDeceptionPlanResponse {
    pub(crate) report: DeceptionMaterializationReport,
    pub(crate) registered_artifact_count: usize,
    pub(crate) registry_path: Option<String>,
    pub(crate) receipt: SignedReceipt,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrCleanupDeceptionPlanInput {
    pub(crate) plan: DeceptionPlan,
    #[serde(default)]
    pub(crate) dry_run: Option<bool>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrCleanupDeceptionPlanResponse {
    pub(crate) report: DeceptionCleanupReport,
    pub(crate) deregistered_artifact_count: usize,
    pub(crate) remaining_registered_artifact_count: usize,
    pub(crate) registry_path: Option<String>,
    pub(crate) receipt: SignedReceipt,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EdrRotateDeceptionPlanInput {
    pub(crate) old_plan: DeceptionPlan,
    pub(crate) new_plan: DeceptionPlan,
    #[serde(default)]
    pub(crate) dry_run: Option<bool>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdrRotateDeceptionPlanResponse {
    pub(crate) report: DeceptionRotationReport,
    pub(crate) deregistered_artifact_count: usize,
    pub(crate) registered_artifact_count: usize,
    pub(crate) remaining_registered_artifact_count: usize,
    pub(crate) registry_path: Option<String>,
    pub(crate) cleanup_receipt: SignedReceipt,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) materialization_receipt: Option<SignedReceipt>,
    pub(crate) rotation_receipt: SignedReceipt,
}
