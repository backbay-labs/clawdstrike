//! Developer activity observation DTOs.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::edr::{
    CredentialKind, DetectionFinding, EndpointObservation, EndpointProcess, HoneyArtifact,
    PackageManager,
};
use hush_core::SignedReceipt;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrDeveloperActivityInput {
    #[serde(default)]
    pub activities: Vec<EdrDeveloperActivity>,
    #[serde(default, alias = "honey_artifacts")]
    pub honey_artifacts: Vec<HoneyArtifact>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrDeveloperActivity {
    #[serde(default, alias = "id", alias = "activityId")]
    pub activity_id: Option<String>,
    pub kind: EdrDeveloperActivityKind,
    #[serde(default, alias = "observedAt", alias = "timestamp")]
    pub observed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, alias = "hostId")]
    pub host_id: Option<String>,
    #[serde(default, alias = "userId")]
    pub user_id: Option<String>,
    #[serde(default, alias = "sessionId")]
    pub session_id: Option<String>,
    #[serde(default, alias = "agentId")]
    pub agent_id: Option<String>,
    #[serde(default, alias = "workloadId")]
    pub workload_id: Option<String>,
    #[serde(default, alias = "approvalId")]
    pub approval_id: Option<String>,
    #[serde(default, alias = "toolCallId", alias = "tool_call_id")]
    pub tool_call_id: Option<String>,
    #[serde(default)]
    pub process: Option<EndpointProcess>,
    #[serde(default, alias = "processGuid", alias = "process_guid")]
    pub process_guid: Option<String>,
    #[serde(default, alias = "parentProcessGuid", alias = "parent_process_guid")]
    pub parent_process_guid: Option<String>,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub ppid: Option<u32>,
    #[serde(default, alias = "processImage", alias = "process_image")]
    pub process_image: Option<String>,
    #[serde(default, alias = "processCommandLine", alias = "process_command_line")]
    pub process_command_line: Option<String>,
    #[serde(default, alias = "processCwd", alias = "process_cwd")]
    pub process_cwd: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, serde_json::Value>,
    #[serde(default, alias = "toolName")]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub parameters: Option<serde_json::Value>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default, alias = "recordType")]
    pub record_type: Option<String>,
    #[serde(default)]
    pub answers: Vec<String>,
    #[serde(default)]
    pub resolver: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub manager: Option<PackageManager>,
    #[serde(default)]
    pub package: Option<String>,
    #[serde(default)]
    pub phase: Option<String>,
    #[serde(default)]
    pub script: Option<String>,
    #[serde(default, alias = "workingDirectory")]
    pub working_directory: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default, alias = "commandLine")]
    pub command_line: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default, alias = "contentHash")]
    pub content_hash: Option<String>,
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
    pub byte_count: Option<u64>,
    #[serde(default, alias = "patchBytes")]
    pub patch_bytes: Option<u64>,
    #[serde(default, alias = "patchHash")]
    pub patch_hash: Option<String>,
    #[serde(default)]
    pub mechanism: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, alias = "credentialKind")]
    pub credential_kind: Option<CredentialKind>,
    #[serde(default)]
    pub browser: Option<String>,
    #[serde(default, alias = "sourceUrl")]
    pub source_url: Option<String>,
    #[serde(default, alias = "extensionId")]
    pub extension_id: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EdrDeveloperActivityKind {
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
    pub fn as_str(self) -> &'static str {
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
pub struct EdrDeveloperActivityResponse {
    pub activity_count: usize,
    pub observation_count: usize,
    pub finding_count: usize,
    pub receipt_count: usize,
    pub observations: Vec<EndpointObservation>,
    pub findings: Vec<DetectionFinding>,
    pub receipts: Vec<SignedReceipt>,
    pub observation_receipts: Vec<SignedReceipt>,
    pub policy_decision_receipts: Vec<SignedReceipt>,
}
