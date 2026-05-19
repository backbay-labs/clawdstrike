use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::super::{
    cloud_cli_name, cloud_credential_env_keys, command_looks_like_package_manager,
    credential_kind_is_developer_secret, ev, finding, FindingRule, honey_artifact,
    honey_artifact_match_evidence, is_install_phase, normalize_hostname, normalize_path_string,
    opt_ev, package_registry_cli_name, package_registry_credential_env_keys,
    path_is_launch_persistence, path_is_user_writable_or_download,
    path_looks_like_browser_extension, path_looks_like_developer_secret, stable_id,
    string_field_nested, suspicious_cloud_cli_reason, suspicious_package_registry_cli_reason,
    suspicious_script_reason,
};
use super::finding::{DetectionEvidence, DetectionFinding, DetectionSeverity};
use super::super::event::{
    CredentialKind, EndpointEvent, EndpointObservation, FileOperation, PackageManager,
};
use super::super::deception::{DeceptionPlan, HoneyArtifact, HoneyArtifactKind};
use super::super::process::EndpointProcess;

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
