//! Detection finding builders and supply-chain path/credential predicates.
//!
//! Named `finding_builders` to avoid colliding with `detection::finding`.
//! These assemble `DetectionFinding`s (stamping shared identity evidence) and
//! provide the path/script/credential heuristics the detectors share.

#![allow(dead_code)]

use super::{
    agent_id_field, approval_id_field, normalize_path_string, normalized_identity_value, stable_id,
    tool_call_id_field, tool_name_field, workload_id_field, CredentialKind, DetectionEvidence,
    DetectionFinding, DetectionSeverity, EndpointObservation,
};

pub(crate) struct FindingRule<'a> {
    pub(crate) rule_id: &'a str,
    pub(crate) title: &'a str,
    pub(crate) severity: DetectionSeverity,
    pub(crate) confidence: f32,
    pub(crate) description: &'a str,
    pub(crate) mitre_attack: Vec<&'a str>,
    pub(crate) tags: Vec<&'a str>,
    pub(crate) remediation: &'a str,
}

pub(crate) fn finding(
    observation: &EndpointObservation,
    mut evidence: Vec<DetectionEvidence>,
    rule: FindingRule<'_>,
) -> DetectionFinding {
    append_observation_identity_evidence(observation, &mut evidence);
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

fn append_observation_identity_evidence(
    observation: &EndpointObservation,
    evidence: &mut Vec<DetectionEvidence>,
) {
    push_optional_identity_evidence(evidence, "hostId", observation.host_id.clone());
    push_optional_identity_evidence(evidence, "userId", observation.user_id.clone());
    push_optional_identity_evidence(evidence, "sessionId", observation.session_id.clone());
    push_optional_identity_evidence(
        evidence,
        "processGuid",
        normalized_identity_value(observation.process.process_guid.as_deref()),
    );
    push_optional_identity_evidence(
        evidence,
        "parentProcessGuid",
        normalized_identity_value(observation.process.parent_process_guid.as_deref()),
    );
    push_optional_identity_evidence(evidence, "agentId", agent_id_field(&observation.metadata));
    push_optional_identity_evidence(
        evidence,
        "workloadId",
        workload_id_field(&observation.metadata),
    );
    push_optional_identity_evidence(
        evidence,
        "approvalId",
        approval_id_field(&observation.metadata),
    );
    push_optional_identity_evidence(evidence, "toolName", tool_name_field(observation));
    push_optional_identity_evidence(
        evidence,
        "toolCallId",
        tool_call_id_field(&observation.metadata),
    );
}

fn push_optional_identity_evidence(
    evidence: &mut Vec<DetectionEvidence>,
    key: &'static str,
    value: Option<String>,
) {
    let Some(value) = value else {
        return;
    };
    if evidence.iter().any(|item| item.key == key) {
        return;
    }
    evidence.push(ev(key, value));
}

pub(crate) fn ev(key: impl Into<String>, value: impl Into<String>) -> DetectionEvidence {
    DetectionEvidence {
        key: key.into(),
        value: value.into(),
    }
}

pub(crate) fn opt_ev(key: impl Into<String>, value: Option<&str>) -> Option<DetectionEvidence> {
    value.map(|value| ev(key, value))
}

pub(crate) fn is_install_phase(phase: &str) -> bool {
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

pub(crate) fn suspicious_script_reason(script: &str) -> Option<&'static str> {
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

pub(crate) fn path_is_user_writable_or_download(path: &str) -> bool {
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

pub(crate) fn path_is_launch_persistence(path: &str) -> bool {
    let path = normalize_path_string(path);
    path.contains("/Library/LaunchAgents/")
        || path.contains("/Library/LaunchDaemons/")
        || path.contains("/System/Library/LaunchAgents/")
        || path.contains("/System/Library/LaunchDaemons/")
}

pub(crate) fn path_looks_like_browser_extension(path: &str) -> bool {
    let path = normalize_path_string(path);
    path.contains("/Extensions/") || path.contains("/Browser Extensions/")
}

pub(crate) fn path_looks_like_developer_secret(path: &str) -> bool {
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

pub(crate) fn credential_kind_is_developer_secret(kind: &CredentialKind) -> bool {
    matches!(
        kind,
        CredentialKind::SshKey
            | CredentialKind::ApiToken
            | CredentialKind::CloudCredential
            | CredentialKind::PackageRegistryToken
            | CredentialKind::SigningKey
    )
}

pub(crate) fn credential_kind_from_secret(scope: &str, secret_name: &str) -> CredentialKind {
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
