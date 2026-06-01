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

mod util;

pub(crate) use util::{
    evidence_hash_for_value, hostname_from_url_like, insert_json, normalize_hostname,
    normalize_path_string, reconstruct_path, response_execution_id_from_effect_digest,
    response_execution_id_from_effects, response_execution_transition_id_from_reason_hash,
    stable_id, telemetry_privacy_report_id_from_evidence_hashes,
    telemetry_privacy_report_id_from_values,
};

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

#[cfg(test)]
mod tests;
