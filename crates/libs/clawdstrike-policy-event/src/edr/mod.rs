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

mod finding_builders;
mod honey;
mod projection;
mod supply_chain_cli;
mod util;

pub(crate) use finding_builders::{
    credential_kind_from_secret, credential_kind_is_developer_secret, ev, finding,
    is_install_phase, opt_ev, path_is_launch_persistence, path_is_user_writable_or_download,
    path_looks_like_browser_extension, path_looks_like_developer_secret, suspicious_script_reason,
    FindingRule,
};
pub(crate) use honey::{
    create_new_honey_file, ensure_safe_relative_path, honey_artifact, honey_artifact_match_evidence,
};
pub(crate) use projection::{count_projection_class, project_observation_privacy};
pub(crate) use supply_chain_cli::{
    cloud_cli_name, cloud_credential_env_keys, command_looks_like_package_manager,
    package_registry_cli_name, package_registry_credential_env_keys, suspicious_cloud_cli_reason,
    suspicious_package_registry_cli_reason,
};
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

#[cfg(test)]
mod tests;
