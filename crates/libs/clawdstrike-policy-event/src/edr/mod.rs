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

mod conversion;
mod finding_builders;
mod honey;
mod projection;
mod supply_chain_cli;
mod util;

pub(crate) use conversion::{
    agent_id_field, approval_id_field, canonical_graph_content_hash, credential_kind_field,
    endpoint_decision_actor_content_hash, endpoint_event_from_policy_event,
    endpoint_observation_content_hash, endpoint_sensor_state_content_hash, event_target_field,
    event_target_hash_field, metadata_as_btree, normalized_identity_value, observation_age_seconds,
    process_command_line_hash_field, process_from_metadata, process_image_hash_field, string_field,
    string_field_nested, tool_call_id_field, tool_name_field, workload_id_field,
};
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

#[cfg(test)]
mod tests;
