pub mod compaction;
pub mod index;

pub use compaction::*;
pub use index::*;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{BufRead as _, BufReader, ErrorKind, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use hush_core::sha256;
use serde::{Deserialize, Serialize};

use self::compaction::{
    EndpointFlightRecorderCompactionManifest, EndpointFlightRecorderCompactionRecord,
    EndpointFlightRecorderCompactionReport,
};
use self::index::{
    EndpointFlightRecorderGraphEdgeIndexEntry, EndpointFlightRecorderGraphNodeIndexEntry,
    EndpointFlightRecorderHistoryIndexEntry,
};
use super::causal::{
    CausalEdge, CausalEdgeKind, CausalGraph, CausalGraphRecorder, CausalNode, CausalNodeKind,
};
use super::event::EndpointObservation;
use super::{
    agent_id_field, approval_id_field, credential_kind_field, event_target_field,
    event_target_hash_field, normalize_path_string, observation_age_seconds,
    process_command_line_hash_field, process_image_hash_field, stable_id, string_field,
    tool_call_id_field, tool_name_field, workload_id_field,
    ENDPOINT_FLIGHT_RECORDER_GRAPH_EDGE_INDEX_SCHEMA_VERSION,
    ENDPOINT_FLIGHT_RECORDER_GRAPH_INDEX_SCHEMA_VERSION,
    ENDPOINT_FLIGHT_RECORDER_HISTORY_INDEX_SCHEMA_VERSION,
};

#[cfg(unix)]
const ENDPOINT_PRIVATE_FILE_MODE: u32 = 0o600;
const ENDPOINT_FLIGHT_RECORDER_LOG_RECORD_SCHEMA_VERSION: u32 = 1;
const ENDPOINT_FLIGHT_RECORDER_COMPACTION_MANIFEST_SCHEMA_VERSION: u8 = 2;

fn endpoint_private_open_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        options.mode(ENDPOINT_PRIVATE_FILE_MODE);
    }
    options
}

fn enforce_endpoint_private_file_mode(path: &Path, target: &str) -> Result<()> {
    #[cfg(unix)]
    {
        let metadata = fs::metadata(path)
            .with_context(|| format!("read {target} metadata {}", path.display()))?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != ENDPOINT_PRIVATE_FILE_MODE {
            let mut permissions = metadata.permissions();
            permissions.set_mode(ENDPOINT_PRIVATE_FILE_MODE);
            fs::set_permissions(path, permissions)
                .with_context(|| format!("set {target} permissions on {}", path.display()))?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, target);
    }
    Ok(())
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

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointFlightRecorderHistoryWindow {
    pub selection_mode: String,
    pub index_path: Option<PathBuf>,
    pub total_observation_count: usize,
    pub matched_observation_count: usize,
    pub selected_observations: Vec<EndpointObservation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EndpointFlightRecorderLogRecord {
    schema_version: u32,
    sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_record_hash: Option<String>,
    observation_hash: String,
    record_hash: String,
    observation: EndpointObservation,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EndpointFlightRecorderLogRecordBody<'a> {
    schema_version: u32,
    sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_record_hash: Option<&'a str>,
    observation_hash: &'a str,
    observation: &'a EndpointObservation,
}

#[derive(Clone, Debug)]
struct EndpointFlightRecorderLogChainState {
    next_sequence: u64,
    previous_record_hash: Option<String>,
}

impl Default for EndpointFlightRecorderLogChainState {
    fn default() -> Self {
        Self {
            next_sequence: 1,
            previous_record_hash: None,
        }
    }
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

            let mut options = endpoint_private_open_options();
            let mut file = options
                .create(true)
                .append(true)
                .read(true)
                .open(path)
                .with_context(|| format!("open endpoint flight recorder log {}", path.display()))?;
            enforce_endpoint_private_file_mode(path, "endpoint flight recorder log")?;
            let mut byte_offset = file
                .seek(SeekFrom::End(0))
                .with_context(|| format!("seek endpoint flight recorder log {}", path.display()))?;
            let mut index_entries = Vec::with_capacity(observations.len());
            let mut chain_state = read_endpoint_flight_recorder_log_chain_state(path)?;

            for observation in observations {
                let record = endpoint_flight_recorder_log_record(observation, &chain_state)
                    .with_context(|| {
                        format!(
                            "hash-chain endpoint observation {}",
                            observation.observation_id
                        )
                    })?;
                let mut bytes = serde_json::to_vec(&record).with_context(|| {
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
                chain_state.advance_hashed_record(record.record_hash);
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
        let Some(path) = self.path.clone() else {
            return Err(anyhow!(
                "endpoint flight recorder compaction requires a durable backing file"
            ));
        };
        let observations = self.read_observations_from_disk()?;
        let pre_compaction_chain = read_endpoint_flight_recorder_log_chain_state(&path)?;
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

        let continuity_manifest = if !dry_run {
            let mut manifest = EndpointFlightRecorderCompactionManifest {
                schema_version: ENDPOINT_FLIGHT_RECORDER_COMPACTION_MANIFEST_SCHEMA_VERSION,
                compacted_at: now,
                reason: format!(
                    "flight recorder compaction retained {} of {} observations",
                    retained.len(),
                    observation_count
                ),
                manifest_hash: None,
                compaction_boundary_hash: None,
                pre_compaction_head: pre_compaction_chain.previous_record_hash.clone(),
                pre_compaction_record_count: pre_compaction_chain.record_count(),
                post_compaction_head: None,
                post_compaction_record_count: pre_compaction_chain.record_count(),
                retained_observation_ids: retained
                    .iter()
                    .map(|observation| observation.observation_id.clone())
                    .collect(),
                removed_records: records.clone(),
            };
            let compaction_boundary_hash =
                endpoint_flight_recorder_compaction_boundary_hash(&manifest)?;
            manifest.compaction_boundary_hash = Some(compaction_boundary_hash.clone());
            let post_compaction_chain = self.rewrite_observations(
                &retained,
                EndpointFlightRecorderLogChainState {
                    next_sequence: pre_compaction_chain.next_sequence,
                    previous_record_hash: Some(compaction_boundary_hash),
                },
            )?;
            manifest.post_compaction_head = post_compaction_chain.previous_record_hash.clone();
            manifest.post_compaction_record_count = post_compaction_chain.record_count();
            let manifest = seal_endpoint_flight_recorder_compaction_manifest(manifest)?;
            append_endpoint_flight_recorder_compaction_manifest(&path, &manifest)?;
            Some(manifest)
        } else {
            None
        };

        Ok(EndpointFlightRecorderCompactionReport {
            observation_count,
            retained_count: retained.len(),
            protected_count,
            continuity_manifest,
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

    fn rewrite_observations(
        &mut self,
        observations: &[EndpointObservation],
        initial_chain_state: EndpointFlightRecorderLogChainState,
    ) -> Result<EndpointFlightRecorderLogChainState> {
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
        let mut chain_state = initial_chain_state;
        {
            let mut options = endpoint_private_open_options();
            let mut file = options
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
            enforce_endpoint_private_file_mode(
                &tmp_path,
                "temporary endpoint flight recorder log",
            )?;
            for observation in observations {
                let record = endpoint_flight_recorder_log_record(observation, &chain_state)
                    .with_context(|| {
                        format!(
                            "hash-chain endpoint observation {}",
                            observation.observation_id
                        )
                    })?;
                let mut bytes = serde_json::to_vec(&record).with_context(|| {
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
                        tmp_path.display()
                    )
                })?;
                let byte_len = bytes.len() as u64;
                index_entries.push(endpoint_observation_index_entry(
                    observation,
                    byte_offset,
                    byte_len,
                ));
                byte_offset = byte_offset.saturating_add(byte_len);
                chain_state.advance_hashed_record(record.record_hash);
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
        enforce_endpoint_private_file_mode(&path, "endpoint flight recorder log")?;
        replace_endpoint_observation_index(&path, &index_entries)?;
        self.rebuild_from_observations(observations);
        replace_endpoint_graph_node_index(&path, self.recorder.graph())?;
        replace_endpoint_graph_edge_index(&path, self.recorder.graph())?;
        Ok(chain_state)
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
    let (mut chain_state, compaction_manifest) =
        endpoint_flight_recorder_compaction_initial_state(path)?;
    let expected_retained_observation_count = compaction_manifest
        .as_ref()
        .map(|manifest| manifest.retained_observation_ids.len())
        .unwrap_or_default();
    let mut observed_retained_observation_ids =
        Vec::with_capacity(expected_retained_observation_count);
    let mut observed_compaction_tail =
        observed_compaction_tail_head(compaction_manifest.as_ref(), &chain_state);
    for (idx, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let observation = parse_endpoint_flight_recorder_log_line(
            path,
            idx + 1,
            trimmed,
            Some(&mut chain_state),
        )?
        .ok_or_else(|| {
            anyhow!(
                "invalid empty endpoint observation JSONL at {}:{}",
                path.display(),
                idx + 1
            )
        })?;
        if observed_retained_observation_ids.len() < expected_retained_observation_count {
            observed_retained_observation_ids.push(observation.observation_id.clone());
        }
        observed_compaction_tail = observed_compaction_tail
            .or_else(|| observed_compaction_tail_head(compaction_manifest.as_ref(), &chain_state));
        observations.push(observation);
    }
    validate_endpoint_flight_recorder_compaction_tail(
        path,
        compaction_manifest.as_ref(),
        &chain_state,
        observed_compaction_tail.as_ref(),
        compaction_manifest
            .as_ref()
            .map(|_| observed_retained_observation_ids.as_slice()),
    )?;
    Ok(observations)
}

fn read_endpoint_flight_recorder_log_chain_state(
    path: &Path,
) -> Result<EndpointFlightRecorderLogChainState> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return Ok(EndpointFlightRecorderLogChainState::default())
        }
        Err(err) => {
            return Err(err)
                .with_context(|| format!("read endpoint flight recorder log {}", path.display()))
        }
    };
    let reader = BufReader::new(file);
    let (mut chain_state, compaction_manifest) =
        endpoint_flight_recorder_compaction_initial_state(path)?;
    let expected_retained_observation_count = compaction_manifest
        .as_ref()
        .map(|manifest| manifest.retained_observation_ids.len())
        .unwrap_or_default();
    let mut observed_retained_observation_ids =
        Vec::with_capacity(expected_retained_observation_count);
    let mut observed_compaction_tail =
        observed_compaction_tail_head(compaction_manifest.as_ref(), &chain_state);
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
        if let Some(observation) =
            parse_endpoint_flight_recorder_log_line(path, idx + 1, trimmed, Some(&mut chain_state))?
        {
            if observed_retained_observation_ids.len() < expected_retained_observation_count {
                observed_retained_observation_ids.push(observation.observation_id);
            }
        }
        observed_compaction_tail = observed_compaction_tail
            .or_else(|| observed_compaction_tail_head(compaction_manifest.as_ref(), &chain_state));
    }
    validate_endpoint_flight_recorder_compaction_tail(
        path,
        compaction_manifest.as_ref(),
        &chain_state,
        observed_compaction_tail.as_ref(),
        compaction_manifest
            .as_ref()
            .map(|_| observed_retained_observation_ids.as_slice()),
    )?;
    Ok(chain_state)
}

fn endpoint_flight_recorder_log_record(
    observation: &EndpointObservation,
    chain_state: &EndpointFlightRecorderLogChainState,
) -> Result<EndpointFlightRecorderLogRecord> {
    let observation_hash = endpoint_flight_recorder_observation_hash(observation)?;
    let body = EndpointFlightRecorderLogRecordBody {
        schema_version: ENDPOINT_FLIGHT_RECORDER_LOG_RECORD_SCHEMA_VERSION,
        sequence: chain_state.next_sequence,
        previous_record_hash: chain_state.previous_record_hash.as_deref(),
        observation_hash: observation_hash.as_str(),
        observation,
    };
    let record_hash = endpoint_flight_recorder_record_hash(&body)?;
    Ok(EndpointFlightRecorderLogRecord {
        schema_version: body.schema_version,
        sequence: body.sequence,
        previous_record_hash: chain_state.previous_record_hash.clone(),
        observation_hash,
        record_hash,
        observation: observation.clone(),
    })
}

fn endpoint_flight_recorder_observation_hash(observation: &EndpointObservation) -> Result<String> {
    let bytes = serde_json::to_vec(observation).with_context(|| {
        format!(
            "serialize endpoint observation {}",
            observation.observation_id
        )
    })?;
    Ok(sha256(&bytes).to_hex_prefixed())
}

fn endpoint_flight_recorder_record_hash(
    body: &EndpointFlightRecorderLogRecordBody<'_>,
) -> Result<String> {
    let bytes = serde_json::to_vec(body).context("serialize endpoint flight recorder hash body")?;
    Ok(sha256(&bytes).to_hex_prefixed())
}

fn parse_endpoint_flight_recorder_log_line(
    path: &Path,
    line_number: usize,
    trimmed: &str,
    chain_state: Option<&mut EndpointFlightRecorderLogChainState>,
) -> Result<Option<EndpointObservation>> {
    if trimmed.is_empty() {
        return Ok(None);
    }
    match serde_json::from_str::<EndpointFlightRecorderLogRecord>(trimmed) {
        Ok(record) => {
            validate_endpoint_flight_recorder_log_record(path, line_number, &record, chain_state)?;
            Ok(Some(record.observation))
        }
        Err(record_err) => {
            if chain_state.is_some() {
                serde_json::from_str::<serde_json::Value>(trimmed).with_context(|| {
                    format!(
                        "invalid endpoint observation JSONL at {}:{}; hash-chain record parse error: {record_err}",
                        path.display(),
                        line_number
                    )
                })?;
                return Err(anyhow!(
                    "legacy endpoint observation JSONL at {}:{} is not accepted by the production hash-chain reader; run an explicit migration before using this log as durable evidence; hash-chain record parse error: {record_err}",
                    path.display(),
                    line_number
                ));
            }
            let observation: EndpointObservation =
                serde_json::from_str(trimmed).with_context(|| {
                    format!(
                        "invalid endpoint observation JSONL at {}:{}; hash-chain record parse error: {record_err}",
                        path.display(),
                        line_number
                    )
                })?;
            Ok(Some(observation))
        }
    }
}

fn validate_endpoint_flight_recorder_log_record(
    path: &Path,
    line_number: usize,
    record: &EndpointFlightRecorderLogRecord,
    chain_state: Option<&mut EndpointFlightRecorderLogChainState>,
) -> Result<()> {
    if record.schema_version != ENDPOINT_FLIGHT_RECORDER_LOG_RECORD_SCHEMA_VERSION {
        return Err(anyhow!(
            "endpoint flight recorder hash-chain schema mismatch at {}:{}: expected {}, found {}",
            path.display(),
            line_number,
            ENDPOINT_FLIGHT_RECORDER_LOG_RECORD_SCHEMA_VERSION,
            record.schema_version
        ));
    }
    let observation_hash = endpoint_flight_recorder_observation_hash(&record.observation)?;
    if record.observation_hash != observation_hash {
        return Err(anyhow!(
            "endpoint flight recorder observation hash mismatch at {}:{} for {}",
            path.display(),
            line_number,
            record.observation.observation_id
        ));
    }
    let body = EndpointFlightRecorderLogRecordBody {
        schema_version: record.schema_version,
        sequence: record.sequence,
        previous_record_hash: record.previous_record_hash.as_deref(),
        observation_hash: record.observation_hash.as_str(),
        observation: &record.observation,
    };
    let record_hash = endpoint_flight_recorder_record_hash(&body)?;
    if record.record_hash != record_hash {
        return Err(anyhow!(
            "endpoint flight recorder record hash mismatch at {}:{} for {}",
            path.display(),
            line_number,
            record.observation.observation_id
        ));
    }
    if let Some(chain_state) = chain_state {
        if record.sequence != chain_state.next_sequence {
            return Err(anyhow!(
                "endpoint flight recorder sequence mismatch at {}:{}: expected {}, found {}",
                path.display(),
                line_number,
                chain_state.next_sequence,
                record.sequence
            ));
        }
        if record.previous_record_hash != chain_state.previous_record_hash {
            return Err(anyhow!(
                "endpoint flight recorder previous hash mismatch at {}:{} for {}",
                path.display(),
                line_number,
                record.observation.observation_id
            ));
        }
        chain_state.advance_hashed_record(record.record_hash.clone());
    }
    Ok(())
}

impl EndpointFlightRecorderLogChainState {
    fn record_count(&self) -> u64 {
        self.next_sequence.saturating_sub(1)
    }

    fn advance_hashed_record(&mut self, record_hash: String) {
        self.previous_record_hash = Some(record_hash);
        self.next_sequence = self.next_sequence.saturating_add(1);
    }
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
        let observation = parse_endpoint_flight_recorder_log_line(path, 0, text.trim(), None)
            .with_context(|| {
                format!(
                    "invalid indexed endpoint observation {} in {}",
                    entry.observation_id,
                    path.display()
                )
            })?
            .ok_or_else(|| {
                anyhow!(
                    "empty indexed endpoint observation {} in {}",
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
            let _ = read_endpoint_flight_recorder_log_chain_state(path)?;
            if validate_endpoint_observation_index_entries(path, &entries).is_ok() {
                return Ok((index_path, entries));
            }
        }
    }

    let entries = rebuild_endpoint_observation_index(path)?;
    replace_endpoint_observation_index(path, &entries)?;
    Ok((index_path, entries))
}

fn validate_endpoint_observation_index_entries(
    path: &Path,
    entries: &[EndpointFlightRecorderHistoryIndexEntry],
) -> Result<()> {
    read_endpoint_observations_at_index_entries(path, entries.to_vec()).map(|_| ())
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
    let (mut chain_state, compaction_manifest) =
        endpoint_flight_recorder_compaction_initial_state(path)?;
    let expected_retained_observation_count = compaction_manifest
        .as_ref()
        .map(|manifest| manifest.retained_observation_ids.len())
        .unwrap_or_default();
    let mut observed_retained_observation_ids =
        Vec::with_capacity(expected_retained_observation_count);
    let mut observed_compaction_tail =
        observed_compaction_tail_head(compaction_manifest.as_ref(), &chain_state);

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
            let observation = parse_endpoint_flight_recorder_log_line(
                path,
                line_number,
                trimmed,
                Some(&mut chain_state),
            )?
            .ok_or_else(|| {
                anyhow!(
                    "invalid empty endpoint observation JSONL at {}:{}",
                    path.display(),
                    line_number
                )
            })?;
            if observed_retained_observation_ids.len() < expected_retained_observation_count {
                observed_retained_observation_ids.push(observation.observation_id.clone());
            }
            observed_compaction_tail = observed_compaction_tail.or_else(|| {
                observed_compaction_tail_head(compaction_manifest.as_ref(), &chain_state)
            });
            entries.push(endpoint_observation_index_entry(
                &observation,
                byte_offset,
                byte_len as u64,
            ));
        }
        byte_offset = byte_offset.saturating_add(byte_len as u64);
    }

    validate_endpoint_flight_recorder_compaction_tail(
        path,
        compaction_manifest.as_ref(),
        &chain_state,
        observed_compaction_tail.as_ref(),
        compaction_manifest
            .as_ref()
            .map(|_| observed_retained_observation_ids.as_slice()),
    )?;

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

pub(crate) fn read_endpoint_observation_index(
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
    let mut options = endpoint_private_open_options();
    let mut file = options
        .create(true)
        .append(true)
        .open(&index_path)
        .with_context(|| {
            format!(
                "open endpoint flight recorder index {}",
                index_path.display()
            )
        })?;
    enforce_endpoint_private_file_mode(&index_path, "endpoint flight recorder index")?;
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

pub(crate) fn replace_endpoint_observation_index(
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
        let mut options = endpoint_private_open_options();
        let mut file = options
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
        enforce_endpoint_private_file_mode(&tmp_path, "temporary endpoint flight recorder index")?;
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
    enforce_endpoint_private_file_mode(&index_path, "endpoint flight recorder index")?;
    Ok(())
}

pub(crate) fn endpoint_flight_recorder_index_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "flight-recorder.jsonl".to_string());
    path.with_file_name(format!("{file_name}.index.jsonl"))
}

fn endpoint_flight_recorder_compaction_manifest_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "flight-recorder.jsonl".to_string());
    path.with_file_name(format!("{file_name}.compaction.jsonl"))
}

fn append_endpoint_flight_recorder_compaction_manifest(
    path: &Path,
    manifest: &EndpointFlightRecorderCompactionManifest,
) -> Result<()> {
    let manifest_path = endpoint_flight_recorder_compaction_manifest_path(path);
    if let Some(parent) = manifest_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "create endpoint flight recorder compaction manifest directory {}",
                    parent.display()
                )
            })?;
        }
    }
    {
        let mut options = endpoint_private_open_options();
        let mut file = options
            .create(true)
            .append(true)
            .open(&manifest_path)
            .with_context(|| {
                format!(
                    "open endpoint flight recorder compaction manifest {}",
                    manifest_path.display()
                )
            })?;
        enforce_endpoint_private_file_mode(
            &manifest_path,
            "endpoint flight recorder compaction manifest",
        )?;
        serde_json::to_writer(&mut file, manifest).with_context(|| {
            format!(
                "serialize endpoint flight recorder compaction manifest {}",
                manifest_path.display()
            )
        })?;
        file.write_all(b"\n").with_context(|| {
            format!(
                "write endpoint flight recorder compaction manifest {}",
                manifest_path.display()
            )
        })?;
        file.flush().with_context(|| {
            format!(
                "flush endpoint flight recorder compaction manifest {}",
                manifest_path.display()
            )
        })?;
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EndpointFlightRecorderCompactionBoundaryHashBody<'a> {
    schema_version: u8,
    compacted_at: &'a DateTime<Utc>,
    reason: &'a str,
    pre_compaction_head: &'a Option<String>,
    pre_compaction_record_count: u64,
    retained_observation_ids: &'a [String],
    removed_records: &'a [EndpointFlightRecorderCompactionRecord],
}

fn endpoint_flight_recorder_compaction_boundary_hash(
    manifest: &EndpointFlightRecorderCompactionManifest,
) -> Result<String> {
    let body = EndpointFlightRecorderCompactionBoundaryHashBody {
        schema_version: manifest.schema_version,
        compacted_at: &manifest.compacted_at,
        reason: manifest.reason.as_str(),
        pre_compaction_head: &manifest.pre_compaction_head,
        pre_compaction_record_count: manifest.pre_compaction_record_count,
        retained_observation_ids: manifest.retained_observation_ids.as_slice(),
        removed_records: manifest.removed_records.as_slice(),
    };
    let bytes = serde_json::to_vec(&body)
        .context("serialize endpoint flight recorder compaction boundary hash payload")?;
    Ok(sha256(&bytes).to_hex_prefixed())
}

fn seal_endpoint_flight_recorder_compaction_manifest(
    mut manifest: EndpointFlightRecorderCompactionManifest,
) -> Result<EndpointFlightRecorderCompactionManifest> {
    manifest.manifest_hash = None;
    manifest.manifest_hash = Some(endpoint_flight_recorder_compaction_manifest_hash(
        &manifest,
    )?);
    Ok(manifest)
}

fn endpoint_flight_recorder_compaction_manifest_hash(
    manifest: &EndpointFlightRecorderCompactionManifest,
) -> Result<String> {
    let mut payload = manifest.clone();
    payload.manifest_hash = None;
    let bytes = serde_json::to_vec(&payload)
        .context("serialize endpoint flight recorder compaction manifest hash payload")?;
    Ok(sha256(&bytes).to_hex_prefixed())
}

fn validate_endpoint_flight_recorder_compaction_manifest_hash(
    path: &Path,
    manifest: &EndpointFlightRecorderCompactionManifest,
) -> Result<()> {
    let expected = manifest.manifest_hash.as_deref().ok_or_else(|| {
        anyhow!(
            "endpoint flight recorder compaction manifest for {} is missing manifest hash",
            path.display()
        )
    })?;
    let actual = endpoint_flight_recorder_compaction_manifest_hash(manifest)?;
    if expected != actual {
        return Err(anyhow!(
            "endpoint flight recorder compaction manifest for {} manifest hash mismatch",
            path.display()
        ));
    }
    Ok(())
}

fn validate_endpoint_flight_recorder_compaction_boundary_hash(
    path: &Path,
    manifest: &EndpointFlightRecorderCompactionManifest,
) -> Result<String> {
    let expected = manifest
        .compaction_boundary_hash
        .as_deref()
        .ok_or_else(|| {
            anyhow!(
                "endpoint flight recorder compaction manifest for {} is missing compaction boundary hash",
                path.display()
            )
        })?;
    let actual = endpoint_flight_recorder_compaction_boundary_hash(manifest)?;
    if expected != actual {
        return Err(anyhow!(
            "endpoint flight recorder compaction manifest for {} compaction boundary hash mismatch",
            path.display()
        ));
    }
    Ok(expected.to_string())
}

fn read_endpoint_flight_recorder_compaction_manifests(
    path: &Path,
) -> Result<Vec<EndpointFlightRecorderCompactionManifest>> {
    let manifest_path = endpoint_flight_recorder_compaction_manifest_path(path);
    let contents = match fs::read_to_string(&manifest_path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "read endpoint flight recorder compaction manifest {}",
                    manifest_path.display()
                )
            })
        }
    };
    let mut manifests = Vec::new();
    for (idx, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let manifest: EndpointFlightRecorderCompactionManifest = serde_json::from_str(trimmed)
            .with_context(|| {
                format!(
                    "invalid endpoint flight recorder compaction manifest JSONL at {}:{}",
                    manifest_path.display(),
                    idx + 1
                )
            })?;
        manifests.push(manifest);
    }
    Ok(manifests)
}

fn endpoint_flight_recorder_compaction_initial_state(
    path: &Path,
) -> Result<(
    EndpointFlightRecorderLogChainState,
    Option<EndpointFlightRecorderCompactionManifest>,
)> {
    let manifests = read_endpoint_flight_recorder_compaction_manifests(path)?;
    let Some(manifest) = manifests.last().cloned() else {
        return Ok((EndpointFlightRecorderLogChainState::default(), None));
    };
    if manifest.schema_version != ENDPOINT_FLIGHT_RECORDER_COMPACTION_MANIFEST_SCHEMA_VERSION {
        return Err(anyhow!(
            "endpoint flight recorder compaction manifest schema mismatch for {}: expected {}, found {}",
            path.display(),
            ENDPOINT_FLIGHT_RECORDER_COMPACTION_MANIFEST_SCHEMA_VERSION,
            manifest.schema_version
        ));
    }
    validate_endpoint_flight_recorder_compaction_manifest_hash(path, &manifest)?;
    let compaction_boundary_hash =
        validate_endpoint_flight_recorder_compaction_boundary_hash(path, &manifest)?;
    let retained_count = manifest
        .post_compaction_record_count
        .checked_sub(manifest.pre_compaction_record_count)
        .ok_or_else(|| {
            anyhow!(
                "endpoint flight recorder compaction manifest for {} has post-compaction count before pre-compaction count",
                path.display()
            )
        })?;
    if retained_count as usize != manifest.retained_observation_ids.len() {
        return Err(anyhow!(
            "endpoint flight recorder compaction manifest for {} retained observation count does not match post/pre count delta",
            path.display()
        ));
    }
    Ok((
        EndpointFlightRecorderLogChainState {
            next_sequence: manifest.pre_compaction_record_count.saturating_add(1),
            previous_record_hash: Some(compaction_boundary_hash),
        },
        Some(manifest),
    ))
}

fn validate_endpoint_flight_recorder_compaction_tail(
    path: &Path,
    manifest: Option<&EndpointFlightRecorderCompactionManifest>,
    chain_state: &EndpointFlightRecorderLogChainState,
    observed_compaction_tail: Option<&Option<String>>,
    observed_retained_observation_ids: Option<&[String]>,
) -> Result<()> {
    let Some(manifest) = manifest else {
        return Ok(());
    };
    let Some(observed_compaction_tail) = observed_compaction_tail else {
        return Err(anyhow!(
            "endpoint flight recorder compaction manifest for {} post-compaction record count mismatch: expected at least {}, found {}",
            path.display(),
            manifest.post_compaction_record_count,
            chain_state.record_count()
        ));
    };
    if observed_compaction_tail != &manifest.post_compaction_head {
        return Err(anyhow!(
            "endpoint flight recorder compaction manifest for {} post-compaction head mismatch",
            path.display()
        ));
    }
    let Some(observed_retained_observation_ids) = observed_retained_observation_ids else {
        return Err(anyhow!(
            "endpoint flight recorder compaction manifest for {} retained observation identities were not validated",
            path.display()
        ));
    };
    if observed_retained_observation_ids != manifest.retained_observation_ids.as_slice() {
        return Err(anyhow!(
            "endpoint flight recorder compaction manifest for {} retained observation identity mismatch",
            path.display()
        ));
    }
    Ok(())
}

fn observed_compaction_tail_head(
    manifest: Option<&EndpointFlightRecorderCompactionManifest>,
    chain_state: &EndpointFlightRecorderLogChainState,
) -> Option<Option<String>> {
    manifest
        .filter(|manifest| chain_state.record_count() == manifest.post_compaction_record_count)
        .map(|_| chain_state.previous_record_hash.clone())
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

pub(crate) fn endpoint_graph_node_index_entries(
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

pub(crate) fn read_endpoint_graph_node_index(
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
        let mut options = endpoint_private_open_options();
        let mut file = options
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
        enforce_endpoint_private_file_mode(
            &tmp_path,
            "temporary endpoint flight recorder graph index",
        )?;
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
    enforce_endpoint_private_file_mode(&index_path, "endpoint flight recorder graph index")?;
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

pub(crate) fn endpoint_graph_edge_index_entries(
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

pub(crate) fn read_endpoint_graph_edge_index(
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
        let mut options = endpoint_private_open_options();
        let mut file = options
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
        enforce_endpoint_private_file_mode(
            &tmp_path,
            "temporary endpoint flight recorder graph edge index",
        )?;
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
    enforce_endpoint_private_file_mode(&index_path, "endpoint flight recorder graph edge index")?;
    Ok(entries)
}

fn endpoint_flight_recorder_graph_edge_index_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "flight-recorder.jsonl".to_string());
    path.with_file_name(format!("{file_name}.graph-edge-index.jsonl"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edr::{EndpointEvent, EndpointProcess};

    fn unique_test_path(name: &str) -> Result<PathBuf> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock before unix epoch")?
            .as_nanos();
        Ok(std::env::temp_dir().join(format!("clawdstrike-flight-recorder-{name}-{nonce}.jsonl")))
    }

    fn test_observation() -> Result<EndpointObservation> {
        test_observation_with_id("obs-private-mode", "2026-05-20T12:00:00Z")
    }

    fn test_observation_with_id(
        observation_id: &str,
        timestamp: &str,
    ) -> Result<EndpointObservation> {
        Ok(EndpointObservation {
            observation_id: observation_id.to_string(),
            timestamp: DateTime::parse_from_rfc3339(timestamp)
                .context("parse test timestamp")?
                .with_timezone(&Utc),
            host_id: Some("host-1".to_string()),
            user_id: Some("user-1".to_string()),
            session_id: Some("session-1".to_string()),
            process: EndpointProcess {
                pid: Some(42),
                image: Some("/bin/zsh".to_string()),
                command_line: Some("/bin/zsh -lc echo ok".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::ProcessExec {
                image: "/bin/zsh".to_string(),
                args: vec!["-lc".to_string(), "echo ok".to_string()],
                env: BTreeMap::new(),
            },
            metadata: BTreeMap::new(),
        })
    }

    fn open_recorder_error(path: &Path) -> Result<anyhow::Error> {
        match EndpointFlightRecorder::open(path) {
            Ok(_) => Err(anyhow!(
                "expected opening endpoint flight recorder {} to fail",
                path.display()
            )),
            Err(err) => Ok(err),
        }
    }

    #[cfg(unix)]
    fn assert_private_mode(path: &Path) -> Result<()> {
        let mode = fs::metadata(path)
            .with_context(|| format!("metadata for {}", path.display()))?
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "unexpected mode for {}", path.display());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn append_creates_private_log_and_sidecar_indexes() -> Result<()> {
        let path = unique_test_path("append")?;
        let mut recorder = EndpointFlightRecorder::open(&path)?;
        recorder.append_observations(&[test_observation()?])?;
        let (node_index_path, _) = recorder.read_graph_node_index()?;
        let (edge_index_path, _) = recorder.read_graph_edge_index()?;
        let history_index_path = endpoint_flight_recorder_index_path(&path);

        assert_private_mode(&path)?;
        assert_private_mode(&history_index_path)?;
        assert_private_mode(&node_index_path)?;
        assert_private_mode(&edge_index_path)?;

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(history_index_path);
        let _ = fs::remove_file(node_index_path);
        let _ = fs::remove_file(edge_index_path);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn compaction_rewrite_preserves_private_log_and_sidecar_modes() -> Result<()> {
        let path = unique_test_path("compact")?;
        let mut recorder = EndpointFlightRecorder::open(&path)?;
        recorder.append_observations(&[
            test_observation_with_id("obs-private-mode-1", "2026-05-20T12:00:00Z")?,
            test_observation_with_id("obs-private-mode-2", "2026-05-20T12:01:00Z")?,
        ])?;

        let report = recorder.compact(
            Some(1),
            0,
            &BTreeSet::new(),
            false,
            DateTime::parse_from_rfc3339("2026-05-20T12:02:00Z")
                .context("parse compaction time")?
                .with_timezone(&Utc),
        )?;
        assert_eq!(report.retained_count, 1);
        let Some(manifest) = report.continuity_manifest.as_ref() else {
            return Err(anyhow!("missing compaction continuity manifest"));
        };
        assert_eq!(manifest.pre_compaction_record_count, 2);
        assert_eq!(manifest.post_compaction_record_count, 3);
        assert!(manifest.pre_compaction_head.is_some());
        assert!(manifest.post_compaction_head.is_some());
        assert_eq!(manifest.removed_records.len(), 1);
        assert_eq!(
            manifest.retained_observation_ids,
            vec!["obs-private-mode-2".to_string()]
        );
        let persisted_manifests = read_endpoint_flight_recorder_compaction_manifests(&path)?;
        assert_eq!(persisted_manifests, vec![manifest.clone()]);

        let (node_index_path, _) = recorder.read_graph_node_index()?;
        let (edge_index_path, _) = recorder.read_graph_edge_index()?;
        let history_index_path = endpoint_flight_recorder_index_path(&path);
        let manifest_path = endpoint_flight_recorder_compaction_manifest_path(&path);

        assert_private_mode(&path)?;
        assert_private_mode(&history_index_path)?;
        assert_private_mode(&node_index_path)?;
        assert_private_mode(&edge_index_path)?;
        assert_private_mode(&manifest_path)?;

        recorder.append_observations(&[test_observation_with_id(
            "obs-private-mode-3",
            "2026-05-20T12:03:00Z",
        )?])?;
        let reopened = EndpointFlightRecorder::open(&path)?;
        assert_eq!(reopened.observation_count(), 2);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(history_index_path);
        let _ = fs::remove_file(node_index_path);
        let _ = fs::remove_file(edge_index_path);
        let _ = fs::remove_file(manifest_path);
        Ok(())
    }

    #[test]
    fn compacted_log_requires_persisted_continuity_manifest() -> Result<()> {
        let path = unique_test_path("compact-manifest-required")?;
        let mut recorder = EndpointFlightRecorder::open(&path)?;
        recorder.append_observations(&[
            test_observation_with_id("obs-manifest-required-1", "2026-05-20T12:00:00Z")?,
            test_observation_with_id("obs-manifest-required-2", "2026-05-20T12:01:00Z")?,
        ])?;

        let _ = recorder.compact(
            Some(1),
            0,
            &BTreeSet::new(),
            false,
            DateTime::parse_from_rfc3339("2026-05-20T12:02:00Z")
                .context("parse compaction time")?
                .with_timezone(&Utc),
        )?;
        let manifest_path = endpoint_flight_recorder_compaction_manifest_path(&path);
        fs::remove_file(&manifest_path).context("remove compaction manifest")?;

        let err = open_recorder_error(&path)?;
        let message = err.to_string();
        assert!(
            message.contains("sequence mismatch") || message.contains("previous hash mismatch"),
            "unexpected reopen error: {message}"
        );

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(endpoint_flight_recorder_index_path(&path));
        let _ = fs::remove_file(endpoint_flight_recorder_graph_index_path(&path));
        let _ = fs::remove_file(endpoint_flight_recorder_graph_edge_index_path(&path));
        Ok(())
    }

    #[test]
    fn compacted_log_rejects_tampered_continuity_manifest() -> Result<()> {
        let path = unique_test_path("compact-manifest-tamper")?;
        let mut recorder = EndpointFlightRecorder::open(&path)?;
        recorder.append_observations(&[
            test_observation_with_id("obs-manifest-tamper-1", "2026-05-20T12:00:00Z")?,
            test_observation_with_id("obs-manifest-tamper-2", "2026-05-20T12:01:00Z")?,
        ])?;

        let _ = recorder.compact(
            Some(1),
            0,
            &BTreeSet::new(),
            false,
            DateTime::parse_from_rfc3339("2026-05-20T12:02:00Z")
                .context("parse compaction time")?
                .with_timezone(&Utc),
        )?;
        let manifest_path = endpoint_flight_recorder_compaction_manifest_path(&path);
        let mut manifest: EndpointFlightRecorderCompactionManifest = serde_json::from_str(
            fs::read_to_string(&manifest_path)?
                .lines()
                .next()
                .unwrap_or_default(),
        )
        .context("parse persisted compaction manifest")?;
        manifest.pre_compaction_record_count = 0;
        manifest.compaction_boundary_hash = Some(
            endpoint_flight_recorder_compaction_boundary_hash(&manifest)?,
        );
        manifest.manifest_hash = Some(endpoint_flight_recorder_compaction_manifest_hash(
            &manifest,
        )?);
        fs::write(
            &manifest_path,
            format!("{}\n", serde_json::to_string(&manifest)?),
        )
        .context("write tampered compaction manifest")?;

        let err = open_recorder_error(&path)?;
        assert!(
            err.to_string().contains("retained observation count"),
            "unexpected reopen error: {err}"
        );

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(endpoint_flight_recorder_index_path(&path));
        let _ = fs::remove_file(endpoint_flight_recorder_graph_index_path(&path));
        let _ = fs::remove_file(endpoint_flight_recorder_graph_edge_index_path(&path));
        let _ = fs::remove_file(manifest_path);
        Ok(())
    }

    #[test]
    fn compacted_log_rebuilds_missing_history_sidecar_after_compaction() -> Result<()> {
        let path = unique_test_path("compact-rebuild-missing-index")?;
        let mut recorder = EndpointFlightRecorder::open(&path)?;
        recorder.append_observations(&[
            test_observation_with_id("obs-compact-rebuild-1", "2026-05-20T12:00:00Z")?,
            test_observation_with_id("obs-compact-rebuild-2", "2026-05-20T12:01:00Z")?,
        ])?;

        let _ = recorder.compact(
            Some(1),
            0,
            &BTreeSet::new(),
            false,
            DateTime::parse_from_rfc3339("2026-05-20T12:02:00Z")
                .context("parse compaction time")?
                .with_timezone(&Utc),
        )?;
        let history_index_path = endpoint_flight_recorder_index_path(&path);
        fs::remove_file(&history_index_path).context("remove history sidecar")?;

        let window = recorder.read_indexed_observation_window(10, |_| true)?;
        assert_eq!(window.selection_mode, "sidecar_index_seek");
        assert_eq!(window.selected_observations.len(), 1);
        assert_eq!(
            window.selected_observations[0].observation_id,
            "obs-compact-rebuild-2"
        );
        assert!(
            history_index_path.exists(),
            "expected missing sidecar to be rebuilt"
        );

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(history_index_path);
        let _ = fs::remove_file(endpoint_flight_recorder_graph_index_path(&path));
        let _ = fs::remove_file(endpoint_flight_recorder_graph_edge_index_path(&path));
        let _ = fs::remove_file(endpoint_flight_recorder_compaction_manifest_path(&path));
        Ok(())
    }

    #[test]
    fn compacted_log_rejects_tampered_retained_or_removed_manifest_identity() -> Result<()> {
        let removed_tamper_path = unique_test_path("compact-manifest-removed-id-tamper")?;
        let mut removed_tamper_recorder = EndpointFlightRecorder::open(&removed_tamper_path)?;
        removed_tamper_recorder.append_observations(&[
            test_observation_with_id("obs-removed-id-tamper-1", "2026-05-20T12:00:00Z")?,
            test_observation_with_id("obs-removed-id-tamper-2", "2026-05-20T12:01:00Z")?,
        ])?;
        let _ = removed_tamper_recorder.compact(
            Some(1),
            0,
            &BTreeSet::new(),
            false,
            DateTime::parse_from_rfc3339("2026-05-20T12:02:00Z")
                .context("parse compaction time")?
                .with_timezone(&Utc),
        )?;
        let removed_manifest_path =
            endpoint_flight_recorder_compaction_manifest_path(&removed_tamper_path);
        let mut removed_manifest: EndpointFlightRecorderCompactionManifest = serde_json::from_str(
            fs::read_to_string(&removed_manifest_path)?
                .lines()
                .next()
                .unwrap_or_default(),
        )
        .context("parse removed tamper manifest")?;
        removed_manifest.removed_records[0].observation_id = "obs-forged-removed-id".to_string();
        removed_manifest.manifest_hash = Some(endpoint_flight_recorder_compaction_manifest_hash(
            &removed_manifest,
        )?);
        fs::write(
            &removed_manifest_path,
            format!("{}\n", serde_json::to_string(&removed_manifest)?),
        )
        .context("write removed identity tamper manifest")?;

        let removed_err = open_recorder_error(&removed_tamper_path)?;
        assert!(
            removed_err
                .to_string()
                .contains("compaction boundary hash mismatch"),
            "unexpected removed identity tamper error: {removed_err}"
        );
        removed_manifest.compaction_boundary_hash = Some(
            endpoint_flight_recorder_compaction_boundary_hash(&removed_manifest)?,
        );
        removed_manifest.manifest_hash = Some(endpoint_flight_recorder_compaction_manifest_hash(
            &removed_manifest,
        )?);
        fs::write(
            &removed_manifest_path,
            format!("{}\n", serde_json::to_string(&removed_manifest)?),
        )
        .context("write re-sealed removed identity tamper manifest")?;
        let resealed_removed_err = open_recorder_error(&removed_tamper_path)?;
        assert!(
            resealed_removed_err
                .to_string()
                .contains("previous hash mismatch"),
            "unexpected re-sealed removed identity tamper error: {resealed_removed_err}"
        );

        let retained_tamper_path = unique_test_path("compact-manifest-retained-id-tamper")?;
        let mut retained_tamper_recorder = EndpointFlightRecorder::open(&retained_tamper_path)?;
        retained_tamper_recorder.append_observations(&[
            test_observation_with_id("obs-retained-id-tamper-1", "2026-05-20T12:00:00Z")?,
            test_observation_with_id("obs-retained-id-tamper-2", "2026-05-20T12:01:00Z")?,
        ])?;
        let _ = retained_tamper_recorder.compact(
            Some(1),
            0,
            &BTreeSet::new(),
            false,
            DateTime::parse_from_rfc3339("2026-05-20T12:02:00Z")
                .context("parse compaction time")?
                .with_timezone(&Utc),
        )?;
        let retained_manifest_path =
            endpoint_flight_recorder_compaction_manifest_path(&retained_tamper_path);
        let mut retained_manifest: EndpointFlightRecorderCompactionManifest = serde_json::from_str(
            fs::read_to_string(&retained_manifest_path)?
                .lines()
                .next()
                .unwrap_or_default(),
        )
        .context("parse retained tamper manifest")?;
        retained_manifest.retained_observation_ids[0] = "obs-forged-retained-id".to_string();
        retained_manifest.manifest_hash = Some(endpoint_flight_recorder_compaction_manifest_hash(
            &retained_manifest,
        )?);
        fs::write(
            &retained_manifest_path,
            format!("{}\n", serde_json::to_string(&retained_manifest)?),
        )
        .context("write retained identity tamper manifest")?;

        let retained_err = open_recorder_error(&retained_tamper_path)?;
        assert!(
            retained_err
                .to_string()
                .contains("compaction boundary hash mismatch"),
            "unexpected retained identity tamper error: {retained_err}"
        );

        let _ = fs::remove_file(&removed_tamper_path);
        let _ = fs::remove_file(endpoint_flight_recorder_index_path(&removed_tamper_path));
        let _ = fs::remove_file(endpoint_flight_recorder_graph_index_path(
            &removed_tamper_path,
        ));
        let _ = fs::remove_file(endpoint_flight_recorder_graph_edge_index_path(
            &removed_tamper_path,
        ));
        let _ = fs::remove_file(removed_manifest_path);
        let _ = fs::remove_file(&retained_tamper_path);
        let _ = fs::remove_file(endpoint_flight_recorder_index_path(&retained_tamper_path));
        let _ = fs::remove_file(endpoint_flight_recorder_graph_index_path(
            &retained_tamper_path,
        ));
        let _ = fs::remove_file(endpoint_flight_recorder_graph_edge_index_path(
            &retained_tamper_path,
        ));
        let _ = fs::remove_file(retained_manifest_path);
        Ok(())
    }

    #[test]
    fn indexed_window_rebuilds_sidecar_when_metadata_no_longer_matches_log() -> Result<()> {
        let path = unique_test_path("stale-index")?;
        let mut recorder = EndpointFlightRecorder::open(&path)?;
        recorder.append_observations(&[test_observation_with_id(
            "obs-stale-index",
            "2026-05-20T12:00:00Z",
        )?])?;

        let mut entries =
            read_endpoint_observation_index(&endpoint_flight_recorder_index_path(&path))?;
        assert_eq!(entries.len(), 1);
        entries[0].event_kind = "file_access".to_string();
        replace_endpoint_observation_index(&path, &entries)?;

        let window = recorder
            .read_indexed_observation_window(10, |entry| entry.event_kind == "process_exec")?;
        assert_eq!(window.matched_observation_count, 1);
        assert_eq!(window.selected_observations.len(), 1);
        assert_eq!(
            window.selected_observations[0].observation_id,
            "obs-stale-index"
        );

        let repaired_entries =
            read_endpoint_observation_index(&endpoint_flight_recorder_index_path(&path))?;
        assert_eq!(repaired_entries[0].event_kind, "process_exec");

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(endpoint_flight_recorder_index_path(&path));
        let _ = fs::remove_file(endpoint_flight_recorder_graph_index_path(&path));
        let _ = fs::remove_file(endpoint_flight_recorder_graph_edge_index_path(&path));
        Ok(())
    }

    #[test]
    fn production_open_rejects_legacy_raw_observation_logs() -> Result<()> {
        let path = unique_test_path("legacy-raw")?;
        let raw_observation = serde_json::to_string(&test_observation()?)
            .context("serialize raw legacy observation")?;
        fs::write(&path, format!("{raw_observation}\n"))
            .with_context(|| format!("write raw legacy log {}", path.display()))?;

        let err = open_recorder_error(&path)?;
        assert!(
            err.to_string()
                .contains("legacy endpoint observation JSONL")
                && err.to_string().contains("not accepted"),
            "expected legacy raw rejection, got {err}"
        );

        let _ = fs::remove_file(&path);
        Ok(())
    }
}
