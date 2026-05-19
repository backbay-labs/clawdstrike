pub mod compaction;
pub mod index;

pub use compaction::*;
pub use index::*;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{BufRead as _, BufReader, ErrorKind, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use self::compaction::{
    EndpointFlightRecorderCompactionRecord, EndpointFlightRecorderCompactionReport,
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

pub(crate) fn endpoint_flight_recorder_index_path(path: &Path) -> PathBuf {
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
