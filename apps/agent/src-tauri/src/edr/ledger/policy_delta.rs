//! Policy-delta store.
//!
//! Persists `EdrPolicyDeltaRecord`s as individual JSON artifacts (one per
//! delta) plus a JSONL index for efficient enumeration. Supports querying by
//! stage, rule_id, and direct lookup by policy_delta_id.

use std::collections::VecDeque;
use std::fs;
use std::io::Write as _;
use std::path::{Path as FsPath, PathBuf};

use anyhow::{Context, Result};

use crate::api_server::{EdrPolicyDeltaApplyRecord, EdrPolicyDeltaRecord, EDR_MAX_STORED_FINDINGS};

use super::{open_private_append, open_private_truncate};

pub(crate) struct EndpointPolicyDeltaStore {
    root: Option<PathBuf>,
    records: VecDeque<EdrPolicyDeltaRecord>,
}

impl EndpointPolicyDeltaStore {
    pub(crate) fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        let records = read_policy_delta_index(&policy_delta_index_path(&root))?;
        Ok(Self {
            root: Some(root),
            records: records.into(),
        })
    }

    #[cfg(test)]
    pub(crate) fn transient() -> Self {
        Self {
            root: None,
            records: VecDeque::new(),
        }
    }

    pub(crate) fn path(&self) -> Option<&FsPath> {
        self.root.as_deref()
    }

    pub(crate) fn append(&mut self, record: &mut EdrPolicyDeltaRecord) -> Result<()> {
        if let Some(root) = &self.root {
            fs::create_dir_all(root).with_context(|| {
                format!("create endpoint policy delta directory {}", root.display())
            })?;
            let artifact_path = root.join(policy_delta_filename(&record.policy_delta_id)?);
            serde_json::to_writer_pretty(
                open_private_truncate(&artifact_path, "endpoint policy delta")?,
                &record.artifact,
            )
            .with_context(|| {
                format!(
                    "serialize endpoint policy delta artifact {}",
                    record.policy_delta_id
                )
            })?;
            record.artifact_path = Some(artifact_path.display().to_string());
        }

        self.records.push_back(record.clone());
        while self.records.len() > EDR_MAX_STORED_FINDINGS {
            let _ = self.records.pop_front();
        }

        let Some(root) = &self.root else {
            return Ok(());
        };
        let index_path = policy_delta_index_path(root);
        let mut file = open_private_append(&index_path, "endpoint policy delta index")?;
        serde_json::to_writer(&mut file, record).with_context(|| {
            format!(
                "serialize endpoint policy delta record {}",
                record.policy_delta_id
            )
        })?;
        file.write_all(b"\n").with_context(|| {
            format!("write endpoint policy delta index {}", index_path.display())
        })?;
        file.flush().with_context(|| {
            format!("flush endpoint policy delta index {}", index_path.display())
        })?;
        Ok(())
    }

    pub(crate) fn read_recent(
        &self,
        limit: usize,
        stage: Option<&str>,
        rule_id: Option<&str>,
    ) -> Result<Vec<EdrPolicyDeltaRecord>> {
        let records = self.all()?;
        Ok(records
            .into_iter()
            .rev()
            .filter(|record| {
                stage.map_or(true, |stage| record.stage == stage)
                    && rule_id.map_or(true, |rule_id| record.rule_id == rule_id)
            })
            .take(limit)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect())
    }

    pub(crate) fn read_by_id(&self, policy_delta_id: &str) -> Result<Option<EdrPolicyDeltaRecord>> {
        Ok(self
            .all()?
            .into_iter()
            .rev()
            .find(|record| record.policy_delta_id == policy_delta_id))
    }

    pub(crate) fn append_apply(&mut self, record: &EdrPolicyDeltaApplyRecord) -> Result<()> {
        let Some(root) = &self.root else {
            return Ok(());
        };
        fs::create_dir_all(root).with_context(|| {
            format!("create endpoint policy delta directory {}", root.display())
        })?;
        let apply_path = policy_delta_apply_index_path(root);
        let mut file = open_private_append(&apply_path, "endpoint policy delta apply index")?;
        serde_json::to_writer(&mut file, record).with_context(|| {
            format!(
                "serialize endpoint policy delta apply record {}",
                record.policy_delta_id
            )
        })?;
        file.write_all(b"\n").with_context(|| {
            format!(
                "write endpoint policy delta apply index {}",
                apply_path.display()
            )
        })?;
        file.flush().with_context(|| {
            format!(
                "flush endpoint policy delta apply index {}",
                apply_path.display()
            )
        })?;
        Ok(())
    }

    pub(crate) fn all(&self) -> Result<Vec<EdrPolicyDeltaRecord>> {
        if let Some(root) = &self.root {
            return read_policy_delta_index(&policy_delta_index_path(root));
        }
        Ok(self.records.iter().cloned().collect())
    }
}

pub(crate) fn policy_delta_index_path(root: &FsPath) -> PathBuf {
    root.join("policy-deltas.jsonl")
}

pub(crate) fn policy_delta_apply_index_path(root: &FsPath) -> PathBuf {
    root.join("policy-delta-applies.jsonl")
}

pub(crate) fn policy_delta_filename(policy_delta_id: &str) -> Result<String> {
    let policy_delta_id = policy_delta_id.trim();
    if policy_delta_id.is_empty() {
        return Err(anyhow::anyhow!("policy delta id must not be empty"));
    }
    if !policy_delta_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_'))
    {
        return Err(anyhow::anyhow!(
            "policy delta id contains invalid characters"
        ));
    }
    Ok(format!("{}.json", policy_delta_id.replace(':', "_")))
}

pub(crate) fn read_policy_delta_index(path: &FsPath) -> Result<Vec<EdrPolicyDeltaRecord>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("read endpoint policy delta index {}", path.display()));
        }
    };

    let mut records = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record: EdrPolicyDeltaRecord = serde_json::from_str(line).with_context(|| {
            format!(
                "parse endpoint policy delta index line {} from {}",
                index + 1,
                path.display()
            )
        })?;
        records.push(record);
    }
    Ok(records)
}
