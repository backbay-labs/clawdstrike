//! Staged-detection ledger.
//!
//! Persists `EdrStagedDetectionRecord`s in audit / limited_block / enforce
//! stages so policy promotion (`/api/v1/agent/edr/policy-deltas/{id}/apply`)
//! can replay the staged history under a proposed constitution.

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path as FsPath, PathBuf};

use anyhow::{Context, Result};

use crate::api_server::{EdrStagedDetectionRecord, EDR_MAX_STORED_FINDINGS};

pub(crate) struct EndpointStagedDetectionLedger {
    path: Option<PathBuf>,
    records: VecDeque<EdrStagedDetectionRecord>,
}

impl EndpointStagedDetectionLedger {
    pub(crate) fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let records = read_staged_detection_ledger(&path)?;
        Ok(Self {
            path: Some(path),
            records: records.into(),
        })
    }

    pub(crate) fn transient() -> Self {
        Self {
            path: None,
            records: VecDeque::new(),
        }
    }

    pub(crate) fn path(&self) -> Option<&FsPath> {
        self.path.as_deref()
    }

    pub(crate) fn append(&mut self, record: &EdrStagedDetectionRecord) -> Result<()> {
        self.records.push_back(record.clone());
        while self.records.len() > EDR_MAX_STORED_FINDINGS {
            let _ = self.records.pop_front();
        }

        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "create endpoint staged detection ledger directory {}",
                    parent.display()
                )
            })?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open endpoint staged detection ledger {}", path.display()))?;
        serde_json::to_writer(&mut file, record).with_context(|| {
            format!(
                "serialize endpoint staged detection {}",
                record.staged_detection_id
            )
        })?;
        file.write_all(b"\n").with_context(|| {
            format!("write endpoint staged detection ledger {}", path.display())
        })?;
        file.flush().with_context(|| {
            format!("flush endpoint staged detection ledger {}", path.display())
        })?;
        Ok(())
    }

    pub(crate) fn read_recent(
        &self,
        limit: usize,
        stage: Option<&str>,
        rule_id: Option<&str>,
    ) -> Result<Vec<EdrStagedDetectionRecord>> {
        let records = self.all()?;
        Ok(records
            .into_iter()
            .rev()
            .filter(|record| {
                stage.map_or(true, |stage| record.stage == stage)
                    && rule_id.map_or(true, |rule_id| record.candidate.rule_id == rule_id)
            })
            .take(limit)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect())
    }

    pub(crate) fn all(&self) -> Result<Vec<EdrStagedDetectionRecord>> {
        if let Some(path) = &self.path {
            return read_staged_detection_ledger(path);
        }
        Ok(self.records.iter().cloned().collect())
    }
}

pub(crate) fn read_staged_detection_ledger(
    path: &FsPath,
) -> Result<Vec<EdrStagedDetectionRecord>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err).with_context(|| {
                format!("read endpoint staged detection ledger {}", path.display())
            });
        }
    };

    let mut records = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record: EdrStagedDetectionRecord = serde_json::from_str(line).with_context(|| {
            format!(
                "parse endpoint staged detection ledger line {} from {}",
                index + 1,
                path.display()
            )
        })?;
        records.push(record);
    }
    Ok(records)
}
