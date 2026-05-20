//! Honey-artifact registry ledger.
//!
//! Persists `HoneyArtifact`s registered by the deception-plan materialisation
//! handler and cleaned up by the deception-plan cleanup handler. The registry
//! is a plain JSONL file; entries are deduped on `artifact_id`.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write as _;
use std::path::{Path as FsPath, PathBuf};

use anyhow::{Context, Result};
use clawdstrike_policy_event::edr::HoneyArtifact;

use super::open_private_truncate;

pub(crate) struct EndpointHoneyRegistry {
    path: Option<PathBuf>,
    artifacts: Vec<HoneyArtifact>,
}

impl EndpointHoneyRegistry {
    pub(crate) fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let artifacts = read_honey_registry(&path)?;
        Ok(Self {
            path: Some(path),
            artifacts,
        })
    }

    pub(crate) fn transient() -> Self {
        Self {
            path: None,
            artifacts: Vec::new(),
        }
    }

    pub(crate) fn path(&self) -> Option<&FsPath> {
        self.path.as_deref()
    }

    pub(crate) fn register(&mut self, artifacts: &[HoneyArtifact]) -> Result<usize> {
        if artifacts.is_empty() {
            return Ok(0);
        }

        let mut added = 0usize;
        for artifact in artifacts {
            if self
                .artifacts
                .iter()
                .any(|existing| existing.artifact_id == artifact.artifact_id)
            {
                continue;
            }
            self.artifacts.push(artifact.clone());
            added = added.saturating_add(1);
        }
        if added > 0 {
            self.persist()?;
        }
        Ok(added)
    }

    pub(crate) fn unregister(&mut self, artifact_ids: &BTreeSet<String>) -> Result<usize> {
        if artifact_ids.is_empty() {
            return Ok(0);
        }

        self.artifacts = self.load()?;
        let before = self.artifacts.len();
        self.artifacts
            .retain(|artifact| !artifact_ids.contains(&artifact.artifact_id));
        let removed = before.saturating_sub(self.artifacts.len());
        if removed > 0 {
            self.persist()?;
        }
        Ok(removed)
    }

    pub(crate) fn load(&self) -> Result<Vec<HoneyArtifact>> {
        if let Some(path) = &self.path {
            return read_honey_registry(path);
        }
        Ok(self.artifacts.clone())
    }

    fn persist(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "create endpoint honey registry directory {}",
                    parent.display()
                )
            })?;
        }

        let mut file = open_private_truncate(path, "endpoint honey registry")?;
        for artifact in &self.artifacts {
            serde_json::to_writer(&mut file, artifact).with_context(|| {
                format!("serialize endpoint honey artifact {}", artifact.artifact_id)
            })?;
            file.write_all(b"\n")
                .with_context(|| format!("write endpoint honey registry {}", path.display()))?;
        }
        file.flush()
            .with_context(|| format!("flush endpoint honey registry {}", path.display()))?;
        Ok(())
    }
}

pub(crate) fn read_honey_registry(path: &FsPath) -> Result<Vec<HoneyArtifact>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("read endpoint honey registry {}", path.display()));
        }
    };

    let mut artifacts = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let artifact: HoneyArtifact = serde_json::from_str(line).with_context(|| {
            format!(
                "parse endpoint honey registry line {} from {}",
                index + 1,
                path.display()
            )
        })?;
        if artifacts
            .iter()
            .any(|existing: &HoneyArtifact| existing.artifact_id == artifact.artifact_id)
        {
            continue;
        }
        artifacts.push(artifact);
    }

    Ok(artifacts)
}
