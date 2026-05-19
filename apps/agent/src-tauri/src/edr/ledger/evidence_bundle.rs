//! Evidence bundle store.
//!
//! Persists `StoredEndpointEvidenceBundle` artifacts (one JSON file per
//! bundle, keyed by bundle_id) in a directory. Validates content hash and
//! node/edge counts on every load and list operation.

use std::collections::HashMap;
use std::fs;
use std::path::{Path as FsPath, PathBuf};

use anyhow::{Context, Result};
use clawdstrike_policy_event::edr::{CausalGraph, EndpointEvidenceBundleReference};
use hush_core::{canonicalize_json, sha256};

use crate::api_server::StoredEndpointEvidenceBundle;

pub(crate) struct EndpointEvidenceBundleStore {
    root: Option<PathBuf>,
    bundles: HashMap<String, StoredEndpointEvidenceBundle>,
}

impl EndpointEvidenceBundleStore {
    pub(crate) fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root).with_context(|| {
            format!(
                "create endpoint evidence bundle directory {}",
                root.display()
            )
        })?;
        Ok(Self {
            root: Some(root),
            bundles: HashMap::new(),
        })
    }

    pub(crate) fn transient() -> Self {
        Self {
            root: None,
            bundles: HashMap::new(),
        }
    }

    pub(crate) fn root_path(&self) -> Option<&FsPath> {
        self.root.as_deref()
    }

    pub(crate) fn store(
        &mut self,
        bundle: &EndpointEvidenceBundleReference,
        graph: &CausalGraph,
    ) -> Result<StoredEndpointEvidenceBundle> {
        let graph_value = serde_json::to_value(graph).context("serialize evidence bundle graph")?;
        let canonical_graph =
            canonicalize_json(&graph_value).context("canonicalize evidence bundle graph")?;
        let content_hash = sha256(canonical_graph.as_bytes()).to_hex_prefixed();
        if content_hash != bundle.content_hash {
            return Err(anyhow::anyhow!(
                "evidence bundle content hash mismatch: expected {}, computed {}",
                bundle.content_hash,
                content_hash
            ));
        }

        let path = self
            .root
            .as_ref()
            .map(|root| evidence_bundle_path(root, &bundle.bundle_id))
            .transpose()?;
        let stored = StoredEndpointEvidenceBundle {
            bundle: bundle.clone(),
            path: path.as_ref().map(|path| path.display().to_string()),
            byte_count: canonical_graph.len(),
            graph: graph.clone(),
        };

        if let Some(path) = &path {
            let value =
                serde_json::to_value(&stored).context("serialize evidence bundle artifact")?;
            let artifact =
                canonicalize_json(&value).context("canonicalize evidence bundle artifact")?;
            crate::security::fs::write_private_atomic(
                path,
                artifact.as_bytes(),
                "endpoint evidence bundle artifact",
            )?;
        }

        self.bundles
            .insert(bundle.bundle_id.clone(), stored.clone());
        Ok(stored)
    }

    pub(crate) fn load(
        &mut self,
        bundle_id: &str,
    ) -> Result<Option<StoredEndpointEvidenceBundle>> {
        if let Some(root) = &self.root {
            let path = evidence_bundle_path(root, bundle_id)?;
            let contents = match fs::read_to_string(&path) {
                Ok(contents) => contents,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    self.bundles.remove(bundle_id);
                    return Ok(None);
                }
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!("read endpoint evidence bundle {}", path.display())
                    });
                }
            };
            let mut stored: StoredEndpointEvidenceBundle = serde_json::from_str(&contents)
                .with_context(|| format!("parse endpoint evidence bundle {}", path.display()))?;
            if stored.bundle.bundle_id != bundle_id {
                return Err(anyhow::anyhow!(
                    "endpoint evidence bundle artifact id mismatch: requested {}, found {}",
                    bundle_id,
                    stored.bundle.bundle_id
                ));
            }
            stored.path = Some(path.display().to_string());
            validate_stored_evidence_bundle_artifact(&stored)?;
            self.bundles.insert(bundle_id.to_string(), stored.clone());
            return Ok(Some(stored));
        }

        if let Some(stored) = self.bundles.get(bundle_id) {
            return Ok(Some(stored.clone()));
        }
        Ok(None)
    }

    pub(crate) fn list(&mut self) -> Result<Vec<StoredEndpointEvidenceBundle>> {
        if let Some(root) = &self.root {
            for entry in fs::read_dir(root).with_context(|| {
                format!("read endpoint evidence bundle directory {}", root.display())
            })? {
                let entry = entry.with_context(|| {
                    format!(
                        "read endpoint evidence bundle directory entry {}",
                        root.display()
                    )
                })?;
                let path = entry.path();
                if !path.is_file()
                    || path.extension().and_then(std::ffi::OsStr::to_str) != Some("json")
                {
                    continue;
                }
                let contents = fs::read_to_string(&path)
                    .with_context(|| format!("read endpoint evidence bundle {}", path.display()))?;
                let mut stored: StoredEndpointEvidenceBundle = serde_json::from_str(&contents)
                    .with_context(|| {
                        format!("parse endpoint evidence bundle {}", path.display())
                    })?;
                validate_stored_evidence_bundle_artifact_path(&stored, &path)?;
                stored.path = Some(path.display().to_string());
                validate_stored_evidence_bundle_artifact(&stored)?;
                self.bundles.insert(stored.bundle.bundle_id.clone(), stored);
            }
        }
        let mut bundles = self.bundles.values().cloned().collect::<Vec<_>>();
        bundles.sort_by(|left, right| {
            right
                .bundle
                .created_at
                .cmp(&left.bundle.created_at)
                .then_with(|| left.bundle.bundle_id.cmp(&right.bundle.bundle_id))
        });
        Ok(bundles)
    }

    pub(crate) fn remove(
        &mut self,
        bundle_id: &str,
    ) -> Result<Option<StoredEndpointEvidenceBundle>> {
        let stored = self.load(bundle_id)?;
        if let Some(root) = &self.root {
            let path = evidence_bundle_path(root, bundle_id)?;
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!("remove endpoint evidence bundle {}", path.display())
                    });
                }
            }
        }
        self.bundles.remove(bundle_id);
        Ok(stored)
    }
}

pub(crate) fn validate_stored_evidence_bundle_artifact(
    stored: &StoredEndpointEvidenceBundle,
) -> Result<()> {
    if stored.bundle.node_count != stored.graph.nodes.len() {
        return Err(anyhow::anyhow!(
            "endpoint evidence bundle artifact node count mismatch: expected {}, computed {}",
            stored.bundle.node_count,
            stored.graph.nodes.len()
        ));
    }
    if stored.bundle.edge_count != stored.graph.edges.len() {
        return Err(anyhow::anyhow!(
            "endpoint evidence bundle artifact edge count mismatch: expected {}, computed {}",
            stored.bundle.edge_count,
            stored.graph.edges.len()
        ));
    }
    let graph_value =
        serde_json::to_value(&stored.graph).context("serialize endpoint evidence bundle graph")?;
    let canonical_graph =
        canonicalize_json(&graph_value).context("canonicalize endpoint evidence bundle graph")?;
    let content_hash = sha256(canonical_graph.as_bytes()).to_hex_prefixed();
    if content_hash != stored.bundle.content_hash {
        return Err(anyhow::anyhow!(
            "endpoint evidence bundle artifact content hash mismatch: expected {}, computed {}",
            stored.bundle.content_hash,
            content_hash
        ));
    }
    if stored.byte_count != canonical_graph.len() {
        return Err(anyhow::anyhow!(
            "endpoint evidence bundle artifact byte count mismatch: expected {}, computed {}",
            stored.byte_count,
            canonical_graph.len()
        ));
    }
    Ok(())
}

pub(crate) fn validate_stored_evidence_bundle_artifact_path(
    stored: &StoredEndpointEvidenceBundle,
    path: &FsPath,
) -> Result<()> {
    let expected_filename = evidence_bundle_filename(&stored.bundle.bundle_id)?;
    let actual_filename = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_default();
    if actual_filename != expected_filename {
        return Err(anyhow::anyhow!(
            "endpoint evidence bundle artifact filename mismatch: expected {}, found {}",
            expected_filename,
            actual_filename
        ));
    }
    Ok(())
}

pub(crate) fn evidence_bundle_path(root: &FsPath, bundle_id: &str) -> Result<PathBuf> {
    let filename = evidence_bundle_filename(bundle_id)?;
    Ok(root.join(filename))
}

pub(crate) fn evidence_bundle_filename(bundle_id: &str) -> Result<String> {
    let bundle_id = bundle_id.trim();
    if bundle_id.is_empty() {
        return Err(anyhow::anyhow!("evidence bundle id must not be empty"));
    }
    if !bundle_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_'))
    {
        return Err(anyhow::anyhow!(
            "evidence bundle id contains invalid characters"
        ));
    }
    Ok(format!("{}.json", bundle_id.replace(':', "_")))
}
