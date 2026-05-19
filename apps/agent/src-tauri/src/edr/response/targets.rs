//! Pure helpers for endpoint response target resolution and path construction.

use anyhow::Result;
use clawdstrike_policy_event::edr::{CausalGraph, CausalNodeKind, EndpointResponsePlan};
use serde_json::Value;
use std::path::{Path as FsPath, PathBuf};

#[derive(Debug, Clone)]
pub(crate) struct ProcessSignalTarget {
    pub(crate) pid: u32,
    pub(crate) label: String,
}

pub(crate) fn quarantine_file_target_path(
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
) -> Result<PathBuf> {
    let node = graph
        .nodes
        .get(&plan.root_node_id)
        .ok_or_else(|| anyhow::anyhow!("root node not found: {}", plan.root_node_id))?;
    if !matches!(
        node.kind,
        CausalNodeKind::File | CausalNodeKind::BrowserDownload
    ) {
        return Err(anyhow::anyhow!(
            "root node must be a file or browser_download node, got {:?}",
            node.kind
        ));
    }
    let path = PathBuf::from(node.label.trim());
    if !path.is_absolute() {
        return Err(anyhow::anyhow!(
            "quarantine target path must be absolute: {}",
            node.label
        ));
    }
    Ok(path)
}

pub(crate) fn suspend_process_tree_targets(
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
) -> Result<Vec<ProcessSignalTarget>> {
    let root = graph
        .nodes
        .get(&plan.root_node_id)
        .ok_or_else(|| anyhow::anyhow!("root node not found: {}", plan.root_node_id))?;
    if root.kind != CausalNodeKind::Process {
        return Err(anyhow::anyhow!(
            "root node must be a process node for process-tree response, got {:?}",
            root.kind
        ));
    }

    let root_pid = process_node_pid(root)
        .ok_or_else(|| anyhow::anyhow!("root process node is missing pid attribute"))?;
    let mut targets = vec![ProcessSignalTarget {
        pid: root_pid,
        label: root.label.clone(),
    }];
    for node in graph.nodes.values() {
        if node.node_id == root.node_id || node.kind != CausalNodeKind::Process {
            continue;
        }
        if let Some(pid) = process_node_pid(node) {
            targets.push(ProcessSignalTarget {
                pid,
                label: node.label.clone(),
            });
        }
    }
    targets.sort_by_key(|target| target.pid);
    targets.dedup_by_key(|target| target.pid);
    targets.sort_by_key(|target| {
        if target.pid == root_pid {
            (0_u8, target.pid)
        } else {
            (1_u8, target.pid)
        }
    });
    Ok(targets)
}

pub(crate) fn process_node_pid(node: &clawdstrike_policy_event::edr::CausalNode) -> Option<u32> {
    node.attributes
        .get("pid")
        .and_then(Value::as_u64)
        .and_then(|pid| u32::try_from(pid).ok())
}

pub(crate) fn quarantine_destination_path(
    quarantine_root: &FsPath,
    plan: &EndpointResponsePlan,
    source_path: &FsPath,
    content_hash: &str,
) -> PathBuf {
    let hash_fragment = content_hash
        .trim_start_matches("0x")
        .chars()
        .take(16)
        .collect::<String>();
    let source_name = source_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("file");
    quarantine_root.join(format!(
        "{}-{}-{}.quarantine",
        safe_filename_fragment(&plan.action_id),
        safe_filename_fragment(&hash_fragment),
        safe_filename_fragment(source_name)
    ))
}

pub(crate) fn safe_filename_fragment(value: &str) -> String {
    let fragment = value
        .chars()
        .take(96)
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if fragment.is_empty() {
        "artifact".to_string()
    } else {
        fragment
    }
}
