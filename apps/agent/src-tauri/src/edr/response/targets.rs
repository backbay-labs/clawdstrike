//! Pure helpers for endpoint response target resolution and path construction.

use anyhow::Result;
use clawdstrike_policy_event::edr::{
    CausalEdgeKind, CausalGraph, CausalNodeKind, EndpointResponsePlan,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path as FsPath, PathBuf};

#[derive(Debug, Clone)]
pub(crate) struct ProcessSignalTarget {
    pub(crate) pid: u32,
    pub(crate) process_identity_key: String,
    pub(crate) label: String,
    depth: usize,
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
    let root_identity = process_node_live_identity_key(root)?;
    let mut targets = vec![ProcessSignalTarget {
        pid: root_pid,
        process_identity_key: root_identity,
        label: root.label.clone(),
        depth: 0,
    }];

    let mut seen_nodes = BTreeSet::from([root.node_id.clone()]);
    let mut queue = VecDeque::from([(root.node_id.clone(), 0_usize)]);
    while let Some((parent_node_id, depth)) = queue.pop_front() {
        for edge in graph
            .edges
            .iter()
            .filter(|edge| edge.kind == CausalEdgeKind::Spawned && edge.from == parent_node_id)
        {
            let child = graph.nodes.get(&edge.to).ok_or_else(|| {
                anyhow::anyhow!(
                    "process tree edge {} points at missing child node {}",
                    edge.edge_id,
                    edge.to
                )
            })?;
            if child.kind != CausalNodeKind::Process {
                return Err(anyhow::anyhow!(
                    "process tree edge {} points at non-process node {} ({:?})",
                    edge.edge_id,
                    child.node_id,
                    child.kind
                ));
            }
            if !seen_nodes.insert(child.node_id.clone()) {
                continue;
            }
            let pid = process_node_pid(child).ok_or_else(|| {
                anyhow::anyhow!(
                    "process tree child node {} is missing pid attribute",
                    child.node_id
                )
            })?;
            let process_identity_key = process_node_live_identity_key(child)?;
            targets.push(ProcessSignalTarget {
                pid,
                process_identity_key,
                label: child.label.clone(),
                depth: depth + 1,
            });
            queue.push_back((child.node_id.clone(), depth + 1));
        }
    }

    let mut pid_sources: BTreeMap<u32, &str> = BTreeMap::new();
    for target in &targets {
        if let Some(previous_label) = pid_sources.insert(target.pid, target.label.as_str()) {
            return Err(anyhow::anyhow!(
                "process tree contains duplicate pid {} for labels {} and {}; refusing ambiguous live signal target",
                target.pid,
                previous_label,
                target.label
            ));
        }
    }
    targets.sort_by(|left, right| {
        (left.depth, left.pid, left.process_identity_key.as_str()).cmp(&(
            right.depth,
            right.pid,
            right.process_identity_key.as_str(),
        ))
    });
    Ok(targets)
}

pub(crate) fn process_node_pid(node: &clawdstrike_policy_event::edr::CausalNode) -> Option<u32> {
    node.attributes
        .get("pid")
        .and_then(Value::as_u64)
        .and_then(|pid| u32::try_from(pid).ok())
}

fn process_node_live_identity_key(
    node: &clawdstrike_policy_event::edr::CausalNode,
) -> Result<String> {
    let identity_strength = node
        .attributes
        .get("processIdentityStrength")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let identity_key = node
        .attributes
        .get("processIdentityKey")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "process node {} is missing durable process identity key",
                node.node_id
            )
        })?;
    if identity_strength != "durable" || !identity_key.starts_with("guid:") {
        return Err(anyhow::anyhow!(
            "process node {} has non-durable identity {}; refusing PID-only live signal target",
            node.node_id,
            identity_strength
        ));
    }
    Ok(identity_key.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use clawdstrike_policy_event::edr::{CausalEdge, CausalNode};
    use serde_json::json;

    fn process_node(node_id: &str, label: &str, pid: Option<u32>) -> CausalNode {
        let mut attributes = BTreeMap::new();
        if let Some(pid) = pid {
            attributes.insert("pid".to_string(), json!(pid));
            attributes.insert("processIdentityStrength".to_string(), json!("durable"));
            attributes.insert(
                "processIdentityKey".to_string(),
                json!(format!("guid:{node_id}")),
            );
        }
        CausalNode {
            node_id: node_id.to_string(),
            kind: CausalNodeKind::Process,
            label: label.to_string(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            attributes,
        }
    }

    fn file_node(node_id: &str, label: &str) -> CausalNode {
        CausalNode {
            node_id: node_id.to_string(),
            kind: CausalNodeKind::File,
            label: label.to_string(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            attributes: BTreeMap::new(),
        }
    }

    fn edge(edge_id: &str, from: &str, to: &str, kind: CausalEdgeKind) -> CausalEdge {
        CausalEdge {
            edge_id: edge_id.to_string(),
            from: from.to_string(),
            to: to.to_string(),
            kind,
            timestamp: Utc::now(),
            observation_id: "obs-1".to_string(),
            attributes: BTreeMap::new(),
        }
    }

    fn suspend_plan(root_node_id: &str, graph: &CausalGraph) -> EndpointResponsePlan {
        EndpointResponsePlan::suspend_process_tree_execution(
            root_node_id,
            graph,
            600,
            "contain process tree",
        )
    }

    #[test]
    fn suspend_process_tree_targets_follow_only_spawned_descendants() {
        let mut graph = CausalGraph::default();
        graph.nodes.insert(
            "root".to_string(),
            process_node("root", "/bin/root", Some(10)),
        );
        graph.nodes.insert(
            "child".to_string(),
            process_node("child", "/bin/child", Some(11)),
        );
        graph.nodes.insert(
            "grandchild".to_string(),
            process_node("grandchild", "/bin/grandchild", Some(12)),
        );
        graph.nodes.insert(
            "unrelated".to_string(),
            process_node("unrelated", "/bin/unrelated", Some(99)),
        );
        graph
            .edges
            .push(edge("e1", "root", "child", CausalEdgeKind::Spawned));
        graph
            .edges
            .push(edge("e2", "child", "grandchild", CausalEdgeKind::Spawned));
        graph
            .edges
            .push(edge("e3", "root", "unrelated", CausalEdgeKind::Related));
        let plan = suspend_plan("root", &graph);

        let targets = suspend_process_tree_targets(&plan, &graph).expect("targets");

        let pids = targets.iter().map(|target| target.pid).collect::<Vec<_>>();
        assert_eq!(pids, vec![10, 11, 12]);
    }

    #[test]
    fn suspend_process_tree_targets_reject_missing_child_pid() {
        let mut graph = CausalGraph::default();
        graph.nodes.insert(
            "root".to_string(),
            process_node("root", "/bin/root", Some(10)),
        );
        graph.nodes.insert(
            "child".to_string(),
            process_node("child", "/bin/child", None),
        );
        graph
            .edges
            .push(edge("e1", "root", "child", CausalEdgeKind::Spawned));
        let plan = suspend_plan("root", &graph);

        let err = suspend_process_tree_targets(&plan, &graph).expect_err("missing pid must fail");

        assert!(err.to_string().contains("missing pid attribute"));
    }

    #[test]
    fn suspend_process_tree_targets_reject_pid_only_identity() {
        let mut graph = CausalGraph::default();
        let mut weak_root = process_node("root", "/bin/root", Some(10));
        weak_root.attributes.insert(
            "processIdentityStrength".to_string(),
            json!("weak_observation_scoped"),
        );
        weak_root.attributes.insert(
            "processIdentityKey".to_string(),
            json!("pid:10:observation:obs-1"),
        );
        graph.nodes.insert("root".to_string(), weak_root);
        let plan = suspend_plan("root", &graph);

        let err =
            suspend_process_tree_targets(&plan, &graph).expect_err("pid-only identity must fail");

        assert!(err.to_string().contains("non-durable identity"));
    }

    #[test]
    fn suspend_process_tree_targets_reject_spawned_non_process_child() {
        let mut graph = CausalGraph::default();
        graph.nodes.insert(
            "root".to_string(),
            process_node("root", "/bin/root", Some(10)),
        );
        graph
            .nodes
            .insert("file".to_string(), file_node("file", "/tmp/not-a-process"));
        graph
            .edges
            .push(edge("e1", "root", "file", CausalEdgeKind::Spawned));
        let plan = suspend_plan("root", &graph);

        let err =
            suspend_process_tree_targets(&plan, &graph).expect_err("non-process child must fail");

        assert!(err.to_string().contains("non-process node"));
    }
}
