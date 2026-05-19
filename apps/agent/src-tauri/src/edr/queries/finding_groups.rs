//! Pure helpers for grouping detection findings into causal clusters.

use clawdstrike_policy_event::edr::{CausalGraph, CausalNodeKind, DetectionFinding};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub(crate) struct PendingFindingGroup {
    pub(crate) root_node_id: String,
    pub(crate) root_label: String,
    pub(crate) node_ids: BTreeSet<String>,
    pub(crate) findings: Vec<DetectionFinding>,
}

pub(crate) fn build_finding_groups(
    graph: &CausalGraph,
    findings: &[DetectionFinding],
    max_depth: usize,
) -> Vec<PendingFindingGroup> {
    let mut groups: Vec<PendingFindingGroup> = Vec::new();
    for finding in findings.iter().rev() {
        let Some(mut group) = pending_group_for_finding(graph, finding, max_depth) else {
            continue;
        };
        let mut index = 0;
        while index < groups.len() {
            if groups[index].node_ids.is_disjoint(&group.node_ids) {
                index += 1;
                continue;
            }
            let existing = groups.remove(index);
            group.node_ids.extend(existing.node_ids);
            group.findings.extend(existing.findings);
            if existing.root_label < group.root_label {
                group.root_node_id = existing.root_node_id;
                group.root_label = existing.root_label;
            }
        }
        groups.push(group);
    }
    groups.sort_by(|left, right| {
        newest_finding_timestamp(right)
            .cmp(&newest_finding_timestamp(left))
            .then_with(|| left.root_label.cmp(&right.root_label))
    });
    groups
}

pub(crate) fn pending_group_for_finding(
    graph: &CausalGraph,
    finding: &DetectionFinding,
    max_depth: usize,
) -> Option<PendingFindingGroup> {
    let touched_node_ids = graph_node_ids_for_observation(graph, &finding.observation_id);
    let root_node_id =
        finding_group_root_node_id(graph, &finding.observation_id, &touched_node_ids)?;
    let context = graph
        .causal_context_around(&root_node_id, max_depth, max_depth)
        .unwrap_or_else(|| {
            graph_slice_for_node_ids(graph, &BTreeSet::from([root_node_id.clone()]))
        });
    let mut node_ids = context.nodes.keys().cloned().collect::<BTreeSet<_>>();
    node_ids.extend(touched_node_ids);
    let root_label = graph
        .nodes
        .get(&root_node_id)
        .map(|node| node.label.clone())
        .unwrap_or_else(|| root_node_id.clone());
    Some(PendingFindingGroup {
        root_node_id,
        root_label,
        node_ids,
        findings: vec![finding.clone()],
    })
}

pub(crate) fn graph_node_ids_for_observation(
    graph: &CausalGraph,
    observation_id: &str,
) -> BTreeSet<String> {
    let mut node_ids = BTreeSet::new();
    for edge in graph
        .edges
        .iter()
        .filter(|edge| edge.observation_id == observation_id)
    {
        node_ids.insert(edge.from.clone());
        node_ids.insert(edge.to.clone());
    }
    node_ids
}

pub(crate) fn finding_group_root_node_id(
    graph: &CausalGraph,
    observation_id: &str,
    node_ids: &BTreeSet<String>,
) -> Option<String> {
    graph
        .edges
        .iter()
        .filter(|edge| edge.observation_id == observation_id)
        .find_map(|edge| {
            graph
                .nodes
                .get(&edge.from)
                .and_then(|node| (node.kind == CausalNodeKind::Process).then(|| edge.from.clone()))
        })
        .or_else(|| {
            node_ids.iter().find_map(|node_id| {
                graph.nodes.get(node_id).and_then(|node| {
                    (node.kind == CausalNodeKind::Process).then(|| node_id.clone())
                })
            })
        })
        .or_else(|| node_ids.iter().next().cloned())
}

pub(crate) fn graph_slice_for_node_ids(
    graph: &CausalGraph,
    node_ids: &BTreeSet<String>,
) -> CausalGraph {
    let nodes = node_ids
        .iter()
        .filter_map(|node_id| {
            graph
                .nodes
                .get(node_id)
                .map(|node| (node_id.clone(), node.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    let edges = graph
        .edges
        .iter()
        .filter(|edge| node_ids.contains(&edge.from) && node_ids.contains(&edge.to))
        .cloned()
        .collect::<Vec<_>>();
    CausalGraph { nodes, edges }
}

pub(crate) fn newest_finding_timestamp(
    group: &PendingFindingGroup,
) -> chrono::DateTime<chrono::Utc> {
    group
        .findings
        .iter()
        .map(|finding| finding.timestamp)
        .max()
        .unwrap_or_else(chrono::Utc::now)
}
