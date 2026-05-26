//! Graph search match builders and node-level filter helpers.

use super::index::{GraphSearchIndex, PendingGraphSearchMatch};
use super::path_attr::{
    graph_node_or_related_edge_attribute_matches, graph_node_or_related_path_matches,
    graph_node_or_related_path_pattern_matches, graph_node_or_related_path_prefix_matches,
    graph_path_pattern_literal_prefix,
};
use crate::api_server::non_empty;
use crate::edr::dto::{EdrGraphSearchInput, EdrGraphSearchQueryPlan};
use axum::http::StatusCode;
use clawdstrike_policy_event::edr::{
    CausalGraph, CausalNodeKind, EndpointFlightRecorderGraphEdgeIndexEntry,
    EndpointFlightRecorderGraphNodeIndexEntry,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub(crate) fn validate_graph_search_input(
    input: &EdrGraphSearchInput,
) -> Result<(), (StatusCode, String)> {
    let has_filter = input.node_kind.is_some()
        || non_empty(input.label_contains.as_deref()).is_some()
        || non_empty(input.path.as_deref()).is_some()
        || non_empty(input.path_prefix.as_deref()).is_some()
        || non_empty(input.path_pattern.as_deref()).is_some()
        || non_empty(input.attribute_key.as_deref()).is_some()
        || non_empty(input.tool_name.as_deref()).is_some()
        || non_empty(input.host_id.as_deref()).is_some()
        || non_empty(input.session_id.as_deref()).is_some()
        || non_empty(input.user_id.as_deref()).is_some()
        || non_empty(input.agent_id.as_deref()).is_some()
        || non_empty(input.workload_id.as_deref()).is_some()
        || non_empty(input.approval_id.as_deref()).is_some();
    if !has_filter {
        return Err((
            StatusCode::BAD_REQUEST,
            "at least one graph search filter must be provided".to_string(),
        ));
    }
    if input.attribute_value.is_some() && non_empty(input.attribute_key.as_deref()).is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "attribute_value requires attribute_key".to_string(),
        ));
    }
    if let Some(path_pattern) = non_empty(input.path_pattern.as_deref()) {
        if graph_path_pattern_literal_prefix(path_pattern).is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                "path_pattern requires a literal path prefix before the first wildcard".to_string(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn build_graph_search_matches(
    graph: &CausalGraph,
    durable_graph_index: Option<(
        &std::path::Path,
        &[EndpointFlightRecorderGraphNodeIndexEntry],
    )>,
    durable_graph_edge_index: Option<(
        &std::path::Path,
        &[EndpointFlightRecorderGraphEdgeIndexEntry],
    )>,
    input: &EdrGraphSearchInput,
    upstream_depth: usize,
    downstream_depth: usize,
    limit: usize,
) -> (Vec<PendingGraphSearchMatch>, usize, EdrGraphSearchQueryPlan) {
    let (index, index_source, index_path) = if let Some((index_path, entries)) = durable_graph_index
    {
        (
            GraphSearchIndex::from_graph_node_index(entries),
            "durable_graph_sidecar",
            Some(index_path.to_path_buf()),
        )
    } else {
        (GraphSearchIndex::from_graph(graph), "in_memory_graph", None)
    };
    let candidate_plan = index.candidate_node_ids(input);
    let candidate_node_ids = candidate_plan
        .node_ids
        .clone()
        .unwrap_or_else(|| graph.nodes.keys().cloned().collect());
    let (
        edge_index_source,
        edge_index_path,
        edge_index_count,
        edge_index_entries,
        context_expansion_strategy,
    ) = if let Some((edge_index_path, entries)) = durable_graph_edge_index {
        (
            "durable_graph_edge_sidecar",
            Some(edge_index_path.to_path_buf()),
            entries.len(),
            Some(entries),
            "durable_graph_edge_sidecar_adjacency",
        )
    } else {
        (
            "in_memory_graph",
            None,
            graph.edges.len(),
            None,
            "in_memory_graph_scan",
        )
    };
    let mut matches = Vec::new();
    let mut total_match_count = 0usize;
    let mut scanned_node_count = 0usize;
    for node_id in &candidate_node_ids {
        let Some(node) = graph.nodes.get(node_id) else {
            continue;
        };
        scanned_node_count = scanned_node_count.saturating_add(1);
        if !graph_search_node_matches(graph, node, input) {
            continue;
        }
        total_match_count = total_match_count.saturating_add(1);
        if matches.len() >= limit {
            continue;
        }
        let context = if let Some(edge_index) = edge_index_entries {
            causal_context_around_with_edge_index(
                graph,
                node_id,
                upstream_depth,
                downstream_depth,
                edge_index,
            )
        } else {
            graph.causal_context_around(node_id, upstream_depth, downstream_depth)
        }
        .unwrap_or_else(|| {
            crate::edr::queries::finding_groups::graph_slice_for_node_ids(
                graph,
                &BTreeSet::from([node_id.clone()]),
            )
        });
        matches.push(PendingGraphSearchMatch {
            root_node_id: node_id.clone(),
            root_label: node.label.clone(),
            root_kind: node.kind.clone(),
            graph: context,
        });
    }

    let query_plan = EdrGraphSearchQueryPlan {
        strategy: if candidate_plan.node_ids.is_some() {
            if index_source == "durable_graph_sidecar" {
                "durable_graph_sidecar_prefilter".to_string()
            } else {
                "indexed_prefilter".to_string()
            }
        } else {
            "full_scan".to_string()
        },
        indexed: candidate_plan.node_ids.is_some(),
        index_source: if candidate_plan.node_ids.is_some() {
            index_source.to_string()
        } else {
            "none".to_string()
        },
        index_path: if candidate_plan.node_ids.is_some() {
            index_path
        } else {
            None
        },
        edge_index_source: edge_index_source.to_string(),
        edge_index_path,
        edge_index_count,
        context_expansion_strategy: context_expansion_strategy.to_string(),
        indexed_keys: candidate_plan.indexed_keys,
        candidate_count: candidate_node_ids.len(),
        scanned_node_count,
    };

    (matches, total_match_count, query_plan)
}

pub(crate) fn intersect_graph_search_candidates(
    existing: Option<BTreeSet<String>>,
    next: BTreeSet<String>,
) -> Option<BTreeSet<String>> {
    Some(match existing {
        Some(existing) => existing.intersection(&next).cloned().collect(),
        None => next,
    })
}

pub(crate) fn causal_context_around_with_edge_index(
    graph: &CausalGraph,
    root_node_id: &str,
    upstream_depth: usize,
    downstream_depth: usize,
    edge_index: &[EndpointFlightRecorderGraphEdgeIndexEntry],
) -> Option<CausalGraph> {
    if !graph.nodes.contains_key(root_node_id) {
        return None;
    }

    let mut incoming: BTreeMap<&str, Vec<&EndpointFlightRecorderGraphEdgeIndexEntry>> =
        BTreeMap::new();
    let mut outgoing: BTreeMap<&str, Vec<&EndpointFlightRecorderGraphEdgeIndexEntry>> =
        BTreeMap::new();
    for edge in edge_index {
        outgoing.entry(edge.from.as_str()).or_default().push(edge);
        incoming.entry(edge.to.as_str()).or_default().push(edge);
    }

    let mut node_ids = BTreeSet::from([root_node_id.to_string()]);
    let mut edge_ids = BTreeSet::new();
    let mut upstream = VecDeque::from([(root_node_id.to_string(), 0usize)]);
    while let Some((node_id, depth)) = upstream.pop_front() {
        if depth >= upstream_depth {
            continue;
        }
        if let Some(edges) = incoming.get(node_id.as_str()) {
            for edge in edges {
                edge_ids.insert(edge.edge_id.clone());
                if node_ids.insert(edge.from.clone()) {
                    upstream.push_back((edge.from.clone(), depth + 1));
                }
            }
        }
    }

    let mut downstream = VecDeque::from([(root_node_id.to_string(), 0usize)]);
    while let Some((node_id, depth)) = downstream.pop_front() {
        if depth >= downstream_depth {
            continue;
        }
        if let Some(edges) = outgoing.get(node_id.as_str()) {
            for edge in edges {
                edge_ids.insert(edge.edge_id.clone());
                if node_ids.insert(edge.to.clone()) {
                    downstream.push_back((edge.to.clone(), depth + 1));
                }
            }
        }
    }

    let nodes = graph
        .nodes
        .iter()
        .filter(|(node_id, _)| node_ids.contains(*node_id))
        .map(|(node_id, node)| (node_id.clone(), node.clone()))
        .collect();
    let edges = graph
        .edges
        .iter()
        .filter(|edge| edge_ids.contains(&edge.edge_id))
        .cloned()
        .collect();

    Some(CausalGraph { nodes, edges })
}

pub(crate) fn graph_search_node_matches(
    graph: &CausalGraph,
    node: &clawdstrike_policy_event::edr::CausalNode,
    input: &EdrGraphSearchInput,
) -> bool {
    if let Some(expected_kind) = input.node_kind.as_ref() {
        if &node.kind != expected_kind {
            return false;
        }
    }
    if let Some(needle) = non_empty(input.label_contains.as_deref()) {
        if !node
            .label
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase())
        {
            return false;
        }
    }
    if let Some(expected_path) = non_empty(input.path.as_deref()) {
        if !graph_node_or_related_path_matches(graph, node, expected_path) {
            return false;
        }
    }
    if let Some(expected_path_prefix) = non_empty(input.path_prefix.as_deref()) {
        if !graph_node_or_related_path_prefix_matches(graph, node, expected_path_prefix) {
            return false;
        }
    }
    if let Some(expected_path_pattern) = non_empty(input.path_pattern.as_deref()) {
        if !graph_node_or_related_path_pattern_matches(graph, node, expected_path_pattern) {
            return false;
        }
    }
    if let Some(attribute_key) = non_empty(input.attribute_key.as_deref()) {
        if !graph_node_or_related_edge_attribute_matches(
            graph,
            &node.node_id,
            attribute_key,
            input.attribute_value.as_deref(),
        ) {
            return false;
        }
    }
    if let Some(tool_name) = non_empty(input.tool_name.as_deref()) {
        if node.kind != CausalNodeKind::Tool || node.label != tool_name {
            return false;
        }
    }
    for (key, value) in [
        ("hostId", input.host_id.as_deref()),
        ("sessionId", input.session_id.as_deref()),
        ("userId", input.user_id.as_deref()),
        ("agentId", input.agent_id.as_deref()),
        ("workloadId", input.workload_id.as_deref()),
        ("approvalId", input.approval_id.as_deref()),
    ] {
        if let Some(expected) = non_empty(value) {
            if !graph_node_or_related_edge_attribute_matches(
                graph,
                &node.node_id,
                key,
                Some(expected),
            ) {
                return false;
            }
        }
    }
    true
}
