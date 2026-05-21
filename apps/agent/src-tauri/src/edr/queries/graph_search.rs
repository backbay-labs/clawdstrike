//! Pure helpers for graph search: index construction, candidate planning, match filtering.

use crate::api_server::{causal_node_kind_name, non_empty};
use crate::edr::dto::{EdrGraphSearchInput, EdrGraphSearchQueryPlan};
use axum::http::StatusCode;
use clawdstrike_policy_event::edr::{
    CausalGraph, CausalNodeKind, EndpointFlightRecorderGraphEdgeIndexEntry,
    EndpointFlightRecorderGraphNodeIndexEntry,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Debug)]
pub(crate) struct PendingGraphSearchMatch {
    pub(crate) root_node_id: String,
    pub(crate) root_label: String,
    pub(crate) root_kind: CausalNodeKind,
    pub(crate) graph: CausalGraph,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct GraphSearchIndex {
    node_ids_by_kind: BTreeMap<String, BTreeSet<String>>,
    node_ids_by_path: BTreeMap<String, BTreeSet<String>>,
    node_ids_by_tool_name: BTreeMap<String, BTreeSet<String>>,
    node_ids_by_attribute: BTreeMap<String, BTreeSet<String>>,
    node_ids_by_attribute_value: BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct GraphSearchCandidatePlan {
    pub(crate) node_ids: Option<BTreeSet<String>>,
    pub(crate) indexed_keys: Vec<String>,
}

impl GraphSearchIndex {
    pub(crate) fn from_graph(graph: &CausalGraph) -> Self {
        let mut index = Self::default();
        for node in graph.nodes.values() {
            index.add_kind(&node.node_id, &node.kind);
            index.add_paths_from_node(&node.node_id, &node.kind, &node.label, &node.attributes);
            if node.kind == CausalNodeKind::Tool {
                index.add_tool_name(&node.node_id, &node.label);
            }
            for (key, value) in &node.attributes {
                index.add_attribute(&node.node_id, key, value);
            }
        }
        for edge in &graph.edges {
            for (key, value) in &edge.attributes {
                index.add_attribute(&edge.from, key, value);
                index.add_attribute(&edge.to, key, value);
            }
        }
        index
    }

    pub(crate) fn from_graph_node_index(
        entries: &[EndpointFlightRecorderGraphNodeIndexEntry],
    ) -> Self {
        let mut index = Self::default();
        for entry in entries {
            index.add_kind(&entry.node_id, &entry.kind);
            index.add_paths_from_node(&entry.node_id, &entry.kind, &entry.label, &entry.attributes);
            if entry.kind == CausalNodeKind::Tool {
                index.add_tool_name(&entry.node_id, &entry.label);
            }
            for (key, value) in &entry.attributes {
                index.add_attribute(&entry.node_id, key, value);
            }
        }
        index
    }

    pub(crate) fn candidate_node_ids(
        &self,
        input: &EdrGraphSearchInput,
    ) -> GraphSearchCandidatePlan {
        let mut candidate_ids: Option<BTreeSet<String>> = None;
        let mut indexed_keys = Vec::new();

        if let Some(kind) = input.node_kind.as_ref() {
            let key = causal_node_kind_name(kind);
            candidate_ids = intersect_graph_search_candidates(
                candidate_ids,
                self.node_ids_by_kind.get(key).cloned().unwrap_or_default(),
            );
            indexed_keys.push("nodeKind".to_string());
        }

        if let Some(path) = non_empty(input.path.as_deref()) {
            candidate_ids = intersect_graph_search_candidates(
                candidate_ids,
                self.node_ids_by_path.get(path).cloned().unwrap_or_default(),
            );
            indexed_keys.push("path".to_string());
        }

        if let Some(path_prefix) = non_empty(input.path_prefix.as_deref()) {
            candidate_ids = intersect_graph_search_candidates(
                candidate_ids,
                self.path_prefix_candidates(path_prefix),
            );
            indexed_keys.push("pathPrefix".to_string());
        }

        if let Some(path_pattern) = non_empty(input.path_pattern.as_deref()) {
            candidate_ids = intersect_graph_search_candidates(
                candidate_ids,
                self.path_pattern_candidates(path_pattern),
            );
            indexed_keys.push("pathPattern".to_string());
        }

        if let Some(attribute_key) = non_empty(input.attribute_key.as_deref()) {
            candidate_ids = intersect_graph_search_candidates(
                candidate_ids,
                self.attribute_candidates(attribute_key, input.attribute_value.as_deref()),
            );
            indexed_keys.push(format!("attribute:{attribute_key}"));
        }

        if let Some(tool_name) = non_empty(input.tool_name.as_deref()) {
            candidate_ids = intersect_graph_search_candidates(
                candidate_ids,
                self.node_ids_by_tool_name
                    .get(tool_name)
                    .cloned()
                    .unwrap_or_default(),
            );
            indexed_keys.push("toolName".to_string());
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
                candidate_ids = intersect_graph_search_candidates(
                    candidate_ids,
                    self.attribute_candidates(key, Some(expected)),
                );
                indexed_keys.push(key.to_string());
            }
        }

        GraphSearchCandidatePlan {
            node_ids: candidate_ids,
            indexed_keys,
        }
    }

    fn add_kind(&mut self, node_id: &str, kind: &CausalNodeKind) {
        self.node_ids_by_kind
            .entry(causal_node_kind_name(kind).to_string())
            .or_default()
            .insert(node_id.to_string());
    }

    fn add_paths_from_node(
        &mut self,
        node_id: &str,
        kind: &CausalNodeKind,
        label: &str,
        attributes: &BTreeMap<String, serde_json::Value>,
    ) {
        if graph_node_kind_has_path_label(kind) {
            self.add_path(node_id, label);
        }
        if let Some(path) = attributes.get("path").and_then(graph_attribute_index_value) {
            self.add_path(node_id, &path);
        }
    }

    fn add_path(&mut self, node_id: &str, path: &str) {
        if let Some(path) = non_empty(Some(path)) {
            self.node_ids_by_path
                .entry(path.to_string())
                .or_default()
                .insert(node_id.to_string());
        }
    }

    fn path_prefix_candidates(&self, path_prefix: &str) -> BTreeSet<String> {
        let mut candidates = BTreeSet::new();
        for (path, node_ids) in self.node_ids_by_path.range(path_prefix.to_string()..) {
            if !path.starts_with(path_prefix) {
                break;
            }
            candidates.extend(node_ids.iter().cloned());
        }
        candidates
    }

    fn path_pattern_candidates(&self, path_pattern: &str) -> BTreeSet<String> {
        let prefix = graph_path_pattern_literal_prefix(path_pattern);
        if prefix.is_empty() {
            return BTreeSet::new();
        }
        self.path_prefix_candidates(&prefix)
    }

    fn add_tool_name(&mut self, node_id: &str, tool_name: &str) {
        if let Some(tool_name) = non_empty(Some(tool_name)) {
            self.node_ids_by_tool_name
                .entry(tool_name.to_string())
                .or_default()
                .insert(node_id.to_string());
        }
    }

    fn add_attribute(&mut self, node_id: &str, key: &str, value: &serde_json::Value) {
        self.node_ids_by_attribute
            .entry(key.to_string())
            .or_default()
            .insert(node_id.to_string());
        if let Some(value_key) = graph_attribute_index_value(value) {
            self.node_ids_by_attribute_value
                .entry(key.to_string())
                .or_default()
                .entry(value_key)
                .or_default()
                .insert(node_id.to_string());
        }
    }

    fn attribute_candidates(&self, key: &str, expected: Option<&str>) -> BTreeSet<String> {
        if let Some(expected) = non_empty(expected) {
            return self
                .node_ids_by_attribute_value
                .get(key)
                .and_then(|values| values.get(expected))
                .cloned()
                .unwrap_or_default();
        }
        self.node_ids_by_attribute
            .get(key)
            .cloned()
            .unwrap_or_default()
    }
}

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

pub(crate) fn graph_node_or_related_path_matches(
    graph: &CausalGraph,
    node: &clawdstrike_policy_event::edr::CausalNode,
    expected_path: &str,
) -> bool {
    graph_node_kind_has_path_label(&node.kind) && node.label == expected_path
        || graph_node_or_related_edge_attribute_matches(
            graph,
            &node.node_id,
            "path",
            Some(expected_path),
        )
}

pub(crate) fn graph_node_or_related_path_prefix_matches(
    graph: &CausalGraph,
    node: &clawdstrike_policy_event::edr::CausalNode,
    expected_path_prefix: &str,
) -> bool {
    graph_node_kind_has_path_label(&node.kind) && node.label.starts_with(expected_path_prefix)
        || graph_node_or_related_path_attribute_matches(graph, &node.node_id, |path| {
            path.starts_with(expected_path_prefix)
        })
}

pub(crate) fn graph_node_or_related_path_pattern_matches(
    graph: &CausalGraph,
    node: &clawdstrike_policy_event::edr::CausalNode,
    expected_path_pattern: &str,
) -> bool {
    graph_node_kind_has_path_label(&node.kind)
        && graph_path_pattern_matches(expected_path_pattern, &node.label)
        || graph_node_or_related_path_attribute_matches(graph, &node.node_id, |path| {
            graph_path_pattern_matches(expected_path_pattern, path)
        })
}

pub(crate) fn graph_path_pattern_literal_prefix(pattern: &str) -> String {
    pattern
        .chars()
        .take_while(|value| !matches!(value, '*' | '?'))
        .collect()
}

pub(crate) fn graph_path_pattern_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut pattern_index = 0usize;
    let mut value_index = 0usize;
    let mut star_index: Option<usize> = None;
    let mut star_value_index = 0usize;

    while value_index < value.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == b'?' || pattern[pattern_index] == value[value_index])
        {
            pattern_index += 1;
            value_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            star_index = Some(pattern_index);
            star_value_index = value_index;
            pattern_index += 1;
        } else if let Some(star) = star_index {
            pattern_index = star + 1;
            star_value_index += 1;
            value_index = star_value_index;
        } else {
            return false;
        }
    }

    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }

    pattern_index == pattern.len()
}

pub(crate) fn graph_node_kind_has_path_label(kind: &CausalNodeKind) -> bool {
    matches!(
        kind,
        CausalNodeKind::Process
            | CausalNodeKind::File
            | CausalNodeKind::PackageScript
            | CausalNodeKind::Credential
            | CausalNodeKind::BrowserDownload
            | CausalNodeKind::BrowserExtension
            | CausalNodeKind::DeceptionArtifact
    )
}

pub(crate) fn graph_node_or_related_path_attribute_matches(
    graph: &CausalGraph,
    node_id: &str,
    predicate: impl Fn(&str) -> bool,
) -> bool {
    if graph
        .nodes
        .get(node_id)
        .and_then(|node| node.attributes.get("path"))
        .and_then(serde_json::Value::as_str)
        .is_some_and(&predicate)
    {
        return true;
    }

    graph
        .edges
        .iter()
        .filter(|edge| edge.from == node_id || edge.to == node_id)
        .any(|edge| {
            edge.attributes
                .get("path")
                .and_then(serde_json::Value::as_str)
                .is_some_and(&predicate)
        })
}

pub(crate) fn graph_node_or_related_edge_attribute_matches(
    graph: &CausalGraph,
    node_id: &str,
    key: &str,
    expected: Option<&str>,
) -> bool {
    graph
        .nodes
        .get(node_id)
        .and_then(|node| node.attributes.get(key))
        .is_some_and(|value| graph_attribute_value_matches(value, expected))
        || graph
            .edges
            .iter()
            .filter(|edge| edge.from == node_id || edge.to == node_id)
            .any(|edge| {
                edge.attributes
                    .get(key)
                    .is_some_and(|value| graph_attribute_value_matches(value, expected))
            })
}

pub(crate) fn graph_attribute_value_matches(
    value: &serde_json::Value,
    expected: Option<&str>,
) -> bool {
    let Some(expected) = non_empty(expected) else {
        return true;
    };
    match value {
        serde_json::Value::String(actual) => actual == expected,
        serde_json::Value::Number(actual) => actual.to_string() == expected,
        serde_json::Value::Bool(actual) => actual.to_string() == expected,
        _ => false,
    }
}

pub(crate) fn graph_attribute_index_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(actual) => Some(actual.clone()),
        serde_json::Value::Number(actual) => Some(actual.to_string()),
        serde_json::Value::Bool(actual) => Some(actual.to_string()),
        _ => None,
    }
}
