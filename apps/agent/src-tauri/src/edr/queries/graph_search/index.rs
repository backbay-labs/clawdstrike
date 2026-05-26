//! Graph search index types and candidate planning.

use super::path_attr::{
    graph_attribute_index_value, graph_node_kind_has_path_label, graph_path_pattern_literal_prefix,
};
use super::matches::intersect_graph_search_candidates;
use crate::api_server::{causal_node_kind_name, non_empty};
use crate::edr::dto::EdrGraphSearchInput;
use clawdstrike_policy_event::edr::{
    CausalGraph, CausalNodeKind, EndpointFlightRecorderGraphNodeIndexEntry,
};
use std::collections::{BTreeMap, BTreeSet};

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
