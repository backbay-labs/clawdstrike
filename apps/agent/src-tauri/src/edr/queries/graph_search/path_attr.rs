//! Path/attribute helpers used by graph search index and match filters.

use crate::api_server::non_empty;
use clawdstrike_policy_event::edr::{CausalGraph, CausalNodeKind};

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
