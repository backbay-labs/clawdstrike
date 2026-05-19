use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use hush_core::{canonicalize_json, sha256};
use serde::{Deserialize, Serialize};

use super::super::causal::CausalGraph;
use super::super::event::EndpointObservation;
use super::super::stable_id;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointEvidenceRedactionClass {
    #[default]
    HashOnly,
    MetadataOnly,
    Redacted,
    RawArtifactPermitted,
    LocalOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointReceiptEvidence {
    pub key: String,
    pub value_hash: String,
    pub redaction_class: EndpointEvidenceRedactionClass,
    pub raw_value: Option<String>,
}

impl Default for EndpointReceiptEvidence {
    fn default() -> Self {
        Self {
            key: String::new(),
            value_hash: String::new(),
            redaction_class: EndpointEvidenceRedactionClass::HashOnly,
            raw_value: None,
        }
    }
}

impl EndpointReceiptEvidence {
    #[must_use]
    pub fn hashed(key: impl Into<String>, value: impl AsRef<str>) -> Self {
        Self {
            key: key.into(),
            value_hash: sha256(value.as_ref().as_bytes()).to_hex_prefixed(),
            redaction_class: EndpointEvidenceRedactionClass::HashOnly,
            raw_value: None,
        }
    }
}


#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointGraphReference {
    pub graph_slice_id: Option<String>,
    pub process_stable_key: Option<String>,
    pub process_node_id: Option<String>,
    pub parent_process_guid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    pub node_ids: Vec<String>,
    pub edge_ids: Vec<String>,
}

impl EndpointGraphReference {
    #[must_use]
    pub fn for_observation(observation: &EndpointObservation, graph: &CausalGraph) -> Self {
        let process_stable_key = observation.process.stable_key();
        let process_node_id = stable_id("node", [process_stable_key.as_str()]);
        let mut node_ids = BTreeSet::new();
        if graph.nodes.contains_key(&process_node_id) {
            node_ids.insert(process_node_id.clone());
        }

        let mut edge_ids = Vec::new();
        for edge in graph
            .edges
            .iter()
            .filter(|edge| edge.observation_id == observation.observation_id)
        {
            edge_ids.push(edge.edge_id.clone());
            node_ids.insert(edge.from.clone());
            node_ids.insert(edge.to.clone());
        }

        let node_count = node_ids.len().to_string();
        let edge_count = edge_ids.len().to_string();
        let graph_slice_id = stable_id(
            "graph_slice",
            [
                observation.observation_id.as_str(),
                process_node_id.as_str(),
                node_count.as_str(),
                edge_count.as_str(),
            ],
        );

        Self {
            graph_slice_id: Some(graph_slice_id),
            process_stable_key: Some(process_stable_key),
            process_node_id: Some(process_node_id),
            parent_process_guid: observation.process.parent_process_guid.clone(),
            content_hash: None,
            node_ids: node_ids.into_iter().collect(),
            edge_ids,
        }
    }

    #[must_use]
    pub fn for_subgraph(root_node_id: impl Into<String>, graph: &CausalGraph) -> Self {
        let root_node_id = root_node_id.into();
        let mut node_ids: Vec<String> = graph.nodes.keys().cloned().collect();
        node_ids.sort();
        let edge_ids: Vec<String> = graph
            .edges
            .iter()
            .map(|edge| edge.edge_id.clone())
            .collect();
        let node_count = node_ids.len().to_string();
        let edge_count = edge_ids.len().to_string();
        let graph_slice_id = stable_id(
            "graph_slice",
            [
                root_node_id.as_str(),
                node_count.as_str(),
                edge_count.as_str(),
            ],
        );

        Self {
            graph_slice_id: Some(graph_slice_id),
            process_stable_key: None,
            process_node_id: Some(root_node_id),
            parent_process_guid: None,
            content_hash: canonical_graph_content_hash(graph),
            node_ids,
            edge_ids,
        }
    }
}

fn canonical_graph_content_hash(graph: &CausalGraph) -> Option<String> {
    serde_json::to_value(graph)
        .ok()
        .and_then(|value| canonicalize_json(&value).ok())
        .map(|canonical_graph| sha256(canonical_graph.as_bytes()).to_hex_prefixed())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointEvidenceBundleReference {
    pub bundle_id: String,
    pub graph_slice_id: String,
    pub content_hash: String,
    pub node_count: usize,
    pub edge_count: usize,
    pub created_at: DateTime<Utc>,
}

impl Default for EndpointEvidenceBundleReference {
    fn default() -> Self {
        Self {
            bundle_id: String::new(),
            graph_slice_id: String::new(),
            content_hash: String::new(),
            node_count: 0,
            edge_count: 0,
            created_at: Utc::now(),
        }
    }
}

