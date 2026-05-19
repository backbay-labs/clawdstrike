use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use super::node::{CausalEdge, CausalNode};

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct CausalGraph {
    pub nodes: BTreeMap<String, CausalNode>,
    pub edges: Vec<CausalEdge>,
}

impl CausalGraph {
    #[must_use]
    pub fn causal_subgraph_from(&self, root_node_id: &str, max_depth: usize) -> Option<Self> {
        if !self.nodes.contains_key(root_node_id) {
            return None;
        }

        let mut node_ids = BTreeSet::from([root_node_id.to_string()]);
        let mut edge_ids = BTreeSet::new();
        let mut queue = VecDeque::from([(root_node_id.to_string(), 0usize)]);

        while let Some((node_id, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }

            for edge in self.edges.iter().filter(|edge| edge.from == node_id) {
                edge_ids.insert(edge.edge_id.clone());
                if node_ids.insert(edge.to.clone()) {
                    queue.push_back((edge.to.clone(), depth + 1));
                }
            }
        }

        let nodes = self
            .nodes
            .iter()
            .filter(|(node_id, _)| node_ids.contains(*node_id))
            .map(|(node_id, node)| (node_id.clone(), node.clone()))
            .collect();
        let edges = self
            .edges
            .iter()
            .filter(|edge| edge_ids.contains(&edge.edge_id))
            .cloned()
            .collect();

        Some(Self { nodes, edges })
    }

    #[must_use]
    pub fn causal_context_around(
        &self,
        root_node_id: &str,
        upstream_depth: usize,
        downstream_depth: usize,
    ) -> Option<Self> {
        if !self.nodes.contains_key(root_node_id) {
            return None;
        }

        let mut node_ids = BTreeSet::from([root_node_id.to_string()]);
        let mut edge_ids = BTreeSet::new();

        let mut upstream = VecDeque::from([(root_node_id.to_string(), 0usize)]);
        while let Some((node_id, depth)) = upstream.pop_front() {
            if depth >= upstream_depth {
                continue;
            }

            for edge in self.edges.iter().filter(|edge| edge.to == node_id) {
                edge_ids.insert(edge.edge_id.clone());
                if node_ids.insert(edge.from.clone()) {
                    upstream.push_back((edge.from.clone(), depth + 1));
                }
            }
        }

        let mut downstream = VecDeque::from([(root_node_id.to_string(), 0usize)]);
        while let Some((node_id, depth)) = downstream.pop_front() {
            if depth >= downstream_depth {
                continue;
            }

            for edge in self.edges.iter().filter(|edge| edge.from == node_id) {
                edge_ids.insert(edge.edge_id.clone());
                if node_ids.insert(edge.to.clone()) {
                    downstream.push_back((edge.to.clone(), depth + 1));
                }
            }
        }

        let nodes = self
            .nodes
            .iter()
            .filter(|(node_id, _)| node_ids.contains(*node_id))
            .map(|(node_id, node)| (node_id.clone(), node.clone()))
            .collect();
        let edges = self
            .edges
            .iter()
            .filter(|edge| edge_ids.contains(&edge.edge_id))
            .cloned()
            .collect();

        Some(Self { nodes, edges })
    }
}
