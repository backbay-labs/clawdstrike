//! Health summary DTOs for the endpoint decision engine API.

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct EdrHealthSummary {
    pub observation_count: usize,
    pub graph_node_count: usize,
    pub graph_edge_count: usize,
    pub recent_finding_count: usize,
}
