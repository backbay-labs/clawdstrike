//! Pure helpers for graph search: index construction, candidate planning, match filtering.

mod index;
mod matches;
mod path_attr;

#[allow(unused_imports)]
pub(crate) use index::{GraphSearchCandidatePlan, GraphSearchIndex, PendingGraphSearchMatch};
#[allow(unused_imports)]
pub(crate) use matches::{
    build_graph_search_matches, causal_context_around_with_edge_index, graph_search_node_matches,
    intersect_graph_search_candidates, validate_graph_search_input,
};
#[allow(unused_imports)]
pub(crate) use path_attr::{
    graph_attribute_index_value, graph_attribute_value_matches, graph_node_kind_has_path_label,
    graph_node_or_related_edge_attribute_matches, graph_node_or_related_path_attribute_matches,
    graph_node_or_related_path_matches, graph_node_or_related_path_pattern_matches,
    graph_node_or_related_path_prefix_matches, graph_path_pattern_literal_prefix,
    graph_path_pattern_matches,
};
