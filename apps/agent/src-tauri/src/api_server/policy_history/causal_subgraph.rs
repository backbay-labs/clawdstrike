use super::*;

pub(crate) fn promotion_suggestions_for_causal_impact(
    contexts: &[EdrPolicyEventHistoryCausalContext],
    max_depth: usize,
    selected_stage: Option<&str>,
    cross_window_hashes: Option<(&str, &str)>,
) -> Vec<EdrPolicyEventHistoryPromotionSuggestion> {
    let mut suggestions = Vec::new();
    let mut seen = BTreeSet::new();
    let selected_stage = selected_stage.unwrap_or("audit").to_string();
    let cross_window_impact_hash =
        cross_window_hashes.map(|(impact_hash, _)| impact_hash.to_string());
    let cross_window_recommendation_hash =
        cross_window_hashes.map(|(_, recommendation_hash)| recommendation_hash.to_string());

    for context in contexts {
        for chain in &context.chains {
            if suggestions.len() >= EDR_MAX_POLICY_EVENT_IMPACT_PROMOTION_SUGGESTIONS {
                return suggestions;
            }
            let Some(target_node) = context.graph.nodes.get(&chain.target_node_id) else {
                continue;
            };
            let action = default_detection_candidate_action(target_node);
            if !supported_edr_simulation_action(&action) {
                continue;
            }
            let dedupe_key = format!("{}:{}", chain.target_node_id, action.as_str());
            if !seen.insert(dedupe_key) {
                continue;
            }
            let description = detection_candidate_description(target_node, &action);
            let note = format!(
                "Stage candidate from history impact event {} ({} -> {}) for review before enforcement.",
                context.event_id, context.current_outcome, context.proposed_outcome
            );
            let suggestion_id = local_stable_id(
                "impact_promotion",
                [
                    context.event_id.as_str(),
                    chain.target_node_id.as_str(),
                    action.as_str(),
                    selected_stage.as_str(),
                ],
            );
            suggestions.push(EdrPolicyEventHistoryPromotionSuggestion {
                suggestion_id,
                event_id: context.event_id.clone(),
                target_node_id: chain.target_node_id.clone(),
                target_label: chain.target_label.clone(),
                target_kind: chain.target_kind.clone(),
                action: action.clone(),
                selected_stage: selected_stage.clone(),
                cross_window_impact_hash: cross_window_impact_hash.clone(),
                cross_window_recommendation_hash: cross_window_recommendation_hash.clone(),
                reason: format!(
                    "Changed verdict {} -> {} on {} chain target {}; simulate and stage through the existing detection-candidate workflow.",
                    context.current_outcome,
                    context.proposed_outcome,
                    chain.target_kind,
                    chain.target_label
                ),
                candidate_endpoint: "/api/v1/agent/edr/detection-candidate".to_string(),
                candidate_request: EdrPolicyEventHistoryPromotionCandidateRequest {
                    root_node_id: chain.target_node_id.clone(),
                    action: action.clone(),
                    max_depth,
                    description: description.clone(),
                },
                stage_endpoint: "/api/v1/agent/edr/staged-detections".to_string(),
                stage_request: EdrPolicyEventHistoryPromotionStageRequest {
                    root_node_id: chain.target_node_id.clone(),
                    action,
                    max_depth,
                    selected_stage: selected_stage.clone(),
                    cross_window_impact_hash: cross_window_impact_hash.clone(),
                    cross_window_recommendation_hash: cross_window_recommendation_hash.clone(),
                    staged_by: "operator".to_string(),
                    note,
                },
            });
        }
    }

    suggestions
}

pub(crate) fn causal_chains_for_changed_observation(
    graph: &CausalGraph,
    root_node_id: &str,
    touched_node_ids: &BTreeSet<String>,
) -> Vec<EdrPolicyEventHistoryCausalChain> {
    let mut chains = Vec::new();
    for target_node_id in touched_node_ids
        .iter()
        .filter(|node_id| node_id.as_str() != root_node_id)
        .filter(|node_id| graph.nodes.contains_key(*node_id))
        .take(EDR_MAX_POLICY_EVENT_IMPACT_CHAINS_PER_CONTEXT)
    {
        let Some(path_node_ids) = causal_path_node_ids(graph, root_node_id, target_node_id) else {
            continue;
        };
        let Some(target_node) = graph.nodes.get(target_node_id) else {
            continue;
        };
        let nodes = path_node_ids
            .iter()
            .filter_map(|node_id| {
                graph
                    .nodes
                    .get(node_id)
                    .map(|node| EdrPolicyEventHistoryCausalChainNode {
                        node_id: node_id.clone(),
                        kind: causal_node_kind_name(&node.kind).to_string(),
                        label: node.label.clone(),
                    })
            })
            .collect::<Vec<_>>();
        let edge_kinds = path_node_ids
            .windows(2)
            .filter_map(|window| {
                graph
                    .edges
                    .iter()
                    .find(|edge| edge.from == window[0] && edge.to == window[1])
                    .map(|edge| causal_edge_kind_name(&edge.kind).to_string())
            })
            .collect::<Vec<_>>();

        chains.push(EdrPolicyEventHistoryCausalChain {
            target_node_id: target_node_id.clone(),
            target_label: target_node.label.clone(),
            target_kind: causal_node_kind_name(&target_node.kind).to_string(),
            path_node_count: nodes.len(),
            path_edge_count: edge_kinds.len(),
            nodes,
            edge_kinds,
        });
    }
    chains
}

fn causal_path_node_ids(graph: &CausalGraph, from: &str, to: &str) -> Option<Vec<String>> {
    if !graph.nodes.contains_key(from) || !graph.nodes.contains_key(to) {
        return None;
    }
    if from == to {
        return Some(vec![from.to_string()]);
    }

    let mut queue = VecDeque::from([from.to_string()]);
    let mut seen = BTreeSet::from([from.to_string()]);
    let mut previous: BTreeMap<String, String> = BTreeMap::new();

    while let Some(node_id) = queue.pop_front() {
        for edge in graph.edges.iter().filter(|edge| edge.from == node_id) {
            if !seen.insert(edge.to.clone()) {
                continue;
            }
            previous.insert(edge.to.clone(), node_id.clone());
            if edge.to == to {
                let mut path = vec![to.to_string()];
                let mut current = to;
                while let Some(parent) = previous.get(current) {
                    path.push(parent.clone());
                    if parent == from {
                        break;
                    }
                    current = parent;
                }
                path.reverse();
                return Some(path);
            }
            queue.push_back(edge.to.clone());
        }
    }

    None
}

pub(crate) fn causal_impact_receipt_graph(
    impact: &EdrPolicyEventHistoryCausalImpact,
) -> Option<(String, CausalGraph)> {
    let root_node_id = impact.contexts.first()?.root_node_id.clone();
    let mut nodes = BTreeMap::new();
    let mut edges = BTreeMap::new();

    for context in &impact.contexts {
        for (node_id, node) in &context.graph.nodes {
            nodes.insert(node_id.clone(), node.clone());
        }
        for edge in &context.graph.edges {
            edges.insert(edge.edge_id.clone(), edge.clone());
        }
    }

    Some((
        root_node_id,
        CausalGraph {
            nodes,
            edges: edges.into_values().collect(),
        },
    ))
}

pub(crate) fn causal_node_kind_counts(graph: &CausalGraph) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for node in graph.nodes.values() {
        *counts
            .entry(causal_node_kind_name(&node.kind).to_string())
            .or_insert(0) += 1;
    }
    counts
}

fn causal_edge_kind_name(kind: &CausalEdgeKind) -> &'static str {
    match kind {
        CausalEdgeKind::ObservedOn => "observed_on",
        CausalEdgeKind::RanAs => "ran_as",
        CausalEdgeKind::InSession => "in_session",
        CausalEdgeKind::UsedAgent => "used_agent",
        CausalEdgeKind::UsedWorkload => "used_workload",
        CausalEdgeKind::AuthorizedBy => "authorized_by",
        CausalEdgeKind::Spawned => "spawned",
        CausalEdgeKind::Executed => "executed",
        CausalEdgeKind::Read => "read",
        CausalEdgeKind::Wrote => "wrote",
        CausalEdgeKind::Connected => "connected",
        CausalEdgeKind::ResolvedDns => "resolved_dns",
        CausalEdgeKind::RanScript => "ran_script",
        CausalEdgeKind::LoadedLibrary => "loaded_library",
        CausalEdgeKind::CreatedPersistence => "created_persistence",
        CausalEdgeKind::InstalledExtension => "installed_extension",
        CausalEdgeKind::Downloaded => "downloaded",
        CausalEdgeKind::AccessedCredential => "accessed_credential",
        CausalEdgeKind::MadeDecision => "made_decision",
        CausalEdgeKind::InvokedTool => "invoked_tool",
        CausalEdgeKind::TemporalNext => "temporal_next",
        CausalEdgeKind::TouchedHoney => "touched_honey",
        CausalEdgeKind::Related => "related",
    }
}
