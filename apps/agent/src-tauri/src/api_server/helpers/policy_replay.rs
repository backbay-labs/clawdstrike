//! Current-policy replay report builder.

use super::super::*;
use clawdstrike_policy_event::edr::{
    CausalGraph, CausalNode, EndpointDecisionAction, EndpointPolicySimulationReport,
    EndpointPolicySnapshot,
};
use std::collections::BTreeSet;

pub(crate) fn policy_replay_rule_id(
    policy: &EndpointPolicySnapshot,
    node: &CausalNode,
    action: &EndpointDecisionAction,
) -> String {
    format!(
        "endpoint.current_policy_replay.epoch_{}.{}.{}.{}",
        policy.policy_epoch,
        action.as_str(),
        causal_node_kind_name(&node.kind),
        rule_id_fragment(&node.label)
    )
}

pub(crate) fn policy_replay_description(
    policy: &EndpointPolicySnapshot,
    node: &CausalNode,
    action: &EndpointDecisionAction,
) -> String {
    format!(
        "Replay current endpoint policy {} epoch {} against captured {} node {} with simulated {} enforcement.",
        policy.policy_version,
        policy.policy_epoch,
        causal_node_kind_name(&node.kind),
        node.label,
        action.as_str()
    )
}

pub(crate) fn build_policy_replay_report(
    policy: EndpointPolicySnapshot,
    root_node: &CausalNode,
    flight_recorder_observation_count: usize,
    simulation: &EndpointPolicySimulationReport,
    graph: &CausalGraph,
) -> EdrPolicyReplayReport {
    let policy_epoch = policy.policy_epoch.to_string();
    let replay_id = local_stable_id(
        "policy_replay",
        [
            policy.policy_hash.as_str(),
            policy_epoch.as_str(),
            simulation.simulation_id.as_str(),
        ],
    );
    let observation_count = graph
        .edges
        .iter()
        .filter_map(|edge| {
            let observation_id = edge.observation_id.trim();
            (!observation_id.is_empty()).then_some(observation_id)
        })
        .collect::<BTreeSet<_>>()
        .len();
    let summary = format!(
        "Replayed graph slice {} under current endpoint policy {} epoch {}; {} would affect {} nodes and {} edges with developer breakage score {}/100.",
        simulation.graph_slice_id,
        policy.policy_version,
        policy.policy_epoch,
        simulation.rule_id,
        simulation.affected_node_count,
        simulation.affected_edge_count,
        simulation.developer_breakage_score
    );

    EdrPolicyReplayReport {
        replay_id,
        replayed_at: chrono::Utc::now(),
        mode: "current_policy_graph_replay".to_string(),
        policy,
        root_node_id: simulation.root_node_id.clone(),
        root_label: root_node.label.clone(),
        root_kind: root_node.kind.clone(),
        action: simulation.action.clone(),
        graph_slice_id: simulation.graph_slice_id.clone(),
        observation_count,
        node_count: graph.nodes.len(),
        edge_count: graph.edges.len(),
        flight_recorder_observation_count,
        would_enforce: simulation.would_block,
        developer_breakage_score: simulation.developer_breakage_score,
        impact_level: simulation.impact_level.clone(),
        summary,
    }
}
