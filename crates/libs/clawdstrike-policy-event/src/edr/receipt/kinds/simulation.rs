use super::super::*;

pub(crate) fn graph_policy_simulation_id_from_signed_fields(
    root_node_id: &str,
    graph_slice_id: &str,
    rule_id: &str,
    action: &EndpointDecisionAction,
    breakage_score: u8,
) -> String {
    let breakage_score = breakage_score.to_string();
    stable_id(
        "policy_simulation",
        [
            root_node_id,
            graph_slice_id,
            rule_id,
            action.as_str(),
            breakage_score.as_str(),
        ],
    )
}

pub(crate) fn require_simulation_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    graph: &EndpointGraphReference,
    policy: &EndpointPolicySnapshot,
) -> Result<()> {
    let rule_id = decision
        .rule_id
        .as_deref()
        .ok_or_else(|| anyhow!("simulation rule id is required"))?;
    match rule_id {
        "endpoint.policy_event_replay" => require_policy_event_replay_evidence(
            evidence,
            decision.finding_id.as_deref(),
            graph,
            policy,
        ),
        "endpoint.policy_event_impact" => require_policy_event_impact_evidence(
            evidence,
            decision.finding_id.as_deref(),
            graph,
            policy,
        ),
        _ => require_graph_policy_simulation_evidence(evidence, decision, graph),
    }
}

pub(crate) fn require_graph_policy_simulation_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    graph: &EndpointGraphReference,
) -> Result<()> {
    let simulation_id = decision
        .finding_id
        .as_deref()
        .ok_or_else(|| anyhow!("simulation signed id is required"))?;
    let root_node_id = graph
        .process_node_id
        .as_deref()
        .ok_or_else(|| anyhow!("simulation root node id is required"))?;
    let graph_slice_id = graph
        .graph_slice_id
        .as_deref()
        .ok_or_else(|| anyhow!("simulation graph slice id is required"))?;
    let content_hash = graph
        .content_hash
        .as_deref()
        .ok_or_else(|| anyhow!("simulation graph content hash is required"))?;
    let breakage_score = simulation_breakage_score_from_confidence(decision.confidence)?;
    require_subgraph_reference(graph, "simulation")?;

    require_evidence_value_hash(
        evidence,
        "simulationId",
        simulation_id,
        "simulation id evidence",
    )?;
    let expected_simulation_id = graph_policy_simulation_id_from_signed_fields(
        root_node_id,
        graph_slice_id,
        decision
            .rule_id
            .as_deref()
            .ok_or_else(|| anyhow!("simulation rule id is required"))?,
        &decision.action,
        breakage_score,
    );
    if simulation_id != expected_simulation_id {
        return Err(anyhow!(
            "simulation id must match signed root, graph slice, rule, action, and breakage score"
        ));
    }
    require_evidence_value_hash(
        evidence,
        "rootNodeId",
        root_node_id,
        "simulation root node evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "graphSliceId",
        graph_slice_id,
        "simulation graph slice evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "wouldBlock",
        simulation_action_would_block(&decision.action).to_string(),
        "simulation would-block evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "developerBreakageScore",
        breakage_score.to_string(),
        "simulation breakage score evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "impactLevel",
        impact_level_for_score(breakage_score).as_str(),
        "simulation impact level evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "affectedNodeCount",
        graph.node_ids.len().to_string(),
        "simulation affected-node count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "affectedEdgeCount",
        graph.edge_ids.len().to_string(),
        "simulation affected-edge count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "affectedIdentityContext",
        "simulation affected identity context evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "affectedToolContext",
        "simulation affected tool context evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "contentHash",
        content_hash,
        "simulation content hash evidence",
    )
}

pub(crate) fn simulation_breakage_score_from_confidence(confidence: Option<f32>) -> Result<u8> {
    let confidence = confidence.ok_or_else(|| anyhow!("simulation confidence is required"))?;
    let score = confidence * 100.0;
    let rounded = score.round();
    if !(0.0..=100.0).contains(&rounded) || (score - rounded).abs() > 0.001 {
        return Err(anyhow!(
            "simulation confidence must encode a whole-number breakage score"
        ));
    }
    Ok(rounded as u8)
}
