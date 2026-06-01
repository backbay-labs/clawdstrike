use super::super::*;

impl EndpointDecisionReceipt {
    #[must_use]
    pub fn for_simulation(input: EndpointSimulationReceiptInput<'_>) -> Self {
        let graph_ref =
            EndpointGraphReference::for_subgraph(&input.simulation.root_node_id, input.graph);
        let affected_identity_context =
            simulation_context_evidence_value(&input.simulation.affected_identities);
        let affected_tool_context =
            simulation_context_evidence_value(&input.simulation.affected_tools);
        let mut evidence = vec![
            EndpointReceiptEvidence::hashed("simulationId", &input.simulation.simulation_id),
            EndpointReceiptEvidence::hashed("rootNodeId", &input.simulation.root_node_id),
            EndpointReceiptEvidence::hashed("graphSliceId", &input.simulation.graph_slice_id),
            EndpointReceiptEvidence::hashed("wouldBlock", input.simulation.would_block.to_string()),
            EndpointReceiptEvidence::hashed(
                "developerBreakageScore",
                input.simulation.developer_breakage_score.to_string(),
            ),
            EndpointReceiptEvidence::hashed("impactLevel", input.simulation.impact_level.as_str()),
            EndpointReceiptEvidence::hashed(
                "affectedNodeCount",
                input.simulation.affected_node_count.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "affectedEdgeCount",
                input.simulation.affected_edge_count.to_string(),
            ),
            EndpointReceiptEvidence::hashed("affectedIdentityContext", affected_identity_context),
            EndpointReceiptEvidence::hashed("affectedToolContext", affected_tool_context),
        ];
        if let Some(content_hash) = graph_ref.content_hash.as_deref() {
            evidence.push(EndpointReceiptEvidence::hashed("contentHash", content_hash));
        }
        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::Simulation,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor: EndpointDecisionActor {
                endpoint_id: input.endpoint_id.to_string(),
                ..EndpointDecisionActor::default()
            },
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: None,
                finding_id: Some(input.simulation.simulation_id.clone()),
                rule_id: Some(input.simulation.rule_id.clone()),
                title: Some("Endpoint policy impact simulation".to_string()),
                severity: None,
                confidence: Some(f32::from(input.simulation.developer_breakage_score) / 100.0),
                action: input.simulation.action.clone(),
                passed: true,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: graph_ref,
            evidence,
        }
    }
}
