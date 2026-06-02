use super::super::*;

impl EndpointDecisionReceipt {
    #[must_use]
    pub fn for_graph_slice(input: EndpointGraphSliceReceiptInput<'_>) -> Self {
        let graph_ref = EndpointGraphReference::for_subgraph(input.root_node_id, input.graph);
        let graph_slice_id = graph_ref.graph_slice_id.clone().unwrap_or_else(|| {
            let node_count = input.graph.nodes.len().to_string();
            let edge_count = input.graph.edges.len().to_string();
            stable_id(
                "graph_slice",
                [input.root_node_id, node_count.as_str(), edge_count.as_str()],
            )
        });
        let graph_content_hash = graph_ref.content_hash.clone();
        let mut evidence = vec![
            EndpointReceiptEvidence::hashed("graphSliceId", graph_slice_id.clone()),
            EndpointReceiptEvidence::hashed("rootNodeId", input.root_node_id),
            EndpointReceiptEvidence::hashed("sliceKind", input.slice_kind),
            EndpointReceiptEvidence::hashed("nodeCount", input.graph.nodes.len().to_string()),
            EndpointReceiptEvidence::hashed("edgeCount", input.graph.edges.len().to_string()),
        ];
        if let Some(graph_content_hash) = graph_content_hash {
            evidence.push(EndpointReceiptEvidence::hashed(
                "contentHash",
                graph_content_hash,
            ));
        }

        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::GraphSlice,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor: EndpointDecisionActor::with_endpoint_id(input.endpoint_id),
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: None,
                finding_id: Some(graph_slice_id.clone()),
                rule_id: Some(format!("endpoint.graph_slice.{}", input.slice_kind)),
                title: Some("Endpoint causal graph slice exported".to_string()),
                severity: None,
                confidence: None,
                action: EndpointDecisionAction::Observe,
                passed: true,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: graph_ref,
            evidence,
        }
    }
}
