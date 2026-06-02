use super::super::*;

impl EndpointDecisionReceipt {
    #[must_use]
    pub fn for_evidence_bundle_manifest(
        input: EndpointEvidenceBundleManifestReceiptInput<'_>,
    ) -> Self {
        let graph_ref = EndpointGraphReference::for_subgraph(input.root_node_id, input.graph);
        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::EvidenceBundleManifest,
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
                finding_id: Some(input.bundle.bundle_id.clone()),
                rule_id: Some("endpoint.evidence_bundle_manifest".to_string()),
                title: Some("Endpoint evidence bundle manifest".to_string()),
                severity: None,
                confidence: None,
                action: EndpointDecisionAction::CollectEvidence,
                passed: true,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: graph_ref,
            evidence: vec![
                EndpointReceiptEvidence::hashed("evidenceBundleId", &input.bundle.bundle_id),
                EndpointReceiptEvidence::hashed("graphSliceId", &input.bundle.graph_slice_id),
                EndpointReceiptEvidence::hashed("contentHash", &input.bundle.content_hash),
                EndpointReceiptEvidence::hashed("nodeCount", input.bundle.node_count.to_string()),
                EndpointReceiptEvidence::hashed("edgeCount", input.bundle.edge_count.to_string()),
            ],
        }
    }
}
