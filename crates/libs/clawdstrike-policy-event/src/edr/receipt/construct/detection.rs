use super::super::*;

impl EndpointDecisionReceipt {
    #[must_use]
    pub fn for_detection(input: EndpointDetectionReceiptInput<'_>) -> Self {
        let graph_ref = EndpointGraphReference::for_observation(input.observation, input.graph);
        let mut evidence = vec![
            EndpointReceiptEvidence::hashed("detectionFindingId", &input.finding.finding_id),
            EndpointReceiptEvidence::hashed(
                "detectionObservationId",
                &input.finding.observation_id,
            ),
            EndpointReceiptEvidence::hashed("detectionRuleId", &input.finding.rule_id),
            EndpointReceiptEvidence::hashed("detectionTitle", &input.finding.title),
            EndpointReceiptEvidence::hashed(
                "detectionSeverity",
                detection_severity_label(&input.finding.severity),
            ),
            EndpointReceiptEvidence::hashed(
                "detectionConfidence",
                input.finding.confidence.to_string(),
            ),
        ];
        if let Some(graph_slice_id) = graph_ref.graph_slice_id.as_deref() {
            evidence.push(EndpointReceiptEvidence::hashed(
                "detectionGraphSliceId",
                graph_slice_id,
            ));
        }
        if let Some(graph_content_hash) = graph_ref.content_hash.as_deref() {
            evidence.push(EndpointReceiptEvidence::hashed(
                "detectionContentHash",
                graph_content_hash,
            ));
        }
        if let Some(process_node_id) = graph_ref.process_node_id.as_deref() {
            evidence.push(EndpointReceiptEvidence::hashed(
                "detectionProcessNodeId",
                process_node_id,
            ));
        }
        evidence.extend(
            input
                .finding
                .evidence
                .iter()
                .map(|item| EndpointReceiptEvidence::hashed(&item.key, &item.value)),
        );

        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::Detection,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor: EndpointDecisionActor::from_observation(input.endpoint_id, input.observation),
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: Some(input.finding.observation_id.clone()),
                finding_id: Some(input.finding.finding_id.clone()),
                rule_id: Some(input.finding.rule_id.clone()),
                title: Some(input.finding.title.clone()),
                severity: Some(input.finding.severity.clone()),
                confidence: Some(input.finding.confidence),
                action: EndpointDecisionAction::Alert,
                passed: false,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: graph_ref,
            evidence,
        }
    }
}
