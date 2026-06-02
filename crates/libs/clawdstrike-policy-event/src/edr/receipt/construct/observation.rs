use super::super::*;

impl EndpointDecisionReceipt {
    #[must_use]
    pub fn for_observation(input: EndpointObservationReceiptInput<'_>) -> Self {
        let event_kind = input.observation.event_name();
        let observation_hash = endpoint_observation_content_hash(input.observation);
        let graph_ref = EndpointGraphReference::for_observation(input.observation, input.graph);
        let graph_slice_id = graph_ref.graph_slice_id.clone().unwrap_or_default();
        let process_node_id = graph_ref.process_node_id.clone().unwrap_or_default();
        let graph_content_hash = graph_ref.content_hash.clone().unwrap_or_default();
        let target = event_target_field(input.observation).unwrap_or_else(|| "unknown".to_string());
        let provider = input.sensor_state.providers.first();
        let provider_id = provider
            .map(|provider| provider.provider_id.clone())
            .unwrap_or_else(|| "unknown".to_string());
        let provider_kind = provider
            .map(|provider| camel_debug_to_snake(format!("{:?}", provider.provider_kind).as_str()))
            .unwrap_or_else(|| "unknown".to_string());
        let observation_receipt_id =
            observation_receipt_id_from_fields(ObservationReceiptIdFields {
                endpoint_id: input.endpoint_id,
                policy_hash: input.policy.policy_hash.as_str(),
                observation_id: input.observation.observation_id.as_str(),
                event_kind,
                observation_hash: observation_hash.as_str(),
                target: target.as_str(),
                graph_slice_id: graph_slice_id.as_str(),
                graph_content_hash: graph_content_hash.as_str(),
                process_node_id: process_node_id.as_str(),
                provider_id: provider_id.as_str(),
                provider_kind: provider_kind.as_str(),
            });

        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::Observation,
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
                observation_id: Some(input.observation.observation_id.clone()),
                finding_id: Some(observation_receipt_id),
                rule_id: Some(format!("endpoint.observation.{event_kind}")),
                title: Some("Endpoint provider observation recorded".to_string()),
                severity: None,
                confidence: Some(1.0),
                action: EndpointDecisionAction::Observe,
                passed: true,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: graph_ref,
            evidence: vec![
                EndpointReceiptEvidence::hashed(
                    "observationId",
                    input.observation.observation_id.as_str(),
                ),
                EndpointReceiptEvidence::hashed("eventKind", event_kind),
                EndpointReceiptEvidence::hashed("observationHash", observation_hash),
                EndpointReceiptEvidence::hashed("target", target),
                EndpointReceiptEvidence::hashed("graphSliceId", graph_slice_id),
                EndpointReceiptEvidence::hashed("contentHash", graph_content_hash),
                EndpointReceiptEvidence::hashed("processNodeId", process_node_id),
                EndpointReceiptEvidence::hashed("providerId", provider_id),
                EndpointReceiptEvidence::hashed("providerKind", provider_kind),
            ],
        }
    }
}
