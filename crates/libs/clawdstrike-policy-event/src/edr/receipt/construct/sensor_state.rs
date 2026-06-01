use super::super::*;

impl EndpointDecisionReceipt {
    #[must_use]
    pub fn for_sensor_state(input: EndpointSensorStateReceiptInput<'_>) -> Self {
        let provider_count = input.sensor_state.providers.len();
        let active_provider_count = input
            .sensor_state
            .providers
            .iter()
            .filter(|provider| provider.active)
            .count();
        let healthy_provider_count = input
            .sensor_state
            .providers
            .iter()
            .filter(|provider| provider.healthy)
            .count();
        let degraded_provider_count = input
            .sensor_state
            .providers
            .iter()
            .filter(|provider| provider.degraded)
            .count();
        let provider_ids = input
            .sensor_state
            .providers
            .iter()
            .map(|provider| provider.provider_id.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let policy_epoch = input.policy.policy_epoch.to_string();
        let provider_count_text = provider_count.to_string();
        let active_count_text = active_provider_count.to_string();
        let healthy_count_text = healthy_provider_count.to_string();
        let degraded_count_text = degraded_provider_count.to_string();
        let sensor_state_hash = endpoint_sensor_state_content_hash(&input.sensor_state);
        let sensor_state_id = stable_id(
            "sensor_state",
            [
                input.endpoint_id,
                input.policy.policy_hash.as_str(),
                policy_epoch.as_str(),
                provider_count_text.as_str(),
                active_count_text.as_str(),
                healthy_count_text.as_str(),
                degraded_count_text.as_str(),
                provider_ids.as_str(),
                sensor_state_hash.as_str(),
            ],
        );

        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::SensorState,
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
                finding_id: Some(sensor_state_id),
                rule_id: Some("endpoint.sensor_state".to_string()),
                title: Some("Endpoint sensor and protection state captured".to_string()),
                severity: None,
                confidence: None,
                action: EndpointDecisionAction::Observe,
                passed: provider_count > 0 && healthy_provider_count == provider_count,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: EndpointGraphReference::default(),
            evidence: vec![
                EndpointReceiptEvidence::hashed("reason", input.reason),
                EndpointReceiptEvidence::hashed("providerCount", provider_count_text),
                EndpointReceiptEvidence::hashed("activeProviderCount", active_count_text),
                EndpointReceiptEvidence::hashed("healthyProviderCount", healthy_count_text),
                EndpointReceiptEvidence::hashed("degradedProviderCount", degraded_count_text),
                EndpointReceiptEvidence::hashed("providerIds", provider_ids),
                EndpointReceiptEvidence::hashed("sensorStateHash", sensor_state_hash),
            ],
        }
    }
}
