use super::super::*;

impl EndpointDecisionReceipt {
    #[must_use]
    pub fn for_provider_degradation(input: EndpointProviderDegradationReceiptInput<'_>) -> Self {
        let provider_kind =
            camel_debug_to_snake(format!("{:?}", input.provider.provider_kind).as_str());
        let dropped_event_count = input.provider.dropped_event_count.to_string();
        let deadline_miss_count = input.provider.deadline_miss_count.to_string();
        let full_disk_access =
            endpoint_provider_full_disk_access_evidence_value(input.provider.full_disk_access);
        let reasons = input.provider.degradation_reasons.join("|");
        let degradation_id = provider_degradation_id_from_provider(
            input.endpoint_id,
            input.policy.policy_hash.as_str(),
            input.provider,
        );

        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::ProviderDegradation,
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
                finding_id: Some(degradation_id),
                rule_id: Some(format!(
                    "endpoint.provider_degradation.{}",
                    input.provider.provider_id
                )),
                title: Some("Endpoint provider degraded".to_string()),
                severity: None,
                confidence: None,
                action: EndpointDecisionAction::Observe,
                passed: false,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: EndpointGraphReference::default(),
            evidence: vec![
                EndpointReceiptEvidence::hashed("providerId", &input.provider.provider_id),
                EndpointReceiptEvidence::hashed("providerKind", provider_kind),
                EndpointReceiptEvidence::hashed("installed", input.provider.installed.to_string()),
                EndpointReceiptEvidence::hashed("active", input.provider.active.to_string()),
                EndpointReceiptEvidence::hashed("healthy", input.provider.healthy.to_string()),
                EndpointReceiptEvidence::hashed("degraded", input.provider.degraded.to_string()),
                EndpointReceiptEvidence::hashed("degradationReasons", reasons),
                EndpointReceiptEvidence::hashed("droppedEventCount", dropped_event_count),
                EndpointReceiptEvidence::hashed("deadlineMissCount", deadline_miss_count),
                EndpointReceiptEvidence::hashed("fullDiskAccess", full_disk_access),
            ],
        }
    }
}
