use super::super::*;

impl EndpointDecisionReceipt {
    #[must_use]
    pub fn for_policy_event_replay(input: EndpointPolicyEventReplayReceiptInput<'_>) -> Self {
        let replay_id = endpoint_policy_event_replay_id(EndpointPolicyEventReplayIdInput {
            policy_hash: input.policy.policy_hash.as_str(),
            policy_epoch: input.policy.policy_epoch,
            event_source: input.event_source,
            event_stream_hash: input.event_stream_hash,
            result_hash: input.result_hash,
            event_count: input.event_count,
            allowed_count: input.allowed_count,
            warn_count: input.warn_count,
            blocked_count: input.blocked_count,
            track_posture: input.track_posture,
        });
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
                finding_id: Some(replay_id.clone()),
                rule_id: Some("endpoint.policy_event_replay".to_string()),
                title: Some("Endpoint policy event replay".to_string()),
                severity: None,
                confidence: None,
                action: EndpointDecisionAction::Observe,
                passed: true,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: EndpointGraphReference {
                graph_slice_id: Some(replay_id.clone()),
                process_stable_key: None,
                process_node_id: Some("policy_event_stream".to_string()),
                parent_process_guid: None,
                content_hash: None,
                node_ids: vec!["policy_event_stream".to_string()],
                edge_ids: Vec::new(),
            },
            evidence: vec![
                EndpointReceiptEvidence::hashed("replayId", replay_id),
                EndpointReceiptEvidence::hashed("eventSource", input.event_source),
                EndpointReceiptEvidence::hashed("eventStreamHash", input.event_stream_hash),
                EndpointReceiptEvidence::hashed("resultHash", input.result_hash),
                EndpointReceiptEvidence::hashed("eventCount", input.event_count.to_string()),
                EndpointReceiptEvidence::hashed("allowedCount", input.allowed_count.to_string()),
                EndpointReceiptEvidence::hashed("warnCount", input.warn_count.to_string()),
                EndpointReceiptEvidence::hashed("blockedCount", input.blocked_count.to_string()),
                EndpointReceiptEvidence::hashed("trackPosture", input.track_posture.to_string()),
            ],
        }
    }

    #[must_use]
    pub fn for_policy_event_impact(input: EndpointPolicyEventImpactReceiptInput<'_>) -> Self {
        let impact_id = endpoint_policy_event_impact_id(EndpointPolicyEventImpactIdInput {
            current_policy_hash: input.policy.policy_hash.as_str(),
            current_policy_epoch: input.policy.policy_epoch,
            proposed_policy_hash: input.proposed_policy_hash,
            proposed_policy_epoch: input.proposed_policy_epoch,
            event_source: input.event_source,
            event_stream_hash: input.event_stream_hash,
            current_result_hash: input.current_result_hash,
            proposed_result_hash: input.proposed_result_hash,
            impact_hash: input.impact_hash,
            event_count: input.event_count,
            changed_count: input.changed_count,
            allow_to_block_count: input.allow_to_block_count,
            track_posture: input.track_posture,
        });
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
                finding_id: Some(impact_id.clone()),
                rule_id: Some("endpoint.policy_event_impact".to_string()),
                title: Some("Endpoint policy event impact analysis".to_string()),
                severity: None,
                confidence: None,
                action: EndpointDecisionAction::Observe,
                passed: true,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: EndpointGraphReference {
                graph_slice_id: Some(impact_id.clone()),
                process_stable_key: None,
                process_node_id: Some("policy_event_stream".to_string()),
                parent_process_guid: None,
                content_hash: None,
                node_ids: vec!["policy_event_stream".to_string()],
                edge_ids: Vec::new(),
            },
            evidence: vec![
                EndpointReceiptEvidence::hashed("impactId", impact_id),
                EndpointReceiptEvidence::hashed("eventSource", input.event_source),
                EndpointReceiptEvidence::hashed("eventStreamHash", input.event_stream_hash),
                EndpointReceiptEvidence::hashed("currentResultHash", input.current_result_hash),
                EndpointReceiptEvidence::hashed("proposedResultHash", input.proposed_result_hash),
                EndpointReceiptEvidence::hashed("impactHash", input.impact_hash),
                EndpointReceiptEvidence::hashed("proposedPolicyHash", input.proposed_policy_hash),
                EndpointReceiptEvidence::hashed(
                    "proposedPolicyEpoch",
                    input.proposed_policy_epoch.to_string(),
                ),
                EndpointReceiptEvidence::hashed("eventCount", input.event_count.to_string()),
                EndpointReceiptEvidence::hashed("changedCount", input.changed_count.to_string()),
                EndpointReceiptEvidence::hashed(
                    "allowToBlockCount",
                    input.allow_to_block_count.to_string(),
                ),
                EndpointReceiptEvidence::hashed("trackPosture", input.track_posture.to_string()),
            ],
        }
    }
}
