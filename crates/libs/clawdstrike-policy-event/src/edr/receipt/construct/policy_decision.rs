use super::super::*;

impl EndpointDecisionReceipt {
    #[must_use]
    pub fn for_policy_decision(input: EndpointPolicyDecisionReceiptInput<'_>) -> Self {
        let allowed_text = input.allowed.to_string();
        let guard = input.guard.unwrap_or("none");
        let actor_hash = endpoint_decision_actor_content_hash(&input.actor);
        let actor_session_id = policy_decision_actor_session_value(&input.actor);
        let policy_epoch = input.policy.policy_epoch.to_string();
        let graph_ref = EndpointGraphReference::for_observation(input.observation, input.graph);
        let decision_id = policy_decision_id_from_fields(PolicyDecisionIdFields {
            endpoint_id: input.actor.endpoint_id.as_str(),
            policy_hash: input.policy.policy_hash.as_str(),
            policy_epoch: input.policy.policy_epoch,
            actor_hash: actor_hash.as_str(),
            actor_session_id: actor_session_id.as_str(),
            action_type: input.action_type,
            target: input.target,
            allowed: input.allowed,
            guard,
        });
        let mut evidence = vec![
            EndpointReceiptEvidence::hashed("actionType", input.action_type),
            EndpointReceiptEvidence::hashed("target", input.target),
            EndpointReceiptEvidence::hashed("allowed", allowed_text),
            EndpointReceiptEvidence::hashed("guard", guard),
            EndpointReceiptEvidence::hashed("actorHash", actor_hash),
            EndpointReceiptEvidence::hashed("actorSessionId", actor_session_id),
            EndpointReceiptEvidence::hashed("policyEpoch", policy_epoch),
            EndpointReceiptEvidence::hashed(
                "observationId",
                input.observation.observation_id.clone(),
            ),
        ];
        if let Some(graph_slice_id) = graph_ref.graph_slice_id.as_deref() {
            evidence.push(EndpointReceiptEvidence::hashed(
                "graphSliceId",
                graph_slice_id,
            ));
        }
        if let Some(content_hash) = graph_ref.content_hash.as_deref() {
            evidence.push(EndpointReceiptEvidence::hashed("contentHash", content_hash));
        }
        if let Some(process_node_id) = graph_ref.process_node_id.as_deref() {
            evidence.push(EndpointReceiptEvidence::hashed(
                "processNodeId",
                process_node_id,
            ));
        }
        if let Some(severity_label) = input.severity_label {
            evidence.push(EndpointReceiptEvidence::hashed("severity", severity_label));
        }
        if let Some(message) = input.message {
            evidence.push(EndpointReceiptEvidence::hashed("message", message));
        }
        if let Some(details) = input.details {
            if let Ok(canonical_details) = canonicalize_json(details) {
                evidence.push(EndpointReceiptEvidence::hashed(
                    "details",
                    canonical_details,
                ));
            }
        }

        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::PolicyDecision,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor: input.actor,
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: Some(input.observation.observation_id.clone()),
                finding_id: Some(decision_id),
                rule_id: Some(format!("endpoint.policy_decision.{}", input.action_type)),
                title: Some(if input.allowed {
                    "Endpoint policy decision allowed".to_string()
                } else {
                    "Endpoint policy decision blocked".to_string()
                }),
                severity: input.severity,
                confidence: Some(1.0),
                action: if input.allowed {
                    EndpointDecisionAction::Allow
                } else {
                    EndpointDecisionAction::Block
                },
                passed: input.allowed,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: graph_ref,
            evidence,
        }
    }
}
