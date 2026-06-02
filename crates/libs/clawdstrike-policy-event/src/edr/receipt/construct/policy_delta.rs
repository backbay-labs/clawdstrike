use super::super::*;

impl EndpointDecisionReceipt {
    #[must_use]
    pub fn for_policy_delta(input: EndpointPolicyDeltaReceiptInput<'_>) -> Self {
        let policy_delta_id = endpoint_policy_delta_id(EndpointPolicyDeltaIdInput {
            endpoint_id: input.endpoint_id,
            rule_id: input.rule_id,
            action: &input.action,
            staged_detection_id: input.staged_detection_id,
            stage: input.stage,
            generated_at: input.generated_at,
            simulation_id: input.simulation_id,
            graph_slice_id: input.graph_slice_id,
            root_node_id: input.root_node_id,
            source_affected_identity_context: input.source_affected_identity_context,
            source_affected_tool_context: input.source_affected_tool_context,
        });
        let has_actor = input.actor.is_some();
        let mut actor = input.actor.unwrap_or_default();
        actor.endpoint_id = input.endpoint_id.to_string();
        let actor_hash = endpoint_decision_actor_content_hash(&actor);
        let mut evidence = vec![
            EndpointReceiptEvidence::hashed("operation", input.operation),
            EndpointReceiptEvidence::hashed("policyDeltaId", &policy_delta_id),
            EndpointReceiptEvidence::hashed("stagedDetectionId", input.staged_detection_id),
            EndpointReceiptEvidence::hashed("stage", input.stage),
            EndpointReceiptEvidence::hashed("generatedAt", input.generated_at),
            EndpointReceiptEvidence::hashed("artifactHash", input.artifact_hash),
            EndpointReceiptEvidence::hashed("simulationId", input.simulation_id),
            EndpointReceiptEvidence::hashed("graphSliceId", input.graph_slice_id),
            EndpointReceiptEvidence::hashed("rootNodeId", input.root_node_id),
            EndpointReceiptEvidence::hashed(
                "sourceAffectedIdentityContext",
                input.source_affected_identity_context,
            ),
            EndpointReceiptEvidence::hashed(
                "sourceAffectedToolContext",
                input.source_affected_tool_context,
            ),
        ];
        if has_actor {
            evidence.push(EndpointReceiptEvidence::hashed("actorHash", actor_hash));
        }
        if let Some(previous_policy_hash) = input.previous_policy_hash {
            evidence.push(EndpointReceiptEvidence::hashed(
                "previousPolicyHash",
                previous_policy_hash,
            ));
        }
        if let Some(new_policy_hash) = input.new_policy_hash {
            evidence.push(EndpointReceiptEvidence::hashed(
                "newPolicyHash",
                new_policy_hash,
            ));
        }
        if let Some(backup_path) = input.backup_path {
            evidence.push(EndpointReceiptEvidence::hashed("backupPath", backup_path));
        }
        if let Some(cross_window_impact_hash) = input.cross_window_impact_hash {
            evidence.push(EndpointReceiptEvidence::hashed(
                "crossWindowImpactHash",
                cross_window_impact_hash,
            ));
        }
        if let Some(cross_window_recommendation_hash) = input.cross_window_recommendation_hash {
            evidence.push(EndpointReceiptEvidence::hashed(
                "crossWindowRecommendationHash",
                cross_window_recommendation_hash,
            ));
        }

        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::PolicyDelta,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor,
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: None,
                finding_id: Some(policy_delta_id),
                rule_id: Some(input.rule_id.to_string()),
                title: Some(format!("Endpoint staged policy delta {}", input.operation)),
                severity: None,
                confidence: None,
                action: input.action,
                passed: true,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: EndpointGraphReference {
                graph_slice_id: Some(input.graph_slice_id.to_string()),
                process_stable_key: None,
                process_node_id: Some(input.root_node_id.to_string()),
                parent_process_guid: None,
                content_hash: None,
                node_ids: vec![input.root_node_id.to_string()],
                edge_ids: Vec::new(),
            },
            evidence,
        }
    }
}
