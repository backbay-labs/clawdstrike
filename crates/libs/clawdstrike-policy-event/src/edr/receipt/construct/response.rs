use super::super::*;

impl EndpointDecisionReceipt {
    #[must_use]
    pub fn for_response_request(input: EndpointResponseReceiptInput<'_>) -> Self {
        let graph_ref = EndpointGraphReference::for_subgraph(&input.plan.root_node_id, input.graph);
        let actor = input.actor.with_endpoint_id_if_missing(input.endpoint_id);
        let actor_hash = endpoint_decision_actor_content_hash(&actor);
        let graph_content_hash = graph_ref.content_hash.clone();
        let mut evidence = vec![
            EndpointReceiptEvidence::hashed("responseActionId", &input.plan.action_id),
            EndpointReceiptEvidence::hashed("rootNodeId", &input.plan.root_node_id),
            EndpointReceiptEvidence::hashed("graphSliceId", &input.plan.graph_slice_id),
            EndpointReceiptEvidence::hashed("ttlSeconds", input.plan.ttl_seconds.to_string()),
            EndpointReceiptEvidence::hashed("rollbackRef", &input.plan.rollback_ref),
            EndpointReceiptEvidence::hashed("dryRun", input.plan.dry_run.to_string()),
            EndpointReceiptEvidence::hashed("reason", &input.plan.reason),
            EndpointReceiptEvidence::hashed("actorHash", actor_hash),
        ];
        if let Some(graph_content_hash) = graph_content_hash {
            evidence.push(EndpointReceiptEvidence::hashed(
                "contentHash",
                graph_content_hash,
            ));
        }
        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::ResponseRequest,
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
                finding_id: Some(input.plan.action_id.clone()),
                rule_id: Some(format!("endpoint.response.{}", input.plan.action.as_str())),
                title: Some(if input.plan.dry_run {
                    "Endpoint response action dry run planned".to_string()
                } else {
                    "Endpoint response action planned".to_string()
                }),
                severity: None,
                confidence: Some(1.0),
                action: input.plan.action.clone(),
                passed: true,
                ttl_seconds: Some(input.plan.ttl_seconds),
                rollback_ref: Some(input.plan.rollback_ref.clone()),
            },
            graph: graph_ref,
            evidence,
        }
    }

    #[must_use]
    pub fn for_response_execution(input: EndpointResponseExecutionReceiptInput<'_>) -> Self {
        let graph_ref =
            EndpointGraphReference::for_subgraph(&input.execution.root_node_id, input.graph);
        let actor = input.actor.with_endpoint_id_if_missing(input.endpoint_id);
        let actor_hash = endpoint_decision_actor_content_hash(&actor);
        let execution_actor_hash = input
            .execution
            .actor
            .as_ref()
            .map(endpoint_decision_actor_content_hash)
            .unwrap_or_else(|| actor_hash.clone());
        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::ResponseExecution,
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
                finding_id: Some(input.execution.execution_id.clone()),
                rule_id: Some(format!(
                    "endpoint.response_execution.{}",
                    input.execution.action.as_str()
                )),
                title: Some(
                    match input.execution.status {
                        EndpointResponseExecutionStatus::Succeeded => {
                            "Endpoint response action executed"
                        }
                        EndpointResponseExecutionStatus::Failed => {
                            "Endpoint response action failed"
                        }
                        EndpointResponseExecutionStatus::Partial => {
                            "Endpoint response action partially executed"
                        }
                        EndpointResponseExecutionStatus::RollbackPending => {
                            "Endpoint response rollback pending"
                        }
                        EndpointResponseExecutionStatus::RollbackFailed => {
                            "Endpoint response rollback failed"
                        }
                        EndpointResponseExecutionStatus::Expired => {
                            "Endpoint response action expired"
                        }
                        EndpointResponseExecutionStatus::Cancelled => {
                            "Endpoint response action cancelled"
                        }
                        EndpointResponseExecutionStatus::RolledBack => {
                            "Endpoint response action rolled back"
                        }
                    }
                    .to_string(),
                ),
                severity: None,
                confidence: Some(1.0),
                action: input.execution.action.clone(),
                passed: input.execution.status == EndpointResponseExecutionStatus::Succeeded,
                ttl_seconds: Some(input.execution.ttl_seconds),
                rollback_ref: Some(input.execution.rollback_ref.clone()),
            },
            graph: graph_ref,
            evidence: {
                let mut evidence = vec![
                    EndpointReceiptEvidence::hashed("responseActionId", &input.execution.action_id),
                    EndpointReceiptEvidence::hashed("executionId", &input.execution.execution_id),
                    EndpointReceiptEvidence::hashed("rootNodeId", &input.execution.root_node_id),
                    EndpointReceiptEvidence::hashed(
                        "graphSliceId",
                        &input.execution.graph_slice_id,
                    ),
                    EndpointReceiptEvidence::hashed(
                        "ttlSeconds",
                        input.execution.ttl_seconds.to_string(),
                    ),
                    EndpointReceiptEvidence::hashed("rollbackRef", &input.execution.rollback_ref),
                    EndpointReceiptEvidence::hashed(
                        "executionStatus",
                        input.execution.status.as_str(),
                    ),
                    EndpointReceiptEvidence::hashed("dryRun", input.execution.dry_run.to_string()),
                    EndpointReceiptEvidence::hashed(
                        "evidenceBundleId",
                        &input.execution.evidence_bundle.bundle_id,
                    ),
                    EndpointReceiptEvidence::hashed(
                        "evidenceBundleContentHash",
                        &input.execution.evidence_bundle.content_hash,
                    ),
                    EndpointReceiptEvidence::hashed("reason", &input.execution.reason),
                    EndpointReceiptEvidence::hashed(
                        "effectCount",
                        input.execution.effects.len().to_string(),
                    ),
                    EndpointReceiptEvidence::hashed("actorHash", actor_hash),
                    EndpointReceiptEvidence::hashed("executionActorHash", execution_actor_hash),
                ];
                for effect in &input.execution.effects {
                    evidence.push(EndpointReceiptEvidence::hashed(
                        format!("executionEffect:{}", effect.effect_id),
                        response_effect_evidence_value(effect),
                    ));
                    evidence.push(EndpointReceiptEvidence::hashed(
                        format!("executionEffectType:{}", effect.effect_id),
                        &effect.effect_type,
                    ));
                }
                evidence
            },
        }
    }

    #[must_use]
    pub fn for_response_rollback(input: EndpointResponseRollbackReceiptInput<'_>) -> Self {
        let graph_ref =
            EndpointGraphReference::for_subgraph(&input.rollback.root_node_id, input.graph);
        let actor = input.actor.with_endpoint_id_if_missing(input.endpoint_id);
        let actor_hash = endpoint_decision_actor_content_hash(&actor);
        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::ResponseRollback,
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
                finding_id: Some(input.rollback.rollback_id.clone()),
                rule_id: Some(format!(
                    "endpoint.response_rollback.{}",
                    input.rollback.action.as_str()
                )),
                title: Some("Endpoint response rollback executed".to_string()),
                severity: None,
                confidence: Some(1.0),
                action: input.rollback.action.clone(),
                passed: input.rollback.status == EndpointResponseExecutionStatus::Succeeded,
                ttl_seconds: Some(input.rollback.ttl_seconds),
                rollback_ref: Some(input.rollback.rollback_ref.clone()),
            },
            graph: graph_ref,
            evidence: {
                let mut evidence = vec![
                    EndpointReceiptEvidence::hashed("rollbackId", &input.rollback.rollback_id),
                    EndpointReceiptEvidence::hashed("executionId", &input.rollback.execution_id),
                    EndpointReceiptEvidence::hashed("responseActionId", &input.rollback.action_id),
                    EndpointReceiptEvidence::hashed("rootNodeId", &input.rollback.root_node_id),
                    EndpointReceiptEvidence::hashed("graphSliceId", &input.rollback.graph_slice_id),
                    EndpointReceiptEvidence::hashed(
                        "ttlSeconds",
                        input.rollback.ttl_seconds.to_string(),
                    ),
                    EndpointReceiptEvidence::hashed("rollbackRef", &input.rollback.rollback_ref),
                    EndpointReceiptEvidence::hashed(
                        "rollbackStatus",
                        input.rollback.status.as_str(),
                    ),
                    EndpointReceiptEvidence::hashed("reason", &input.rollback.reason),
                    EndpointReceiptEvidence::hashed(
                        "effectCount",
                        input.rollback.effects.len().to_string(),
                    ),
                    EndpointReceiptEvidence::hashed("actorHash", actor_hash),
                ];
                for effect in &input.rollback.effects {
                    evidence.push(EndpointReceiptEvidence::hashed(
                        format!("rollbackEffect:{}", effect.effect_id),
                        response_effect_evidence_value(effect),
                    ));
                    evidence.push(EndpointReceiptEvidence::hashed(
                        format!("rollbackEffectType:{}", effect.effect_id),
                        &effect.effect_type,
                    ));
                }
                evidence
            },
        }
    }

    #[must_use]
    pub fn for_response_acknowledgement(
        input: EndpointResponseAcknowledgementReceiptInput<'_>,
    ) -> Self {
        let graph_ref =
            EndpointGraphReference::for_subgraph(&input.acknowledgement.root_node_id, input.graph);
        let mut actor = input.actor.with_endpoint_id_if_missing(input.endpoint_id);
        actor.agent_id = Some(input.acknowledgement.acknowledged_by.clone());
        let actor_hash = endpoint_decision_actor_content_hash(&actor);
        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::ResponseAcknowledgement,
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
                finding_id: Some(input.acknowledgement.acknowledgement_id.clone()),
                rule_id: Some(format!(
                    "endpoint.response_acknowledgement.{}",
                    input.acknowledgement.action.as_str()
                )),
                title: Some(format!(
                    "Endpoint response execution acknowledged: {}",
                    input.acknowledgement.status.as_str()
                )),
                severity: None,
                confidence: Some(1.0),
                action: input.acknowledgement.action.clone(),
                passed: true,
                ttl_seconds: Some(input.acknowledgement.ttl_seconds),
                rollback_ref: Some(input.acknowledgement.rollback_ref.clone()),
            },
            graph: graph_ref,
            evidence: {
                let mut evidence = vec![
                    EndpointReceiptEvidence::hashed(
                        "acknowledgementId",
                        &input.acknowledgement.acknowledgement_id,
                    ),
                    EndpointReceiptEvidence::hashed(
                        "executionId",
                        &input.acknowledgement.execution_id,
                    ),
                    EndpointReceiptEvidence::hashed(
                        "responseActionId",
                        &input.acknowledgement.action_id,
                    ),
                    EndpointReceiptEvidence::hashed(
                        "rootNodeId",
                        &input.acknowledgement.root_node_id,
                    ),
                    EndpointReceiptEvidence::hashed(
                        "graphSliceId",
                        &input.acknowledgement.graph_slice_id,
                    ),
                    EndpointReceiptEvidence::hashed(
                        "ttlSeconds",
                        input.acknowledgement.ttl_seconds.to_string(),
                    ),
                    EndpointReceiptEvidence::hashed(
                        "rollbackRef",
                        &input.acknowledgement.rollback_ref,
                    ),
                    EndpointReceiptEvidence::hashed(
                        "acknowledgedStatus",
                        input.acknowledgement.status.as_str(),
                    ),
                    EndpointReceiptEvidence::hashed(
                        "acknowledgedBy",
                        &input.acknowledgement.acknowledged_by,
                    ),
                    EndpointReceiptEvidence::hashed(
                        "effectCount",
                        input.acknowledgement.effects.len().to_string(),
                    ),
                    EndpointReceiptEvidence::hashed("actorHash", actor_hash),
                ];
                if let Some(note) = &input.acknowledgement.note {
                    evidence.push(EndpointReceiptEvidence::hashed("note", note));
                }
                if let Some(control) = &input.acknowledgement.control_correlation {
                    evidence.push(EndpointReceiptEvidence::hashed(
                        "controlResponseActionId",
                        &control.response_action_id,
                    ));
                    if let Some(delivery_id) = &control.delivery_id {
                        evidence.push(EndpointReceiptEvidence::hashed(
                            "controlDeliveryId",
                            delivery_id,
                        ));
                    }
                    evidence.push(EndpointReceiptEvidence::hashed(
                        "controlTargetKind",
                        &control.target_kind,
                    ));
                    evidence.push(EndpointReceiptEvidence::hashed(
                        "controlTargetId",
                        &control.target_id,
                    ));
                    evidence.push(EndpointReceiptEvidence {
                        key: "controlAckTokenHash".to_string(),
                        value_hash: control.ack_token_hash.clone(),
                        redaction_class: EndpointEvidenceRedactionClass::HashOnly,
                        raw_value: None,
                    });
                    evidence.push(EndpointReceiptEvidence::hashed(
                        "controlAckStatus",
                        &control.ack_status,
                    ));
                    if let Some(resulting_state) = &control.resulting_state {
                        evidence.push(EndpointReceiptEvidence::hashed(
                            "controlResultingState",
                            resulting_state,
                        ));
                    }
                }
                for effect in &input.acknowledgement.effects {
                    evidence.push(EndpointReceiptEvidence::hashed(
                        format!("acknowledgementEffect:{}", effect.effect_id),
                        response_effect_evidence_value(effect),
                    ));
                    evidence.push(EndpointReceiptEvidence::hashed(
                        format!("acknowledgementEffectType:{}", effect.effect_id),
                        &effect.effect_type,
                    ));
                }
                evidence
            },
        }
    }
}
