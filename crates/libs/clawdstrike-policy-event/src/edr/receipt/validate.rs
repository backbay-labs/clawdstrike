use anyhow::{anyhow, Context, Result};
use hush_core::Hash;

use super::*;

impl EndpointDecisionReceipt {
    pub fn validate(&self) -> Result<()> {
        require_field_eq(
            self.schema_version.as_str(),
            ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION,
            "endpoint decision receipt schema version",
        )?;
        require_nonempty(self.actor.endpoint_id.as_str(), "endpoint id")?;
        require_nonzero(self.local_sequence, "local sequence")?;
        require_nonempty(
            self.signer.signer_identity.as_str(),
            "endpoint receipt signer identity",
        )?;
        require_nonempty(self.policy.policy_version.as_str(), "policy version")?;
        require_nonempty(self.policy.policy_hash.as_str(), "policy hash")?;
        Hash::from_hex(self.policy.policy_hash.as_str())
            .with_context(|| "policy hash must be a 32-byte hex hash")?;
        require_nonzero(self.policy.policy_epoch, "policy epoch")?;
        require_nonempty(self.clock.source.as_str(), "clock source")?;
        if self.sensor_state.providers.is_empty() {
            return Err(anyhow!(
                "endpoint receipt requires at least one sensor state"
            ));
        }
        let mut provider_ids = BTreeSet::new();
        for provider in &self.sensor_state.providers {
            require_nonempty(provider.provider_id.as_str(), "sensor provider id")?;
            if !provider_ids.insert(provider.provider_id.as_str()) {
                return Err(anyhow!(
                    "duplicate sensor provider id {}",
                    provider.provider_id
                ));
            }
            require_provider_last_seen_consistency(provider, &self.clock.captured_at)?;
            require_provider_degradation_consistency(provider)?;
            if provider.degraded && provider.degradation_reasons.is_empty() {
                return Err(anyhow!(
                    "degraded sensor provider {} requires a degradation reason",
                    provider.provider_id
                ));
            }
            if provider.degraded {
                for reason in &provider.degradation_reasons {
                    require_nonempty(reason.as_str(), "sensor provider degradation reason")?;
                }
            }
        }
        require_receipt_evidence(&self.evidence)?;
        if let Some(confidence) = self.decision.confidence {
            if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
                return Err(anyhow!("decision confidence must be between 0.0 and 1.0"));
            }
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::SensorState {
            require_optional_nonempty(self.decision.finding_id.as_deref(), "sensor state id")?;
            require_optional_nonempty(self.decision.rule_id.as_deref(), "sensor state rule id")?;
            if self.decision.action != EndpointDecisionAction::Observe {
                return Err(anyhow!("sensor state receipt action must be observe"));
            }
            require_sensor_state_evidence(
                &self.evidence,
                &self.decision,
                &self.actor,
                &self.policy,
                &self.sensor_state,
            )?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::PrivacyReport {
            require_optional_nonempty(self.decision.finding_id.as_deref(), "privacy report id")?;
            require_optional_nonempty(self.decision.rule_id.as_deref(), "privacy report rule id")?;
            if self.decision.action != EndpointDecisionAction::Observe {
                return Err(anyhow!("privacy report receipt action must be observe"));
            }
            require_privacy_report_evidence(&self.evidence, self.decision.finding_id.as_deref())?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::ProviderDegradation {
            require_optional_nonempty(
                self.decision.finding_id.as_deref(),
                "provider degradation id",
            )?;
            require_optional_nonempty(
                self.decision.rule_id.as_deref(),
                "provider degradation rule id",
            )?;
            if self
                .sensor_state
                .providers
                .iter()
                .all(|provider| !provider.degraded)
            {
                return Err(anyhow!(
                    "provider degradation receipt requires a degraded provider"
                ));
            }
            require_provider_degradation_evidence(
                &self.evidence,
                self.decision.finding_id.as_deref(),
                self.decision.rule_id.as_deref(),
                &self.actor,
                &self.policy,
                &self.sensor_state,
            )?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::Observation {
            require_optional_nonempty(self.decision.observation_id.as_deref(), "observation id")?;
            require_optional_nonempty(
                self.decision.finding_id.as_deref(),
                "observation receipt id",
            )?;
            require_optional_nonempty(
                self.decision.rule_id.as_deref(),
                "observation receipt rule id",
            )?;
            require_confidence(self.decision.confidence, "observation receipt confidence")?;
            require_optional_nonempty(self.graph.graph_slice_id.as_deref(), "graph slice id")?;
            require_optional_nonempty(self.graph.process_node_id.as_deref(), "process node id")?;
            if self.decision.action != EndpointDecisionAction::Observe {
                return Err(anyhow!("observation receipt action must be observe"));
            }
            if !self.decision.passed {
                return Err(anyhow!("observation receipt must pass"));
            }
            require_observation_evidence(
                &self.evidence,
                &self.decision,
                &self.actor,
                &self.policy,
                &self.sensor_state,
                &self.graph,
            )?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::PolicyDecision {
            require_optional_nonempty(self.decision.finding_id.as_deref(), "policy decision id")?;
            require_optional_nonempty(self.decision.rule_id.as_deref(), "policy decision rule id")?;
            if !matches!(
                self.decision.action,
                EndpointDecisionAction::Allow | EndpointDecisionAction::Block
            ) {
                return Err(anyhow!(
                    "policy decision receipt action must be allow or block"
                ));
            }
            match self.decision.action {
                EndpointDecisionAction::Allow if !self.decision.passed => {
                    return Err(anyhow!("policy decision allow action must pass"));
                }
                EndpointDecisionAction::Block if self.decision.passed => {
                    return Err(anyhow!("policy decision block action must fail"));
                }
                _ => {}
            }
            require_policy_decision_evidence(
                &self.evidence,
                &self.decision,
                &self.actor,
                &self.policy,
                &self.graph,
            )?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::PolicyDelta {
            require_optional_nonempty(self.decision.finding_id.as_deref(), "policy delta id")?;
            require_optional_nonempty(self.decision.rule_id.as_deref(), "policy delta rule id")?;
            require_optional_nonempty(self.graph.graph_slice_id.as_deref(), "graph slice id")?;
            require_optional_nonempty(
                self.graph.process_node_id.as_deref(),
                "policy delta root node id",
            )?;
            require_policy_delta_graph_reference(&self.graph)?;
            require_policy_delta_evidence(
                &self.evidence,
                &self.decision,
                &self.actor,
                &self.policy,
                self.graph.graph_slice_id.as_deref(),
                self.graph.process_node_id.as_deref(),
            )?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::GraphSlice {
            require_optional_nonempty(self.decision.finding_id.as_deref(), "graph slice id")?;
            require_optional_nonempty(self.decision.rule_id.as_deref(), "graph slice rule id")?;
            require_optional_nonempty(self.graph.graph_slice_id.as_deref(), "graph slice id")?;
            require_optional_nonempty(
                self.graph.process_node_id.as_deref(),
                "graph slice root node id",
            )?;
            require_subgraph_reference(&self.graph, "graph slice")?;
            require_graph_slice_evidence(
                &self.evidence,
                self.decision.finding_id.as_deref(),
                self.graph.graph_slice_id.as_deref(),
                self.graph.process_node_id.as_deref(),
                self.graph.node_ids.len(),
                self.graph.edge_ids.len(),
            )?;
            require_graph_slice_content_hash_evidence(
                &self.evidence,
                self.graph.content_hash.as_deref(),
            )?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::Detection {
            require_optional_nonempty(
                self.decision.observation_id.as_deref(),
                "detection observation id",
            )?;
            require_optional_nonempty(self.decision.finding_id.as_deref(), "detection finding id")?;
            require_optional_nonempty(self.decision.rule_id.as_deref(), "detection rule id")?;
            require_confidence(self.decision.confidence, "detection confidence")?;
            require_optional_nonempty(self.graph.graph_slice_id.as_deref(), "graph slice id")?;
            require_optional_nonempty(self.graph.process_node_id.as_deref(), "process node id")?;
            if self.decision.action != EndpointDecisionAction::Alert {
                return Err(anyhow!("detection receipt action must be alert"));
            }
            if self.decision.passed {
                return Err(anyhow!("detection receipt must fail the decision gate"));
            }
            require_detection_evidence(&self.evidence, &self.decision, &self.graph)?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::EvidenceBundleManifest {
            require_optional_nonempty(self.decision.finding_id.as_deref(), "evidence bundle id")?;
            require_optional_nonempty(self.decision.rule_id.as_deref(), "evidence bundle rule id")?;
            require_optional_nonempty(self.graph.graph_slice_id.as_deref(), "graph slice id")?;
            require_optional_nonempty(self.graph.process_node_id.as_deref(), "process node id")?;
            require_subgraph_reference(&self.graph, "evidence bundle")?;
            require_evidence_bundle_manifest_evidence(
                &self.evidence,
                self.decision.finding_id.as_deref(),
                self.graph.graph_slice_id.as_deref(),
                self.graph.content_hash.as_deref(),
                self.graph.node_ids.len(),
                self.graph.edge_ids.len(),
            )?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::Simulation {
            require_optional_nonempty(self.decision.finding_id.as_deref(), "simulation id")?;
            require_optional_nonempty(self.decision.rule_id.as_deref(), "simulation rule id")?;
            require_optional_nonempty(self.graph.graph_slice_id.as_deref(), "graph slice id")?;
            require_optional_nonempty(
                self.graph.process_node_id.as_deref(),
                "simulation root node id",
            )?;
            require_simulation_evidence(&self.evidence, &self.decision, &self.graph, &self.policy)?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::DeceptionMaterialization {
            require_optional_nonempty(
                self.decision.finding_id.as_deref(),
                "deception materialization id",
            )?;
            require_optional_nonempty(
                self.decision.rule_id.as_deref(),
                "deception materialization rule id",
            )?;
            if self.decision.action != EndpointDecisionAction::Observe {
                return Err(anyhow!(
                    "deception materialization receipt action must be observe"
                ));
            }
            require_deception_materialization_evidence(
                &self.evidence,
                &self.actor,
                &self.policy,
                self.decision.finding_id.as_deref(),
            )?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::DeceptionCleanup {
            require_optional_nonempty(self.decision.finding_id.as_deref(), "deception cleanup id")?;
            require_optional_nonempty(
                self.decision.rule_id.as_deref(),
                "deception cleanup rule id",
            )?;
            if self.decision.action != EndpointDecisionAction::Observe {
                return Err(anyhow!("deception cleanup receipt action must be observe"));
            }
            require_deception_cleanup_evidence(
                &self.evidence,
                &self.decision,
                &self.actor,
                &self.policy,
                self.decision.finding_id.as_deref(),
            )?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::DeceptionRotation {
            require_optional_nonempty(
                self.decision.finding_id.as_deref(),
                "deception rotation id",
            )?;
            require_optional_nonempty(
                self.decision.rule_id.as_deref(),
                "deception rotation rule id",
            )?;
            if self.decision.action != EndpointDecisionAction::Observe {
                return Err(anyhow!("deception rotation receipt action must be observe"));
            }
            require_deception_rotation_evidence(
                &self.evidence,
                &self.decision,
                &self.actor,
                &self.policy,
                self.decision.finding_id.as_deref(),
            )?;
        }
        if matches!(
            self.receipt_family,
            EndpointDecisionReceiptFamily::ResponseRequest
                | EndpointDecisionReceiptFamily::ResponseExecution
                | EndpointDecisionReceiptFamily::ResponseRollback
                | EndpointDecisionReceiptFamily::ResponseAcknowledgement
        ) {
            require_optional_nonempty(self.decision.finding_id.as_deref(), "response action id")?;
            require_optional_nonempty(self.decision.rule_id.as_deref(), "response rule id")?;
            require_optional_nonempty(self.graph.graph_slice_id.as_deref(), "graph slice id")?;
            require_optional_nonempty(
                self.graph.process_node_id.as_deref(),
                "response root node id",
            )?;
            require_response_action_for_family(&self.receipt_family, &self.decision)?;
            require_confidence(self.decision.confidence, "response confidence")?;
            require_response_actor_context(&self.actor)?;
            require_response_actor_evidence(&self.actor, &self.evidence)?;
            require_optional_nonempty(self.decision.rollback_ref.as_deref(), "rollback ref")?;
            match self.decision.ttl_seconds {
                Some(ttl) if ttl > 0 => {}
                _ => return Err(anyhow!("response ttl seconds is required")),
            }
            require_subgraph_reference(&self.graph, "response")?;
            if self.receipt_family == EndpointDecisionReceiptFamily::ResponseRequest {
                require_response_request_receipt_evidence(
                    &self.decision,
                    &self.evidence,
                    self.graph.process_node_id.as_deref().unwrap_or_default(),
                    self.graph.graph_slice_id.as_deref().unwrap_or_default(),
                    self.graph.content_hash.as_deref(),
                    self.decision.ttl_seconds.unwrap_or_default(),
                    self.decision.rollback_ref.as_deref().unwrap_or_default(),
                )?;
            } else {
                require_response_receipt_evidence(
                    &self.evidence,
                    &self.decision.action,
                    self.graph.process_node_id.as_deref().unwrap_or_default(),
                    self.graph.graph_slice_id.as_deref().unwrap_or_default(),
                    self.decision.ttl_seconds.unwrap_or_default(),
                    self.decision.rollback_ref.as_deref().unwrap_or_default(),
                )?;
            }
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::ResponseRequest {
            require_response_request_dry_run_evidence(&self.decision, &self.evidence)?;
            require_response_reason_evidence(&self.evidence)?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::ResponseExecution {
            require_response_execution_id_evidence(
                &self.evidence,
                &self.decision,
                self.graph.graph_slice_id.as_deref().unwrap_or_default(),
                self.graph.content_hash.as_deref(),
            )?;
            require_response_execution_status_evidence(&self.decision, &self.evidence)?;
            require_response_reason_evidence(&self.evidence)?;
            require_response_execution_evidence_bundle_evidence(
                &self.evidence,
                &self.decision,
                self.graph.graph_slice_id.as_deref().unwrap_or_default(),
                self.graph.content_hash.as_deref(),
            )?;
            require_response_execution_dry_run_evidence(&self.evidence)?;
            require_response_execution_actor_evidence(&self.evidence)?;
            require_response_effect_count_evidence(
                &self.evidence,
                "executionEffect:",
                "execution effect count evidence",
            )?;
            require_response_effect_evidence_hashes(
                &self.evidence,
                "executionEffect:",
                "execution effect evidence",
            )?;
            require_response_execution_effect_type_evidence(&self.decision, &self.evidence)?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::ResponseRollback {
            require_response_family_id_evidence(
                &self.evidence,
                "rollbackId",
                self.decision.finding_id.as_deref(),
                "rollback id evidence",
            )?;
            require_response_rollback_status_evidence(&self.decision, &self.evidence)?;
            require_response_reason_evidence(&self.evidence)?;
            let rollback_ref = self.decision.rollback_ref.as_deref().unwrap_or_default();
            let response_action_id =
                response_action_id_from_rollback_ref(&self.decision.action, rollback_ref)?;
            require_response_rollback_execution_id_evidence(
                &self.evidence,
                self.decision.finding_id.as_deref(),
                response_action_id.as_str(),
                rollback_ref,
            )?;
            require_response_effect_count_evidence(
                &self.evidence,
                "rollbackEffect:",
                "rollback effect count evidence",
            )?;
            require_response_effect_evidence_hashes(
                &self.evidence,
                "rollbackEffect:",
                "rollback effect evidence",
            )?;
            require_response_rollback_effect_type_evidence(&self.decision, &self.evidence)?;
        }
        if self.receipt_family == EndpointDecisionReceiptFamily::ResponseAcknowledgement {
            require_response_family_id_evidence(
                &self.evidence,
                "acknowledgementId",
                self.decision.finding_id.as_deref(),
                "acknowledgement id evidence",
            )?;
            require_response_acknowledgement_status_evidence(&self.decision, &self.evidence)?;
            require_response_acknowledged_by_evidence(&self.actor, &self.evidence)?;
            let rollback_ref = self.decision.rollback_ref.as_deref().unwrap_or_default();
            let response_action_id =
                response_action_id_from_rollback_ref(&self.decision.action, rollback_ref)?;
            require_response_acknowledgement_note_evidence(&self.evidence)?;
            require_response_control_acknowledgement_evidence(&self.evidence)?;
            require_response_effect_count_evidence(
                &self.evidence,
                "acknowledgementEffect:",
                "acknowledgement effect count evidence",
            )?;
            require_response_effect_evidence_hashes(
                &self.evidence,
                "acknowledgementEffect:",
                "acknowledgement effect evidence",
            )?;
            require_response_acknowledgement_effect_evidence(&self.decision, &self.evidence)?;
            require_response_acknowledgement_effect_type_evidence(&self.decision, &self.evidence)?;
            require_response_acknowledgement_execution_id_evidence(
                &self.evidence,
                self.decision.finding_id.as_deref(),
                response_action_id.as_str(),
                rollback_ref,
                self.actor.agent_id.as_deref().unwrap_or_default(),
            )?;
        }
        Ok(())
    }
}
