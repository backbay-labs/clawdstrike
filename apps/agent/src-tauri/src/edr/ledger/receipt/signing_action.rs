//! `impl EndpointReceiptLedger` — signing methods for policy event replay /
//! impact, policy delta, response request / execution / rollback / ack,
//! evidence bundle manifest, and deception materialization / cleanup /
//! rotation receipts.

use anyhow::Result;
use clawdstrike_policy_event::edr::{
    CausalGraph, DeceptionMaterializationReport, DeceptionPlan, EndpointDecisionActor,
    EndpointDecisionReceipt, EndpointDeceptionCleanupReceiptInput,
    EndpointDeceptionMaterializationReceiptInput, EndpointDeceptionRotationReceiptInput,
    EndpointEvidenceBundleManifestReceiptInput, EndpointPolicyDeltaReceiptInput,
    EndpointPolicyEventImpactReceiptInput, EndpointPolicyEventReplayReceiptInput,
    EndpointPolicySnapshot, EndpointResponseAcknowledgementReceiptInput,
    EndpointResponseAcknowledgementReport, EndpointResponseExecutionReceiptInput,
    EndpointResponseExecutionReport, EndpointResponsePlan, EndpointResponseReceiptInput,
    EndpointResponseRollbackReceiptInput, EndpointResponseRollbackReport, EndpointSensorState,
};
use hush_core::SignedReceipt;

use super::{
    DeceptionCleanupReceiptSigningInput, DeceptionRotationReceiptSigningInput,
    EdrPolicyDeltaReceiptSigningInput, EndpointReceiptLedger, ResponseExecutionReceiptSigningInput,
};
use crate::api_server::{
    endpoint_id_for_settings, policy_delta_source_context_evidence_value,
    EdrPolicyEventImpactReport, EdrPolicyEventReplayReport,
};
use crate::settings::Settings;

impl EndpointReceiptLedger {
    pub(crate) fn sign_policy_event_replay_receipt(
        &mut self,
        settings: &Settings,
        policy: EndpointPolicySnapshot,
        sensor_state: EndpointSensorState,
        replay: &EdrPolicyEventReplayReport,
    ) -> Result<SignedReceipt> {
        let endpoint_id = endpoint_id_for_settings(settings);
        let mut receipt = EndpointDecisionReceipt::for_policy_event_replay(
            EndpointPolicyEventReplayReceiptInput {
                local_sequence: self.next_sequence,
                endpoint_id: endpoint_id.as_str(),
                signer_identity: self.signer_identity.as_str(),
                policy,
                sensor_state,
                replay_id: replay.replay_id.as_str(),
                event_source: replay.source.as_str(),
                event_stream_hash: replay.event_stream_hash.as_str(),
                result_hash: replay.result_hash.as_str(),
                event_count: replay.event_count,
                allowed_count: replay.allowed_count,
                warn_count: replay.warn_count,
                blocked_count: replay.blocked_count,
                track_posture: replay.track_posture,
            },
        );
        receipt.signer.signer_public_key = Some(self.signer_public_key.clone());
        let signed = receipt.sign_with(&self.keypair)?;
        self.append(std::slice::from_ref(&signed))?;
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(signed)
    }

    pub(crate) fn sign_policy_event_impact_receipt(
        &mut self,
        settings: &Settings,
        policy: EndpointPolicySnapshot,
        sensor_state: EndpointSensorState,
        impact: &EdrPolicyEventImpactReport,
    ) -> Result<SignedReceipt> {
        let endpoint_id = endpoint_id_for_settings(settings);
        let mut receipt = EndpointDecisionReceipt::for_policy_event_impact(
            EndpointPolicyEventImpactReceiptInput {
                local_sequence: self.next_sequence,
                endpoint_id: endpoint_id.as_str(),
                signer_identity: self.signer_identity.as_str(),
                policy,
                sensor_state,
                impact_id: impact.impact_id.as_str(),
                event_source: impact.source.as_str(),
                event_stream_hash: impact.event_stream_hash.as_str(),
                current_result_hash: impact.current_result_hash.as_str(),
                proposed_result_hash: impact.proposed_result_hash.as_str(),
                impact_hash: impact.impact_hash.as_str(),
                proposed_policy_hash: impact.proposed_policy.policy_hash.as_str(),
                proposed_policy_epoch: impact.proposed_policy.policy_epoch,
                event_count: impact.event_count,
                changed_count: impact.changed_count,
                allow_to_block_count: impact.allow_to_block_count,
                track_posture: impact.track_posture,
            },
        );
        receipt.signer.signer_public_key = Some(self.signer_public_key.clone());
        let signed = receipt.sign_with(&self.keypair)?;
        self.append(std::slice::from_ref(&signed))?;
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(signed)
    }

    pub(crate) fn sign_policy_delta_receipt(
        &mut self,
        settings: &Settings,
        policy: EndpointPolicySnapshot,
        sensor_state: EndpointSensorState,
        input: EdrPolicyDeltaReceiptSigningInput<'_>,
    ) -> Result<SignedReceipt> {
        let endpoint_id = endpoint_id_for_settings(settings);
        let generated_at = input.artifact.generated_at.to_rfc3339();
        let source_affected_identity_context =
            policy_delta_source_context_evidence_value(&input.artifact.source_affected_identities);
        let source_affected_tool_context =
            policy_delta_source_context_evidence_value(&input.artifact.source_affected_tools);
        let mut receipt =
            EndpointDecisionReceipt::for_policy_delta(EndpointPolicyDeltaReceiptInput {
                local_sequence: self.next_sequence,
                endpoint_id: endpoint_id.as_str(),
                signer_identity: self.signer_identity.as_str(),
                actor: input.actor,
                policy,
                sensor_state,
                operation: input.operation,
                policy_delta_id: input.artifact.policy_delta_id.as_str(),
                staged_detection_id: input.artifact.staged_detection_id.as_str(),
                rule_id: input.artifact.candidate.rule_id.as_str(),
                stage: input.artifact.rollout.stage.as_str(),
                generated_at: generated_at.as_str(),
                action: input.artifact.rollout.action.clone(),
                artifact_hash: input.artifact_hash,
                simulation_id: input.artifact.source_simulation_id.as_str(),
                graph_slice_id: input.artifact.candidate.graph_slice_id.as_str(),
                root_node_id: input.artifact.candidate.root_node_id.as_str(),
                source_affected_identity_context: source_affected_identity_context.as_str(),
                source_affected_tool_context: source_affected_tool_context.as_str(),
                cross_window_impact_hash: input
                    .artifact
                    .rollout
                    .cross_window_impact_hash
                    .as_deref(),
                cross_window_recommendation_hash: input
                    .artifact
                    .rollout
                    .cross_window_recommendation_hash
                    .as_deref(),
                previous_policy_hash: input.previous_policy_hash,
                new_policy_hash: input.new_policy_hash,
                backup_path: input.backup_path,
            });
        receipt.signer.signer_public_key = Some(self.signer_public_key.clone());
        let signed = receipt.sign_with(&self.keypair)?;
        self.append(std::slice::from_ref(&signed))?;
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(signed)
    }

    pub(crate) fn sign_response_receipt(
        &mut self,
        settings: &Settings,
        actor: EndpointDecisionActor,
        policy: EndpointPolicySnapshot,
        sensor_state: EndpointSensorState,
        plan: &EndpointResponsePlan,
        graph: &CausalGraph,
    ) -> Result<SignedReceipt> {
        let endpoint_id = endpoint_id_for_settings(settings);
        let mut receipt =
            EndpointDecisionReceipt::for_response_request(EndpointResponseReceiptInput {
                local_sequence: self.next_sequence,
                endpoint_id: endpoint_id.as_str(),
                signer_identity: self.signer_identity.as_str(),
                actor,
                policy,
                sensor_state,
                plan,
                graph,
            });
        receipt.signer.signer_public_key = Some(self.signer_public_key.clone());
        let signed = receipt.sign_with(&self.keypair)?;
        self.append(std::slice::from_ref(&signed))?;
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(signed)
    }

    pub(crate) fn sign_response_execution_receipt(
        &mut self,
        input: ResponseExecutionReceiptSigningInput<'_>,
    ) -> Result<SignedReceipt> {
        let endpoint_id = endpoint_id_for_settings(input.settings);
        let mut receipt = EndpointDecisionReceipt::for_response_execution(
            EndpointResponseExecutionReceiptInput {
                local_sequence: self.next_sequence,
                endpoint_id: endpoint_id.as_str(),
                signer_identity: self.signer_identity.as_str(),
                actor: input.actor,
                policy: input.policy,
                sensor_state: input.sensor_state,
                execution: input.execution,
                graph: input.graph,
            },
        );
        receipt
            .evidence
            .extend(input.additional_evidence.iter().cloned());
        receipt.signer.signer_public_key = Some(self.signer_public_key.clone());
        let signed = receipt.sign_with(&self.keypair)?;
        self.append(std::slice::from_ref(&signed))?;
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(signed)
    }

    pub(crate) fn sign_response_rollback_receipt(
        &mut self,
        settings: &Settings,
        actor: EndpointDecisionActor,
        policy: EndpointPolicySnapshot,
        sensor_state: EndpointSensorState,
        rollback: &EndpointResponseRollbackReport,
        graph: &CausalGraph,
    ) -> Result<SignedReceipt> {
        let endpoint_id = endpoint_id_for_settings(settings);
        let mut receipt =
            EndpointDecisionReceipt::for_response_rollback(EndpointResponseRollbackReceiptInput {
                local_sequence: self.next_sequence,
                endpoint_id: endpoint_id.as_str(),
                signer_identity: self.signer_identity.as_str(),
                actor,
                policy,
                sensor_state,
                rollback,
                graph,
            });
        receipt.signer.signer_public_key = Some(self.signer_public_key.clone());
        let signed = receipt.sign_with(&self.keypair)?;
        self.append(std::slice::from_ref(&signed))?;
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(signed)
    }

    pub(crate) fn sign_response_acknowledgement_receipt(
        &mut self,
        settings: &Settings,
        actor: EndpointDecisionActor,
        policy: EndpointPolicySnapshot,
        sensor_state: EndpointSensorState,
        acknowledgement: &EndpointResponseAcknowledgementReport,
        graph: &CausalGraph,
    ) -> Result<SignedReceipt> {
        let endpoint_id = endpoint_id_for_settings(settings);
        let mut receipt = EndpointDecisionReceipt::for_response_acknowledgement(
            EndpointResponseAcknowledgementReceiptInput {
                local_sequence: self.next_sequence,
                endpoint_id: endpoint_id.as_str(),
                signer_identity: self.signer_identity.as_str(),
                actor,
                policy,
                sensor_state,
                acknowledgement,
                graph,
            },
        );
        receipt.signer.signer_public_key = Some(self.signer_public_key.clone());
        let signed = receipt.sign_with(&self.keypair)?;
        self.append(std::slice::from_ref(&signed))?;
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(signed)
    }

    pub(crate) fn sign_evidence_bundle_manifest_receipt(
        &mut self,
        settings: &Settings,
        policy: EndpointPolicySnapshot,
        sensor_state: EndpointSensorState,
        execution: &EndpointResponseExecutionReport,
        graph: &CausalGraph,
    ) -> Result<SignedReceipt> {
        let endpoint_id = endpoint_id_for_settings(settings);
        let mut receipt = EndpointDecisionReceipt::for_evidence_bundle_manifest(
            EndpointEvidenceBundleManifestReceiptInput {
                local_sequence: self.next_sequence,
                endpoint_id: endpoint_id.as_str(),
                signer_identity: self.signer_identity.as_str(),
                policy,
                sensor_state,
                root_node_id: execution.root_node_id.as_str(),
                bundle: &execution.evidence_bundle,
                graph,
            },
        );
        receipt.signer.signer_public_key = Some(self.signer_public_key.clone());
        let signed = receipt.sign_with(&self.keypair)?;
        self.append(std::slice::from_ref(&signed))?;
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(signed)
    }

    pub(crate) fn sign_deception_materialization_receipt(
        &mut self,
        settings: &Settings,
        policy: EndpointPolicySnapshot,
        sensor_state: EndpointSensorState,
        plan: &DeceptionPlan,
        report: &DeceptionMaterializationReport,
        registered_artifact_count: usize,
    ) -> Result<SignedReceipt> {
        let endpoint_id = endpoint_id_for_settings(settings);
        let mut receipt = EndpointDecisionReceipt::for_deception_materialization(
            EndpointDeceptionMaterializationReceiptInput {
                local_sequence: self.next_sequence,
                endpoint_id: endpoint_id.as_str(),
                signer_identity: self.signer_identity.as_str(),
                policy,
                sensor_state,
                plan,
                report,
                registered_artifact_count,
            },
        );
        receipt.signer.signer_public_key = Some(self.signer_public_key.clone());
        let signed = receipt.sign_with(&self.keypair)?;
        self.append(std::slice::from_ref(&signed))?;
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(signed)
    }

    pub(crate) fn sign_deception_cleanup_receipt(
        &mut self,
        input: DeceptionCleanupReceiptSigningInput<'_>,
    ) -> Result<SignedReceipt> {
        let endpoint_id = endpoint_id_for_settings(input.settings);
        let mut receipt =
            EndpointDecisionReceipt::for_deception_cleanup(EndpointDeceptionCleanupReceiptInput {
                local_sequence: self.next_sequence,
                endpoint_id: endpoint_id.as_str(),
                signer_identity: self.signer_identity.as_str(),
                policy: input.policy,
                sensor_state: input.sensor_state,
                plan: input.plan,
                report: input.report,
                deregistered_artifact_count: input.deregistered_artifact_count,
                remaining_registered_artifact_count: input.remaining_registered_artifact_count,
            });
        receipt.signer.signer_public_key = Some(self.signer_public_key.clone());
        let signed = receipt.sign_with(&self.keypair)?;
        self.append(std::slice::from_ref(&signed))?;
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(signed)
    }

    pub(crate) fn sign_deception_rotation_receipt(
        &mut self,
        input: DeceptionRotationReceiptSigningInput<'_>,
    ) -> Result<SignedReceipt> {
        let endpoint_id = endpoint_id_for_settings(input.settings);
        let mut receipt = EndpointDecisionReceipt::for_deception_rotation(
            EndpointDeceptionRotationReceiptInput {
                local_sequence: self.next_sequence,
                endpoint_id: endpoint_id.as_str(),
                signer_identity: self.signer_identity.as_str(),
                policy: input.policy,
                sensor_state: input.sensor_state,
                old_plan: input.old_plan,
                new_plan: input.new_plan,
                report: input.report,
            },
        );
        receipt.signer.signer_public_key = Some(self.signer_public_key.clone());
        let signed = receipt.sign_with(&self.keypair)?;
        self.append(std::slice::from_ref(&signed))?;
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(signed)
    }
}
