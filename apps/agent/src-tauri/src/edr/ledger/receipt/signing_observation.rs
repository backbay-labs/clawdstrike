//! `impl EndpointReceiptLedger` — signing methods for observation, detection,
//! sensor state, telemetry privacy, provider degradation, policy decisions,
//! graph slices, and simulations.

use anyhow::{Context, Result};
use clawdstrike_policy_event::edr::{
    CausalGraph, DetectionFinding, EndpointDecisionReceipt, EndpointDetectionReceiptInput,
    EndpointGraphSliceReceiptInput, EndpointObservation, EndpointObservationReceiptInput,
    EndpointPolicyDecisionReceiptInput, EndpointPolicySimulationReport, EndpointPolicySnapshot,
    EndpointProviderDegradationReceiptInput, EndpointSensorState, EndpointSensorStateReceiptInput,
    EndpointSimulationReceiptInput, EndpointTelemetryPrivacyReceiptInput,
    EndpointTelemetryPrivacyReport,
};
use hush_core::SignedReceipt;

use super::{EndpointReceiptLedger, PolicyDecisionReceiptSigningInput};
use crate::api_server::{
    detection_severity_from_policy_label, endpoint_id_for_observation, endpoint_id_for_settings,
    provider_policy_decision_provider_state,
};
use crate::settings::Settings;

impl EndpointReceiptLedger {
    pub(crate) fn sign_observation_receipts(
        &mut self,
        settings: &Settings,
        policy: EndpointPolicySnapshot,
        observations: &[EndpointObservation],
        graph: &CausalGraph,
    ) -> Result<Vec<SignedReceipt>> {
        if observations.is_empty() {
            return Ok(Vec::new());
        }

        let mut signed_receipts = Vec::with_capacity(observations.len());
        let mut next_sequence = self.next_sequence;
        for observation in observations {
            let endpoint_id = endpoint_id_for_observation(settings, observation);
            let sensor_state = EndpointSensorState {
                providers: vec![provider_policy_decision_provider_state(observation)],
            };
            let mut receipt =
                EndpointDecisionReceipt::for_observation(EndpointObservationReceiptInput {
                    local_sequence: next_sequence,
                    endpoint_id: endpoint_id.as_str(),
                    signer_identity: self.signer_identity.as_str(),
                    policy: policy.clone(),
                    sensor_state,
                    observation,
                    graph,
                });
            receipt.signer.signer_public_key = Some(self.signer_public_key.clone());
            signed_receipts.push(receipt.sign_with(&self.keypair)?);
            next_sequence = next_sequence.saturating_add(1);
        }

        self.append(&signed_receipts)?;
        self.next_sequence = next_sequence;
        Ok(signed_receipts)
    }

    pub(crate) fn sign_detection_receipts(
        &mut self,
        settings: &Settings,
        policy: EndpointPolicySnapshot,
        sensor_state: EndpointSensorState,
        observations: &[EndpointObservation],
        findings: &[DetectionFinding],
        graph: &CausalGraph,
    ) -> Result<Vec<SignedReceipt>> {
        if findings.is_empty() {
            return Ok(Vec::new());
        }

        let mut signed_receipts = Vec::with_capacity(findings.len());
        let mut next_sequence = self.next_sequence;
        for finding in findings {
            let observation = observations
                .iter()
                .find(|observation| observation.observation_id == finding.observation_id)
                .with_context(|| {
                    format!(
                        "finding {} references missing observation {}",
                        finding.finding_id, finding.observation_id
                    )
                })?;
            let endpoint_id = endpoint_id_for_observation(settings, observation);
            let mut receipt =
                EndpointDecisionReceipt::for_detection(EndpointDetectionReceiptInput {
                    local_sequence: next_sequence,
                    endpoint_id: endpoint_id.as_str(),
                    signer_identity: self.signer_identity.as_str(),
                    policy: policy.clone(),
                    sensor_state: sensor_state.clone(),
                    observation,
                    finding,
                    graph,
                });
            receipt.signer.signer_public_key = Some(self.signer_public_key.clone());
            signed_receipts.push(receipt.sign_with(&self.keypair)?);
            next_sequence = next_sequence.saturating_add(1);
        }

        self.append(&signed_receipts)?;
        self.next_sequence = next_sequence;
        Ok(signed_receipts)
    }

    pub(crate) fn sign_sensor_state_receipt(
        &mut self,
        settings: &Settings,
        policy: EndpointPolicySnapshot,
        sensor_state: EndpointSensorState,
        reason: &str,
    ) -> Result<SignedReceipt> {
        self.sign_sensor_state_receipt_with_evidence(settings, policy, sensor_state, reason, &[])
    }

    pub(crate) fn sign_sensor_state_receipt_with_evidence(
        &mut self,
        settings: &Settings,
        policy: EndpointPolicySnapshot,
        sensor_state: EndpointSensorState,
        reason: &str,
        additional_evidence: &[clawdstrike_policy_event::edr::EndpointReceiptEvidence],
    ) -> Result<SignedReceipt> {
        let endpoint_id = endpoint_id_for_settings(settings);
        let mut receipt =
            EndpointDecisionReceipt::for_sensor_state(EndpointSensorStateReceiptInput {
                local_sequence: self.next_sequence,
                endpoint_id: endpoint_id.as_str(),
                signer_identity: self.signer_identity.as_str(),
                policy,
                sensor_state,
                reason,
            });
        receipt.evidence.extend(additional_evidence.iter().cloned());
        receipt.signer.signer_public_key = Some(self.signer_public_key.clone());
        let signed = receipt.sign_with(&self.keypair)?;
        self.append(std::slice::from_ref(&signed))?;
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(signed)
    }

    pub(crate) fn sign_telemetry_privacy_receipt(
        &mut self,
        settings: &Settings,
        policy: EndpointPolicySnapshot,
        sensor_state: EndpointSensorState,
        report: &EndpointTelemetryPrivacyReport,
    ) -> Result<SignedReceipt> {
        let endpoint_id = endpoint_id_for_settings(settings);
        let mut receipt =
            EndpointDecisionReceipt::for_telemetry_privacy(EndpointTelemetryPrivacyReceiptInput {
                local_sequence: self.next_sequence,
                endpoint_id: endpoint_id.as_str(),
                signer_identity: self.signer_identity.as_str(),
                policy,
                sensor_state,
                report,
            });
        receipt.signer.signer_public_key = Some(self.signer_public_key.clone());
        let signed = receipt.sign_with(&self.keypair)?;
        self.append(std::slice::from_ref(&signed))?;
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(signed)
    }

    pub(crate) fn sign_provider_degradation_receipts(
        &mut self,
        settings: &Settings,
        policy: EndpointPolicySnapshot,
        sensor_state: EndpointSensorState,
    ) -> Result<Vec<SignedReceipt>> {
        let degraded_providers: Vec<_> = sensor_state
            .providers
            .iter()
            .filter(|provider| provider.degraded)
            .cloned()
            .collect();
        if degraded_providers.is_empty() {
            return Ok(Vec::new());
        }

        let endpoint_id = endpoint_id_for_settings(settings);
        let mut signed_receipts = Vec::with_capacity(degraded_providers.len());
        let mut next_sequence = self.next_sequence;
        for provider in &degraded_providers {
            let mut receipt = EndpointDecisionReceipt::for_provider_degradation(
                EndpointProviderDegradationReceiptInput {
                    local_sequence: next_sequence,
                    endpoint_id: endpoint_id.as_str(),
                    signer_identity: self.signer_identity.as_str(),
                    policy: policy.clone(),
                    sensor_state: sensor_state.clone(),
                    provider,
                },
            );
            receipt.signer.signer_public_key = Some(self.signer_public_key.clone());
            signed_receipts.push(receipt.sign_with(&self.keypair)?);
            next_sequence = next_sequence.saturating_add(1);
        }

        self.append(&signed_receipts)?;
        self.next_sequence = next_sequence;
        Ok(signed_receipts)
    }

    pub(crate) fn sign_policy_decision_receipt(
        &mut self,
        input: PolicyDecisionReceiptSigningInput<'_>,
    ) -> Result<SignedReceipt> {
        let mut receipt =
            EndpointDecisionReceipt::for_policy_decision(EndpointPolicyDecisionReceiptInput {
                local_sequence: self.next_sequence,
                signer_identity: self.signer_identity.as_str(),
                actor: input.actor,
                policy: input.policy,
                sensor_state: input.sensor_state,
                observation: input.observation,
                graph: input.graph,
                action_type: input.action_type,
                target: input.target,
                allowed: input.decision.allowed,
                guard: input.decision.guard.as_deref(),
                severity: detection_severity_from_policy_label(input.decision.severity.as_deref()),
                severity_label: input.decision.severity.as_deref(),
                message: input.decision.message.as_deref(),
                details: input.decision.details.as_ref(),
            });
        receipt.signer.signer_public_key = Some(self.signer_public_key.clone());
        let signed = receipt.sign_with(&self.keypair)?;
        self.append(std::slice::from_ref(&signed))?;
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(signed)
    }

    pub(crate) fn sign_graph_slice_receipt(
        &mut self,
        settings: &Settings,
        policy: EndpointPolicySnapshot,
        sensor_state: EndpointSensorState,
        root_node_id: &str,
        slice_kind: &str,
        graph: &CausalGraph,
    ) -> Result<SignedReceipt> {
        let endpoint_id = endpoint_id_for_settings(settings);
        let mut receipt =
            EndpointDecisionReceipt::for_graph_slice(EndpointGraphSliceReceiptInput {
                local_sequence: self.next_sequence,
                endpoint_id: endpoint_id.as_str(),
                signer_identity: self.signer_identity.as_str(),
                policy,
                sensor_state,
                root_node_id,
                slice_kind,
                graph,
            });
        receipt.signer.signer_public_key = Some(self.signer_public_key.clone());
        let signed = receipt.sign_with(&self.keypair)?;
        self.append(std::slice::from_ref(&signed))?;
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(signed)
    }

    pub(crate) fn sign_simulation_receipt(
        &mut self,
        settings: &Settings,
        policy: EndpointPolicySnapshot,
        sensor_state: EndpointSensorState,
        simulation: &EndpointPolicySimulationReport,
        graph: &CausalGraph,
    ) -> Result<SignedReceipt> {
        let endpoint_id = endpoint_id_for_settings(settings);
        let mut receipt = EndpointDecisionReceipt::for_simulation(EndpointSimulationReceiptInput {
            local_sequence: self.next_sequence,
            endpoint_id: endpoint_id.as_str(),
            signer_identity: self.signer_identity.as_str(),
            policy,
            sensor_state,
            simulation,
            graph,
        });
        receipt.signer.signer_public_key = Some(self.signer_public_key.clone());
        let signed = receipt.sign_with(&self.keypair)?;
        self.append(std::slice::from_ref(&signed))?;
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(signed)
    }
}
