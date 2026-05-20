//! Endpoint receipt ledger.
//!
//! Signs and persists `SignedReceipt`s for every EDR decision event (sensor
//! observations, detections, response actions, policy deltas, simulations,
//! deception ops). Receipts are Ed25519-signed over canonical JSON before
//! being appended. A parallel JSONL index accelerates recent-N queries.
//!
//! Sequence numbers are monotonically increasing within a given ledger path.
//! DO NOT construct two `EndpointReceiptLedger::open()` instances pointing at
//! the same path — see the "Receipt sequence integrity" trap door in the plan.

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::{Seek as _, SeekFrom, Write as _};
use std::path::{Path as FsPath, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use anyhow::{Context, Result};
use clawdstrike_policy_event::edr::{
    CausalGraph, DeceptionCleanupReport, DeceptionMaterializationReport, DeceptionPlan,
    DeceptionRotationReport, DetectionFinding, EndpointDecisionActor, EndpointDecisionReceipt,
    EndpointDeceptionCleanupReceiptInput, EndpointDeceptionMaterializationReceiptInput,
    EndpointDeceptionRotationReceiptInput, EndpointDetectionReceiptInput,
    EndpointEvidenceBundleManifestReceiptInput, EndpointGraphSliceReceiptInput,
    EndpointObservation, EndpointObservationReceiptInput,
    EndpointPolicyDecisionReceiptInput, EndpointPolicyDeltaReceiptInput,
    EndpointPolicyEventImpactReceiptInput, EndpointPolicyEventReplayReceiptInput,
    EndpointPolicySimulationReport, EndpointPolicySnapshot, EndpointProviderDegradationReceiptInput,
    EndpointReceiptEvidence, EndpointResponseAcknowledgementReceiptInput,
    EndpointResponseAcknowledgementReport, EndpointResponseExecutionReceiptInput,
    EndpointResponseExecutionReport, EndpointResponsePlan, EndpointResponseReceiptInput,
    EndpointResponseRollbackReceiptInput, EndpointResponseRollbackReport,
    EndpointSensorState, EndpointSensorStateReceiptInput, EndpointSimulationReceiptInput,
    EndpointTelemetryPrivacyReceiptInput, EndpointTelemetryPrivacyReport,
};
use hush_core::{Keypair, SignedReceipt};

use crate::api_server::{
    detection_severity_from_policy_label, endpoint_id_for_observation, endpoint_id_for_settings,
    endpoint_receipt_index_path, endpoint_receipt_index_record, load_or_create_edr_receipt_signer,
    next_receipt_sequence, policy_delta_source_context_evidence_value,
    provider_policy_decision_provider_state, read_endpoint_receipt_ledger,
    read_recent_indexed_endpoint_receipts, rebuild_endpoint_receipt_index, receipt_age_seconds,
    receipt_compaction_record, receipt_local_sequence, receipt_matches_filter,
    EdrPolicyDeltaArtifact, EdrPolicyEventImpactReport, EdrPolicyEventReplayReport,
    EdrReceiptCompactionRecord, EdrReceiptFilter,
};
use crate::policy::PolicyCheckOutput;
use crate::settings::Settings;

pub(crate) struct EndpointReceiptLedger {
    pub(crate) path: Option<PathBuf>,
    pub(crate) next_sequence: u64,
    pub(crate) keypair: Keypair,
    pub(crate) signer_identity: String,
    pub(crate) signer_public_key: String,
}

pub(crate) struct ReceiptCompactionReport {
    pub(crate) receipt_count: usize,
    pub(crate) retained_count: usize,
    pub(crate) records: Vec<EdrReceiptCompactionRecord>,
}

pub(crate) struct ResponseExecutionReceiptSigningInput<'a> {
    pub(crate) settings: &'a Settings,
    pub(crate) actor: EndpointDecisionActor,
    pub(crate) policy: EndpointPolicySnapshot,
    pub(crate) sensor_state: EndpointSensorState,
    pub(crate) execution: &'a EndpointResponseExecutionReport,
    pub(crate) graph: &'a CausalGraph,
    pub(crate) additional_evidence: &'a [EndpointReceiptEvidence],
}

pub(crate) struct EdrPolicyDeltaReceiptSigningInput<'a> {
    pub(crate) artifact: &'a EdrPolicyDeltaArtifact,
    pub(crate) artifact_hash: &'a str,
    pub(crate) operation: &'a str,
    pub(crate) previous_policy_hash: Option<&'a str>,
    pub(crate) new_policy_hash: Option<&'a str>,
    pub(crate) backup_path: Option<&'a str>,
}

pub(crate) struct DeceptionCleanupReceiptSigningInput<'a> {
    pub(crate) settings: &'a Settings,
    pub(crate) policy: EndpointPolicySnapshot,
    pub(crate) sensor_state: EndpointSensorState,
    pub(crate) plan: &'a DeceptionPlan,
    pub(crate) report: &'a DeceptionCleanupReport,
    pub(crate) deregistered_artifact_count: usize,
    pub(crate) remaining_registered_artifact_count: usize,
}

pub(crate) struct DeceptionRotationReceiptSigningInput<'a> {
    pub(crate) settings: &'a Settings,
    pub(crate) policy: EndpointPolicySnapshot,
    pub(crate) sensor_state: EndpointSensorState,
    pub(crate) old_plan: &'a DeceptionPlan,
    pub(crate) new_plan: &'a DeceptionPlan,
    pub(crate) report: &'a DeceptionRotationReport,
}

impl EndpointReceiptLedger {
    pub(crate) fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let next_sequence = next_receipt_sequence(&path)?;
        let (keypair, signer_identity) = load_or_create_edr_receipt_signer()?;
        let signer_public_key = keypair.public_key().to_hex();
        Ok(Self {
            path: Some(path),
            next_sequence,
            keypair,
            signer_identity,
            signer_public_key,
        })
    }

    pub(crate) fn transient(keypair: Keypair, signer_identity: impl Into<String>) -> Self {
        let signer_public_key = keypair.public_key().to_hex();
        Self {
            path: None,
            next_sequence: 1,
            keypair,
            signer_identity: signer_identity.into(),
            signer_public_key,
        }
    }

    pub(crate) fn path(&self) -> Option<&FsPath> {
        self.path.as_deref()
    }

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
        additional_evidence: &[EndpointReceiptEvidence],
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
        actor: EndpointDecisionActor,
        policy: EndpointPolicySnapshot,
        sensor_state: EndpointSensorState,
        action_type: &str,
        target: &str,
        decision: &PolicyCheckOutput,
    ) -> Result<SignedReceipt> {
        let mut receipt =
            EndpointDecisionReceipt::for_policy_decision(EndpointPolicyDecisionReceiptInput {
                local_sequence: self.next_sequence,
                signer_identity: self.signer_identity.as_str(),
                actor,
                policy,
                sensor_state,
                action_type,
                target,
                allowed: decision.allowed,
                guard: decision.guard.as_deref(),
                severity: detection_severity_from_policy_label(decision.severity.as_deref()),
                severity_label: decision.severity.as_deref(),
                message: decision.message.as_deref(),
                details: decision.details.as_ref(),
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

    pub(crate) fn read_recent(
        &self,
        limit: usize,
        filter: EdrReceiptFilter<'_>,
    ) -> Result<Vec<SignedReceipt>> {
        if let Some(path) = &self.path {
            if let Some(receipts) = read_recent_indexed_endpoint_receipts(path, limit, filter)? {
                return Ok(receipts);
            }
        }

        let mut receipts = VecDeque::new();
        for receipt in self.all()? {
            if !receipt_matches_filter(&receipt, filter) {
                continue;
            }
            receipts.push_back(receipt);
            while receipts.len() > limit {
                let _ = receipts.pop_front();
            }
        }

        Ok(receipts.into_iter().collect())
    }

    pub(crate) fn compact(
        &mut self,
        max_receipts: Option<usize>,
        min_age_seconds: u64,
        dry_run: bool,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ReceiptCompactionReport> {
        let receipts = self.all()?;
        let receipt_count = receipts.len();
        let mut retained = Vec::with_capacity(receipts.len());
        let mut records = Vec::new();
        for (index, receipt) in receipts.iter().enumerate() {
            let age_seconds = receipt_age_seconds(receipt, now);
            let beyond_limit =
                max_receipts.is_some_and(|max| receipts.len().saturating_sub(index) > max);
            let old_enough = age_seconds >= min_age_seconds;
            if !old_enough || max_receipts.is_some() && !beyond_limit {
                retained.push(receipt.clone());
                continue;
            }
            let reason = if beyond_limit {
                format!(
                    "receipt exceeds max_receipts {} and is at least {min_age_seconds}s old",
                    max_receipts.unwrap_or_default()
                )
            } else {
                format!("receipt is at least {min_age_seconds}s old")
            };
            records.push(receipt_compaction_record(
                receipt,
                age_seconds,
                !dry_run,
                reason,
            ));
            if dry_run {
                retained.push(receipt.clone());
            }
        }

        if !dry_run {
            self.rewrite(&retained)?;
        }
        self.next_sequence = receipts
            .iter()
            .filter_map(receipt_local_sequence)
            .max()
            .unwrap_or(0)
            .saturating_add(1)
            .max(self.next_sequence);

        Ok(ReceiptCompactionReport {
            receipt_count,
            retained_count: retained.len(),
            records,
        })
    }

    pub(crate) fn all(&self) -> Result<Vec<SignedReceipt>> {
        let Some(path) = &self.path else {
            return Ok(Vec::new());
        };
        read_endpoint_receipt_ledger(path)
    }

    pub(crate) fn rewrite(&self, receipts: &[SignedReceipt]) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "create endpoint receipt ledger directory {}",
                    parent.display()
                )
            })?;
        }
        let mut contents = String::new();
        for receipt in receipts {
            let line = serde_json::to_string(receipt).context("serialize endpoint receipt")?;
            contents.push_str(&line);
            contents.push('\n');
        }
        crate::security::fs::write_private_atomic(
            path,
            contents.as_bytes(),
            "endpoint receipt ledger",
        )?;
        self.rebuild_index()
    }

    pub(crate) fn append(&self, receipts: &[SignedReceipt]) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "create endpoint receipt ledger directory {}",
                    parent.display()
                )
            })?;
        }

        let mut ledger_options = OpenOptions::new();
        #[cfg(unix)]
        ledger_options.mode(0o600);
        let mut file = ledger_options
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open endpoint receipt ledger {}", path.display()))?;
        crate::settings::enforce_private_mode(path, "endpoint receipt ledger")?;

        let index_path = endpoint_receipt_index_path(path);
        let mut index_options = OpenOptions::new();
        #[cfg(unix)]
        index_options.mode(0o600);
        let mut index_file = index_options
            .create(true)
            .append(true)
            .open(&index_path)
            .with_context(|| format!("open endpoint receipt index {}", index_path.display()))?;
        crate::settings::enforce_private_mode(&index_path, "endpoint receipt index")?;
        for receipt in receipts {
            let line = serde_json::to_vec(receipt).with_context(|| {
                format!(
                    "serialize endpoint receipt {}",
                    receipt
                        .receipt
                        .receipt_id
                        .as_deref()
                        .unwrap_or("<missing-receipt-id>")
                )
            })?;
            let byte_offset = file
                .seek(SeekFrom::End(0))
                .with_context(|| format!("seek endpoint receipt ledger {}", path.display()))?;
            file.write_all(&line)
                .with_context(|| format!("write endpoint receipt to {}", path.display()))?;
            file.write_all(b"\n")
                .with_context(|| format!("write endpoint receipt to {}", path.display()))?;
            let record = endpoint_receipt_index_record(receipt, byte_offset, line.len() as u64);
            serde_json::to_writer(&mut index_file, &record).with_context(|| {
                format!(
                    "serialize endpoint receipt index {}",
                    receipt
                        .receipt
                        .receipt_id
                        .as_deref()
                        .unwrap_or("<missing-receipt-id>")
                )
            })?;
            index_file.write_all(b"\n").with_context(|| {
                format!(
                    "write endpoint receipt index {}",
                    index_path.display()
                )
            })?;
        }
        file.flush()
            .with_context(|| format!("flush endpoint receipt ledger {}", path.display()))?;
        index_file.flush().with_context(|| {
            format!(
                "flush endpoint receipt index {}",
                index_path.display()
            )
        })?;
        Ok(())
    }

    pub(crate) fn rebuild_index(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        rebuild_endpoint_receipt_index(path)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use clawdstrike_policy_event::edr::{
        EndpointEvent, EndpointProcess, EndpointTelemetryPrivacyMode,
    };

    fn unique_test_path(name: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("clawdstrike-receipt-ledger-{name}-{nonce}.jsonl"))
    }

    fn signed_test_receipt() -> SignedReceipt {
        let observation = EndpointObservation {
            observation_id: "obs-receipt-private-mode".to_string(),
            timestamp: chrono::DateTime::parse_from_rfc3339("2026-05-20T12:00:00Z")
                .expect("timestamp")
                .with_timezone(&chrono::Utc),
            host_id: Some("host-1".to_string()),
            user_id: Some("user-1".to_string()),
            session_id: Some("session-1".to_string()),
            process: EndpointProcess {
                pid: Some(42),
                image: Some("/bin/zsh".to_string()),
                command_line: Some("/bin/zsh -lc echo ok".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::ProcessExec {
                image: "/bin/zsh".to_string(),
                args: vec!["-lc".to_string(), "echo ok".to_string()],
                env: std::collections::BTreeMap::new(),
            },
            metadata: std::collections::BTreeMap::new(),
        };
        let report = EndpointTelemetryPrivacyReport::from_observations(
            &[observation],
            EndpointTelemetryPrivacyMode::HashesFeatures,
        );
        let keypair = Keypair::from_seed(&[17u8; 32]);
        let mut receipt = EndpointDecisionReceipt::for_telemetry_privacy(
            EndpointTelemetryPrivacyReceiptInput {
                local_sequence: 1,
                endpoint_id: "endpoint-test",
                signer_identity: "local-edr:endpoint-test",
                policy: EndpointPolicySnapshot {
                    policy_version: "test-policy@1".to_string(),
                    policy_hash: hush_core::sha256(b"test-policy").to_hex_prefixed(),
                    policy_epoch: 1,
                },
                sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
                report: &report,
            },
        );
        receipt.signer.signer_public_key = Some(keypair.public_key().to_hex());
        receipt.sign_with(&keypair).expect("signed receipt")
    }

    #[cfg(unix)]
    fn assert_private_mode(path: &FsPath) {
        use std::os::unix::fs::PermissionsExt;

        let mode = fs::metadata(path)
            .unwrap_or_else(|err| panic!("metadata for {}: {err}", path.display()))
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "unexpected mode for {}", path.display());
    }

    #[cfg(unix)]
    #[test]
    fn append_creates_private_receipt_ledger_and_index() {
        let path = unique_test_path("append");
        let ledger_keypair = Keypair::from_seed(&[18u8; 32]);
        let ledger = EndpointReceiptLedger {
            path: Some(path.clone()),
            next_sequence: 1,
            signer_identity: "local-edr:endpoint-test".to_string(),
            signer_public_key: ledger_keypair.public_key().to_hex(),
            keypair: ledger_keypair,
        };
        ledger
            .append(&[signed_test_receipt()])
            .expect("append receipt");
        let index_path = endpoint_receipt_index_path(&path);

        assert_private_mode(&path);
        assert_private_mode(&index_path);

        let _ = fs::remove_file(path);
        let _ = fs::remove_file(index_path);
    }
}
