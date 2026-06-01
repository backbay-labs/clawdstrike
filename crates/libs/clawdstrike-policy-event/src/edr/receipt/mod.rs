mod common;
pub mod evidence;
pub mod families;
pub mod inputs;
mod kinds;
mod serialize;
mod validate;

pub use evidence::*;
pub use families::*;
pub use inputs::*;

pub(crate) use common::*;
pub(crate) use kinds::*;

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use hush_core::{canonicalize_json, sha256, Hash};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub(crate) use super::{
    action::EndpointDecisionAction,
    actor::{
        EndpointClockState, EndpointDecisionActor, EndpointPolicySnapshot, EndpointReceiptSigner,
    },
    causal::{CausalGraph, CausalNode},
    deception::{
        DeceptionCleanupReport, DeceptionMaterializationReport, DeceptionPlan,
        DeceptionRotationReport,
    },
    detection::{DetectionFinding, DetectionSeverity},
    event::EndpointObservation,
    privacy::EndpointTelemetryPrivacyReport,
    response::{
        EndpointResponseAcknowledgementReport, EndpointResponseControlCorrelation,
        EndpointResponseExecutionEffect, EndpointResponseExecutionReport,
        EndpointResponseExecutionStatus, EndpointResponsePlan, EndpointResponseRollbackReport,
    },
    sensor_state::{EndpointProviderState, EndpointSensorState},
    simulation::{
        impact_level_for_score, simulation_action_would_block, simulation_context_evidence_value,
        EndpointPolicySimulationReport,
    },
};
pub(crate) use super::{
    endpoint_decision_actor_content_hash, endpoint_observation_content_hash,
    endpoint_policy_delta_id, endpoint_policy_event_impact_id, endpoint_policy_event_replay_id,
    endpoint_sensor_state_content_hash, event_target_field, evidence_hash_for_value, finding,
    stable_id,
};
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointDecisionRecord {
    pub observation_id: Option<String>,
    pub finding_id: Option<String>,
    pub rule_id: Option<String>,
    pub title: Option<String>,
    pub severity: Option<DetectionSeverity>,
    pub confidence: Option<f32>,
    pub action: EndpointDecisionAction,
    pub passed: bool,
    pub ttl_seconds: Option<u64>,
    pub rollback_ref: Option<String>,
}

impl Default for EndpointDecisionRecord {
    fn default() -> Self {
        Self {
            observation_id: None,
            finding_id: None,
            rule_id: None,
            title: None,
            severity: None,
            confidence: None,
            action: EndpointDecisionAction::Observe,
            passed: false,
            ttl_seconds: None,
            rollback_ref: None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointDecisionReceipt {
    pub schema_version: String,
    pub receipt_family: EndpointDecisionReceiptFamily,
    pub local_sequence: u64,
    pub clock: EndpointClockState,
    pub signer: EndpointReceiptSigner,
    pub actor: EndpointDecisionActor,
    pub policy: EndpointPolicySnapshot,
    pub sensor_state: EndpointSensorState,
    pub decision: EndpointDecisionRecord,
    pub graph: EndpointGraphReference,
    pub evidence: Vec<EndpointReceiptEvidence>,
}

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

    #[must_use]
    pub fn for_telemetry_privacy(input: EndpointTelemetryPrivacyReceiptInput<'_>) -> Self {
        let privacy_mode = input.report.privacy_mode.as_str();
        let mut evidence = vec![
            EndpointReceiptEvidence::hashed("privacyReportId", &input.report.report_id),
            EndpointReceiptEvidence::hashed("privacyMode", privacy_mode),
            EndpointReceiptEvidence::hashed(
                "rawArtifactUploadPermitted",
                input.report.raw_artifact_upload_permitted.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "projectionContentHash",
                input.report.projection_content_hash.as_str(),
            ),
            EndpointReceiptEvidence::hashed(
                "observationCount",
                input.report.observation_count.to_string(),
            ),
            EndpointReceiptEvidence::hashed("fieldCount", input.report.field_count.to_string()),
            EndpointReceiptEvidence::hashed(
                "hashOnlyCount",
                input.report.hash_only_count.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "metadataOnlyCount",
                input.report.metadata_only_count.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "redactedCount",
                input.report.redacted_count.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "rawSuppressedCount",
                input.report.raw_suppressed_count.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "localOnlyCount",
                input.report.local_only_count.to_string(),
            ),
        ];
        if input.report.raw_artifact_upload_permitted {
            evidence.push(EndpointReceiptEvidence::hashed(
                "rawArtifactApprovalId",
                input
                    .report
                    .raw_artifact_approval_id
                    .as_deref()
                    .unwrap_or_default(),
            ));
            evidence.push(EndpointReceiptEvidence::hashed(
                "rawArtifactApprovalReasonHash",
                input
                    .report
                    .raw_artifact_approval_reason_hash
                    .as_deref()
                    .unwrap_or_default(),
            ));
        }
        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::PrivacyReport,
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
                finding_id: Some(input.report.report_id.clone()),
                rule_id: Some("endpoint.telemetry_privacy".to_string()),
                title: Some("Endpoint telemetry privacy mode applied".to_string()),
                severity: None,
                confidence: None,
                action: EndpointDecisionAction::Observe,
                passed: true,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: EndpointGraphReference::default(),
            evidence,
        }
    }

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

    #[must_use]
    pub fn for_observation(input: EndpointObservationReceiptInput<'_>) -> Self {
        let event_kind = input.observation.event_name();
        let observation_hash = endpoint_observation_content_hash(input.observation);
        let graph_ref = EndpointGraphReference::for_observation(input.observation, input.graph);
        let graph_slice_id = graph_ref.graph_slice_id.clone().unwrap_or_default();
        let process_node_id = graph_ref.process_node_id.clone().unwrap_or_default();
        let graph_content_hash = graph_ref.content_hash.clone().unwrap_or_default();
        let target = event_target_field(input.observation).unwrap_or_else(|| "unknown".to_string());
        let provider = input.sensor_state.providers.first();
        let provider_id = provider
            .map(|provider| provider.provider_id.clone())
            .unwrap_or_else(|| "unknown".to_string());
        let provider_kind = provider
            .map(|provider| camel_debug_to_snake(format!("{:?}", provider.provider_kind).as_str()))
            .unwrap_or_else(|| "unknown".to_string());
        let observation_receipt_id =
            observation_receipt_id_from_fields(ObservationReceiptIdFields {
                endpoint_id: input.endpoint_id,
                policy_hash: input.policy.policy_hash.as_str(),
                observation_id: input.observation.observation_id.as_str(),
                event_kind,
                observation_hash: observation_hash.as_str(),
                target: target.as_str(),
                graph_slice_id: graph_slice_id.as_str(),
                graph_content_hash: graph_content_hash.as_str(),
                process_node_id: process_node_id.as_str(),
                provider_id: provider_id.as_str(),
                provider_kind: provider_kind.as_str(),
            });

        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::Observation,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor: EndpointDecisionActor::from_observation(input.endpoint_id, input.observation),
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: Some(input.observation.observation_id.clone()),
                finding_id: Some(observation_receipt_id),
                rule_id: Some(format!("endpoint.observation.{event_kind}")),
                title: Some("Endpoint provider observation recorded".to_string()),
                severity: None,
                confidence: Some(1.0),
                action: EndpointDecisionAction::Observe,
                passed: true,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: graph_ref,
            evidence: vec![
                EndpointReceiptEvidence::hashed(
                    "observationId",
                    input.observation.observation_id.as_str(),
                ),
                EndpointReceiptEvidence::hashed("eventKind", event_kind),
                EndpointReceiptEvidence::hashed("observationHash", observation_hash),
                EndpointReceiptEvidence::hashed("target", target),
                EndpointReceiptEvidence::hashed("graphSliceId", graph_slice_id),
                EndpointReceiptEvidence::hashed("contentHash", graph_content_hash),
                EndpointReceiptEvidence::hashed("processNodeId", process_node_id),
                EndpointReceiptEvidence::hashed("providerId", provider_id),
                EndpointReceiptEvidence::hashed("providerKind", provider_kind),
            ],
        }
    }

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

    #[must_use]
    pub fn for_graph_slice(input: EndpointGraphSliceReceiptInput<'_>) -> Self {
        let graph_ref = EndpointGraphReference::for_subgraph(input.root_node_id, input.graph);
        let graph_slice_id = graph_ref.graph_slice_id.clone().unwrap_or_else(|| {
            let node_count = input.graph.nodes.len().to_string();
            let edge_count = input.graph.edges.len().to_string();
            stable_id(
                "graph_slice",
                [input.root_node_id, node_count.as_str(), edge_count.as_str()],
            )
        });
        let graph_content_hash = graph_ref.content_hash.clone();
        let mut evidence = vec![
            EndpointReceiptEvidence::hashed("graphSliceId", graph_slice_id.clone()),
            EndpointReceiptEvidence::hashed("rootNodeId", input.root_node_id),
            EndpointReceiptEvidence::hashed("sliceKind", input.slice_kind),
            EndpointReceiptEvidence::hashed("nodeCount", input.graph.nodes.len().to_string()),
            EndpointReceiptEvidence::hashed("edgeCount", input.graph.edges.len().to_string()),
        ];
        if let Some(graph_content_hash) = graph_content_hash {
            evidence.push(EndpointReceiptEvidence::hashed(
                "contentHash",
                graph_content_hash,
            ));
        }

        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::GraphSlice,
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
                finding_id: Some(graph_slice_id.clone()),
                rule_id: Some(format!("endpoint.graph_slice.{}", input.slice_kind)),
                title: Some("Endpoint causal graph slice exported".to_string()),
                severity: None,
                confidence: None,
                action: EndpointDecisionAction::Observe,
                passed: true,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: graph_ref,
            evidence,
        }
    }

    #[must_use]
    pub fn for_detection(input: EndpointDetectionReceiptInput<'_>) -> Self {
        let graph_ref = EndpointGraphReference::for_observation(input.observation, input.graph);
        let mut evidence = vec![
            EndpointReceiptEvidence::hashed("detectionFindingId", &input.finding.finding_id),
            EndpointReceiptEvidence::hashed(
                "detectionObservationId",
                &input.finding.observation_id,
            ),
            EndpointReceiptEvidence::hashed("detectionRuleId", &input.finding.rule_id),
            EndpointReceiptEvidence::hashed("detectionTitle", &input.finding.title),
            EndpointReceiptEvidence::hashed(
                "detectionSeverity",
                detection_severity_label(&input.finding.severity),
            ),
            EndpointReceiptEvidence::hashed(
                "detectionConfidence",
                input.finding.confidence.to_string(),
            ),
        ];
        if let Some(graph_slice_id) = graph_ref.graph_slice_id.as_deref() {
            evidence.push(EndpointReceiptEvidence::hashed(
                "detectionGraphSliceId",
                graph_slice_id,
            ));
        }
        if let Some(graph_content_hash) = graph_ref.content_hash.as_deref() {
            evidence.push(EndpointReceiptEvidence::hashed(
                "detectionContentHash",
                graph_content_hash,
            ));
        }
        if let Some(process_node_id) = graph_ref.process_node_id.as_deref() {
            evidence.push(EndpointReceiptEvidence::hashed(
                "detectionProcessNodeId",
                process_node_id,
            ));
        }
        evidence.extend(
            input
                .finding
                .evidence
                .iter()
                .map(|item| EndpointReceiptEvidence::hashed(&item.key, &item.value)),
        );

        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::Detection,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor: EndpointDecisionActor::from_observation(input.endpoint_id, input.observation),
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: Some(input.finding.observation_id.clone()),
                finding_id: Some(input.finding.finding_id.clone()),
                rule_id: Some(input.finding.rule_id.clone()),
                title: Some(input.finding.title.clone()),
                severity: Some(input.finding.severity.clone()),
                confidence: Some(input.finding.confidence),
                action: EndpointDecisionAction::Alert,
                passed: false,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: graph_ref,
            evidence,
        }
    }

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

    #[must_use]
    pub fn for_evidence_bundle_manifest(
        input: EndpointEvidenceBundleManifestReceiptInput<'_>,
    ) -> Self {
        let graph_ref = EndpointGraphReference::for_subgraph(input.root_node_id, input.graph);
        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::EvidenceBundleManifest,
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
                finding_id: Some(input.bundle.bundle_id.clone()),
                rule_id: Some("endpoint.evidence_bundle_manifest".to_string()),
                title: Some("Endpoint evidence bundle manifest".to_string()),
                severity: None,
                confidence: None,
                action: EndpointDecisionAction::CollectEvidence,
                passed: true,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: graph_ref,
            evidence: vec![
                EndpointReceiptEvidence::hashed("evidenceBundleId", &input.bundle.bundle_id),
                EndpointReceiptEvidence::hashed("graphSliceId", &input.bundle.graph_slice_id),
                EndpointReceiptEvidence::hashed("contentHash", &input.bundle.content_hash),
                EndpointReceiptEvidence::hashed("nodeCount", input.bundle.node_count.to_string()),
                EndpointReceiptEvidence::hashed("edgeCount", input.bundle.edge_count.to_string()),
            ],
        }
    }

    #[must_use]
    pub fn for_deception_materialization(
        input: EndpointDeceptionMaterializationReceiptInput<'_>,
    ) -> Self {
        let plan_value = serde_json::to_value(input.plan)
            .ok()
            .and_then(|value| canonicalize_json(&value).ok())
            .unwrap_or_else(|| input.plan.endpoint_id.clone());
        let report_value = serde_json::to_value(input.report)
            .ok()
            .and_then(|value| canonicalize_json(&value).ok())
            .unwrap_or_default();
        let plan_root = input.plan.root.display().to_string();
        let plan_hash = sha256(plan_value.as_bytes()).to_hex_prefixed();
        let report_hash = sha256(report_value.as_bytes()).to_hex_prefixed();
        let artifact_count = input.plan.artifacts.len().to_string();
        let created_count = input.report.created.len().to_string();
        let skipped_count = input.report.skipped.len().to_string();
        let registered_artifact_count = input.registered_artifact_count.to_string();
        let mut artifact_ids = input
            .plan
            .artifacts
            .iter()
            .map(|artifact| artifact.artifact_id.as_str())
            .collect::<Vec<_>>();
        artifact_ids.sort_unstable();
        let artifact_ids = artifact_ids.join(",");
        let materialization_id = deception_materialization_id_from_hashes(
            input.endpoint_id,
            input.policy.policy_hash.as_str(),
            DeceptionMaterializationIdValues {
                plan_root: plan_root.as_str(),
                plan_hash: plan_hash.as_str(),
                report_hash: report_hash.as_str(),
                artifact_count: artifact_count.as_str(),
                created_count: created_count.as_str(),
                skipped_count: skipped_count.as_str(),
                registered_artifact_count: registered_artifact_count.as_str(),
                artifact_ids: artifact_ids.as_str(),
            },
        );

        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::DeceptionMaterialization,
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
                finding_id: Some(materialization_id),
                rule_id: Some("endpoint.deception.materialization".to_string()),
                title: Some("Endpoint deception materialized".to_string()),
                severity: None,
                confidence: Some(1.0),
                action: EndpointDecisionAction::Observe,
                passed: true,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: EndpointGraphReference::default(),
            evidence: vec![
                EndpointReceiptEvidence::hashed("endpointId", input.endpoint_id),
                EndpointReceiptEvidence::hashed("deceptionPlanRoot", plan_root),
                EndpointReceiptEvidence::hashed("deceptionPlanHash", &plan_hash),
                EndpointReceiptEvidence::hashed("materializationReportHash", &report_hash),
                EndpointReceiptEvidence::hashed("artifactCount", artifact_count),
                EndpointReceiptEvidence::hashed("createdCount", created_count),
                EndpointReceiptEvidence::hashed("skippedCount", skipped_count),
                EndpointReceiptEvidence::hashed(
                    "registeredArtifactCount",
                    registered_artifact_count,
                ),
                EndpointReceiptEvidence::hashed("artifactIds", artifact_ids),
            ],
        }
    }

    #[must_use]
    pub fn for_deception_cleanup(input: EndpointDeceptionCleanupReceiptInput<'_>) -> Self {
        let plan_value = serde_json::to_value(input.plan)
            .ok()
            .and_then(|value| canonicalize_json(&value).ok())
            .unwrap_or_else(|| input.plan.endpoint_id.clone());
        let report_value = serde_json::to_value(input.report)
            .ok()
            .and_then(|value| canonicalize_json(&value).ok())
            .unwrap_or_default();
        let plan_root = input.plan.root.display().to_string();
        let plan_hash = sha256(plan_value.as_bytes()).to_hex_prefixed();
        let report_hash = sha256(report_value.as_bytes()).to_hex_prefixed();
        let artifact_count = input.plan.artifacts.len().to_string();
        let dry_run = input.report.dry_run.to_string();
        let removed_count = input.report.removed.len().to_string();
        let would_remove_count = input.report.would_remove.len().to_string();
        let missing_count = input.report.missing.len().to_string();
        let refused_count = input.report.refused.len().to_string();
        let deregistered_artifact_count = input.deregistered_artifact_count.to_string();
        let remaining_registered_artifact_count =
            input.remaining_registered_artifact_count.to_string();
        let cleanup_id = deception_cleanup_id_from_hashes(
            input.endpoint_id,
            input.policy.policy_hash.as_str(),
            DeceptionCleanupIdValues {
                plan_root: plan_root.as_str(),
                plan_hash: plan_hash.as_str(),
                report_hash: report_hash.as_str(),
                artifact_count: artifact_count.as_str(),
                dry_run: dry_run.as_str(),
                removed_count: removed_count.as_str(),
                would_remove_count: would_remove_count.as_str(),
                missing_count: missing_count.as_str(),
                refused_count: refused_count.as_str(),
                deregistered_artifact_count: deregistered_artifact_count.as_str(),
                remaining_registered_artifact_count: remaining_registered_artifact_count.as_str(),
            },
        );

        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::DeceptionCleanup,
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
                finding_id: Some(cleanup_id),
                rule_id: Some("endpoint.deception.cleanup".to_string()),
                title: Some(if input.report.dry_run {
                    "Endpoint deception cleanup dry run planned".to_string()
                } else {
                    "Endpoint deception cleanup executed".to_string()
                }),
                severity: None,
                confidence: Some(1.0),
                action: EndpointDecisionAction::Observe,
                passed: refused_count == "0",
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: EndpointGraphReference::default(),
            evidence: vec![
                EndpointReceiptEvidence::hashed("endpointId", input.endpoint_id),
                EndpointReceiptEvidence::hashed("deceptionPlanRoot", plan_root),
                EndpointReceiptEvidence::hashed("deceptionPlanHash", &plan_hash),
                EndpointReceiptEvidence::hashed("cleanupReportHash", &report_hash),
                EndpointReceiptEvidence::hashed("artifactCount", artifact_count),
                EndpointReceiptEvidence::hashed("dryRun", dry_run),
                EndpointReceiptEvidence::hashed("removedCount", removed_count),
                EndpointReceiptEvidence::hashed("wouldRemoveCount", would_remove_count),
                EndpointReceiptEvidence::hashed("missingCount", missing_count),
                EndpointReceiptEvidence::hashed("refusedCount", refused_count),
                EndpointReceiptEvidence::hashed(
                    "deregisteredArtifactCount",
                    deregistered_artifact_count,
                ),
                EndpointReceiptEvidence::hashed(
                    "remainingRegisteredArtifactCount",
                    remaining_registered_artifact_count,
                ),
            ],
        }
    }

    #[must_use]
    pub fn for_deception_rotation(input: EndpointDeceptionRotationReceiptInput<'_>) -> Self {
        let old_plan_value = serde_json::to_value(input.old_plan)
            .ok()
            .and_then(|value| canonicalize_json(&value).ok())
            .unwrap_or_else(|| input.old_plan.endpoint_id.clone());
        let new_plan_value = serde_json::to_value(input.new_plan)
            .ok()
            .and_then(|value| canonicalize_json(&value).ok())
            .unwrap_or_else(|| input.new_plan.endpoint_id.clone());
        let report_value = serde_json::to_value(input.report)
            .ok()
            .and_then(|value| canonicalize_json(&value).ok())
            .unwrap_or_default();
        let old_plan_root = input.old_plan.root.display().to_string();
        let new_plan_root = input.new_plan.root.display().to_string();
        let old_plan_hash = sha256(old_plan_value.as_bytes()).to_hex_prefixed();
        let new_plan_hash = sha256(new_plan_value.as_bytes()).to_hex_prefixed();
        let report_hash = sha256(report_value.as_bytes()).to_hex_prefixed();
        let dry_run = input.report.dry_run.to_string();
        let cleanup_removed_count = input.report.cleanup.removed.len().to_string();
        let cleanup_would_remove_count = input.report.cleanup.would_remove.len().to_string();
        let cleanup_missing_count = input.report.cleanup.missing.len().to_string();
        let cleanup_refused_count = input.report.cleanup.refused.len().to_string();
        let materialization_created_count = input
            .report
            .materialization
            .as_ref()
            .map_or(0, |report| report.created.len())
            .to_string();
        let materialization_skipped_count = input
            .report
            .materialization
            .as_ref()
            .map_or(0, |report| report.skipped.len())
            .to_string();
        let deregistered_artifact_count = input.report.deregistered_artifact_count.to_string();
        let registered_artifact_count = input.report.registered_artifact_count.to_string();
        let remaining_registered_artifact_count =
            input.report.remaining_registered_artifact_count.to_string();
        let rotation_id = deception_rotation_id_from_hashes(
            input.endpoint_id,
            input.policy.policy_hash.as_str(),
            DeceptionRotationIdValues {
                old_plan_root: old_plan_root.as_str(),
                new_plan_root: new_plan_root.as_str(),
                old_plan_hash: old_plan_hash.as_str(),
                new_plan_hash: new_plan_hash.as_str(),
                report_hash: report_hash.as_str(),
                dry_run: dry_run.as_str(),
                cleanup_removed_count: cleanup_removed_count.as_str(),
                cleanup_would_remove_count: cleanup_would_remove_count.as_str(),
                cleanup_missing_count: cleanup_missing_count.as_str(),
                cleanup_refused_count: cleanup_refused_count.as_str(),
                materialization_created_count: materialization_created_count.as_str(),
                materialization_skipped_count: materialization_skipped_count.as_str(),
                deregistered_artifact_count: deregistered_artifact_count.as_str(),
                registered_artifact_count: registered_artifact_count.as_str(),
                remaining_registered_artifact_count: remaining_registered_artifact_count.as_str(),
            },
        );

        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::DeceptionRotation,
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
                finding_id: Some(rotation_id),
                rule_id: Some("endpoint.deception.rotation".to_string()),
                title: Some(if input.report.dry_run {
                    "Endpoint deception rotation dry run planned".to_string()
                } else {
                    "Endpoint deception rotation executed".to_string()
                }),
                severity: None,
                confidence: Some(1.0),
                action: EndpointDecisionAction::Observe,
                passed: cleanup_refused_count == "0",
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: EndpointGraphReference::default(),
            evidence: vec![
                EndpointReceiptEvidence::hashed("endpointId", input.endpoint_id),
                EndpointReceiptEvidence::hashed("oldDeceptionPlanRoot", old_plan_root),
                EndpointReceiptEvidence::hashed("newDeceptionPlanRoot", new_plan_root),
                EndpointReceiptEvidence::hashed("oldDeceptionPlanHash", &old_plan_hash),
                EndpointReceiptEvidence::hashed("newDeceptionPlanHash", &new_plan_hash),
                EndpointReceiptEvidence::hashed("rotationReportHash", &report_hash),
                EndpointReceiptEvidence::hashed("dryRun", dry_run),
                EndpointReceiptEvidence::hashed("cleanupRemovedCount", cleanup_removed_count),
                EndpointReceiptEvidence::hashed(
                    "cleanupWouldRemoveCount",
                    cleanup_would_remove_count,
                ),
                EndpointReceiptEvidence::hashed("cleanupMissingCount", cleanup_missing_count),
                EndpointReceiptEvidence::hashed("cleanupRefusedCount", cleanup_refused_count),
                EndpointReceiptEvidence::hashed(
                    "materializationCreatedCount",
                    materialization_created_count,
                ),
                EndpointReceiptEvidence::hashed(
                    "materializationSkippedCount",
                    materialization_skipped_count,
                ),
                EndpointReceiptEvidence::hashed(
                    "deregisteredArtifactCount",
                    deregistered_artifact_count,
                ),
                EndpointReceiptEvidence::hashed(
                    "registeredArtifactCount",
                    registered_artifact_count,
                ),
                EndpointReceiptEvidence::hashed(
                    "remainingRegisteredArtifactCount",
                    remaining_registered_artifact_count,
                ),
            ],
        }
    }

    #[must_use]
    pub fn for_simulation(input: EndpointSimulationReceiptInput<'_>) -> Self {
        let graph_ref =
            EndpointGraphReference::for_subgraph(&input.simulation.root_node_id, input.graph);
        let affected_identity_context =
            simulation_context_evidence_value(&input.simulation.affected_identities);
        let affected_tool_context =
            simulation_context_evidence_value(&input.simulation.affected_tools);
        let mut evidence = vec![
            EndpointReceiptEvidence::hashed("simulationId", &input.simulation.simulation_id),
            EndpointReceiptEvidence::hashed("rootNodeId", &input.simulation.root_node_id),
            EndpointReceiptEvidence::hashed("graphSliceId", &input.simulation.graph_slice_id),
            EndpointReceiptEvidence::hashed("wouldBlock", input.simulation.would_block.to_string()),
            EndpointReceiptEvidence::hashed(
                "developerBreakageScore",
                input.simulation.developer_breakage_score.to_string(),
            ),
            EndpointReceiptEvidence::hashed("impactLevel", input.simulation.impact_level.as_str()),
            EndpointReceiptEvidence::hashed(
                "affectedNodeCount",
                input.simulation.affected_node_count.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "affectedEdgeCount",
                input.simulation.affected_edge_count.to_string(),
            ),
            EndpointReceiptEvidence::hashed("affectedIdentityContext", affected_identity_context),
            EndpointReceiptEvidence::hashed("affectedToolContext", affected_tool_context),
        ];
        if let Some(content_hash) = graph_ref.content_hash.as_deref() {
            evidence.push(EndpointReceiptEvidence::hashed("contentHash", content_hash));
        }
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
                finding_id: Some(input.simulation.simulation_id.clone()),
                rule_id: Some(input.simulation.rule_id.clone()),
                title: Some("Endpoint policy impact simulation".to_string()),
                severity: None,
                confidence: Some(f32::from(input.simulation.developer_breakage_score) / 100.0),
                action: input.simulation.action.clone(),
                passed: true,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: graph_ref,
            evidence,
        }
    }

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
