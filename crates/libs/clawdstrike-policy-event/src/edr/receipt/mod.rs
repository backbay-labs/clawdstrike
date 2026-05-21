pub mod evidence;
pub mod families;
pub mod inputs;

pub use evidence::*;
pub use families::*;
pub use inputs::*;

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use hush_core::{
    canonicalize_json, sha256, Hash, Provenance, Receipt, SignedReceipt, Signer, Verdict,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
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
use super::{
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
        let decision_id = policy_decision_id_from_fields(
            input.actor.endpoint_id.as_str(),
            input.policy.policy_hash.as_str(),
            input.action_type,
            input.target,
            input.allowed,
            guard,
        );
        let mut evidence = vec![
            EndpointReceiptEvidence::hashed("actionType", input.action_type),
            EndpointReceiptEvidence::hashed("target", input.target),
            EndpointReceiptEvidence::hashed("allowed", allowed_text),
            EndpointReceiptEvidence::hashed("guard", guard),
        ];
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
                observation_id: None,
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
            graph: EndpointGraphReference::default(),
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
            actor: EndpointDecisionActor {
                endpoint_id: input.endpoint_id.to_string(),
                ..EndpointDecisionActor::default()
            },
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

    pub fn to_receipt(&self) -> Result<Receipt> {
        self.validate()?;
        let endpoint_metadata =
            serde_json::to_value(self).context("serialize endpoint decision receipt metadata")?;
        let canonical = canonicalize_json(&endpoint_metadata)
            .context("canonicalize endpoint decision receipt metadata")?;
        let content_hash = sha256(canonical.as_bytes());
        let policy_hash = Hash::from_hex(self.policy.policy_hash.as_str())
            .with_context(|| "policy hash must be a 32-byte hex hash")?;

        Ok(Receipt::new(content_hash, self.to_verdict())
            .with_id(self.receipt_id())
            .with_provenance(Provenance {
                clawdstrike_version: Some(env!("CARGO_PKG_VERSION").to_string()),
                provider: Some("clawdstrike.endpoint_decision_engine".to_string()),
                policy_hash: Some(policy_hash),
                ruleset: Some(self.policy.policy_version.clone()),
                violations: Vec::new(),
            })
            .with_metadata(serde_json::json!({
                "endpointDecision": endpoint_metadata,
            })))
    }

    pub fn sign_with(&self, signer: &dyn Signer) -> Result<SignedReceipt> {
        let actual_public_key = signer.public_key().to_hex();
        if let Some(expected_public_key) = self.signer.signer_public_key.as_deref() {
            if !hex_strings_match(expected_public_key, actual_public_key.as_str()) {
                return Err(anyhow!(
                    "endpoint receipt signer public key does not match signer identity metadata"
                ));
            }
        }

        let mut receipt = self.clone();
        if receipt.signer.signer_public_key.is_none() {
            receipt.signer.signer_public_key = Some(actual_public_key);
        }

        SignedReceipt::sign_with(receipt.to_receipt()?, signer)
            .context("sign endpoint decision receipt")
    }

    #[must_use]
    pub fn receipt_id(&self) -> String {
        let family = format!("{:?}", self.receipt_family);
        let sequence = self.local_sequence.to_string();
        let observation_id = self.decision.observation_id.as_deref().unwrap_or_default();
        let finding_id = self.decision.finding_id.as_deref().unwrap_or_default();
        stable_id(
            "endpoint_receipt",
            [
                self.schema_version.as_str(),
                self.actor.endpoint_id.as_str(),
                family.as_str(),
                sequence.as_str(),
                observation_id,
                finding_id,
            ],
        )
    }

    fn to_verdict(&self) -> Verdict {
        Verdict {
            passed: self.decision.passed,
            gate_id: self.decision.rule_id.clone().or_else(|| {
                Some(camel_debug_to_snake(
                    format!("{:?}", self.receipt_family).as_str(),
                ))
            }),
            scores: self.decision.confidence.map(|confidence| {
                serde_json::json!({
                    "confidence": confidence,
                })
            }),
            threshold: None,
        }
    }
}

fn require_field_eq(actual: &str, expected: &str, field_name: &str) -> Result<()> {
    if actual == expected {
        return Ok(());
    }
    Err(anyhow!(
        "{field_name} must be {expected}, got {}",
        if actual.is_empty() {
            "<missing>"
        } else {
            actual
        }
    ))
}

fn require_nonempty(value: &str, field_name: &str) -> Result<()> {
    if !value.trim().is_empty() {
        return Ok(());
    }
    Err(anyhow!("{field_name} is required"))
}

fn require_optional_nonempty(value: Option<&str>, field_name: &str) -> Result<()> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some(_) => Ok(()),
        None => Err(anyhow!("{field_name} is required")),
    }
}

fn require_nonzero(value: u64, field_name: &str) -> Result<()> {
    if value > 0 {
        return Ok(());
    }
    Err(anyhow!("{field_name} is required"))
}

fn require_confidence(value: Option<f32>, field_name: &str) -> Result<()> {
    match value {
        Some(value) if value.is_finite() && (0.0..=1.0).contains(&value) => Ok(()),
        Some(_) => Err(anyhow!("{field_name} must be between 0.0 and 1.0")),
        None => Err(anyhow!("{field_name} is required")),
    }
}

fn require_receipt_evidence(evidence: &[EndpointReceiptEvidence]) -> Result<()> {
    if evidence.is_empty() {
        return Err(anyhow!("endpoint receipt evidence is required"));
    }
    let mut evidence_keys = BTreeSet::new();
    for item in evidence {
        require_nonempty(item.key.as_str(), "endpoint receipt evidence key")?;
        let evidence_key = item.key.trim();
        if !evidence_keys.insert(evidence_key) {
            return Err(anyhow!(
                "duplicate evidence key {evidence_key} in endpoint receipt"
            ));
        }
        require_nonempty(
            item.value_hash.as_str(),
            "endpoint receipt evidence value hash",
        )?;
        Hash::from_hex(item.value_hash.as_str())
            .with_context(|| "endpoint receipt evidence value hash must be a 32-byte hex hash")?;
        if let Some(raw_value) = item.raw_value.as_deref() {
            if item.redaction_class != EndpointEvidenceRedactionClass::RawArtifactPermitted {
                return Err(anyhow!(
                    "endpoint receipt raw evidence requires raw artifact permitted redaction"
                ));
            }
            require_nonempty(raw_value, "endpoint receipt evidence raw value")?;
            let raw_value_hash = sha256(raw_value.as_bytes()).to_hex_prefixed();
            if item.value_hash != raw_value_hash {
                return Err(anyhow!(
                    "endpoint receipt raw evidence hash does not match raw evidence value"
                ));
            }
        }
    }
    Ok(())
}

fn require_evidence_value_hash(
    evidence: &[EndpointReceiptEvidence],
    key: &str,
    expected_value: impl AsRef<str>,
    field_name: &str,
) -> Result<()> {
    let Some(item) = evidence.iter().find(|item| item.key == key) else {
        return Err(anyhow!("{field_name} is required"));
    };
    let expected_hash = sha256(expected_value.as_ref().as_bytes()).to_hex_prefixed();
    if item.value_hash != expected_hash {
        return Err(anyhow!("{field_name} hash must match signed receipt field"));
    }
    Ok(())
}

fn require_response_request_receipt_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
    root_node_id: &str,
    graph_slice_id: &str,
    graph_content_hash: Option<&str>,
    ttl_seconds: u64,
    rollback_ref: &str,
) -> Result<()> {
    let dry_run = response_request_dry_run_from_decision(decision)?;
    let response_action_id = decision
        .finding_id
        .as_deref()
        .ok_or_else(|| anyhow!("response action id is required"))?;
    require_response_action_id_matches_signed_response_fields(
        response_action_id,
        root_node_id,
        graph_slice_id,
        &decision.action,
        ttl_seconds,
        if dry_run { "dry_run" } else { "execute" },
    )?;
    let expected_rollback_ref =
        expected_response_rollback_ref(&decision.action, dry_run, response_action_id);
    if rollback_ref != expected_rollback_ref {
        return Err(anyhow!(
            "response rollback evidence hash must match signed response action fields"
        ));
    }
    require_response_receipt_evidence_fields(
        evidence,
        response_action_id,
        root_node_id,
        graph_slice_id,
        graph_content_hash,
        ttl_seconds,
        rollback_ref,
    )
}

fn require_response_receipt_evidence(
    evidence: &[EndpointReceiptEvidence],
    action: &EndpointDecisionAction,
    root_node_id: &str,
    graph_slice_id: &str,
    ttl_seconds: u64,
    rollback_ref: &str,
) -> Result<()> {
    let response_action_id = response_action_id_from_rollback_ref(action, rollback_ref)?;
    require_response_action_id_matches_signed_response_fields(
        response_action_id.as_str(),
        root_node_id,
        graph_slice_id,
        action,
        ttl_seconds,
        "execute",
    )?;
    require_evidence_value_hash(
        evidence,
        "responseActionId",
        response_action_id.as_str(),
        "response action id evidence",
    )?;
    let expected_rollback_ref = expected_live_response_rollback_ref(action, &response_action_id);
    if rollback_ref != expected_rollback_ref {
        return Err(anyhow!(
            "response rollback evidence hash must match signed response action fields"
        ));
    }
    require_response_receipt_evidence_fields(
        evidence,
        response_action_id.as_str(),
        root_node_id,
        graph_slice_id,
        None,
        ttl_seconds,
        rollback_ref,
    )
}

fn require_response_receipt_evidence_fields(
    evidence: &[EndpointReceiptEvidence],
    response_action_id: &str,
    root_node_id: &str,
    graph_slice_id: &str,
    graph_content_hash: Option<&str>,
    ttl_seconds: u64,
    rollback_ref: &str,
) -> Result<()> {
    require_evidence_value_hash(
        evidence,
        "responseActionId",
        response_action_id,
        "response action id evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "rootNodeId",
        root_node_id,
        "response root node evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "graphSliceId",
        graph_slice_id,
        "response graph slice evidence",
    )?;
    if let Some(graph_content_hash) = graph_content_hash {
        require_evidence_value_hash(
            evidence,
            "contentHash",
            graph_content_hash,
            "response graph content hash evidence",
        )?;
    }
    require_evidence_value_hash(
        evidence,
        "ttlSeconds",
        ttl_seconds.to_string(),
        "response ttl evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "rollbackRef",
        rollback_ref,
        "response rollback evidence",
    )?;
    Ok(())
}

fn response_action_id_from_rollback_ref(
    action: &EndpointDecisionAction,
    rollback_ref: &str,
) -> Result<String> {
    let action_id = if action == &EndpointDecisionAction::CollectEvidence {
        rollback_ref
            .strip_prefix("rollback:noop:")
            .or_else(|| rollback_ref.strip_prefix("rollback:"))
    } else {
        rollback_ref.strip_prefix("rollback:")
    }
    .ok_or_else(|| {
        anyhow!("response rollback evidence hash must match signed response action fields")
    })?;
    require_nonempty(action_id, "response action id")?;
    Ok(action_id.to_string())
}

fn require_response_action_id_matches_signed_response_fields(
    response_action_id: &str,
    root_node_id: &str,
    graph_slice_id: &str,
    action: &EndpointDecisionAction,
    ttl_seconds: u64,
    mode: &str,
) -> Result<()> {
    let stable_response_action_id = response_action_id_from_signed_response_fields_with_mode(
        root_node_id,
        graph_slice_id,
        action,
        ttl_seconds,
        mode,
    );
    if response_action_id == stable_response_action_id {
        return Ok(());
    }
    let Some(issuance_id) = response_action_id
        .strip_prefix(stable_response_action_id.as_str())
        .and_then(|suffix| suffix.strip_prefix(':'))
    else {
        return Err(anyhow!(
            "response action id evidence hash must match signed response action fields"
        ));
    };
    Uuid::parse_str(issuance_id).map_err(|_| {
        anyhow!("response action id evidence hash must match signed response action fields")
    })?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn response_action_id_from_signed_response_fields(
    root_node_id: &str,
    graph_slice_id: &str,
    action: &EndpointDecisionAction,
    ttl_seconds: u64,
) -> String {
    response_action_id_from_signed_response_fields_with_mode(
        root_node_id,
        graph_slice_id,
        action,
        ttl_seconds,
        "execute",
    )
}

fn response_action_id_from_signed_response_fields_with_mode(
    root_node_id: &str,
    graph_slice_id: &str,
    action: &EndpointDecisionAction,
    ttl_seconds: u64,
    mode: &str,
) -> String {
    let ttl = ttl_seconds.to_string();
    stable_id(
        "response_action",
        [
            root_node_id,
            graph_slice_id,
            action.as_str(),
            mode,
            ttl.as_str(),
        ],
    )
}

fn expected_response_rollback_ref(
    action: &EndpointDecisionAction,
    dry_run: bool,
    response_action_id: &str,
) -> String {
    if !dry_run && action == &EndpointDecisionAction::CollectEvidence {
        format!("rollback:noop:{response_action_id}")
    } else {
        format!("rollback:{response_action_id}")
    }
}

fn expected_live_response_rollback_ref(
    action: &EndpointDecisionAction,
    response_action_id: &str,
) -> String {
    expected_response_rollback_ref(action, false, response_action_id)
}

fn telemetry_privacy_report_id_from_values(
    privacy_mode: &str,
    raw_artifact_upload_permitted: bool,
    raw_artifact_approval_id: Option<&str>,
    raw_artifact_approval_reason_hash: Option<&str>,
    count_values: [&str; 7],
) -> String {
    let privacy_mode_hash = sha256(privacy_mode.as_bytes()).to_hex_prefixed();
    let raw_permitted = raw_artifact_upload_permitted.to_string();
    let raw_permitted_hash = sha256(raw_permitted.as_bytes()).to_hex_prefixed();
    let observation_count_hash = sha256(count_values[0].as_bytes()).to_hex_prefixed();
    let field_count_hash = sha256(count_values[1].as_bytes()).to_hex_prefixed();
    let hash_only_count_hash = sha256(count_values[2].as_bytes()).to_hex_prefixed();
    let metadata_only_count_hash = sha256(count_values[3].as_bytes()).to_hex_prefixed();
    let redacted_count_hash = sha256(count_values[4].as_bytes()).to_hex_prefixed();
    let raw_suppressed_count_hash = sha256(count_values[5].as_bytes()).to_hex_prefixed();
    let local_only_count_hash = sha256(count_values[6].as_bytes()).to_hex_prefixed();
    let mut evidence_hashes = vec![
        privacy_mode_hash.as_str(),
        raw_permitted_hash.as_str(),
        observation_count_hash.as_str(),
        field_count_hash.as_str(),
        hash_only_count_hash.as_str(),
        metadata_only_count_hash.as_str(),
        redacted_count_hash.as_str(),
        raw_suppressed_count_hash.as_str(),
        local_only_count_hash.as_str(),
    ];
    let raw_artifact_approval_id_hash =
        raw_artifact_approval_id.map(|value| sha256(value.as_bytes()).to_hex_prefixed());
    let raw_artifact_approval_reason_hash_hash =
        raw_artifact_approval_reason_hash.map(|value| sha256(value.as_bytes()).to_hex_prefixed());
    let empty_hash = sha256(b"").to_hex_prefixed();
    if raw_artifact_upload_permitted {
        evidence_hashes.push(
            raw_artifact_approval_id_hash
                .as_deref()
                .unwrap_or(empty_hash.as_str()),
        );
        evidence_hashes.push(
            raw_artifact_approval_reason_hash_hash
                .as_deref()
                .unwrap_or(empty_hash.as_str()),
        );
    }
    telemetry_privacy_report_id_from_evidence_hashes(evidence_hashes)
}

fn telemetry_privacy_report_id_from_evidence(
    evidence: &[EndpointReceiptEvidence],
) -> Result<String> {
    let raw_artifact_upload_permitted_hash = evidence_value_hash(
        evidence,
        "rawArtifactUploadPermitted",
        "privacy report raw artifact permission evidence",
    )?;
    let mut evidence_hashes = vec![
        evidence_value_hash(evidence, "privacyMode", "privacy report mode evidence")?,
        raw_artifact_upload_permitted_hash,
        evidence_value_hash(
            evidence,
            "observationCount",
            "privacy report observation count evidence",
        )?,
        evidence_value_hash(
            evidence,
            "fieldCount",
            "privacy report field count evidence",
        )?,
        evidence_value_hash(
            evidence,
            "hashOnlyCount",
            "privacy report hash-only count evidence",
        )?,
        evidence_value_hash(
            evidence,
            "metadataOnlyCount",
            "privacy report metadata-only count evidence",
        )?,
        evidence_value_hash(
            evidence,
            "redactedCount",
            "privacy report redacted count evidence",
        )?,
        evidence_value_hash(
            evidence,
            "rawSuppressedCount",
            "privacy report raw suppressed count evidence",
        )?,
        evidence_value_hash(
            evidence,
            "localOnlyCount",
            "privacy report local-only count evidence",
        )?,
    ];
    let true_hash = sha256(b"true").to_hex_prefixed();
    if hex_strings_match(raw_artifact_upload_permitted_hash, true_hash.as_str()) {
        evidence_hashes.push(evidence_value_hash(
            evidence,
            "rawArtifactApprovalId",
            "privacy report raw artifact approval id evidence",
        )?);
        evidence_hashes.push(evidence_value_hash(
            evidence,
            "rawArtifactApprovalReasonHash",
            "privacy report raw artifact approval reason hash evidence",
        )?);
    }
    Ok(telemetry_privacy_report_id_from_evidence_hashes(
        evidence_hashes,
    ))
}

fn telemetry_privacy_report_id_from_evidence_hashes<'a>(
    evidence_hashes: impl IntoIterator<Item = &'a str>,
) -> String {
    stable_id("telemetry_privacy_report", evidence_hashes)
}

fn provider_degradation_id_from_provider(
    endpoint_id: &str,
    policy_hash: &str,
    provider: &EndpointProviderState,
) -> String {
    let provider_kind = camel_debug_to_snake(format!("{:?}", provider.provider_kind).as_str());
    let reasons = provider.degradation_reasons.join("|");
    let dropped_event_count = provider.dropped_event_count.to_string();
    let deadline_miss_count = provider.deadline_miss_count.to_string();
    let full_disk_access =
        endpoint_provider_full_disk_access_evidence_value(provider.full_disk_access);
    let provider_id_hash = sha256(provider.provider_id.as_bytes()).to_hex_prefixed();
    let provider_kind_hash = sha256(provider_kind.as_bytes()).to_hex_prefixed();
    let installed_hash = sha256(provider.installed.to_string().as_bytes()).to_hex_prefixed();
    let active_hash = sha256(provider.active.to_string().as_bytes()).to_hex_prefixed();
    let healthy_hash = sha256(provider.healthy.to_string().as_bytes()).to_hex_prefixed();
    let degraded_hash = sha256(provider.degraded.to_string().as_bytes()).to_hex_prefixed();
    let reasons_hash = sha256(reasons.as_bytes()).to_hex_prefixed();
    let dropped_event_count_hash = sha256(dropped_event_count.as_bytes()).to_hex_prefixed();
    let deadline_miss_count_hash = sha256(deadline_miss_count.as_bytes()).to_hex_prefixed();
    let full_disk_access_hash = sha256(full_disk_access.as_bytes()).to_hex_prefixed();
    provider_degradation_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        [
            provider_id_hash.as_str(),
            provider_kind_hash.as_str(),
            installed_hash.as_str(),
            active_hash.as_str(),
            healthy_hash.as_str(),
            degraded_hash.as_str(),
            reasons_hash.as_str(),
            dropped_event_count_hash.as_str(),
            deadline_miss_count_hash.as_str(),
            full_disk_access_hash.as_str(),
        ],
    )
}

fn provider_degradation_id_from_evidence(
    evidence: &[EndpointReceiptEvidence],
    endpoint_id: &str,
    policy_hash: &str,
) -> Result<String> {
    Ok(provider_degradation_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        [
            evidence_value_hash(
                evidence,
                "providerId",
                "provider degradation provider id evidence",
            )?,
            evidence_value_hash(
                evidence,
                "providerKind",
                "provider degradation provider kind evidence",
            )?,
            evidence_value_hash(
                evidence,
                "installed",
                "provider degradation installed evidence",
            )?,
            evidence_value_hash(evidence, "active", "provider degradation active evidence")?,
            evidence_value_hash(evidence, "healthy", "provider degradation healthy evidence")?,
            evidence_value_hash(
                evidence,
                "degraded",
                "provider degradation degraded evidence",
            )?,
            evidence_value_hash(
                evidence,
                "degradationReasons",
                "provider degradation reasons evidence",
            )?,
            evidence_value_hash(
                evidence,
                "droppedEventCount",
                "provider degradation dropped-event count evidence",
            )?,
            evidence_value_hash(
                evidence,
                "deadlineMissCount",
                "provider degradation deadline-miss count evidence",
            )?,
            evidence_value_hash(
                evidence,
                "fullDiskAccess",
                "provider degradation full-disk-access evidence",
            )?,
        ],
    ))
}

fn provider_degradation_id_from_evidence_hashes(
    endpoint_id: &str,
    policy_hash: &str,
    evidence_hashes: [&str; 10],
) -> String {
    stable_id(
        "provider_degradation",
        [
            endpoint_id,
            policy_hash,
            evidence_hashes[0],
            evidence_hashes[1],
            evidence_hashes[2],
            evidence_hashes[3],
            evidence_hashes[4],
            evidence_hashes[5],
            evidence_hashes[6],
            evidence_hashes[7],
            evidence_hashes[8],
            evidence_hashes[9],
        ],
    )
}

fn endpoint_provider_full_disk_access_evidence_value(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "unknown",
    }
}

fn policy_decision_id_from_fields(
    endpoint_id: &str,
    policy_hash: &str,
    action_type: &str,
    target: &str,
    allowed: bool,
    guard: &str,
) -> String {
    let target_evidence_hash = sha256(target.as_bytes()).to_hex_prefixed();
    let guard_evidence_hash = sha256(guard.as_bytes()).to_hex_prefixed();
    policy_decision_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        action_type,
        target_evidence_hash.as_str(),
        allowed,
        guard_evidence_hash.as_str(),
    )
}

fn policy_decision_id_from_evidence(
    evidence: &[EndpointReceiptEvidence],
    endpoint_id: &str,
    policy_hash: &str,
    action_type: &str,
    allowed: bool,
) -> Result<String> {
    let target_evidence_hash =
        evidence_value_hash(evidence, "target", "policy decision target evidence")?;
    let guard_evidence_hash =
        evidence_value_hash(evidence, "guard", "policy decision guard evidence")?;
    Ok(policy_decision_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        action_type,
        target_evidence_hash,
        allowed,
        guard_evidence_hash,
    ))
}

fn policy_decision_id_from_evidence_hashes(
    endpoint_id: &str,
    policy_hash: &str,
    action_type: &str,
    target_evidence_hash: &str,
    allowed: bool,
    guard_evidence_hash: &str,
) -> String {
    let allowed_text = allowed.to_string();
    stable_id(
        "policy_decision",
        [
            endpoint_id,
            policy_hash,
            action_type,
            target_evidence_hash,
            allowed_text.as_str(),
            guard_evidence_hash,
        ],
    )
}

fn require_subgraph_reference(graph: &EndpointGraphReference, label: &str) -> Result<()> {
    let root_node_id = graph
        .process_node_id
        .as_deref()
        .ok_or_else(|| anyhow!("{label} graph root reference is required"))?;
    if !graph.node_ids.iter().any(|node_id| node_id == root_node_id) {
        return Err(anyhow!(
            "{label} graph root reference must be included in graph node ids"
        ));
    }

    let graph_slice_id = graph
        .graph_slice_id
        .as_deref()
        .ok_or_else(|| anyhow!("{label} graph slice reference is required"))?;
    let graph_content_hash = graph
        .content_hash
        .as_deref()
        .ok_or_else(|| anyhow!("{label} graph content hash is required"))?;
    let expected_graph_slice_id = stable_id("graph_slice", [root_node_id, graph_content_hash]);
    if graph_slice_id != expected_graph_slice_id {
        return Err(anyhow!(
            "{label} graph slice reference must match root and graph content hash"
        ));
    }
    Ok(())
}

fn require_response_family_id_evidence(
    evidence: &[EndpointReceiptEvidence],
    key: &str,
    signed_id: Option<&str>,
    field_name: &str,
) -> Result<()> {
    let signed_id = signed_id.ok_or_else(|| anyhow!("{field_name} signed id is required"))?;
    require_evidence_value_hash(evidence, key, signed_id, field_name)
}

fn require_response_request_dry_run_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let expected_dry_run = if response_request_dry_run_from_decision(decision)? {
        "true"
    } else {
        "false"
    };
    require_evidence_value_hash(
        evidence,
        "dryRun",
        expected_dry_run,
        "response dry-run evidence",
    )
}

fn response_request_dry_run_from_decision(decision: &EndpointDecisionRecord) -> Result<bool> {
    let title = decision
        .title
        .as_deref()
        .ok_or_else(|| anyhow!("response request title is required"))?;
    match title {
        "Endpoint response action dry run planned" => Ok(true),
        "Endpoint response action planned" => Ok(false),
        _ => Err(anyhow!("response request title is invalid")),
    }
}

fn require_response_reason_evidence(evidence: &[EndpointReceiptEvidence]) -> Result<()> {
    let Some(item) = evidence.iter().find(|item| item.key == "reason") else {
        return Err(anyhow!("response reason evidence is required"));
    };
    let empty_reason_hash = sha256(b"").to_hex_prefixed();
    if item.value_hash == empty_reason_hash {
        return Err(anyhow!("response reason evidence must not be empty"));
    }
    Ok(())
}

fn require_response_execution_id_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    graph_slice_id: &str,
    graph_content_hash: Option<&str>,
) -> Result<()> {
    require_response_family_id_evidence(
        evidence,
        "executionId",
        decision.finding_id.as_deref(),
        "execution id evidence",
    )?;
    let Some(expected_execution_id) = response_execution_id_from_signed_fields(
        decision,
        graph_slice_id,
        graph_content_hash,
        evidence,
    )?
    else {
        return Ok(());
    };
    if decision.finding_id.as_deref() != Some(expected_execution_id.as_str()) {
        return Err(anyhow!(
            "execution id evidence hash must match signed response action fields"
        ));
    }
    require_evidence_value_hash(
        evidence,
        "executionId",
        expected_execution_id.as_str(),
        "execution id evidence",
    )
}

fn require_response_execution_evidence_bundle_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    graph_slice_id: &str,
    graph_content_hash: Option<&str>,
) -> Result<()> {
    let graph_content_hash = graph_content_hash
        .ok_or_else(|| anyhow!("execution evidence bundle graph content hash is required"))?;
    let evidence_bundle_id = response_execution_bundle_id_from_signed_fields(
        decision,
        graph_slice_id,
        graph_content_hash,
    )?;
    require_evidence_value_hash(
        evidence,
        "evidenceBundleId",
        evidence_bundle_id.as_str(),
        "execution evidence bundle id evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "evidenceBundleContentHash",
        graph_content_hash,
        "execution evidence bundle content hash evidence",
    )
}

fn response_execution_id_from_signed_fields(
    decision: &EndpointDecisionRecord,
    graph_slice_id: &str,
    graph_content_hash: Option<&str>,
    evidence: &[EndpointReceiptEvidence],
) -> Result<Option<String>> {
    let status = response_execution_status_from_decision(decision)?;
    let graph_content_hash =
        graph_content_hash.ok_or_else(|| anyhow!("execution id graph content hash is required"))?;
    let evidence_bundle_id = response_execution_bundle_id_from_signed_fields(
        decision,
        graph_slice_id,
        graph_content_hash,
    )?;
    let rollback_ref = decision
        .rollback_ref
        .as_deref()
        .ok_or_else(|| anyhow!("response rollback ref is required"))?;
    let response_action_id = response_action_id_from_rollback_ref(&decision.action, rollback_ref)?;
    if let Some(prefix) = response_execution_transition_id_prefix(status) {
        let reason_hash = response_execution_reason_evidence_hash(evidence)?;
        return Ok(Some(response_execution_transition_id_from_reason_hash(
            prefix,
            response_action_id.as_str(),
            evidence_bundle_id.as_str(),
            rollback_ref,
            reason_hash,
        )));
    }
    if let Some(effect_binding_digest) =
        response_execution_effect_binding_digest_from_evidence(evidence)?
    {
        if decision.action == EndpointDecisionAction::CollectEvidence {
            return Err(anyhow!(
                "collect evidence execution effect evidence is invalid"
            ));
        }
        return Ok(Some(response_execution_id_from_effect_digest(
            response_action_id.as_str(),
            evidence_bundle_id.as_str(),
            effect_binding_digest.as_str(),
        )));
    }
    if decision.action != EndpointDecisionAction::CollectEvidence {
        return Err(anyhow!("execution effect evidence is required"));
    }
    Ok(Some(stable_id(
        "response_execution",
        [
            response_action_id.as_str(),
            evidence_bundle_id.as_str(),
            graph_content_hash,
        ],
    )))
}

fn response_execution_transition_id_prefix(status: &str) -> Option<&'static str> {
    match status {
        "failed" => Some("response_execution_failed"),
        "partial" => Some("response_execution_partial"),
        "rollback_pending" => Some("response_execution_rollback_pending"),
        "rollback_failed" => Some("response_execution_rollback_failed"),
        "expired" => Some("response_execution_expired"),
        "cancelled" => Some("response_execution_cancelled"),
        "rolled_back" => Some("response_execution_rolled_back"),
        _ => None,
    }
}

fn response_execution_reason_evidence_hash(evidence: &[EndpointReceiptEvidence]) -> Result<&str> {
    let Some(reason) = evidence.iter().find(|item| item.key == "reason") else {
        return Err(anyhow!("response transition reason evidence is required"));
    };
    require_evidence_hash_not_empty(reason, "response transition reason evidence")?;
    Ok(reason.value_hash.as_str())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResponseExecutionEffectBindingEntry {
    key: String,
    value_hash: String,
}

fn response_execution_id_from_effects(
    response_action_id: &str,
    evidence_bundle_id: &str,
    effects: &[EndpointResponseExecutionEffect],
) -> Result<String> {
    let effect_binding_digest = response_execution_effect_binding_digest_from_effects(effects)?
        .ok_or_else(|| anyhow!("response execution effect binding requires at least one effect"))?;
    Ok(response_execution_id_from_effect_digest(
        response_action_id,
        evidence_bundle_id,
        effect_binding_digest.as_str(),
    ))
}

fn response_execution_id_from_effect_digest(
    response_action_id: &str,
    evidence_bundle_id: &str,
    effect_binding_digest: &str,
) -> String {
    stable_id(
        "response_execution",
        [
            response_action_id,
            evidence_bundle_id,
            effect_binding_digest,
        ],
    )
}

fn response_execution_transition_id_from_reason_hash(
    prefix: &str,
    response_action_id: &str,
    evidence_bundle_id: &str,
    rollback_ref: &str,
    reason_hash: &str,
) -> String {
    stable_id(
        prefix,
        [
            response_action_id,
            evidence_bundle_id,
            rollback_ref,
            reason_hash,
        ],
    )
}

struct DeceptionMaterializationIdValues<'a> {
    plan_root: &'a str,
    plan_hash: &'a str,
    report_hash: &'a str,
    artifact_count: &'a str,
    created_count: &'a str,
    skipped_count: &'a str,
    registered_artifact_count: &'a str,
    artifact_ids: &'a str,
}

struct DeceptionMaterializationIdEvidenceHashes<'a> {
    plan_root_evidence_hash: &'a str,
    plan_hash_evidence_hash: &'a str,
    report_hash_evidence_hash: &'a str,
    artifact_count_evidence_hash: &'a str,
    created_count_evidence_hash: &'a str,
    skipped_count_evidence_hash: &'a str,
    registered_artifact_count_evidence_hash: &'a str,
    artifact_ids_evidence_hash: &'a str,
}

fn deception_materialization_id_from_hashes(
    endpoint_id: &str,
    policy_hash: &str,
    values: DeceptionMaterializationIdValues<'_>,
) -> String {
    let plan_root_evidence_hash = sha256(values.plan_root.as_bytes()).to_hex_prefixed();
    let plan_hash_evidence_hash = sha256(values.plan_hash.as_bytes()).to_hex_prefixed();
    let report_hash_evidence_hash = sha256(values.report_hash.as_bytes()).to_hex_prefixed();
    let artifact_count_evidence_hash = sha256(values.artifact_count.as_bytes()).to_hex_prefixed();
    let created_count_evidence_hash = sha256(values.created_count.as_bytes()).to_hex_prefixed();
    let skipped_count_evidence_hash = sha256(values.skipped_count.as_bytes()).to_hex_prefixed();
    let registered_artifact_count_evidence_hash =
        sha256(values.registered_artifact_count.as_bytes()).to_hex_prefixed();
    let artifact_ids_evidence_hash = sha256(values.artifact_ids.as_bytes()).to_hex_prefixed();
    deception_materialization_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        DeceptionMaterializationIdEvidenceHashes {
            plan_root_evidence_hash: plan_root_evidence_hash.as_str(),
            plan_hash_evidence_hash: plan_hash_evidence_hash.as_str(),
            report_hash_evidence_hash: report_hash_evidence_hash.as_str(),
            artifact_count_evidence_hash: artifact_count_evidence_hash.as_str(),
            created_count_evidence_hash: created_count_evidence_hash.as_str(),
            skipped_count_evidence_hash: skipped_count_evidence_hash.as_str(),
            registered_artifact_count_evidence_hash: registered_artifact_count_evidence_hash
                .as_str(),
            artifact_ids_evidence_hash: artifact_ids_evidence_hash.as_str(),
        },
    )
}

fn deception_materialization_id_from_evidence(
    evidence: &[EndpointReceiptEvidence],
    endpoint_id: &str,
    policy_hash: &str,
) -> Result<String> {
    let plan_root_evidence_hash = evidence_value_hash(
        evidence,
        "deceptionPlanRoot",
        "deception materialization plan root evidence",
    )?;
    let plan_hash_evidence_hash = evidence_value_hash(
        evidence,
        "deceptionPlanHash",
        "deception materialization plan hash evidence",
    )?;
    let report_hash_evidence_hash = evidence_value_hash(
        evidence,
        "materializationReportHash",
        "deception materialization report hash evidence",
    )?;
    let artifact_count_evidence_hash = evidence_value_hash(
        evidence,
        "artifactCount",
        "deception materialization artifact count evidence",
    )?;
    let created_count_evidence_hash = evidence_value_hash(
        evidence,
        "createdCount",
        "deception materialization created count evidence",
    )?;
    let skipped_count_evidence_hash = evidence_value_hash(
        evidence,
        "skippedCount",
        "deception materialization skipped count evidence",
    )?;
    let registered_artifact_count_evidence_hash = evidence_value_hash(
        evidence,
        "registeredArtifactCount",
        "deception materialization registered artifact count evidence",
    )?;
    let artifact_ids_evidence_hash = evidence_value_hash(
        evidence,
        "artifactIds",
        "deception materialization artifact ids evidence",
    )?;
    Ok(deception_materialization_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        DeceptionMaterializationIdEvidenceHashes {
            plan_root_evidence_hash,
            plan_hash_evidence_hash,
            report_hash_evidence_hash,
            artifact_count_evidence_hash,
            created_count_evidence_hash,
            skipped_count_evidence_hash,
            registered_artifact_count_evidence_hash,
            artifact_ids_evidence_hash,
        },
    ))
}

fn deception_materialization_id_from_evidence_hashes(
    endpoint_id: &str,
    policy_hash: &str,
    evidence_hashes: DeceptionMaterializationIdEvidenceHashes<'_>,
) -> String {
    stable_id(
        "deception_materialization",
        [
            endpoint_id,
            policy_hash,
            evidence_hashes.plan_root_evidence_hash,
            evidence_hashes.plan_hash_evidence_hash,
            evidence_hashes.report_hash_evidence_hash,
            evidence_hashes.artifact_count_evidence_hash,
            evidence_hashes.created_count_evidence_hash,
            evidence_hashes.skipped_count_evidence_hash,
            evidence_hashes.registered_artifact_count_evidence_hash,
            evidence_hashes.artifact_ids_evidence_hash,
        ],
    )
}

struct DeceptionCleanupIdValues<'a> {
    plan_root: &'a str,
    plan_hash: &'a str,
    report_hash: &'a str,
    artifact_count: &'a str,
    dry_run: &'a str,
    removed_count: &'a str,
    would_remove_count: &'a str,
    missing_count: &'a str,
    refused_count: &'a str,
    deregistered_artifact_count: &'a str,
    remaining_registered_artifact_count: &'a str,
}

struct DeceptionCleanupIdEvidenceHashes<'a> {
    plan_root_evidence_hash: &'a str,
    plan_hash_evidence_hash: &'a str,
    report_hash_evidence_hash: &'a str,
    artifact_count_evidence_hash: &'a str,
    dry_run_evidence_hash: &'a str,
    removed_count_evidence_hash: &'a str,
    would_remove_count_evidence_hash: &'a str,
    missing_count_evidence_hash: &'a str,
    refused_count_evidence_hash: &'a str,
    deregistered_artifact_count_evidence_hash: &'a str,
    remaining_registered_artifact_count_evidence_hash: &'a str,
}

fn deception_cleanup_id_from_hashes(
    endpoint_id: &str,
    policy_hash: &str,
    values: DeceptionCleanupIdValues<'_>,
) -> String {
    let plan_root_evidence_hash = sha256(values.plan_root.as_bytes()).to_hex_prefixed();
    let plan_hash_evidence_hash = sha256(values.plan_hash.as_bytes()).to_hex_prefixed();
    let report_hash_evidence_hash = sha256(values.report_hash.as_bytes()).to_hex_prefixed();
    let artifact_count_evidence_hash = sha256(values.artifact_count.as_bytes()).to_hex_prefixed();
    let dry_run_evidence_hash = sha256(values.dry_run.as_bytes()).to_hex_prefixed();
    let removed_count_evidence_hash = sha256(values.removed_count.as_bytes()).to_hex_prefixed();
    let would_remove_count_evidence_hash =
        sha256(values.would_remove_count.as_bytes()).to_hex_prefixed();
    let missing_count_evidence_hash = sha256(values.missing_count.as_bytes()).to_hex_prefixed();
    let refused_count_evidence_hash = sha256(values.refused_count.as_bytes()).to_hex_prefixed();
    let deregistered_artifact_count_evidence_hash =
        sha256(values.deregistered_artifact_count.as_bytes()).to_hex_prefixed();
    let remaining_registered_artifact_count_evidence_hash =
        sha256(values.remaining_registered_artifact_count.as_bytes()).to_hex_prefixed();
    deception_cleanup_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        DeceptionCleanupIdEvidenceHashes {
            plan_root_evidence_hash: plan_root_evidence_hash.as_str(),
            plan_hash_evidence_hash: plan_hash_evidence_hash.as_str(),
            report_hash_evidence_hash: report_hash_evidence_hash.as_str(),
            artifact_count_evidence_hash: artifact_count_evidence_hash.as_str(),
            dry_run_evidence_hash: dry_run_evidence_hash.as_str(),
            removed_count_evidence_hash: removed_count_evidence_hash.as_str(),
            would_remove_count_evidence_hash: would_remove_count_evidence_hash.as_str(),
            missing_count_evidence_hash: missing_count_evidence_hash.as_str(),
            refused_count_evidence_hash: refused_count_evidence_hash.as_str(),
            deregistered_artifact_count_evidence_hash: deregistered_artifact_count_evidence_hash
                .as_str(),
            remaining_registered_artifact_count_evidence_hash:
                remaining_registered_artifact_count_evidence_hash.as_str(),
        },
    )
}

fn deception_cleanup_id_from_evidence(
    evidence: &[EndpointReceiptEvidence],
    endpoint_id: &str,
    policy_hash: &str,
) -> Result<String> {
    let plan_root_evidence_hash = evidence_value_hash(
        evidence,
        "deceptionPlanRoot",
        "deception cleanup plan root evidence",
    )?;
    let plan_hash_evidence_hash = evidence_value_hash(
        evidence,
        "deceptionPlanHash",
        "deception cleanup plan hash evidence",
    )?;
    let report_hash_evidence_hash = evidence_value_hash(
        evidence,
        "cleanupReportHash",
        "deception cleanup report hash evidence",
    )?;
    let artifact_count_evidence_hash = evidence_value_hash(
        evidence,
        "artifactCount",
        "deception cleanup artifact count evidence",
    )?;
    let dry_run_evidence_hash =
        evidence_value_hash(evidence, "dryRun", "deception cleanup dry-run evidence")?;
    let removed_count_evidence_hash = evidence_value_hash(
        evidence,
        "removedCount",
        "deception cleanup removed count evidence",
    )?;
    let would_remove_count_evidence_hash = evidence_value_hash(
        evidence,
        "wouldRemoveCount",
        "deception cleanup would-remove count evidence",
    )?;
    let missing_count_evidence_hash = evidence_value_hash(
        evidence,
        "missingCount",
        "deception cleanup missing count evidence",
    )?;
    let refused_count_evidence_hash = evidence_value_hash(
        evidence,
        "refusedCount",
        "deception cleanup refused count evidence",
    )?;
    let deregistered_artifact_count_evidence_hash = evidence_value_hash(
        evidence,
        "deregisteredArtifactCount",
        "deception cleanup deregistered artifact count evidence",
    )?;
    let remaining_registered_artifact_count_evidence_hash = evidence_value_hash(
        evidence,
        "remainingRegisteredArtifactCount",
        "deception cleanup remaining registered artifact count evidence",
    )?;
    Ok(deception_cleanup_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        DeceptionCleanupIdEvidenceHashes {
            plan_root_evidence_hash,
            plan_hash_evidence_hash,
            report_hash_evidence_hash,
            artifact_count_evidence_hash,
            dry_run_evidence_hash,
            removed_count_evidence_hash,
            would_remove_count_evidence_hash,
            missing_count_evidence_hash,
            refused_count_evidence_hash,
            deregistered_artifact_count_evidence_hash,
            remaining_registered_artifact_count_evidence_hash,
        },
    ))
}

fn deception_cleanup_id_from_evidence_hashes(
    endpoint_id: &str,
    policy_hash: &str,
    evidence_hashes: DeceptionCleanupIdEvidenceHashes<'_>,
) -> String {
    stable_id(
        "deception_cleanup",
        [
            endpoint_id,
            policy_hash,
            evidence_hashes.plan_root_evidence_hash,
            evidence_hashes.plan_hash_evidence_hash,
            evidence_hashes.report_hash_evidence_hash,
            evidence_hashes.artifact_count_evidence_hash,
            evidence_hashes.dry_run_evidence_hash,
            evidence_hashes.removed_count_evidence_hash,
            evidence_hashes.would_remove_count_evidence_hash,
            evidence_hashes.missing_count_evidence_hash,
            evidence_hashes.refused_count_evidence_hash,
            evidence_hashes.deregistered_artifact_count_evidence_hash,
            evidence_hashes.remaining_registered_artifact_count_evidence_hash,
        ],
    )
}

struct DeceptionRotationIdValues<'a> {
    old_plan_root: &'a str,
    new_plan_root: &'a str,
    old_plan_hash: &'a str,
    new_plan_hash: &'a str,
    report_hash: &'a str,
    dry_run: &'a str,
    cleanup_removed_count: &'a str,
    cleanup_would_remove_count: &'a str,
    cleanup_missing_count: &'a str,
    cleanup_refused_count: &'a str,
    materialization_created_count: &'a str,
    materialization_skipped_count: &'a str,
    deregistered_artifact_count: &'a str,
    registered_artifact_count: &'a str,
    remaining_registered_artifact_count: &'a str,
}

struct DeceptionRotationIdEvidenceHashes<'a> {
    old_plan_root_evidence_hash: &'a str,
    new_plan_root_evidence_hash: &'a str,
    old_plan_hash_evidence_hash: &'a str,
    new_plan_hash_evidence_hash: &'a str,
    report_hash_evidence_hash: &'a str,
    dry_run_evidence_hash: &'a str,
    cleanup_removed_count_evidence_hash: &'a str,
    cleanup_would_remove_count_evidence_hash: &'a str,
    cleanup_missing_count_evidence_hash: &'a str,
    cleanup_refused_count_evidence_hash: &'a str,
    materialization_created_count_evidence_hash: &'a str,
    materialization_skipped_count_evidence_hash: &'a str,
    deregistered_artifact_count_evidence_hash: &'a str,
    registered_artifact_count_evidence_hash: &'a str,
    remaining_registered_artifact_count_evidence_hash: &'a str,
}

fn deception_rotation_id_from_hashes(
    endpoint_id: &str,
    policy_hash: &str,
    values: DeceptionRotationIdValues<'_>,
) -> String {
    let old_plan_root_evidence_hash = sha256(values.old_plan_root.as_bytes()).to_hex_prefixed();
    let new_plan_root_evidence_hash = sha256(values.new_plan_root.as_bytes()).to_hex_prefixed();
    let old_plan_hash_evidence_hash = sha256(values.old_plan_hash.as_bytes()).to_hex_prefixed();
    let new_plan_hash_evidence_hash = sha256(values.new_plan_hash.as_bytes()).to_hex_prefixed();
    let report_hash_evidence_hash = sha256(values.report_hash.as_bytes()).to_hex_prefixed();
    let dry_run_evidence_hash = sha256(values.dry_run.as_bytes()).to_hex_prefixed();
    let cleanup_removed_count_evidence_hash =
        sha256(values.cleanup_removed_count.as_bytes()).to_hex_prefixed();
    let cleanup_would_remove_count_evidence_hash =
        sha256(values.cleanup_would_remove_count.as_bytes()).to_hex_prefixed();
    let cleanup_missing_count_evidence_hash =
        sha256(values.cleanup_missing_count.as_bytes()).to_hex_prefixed();
    let cleanup_refused_count_evidence_hash =
        sha256(values.cleanup_refused_count.as_bytes()).to_hex_prefixed();
    let materialization_created_count_evidence_hash =
        sha256(values.materialization_created_count.as_bytes()).to_hex_prefixed();
    let materialization_skipped_count_evidence_hash =
        sha256(values.materialization_skipped_count.as_bytes()).to_hex_prefixed();
    let deregistered_artifact_count_evidence_hash =
        sha256(values.deregistered_artifact_count.as_bytes()).to_hex_prefixed();
    let registered_artifact_count_evidence_hash =
        sha256(values.registered_artifact_count.as_bytes()).to_hex_prefixed();
    let remaining_registered_artifact_count_evidence_hash =
        sha256(values.remaining_registered_artifact_count.as_bytes()).to_hex_prefixed();
    deception_rotation_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        DeceptionRotationIdEvidenceHashes {
            old_plan_root_evidence_hash: old_plan_root_evidence_hash.as_str(),
            new_plan_root_evidence_hash: new_plan_root_evidence_hash.as_str(),
            old_plan_hash_evidence_hash: old_plan_hash_evidence_hash.as_str(),
            new_plan_hash_evidence_hash: new_plan_hash_evidence_hash.as_str(),
            report_hash_evidence_hash: report_hash_evidence_hash.as_str(),
            dry_run_evidence_hash: dry_run_evidence_hash.as_str(),
            cleanup_removed_count_evidence_hash: cleanup_removed_count_evidence_hash.as_str(),
            cleanup_would_remove_count_evidence_hash: cleanup_would_remove_count_evidence_hash
                .as_str(),
            cleanup_missing_count_evidence_hash: cleanup_missing_count_evidence_hash.as_str(),
            cleanup_refused_count_evidence_hash: cleanup_refused_count_evidence_hash.as_str(),
            materialization_created_count_evidence_hash:
                materialization_created_count_evidence_hash.as_str(),
            materialization_skipped_count_evidence_hash:
                materialization_skipped_count_evidence_hash.as_str(),
            deregistered_artifact_count_evidence_hash: deregistered_artifact_count_evidence_hash
                .as_str(),
            registered_artifact_count_evidence_hash: registered_artifact_count_evidence_hash
                .as_str(),
            remaining_registered_artifact_count_evidence_hash:
                remaining_registered_artifact_count_evidence_hash.as_str(),
        },
    )
}

fn deception_rotation_id_from_evidence(
    evidence: &[EndpointReceiptEvidence],
    endpoint_id: &str,
    policy_hash: &str,
) -> Result<String> {
    let old_plan_root_evidence_hash = evidence_value_hash(
        evidence,
        "oldDeceptionPlanRoot",
        "deception rotation old plan root evidence",
    )?;
    let new_plan_root_evidence_hash = evidence_value_hash(
        evidence,
        "newDeceptionPlanRoot",
        "deception rotation new plan root evidence",
    )?;
    let old_plan_hash_evidence_hash = evidence_value_hash(
        evidence,
        "oldDeceptionPlanHash",
        "deception rotation old plan hash evidence",
    )?;
    let new_plan_hash_evidence_hash = evidence_value_hash(
        evidence,
        "newDeceptionPlanHash",
        "deception rotation new plan hash evidence",
    )?;
    let report_hash_evidence_hash = evidence_value_hash(
        evidence,
        "rotationReportHash",
        "deception rotation report hash evidence",
    )?;
    let dry_run_evidence_hash =
        evidence_value_hash(evidence, "dryRun", "deception rotation dry-run evidence")?;
    let cleanup_removed_count_evidence_hash = evidence_value_hash(
        evidence,
        "cleanupRemovedCount",
        "deception rotation cleanup removed count evidence",
    )?;
    let cleanup_would_remove_count_evidence_hash = evidence_value_hash(
        evidence,
        "cleanupWouldRemoveCount",
        "deception rotation cleanup would-remove count evidence",
    )?;
    let cleanup_missing_count_evidence_hash = evidence_value_hash(
        evidence,
        "cleanupMissingCount",
        "deception rotation cleanup missing count evidence",
    )?;
    let cleanup_refused_count_evidence_hash = evidence_value_hash(
        evidence,
        "cleanupRefusedCount",
        "deception rotation cleanup refused count evidence",
    )?;
    let materialization_created_count_evidence_hash = evidence_value_hash(
        evidence,
        "materializationCreatedCount",
        "deception rotation materialization created count evidence",
    )?;
    let materialization_skipped_count_evidence_hash = evidence_value_hash(
        evidence,
        "materializationSkippedCount",
        "deception rotation materialization skipped count evidence",
    )?;
    let deregistered_artifact_count_evidence_hash = evidence_value_hash(
        evidence,
        "deregisteredArtifactCount",
        "deception rotation deregistered artifact count evidence",
    )?;
    let registered_artifact_count_evidence_hash = evidence_value_hash(
        evidence,
        "registeredArtifactCount",
        "deception rotation registered artifact count evidence",
    )?;
    let remaining_registered_artifact_count_evidence_hash = evidence_value_hash(
        evidence,
        "remainingRegisteredArtifactCount",
        "deception rotation remaining registered artifact count evidence",
    )?;
    Ok(deception_rotation_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        DeceptionRotationIdEvidenceHashes {
            old_plan_root_evidence_hash,
            new_plan_root_evidence_hash,
            old_plan_hash_evidence_hash,
            new_plan_hash_evidence_hash,
            report_hash_evidence_hash,
            dry_run_evidence_hash,
            cleanup_removed_count_evidence_hash,
            cleanup_would_remove_count_evidence_hash,
            cleanup_missing_count_evidence_hash,
            cleanup_refused_count_evidence_hash,
            materialization_created_count_evidence_hash,
            materialization_skipped_count_evidence_hash,
            deregistered_artifact_count_evidence_hash,
            registered_artifact_count_evidence_hash,
            remaining_registered_artifact_count_evidence_hash,
        },
    ))
}

fn deception_rotation_id_from_evidence_hashes(
    endpoint_id: &str,
    policy_hash: &str,
    evidence_hashes: DeceptionRotationIdEvidenceHashes<'_>,
) -> String {
    stable_id(
        "deception_rotation",
        [
            endpoint_id,
            policy_hash,
            evidence_hashes.old_plan_root_evidence_hash,
            evidence_hashes.new_plan_root_evidence_hash,
            evidence_hashes.old_plan_hash_evidence_hash,
            evidence_hashes.new_plan_hash_evidence_hash,
            evidence_hashes.report_hash_evidence_hash,
            evidence_hashes.dry_run_evidence_hash,
            evidence_hashes.cleanup_removed_count_evidence_hash,
            evidence_hashes.cleanup_would_remove_count_evidence_hash,
            evidence_hashes.cleanup_missing_count_evidence_hash,
            evidence_hashes.cleanup_refused_count_evidence_hash,
            evidence_hashes.materialization_created_count_evidence_hash,
            evidence_hashes.materialization_skipped_count_evidence_hash,
            evidence_hashes.deregistered_artifact_count_evidence_hash,
            evidence_hashes.registered_artifact_count_evidence_hash,
            evidence_hashes.remaining_registered_artifact_count_evidence_hash,
        ],
    )
}

pub(crate) fn response_execution_effect_binding_digest_from_effects(
    effects: &[EndpointResponseExecutionEffect],
) -> Result<Option<String>> {
    let entries = effects
        .iter()
        .map(|effect| ResponseExecutionEffectBindingEntry {
            key: format!("executionEffect:{}", effect.effect_id),
            value_hash: sha256(response_effect_evidence_value(effect).as_bytes()).to_hex_prefixed(),
        })
        .collect();
    response_execution_effect_binding_digest(entries)
}

fn response_execution_effect_binding_digest_from_evidence(
    evidence: &[EndpointReceiptEvidence],
) -> Result<Option<String>> {
    let entries = evidence
        .iter()
        .filter(|item| item.key.starts_with("executionEffect:"))
        .map(|item| ResponseExecutionEffectBindingEntry {
            key: item.key.clone(),
            value_hash: item.value_hash.clone(),
        })
        .collect();
    response_execution_effect_binding_digest(entries)
}

fn response_execution_effect_binding_digest(
    mut entries: Vec<ResponseExecutionEffectBindingEntry>,
) -> Result<Option<String>> {
    if entries.is_empty() {
        return Ok(None);
    }
    entries.sort_by(|left, right| left.key.cmp(&right.key));
    let value =
        serde_json::to_value(entries).context("serialize response execution effect binding")?;
    let canonical =
        canonicalize_json(&value).context("canonicalize response execution effect binding")?;
    Ok(Some(sha256(canonical.as_bytes()).to_hex_prefixed()))
}

pub(crate) fn response_rollback_id_from_effects(
    execution_id: &str,
    response_action_id: &str,
    rollback_ref: &str,
    effects: &[EndpointResponseExecutionEffect],
) -> Result<String> {
    let execution_id_hash = sha256(execution_id.as_bytes()).to_hex_prefixed();
    let effect_binding_digest = response_rollback_effect_binding_digest_from_effects(effects)?
        .ok_or_else(|| anyhow!("response rollback effect binding requires at least one effect"))?;
    Ok(response_rollback_id_from_effect_digest(
        response_action_id,
        rollback_ref,
        execution_id_hash.as_str(),
        effect_binding_digest.as_str(),
    ))
}

pub(crate) fn response_rollback_id_from_signed_evidence(
    evidence: &[EndpointReceiptEvidence],
    response_action_id: &str,
    rollback_ref: &str,
) -> Result<String> {
    let Some(execution_id) = evidence.iter().find(|item| item.key == "executionId") else {
        return Err(anyhow!("rollback execution id evidence is required"));
    };
    require_evidence_hash_not_empty(execution_id, "rollback execution id evidence")?;
    let effect_binding_digest = response_rollback_effect_binding_digest_from_evidence(evidence)?
        .ok_or_else(|| anyhow!("rollback effect evidence is required"))?;
    Ok(response_rollback_id_from_effect_digest(
        response_action_id,
        rollback_ref,
        execution_id.value_hash.as_str(),
        effect_binding_digest.as_str(),
    ))
}

fn response_rollback_id_from_effect_digest(
    response_action_id: &str,
    rollback_ref: &str,
    execution_id_hash: &str,
    effect_binding_digest: &str,
) -> String {
    stable_id(
        "response_rollback",
        [
            response_action_id,
            rollback_ref,
            execution_id_hash,
            effect_binding_digest,
        ],
    )
}

fn response_rollback_effect_binding_digest_from_effects(
    effects: &[EndpointResponseExecutionEffect],
) -> Result<Option<String>> {
    let entries = effects
        .iter()
        .map(|effect| ResponseExecutionEffectBindingEntry {
            key: format!("rollbackEffect:{}", effect.effect_id),
            value_hash: sha256(response_effect_evidence_value(effect).as_bytes()).to_hex_prefixed(),
        })
        .collect();
    response_execution_effect_binding_digest(entries)
}

fn response_rollback_effect_binding_digest_from_evidence(
    evidence: &[EndpointReceiptEvidence],
) -> Result<Option<String>> {
    let entries = evidence
        .iter()
        .filter(|item| item.key.starts_with("rollbackEffect:"))
        .map(|item| ResponseExecutionEffectBindingEntry {
            key: item.key.clone(),
            value_hash: item.value_hash.clone(),
        })
        .collect();
    response_execution_effect_binding_digest(entries)
}

pub(crate) fn response_effect_evidence_value(effect: &EndpointResponseExecutionEffect) -> String {
    serde_json::to_value(effect)
        .ok()
        .and_then(|value| canonicalize_json(&value).ok())
        .unwrap_or_else(|| effect.effect_id.clone())
}

pub(crate) fn response_acknowledgement_id_from_report_fields(
    execution_id: &str,
    response_action_id: &str,
    rollback_ref: &str,
    acknowledged_by: &str,
    note: Option<&str>,
    effects: &[EndpointResponseExecutionEffect],
) -> String {
    response_acknowledgement_id_from_report_fields_with_control(
        execution_id,
        response_action_id,
        rollback_ref,
        acknowledged_by,
        note,
        effects,
        None,
    )
}

pub(crate) fn response_acknowledgement_id_from_report_fields_with_control(
    execution_id: &str,
    response_action_id: &str,
    rollback_ref: &str,
    acknowledged_by: &str,
    note: Option<&str>,
    effects: &[EndpointResponseExecutionEffect],
    control_correlation: Option<&EndpointResponseControlCorrelation>,
) -> String {
    let execution_id_hash = sha256(execution_id.as_bytes()).to_hex_prefixed();
    let note_hash = note
        .map(|note| sha256(note.as_bytes()).to_hex_prefixed())
        .unwrap_or_else(response_acknowledgement_absent_note_marker);
    let effect_binding_digest =
        response_acknowledgement_effect_binding_digest_from_effects(effects)
            .ok()
            .flatten()
            .unwrap_or_else(response_acknowledgement_absent_effect_marker);
    let control_binding_digest = control_correlation.and_then(|control| {
        response_control_acknowledgement_binding_digest_from_control(control).ok()
    });
    response_acknowledgement_id_from_evidence_hashes(
        response_action_id,
        rollback_ref,
        execution_id_hash.as_str(),
        acknowledged_by,
        note_hash.as_str(),
        effect_binding_digest.as_str(),
        control_binding_digest.as_deref(),
    )
}

pub(crate) fn response_acknowledgement_id_from_signed_evidence(
    evidence: &[EndpointReceiptEvidence],
    response_action_id: &str,
    rollback_ref: &str,
    acknowledged_by: &str,
) -> Result<String> {
    let Some(execution_id) = evidence.iter().find(|item| item.key == "executionId") else {
        return Err(anyhow!("acknowledgement execution id evidence is required"));
    };
    require_evidence_hash_not_empty(execution_id, "acknowledgement execution id evidence")?;
    let note_hash = if let Some(note) = evidence.iter().find(|item| item.key == "note") {
        require_evidence_hash_not_empty(note, "acknowledgement note evidence")?;
        note.value_hash.clone()
    } else {
        response_acknowledgement_absent_note_marker()
    };
    let effect_binding_digest =
        response_acknowledgement_effect_binding_digest_from_evidence(evidence)?
            .unwrap_or_else(response_acknowledgement_absent_effect_marker);
    let control_binding_digest =
        response_control_acknowledgement_binding_digest_from_evidence(evidence)?;
    Ok(response_acknowledgement_id_from_evidence_hashes(
        response_action_id,
        rollback_ref,
        execution_id.value_hash.as_str(),
        acknowledged_by,
        note_hash.as_str(),
        effect_binding_digest.as_str(),
        control_binding_digest.as_deref(),
    ))
}

fn response_acknowledgement_id_from_evidence_hashes(
    response_action_id: &str,
    rollback_ref: &str,
    execution_id_hash: &str,
    acknowledged_by: &str,
    note_hash: &str,
    effect_binding_digest: &str,
    control_binding_digest: Option<&str>,
) -> String {
    let mut parts = vec![
        response_action_id,
        rollback_ref,
        execution_id_hash,
        acknowledged_by,
        note_hash,
        effect_binding_digest,
    ];
    if let Some(control_binding_digest) = control_binding_digest {
        parts.push(control_binding_digest);
    }
    stable_id("response_acknowledgement", parts)
}

fn response_acknowledgement_absent_note_marker() -> String {
    "note:absent".to_string()
}

fn response_acknowledgement_absent_effect_marker() -> String {
    "effect:absent".to_string()
}

fn response_acknowledgement_effect_binding_digest_from_effects(
    effects: &[EndpointResponseExecutionEffect],
) -> Result<Option<String>> {
    let entries = effects
        .iter()
        .map(|effect| ResponseExecutionEffectBindingEntry {
            key: format!("acknowledgementEffect:{}", effect.effect_id),
            value_hash: sha256(response_effect_evidence_value(effect).as_bytes()).to_hex_prefixed(),
        })
        .collect();
    response_execution_effect_binding_digest(entries)
}

fn response_acknowledgement_effect_binding_digest_from_evidence(
    evidence: &[EndpointReceiptEvidence],
) -> Result<Option<String>> {
    let entries = evidence
        .iter()
        .filter(|item| item.key.starts_with("acknowledgementEffect:"))
        .map(|item| ResponseExecutionEffectBindingEntry {
            key: item.key.clone(),
            value_hash: item.value_hash.clone(),
        })
        .collect();
    response_execution_effect_binding_digest(entries)
}

fn response_control_acknowledgement_binding_digest_from_control(
    control: &EndpointResponseControlCorrelation,
) -> Result<String> {
    let mut entries = vec![
        ResponseExecutionEffectBindingEntry {
            key: "controlResponseActionId".to_string(),
            value_hash: sha256(control.response_action_id.as_bytes()).to_hex_prefixed(),
        },
        ResponseExecutionEffectBindingEntry {
            key: "controlTargetKind".to_string(),
            value_hash: sha256(control.target_kind.as_bytes()).to_hex_prefixed(),
        },
        ResponseExecutionEffectBindingEntry {
            key: "controlTargetId".to_string(),
            value_hash: sha256(control.target_id.as_bytes()).to_hex_prefixed(),
        },
        ResponseExecutionEffectBindingEntry {
            key: "controlAckTokenHash".to_string(),
            value_hash: control.ack_token_hash.clone(),
        },
        ResponseExecutionEffectBindingEntry {
            key: "controlAckStatus".to_string(),
            value_hash: sha256(control.ack_status.as_bytes()).to_hex_prefixed(),
        },
    ];
    if let Some(delivery_id) = &control.delivery_id {
        entries.push(ResponseExecutionEffectBindingEntry {
            key: "controlDeliveryId".to_string(),
            value_hash: sha256(delivery_id.as_bytes()).to_hex_prefixed(),
        });
    }
    if let Some(resulting_state) = &control.resulting_state {
        entries.push(ResponseExecutionEffectBindingEntry {
            key: "controlResultingState".to_string(),
            value_hash: sha256(resulting_state.as_bytes()).to_hex_prefixed(),
        });
    }
    response_execution_effect_binding_digest(entries)?
        .ok_or_else(|| anyhow!("control acknowledgement binding evidence is required"))
}

fn response_control_acknowledgement_binding_digest_from_evidence(
    evidence: &[EndpointReceiptEvidence],
) -> Result<Option<String>> {
    if !evidence.iter().any(|item| item.key.starts_with("control")) {
        return Ok(None);
    }

    let mut entries = Vec::new();
    for (key, field_name) in [
        (
            "controlResponseActionId",
            "control acknowledgement response action id evidence",
        ),
        (
            "controlTargetKind",
            "control acknowledgement target kind evidence",
        ),
        (
            "controlTargetId",
            "control acknowledgement target id evidence",
        ),
        (
            "controlAckTokenHash",
            "control acknowledgement token hash evidence",
        ),
        (
            "controlAckStatus",
            "control acknowledgement status evidence",
        ),
    ] {
        let item = evidence
            .iter()
            .find(|item| item.key == key)
            .ok_or_else(|| anyhow!("{field_name} is required"))?;
        require_evidence_hash_not_empty(item, field_name)?;
        entries.push(ResponseExecutionEffectBindingEntry {
            key: key.to_string(),
            value_hash: item.value_hash.clone(),
        });
    }
    for (key, field_name) in [
        (
            "controlDeliveryId",
            "control acknowledgement delivery id evidence",
        ),
        (
            "controlResultingState",
            "control acknowledgement resulting state evidence",
        ),
    ] {
        if let Some(item) = evidence.iter().find(|item| item.key == key) {
            require_evidence_hash_not_empty(item, field_name)?;
            entries.push(ResponseExecutionEffectBindingEntry {
                key: key.to_string(),
                value_hash: item.value_hash.clone(),
            });
        }
    }
    Ok(Some(
        response_execution_effect_binding_digest(entries)?
            .ok_or_else(|| anyhow!("control acknowledgement binding evidence is required"))?,
    ))
}

fn response_execution_bundle_id_from_signed_fields(
    decision: &EndpointDecisionRecord,
    graph_slice_id: &str,
    graph_content_hash: &str,
) -> Result<String> {
    let rollback_ref = decision
        .rollback_ref
        .as_deref()
        .ok_or_else(|| anyhow!("response rollback ref is required"))?;
    let response_action_id = response_action_id_from_rollback_ref(&decision.action, rollback_ref)?;
    let status = response_execution_status_from_decision(decision)?;
    if status == "failed" {
        return Ok(stable_id(
            "evidence_bundle",
            [
                response_action_id.as_str(),
                graph_slice_id,
                graph_content_hash,
                "failed",
            ],
        ));
    }
    Ok(stable_id(
        "evidence_bundle",
        [
            response_action_id.as_str(),
            graph_slice_id,
            graph_content_hash,
        ],
    ))
}

fn require_response_execution_dry_run_evidence(evidence: &[EndpointReceiptEvidence]) -> Result<()> {
    require_evidence_value_hash(evidence, "dryRun", "false", "execution dry-run evidence")
}

fn require_response_execution_actor_evidence(evidence: &[EndpointReceiptEvidence]) -> Result<()> {
    let actor_hash = evidence_value_hash(evidence, "actorHash", "response actor evidence")?;
    let execution_actor_hash =
        evidence_value_hash(evidence, "executionActorHash", "execution actor evidence")?;
    if !hex_strings_match(actor_hash, execution_actor_hash) {
        return Err(anyhow!(
            "execution actor evidence hash must match response actor evidence"
        ));
    }
    Ok(())
}

fn require_response_rollback_execution_id_evidence(
    evidence: &[EndpointReceiptEvidence],
    signed_rollback_id: Option<&str>,
    response_action_id: &str,
    rollback_ref: &str,
) -> Result<()> {
    require_nonempty_hashed_evidence(evidence, "executionId", "rollback execution id evidence")?;
    let rollback_id =
        response_rollback_id_from_signed_evidence(evidence, response_action_id, rollback_ref)?;
    if signed_rollback_id != Some(rollback_id.as_str()) {
        return Err(anyhow!(
            "rollback execution id evidence hash must match signed rollback proof"
        ));
    }
    Ok(())
}

fn require_response_acknowledgement_execution_id_evidence(
    evidence: &[EndpointReceiptEvidence],
    signed_acknowledgement_id: Option<&str>,
    response_action_id: &str,
    rollback_ref: &str,
    acknowledged_by: &str,
) -> Result<()> {
    require_nonempty_hashed_evidence(
        evidence,
        "executionId",
        "acknowledgement execution id evidence",
    )?;
    let acknowledgement_id = response_acknowledgement_id_from_signed_evidence(
        evidence,
        response_action_id,
        rollback_ref,
        acknowledged_by,
    )?;
    if signed_acknowledgement_id != Some(acknowledgement_id.as_str()) {
        return Err(anyhow!(
            "acknowledgement execution id evidence hash must match signed acknowledgement proof"
        ));
    }
    Ok(())
}

fn require_response_acknowledgement_note_evidence(
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    if evidence.iter().any(|item| item.key == "note") {
        require_nonempty_hashed_evidence(evidence, "note", "acknowledgement note evidence")?;
    }
    Ok(())
}

fn require_response_effect_count_evidence(
    evidence: &[EndpointReceiptEvidence],
    effect_key_prefix: &str,
    field_name: &str,
) -> Result<()> {
    let effect_count = evidence
        .iter()
        .filter(|item| item.key.starts_with(effect_key_prefix))
        .count();
    require_evidence_value_hash(
        evidence,
        "effectCount",
        effect_count.to_string(),
        field_name,
    )
}

fn require_response_effect_evidence_hashes(
    evidence: &[EndpointReceiptEvidence],
    effect_key_prefix: &str,
    field_name: &str,
) -> Result<()> {
    for effect_evidence in evidence
        .iter()
        .filter(|item| item.key.starts_with(effect_key_prefix))
    {
        require_evidence_hash_not_empty(effect_evidence, field_name)?;
    }
    Ok(())
}

fn require_response_execution_effect_type_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let expected_effect_type = response_execution_effect_type_for_action(&decision.action);
    require_response_typed_effect_evidence(
        evidence,
        "executionEffect:",
        "executionEffectType:",
        expected_effect_type,
        "execution effect type evidence",
    )
}

fn require_response_rollback_effect_type_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let expected_effect_type = response_rollback_effect_type_for_action(&decision.action);
    require_response_typed_effect_evidence(
        evidence,
        "rollbackEffect:",
        "rollbackEffectType:",
        expected_effect_type,
        "rollback effect type evidence",
    )
}

fn require_response_acknowledgement_effect_type_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let expected_effect_type = response_execution_effect_type_for_action(&decision.action);
    require_response_typed_effect_evidence(
        evidence,
        "acknowledgementEffect:",
        "acknowledgementEffectType:",
        expected_effect_type,
        "acknowledgement effect type evidence",
    )
}

fn require_response_typed_effect_evidence(
    evidence: &[EndpointReceiptEvidence],
    effect_key_prefix: &str,
    effect_type_key_prefix: &str,
    expected_effect_type: Option<&str>,
    field_name: &str,
) -> Result<()> {
    let effect_ids = evidence
        .iter()
        .filter_map(|item| item.key.strip_prefix(effect_key_prefix))
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();
    let effect_type_ids = evidence
        .iter()
        .filter_map(|item| item.key.strip_prefix(effect_type_key_prefix))
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();

    if effect_ids != effect_type_ids {
        return Err(anyhow!("{field_name} must match response effect evidence"));
    }
    if effect_ids.is_empty() {
        return Ok(());
    }

    let expected_effect_type =
        expected_effect_type.ok_or_else(|| anyhow!("{field_name} is invalid for action"))?;
    for effect_id in effect_ids {
        let effect_type_key = format!("{effect_type_key_prefix}{effect_id}");
        require_evidence_value_hash(
            evidence,
            effect_type_key.as_str(),
            expected_effect_type,
            field_name,
        )?;
    }
    Ok(())
}

fn response_execution_effect_type_for_action(
    action: &EndpointDecisionAction,
) -> Option<&'static str> {
    match action {
        EndpointDecisionAction::RestrictEgress => Some("restrict_egress"),
        EndpointDecisionAction::QuarantineFile => Some("quarantine_file"),
        EndpointDecisionAction::DisablePersistence => Some("disable_persistence"),
        EndpointDecisionAction::RevokeGrant => Some("revoke_grant"),
        EndpointDecisionAction::SuspendProcessTree => Some("suspend_process_tree"),
        EndpointDecisionAction::TerminateProcessTree => Some("terminate_process_tree"),
        EndpointDecisionAction::CollectEvidence => None,
        _ => None,
    }
}

fn response_rollback_effect_type_for_action(
    action: &EndpointDecisionAction,
) -> Option<&'static str> {
    match action {
        EndpointDecisionAction::RestrictEgress => Some("restore_egress"),
        EndpointDecisionAction::QuarantineFile => Some("restore_quarantine_file"),
        EndpointDecisionAction::DisablePersistence => Some("restore_persistence_file"),
        EndpointDecisionAction::SuspendProcessTree => Some("resume_process_tree"),
        _ => None,
    }
}

fn require_response_acknowledgement_effect_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let status = response_acknowledgement_status_from_decision(decision)?;
    let effect_count = evidence
        .iter()
        .filter(|item| item.key.starts_with("acknowledgementEffect:"))
        .count();
    if matches!(decision.action, EndpointDecisionAction::CollectEvidence) && effect_count > 0 {
        return Err(anyhow!(
            "collect evidence acknowledgement effect evidence is invalid"
        ));
    }
    if status == "succeeded"
        && !matches!(decision.action, EndpointDecisionAction::CollectEvidence)
        && effect_count == 0
    {
        return Err(anyhow!("acknowledgement effect evidence is required"));
    }
    Ok(())
}

fn require_evidence_bundle_manifest_evidence(
    evidence: &[EndpointReceiptEvidence],
    signed_bundle_id: Option<&str>,
    graph_slice_id: Option<&str>,
    content_hash: Option<&str>,
    node_count: usize,
    edge_count: usize,
) -> Result<()> {
    let signed_bundle_id =
        signed_bundle_id.ok_or_else(|| anyhow!("evidence bundle id signed id is required"))?;
    let graph_slice_id =
        graph_slice_id.ok_or_else(|| anyhow!("evidence bundle graph slice id is required"))?;
    let content_hash =
        content_hash.ok_or_else(|| anyhow!("evidence bundle content hash is required"))?;
    require_evidence_value_hash(
        evidence,
        "evidenceBundleId",
        signed_bundle_id,
        "evidence bundle id evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "graphSliceId",
        graph_slice_id,
        "evidence bundle graph slice evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "contentHash",
        content_hash,
        "evidence bundle content hash evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "nodeCount",
        node_count.to_string(),
        "evidence bundle node count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "edgeCount",
        edge_count.to_string(),
        "evidence bundle edge count evidence",
    )
}

fn require_graph_slice_content_hash_evidence(
    evidence: &[EndpointReceiptEvidence],
    content_hash: Option<&str>,
) -> Result<()> {
    let content_hash =
        content_hash.ok_or_else(|| anyhow!("graph slice content hash is required"))?;
    require_evidence_value_hash(
        evidence,
        "contentHash",
        content_hash,
        "graph slice content hash evidence",
    )
}

fn require_graph_slice_evidence(
    evidence: &[EndpointReceiptEvidence],
    signed_graph_slice_id: Option<&str>,
    graph_slice_id: Option<&str>,
    root_node_id: Option<&str>,
    node_count: usize,
    edge_count: usize,
) -> Result<()> {
    let signed_graph_slice_id =
        signed_graph_slice_id.ok_or_else(|| anyhow!("graph slice signed id is required"))?;
    let graph_slice_id = graph_slice_id.ok_or_else(|| anyhow!("graph slice id is required"))?;
    let root_node_id =
        root_node_id.ok_or_else(|| anyhow!("graph slice root node id is required"))?;
    if signed_graph_slice_id != graph_slice_id {
        return Err(anyhow!(
            "graph slice signed id must match graph reference id"
        ));
    }
    require_evidence_value_hash(
        evidence,
        "graphSliceId",
        graph_slice_id,
        "graph slice id evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "rootNodeId",
        root_node_id,
        "graph slice root node evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "sliceKind", "graph slice kind evidence")?;
    require_evidence_value_hash(
        evidence,
        "nodeCount",
        node_count.to_string(),
        "graph slice node count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "edgeCount",
        edge_count.to_string(),
        "graph slice edge count evidence",
    )
}

fn require_sensor_state_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    actor: &EndpointDecisionActor,
    policy: &EndpointPolicySnapshot,
    sensor_state: &EndpointSensorState,
) -> Result<()> {
    let signed_id = decision
        .finding_id
        .as_deref()
        .ok_or_else(|| anyhow!("sensor state signed id is required"))?;
    let rule_id = decision
        .rule_id
        .as_deref()
        .ok_or_else(|| anyhow!("sensor state rule id is required"))?;
    if rule_id != "endpoint.sensor_state" {
        return Err(anyhow!("sensor state rule id is invalid"));
    }

    let provider_count = sensor_state.providers.len();
    let active_provider_count = sensor_state
        .providers
        .iter()
        .filter(|provider| provider.active)
        .count();
    let healthy_provider_count = sensor_state
        .providers
        .iter()
        .filter(|provider| provider.healthy)
        .count();
    let degraded_provider_count = sensor_state
        .providers
        .iter()
        .filter(|provider| provider.degraded)
        .count();
    let provider_ids = sensor_state
        .providers
        .iter()
        .map(|provider| provider.provider_id.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let provider_count_text = provider_count.to_string();
    let active_count_text = active_provider_count.to_string();
    let healthy_count_text = healthy_provider_count.to_string();
    let degraded_count_text = degraded_provider_count.to_string();
    let sensor_state_hash = endpoint_sensor_state_content_hash(sensor_state);
    let policy_epoch = policy.policy_epoch.to_string();
    let expected_sensor_state_id = stable_id(
        "sensor_state",
        [
            actor.endpoint_id.as_str(),
            policy.policy_hash.as_str(),
            policy_epoch.as_str(),
            provider_count_text.as_str(),
            active_count_text.as_str(),
            healthy_count_text.as_str(),
            degraded_count_text.as_str(),
            provider_ids.as_str(),
            sensor_state_hash.as_str(),
        ],
    );
    if signed_id != expected_sensor_state_id {
        return Err(anyhow!(
            "sensor state id must match endpoint, policy, provider counts, degraded count, provider ids, and sensor state hash"
        ));
    }
    let expected_passed = provider_count > 0 && healthy_provider_count == provider_count;
    if decision.passed != expected_passed {
        return Err(anyhow!(
            "sensor state passed flag must match provider health"
        ));
    }

    require_nonempty_hashed_evidence(evidence, "reason", "sensor state reason evidence")?;
    require_evidence_value_hash(
        evidence,
        "providerCount",
        provider_count.to_string(),
        "sensor state provider count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "activeProviderCount",
        active_count_text,
        "sensor state active-provider count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "healthyProviderCount",
        healthy_count_text,
        "sensor state healthy-provider count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "degradedProviderCount",
        degraded_provider_count.to_string(),
        "sensor state degraded-provider count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "providerIds",
        provider_ids,
        "sensor state provider ids evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "sensorStateHash",
        sensor_state_hash,
        "sensor state content hash evidence",
    )
}

fn require_detection_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    graph: &EndpointGraphReference,
) -> Result<()> {
    let observation_id = decision
        .observation_id
        .as_deref()
        .ok_or_else(|| anyhow!("detection observation id is required"))?;
    let finding_id = decision
        .finding_id
        .as_deref()
        .ok_or_else(|| anyhow!("detection finding id is required"))?;
    let rule_id = decision
        .rule_id
        .as_deref()
        .ok_or_else(|| anyhow!("detection rule id is required"))?;
    let title = decision
        .title
        .as_deref()
        .ok_or_else(|| anyhow!("detection title is required"))?;
    let severity = decision
        .severity
        .as_ref()
        .ok_or_else(|| anyhow!("detection severity is required"))?;
    let confidence = decision
        .confidence
        .ok_or_else(|| anyhow!("detection confidence is required"))?;
    let graph_slice_id = graph
        .graph_slice_id
        .as_deref()
        .ok_or_else(|| anyhow!("detection graph slice id is required"))?;
    let graph_content_hash = graph
        .content_hash
        .as_deref()
        .ok_or_else(|| anyhow!("detection graph content hash is required"))?;
    let process_node_id = graph
        .process_node_id
        .as_deref()
        .ok_or_else(|| anyhow!("detection process node id is required"))?;
    require_detection_graph_reference(
        graph,
        observation_id,
        graph_slice_id,
        graph_content_hash,
        process_node_id,
    )?;

    require_evidence_value_hash(
        evidence,
        "detectionFindingId",
        finding_id,
        "detection finding id evidence",
    )?;
    let expected_finding_id = detection_finding_id_from_signed_fields(rule_id, observation_id);
    if finding_id != expected_finding_id {
        return Err(anyhow!(
            "detection finding id must match signed rule and observation"
        ));
    }
    require_evidence_value_hash(
        evidence,
        "detectionObservationId",
        observation_id,
        "detection observation id evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "detectionRuleId",
        rule_id,
        "detection rule id evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "detectionTitle",
        title,
        "detection title evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "detectionSeverity",
        detection_severity_label(severity),
        "detection severity evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "detectionConfidence",
        confidence.to_string(),
        "detection confidence evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "detectionGraphSliceId",
        graph_slice_id,
        "detection graph slice evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "detectionContentHash",
        graph_content_hash,
        "detection graph content hash evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "detectionProcessNodeId",
        process_node_id,
        "detection process node evidence",
    )
}

fn require_observation_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    actor: &EndpointDecisionActor,
    policy: &EndpointPolicySnapshot,
    sensor_state: &EndpointSensorState,
    graph: &EndpointGraphReference,
) -> Result<()> {
    let observation_id = decision
        .observation_id
        .as_deref()
        .ok_or_else(|| anyhow!("observation id is required"))?;
    let receipt_id = decision
        .finding_id
        .as_deref()
        .ok_or_else(|| anyhow!("observation receipt id is required"))?;
    let rule_id = decision
        .rule_id
        .as_deref()
        .ok_or_else(|| anyhow!("observation receipt rule id is required"))?;
    let event_kind = rule_id
        .strip_prefix("endpoint.observation.")
        .ok_or_else(|| anyhow!("observation receipt rule id must include event kind"))?;
    require_nonempty(event_kind, "observation receipt event kind")?;
    let graph_slice_id = graph
        .graph_slice_id
        .as_deref()
        .ok_or_else(|| anyhow!("observation graph slice id is required"))?;
    let graph_content_hash = graph
        .content_hash
        .as_deref()
        .ok_or_else(|| anyhow!("observation graph content hash is required"))?;
    let process_node_id = graph
        .process_node_id
        .as_deref()
        .ok_or_else(|| anyhow!("observation process node id is required"))?;
    require_detection_graph_reference(
        graph,
        observation_id,
        graph_slice_id,
        graph_content_hash,
        process_node_id,
    )?;

    require_evidence_value_hash(
        evidence,
        "observationId",
        observation_id,
        "observation id evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "eventKind",
        event_kind,
        "observation event kind evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "observationHash",
        "observation content hash evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "target", "observation target evidence")?;
    require_evidence_value_hash(
        evidence,
        "graphSliceId",
        graph_slice_id,
        "observation graph slice evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "contentHash",
        graph_content_hash,
        "observation graph content hash evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "processNodeId",
        process_node_id,
        "observation process node evidence",
    )?;
    let provider_id_hash = evidence_value_hash(evidence, "providerId", "provider id evidence")?;
    let provider_kind_hash =
        evidence_value_hash(evidence, "providerKind", "provider kind evidence")?;
    let provider = sensor_state
        .providers
        .iter()
        .find(|provider| {
            let expected_provider_id_hash =
                sha256(provider.provider_id.as_bytes()).to_hex_prefixed();
            hex_strings_match(expected_provider_id_hash.as_str(), provider_id_hash)
        })
        .ok_or_else(|| anyhow!("observation receipt provider id is not present in sensor state"))?;
    let expected_provider_kind_hash =
        sha256(camel_debug_to_snake(format!("{:?}", provider.provider_kind).as_str()).as_bytes())
            .to_hex_prefixed();
    if !hex_strings_match(expected_provider_kind_hash.as_str(), provider_kind_hash) {
        return Err(anyhow!(
            "observation receipt provider kind evidence must match sensor state"
        ));
    }

    let expected_receipt_id = observation_receipt_id_from_evidence(
        actor.endpoint_id.as_str(),
        policy.policy_hash.as_str(),
        evidence,
    )?;
    if receipt_id != expected_receipt_id {
        return Err(anyhow!(
            "observation receipt id must match signed endpoint, policy, observation, graph, provider, target, and content-hash evidence"
        ));
    }
    Ok(())
}

fn require_detection_graph_reference(
    graph: &EndpointGraphReference,
    observation_id: &str,
    graph_slice_id: &str,
    graph_content_hash: &str,
    process_node_id: &str,
) -> Result<()> {
    if !graph
        .node_ids
        .iter()
        .any(|node_id| node_id == process_node_id)
    {
        return Err(anyhow!(
            "detection process node reference must be included in graph node ids"
        ));
    }

    let expected_graph_slice_id = stable_id(
        "graph_slice",
        [observation_id, process_node_id, graph_content_hash],
    );
    if graph_slice_id != expected_graph_slice_id {
        return Err(anyhow!(
            "detection graph slice reference must match observation, process, and graph content hash"
        ));
    }
    Ok(())
}

fn detection_severity_label(severity: &DetectionSeverity) -> &'static str {
    match severity {
        DetectionSeverity::Info => "info",
        DetectionSeverity::Low => "low",
        DetectionSeverity::Medium => "medium",
        DetectionSeverity::High => "high",
        DetectionSeverity::Critical => "critical",
    }
}

fn detection_finding_id_from_signed_fields(rule_id: &str, observation_id: &str) -> String {
    stable_id("finding", [rule_id, observation_id])
}

struct ObservationReceiptIdFields<'a> {
    endpoint_id: &'a str,
    policy_hash: &'a str,
    observation_id: &'a str,
    event_kind: &'a str,
    observation_hash: &'a str,
    target: &'a str,
    graph_slice_id: &'a str,
    graph_content_hash: &'a str,
    process_node_id: &'a str,
    provider_id: &'a str,
    provider_kind: &'a str,
}

fn observation_receipt_id_from_fields(fields: ObservationReceiptIdFields<'_>) -> String {
    let observation_id_hash = sha256(fields.observation_id.as_bytes()).to_hex_prefixed();
    let event_kind_hash = sha256(fields.event_kind.as_bytes()).to_hex_prefixed();
    let observation_hash_hash = sha256(fields.observation_hash.as_bytes()).to_hex_prefixed();
    let target_hash = sha256(fields.target.as_bytes()).to_hex_prefixed();
    let graph_slice_id_hash = sha256(fields.graph_slice_id.as_bytes()).to_hex_prefixed();
    let graph_content_hash_hash = sha256(fields.graph_content_hash.as_bytes()).to_hex_prefixed();
    let process_node_id_hash = sha256(fields.process_node_id.as_bytes()).to_hex_prefixed();
    let provider_id_hash = sha256(fields.provider_id.as_bytes()).to_hex_prefixed();
    let provider_kind_hash = sha256(fields.provider_kind.as_bytes()).to_hex_prefixed();
    observation_receipt_id_from_evidence_hashes(
        fields.endpoint_id,
        fields.policy_hash,
        ObservationReceiptIdEvidenceHashes {
            observation_id_hash: observation_id_hash.as_str(),
            event_kind_hash: event_kind_hash.as_str(),
            observation_hash_hash: observation_hash_hash.as_str(),
            target_hash: target_hash.as_str(),
            graph_slice_id_hash: graph_slice_id_hash.as_str(),
            graph_content_hash_hash: graph_content_hash_hash.as_str(),
            process_node_id_hash: process_node_id_hash.as_str(),
            provider_id_hash: provider_id_hash.as_str(),
            provider_kind_hash: provider_kind_hash.as_str(),
        },
    )
}

fn observation_receipt_id_from_evidence(
    endpoint_id: &str,
    policy_hash: &str,
    evidence: &[EndpointReceiptEvidence],
) -> Result<String> {
    Ok(observation_receipt_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        ObservationReceiptIdEvidenceHashes {
            observation_id_hash: evidence_value_hash(
                evidence,
                "observationId",
                "observation id evidence",
            )?,
            event_kind_hash: evidence_value_hash(
                evidence,
                "eventKind",
                "observation event kind evidence",
            )?,
            observation_hash_hash: evidence_value_hash(
                evidence,
                "observationHash",
                "observation content hash evidence",
            )?,
            target_hash: evidence_value_hash(evidence, "target", "observation target evidence")?,
            graph_slice_id_hash: evidence_value_hash(
                evidence,
                "graphSliceId",
                "observation graph slice evidence",
            )?,
            graph_content_hash_hash: evidence_value_hash(
                evidence,
                "contentHash",
                "observation graph content hash evidence",
            )?,
            process_node_id_hash: evidence_value_hash(
                evidence,
                "processNodeId",
                "observation process node evidence",
            )?,
            provider_id_hash: evidence_value_hash(evidence, "providerId", "provider id evidence")?,
            provider_kind_hash: evidence_value_hash(
                evidence,
                "providerKind",
                "provider kind evidence",
            )?,
        },
    ))
}

struct ObservationReceiptIdEvidenceHashes<'a> {
    observation_id_hash: &'a str,
    event_kind_hash: &'a str,
    observation_hash_hash: &'a str,
    target_hash: &'a str,
    graph_slice_id_hash: &'a str,
    graph_content_hash_hash: &'a str,
    process_node_id_hash: &'a str,
    provider_id_hash: &'a str,
    provider_kind_hash: &'a str,
}

fn observation_receipt_id_from_evidence_hashes(
    endpoint_id: &str,
    policy_hash: &str,
    evidence_hashes: ObservationReceiptIdEvidenceHashes<'_>,
) -> String {
    stable_id(
        "observation_receipt",
        [
            endpoint_id,
            policy_hash,
            evidence_hashes.observation_id_hash,
            evidence_hashes.event_kind_hash,
            evidence_hashes.observation_hash_hash,
            evidence_hashes.target_hash,
            evidence_hashes.graph_slice_id_hash,
            evidence_hashes.graph_content_hash_hash,
            evidence_hashes.process_node_id_hash,
            evidence_hashes.provider_id_hash,
            evidence_hashes.provider_kind_hash,
        ],
    )
}

fn graph_policy_simulation_id_from_signed_fields(
    root_node_id: &str,
    graph_slice_id: &str,
    rule_id: &str,
    action: &EndpointDecisionAction,
    breakage_score: u8,
) -> String {
    let breakage_score = breakage_score.to_string();
    stable_id(
        "policy_simulation",
        [
            root_node_id,
            graph_slice_id,
            rule_id,
            action.as_str(),
            breakage_score.as_str(),
        ],
    )
}

fn require_policy_decision_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    actor: &EndpointDecisionActor,
    policy: &EndpointPolicySnapshot,
) -> Result<()> {
    let signed_id = decision
        .finding_id
        .as_deref()
        .ok_or_else(|| anyhow!("policy decision signed id is required"))?;
    let rule_id = decision
        .rule_id
        .as_deref()
        .ok_or_else(|| anyhow!("policy decision rule id is required"))?;
    let action_type = rule_id
        .strip_prefix("endpoint.policy_decision.")
        .ok_or_else(|| anyhow!("policy decision rule id must include action type"))?;
    require_nonempty(action_type, "policy decision action type")?;
    require_evidence_value_hash(
        evidence,
        "actionType",
        action_type,
        "policy decision action type evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "target", "policy decision target evidence")?;
    require_evidence_value_hash(
        evidence,
        "allowed",
        decision.passed.to_string(),
        "policy decision allowed evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "guard", "policy decision guard evidence")?;
    let expected_decision_id = policy_decision_id_from_evidence(
        evidence,
        actor.endpoint_id.as_str(),
        policy.policy_hash.as_str(),
        action_type,
        decision.passed,
    )?;
    if signed_id != expected_decision_id {
        return Err(anyhow!(
            "policy decision id must match signed endpoint, policy, action, target, allowed, and guard evidence"
        ));
    }
    if evidence.iter().any(|item| item.key == "severity") {
        require_nonempty_hashed_evidence(
            evidence,
            "severity",
            "policy decision severity evidence",
        )?;
    }
    if evidence.iter().any(|item| item.key == "message") {
        require_nonempty_hashed_evidence(evidence, "message", "policy decision message evidence")?;
    }
    if evidence.iter().any(|item| item.key == "details") {
        require_nonempty_hashed_evidence(evidence, "details", "policy decision details evidence")?;
    }
    Ok(())
}

fn require_simulation_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    graph: &EndpointGraphReference,
    policy: &EndpointPolicySnapshot,
) -> Result<()> {
    let rule_id = decision
        .rule_id
        .as_deref()
        .ok_or_else(|| anyhow!("simulation rule id is required"))?;
    match rule_id {
        "endpoint.policy_event_replay" => require_policy_event_replay_evidence(
            evidence,
            decision.finding_id.as_deref(),
            graph,
            policy,
        ),
        "endpoint.policy_event_impact" => require_policy_event_impact_evidence(
            evidence,
            decision.finding_id.as_deref(),
            graph,
            policy,
        ),
        _ => require_graph_policy_simulation_evidence(evidence, decision, graph),
    }
}

fn require_graph_policy_simulation_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    graph: &EndpointGraphReference,
) -> Result<()> {
    let simulation_id = decision
        .finding_id
        .as_deref()
        .ok_or_else(|| anyhow!("simulation signed id is required"))?;
    let root_node_id = graph
        .process_node_id
        .as_deref()
        .ok_or_else(|| anyhow!("simulation root node id is required"))?;
    let graph_slice_id = graph
        .graph_slice_id
        .as_deref()
        .ok_or_else(|| anyhow!("simulation graph slice id is required"))?;
    let content_hash = graph
        .content_hash
        .as_deref()
        .ok_or_else(|| anyhow!("simulation graph content hash is required"))?;
    let breakage_score = simulation_breakage_score_from_confidence(decision.confidence)?;
    require_subgraph_reference(graph, "simulation")?;

    require_evidence_value_hash(
        evidence,
        "simulationId",
        simulation_id,
        "simulation id evidence",
    )?;
    let expected_simulation_id = graph_policy_simulation_id_from_signed_fields(
        root_node_id,
        graph_slice_id,
        decision
            .rule_id
            .as_deref()
            .ok_or_else(|| anyhow!("simulation rule id is required"))?,
        &decision.action,
        breakage_score,
    );
    if simulation_id != expected_simulation_id {
        return Err(anyhow!(
            "simulation id must match signed root, graph slice, rule, action, and breakage score"
        ));
    }
    require_evidence_value_hash(
        evidence,
        "rootNodeId",
        root_node_id,
        "simulation root node evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "graphSliceId",
        graph_slice_id,
        "simulation graph slice evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "wouldBlock",
        simulation_action_would_block(&decision.action).to_string(),
        "simulation would-block evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "developerBreakageScore",
        breakage_score.to_string(),
        "simulation breakage score evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "impactLevel",
        impact_level_for_score(breakage_score).as_str(),
        "simulation impact level evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "affectedNodeCount",
        graph.node_ids.len().to_string(),
        "simulation affected-node count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "affectedEdgeCount",
        graph.edge_ids.len().to_string(),
        "simulation affected-edge count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "affectedIdentityContext",
        "simulation affected identity context evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "affectedToolContext",
        "simulation affected tool context evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "contentHash",
        content_hash,
        "simulation content hash evidence",
    )
}

fn simulation_breakage_score_from_confidence(confidence: Option<f32>) -> Result<u8> {
    let confidence = confidence.ok_or_else(|| anyhow!("simulation confidence is required"))?;
    let score = confidence * 100.0;
    let rounded = score.round();
    if !(0.0..=100.0).contains(&rounded) || (score - rounded).abs() > 0.001 {
        return Err(anyhow!(
            "simulation confidence must encode a whole-number breakage score"
        ));
    }
    Ok(rounded as u8)
}

fn require_policy_event_replay_evidence(
    evidence: &[EndpointReceiptEvidence],
    replay_id: Option<&str>,
    graph: &EndpointGraphReference,
    policy: &EndpointPolicySnapshot,
) -> Result<()> {
    let replay_id =
        replay_id.ok_or_else(|| anyhow!("policy event replay signed id is required"))?;
    require_policy_event_stream_graph_reference(graph, replay_id, "policy event replay")?;
    require_evidence_value_hash(
        evidence,
        "replayId",
        replay_id,
        "policy event replay id evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "eventStreamHash",
        "policy event replay stream hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "resultHash",
        "policy event replay result hash evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "eventCount", "policy event replay count evidence")?;
    require_nonempty_hashed_evidence(
        evidence,
        "allowedCount",
        "policy event replay allowed count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "warnCount",
        "policy event replay warn count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "blockedCount",
        "policy event replay blocked count evidence",
    )?;
    require_boolean_hashed_evidence(
        evidence,
        "trackPosture",
        "policy event replay posture evidence",
    )?;
    let expected_replay_id = policy_event_replay_id_from_evidence(policy, evidence)?;
    if replay_id != expected_replay_id {
        return Err(anyhow!(
            "policy event replay id must match signed policy, stream, result, count, and posture evidence"
        ));
    }
    Ok(())
}

fn require_policy_event_impact_evidence(
    evidence: &[EndpointReceiptEvidence],
    impact_id: Option<&str>,
    graph: &EndpointGraphReference,
    policy: &EndpointPolicySnapshot,
) -> Result<()> {
    let impact_id =
        impact_id.ok_or_else(|| anyhow!("policy event impact signed id is required"))?;
    require_policy_event_stream_graph_reference(graph, impact_id, "policy event impact")?;
    require_evidence_value_hash(
        evidence,
        "impactId",
        impact_id,
        "policy event impact id evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "eventStreamHash",
        "policy event impact stream hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "currentResultHash",
        "policy event impact current-result evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "proposedResultHash",
        "policy event impact proposed-result evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "impactHash", "policy event impact hash evidence")?;
    require_nonempty_hashed_evidence(
        evidence,
        "proposedPolicyHash",
        "policy event impact proposed-policy hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "proposedPolicyEpoch",
        "policy event impact proposed-policy epoch evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "eventCount", "policy event impact count evidence")?;
    require_nonempty_hashed_evidence(
        evidence,
        "changedCount",
        "policy event impact changed count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "allowToBlockCount",
        "policy event impact allow-to-block count evidence",
    )?;
    require_boolean_hashed_evidence(
        evidence,
        "trackPosture",
        "policy event impact posture evidence",
    )?;
    let expected_impact_id = policy_event_impact_id_from_evidence(policy, evidence)?;
    if impact_id != expected_impact_id {
        return Err(anyhow!(
            "policy event impact id must match signed policy, proposed policy, stream, result, impact, count, and posture evidence"
        ));
    }
    Ok(())
}

fn policy_event_replay_id_from_evidence(
    policy: &EndpointPolicySnapshot,
    evidence: &[EndpointReceiptEvidence],
) -> Result<String> {
    let policy_epoch = policy.policy_epoch.to_string();
    Ok(stable_id(
        "policy_event_replay",
        [
            policy.policy_hash.as_str(),
            policy_epoch.as_str(),
            evidence_value_hash(
                evidence,
                "eventStreamHash",
                "policy event replay stream hash evidence",
            )?,
            evidence_value_hash(
                evidence,
                "resultHash",
                "policy event replay result hash evidence",
            )?,
            evidence_value_hash(evidence, "eventCount", "policy event replay count evidence")?,
            evidence_value_hash(
                evidence,
                "allowedCount",
                "policy event replay allowed count evidence",
            )?,
            evidence_value_hash(
                evidence,
                "warnCount",
                "policy event replay warn count evidence",
            )?,
            evidence_value_hash(
                evidence,
                "blockedCount",
                "policy event replay blocked count evidence",
            )?,
            evidence_value_hash(
                evidence,
                "trackPosture",
                "policy event replay posture evidence",
            )?,
        ],
    ))
}

fn policy_event_impact_id_from_evidence(
    policy: &EndpointPolicySnapshot,
    evidence: &[EndpointReceiptEvidence],
) -> Result<String> {
    let policy_epoch = policy.policy_epoch.to_string();
    Ok(stable_id(
        "policy_event_impact",
        [
            policy.policy_hash.as_str(),
            policy_epoch.as_str(),
            evidence_value_hash(
                evidence,
                "proposedPolicyHash",
                "policy event impact proposed-policy hash evidence",
            )?,
            evidence_value_hash(
                evidence,
                "proposedPolicyEpoch",
                "policy event impact proposed-policy epoch evidence",
            )?,
            evidence_value_hash(
                evidence,
                "eventStreamHash",
                "policy event impact stream hash evidence",
            )?,
            evidence_value_hash(
                evidence,
                "currentResultHash",
                "policy event impact current-result evidence",
            )?,
            evidence_value_hash(
                evidence,
                "proposedResultHash",
                "policy event impact proposed-result evidence",
            )?,
            evidence_value_hash(evidence, "impactHash", "policy event impact hash evidence")?,
            evidence_value_hash(evidence, "eventCount", "policy event impact count evidence")?,
            evidence_value_hash(
                evidence,
                "changedCount",
                "policy event impact changed count evidence",
            )?,
            evidence_value_hash(
                evidence,
                "allowToBlockCount",
                "policy event impact allow-to-block count evidence",
            )?,
            evidence_value_hash(
                evidence,
                "trackPosture",
                "policy event impact posture evidence",
            )?,
        ],
    ))
}

fn require_policy_event_stream_graph_reference(
    graph: &EndpointGraphReference,
    stream_id: &str,
    label: &str,
) -> Result<()> {
    let graph_slice_id = graph
        .graph_slice_id
        .as_deref()
        .ok_or_else(|| anyhow!("{label} graph slice reference is required"))?;
    if graph_slice_id != stream_id {
        return Err(anyhow!(
            "{label} graph slice reference must match signed id"
        ));
    }
    let process_node_id = graph
        .process_node_id
        .as_deref()
        .ok_or_else(|| anyhow!("{label} stream node reference is required"))?;
    if process_node_id != "policy_event_stream" {
        return Err(anyhow!(
            "{label} stream node reference must be policy_event_stream"
        ));
    }
    if !graph
        .node_ids
        .iter()
        .any(|node_id| node_id == "policy_event_stream")
    {
        return Err(anyhow!(
            "{label} stream node reference must be included in graph node ids"
        ));
    }
    Ok(())
}

fn require_deception_materialization_evidence(
    evidence: &[EndpointReceiptEvidence],
    actor: &EndpointDecisionActor,
    policy: &EndpointPolicySnapshot,
    signed_materialization_id: Option<&str>,
) -> Result<()> {
    require_evidence_value_hash(
        evidence,
        "endpointId",
        actor.endpoint_id.as_str(),
        "deception materialization endpoint evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "deceptionPlanRoot",
        "deception materialization plan root evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "deceptionPlanHash",
        "deception materialization plan hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "materializationReportHash",
        "deception materialization report hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "artifactCount",
        "deception materialization artifact count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "createdCount",
        "deception materialization created count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "skippedCount",
        "deception materialization skipped count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "registeredArtifactCount",
        "deception materialization registered artifact count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "artifactIds",
        "deception materialization artifact ids evidence",
    )?;
    let materialization_id = deception_materialization_id_from_evidence(
        evidence,
        actor.endpoint_id.as_str(),
        policy.policy_hash.as_str(),
    )?;
    if signed_materialization_id != Some(materialization_id.as_str()) {
        return Err(anyhow!(
            "deception materialization id must match signed plan root, plan, report, count, and artifact evidence"
        ));
    }
    Ok(())
}

fn require_deception_cleanup_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    actor: &EndpointDecisionActor,
    policy: &EndpointPolicySnapshot,
    signed_cleanup_id: Option<&str>,
) -> Result<()> {
    require_evidence_value_hash(
        evidence,
        "endpointId",
        actor.endpoint_id.as_str(),
        "deception cleanup endpoint evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "deceptionPlanRoot",
        "deception cleanup plan root evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "deceptionPlanHash",
        "deception cleanup plan hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "cleanupReportHash",
        "deception cleanup report hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "artifactCount",
        "deception cleanup artifact count evidence",
    )?;
    let dry_run = deception_cleanup_dry_run_from_decision(decision)?;
    require_evidence_value_hash(
        evidence,
        "dryRun",
        dry_run.to_string(),
        "deception cleanup dry-run evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "removedCount",
        "deception cleanup removed count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "wouldRemoveCount",
        "deception cleanup would-remove count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "missingCount",
        "deception cleanup missing count evidence",
    )?;
    let refused_count = evidence
        .iter()
        .find(|item| item.key == "refusedCount")
        .ok_or_else(|| anyhow!("deception cleanup refused count evidence is required"))?;
    require_evidence_hash_not_empty(refused_count, "deception cleanup refused count evidence")?;
    let zero_refused_hash = sha256(b"0").to_hex_prefixed();
    let refused_count_is_zero = hex_strings_match(
        zero_refused_hash.as_str(),
        refused_count.value_hash.as_str(),
    );
    if decision.passed != refused_count_is_zero {
        return Err(anyhow!(
            "deception cleanup refused count evidence hash must match signed pass state"
        ));
    }
    require_nonempty_hashed_evidence(
        evidence,
        "deregisteredArtifactCount",
        "deception cleanup deregistered artifact count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "remainingRegisteredArtifactCount",
        "deception cleanup remaining registered artifact count evidence",
    )?;
    let cleanup_id = deception_cleanup_id_from_evidence(
        evidence,
        actor.endpoint_id.as_str(),
        policy.policy_hash.as_str(),
    )?;
    if signed_cleanup_id != Some(cleanup_id.as_str()) {
        return Err(anyhow!(
            "deception cleanup id must match signed plan root, plan, report, mode, count, and registry evidence"
        ));
    }
    Ok(())
}

fn deception_cleanup_dry_run_from_decision(decision: &EndpointDecisionRecord) -> Result<bool> {
    let title = decision
        .title
        .as_deref()
        .ok_or_else(|| anyhow!("deception cleanup title is required"))?;
    match title {
        "Endpoint deception cleanup dry run planned" => Ok(true),
        "Endpoint deception cleanup executed" => Ok(false),
        _ => Err(anyhow!("deception cleanup title is invalid")),
    }
}

fn require_deception_rotation_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    actor: &EndpointDecisionActor,
    policy: &EndpointPolicySnapshot,
    signed_rotation_id: Option<&str>,
) -> Result<()> {
    require_evidence_value_hash(
        evidence,
        "endpointId",
        actor.endpoint_id.as_str(),
        "deception rotation endpoint evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "oldDeceptionPlanRoot",
        "deception rotation old plan root evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "newDeceptionPlanRoot",
        "deception rotation new plan root evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "oldDeceptionPlanHash",
        "deception rotation old plan hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "newDeceptionPlanHash",
        "deception rotation new plan hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "rotationReportHash",
        "deception rotation report hash evidence",
    )?;
    let dry_run = deception_rotation_dry_run_from_decision(decision)?;
    require_evidence_value_hash(
        evidence,
        "dryRun",
        dry_run.to_string(),
        "deception rotation dry-run evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "cleanupRemovedCount",
        "deception rotation cleanup removed count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "cleanupWouldRemoveCount",
        "deception rotation cleanup would-remove count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "cleanupMissingCount",
        "deception rotation cleanup missing count evidence",
    )?;
    let refused_count = evidence
        .iter()
        .find(|item| item.key == "cleanupRefusedCount")
        .ok_or_else(|| anyhow!("deception rotation cleanup refused count evidence is required"))?;
    require_evidence_hash_not_empty(
        refused_count,
        "deception rotation cleanup refused count evidence",
    )?;
    let zero_refused_hash = sha256(b"0").to_hex_prefixed();
    let refused_count_is_zero = hex_strings_match(
        zero_refused_hash.as_str(),
        refused_count.value_hash.as_str(),
    );
    if decision.passed != refused_count_is_zero {
        return Err(anyhow!(
            "deception rotation cleanup refused count evidence hash must match signed pass state"
        ));
    }
    require_nonempty_hashed_evidence(
        evidence,
        "materializationCreatedCount",
        "deception rotation materialization created count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "materializationSkippedCount",
        "deception rotation materialization skipped count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "deregisteredArtifactCount",
        "deception rotation deregistered artifact count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "registeredArtifactCount",
        "deception rotation registered artifact count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "remainingRegisteredArtifactCount",
        "deception rotation remaining registered artifact count evidence",
    )?;
    let rotation_id = deception_rotation_id_from_evidence(
        evidence,
        actor.endpoint_id.as_str(),
        policy.policy_hash.as_str(),
    )?;
    if signed_rotation_id != Some(rotation_id.as_str()) {
        return Err(anyhow!(
            "deception rotation id must match signed plan root, plan, report, mode, count, and registry evidence"
        ));
    }
    Ok(())
}

fn deception_rotation_dry_run_from_decision(decision: &EndpointDecisionRecord) -> Result<bool> {
    let title = decision
        .title
        .as_deref()
        .ok_or_else(|| anyhow!("deception rotation title is required"))?;
    match title {
        "Endpoint deception rotation dry run planned" => Ok(true),
        "Endpoint deception rotation executed" => Ok(false),
        _ => Err(anyhow!("deception rotation title is invalid")),
    }
}

fn require_policy_delta_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    actor: &EndpointDecisionActor,
    policy: &EndpointPolicySnapshot,
    graph_slice_id: Option<&str>,
    root_node_id: Option<&str>,
) -> Result<()> {
    let policy_delta_id = decision
        .finding_id
        .as_deref()
        .ok_or_else(|| anyhow!("policy delta signed id is required"))?;
    let rule_id = decision
        .rule_id
        .as_deref()
        .ok_or_else(|| anyhow!("policy delta rule id is required"))?;
    let graph_slice_id =
        graph_slice_id.ok_or_else(|| anyhow!("policy delta graph slice id is required"))?;
    let root_node_id =
        root_node_id.ok_or_else(|| anyhow!("policy delta root node id is required"))?;
    let operation = policy_delta_operation_from_title(decision)?;
    require_evidence_value_hash(
        evidence,
        "operation",
        operation,
        "policy delta operation evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "policyDeltaId",
        policy_delta_id,
        "policy delta id evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "stagedDetectionId",
        "policy delta staged detection evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "stage", "policy delta stage evidence")?;
    require_policy_delta_stage_action_evidence(evidence, &decision.action)?;
    require_nonempty_hashed_evidence(
        evidence,
        "generatedAt",
        "policy delta generated-at evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "artifactHash",
        "policy delta artifact hash evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "simulationId", "policy delta simulation evidence")?;
    require_evidence_value_hash(
        evidence,
        "graphSliceId",
        graph_slice_id,
        "policy delta graph slice evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "rootNodeId",
        root_node_id,
        "policy delta root node evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "sourceAffectedIdentityContext",
        "policy delta source affected identity context evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "sourceAffectedToolContext",
        "policy delta source affected tool context evidence",
    )?;
    let expected_policy_delta_id = policy_delta_id_from_evidence(
        evidence,
        actor.endpoint_id.as_str(),
        rule_id,
        &decision.action,
    )?;
    if policy_delta_id != expected_policy_delta_id {
        return Err(anyhow!(
            "policy delta id must match signed endpoint, rule, action, staged source, generation time, simulation, and graph evidence"
        ));
    }
    require_policy_delta_operation_evidence(evidence, operation, policy)?;
    Ok(())
}

fn require_policy_delta_stage_action_evidence(
    evidence: &[EndpointReceiptEvidence],
    action: &EndpointDecisionAction,
) -> Result<()> {
    let stage_hash = evidence_value_hash(evidence, "stage", "policy delta stage evidence")?;
    let Some(stage) = policy_delta_stage_from_hash(stage_hash) else {
        return Err(anyhow!(
            "policy delta stage evidence must be observe, audit, warn, limited_block, or full_block"
        ));
    };
    if matches!(stage, "limited_block" | "full_block")
        && !policy_delta_receipt_enforcement_action_supported(action)
    {
        return Err(anyhow!(
            "policy delta enforcement stage requires a rollback-capable policy action"
        ));
    }
    Ok(())
}

fn policy_delta_stage_from_hash(stage_hash: &str) -> Option<&'static str> {
    ["observe", "audit", "warn", "limited_block", "full_block"]
        .into_iter()
        .find(|stage| {
            let expected_hash = sha256(stage.as_bytes()).to_hex_prefixed();
            hex_strings_match(expected_hash.as_str(), stage_hash)
        })
}

fn policy_delta_receipt_enforcement_action_supported(action: &EndpointDecisionAction) -> bool {
    matches!(
        action,
        EndpointDecisionAction::Block
            | EndpointDecisionAction::RestrictEgress
            | EndpointDecisionAction::SuspendProcessTree
            | EndpointDecisionAction::QuarantineFile
            | EndpointDecisionAction::RevokeGrant
            | EndpointDecisionAction::DisablePersistence
    )
}

fn policy_delta_operation_from_title(decision: &EndpointDecisionRecord) -> Result<&str> {
    let title = decision
        .title
        .as_deref()
        .ok_or_else(|| anyhow!("policy delta operation title is required"))?;
    let Some(operation) = title.strip_prefix("Endpoint staged policy delta ") else {
        return Err(anyhow!("policy delta operation title is invalid"));
    };
    match operation {
        "generated" | "prepared" | "applied" => Ok(operation),
        _ => Err(anyhow!("policy delta operation title is invalid")),
    }
}

fn require_policy_delta_operation_evidence(
    evidence: &[EndpointReceiptEvidence],
    operation: &str,
    policy: &EndpointPolicySnapshot,
) -> Result<()> {
    let has_previous_policy_hash = evidence.iter().any(|item| item.key == "previousPolicyHash");
    let has_new_policy_hash = evidence.iter().any(|item| item.key == "newPolicyHash");
    let has_backup_path = evidence.iter().any(|item| item.key == "backupPath");

    match operation {
        "generated" => {
            if has_previous_policy_hash || has_new_policy_hash || has_backup_path {
                return Err(anyhow!(
                    "policy delta generated receipt must not include apply evidence"
                ));
            }
        }
        "prepared" | "applied" => {
            require_nonempty_hashed_evidence(
                evidence,
                "previousPolicyHash",
                "policy delta applied previous policy evidence",
            )?;
            require_evidence_value_hash(
                evidence,
                "newPolicyHash",
                policy.policy_hash.as_str(),
                "policy delta applied new policy evidence",
            )?;
            require_nonempty_hashed_evidence(
                evidence,
                "backupPath",
                "policy delta applied backup evidence",
            )?;
        }
        _ => unreachable!("policy delta operation already validated"),
    }

    Ok(())
}

fn policy_delta_id_from_evidence(
    evidence: &[EndpointReceiptEvidence],
    endpoint_id: &str,
    rule_id: &str,
    action: &EndpointDecisionAction,
) -> Result<String> {
    Ok(stable_id(
        "policy_delta",
        [
            endpoint_id,
            rule_id,
            action.as_str(),
            evidence_value_hash(
                evidence,
                "stagedDetectionId",
                "policy delta staged detection evidence",
            )?,
            evidence_value_hash(evidence, "stage", "policy delta stage evidence")?,
            evidence_value_hash(
                evidence,
                "generatedAt",
                "policy delta generated-at evidence",
            )?,
            evidence_value_hash(evidence, "simulationId", "policy delta simulation evidence")?,
            evidence_value_hash(
                evidence,
                "graphSliceId",
                "policy delta graph slice evidence",
            )?,
            evidence_value_hash(evidence, "rootNodeId", "policy delta root node evidence")?,
            evidence_value_hash(
                evidence,
                "sourceAffectedIdentityContext",
                "policy delta source affected identity context evidence",
            )?,
            evidence_value_hash(
                evidence,
                "sourceAffectedToolContext",
                "policy delta source affected tool context evidence",
            )?,
        ],
    ))
}

fn require_policy_delta_graph_reference(graph: &EndpointGraphReference) -> Result<()> {
    let root_node_id = graph
        .process_node_id
        .as_deref()
        .ok_or_else(|| anyhow!("policy delta root node id is required"))?;
    if !graph.node_ids.iter().any(|node_id| node_id == root_node_id) {
        return Err(anyhow!(
            "policy delta root node reference must be included in graph node ids"
        ));
    }
    Ok(())
}

fn require_privacy_report_evidence(
    evidence: &[EndpointReceiptEvidence],
    privacy_report_id: Option<&str>,
) -> Result<()> {
    let privacy_report_id =
        privacy_report_id.ok_or_else(|| anyhow!("privacy report signed id is required"))?;
    require_evidence_value_hash(
        evidence,
        "privacyReportId",
        privacy_report_id,
        "privacy report id evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "privacyMode", "privacy report mode evidence")?;
    require_boolean_hashed_evidence(
        evidence,
        "rawArtifactUploadPermitted",
        "privacy report raw artifact permission evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "observationCount",
        "privacy report observation count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "fieldCount",
        "privacy report field count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "hashOnlyCount",
        "privacy report hash-only count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "metadataOnlyCount",
        "privacy report metadata-only count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "redactedCount",
        "privacy report redacted count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "rawSuppressedCount",
        "privacy report raw suppressed count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "localOnlyCount",
        "privacy report local-only count evidence",
    )?;
    let raw_artifact_upload_permitted_hash = evidence_value_hash(
        evidence,
        "rawArtifactUploadPermitted",
        "privacy report raw artifact permission evidence",
    )?;
    let true_hash = sha256(b"true").to_hex_prefixed();
    if hex_strings_match(raw_artifact_upload_permitted_hash, true_hash.as_str()) {
        require_nonempty_hashed_evidence(
            evidence,
            "rawArtifactApprovalId",
            "privacy report raw artifact approval id evidence",
        )?;
        require_nonempty_hashed_evidence(
            evidence,
            "rawArtifactApprovalReasonHash",
            "privacy report raw artifact approval reason hash evidence",
        )?;
    }
    let expected_privacy_report_id = telemetry_privacy_report_id_from_evidence(evidence)?;
    if privacy_report_id != expected_privacy_report_id {
        return Err(anyhow!(
            "privacy report id must match signed mode and count evidence"
        ));
    }
    Ok(())
}

fn require_provider_degradation_evidence(
    evidence: &[EndpointReceiptEvidence],
    signed_degradation_id: Option<&str>,
    rule_id: Option<&str>,
    actor: &EndpointDecisionActor,
    policy: &EndpointPolicySnapshot,
    sensor_state: &EndpointSensorState,
) -> Result<()> {
    let signed_degradation_id = signed_degradation_id
        .ok_or_else(|| anyhow!("provider degradation signed id is required"))?;
    let rule_id = rule_id.ok_or_else(|| anyhow!("provider degradation rule id is required"))?;
    let provider_id = rule_id
        .strip_prefix("endpoint.provider_degradation.")
        .ok_or_else(|| anyhow!("provider degradation rule id must include provider id"))?;
    let provider = sensor_state
        .providers
        .iter()
        .find(|provider| provider.provider_id == provider_id)
        .ok_or_else(|| {
            anyhow!("provider degradation provider id is not present in sensor state")
        })?;
    let provider_kind = camel_debug_to_snake(format!("{:?}", provider.provider_kind).as_str());
    let reasons = provider.degradation_reasons.join("|");

    require_evidence_value_hash(
        evidence,
        "providerId",
        provider.provider_id.as_str(),
        "provider degradation provider id evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "providerKind",
        provider_kind.as_str(),
        "provider degradation provider kind evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "installed",
        provider.installed.to_string(),
        "provider degradation installed evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "active",
        provider.active.to_string(),
        "provider degradation active evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "healthy",
        provider.healthy.to_string(),
        "provider degradation healthy evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "degraded",
        provider.degraded.to_string(),
        "provider degradation degraded evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "degradationReasons",
        reasons,
        "provider degradation reasons evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "droppedEventCount",
        provider.dropped_event_count.to_string(),
        "provider degradation dropped-event count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "deadlineMissCount",
        provider.deadline_miss_count.to_string(),
        "provider degradation deadline-miss count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "fullDiskAccess",
        endpoint_provider_full_disk_access_evidence_value(provider.full_disk_access),
        "provider degradation full-disk-access evidence",
    )?;
    let expected_degradation_id = provider_degradation_id_from_evidence(
        evidence,
        actor.endpoint_id.as_str(),
        policy.policy_hash.as_str(),
    )?;
    if signed_degradation_id != expected_degradation_id {
        return Err(anyhow!(
            "provider degradation id must match signed endpoint, policy, provider state, reason, and counter evidence"
        ));
    }
    Ok(())
}

fn require_response_execution_status_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let expected_status = response_execution_status_from_decision(decision)?;
    require_evidence_value_hash(
        evidence,
        "executionStatus",
        expected_status,
        "execution status evidence",
    )
}

fn response_execution_status_from_decision(
    decision: &EndpointDecisionRecord,
) -> Result<&'static str> {
    let Some(title) = decision.title.as_deref() else {
        return Err(anyhow!("execution status title is required"));
    };
    let expected = match title {
        "Endpoint response action executed" => "succeeded",
        "Endpoint response action failed" => "failed",
        "Endpoint response action partially executed" => "partial",
        "Endpoint response rollback pending" => "rollback_pending",
        "Endpoint response rollback failed" => "rollback_failed",
        "Endpoint response action expired" => "expired",
        "Endpoint response action cancelled" => "cancelled",
        "Endpoint response action rolled back" => "rolled_back",
        _ => return Err(anyhow!("execution status title is invalid")),
    };
    let expected_passed = expected == "succeeded";
    if decision.passed != expected_passed {
        return Err(anyhow!("execution status passed flag is inconsistent"));
    }
    Ok(expected)
}

fn require_response_rollback_status_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    if decision.title.as_deref() != Some("Endpoint response rollback executed") {
        return Err(anyhow!("rollback status title is invalid"));
    }
    if !decision.passed {
        return Err(anyhow!("rollback status passed flag is inconsistent"));
    }
    require_evidence_value_hash(
        evidence,
        "rollbackStatus",
        "succeeded",
        "rollback status evidence",
    )
}

fn require_response_acknowledgement_status_evidence(
    decision: &EndpointDecisionRecord,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let expected_status = response_acknowledgement_status_from_decision(decision)?;
    require_evidence_value_hash(
        evidence,
        "acknowledgedStatus",
        expected_status,
        "acknowledgement status evidence",
    )
}

fn response_acknowledgement_status_from_decision(
    decision: &EndpointDecisionRecord,
) -> Result<&str> {
    let Some(title) = decision.title.as_deref() else {
        return Err(anyhow!("acknowledgement status title is required"));
    };
    let Some(status) = title.strip_prefix("Endpoint response execution acknowledged: ") else {
        return Err(anyhow!("acknowledgement status title is invalid"));
    };
    match status {
        "succeeded" | "failed" | "partial" | "expired" | "cancelled" | "rolled_back" => {}
        _ => return Err(anyhow!("acknowledgement status title is invalid")),
    }
    if !decision.passed {
        return Err(anyhow!(
            "acknowledgement status passed flag is inconsistent"
        ));
    }
    Ok(status)
}

fn require_response_acknowledged_by_evidence(
    actor: &EndpointDecisionActor,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let acknowledged_by = actor
        .agent_id
        .as_deref()
        .ok_or_else(|| anyhow!("acknowledged-by actor identity is required"))?;
    require_nonempty(acknowledged_by, "acknowledged-by actor identity")?;
    require_evidence_value_hash(
        evidence,
        "acknowledgedBy",
        acknowledged_by,
        "acknowledged-by evidence",
    )
}

fn require_response_control_acknowledgement_evidence(
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    let has_control_evidence = evidence.iter().any(|item| item.key.starts_with("control"));
    if !has_control_evidence {
        return Ok(());
    }

    require_nonempty_hashed_evidence(
        evidence,
        "controlResponseActionId",
        "control acknowledgement response action id evidence",
    )?;
    require_control_target_kind_evidence(evidence)?;
    require_nonempty_hashed_evidence(
        evidence,
        "controlTargetId",
        "control acknowledgement target id evidence",
    )?;
    require_control_ack_token_hash_evidence(evidence)?;
    require_control_ack_status_evidence(evidence)?;

    for (key, field_name) in [
        (
            "controlDeliveryId",
            "control acknowledgement delivery id evidence",
        ),
        (
            "controlResultingState",
            "control acknowledgement resulting state evidence",
        ),
    ] {
        if evidence.iter().any(|item| item.key == key) {
            require_nonempty_hashed_evidence(evidence, key, field_name)?;
        }
    }

    Ok(())
}

fn require_control_ack_token_hash_evidence(evidence: &[EndpointReceiptEvidence]) -> Result<()> {
    let Some(item) = evidence
        .iter()
        .find(|item| item.key == "controlAckTokenHash")
    else {
        return Err(anyhow!(
            "control acknowledgement token hash evidence is required"
        ));
    };
    if item.redaction_class != EndpointEvidenceRedactionClass::HashOnly || item.raw_value.is_some()
    {
        return Err(anyhow!(
            "control acknowledgement token hash evidence must be hash-only"
        ));
    }
    require_evidence_hash_not_empty(item, "control acknowledgement token hash evidence")
}

fn require_control_ack_status_evidence(evidence: &[EndpointReceiptEvidence]) -> Result<()> {
    let Some(item) = evidence.iter().find(|item| item.key == "controlAckStatus") else {
        return Err(anyhow!(
            "control acknowledgement status evidence is required"
        ));
    };
    require_evidence_hash_not_empty(item, "control acknowledgement status evidence")?;
    let allowed_statuses = [
        "acknowledged",
        "rejected",
        "failed",
        "expired",
        "rolled_back",
    ];
    if allowed_statuses.iter().any(|status| {
        let expected_hash = sha256(status.as_bytes()).to_hex_prefixed();
        hex_strings_match(expected_hash.as_str(), item.value_hash.as_str())
    }) {
        return Ok(());
    }
    Err(anyhow!(
        "control acknowledgement status evidence must be acknowledged, rejected, failed, expired, or rolled_back"
    ))
}

fn require_control_target_kind_evidence(evidence: &[EndpointReceiptEvidence]) -> Result<()> {
    let Some(item) = evidence.iter().find(|item| item.key == "controlTargetKind") else {
        return Err(anyhow!(
            "control acknowledgement target kind evidence is required"
        ));
    };
    require_evidence_hash_not_empty(item, "control acknowledgement target kind evidence")?;
    let allowed_target_kinds = [
        "endpoint",
        "runtime",
        "session",
        "principal",
        "grant",
        "swarm",
        "project",
    ];
    if allowed_target_kinds.iter().any(|target_kind| {
        let expected_hash = sha256(target_kind.as_bytes()).to_hex_prefixed();
        hex_strings_match(expected_hash.as_str(), item.value_hash.as_str())
    }) {
        return Ok(());
    }
    Err(anyhow!(
        "control acknowledgement target kind evidence must be endpoint, runtime, session, principal, grant, swarm, or project"
    ))
}

fn require_nonempty_hashed_evidence(
    evidence: &[EndpointReceiptEvidence],
    key: &str,
    field_name: &str,
) -> Result<()> {
    let Some(item) = evidence.iter().find(|item| item.key == key) else {
        return Err(anyhow!("{field_name} is required"));
    };
    require_evidence_hash_not_empty(item, field_name)
}

fn evidence_value_hash<'a>(
    evidence: &'a [EndpointReceiptEvidence],
    key: &str,
    field_name: &str,
) -> Result<&'a str> {
    let Some(item) = evidence.iter().find(|item| item.key == key) else {
        return Err(anyhow!("{field_name} is required"));
    };
    require_evidence_hash_not_empty(item, field_name)?;
    Ok(item.value_hash.as_str())
}

fn require_boolean_hashed_evidence(
    evidence: &[EndpointReceiptEvidence],
    key: &str,
    field_name: &str,
) -> Result<()> {
    let Some(item) = evidence.iter().find(|item| item.key == key) else {
        return Err(anyhow!("{field_name} is required"));
    };
    require_evidence_hash_not_empty(item, field_name)?;
    let true_hash = sha256(b"true").to_hex_prefixed();
    let false_hash = sha256(b"false").to_hex_prefixed();
    if !hex_strings_match(true_hash.as_str(), item.value_hash.as_str())
        && !hex_strings_match(false_hash.as_str(), item.value_hash.as_str())
    {
        return Err(anyhow!("{field_name} must be boolean"));
    }
    Ok(())
}

fn require_evidence_hash_not_empty(item: &EndpointReceiptEvidence, field_name: &str) -> Result<()> {
    let empty_value_hash = sha256(b"").to_hex_prefixed();
    if hex_strings_match(empty_value_hash.as_str(), item.value_hash.as_str()) {
        return Err(anyhow!("{field_name} must not be empty"));
    }
    Ok(())
}

fn require_response_action(action: &EndpointDecisionAction) -> Result<()> {
    if matches!(
        action,
        EndpointDecisionAction::RestrictEgress
            | EndpointDecisionAction::SuspendProcessTree
            | EndpointDecisionAction::TerminateProcessTree
            | EndpointDecisionAction::QuarantineFile
            | EndpointDecisionAction::RevokeGrant
            | EndpointDecisionAction::DisablePersistence
            | EndpointDecisionAction::CollectEvidence
    ) {
        return Ok(());
    }

    Err(anyhow!(
        "response action must be a bounded local response action"
    ))
}

fn require_response_action_for_family(
    family: &EndpointDecisionReceiptFamily,
    decision: &EndpointDecisionRecord,
) -> Result<()> {
    require_response_action(&decision.action)?;
    if decision.action != EndpointDecisionAction::TerminateProcessTree {
        return Ok(());
    }

    if family == &EndpointDecisionReceiptFamily::ResponseRequest
        && response_request_dry_run_from_decision(decision)?
    {
        return Ok(());
    }

    Err(anyhow!(
        "terminate_process_tree response proofs are limited to dry-run response requests"
    ))
}

fn require_provider_last_seen_consistency(
    provider: &EndpointProviderState,
    captured_at: &DateTime<Utc>,
) -> Result<()> {
    if (provider.active || provider.healthy) && provider.last_seen.is_none() {
        return Err(anyhow!(
            "sensor provider {} last seen timestamp is required when provider is active or healthy",
            provider.provider_id
        ));
    }
    if let Some(last_seen) = provider.last_seen.as_ref() {
        if last_seen > captured_at {
            return Err(anyhow!(
                "sensor provider {} last seen timestamp is after receipt capture time",
                provider.provider_id
            ));
        }
    }
    Ok(())
}

fn require_provider_degradation_consistency(provider: &EndpointProviderState) -> Result<()> {
    let has_degradation_signal = !provider.installed
        || !provider.active
        || !provider.healthy
        || provider.dropped_event_count > 0
        || provider.deadline_miss_count > 0
        || provider.full_disk_access == Some(false);

    if has_degradation_signal && !provider.degraded {
        return Err(anyhow!(
            "sensor provider {} must be marked degraded when installed, active, healthy, event-loss, deadline, or full-disk-access evidence indicates degraded protection",
            provider.provider_id
        ));
    }
    Ok(())
}

fn require_response_actor_context(actor: &EndpointDecisionActor) -> Result<()> {
    let has_actor_context = [
        actor.user_id.as_deref(),
        actor.session_id.as_deref(),
        actor.agent_id.as_deref(),
        actor.workload_id.as_deref(),
        actor.approval_id.as_deref(),
    ]
    .into_iter()
    .flatten()
    .any(|value| !value.trim().is_empty());

    if has_actor_context {
        return Ok(());
    }
    Err(anyhow!("response actor context is required"))
}

fn require_response_actor_evidence(
    actor: &EndpointDecisionActor,
    evidence: &[EndpointReceiptEvidence],
) -> Result<()> {
    require_evidence_value_hash(
        evidence,
        "actorHash",
        endpoint_decision_actor_content_hash(actor),
        "response actor evidence",
    )
}

fn hex_strings_match(expected: &str, actual: &str) -> bool {
    trim_hex_prefix(expected).eq_ignore_ascii_case(trim_hex_prefix(actual))
}

fn trim_hex_prefix(value: &str) -> &str {
    value
        .trim()
        .strip_prefix("0x")
        .or_else(|| value.trim().strip_prefix("0X"))
        .unwrap_or_else(|| value.trim())
}

fn camel_debug_to_snake(value: &str) -> String {
    let mut out = String::new();
    for (idx, ch) in value.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if idx > 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

fn reconstruct_path(from: &str, to: &str, previous: &BTreeMap<String, String>) -> Vec<String> {
    let mut path = vec![to.to_string()];
    let mut cursor = to;
    while let Some(prev) = previous.get(cursor) {
        path.push(prev.clone());
        if prev == from {
            break;
        }
        cursor = prev;
    }
    path.reverse();
    path
}
