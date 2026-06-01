mod common;
mod construct;
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
