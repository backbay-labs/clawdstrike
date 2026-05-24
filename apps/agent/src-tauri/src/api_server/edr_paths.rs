//! On-disk path defaults for EDR ledgers, registries, and recorders.
//!
//! Each `default_edr_*_path` resolves under `crate::settings::get_config_dir()`
//! and each `default_edr_*_*_ledger` (or `_store`, `_registry`, `_outbox`,
//! `_recorder`) opens that path with a tracing warning if it fails, falling
//! back to the transient in-memory variant so the agent never panics during
//! initialization on a partially-provisioned host.

use clawdstrike_policy_event::edr::EndpointFlightRecorder;
use hush_core::Keypair;
use std::path::PathBuf;

use crate::edr::ledger::{
    EndpointControlAckPostbackRetryLedger, EndpointControlArchiveUploadRetryLedger,
    EndpointControlReceiptUploadRetryLedger, EndpointEgressRestrictionLedger,
    EndpointEvidenceBundleStore, EndpointFleetHuntEventOutbox, EndpointHoneyRegistry,
    EndpointPolicyDeltaStore, EndpointReceiptLedger, EndpointResponseAcknowledgementLedger,
    EndpointResponseExecutionLedger, EndpointStagedDetectionLedger,
};

pub(super) fn default_edr_flight_recorder_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("flight-recorder.jsonl")
}

pub(super) fn default_edr_flight_recorder() -> EndpointFlightRecorder {
    let path = default_edr_flight_recorder_path();
    match EndpointFlightRecorder::open(&path) {
        Ok(recorder) => recorder,
        Err(err) => {
            tracing::warn!(
                error = %err,
                path = %path.display(),
                "failed to open endpoint flight recorder, using transient recorder"
            );
            EndpointFlightRecorder::transient()
        }
    }
}

pub(super) fn default_edr_receipt_ledger_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("decision-receipts.jsonl")
}

pub(super) fn default_edr_honey_registry_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("honey-artifacts.jsonl")
}

pub(super) fn default_edr_evidence_bundle_dir() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("evidence-bundles")
}

pub(super) fn default_edr_quarantine_dir() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("quarantine")
}

pub(super) fn default_edr_response_execution_ledger_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("response-executions.jsonl")
}

pub(super) fn default_edr_response_acknowledgement_ledger_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("response-acknowledgements.jsonl")
}

pub(super) fn default_edr_control_ack_postback_retry_ledger_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("control-ack-postback-retries.json")
}

pub(super) fn default_edr_control_archive_upload_retry_ledger_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("control-archive-upload-retries.json")
}

pub(super) fn default_edr_control_receipt_upload_retry_ledger_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("control-receipt-upload-retries.json")
}

pub(super) fn default_edr_fleet_hunt_event_outbox_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("fleet-hunt-event-outbox.json")
}

pub(super) fn default_edr_egress_restriction_ledger_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("egress-restrictions.jsonl")
}

pub(super) fn default_edr_staged_detection_ledger_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("staged-detections.jsonl")
}

pub(super) fn default_edr_policy_delta_dir() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("policy-deltas")
}

pub(super) fn default_edr_network_extension_egress_policy_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("network-extension-egress-policy.json")
}

pub(super) fn default_edr_receipt_signing_key_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("receipt-signing.key")
}

pub(super) fn default_edr_receipt_ledger() -> EndpointReceiptLedger {
    match EndpointReceiptLedger::open(default_edr_receipt_ledger_path()) {
        Ok(ledger) => ledger,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "Failed to open endpoint receipt ledger; using transient EDR receipt signer"
            );
            EndpointReceiptLedger::transient(Keypair::generate(), "transient-edr")
        }
    }
}

pub(super) fn default_edr_honey_registry() -> EndpointHoneyRegistry {
    match EndpointHoneyRegistry::open(default_edr_honey_registry_path()) {
        Ok(registry) => registry,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "Failed to open endpoint honey registry; using transient registry"
            );
            EndpointHoneyRegistry::transient()
        }
    }
}

pub(super) fn default_edr_evidence_bundle_store() -> EndpointEvidenceBundleStore {
    match EndpointEvidenceBundleStore::open(default_edr_evidence_bundle_dir()) {
        Ok(store) => store,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "Failed to open endpoint evidence bundle store; using transient store"
            );
            EndpointEvidenceBundleStore::transient()
        }
    }
}

pub(super) fn default_edr_response_execution_ledger() -> EndpointResponseExecutionLedger {
    match EndpointResponseExecutionLedger::open(default_edr_response_execution_ledger_path()) {
        Ok(ledger) => ledger,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "Failed to open endpoint response execution ledger; using transient ledger"
            );
            EndpointResponseExecutionLedger::transient()
        }
    }
}

pub(super) fn default_edr_response_acknowledgement_ledger() -> EndpointResponseAcknowledgementLedger
{
    match EndpointResponseAcknowledgementLedger::open(
        default_edr_response_acknowledgement_ledger_path(),
    ) {
        Ok(ledger) => ledger,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "Failed to open endpoint response acknowledgement ledger; using transient ledger"
            );
            EndpointResponseAcknowledgementLedger::transient()
        }
    }
}

pub(super) fn default_edr_control_ack_postback_retry_ledger() -> EndpointControlAckPostbackRetryLedger
{
    match EndpointControlAckPostbackRetryLedger::open(
        default_edr_control_ack_postback_retry_ledger_path(),
    ) {
        Ok(ledger) => ledger,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "Failed to open endpoint Control API acknowledgement retry queue; using transient queue"
            );
            EndpointControlAckPostbackRetryLedger::transient()
        }
    }
}

pub(super) fn default_edr_control_archive_upload_retry_ledger() -> EndpointControlArchiveUploadRetryLedger
{
    match EndpointControlArchiveUploadRetryLedger::open(
        default_edr_control_archive_upload_retry_ledger_path(),
    ) {
        Ok(ledger) => ledger,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "Failed to open endpoint Control API archive upload retry queue; using transient queue"
            );
            EndpointControlArchiveUploadRetryLedger::transient()
        }
    }
}

pub(super) fn default_edr_control_receipt_upload_retry_ledger() -> EndpointControlReceiptUploadRetryLedger
{
    match EndpointControlReceiptUploadRetryLedger::open(
        default_edr_control_receipt_upload_retry_ledger_path(),
    ) {
        Ok(ledger) => ledger,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "Failed to open endpoint Control API receipt upload retry queue; using transient queue"
            );
            EndpointControlReceiptUploadRetryLedger::transient()
        }
    }
}

pub(super) fn default_edr_fleet_hunt_event_outbox() -> EndpointFleetHuntEventOutbox {
    match EndpointFleetHuntEventOutbox::open(default_edr_fleet_hunt_event_outbox_path()) {
        Ok(outbox) => outbox,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "Failed to open endpoint fleet hunt-event outbox; using transient outbox"
            );
            EndpointFleetHuntEventOutbox::transient()
        }
    }
}

pub(super) fn default_edr_egress_restriction_ledger() -> EndpointEgressRestrictionLedger {
    match EndpointEgressRestrictionLedger::open(default_edr_egress_restriction_ledger_path()) {
        Ok(ledger) => ledger,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "Failed to open endpoint egress restriction ledger; using transient ledger"
            );
            EndpointEgressRestrictionLedger::transient()
        }
    }
}

pub(super) fn default_edr_staged_detection_ledger() -> EndpointStagedDetectionLedger {
    match EndpointStagedDetectionLedger::open(default_edr_staged_detection_ledger_path()) {
        Ok(ledger) => ledger,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "Failed to open endpoint staged detection ledger; using transient ledger"
            );
            EndpointStagedDetectionLedger::transient()
        }
    }
}

pub(super) fn default_edr_policy_delta_store() -> EndpointPolicyDeltaStore {
    match EndpointPolicyDeltaStore::open(default_edr_policy_delta_dir()) {
        Ok(store) => store,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "Failed to open endpoint policy delta store; using transient store"
            );
            EndpointPolicyDeltaStore::transient()
        }
    }
}
