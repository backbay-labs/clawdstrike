//! Default file paths and on-disk ledger constructors for the EDR pipeline.
//!
//! These functions return `PathBuf`s rooted in the agent config directory and
//! open the corresponding durable JSONL ledgers. They are called by
//! `AgentApiServer::try_new` when seeding `AgentApiState`.

use super::*;
use anyhow::{Context, Result};
use hush_core::{Keypair, SignedReceipt};
use std::path::PathBuf;

use crate::settings::Settings;

pub(crate) fn default_edr_flight_recorder_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("flight-recorder.jsonl")
}

pub(crate) fn default_edr_flight_recorder(
) -> Result<clawdstrike_policy_event::edr::EndpointFlightRecorder> {
    let path = default_edr_flight_recorder_path();
    clawdstrike_policy_event::edr::EndpointFlightRecorder::open(&path)
        .with_context(|| format!("open durable endpoint flight recorder {}", path.display()))
}

pub(crate) fn default_edr_receipt_ledger_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("decision-receipts.jsonl")
}

pub(crate) fn default_edr_honey_registry_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("honey-artifacts.jsonl")
}

pub(crate) fn default_edr_evidence_bundle_dir() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("evidence-bundles")
}

pub(crate) fn default_edr_quarantine_dir() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("quarantine")
}

pub(crate) fn default_edr_response_execution_ledger_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("response-executions.jsonl")
}

pub(crate) fn default_edr_response_acknowledgement_ledger_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("response-acknowledgements.jsonl")
}

pub(crate) fn default_edr_control_ack_postback_retry_ledger_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("control-ack-postback-retries.json")
}

pub(crate) fn default_edr_control_archive_upload_retry_ledger_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("control-archive-upload-retries.json")
}

pub(crate) fn default_edr_control_receipt_upload_retry_ledger_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("control-receipt-upload-retries.json")
}

pub(crate) fn default_edr_fleet_hunt_event_outbox_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("fleet-hunt-event-outbox.json")
}

pub(crate) fn default_edr_egress_restriction_ledger_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("egress-restrictions.jsonl")
}

pub(crate) fn default_edr_staged_detection_ledger_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("staged-detections.jsonl")
}

pub(crate) fn default_edr_policy_delta_dir() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("policy-deltas")
}

pub(crate) fn default_edr_network_extension_egress_policy_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("network-extension-egress-policy.json")
}

pub(crate) fn default_edr_receipt_signing_key_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("receipt-signing.key")
}

pub(crate) fn edr_receipt_signer_requires_enrollment(settings: &Settings) -> bool {
    settings.enrollment.enrolled || settings.nats.enabled || settings.control_api.enabled
}

pub(crate) async fn require_cloud_mode_enrolled_receipt_signer(
    state: &AgentApiState,
    label: &str,
) -> Result<(), (axum::http::StatusCode, String)> {
    let settings = state.settings.read().await.clone();
    if !edr_receipt_signer_requires_enrollment(&settings) {
        return Ok(());
    }
    require_enrolled_edr_receipt_signer_for_settings(state, &settings, label).await
}

pub(crate) async fn require_enrolled_edr_receipt_signer_for_settings(
    state: &AgentApiState,
    settings: &Settings,
    label: &str,
) -> Result<(), (axum::http::StatusCode, String)> {
    use axum::http::StatusCode;
    if !edr_receipt_signer_requires_enrollment(settings) {
        return Ok(());
    }
    let (signer_identity, signer_public_key) = {
        let ledger = state.edr_receipt_ledger.lock().await;
        (
            ledger.signer_identity.clone(),
            ledger.signer_public_key.clone(),
        )
    };
    let expected_identity = format!("agent-enrollment:{signer_public_key}");
    if signer_identity != expected_identity {
        return Err((
            StatusCode::CONFLICT,
            format!("{label} requires an enrolled EDR receipt signer in cloud/control mode"),
        ));
    }
    if let Some(key_hex) = crate::enrollment::load_enrollment_key_hex().map_err(internal_error)? {
        let enrollment_public_key = Keypair::from_hex(key_hex.trim())
            .map_err(|err| internal_error(anyhow::anyhow!("parse enrollment key: {err}")))?
            .public_key()
            .to_hex();
        if signer_public_key != enrollment_public_key {
            return Err((
                StatusCode::CONFLICT,
                format!("{label} signer does not match the enrolled agent key"),
            ));
        }
    }
    Ok(())
}

pub(crate) async fn require_cloud_mode_receipts_signed_by_current_signer(
    state: &AgentApiState,
    receipts: &[SignedReceipt],
    label: &str,
) -> Result<(), (axum::http::StatusCode, String)> {
    use axum::http::StatusCode;
    let settings = state.settings.read().await.clone();
    if !edr_receipt_signer_requires_enrollment(&settings) {
        return Ok(());
    }
    require_enrolled_edr_receipt_signer_for_settings(state, &settings, label).await?;
    let (signer_identity, signer_public_key) = {
        let ledger = state.edr_receipt_ledger.lock().await;
        (
            ledger.signer_identity.clone(),
            ledger.signer_public_key.clone(),
        )
    };
    for receipt in receipts {
        let receipt_id = receipt.receipt.receipt_id.as_deref().unwrap_or("<missing>");
        if receipt_endpoint_decision_str(receipt, &["signer", "signerIdentity"])
            != Some(signer_identity.as_str())
        {
            return Err((
                StatusCode::CONFLICT,
                format!("{label} contains receipt {receipt_id} from a non-current EDR signer"),
            ));
        }
        if receipt_endpoint_decision_str(receipt, &["signer", "signerPublicKey"])
            != Some(signer_public_key.as_str())
        {
            return Err((
                StatusCode::CONFLICT,
                format!("{label} contains receipt {receipt_id} from an untrusted EDR signer"),
            ));
        }
    }
    Ok(())
}

pub(crate) fn default_edr_receipt_ledger(
    require_enrolled_receipt_signer: bool,
) -> Result<EndpointReceiptLedger> {
    let path = default_edr_receipt_ledger_path();
    let ledger = if require_enrolled_receipt_signer {
        EndpointReceiptLedger::open_require_enrollment(&path)
    } else {
        EndpointReceiptLedger::open(&path)
    };
    ledger.with_context(|| format!("open durable endpoint receipt ledger {}", path.display()))
}

pub(crate) fn default_edr_honey_registry() -> Result<EndpointHoneyRegistry> {
    let path = default_edr_honey_registry_path();
    EndpointHoneyRegistry::open(&path)
        .with_context(|| format!("open durable endpoint honey registry {}", path.display()))
}

pub(crate) fn default_edr_evidence_bundle_store() -> Result<EndpointEvidenceBundleStore> {
    let root = default_edr_evidence_bundle_dir();
    EndpointEvidenceBundleStore::open(&root).with_context(|| {
        format!(
            "open durable endpoint evidence bundle store {}",
            root.display()
        )
    })
}

pub(crate) fn default_edr_response_execution_ledger() -> Result<EndpointResponseExecutionLedger> {
    let path = default_edr_response_execution_ledger_path();
    EndpointResponseExecutionLedger::open(&path).with_context(|| {
        format!(
            "open durable endpoint response execution ledger {}",
            path.display()
        )
    })
}

pub(crate) fn default_edr_response_acknowledgement_ledger(
) -> Result<EndpointResponseAcknowledgementLedger> {
    let path = default_edr_response_acknowledgement_ledger_path();
    EndpointResponseAcknowledgementLedger::open(&path).with_context(|| {
        format!(
            "open durable endpoint response acknowledgement ledger {}",
            path.display()
        )
    })
}

pub(crate) fn default_edr_control_ack_postback_retry_ledger(
) -> Result<EndpointControlAckPostbackRetryLedger> {
    let path = default_edr_control_ack_postback_retry_ledger_path();
    EndpointControlAckPostbackRetryLedger::open(&path).with_context(|| {
        format!(
            "open durable endpoint Control API acknowledgement retry queue {}",
            path.display()
        )
    })
}

pub(crate) fn default_edr_control_archive_upload_retry_ledger(
) -> Result<EndpointControlArchiveUploadRetryLedger> {
    let path = default_edr_control_archive_upload_retry_ledger_path();
    EndpointControlArchiveUploadRetryLedger::open(&path).with_context(|| {
        format!(
            "open durable endpoint Control API archive upload retry queue {}",
            path.display()
        )
    })
}

pub(crate) fn default_edr_control_receipt_upload_retry_ledger(
) -> Result<EndpointControlReceiptUploadRetryLedger> {
    let path = default_edr_control_receipt_upload_retry_ledger_path();
    EndpointControlReceiptUploadRetryLedger::open(&path).with_context(|| {
        format!(
            "open durable endpoint Control API receipt upload retry queue {}",
            path.display()
        )
    })
}

pub(crate) fn default_edr_fleet_hunt_event_outbox() -> Result<EndpointFleetHuntEventOutbox> {
    let path = default_edr_fleet_hunt_event_outbox_path();
    EndpointFleetHuntEventOutbox::open(&path).with_context(|| {
        format!(
            "open durable endpoint fleet hunt-event outbox {}",
            path.display()
        )
    })
}

pub(crate) fn default_edr_egress_restriction_ledger() -> Result<EndpointEgressRestrictionLedger> {
    let path = default_edr_egress_restriction_ledger_path();
    EndpointEgressRestrictionLedger::open(&path).with_context(|| {
        format!(
            "open durable endpoint egress restriction ledger {}",
            path.display()
        )
    })
}

pub(crate) fn default_edr_staged_detection_ledger() -> Result<EndpointStagedDetectionLedger> {
    let path = default_edr_staged_detection_ledger_path();
    EndpointStagedDetectionLedger::open(&path).with_context(|| {
        format!(
            "open durable endpoint staged detection ledger {}",
            path.display()
        )
    })
}

pub(crate) fn default_edr_policy_delta_store() -> Result<EndpointPolicyDeltaStore> {
    let root = default_edr_policy_delta_dir();
    EndpointPolicyDeltaStore::open(&root).with_context(|| {
        format!(
            "open durable endpoint policy delta store {}",
            root.display()
        )
    })
}
