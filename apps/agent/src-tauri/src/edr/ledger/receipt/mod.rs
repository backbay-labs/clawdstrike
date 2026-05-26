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

mod compaction;
mod signing_action;
mod signing_observation;
mod storage;

#[allow(unused_imports)]
pub(crate) use compaction::{endpoint_receipt_compaction_manifest_path, ReceiptCompactionReport};

use std::path::{Path as FsPath, PathBuf};

use anyhow::Result;
use clawdstrike_policy_event::edr::{
    CausalGraph, DeceptionCleanupReport, DeceptionPlan, DeceptionRotationReport,
    EndpointDecisionActor, EndpointPolicySnapshot, EndpointReceiptEvidence,
    EndpointResponseExecutionReport, EndpointSensorState,
};
use hush_core::Keypair;

use crate::api_server::{
    load_or_create_edr_receipt_signer_with_requirement, next_receipt_sequence,
    EdrPolicyDeltaArtifact,
};
use crate::settings::Settings;

pub(crate) struct EndpointReceiptLedger {
    pub(crate) path: Option<PathBuf>,
    pub(crate) next_sequence: u64,
    pub(crate) keypair: Keypair,
    pub(crate) signer_identity: String,
    pub(crate) signer_public_key: String,
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

pub(crate) struct PolicyDecisionReceiptSigningInput<'a> {
    pub(crate) actor: EndpointDecisionActor,
    pub(crate) policy: EndpointPolicySnapshot,
    pub(crate) sensor_state: EndpointSensorState,
    pub(crate) observation: &'a clawdstrike_policy_event::edr::EndpointObservation,
    pub(crate) graph: &'a CausalGraph,
    pub(crate) action_type: &'a str,
    pub(crate) target: &'a str,
    pub(crate) decision: &'a crate::policy::PolicyCheckOutput,
}

pub(crate) struct EdrPolicyDeltaReceiptSigningInput<'a> {
    pub(crate) artifact: &'a EdrPolicyDeltaArtifact,
    pub(crate) artifact_hash: &'a str,
    pub(crate) operation: &'a str,
    pub(crate) actor: Option<EndpointDecisionActor>,
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
        Self::open_with_signer_requirement(path, false)
    }

    pub(crate) fn open_require_enrollment(path: impl Into<PathBuf>) -> Result<Self> {
        Self::open_with_signer_requirement(path, true)
    }

    fn open_with_signer_requirement(
        path: impl Into<PathBuf>,
        require_enrolled_signer: bool,
    ) -> Result<Self> {
        let path = path.into();
        let next_sequence = next_receipt_sequence(&path)?;
        let (keypair, signer_identity) =
            load_or_create_edr_receipt_signer_with_requirement(require_enrolled_signer)?;
        let signer_public_key = keypair.public_key().to_hex();
        Ok(Self {
            path: Some(path),
            next_sequence,
            keypair,
            signer_identity,
            signer_public_key,
        })
    }

    #[cfg(test)]
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
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use clawdstrike_policy_event::edr::{
        EndpointDecisionReceipt, EndpointEvent, EndpointObservation, EndpointProcess,
        EndpointTelemetryPrivacyMode, EndpointTelemetryPrivacyReceiptInput,
        EndpointTelemetryPrivacyReport,
    };
    use hush_core::SignedReceipt;
    use std::fs;

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
        let mut receipt =
            EndpointDecisionReceipt::for_telemetry_privacy(EndpointTelemetryPrivacyReceiptInput {
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
            });
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
        let index_path = crate::api_server::endpoint_receipt_index_path(&path);

        assert_private_mode(&path);
        assert_private_mode(&index_path);

        let _ = fs::remove_file(path);
        let _ = fs::remove_file(index_path);
    }
}
