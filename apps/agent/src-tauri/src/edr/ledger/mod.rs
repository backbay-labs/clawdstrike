//! Durable JSONL-backed ledgers for the endpoint decision engine.
//!
//! Each ledger is an append-only persistence layer with monotonic
//! sequence numbers (where applicable) and content hashes. Receipts are
//! Ed25519-signed over canonical JSON before being appended. Ledgers do
//! not reference one another; the `AgentApiState` composes them via
//! `Arc<Mutex<_>>`.

pub(crate) mod control_ack_postback_retry;
pub(crate) mod control_archive_upload_retry;
pub(crate) mod control_receipt_upload_retry;
pub(crate) mod egress_restriction;
pub(crate) mod evidence_bundle;
pub(crate) mod fleet_hunt_event_outbox;
pub(crate) mod honey_registry;
pub(crate) mod policy_delta;
pub(crate) mod receipt;
pub(crate) mod response_acknowledgement;
pub(crate) mod response_execution;
pub(crate) mod staged_detection;

pub(crate) use control_ack_postback_retry::{
    read_control_ack_postback_retry_ledger, EndpointControlAckPostbackRetry,
    EndpointControlAckPostbackRetryLedger,
};
pub(crate) use control_archive_upload_retry::{
    read_control_archive_upload_retry_ledger, EndpointControlArchiveUploadRetry,
    EndpointControlArchiveUploadRetryLedger,
};
pub(crate) use control_receipt_upload_retry::{
    read_control_receipt_upload_retry_ledger, EndpointControlReceiptUploadRetry,
    EndpointControlReceiptUploadRetryLedger,
};
pub(crate) use egress_restriction::{
    read_egress_restriction_ledger, write_network_extension_egress_policy_snapshot,
    EndpointEgressRestriction, EndpointEgressRestrictionLedger,
    NetworkExtensionEgressPolicySnapshot,
};
pub(crate) use evidence_bundle::EndpointEvidenceBundleStore;
pub(crate) use fleet_hunt_event_outbox::{
    read_fleet_hunt_event_outbox, EndpointFleetHuntEventOutbox, EndpointFleetHuntEventOutboxEntry,
};
pub(crate) use honey_registry::EndpointHoneyRegistry;
pub(crate) use policy_delta::EndpointPolicyDeltaStore;
pub(crate) use receipt::{
    DeceptionCleanupReceiptSigningInput, DeceptionRotationReceiptSigningInput,
    EdrPolicyDeltaReceiptSigningInput, EndpointReceiptLedger, ResponseExecutionReceiptSigningInput,
};
pub(crate) use response_acknowledgement::EndpointResponseAcknowledgementLedger;
pub(crate) use response_execution::EndpointResponseExecutionLedger;
pub(crate) use staged_detection::EndpointStagedDetectionLedger;

use std::fs::{File, OpenOptions};
use std::path::Path;

use anyhow::{Context, Result};

pub(super) fn open_private_append(path: &Path, target: &str) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    apply_private_create_mode(&mut options);
    let file = options
        .open(path)
        .with_context(|| format!("open {target} {}", path.display()))?;
    enforce_private_file_mode(path, target)?;
    Ok(file)
}

pub(super) fn open_private_truncate(path: &Path, target: &str) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);
    apply_private_create_mode(&mut options);
    let file = options
        .open(path)
        .with_context(|| format!("open {target} {}", path.display()))?;
    enforce_private_file_mode(path, target)?;
    Ok(file)
}

#[cfg(unix)]
fn apply_private_create_mode(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.mode(0o600);
}

#[cfg(not(unix))]
fn apply_private_create_mode(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn enforce_private_file_mode(path: &Path, target: &str) -> Result<()> {
    crate::settings::enforce_private_mode(path, target)
}

#[cfg(not(unix))]
fn enforce_private_file_mode(_path: &Path, _target: &str) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn temp_ledger_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "clawdstrike-private-ledger-{name}-{}",
            uuid::Uuid::new_v4()
        ))
    }

    #[cfg(unix)]
    fn assert_private_mode(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(path)
            .unwrap_or_else(|err| panic!("stat {}: {err}", path.display()))
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "unexpected mode for {}", path.display());
    }

    #[test]
    fn private_append_creates_private_file() {
        let path = temp_ledger_path("append");
        {
            let mut file = open_private_append(&path, "test ledger")
                .unwrap_or_else(|err| panic!("open append ledger: {err}"));
            file.write_all(b"{}\n")
                .unwrap_or_else(|err| panic!("write append ledger: {err}"));
        }

        #[cfg(unix)]
        assert_private_mode(&path);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn private_truncate_corrects_existing_file_mode() {
        let path = temp_ledger_path("truncate");
        std::fs::write(&path, b"stale\n").unwrap_or_else(|err| panic!("seed ledger: {err}"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
                .unwrap_or_else(|err| panic!("chmod seeded ledger: {err}"));
        }

        {
            let mut file = open_private_truncate(&path, "test ledger")
                .unwrap_or_else(|err| panic!("open truncate ledger: {err}"));
            file.write_all(b"fresh\n")
                .unwrap_or_else(|err| panic!("write truncate ledger: {err}"));
        }

        #[cfg(unix)]
        assert_private_mode(&path);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read ledger: {err}")),
            "fresh\n"
        );
        let _ = std::fs::remove_file(path);
    }
}
