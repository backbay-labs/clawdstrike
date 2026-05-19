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
    EndpointControlAckPostbackRetry, EndpointControlAckPostbackRetryLedger,
    read_control_ack_postback_retry_ledger,
};
pub(crate) use control_archive_upload_retry::{
    EndpointControlArchiveUploadRetry, EndpointControlArchiveUploadRetryLedger,
    read_control_archive_upload_retry_ledger,
};
pub(crate) use control_receipt_upload_retry::{
    EndpointControlReceiptUploadRetry, EndpointControlReceiptUploadRetryLedger,
    read_control_receipt_upload_retry_ledger,
};
pub(crate) use egress_restriction::{
    EndpointEgressRestriction, EndpointEgressRestrictionLedger,
    NetworkExtensionEgressPolicySnapshot, write_network_extension_egress_policy_snapshot,
    read_egress_restriction_ledger,
};
pub(crate) use evidence_bundle::EndpointEvidenceBundleStore;
pub(crate) use fleet_hunt_event_outbox::{
    EndpointFleetHuntEventOutbox, EndpointFleetHuntEventOutboxEntry,
    read_fleet_hunt_event_outbox,
};
pub(crate) use honey_registry::EndpointHoneyRegistry;
pub(crate) use policy_delta::EndpointPolicyDeltaStore;
pub(crate) use receipt::{
    DeceptionCleanupReceiptSigningInput, DeceptionRotationReceiptSigningInput,
    EdrPolicyDeltaReceiptSigningInput, EndpointReceiptLedger,
    ResponseExecutionReceiptSigningInput,
};
pub(crate) use response_acknowledgement::EndpointResponseAcknowledgementLedger;
pub(crate) use response_execution::EndpointResponseExecutionLedger;
pub(crate) use staged_detection::EndpointStagedDetectionLedger;
