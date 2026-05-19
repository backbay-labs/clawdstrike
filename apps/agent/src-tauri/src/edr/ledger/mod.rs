//! Durable JSONL-backed ledgers for the endpoint decision engine.
//!
//! Each ledger is an append-only persistence layer with monotonic
//! sequence numbers (where applicable) and content hashes. Receipts are
//! Ed25519-signed over canonical JSON before being appended. Ledgers do
//! not reference one another; the `AgentApiState` composes them via
//! `Arc<Mutex<_>>`.

pub(crate) mod staged_detection;

pub(crate) use staged_detection::EndpointStagedDetectionLedger;
