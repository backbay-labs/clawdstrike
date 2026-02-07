#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

//! # spine
//!
//! Aegis Spine protocol adapted for ClawdStrike.
//!
//! Provides:
//! - Signed envelope creation, hashing, and verification
//! - Checkpoint statements and witness co-signatures
//! - Trust bundles (allowlists + quorum)
//! - Hash normalization utilities
//! - NATS connection and JetStream helpers
//!
//! All cryptographic operations delegate to [`hush_core`].

pub mod checkpoint;
pub mod envelope;
pub mod error;
pub mod hash;
pub mod nats_transport;
pub mod trust;

pub use checkpoint::{
    checkpoint_hash, checkpoint_statement, checkpoint_witness_message, sign_checkpoint_statement,
    verify_witness_signature, CHECKPOINT_STATEMENT_SCHEMA_V1,
};
pub use envelope::{
    build_signed_envelope, compute_envelope_hash, compute_envelope_hash_hex,
    envelope_signing_bytes, extract_envelope_hash, issuer_from_keypair, now_rfc3339,
    parse_issuer_pubkey_hex, sign_envelope, verify_envelope, ENVELOPE_SCHEMA_V1,
};
pub use error::{Error, Result};
pub use hash::{normalize_hash_hex, policy_index_key, receipt_verification_prefix};
pub use trust::TrustBundle;

/// Normalize a hex seed string by trimming whitespace and stripping an optional `0x` prefix.
pub fn normalize_seed_hex(seed: &str) -> String {
    let trimmed = seed.trim();
    trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed)
        .to_string()
}
