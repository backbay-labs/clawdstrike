//! Pure decision-making core (no I/O, no serde, no async).
//!
//! The existing `engine.rs` and `policy.rs` delegate to these functions,
//! keeping the original public API unchanged.

pub use hush_core::{
    canonical, canonicalize_json, duration, error, hashing, keccak256, keccak256_hex, merkle,
    parse_human_duration, prelude, receipt, sha256, sha256_hex, signing, Error, Hash, Keypair,
    MerkleProof, MerkleTree, Provenance, PublicKey, Receipt, Result, Signature, SignedReceipt,
    Signer, Verdict,
};
#[cfg(not(target_arch = "wasm32"))]
pub use hush_core::{tpm, TpmSealedBlob, TpmSealedSeedSigner};

pub mod aggregate;
pub mod cycle;
pub mod merge;
pub mod verdict;

pub use aggregate::{aggregate_index, aggregate_overall};
pub use cycle::{check_extends_cycle, CycleCheckResult, MAX_POLICY_EXTENDS_DEPTH};
pub use merge::{
    child_overrides, child_overrides_option, child_overrides_str, merge_keyed_vec,
    merge_keyed_vec_pure, CoreMergeStrategy,
};
pub use verdict::{severity_ord, CoreSeverity, CoreVerdict};
