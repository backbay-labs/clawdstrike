#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

//! # hush-core
//!
//! Cryptographic primitives for the hushclaw attestation system.
//!
//! This crate provides:
//! - Ed25519 signing and verification
//! - SHA-256 and Keccak-256 hashing
//! - Merkle tree construction and proof verification
//! - Canonical JSON (RFC 8785)
//! - Receipt types and signing
//!
//! ## Quick Start
//!
//! ```rust
//! use hush_core::{sha256, keccak256, Keypair};
//!
//! // Hash some data
//! let hash = sha256(b"hello world");
//! assert_eq!(hash.as_bytes().len(), 32);
//!
//! // Keccak-256 (Ethereum-compatible)
//! let eth_hash = keccak256(b"hello world");
//! assert_eq!(eth_hash.as_bytes().len(), 32);
//!
//! // Sign and verify
//! let keypair = Keypair::generate();
//! let message = b"important message";
//! let signature = keypair.sign(message);
//! assert!(keypair.public_key().verify(message, &signature));
//! ```
//!
//! ## Merkle Trees
//!
//! ```rust
//! use hush_core::MerkleTree;
//!
//! let leaves = vec![b"leaf1".to_vec(), b"leaf2".to_vec(), b"leaf3".to_vec()];
//! let tree = MerkleTree::from_leaves(&leaves).unwrap();
//!
//! // Generate and verify inclusion proof
//! let proof = tree.inclusion_proof(1).unwrap();
//! assert!(proof.verify(&leaves[1], &tree.root()));
//! ```

pub mod canonical;
pub mod error;
pub mod hashing;
pub mod merkle;
pub mod receipt;
pub mod signing;

pub use canonical::canonicalize as canonicalize_json;
pub use error::{Error, Result};
pub use hashing::{keccak256, keccak256_hex, sha256, sha256_hex, Hash};
pub use merkle::{MerkleProof, MerkleTree};
pub use receipt::{Provenance, Receipt, SignedReceipt, Verdict};
pub use signing::{Keypair, PublicKey, Signature};

/// Commonly used types
pub mod prelude {
    pub use crate::{
        keccak256, sha256, Error, Hash, Keypair, MerkleProof, MerkleTree, PublicKey, Receipt,
        Result, Signature, SignedReceipt,
    };
}
