//! Error types for hush-core operations

use thiserror::Error;

/// Errors that can occur during cryptographic operations
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid private key")]
    InvalidPrivateKey,

    #[error("Invalid hex encoding: {0}")]
    InvalidHex(String),

    #[error("Invalid hash length: expected {expected}, got {actual}")]
    InvalidHashLength { expected: usize, actual: usize },

    #[error("Merkle proof verification failed")]
    MerkleProofFailed,

    #[error("Empty tree: cannot compute root")]
    EmptyTree,

    #[error("Invalid proof: leaf index {index} out of bounds for tree with {leaves} leaves")]
    InvalidProofIndex { index: usize, leaves: usize },

    #[error("JSON serialization error: {0}")]
    JsonError(String),

    #[error("Receipt verification failed: {0}")]
    ReceiptVerificationFailed(String),

    #[error("Invalid receipt version: {version}")]
    InvalidReceiptVersion { version: String },

    #[error("Unsupported receipt version: {found} (supported: {supported})")]
    UnsupportedReceiptVersion { found: String, supported: String },
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::JsonError(e.to_string())
    }
}

/// Result type for hush-core operations
pub type Result<T> = std::result::Result<T, Error>;
