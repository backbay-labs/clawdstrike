//! Error types for the spine crate.

use thiserror::Error;

/// Errors that can occur during spine operations.
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid issuer string: {0}")]
    InvalidIssuer(String),

    #[error("missing required field: {0}")]
    MissingField(&'static str),

    #[error("invalid witness signature")]
    InvalidWitnessSignature,

    #[error("invalid trust bundle: {0}")]
    InvalidTrustBundle(String),

    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(String),

    #[error("NATS error: {0}")]
    Nats(String),

    #[error("IO error: {0}")]
    Io(String),

    #[error("JSON error: {0}")]
    Json(String),

    #[error(transparent)]
    Crypto(#[from] hush_core::Error),
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e.to_string())
    }
}

/// Result type for spine operations.
pub type Result<T> = std::result::Result<T, Error>;
