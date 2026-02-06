use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid ID: {0}")]
    InvalidId(String),

    #[error("Identity already exists: {0}")]
    IdentityAlreadyExists(String),

    #[error("Invalid claims: {0}")]
    InvalidClaims(String),

    #[error("Signature verification failed")]
    InvalidSignature,

    #[error("Token is expired")]
    Expired,

    #[error("Token not yet valid")]
    NotYetValid,

    #[error("Token audience mismatch")]
    AudienceMismatch,

    #[error("Token subject mismatch")]
    SubjectMismatch,

    #[error("Token revoked")]
    Revoked,

    #[error("Delegation chain violation: {0}")]
    DelegationChainViolation(String),

    #[error("Replay detected")]
    Replay,

    #[error("Core error: {0}")]
    Core(#[from] hush_core::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Database error: {0}")]
    Database(String),
}

pub type Result<T> = std::result::Result<T, Error>;
