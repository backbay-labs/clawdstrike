use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid ID: {0}")]
    InvalidId(String),

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

    #[error("Replay detected")]
    Replay,

    #[error("Core error: {0}")]
    Core(#[from] hush_core::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
