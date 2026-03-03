//! Error types for the auditd-bridge crate.

use thiserror::Error;

/// Errors that can occur during bridge operations.
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("NATS error: {0}")]
    Nats(String),

    #[error("spine error: {0}")]
    Spine(#[from] spine::Error),

    #[error("signing error: {0}")]
    Signing(#[from] hush_core::Error),

    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("configuration error: {0}")]
    Config(String),
}

/// Result type for bridge operations.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn error_variants_display() {
        let io = Error::from(std::io::Error::other("disk"));
        let parse = Error::Parse("bad line".to_string());
        let nats = Error::Nats("disconnected".to_string());
        let config = Error::Config("missing key".to_string());

        assert!(io.to_string().contains("I/O error"));
        assert!(parse.to_string().contains("parse error"));
        assert!(nats.to_string().contains("NATS error"));
        assert!(config.to_string().contains("configuration error"));
    }
}
