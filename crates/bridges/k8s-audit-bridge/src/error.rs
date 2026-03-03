//! Error types for the k8s-audit-bridge crate.

use thiserror::Error;

/// Errors that can occur during bridge operations.
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum Error {
    #[error("HTTP error: {0}")]
    Http(String),

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
        let http = Error::Http("bind failed".to_string());
        let nats = Error::Nats("publish failed".to_string());
        let config = Error::Config("invalid stream".to_string());
        let json = Error::from(serde_json::from_str::<serde_json::Value>("{").unwrap_err());

        assert!(http.to_string().contains("HTTP error"));
        assert!(nats.to_string().contains("NATS error"));
        assert!(config.to_string().contains("configuration error"));
        assert!(json.to_string().contains("serialization error"));
    }
}
