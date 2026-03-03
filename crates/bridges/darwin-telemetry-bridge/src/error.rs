//! Error types for the darwin-telemetry-bridge crate.

use thiserror::Error;

/// Errors that can occur during bridge operations.
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("process collector error: {0}")]
    Process(String),

    #[error("FSEvents error: {0}")]
    FsEvents(String),

    #[error("unified log error: {0}")]
    UnifiedLog(String),

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

    #[error("channel send error: {0}")]
    Channel(String),
}

/// Result type for bridge operations.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn error_variants_display() {
        let io = Error::from(std::io::Error::other("read"));
        let process = Error::Process("collector failed".to_string());
        let fs = Error::FsEvents("stream failed".to_string());
        let unified_log = Error::UnifiedLog("parse failed".to_string());
        let nats = Error::Nats("disconnected".to_string());
        let channel = Error::Channel("closed".to_string());

        assert!(io.to_string().contains("I/O error"));
        assert!(process.to_string().contains("process collector error"));
        assert!(fs.to_string().contains("FSEvents error"));
        assert!(unified_log.to_string().contains("unified log error"));
        assert!(nats.to_string().contains("NATS error"));
        assert!(channel.to_string().contains("channel send error"));
    }
}
