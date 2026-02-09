//! Error types for hush-proxy

use thiserror::Error;

/// Errors that can occur during proxy operations
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum Error {
    #[error("DNS parsing error: {0}")]
    DnsParseError(String),

    #[error("SNI parsing error: {0}")]
    SniParseError(String),

    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Result type for hush-proxy operations
pub type Result<T> = std::result::Result<T, Error>;
