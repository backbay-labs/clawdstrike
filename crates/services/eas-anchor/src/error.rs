//! Error types for the EAS anchor service.

use std::fmt;

/// Convenience alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur in the EAS anchor service.
#[derive(Debug)]
pub enum Error {
    /// Configuration error (invalid TOML, missing fields, etc.).
    Config(String),
    /// JSON/envelope parsing error.
    Parse(String),
    /// NATS connection or subscription error.
    Nats(String),
    /// EAS client / contract interaction error.
    Client(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config(msg) => write!(f, "config error: {msg}"),
            Error::Parse(msg) => write!(f, "parse error: {msg}"),
            Error::Nats(msg) => write!(f, "nats error: {msg}"),
            Error::Client(msg) => write!(f, "eas client error: {msg}"),
        }
    }
}

impl std::error::Error for Error {}
