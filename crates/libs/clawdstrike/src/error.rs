//! Error types for clawdstrike

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// A single policy validation error with a stable field path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyFieldError {
    pub path: String,
    pub message: String,
}

impl PolicyFieldError {
    pub fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

/// A collection of validation errors for a single policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyValidationError {
    pub errors: Vec<PolicyFieldError>,
}

impl PolicyValidationError {
    pub fn new(errors: Vec<PolicyFieldError>) -> Self {
        Self { errors }
    }

    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }
}

impl fmt::Display for PolicyValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.errors.is_empty() {
            return write!(f, "Policy validation failed (no details)");
        }

        writeln!(
            f,
            "Policy validation failed with {} error(s):",
            self.errors.len()
        )?;
        for err in &self.errors {
            writeln!(f, "- {}: {}", err.path, err.message)?;
        }
        Ok(())
    }
}

impl std::error::Error for PolicyValidationError {}

/// Errors that can occur during guard operations
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Guard check failed: {0}")]
    GuardFailed(String),

    #[error("Policy violation: {guard} - {message}")]
    PolicyViolation { guard: String, message: String },

    #[error("Invalid policy version: {version}")]
    InvalidPolicyVersion { version: String },

    #[error("Unsupported policy version: found {found}, supported {supported}")]
    UnsupportedPolicyVersion { found: String, supported: String },

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error(transparent)]
    PolicyValidation(#[from] PolicyValidationError),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("YAML error: {0}")]
    YamlError(#[from] serde_yaml::Error),

    #[error("Regex error: {0}")]
    RegexError(#[from] regex::Error),

    #[error("Core error: {0}")]
    CoreError(#[from] hush_core::Error),

    #[error("Spine error: {0}")]
    SpineError(String),
}

impl From<spine::Error> for Error {
    fn from(e: spine::Error) -> Self {
        Error::SpineError(e.to_string())
    }
}

/// Result type for clawdstrike operations
pub type Result<T> = std::result::Result<T, Error>;
