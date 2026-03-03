//! Guest-side types that mirror the host-side ABI contract.

use serde::{Deserialize, Serialize};

/// Input envelope deserialized from the JSON the host writes to linear memory.
///
/// Matches `WasmGuardInputEnvelope` in the host runtime.
#[derive(Clone, Debug, Deserialize)]
pub struct GuardInput {
    /// Guard name (as declared in the plugin manifest).
    pub guard: String,
    /// The action type string (e.g. `"tool_call"`, `"file_access"`).
    #[serde(default)]
    pub action_type: Option<String>,
    /// The action payload — guard-specific data.
    pub payload: serde_json::Value,
    /// Per-guard configuration from the policy.
    #[serde(default)]
    pub config: serde_json::Value,
}

/// Output the guard sends back to the host via the `set_output` hostcall.
///
/// Matches `WasmGuardOutput` in the host runtime.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardOutput {
    /// Whether the action is allowed.
    pub allowed: bool,
    /// Optional guard name override.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guard: Option<String>,
    /// Severity string (e.g. `"info"`, `"warning"`, `"error"`, `"critical"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Human-readable explanation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Optional structured details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl GuardOutput {
    /// Create an allow output with default severity and message.
    pub fn allow() -> Self {
        Self {
            allowed: true,
            guard: None,
            severity: Some("info".to_string()),
            message: Some("Allowed".to_string()),
            details: None,
        }
    }

    /// Create an allow output with a custom message.
    pub fn allow_with_message(message: impl Into<String>) -> Self {
        Self {
            allowed: true,
            guard: None,
            severity: Some("info".to_string()),
            message: Some(message.into()),
            details: None,
        }
    }

    /// Create a deny output.
    pub fn deny(severity: Severity, message: impl Into<String>) -> Self {
        Self {
            allowed: false,
            guard: None,
            severity: Some(severity.as_str().to_string()),
            message: Some(message.into()),
            details: None,
        }
    }

    /// Create a deny output with structured details.
    pub fn deny_with_details(
        severity: Severity,
        message: impl Into<String>,
        details: serde_json::Value,
    ) -> Self {
        Self {
            allowed: false,
            guard: None,
            severity: Some(severity.as_str().to_string()),
            message: Some(message.into()),
            details: Some(details),
        }
    }

    /// Set the guard name on this output.
    pub fn with_guard(mut self, guard: impl Into<String>) -> Self {
        self.guard = Some(guard.into());
        self
    }

    /// Set additional details.
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

/// Convenience enum for building guard outputs.
pub enum Verdict {
    /// The action is allowed.
    Allow {
        /// Optional message.
        message: Option<String>,
    },
    /// The action is denied.
    Deny {
        /// Severity of the denial.
        severity: Severity,
        /// Explanation.
        message: String,
        /// Optional structured details.
        details: Option<serde_json::Value>,
    },
}

impl From<Verdict> for GuardOutput {
    fn from(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Allow { message } => Self {
                allowed: true,
                guard: None,
                severity: Some("info".to_string()),
                message: message.or_else(|| Some("Allowed".to_string())),
                details: None,
            },
            Verdict::Deny {
                severity,
                message,
                details,
            } => Self {
                allowed: false,
                guard: None,
                severity: Some(severity.as_str().to_string()),
                message: Some(message),
                details,
            },
        }
    }
}

/// Severity levels matching the host-side `Severity` enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational — logged but allowed.
    Info,
    /// Warning — logged, may be flagged.
    Warning,
    /// Error — action is blocked.
    Error,
    /// Critical — action is blocked, session may be terminated.
    Critical,
}

impl Severity {
    /// Return the wire-format string for this severity.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
}

/// Host capabilities that a guard can request at runtime.
///
/// Maps to the integer codes used by the `request_capability` hostcall:
/// - 0 = Network
/// - 1 = Subprocess
/// - 2 = FsRead
/// - 3 = FsWrite
/// - 4 = Secrets
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Capability {
    /// Network access.
    Network = 0,
    /// Subprocess spawning.
    Subprocess = 1,
    /// Filesystem read access.
    FsRead = 2,
    /// Filesystem write access.
    FsWrite = 3,
    /// Secrets access.
    Secrets = 4,
}
