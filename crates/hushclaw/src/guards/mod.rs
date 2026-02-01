//! Security guards for AI agent execution
//!
//! Guards implement async checks that can allow, block, or log actions.

mod egress_allowlist;
mod forbidden_path;
mod mcp_tool;
mod patch_integrity;
mod secret_leak;

pub use egress_allowlist::{EgressAllowlistConfig, EgressAllowlistGuard};
pub use forbidden_path::{ForbiddenPathConfig, ForbiddenPathGuard};
pub use mcp_tool::{McpToolConfig, McpToolGuard};
pub use patch_integrity::{PatchIntegrityConfig, PatchIntegrityGuard};
pub use secret_leak::{SecretLeakConfig, SecretLeakGuard};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Severity level for violations
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational, logged but allowed
    Info,
    /// Warning, logged and may be flagged
    Warning,
    /// Error, action is blocked
    Error,
    /// Critical, action is blocked and session may be terminated
    Critical,
}

/// Result of a guard check
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardResult {
    /// Whether the action is allowed
    pub allowed: bool,
    /// Guard that produced this result
    pub guard: String,
    /// Severity of any violation
    pub severity: Severity,
    /// Human-readable message
    pub message: String,
    /// Optional details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl GuardResult {
    /// Create an allow result
    pub fn allow(guard: impl Into<String>) -> Self {
        Self {
            allowed: true,
            guard: guard.into(),
            severity: Severity::Info,
            message: "Allowed".to_string(),
            details: None,
        }
    }

    /// Create a block result
    pub fn block(guard: impl Into<String>, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            allowed: false,
            guard: guard.into(),
            severity,
            message: message.into(),
            details: None,
        }
    }

    /// Create a warning result (allowed but logged)
    pub fn warn(guard: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            allowed: true,
            guard: guard.into(),
            severity: Severity::Warning,
            message: message.into(),
            details: None,
        }
    }

    /// Add details to the result
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

/// Context passed to guards for evaluation
#[derive(Clone, Debug, Default)]
pub struct GuardContext {
    /// Current working directory
    pub cwd: Option<String>,
    /// Session/run identifier
    pub session_id: Option<String>,
    /// User/agent identifier
    pub agent_id: Option<String>,
    /// Additional context
    pub metadata: Option<serde_json::Value>,
}

impl GuardContext {
    /// Create a new context
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the working directory
    pub fn with_cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Set the session ID
    pub fn with_session_id(mut self, id: impl Into<String>) -> Self {
        self.session_id = Some(id.into());
        self
    }

    /// Set the agent ID
    pub fn with_agent_id(mut self, id: impl Into<String>) -> Self {
        self.agent_id = Some(id.into());
        self
    }
}

/// Action type for guard checks
#[derive(Clone, Debug)]
pub enum GuardAction<'a> {
    /// File system access (path)
    FileAccess(&'a str),
    /// File write (path, content)
    FileWrite(&'a str, &'a [u8]),
    /// Network egress (host, port)
    NetworkEgress(&'a str, u16),
    /// Shell command execution
    ShellCommand(&'a str),
    /// MCP tool invocation (tool_name, args)
    McpTool(&'a str, &'a serde_json::Value),
    /// Patch application (file, diff)
    Patch(&'a str, &'a str),
    /// Generic action with custom type
    Custom(&'a str, &'a serde_json::Value),
}

/// Trait for security guards
#[async_trait]
pub trait Guard: Send + Sync {
    /// Name of the guard
    fn name(&self) -> &str;

    /// Check if this guard handles the given action type
    fn handles(&self, action: &GuardAction<'_>) -> bool;

    /// Evaluate the action
    async fn check(&self, action: &GuardAction<'_>, context: &GuardContext) -> GuardResult;
}
