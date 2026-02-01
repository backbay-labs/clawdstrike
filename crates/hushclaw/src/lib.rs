//! Hushclaw - Security Guards and Policy Engine
//!
//! This crate provides security guards for AI agent execution:
//! - ForbiddenPathGuard: Blocks access to sensitive paths
//! - EgressAllowlistGuard: Controls network egress
//! - SecretLeakGuard: Detects potential secret exposure
//! - PatchIntegrityGuard: Validates patch safety
//! - McpToolGuard: Restricts MCP tool invocations
//!
//! Additionally, the IRM (Inline Reference Monitor) module provides runtime
//! interception for filesystem, network, and execution operations.
//!
//! Guards can be composed into rulesets and configured via YAML.

pub mod engine;
pub mod error;
pub mod guards;
pub mod irm;
pub mod policy;

pub use engine::HushEngine;
pub use error::{Error, Result};
pub use guards::{
    EgressAllowlistGuard, ForbiddenPathGuard, Guard, GuardContext, GuardResult, McpToolGuard,
    PatchIntegrityGuard, SecretLeakGuard, Severity,
};
pub use policy::{Policy, RuleSet};

// IRM exports
pub use irm::{
    Decision, EventType, ExecOperation, ExecutionIrm, FilesystemIrm, FsOperation, HostCall,
    HostCallMetadata, IrmEvent, IrmRouter, Monitor, NetOperation, NetworkIrm, Sandbox,
    SandboxConfig, SandboxStats,
};

/// Re-export core types
pub mod core {
    pub use hush_core::*;
}
