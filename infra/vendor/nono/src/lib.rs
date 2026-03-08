//! nono - Capability-based sandboxing library
//!
//! This library provides OS-level sandboxing using Landlock (Linux) and
//! Seatbelt (macOS) for capability-based filesystem and network isolation.
//!
//! # Overview
//!
//! nono is a pure sandboxing primitive - it provides the mechanism for
//! OS-enforced isolation without imposing any security policy. Clients
//! (CLI tools, language bindings) define their own policies.
//!
//! # Platform Support
//!
//! - **Linux**: Uses Landlock LSM (kernel 5.13+)
//! - **macOS**: Uses Seatbelt sandbox
//! - **Other platforms**: Returns `UnsupportedPlatform` error

// Cross-platform modules (always available)
pub mod capability;
pub mod diagnostic;
pub mod error;
pub mod net_filter;
pub mod query;
pub mod state;

// Unix-only modules
#[cfg(unix)]
pub mod sandbox;
#[cfg(unix)]
pub mod supervisor;

// Cross-platform re-exports
pub use capability::{
    AccessMode, CapabilitySet, CapabilitySource, FsCapability, NetworkMode, SignalMode,
};
pub use diagnostic::{DenialReason, DenialRecord, DiagnosticFormatter, DiagnosticMode};
pub use error::{NonoError, Result};
pub use net_filter::{FilterResult, HostFilter};
pub use state::SandboxState;

// Unix-only re-exports
#[cfg(unix)]
pub use sandbox::{Sandbox, SupportInfo};
#[cfg(unix)]
pub use supervisor::{
    ApprovalBackend, ApprovalDecision, CapabilityRequest, NeverGrantChecker, SupervisorSocket,
};
