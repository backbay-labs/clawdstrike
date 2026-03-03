//! Convenience re-exports for guard authors.
//!
//! ```ignore
//! use clawdstrike_guard_sdk::prelude::*;
//! ```

pub use crate::host;
pub use crate::types::{Capability, GuardInput, GuardOutput, Severity, Verdict};
pub use crate::Guard;
pub use clawdstrike_guard_sdk_macros::clawdstrike_guard;

// Re-export serde_json::json! so guard authors can construct details without
// adding serde_json as a direct dependency.
pub use serde_json::json;
