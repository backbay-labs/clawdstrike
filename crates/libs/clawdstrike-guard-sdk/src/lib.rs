//! Guest-side SDK for writing clawdstrike WASM guard plugins.
//!
//! Guard authors depend on this crate to implement security guards that compile
//! to `wasm32-unknown-unknown` and run inside the clawdstrike plugin sandbox.
//!
//! # Quick start
//!
//! ```ignore
//! use clawdstrike_guard_sdk::prelude::*;
//!
//! #[clawdstrike_guard]
//! #[derive(Default)]
//! struct MyGuard;
//!
//! impl Guard for MyGuard {
//!     fn name(&self) -> &str { "my-guard" }
//!     fn handles(&self, action_type: &str) -> bool { true }
//!     fn check(&self, input: GuardInput) -> GuardOutput {
//!         GuardOutput::allow()
//!     }
//! }
//! ```

mod types;

pub mod host;
pub mod prelude;

pub use clawdstrike_guard_sdk_macros::clawdstrike_guard;
pub use serde_json;
pub use types::{Capability, GuardInput, GuardOutput, Severity, Verdict};

/// Trait that guest-side guards must implement.
///
/// This mirrors the host-side `Guard` trait but is synchronous and operates on
/// the guest-side types ([`GuardInput`] / [`GuardOutput`]).
pub trait Guard {
    /// A unique name for this guard (e.g. `"acme.deny-all"`).
    fn name(&self) -> &str;

    /// Return `true` if this guard should evaluate the given action type.
    fn handles(&self, action_type: &str) -> bool;

    /// Evaluate the action described by `input` and return a verdict.
    fn check(&self, input: GuardInput) -> GuardOutput;
}
