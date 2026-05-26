//! Canonical PolicyEvent types, synthesis, simulation, bridge, and OCSF converters.
//!
//! This crate extracts the pure logic from `hush-cli` and `hushd` into a
//! reusable library. It provides:
//!
//! - [`event`] - PolicyEvent types, mapping, and validation
//! - [`stream`] - JSONL read/write helpers
//! - [`synth`] - Policy synthesis from observed events
//! - [`simulate`] - Replay events against a policy
//! - [`bridge`] - PolicyEvent to TimelineEvent conversion
//! - [`edr`] - endpoint detection, deception, and causal graph primitives
//! - [`ocsf`] - PolicyEvent to OCSF conversion
//! - [`facade`] - JSON-in/JSON-out facade for cross-language bindings
//! - [`wire`] - Wire-format request/response DTOs over EDR types

#[cfg(feature = "timeline")]
pub mod bridge;
mod decision;
pub mod edr;
pub mod event;
pub mod facade;
pub mod ocsf;
#[cfg(feature = "simulate")]
pub mod simulate;
pub mod stream;
pub mod synth;
pub mod wire;

pub use event::*;
#[cfg(feature = "simulate")]
pub use facade::SimulateResult;
pub use facade::{PolicyLabHandle, SynthResult};
