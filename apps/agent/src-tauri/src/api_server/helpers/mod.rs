//! Cross-cutting EDR helper functions used by the route handlers.
//!
//! Split by feature area:
//! - `graph_slice` — graph root resolution + slice export + evidence builders + bounded validators
//! - `detection_candidate` — staged-detection candidate builders and promotion-readiness checks
//! - `policy_replay` — current-policy replay report builder
//! - `deception` — honey-artifact deception plan validation and cleanup
//! - `attribution` — response-execution record attribution hydration
//! - `findings` — recent-findings ring buffer + size validators

mod attribution;
mod deception;
mod detection_candidate;
mod findings;
mod graph_slice;
mod policy_replay;

pub(crate) use attribution::*;
pub(crate) use deception::*;
pub(crate) use detection_candidate::*;
pub(crate) use findings::*;
pub(crate) use graph_slice::*;
pub(crate) use policy_replay::*;
