//! Per-action approval mechanism for the desktop agent.
//!
//! When a pre-flight guard denies a non-critical action, the adapter can submit
//! an approval request. The agent queues it, surfaces it via OS notification and
//! tray badge, and the user resolves it. Unresolved requests expire after a
//! configurable TTL (default 60s) and are treated as denied.

mod queue;
mod types;

pub use queue::ApprovalQueue;
#[allow(unused_imports)]
pub use types::ApprovalRequest;
pub use types::{
    ApprovalError, ApprovalEvent, ApprovalRequestInput, ApprovalResolution, ApprovalResolveInput,
    ApprovalStatus, ApprovalStatusResponse,
};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
