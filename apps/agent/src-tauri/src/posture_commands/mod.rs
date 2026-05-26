//! NATS request-based posture command handler.
//!
//! Subscribes to a tenant/agent-scoped command subject and processes
//! remote management commands (set_posture, kill_switch, request_policy_reload).

mod handler;
mod signing;
mod types;

pub use handler::PostureCommandHandler;
#[allow(unused_imports)]
pub use types::PostureCommand;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
