//! NATS response-action command handler.
//!
//! The Control API publishes canonical `response_action_v1` envelopes on
//! tenant-scoped response command subjects. This module subscribes,
//! validates each signed envelope, executes the endpoint policy rule-diff
//! validation action locally, and posts the resulting raw acknowledgement
//! payload back to Control API for proposal collection.

mod control_ack;
mod dto;
mod handler;
mod policy_rule_diff;
mod validate;

pub use handler::ResponseActionCommandHandler;

#[cfg(test)]
mod tests;
