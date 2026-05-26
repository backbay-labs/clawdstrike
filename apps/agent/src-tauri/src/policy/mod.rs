//! Shared policy-check gate for hook/API/MCP paths.

mod audit;
mod evaluate;
mod types;

pub use evaluate::evaluate_policy_check;
pub use types::{PolicyCheckInput, PolicyCheckOutput};

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default
)]
mod tests;
