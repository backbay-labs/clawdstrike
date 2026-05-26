//! Event streaming from hushd daemon.
//!
//! Uses SSE as the primary transport and falls back to audit polling when SSE is unavailable.

mod dedupe;
mod stream;
mod types;

#[cfg(test)]
mod tests;

pub use stream::EventManager;
pub use types::{DaemonEvent, PolicyEvent};
