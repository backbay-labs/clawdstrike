//! Session lifecycle management for hushd integration.
//!
//! Manages a session with hushd that enables posture tracking and budget enforcement.

mod hushd_info;
mod manager;
mod state;

#[cfg(test)]
mod tests;

pub use manager::SessionManager;
pub use state::SessionState;
