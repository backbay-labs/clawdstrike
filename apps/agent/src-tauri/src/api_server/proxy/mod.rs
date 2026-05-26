//! Daemon HTTP proxy handlers and helpers.
//!
//! These handlers forward authenticated requests from the agent's local API
//! to the hushd daemon, stripping the agent auth token and applying the
//! daemon API key when present.

mod builder;
mod events;
mod get;
mod mutation;

pub(crate) use builder::*;
pub(crate) use events::*;
pub(crate) use get::*;
pub(crate) use mutation::*;
