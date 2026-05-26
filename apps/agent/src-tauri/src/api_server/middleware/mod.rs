//! Axum middleware for authentication, rate limiting, and UI cookie attachment.

mod auth;
mod rate_limit;

pub(crate) use auth::*;
pub(crate) use rate_limit::*;
