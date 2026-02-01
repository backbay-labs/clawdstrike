//! API key authentication for hushd

pub mod store;
pub mod types;

pub use store::{AuthError, AuthStore};
pub use types::{ApiKey, Scope};
