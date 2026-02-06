//! API key authentication for hushd

pub mod middleware;
pub mod store;
pub mod types;

pub use middleware::{require_auth, require_scope, scope_layer, AuthenticatedActor};
pub use store::{AuthError, AuthStore, SqliteAuthStore};
pub use types::{ApiKey, ApiKeyTier, Scope};
