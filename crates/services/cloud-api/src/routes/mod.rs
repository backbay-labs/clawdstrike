pub mod agents;
pub mod alerts;
pub mod billing;
pub mod compliance;
pub mod events;
pub mod health;
pub mod policies;
pub mod tenants;

use axum::{middleware, Router};

use crate::auth;
use crate::state::AppState;

/// Build the full application router.
pub fn router(state: AppState) -> Router {
    // Public routes (no auth required)
    let public = Router::new()
        .merge(health::router())
        .merge(billing::router());

    // Authenticated routes
    let authenticated = Router::new()
        .merge(tenants::router())
        .merge(agents::router())
        .merge(policies::router())
        .merge(events::router())
        .merge(alerts::router())
        .merge(compliance::router())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ));

    Router::new()
        .nest("/api/v1", authenticated)
        .nest("/api/v1", public)
        .with_state(state)
}
