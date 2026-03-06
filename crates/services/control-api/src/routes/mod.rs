pub mod agents;
pub mod alerts;
pub mod approvals;
pub mod billing;
pub mod cases;
pub mod compliance;
pub mod console;
pub mod delegation_graph;
pub mod events;
pub mod health;
pub mod hunt;
pub mod policies;
pub mod response_actions;
pub mod tenants;

use axum::{middleware, Router};

use crate::auth;
use crate::state::AppState;

/// Build the full application router.
pub fn router(state: AppState) -> Router {
    // Public routes (no auth required)
    let public = Router::new()
        .merge(health::router())
        .merge(billing::router())
        .merge(agents::enrollment_router());

    // Authenticated routes
    let authenticated = Router::new()
        .merge(tenants::router())
        .merge(agents::router())
        .merge(approvals::router())
        .merge(policies::router())
        .merge(events::router())
        .merge(console::router())
        .merge(alerts::router())
        .merge(compliance::router())
        .merge(hunt::router())
        .merge(response_actions::router())
        .merge(cases::router())
        .merge(delegation_graph::router())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ));

    Router::new()
        .nest("/api/v1", authenticated)
        .nest("/api/v1", public)
        .with_state(state)
}
