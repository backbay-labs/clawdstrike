//! HTTP API for hushd daemon

pub mod audit;
pub mod check;
pub mod events;
pub mod health;
pub mod policy;

use axum::{
    middleware,
    routing::{get, post, put},
    Router,
};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::auth::{require_auth, scope_layer, Scope};
use crate::state::AppState;

pub use audit::{AuditQuery, AuditResponse, AuditStatsResponse};
pub use check::{CheckRequest, CheckResponse};
pub use health::HealthResponse;
pub use policy::{PolicyResponse, UpdatePolicyRequest, UpdatePolicyResponse};

/// Create the API router
pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Public routes - no auth required
    let public_routes = Router::new().route("/health", get(health::health));

    // Routes requiring authentication with check or read scope
    let authenticated_routes = Router::new()
        .route("/api/v1/check", post(check::check_action))
        .route("/api/v1/policy", get(policy::get_policy))
        .route("/api/v1/audit", get(audit::query_audit))
        .route("/api/v1/audit/stats", get(audit::audit_stats))
        .route("/api/v1/events", get(events::stream_events))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    // Admin routes - require auth + admin scope
    let admin_routes = Router::new()
        .route("/api/v1/policy", put(policy::update_policy))
        .route("/api/v1/policy/reload", post(policy::reload_policy))
        .layer(middleware::from_fn(scope_layer(Scope::Admin)))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    Router::new()
        .merge(public_routes)
        .merge(authenticated_routes)
        .merge(admin_routes)
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}
