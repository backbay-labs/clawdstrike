//! HTTP API for hushd daemon

pub mod audit;
pub mod check;
pub mod events;
pub mod health;
pub mod metrics;
pub mod policy;
pub mod shutdown;

use axum::{
    middleware,
    routing::{get, post, put},
    Router,
};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::auth::{require_auth, scope_layer, Scope};
use crate::rate_limit::rate_limit_middleware;
use crate::state::AppState;

pub use audit::{AuditQuery, AuditResponse, AuditStatsResponse};
pub use check::{CheckRequest, CheckResponse};
pub use health::HealthResponse;
pub use policy::{PolicyResponse, UpdatePolicyRequest, UpdatePolicyResponse};
pub use shutdown::ShutdownResponse;

/// Create the API router
pub fn create_router(state: AppState) -> Router {
    let cors_enabled = state.config.cors_enabled;
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Public routes - no auth required
    let public_routes = Router::new()
        .route("/health", get(health::health))
        .route("/metrics", get(metrics::metrics));

    // Check routes - require auth + check scope (when auth is enabled).
    let check_routes = Router::new()
        .route("/api/v1/check", post(check::check_action))
        .layer(middleware::from_fn(scope_layer(Scope::Check)))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    // Read routes - require auth + read scope (when auth is enabled).
    let read_routes = Router::new()
        .route("/api/v1/policy", get(policy::get_policy))
        .route("/api/v1/policy/bundle", get(policy::get_policy_bundle))
        .route("/api/v1/audit", get(audit::query_audit))
        .route("/api/v1/audit/stats", get(audit::audit_stats))
        .route("/api/v1/events", get(events::stream_events))
        .layer(middleware::from_fn(scope_layer(Scope::Read)))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    // Admin routes - require auth + admin scope
    let admin_routes = Router::new()
        .route("/api/v1/policy", put(policy::update_policy))
        .route("/api/v1/policy/bundle", put(policy::update_policy_bundle))
        .route("/api/v1/policy/reload", post(policy::reload_policy))
        .route("/api/v1/shutdown", post(shutdown::shutdown))
        .layer(middleware::from_fn(scope_layer(Scope::Admin)))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    // Note: Rate limiting is applied to all routes except /health (handled in middleware).
    // CORS is applied only if enabled in config.
    let app = Router::new()
        .merge(public_routes)
        .merge(check_routes)
        .merge(read_routes)
        .merge(admin_routes)
        .layer(middleware::from_fn_with_state(
            state.rate_limit.clone(),
            rate_limit_middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    if cors_enabled {
        app.layer(cors)
    } else {
        app
    }
}
