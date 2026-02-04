//! HTTP API for hushd daemon

pub mod audit;
pub mod check;
pub mod eval;
pub mod events;
pub mod health;
pub mod me;
pub mod metrics;
pub mod policy;
pub mod policy_scoping;
pub mod saml;
pub mod session;
pub mod shutdown;
pub mod webhooks;

use axum::{
    middleware,
    routing::{delete, get, patch, post, put},
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
pub use me::MeResponse;
pub use metrics as metrics_api;
pub use policy::{PolicyResponse, UpdatePolicyRequest, UpdatePolicyResponse};
pub use policy_scoping::{
    CreateAssignmentRequest, CreateScopedPolicyRequest, ListAssignmentsResponse,
    ListScopedPoliciesResponse, ResolvePolicyResponse, UpdateScopedPolicyRequest,
};
pub use saml::{SamlExchangeRequest, SamlExchangeResponse};
pub use session::{CreateSessionResponse, GetSessionResponse, TerminateSessionResponse};
pub use shutdown::ShutdownResponse;

/// Create the API router
pub fn create_router(state: AppState) -> Router {
    let cors_enabled = state.config.cors_enabled;
    let metrics = state.metrics.clone();
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Public routes - no auth required
    let public_routes = Router::new()
        .route("/health", get(health::health))
        .route("/api/v1/webhooks/okta", post(webhooks::okta_webhook))
        .route("/api/v1/webhooks/auth0", post(webhooks::auth0_webhook));

    // Check routes - require auth + check scope (when auth is enabled).
    let check_routes = Router::new()
        .route("/api/v1/check", post(check::check_action))
        .route("/api/v1/eval", post(eval::eval_policy_event))
        .route("/api/v1/me", get(me::me))
        .route("/api/v1/session", post(session::create_session))
        .route("/api/v1/auth/saml", post(saml::exchange_saml))
        .layer(middleware::from_fn(scope_layer(Scope::Check)))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    // Read routes - require auth + read scope (when auth is enabled).
    let read_routes = Router::new()
        .route("/metrics", get(metrics::metrics))
        .route("/api/v1/policy", get(policy::get_policy))
        .route("/api/v1/policy/resolve", get(policy_scoping::resolve_policy))
        .route("/api/v1/scoped-policies", get(policy_scoping::list_scoped_policies))
        .route("/api/v1/policy-assignments", get(policy_scoping::list_assignments))
        .route("/api/v1/session/:id", get(session::get_session))
        .route("/api/v1/audit", get(audit::query_audit))
        .route("/api/v1/audit/stats", get(audit::audit_stats))
        .route("/api/v1/events", get(events::stream_events))
        .layer(middleware::from_fn(scope_layer(Scope::Read)))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    // Admin routes - require auth + admin scope
    let admin_routes = Router::new()
        .route("/api/v1/policy", put(policy::update_policy))
        .route("/api/v1/policy/reload", post(policy::reload_policy))
        .route("/api/v1/scoped-policies", post(policy_scoping::create_scoped_policy))
        .route(
            "/api/v1/scoped-policies/:id",
            patch(policy_scoping::update_scoped_policy).delete(policy_scoping::delete_scoped_policy),
        )
        .route("/api/v1/policy-assignments", post(policy_scoping::create_assignment))
        .route(
            "/api/v1/policy-assignments/:id",
            delete(policy_scoping::delete_assignment),
        )
        .route("/api/v1/session/:id", delete(session::terminate_session))
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
        .layer(middleware::from_fn_with_state(
            metrics,
            metrics::metrics_middleware,
        ))
        .with_state(state);

    if cors_enabled {
        app.layer(cors)
    } else {
        app
    }
}
