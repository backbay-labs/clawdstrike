//! HTTP API for hushd daemon

pub mod audit;
pub mod check;
pub mod events;
pub mod health;
pub mod policy;

use axum::{
    routing::{get, post},
    Router,
};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

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

    Router::new()
        // Health check
        .route("/health", get(health::health))
        // Action checking
        .route("/api/v1/check", post(check::check_action))
        // Policy management
        .route(
            "/api/v1/policy",
            get(policy::get_policy).put(policy::update_policy),
        )
        .route("/api/v1/policy/reload", post(policy::reload_policy))
        // Audit log
        .route("/api/v1/audit", get(audit::query_audit))
        .route("/api/v1/audit/stats", get(audit::audit_stats))
        // Event streaming
        .route("/api/v1/events", get(events::stream_events))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}
