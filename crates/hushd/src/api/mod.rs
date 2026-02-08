//! HTTP API for hushd daemon

pub mod agents;
pub mod audit;
pub mod certification;
pub mod check;
pub mod eval;
pub mod events;
pub mod health;
pub mod me;
pub mod metrics;
pub mod policy;
pub mod policy_scoping;
pub mod rbac;
pub mod saml;
pub mod session;
pub mod shutdown;
pub mod siem;
pub mod v1;
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
use crate::v1_rate_limit::v1_rate_limit_middleware;

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
pub use rbac::{
    CreateRoleAssignmentResponse, DeleteRoleAssignmentResponse, DeleteRoleResponse,
    GetRoleResponse, ListRoleAssignmentsResponse, ListRolesResponse, UpsertRoleResponse,
};
pub use saml::{SamlExchangeRequest, SamlExchangeResponse};
pub use session::{
    CreateSessionResponse, GetSessionResponse, SessionPostureResponse, TerminateSessionResponse,
    TransitionSessionPostureResponse,
};
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
        .route("/.well-known/ca.json", get(certification::well_known_ca))
        .route("/verify/{certificationId}", get(certification::verify_page))
        .route("/api/v1/webhooks/okta", post(webhooks::okta_webhook))
        .route("/api/v1/webhooks/auth0", post(webhooks::auth0_webhook));

    // Certification API (/v1/*)
    let v1_public_routes = Router::new()
        .route("/openapi.json", get(certification::openapi_json))
        .route(
            "/certifications/{certificationId}/badge",
            get(certification::get_badge),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            certification::optional_auth_v1,
        ));

    let v1_read_routes = Router::new()
        .route("/certifications", get(certification::list_certifications))
        .route(
            "/certifications/{certificationId}",
            get(certification::get_certification),
        )
        .route(
            "/certifications/{certificationId}/policy",
            get(certification::get_policy_snapshot),
        )
        .route(
            "/certifications/{certificationId}/policy/history",
            get(certification::get_policy_history),
        )
        .layer(middleware::from_fn_with_state(
            state.v1_rate_limit.clone(),
            v1_rate_limit_middleware,
        ))
        .layer(middleware::from_fn(certification::scope_layer_v1(
            Scope::CertificationsRead,
        )))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            certification::require_auth_v1,
        ));

    let v1_verify_routes = Router::new()
        .route(
            "/certifications/{certificationId}/verify",
            post(certification::verify_certification),
        )
        .route(
            "/certifications/verify-batch",
            post(certification::verify_batch),
        )
        .layer(middleware::from_fn_with_state(
            state.v1_rate_limit.clone(),
            v1_rate_limit_middleware,
        ))
        .layer(middleware::from_fn(certification::scope_layer_v1(
            Scope::CertificationsVerify,
        )))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            certification::require_auth_v1,
        ));

    let v1_write_routes = Router::new()
        .route("/certifications", post(certification::create_certification))
        .route(
            "/certifications/{certificationId}/revoke",
            post(certification::revoke_certification),
        )
        .layer(middleware::from_fn_with_state(
            state.v1_rate_limit.clone(),
            v1_rate_limit_middleware,
        ))
        .layer(middleware::from_fn(certification::scope_layer_v1(
            Scope::CertificationsWrite,
        )))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            certification::require_auth_v1,
        ));

    let v1_evidence_read_routes = Router::new()
        .route(
            "/certifications/{certificationId}/evidence",
            get(certification::list_evidence),
        )
        .route(
            "/evidence-exports/{exportId}",
            get(certification::get_evidence_export),
        )
        .route(
            "/evidence-exports/{exportId}/download",
            get(certification::download_evidence_export),
        )
        .route(
            "/certifications/{certificationId}/revocation",
            get(certification::get_revocation_status),
        )
        .layer(middleware::from_fn_with_state(
            state.v1_rate_limit.clone(),
            v1_rate_limit_middleware,
        ))
        .layer(middleware::from_fn(certification::scope_layer_v1(
            Scope::EvidenceRead,
        )))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            certification::require_auth_v1,
        ));

    let v1_evidence_export_routes = Router::new()
        .route(
            "/certifications/{certificationId}/evidence/export",
            post(certification::export_evidence),
        )
        .layer(middleware::from_fn_with_state(
            state.v1_rate_limit.clone(),
            v1_rate_limit_middleware,
        ))
        .layer(middleware::from_fn(certification::scope_layer_v1(
            Scope::EvidenceExport,
        )))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            certification::require_auth_v1,
        ));

    let v1_webhook_routes = Router::new()
        .route(
            "/webhooks",
            get(certification::list_webhooks).post(certification::create_webhook),
        )
        .route(
            "/webhooks/{webhookId}",
            get(certification::get_webhook)
                .patch(certification::update_webhook)
                .delete(certification::delete_webhook),
        )
        .layer(middleware::from_fn_with_state(
            state.v1_rate_limit.clone(),
            v1_rate_limit_middleware,
        ))
        .layer(middleware::from_fn(certification::scope_layer_v1(
            Scope::WebhooksManage,
        )))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            certification::require_auth_v1,
        ));

    let v1_routes = Router::new()
        .merge(v1_public_routes)
        .merge(v1_read_routes)
        .merge(v1_verify_routes)
        .merge(v1_write_routes)
        .merge(v1_evidence_read_routes)
        .merge(v1_evidence_export_routes)
        .merge(v1_webhook_routes);

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
        .route("/api/v1/policy/bundle", get(policy::get_policy_bundle))
        .route("/api/v1/rbac/roles", get(rbac::list_roles))
        .route("/api/v1/rbac/roles/{id}", get(rbac::get_role))
        .route("/api/v1/rbac/assignments", get(rbac::list_role_assignments))
        .route(
            "/api/v1/policy/resolve",
            get(policy_scoping::resolve_policy),
        )
        .route(
            "/api/v1/scoped-policies",
            get(policy_scoping::list_scoped_policies),
        )
        .route(
            "/api/v1/policy-assignments",
            get(policy_scoping::list_assignments),
        )
        .route("/api/v1/session/{id}", get(session::get_session))
        .route(
            "/api/v1/session/{id}/posture",
            get(session::get_session_posture),
        )
        .route("/api/v1/audit", get(audit::query_audit))
        .route("/api/v1/audit/stats", get(audit::audit_stats))
        .route("/api/v1/agents", get(agents::list_agents))
        .route("/api/v1/delegations", get(agents::list_delegations))
        .route("/api/v1/events", get(events::stream_events))
        .route("/api/v1/siem/exporters", get(siem::exporters))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    // Admin routes - require auth + admin scope
    let admin_routes = Router::new()
        .route("/api/v1/policy", put(policy::update_policy))
        .route("/api/v1/policy/bundle", put(policy::update_policy_bundle))
        .route("/api/v1/policy/reload", post(policy::reload_policy))
        .route("/api/v1/rbac/roles", post(rbac::create_role))
        .route(
            "/api/v1/rbac/roles/{id}",
            patch(rbac::update_role).delete(rbac::delete_role),
        )
        .route(
            "/api/v1/rbac/assignments",
            post(rbac::create_role_assignment),
        )
        .route(
            "/api/v1/rbac/assignments/{id}",
            delete(rbac::delete_role_assignment),
        )
        .route(
            "/api/v1/scoped-policies",
            post(policy_scoping::create_scoped_policy),
        )
        .route(
            "/api/v1/scoped-policies/{id}",
            patch(policy_scoping::update_scoped_policy)
                .delete(policy_scoping::delete_scoped_policy),
        )
        .route(
            "/api/v1/policy-assignments",
            post(policy_scoping::create_assignment),
        )
        .route(
            "/api/v1/policy-assignments/{id}",
            delete(policy_scoping::delete_assignment),
        )
        .route("/api/v1/session/{id}", delete(session::terminate_session))
        .route(
            "/api/v1/session/{id}/transition",
            post(session::transition_session_posture),
        )
        .route("/api/v1/shutdown", post(shutdown::shutdown))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    // Note: Rate limiting is applied to all routes except /health (handled in middleware).
    // CORS is applied only if enabled in config.
    let app = Router::new()
        .merge(public_routes)
        .nest("/v1", v1_routes)
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
