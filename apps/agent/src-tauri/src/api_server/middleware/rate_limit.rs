//! Route-level rate limiting middleware.
//!
//! Applies to the bootstrap, policy-check, integration-test, and OpenClaw routes.
//! Per-route limits are configured by the constants in `state.rs`.

use super::super::*;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;
use std::time::Instant;

pub(crate) async fn route_rate_limit(
    State(state): State<Arc<AgentApiState>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let method = request.method().clone();
    let now = Instant::now();

    let limited = if path == "/api/v1/ui/bootstrap/start" {
        let mut limiter = state.ui_bootstrap_start_rate_limiter.lock().await;
        limiter
            .allow_now(
                now,
                ROUTE_RATE_LIMIT_WINDOW,
                ROUTE_RATE_LIMIT_UI_BOOTSTRAP_START,
            )
            .err()
    } else if path == "/ui/bootstrap" && method == axum::http::Method::POST {
        let mut limiter = state.ui_bootstrap_verify_rate_limiter.lock().await;
        limiter
            .allow_now(
                now,
                ROUTE_RATE_LIMIT_WINDOW,
                ROUTE_RATE_LIMIT_UI_BOOTSTRAP_VERIFY,
            )
            .err()
    } else if path == "/api/v1/agent/policy-check" {
        let mut limiter = state.policy_check_rate_limiter.lock().await;
        limiter
            .allow_now(now, ROUTE_RATE_LIMIT_WINDOW, ROUTE_RATE_LIMIT_POLICY_CHECK)
            .err()
    } else if path == "/api/v1/agent/integrations/test" {
        let mut limiter = state.integration_test_rate_limiter.lock().await;
        limiter
            .allow_now(
                now,
                ROUTE_RATE_LIMIT_WINDOW,
                ROUTE_RATE_LIMIT_INTEGRATION_TEST,
            )
            .err()
    } else if path == "/api/v1/openclaw/request" {
        let mut limiter = state.openclaw_request_rate_limiter.lock().await;
        limiter
            .allow_now(
                now,
                ROUTE_RATE_LIMIT_WINDOW,
                ROUTE_RATE_LIMIT_OPENCLAW_REQUEST,
            )
            .err()
    } else {
        None
    };

    if let Some(retry_after) = limited {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            format!("Rate limit exceeded; retry in {}s", retry_after),
        )
            .into_response();
    }

    next.run(request).await
}
