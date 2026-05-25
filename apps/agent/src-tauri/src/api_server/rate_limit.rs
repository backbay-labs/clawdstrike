//! Sliding-window rate limiters used by the agent API.
//!
//! Two flavours live here:
//!   - `ApprovalSubmissionLimiter` enforces both a per-minute quota and a
//!     short burst window for `/api/v1/approval/request`.
//!   - `RouteRateLimiter` is a generic single-window limiter that
//!     `route_rate_limit` (middleware) picks per-path from `AgentApiState`.
//!
//! Both expect monotonic `Instant` timestamps and never panic on a poisoned
//! mutex (the parent holds them under `tokio::sync::Mutex`, so there's no
//! poisoning, but the API stays infallible regardless).

use super::AgentApiState;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(crate) const APPROVAL_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
pub(crate) const APPROVAL_RATE_LIMIT_BURST_WINDOW: Duration = Duration::from_secs(1);
pub(crate) const APPROVAL_RATE_LIMIT_PER_MINUTE: usize = 30;
pub(crate) const APPROVAL_RATE_LIMIT_BURST: usize = 10;
pub(crate) const ROUTE_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
pub(crate) const ROUTE_RATE_LIMIT_UI_BOOTSTRAP_START: usize = 20;
pub(crate) const ROUTE_RATE_LIMIT_UI_BOOTSTRAP_VERIFY: usize = 60;
pub(crate) const ROUTE_RATE_LIMIT_POLICY_CHECK: usize = 1200;
pub(crate) const ROUTE_RATE_LIMIT_INTEGRATION_TEST: usize = 30;
pub(crate) const ROUTE_RATE_LIMIT_OPENCLAW_REQUEST: usize = 120;

#[derive(Debug, Default)]
pub(crate) struct ApprovalSubmissionLimiter {
    minute_events: VecDeque<Instant>,
    burst_events: VecDeque<Instant>,
}

#[derive(Debug, Default)]
pub(crate) struct RouteRateLimiter {
    events: VecDeque<Instant>,
}

impl ApprovalSubmissionLimiter {
    pub(crate) fn allow_now(&mut self, now: Instant) -> std::result::Result<(), u64> {
        while self
            .minute_events
            .front()
            .is_some_and(|ts| now.duration_since(*ts) >= APPROVAL_RATE_LIMIT_WINDOW)
        {
            let _ = self.minute_events.pop_front();
        }
        while self
            .burst_events
            .front()
            .is_some_and(|ts| now.duration_since(*ts) >= APPROVAL_RATE_LIMIT_BURST_WINDOW)
        {
            let _ = self.burst_events.pop_front();
        }

        if self.minute_events.len() >= APPROVAL_RATE_LIMIT_PER_MINUTE {
            if let Some(oldest) = self.minute_events.front().copied() {
                let retry_after = APPROVAL_RATE_LIMIT_WINDOW
                    .saturating_sub(now.duration_since(oldest))
                    .as_secs()
                    .max(1);
                return Err(retry_after);
            }
            return Err(1);
        }

        if self.burst_events.len() >= APPROVAL_RATE_LIMIT_BURST {
            if let Some(oldest) = self.burst_events.front().copied() {
                let retry_after = APPROVAL_RATE_LIMIT_BURST_WINDOW
                    .saturating_sub(now.duration_since(oldest))
                    .as_secs()
                    .max(1);
                return Err(retry_after);
            }
            return Err(1);
        }

        self.minute_events.push_back(now);
        self.burst_events.push_back(now);
        Ok(())
    }
}

impl RouteRateLimiter {
    pub(crate) fn allow_now(
        &mut self,
        now: Instant,
        window: Duration,
        limit: usize,
    ) -> std::result::Result<(), u64> {
        while self
            .events
            .front()
            .is_some_and(|ts| now.duration_since(*ts) >= window)
        {
            let _ = self.events.pop_front();
        }

        if self.events.len() >= limit {
            if let Some(oldest) = self.events.front().copied() {
                let retry_after = window
                    .saturating_sub(now.duration_since(oldest))
                    .as_secs()
                    .max(1);
                return Err(retry_after);
            }
            return Err(1);
        }

        self.events.push_back(now);
        Ok(())
    }
}

pub(super) async fn route_rate_limit(
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
