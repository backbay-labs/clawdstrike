//! Tiered rate limiting for the public `/v1/*` API surface.
//!
//! This is distinct from the existing per-IP limiter (`crate::rate_limit`) and is applied
//! only to authenticated `/v1` requests. Unauthenticated public routes rely on the global
//! per-IP limiter as a fallback.

use std::num::NonZeroU32;
use std::sync::Arc;

use axum::{
    body::Body,
    http::{header, HeaderName, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::IntoResponse,
    response::Response,
};
use governor::{
    clock::{Clock, DefaultClock},
    middleware::StateInformationMiddleware,
    state::InMemoryState,
    Quota, RateLimiter,
};
use tokio::sync::Semaphore;

use crate::api::v1::V1Error;
use crate::auth::{ApiKeyTier, AuthenticatedActor};

type Key = String;
type KeyedRateLimiter =
    RateLimiter<Key, dashmap::DashMap<Key, InMemoryState>, DefaultClock, StateInformationMiddleware>;

#[derive(Clone)]
pub struct V1RateLimitState {
    enabled: bool,
    free: Arc<KeyedRateLimiter>,
    silver: Arc<KeyedRateLimiter>,
    gold: Arc<KeyedRateLimiter>,
    platinum: Arc<KeyedRateLimiter>,
    concurrency: Arc<dashmap::DashMap<Key, Arc<Semaphore>>>,
}

impl Default for V1RateLimitState {
    fn default() -> Self {
        Self::new(true)
    }
}

impl V1RateLimitState {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            free: Arc::new(Self::build_limiter(ApiKeyTier::Free)),
            silver: Arc::new(Self::build_limiter(ApiKeyTier::Silver)),
            gold: Arc::new(Self::build_limiter(ApiKeyTier::Gold)),
            platinum: Arc::new(Self::build_limiter(ApiKeyTier::Platinum)),
            concurrency: Arc::new(dashmap::DashMap::new()),
        }
    }

    fn build_limiter(tier: ApiKeyTier) -> KeyedRateLimiter {
        let (rpm, burst, _) = tier_limits(tier);
        // Safety: rpm/burst are non-zero in our table.
        let rpm = NonZeroU32::new(rpm).unwrap_or(NonZeroU32::MIN);
        let burst = NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN);
        let quota = Quota::per_minute(rpm).allow_burst(burst);
        RateLimiter::keyed(quota).with_middleware::<StateInformationMiddleware>()
    }

    fn limiter_for(&self, tier: ApiKeyTier) -> &Arc<KeyedRateLimiter> {
        match tier {
            ApiKeyTier::Free => &self.free,
            ApiKeyTier::Silver => &self.silver,
            ApiKeyTier::Gold => &self.gold,
            ApiKeyTier::Platinum => &self.platinum,
        }
    }
}

fn tier_limits(tier: ApiKeyTier) -> (u32, u32, usize) {
    // (requests/minute, burst, concurrent)
    match tier {
        ApiKeyTier::Free => (10, 20, 2),
        ApiKeyTier::Silver => (100, 200, 10),
        ApiKeyTier::Gold => (500, 1000, 50),
        ApiKeyTier::Platinum => (2000, 5000, 200),
    }
}

fn actor_key_and_tier(actor: &AuthenticatedActor) -> (Key, ApiKeyTier) {
    match actor {
        AuthenticatedActor::ApiKey(key) => (
            format!("api:{}", key.id),
            key.tier.unwrap_or(ApiKeyTier::Silver),
        ),
        AuthenticatedActor::User(principal) => {
            // Until org-tier claims are wired, treat user principals as Silver.
            (format!("user:{}", principal.id), ApiKeyTier::Silver)
        }
    }
}

fn epoch_seconds_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `/v1` tiered rate limiting middleware.
pub async fn v1_rate_limit_middleware(
    axum::extract::State(rate_limit): axum::extract::State<V1RateLimitState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if !rate_limit.enabled {
        return next.run(req).await;
    }

    // Only apply tiered limits when we have an authenticated actor; public routes are handled by
    // the global per-IP limiter.
    let Some(actor) = req.extensions().get::<AuthenticatedActor>().cloned() else {
        return next.run(req).await;
    };

    let (key, tier) = actor_key_and_tier(&actor);
    let (limit, burst, concurrent) = tier_limits(tier);

    // Concurrency limiting (best-effort).
    let semaphore = rate_limit
        .concurrency
        .entry(key.clone())
        .or_insert_with(|| Arc::new(Semaphore::new(concurrent)))
        .clone();

    let permit = match semaphore.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            let mut resp = V1Error::new(
                StatusCode::TOO_MANY_REQUESTS,
                "RATE_LIMIT_EXCEEDED",
                "Too many concurrent requests. Please retry shortly.",
            )
            .with_retry_after(1)
            .into_response();
            resp.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from_static("1"),
            );
            return resp;
        }
    };

    // Token bucket.
    let limiter = rate_limit.limiter_for(tier);
    match limiter.check_key(&key) {
        Ok(snapshot) => {
            let remaining = snapshot.remaining_burst_capacity();
            let mut resp = next.run(req).await;
            drop(permit);

            // Attach headers specified in the API docs.
            let reset_epoch = epoch_seconds_now().saturating_add(60);
            let _ = resp.headers_mut().insert(
                HeaderName::from_static("x-ratelimit-limit"),
                HeaderValue::from_str(&limit.to_string()).unwrap_or_else(|_| HeaderValue::from_static("0")),
            );
            let _ = resp.headers_mut().insert(
                HeaderName::from_static("x-ratelimit-remaining"),
                HeaderValue::from_str(&remaining.to_string())
                    .unwrap_or_else(|_| HeaderValue::from_static("0")),
            );
            let _ = resp.headers_mut().insert(
                HeaderName::from_static("x-ratelimit-reset"),
                HeaderValue::from_str(&reset_epoch.to_string())
                    .unwrap_or_else(|_| HeaderValue::from_static("0")),
            );
            let _ = resp.headers_mut().insert(
                HeaderName::from_static("x-ratelimit-retryafter"),
                HeaderValue::from_static("0"),
            );

            // Emit burst information as well (useful for debugging).
            let _ = resp.headers_mut().insert(
                HeaderName::from_static("x-ratelimit-burst"),
                HeaderValue::from_str(&burst.to_string()).unwrap_or_else(|_| HeaderValue::from_static("0")),
            );
            resp
        }
        Err(not_until) => {
            drop(permit);
            let wait = not_until.wait_time_from(DefaultClock::default().now());
            let mut retry_after_secs = wait.as_secs();
            if wait.subsec_nanos() > 0 {
                retry_after_secs = retry_after_secs.saturating_add(1);
            }
            if retry_after_secs == 0 {
                retry_after_secs = 1;
            }

            let reset_epoch = epoch_seconds_now().saturating_add(retry_after_secs);
            let mut resp = V1Error::new(
                StatusCode::TOO_MANY_REQUESTS,
                "RATE_LIMIT_EXCEEDED",
                format!("Rate limit exceeded. Please retry after {retry_after_secs} seconds."),
            )
            .with_retry_after(retry_after_secs)
            .into_response();

            resp.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from_str(&retry_after_secs.to_string())
                    .unwrap_or_else(|_| HeaderValue::from_static("1")),
            );
            resp.headers_mut().insert(
                HeaderName::from_static("x-ratelimit-limit"),
                HeaderValue::from_str(&limit.to_string()).unwrap_or_else(|_| HeaderValue::from_static("0")),
            );
            resp.headers_mut().insert(
                HeaderName::from_static("x-ratelimit-remaining"),
                HeaderValue::from_static("0"),
            );
            resp.headers_mut().insert(
                HeaderName::from_static("x-ratelimit-reset"),
                HeaderValue::from_str(&reset_epoch.to_string())
                    .unwrap_or_else(|_| HeaderValue::from_static("0")),
            );
            resp.headers_mut().insert(
                HeaderName::from_static("x-ratelimit-retryafter"),
                HeaderValue::from_str(&retry_after_secs.to_string())
                    .unwrap_or_else(|_| HeaderValue::from_static("1")),
            );
            resp.headers_mut().insert(
                HeaderName::from_static("x-ratelimit-burst"),
                HeaderValue::from_str(&burst.to_string()).unwrap_or_else(|_| HeaderValue::from_static("0")),
            );
            resp
        }
    }
}
