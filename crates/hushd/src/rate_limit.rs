//! Rate limiting middleware for hushd
//!
//! Uses a token bucket algorithm with per-IP rate limiting.
//! The /health endpoint is excluded from rate limiting.
//!
//! ## Security Note
//!
//! By default, X-Forwarded-For and X-Real-IP headers are NOT trusted
//! to prevent rate limit bypass attacks. Configure `trusted_proxies`
//! with your proxy IP addresses to enable header-based IP detection.

use std::collections::HashSet;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use governor::{
    clock::DefaultClock, middleware::NoOpMiddleware, state::InMemoryState, Quota, RateLimiter,
};

use crate::config::RateLimitConfig;

/// Type alias for our keyed rate limiter
pub type KeyedRateLimiter =
    RateLimiter<IpAddr, dashmap::DashMap<IpAddr, InMemoryState>, DefaultClock, NoOpMiddleware>;

/// Shared rate limiter state
#[derive(Clone)]
pub struct RateLimitState {
    limiter: Option<Arc<KeyedRateLimiter>>,
    config: RateLimitConfig,
    trusted_proxies: HashSet<IpAddr>,
}

impl RateLimitState {
    /// Create a new rate limit state from config
    pub fn new(config: &RateLimitConfig) -> Self {
        if !config.enabled {
            return Self {
                limiter: None,
                config: config.clone(),
                trusted_proxies: HashSet::new(),
            };
        }

        // Create quota: burst_size requests, refilling at requests_per_second.
        //
        // If the config specifies 0 for either field, fall back to safe defaults.
        let default_rps = unsafe {
            // SAFETY: 100 is non-zero.
            NonZeroU32::new_unchecked(100)
        };
        let default_burst = unsafe {
            // SAFETY: 50 is non-zero.
            NonZeroU32::new_unchecked(50)
        };

        let rps = NonZeroU32::new(config.requests_per_second).unwrap_or(default_rps);
        let burst = NonZeroU32::new(config.burst_size).unwrap_or(default_burst);

        let quota = Quota::per_second(rps).allow_burst(burst);

        let limiter = RateLimiter::keyed(quota);

        // Parse trusted proxy IPs
        let trusted_proxies: HashSet<IpAddr> = config
            .trusted_proxies
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        if !trusted_proxies.is_empty() {
            tracing::info!(
                count = trusted_proxies.len(),
                "Configured trusted proxies for rate limiting"
            );
        }

        Self {
            limiter: Some(Arc::new(limiter)),
            config: config.clone(),
            trusted_proxies,
        }
    }

    /// Check if rate limiting is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled && self.limiter.is_some()
    }

    /// Check if headers should be trusted for the given connection IP
    pub fn should_trust_headers(&self, connection_ip: Option<IpAddr>) -> bool {
        // If trust_xff_from_any is set, always trust (INSECURE)
        if self.config.trust_xff_from_any {
            return true;
        }

        // Otherwise, only trust if connection IP is in trusted_proxies
        match connection_ip {
            Some(ip) => self.trusted_proxies.contains(&ip),
            None => false,
        }
    }
}

/// Rate limiting middleware
///
/// Returns 429 Too Many Requests if the client exceeds their rate limit.
/// The /health endpoint is excluded from rate limiting.
pub async fn rate_limit_middleware(
    axum::extract::State(rate_limit): axum::extract::State<RateLimitState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    // Skip rate limiting if disabled
    if !rate_limit.is_enabled() {
        return next.run(req).await;
    }

    // Skip rate limiting for health endpoint
    if req.uri().path() == "/health" {
        return next.run(req).await;
    }

    // Extract client IP with trusted proxy check
    let client_ip = extract_client_ip(&req, &rate_limit);

    // Check rate limit
    if let Some(ref limiter) = rate_limit.limiter {
        match limiter.check_key(&client_ip) {
            Ok(_) => {
                // Request allowed
                next.run(req).await
            }
            Err(_not_until) => {
                // Rate limit exceeded
                tracing::debug!(
                    client_ip = %client_ip,
                    "Rate limit exceeded"
                );
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    [("Retry-After", "1")],
                    "Rate limit exceeded. Please slow down.",
                )
                    .into_response()
            }
        }
    } else {
        next.run(req).await
    }
}

/// Extract client IP from request
///
/// Only trusts X-Forwarded-For and X-Real-IP headers if the connection
/// comes from a trusted proxy IP. This prevents rate limit bypass attacks.
fn extract_client_ip(req: &Request<Body>, rate_limit: &RateLimitState) -> IpAddr {
    // Get the connection IP from request extensions (would come from ConnectInfo in production)
    // TODO: In production, use axum::extract::ConnectInfo to get the actual socket address
    let connection_ip: Option<IpAddr> = req
        .extensions()
        .get::<std::net::SocketAddr>()
        .map(|addr| addr.ip());

    // Only trust headers if connection is from a trusted proxy
    if rate_limit.should_trust_headers(connection_ip) {
        // Check X-Forwarded-For header (for proxied requests)
        if let Some(forwarded) = req
            .headers()
            .get("X-Forwarded-For")
            .and_then(|v| v.to_str().ok())
        {
            // Take the first IP in the chain (client IP)
            if let Some(ip_str) = forwarded.split(',').next() {
                if let Ok(ip) = ip_str.trim().parse() {
                    return ip;
                }
            }
        }

        // Check X-Real-IP header
        if let Some(real_ip) = req.headers().get("X-Real-IP").and_then(|v| v.to_str().ok()) {
            if let Ok(ip) = real_ip.trim().parse() {
                return ip;
            }
        }
    }

    // Use connection IP if available, otherwise fallback to loopback
    connection_ip.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_state_disabled() {
        let config = RateLimitConfig {
            enabled: false,
            requests_per_second: 100,
            burst_size: 50,
            trusted_proxies: vec![],
            trust_xff_from_any: false,
        };
        let state = RateLimitState::new(&config);
        assert!(!state.is_enabled());
        assert!(state.limiter.is_none());
    }

    #[test]
    fn test_rate_limit_state_enabled() {
        let config = RateLimitConfig {
            enabled: true,
            requests_per_second: 100,
            burst_size: 50,
            trusted_proxies: vec![],
            trust_xff_from_any: false,
        };
        let state = RateLimitState::new(&config);
        assert!(state.is_enabled());
        assert!(state.limiter.is_some());
    }

    #[test]
    fn test_rate_limiter_allows_requests_within_limit() {
        let config = RateLimitConfig {
            enabled: true,
            requests_per_second: 10,
            burst_size: 5,
            trusted_proxies: vec![],
            trust_xff_from_any: false,
        };
        let state = RateLimitState::new(&config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Should allow burst_size requests immediately
        for _ in 0..5 {
            assert!(state.limiter.as_ref().unwrap().check_key(&ip).is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_blocks_after_burst() {
        let config = RateLimitConfig {
            enabled: true,
            requests_per_second: 10,
            burst_size: 3,
            trusted_proxies: vec![],
            trust_xff_from_any: false,
        };
        let state = RateLimitState::new(&config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Exhaust the burst
        for _ in 0..3 {
            assert!(state.limiter.as_ref().unwrap().check_key(&ip).is_ok());
        }

        // Next request should be blocked
        assert!(state.limiter.as_ref().unwrap().check_key(&ip).is_err());
    }

    #[test]
    fn test_rate_limiter_separate_ips() {
        let config = RateLimitConfig {
            enabled: true,
            requests_per_second: 10,
            burst_size: 2,
            trusted_proxies: vec![],
            trust_xff_from_any: false,
        };
        let state = RateLimitState::new(&config);
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        // Exhaust burst for ip1
        for _ in 0..2 {
            assert!(state.limiter.as_ref().unwrap().check_key(&ip1).is_ok());
        }
        assert!(state.limiter.as_ref().unwrap().check_key(&ip1).is_err());

        // ip2 should still have full quota
        for _ in 0..2 {
            assert!(state.limiter.as_ref().unwrap().check_key(&ip2).is_ok());
        }
    }

    #[test]
    fn test_extract_client_ip_from_forwarded_with_trust() {
        let config = RateLimitConfig {
            enabled: true,
            requests_per_second: 100,
            burst_size: 50,
            trusted_proxies: vec![],
            trust_xff_from_any: true, // Trust headers (for testing)
        };
        let state = RateLimitState::new(&config);

        let req = Request::builder()
            .header(
                "X-Forwarded-For",
                "203.0.113.195, 70.41.3.18, 150.172.238.178",
            )
            .body(Body::empty())
            .unwrap();

        let ip = extract_client_ip(&req, &state);
        assert_eq!(ip, "203.0.113.195".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_extract_client_ip_ignores_untrusted_headers() {
        let config = RateLimitConfig {
            enabled: true,
            requests_per_second: 100,
            burst_size: 50,
            trusted_proxies: vec![],
            trust_xff_from_any: false, // Don't trust headers
        };
        let state = RateLimitState::new(&config);

        let req = Request::builder()
            .header("X-Forwarded-For", "203.0.113.195")
            .body(Body::empty())
            .unwrap();

        // Should ignore the header and return fallback
        let ip = extract_client_ip(&req, &state);
        assert_eq!(ip, "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_extract_client_ip_from_real_ip_with_trust() {
        let config = RateLimitConfig {
            enabled: true,
            requests_per_second: 100,
            burst_size: 50,
            trusted_proxies: vec![],
            trust_xff_from_any: true,
        };
        let state = RateLimitState::new(&config);

        let req = Request::builder()
            .header("X-Real-IP", "203.0.113.195")
            .body(Body::empty())
            .unwrap();

        let ip = extract_client_ip(&req, &state);
        assert_eq!(ip, "203.0.113.195".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_extract_client_ip_fallback() {
        let config = RateLimitConfig {
            enabled: true,
            requests_per_second: 100,
            burst_size: 50,
            trusted_proxies: vec![],
            trust_xff_from_any: false,
        };
        let state = RateLimitState::new(&config);

        let req = Request::builder().body(Body::empty()).unwrap();

        let ip = extract_client_ip(&req, &state);
        assert_eq!(ip, "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_trusted_proxies_config() {
        let config = RateLimitConfig {
            enabled: true,
            requests_per_second: 100,
            burst_size: 50,
            trusted_proxies: vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()],
            trust_xff_from_any: false,
        };
        let state = RateLimitState::new(&config);

        // Should trust headers from configured proxy IPs
        assert!(state.should_trust_headers(Some("10.0.0.1".parse().unwrap())));
        assert!(state.should_trust_headers(Some("10.0.0.2".parse().unwrap())));

        // Should not trust headers from other IPs
        assert!(!state.should_trust_headers(Some("192.168.1.1".parse().unwrap())));
        assert!(!state.should_trust_headers(None));
    }
}
