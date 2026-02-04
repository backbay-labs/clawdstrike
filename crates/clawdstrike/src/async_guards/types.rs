use std::time::Duration;

use async_trait::async_trait;

use crate::guards::{GuardAction, GuardContext, GuardResult};
use crate::policy::{AsyncExecutionMode, TimeoutBehavior};

#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    /// Requests per second.
    pub requests_per_second: f64,
    /// Maximum burst size (tokens).
    pub burst: u32,
}

#[derive(Clone, Debug)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub reset_timeout: Duration,
    pub success_threshold: u32,
}

#[derive(Clone, Debug)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub multiplier: f64,
}

#[derive(Clone, Debug)]
pub struct AsyncGuardConfig {
    pub timeout: Duration,
    pub on_timeout: TimeoutBehavior,
    pub execution_mode: AsyncExecutionMode,
    pub cache_enabled: bool,
    pub cache_ttl: Duration,
    pub cache_max_size_bytes: usize,
    pub rate_limit: Option<RateLimitConfig>,
    pub circuit_breaker: Option<CircuitBreakerConfig>,
    pub retry: Option<RetryConfig>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsyncGuardErrorKind {
    Timeout,
    CircuitOpen,
    Http,
    Parse,
    Other,
}

#[derive(Clone, Debug)]
pub struct AsyncGuardError {
    pub kind: AsyncGuardErrorKind,
    pub message: String,
    pub status: Option<u16>,
}

impl AsyncGuardError {
    pub fn new(kind: AsyncGuardErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            status: None,
        }
    }

    pub fn with_status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }
}

impl std::fmt::Display for AsyncGuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.status {
            Some(code) => write!(f, "{} (status {})", self.message, code),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for AsyncGuardError {}

#[async_trait]
pub trait AsyncGuard: Send + Sync {
    fn name(&self) -> &str;

    fn handles(&self, action: &GuardAction<'_>) -> bool;

    fn config(&self) -> &AsyncGuardConfig;

    /// Cache key for this event, if applicable. Returning `None` disables caching for this event.
    fn cache_key(&self, action: &GuardAction<'_>, context: &GuardContext) -> Option<String>;

    /// Run the guard check without caching, timeouts, circuit breaker, or rate limiting.
    ///
    /// The runtime applies these protections and then calls `check_uncached`.
    async fn check_uncached(
        &self,
        action: &GuardAction<'_>,
        context: &GuardContext,
        http: &crate::async_guards::http::HttpClient,
    ) -> std::result::Result<GuardResult, AsyncGuardError>;
}
