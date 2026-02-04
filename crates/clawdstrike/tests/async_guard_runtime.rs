#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use clawdstrike::async_guards::{
    AsyncGuard, AsyncGuardConfig, AsyncGuardError, AsyncGuardRuntime, CircuitBreakerConfig,
    RateLimitConfig,
};
use clawdstrike::guards::{GuardAction, GuardContext, GuardResult};
use clawdstrike::policy::{AsyncExecutionMode, TimeoutBehavior};
use clawdstrike::Severity;

struct SleepGuard {
    name: &'static str,
    cfg: AsyncGuardConfig,
    calls: Arc<AtomicUsize>,
    sleep: Duration,
}

#[async_trait]
impl AsyncGuard for SleepGuard {
    fn name(&self) -> &str {
        self.name
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        matches!(action, GuardAction::FileAccess(_))
    }

    fn config(&self) -> &AsyncGuardConfig {
        &self.cfg
    }

    fn cache_key(&self, _action: &GuardAction<'_>, _context: &GuardContext) -> Option<String> {
        Some("k".to_string())
    }

    async fn check_uncached(
        &self,
        _action: &GuardAction<'_>,
        _context: &GuardContext,
        _http: &clawdstrike::async_guards::http::HttpClient,
    ) -> std::result::Result<GuardResult, AsyncGuardError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        tokio::time::sleep(self.sleep).await;
        Ok(GuardResult::allow(self.name()))
    }
}

struct ResultGuard {
    name: &'static str,
    cfg: AsyncGuardConfig,
    calls: Arc<AtomicUsize>,
    allowed: bool,
}

#[async_trait]
impl AsyncGuard for ResultGuard {
    fn name(&self) -> &str {
        self.name
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        matches!(action, GuardAction::FileAccess(_))
    }

    fn config(&self) -> &AsyncGuardConfig {
        &self.cfg
    }

    fn cache_key(&self, _action: &GuardAction<'_>, _context: &GuardContext) -> Option<String> {
        None
    }

    async fn check_uncached(
        &self,
        _action: &GuardAction<'_>,
        _context: &GuardContext,
        _http: &clawdstrike::async_guards::http::HttpClient,
    ) -> std::result::Result<GuardResult, AsyncGuardError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(if self.allowed {
            GuardResult::allow(self.name())
        } else {
            GuardResult::block(self.name(), Severity::Error, "denied")
        })
    }
}

fn base_async_cfg() -> AsyncGuardConfig {
    AsyncGuardConfig {
        timeout: Duration::from_millis(10),
        on_timeout: TimeoutBehavior::Warn,
        execution_mode: AsyncExecutionMode::Sequential,
        cache_enabled: false,
        cache_ttl: Duration::from_secs(60),
        cache_max_size_bytes: 1024 * 1024,
        rate_limit: None,
        circuit_breaker: None,
        retry: None,
    }
}

#[tokio::test]
async fn timeout_warns() {
    let calls = Arc::new(AtomicUsize::new(0));
    let guard = Arc::new(SleepGuard {
        name: "sleep",
        cfg: AsyncGuardConfig {
            on_timeout: TimeoutBehavior::Warn,
            ..base_async_cfg()
        },
        calls: calls.clone(),
        sleep: Duration::from_millis(200),
    });

    let runtime = Arc::new(AsyncGuardRuntime::new());
    let ctx = GuardContext::new();
    let results = runtime
        .evaluate_async_guards(&[guard], &GuardAction::FileAccess("/tmp/a"), &ctx, false)
        .await;

    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(results.len(), 1);
    assert!(results[0].allowed);
    assert!(matches!(
        results[0].severity,
        clawdstrike::Severity::Warning
    ));
}

#[tokio::test]
async fn timeout_denies() {
    let calls = Arc::new(AtomicUsize::new(0));
    let guard = Arc::new(SleepGuard {
        name: "sleep",
        cfg: AsyncGuardConfig {
            on_timeout: TimeoutBehavior::Deny,
            ..base_async_cfg()
        },
        calls: calls.clone(),
        sleep: Duration::from_millis(200),
    });

    let runtime = Arc::new(AsyncGuardRuntime::new());
    let ctx = GuardContext::new();
    let results = runtime
        .evaluate_async_guards(&[guard], &GuardAction::FileAccess("/tmp/a"), &ctx, false)
        .await;

    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(results.len(), 1);
    assert!(!results[0].allowed);
}

#[tokio::test]
async fn rate_limit_is_best_effort() {
    let calls = Arc::new(AtomicUsize::new(0));
    let guard = Arc::new(SleepGuard {
        name: "sleep",
        cfg: AsyncGuardConfig {
            rate_limit: Some(RateLimitConfig {
                requests_per_second: 10_000.0,
                burst: 1,
            }),
            ..base_async_cfg()
        },
        calls: calls.clone(),
        sleep: Duration::from_millis(0),
    });

    let runtime = Arc::new(AsyncGuardRuntime::new());
    let ctx = GuardContext::new();
    let _ = runtime
        .evaluate_async_guards(
            &[guard.clone(), guard],
            &GuardAction::FileAccess("/tmp/a"),
            &ctx,
            false,
        )
        .await;

    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn fail_fast_false_evaluates_all_sequential_guards() {
    let calls_a = Arc::new(AtomicUsize::new(0));
    let calls_b = Arc::new(AtomicUsize::new(0));

    let guard_a = Arc::new(ResultGuard {
        name: "deny_a",
        cfg: base_async_cfg(),
        calls: calls_a.clone(),
        allowed: false,
    });
    let guard_b = Arc::new(ResultGuard {
        name: "deny_b",
        cfg: base_async_cfg(),
        calls: calls_b.clone(),
        allowed: false,
    });

    let runtime = Arc::new(AsyncGuardRuntime::new());
    let ctx = GuardContext::new();
    let results = runtime
        .evaluate_async_guards(
            &[guard_a, guard_b],
            &GuardAction::FileAccess("/tmp/a"),
            &ctx,
            false,
        )
        .await;

    assert_eq!(calls_a.load(Ordering::Relaxed), 1);
    assert_eq!(calls_b.load(Ordering::Relaxed), 1);
    assert_eq!(results.len(), 2);
    assert!(!results[0].allowed);
    assert!(!results[1].allowed);
}

#[tokio::test]
async fn fail_fast_true_short_circuits_sequential_guards() {
    let calls_a = Arc::new(AtomicUsize::new(0));
    let calls_b = Arc::new(AtomicUsize::new(0));

    let guard_a = Arc::new(ResultGuard {
        name: "deny_a",
        cfg: base_async_cfg(),
        calls: calls_a.clone(),
        allowed: false,
    });
    let guard_b = Arc::new(ResultGuard {
        name: "deny_b",
        cfg: base_async_cfg(),
        calls: calls_b.clone(),
        allowed: false,
    });

    let runtime = Arc::new(AsyncGuardRuntime::new());
    let ctx = GuardContext::new();
    let results = runtime
        .evaluate_async_guards(
            &[guard_a, guard_b],
            &GuardAction::FileAccess("/tmp/a"),
            &ctx,
            true,
        )
        .await;

    assert_eq!(calls_a.load(Ordering::Relaxed), 1);
    assert_eq!(calls_b.load(Ordering::Relaxed), 0);
    assert_eq!(results.len(), 1);
    assert!(!results[0].allowed);
}

#[tokio::test]
async fn circuit_breaker_opens_on_timeouts() {
    let calls = Arc::new(AtomicUsize::new(0));
    let guard: Arc<dyn AsyncGuard> = Arc::new(SleepGuard {
        name: "sleep",
        cfg: AsyncGuardConfig {
            circuit_breaker: Some(CircuitBreakerConfig {
                failure_threshold: 2,
                reset_timeout: Duration::from_secs(60),
                success_threshold: 1,
            }),
            ..base_async_cfg()
        },
        calls: calls.clone(),
        sleep: Duration::from_millis(200),
    });

    let runtime = Arc::new(AsyncGuardRuntime::new());
    let ctx = GuardContext::new();

    let _ = runtime
        .evaluate_async_guards(
            std::slice::from_ref(&guard),
            &GuardAction::FileAccess("/tmp/a"),
            &ctx,
            false,
        )
        .await;
    let _ = runtime
        .evaluate_async_guards(
            std::slice::from_ref(&guard),
            &GuardAction::FileAccess("/tmp/a"),
            &ctx,
            false,
        )
        .await;

    let results = runtime
        .evaluate_async_guards(
            std::slice::from_ref(&guard),
            &GuardAction::FileAccess("/tmp/a"),
            &ctx,
            false,
        )
        .await;

    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0]
            .details
            .as_ref()
            .and_then(|d| d["async_error"]["kind"].as_str()),
        Some("CircuitOpen")
    );
}
