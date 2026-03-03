#![cfg(feature = "full")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use clawdstrike::async_guards::{AsyncGuard, AsyncGuardConfig, AsyncGuardError, AsyncGuardRuntime};
use clawdstrike::guards::{GuardAction, GuardContext, GuardResult};
use clawdstrike::policy::{AsyncExecutionMode, TimeoutBehavior};
use clawdstrike::{FilesystemIrm, HostCall, Monitor, NetworkIrm, Policy};

struct SleepGuard {
    cfg: AsyncGuardConfig,
    calls: Arc<AtomicUsize>,
    sleep: Duration,
}

#[async_trait]
impl AsyncGuard for SleepGuard {
    fn name(&self) -> &str {
        "security_regression_background_sleep"
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        matches!(action, GuardAction::FileAccess(_))
    }

    fn config(&self) -> &AsyncGuardConfig {
        &self.cfg
    }

    fn cache_key(&self, _action: &GuardAction<'_>, _context: &GuardContext) -> Option<String> {
        Some("security-regression".to_string())
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

fn background_cfg() -> AsyncGuardConfig {
    AsyncGuardConfig {
        timeout: Duration::from_secs(1),
        on_timeout: TimeoutBehavior::Warn,
        execution_mode: AsyncExecutionMode::Background,
        cache_enabled: false,
        cache_ttl: Duration::from_secs(60),
        cache_max_size_bytes: 1024 * 1024,
        rate_limit: None,
        circuit_breaker: None,
        retry: None,
    }
}

#[tokio::test]
async fn security_regression_fs_traversal_in_nonfirst_object_arg_is_denied() {
    let irm = FilesystemIrm::new();
    let policy = Policy::default();

    let call = HostCall::new(
        "fd_read",
        vec![
            serde_json::json!({"fd": 3}),
            serde_json::json!({"path": "../../etc/passwd"}),
        ],
    );

    let decision = irm.evaluate(&call, &policy).await;
    assert!(
        !decision.is_allowed(),
        "relative traversal path must be denied"
    );
}

#[tokio::test]
async fn security_regression_net_userinfo_spoof_is_denied_using_actual_host() {
    let irm = NetworkIrm::new();
    let policy = Policy::from_yaml(
        r#"
version: "1.1.0"
name: "security-regression-net"
guards:
  egress_allowlist:
    allow: ["api.openai.com"]
    default_action: block
"#,
    )
    .expect("policy");

    let call = HostCall::new(
        "sock_connect",
        vec![serde_json::json!(
            "https://api.openai.com:443@evil.example/path"
        )],
    );

    let decision = irm.evaluate(&call, &policy).await;
    assert!(
        !decision.is_allowed(),
        "userinfo spoof URL must be evaluated against evil.example and denied"
    );
}

#[tokio::test]
async fn security_regression_async_background_guards_enforce_inflight_limit() {
    let calls = Arc::new(AtomicUsize::new(0));
    let guard: Arc<dyn AsyncGuard> = Arc::new(SleepGuard {
        cfg: background_cfg(),
        calls: calls.clone(),
        sleep: Duration::from_millis(250),
    });

    let runtime = Arc::new(AsyncGuardRuntime::with_background_in_flight_limit(2));
    let ctx = GuardContext::new();

    for _ in 0..20 {
        let _ = runtime
            .evaluate_async_guards(
                std::slice::from_ref(&guard),
                &GuardAction::FileAccess("/tmp/security-regression"),
                &ctx,
                false,
            )
            .await;
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(
        runtime.background_peak_inflight() <= 2,
        "background in-flight peak exceeded configured limit"
    );
    assert!(
        runtime.background_dropped_count() > 0,
        "burst load should drop background tasks once in-flight limit is saturated"
    );
}
