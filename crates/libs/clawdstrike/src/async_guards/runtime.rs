use std::sync::Arc;

use dashmap::DashMap;
use futures::stream::{FuturesUnordered, StreamExt};

use crate::async_guards::cache::TtlCache;
use crate::async_guards::circuit_breaker::CircuitBreaker;
use crate::async_guards::http::HttpClient;
use crate::async_guards::rate_limit::TokenBucket;
use crate::async_guards::retry;
use crate::async_guards::types::{
    AsyncGuard, AsyncGuardConfig, AsyncGuardErrorKind, RateLimitConfig,
};
use crate::guards::{GuardAction, GuardContext, GuardResult, Severity};
use crate::policy::{AsyncExecutionMode, TimeoutBehavior};

#[derive(Clone, Debug)]
pub enum OwnedGuardAction {
    FileAccess {
        path: String,
    },
    FileWrite {
        path: String,
        content: Vec<u8>,
    },
    NetworkEgress {
        host: String,
        port: u16,
    },
    ShellCommand {
        commandline: String,
    },
    McpTool {
        tool: String,
        args: serde_json::Value,
    },
    Patch {
        path: String,
        diff: String,
    },
    Custom {
        kind: String,
        data: serde_json::Value,
    },
}

impl OwnedGuardAction {
    pub fn from_borrowed(action: &GuardAction<'_>) -> Self {
        match action {
            GuardAction::FileAccess(p) => Self::FileAccess {
                path: (*p).to_string(),
            },
            GuardAction::FileWrite(p, c) => Self::FileWrite {
                path: (*p).to_string(),
                content: c.to_vec(),
            },
            GuardAction::NetworkEgress(h, p) => Self::NetworkEgress {
                host: (*h).to_string(),
                port: *p,
            },
            GuardAction::ShellCommand(c) => Self::ShellCommand {
                commandline: (*c).to_string(),
            },
            GuardAction::McpTool(t, args) => Self::McpTool {
                tool: (*t).to_string(),
                args: (*args).clone(),
            },
            GuardAction::Patch(p, d) => Self::Patch {
                path: (*p).to_string(),
                diff: (*d).to_string(),
            },
            GuardAction::Custom(kind, data) => Self::Custom {
                kind: (*kind).to_string(),
                data: (*data).clone(),
            },
        }
    }

    pub fn as_guard_action(&self) -> GuardAction<'_> {
        match self {
            Self::FileAccess { path } => GuardAction::FileAccess(path),
            Self::FileWrite { path, content } => GuardAction::FileWrite(path, content),
            Self::NetworkEgress { host, port } => GuardAction::NetworkEgress(host, *port),
            Self::ShellCommand { commandline } => GuardAction::ShellCommand(commandline),
            Self::McpTool { tool, args } => GuardAction::McpTool(tool, args),
            Self::Patch { path, diff } => GuardAction::Patch(path, diff),
            Self::Custom { kind, data } => GuardAction::Custom(kind, data),
        }
    }
}

pub struct AsyncGuardRuntime {
    http: HttpClient,
    caches: DashMap<String, Arc<TtlCache>>,
    limiters: DashMap<String, Arc<TokenBucket>>,
    breakers: DashMap<String, Arc<CircuitBreaker>>,
}

impl Default for AsyncGuardRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl AsyncGuardRuntime {
    pub fn new() -> Self {
        Self {
            http: HttpClient::new(),
            caches: DashMap::new(),
            limiters: DashMap::new(),
            breakers: DashMap::new(),
        }
    }

    pub fn http(&self) -> &HttpClient {
        &self.http
    }

    pub async fn evaluate_async_guards(
        self: &Arc<Self>,
        guards: &[Arc<dyn AsyncGuard>],
        action: &GuardAction<'_>,
        context: &GuardContext,
        fail_fast: bool,
    ) -> Vec<GuardResult> {
        let mut out: Vec<GuardResult> = Vec::new();

        let mut sequential: Vec<(usize, Arc<dyn AsyncGuard>)> = Vec::new();
        let mut parallel: Vec<(usize, Arc<dyn AsyncGuard>)> = Vec::new();
        let mut background: Vec<(usize, Arc<dyn AsyncGuard>)> = Vec::new();

        for (idx, g) in guards.iter().cloned().enumerate() {
            if !g.handles(action) {
                continue;
            }

            match g.config().execution_mode {
                AsyncExecutionMode::Sequential => sequential.push((idx, g)),
                AsyncExecutionMode::Parallel => parallel.push((idx, g)),
                AsyncExecutionMode::Background => background.push((idx, g)),
            }
        }

        // Sequential guards (stable order by policy list).
        sequential.sort_by_key(|(idx, _)| *idx);
        for (_idx, g) in sequential {
            let result = self.evaluate_one(g, action, context).await;
            let denied = !result.allowed;
            out.push(result);
            if fail_fast && denied {
                return out;
            }
        }

        // Parallel guards. Short-circuit on deny.
        parallel.sort_by_key(|(idx, _)| *idx);
        if !parallel.is_empty() {
            let results_by_idx: DashMap<usize, GuardResult> = DashMap::new();
            let mut futs = FuturesUnordered::new();

            for (idx, g) in parallel.iter().cloned() {
                let runtime = Arc::clone(self);
                futs.push(async move { (idx, runtime.evaluate_one(g, action, context).await) });
            }

            let mut denied = false;
            while let Some((idx, res)) = futs.next().await {
                if !res.allowed {
                    denied = true;
                }
                results_by_idx.insert(idx, res);
                if fail_fast && denied {
                    break;
                }
            }

            if fail_fast && denied {
                // Remaining futures are dropped here (best-effort cancellation).
                drop(futs);
            }

            for (idx, g) in parallel {
                if let Some((_, res)) = results_by_idx.remove(&idx) {
                    let denied = !res.allowed;
                    out.push(res);
                    if fail_fast && denied {
                        return out;
                    }
                } else {
                    // Canceled due to deny in another parallel guard.
                    out.push(
                        GuardResult::warn(
                            g.name(),
                            "Canceled due to earlier deny in parallel group",
                        )
                        .with_details(serde_json::json!({ "canceled": true })),
                    );
                }
            }

            if fail_fast && denied {
                return out;
            }
        }

        // Background guards: schedule and return allow placeholders.
        if !background.is_empty() {
            let owned_action = OwnedGuardAction::from_borrowed(action);
            let ctx = context.clone();

            background.sort_by_key(|(idx, _)| *idx);
            for (_idx, g) in background {
                self.spawn_background(g.clone(), owned_action.clone(), ctx.clone());
                out.push(
                    GuardResult::allow(g.name()).with_details(serde_json::json!({
                        "background": true,
                        "note": "scheduled"
                    })),
                );
            }
        }

        out
    }

    fn spawn_background(
        self: &Arc<Self>,
        guard: Arc<dyn AsyncGuard>,
        action: OwnedGuardAction,
        context: GuardContext,
    ) {
        let runtime = Arc::clone(self);
        tokio::spawn(async move {
            let borrowed = action.as_guard_action();
            let result = runtime
                .evaluate_one(guard.clone(), &borrowed, &context)
                .await;

            if !result.allowed {
                tracing::warn!(
                    guard = guard.name(),
                    action = "alert",
                    message = %result.message,
                    severity = ?result.severity,
                    "background async guard would have denied"
                );
            }
        });
    }

    async fn evaluate_one(
        self: &Arc<Self>,
        guard: Arc<dyn AsyncGuard>,
        action: &GuardAction<'_>,
        context: &GuardContext,
    ) -> GuardResult {
        let name = guard.name().to_string();
        let cfg = guard.config().clone();

        let cache_key = guard.cache_key(action, context);
        if cfg.cache_enabled {
            if let Some(ref key) = cache_key {
                if let Some(mut cached) = self.cache_for(&name, &cfg).get_guard_result(key) {
                    let merged =
                        merge_details(cached.details.take(), serde_json::json!({ "cache": "hit" }));
                    cached.details = Some(merged);
                    return cached;
                }
            }
        }

        if let Some(cb_cfg) = cfg.circuit_breaker.clone() {
            let breaker = self
                .breakers
                .entry(name.clone())
                .or_insert_with(|| Arc::new(CircuitBreaker::new(cb_cfg)))
                .clone();

            if breaker.before_request().await.is_err() {
                return fallback(
                    &name,
                    &cfg,
                    AsyncGuardErrorKind::CircuitOpen,
                    "circuit breaker open",
                    cache_key.as_deref(),
                    self.cache_for(&name, &cfg),
                );
            }
        }

        if let Some(RateLimitConfig {
            requests_per_second,
            burst,
        }) = cfg.rate_limit.clone()
        {
            let limiter = self
                .limiters
                .entry(name.clone())
                .or_insert_with(|| Arc::new(TokenBucket::new(requests_per_second, burst)))
                .clone();
            limiter.acquire().await;
        }

        let attempt = async {
            if let Some(retry_cfg) = cfg.retry.clone() {
                retry::retry(&retry_cfg, |attempt| {
                    let guard = guard.clone();
                    async move {
                        guard
                            .check_uncached(action, context, &self.http)
                            .await
                            .map_err(|mut e| {
                                if e.kind == AsyncGuardErrorKind::Other && e.status.is_none() {
                                    e.message =
                                        format!("attempt {} failed: {}", attempt + 1, e.message);
                                }
                                e
                            })
                    }
                })
                .await
            } else {
                guard.check_uncached(action, context, &self.http).await
            }
        };

        let timed = tokio::time::timeout(cfg.timeout, attempt).await;

        match timed {
            Ok(Ok(res)) => {
                // Cache success.
                if cfg.cache_enabled {
                    if let Some(ref key) = cache_key {
                        self.cache_for(&name, &cfg).set_guard_result(
                            key.clone(),
                            &res,
                            cfg.cache_ttl,
                        );
                    }
                }

                if cfg.circuit_breaker.is_some() {
                    if let Some(b) = self.breakers.get(&name) {
                        b.record_success().await;
                    }
                }

                res
            }
            Ok(Err(err)) => {
                if cfg.circuit_breaker.is_some() {
                    if let Some(b) = self.breakers.get(&name) {
                        b.record_failure().await;
                    }
                }

                fallback(
                    &name,
                    &cfg,
                    err.kind,
                    &err.message,
                    cache_key.as_deref(),
                    self.cache_for(&name, &cfg),
                )
            }
            Err(_) => {
                if cfg.circuit_breaker.is_some() {
                    if let Some(b) = self.breakers.get(&name) {
                        b.record_failure().await;
                    }
                }

                fallback(
                    &name,
                    &cfg,
                    AsyncGuardErrorKind::Timeout,
                    "timeout",
                    cache_key.as_deref(),
                    self.cache_for(&name, &cfg),
                )
            }
        }
    }

    fn cache_for(&self, guard_name: &str, cfg: &AsyncGuardConfig) -> Arc<TtlCache> {
        self.caches
            .entry(guard_name.to_string())
            .or_insert_with(|| Arc::new(TtlCache::new(cfg.cache_max_size_bytes.max(1024))))
            .clone()
    }
}

fn fallback(
    guard: &str,
    cfg: &AsyncGuardConfig,
    kind: AsyncGuardErrorKind,
    message: &str,
    cache_key: Option<&str>,
    cache: Arc<TtlCache>,
) -> GuardResult {
    let detail = serde_json::json!({
        "async_error": {
            "kind": format!("{:?}", kind),
            "message": message,
        }
    });

    match cfg.on_timeout {
        TimeoutBehavior::Allow => GuardResult::allow(guard).with_details(detail),
        TimeoutBehavior::Warn => {
            GuardResult::warn(guard, format!("Async guard error: {}", message)).with_details(detail)
        }
        TimeoutBehavior::Deny => GuardResult::block(
            guard,
            Severity::Error,
            format!("Async guard error: {}", message),
        )
        .with_details(detail),
        TimeoutBehavior::Defer => {
            if let Some(key) = cache_key {
                if let Some(mut cached) = cache.get_guard_result(key) {
                    cached.details = Some(merge_details(
                        cached.details,
                        serde_json::json!({ "cache": "defer_hit" }),
                    ));
                    return cached;
                }
            }
            GuardResult::warn(guard, "Deferred async guard had no cached result")
                .with_details(detail)
        }
    }
}

fn merge_details(
    existing: Option<serde_json::Value>,
    extra: serde_json::Value,
) -> serde_json::Value {
    match existing {
        None => extra,
        Some(mut a) => match extra {
            serde_json::Value::Object(b_obj) => {
                if let serde_json::Value::Object(ref mut a_obj) = a {
                    for (k, v) in b_obj {
                        a_obj.insert(k, v);
                    }
                    a
                } else {
                    serde_json::json!({ "details": a, "extra": serde_json::Value::Object(b_obj) })
                }
            }
            b => serde_json::json!({ "details": a, "extra": b }),
        },
    }
}
