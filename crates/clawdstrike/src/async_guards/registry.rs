use std::sync::Arc;
use std::time::Duration;

use crate::async_guards::threat_intel::{
    SafeBrowsingGuard, SafeBrowsingPolicyConfig, SnykGuard, SnykPolicyConfig, VirusTotalGuard,
    VirusTotalPolicyConfig,
};
use crate::async_guards::types::{
    AsyncGuard, AsyncGuardConfig, CircuitBreakerConfig, RateLimitConfig, RetryConfig,
};
use crate::error::{Error, Result};
use crate::policy::{
    AsyncCircuitBreakerPolicyConfig, AsyncExecutionMode, AsyncGuardPolicyConfig,
    AsyncRateLimitPolicyConfig, AsyncRetryPolicyConfig, CustomGuardSpec, Policy, TimeoutBehavior,
};

const DEFAULT_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_CACHE_TTL_SECONDS: u64 = 3_600;
const DEFAULT_CACHE_MAX_SIZE_MB: u64 = 64;

pub fn build_async_guards(policy: &Policy) -> Result<Vec<Arc<dyn AsyncGuard>>> {
    let mut out: Vec<Arc<dyn AsyncGuard>> = Vec::new();

    for spec in &policy.guards.custom {
        if !spec.enabled {
            continue;
        }

        out.push(build_guard(spec)?);
    }

    Ok(out)
}

fn build_guard(spec: &CustomGuardSpec) -> Result<Arc<dyn AsyncGuard>> {
    let async_cfg = async_config_for_spec(spec.async_config.as_ref())?;
    let config = resolve_placeholders_in_json(spec.config.clone())?;

    match spec.package.as_str() {
        "clawdstrike-virustotal" => {
            let typed: VirusTotalPolicyConfig = serde_json::from_value(config)?;
            Ok(Arc::new(VirusTotalGuard::new(typed, async_cfg)))
        }
        "clawdstrike-safe-browsing" => {
            let typed: SafeBrowsingPolicyConfig = serde_json::from_value(config)?;
            Ok(Arc::new(SafeBrowsingGuard::new(typed, async_cfg)))
        }
        "clawdstrike-snyk" => {
            let typed: SnykPolicyConfig = serde_json::from_value(config)?;
            Ok(Arc::new(SnykGuard::new(typed, async_cfg)))
        }
        other => Err(Error::ConfigError(format!(
            "unsupported custom guard package: {other}"
        ))),
    }
}

fn async_config_for_spec(spec: Option<&AsyncGuardPolicyConfig>) -> Result<AsyncGuardConfig> {
    let timeout = Duration::from_millis(
        spec.and_then(|c| c.timeout_ms)
            .unwrap_or(DEFAULT_TIMEOUT_MS),
    );
    let on_timeout = spec
        .and_then(|c| c.on_timeout.clone())
        .unwrap_or(TimeoutBehavior::Warn);
    let execution_mode = spec
        .and_then(|c| c.execution_mode.clone())
        .unwrap_or(AsyncExecutionMode::Parallel);

    let cache_enabled = spec
        .and_then(|c| c.cache.as_ref())
        .and_then(|c| c.enabled)
        .unwrap_or(true);
    let cache_ttl = Duration::from_secs(
        spec.and_then(|c| c.cache.as_ref())
            .and_then(|c| c.ttl_seconds)
            .unwrap_or(DEFAULT_CACHE_TTL_SECONDS),
    );
    let cache_max_size_bytes: usize = (spec
        .and_then(|c| c.cache.as_ref())
        .and_then(|c| c.max_size_mb)
        .unwrap_or(DEFAULT_CACHE_MAX_SIZE_MB)
        .saturating_mul(1024)
        .saturating_mul(1024)) as usize;

    let rate_limit = spec
        .and_then(|c| c.rate_limit.as_ref())
        .and_then(rate_limit_for_policy);
    let circuit_breaker = spec
        .and_then(|c| c.circuit_breaker.as_ref())
        .map(circuit_breaker_for_policy);
    let retry = spec.and_then(|c| c.retry.as_ref()).map(retry_for_policy);

    Ok(AsyncGuardConfig {
        timeout,
        on_timeout,
        execution_mode,
        cache_enabled,
        cache_ttl,
        cache_max_size_bytes,
        rate_limit,
        circuit_breaker,
        retry,
    })
}

fn rate_limit_for_policy(cfg: &AsyncRateLimitPolicyConfig) -> Option<RateLimitConfig> {
    let requests_per_second = if let Some(rps) = cfg.requests_per_second {
        rps
    } else if let Some(rpm) = cfg.requests_per_minute {
        rpm / 60.0
    } else {
        return None;
    };

    let burst = cfg.burst.unwrap_or(1).max(1);

    Some(RateLimitConfig {
        requests_per_second,
        burst,
    })
}

fn circuit_breaker_for_policy(cfg: &AsyncCircuitBreakerPolicyConfig) -> CircuitBreakerConfig {
    CircuitBreakerConfig {
        failure_threshold: cfg.failure_threshold.unwrap_or(5).max(1),
        reset_timeout: Duration::from_millis(cfg.reset_timeout_ms.unwrap_or(30_000).max(1000)),
        success_threshold: cfg.success_threshold.unwrap_or(2).max(1),
    }
}

fn retry_for_policy(cfg: &AsyncRetryPolicyConfig) -> RetryConfig {
    RetryConfig {
        max_retries: cfg.max_retries.unwrap_or(2),
        initial_backoff: Duration::from_millis(cfg.initial_backoff_ms.unwrap_or(250).max(100)),
        max_backoff: Duration::from_millis(cfg.max_backoff_ms.unwrap_or(2_000).max(100)),
        multiplier: cfg.multiplier.unwrap_or(2.0).max(1.0),
    }
}

fn env_var_for_placeholder(raw: &str) -> std::result::Result<String, String> {
    if let Some(rest) = raw.strip_prefix("secrets.") {
        if rest.is_empty() {
            return Err("placeholder ${secrets.} is invalid".to_string());
        }
        return Ok(rest.to_string());
    }

    if raw.is_empty() {
        return Err("placeholder ${} is invalid".to_string());
    }

    Ok(raw.to_string())
}

fn resolve_placeholders_in_string(input: &str) -> Result<String> {
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    while let Some(start_rel) = input[i..].find("${") {
        let start = i + start_rel;
        let after = start + 2;

        let Some(end_rel) = input[after..].find('}') else {
            break;
        };
        let end = after + end_rel;

        out.push_str(&input[i..start]);

        let raw = &input[after..end];
        let env_name = env_var_for_placeholder(raw)
            .map_err(|msg| Error::ConfigError(format!("invalid placeholder: {msg}")))?;
        let value = std::env::var(&env_name).map_err(|_| {
            Error::ConfigError(format!("missing environment variable {}", env_name))
        })?;
        out.push_str(&value);

        i = end + 1;
    }

    out.push_str(&input[i..]);
    Ok(out)
}

fn resolve_placeholders_in_json_inner(value: serde_json::Value) -> Result<serde_json::Value> {
    match value {
        serde_json::Value::String(s) => Ok(serde_json::Value::String(
            resolve_placeholders_in_string(&s)?,
        )),
        serde_json::Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(resolve_placeholders_in_json_inner(item)?);
            }
            Ok(serde_json::Value::Array(out))
        }
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                out.insert(k, resolve_placeholders_in_json_inner(v)?);
            }
            Ok(serde_json::Value::Object(out))
        }
        other => Ok(other),
    }
}

fn resolve_placeholders_in_json(value: serde_json::Value) -> Result<serde_json::Value> {
    resolve_placeholders_in_json_inner(value)
}
