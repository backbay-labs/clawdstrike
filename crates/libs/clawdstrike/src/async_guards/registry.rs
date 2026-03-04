use std::sync::Arc;
use std::time::Duration;

use crate::async_guards::threat_intel::{
    SafeBrowsingGuard, SafeBrowsingPolicyConfig, SnykGuard, SnykPolicyConfig, SpiderSenseGuard,
    SpiderSensePolicyConfig, VirusTotalGuard, VirusTotalPolicyConfig,
};
use crate::async_guards::types::{
    AsyncGuard, AsyncGuardConfig, CircuitBreakerConfig, RateLimitConfig, RetryConfig,
};
use crate::error::{Error, Result};
use crate::placeholders::resolve_placeholders_in_json;
use crate::policy::{
    AsyncCircuitBreakerPolicyConfig, AsyncExecutionMode, AsyncGuardPolicyConfig,
    AsyncRateLimitPolicyConfig, AsyncRetryPolicyConfig, CustomGuardSpec, Policy, TimeoutBehavior,
};

const DEFAULT_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_CACHE_TTL_SECONDS: u64 = 3_600;
const DEFAULT_CACHE_MAX_SIZE_MB: u64 = 64;

pub fn build_async_guards(policy: &Policy) -> Result<Vec<Arc<dyn AsyncGuard>>> {
    let mut out: Vec<Arc<dyn AsyncGuard>> = Vec::new();
    let has_first_class_spider = policy
        .guards
        .spider_sense
        .as_ref()
        .map(|cfg| cfg.enabled)
        .unwrap_or(false);

    // First-class spider_sense field.
    if let Some(ref ss_cfg) = policy.guards.spider_sense {
        if !ss_cfg.enabled {
            tracing::info!("guards.spider_sense disabled by config");
        } else {
            let async_cfg = async_config_for_spec(ss_cfg.async_config.as_ref())?;
            // Resolve env-var placeholders (${VAR}) in the config, matching the
            // guards.custom path which calls resolve_placeholders_in_json.
            let json = serde_json::to_value(ss_cfg)
                .map_err(|e| Error::ConfigError(format!("spider-sense serialize: {e}")))?;
            let resolved = resolve_placeholders_in_json(json)?;
            let resolved_cfg: SpiderSensePolicyConfig = serde_json::from_value(resolved)
                .map_err(|e| Error::ConfigError(format!("spider-sense deserialize: {e}")))?;
            let guard = SpiderSenseGuard::new(resolved_cfg, async_cfg)
                .map_err(|e| Error::ConfigError(format!("spider-sense init: {e}")))?;
            out.push(Arc::new(guard));
        }
    }

    for spec in &policy.guards.custom {
        if !spec.enabled {
            continue;
        }
        if has_first_class_spider && spec.package == "clawdstrike-spider-sense" {
            tracing::warn!(
                "guards.custom[package=\"clawdstrike-spider-sense\"] is ignored because \
                 guards.spider_sense is configured"
            );
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
        "clawdstrike-spider-sense" => {
            tracing::warn!(
                "guards.custom[package=\"clawdstrike-spider-sense\"] is deprecated; \
                 use guards.spider_sense instead"
            );
            let typed: SpiderSensePolicyConfig = serde_json::from_value(config)?;
            let guard = SpiderSenseGuard::new(typed, async_cfg)
                .map_err(|e| Error::ConfigError(format!("spider-sense init: {e}")))?;
            Ok(Arc::new(guard))
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn spider_config() -> SpiderSensePolicyConfig {
        SpiderSensePolicyConfig {
            enabled: true,
            embedding_api_url: "https://api.openai.com/v1/embeddings".to_string(),
            embedding_api_key: "test-key".to_string(),
            embedding_model: "text-embedding-3-small".to_string(),
            similarity_threshold: 0.85,
            ambiguity_band: 0.10,
            top_k: 5,
            pattern_db_path: "builtin:s2bench-v1".to_string(),
            pattern_db_version: None,
            pattern_db_checksum: None,
            pattern_db_signature: None,
            pattern_db_signature_key_id: None,
            pattern_db_public_key: None,
            pattern_db_trust_store_path: None,
            pattern_db_trusted_keys: vec![],
            pattern_db_manifest_path: None,
            pattern_db_manifest_trust_store_path: None,
            pattern_db_manifest_trusted_keys: vec![],
            llm_api_url: None,
            llm_api_key: None,
            llm_model: None,
            llm_prompt_template_id: None,
            llm_prompt_template_version: None,
            llm_timeout_ms: None,
            llm_fail_mode: None,
            async_config: None,
        }
    }

    #[test]
    fn skips_deprecated_custom_spider_when_first_class_present() {
        let mut policy = Policy::default();
        policy.guards.spider_sense = Some(spider_config());
        policy.guards.custom.push(CustomGuardSpec {
            package: "clawdstrike-spider-sense".to_string(),
            registry: None,
            version: None,
            enabled: true,
            config: json!({
                "embedding_api_url": "https://api.openai.com/v1/embeddings",
                "embedding_api_key": "test-key",
                "embedding_model": "text-embedding-3-small",
                "pattern_db_path": "builtin:s2bench-v1",
            }),
            async_config: None,
        });

        let guards = build_async_guards(&policy).expect("build async guards");
        assert_eq!(guards.len(), 1, "custom spider-sense should be skipped");
    }

    #[test]
    fn disabled_first_class_spider_does_not_shadow_custom_spider() {
        let mut policy = Policy::default();
        policy.guards.spider_sense = Some(
            serde_json::from_value(json!({
                "enabled": false
            }))
            .expect("disabled first-class spider config should parse"),
        );
        policy.guards.custom.push(CustomGuardSpec {
            package: "clawdstrike-spider-sense".to_string(),
            registry: None,
            version: None,
            enabled: true,
            config: json!({
                "embedding_api_url": "https://api.openai.com/v1/embeddings",
                "embedding_api_key": "test-key",
                "embedding_model": "text-embedding-3-small",
                "pattern_db_path": "builtin:s2bench-v1",
            }),
            async_config: None,
        });

        let guards = build_async_guards(&policy).expect("build async guards");
        assert_eq!(guards.len(), 1, "custom spider-sense should remain active");
    }
}
