//! Custom-guard, async-config, and provider-spec validators.

use crate::error::PolicyFieldError;

use super::super::{AsyncGuardPolicyConfig, CustomGuardSpec};
use super::{validate_placeholders_in_json, validate_placeholders_in_string};

pub(in crate::policy) fn validate_custom_guards(
    errors: &mut Vec<PolicyFieldError>,
    guards: &[CustomGuardSpec],
    require_env: bool,
) {
    for (idx, spec) in guards.iter().enumerate() {
        let base = format!("guards.custom[{}]", idx);

        validate_placeholders_in_string(
            errors,
            &format!("{base}.package"),
            &spec.package,
            spec.enabled,
            require_env,
        );
        if let Some(v) = spec.version.as_ref() {
            validate_placeholders_in_string(
                errors,
                &format!("{base}.version"),
                v,
                spec.enabled,
                require_env,
            );
        }
        if let Some(r) = spec.registry.as_ref() {
            validate_placeholders_in_string(
                errors,
                &format!("{base}.registry"),
                r,
                spec.enabled,
                require_env,
            );
        }

        validate_placeholders_in_json(
            errors,
            &format!("{base}.config"),
            &spec.config,
            spec.enabled,
            require_env,
        );

        if let Some(async_cfg) = spec.async_config.as_ref() {
            validate_async_policy_config(errors, &format!("{base}.async"), async_cfg);
        }

        if !spec.enabled {
            continue;
        }

        match spec.package.as_str() {
            "clawdstrike-virustotal" => validate_virustotal_spec(errors, &base, &spec.config),
            "clawdstrike-safe-browsing" => validate_safe_browsing_spec(errors, &base, &spec.config),
            "clawdstrike-snyk" => validate_snyk_spec(errors, &base, &spec.config),
            "clawdstrike-spider-sense" => {
                // Spider-Sense config is validated at guard construction time (fail-closed).
                // Deprecated: use guards.spider_sense instead of guards.custom.
            }
            other => errors.push(PolicyFieldError::new(
                format!("{base}.package"),
                format!("unsupported custom guard package: {}", other),
            )),
        }
    }
}

fn validate_async_policy_config(
    errors: &mut Vec<PolicyFieldError>,
    base: &str,
    cfg: &AsyncGuardPolicyConfig,
) {
    if let Some(timeout_ms) = cfg.timeout_ms {
        if !(100..=300_000).contains(&timeout_ms) {
            errors.push(PolicyFieldError::new(
                format!("{}.timeout_ms", base),
                "timeout_ms must be between 100 and 300000".to_string(),
            ));
        }
    }

    if let Some(cache) = cfg.cache.as_ref() {
        if let Some(ttl) = cache.ttl_seconds {
            if ttl == 0 {
                errors.push(PolicyFieldError::new(
                    format!("{}.cache.ttl_seconds", base),
                    "ttl_seconds must be >= 1".to_string(),
                ));
            }
        }
        if let Some(max) = cache.max_size_mb {
            if max == 0 {
                errors.push(PolicyFieldError::new(
                    format!("{}.cache.max_size_mb", base),
                    "max_size_mb must be >= 1".to_string(),
                ));
            }
        }
    }

    if let Some(rl) = cfg.rate_limit.as_ref() {
        if let Some(rps) = rl.requests_per_second {
            if rps <= 0.0 {
                errors.push(PolicyFieldError::new(
                    format!("{}.rate_limit.requests_per_second", base),
                    "requests_per_second must be > 0".to_string(),
                ));
            }
        }
        if let Some(rpm) = rl.requests_per_minute {
            if rpm <= 0.0 {
                errors.push(PolicyFieldError::new(
                    format!("{}.rate_limit.requests_per_minute", base),
                    "requests_per_minute must be > 0".to_string(),
                ));
            }
        }
        if rl.requests_per_second.is_some() && rl.requests_per_minute.is_some() {
            errors.push(PolicyFieldError::new(
                format!("{}.rate_limit", base),
                "specify only one of requests_per_second or requests_per_minute".to_string(),
            ));
        }
        if let Some(burst) = rl.burst {
            if burst == 0 {
                errors.push(PolicyFieldError::new(
                    format!("{}.rate_limit.burst", base),
                    "burst must be >= 1".to_string(),
                ));
            }
        }
    }

    if let Some(cb) = cfg.circuit_breaker.as_ref() {
        if let Some(thr) = cb.failure_threshold {
            if thr == 0 {
                errors.push(PolicyFieldError::new(
                    format!("{}.circuit_breaker.failure_threshold", base),
                    "failure_threshold must be >= 1".to_string(),
                ));
            }
        }
        if let Some(ms) = cb.reset_timeout_ms {
            if ms < 1000 {
                errors.push(PolicyFieldError::new(
                    format!("{}.circuit_breaker.reset_timeout_ms", base),
                    "reset_timeout_ms must be >= 1000".to_string(),
                ));
            }
        }
        if let Some(thr) = cb.success_threshold {
            if thr == 0 {
                errors.push(PolicyFieldError::new(
                    format!("{}.circuit_breaker.success_threshold", base),
                    "success_threshold must be >= 1".to_string(),
                ));
            }
        }
    }

    if let Some(retry) = cfg.retry.as_ref() {
        if let Some(mult) = retry.multiplier {
            if mult < 1.0 {
                errors.push(PolicyFieldError::new(
                    format!("{}.retry.multiplier", base),
                    "multiplier must be >= 1".to_string(),
                ));
            }
        }
        if let Some(ms) = retry.initial_backoff_ms {
            if ms < 100 {
                errors.push(PolicyFieldError::new(
                    format!("{}.retry.initial_backoff_ms", base),
                    "initial_backoff_ms must be >= 100".to_string(),
                ));
            }
        }
        if let Some(ms) = retry.max_backoff_ms {
            if ms < 100 {
                errors.push(PolicyFieldError::new(
                    format!("{}.retry.max_backoff_ms", base),
                    "max_backoff_ms must be >= 100".to_string(),
                ));
            }
        }
        if let (Some(init), Some(max)) = (retry.initial_backoff_ms, retry.max_backoff_ms) {
            if max < init {
                errors.push(PolicyFieldError::new(
                    format!("{}.retry.max_backoff_ms", base),
                    "max_backoff_ms must be >= initial_backoff_ms".to_string(),
                ));
            }
        }
    }
}

fn require_config_string(
    errors: &mut Vec<PolicyFieldError>,
    base: &str,
    config: &serde_json::Value,
    key: &str,
) -> Option<String> {
    let serde_json::Value::Object(map) = config else {
        errors.push(PolicyFieldError::new(
            format!("{base}.config"),
            "config must be an object".to_string(),
        ));
        return None;
    };

    match map.get(key) {
        Some(serde_json::Value::String(s)) if !s.trim().is_empty() => Some(s.clone()),
        _ => {
            errors.push(PolicyFieldError::new(
                format!("{base}.config.{key}"),
                "missing/invalid required string".to_string(),
            ));
            None
        }
    }
}

fn validate_virustotal_spec(
    errors: &mut Vec<PolicyFieldError>,
    base: &str,
    config: &serde_json::Value,
) {
    let _ = require_config_string(errors, base, config, "api_key");
}

fn validate_safe_browsing_spec(
    errors: &mut Vec<PolicyFieldError>,
    base: &str,
    config: &serde_json::Value,
) {
    let _ = require_config_string(errors, base, config, "api_key");
    let _ = require_config_string(errors, base, config, "client_id");
}

fn validate_snyk_spec(errors: &mut Vec<PolicyFieldError>, base: &str, config: &serde_json::Value) {
    let _ = require_config_string(errors, base, config, "api_token");
    let _ = require_config_string(errors, base, config, "org_id");
}
