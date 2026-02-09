import type { AsyncGuardPolicyConfig } from '../policy/schema.js';

import type { AsyncGuardConfig, CircuitBreakerConfig, RateLimitConfig, RetryConfig } from './types.js';

const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_ON_TIMEOUT = 'warn' as const;
const DEFAULT_EXECUTION_MODE = 'parallel' as const;
const DEFAULT_CACHE_TTL_SECONDS = 3_600;
const DEFAULT_CACHE_MAX_SIZE_MB = 64;

export function buildAsyncGuardConfig(policy?: AsyncGuardPolicyConfig): AsyncGuardConfig {
  const timeoutMs = policy?.timeout_ms ?? DEFAULT_TIMEOUT_MS;
  const onTimeout = policy?.on_timeout ?? DEFAULT_ON_TIMEOUT;
  const executionMode = policy?.execution_mode ?? DEFAULT_EXECUTION_MODE;

  const cacheEnabled = policy?.cache?.enabled ?? true;
  const cacheTtlSeconds = policy?.cache?.ttl_seconds ?? DEFAULT_CACHE_TTL_SECONDS;
  const cacheMaxSizeBytes = (policy?.cache?.max_size_mb ?? DEFAULT_CACHE_MAX_SIZE_MB) * 1024 * 1024;

  const rateLimit = buildRateLimit(policy?.rate_limit);
  const circuitBreaker = buildCircuitBreaker(policy?.circuit_breaker);
  const retry = buildRetry(policy?.retry);

  return {
    timeoutMs,
    onTimeout,
    executionMode,
    cacheEnabled,
    cacheTtlSeconds,
    cacheMaxSizeBytes,
    rateLimit,
    circuitBreaker,
    retry,
  };
}

function buildRateLimit(policy: AsyncGuardPolicyConfig['rate_limit']): RateLimitConfig | undefined {
  if (!policy) return undefined;
  const rps =
    typeof policy.requests_per_second === 'number'
      ? policy.requests_per_second
      : typeof policy.requests_per_minute === 'number'
        ? policy.requests_per_minute / 60
        : undefined;
  if (!rps || rps <= 0) return undefined;
  const burst = Math.max(1, Math.trunc(policy.burst ?? 1));
  return { requestsPerSecond: rps, burst };
}

function buildCircuitBreaker(
  policy: AsyncGuardPolicyConfig['circuit_breaker'],
): CircuitBreakerConfig | undefined {
  if (!policy) return undefined;
  const failureThreshold = Math.max(1, Math.trunc(policy.failure_threshold ?? 5));
  const resetTimeoutMs = Math.max(1000, Math.trunc(policy.reset_timeout_ms ?? 30_000));
  const successThreshold = Math.max(1, Math.trunc(policy.success_threshold ?? 2));
  return { failureThreshold, resetTimeoutMs, successThreshold };
}

function buildRetry(policy: AsyncGuardPolicyConfig['retry']): RetryConfig | undefined {
  if (!policy) return undefined;
  const multiplier = Math.max(1, typeof policy.multiplier === 'number' ? policy.multiplier : 2);
  const maxRetries = Math.max(0, Math.trunc(policy.max_retries ?? 2));
  const initialBackoffMs = Math.max(100, Math.trunc(policy.initial_backoff_ms ?? 250));
  const maxBackoffMs = Math.max(100, Math.trunc(policy.max_backoff_ms ?? 2_000));
  return { multiplier, maxRetries, initialBackoffMs, maxBackoffMs };
}

