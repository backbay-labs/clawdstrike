export type PolicySchemaVersion = '1.1.0';

export type TimeoutBehavior = 'allow' | 'deny' | 'warn' | 'defer';
export type AsyncExecutionMode = 'parallel' | 'sequential' | 'background';

export type MergeStrategy = 'replace' | 'merge' | 'deep_merge';

export interface AsyncCachePolicyConfig {
  enabled?: boolean;
  ttl_seconds?: number;
  max_size_mb?: number;
}

export interface AsyncRateLimitPolicyConfig {
  requests_per_second?: number;
  requests_per_minute?: number;
  burst?: number;
}

export interface AsyncCircuitBreakerPolicyConfig {
  failure_threshold?: number;
  reset_timeout_ms?: number;
  success_threshold?: number;
}

export interface AsyncRetryPolicyConfig {
  max_retries?: number;
  initial_backoff_ms?: number;
  max_backoff_ms?: number;
  multiplier?: number;
}

export interface AsyncGuardPolicyConfig {
  timeout_ms?: number;
  on_timeout?: TimeoutBehavior;
  execution_mode?: AsyncExecutionMode;
  cache?: AsyncCachePolicyConfig;
  rate_limit?: AsyncRateLimitPolicyConfig;
  circuit_breaker?: AsyncCircuitBreakerPolicyConfig;
  retry?: AsyncRetryPolicyConfig;
}

export interface CustomGuardSpec {
  package: string;
  registry?: string;
  version?: string;
  enabled?: boolean;
  config?: Record<string, unknown>;
  async?: AsyncGuardPolicyConfig;
}

export interface GuardConfigs {
  custom?: CustomGuardSpec[];
  // Other guard configs exist in Rust, but threat-intel MVP is custom-only for TS.
  [key: string]: unknown;
}

export interface PolicySettings {
  fail_fast?: boolean;
  verbose_logging?: boolean;
  session_timeout_secs?: number;
}

export interface PolicyCustomGuardSpec {
  id: string;
  enabled?: boolean;
  config?: Record<string, unknown>;
}

export interface Policy {
  version?: string;
  name?: string;
  description?: string;
  extends?: string;
  merge_strategy?: MergeStrategy;
  guards?: GuardConfigs;
  custom_guards?: PolicyCustomGuardSpec[];
  settings?: PolicySettings;
}
