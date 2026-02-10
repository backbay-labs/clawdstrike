import type { PolicyEvent } from '@clawdstrike/adapter-core';

import type { AsyncExecutionMode, TimeoutBehavior } from '../policy/schema.js';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface GuardResult {
  allowed: boolean;
  guard: string;
  severity: Severity;
  message: string;
  details?: Record<string, unknown>;
}

export interface RateLimitConfig {
  requestsPerSecond: number;
  burst: number;
}

export interface CircuitBreakerConfig {
  failureThreshold: number;
  resetTimeoutMs: number;
  successThreshold: number;
}

export interface RetryConfig {
  maxRetries: number;
  initialBackoffMs: number;
  maxBackoffMs: number;
  multiplier: number;
}

export interface AsyncGuardConfig {
  timeoutMs: number;
  onTimeout: TimeoutBehavior;
  executionMode: AsyncExecutionMode;
  cacheEnabled: boolean;
  cacheTtlSeconds: number;
  cacheMaxSizeBytes: number;
  rateLimit?: RateLimitConfig;
  circuitBreaker?: CircuitBreakerConfig;
  retry?: RetryConfig;
}

export type AsyncGuardErrorKind = 'timeout' | 'circuit_open' | 'http' | 'parse' | 'other';

export class AsyncGuardError extends Error {
  readonly kind: AsyncGuardErrorKind;
  readonly status?: number;

  constructor(kind: AsyncGuardErrorKind, message: string, status?: number) {
    super(message);
    this.kind = kind;
    this.status = status;
  }
}

export interface HttpRequestPolicy {
  allowedHosts?: string[];
  allowInsecureHttpForLoopback?: boolean;
  maxRequestSizeBytes?: number;
  maxResponseSizeBytes?: number;
  timeoutMs?: number;
  allowedMethods?: string[];
}

export interface HttpResponse {
  status: number;
  json: unknown;
  audit: {
    method: string;
    url: string;
    status: number;
    durationMs: number;
  };
}

export interface HttpClient {
  requestJson(
    guard: string,
    method: string,
    url: string,
    headers: Record<string, string>,
    body: unknown | null,
    policy: HttpRequestPolicy,
    signal?: AbortSignal,
  ): Promise<HttpResponse>;
}

export interface AsyncGuard {
  name: string;
  config: AsyncGuardConfig;

  handles(event: PolicyEvent): boolean;
  cacheKey(event: PolicyEvent): string | null;

  checkUncached(event: PolicyEvent, http: HttpClient, signal?: AbortSignal): Promise<GuardResult>;
}

