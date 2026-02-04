import type { PolicyEvent } from '@clawdstrike/adapter-core';

import { GuardCache } from './cache.js';
import { CircuitBreaker } from './circuit-breaker.js';
import { FetchHttpClient } from './http.js';
import { TokenBucket } from './rate-limit.js';
import { retry } from './retry.js';
import type { AsyncGuard, AsyncGuardConfig, GuardResult, HttpClient } from './types.js';

export class AsyncGuardRuntime {
  private readonly http: HttpClient;
  private readonly caches = new Map<string, GuardCache>();
  private readonly limiters = new Map<string, TokenBucket>();
  private readonly breakers = new Map<string, CircuitBreaker>();

  constructor(http: HttpClient = new FetchHttpClient()) {
    this.http = http;
  }

  async evaluateAsyncGuards(
    guards: Array<{ index: number; guard: AsyncGuard }>,
    event: PolicyEvent,
  ): Promise<GuardResult[]> {
    const out: GuardResult[] = [];

    const sequential: Array<{ index: number; guard: AsyncGuard }> = [];
    const parallel: Array<{ index: number; guard: AsyncGuard }> = [];
    const background: Array<{ index: number; guard: AsyncGuard }> = [];

    for (const g of guards) {
      if (!g.guard.handles(event)) continue;
      if (g.guard.config.executionMode === 'sequential') sequential.push(g);
      else if (g.guard.config.executionMode === 'parallel') parallel.push(g);
      else background.push(g);
    }

    sequential.sort((a, b) => a.index - b.index);
    for (const g of sequential) {
      const res = await this.evaluateOne(g.guard, event);
      out.push(res);
      if (!res.allowed) return out;
    }

    parallel.sort((a, b) => a.index - b.index);
    if (parallel.length > 0) {
      const byIndex = new Map<number, GuardResult>();
      const controller = new AbortController();
      let denied = false;

      const pending = new Map<number, Promise<{ index: number; res: GuardResult }>>();
      for (const g of parallel) {
        const p = this.evaluateOne(g.guard, event, controller.signal).then((res) => ({
          index: g.index,
          res,
        }));
        pending.set(g.index, p);
      }

      while (pending.size > 0) {
        const { index, res } = await Promise.race(pending.values());
        pending.delete(index);
        byIndex.set(index, res);
        if (!res.allowed) {
          denied = true;
          controller.abort();
          break;
        }
      }

      for (const g of parallel) {
        const res = byIndex.get(g.index);
        if (res) {
          out.push(res);
          if (!res.allowed) return out;
        } else {
          out.push({
            allowed: true,
            guard: g.guard.name,
            severity: 'medium',
            message: 'Canceled due to earlier deny in parallel group',
            details: { canceled: true },
          });
        }
      }

      if (denied) return out;
    }

    background.sort((a, b) => a.index - b.index);
    if (background.length > 0) {
      for (const g of background) {
        void this.evaluateOne(g.guard, event).then((res) => {
          if (!res.allowed) {
            // Background mode never changes the immediate decision.
            // Emit an alert-style log for visibility.
            // eslint-disable-next-line no-console
            console.warn(
              `[clawdstrike] background async guard would have denied: ${g.guard.name}: ${res.message}`,
            );
          }
        });

        out.push({
          allowed: true,
          guard: g.guard.name,
          severity: 'low',
          message: 'Allowed',
          details: { background: true, note: 'scheduled' },
        });
      }
    }

    return out;
  }

  private async evaluateOne(guard: AsyncGuard, event: PolicyEvent, signal?: AbortSignal): Promise<GuardResult> {
    const cfg = guard.config;

    const cacheKey = guard.cacheKey(event);
    if (cacheKey && cfg.cacheEnabled) {
      const cached = this.cacheFor(guard.name, cfg).get(cacheKey);
      if (cached) {
        return withMergedDetails(cached, { cache: 'hit' });
      }
    }

    if (cfg.circuitBreaker) {
      const breaker = this.breakerFor(guard.name, cfg);
      const ok = breaker.beforeRequest();
      if (!ok.ok) {
        return this.fallback(guard, cfg, 'circuit_open', 'circuit breaker open', cacheKey);
      }
    }

    if (cfg.rateLimit) {
      await this.limiterFor(guard.name, cfg).acquire(signal);
    }

    const controller = new AbortController();
    const combined = signal ? anySignal([signal, controller.signal]) : controller;

    const timeoutId = setTimeout(() => controller.abort(), cfg.timeoutMs);
    timeoutId.unref?.();

    try {
      const attempt = async () => {
        if (cfg.retry) {
          return await retry(
            cfg.retry,
            async () => await guard.checkUncached(event, this.http, combined.signal),
            combined.signal,
          );
        }
        return await guard.checkUncached(event, this.http, combined.signal);
      };

      const res = await attempt();

      if (cacheKey && cfg.cacheEnabled) {
        this.cacheFor(guard.name, cfg).set(cacheKey, res);
      }

      if (cfg.circuitBreaker) {
        this.breakerFor(guard.name, cfg).recordSuccess();
      }

      return res;
    } catch (err) {
      if (cfg.circuitBreaker) {
        this.breakerFor(guard.name, cfg).recordFailure();
      }

      const message = err instanceof Error ? err.message : String(err);
      const kind = combined.signal.aborted ? 'timeout' : 'other';
      return this.fallback(guard, cfg, kind, message, cacheKey);
    } finally {
      clearTimeout(timeoutId);
    }
  }

  private cacheFor(guardName: string, cfg: AsyncGuardConfig): GuardCache {
    const existing = this.caches.get(guardName);
    if (existing) return existing;
    const cache = new GuardCache(cfg.cacheMaxSizeBytes, cfg.cacheTtlSeconds);
    this.caches.set(guardName, cache);
    return cache;
  }

  private limiterFor(guardName: string, cfg: AsyncGuardConfig): TokenBucket {
    const existing = this.limiters.get(guardName);
    if (existing) return existing;
    const rl = cfg.rateLimit ?? { requestsPerSecond: 0, burst: 1 };
    const limiter = new TokenBucket(rl.requestsPerSecond, Math.max(1, rl.burst));
    this.limiters.set(guardName, limiter);
    return limiter;
  }

  private breakerFor(guardName: string, cfg: AsyncGuardConfig): CircuitBreaker {
    const existing = this.breakers.get(guardName);
    if (existing) return existing;
    const cb = cfg.circuitBreaker ?? { failureThreshold: 5, resetTimeoutMs: 30_000, successThreshold: 2 };
    const breaker = new CircuitBreaker(cb.failureThreshold, cb.resetTimeoutMs, cb.successThreshold);
    this.breakers.set(guardName, breaker);
    return breaker;
  }

  private fallback(
    guard: AsyncGuard,
    cfg: AsyncGuardConfig,
    kind: string,
    message: string,
    cacheKey: string | null,
  ): GuardResult {
    const details = { async_error: { kind, message } };

    if (cfg.onTimeout === 'allow') {
      return { allowed: true, guard: guard.name, severity: 'low', message: 'Allowed', details };
    }

    if (cfg.onTimeout === 'deny') {
      return { allowed: false, guard: guard.name, severity: 'high', message: `Async guard error: ${message}`, details };
    }

    if (cfg.onTimeout === 'defer') {
      if (cacheKey) {
        const cached = this.cacheFor(guard.name, cfg).get(cacheKey);
        if (cached) return withMergedDetails(cached, { cache: 'defer_hit' });
      }
      return {
        allowed: true,
        guard: guard.name,
        severity: 'medium',
        message: 'Deferred async guard had no cached result',
        details,
      };
    }

    // warn (default)
    return { allowed: true, guard: guard.name, severity: 'medium', message: `Async guard error: ${message}`, details };
  }
}

function withMergedDetails(result: GuardResult, extra: Record<string, unknown>): GuardResult {
  const details = result.details ? { ...result.details, ...extra } : extra;
  return { ...result, details };
}

function anySignal(signals: AbortSignal[]): AbortController {
  const controller = new AbortController();
  const onAbort = () => controller.abort();
  for (const s of signals) {
    if (s.aborted) {
      controller.abort();
      return controller;
    }
    s.addEventListener('abort', onAbort, { once: true });
  }
  return controller;
}
