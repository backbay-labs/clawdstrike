import type { RetryConfig } from './types.js';
import { sleep } from './util.js';

export async function retry<T>(
  cfg: RetryConfig,
  fn: (attempt: number, signal?: AbortSignal) => Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await fn(attempt, signal);
    } catch (err) {
      if (attempt >= cfg.maxRetries) {
        throw err;
      }
      const backoffMs = backoffForAttempt(cfg, attempt);
      await sleep(backoffMs, signal);
    }
  }
}

function backoffForAttempt(cfg: RetryConfig, attempt: number): number {
  const base = Math.max(0, cfg.initialBackoffMs);
  const mult = Math.max(1, cfg.multiplier);
  const scaled = base * Math.pow(mult, attempt);
  const capped = Math.min(scaled, Math.max(cfg.maxBackoffMs, base));
  const jitterMs = (attempt * 17) % 97;
  return capped + jitterMs;
}

