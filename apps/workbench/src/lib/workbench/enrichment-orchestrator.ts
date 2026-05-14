import type { Indicator, EnrichmentResult, ThreatIntelSource } from "@clawdstrike/plugin-sdk";
import {
  getThreatIntelSource,
  getThreatIntelSourcesForIndicator,
} from "./threat-intel-registry";

class TokenBucket {
  private tokens: number;
  private readonly maxTokens: number;
  private lastRefill: number;
  private readonly refillIntervalMs = 60_000; // 1 minute

  constructor(maxPerMinute: number) {
    this.maxTokens = maxPerMinute;
    this.tokens = maxPerMinute;
    this.lastRefill = Date.now();
  }

  tryConsume(): boolean {
    this.refill();
    if (this.tokens > 0) {
      this.tokens--;
      return true;
    }
    return false;
  }

  msUntilToken(): number {
    this.refill();
    if (this.tokens > 0) return 0;
    return this.refillIntervalMs - (Date.now() - this.lastRefill);
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = now - this.lastRefill;
    if (elapsed >= this.refillIntervalMs) {
      const periods = Math.floor(elapsed / this.refillIntervalMs);
      this.tokens = Math.min(this.tokens + periods * this.maxTokens, this.maxTokens);
      this.lastRefill += periods * this.refillIntervalMs;
    }
  }
}

interface CacheEntry {
  result: EnrichmentResult;
  expiresAt: number;
}

function cacheKey(sourceId: string, indicator: Indicator): string {
  return `${sourceId}:${indicator.type}:${indicator.value}`;
}

const MAX_CACHE_SIZE = 10_000;
const CACHE_CLEANUP_INTERVAL_MS = 300_000; // 5 minutes

export interface EnrichOptions {
  /** Restrict enrichment to specific source IDs. */
  sourceIds?: string[];
  /** AbortSignal for cancellation. */
  signal?: AbortSignal;
  /** Callback invoked for each result as it arrives. */
  onResult?: (result: EnrichmentResult) => void;
}

export class EnrichmentOrchestrator {
  private readonly rateLimiters = new Map<string, TokenBucket>();
  private readonly cache = new Map<string, CacheEntry>();
  private readonly cleanupTimer: ReturnType<typeof setInterval>;

  constructor() {
    // Periodically purge expired cache entries to bound memory
    this.cleanupTimer = setInterval(() => {
      this.evictExpiredEntries();
    }, CACHE_CLEANUP_INTERVAL_MS);
  }

  /** Stop the periodic cleanup timer. */
  destroy(): void {
    clearInterval(this.cleanupTimer);
  }

  /**
   * Enrich an indicator across matching or specified sources.
   *
   * - Checks cache before calling source.enrich()
   * - Applies per-source token bucket rate limiting
   * - Supports AbortSignal cancellation
   * - Calls onResult for each result as it arrives
   * - One source failing does not block other sources
   */
  async enrich(
    indicator: Indicator,
    options: EnrichOptions = {},
  ): Promise<EnrichmentResult[]> {
    const { sourceIds, signal, onResult } = options;

    const sources = this.resolveSources(indicator, sourceIds);

    const settled = await Promise.allSettled(
      sources.map((source) =>
        this.enrichFromSource(source, indicator, signal, onResult),
      ),
    );

    const results: EnrichmentResult[] = [];
    for (const outcome of settled) {
      if (outcome.status === "fulfilled" && outcome.value != null) {
        results.push(outcome.value);
      }
    }

    return results;
  }

  /** Clear the entire result cache. */
  clearCache(): void {
    this.cache.clear();
  }

  /** Clear cached entries for a specific source. */
  clearCacheForSource(sourceId: string): void {
    const prefix = `${sourceId}:`;
    for (const key of Array.from(this.cache.keys())) {
      if (key.startsWith(prefix)) {
        this.cache.delete(key);
      }
    }
  }

  private resolveSources(
    indicator: Indicator,
    sourceIds?: string[],
  ): ThreatIntelSource[] {
    if (sourceIds && sourceIds.length > 0) {
      const resolved: ThreatIntelSource[] = [];
      for (const id of sourceIds) {
        const source = getThreatIntelSource(id);
        if (source) {
          resolved.push(source);
        }
      }
      return resolved;
    }
    return getThreatIntelSourcesForIndicator(indicator.type);
  }

  private async enrichFromSource(
    source: ThreatIntelSource,
    indicator: Indicator,
    signal?: AbortSignal,
    onResult?: (result: EnrichmentResult) => void,
  ): Promise<EnrichmentResult | null> {
    if (signal?.aborted) {
      return null;
    }

    const key = cacheKey(source.id, indicator);
    const cached = this.cache.get(key);
    if (cached && Date.now() < cached.expiresAt) {
      onResult?.(cached.result);
      return cached.result;
    }

    let bucket = this.rateLimiters.get(source.id);
    if (!bucket) {
      bucket = new TokenBucket(source.rateLimit.maxPerMinute);
      this.rateLimiters.set(source.id, bucket);
    }

    if (!bucket.tryConsume()) {
      const waitMs = bucket.msUntilToken();
      if (waitMs > 0) {
        await this.waitWithAbort(waitMs, signal);
        if (signal?.aborted) {
          return null;
        }
        if (!bucket.tryConsume()) {
          return null; // Still no token available
        }
      }
    }

    if (signal?.aborted) {
      return null;
    }

    try {
      const result = await source.enrich(indicator);

      this.cache.set(key, {
        result,
        expiresAt: Date.now() + result.cacheTtlMs,
      });

      if (this.cache.size > MAX_CACHE_SIZE) {
        this.evictOldestEntries(this.cache.size - MAX_CACHE_SIZE);
      }

      onResult?.(result);
      return result;
    } catch (err: unknown) {
      console.error(
        `[EnrichmentOrchestrator] Source ${source.id} failed for ${indicator.type}:${indicator.value}:`,
        err instanceof Error ? err.message : String(err),
      );
      return null;
    }
  }

  /** Remove the N oldest (first-inserted) cache entries. */
  private evictOldestEntries(count: number): void {
    const keys = this.cache.keys();
    for (let i = 0; i < count; i++) {
      const next = keys.next();
      if (next.done) break;
      this.cache.delete(next.value);
    }
  }

  /** Remove all expired cache entries. */
  private evictExpiredEntries(): void {
    const now = Date.now();
    for (const [key, entry] of this.cache) {
      if (now >= entry.expiresAt) {
        this.cache.delete(key);
      }
    }
  }

  private waitWithAbort(ms: number, signal?: AbortSignal): Promise<void> {
    return new Promise<void>((resolve) => {
      if (signal?.aborted) {
        resolve();
        return;
      }

      const timer = setTimeout(() => {
        resolve();
      }, ms);

      if (signal) {
        const onAbort = () => {
          clearTimeout(timer);
          resolve();
        };
        signal.addEventListener("abort", onAbort, { once: true });
      }
    });
  }
}

/** Singleton orchestrator instance. */
export const enrichmentOrchestrator = new EnrichmentOrchestrator();
