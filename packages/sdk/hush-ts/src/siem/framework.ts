import type { SecurityEvent } from "./types";

export enum SchemaFormat {
  ECS = "ecs",
  CEF = "cef",
  OCSF = "ocsf",
  Native = "native",
}

export interface RetryConfig {
  maxRetries: number;
  initialBackoffMs: number;
  maxBackoffMs: number;
  backoffMultiplier: number;
}

export interface RateLimitConfig {
  requestsPerSecond: number;
  burstSize: number;
}

export interface ExporterConfig {
  batchSize: number;
  flushIntervalMs: number;
  retry: RetryConfig;
  rateLimit?: RateLimitConfig;
}

export interface NormalizedExporterConfig {
  batchSize: number;
  flushIntervalMs: number;
  retry: RetryConfig;
  rateLimit?: RateLimitConfig;
}

export interface ExportError {
  eventId: string;
  error: string;
  retryable: boolean;
}

export interface ExportResult {
  exported: number;
  failed: number;
  errors: ExportError[];
}

export interface Exporter {
  readonly name: string;
  readonly schema: SchemaFormat;

  export(events: SecurityEvent[]): Promise<ExportResult>;
  healthCheck(): Promise<void>;
  shutdown(): Promise<void>;
}

class TokenBucketLimiter {
  private tokens: number;
  private lastRefillMs: number;

  constructor(
    private readonly requestsPerSecond: number,
    private readonly burstSize: number
  ) {
    this.tokens = burstSize;
    this.lastRefillMs = Date.now();
  }

  async acquire(): Promise<void> {
    for (;;) {
      this.refill();
      if (this.tokens >= 1) {
        this.tokens -= 1;
        return;
      }
      const waitMs = Math.max(1, Math.ceil(1000 / Math.max(1, this.requestsPerSecond)));
      await new Promise<void>(resolve => setTimeout(resolve, waitMs));
    }
  }

  private refill(): void {
    const now = Date.now();
    const elapsedMs = now - this.lastRefillMs;
    if (elapsedMs <= 0) {
      return;
    }

    const refillTokens = (elapsedMs / 1000) * this.requestsPerSecond;
    if (refillTokens <= 0) {
      return;
    }

    this.tokens = Math.min(this.burstSize, this.tokens + refillTokens);
    this.lastRefillMs = now;
  }
}

/**
 * Base class providing common exporter functionality:
 * - buffering + flush interval
 * - retry/backoff
 * - optional rate limiting
 */
export abstract class BaseExporter implements Exporter {
  abstract readonly name: string;
  abstract readonly schema: SchemaFormat;

  protected readonly config: NormalizedExporterConfig;
  private readonly rateLimiter?: TokenBucketLimiter;

  protected buffer: SecurityEvent[] = [];
  protected flushTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(config: Partial<ExporterConfig> = {}) {
    this.config = {
      batchSize: config.batchSize ?? 100,
      flushIntervalMs: config.flushIntervalMs ?? 5000,
      retry: config.retry ?? {
        maxRetries: 3,
        initialBackoffMs: 1000,
        maxBackoffMs: 30000,
        backoffMultiplier: 2,
      },
      rateLimit: config.rateLimit,
    };

    if (this.config.rateLimit) {
      this.rateLimiter = new TokenBucketLimiter(
        Math.max(1, this.config.rateLimit.requestsPerSecond),
        Math.max(1, this.config.rateLimit.burstSize)
      );
    }
  }

  async enqueue(event: SecurityEvent): Promise<void> {
    this.buffer.push(event);

    if (this.buffer.length >= this.config.batchSize) {
      await this.flush();
      return;
    }

    if (!this.flushTimer) {
      this.flushTimer = setTimeout(() => {
        void this.flush();
      }, this.config.flushIntervalMs);
    }
  }

  async flush(): Promise<ExportResult> {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }

    const events = this.buffer.splice(0);
    if (events.length === 0) {
      return { exported: 0, failed: 0, errors: [] };
    }

    return this.exportWithRetry(events);
  }

  protected async exportWithRetry(events: SecurityEvent[]): Promise<ExportResult> {
    let lastError: Error | null = null;
    let backoffMs = this.config.retry.initialBackoffMs;

    for (let attempt = 0; attempt <= this.config.retry.maxRetries; attempt++) {
      try {
        if (this.rateLimiter) {
          await this.rateLimiter.acquire();
        }
        return await this.export(events);
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));

        if (attempt < this.config.retry.maxRetries) {
          await this.sleep(backoffMs);
          backoffMs = Math.min(
            Math.floor(backoffMs * this.config.retry.backoffMultiplier),
            this.config.retry.maxBackoffMs
          );
        }
      }
    }

    return {
      exported: 0,
      failed: events.length,
      errors: events.map(e => ({
        eventId: e.event_id,
        error: lastError?.message ?? "Unknown error",
        retryable: false,
      })),
    };
  }

  protected sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  abstract export(events: SecurityEvent[]): Promise<ExportResult>;
  abstract healthCheck(): Promise<void>;

  async shutdown(): Promise<void> {
    await this.flush();
  }
}
