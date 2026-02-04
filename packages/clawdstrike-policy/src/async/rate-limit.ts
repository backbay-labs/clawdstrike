import { sleep } from './util.js';

export class TokenBucket {
  private tokens: number;
  private lastRefillMs: number;

  constructor(
    private readonly ratePerSec: number,
    private readonly capacity: number,
  ) {
    this.tokens = capacity;
    this.lastRefillMs = Date.now();
  }

  async acquire(signal?: AbortSignal): Promise<void> {
    if (!Number.isFinite(this.ratePerSec) || this.ratePerSec <= 0) return;

    for (;;) {
      this.refill();
      if (this.tokens >= 1) {
        this.tokens -= 1;
        return;
      }

      const needed = 1 - this.tokens;
      const waitMs = Math.max(0, (needed / this.ratePerSec) * 1000);
      await sleep(waitMs, signal);
    }
  }

  private refill(): void {
    const now = Date.now();
    const elapsedSec = (now - this.lastRefillMs) / 1000;
    this.lastRefillMs = now;

    const added = elapsedSec * this.ratePerSec;
    this.tokens = Math.min(this.capacity, this.tokens + added);
  }
}

