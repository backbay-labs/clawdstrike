export type BreakerState = 'closed' | 'open' | 'half_open';

export class CircuitBreaker {
  private state: BreakerState = 'closed';
  private failures = 0;
  private successes = 0;
  private openedAtMs: number | null = null;

  constructor(
    private readonly failureThreshold: number,
    private readonly resetTimeoutMs: number,
    private readonly successThreshold: number,
  ) {}

  beforeRequest(): { ok: true } | { ok: false } {
    if (this.state === 'closed') return { ok: true };
    if (this.state === 'half_open') return { ok: true };

    const now = Date.now();
    if (this.openedAtMs === null) {
      this.openedAtMs = now;
      return { ok: false };
    }

    const elapsed = now - this.openedAtMs;
    if (elapsed >= this.resetTimeoutMs) {
      this.state = 'half_open';
      this.failures = 0;
      this.successes = 0;
      return { ok: true };
    }

    return { ok: false };
  }

  recordSuccess(): void {
    if (this.state === 'closed') {
      this.failures = 0;
      return;
    }
    if (this.state === 'half_open') {
      this.successes += 1;
      if (this.successes >= this.successThreshold) {
        this.state = 'closed';
        this.failures = 0;
        this.successes = 0;
        this.openedAtMs = null;
      }
    }
  }

  recordFailure(): void {
    if (this.state === 'closed') {
      this.failures += 1;
      if (this.failures >= this.failureThreshold) {
        this.state = 'open';
        this.openedAtMs = Date.now();
        this.successes = 0;
      }
      return;
    }

    if (this.state === 'half_open') {
      this.state = 'open';
      this.openedAtMs = Date.now();
      this.failures = 0;
      this.successes = 0;
    }
  }
}

