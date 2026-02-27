import type { SSEEvent } from "../hooks/useSSE";

export function bucketByTime(events: SSEEvent[], bucketMinutes: number, totalBuckets: number): number[] {
  const now = Date.now();
  const windowMs = bucketMinutes * 60_000;
  const buckets = new Array(totalBuckets).fill(0);
  for (const e of events) {
    const age = now - new Date(e.timestamp).getTime();
    const idx = totalBuckets - 1 - Math.floor(age / windowMs);
    if (idx >= 0 && idx < totalBuckets) buckets[idx]++;
  }
  return buckets;
}

export function computeGuardFrequency(events: SSEEvent[]): Record<string, number> {
  const freq: Record<string, number> = {};
  for (const e of events) {
    if (e.guard) freq[e.guard] = (freq[e.guard] || 0) + 1;
  }
  return freq;
}

export function computeDecisionRatio(events: SSEEvent[]): { allowed: number; blocked: number; warn: number } {
  let allowed = 0, blocked = 0, warn = 0;
  for (const e of events) {
    if (e.allowed === true) allowed++;
    else if (e.allowed === false) blocked++;
    else if (e.allowed != null) warn++;
    // skip events with no decision (e.g. policy_updated)
  }
  return { allowed, blocked, warn };
}
