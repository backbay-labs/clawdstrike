import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { bucketByTime, computeGuardFrequency, computeDecisionRatio } from "./vizHelpers";
import type { SSEEvent } from "../hooks/useSSE";

function makeEvent(overrides: Partial<SSEEvent> = {}): SSEEvent {
  return {
    _id: 1,
    event_type: "check",
    timestamp: new Date().toISOString(),
    ...overrides,
  } as SSEEvent;
}

describe("bucketByTime", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T12:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("returns empty buckets when no events", () => {
    const result = bucketByTime([], 5, 12);
    expect(result).toHaveLength(12);
    expect(result.every((v) => v === 0)).toBe(true);
  });

  it("places events into correct buckets", () => {
    const events = [
      makeEvent({ timestamp: new Date("2026-01-01T11:58:00Z").toISOString() }), // ~2 min ago → bucket 11
      makeEvent({ timestamp: new Date("2026-01-01T11:50:00Z").toISOString() }), // ~10 min ago → bucket 9
    ];
    const result = bucketByTime(events, 5, 12);
    expect(result[11]).toBe(1); // most recent bucket
    expect(result[9]).toBe(1); // 10 min ago in 5-min buckets = 2 buckets back → idx 9
  });

  it("ignores events outside the window", () => {
    const events = [
      makeEvent({ timestamp: new Date("2026-01-01T10:00:00Z").toISOString() }), // 2 hours ago
    ];
    const result = bucketByTime(events, 5, 12);
    expect(result.every((v) => v === 0)).toBe(true);
  });
});

describe("computeGuardFrequency", () => {
  it("returns empty object for no events", () => {
    expect(computeGuardFrequency([])).toEqual({});
  });

  it("counts guard occurrences", () => {
    const events = [
      makeEvent({ guard: "ForbiddenPathGuard" }),
      makeEvent({ guard: "ForbiddenPathGuard" }),
      makeEvent({ guard: "EgressAllowlistGuard" }),
      makeEvent({ guard: undefined }),
    ];
    const freq = computeGuardFrequency(events);
    expect(freq).toEqual({
      ForbiddenPathGuard: 2,
      EgressAllowlistGuard: 1,
    });
  });
});

describe("computeDecisionRatio", () => {
  it("returns all zeros for no events", () => {
    expect(computeDecisionRatio([])).toEqual({ allowed: 0, blocked: 0, warn: 0 });
  });

  it("counts allowed and blocked", () => {
    const events = [
      makeEvent({ allowed: true }),
      makeEvent({ allowed: true }),
      makeEvent({ allowed: false }),
    ];
    expect(computeDecisionRatio(events)).toEqual({ allowed: 2, blocked: 1, warn: 0 });
  });

  it("skips events with undefined allowed (e.g., policy_updated)", () => {
    const events = [
      makeEvent({ allowed: true }),
      makeEvent({ allowed: undefined, event_type: "policy_updated" }),
      makeEvent({ allowed: false }),
    ];
    const result = computeDecisionRatio(events);
    expect(result).toEqual({ allowed: 1, blocked: 1, warn: 0 });
  });
});
