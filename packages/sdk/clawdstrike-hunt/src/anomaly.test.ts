import { describe, it, expect } from "vitest";
import { Baseline, scoreAnomalies } from "./anomaly.js";
import type { TimelineEvent } from "./types.js";

function makeEvent(
  overrides: Partial<TimelineEvent> = {}
): TimelineEvent {
  return {
    timestamp: new Date("2025-06-15T12:00:00Z"),
    source: "tetragon",
    kind: "process_exec",
    verdict: "allow",
    summary: "normal event",
    ...overrides,
  };
}

function makeEvents(count: number, overrides: Partial<TimelineEvent> = {}): TimelineEvent[] {
  return Array.from({ length: count }, () => makeEvent(overrides));
}

// ---------------------------------------------------------------------------
// Baseline.build
// ---------------------------------------------------------------------------

describe("Baseline.build", () => {
  it("builds correct counts from multiple events", () => {
    const events = [
      makeEvent({ source: "tetragon" }),
      makeEvent({ source: "tetragon" }),
      makeEvent({ source: "hubble" }),
    ];
    const baseline = Baseline.build(events);
    const json = baseline.toJSON();
    expect(json.totalEvents).toBe(3);
    expect(json.sourceCounts["tetragon"]).toBe(2);
    expect(json.sourceCounts["hubble"]).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Baseline.score
// ---------------------------------------------------------------------------

describe("Baseline.score", () => {
  it("scores common event low", () => {
    const events = makeEvents(10, { source: "tetragon", kind: "process_exec", verdict: "allow" });
    const baseline = Baseline.build(events);
    const score = baseline.score(makeEvent());
    expect(score).toBeLessThan(0.3);
  });

  it("scores rare event high", () => {
    const events = makeEvents(10, { source: "tetragon", kind: "process_exec", verdict: "allow" });
    const baseline = Baseline.build(events);
    const rare = makeEvent({ source: "hubble", kind: "network_flow", verdict: "deny" });
    const score = baseline.score(rare);
    expect(score).toBeGreaterThan(0.5);
  });

  it("scores unseen event near 1.0", () => {
    const events = makeEvents(10);
    const baseline = Baseline.build(events);
    const unseen = makeEvent({
      source: "scan",
      kind: "scan_result",
      verdict: "deny",
      actionType: "unknown_action",
      process: "evil_process",
      namespace: "rogue_ns",
      timestamp: new Date("2025-06-15T03:00:00Z"),
    });
    const score = baseline.score(unseen);
    expect(score).toBeGreaterThan(0.8);
  });
});

// ---------------------------------------------------------------------------
// Baseline.scoreDetailed
// ---------------------------------------------------------------------------

describe("Baseline.scoreDetailed", () => {
  it("returns feature breakdown", () => {
    const events = makeEvents(5);
    const baseline = Baseline.build(events);
    const result = baseline.scoreDetailed(makeEvent());
    expect(result.featureScores).toHaveProperty("source");
    expect(result.featureScores).toHaveProperty("kind");
    expect(result.featureScores).toHaveProperty("verdict");
    expect(result.featureScores).toHaveProperty("hourOfDay");
    expect(result.anomalyScore).toBeGreaterThanOrEqual(0);
    expect(result.anomalyScore).toBeLessThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// scoreAnomalies
// ---------------------------------------------------------------------------

describe("scoreAnomalies", () => {
  it("filters by threshold", () => {
    const baselineEvents = makeEvents(10);
    const baseline = Baseline.build(baselineEvents);
    const testEvents = [
      makeEvent(), // common → low score
      makeEvent({ source: "scan", kind: "scan_result", verdict: "deny", timestamp: new Date("2025-06-15T03:00:00Z") }), // rare → high
    ];
    const result = scoreAnomalies(testEvents, baseline, 0.5);
    expect(result.length).toBeGreaterThanOrEqual(1);
    for (const s of result) {
      expect(s.anomalyScore).toBeGreaterThanOrEqual(0.5);
    }
  });

  it("sorts descending by score", () => {
    const baselineEvents = makeEvents(10);
    const baseline = Baseline.build(baselineEvents);
    const testEvents = [
      makeEvent(),
      makeEvent({ source: "scan", kind: "scan_result", verdict: "deny", timestamp: new Date("2025-06-15T03:00:00Z") }),
      makeEvent({ source: "hubble", kind: "network_flow", verdict: "warn", timestamp: new Date("2025-06-15T02:00:00Z") }),
    ];
    const result = scoreAnomalies(testEvents, baseline, 0);
    for (let i = 1; i < result.length; i++) {
      expect(result[i - 1].anomalyScore).toBeGreaterThanOrEqual(result[i].anomalyScore);
    }
  });

  it("threshold 0 returns all events", () => {
    const baselineEvents = makeEvents(5);
    const baseline = Baseline.build(baselineEvents);
    const testEvents = makeEvents(3);
    const result = scoreAnomalies(testEvents, baseline, 0);
    expect(result).toHaveLength(3);
  });

  it("threshold 1.0 returns few or none", () => {
    const baselineEvents = makeEvents(10);
    const baseline = Baseline.build(baselineEvents);
    const testEvents = makeEvents(5);
    const result = scoreAnomalies(testEvents, baseline, 1.0);
    // Common events should score below 1.0
    expect(result).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Empty baseline
// ---------------------------------------------------------------------------

describe("empty baseline", () => {
  it("scores 1.0 for any event", () => {
    const baseline = Baseline.build([]);
    const score = baseline.score(makeEvent());
    expect(score).toBe(1.0);
  });
});

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

describe("toJSON / fromJSON", () => {
  it("roundtrips correctly", () => {
    const events = [
      makeEvent({ source: "tetragon", process: "curl" }),
      makeEvent({ source: "hubble", namespace: "default" }),
    ];
    const baseline = Baseline.build(events);
    const json = baseline.toJSON();
    const restored = Baseline.fromJSON(json);
    const score1 = baseline.score(makeEvent());
    const score2 = restored.score(makeEvent());
    expect(score1).toBe(score2);
  });
});

// ---------------------------------------------------------------------------
// hourOfDay feature
// ---------------------------------------------------------------------------

describe("hourOfDay feature", () => {
  it("includes hourOfDay in feature scores", () => {
    const events = makeEvents(5, { timestamp: new Date("2025-06-15T10:00:00Z") });
    const baseline = Baseline.build(events);
    const nightEvent = makeEvent({ timestamp: new Date("2025-06-15T03:00:00Z") });
    const result = baseline.scoreDetailed(nightEvent);
    expect(result.featureScores.hourOfDay).toBe(1.0);
  });
});
