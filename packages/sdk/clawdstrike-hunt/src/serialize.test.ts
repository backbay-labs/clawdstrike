import { describe, it, expect } from "vitest";
import { eventsToJSON, alertsToJSON, eventsToCSV, alertsToCSV } from "./serialize.js";
import type { TimelineEvent, Alert } from "./types.js";

function makeEvent(overrides?: Partial<TimelineEvent>): TimelineEvent {
  return {
    timestamp: new Date("2025-06-15T12:00:00Z"),
    source: "receipt" as TimelineEvent["source"],
    kind: "guard_decision" as TimelineEvent["kind"],
    verdict: "deny" as TimelineEvent["verdict"],
    summary: "test event",
    ...overrides,
  };
}

function makeAlert(overrides?: Partial<Alert>): Alert {
  return {
    ruleName: "test-rule",
    severity: "high" as Alert["severity"],
    title: "Test Alert",
    triggeredAt: new Date("2025-06-15T12:00:00Z"),
    evidence: [makeEvent()],
    description: "A test alert",
    ...overrides,
  };
}

describe("eventsToJSON", () => {
  it("converts events to JSON records", () => {
    const events = [makeEvent({ process: "curl", namespace: "default" })];
    const result = eventsToJSON(events);
    expect(result).toHaveLength(1);
    expect(result[0].timestamp).toBe("2025-06-15T12:00:00.000Z");
    expect(result[0].source).toBe("receipt");
    expect(result[0].verdict).toBe("deny");
    expect(result[0].process).toBe("curl");
    expect(result[0].namespace).toBe("default");
  });

  it("nulls missing optional fields", () => {
    const events = [makeEvent()];
    const result = eventsToJSON(events);
    expect(result[0].severity).toBeNull();
    expect(result[0].process).toBeNull();
    expect(result[0].namespace).toBeNull();
    expect(result[0].pod).toBeNull();
    expect(result[0].actionType).toBeNull();
    expect(result[0].signatureValid).toBeNull();
  });

  it("handles empty array", () => {
    expect(eventsToJSON([])).toEqual([]);
  });
});

describe("alertsToJSON", () => {
  it("converts alerts to JSON records", () => {
    const alerts = [makeAlert()];
    const result = alertsToJSON(alerts);
    expect(result).toHaveLength(1);
    expect(result[0].ruleName).toBe("test-rule");
    expect(result[0].severity).toBe("high");
    expect(result[0].evidenceCount).toBe(1);
  });

  it("handles empty array", () => {
    expect(alertsToJSON([])).toEqual([]);
  });
});

describe("eventsToCSV", () => {
  it("produces CSV with headers", () => {
    const events = [makeEvent({ process: "curl" })];
    const csv = eventsToCSV(events);
    const lines = csv.split("\n");
    expect(lines[0]).toBe("timestamp,source,kind,verdict,severity,summary,process,namespace,pod,actionType");
    expect(lines).toHaveLength(2);
    expect(lines[1]).toContain("receipt");
    expect(lines[1]).toContain("curl");
  });

  it("escapes values with commas", () => {
    const events = [makeEvent({ summary: "hello, world" })];
    const csv = eventsToCSV(events);
    expect(csv).toContain('"hello, world"');
  });

  it("escapes values with double quotes", () => {
    const events = [makeEvent({ summary: 'say "hello"' })];
    const csv = eventsToCSV(events);
    expect(csv).toContain('"say ""hello"""');
  });

  it("handles empty events", () => {
    const csv = eventsToCSV([]);
    const lines = csv.split("\n");
    expect(lines).toHaveLength(1);
    expect(lines[0]).toBe("timestamp,source,kind,verdict,severity,summary,process,namespace,pod,actionType");
  });
});

describe("alertsToCSV", () => {
  it("produces CSV with headers", () => {
    const alerts = [makeAlert()];
    const csv = alertsToCSV(alerts);
    const lines = csv.split("\n");
    expect(lines[0]).toBe("ruleName,severity,title,triggeredAt,description,evidenceCount");
    expect(lines).toHaveLength(2);
  });

  it("handles empty alerts", () => {
    const csv = alertsToCSV([]);
    const lines = csv.split("\n");
    expect(lines).toHaveLength(1);
  });
});
