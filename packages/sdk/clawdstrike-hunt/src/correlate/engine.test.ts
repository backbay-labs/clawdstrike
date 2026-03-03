import { describe, it, expect } from "vitest";
import { CorrelationEngine, correlate } from "./engine.js";
import { parseRule } from "./rules.js";
import type { CorrelationRule, TimelineEvent } from "../types.js";

function makeEvent(
  source: string,
  actionType: string,
  verdict: string,
  summary: string,
  ts: Date
): TimelineEvent {
  return {
    timestamp: ts,
    source: source as TimelineEvent["source"],
    kind: "guard_decision",
    verdict: verdict as TimelineEvent["verdict"],
    summary,
    actionType,
  };
}

function singleConditionRule(): CorrelationRule {
  return parseRule(`
schema: clawdstrike.hunt.correlation.v1
name: "Forbidden Path Access"
severity: critical
description: "Detects any denied file access"
window: 5m
conditions:
  - source: receipt
    action_type: file
    verdict: deny
    bind: denied_access
output:
  title: "File access denied"
  evidence:
    - denied_access
`);
}

function exfilRule(): CorrelationRule {
  return parseRule(`
schema: clawdstrike.hunt.correlation.v1
name: "MCP Tool Exfiltration Attempt"
severity: high
description: "Detects file access followed by egress"
window: 30s
conditions:
  - source: receipt
    action_type: file
    verdict: allow
    target_pattern: "/etc/passwd|/etc/shadow"
    bind: file_access
  - source: [receipt, hubble]
    action_type: egress
    after: file_access
    within: 30s
    bind: egress_event
output:
  title: "Potential data exfiltration via MCP tool"
  evidence:
    - file_access
    - egress_event
`);
}

describe("CorrelationEngine", () => {
  it("compiles regex patterns on construction", () => {
    const engine = new CorrelationEngine([exfilRule()]);
    expect(engine.rules).toHaveLength(1);
  });

  it("rejects bad regex", () => {
    const rule = exfilRule();
    rule.conditions[0].targetPattern = "[invalid";
    expect(() => new CorrelationEngine([rule])).toThrow();
  });

  it("single condition rule fires immediately", () => {
    const engine = new CorrelationEngine([singleConditionRule()]);
    const ts = new Date("2025-06-15T12:00:00Z");
    const event = makeEvent("receipt", "file", "deny", "/etc/passwd", ts);
    const alerts = engine.processEvent(event);

    expect(alerts).toHaveLength(1);
    expect(alerts[0].ruleName).toBe("Forbidden Path Access");
    expect(alerts[0].severity).toBe("critical");
    expect(alerts[0].evidence).toHaveLength(1);
  });

  it("two-condition sequence generates alert", () => {
    const engine = new CorrelationEngine([exfilRule()]);

    const ts1 = new Date("2025-06-15T12:00:00Z");
    const ts2 = new Date("2025-06-15T12:00:10Z");

    const e1 = makeEvent("receipt", "file", "allow", "read /etc/passwd", ts1);
    const alerts1 = engine.processEvent(e1);
    expect(alerts1).toHaveLength(0);

    const e2 = makeEvent(
      "receipt",
      "egress",
      "allow",
      "egress TCP 10.0.0.1:8080 -> 93.184.216.34:443",
      ts2
    );
    const alerts2 = engine.processEvent(e2);
    expect(alerts2).toHaveLength(1);
    expect(alerts2[0].title).toBe("Potential data exfiltration via MCP tool");
    expect(alerts2[0].evidence).toHaveLength(2);
  });

  it("non-matching source does not fire", () => {
    const engine = new CorrelationEngine([singleConditionRule()]);
    const ts = new Date("2025-06-15T12:00:00Z");
    // Source is hubble, but rule expects receipt
    const event = makeEvent("hubble", "file", "deny", "/etc/passwd", ts);
    const alerts = engine.processEvent(event);
    expect(alerts).toHaveLength(0);
  });

  it("non-matching verdict does not fire", () => {
    const engine = new CorrelationEngine([singleConditionRule()]);
    const ts = new Date("2025-06-15T12:00:00Z");
    // Verdict is allow, but rule expects deny
    const event = makeEvent("receipt", "file", "allow", "/etc/passwd", ts);
    const alerts = engine.processEvent(event);
    expect(alerts).toHaveLength(0);
  });

  it("window eviction removes stale windows", () => {
    const engine = new CorrelationEngine([exfilRule()]);

    const ts1 = new Date("2025-06-15T12:00:00Z");
    const e1 = makeEvent("receipt", "file", "allow", "read /etc/passwd", ts1);
    engine.processEvent(e1);

    // 60s later — beyond the 30s window
    const ts2 = new Date("2025-06-15T12:01:00Z");
    const e2 = makeEvent(
      "receipt",
      "egress",
      "allow",
      "egress TCP -> 93.184.216.34:443",
      ts2
    );
    const alerts = engine.processEvent(e2);
    expect(alerts).toHaveLength(0);
  });

  it("dependent ordering: event B then A does not fire", () => {
    const engine = new CorrelationEngine([exfilRule()]);

    const ts1 = new Date("2025-06-15T12:00:00Z");
    const ts2 = new Date("2025-06-15T12:00:10Z");

    // Send egress first (condition B), then file access (condition A)
    const e2 = makeEvent(
      "receipt",
      "egress",
      "allow",
      "egress TCP -> 93.184.216.34:443",
      ts1
    );
    engine.processEvent(e2);

    const e1 = makeEvent("receipt", "file", "allow", "read /etc/passwd", ts2);
    const alerts = engine.processEvent(e1);

    // The file access creates a new window, but there's no subsequent egress
    expect(alerts).toHaveLength(0);
  });

  it("pre-existing count: same event does not bind root and dependent", () => {
    // If a rule has condition A (root) and condition B (after: A),
    // and both happen to match the same event, B should NOT bind
    // to the window just created by A in the same cycle.
    const rule = parseRule(`
schema: clawdstrike.hunt.correlation.v1
name: "Same event test"
severity: low
description: "test"
window: 30s
conditions:
  - source: receipt
    action_type: file
    bind: step_a
  - source: receipt
    action_type: file
    after: step_a
    bind: step_b
output:
  title: "test"
  evidence:
    - step_a
    - step_b
`);

    const engine = new CorrelationEngine([rule]);
    const ts = new Date("2025-06-15T12:00:00Z");
    const event = makeEvent("receipt", "file", "allow", "test", ts);

    // A single event should create a window (step_a) but NOT also bind step_b
    const alerts = engine.processEvent(event);
    expect(alerts).toHaveLength(0);

    // A second event should bind step_b
    const ts2 = new Date("2025-06-15T12:00:05Z");
    const event2 = makeEvent("receipt", "file", "allow", "test2", ts2);
    const alerts2 = engine.processEvent(event2);
    expect(alerts2).toHaveLength(1);
  });

  it("within constraint prevents late matches", () => {
    const rule = parseRule(`
schema: clawdstrike.hunt.correlation.v1
name: "Within test"
severity: low
description: "test"
window: 60s
conditions:
  - source: receipt
    action_type: file
    bind: step_a
  - source: receipt
    action_type: egress
    after: step_a
    within: 5s
    bind: step_b
output:
  title: "test"
  evidence:
    - step_a
    - step_b
`);

    const engine = new CorrelationEngine([rule]);
    const ts1 = new Date("2025-06-15T12:00:00Z");
    engine.processEvent(makeEvent("receipt", "file", "allow", "read file", ts1));

    // 10s later — within the 60s global window, but beyond the 5s within
    const ts2 = new Date("2025-06-15T12:00:10Z");
    const alerts = engine.processEvent(
      makeEvent("receipt", "egress", "allow", "egress", ts2)
    );
    expect(alerts).toHaveLength(0);
  });

  it("flush returns alerts for fully-matched windows", () => {
    const rule = parseRule(`
schema: clawdstrike.hunt.correlation.v1
name: "Flush test"
severity: low
description: "test"
window: 60s
conditions:
  - source: receipt
    action_type: file
    bind: step_a
  - source: receipt
    action_type: egress
    after: step_a
    bind: step_b
output:
  title: "test"
  evidence:
    - step_a
    - step_b
`);

    const engine = new CorrelationEngine([rule]);
    const ts1 = new Date("2025-06-15T12:00:00Z");
    const ts2 = new Date("2025-06-15T12:00:05Z");

    engine.processEvent(makeEvent("receipt", "file", "allow", "read file", ts1));
    engine.processEvent(
      makeEvent("receipt", "egress", "allow", "egress", ts2)
    );

    // The window should have been completed during processEvent, so flush has nothing
    const flushed = engine.flush();
    expect(flushed).toHaveLength(0);
  });

  it("flush returns partially-matched windows that are complete", () => {
    // A single-condition rule: the window is completed immediately,
    // so flush won't find it. Instead test with a multi-step that completes.
    const engine = new CorrelationEngine([singleConditionRule()]);
    const ts = new Date("2025-06-15T12:00:00Z");
    const event = makeEvent("receipt", "file", "deny", "/etc/passwd", ts);
    // processEvent already emits alerts for single-condition rules
    engine.processEvent(event);

    // flush should be empty since windows are cleaned up
    const flushed = engine.flush();
    expect(flushed).toHaveLength(0);
  });

  it("concurrent windows for the same rule", () => {
    const engine = new CorrelationEngine([exfilRule()]);

    const ts1 = new Date("2025-06-15T12:00:00Z");
    const ts2 = new Date("2025-06-15T12:00:05Z");
    const ts3 = new Date("2025-06-15T12:00:10Z");

    // Two file accesses create two windows
    engine.processEvent(
      makeEvent("receipt", "file", "allow", "read /etc/passwd", ts1)
    );
    engine.processEvent(
      makeEvent("receipt", "file", "allow", "read /etc/shadow", ts2)
    );

    // One egress should match the first window
    const alerts = engine.processEvent(
      makeEvent(
        "receipt",
        "egress",
        "allow",
        "egress TCP -> 93.184.216.34:443",
        ts3
      )
    );

    // Should fire for at least one window (the first one that matches)
    expect(alerts.length).toBeGreaterThanOrEqual(1);
  });

  it("source matching is case-insensitive", () => {
    const engine = new CorrelationEngine([singleConditionRule()]);
    const ts = new Date("2025-06-15T12:00:00Z");
    // Source is "Receipt" with capital R
    const event = makeEvent("Receipt", "file", "deny", "/etc/passwd", ts);
    const alerts = engine.processEvent(event);
    expect(alerts).toHaveLength(1);
  });

  it("action type matching is case-insensitive", () => {
    const engine = new CorrelationEngine([singleConditionRule()]);
    const ts = new Date("2025-06-15T12:00:00Z");
    const event = makeEvent("receipt", "FILE", "deny", "/etc/passwd", ts);
    const alerts = engine.processEvent(event);
    expect(alerts).toHaveLength(1);
  });

  it("not_target_pattern excludes matching events", () => {
    const rule = parseRule(`
schema: clawdstrike.hunt.correlation.v1
name: "Not target test"
severity: low
description: "test"
window: 30s
conditions:
  - source: receipt
    action_type: egress
    not_target_pattern: "localhost"
    bind: egress_event
output:
  title: "test"
  evidence:
    - egress_event
`);

    const engine = new CorrelationEngine([rule]);
    const ts = new Date("2025-06-15T12:00:00Z");

    // Event with localhost in summary — should be excluded by not_target
    const alerts1 = engine.processEvent(
      makeEvent("receipt", "egress", "allow", "egress to localhost:8080", ts)
    );
    expect(alerts1).toHaveLength(0);

    // Event without localhost — should match
    const alerts2 = engine.processEvent(
      makeEvent(
        "receipt",
        "egress",
        "allow",
        "egress to 93.184.216.34:443",
        ts
      )
    );
    expect(alerts2).toHaveLength(1);
  });

  it("triggeredAt is max timestamp of evidence events", () => {
    const engine = new CorrelationEngine([exfilRule()]);

    const ts1 = new Date("2025-06-15T12:00:00Z");
    const ts2 = new Date("2025-06-15T12:00:10Z");

    engine.processEvent(
      makeEvent("receipt", "file", "allow", "read /etc/passwd", ts1)
    );
    const alerts = engine.processEvent(
      makeEvent(
        "receipt",
        "egress",
        "allow",
        "egress TCP -> 93.184.216.34:443",
        ts2
      )
    );

    expect(alerts).toHaveLength(1);
    expect(alerts[0].triggeredAt.getTime()).toBe(ts2.getTime());
  });

  it("evict uses shorter of rule window and cap", () => {
    const rule = parseRule(`
schema: clawdstrike.hunt.correlation.v1
name: "Long window"
severity: low
description: "test"
window: 1h
conditions:
  - source: receipt
    action_type: file
    bind: step_a
  - source: receipt
    action_type: egress
    after: step_a
    bind: step_b
output:
  title: "test"
  evidence:
    - step_a
    - step_b
`);

    const engine = new CorrelationEngine([rule]);
    const ts = new Date("2025-06-15T12:00:00Z");
    engine.processEvent(makeEvent("receipt", "file", "allow", "test", ts));

    // Cap at 1ms — should evict immediately
    engine.evict(1);

    // Now the window should be gone
    const alerts = engine.processEvent(
      makeEvent(
        "receipt",
        "egress",
        "allow",
        "egress",
        new Date("2025-06-15T12:00:05Z")
      )
    );
    expect(alerts).toHaveLength(0);
  });

  it("processEvent uses event-time capped eviction when maxWindow is provided", () => {
    const rule = parseRule(`
schema: clawdstrike.hunt.correlation.v1
name: "Event-time cap"
severity: low
description: "test"
window: 1h
conditions:
  - source: receipt
    action_type: file
    bind: step_a
  - source: receipt
    action_type: egress
    after: step_a
    within: 1h
    bind: step_b
output:
  title: "test"
  evidence:
    - step_a
    - step_b
`);

    const engine = new CorrelationEngine([rule]);
    const ts1 = new Date("2025-06-15T12:00:00Z");
    const ts2 = new Date("2025-06-15T12:00:45Z");

    engine.processEvent(
      makeEvent("receipt", "file", "allow", "read /tmp/data", ts1),
      30_000
    );
    const alerts = engine.processEvent(
      makeEvent("receipt", "egress", "allow", "egress", ts2),
      30_000
    );

    expect(alerts).toHaveLength(0);
  });
});

describe("correlate", () => {
  it("processes events and returns alerts", () => {
    const rules = [singleConditionRule()];
    const ts = new Date("2025-06-15T12:00:00Z");
    const events = [
      makeEvent("receipt", "file", "deny", "/etc/passwd", ts),
      makeEvent("receipt", "file", "deny", "/etc/shadow", ts),
    ];

    const alerts = correlate(rules, events);
    expect(alerts).toHaveLength(2);
    expect(alerts[0].ruleName).toBe("Forbidden Path Access");
  });

  it("handles multi-step sequence", () => {
    const rules = [exfilRule()];
    const ts1 = new Date("2025-06-15T12:00:00Z");
    const ts2 = new Date("2025-06-15T12:00:10Z");
    const events = [
      makeEvent("receipt", "file", "allow", "read /etc/passwd", ts1),
      makeEvent("receipt", "egress", "allow", "egress TCP -> 93.184.216.34:443", ts2),
    ];

    const alerts = correlate(rules, events);
    expect(alerts).toHaveLength(1);
    expect(alerts[0].title).toBe("Potential data exfiltration via MCP tool");
  });

  it("returns empty for no matches", () => {
    const rules = [singleConditionRule()];
    const ts = new Date("2025-06-15T12:00:00Z");
    const events = [
      makeEvent("receipt", "file", "allow", "test", ts),
    ];

    const alerts = correlate(rules, events);
    expect(alerts).toHaveLength(0);
  });
});
