import { describe, it, expect } from "vitest";
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { event, testRule } from "./testing.js";
import { parseRule } from "./correlate/index.js";
import type { TimelineEvent } from "./types.js";
import { EventSourceType, TimelineEventKind, NormalizedVerdict } from "./types.js";

const SINGLE_RULE_YAML = `
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
`;

function makeEvent(
  source: string,
  actionType: string,
  verdict: string,
  summary: string,
  ts: Date,
): TimelineEvent {
  return {
    timestamp: ts,
    source: source as TimelineEvent["source"],
    kind: "guard_decision" as TimelineEvent["kind"],
    verdict: verdict as TimelineEvent["verdict"],
    summary,
    actionType,
  };
}

describe("event()", () => {
  it("creates a valid event with defaults", () => {
    const e = event();
    expect(e.timestamp).toBeInstanceOf(Date);
    expect(e.source).toBe(EventSourceType.Receipt);
    expect(e.kind).toBe(TimelineEventKind.GuardDecision);
    expect(e.verdict).toBe(NormalizedVerdict.Allow);
    expect(e.summary).toBe("test event");
  });

  it("allows overrides", () => {
    const ts = new Date("2025-06-15T12:00:00Z");
    const e = event({
      timestamp: ts,
      source: EventSourceType.Tetragon,
      summary: "custom summary",
      actionType: "file",
    });
    expect(e.timestamp).toBe(ts);
    expect(e.source).toBe(EventSourceType.Tetragon);
    expect(e.summary).toBe("custom summary");
    expect(e.actionType).toBe("file");
  });
});

describe("testRule()", () => {
  it("accepts YAML string and matches alerts", async () => {
    const ts = new Date("2025-06-15T12:00:00Z");
    const events = [makeEvent("receipt", "file", "deny", "/etc/passwd", ts)];
    const result = await testRule(SINGLE_RULE_YAML, {
      given: events,
      expectAlerts: 1,
    });
    expect(result.passed).toBe(true);
    expect(result.alerts).toHaveLength(1);
    expect(result.eventsProcessed).toBe(1);
    expect(result.mismatches).toHaveLength(0);
  });

  it("accepts CorrelationRule object", async () => {
    const rule = parseRule(SINGLE_RULE_YAML);
    const ts = new Date("2025-06-15T12:00:00Z");
    const events = [makeEvent("receipt", "file", "deny", "/etc/passwd", ts)];
    const result = await testRule(rule, {
      given: events,
      expectAlerts: 1,
    });
    expect(result.passed).toBe(true);
    expect(result.alerts).toHaveLength(1);
  });

  it("accepts file path", async () => {
    const dir = join(tmpdir(), `hunt-test-${Date.now()}`);
    await mkdir(dir, { recursive: true });
    const filePath = join(dir, "rule.yaml");
    await writeFile(filePath, SINGLE_RULE_YAML.trim());

    const ts = new Date("2025-06-15T12:00:00Z");
    const events = [makeEvent("receipt", "file", "deny", "/etc/passwd", ts)];
    const result = await testRule(filePath, {
      given: events,
      expectAlerts: 1,
    });
    expect(result.passed).toBe(true);
  });

  it("reports mismatch when expectAlerts differs", async () => {
    const ts = new Date("2025-06-15T12:00:00Z");
    const events = [makeEvent("receipt", "file", "allow", "test", ts)];
    const result = await testRule(SINGLE_RULE_YAML, {
      given: events,
      expectAlerts: 1,
    });
    expect(result.passed).toBe(false);
    expect(result.mismatches).toHaveLength(1);
    expect(result.mismatches[0]).toContain("expected 1 alerts, got 0");
  });

  it("checks expectSeverity", async () => {
    const ts = new Date("2025-06-15T12:00:00Z");
    const events = [makeEvent("receipt", "file", "deny", "/etc/passwd", ts)];
    const result = await testRule(SINGLE_RULE_YAML, {
      given: events,
      expectSeverity: "low",
    });
    expect(result.passed).toBe(false);
    expect(result.mismatches[0]).toContain("expected severity 'low'");
  });

  it("checks expectRuleName", async () => {
    const ts = new Date("2025-06-15T12:00:00Z");
    const events = [makeEvent("receipt", "file", "deny", "/etc/passwd", ts)];
    const result = await testRule(SINGLE_RULE_YAML, {
      given: events,
      expectRuleName: "Wrong Name",
    });
    expect(result.passed).toBe(false);
    expect(result.mismatches[0]).toContain("expected rule name 'Wrong Name'");
  });

  it("no events with expectAlerts=0 passes", async () => {
    const result = await testRule(SINGLE_RULE_YAML, {
      given: [],
      expectAlerts: 0,
    });
    expect(result.passed).toBe(true);
    expect(result.alerts).toHaveLength(0);
    expect(result.eventsProcessed).toBe(0);
  });

  it("collects multiple mismatches", async () => {
    const ts = new Date("2025-06-15T12:00:00Z");
    const events = [makeEvent("receipt", "file", "deny", "/etc/passwd", ts)];
    const result = await testRule(SINGLE_RULE_YAML, {
      given: events,
      expectAlerts: 2,
      expectSeverity: "low",
      expectRuleName: "Wrong",
    });
    expect(result.passed).toBe(false);
    // expectAlerts mismatch + severity mismatch + rule name mismatch
    expect(result.mismatches.length).toBeGreaterThanOrEqual(2);
  });

  it("passes when severity matches", async () => {
    const ts = new Date("2025-06-15T12:00:00Z");
    const events = [makeEvent("receipt", "file", "deny", "/etc/passwd", ts)];
    const result = await testRule(SINGLE_RULE_YAML, {
      given: events,
      expectSeverity: "critical",
    });
    expect(result.passed).toBe(true);
  });
});
