import { describe, it, expect, vi } from "vitest";
import { Playbook } from "./playbook.js";
import type { PlaybookResult } from "./playbook.js";
import { parseRule } from "./correlate/index.js";
import { IocDatabase } from "./correlate/index.js";
import type { CorrelationRule, TimelineEvent, Alert, HuntReport, EvidenceItem } from "./types.js";

// Mock the hunt function to return controlled data
vi.mock("./local.js", () => ({
  hunt: vi.fn(async () => []),
}));

// Mock report functions to avoid canonicalize issues with undefined fields
vi.mock("./report.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./report.js")>();
  return {
    ...actual,
    buildReport: vi.fn((title: string, items: EvidenceItem[]): HuntReport => ({
      title,
      generatedAt: new Date(),
      evidence: items,
      merkleRoot: "abcd1234",
      merkleProofs: items.map(() => "proof"),
    })),
    signReport: vi.fn(async (report: HuntReport, _key: string): Promise<HuntReport> => ({
      ...report,
      signature: "sig",
      signer: "signer",
    })),
  };
});

import { hunt } from "./local.js";

const mockedHunt = vi.mocked(hunt);

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
    raw: null,
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

describe("Playbook", () => {
  it("create() creates an instance", () => {
    const pb = Playbook.create();
    expect(pb).toBeInstanceOf(Playbook);
  });

  it("builder chaining returns new instances", () => {
    const pb1 = Playbook.create();
    const pb2 = pb1.since("1h");
    const pb3 = pb2.filter("deny" as TimelineEvent["verdict"]);
    const pb4 = pb3.correlate([singleConditionRule()]);
    const pb5 = pb4.deduplicate(5000);
    const pb6 = pb5.report("Test Report");
    const pb7 = pb6.sign("aabbccdd");

    // Each method returns a new Playbook
    expect(pb1).not.toBe(pb2);
    expect(pb2).not.toBe(pb3);
    expect(pb3).not.toBe(pb4);
    expect(pb4).not.toBe(pb5);
    expect(pb5).not.toBe(pb6);
    expect(pb6).not.toBe(pb7);
  });

  it("immutability: each method returns new Playbook", () => {
    const pb1 = Playbook.create();
    const json1 = pb1.toJSON();
    pb1.since("1h");
    const json2 = pb1.toJSON();
    expect(json1).toEqual(json2);
  });

  it("run() with no rules returns just events", async () => {
    const ts = new Date("2025-06-15T12:00:00Z");
    const events = [makeEvent("receipt", "file", "allow", "read /tmp/test", ts)];
    mockedHunt.mockResolvedValueOnce(events);

    const pb = Playbook.create().since("1h");
    const result = await pb.run();

    expect(result.events).toHaveLength(1);
    expect(result.alerts).toHaveLength(0);
    expect(result.iocMatches).toHaveLength(0);
    expect(result.report).toBeUndefined();
  });

  it("run() with rules returns alerts", async () => {
    const ts = new Date("2025-06-15T12:00:00Z");
    const events = [makeEvent("receipt", "file", "deny", "/etc/passwd", ts)];
    mockedHunt.mockResolvedValueOnce(events);

    const pb = Playbook.create()
      .since("1h")
      .correlate([singleConditionRule()]);
    const result = await pb.run();

    expect(result.alerts).toHaveLength(1);
    expect(result.alerts[0].ruleName).toBe("Forbidden Path Access");
  });

  it("run() with IOC db returns matches", async () => {
    const ts = new Date("2025-06-15T12:00:00Z");
    const events = [makeEvent("receipt", "file", "allow", "evil.com download", ts)];
    mockedHunt.mockResolvedValueOnce(events);

    const db = new IocDatabase();
    db.addEntry({
      indicator: "evil.com",
      iocType: "domain" as any,
      description: "malicious domain",
    });

    const pb = Playbook.create().since("1h").enrich(db);
    const result = await pb.run();

    expect(result.iocMatches).toHaveLength(1);
  });

  it("deduplication filters duplicate alerts", async () => {
    const ts1 = new Date("2025-06-15T12:00:00Z");
    const ts2 = new Date("2025-06-15T12:00:01Z");
    const ts3 = new Date("2025-06-15T12:00:10Z");
    const events = [
      makeEvent("receipt", "file", "deny", "/etc/passwd", ts1),
      makeEvent("receipt", "file", "deny", "/etc/shadow", ts2),
      makeEvent("receipt", "file", "deny", "/etc/hosts", ts3),
    ];
    mockedHunt.mockResolvedValueOnce(events);

    const pb = Playbook.create()
      .since("1h")
      .correlate([singleConditionRule()])
      .deduplicate(5000);
    const result = await pb.run();

    // ts1 and ts2 are within 5s, ts3 is outside
    expect(result.alerts).toHaveLength(2);
  });

  it("report generation", async () => {
    const ts = new Date("2025-06-15T12:00:00Z");
    const events = [makeEvent("receipt", "file", "deny", "/etc/passwd", ts)];
    mockedHunt.mockResolvedValueOnce(events);

    const pb = Playbook.create()
      .since("1h")
      .correlate([singleConditionRule()])
      .report("Security Hunt Report");
    const result = await pb.run();

    expect(result.report).toBeDefined();
    expect(result.report?.title).toBe("Security Hunt Report");
    expect(result.report?.merkleRoot).toBeTruthy();
  });

  it("toJSON/fromJSON roundtrip", () => {
    const pb = Playbook.create()
      .since("1h")
      .filter("deny" as TimelineEvent["verdict"])
      .correlate([singleConditionRule()])
      .deduplicate(5000)
      .report("Test Report");

    const json = pb.toJSON();
    const restored = Playbook.fromJSON(json);
    const restoredJson = restored.toJSON();

    expect(restoredJson.start).toBe(json.start);
    expect(restoredJson.verdictFilter).toBe(json.verdictFilter);
    expect(restoredJson.deduplicateWindow).toBe(json.deduplicateWindow);
    expect(restoredJson.reportTitle).toBe(json.reportTitle);
  });

  it("empty events returns empty result", async () => {
    mockedHunt.mockResolvedValueOnce([]);

    const pb = Playbook.create()
      .since("1h")
      .correlate([singleConditionRule()]);
    const result = await pb.run();

    expect(result.events).toHaveLength(0);
    expect(result.alerts).toHaveLength(0);
    expect(result.iocMatches).toHaveLength(0);
    expect(result.report).toBeUndefined();
  });

  it("verdict filter applies", async () => {
    const ts = new Date("2025-06-15T12:00:00Z");
    const events = [
      makeEvent("receipt", "file", "allow", "read /tmp/test", ts),
      makeEvent("receipt", "file", "deny", "/etc/passwd", ts),
    ];
    mockedHunt.mockResolvedValueOnce(events);

    const pb = Playbook.create()
      .since("1h")
      .filter("deny" as TimelineEvent["verdict"])
      .correlate([singleConditionRule()]);
    const result = await pb.run();

    expect(result.events).toHaveLength(1);
    expect(result.events[0].verdict).toBe("deny");
    expect(result.alerts).toHaveLength(1);
  });
});
