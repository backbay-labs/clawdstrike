import { describe, it, expect } from "vitest";
import {
  buildReport,
  signReport,
  verifyReport,
  evidenceFromAlert,
  evidenceFromEvents,
  evidenceFromIocMatches,
  collectEvidence,
} from "./report.js";
import type {
  Alert,
  EvidenceItem,
  IocMatch,
  TimelineEvent,
} from "./types.js";

function sampleItems(): EvidenceItem[] {
  const ts = new Date("2025-06-15T12:00:00Z");
  return [
    {
      index: 0,
      sourceType: "alert",
      timestamp: ts,
      summary: "Suspicious file access",
      data: { rule: "exfil", severity: "high" },
    },
    {
      index: 1,
      sourceType: "event",
      timestamp: ts,
      summary: "read /etc/passwd",
      data: { path: "/etc/passwd" },
    },
    {
      index: 2,
      sourceType: "ioc_match",
      timestamp: ts,
      summary: "IOC match: evil.com",
      data: { domain: "evil.com" },
    },
  ];
}

function makeTimelineEvent(summary: string, ts: Date): TimelineEvent {
  return {
    timestamp: ts,
    source: "receipt",
    kind: "guard_decision",
    verdict: "deny",
    severity: "high",
    summary,
    actionType: "file",
  };
}

describe("buildReport", () => {
  it("builds a report with sample evidence", () => {
    const items = sampleItems();
    const report = buildReport("Test Report", items);

    expect(report.title).toBe("Test Report");
    expect(report.evidence).toHaveLength(3);
    expect(report.merkleRoot).toBeTruthy();
    expect(report.merkleProofs).toHaveLength(3);
    expect(report.signature).toBeUndefined();
    expect(report.signer).toBeUndefined();
  });

  it("builds a report with a single item", () => {
    const ts = new Date("2025-06-15T12:00:00Z");
    const items: EvidenceItem[] = [
      {
        index: 0,
        sourceType: "event",
        timestamp: ts,
        summary: "single event",
        data: { key: "value" },
      },
    ];

    const report = buildReport("Single Item Report", items);
    expect(report.evidence).toHaveLength(1);
    expect(report.merkleRoot).toBeTruthy();
    expect(report.merkleProofs).toHaveLength(1);
  });

  it("throws on empty items", () => {
    expect(() => buildReport("Empty", [])).toThrow("no evidence");
  });
});

describe("signReport and verifyReport", () => {
  it("unsigned report verifies", async () => {
    const items = sampleItems();
    const report = buildReport("Test", items);
    const valid = await verifyReport(report);
    expect(valid).toBe(true);
  });

  it("sign and verify round-trip", async () => {
    const items = sampleItems();
    const report = buildReport("Signed Report", items);

    // Generate a deterministic seed (32 bytes of 0x01)
    const seed = "0101010101010101010101010101010101010101010101010101010101010101";
    const signed = await signReport(report, seed);

    expect(signed.signature).toBeTruthy();
    expect(signed.signer).toBeTruthy();
    // Original report should be unchanged
    expect(report.signature).toBeUndefined();

    const valid = await verifyReport(signed);
    expect(valid).toBe(true);
  });

  it("tampered signature fails verification", async () => {
    const items = sampleItems();
    const report = buildReport("Tampered", items);

    const seed = "0202020202020202020202020202020202020202020202020202020202020202";
    const signed = await signReport(report, seed);

    // Tamper with the signature
    const sig = signed.signature!;
    const chars = sig.split("");
    chars[0] = chars[0] === "a" ? "b" : "a";
    const tampered = { ...signed, signature: chars.join("") };

    const valid = await verifyReport(tampered);
    // Either false or throws (invalid hex)
    expect(valid).toBe(false);
  });

  it("signature without signer fails verification", async () => {
    const items = sampleItems();
    const report = buildReport("Missing Signer", items);

    const seed = "0303030303030303030303030303030303030303030303030303030303030303";
    const signed = await signReport(report, seed);
    const broken = { ...signed, signer: undefined };

    const valid = await verifyReport(broken);
    expect(valid).toBe(false);
  });

  it("signer without signature fails verification", async () => {
    const items = sampleItems();
    const report = buildReport("Missing Signature", items);

    const broken = { ...report, signer: "aa".repeat(32) };

    const valid = await verifyReport(broken);
    expect(valid).toBe(false);
  });

  it("returns false for malformed merkle root instead of throwing", async () => {
    const items = sampleItems();
    const report = buildReport("Bad Root", items);
    const malformed = { ...report, merkleRoot: "zz-not-hex" };

    await expect(verifyReport(malformed)).resolves.toBe(false);
  });

  it("returns false for malformed proof payloads", async () => {
    const items = sampleItems();
    const report = buildReport("Bad Proof", items);
    const malformed = { ...report, merkleProofs: ["not json", ...report.merkleProofs.slice(1)] };

    await expect(verifyReport(malformed)).resolves.toBe(false);
  });
});

describe("evidence conversion helpers", () => {
  it("evidenceFromAlert converts alert to evidence items", () => {
    const ts = new Date("2025-06-15T12:00:00Z");
    const event = makeTimelineEvent("read /etc/passwd", ts);
    const alert: Alert = {
      ruleName: "exfil_rule",
      severity: "high",
      title: "Data exfiltration",
      triggeredAt: ts,
      evidence: [event],
      description: "Test alert",
    };

    const items = evidenceFromAlert(alert, 0);
    expect(items).toHaveLength(2);
    expect(items[0].sourceType).toBe("alert");
    expect(items[0].index).toBe(0);
    expect(items[0].summary).toContain("exfil_rule");
    expect(items[1].sourceType).toBe("event");
    expect(items[1].index).toBe(1);
    expect(items[1].summary).toContain("read /etc/passwd");
  });

  it("evidenceFromEvents converts events with start index", () => {
    const ts1 = new Date("2025-06-15T12:00:00Z");
    const ts2 = new Date("2025-06-15T12:01:00Z");
    const events = [
      makeTimelineEvent("event one", ts1),
      makeTimelineEvent("event two", ts2),
    ];

    const items = evidenceFromEvents(events, 5);
    expect(items).toHaveLength(2);
    expect(items[0].index).toBe(5);
    expect(items[1].index).toBe(6);
    expect(items[0].sourceType).toBe("event");
    expect(items[0].summary).toContain("event one");
    expect(items[1].summary).toContain("event two");
  });

  it("evidenceFromIocMatches converts IOC matches", () => {
    const ts = new Date("2025-06-15T12:00:00Z");
    const event: TimelineEvent = {
      timestamp: ts,
      source: "tetragon",
      kind: "process_exec",
      verdict: "none",
      summary: "curl evil.com",
      process: "curl",
    };

    const iocMatch: IocMatch = {
      event,
      matchedIocs: [
        {
          indicator: "evil.com",
          iocType: "domain",
          description: "C2 domain",
        },
      ],
      matchField: "summary",
    };

    const items = evidenceFromIocMatches([iocMatch], 10);
    expect(items).toHaveLength(1);
    expect(items[0].index).toBe(10);
    expect(items[0].sourceType).toBe("ioc_match");
    expect(items[0].summary).toContain("evil.com");
    expect(items[0].summary).toContain("summary");
  });
});

describe("collectEvidence", () => {
  it("auto-indexes across mixed sources", () => {
    const ts = new Date("2025-06-15T12:00:00Z");
    const event1 = makeTimelineEvent("read /etc/passwd", ts);
    const event2 = makeTimelineEvent("egress to evil.com", ts);
    const alert: Alert = {
      ruleName: "test_rule",
      severity: "high",
      title: "Test alert",
      triggeredAt: ts,
      evidence: [event1],
      description: "desc",
    };
    const iocMatch: IocMatch = {
      event: event2,
      matchedIocs: [{ indicator: "evil.com", iocType: "domain" }],
      matchField: "summary",
    };

    const items = collectEvidence(alert, [event2], [iocMatch]);

    // Alert produces 2 items (alert + 1 evidence event)
    // Events produces 1 item
    // IOC matches produces 1 item
    expect(items).toHaveLength(4);
    expect(items[0].index).toBe(0);
    expect(items[1].index).toBe(1);
    expect(items[2].index).toBe(2);
    expect(items[3].index).toBe(3);
    expect(items[0].sourceType).toBe("alert");
    expect(items[2].sourceType).toBe("event");
    expect(items[3].sourceType).toBe("ioc_match");
  });

  it("handles empty input", () => {
    const items = collectEvidence();
    expect(items).toHaveLength(0);
  });
});
