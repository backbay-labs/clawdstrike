import { describe, it, expect } from "vitest";
import type { AgentEvent, Investigation, HuntPattern } from "../hunt-types";
import type { CoverageGapCandidate } from "../detection-workflow/shared-types";
import {
  discoverCoverageGaps,
  deduplicateGaps,
  rankGaps,
  suppressNoisyGaps,
  type CoverageGapInput,
  type DocumentCoverageEntry,
} from "../detection-workflow/coverage-gap-engine";

// ---- Test Helpers ----

function makeEvent(overrides: Partial<AgentEvent> = {}): AgentEvent {
  return {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    agentId: "agent-1",
    agentName: "TestAgent",
    sessionId: "session-1",
    actionType: "shell_command",
    target: "whoami",
    verdict: "allow",
    guardResults: [],
    policyVersion: "1.2.0",
    flags: [],
    ...overrides,
  };
}

function makeInvestigation(overrides: Partial<Investigation> = {}): Investigation {
  return {
    id: "inv-1",
    title: "Suspicious shell activity",
    status: "open",
    severity: "high",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    createdBy: "analyst",
    agentIds: ["agent-1"],
    sessionIds: ["session-1"],
    timeRange: {
      start: new Date(Date.now() - 3600000).toISOString(),
      end: new Date().toISOString(),
    },
    eventIds: ["evt-1", "evt-2"],
    annotations: [],
    ...overrides,
  };
}

function makePattern(overrides: Partial<HuntPattern> = {}): HuntPattern {
  return {
    id: "pat-1",
    name: "Recon then exfil",
    description: "Discovery followed by data exfiltration",
    discoveredAt: new Date().toISOString(),
    status: "confirmed",
    sequence: [
      { step: 1, actionType: "shell_command", targetPattern: "whoami" },
      { step: 2, actionType: "network_egress", targetPattern: "*.evil.com" },
    ],
    matchCount: 10,
    exampleSessionIds: ["s1"],
    agentIds: ["agent-1"],
    ...overrides,
  };
}

function makeCoverage(overrides: Partial<DocumentCoverageEntry> = {}): DocumentCoverageEntry {
  return {
    documentId: "doc-1",
    fileType: "sigma_rule",
    techniques: [],
    dataSources: [],
    ...overrides,
  };
}

// ---- Tests ----

describe("discoverCoverageGaps", () => {
  it("finds gaps from events with uncovered techniques", () => {
    // "whoami" maps to T1033 (discovery)
    const events = [
      makeEvent({ target: "whoami", actionType: "shell_command" }),
      makeEvent({ target: "whoami", actionType: "shell_command" }),
      makeEvent({ target: "whoami", actionType: "shell_command" }),
    ];

    const gaps = discoverCoverageGaps({ events });

    expect(gaps.length).toBeGreaterThan(0);
    // Should have T1033 in technique hints
    const hasT1033 = gaps.some((g) => g.techniqueHints.includes("T1033"));
    expect(hasT1033).toBe(true);
  });

  it("handles empty input", () => {
    const gaps = discoverCoverageGaps({});
    expect(gaps).toEqual([]);
  });

  it("handles empty arrays", () => {
    const gaps = discoverCoverageGaps({
      events: [],
      investigations: [],
      patterns: [],
    });
    expect(gaps).toEqual([]);
  });

  it("does not report gaps for already-covered techniques", () => {
    const events = [
      makeEvent({ target: "whoami", actionType: "shell_command" }),
    ];

    const gaps = discoverCoverageGaps({
      events,
      openDocumentCoverage: [
        makeCoverage({ techniques: ["T1033"], dataSources: ["process"] }),
      ],
    });

    // T1033 should not appear since it's covered
    const hasT1033 = gaps.some((g) => g.techniqueHints.includes("T1033"));
    expect(hasT1033).toBe(false);
  });

  it("discovers gaps from investigations with technique annotations", () => {
    const inv = makeInvestigation({
      annotations: [
        { id: "a1", text: "Possible T1059.001 PowerShell abuse", createdAt: new Date().toISOString(), createdBy: "analyst" },
      ],
    });

    const gaps = discoverCoverageGaps({ investigations: [inv] });

    expect(gaps.length).toBeGreaterThan(0);
    const hasTechnique = gaps.some((g) => g.techniqueHints.includes("T1059.001"));
    expect(hasTechnique).toBe(true);
  });

  it("discovers gaps from confirmed patterns with high match counts", () => {
    const pattern = makePattern({ matchCount: 10, status: "confirmed" });

    const gaps = discoverCoverageGaps({ patterns: [pattern] });

    expect(gaps.length).toBeGreaterThan(0);
    expect(gaps[0].sourceKind).toBe("pattern");
    expect(gaps[0].sourceIds).toContain("pat-1");
  });

  it("skips dismissed patterns", () => {
    const pattern = makePattern({ status: "dismissed" });

    const gaps = discoverCoverageGaps({ patterns: [pattern] });

    expect(gaps).toEqual([]);
  });

  it("detects high-anomaly events without technique matches", () => {
    // Use a target that won't match any technique patterns
    const events = [
      makeEvent({ target: "custom-binary", actionType: "shell_command", anomalyScore: 0.9 }),
      makeEvent({ target: "custom-binary", actionType: "shell_command", anomalyScore: 0.85 }),
    ];

    const gaps = discoverCoverageGaps({ events });

    // Should have at least one gap from high-anomaly events
    const anomalyGap = gaps.find((g) => g.rationale.includes("high-anomaly"));
    expect(anomalyGap).toBeDefined();
  });
});

describe("deduplicateGaps", () => {
  it("removes candidates covered by open documents", () => {
    const candidates: CoverageGapCandidate[] = [
      {
        id: "gap-1",
        sourceKind: "event",
        sourceIds: ["e1"],
        severity: "medium",
        confidence: 0.7,
        suggestedFormats: ["sigma_rule"],
        techniqueHints: ["T1033"],
        dataSourceHints: ["process"],
        rationale: "Test gap",
      },
      {
        id: "gap-2",
        sourceKind: "event",
        sourceIds: ["e2"],
        severity: "low",
        confidence: 0.5,
        suggestedFormats: ["sigma_rule"],
        techniqueHints: ["T1059"],
        dataSourceHints: ["process"],
        rationale: "Another gap",
      },
    ];

    const knownCoverage: DocumentCoverageEntry[] = [
      makeCoverage({ techniques: ["T1033"], dataSources: ["process"] }),
    ];

    const result = deduplicateGaps(candidates, knownCoverage);

    // T1033 gap should be removed, T1059 should remain
    expect(result.some((g) => g.techniqueHints.includes("T1033"))).toBe(false);
    expect(result.some((g) => g.techniqueHints.includes("T1059"))).toBe(true);
  });

  it("merges same-technique candidates keeping highest confidence", () => {
    const candidates: CoverageGapCandidate[] = [
      {
        id: "gap-1",
        sourceKind: "event",
        sourceIds: ["e1"],
        severity: "low",
        confidence: 0.5,
        suggestedFormats: ["sigma_rule"],
        techniqueHints: ["T1059"],
        dataSourceHints: ["process"],
        rationale: "Lower confidence",
      },
      {
        id: "gap-2",
        sourceKind: "event",
        sourceIds: ["e2"],
        severity: "medium",
        confidence: 0.8,
        suggestedFormats: ["sigma_rule"],
        techniqueHints: ["T1059"],
        dataSourceHints: ["process"],
        rationale: "Higher confidence",
      },
    ];

    const result = deduplicateGaps(candidates, []);

    // Should merge into one candidate with higher confidence
    const t1059Gaps = result.filter((g) => g.techniqueHints.includes("T1059"));
    expect(t1059Gaps.length).toBe(1);
    expect(t1059Gaps[0].confidence).toBe(0.8);
  });
});

describe("suppressNoisyGaps", () => {
  it("filters low-confidence duplicates from same source kind", () => {
    const candidates: CoverageGapCandidate[] = [
      {
        id: "gap-1",
        sourceKind: "event",
        sourceIds: ["e1"],
        severity: "low",
        confidence: 0.2,
        suggestedFormats: ["sigma_rule"],
        techniqueHints: ["T1033"],
        dataSourceHints: ["process"],
        rationale: "Low confidence gap 1",
      },
      {
        id: "gap-2",
        sourceKind: "event",
        sourceIds: ["e2"],
        severity: "low",
        confidence: 0.3,
        suggestedFormats: ["sigma_rule"],
        techniqueHints: ["T1059"],
        dataSourceHints: ["process"],
        rationale: "Low confidence gap 2",
      },
      {
        id: "gap-3",
        sourceKind: "pattern",
        sourceIds: ["p1"],
        severity: "medium",
        confidence: 0.7,
        suggestedFormats: ["sigma_rule"],
        techniqueHints: ["T1105"],
        dataSourceHints: ["network"],
        rationale: "High confidence gap",
      },
    ];

    const result = suppressNoisyGaps(candidates, 0.4);

    // High confidence gap should remain
    expect(result.some((g) => g.id === "gap-3")).toBe(true);

    // Only one of the two low-confidence event gaps should remain (the better one)
    const eventGaps = result.filter((g) => g.sourceKind === "event");
    expect(eventGaps.length).toBe(1);
    expect(eventGaps[0].confidence).toBe(0.3);
  });

  it("keeps all candidates above threshold", () => {
    const candidates: CoverageGapCandidate[] = [
      {
        id: "gap-1",
        sourceKind: "event",
        sourceIds: ["e1"],
        severity: "high",
        confidence: 0.8,
        suggestedFormats: ["sigma_rule"],
        techniqueHints: ["T1033"],
        dataSourceHints: ["process"],
        rationale: "Gap 1",
      },
      {
        id: "gap-2",
        sourceKind: "event",
        sourceIds: ["e2"],
        severity: "medium",
        confidence: 0.6,
        suggestedFormats: ["sigma_rule"],
        techniqueHints: ["T1059"],
        dataSourceHints: ["process"],
        rationale: "Gap 2",
      },
    ];

    const result = suppressNoisyGaps(candidates, 0.4);

    expect(result.length).toBe(2);
  });
});

describe("rankGaps", () => {
  it("sorts by severity then confidence descending", () => {
    const candidates: CoverageGapCandidate[] = [
      {
        id: "gap-1",
        sourceKind: "event",
        sourceIds: [],
        severity: "low",
        confidence: 0.9,
        suggestedFormats: [],
        techniqueHints: [],
        dataSourceHints: [],
        rationale: "Low sev high conf",
      },
      {
        id: "gap-2",
        sourceKind: "event",
        sourceIds: [],
        severity: "high",
        confidence: 0.6,
        suggestedFormats: [],
        techniqueHints: [],
        dataSourceHints: [],
        rationale: "High sev lower conf",
      },
      {
        id: "gap-3",
        sourceKind: "event",
        sourceIds: [],
        severity: "high",
        confidence: 0.9,
        suggestedFormats: [],
        techniqueHints: [],
        dataSourceHints: [],
        rationale: "High sev high conf",
      },
      {
        id: "gap-4",
        sourceKind: "event",
        sourceIds: [],
        severity: "medium",
        confidence: 0.7,
        suggestedFormats: [],
        techniqueHints: [],
        dataSourceHints: [],
        rationale: "Medium sev",
      },
    ];

    const ranked = rankGaps(candidates);

    // High severity first (sorted by confidence within same severity)
    expect(ranked[0].id).toBe("gap-3"); // high, 0.9
    expect(ranked[1].id).toBe("gap-2"); // high, 0.6
    expect(ranked[2].id).toBe("gap-4"); // medium, 0.7
    expect(ranked[3].id).toBe("gap-1"); // low, 0.9
  });
});

describe("gap candidate properties", () => {
  it("gap candidates have valid rationale strings", () => {
    const events = [
      makeEvent({ target: "whoami", actionType: "shell_command" }),
    ];

    const gaps = discoverCoverageGaps({ events });

    for (const gap of gaps) {
      expect(typeof gap.rationale).toBe("string");
      expect(gap.rationale.length).toBeGreaterThan(0);
    }
  });

  it("confidence scoring reflects event volume", () => {
    const fewEvents = [
      makeEvent({ target: "whoami", actionType: "shell_command" }),
    ];
    const manyEvents = Array.from({ length: 15 }, () =>
      makeEvent({ target: "whoami", actionType: "shell_command" }),
    );

    const fewGaps = discoverCoverageGaps({ events: fewEvents });
    const manyGaps = discoverCoverageGaps({ events: manyEvents });

    // Find the T1033 gaps
    const fewT1033 = fewGaps.find((g) => g.techniqueHints.includes("T1033"));
    const manyT1033 = manyGaps.find((g) => g.techniqueHints.includes("T1033"));

    expect(fewT1033).toBeDefined();
    expect(manyT1033).toBeDefined();
    expect(manyT1033!.confidence).toBeGreaterThan(fewT1033!.confidence);
  });

  it("data source families map correctly from action types", () => {
    const fileEvents = [
      makeEvent({ target: "/etc/passwd", actionType: "file_access" }),
    ];
    const networkEvents = [
      makeEvent({ target: "evil.com", actionType: "network_egress" }),
    ];

    const fileGaps = discoverCoverageGaps({ events: fileEvents });
    const networkGaps = discoverCoverageGaps({ events: networkEvents });

    // File events should produce "file" data source hint
    for (const gap of fileGaps) {
      if (gap.dataSourceHints.length > 0) {
        expect(gap.dataSourceHints).toContain("file");
      }
    }

    // Network events should produce "network" data source hint
    for (const gap of networkGaps) {
      if (gap.dataSourceHints.length > 0) {
        expect(gap.dataSourceHints).toContain("network");
      }
    }
  });
});
