import { describe, it, expect } from "vitest";
import type { Finding, Enrichment } from "../finding-engine";
import type { Signal } from "../signal-pipeline";
import type { DraftSeed } from "../detection-workflow/shared-types";
import {
  mapFindingToDraftSeed,
  recommendFormats,
} from "../detection-workflow/draft-mappers";

// ---- Test Helpers ----

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "fnd_test001",
    title: "Suspicious activity on agent-1",
    status: "confirmed",
    severity: "high",
    confidence: 0.85,
    signalIds: ["sig-1", "sig-2"],
    signalCount: 2,
    scope: {
      agentIds: ["agent-1"],
      sessionIds: ["session-1"],
      timeRange: {
        start: new Date(Date.now() - 3600000).toISOString(),
        end: new Date().toISOString(),
      },
    },
    timeline: [],
    enrichments: [],
    annotations: [],
    verdict: null,
    actions: [],
    promotedToIntel: null,
    receipt: null,
    speakeasyId: null,
    createdBy: "sentinel-1",
    updatedBy: "sentinel-1",
    createdAt: Date.now() - 3600000,
    updatedAt: Date.now(),
    ...overrides,
  };
}

function makeSignal(overrides: Partial<Signal> = {}): Signal {
  return {
    id: "sig-1",
    type: "detection",
    source: {
      sentinelId: "sentinel-1",
      guardId: "guard-1",
      externalFeed: null,
      provenance: "guard_evaluation",
    },
    timestamp: Date.now(),
    severity: "high",
    confidence: 0.9,
    data: {
      kind: "policy_violation",
      summary: "Shell command blocked",
      actionType: "shell_command",
      sourceEventId: "evt-1",
    },
    context: {
      agentId: "agent-1",
      agentName: "TestAgent",
      sessionId: "session-1",
      flags: [],
    },
    relatedSignals: [],
    ttl: null,
    findingId: null,
    ...overrides,
  };
}

function makeMitreEnrichment(
  techniques: Array<{ id: string; name: string; tactic: string }>,
): Enrichment {
  return {
    id: "enr_mitre_001",
    type: "mitre_attack",
    label: `MITRE ATT&CK: ${techniques.length} technique(s)`,
    data: {
      kind: "mitre_attack",
      techniques,
      killChainDepth: new Set(techniques.map((t) => t.tactic)).size,
      tactics: [...new Set(techniques.map((t) => t.tactic))],
    },
    addedAt: Date.now(),
    source: "enrichment_pipeline",
  };
}

function makeIocEnrichment(
  indicators: Array<{ indicator: string; iocType: string }>,
): Enrichment {
  return {
    id: "enr_ioc_001",
    type: "ioc_extraction",
    label: `${indicators.length} IOC(s) extracted`,
    data: {
      kind: "ioc_lookup",
      indicators,
      count: indicators.length,
    },
    addedAt: Date.now(),
    source: "enrichment_pipeline",
  };
}

// ---- Tests ----

describe("mapFindingToDraftSeed", () => {
  it("returns a seed with kind 'finding' and correct findingId", () => {
    const finding = makeFinding();
    const signals = [makeSignal({ id: "sig-1" }), makeSignal({ id: "sig-2" })];

    const seed = mapFindingToDraftSeed(finding, signals);

    expect(seed.kind).toBe("finding");
    expect(seed.findingId).toBe("fnd_test001");
    expect(seed.id).toBeTruthy();
    expect(seed.createdAt).toBeTruthy();
  });

  it("extracts MITRE technique hints from mitre_attack enrichments", () => {
    const finding = makeFinding({
      enrichments: [
        makeMitreEnrichment([
          { id: "T1059.001", name: "PowerShell", tactic: "execution" },
          { id: "T1552.004", name: "Private Keys", tactic: "credential-access" },
        ]),
      ],
    });
    const signals = [makeSignal({ id: "sig-1" }), makeSignal({ id: "sig-2" })];

    const seed = mapFindingToDraftSeed(finding, signals);

    expect(seed.techniqueHints).toContain("T1059.001");
    expect(seed.techniqueHints).toContain("T1552.004");
  });

  it("extracts data source hints from signal action types", () => {
    const finding = makeFinding();
    const signals = [
      makeSignal({
        id: "sig-1",
        data: {
          kind: "policy_violation",
          actionType: "shell_command",
          sourceEventId: "evt-1",
        },
      }),
      makeSignal({
        id: "sig-2",
        data: {
          kind: "detection",
          actionType: "file_access",
          sourceEventId: "evt-2",
        },
      }),
    ];

    const seed = mapFindingToDraftSeed(finding, signals);

    expect(seed.dataSourceHints).toContain("process");
    expect(seed.dataSourceHints).toContain("command");
    expect(seed.dataSourceHints).toContain("file");
  });

  it("extracts IOC indicators from ioc_extraction enrichments into extractedFields", () => {
    const iocs = [
      { indicator: "192.168.1.100", iocType: "ip" },
      { indicator: "evil.example.com", iocType: "domain" },
    ];
    const finding = makeFinding({
      enrichments: [makeIocEnrichment(iocs)],
    });
    const signals = [makeSignal({ id: "sig-1" }), makeSignal({ id: "sig-2" })];

    const seed = mapFindingToDraftSeed(finding, signals);

    const extracted = seed.extractedFields as Record<string, unknown>;
    expect(extracted.iocIndicators).toBeDefined();
    const iocIndicators = extracted.iocIndicators as Array<{
      indicator: string;
      iocType: string;
    }>;
    expect(iocIndicators).toHaveLength(2);
    expect(iocIndicators[0].indicator).toBe("192.168.1.100");
    expect(iocIndicators[1].iocType).toBe("domain");
  });

  it("confidence in seed matches finding.confidence", () => {
    const finding = makeFinding({ confidence: 0.92 });
    const signals = [makeSignal({ id: "sig-1" }), makeSignal({ id: "sig-2" })];

    const seed = mapFindingToDraftSeed(finding, signals);

    expect(seed.confidence).toBe(0.92);
  });

  it("recommendFormats returns ['ocsf_event', 'sigma_rule'] for finding seeds", () => {
    const seed: DraftSeed = {
      id: "test-seed",
      kind: "finding",
      sourceEventIds: [],
      findingId: "fnd_001",
      preferredFormats: [],
      techniqueHints: [],
      dataSourceHints: [],
      extractedFields: {},
      createdAt: new Date().toISOString(),
      confidence: 0.8,
    };

    const formats = recommendFormats(seed);

    expect(formats).toEqual(["ocsf_event", "sigma_rule"]);
  });

  it("merges selectedGap.techniqueHints into seed.techniqueHints", () => {
    const finding = makeFinding({
      enrichments: [
        makeMitreEnrichment([
          { id: "T1059", name: "Command and Scripting Interpreter", tactic: "execution" },
        ]),
      ],
    });
    const signals = [makeSignal({ id: "sig-1" }), makeSignal({ id: "sig-2" })];
    const gap = {
      id: "gap-1",
      sourceKind: "investigation" as const,
      sourceIds: ["inv-1"],
      severity: "high" as const,
      confidence: 0.9,
      suggestedFormats: ["sigma_rule" as const],
      techniqueHints: ["T1105", "T1095"],
      dataSourceHints: ["network"],
      rationale: "Network exfiltration gap",
    };

    const seed = mapFindingToDraftSeed(finding, signals, gap);

    expect(seed.techniqueHints).toContain("T1059");
    expect(seed.techniqueHints).toContain("T1105");
    expect(seed.techniqueHints).toContain("T1095");
    expect(seed.dataSourceHints).toContain("network");
    // Gap formats should be used as preferred
    expect(seed.preferredFormats).toContain("sigma_rule");
  });
});
