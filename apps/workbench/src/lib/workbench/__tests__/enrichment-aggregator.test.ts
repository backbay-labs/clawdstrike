import { describe, it, expect } from "vitest";
import {
  aggregateIndicators,
  aggregateVerdictsBySource,
  getSourceHealthSummary,
  type IndicatorAggregation,
  type VerdictSummary,
  type SourceHealthInput,
  type SourceHealthStatus,
} from "../enrichment-aggregator";
import type { Finding } from "../finding-engine";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeFinding(
  overrides: Partial<Finding> & { id: string; title: string },
): Finding {
  return {
    status: "emerging",
    severity: "medium",
    confidence: 0.7,
    signalIds: [],
    signalCount: 0,
    scope: { agentIds: [], sessionIds: [], timeRange: { start: "", end: "" } },
    timeline: [],
    enrichments: [],
    annotations: [],
    verdict: null,
    actions: [],
    promotedToIntel: null,
    receipt: null,
    speakeasyId: null,
    createdBy: "test",
    updatedBy: "test",
    createdAt: Date.now(),
    updatedAt: Date.now(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// aggregateIndicators
// ---------------------------------------------------------------------------

describe("aggregateIndicators", () => {
  it("returns empty array when no findings have ioc_extraction enrichments", () => {
    const findings = [makeFinding({ id: "f1", title: "Finding 1" })];
    expect(aggregateIndicators(findings)).toEqual([]);
  });

  it("identifies indicators shared across multiple findings", () => {
    const findingA = makeFinding({
      id: "fA",
      title: "Finding A",
      enrichments: [
        {
          id: "e1",
          type: "ioc_extraction",
          label: "IOCs",
          data: {
            indicators: [
              { indicator: "1.2.3.4", iocType: "ip" },
              { indicator: "evil.com", iocType: "domain" },
            ],
          },
          addedAt: 1000,
          source: "pipeline",
        },
      ],
    });

    const findingB = makeFinding({
      id: "fB",
      title: "Finding B",
      enrichments: [
        {
          id: "e2",
          type: "ioc_extraction",
          label: "IOCs",
          data: {
            indicators: [
              { indicator: "5.6.7.8", iocType: "ip" },
            ],
          },
          addedAt: 2000,
          source: "pipeline",
        },
      ],
    });

    const findingC = makeFinding({
      id: "fC",
      title: "Finding C",
      enrichments: [
        {
          id: "e3",
          type: "ioc_extraction",
          label: "IOCs",
          data: {
            indicators: [
              { indicator: "1.2.3.4", iocType: "ip" },
            ],
          },
          addedAt: 3000,
          source: "pipeline",
        },
      ],
    });

    const result = aggregateIndicators([findingA, findingB, findingC]);

    // "1.2.3.4" appears in fA and fC => count 2, sorted first
    const ipAgg = result.find((r) => r.indicator === "1.2.3.4");
    expect(ipAgg).toBeDefined();
    expect(ipAgg!.count).toBe(2);
    expect(ipAgg!.findingIds).toContain("fA");
    expect(ipAgg!.findingIds).toContain("fC");
    expect(ipAgg!.iocType).toBe("ip");

    // Sorted by count desc: cross-finding indicators first
    expect(result[0].indicator).toBe("1.2.3.4");
  });

  it("deduplicates by (iocType, indicator) tuple", () => {
    const finding = makeFinding({
      id: "f1",
      title: "Finding 1",
      enrichments: [
        {
          id: "e1",
          type: "ioc_extraction",
          label: "IOCs",
          data: {
            indicators: [
              { indicator: "1.2.3.4", iocType: "ip" },
              { indicator: "1.2.3.4", iocType: "ip" }, // duplicate
            ],
          },
          addedAt: 1000,
          source: "pipeline",
        },
      ],
    });

    const result = aggregateIndicators([finding]);
    const ipMatches = result.filter((r) => r.indicator === "1.2.3.4");
    expect(ipMatches).toHaveLength(1);
    expect(ipMatches[0].count).toBe(1);
  });

  it("tracks findingTitles alongside findingIds", () => {
    const findingA = makeFinding({
      id: "fA",
      title: "Alpha Finding",
      enrichments: [
        {
          id: "e1",
          type: "ioc_extraction",
          label: "IOCs",
          data: { indicators: [{ indicator: "hash123", iocType: "sha256" }] },
          addedAt: 1000,
          source: "pipeline",
        },
      ],
    });

    const findingB = makeFinding({
      id: "fB",
      title: "Beta Finding",
      enrichments: [
        {
          id: "e2",
          type: "ioc_extraction",
          label: "IOCs",
          data: { indicators: [{ indicator: "hash123", iocType: "sha256" }] },
          addedAt: 2000,
          source: "pipeline",
        },
      ],
    });

    const result = aggregateIndicators([findingA, findingB]);
    const agg = result.find((r) => r.indicator === "hash123");
    expect(agg!.findingTitles).toContain("Alpha Finding");
    expect(agg!.findingTitles).toContain("Beta Finding");
  });

  it("tracks lastSeenAt as most recent addedAt", () => {
    const findingA = makeFinding({
      id: "fA",
      title: "Finding A",
      enrichments: [
        {
          id: "e1",
          type: "ioc_extraction",
          label: "IOCs",
          data: { indicators: [{ indicator: "1.2.3.4", iocType: "ip" }] },
          addedAt: 1000,
          source: "pipeline",
        },
      ],
    });

    const findingB = makeFinding({
      id: "fB",
      title: "Finding B",
      enrichments: [
        {
          id: "e2",
          type: "ioc_extraction",
          label: "IOCs",
          data: { indicators: [{ indicator: "1.2.3.4", iocType: "ip" }] },
          addedAt: 5000,
          source: "pipeline",
        },
      ],
    });

    const result = aggregateIndicators([findingA, findingB]);
    expect(result[0].lastSeenAt).toBe(5000);
  });
});

// ---------------------------------------------------------------------------
// aggregateVerdictsBySource
// ---------------------------------------------------------------------------

describe("aggregateVerdictsBySource", () => {
  it("groups enrichments by source and counts verdicts", () => {
    const finding = makeFinding({
      id: "f1",
      title: "Finding 1",
      enrichments: [
        {
          id: "e1",
          type: "reputation",
          label: "VT",
          data: { verdict: "malicious" },
          addedAt: 1000,
          source: "virustotal",
        },
        {
          id: "e2",
          type: "reputation",
          label: "VT2",
          data: { verdict: "benign" },
          addedAt: 2000,
          source: "virustotal",
        },
        {
          id: "e3",
          type: "reputation",
          label: "GN",
          data: { classification: "suspicious" },
          addedAt: 3000,
          source: "greynoise",
        },
      ],
    });

    const result = aggregateVerdictsBySource([finding]);

    // Should have 2 sources
    expect(result).toHaveLength(2);

    const vt = result.find((r) => r.sourceId === "virustotal");
    expect(vt).toBeDefined();
    expect(vt!.total).toBe(2);
    expect(vt!.malicious).toBe(1);
    expect(vt!.benign).toBe(1);
    expect(vt!.unknown).toBe(0);
    expect(vt!.suspicious).toBe(0);

    const gn = result.find((r) => r.sourceId === "greynoise");
    expect(gn).toBeDefined();
    expect(gn!.total).toBe(1);
    expect(gn!.suspicious).toBe(1);
  });

  it("classifies enrichments without verdict data as unknown", () => {
    const finding = makeFinding({
      id: "f1",
      title: "Finding 1",
      enrichments: [
        {
          id: "e1",
          type: "reputation",
          label: "Test",
          data: { someOtherField: true },
          addedAt: 1000,
          source: "testsource",
        },
      ],
    });

    const result = aggregateVerdictsBySource([finding]);
    expect(result[0].unknown).toBe(1);
  });

  it("returns empty array when no findings have enrichments", () => {
    const findings = [makeFinding({ id: "f1", title: "Finding 1" })];
    expect(aggregateVerdictsBySource(findings)).toEqual([]);
  });

  it("sorts by total desc", () => {
    const finding = makeFinding({
      id: "f1",
      title: "Finding 1",
      enrichments: [
        { id: "e1", type: "reputation", label: "A", data: { verdict: "malicious" }, addedAt: 1, source: "sourceA" },
        { id: "e2", type: "reputation", label: "B", data: { verdict: "benign" }, addedAt: 2, source: "sourceB" },
        { id: "e3", type: "reputation", label: "A2", data: { verdict: "malicious" }, addedAt: 3, source: "sourceA" },
        { id: "e4", type: "reputation", label: "A3", data: { verdict: "suspicious" }, addedAt: 4, source: "sourceA" },
      ],
    });

    const result = aggregateVerdictsBySource([finding]);
    // sourceA has 3 enrichments, sourceB has 1
    expect(result[0].sourceId).toBe("sourceA");
    expect(result[0].total).toBe(3);
    expect(result[1].sourceId).toBe("sourceB");
    expect(result[1].total).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// getSourceHealthSummary
// ---------------------------------------------------------------------------

describe("getSourceHealthSummary", () => {
  const NOW = Date.now();
  const ONE_HOUR = 60 * 60 * 1000;

  it("returns healthy when quota is low and recent success", () => {
    const sources: SourceHealthInput[] = [
      {
        id: "vt",
        name: "VirusTotal",
        rateLimit: { maxPerMinute: 4 },
        quotaUsed: 100,
        quotaTotal: 500,
        lastSuccessAt: NOW - 5000,
        lastErrorAt: null,
      },
    ];

    const result = getSourceHealthSummary(sources);
    expect(result).toHaveLength(1);
    expect(result[0].health).toBe("healthy");
    expect(result[0].quotaPercent).toBe(20);
  });

  it("returns degraded when quota > 80%", () => {
    const sources: SourceHealthInput[] = [
      {
        id: "gn",
        name: "GreyNoise",
        rateLimit: { maxPerMinute: 10 },
        quotaUsed: 850,
        quotaTotal: 1000,
        lastSuccessAt: NOW - 5000,
        lastErrorAt: null,
      },
    ];

    const result = getSourceHealthSummary(sources);
    expect(result[0].health).toBe("degraded");
    expect(result[0].quotaPercent).toBe(85);
  });

  it("returns unhealthy when quota > 95%", () => {
    const sources: SourceHealthInput[] = [
      {
        id: "sh",
        name: "Shodan",
        rateLimit: { maxPerMinute: 1 },
        quotaUsed: 960,
        quotaTotal: 1000,
        lastSuccessAt: NOW - 5000,
        lastErrorAt: null,
      },
    ];

    const result = getSourceHealthSummary(sources);
    expect(result[0].health).toBe("unhealthy");
    expect(result[0].quotaPercent).toBe(96);
  });

  it("returns degraded when error in last hour", () => {
    const sources: SourceHealthInput[] = [
      {
        id: "ab",
        name: "AbuseIPDB",
        rateLimit: { maxPerMinute: 5 },
        quotaUsed: 50,
        quotaTotal: 1000,
        lastSuccessAt: NOW - 5000,
        lastErrorAt: NOW - 10000, // 10s ago (within last hour)
        lastErrorMessage: "Rate limited",
      },
    ];

    const result = getSourceHealthSummary(sources);
    expect(result[0].health).toBe("degraded");
  });

  it("returns unhealthy when error recent and no success since", () => {
    const sources: SourceHealthInput[] = [
      {
        id: "otx",
        name: "OTX",
        rateLimit: { maxPerMinute: 10 },
        quotaUsed: 0,
        quotaTotal: 1000,
        lastSuccessAt: null,
        lastErrorAt: NOW - 10000,
        lastErrorMessage: "Connection refused",
      },
    ];

    const result = getSourceHealthSummary(sources);
    expect(result[0].health).toBe("unhealthy");
  });

  it("returns quotaPercent of 0 when quotaTotal is 0", () => {
    const sources: SourceHealthInput[] = [
      {
        id: "x",
        name: "NoQuota",
        rateLimit: { maxPerMinute: 10 },
        quotaUsed: 0,
        quotaTotal: 0,
        lastSuccessAt: NOW - 5000,
        lastErrorAt: null,
      },
    ];

    const result = getSourceHealthSummary(sources);
    expect(result[0].quotaPercent).toBe(0);
    expect(result[0].health).toBe("healthy");
  });

  it("preserves all input fields in output", () => {
    const sources: SourceHealthInput[] = [
      {
        id: "vt",
        name: "VirusTotal",
        rateLimit: { maxPerMinute: 4 },
        quotaUsed: 100,
        quotaTotal: 500,
        lastSuccessAt: NOW - 5000,
        lastErrorAt: null,
        lastErrorMessage: undefined,
      },
    ];

    const result = getSourceHealthSummary(sources);
    expect(result[0].id).toBe("vt");
    expect(result[0].name).toBe("VirusTotal");
    expect(result[0].rateLimit.maxPerMinute).toBe(4);
    expect(result[0].quotaUsed).toBe(100);
    expect(result[0].quotaTotal).toBe(500);
    expect(result[0].lastSuccessAt).toBe(NOW - 5000);
    expect(result[0].lastErrorAt).toBeNull();
  });
});
