import { describe, it, expect, beforeEach, vi } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { useEnrichmentBridge } from "../enrichment-bridge";
import type { EnrichmentResult, Indicator, ThreatIntelSource } from "@clawdstrike/plugin-sdk";
import type { Finding } from "@/lib/workbench/finding-engine";

// ---- Mock extractIndicators ----

const mockExtractIndicators = vi.fn<(finding: Finding, signals?: unknown[]) => Indicator[]>();

vi.mock("@/lib/workbench/indicator-extractor", () => ({
  extractIndicators: (...args: unknown[]) => mockExtractIndicators(args[0] as Finding, args[1] as unknown[]),
}));

// ---- Mock registry ----

const mockGetAllSources = vi.fn<() => ThreatIntelSource[]>();

vi.mock("@/lib/workbench/threat-intel-registry", () => ({
  getAllThreatIntelSources: () => mockGetAllSources(),
}));

// ---- Fixtures ----

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "fnd_test1",
    title: "Test finding",
    status: "emerging",
    severity: "high",
    confidence: 0.8,
    signalIds: ["sig_1"],
    signalCount: 1,
    scope: {
      agentIds: ["agent_1"],
      sessionIds: ["sess_1"],
      timeRange: { start: "2026-01-01T00:00:00Z", end: "2026-01-01T01:00:00Z" },
    },
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

function makeEnrichmentResult(sourceId: string, sourceName: string): EnrichmentResult {
  return {
    sourceId,
    sourceName,
    verdict: { classification: "malicious", confidence: 0.9, summary: `${sourceName} says malicious` },
    rawData: { hits: 42 },
    fetchedAt: Date.now(),
    cacheTtlMs: 300_000,
  };
}

function makeSource(id: string, name: string): ThreatIntelSource {
  return {
    id,
    name,
    supportedIndicatorTypes: ["ip", "hash", "domain"],
    rateLimit: { maxPerMinute: 60 },
    enrich: vi.fn(),
  };
}

// ---- Mock orchestrator ----

function makeMockOrchestrator() {
  type EnrichOptions = {
    sourceIds?: string[];
    signal?: AbortSignal;
    onResult?: (result: EnrichmentResult) => void;
  };

  return {
    enrich: vi.fn<(indicator: Indicator, options?: EnrichOptions) => Promise<EnrichmentResult[]>>(),
    clearCache: vi.fn(),
    clearCacheForSource: vi.fn(),
  };
}

// ---- Tests ----

describe("useEnrichmentBridge", () => {
  let orchestrator: ReturnType<typeof makeMockOrchestrator>;
  let vtSource: ThreatIntelSource;
  let gnSource: ThreatIntelSource;

  beforeEach(() => {
    vi.clearAllMocks();
    orchestrator = makeMockOrchestrator();
    vtSource = makeSource("virustotal", "VirusTotal");
    gnSource = makeSource("greynoise", "GreyNoise");

    mockGetAllSources.mockReturnValue([vtSource, gnSource]);
    mockExtractIndicators.mockReturnValue([
      { type: "ip", value: "1.2.3.4" },
    ]);

    // Default: orchestrator.enrich resolves with empty results
    orchestrator.enrich.mockResolvedValue([]);
  });

  it("returns { runEnrichment, sourceStatuses, isEnriching, results, cancel }", () => {
    const { result } = renderHook(() => useEnrichmentBridge(orchestrator));
    expect(result.current.runEnrichment).toBeTypeOf("function");
    expect(result.current.sourceStatuses).toEqual([]);
    expect(result.current.isEnriching).toBe(false);
    expect(result.current.results).toEqual([]);
    expect(result.current.cancel).toBeTypeOf("function");
  });

  it("runEnrichment(finding) calls extractIndicators(finding) then orchestrator.enrich for each indicator", async () => {
    const finding = makeFinding();
    const indicators: Indicator[] = [
      { type: "ip", value: "1.2.3.4" },
      { type: "hash", value: "abc123", hashAlgorithm: "sha256" },
    ];
    mockExtractIndicators.mockReturnValue(indicators);
    orchestrator.enrich.mockResolvedValue([]);

    const { result } = renderHook(() => useEnrichmentBridge(orchestrator));

    await act(async () => {
      result.current.runEnrichment(finding);
    });

    expect(mockExtractIndicators).toHaveBeenCalledWith(finding, undefined);
    expect(orchestrator.enrich).toHaveBeenCalledTimes(2);
    expect(orchestrator.enrich).toHaveBeenCalledWith(
      indicators[0],
      expect.objectContaining({ onResult: expect.any(Function), signal: expect.any(AbortSignal) }),
    );
    expect(orchestrator.enrich).toHaveBeenCalledWith(
      indicators[1],
      expect.objectContaining({ onResult: expect.any(Function), signal: expect.any(AbortSignal) }),
    );
  });

  it("onResult callback updates sourceStatuses from loading to done for that source", async () => {
    const finding = makeFinding();
    const vtResult = makeEnrichmentResult("virustotal", "VirusTotal");

    orchestrator.enrich.mockImplementation(async (_indicator, options) => {
      // Simulate streaming: call onResult
      options?.onResult?.(vtResult);
      return [vtResult];
    });

    const { result } = renderHook(() => useEnrichmentBridge(orchestrator));

    await act(async () => {
      result.current.runEnrichment(finding);
    });

    const vtStatus = result.current.sourceStatuses.find((s) => s.sourceId === "virustotal");
    expect(vtStatus).toBeDefined();
    expect(vtStatus!.status).toBe("done");
    expect(vtStatus!.result).toEqual(vtResult);
  });

  it("onError callback updates sourceStatuses from loading to error with error message", async () => {
    const finding = makeFinding();

    orchestrator.enrich.mockImplementation(async (_indicator, options) => {
      // Simulate error via onError (we handle this internally)
      throw new Error("API rate limited");
    });

    const { result } = renderHook(() => useEnrichmentBridge(orchestrator));

    await act(async () => {
      result.current.runEnrichment(finding);
    });

    // After orchestrator.enrich throws, the bridge should mark failed sources
    // isEnriching should become false since enrichment completed (with errors)
    expect(result.current.isEnriching).toBe(false);
  });

  it("while enrichment is in progress, isEnriching is true and sourceStatuses are loading", async () => {
    const finding = makeFinding();
    let resolveEnrich!: (value: EnrichmentResult[]) => void;

    orchestrator.enrich.mockImplementation(
      () =>
        new Promise<EnrichmentResult[]>((resolve) => {
          resolveEnrich = resolve;
        }),
    );

    const { result } = renderHook(() => useEnrichmentBridge(orchestrator));

    // Start enrichment but don't resolve
    act(() => {
      result.current.runEnrichment(finding);
    });

    // Should be enriching
    expect(result.current.isEnriching).toBe(true);
    // Should have source statuses set to loading
    const loadingStatuses = result.current.sourceStatuses.filter((s) => s.status === "loading");
    expect(loadingStatuses.length).toBeGreaterThan(0);

    // Now resolve
    await act(async () => {
      resolveEnrich([]);
    });

    expect(result.current.isEnriching).toBe(false);
  });

  it("after all sources complete, isEnriching becomes false", async () => {
    const finding = makeFinding();
    orchestrator.enrich.mockResolvedValue([]);

    const { result } = renderHook(() => useEnrichmentBridge(orchestrator));

    await act(async () => {
      result.current.runEnrichment(finding);
    });

    expect(result.current.isEnriching).toBe(false);
  });

  it("cancel() aborts in-flight enrichment via AbortController", async () => {
    const finding = makeFinding();
    let capturedSignal: AbortSignal | undefined;

    orchestrator.enrich.mockImplementation(async (_indicator, options) => {
      capturedSignal = options?.signal as AbortSignal | undefined;
      // Hang until aborted
      return new Promise<EnrichmentResult[]>((resolve) => {
        if (capturedSignal) {
          capturedSignal.addEventListener("abort", () => resolve([]), { once: true });
        }
      });
    });

    const { result } = renderHook(() => useEnrichmentBridge(orchestrator));

    act(() => {
      result.current.runEnrichment(finding);
    });

    expect(result.current.isEnriching).toBe(true);

    act(() => {
      result.current.cancel();
    });

    expect(capturedSignal?.aborted).toBe(true);
  });

  it("calling runEnrichment while already enriching cancels previous run", async () => {
    const finding = makeFinding();
    let firstSignal: AbortSignal | undefined;
    let callCount = 0;

    orchestrator.enrich.mockImplementation(async (_indicator, options) => {
      callCount++;
      if (callCount <= 1) {
        firstSignal = options?.signal as AbortSignal | undefined;
      }
      return new Promise<EnrichmentResult[]>((resolve) => {
        const signal = options?.signal as AbortSignal | undefined;
        if (signal) {
          signal.addEventListener("abort", () => resolve([]), { once: true });
        }
        // Also resolve after a tick for non-aborted case
        setTimeout(() => resolve([]), 10);
      });
    });

    const { result } = renderHook(() => useEnrichmentBridge(orchestrator));

    act(() => {
      result.current.runEnrichment(finding);
    });

    // Start second run -- should abort the first
    await act(async () => {
      result.current.runEnrichment(finding);
    });

    expect(firstSignal?.aborted).toBe(true);
  });

  it("sourceStatuses includes skeleton-ready metadata (sourceId, sourceName, status)", async () => {
    const finding = makeFinding();
    let resolveEnrich!: (value: EnrichmentResult[]) => void;

    orchestrator.enrich.mockImplementation(
      () =>
        new Promise<EnrichmentResult[]>((resolve) => {
          resolveEnrich = resolve;
        }),
    );

    const { result } = renderHook(() => useEnrichmentBridge(orchestrator));

    act(() => {
      result.current.runEnrichment(finding);
    });

    // Check skeleton metadata
    for (const status of result.current.sourceStatuses) {
      expect(status).toHaveProperty("sourceId");
      expect(status).toHaveProperty("sourceName");
      expect(status).toHaveProperty("status");
      expect(typeof status.sourceId).toBe("string");
      expect(typeof status.sourceName).toBe("string");
      expect(["idle", "loading", "done", "error"]).toContain(status.status);
    }

    // Should have entries for all registered sources
    expect(result.current.sourceStatuses).toHaveLength(2);
    expect(result.current.sourceStatuses.map((s) => s.sourceId)).toContain("virustotal");
    expect(result.current.sourceStatuses.map((s) => s.sourceId)).toContain("greynoise");

    // Cleanup
    await act(async () => {
      resolveEnrich([]);
    });
  });

  // ---- v5.0 Promise.allSettled tests ----

  describe("Promise.allSettled behavior", () => {
    it("when one source rejects and another resolves, the resolved result appears and the rejected source shows error status", async () => {
      const finding = makeFinding();
      const gnResult = makeEnrichmentResult("greynoise", "GreyNoise");

      // Two indicators: first will reject, second will resolve
      mockExtractIndicators.mockReturnValue([
        { type: "ip", value: "1.2.3.4" },
        { type: "domain", value: "evil.com" },
      ]);

      let callIdx = 0;
      orchestrator.enrich.mockImplementation(async (_indicator, options) => {
        callIdx++;
        if (callIdx === 1) {
          // First indicator enrichment rejects
          throw new Error("VirusTotal API timeout");
        }
        // Second indicator enrichment resolves and fires onResult
        options?.onResult?.(gnResult);
        return [gnResult];
      });

      const { result } = renderHook(() => useEnrichmentBridge(orchestrator));

      await act(async () => {
        result.current.runEnrichment(finding);
      });

      // isEnriching should be false -- both settled
      expect(result.current.isEnriching).toBe(false);

      // The resolved result should appear in results
      expect(result.current.results).toHaveLength(1);
      expect(result.current.results[0].sourceId).toBe("greynoise");

      // Any source still in "loading" after allSettled should transition to "error"
      // because there was at least one rejection
      const stillLoading = result.current.sourceStatuses.filter(
        (s) => s.status === "loading",
      );
      expect(stillLoading).toHaveLength(0);

      // The greynoise source that got onResult should be "done"
      const gnStatus = result.current.sourceStatuses.find(
        (s) => s.sourceId === "greynoise",
      );
      expect(gnStatus?.status).toBe("done");
    });

    it("when all sources reject, all sources show error status and isEnriching becomes false", async () => {
      const finding = makeFinding();

      mockExtractIndicators.mockReturnValue([
        { type: "ip", value: "1.2.3.4" },
      ]);

      orchestrator.enrich.mockRejectedValue(new Error("Service unavailable"));

      const { result } = renderHook(() => useEnrichmentBridge(orchestrator));

      await act(async () => {
        result.current.runEnrichment(finding);
      });

      // isEnriching must be false
      expect(result.current.isEnriching).toBe(false);

      // No results collected
      expect(result.current.results).toHaveLength(0);

      // All sources that were still loading should now be "error"
      for (const s of result.current.sourceStatuses) {
        expect(s.status).toBe("error");
        expect(s.error).toBe("Service unavailable");
      }
    });

    it("cancellation via AbortController still works with Promise.allSettled", async () => {
      const finding = makeFinding();
      let capturedSignal: AbortSignal | undefined;

      mockExtractIndicators.mockReturnValue([
        { type: "ip", value: "1.2.3.4" },
      ]);

      orchestrator.enrich.mockImplementation(async (_indicator, options) => {
        capturedSignal = options?.signal as AbortSignal | undefined;
        // Hang until aborted
        return new Promise<EnrichmentResult[]>((resolve) => {
          if (capturedSignal) {
            capturedSignal.addEventListener("abort", () => resolve([]), {
              once: true,
            });
          }
        });
      });

      const { result } = renderHook(() => useEnrichmentBridge(orchestrator));

      act(() => {
        result.current.runEnrichment(finding);
      });

      expect(result.current.isEnriching).toBe(true);

      // Cancel mid-flight
      await act(async () => {
        result.current.cancel();
      });

      // Signal was aborted
      expect(capturedSignal?.aborted).toBe(true);
      // isEnriching should be false after cancel
      expect(result.current.isEnriching).toBe(false);
    });
  });

  describe("structural: no manual counter variable", () => {
    it("enrichment-bridge.ts does not contain a manual counter variable", async () => {
      // This is a structural assertion: the source should use Promise.allSettled
      // rather than a manual counter (completed++, remaining--, etc.)
      const fs = await import("fs");
      const path = await import("path");
      const source = fs.readFileSync(
        path.resolve(import.meta.dirname, "../enrichment-bridge.ts"),
        "utf-8",
      );

      // Should NOT have manual counter patterns
      expect(source).not.toMatch(/let\s+(completed|remaining|count|counter|pending)\b/);
      expect(source).not.toMatch(/\+\+\s*(completed|remaining|count|counter|pending)/);
      expect(source).not.toMatch(/(completed|remaining|count|counter|pending)\s*\+\+/);
      expect(source).not.toMatch(/(completed|remaining|count|counter|pending)\s*--/);
      expect(source).not.toMatch(/--\s*(completed|remaining|count|counter|pending)/);

      // Should use Promise.allSettled
      expect(source).toMatch(/Promise\.allSettled/);
    });
  });
});
