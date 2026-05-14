/**
 * Auto-enrichment manager tests.
 *
 * Validates that AutoEnrichmentManager:
 * - Respects enabled/disabled config
 * - Gates on confidence threshold
 * - Filters by sentinel and source
 * - Skips already-enriched sources
 * - Debounces rapid duplicate calls
 * - Persists config to localStorage
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  AutoEnrichmentManager,
  type AutoEnrichmentConfig,
} from "../auto-enrichment";
import type { Finding, Enrichment } from "../finding-engine";
import type { Indicator, EnrichmentResult } from "@clawdstrike/plugin-sdk";

// ---- Test helpers ----

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "fnd_test001",
    title: "Test finding",
    status: "emerging",
    severity: "high",
    confidence: 0.8,
    signalIds: ["sig_1"],
    signalCount: 1,
    scope: {
      agentIds: ["agent-1"],
      sessionIds: ["sess-1"],
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
    createdBy: "sentinel-alpha",
    updatedBy: "sentinel-alpha",
    createdAt: Date.now(),
    updatedAt: Date.now(),
    ...overrides,
  };
}

function makeEnrichment(source: string): Enrichment {
  return {
    id: "enr_test001",
    type: "reputation",
    label: `Enrichment from ${source}`,
    data: {},
    addedAt: Date.now(),
    source,
  };
}

function mockOrchestrator() {
  return {
    enrich: vi.fn().mockResolvedValue([]),
  };
}

function mockExtractIndicators(): (finding: Finding) => Indicator[] {
  return vi.fn().mockReturnValue([
    { type: "ip" as const, value: "1.2.3.4" },
    { type: "domain" as const, value: "evil.com" },
  ]);
}

describe("AutoEnrichmentManager", () => {
  let storage: Record<string, string>;

  beforeEach(() => {
    storage = {};
    vi.stubGlobal("localStorage", {
      getItem: vi.fn((key: string) => storage[key] ?? null),
      setItem: vi.fn((key: string, value: string) => {
        storage[key] = value;
      }),
      removeItem: vi.fn((key: string) => {
        delete storage[key];
      }),
    });
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  // Test 1: Config shape
  it("AutoEnrichmentConfig has enabled, confidenceThreshold, enabledSources, and enabledSentinels", () => {
    const config: AutoEnrichmentConfig = {
      enabled: true,
      confidenceThreshold: 0.7,
      enabledSources: ["vt", "gn"],
      enabledSentinels: ["sentinel-alpha"],
    };
    expect(config.enabled).toBe(true);
    expect(config.confidenceThreshold).toBe(0.7);
    expect(config.enabledSources).toEqual(["vt", "gn"]);
    expect(config.enabledSentinels).toEqual(["sentinel-alpha"]);
  });

  // Test 2: processNewFinding queues enrichment when enabled and above threshold
  it("processNewFinding() with enabled=true and confidence above threshold queues enrichment", () => {
    const orch = mockOrchestrator();
    const extract = mockExtractIndicators();
    const manager = new AutoEnrichmentManager({
      orchestrator: orch,
      extractIndicators: extract,
      config: {
        enabled: true,
        confidenceThreshold: 0.5,
        enabledSources: [],
        enabledSentinels: "all",
      },
    });

    const finding = makeFinding({ confidence: 0.8 });
    manager.processNewFinding(finding);

    expect(extract).toHaveBeenCalledWith(finding);
    expect(orch.enrich).toHaveBeenCalled();

    manager.destroy();
  });

  // Test 3: processNewFinding does NOT queue enrichment below threshold
  it("processNewFinding() with enabled=true and confidence below threshold does NOT queue enrichment", () => {
    const orch = mockOrchestrator();
    const extract = mockExtractIndicators();
    const manager = new AutoEnrichmentManager({
      orchestrator: orch,
      extractIndicators: extract,
      config: {
        enabled: true,
        confidenceThreshold: 0.9,
        enabledSources: [],
        enabledSentinels: "all",
      },
    });

    const finding = makeFinding({ confidence: 0.5 });
    manager.processNewFinding(finding);

    expect(orch.enrich).not.toHaveBeenCalled();

    manager.destroy();
  });

  // Test 4: processNewFinding does NOT queue enrichment when disabled
  it("processNewFinding() with enabled=false does NOT queue enrichment regardless of confidence", () => {
    const orch = mockOrchestrator();
    const extract = mockExtractIndicators();
    const manager = new AutoEnrichmentManager({
      orchestrator: orch,
      extractIndicators: extract,
      config: {
        enabled: false,
        confidenceThreshold: 0.1,
        enabledSources: [],
        enabledSentinels: "all",
      },
    });

    const finding = makeFinding({ confidence: 0.99 });
    manager.processNewFinding(finding);

    expect(orch.enrich).not.toHaveBeenCalled();

    manager.destroy();
  });

  // Test 5: processNewFinding respects enabledSentinels
  it("processNewFinding() respects enabledSentinels -- only enriches findings from listed sentinels", () => {
    const orch = mockOrchestrator();
    const extract = mockExtractIndicators();
    const manager = new AutoEnrichmentManager({
      orchestrator: orch,
      extractIndicators: extract,
      config: {
        enabled: true,
        confidenceThreshold: 0.5,
        enabledSources: [],
        enabledSentinels: ["sentinel-alpha"],
      },
    });

    // From non-listed sentinel -- should be skipped
    const finding = makeFinding({ createdBy: "sentinel-beta", confidence: 0.9 });
    manager.processNewFinding(finding);
    expect(orch.enrich).not.toHaveBeenCalled();

    // From listed sentinel -- should be enriched
    const finding2 = makeFinding({ id: "fnd_test002", createdBy: "sentinel-alpha", confidence: 0.9 });
    manager.processNewFinding(finding2);
    expect(orch.enrich).toHaveBeenCalled();

    manager.destroy();
  });

  // Test 6: processNewFinding with enabledSentinels="all" enriches all
  it("processNewFinding() with enabledSentinels='all' enriches findings from any sentinel", () => {
    const orch = mockOrchestrator();
    const extract = mockExtractIndicators();
    const manager = new AutoEnrichmentManager({
      orchestrator: orch,
      extractIndicators: extract,
      config: {
        enabled: true,
        confidenceThreshold: 0.5,
        enabledSources: [],
        enabledSentinels: "all",
      },
    });

    const finding = makeFinding({ createdBy: "sentinel-gamma", confidence: 0.9 });
    manager.processNewFinding(finding);
    expect(orch.enrich).toHaveBeenCalled();

    manager.destroy();
  });

  // Test 7: processNewFinding respects enabledSources
  it("processNewFinding() respects enabledSources -- only requests enrichment from listed source IDs", () => {
    const orch = mockOrchestrator();
    const extract = mockExtractIndicators();
    const manager = new AutoEnrichmentManager({
      orchestrator: orch,
      extractIndicators: extract,
      config: {
        enabled: true,
        confidenceThreshold: 0.5,
        enabledSources: ["virustotal", "greynoise"],
        enabledSentinels: "all",
      },
    });

    const finding = makeFinding({ confidence: 0.9 });
    manager.processNewFinding(finding);

    // The orchestrator should receive sourceIds filter
    expect(orch.enrich).toHaveBeenCalled();
    const call = orch.enrich.mock.calls[0];
    // Second arg is options with sourceIds
    expect(call[1]).toEqual(
      expect.objectContaining({ sourceIds: ["virustotal", "greynoise"] }),
    );

    manager.destroy();
  });

  // Test 8: processNewFinding skips sources that already enriched the finding
  it("processNewFinding() skips sources that have already enriched the finding (dedup check)", () => {
    const orch = mockOrchestrator();
    const extract = mockExtractIndicators();
    const manager = new AutoEnrichmentManager({
      orchestrator: orch,
      extractIndicators: extract,
      config: {
        enabled: true,
        confidenceThreshold: 0.5,
        enabledSources: ["virustotal", "greynoise"],
        enabledSentinels: "all",
      },
    });

    // Finding already has enrichment from "virustotal"
    const finding = makeFinding({
      confidence: 0.9,
      enrichments: [makeEnrichment("virustotal")],
    });
    manager.processNewFinding(finding);

    expect(orch.enrich).toHaveBeenCalled();
    const call = orch.enrich.mock.calls[0];
    // Should only include greynoise, virustotal already done
    expect(call[1]).toEqual(
      expect.objectContaining({ sourceIds: ["greynoise"] }),
    );

    manager.destroy();
  });

  // Test 9: processNewFinding debounces rapid successive calls for same finding ID
  it("processNewFinding() debounces rapid successive calls for the same finding ID (100ms window)", () => {
    const orch = mockOrchestrator();
    // Use single-indicator extractor so call counts are 1:1 with processNewFinding
    const extract = vi.fn().mockReturnValue([
      { type: "ip" as const, value: "1.2.3.4" },
    ]);
    const manager = new AutoEnrichmentManager({
      orchestrator: orch,
      extractIndicators: extract,
      config: {
        enabled: true,
        confidenceThreshold: 0.5,
        enabledSources: [],
        enabledSentinels: "all",
      },
    });

    const finding = makeFinding({ confidence: 0.9 });

    // Call three times rapidly
    manager.processNewFinding(finding);
    manager.processNewFinding(finding);
    manager.processNewFinding(finding);

    // Only first call should trigger enrichment (1 indicator = 1 enrich call)
    expect(orch.enrich).toHaveBeenCalledTimes(1);

    // After 100ms, a new call should work
    vi.advanceTimersByTime(101);
    manager.processNewFinding(finding);
    expect(orch.enrich).toHaveBeenCalledTimes(2);

    manager.destroy();
  });

  // Test 10: getConfig returns current configuration
  it("getConfig() returns current configuration", () => {
    const orch = mockOrchestrator();
    const extract = mockExtractIndicators();
    const config: AutoEnrichmentConfig = {
      enabled: true,
      confidenceThreshold: 0.7,
      enabledSources: ["vt"],
      enabledSentinels: "all",
    };
    const manager = new AutoEnrichmentManager({
      orchestrator: orch,
      extractIndicators: extract,
      config,
    });

    expect(manager.getConfig()).toEqual(config);

    manager.destroy();
  });

  // Test 11: updateConfig persists new configuration
  it("updateConfig() persists new configuration to localStorage", () => {
    const orch = mockOrchestrator();
    const extract = mockExtractIndicators();
    const manager = new AutoEnrichmentManager({
      orchestrator: orch,
      extractIndicators: extract,
    });

    manager.updateConfig({ enabled: true, confidenceThreshold: 0.8 });

    const config = manager.getConfig();
    expect(config.enabled).toBe(true);
    expect(config.confidenceThreshold).toBe(0.8);

    // Should have been persisted to localStorage
    expect(localStorage.setItem).toHaveBeenCalledWith(
      "clawdstrike:auto-enrichment-config",
      expect.any(String),
    );

    // Parse persisted value to verify
    const persisted = JSON.parse(
      (localStorage.setItem as ReturnType<typeof vi.fn>).mock.calls[0][1],
    );
    expect(persisted.enabled).toBe(true);
    expect(persisted.confidenceThreshold).toBe(0.8);

    manager.destroy();
  });

  // Test 12: Default config
  it("Default config: enabled=false, confidenceThreshold=0.5, enabledSources=[], enabledSentinels='all'", () => {
    const orch = mockOrchestrator();
    const extract = mockExtractIndicators();
    const manager = new AutoEnrichmentManager({
      orchestrator: orch,
      extractIndicators: extract,
    });

    const config = manager.getConfig();
    expect(config.enabled).toBe(false);
    expect(config.confidenceThreshold).toBe(0.5);
    expect(config.enabledSources).toEqual([]);
    expect(config.enabledSentinels).toBe("all");

    manager.destroy();
  });

  // Additional: all sources skipped when all already enriched (enabledSources non-empty)
  it("processNewFinding() does not call orchestrator if all enabledSources already enriched", () => {
    const orch = mockOrchestrator();
    const extract = mockExtractIndicators();
    const manager = new AutoEnrichmentManager({
      orchestrator: orch,
      extractIndicators: extract,
      config: {
        enabled: true,
        confidenceThreshold: 0.5,
        enabledSources: ["virustotal"],
        enabledSentinels: "all",
      },
    });

    const finding = makeFinding({
      confidence: 0.9,
      enrichments: [makeEnrichment("virustotal")],
    });
    manager.processNewFinding(finding);

    // All sources already enriched -- should not call orchestrator
    expect(orch.enrich).not.toHaveBeenCalled();

    manager.destroy();
  });

  // Constructor loads from localStorage
  it("loads config from localStorage on construction", () => {
    const saved: AutoEnrichmentConfig = {
      enabled: true,
      confidenceThreshold: 0.9,
      enabledSources: ["shodan"],
      enabledSentinels: ["sentinel-x"],
    };
    storage["clawdstrike:auto-enrichment-config"] = JSON.stringify(saved);

    const orch = mockOrchestrator();
    const extract = mockExtractIndicators();
    const manager = new AutoEnrichmentManager({
      orchestrator: orch,
      extractIndicators: extract,
    });

    expect(manager.getConfig()).toEqual(saved);

    manager.destroy();
  });

  // ---- Error handling: orchestrator.enrich() rejection ----

  it("when orchestrator.enrich() rejects, console.error is called and manager continues processing subsequent findings", async () => {
    const consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const orch = {
      enrich: vi.fn()
        // First call rejects
        .mockRejectedValueOnce(new Error("API unavailable"))
        // Second call succeeds (one per indicator extracted)
        .mockResolvedValue([]),
    };

    // Extract single indicator to keep call counts predictable
    const extract = vi.fn().mockReturnValue([
      { type: "ip" as const, value: "1.2.3.4" },
    ]);

    const manager = new AutoEnrichmentManager({
      orchestrator: orch,
      extractIndicators: extract,
      config: {
        enabled: true,
        confidenceThreshold: 0.5,
        enabledSources: [],
        enabledSentinels: "all",
      },
    });

    // Process first finding -- orchestrator will reject
    const finding1 = makeFinding({ id: "fnd_fail", confidence: 0.9 });
    manager.processNewFinding(finding1);

    // Allow the promise rejection to propagate through the .catch()
    await vi.advanceTimersByTimeAsync(0);
    // Flush microtasks
    await Promise.resolve();

    // console.error should have been called by the .catch() handler
    expect(consoleErrorSpy).toHaveBeenCalledWith(
      expect.stringContaining("[AutoEnrichment]"),
      expect.stringContaining("API unavailable"),
    );

    // Process second finding -- should still work
    vi.advanceTimersByTime(200); // Past debounce window
    const finding2 = makeFinding({ id: "fnd_ok", confidence: 0.9 });
    manager.processNewFinding(finding2);

    // Orchestrator should have been called for the second finding too
    expect(orch.enrich).toHaveBeenCalledTimes(2);

    consoleErrorSpy.mockRestore();
    manager.destroy();
  });
});
