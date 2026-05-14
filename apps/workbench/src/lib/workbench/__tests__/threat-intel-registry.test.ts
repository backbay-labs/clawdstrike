import { describe, it, expect, beforeEach } from "vitest";
import type { ThreatIntelSource, EnrichmentResult } from "@clawdstrike/plugin-sdk";
import {
  registerThreatIntelSource,
  unregisterThreatIntelSource,
  getThreatIntelSource,
  getAllThreatIntelSources,
  getThreatIntelSourcesForIndicator,
  _resetForTesting,
} from "../threat-intel-registry";

function makeMockSource(overrides: Partial<ThreatIntelSource> = {}): ThreatIntelSource {
  return {
    id: "test-source",
    name: "Test Source",
    supportedIndicatorTypes: ["ip", "domain"],
    rateLimit: { maxPerMinute: 10 },
    enrich: async () =>
      ({
        sourceId: "test-source",
        sourceName: "Test Source",
        verdict: { classification: "unknown", confidence: 0, summary: "No data" },
        rawData: {},
        fetchedAt: Date.now(),
        cacheTtlMs: 60_000,
      }) satisfies EnrichmentResult,
    ...overrides,
  };
}

describe("ThreatIntelSourceRegistry", () => {
  beforeEach(() => {
    _resetForTesting();
  });

  it("registerThreatIntelSource adds a source and returns a dispose function", () => {
    const source = makeMockSource();
    const dispose = registerThreatIntelSource(source);

    expect(typeof dispose).toBe("function");
    expect(getThreatIntelSource("test-source")).toBeDefined();
    expect(getThreatIntelSource("test-source")!.name).toBe("Test Source");
  });

  it("registerThreatIntelSource throws if ID already registered", () => {
    const source = makeMockSource();
    registerThreatIntelSource(source);

    expect(() => registerThreatIntelSource(source)).toThrow(
      'Threat intel source "test-source" is already registered',
    );
  });

  it("dispose function from register removes the source", () => {
    const source = makeMockSource();
    const dispose = registerThreatIntelSource(source);

    expect(getThreatIntelSource("test-source")).toBeDefined();
    dispose();
    expect(getThreatIntelSource("test-source")).toBeUndefined();
  });

  it("unregisterThreatIntelSource removes by ID, no-op if missing", () => {
    const source = makeMockSource();
    registerThreatIntelSource(source);

    expect(getThreatIntelSource("test-source")).toBeDefined();
    unregisterThreatIntelSource("test-source");
    expect(getThreatIntelSource("test-source")).toBeUndefined();

    // No-op for missing ID
    expect(() => unregisterThreatIntelSource("nonexistent")).not.toThrow();
  });

  it("getThreatIntelSource returns source by ID, undefined if missing", () => {
    const source = makeMockSource();
    registerThreatIntelSource(source);

    expect(getThreatIntelSource("test-source")).toBeDefined();
    expect(getThreatIntelSource("test-source")!.id).toBe("test-source");
    expect(getThreatIntelSource("nonexistent")).toBeUndefined();
  });

  it("getAllThreatIntelSources returns all registered sources", () => {
    expect(getAllThreatIntelSources()).toHaveLength(0);

    registerThreatIntelSource(makeMockSource({ id: "source-a", name: "Source A" }));
    registerThreatIntelSource(makeMockSource({ id: "source-b", name: "Source B" }));

    const all = getAllThreatIntelSources();
    expect(all).toHaveLength(2);
    expect(all.map((s) => s.id).sort()).toEqual(["source-a", "source-b"]);
  });

  it("getThreatIntelSourcesForIndicator('ip') returns only sources with 'ip' in supportedIndicatorTypes", () => {
    registerThreatIntelSource(
      makeMockSource({ id: "ip-source", supportedIndicatorTypes: ["ip"] }),
    );
    registerThreatIntelSource(
      makeMockSource({ id: "domain-source", supportedIndicatorTypes: ["domain"] }),
    );
    registerThreatIntelSource(
      makeMockSource({
        id: "multi-source",
        supportedIndicatorTypes: ["ip", "domain", "hash"],
      }),
    );

    const ipSources = getThreatIntelSourcesForIndicator("ip");
    expect(ipSources).toHaveLength(2);
    const ids = ipSources.map((s) => s.id).sort();
    expect(ids).toEqual(["ip-source", "multi-source"]);
  });

  it("getThreatIntelSourcesForIndicator returns empty array when no sources match", () => {
    registerThreatIntelSource(
      makeMockSource({ id: "ip-only", supportedIndicatorTypes: ["ip"] }),
    );

    const emailSources = getThreatIntelSourcesForIndicator("email");
    expect(emailSources).toHaveLength(0);
  });
});
