import { describe, it, expect, expectTypeOf } from "vitest";
import type {
  IndicatorType,
  Indicator,
  ThreatVerdict,
  EnrichmentResult,
  ThreatIntelSource,
} from "../src/index";

describe("threat intel types", () => {
  it("IndicatorType union includes hash, ip, domain, url, email", () => {
    const types: IndicatorType[] = ["hash", "ip", "domain", "url", "email"];
    expect(types).toHaveLength(5);
    for (const t of types) {
      expect(["hash", "ip", "domain", "url", "email"]).toContain(t);
    }
  });

  it("Indicator has required type and value, optional hashAlgorithm and context", () => {
    const minimal: Indicator = { type: "ip", value: "1.2.3.4" };
    expect(minimal.type).toBe("ip");
    expect(minimal.value).toBe("1.2.3.4");

    const withOptionals: Indicator = {
      type: "hash",
      value: "abc123",
      hashAlgorithm: "sha256",
      context: { findingId: "fnd_123", signalIds: ["sig_1"] },
    };
    expect(withOptionals.hashAlgorithm).toBe("sha256");
    expect(withOptionals.context?.findingId).toBe("fnd_123");
  });

  it("ThreatVerdict has classification, confidence, and summary", () => {
    const verdict: ThreatVerdict = {
      classification: "malicious",
      confidence: 0.95,
      summary: "Known C2 server",
    };
    expect(verdict.classification).toBe("malicious");
    expect(verdict.confidence).toBe(0.95);
    expect(verdict.summary).toBe("Known C2 server");

    // All classification values should be valid
    const classifications: ThreatVerdict["classification"][] = [
      "malicious",
      "benign",
      "suspicious",
      "unknown",
    ];
    expect(classifications).toHaveLength(4);
  });

  it("EnrichmentResult has required and optional fields", () => {
    const result: EnrichmentResult = {
      sourceId: "vt-1",
      sourceName: "VirusTotal",
      verdict: { classification: "malicious", confidence: 0.99, summary: "Bad" },
      rawData: { hits: 42 },
      fetchedAt: Date.now(),
      cacheTtlMs: 300_000,
    };
    expect(result.sourceId).toBe("vt-1");
    expect(result.sourceName).toBe("VirusTotal");
    expect(result.verdict.classification).toBe("malicious");
    expect(result.rawData).toEqual({ hits: 42 });
    expect(result.fetchedAt).toBeGreaterThan(0);
    expect(result.cacheTtlMs).toBe(300_000);

    // With optional fields
    const full: EnrichmentResult = {
      ...result,
      mitreTechniques: [{ techniqueId: "T1059", techniqueName: "Command Scripting", tactic: "Execution" }],
      relatedIndicators: [{ type: "ip", value: "5.6.7.8" }],
      permalink: "https://virustotal.com/results/123",
    };
    expect(full.mitreTechniques).toHaveLength(1);
    expect(full.relatedIndicators).toHaveLength(1);
    expect(full.permalink).toBe("https://virustotal.com/results/123");
  });

  it("ThreatIntelSource has required fields and enrich function", () => {
    const source: ThreatIntelSource = {
      id: "test-source",
      name: "Test Source",
      supportedIndicatorTypes: ["ip", "domain"],
      rateLimit: { maxPerMinute: 10 },
      enrich: async (indicator) => ({
        sourceId: "test-source",
        sourceName: "Test Source",
        verdict: { classification: "unknown", confidence: 0, summary: "No data" },
        rawData: {},
        fetchedAt: Date.now(),
        cacheTtlMs: 60_000,
      }),
    };
    expect(source.id).toBe("test-source");
    expect(source.name).toBe("Test Source");
    expect(source.supportedIndicatorTypes).toEqual(["ip", "domain"]);
    expect(source.rateLimit.maxPerMinute).toBe(10);
    expect(typeof source.enrich).toBe("function");

    // Optional healthCheck
    const withHealth: ThreatIntelSource = {
      ...source,
      healthCheck: async () => ({ healthy: true, message: "OK" }),
    };
    expect(typeof withHealth.healthCheck).toBe("function");
  });
});
