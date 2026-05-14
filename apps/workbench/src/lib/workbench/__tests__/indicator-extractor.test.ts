import { describe, it, expect } from "vitest";
import type { Signal, Finding, SignalData } from "../sentinel-types";
import type { Indicator } from "@clawdstrike/plugin-sdk";
import { extractIndicators } from "../indicator-extractor";

// ---- Test helpers ----

function makeSignal(data: SignalData, overrides: Partial<Signal> = {}): Signal {
  return {
    id: `sig_test_${Math.random().toString(36).slice(2, 10)}`,
    type: data.kind === "anomaly"
      ? "anomaly"
      : data.kind === "detection"
        ? "detection"
        : data.kind === "indicator"
          ? "indicator"
          : data.kind === "policy_violation"
            ? "policy_violation"
            : "behavioral",
    source: {
      sentinelId: null,
      guardId: null,
      externalFeed: null,
      provenance: "guard_evaluation",
    },
    timestamp: Date.now(),
    severity: "medium",
    confidence: 0.8,
    data,
    context: {
      agentId: "agent-1",
      agentName: "Test Agent",
      sessionId: "session-1",
      flags: [],
    },
    relatedSignals: [],
    ttl: null,
    findingId: null,
    ...overrides,
  };
}

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "fnd_test_123",
    title: "Test Finding",
    status: "emerging",
    severity: "medium",
    confidence: 0.8,
    signalIds: [],
    signalCount: 0,
    scope: {
      agentIds: [],
      sessionIds: [],
      timeRange: {
        start: new Date(Date.now() - 60_000).toISOString(),
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
    createdAt: Date.now(),
    updatedAt: Date.now(),
    createdBy: "operator-1",
    updatedBy: "operator-1",
    ...overrides,
  };
}

// ---- Tests ----

describe("extractIndicators", () => {
  // ---- IP extraction from egress guard violations ----

  describe("IP extraction from egress guard violations", () => {
    it("extracts IP indicators from egress_allowlist guard evidence", () => {
      const signal = makeSignal(
        {
          kind: "detection",
          guardResults: [
            {
              guardId: "egress_allowlist",
              guardName: "Egress Allowlist",
              verdict: "deny",
              message: "Blocked egress to 10.0.0.1",
              evidence: { blocked_domain: "10.0.0.1", ip: "10.0.0.1" },
            },
          ],
        },
        { id: "sig_egress_ip" },
      );

      const indicators = extractIndicators(makeFinding(), [signal]);

      expect(indicators.some((i) => i.type === "ip" && i.value === "10.0.0.1")).toBe(true);
    });

    it("extracts IP from policy violation target", () => {
      const signal = makeSignal(
        {
          kind: "policy_violation",
          guardResults: [
            {
              guardId: "egress_allowlist",
              guardName: "Egress Allowlist",
              verdict: "deny",
              message: "Blocked",
            },
          ],
          policyName: "strict",
          actionType: "network_egress",
          target: "192.168.1.100",
          verdict: "deny",
        },
        { id: "sig_pv_ip" },
      );

      const indicators = extractIndicators(makeFinding(), [signal]);

      expect(indicators.some((i) => i.type === "ip" && i.value === "192.168.1.100")).toBe(true);
    });
  });

  // ---- Domain extraction ----

  describe("domain extraction", () => {
    it("extracts domain indicators from egress guard evidence", () => {
      const signal = makeSignal(
        {
          kind: "detection",
          guardResults: [
            {
              guardId: "egress_allowlist",
              guardName: "Egress Allowlist",
              verdict: "deny",
              message: "Blocked egress to evil.example.com",
              evidence: { domain: "evil.example.com" },
            },
          ],
        },
        { id: "sig_domain" },
      );

      const indicators = extractIndicators(makeFinding(), [signal]);

      expect(indicators.some((i) => i.type === "domain" && i.value === "evil.example.com")).toBe(true);
    });
  });

  // ---- Hash extraction ----

  describe("hash extraction", () => {
    it("extracts SHA-256 hash with correct hashAlgorithm", () => {
      const sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
      const signal = makeSignal(
        {
          kind: "detection",
          guardResults: [
            {
              guardId: "forbidden_path",
              guardName: "Forbidden Path",
              verdict: "deny",
              message: `File hash: ${sha256}`,
              evidence: { file_hash: sha256 },
            },
          ],
        },
        { id: "sig_sha256" },
      );

      const indicators = extractIndicators(makeFinding(), [signal]);

      const hashIndicator = indicators.find((i) => i.type === "hash" && i.value === sha256);
      expect(hashIndicator).toBeDefined();
      expect(hashIndicator!.hashAlgorithm).toBe("sha256");
    });

    it("differentiates MD5, SHA-1, SHA-256 by length", () => {
      const md5 = "d41d8cd98f00b204e9800998ecf8427e";
      const sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
      const sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

      const signal = makeSignal(
        {
          kind: "detection",
          guardResults: [
            {
              guardId: "secret_leak",
              guardName: "Secret Leak",
              verdict: "warn",
              message: `Hashes: ${md5} ${sha1} ${sha256}`,
            },
          ],
        },
        { id: "sig_hashes" },
      );

      const indicators = extractIndicators(makeFinding(), [signal]);

      const md5Ind = indicators.find((i) => i.type === "hash" && i.value === md5);
      const sha1Ind = indicators.find((i) => i.type === "hash" && i.value === sha1);
      const sha256Ind = indicators.find((i) => i.type === "hash" && i.value === sha256);

      expect(md5Ind).toBeDefined();
      expect(md5Ind!.hashAlgorithm).toBe("md5");
      expect(sha1Ind).toBeDefined();
      expect(sha1Ind!.hashAlgorithm).toBe("sha1");
      expect(sha256Ind).toBeDefined();
      expect(sha256Ind!.hashAlgorithm).toBe("sha256");
    });
  });

  // ---- Indicator signal passthrough ----

  describe("indicator signal passthrough", () => {
    it("maps SignalDataIndicator directly to Indicator", () => {
      const signal = makeSignal(
        {
          kind: "indicator",
          indicatorType: "ip",
          value: "1.2.3.4",
          feedSource: "abuse-ipdb",
        },
        { id: "sig_ind_pass" },
      );

      const indicators = extractIndicators(makeFinding(), [signal]);

      expect(indicators.some((i) => i.type === "ip" && i.value === "1.2.3.4")).toBe(true);
    });
  });

  // ---- Deduplication ----

  describe("deduplication", () => {
    it("deduplicates same IP appearing in multiple signals", () => {
      const signal1 = makeSignal(
        {
          kind: "detection",
          guardResults: [
            {
              guardId: "egress_allowlist",
              guardName: "Egress Allowlist",
              verdict: "deny",
              message: "Blocked 10.0.0.1",
              evidence: { ip: "10.0.0.1" },
            },
          ],
        },
        { id: "sig_dup1" },
      );

      const signal2 = makeSignal(
        {
          kind: "detection",
          guardResults: [
            {
              guardId: "egress_allowlist",
              guardName: "Egress Allowlist",
              verdict: "deny",
              message: "Blocked 10.0.0.1",
              evidence: { ip: "10.0.0.1" },
            },
          ],
        },
        { id: "sig_dup2" },
      );

      const indicators = extractIndicators(makeFinding(), [signal1, signal2]);

      const ipIndicators = indicators.filter((i) => i.type === "ip" && i.value === "10.0.0.1");
      expect(ipIndicators).toHaveLength(1);
    });

    it("keeps same value with different types as separate indicators", () => {
      // "example.com" could appear as both domain and url
      const signal1 = makeSignal(
        {
          kind: "indicator",
          indicatorType: "domain",
          value: "example.com",
          feedSource: "dns-feed",
        },
        { id: "sig_type1" },
      );

      const signal2 = makeSignal(
        {
          kind: "indicator",
          indicatorType: "url",
          value: "example.com",
          feedSource: "url-feed",
        },
        { id: "sig_type2" },
      );

      const indicators = extractIndicators(makeFinding(), [signal1, signal2]);

      const domainInd = indicators.filter((i) => i.type === "domain" && i.value === "example.com");
      const urlInd = indicators.filter((i) => i.type === "url" && i.value === "example.com");
      expect(domainInd).toHaveLength(1);
      expect(urlInd).toHaveLength(1);
    });
  });

  // ---- Context linking ----

  describe("context linking", () => {
    it("sets context.findingId to the finding's ID", () => {
      const finding = makeFinding({ id: "fnd_ctx_test" });
      const signal = makeSignal(
        {
          kind: "indicator",
          indicatorType: "ip",
          value: "8.8.8.8",
          feedSource: "test",
        },
        { id: "sig_ctx" },
      );

      const indicators = extractIndicators(finding, [signal]);

      expect(indicators[0]!.context?.findingId).toBe("fnd_ctx_test");
    });

    it("sets context.signalIds to the signal IDs that produced the indicator", () => {
      const signal = makeSignal(
        {
          kind: "indicator",
          indicatorType: "domain",
          value: "evil.com",
          feedSource: "test",
        },
        { id: "sig_ctx_ids" },
      );

      const indicators = extractIndicators(makeFinding(), [signal]);

      expect(indicators[0]!.context?.signalIds).toContain("sig_ctx_ids");
    });
  });

  // ---- Edge cases ----

  describe("edge cases", () => {
    it("returns empty array for finding with no signals", () => {
      const indicators = extractIndicators(makeFinding(), []);
      expect(indicators).toHaveLength(0);
    });

    it("returns no indicators for signals with no guard results or evidence", () => {
      const signal = makeSignal(
        {
          kind: "detection",
          guardResults: [],
        },
        { id: "sig_empty" },
      );

      const indicators = extractIndicators(makeFinding(), [signal]);
      expect(indicators).toHaveLength(0);
    });
  });
});
