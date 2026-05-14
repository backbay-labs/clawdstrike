import { describe, expect, it } from "vitest";
import type { Signal, SignalCluster } from "../signal-pipeline";
import { generateSignalId } from "../signal-pipeline";
import type { Finding } from "../finding-engine";
import {
  runCorrelationPipeline,
  type CorrelationPipelineInput,
  type CorrelationPipelineResult,
} from "../signal-correlator";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const BASE_TS = 1_700_000_000_000;

function makeSignal(overrides: Partial<Signal> = {}): Signal {
  return {
    id: overrides.id ?? generateSignalId(),
    type: overrides.type ?? "detection",
    source: overrides.source ?? {
      sentinelId: null,
      guardId: "test_guard",
      externalFeed: null,
      provenance: "guard_evaluation",
    },
    timestamp: overrides.timestamp ?? BASE_TS,
    severity: overrides.severity ?? "medium",
    confidence: overrides.confidence ?? 0.7,
    data: overrides.data ?? {
      kind: "detection",
      summary: "Test detection signal",
    },
    context: overrides.context ?? {
      agentId: "agent_1",
      agentName: "Test Agent",
      sessionId: "session_1",
      flags: [],
    },
    relatedSignals: overrides.relatedSignals ?? [],
    ttl: overrides.ttl ?? null,
    findingId: overrides.findingId ?? null,
  };
}

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: overrides.id ?? "fnd_existing_1",
    title: overrides.title ?? "Existing finding",
    status: overrides.status ?? "emerging",
    severity: overrides.severity ?? "medium",
    confidence: overrides.confidence ?? 0.7,
    signalIds: overrides.signalIds ?? ["sig_existing_1", "sig_existing_2"],
    signalCount: overrides.signalCount ?? 2,
    scope: overrides.scope ?? {
      agentIds: ["agent_1"],
      sessionIds: ["session_1"],
      timeRange: {
        start: new Date(BASE_TS).toISOString(),
        end: new Date(BASE_TS + 1000).toISOString(),
      },
    },
    timeline: overrides.timeline ?? [],
    enrichments: overrides.enrichments ?? [],
    annotations: overrides.annotations ?? [],
    verdict: overrides.verdict ?? null,
    actions: overrides.actions ?? [],
    promotedToIntel: overrides.promotedToIntel ?? null,
    receipt: overrides.receipt ?? null,
    speakeasyId: overrides.speakeasyId ?? null,
    createdBy: overrides.createdBy ?? "test",
    updatedBy: overrides.updatedBy ?? "test",
    createdAt: overrides.createdAt ?? BASE_TS,
    updatedAt: overrides.updatedAt ?? BASE_TS,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("runCorrelationPipeline", () => {
  it("produces 1 cluster and 1 finding from 3 same-agent signals within 5min window", () => {
    const signals: Signal[] = [
      makeSignal({ id: "sig_a1", timestamp: BASE_TS }),
      makeSignal({ id: "sig_a2", timestamp: BASE_TS + 60_000 }),
      makeSignal({ id: "sig_a3", timestamp: BASE_TS + 120_000 }),
    ];

    const input: CorrelationPipelineInput = {
      signals,
      existingFindings: [],
    };

    const result = runCorrelationPipeline(input);

    expect(result.clusters.length).toBeGreaterThanOrEqual(1);
    expect(result.newFindings.length).toBe(1);
    expect(result.newFindings[0].signalIds).toEqual(
      expect.arrayContaining(["sig_a1", "sig_a2", "sig_a3"]),
    );
    expect(result.newFindings[0].status).toBe("emerging");
  });

  it("produces no findings when cluster confidence is below MIN_CLUSTER_CONFIDENCE (0.3)", () => {
    const signals: Signal[] = [
      makeSignal({
        id: "sig_low1",
        confidence: 0.1,
        severity: "info",
        timestamp: BASE_TS,
      }),
      makeSignal({
        id: "sig_low2",
        confidence: 0.15,
        severity: "info",
        timestamp: BASE_TS + 30_000,
      }),
    ];

    const input: CorrelationPipelineInput = {
      signals,
      existingFindings: [],
    };

    const result = runCorrelationPipeline(input);

    // Clusters may form but findings should not be created due to low confidence
    expect(result.newFindings.length).toBe(0);
  });

  it("produces no findings with only 1 signal (below MIN_CLUSTER_SIGNALS=2)", () => {
    const signals: Signal[] = [
      makeSignal({ id: "sig_lonely", confidence: 0.9 }),
    ];

    const input: CorrelationPipelineInput = {
      signals,
      existingFindings: [],
    };

    const result = runCorrelationPipeline(input);

    expect(result.newFindings.length).toBe(0);
    expect(result.clusters.length).toBe(0);
  });

  it("skips signals already assigned to existing findings (signal.findingId !== null)", () => {
    const assignedSignal = makeSignal({
      id: "sig_assigned",
      findingId: "fnd_old",
      timestamp: BASE_TS,
    });
    const freeSignal1 = makeSignal({
      id: "sig_free1",
      timestamp: BASE_TS + 10_000,
    });
    const freeSignal2 = makeSignal({
      id: "sig_free2",
      timestamp: BASE_TS + 20_000,
    });

    const input: CorrelationPipelineInput = {
      signals: [assignedSignal, freeSignal1, freeSignal2],
      existingFindings: [],
    };

    const result = runCorrelationPipeline(input);

    expect(result.skippedSignalIds).toContain("sig_assigned");
    // The two free signals should still be eligible for clustering
    expect(result.skippedSignalIds).not.toContain("sig_free1");
    expect(result.skippedSignalIds).not.toContain("sig_free2");
  });

  it("runs enrichment pipeline on new findings when MITRE data is provided", () => {
    const signals: Signal[] = [
      makeSignal({ id: "sig_e1", timestamp: BASE_TS }),
      makeSignal({ id: "sig_e2", timestamp: BASE_TS + 60_000 }),
      makeSignal({ id: "sig_e3", timestamp: BASE_TS + 120_000 }),
    ];

    const input: CorrelationPipelineInput = {
      signals,
      existingFindings: [],
      enrichmentData: {
        mitreTechniques: [
          { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
        ],
      },
    };

    const result = runCorrelationPipeline(input);

    expect(result.newFindings.length).toBe(1);
    expect(result.newFindings[0].enrichments.length).toBeGreaterThan(0);
    expect(result.newFindings[0].enrichments[0].type).toBe("mitre_attack");
  });

  it("calls checkAutoPromotion and updates finding status when thresholds met", () => {
    // Create many high-confidence signals to trigger auto-confirm
    const signals: Signal[] = Array.from({ length: 6 }, (_, i) =>
      makeSignal({
        id: `sig_promo_${i}`,
        confidence: 0.95,
        severity: "high",
        timestamp: BASE_TS + i * 10_000,
        // Alternate source provenances to enable corroboration
        source: {
          sentinelId: null,
          guardId: i < 3 ? "guard_a" : null,
          externalFeed: i >= 3 ? "feed_x" : null,
          provenance: i < 3 ? "guard_evaluation" : "external_feed",
        },
      }),
    );

    const input: CorrelationPipelineInput = {
      signals,
      existingFindings: [],
      enrichmentData: {
        mitreTechniques: [
          { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
        ],
      },
      autoPromotionRules: {
        autoConfirmThresholds: {
          minSignals: 5,
          minConfidence: 0.8,
          minSeverity: "high",
          requireMitreMapping: true,
        },
        autoPromoteThresholds: {
          minConfidence: 0.9,
          minSeverity: "critical",
          requireCorroboration: true,
        },
      },
    };

    const result = runCorrelationPipeline(input);

    expect(result.newFindings.length).toBeGreaterThanOrEqual(1);
    // Should have been auto-confirmed since it meets all auto-confirm thresholds
    const confirmedFinding = result.newFindings.find(
      (f) => f.status === "confirmed",
    );
    expect(confirmedFinding).toBeDefined();
  });

  it("deduplicates -- signals already in existing findings are excluded from correlation", () => {
    const existingFinding = makeFinding({
      signalIds: ["sig_dup1", "sig_dup2"],
    });

    const signals: Signal[] = [
      makeSignal({ id: "sig_dup1", timestamp: BASE_TS }),
      makeSignal({ id: "sig_dup2", timestamp: BASE_TS + 10_000 }),
      makeSignal({ id: "sig_new1", timestamp: BASE_TS + 20_000 }),
      makeSignal({ id: "sig_new2", timestamp: BASE_TS + 30_000 }),
    ];

    const input: CorrelationPipelineInput = {
      signals,
      existingFindings: [existingFinding],
    };

    const result = runCorrelationPipeline(input);

    expect(result.skippedSignalIds).toContain("sig_dup1");
    expect(result.skippedSignalIds).toContain("sig_dup2");

    // If any findings were created, they should only contain the new signals
    for (const finding of result.newFindings) {
      expect(finding.signalIds).not.toContain("sig_dup1");
      expect(finding.signalIds).not.toContain("sig_dup2");
    }
  });
});
