/**
 * Unit tests for swarm-board-analytics — pure receipt posture and guard
 * heatmap summarization functions.
 */
import { describe, expect, it } from "vitest";
import type { Node } from "@xyflow/react";
import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";
import {
  summarizeReceiptPosture,
  summarizeGuardPolicyHeatmap,
} from "../swarm-board-analytics";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeReceiptNode(
  id: string,
  overrides: Partial<SwarmBoardNodeData> = {},
): Node<SwarmBoardNodeData> {
  return {
    id,
    type: "receipt",
    position: { x: 0, y: 0 },
    data: {
      title: `Receipt ${id}`,
      status: "completed",
      nodeType: "receipt",
      verdict: "allow",
      ...overrides,
    },
  };
}

function makeNonReceiptNode(id: string): Node<SwarmBoardNodeData> {
  return {
    id,
    type: "agentSession",
    position: { x: 0, y: 0 },
    data: {
      title: `Agent ${id}`,
      status: "running",
      nodeType: "agentSession",
    },
  };
}

// ---------------------------------------------------------------------------
// summarizeReceiptPosture
// ---------------------------------------------------------------------------

describe("summarizeReceiptPosture", () => {
  it("returns neutral/zero state for an empty node array", () => {
    const result = summarizeReceiptPosture([]);
    expect(result).toEqual({
      totalReceipts: 0,
      totalSignals: 0,
      allowCount: 0,
      warnCount: 0,
      denyCount: 0,
      allowRatio: 0,
      warnRatio: 0,
      denyRatio: 0,
      dominantState: "neutral",
    });
  });

  it("counts allow/warn/deny verdicts correctly", () => {
    const nodes = [
      makeReceiptNode("r1", { verdict: "allow" }),
      makeReceiptNode("r2", { verdict: "allow" }),
      makeReceiptNode("r3", { verdict: "warn" }),
      makeReceiptNode("r4", { verdict: "deny" }),
    ];
    const result = summarizeReceiptPosture(nodes);
    expect(result.allowCount).toBe(2);
    expect(result.warnCount).toBe(1);
    expect(result.denyCount).toBe(1);
    expect(result.totalReceipts).toBe(4);
    expect(result.totalSignals).toBe(4);
  });

  it("resolves dominant state to deny when deny >= others", () => {
    const nodes = [
      makeReceiptNode("r1", { verdict: "deny" }),
      makeReceiptNode("r2", { verdict: "deny" }),
      makeReceiptNode("r3", { verdict: "allow" }),
    ];
    const result = summarizeReceiptPosture(nodes);
    expect(result.dominantState).toBe("deny");
  });

  it("resolves dominant state to warn when warn >= allow and no deny dominates", () => {
    const nodes = [
      makeReceiptNode("r1", { verdict: "warn" }),
      makeReceiptNode("r2", { verdict: "warn" }),
      makeReceiptNode("r3", { verdict: "allow" }),
    ];
    const result = summarizeReceiptPosture(nodes);
    expect(result.dominantState).toBe("warn");
  });

  it("resolves dominant state to allow when only allow verdicts exist", () => {
    const nodes = [
      makeReceiptNode("r1", { verdict: "allow" }),
      makeReceiptNode("r2", { verdict: "allow" }),
    ];
    const result = summarizeReceiptPosture(nodes);
    expect(result.dominantState).toBe("allow");
  });

  it("infers deny verdict from guardResults when verdict field absent", () => {
    const nodes = [
      makeReceiptNode("r1", {
        verdict: undefined,
        guardResults: [
          { guard: "ForbiddenPathGuard", allowed: true },
          { guard: "SecretLeakGuard", allowed: false },
        ],
      }),
    ];
    const result = summarizeReceiptPosture(nodes);
    expect(result.denyCount).toBe(1);
    expect(result.dominantState).toBe("deny");
  });

  it("infers allow verdict from guardResults when all pass and verdict absent", () => {
    const nodes = [
      makeReceiptNode("r1", {
        verdict: undefined,
        guardResults: [
          { guard: "ForbiddenPathGuard", allowed: true },
          { guard: "SecretLeakGuard", allowed: true },
        ],
      }),
    ];
    const result = summarizeReceiptPosture(nodes);
    expect(result.allowCount).toBe(1);
    expect(result.dominantState).toBe("allow");
  });

  it("skips non-receipt nodes", () => {
    const nodes = [
      makeNonReceiptNode("a1"),
      makeReceiptNode("r1", { verdict: "allow" }),
      makeNonReceiptNode("a2"),
    ];
    const result = summarizeReceiptPosture(nodes);
    expect(result.totalReceipts).toBe(1);
    expect(result.allowCount).toBe(1);
  });

  it("computes correct ratios", () => {
    const nodes = [
      makeReceiptNode("r1", { verdict: "allow" }),
      makeReceiptNode("r2", { verdict: "warn" }),
      makeReceiptNode("r3", { verdict: "deny" }),
      makeReceiptNode("r4", { verdict: "allow" }),
    ];
    const result = summarizeReceiptPosture(nodes);
    expect(result.allowRatio).toBe(0.5);
    expect(result.warnRatio).toBe(0.25);
    expect(result.denyRatio).toBe(0.25);
  });

  it("returns zero ratios when no signals exist", () => {
    // Receipt with no verdict and no guardResults -> null posture
    const nodes = [
      makeReceiptNode("r1", { verdict: undefined, guardResults: [] }),
    ];
    const result = summarizeReceiptPosture(nodes);
    expect(result.totalReceipts).toBe(1);
    expect(result.totalSignals).toBe(0);
    expect(result.allowRatio).toBe(0);
    expect(result.dominantState).toBe("neutral");
  });
});

// ---------------------------------------------------------------------------
// summarizeGuardPolicyHeatmap
// ---------------------------------------------------------------------------

describe("summarizeGuardPolicyHeatmap", () => {
  it("returns zero state for an empty node array", () => {
    const result = summarizeGuardPolicyHeatmap([]);
    expect(result.totalReceipts).toBe(0);
    expect(result.receiptsWithGuards).toBe(0);
    expect(result.totalEvaluations).toBe(0);
    expect(result.uniqueGuards).toBe(0);
    expect(result.guards).toEqual([]);
  });

  it("skips non-receipt nodes", () => {
    const nodes = [makeNonReceiptNode("a1"), makeNonReceiptNode("a2")];
    const result = summarizeGuardPolicyHeatmap(nodes);
    expect(result.totalReceipts).toBe(0);
    expect(result.guards).toEqual([]);
  });

  it("aggregates guard evaluations across receipts", () => {
    const nodes = [
      makeReceiptNode("r1", {
        verdict: "allow",
        guardResults: [
          { guard: "ForbiddenPathGuard", allowed: true, duration_ms: 2 },
          { guard: "SecretLeakGuard", allowed: true, duration_ms: 5 },
        ],
      }),
      makeReceiptNode("r2", {
        verdict: "deny",
        guardResults: [
          { guard: "ForbiddenPathGuard", allowed: true, duration_ms: 3 },
          { guard: "SecretLeakGuard", allowed: false, duration_ms: 10 },
        ],
      }),
    ];
    const result = summarizeGuardPolicyHeatmap(nodes);

    expect(result.totalReceipts).toBe(2);
    expect(result.receiptsWithGuards).toBe(2);
    expect(result.totalEvaluations).toBe(4);
    expect(result.uniqueGuards).toBe(2);
  });

  it("sorts guards by evaluation count descending", () => {
    const nodes = [
      makeReceiptNode("r1", {
        verdict: "allow",
        guardResults: [
          { guard: "GuardA", allowed: true },
        ],
      }),
      makeReceiptNode("r2", {
        verdict: "allow",
        guardResults: [
          { guard: "GuardA", allowed: true },
          { guard: "GuardB", allowed: true },
        ],
      }),
      makeReceiptNode("r3", {
        verdict: "allow",
        guardResults: [
          { guard: "GuardA", allowed: true },
          { guard: "GuardB", allowed: true },
          { guard: "GuardC", allowed: true },
        ],
      }),
    ];
    const result = summarizeGuardPolicyHeatmap(nodes);

    expect(result.guards[0].guard).toBe("GuardA");
    expect(result.guards[0].totalEvaluations).toBe(3);
    expect(result.guards[1].guard).toBe("GuardB");
    expect(result.guards[1].totalEvaluations).toBe(2);
    expect(result.guards[2].guard).toBe("GuardC");
    expect(result.guards[2].totalEvaluations).toBe(1);
  });

  it("computes average and max latency correctly", () => {
    const nodes = [
      makeReceiptNode("r1", {
        verdict: "allow",
        guardResults: [
          { guard: "GuardA", allowed: true, duration_ms: 10 },
        ],
      }),
      makeReceiptNode("r2", {
        verdict: "allow",
        guardResults: [
          { guard: "GuardA", allowed: true, duration_ms: 20 },
        ],
      }),
    ];
    const result = summarizeGuardPolicyHeatmap(nodes);
    const guardA = result.guards.find((g) => g.guard === "GuardA")!;
    expect(guardA.averageLatencyMs).toBe(15);
    expect(guardA.maxLatencyMs).toBe(20);
  });

  it("returns null latency when no duration_ms values exist", () => {
    const nodes = [
      makeReceiptNode("r1", {
        verdict: "allow",
        guardResults: [
          { guard: "GuardA", allowed: true },
        ],
      }),
    ];
    const result = summarizeGuardPolicyHeatmap(nodes);
    const guardA = result.guards.find((g) => g.guard === "GuardA")!;
    expect(guardA.averageLatencyMs).toBeNull();
    expect(guardA.maxLatencyMs).toBeNull();
  });

  it("counts receiptsWithGuards only for those with guard results", () => {
    const nodes = [
      makeReceiptNode("r1", {
        verdict: "allow",
        guardResults: [{ guard: "GuardA", allowed: true }],
      }),
      makeReceiptNode("r2", {
        verdict: "allow",
        guardResults: [],
      }),
      makeReceiptNode("r3", {
        verdict: "allow",
        guardResults: undefined,
      }),
    ];
    const result = summarizeGuardPolicyHeatmap(nodes);
    expect(result.totalReceipts).toBe(3);
    expect(result.receiptsWithGuards).toBe(1);
  });

  it("computes per-guard allow/warn/deny ratios", () => {
    const nodes = [
      makeReceiptNode("r1", {
        verdict: "allow",
        guardResults: [
          { guard: "GuardA", allowed: true },
          { guard: "GuardA", allowed: true },
        ],
      }),
      makeReceiptNode("r2", {
        verdict: "deny",
        guardResults: [
          { guard: "GuardA", allowed: false },
        ],
      }),
    ];
    const result = summarizeGuardPolicyHeatmap(nodes);
    const guardA = result.guards.find((g) => g.guard === "GuardA")!;
    expect(guardA.totalEvaluations).toBe(3);
    expect(guardA.allowCount).toBe(2);
    expect(guardA.denyCount).toBe(1);
    expect(guardA.allowRatio).toBeCloseTo(2 / 3);
    expect(guardA.denyRatio).toBeCloseTo(1 / 3);
  });

  it("treats allowed guards in warn receipts as warn verdicts", () => {
    const nodes = [
      makeReceiptNode("r1", {
        verdict: "warn",
        guardResults: [
          { guard: "GuardA", allowed: true },
        ],
      }),
    ];
    const result = summarizeGuardPolicyHeatmap(nodes);
    const guardA = result.guards.find((g) => g.guard === "GuardA")!;
    expect(guardA.warnCount).toBe(1);
    expect(guardA.allowCount).toBe(0);
  });

  it("secondary sort by deny count then warn count then alphabetical", () => {
    const nodes = [
      makeReceiptNode("r1", {
        verdict: "allow",
        guardResults: [
          { guard: "Zebra", allowed: true },
          { guard: "Alpha", allowed: true },
        ],
      }),
    ];
    const result = summarizeGuardPolicyHeatmap(nodes);
    // Same evaluation count, same deny count, same warn count -> alphabetical
    expect(result.guards[0].guard).toBe("Alpha");
    expect(result.guards[1].guard).toBe("Zebra");
  });
});
