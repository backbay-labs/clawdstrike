// ---------------------------------------------------------------------------
// SwarmBoard Analytics — pure receipt posture and guard heatmap summarization
//
// Extracted from swarm-board-store.tsx. All functions are pure: they take
// Node<SwarmBoardNodeData>[] as input and return summary objects. Zero store
// dependency.
// ---------------------------------------------------------------------------
import type { Node } from "@xyflow/react";
import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ReceiptPostureState = "neutral" | "allow" | "warn" | "deny";

export interface ReceiptPostureSummary {
  totalReceipts: number;
  totalSignals: number;
  allowCount: number;
  warnCount: number;
  denyCount: number;
  allowRatio: number;
  warnRatio: number;
  denyRatio: number;
  dominantState: ReceiptPostureState;
}

export interface GuardPolicySummary {
  guard: string;
  receiptCount: number;
  totalEvaluations: number;
  allowCount: number;
  warnCount: number;
  denyCount: number;
  allowRatio: number;
  warnRatio: number;
  denyRatio: number;
  averageLatencyMs: number | null;
  maxLatencyMs: number | null;
}

export interface GuardPolicyHeatmapSummary {
  totalReceipts: number;
  receiptsWithGuards: number;
  totalEvaluations: number;
  uniqueGuards: number;
  allowCount: number;
  warnCount: number;
  denyCount: number;
  guards: GuardPolicySummary[];
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function resolveReceiptPosture(data: SwarmBoardNodeData): Exclude<ReceiptPostureState, "neutral"> | null {
  if (data.verdict === "allow" || data.verdict === "warn" || data.verdict === "deny") {
    return data.verdict;
  }

  const guardResults = data.guardResults ?? [];
  if (guardResults.some((guard) => !guard.allowed)) {
    return "deny";
  }
  if (guardResults.length > 0) {
    return "allow";
  }

  return null;
}

function resolveGuardPolicyVerdict(
  receipt: SwarmBoardNodeData,
  guardResult: { allowed: boolean },
): Exclude<ReceiptPostureState, "neutral"> {
  if (!guardResult.allowed) {
    return "deny";
  }

  // Board-level guard results do not encode warn directly, so warning receipts
  // treat otherwise-allowed guard evaluations as warning posture.
  return receipt.verdict === "warn" ? "warn" : "allow";
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function summarizeReceiptPosture(
  nodes: Array<Node<SwarmBoardNodeData>>,
): ReceiptPostureSummary {
  let totalReceipts = 0;
  let allowCount = 0;
  let warnCount = 0;
  let denyCount = 0;

  for (const node of nodes) {
    const data = node.data as SwarmBoardNodeData;
    if (data.nodeType !== "receipt") {
      continue;
    }

    totalReceipts += 1;
    const posture = resolveReceiptPosture(data);
    if (posture === "allow") {
      allowCount += 1;
    } else if (posture === "warn") {
      warnCount += 1;
    } else if (posture === "deny") {
      denyCount += 1;
    }
  }

  const totalSignals = allowCount + warnCount + denyCount;
  const dominantState: ReceiptPostureState =
    denyCount > 0 && denyCount >= warnCount && denyCount >= allowCount
      ? "deny"
      : warnCount > 0 && warnCount >= allowCount
        ? "warn"
        : allowCount > 0
          ? "allow"
          : "neutral";

  return {
    totalReceipts,
    totalSignals,
    allowCount,
    warnCount,
    denyCount,
    allowRatio: totalSignals > 0 ? allowCount / totalSignals : 0,
    warnRatio: totalSignals > 0 ? warnCount / totalSignals : 0,
    denyRatio: totalSignals > 0 ? denyCount / totalSignals : 0,
    dominantState,
  };
}

export function summarizeGuardPolicyHeatmap(
  nodes: Array<Node<SwarmBoardNodeData>>,
): GuardPolicyHeatmapSummary {
  const guardMap = new Map<
    string,
    {
      receiptIds: Set<string>;
      totalEvaluations: number;
      allowCount: number;
      warnCount: number;
      denyCount: number;
      latencyTotalMs: number;
      latencySamples: number;
      maxLatencyMs: number | null;
    }
  >();

  let totalReceipts = 0;
  let receiptsWithGuards = 0;
  let totalEvaluations = 0;
  let allowCount = 0;
  let warnCount = 0;
  let denyCount = 0;

  for (const node of nodes) {
    const data = node.data as SwarmBoardNodeData;
    if (data.nodeType !== "receipt") {
      continue;
    }

    totalReceipts += 1;
    const guardResults = data.guardResults ?? [];
    if (guardResults.length === 0) {
      continue;
    }

    receiptsWithGuards += 1;

    for (const guardResult of guardResults) {
      const entry = guardMap.get(guardResult.guard) ?? {
        receiptIds: new Set<string>(),
        totalEvaluations: 0,
        allowCount: 0,
        warnCount: 0,
        denyCount: 0,
        latencyTotalMs: 0,
        latencySamples: 0,
        maxLatencyMs: null,
      };

      entry.receiptIds.add(node.id);
      entry.totalEvaluations += 1;
      totalEvaluations += 1;

      const verdict = resolveGuardPolicyVerdict(data, guardResult);
      if (verdict === "allow") {
        entry.allowCount += 1;
        allowCount += 1;
      } else if (verdict === "warn") {
        entry.warnCount += 1;
        warnCount += 1;
      } else {
        entry.denyCount += 1;
        denyCount += 1;
      }

      if (typeof guardResult.duration_ms === "number") {
        entry.latencyTotalMs += guardResult.duration_ms;
        entry.latencySamples += 1;
        entry.maxLatencyMs =
          entry.maxLatencyMs == null
            ? guardResult.duration_ms
            : Math.max(entry.maxLatencyMs, guardResult.duration_ms);
      }

      guardMap.set(guardResult.guard, entry);
    }
  }

  const guards = Array.from(guardMap.entries())
    .map(([guard, entry]): GuardPolicySummary => ({
      guard,
      receiptCount: entry.receiptIds.size,
      totalEvaluations: entry.totalEvaluations,
      allowCount: entry.allowCount,
      warnCount: entry.warnCount,
      denyCount: entry.denyCount,
      allowRatio: entry.totalEvaluations > 0 ? entry.allowCount / entry.totalEvaluations : 0,
      warnRatio: entry.totalEvaluations > 0 ? entry.warnCount / entry.totalEvaluations : 0,
      denyRatio: entry.totalEvaluations > 0 ? entry.denyCount / entry.totalEvaluations : 0,
      averageLatencyMs:
        entry.latencySamples > 0 ? entry.latencyTotalMs / entry.latencySamples : null,
      maxLatencyMs: entry.maxLatencyMs,
    }))
    .sort((left, right) => {
      if (right.totalEvaluations !== left.totalEvaluations) {
        return right.totalEvaluations - left.totalEvaluations;
      }
      if (right.denyCount !== left.denyCount) {
        return right.denyCount - left.denyCount;
      }
      if (right.warnCount !== left.warnCount) {
        return right.warnCount - left.warnCount;
      }
      return left.guard.localeCompare(right.guard);
    });

  return {
    totalReceipts,
    receiptsWithGuards,
    totalEvaluations,
    uniqueGuards: guards.length,
    allowCount,
    warnCount,
    denyCount,
    guards,
  };
}
