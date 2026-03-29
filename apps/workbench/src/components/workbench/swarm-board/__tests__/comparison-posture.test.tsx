/**
 * PostureSummaryBar + GuardHeatmapTable unit tests.
 */
import React from "react";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type {
  ReceiptPostureSummary,
  GuardPolicySummary,
  GuardPolicyHeatmapSummary,
} from "@/features/swarm/stores/swarm-board-store";

import {
  PostureSummaryBar,
  GuardHeatmapTable,
} from "../comparison/comparison-posture";

// ---------------------------------------------------------------------------
// PostureSummaryBar
// ---------------------------------------------------------------------------

describe("PostureSummaryBar", () => {
  it("renders allow/warn/deny counts", () => {
    const posture: ReceiptPostureSummary = {
      totalReceipts: 10,
      totalSignals: 6,
      allowCount: 3,
      warnCount: 2,
      denyCount: 1,
      allowRatio: 0.5,
      warnRatio: 0.333,
      denyRatio: 0.167,
      dominantState: "allow",
    };
    const { container } = render(<PostureSummaryBar posture={posture} />);
    const text = container.textContent ?? "";

    // Verify counts and labels appear in the rendered text
    expect(text).toContain("3");
    expect(text).toContain("2");
    expect(text).toContain("1");
    expect(text).toContain("allow");
    expect(text).toContain("warn");
    expect(text).toContain("deny");
  });

  it("renders neutral state for zero counts", () => {
    const posture: ReceiptPostureSummary = {
      totalReceipts: 0,
      totalSignals: 0,
      allowCount: 0,
      warnCount: 0,
      denyCount: 0,
      allowRatio: 0,
      warnRatio: 0,
      denyRatio: 0,
      dominantState: "neutral",
    };
    render(<PostureSummaryBar posture={posture} />);

    expect(screen.getByText("neutral")).toBeInTheDocument();
  });

  it("renders dominant state label", () => {
    const posture: ReceiptPostureSummary = {
      totalReceipts: 5,
      totalSignals: 5,
      allowCount: 1,
      warnCount: 1,
      denyCount: 3,
      allowRatio: 0.2,
      warnRatio: 0.2,
      denyRatio: 0.6,
      dominantState: "deny",
    };
    const { container } = render(<PostureSummaryBar posture={posture} />);
    const text = container.textContent ?? "";

    // The dominant state section includes "(dominant: deny)"
    expect(text).toContain("dominant:");
    expect(text).toContain("deny");
  });
});

// ---------------------------------------------------------------------------
// GuardHeatmapTable
// ---------------------------------------------------------------------------

describe("GuardHeatmapTable", () => {
  it("returns null for empty guards", () => {
    const heatmap: GuardPolicyHeatmapSummary = {
      totalReceipts: 0,
      receiptsWithGuards: 0,
      totalEvaluations: 0,
      uniqueGuards: 0,
      allowCount: 0,
      warnCount: 0,
      denyCount: 0,
      guards: [],
    };
    const { container } = render(<GuardHeatmapTable heatmap={heatmap} />);
    expect(container.innerHTML).toBe("");
  });

  it("renders guard rows with allow%, latency", () => {
    const guard: GuardPolicySummary = {
      guard: "ForbiddenPathGuard",
      receiptCount: 3,
      totalEvaluations: 5,
      allowCount: 4,
      warnCount: 0,
      denyCount: 1,
      allowRatio: 0.8,
      warnRatio: 0,
      denyRatio: 0.2,
      averageLatencyMs: 12.5,
      maxLatencyMs: 25,
    };
    const heatmap: GuardPolicyHeatmapSummary = {
      totalReceipts: 3,
      receiptsWithGuards: 3,
      totalEvaluations: 5,
      uniqueGuards: 1,
      allowCount: 4,
      warnCount: 0,
      denyCount: 1,
      guards: [guard],
    };
    render(<GuardHeatmapTable heatmap={heatmap} />);

    expect(screen.getByText("ForbiddenPathGuard")).toBeInTheDocument();
    expect(screen.getByText("80%")).toBeInTheDocument();
    expect(screen.getByText("13ms")).toBeInTheDocument(); // Math.round(12.5)
    expect(screen.getByText("25ms")).toBeInTheDocument();
  });

  it("shows '--' for null latency values", () => {
    const guard: GuardPolicySummary = {
      guard: "SecretLeakGuard",
      receiptCount: 2,
      totalEvaluations: 2,
      allowCount: 2,
      warnCount: 0,
      denyCount: 0,
      allowRatio: 1,
      warnRatio: 0,
      denyRatio: 0,
      averageLatencyMs: null,
      maxLatencyMs: null,
    };
    const heatmap: GuardPolicyHeatmapSummary = {
      totalReceipts: 2,
      receiptsWithGuards: 2,
      totalEvaluations: 2,
      uniqueGuards: 1,
      allowCount: 2,
      warnCount: 0,
      denyCount: 0,
      guards: [guard],
    };
    render(<GuardHeatmapTable heatmap={heatmap} />);

    expect(screen.getByText("SecretLeakGuard")).toBeInTheDocument();
    // Two '--' cells (avg and max latency)
    const dashes = screen.getAllByText("--");
    expect(dashes.length).toBe(2);
  });

  it("renders multiple guard rows", () => {
    const guards: GuardPolicySummary[] = [
      {
        guard: "GuardA",
        receiptCount: 1,
        totalEvaluations: 1,
        allowCount: 1,
        warnCount: 0,
        denyCount: 0,
        allowRatio: 1,
        warnRatio: 0,
        denyRatio: 0,
        averageLatencyMs: 5,
        maxLatencyMs: 5,
      },
      {
        guard: "GuardB",
        receiptCount: 1,
        totalEvaluations: 1,
        allowCount: 0,
        warnCount: 0,
        denyCount: 1,
        allowRatio: 0,
        warnRatio: 0,
        denyRatio: 1,
        averageLatencyMs: 100,
        maxLatencyMs: 100,
      },
    ];
    const heatmap: GuardPolicyHeatmapSummary = {
      totalReceipts: 1,
      receiptsWithGuards: 1,
      totalEvaluations: 2,
      uniqueGuards: 2,
      allowCount: 1,
      warnCount: 0,
      denyCount: 1,
      guards,
    };
    render(<GuardHeatmapTable heatmap={heatmap} />);

    expect(screen.getByText("GuardA")).toBeInTheDocument();
    expect(screen.getByText("GuardB")).toBeInTheDocument();
  });
});
