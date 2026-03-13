import { describe, it, expect } from "vitest";
import {
  calculateExploitabilityScore,
  calculatePluginRiskScore,
  calculateSystemRiskScore,
  scoreToLevel,
} from "../redteam/risk-scoring";
import type { RedTeamPluginRiskScore } from "../redteam/types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a RedTeamPluginRiskScore from a plugin severity and test outcome.
 * Uses `calculatePluginRiskScore` to compute the inner riskScore.
 */
function makePluginScore(
  pluginId: string,
  severity: "critical" | "high" | "medium" | "low",
  testCount: number,
  passCount: number,
): RedTeamPluginRiskScore {
  const successRate = testCount === 0 ? 0 : 1 - passCount / testCount;
  const riskScore = calculatePluginRiskScore(severity, successRate);
  return {
    pluginId,
    severity,
    successRate,
    riskScore,
    testCount,
    passCount,
  };
}

// ---------------------------------------------------------------------------
// calculateExploitabilityScore
// ---------------------------------------------------------------------------

describe("calculateExploitabilityScore", () => {
  it("returns higher scores for human-exploitable + low-complexity", () => {
    const score = calculateExploitabilityScore(true, "low");
    expect(score).toBeGreaterThanOrEqual(7);
    expect(score).toBeLessThanOrEqual(10);
  });

  it("returns lower scores for non-human-exploitable + high-complexity", () => {
    const score = calculateExploitabilityScore(false, "high");
    expect(score).toBeLessThanOrEqual(4);
    expect(score).toBeGreaterThanOrEqual(0);
  });
});

// ---------------------------------------------------------------------------
// calculatePluginRiskScore
// ---------------------------------------------------------------------------

describe("calculatePluginRiskScore", () => {
  it("critical severity + high success rate = critical level", () => {
    // successRate = 0.9 means 90% of tests were bypassed (high attack success)
    const result = calculatePluginRiskScore("critical", 0.9);
    expect(result.level).toBe("critical");
    expect(result.score).toBeGreaterThanOrEqual(8);
  });

  it("low severity + low success rate = low/informational level", () => {
    // successRate = 0, no tests bypassed, with non-exploitable strategy
    const result = calculatePluginRiskScore("low", 0, {
      humanExploitable: false,
      humanComplexity: "high",
    });
    expect(["low", "informational"]).toContain(result.level);
    expect(result.score).toBeLessThanOrEqual(4);
  });
});

// ---------------------------------------------------------------------------
// calculateSystemRiskScore
// ---------------------------------------------------------------------------

describe("calculateSystemRiskScore", () => {
  it("aggregates multiple plugin scores correctly", () => {
    const pluginScores = [
      makePluginScore("p1", "critical", 10, 2),
      makePluginScore("p2", "low", 10, 9),
    ];
    const system = calculateSystemRiskScore(pluginScores);
    expect(system.score).toBeGreaterThan(0);
    expect(system.plugins).toHaveLength(2);
    expect(typeof system.level).toBe("string");
  });

  it("with empty array returns score 0", () => {
    const system = calculateSystemRiskScore([]);
    expect(system.score).toBe(0);
    expect(system.plugins).toHaveLength(0);
  });

  it("distribution counts are correct", () => {
    const pluginScores = [
      makePluginScore("p1", "critical", 10, 1),
      makePluginScore("p2", "critical", 10, 0),
      makePluginScore("p3", "low", 10, 9),
    ];
    const system = calculateSystemRiskScore(pluginScores);
    const totalDistribution = Object.values(system.distribution).reduce((a, b) => a + b, 0);
    expect(totalDistribution).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// scoreToLevel
// ---------------------------------------------------------------------------

describe("scoreToLevel", () => {
  it("maps score ranges correctly", () => {
    // 0 with no severity = informational
    expect(scoreToLevel(0)).toBe("informational");

    // Low range: (0, 4)
    expect(scoreToLevel(1)).toBe("low");
    expect(scoreToLevel(2)).toBe("low");
    expect(scoreToLevel(3)).toBe("low");
    expect(scoreToLevel(3.9)).toBe("low");

    // Medium range: [4, 7)
    expect(scoreToLevel(4)).toBe("medium");
    expect(scoreToLevel(5)).toBe("medium");
    expect(scoreToLevel(6)).toBe("medium");
    expect(scoreToLevel(6.9)).toBe("medium");

    // High range: [7, 9)
    expect(scoreToLevel(7)).toBe("high");
    expect(scoreToLevel(8)).toBe("high");
    expect(scoreToLevel(8.9)).toBe("high");

    // Critical range: [9, 10]
    expect(scoreToLevel(9)).toBe("critical");
    expect(scoreToLevel(10)).toBe("critical");
  });
});
