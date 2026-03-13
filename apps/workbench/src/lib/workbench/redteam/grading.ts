/**
 * Red Team Grading
 *
 * Grades simulation results against expected verdicts from red-team scenarios.
 * Produces per-scenario scores and aggregate summaries by plugin.
 */

import type { TestScenario, SimulationResult, Verdict } from "../types";
import type { RedTeamGradingResult } from "./types";

// ---------------------------------------------------------------------------
// Verdict comparison helpers
// ---------------------------------------------------------------------------

const VERDICT_SEVERITY: Record<Verdict, number> = {
  deny: 2,
  warn: 1,
  allow: 0,
};

// Note: scenario names are embedded in reason strings. React auto-escapes these
// in JSX, but consumers rendering as raw HTML must escape manually.

/**
 * Score a simulation result against the scenario's expected verdict.
 *
 *  - 1.0  exact match (e.g. expected deny, got deny)
 *  - 0.5  partial (e.g. expected deny, got warn — still flagged but not blocked)
 *  - 0.0  opposite (e.g. expected deny, got allow — guard missed the attack)
 */
function computeScore(expected: Verdict, actual: Verdict): number {
  if (expected === actual) return 1.0;

  const diff = Math.abs(VERDICT_SEVERITY[expected] - VERDICT_SEVERITY[actual]);
  // diff === 1 → partial, diff === 2 → opposite
  return diff === 1 ? 0.5 : 0.0;
}

function buildReason(
  expected: Verdict,
  actual: Verdict,
  score: number,
  scenarioName: string,
): string {
  if (score === 1.0) {
    return `PASS: "${scenarioName}" — expected ${expected}, got ${actual}. Guard correctly handled the scenario.`;
  }
  if (score === 0.5) {
    return `PARTIAL: "${scenarioName}" — expected ${expected}, got ${actual}. Guard flagged the scenario but at a different enforcement level.`;
  }
  return `FAIL: "${scenarioName}" — expected ${expected}, got ${actual}. Guard did not catch the attack.`;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Grade a single simulation result against its source scenario.
 *
 * Returns a RedTeamGradingResult with pass (score >= 1.0), numeric score, and
 * a human-readable reason.
 */
export function gradeSimulationResult(
  scenario: TestScenario,
  result: SimulationResult,
): RedTeamGradingResult {
  const expected = scenario.expectedVerdict;
  if (!expected) {
    return {
      pass: true,
      score: 1.0,
      reason: `No expected verdict for "${scenario.name}" — grading skipped.`,
      skipped: true,
    };
  }

  const actual = result.overallVerdict;
  const score = computeScore(expected, actual);
  // Strict threshold: only a full match (deny→deny, allow→allow) counts as pass.
  // A warn when deny was expected means the attack was detected but not blocked.
  const pass = score >= 1.0;
  const reason = buildReason(expected, actual, score, scenario.name);

  return { pass, score, reason };
}

// ---------------------------------------------------------------------------
// Batch grading
// ---------------------------------------------------------------------------

export interface PluginGradeSummary {
  passed: number;
  failed: number;
  successRate: number;
}

export interface BatchGradeResult {
  grades: RedTeamGradingResult[];
  summary: {
    total: number;
    passed: number;
    failed: number;
    skipped: number;
    passRate: number;
  };
  perPlugin: Record<string, PluginGradeSummary>;
}

/**
 * Grade a batch of scenarios against their simulation results.
 *
 * Scenarios and results are matched by index. Both arrays must have the same
 * length.
 *
 * Returns per-scenario grades, an aggregate summary, and per-plugin breakdown.
 */
export function gradeBatch(
  scenarios: TestScenario[],
  results: SimulationResult[],
): BatchGradeResult {
  if (scenarios.length !== results.length) {
    throw new Error(`gradeBatch: scenarios (${scenarios.length}) and results (${results.length}) must have same length`);
  }

  const grades: RedTeamGradingResult[] = [];
  const perPlugin: Record<string, { passed: number; failed: number }> = {};

  let passed = 0;
  let failed = 0;
  let skipped = 0;

  for (let i = 0; i < scenarios.length; i++) {
    const scenario = scenarios[i];
    const result = results[i];

    if (!result) {
      grades.push({
        pass: false,
        score: 0,
        reason: `No simulation result for scenario "${scenario.name}".`,
      });
      failed++;
      continue;
    }

    const grade = gradeSimulationResult(scenario, result);
    grades.push(grade);

    if (grade.skipped) {
      skipped++;
      continue;
    }

    if (grade.pass) {
      passed++;
    } else {
      failed++;
    }

    // Track per-plugin stats using the redteamPluginId if present
    const pluginId =
      (scenario as { redteamPluginId?: string }).redteamPluginId ?? "unknown";
    if (!perPlugin[pluginId]) {
      perPlugin[pluginId] = { passed: 0, failed: 0 };
    }
    if (grade.pass) {
      perPlugin[pluginId].passed++;
    } else {
      perPlugin[pluginId].failed++;
    }
  }

  const total = scenarios.length;
  const gradedTotal = total - skipped;
  const passRate = gradedTotal > 0 ? passed / gradedTotal : 1.0;

  // Convert accumulated counts to PluginGradeSummary with successRate
  const perPluginSummary: Record<string, PluginGradeSummary> = {};
  for (const [pid, counts] of Object.entries(perPlugin)) {
    const pluginTotal = counts.passed + counts.failed;
    perPluginSummary[pid] = {
      ...counts,
      successRate: pluginTotal > 0 ? counts.passed / pluginTotal : 0,
    };
  }

  return {
    grades,
    summary: { total, passed, failed, skipped, passRate },
    perPlugin: perPluginSummary,
  };
}
