/**
 * Bridge types for integrating promptfoo red teaming data into the
 * ClawdStrike policy builder workbench.
 *
 * Types that overlap with promptfoo are documented with their source.
 */

import type { GuardId, ThreatSeverity, TestScenario } from "../types.ts";


/** A promptfoo red-team plugin mapped to ClawdStrike guards. */
export interface RedTeamPlugin {
  id: string;
  description: string;
  severity: ThreatSeverity;
  category: string;
  guardMapping: GuardId[];
}

/**
 * Strategy metadata (human exploitability & complexity).
 * Copied from promptfoo/src/redteam/riskScoring.ts — StrategyMetadata
 */
export interface RedTeamStrategy {
  id: string;
  description: string;
  humanExploitable: boolean;
  humanComplexity: "low" | "medium" | "high";
}


/**
 * Per-plugin risk score result.
 * Mirrors promptfoo's RiskScore structure (score + level).
 */
export interface RedTeamRiskScore {
  score: number;
  level: "critical" | "high" | "medium" | "low" | "informational";
}

/**
 * Extended plugin risk score with test metadata.
 */
export interface RedTeamPluginRiskScore {
  pluginId: string;
  severity: ThreatSeverity;
  successRate: number;
  riskScore: RedTeamRiskScore;
  testCount: number;
  passCount: number;
}

/**
 * System-level risk aggregation.
 * Mirrors promptfoo's SystemRiskScore structure.
 */
export interface RedTeamSystemRiskScore {
  score: number;
  level: string;
  plugins: RedTeamPluginRiskScore[];
  distribution: Record<string, number>;
}


/**
 * Result of grading a single red-team scenario.
 */
export interface RedTeamGradingResult {
  pass: boolean;
  score: number;
  reason: string;
  skipped?: boolean;
}


/** Extends the workbench TestScenario with optional red-team identifiers. */
export interface RedTeamScenario extends TestScenario {
  redteamPluginId?: string;
  redteamStrategyId?: string;
}
