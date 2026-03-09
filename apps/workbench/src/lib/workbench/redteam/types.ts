/**
 * Bridge types for integrating promptfoo red teaming data into the
 * ClawdStrike policy builder workbench.
 */

import type { GuardId, ThreatSeverity, TestScenario } from "../types.ts";

// ---------------------------------------------------------------------------
// Plugin & Strategy metadata
// ---------------------------------------------------------------------------

/** A promptfoo red-team plugin mapped to ClawdStrike guards. */
export interface RedTeamPlugin {
  id: string;
  description: string;
  severity: ThreatSeverity;
  category: string;
  guardMapping: GuardId[];
}

/** Strategy metadata (human exploitability & complexity). */
export interface RedTeamStrategy {
  id: string;
  description: string;
  humanExploitable: boolean;
  humanComplexity: "low" | "medium" | "high";
}

// ---------------------------------------------------------------------------
// Risk scoring
// ---------------------------------------------------------------------------

export interface RedTeamRiskScore {
  score: number;
  level: "critical" | "high" | "medium" | "low" | "informational";
}

export interface RedTeamPluginRiskScore {
  pluginId: string;
  severity: ThreatSeverity;
  successRate: number;
  riskScore: RedTeamRiskScore;
  testCount: number;
  passCount: number;
}

export interface RedTeamSystemRiskScore {
  score: number;
  level: string;
  plugins: RedTeamPluginRiskScore[];
  distribution: Record<string, number>;
}

// ---------------------------------------------------------------------------
// Grading
// ---------------------------------------------------------------------------

export interface RedTeamGradingResult {
  pass: boolean;
  score: number;
  reason: string;
}

// ---------------------------------------------------------------------------
// Scenario extension
// ---------------------------------------------------------------------------

/** Extends the workbench TestScenario with optional red-team identifiers. */
export interface RedTeamScenario extends TestScenario {
  redteamPluginId?: string;
  redteamStrategyId?: string;
}
