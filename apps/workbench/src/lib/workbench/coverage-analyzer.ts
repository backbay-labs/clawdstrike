/**
 * Coverage Analyzer
 *
 * Maps test scenarios to the guards they exercise and computes coverage metrics.
 * Works with both pre-built and auto-generated scenarios.
 */

import type {
  GuardId,
  GuardConfigMap,
  TestScenario,
  TestActionType,
} from "./types";
import { ALL_GUARD_IDS, GUARD_DISPLAY_NAMES } from "./guard-registry";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type GuardCoverageStatus = "covered" | "uncovered" | "disabled";

export interface GuardCoverage {
  guardId: GuardId;
  guardName: string;
  status: GuardCoverageStatus;
  /** Number of scenarios that exercise this guard. */
  scenarioCount: number;
  /** IDs of scenarios that exercise this guard. */
  scenarioIds: string[];
}

export interface CoverageReport {
  /** Total number of guards in the system. */
  totalGuards: number;
  /** Number of enabled guards. */
  enabledGuards: number;
  /** Number of enabled guards with at least one scenario. */
  coveredGuards: number;
  /** Coverage as a percentage of enabled guards (0-100). */
  coveragePercent: number;
  /** Per-guard coverage breakdown. */
  guards: GuardCoverage[];
  /** Guard IDs that are enabled but have no test scenarios. */
  gaps: GuardId[];
}

// ---------------------------------------------------------------------------
// Action type to guard mapping
// ---------------------------------------------------------------------------

/**
 * Maps an action type to the guards it could potentially exercise.
 * Some scenarios can exercise multiple guards (e.g., a file_write
 * could trigger both forbidden_path and secret_leak).
 */
function guardsForActionType(actionType: TestActionType): GuardId[] {
  switch (actionType) {
    case "file_access":
      return ["forbidden_path", "path_allowlist"];
    case "file_write":
      return ["forbidden_path", "path_allowlist", "secret_leak"];
    case "network_egress":
      return ["egress_allowlist"];
    case "shell_command":
      return ["shell_command"];
    case "mcp_tool_call":
      return ["mcp_tool", "computer_use", "remote_desktop_side_channel", "input_injection_capability"];
    case "patch_apply":
      return ["patch_integrity", "path_allowlist"];
    case "user_input":
      return ["prompt_injection", "jailbreak", "spider_sense"];
    default:
      return [];
  }
}

/**
 * Determine which guards a specific scenario exercises based on its action
 * type and ID prefix (auto-generated scenarios encode the guard in the ID).
 */
export function guardsExercisedByScenario(scenario: TestScenario): GuardId[] {
  // Auto-generated scenarios have IDs like "auto-forbidden_path-deny-0"
  // which directly indicate the target guard.
  if (scenario.id.startsWith("auto-")) {
    const parts = scenario.id.split("-");
    // Guard IDs with underscores: reconstruct by taking parts after "auto-"
    // until we hit a known suffix (deny, allow, edge, warn, unknown, etc.)
    const suffixes = new Set([
      "deny", "allow", "edge", "warn", "unknown", "disallowed",
      "default", "listed", "blocked", "configured", "safe", "small",
    ]);
    const guardParts: string[] = [];
    for (let i = 1; i < parts.length; i++) {
      if (suffixes.has(parts[i])) break;
      guardParts.push(parts[i]);
    }
    const guardId = guardParts.join("_") as GuardId;
    if (ALL_GUARD_IDS.includes(guardId)) {
      return [guardId];
    }
  }

  // For pre-built or manual scenarios, infer from action type
  return guardsForActionType(scenario.actionType);
}

// ---------------------------------------------------------------------------
// Main analyzer
// ---------------------------------------------------------------------------

/**
 * Compute coverage metrics for the given scenarios against the policy's guard
 * configuration.
 *
 * @param guardConfigs  The guard configuration map from the active policy
 * @param scenarios     All scenarios to analyze (pre-built + auto-generated + custom)
 * @returns A CoverageReport with per-guard status and overall metrics
 */
export function analyzeCoverage(
  guardConfigs: GuardConfigMap,
  scenarios: TestScenario[],
): CoverageReport {
  // Build a map of guard -> scenario IDs
  const guardScenarioMap = new Map<GuardId, Set<string>>();
  for (const guardId of ALL_GUARD_IDS) {
    guardScenarioMap.set(guardId, new Set());
  }

  for (const scenario of scenarios) {
    const exercised = guardsExercisedByScenario(scenario);
    for (const guardId of exercised) {
      guardScenarioMap.get(guardId)?.add(scenario.id);
    }
  }

  // Build per-guard coverage
  const guards: GuardCoverage[] = [];
  const gaps: GuardId[] = [];
  let enabledCount = 0;
  let coveredCount = 0;

  for (const guardId of ALL_GUARD_IDS) {
    const config = guardConfigs[guardId];
    // Match the simulation engine's logic: a guard is enabled if config exists
    // and enabled is not explicitly false. This means { patterns: [...] } with
    // no "enabled" field is treated as enabled (consistent with fail-closed design).
    const guardEnabled = !!(config && (config as { enabled?: boolean }).enabled !== false);
    const scenarioIds = Array.from(guardScenarioMap.get(guardId) ?? []);
    const scenarioCount = scenarioIds.length;

    let status: GuardCoverageStatus;
    if (!guardEnabled) {
      status = "disabled";
    } else if (scenarioCount > 0) {
      status = "covered";
      coveredCount++;
    } else {
      status = "uncovered";
      gaps.push(guardId);
    }

    if (guardEnabled) {
      enabledCount++;
    }

    guards.push({
      guardId,
      guardName: GUARD_DISPLAY_NAMES[guardId],
      status,
      scenarioCount,
      scenarioIds,
    });
  }

  const coveragePercent = enabledCount > 0
    ? Math.round((coveredCount / enabledCount) * 100)
    : 100;

  return {
    totalGuards: ALL_GUARD_IDS.length,
    enabledGuards: enabledCount,
    coveredGuards: coveredCount,
    coveragePercent,
    guards,
    gaps,
  };
}
