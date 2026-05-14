/**
 * Coverage Bridge
 *
 * Connects the red-team scenario generator with the coverage analyzer to
 * identify untested guards, suggest plugins, and auto-generate gap-filling
 * scenarios.
 */

import type {
  WorkbenchPolicy,
  GuardId,
  TestScenario,
} from "../types";
import type { CoverageReport } from "../coverage-analyzer";
import type { RedTeamScenario } from "./types";
import { GUARD_TO_PLUGINS } from "./plugin-registry";
import { generateRedTeamScenarios } from "./scenario-generator";


function pluginsForGuard(guardId: GuardId): string[] {
  return GUARD_TO_PLUGINS[guardId] ?? [];
}


export interface RedTeamGap {
  guardId: GuardId;
  suggestedPlugins: string[];
  suggestedScenarioCount: number;
}

/**
 * Cross-reference a coverage report with the policy to find guards that
 * are enabled but have no (or insufficient) red-team scenario coverage.
 *
 * For each gap, suggest which promptfoo plugins should be used and how many
 * scenarios to generate.
 */
export function identifyRedTeamGaps(
  coverageReport: CoverageReport,
  _policy: WorkbenchPolicy,
): RedTeamGap[] {
  const gaps: RedTeamGap[] = [];

  for (const guard of coverageReport.guards) {
    if (guard.status === "disabled") continue;

    // An "uncovered" guard definitely needs scenarios.
    // A "covered" guard with fewer than 2 scenarios is also a gap worth filling.
    const needsMore = guard.status === "uncovered" || guard.scenarioCount < 2;
    if (!needsMore) continue;

    const plugins = pluginsForGuard(guard.guardId);
    // Suggest 2-3 scenarios per plugin, capped by number of plugins
    const suggestedCount = Math.max(2, plugins.length * 2);

    gaps.push({
      guardId: guard.guardId,
      suggestedPlugins: plugins,
      suggestedScenarioCount: suggestedCount,
    });
  }

  return gaps;
}


/**
 * Auto-generate red-team scenarios for guards identified as coverage gaps.
 *
 * Uses the red-team scenario generator scoped to just the gap guard IDs.
 */
export function generateGapFillingScenarios(
  gaps: RedTeamGap[],
  policy: WorkbenchPolicy,
): RedTeamScenario[] {
  if (gaps.length === 0) return [];

  const guardIds = gaps.map((g) => g.guardId);

  // Use the maximum suggested count across all gaps as the per-guard limit
  const maxPerGuard = Math.max(...gaps.map((g) => g.suggestedScenarioCount));

  return generateRedTeamScenarios(policy, {
    guardIds,
    maxPerGuard,
  });
}


export interface GuardRedTeamCoverage {
  total: number;
  covered: number;
}

export interface RedTeamCoverageReport {
  totalPlugins: number;
  coveredPlugins: number;
  coveragePercent: number;
  byGuard: Record<GuardId, GuardRedTeamCoverage>;
}

/**
 * Compute red-team coverage: how many of the relevant plugins for each
 * enabled guard have at least one scenario exercising them?
 */
export function computeRedTeamCoverage(
  policy: WorkbenchPolicy,
  scenarios: TestScenario[],
): RedTeamCoverageReport {
  // Build a set of plugin IDs present in the scenario list
  const coveredPluginIds = new Set<string>();
  for (const s of scenarios) {
    const pluginId = (s as RedTeamScenario).redteamPluginId;
    if (pluginId) {
      coveredPluginIds.add(pluginId);
    }
  }

  // For each enabled guard, compute how many of its relevant plugins are covered
  const byGuard: Record<string, GuardRedTeamCoverage> = {};
  const allPluginIds = new Set<string>();
  const allCoveredPluginIds = new Set<string>();

  for (const [guardId, config] of Object.entries(policy.guards)) {
    if (!config) continue;
    const enabled = (config as { enabled?: boolean }).enabled !== false;
    if (!enabled) continue;

    const gid = guardId as GuardId;
    const plugins = pluginsForGuard(gid);
    const total = plugins.length;
    let covered = 0;

    for (const pid of plugins) {
      allPluginIds.add(pid);
      // Use prefix matching to bridge canonical IDs (e.g. "pii:direct") with
      // scenario-template-local IDs (e.g. "pii"). "pii" matches "pii:direct",
      // and "pii:direct" matches "pii".
      const isCovered = [...coveredPluginIds].some(
        (covId) =>
          covId === pid ||
          covId.startsWith(pid + ":") ||
          pid.startsWith(covId + ":"),
      );
      if (isCovered) {
        covered++;
        allCoveredPluginIds.add(pid);
      }
    }

    byGuard[gid] = { total, covered };
  }

  const totalPlugins = allPluginIds.size;
  const coveredPlugins = allCoveredPluginIds.size;
  const coveragePercent =
    totalPlugins > 0 ? Math.round((coveredPlugins / totalPlugins) * 100) : 100;

  return {
    totalPlugins,
    coveredPlugins,
    coveragePercent,
    byGuard: byGuard as Record<GuardId, GuardRedTeamCoverage>,
  };
}
