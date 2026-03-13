/**
 * Threat Matrix data definitions.
 *
 * Maps 13 guards against 8 attack categories to compute coverage scores
 * and identify gaps in a policy configuration.
 */

import type { GuardId, GuardConfigMap, WorkbenchPolicy } from "./types";
import type { TestScenario, TestActionType, SimulationResult } from "./types";
import { ALL_GUARD_IDS, GUARD_DISPLAY_NAMES } from "./guard-registry";

// ---------------------------------------------------------------------------
// Attack categories
// ---------------------------------------------------------------------------

export type AttackCategory =
  | "file_exfiltration"
  | "network_egress"
  | "command_injection"
  | "credential_theft"
  | "prompt_injection"
  | "jailbreak"
  | "mcp_abuse"
  | "patch_tampering";

export interface AttackCategoryMeta {
  id: AttackCategory;
  label: string;
  shortLabel: string;
  description: string;
}

export const ATTACK_CATEGORIES: AttackCategoryMeta[] = [
  {
    id: "file_exfiltration",
    label: "File Exfiltration",
    shortLabel: "File Exfil",
    description: "Unauthorized access or extraction of sensitive files from the filesystem.",
  },
  {
    id: "network_egress",
    label: "Network Egress",
    shortLabel: "Net Egress",
    description: "Unauthorized outbound network connections to exfiltrate data or contact C2.",
  },
  {
    id: "command_injection",
    label: "Command Injection",
    shortLabel: "Cmd Inject",
    description: "Execution of dangerous shell commands, reverse shells, or destructive operations.",
  },
  {
    id: "credential_theft",
    label: "Credential Theft",
    shortLabel: "Cred Theft",
    description: "Attempts to read, copy, or exfiltrate secrets, API keys, and authentication tokens.",
  },
  {
    id: "prompt_injection",
    label: "Prompt Injection",
    shortLabel: "Prompt Inj",
    description: "Manipulation of agent instructions through crafted prompts to override system behavior.",
  },
  {
    id: "jailbreak",
    label: "Jailbreak",
    shortLabel: "Jailbreak",
    description: "Attempts to bypass agent safety guardrails through social engineering or role-playing.",
  },
  {
    id: "mcp_abuse",
    label: "MCP Abuse",
    shortLabel: "MCP Abuse",
    description: "Unauthorized or excessive use of MCP tool capabilities beyond intended scope.",
  },
  {
    id: "patch_tampering",
    label: "Patch Tampering",
    shortLabel: "Patch Tamp",
    description: "Malicious code changes through oversized patches, forbidden patterns, or backdoors.",
  },
];

// ---------------------------------------------------------------------------
// Guard-to-Attack coverage mapping
// ---------------------------------------------------------------------------

export type CoverageLevel = "full" | "partial" | "none" | "na";

/**
 * Static mapping of which guards cover which attack categories.
 * "full" = primary defense, "partial" = secondary/indirect, "na" = not applicable.
 */
const STATIC_COVERAGE: Record<GuardId, Record<AttackCategory, CoverageLevel>> = {
  forbidden_path: {
    file_exfiltration: "full",
    network_egress: "na",
    command_injection: "partial",
    credential_theft: "full",
    prompt_injection: "na",
    jailbreak: "na",
    mcp_abuse: "na",
    patch_tampering: "na",
  },
  path_allowlist: {
    file_exfiltration: "full",
    network_egress: "na",
    command_injection: "na",
    credential_theft: "full",
    prompt_injection: "na",
    jailbreak: "na",
    mcp_abuse: "na",
    patch_tampering: "partial",
  },
  egress_allowlist: {
    file_exfiltration: "partial",
    network_egress: "full",
    command_injection: "partial",
    credential_theft: "partial",
    prompt_injection: "na",
    jailbreak: "na",
    mcp_abuse: "na",
    patch_tampering: "na",
  },
  secret_leak: {
    file_exfiltration: "partial",
    network_egress: "na",
    command_injection: "na",
    credential_theft: "full",
    prompt_injection: "na",
    jailbreak: "na",
    mcp_abuse: "na",
    patch_tampering: "partial",
  },
  patch_integrity: {
    file_exfiltration: "na",
    network_egress: "na",
    command_injection: "na",
    credential_theft: "na",
    prompt_injection: "na",
    jailbreak: "na",
    mcp_abuse: "na",
    patch_tampering: "full",
  },
  shell_command: {
    file_exfiltration: "partial",
    network_egress: "partial",
    command_injection: "full",
    credential_theft: "partial",
    prompt_injection: "na",
    jailbreak: "na",
    mcp_abuse: "na",
    patch_tampering: "na",
  },
  mcp_tool: {
    file_exfiltration: "partial",
    network_egress: "na",
    command_injection: "partial",
    credential_theft: "na",
    prompt_injection: "na",
    jailbreak: "na",
    mcp_abuse: "full",
    patch_tampering: "na",
  },
  prompt_injection: {
    file_exfiltration: "na",
    network_egress: "na",
    command_injection: "na",
    credential_theft: "na",
    prompt_injection: "full",
    jailbreak: "partial",
    mcp_abuse: "partial",
    patch_tampering: "na",
  },
  jailbreak: {
    file_exfiltration: "na",
    network_egress: "na",
    command_injection: "na",
    credential_theft: "na",
    prompt_injection: "partial",
    jailbreak: "full",
    mcp_abuse: "na",
    patch_tampering: "na",
  },
  computer_use: {
    file_exfiltration: "partial",
    network_egress: "na",
    command_injection: "partial",
    credential_theft: "na",
    prompt_injection: "na",
    jailbreak: "na",
    mcp_abuse: "partial",
    patch_tampering: "na",
  },
  remote_desktop_side_channel: {
    file_exfiltration: "partial",
    network_egress: "partial",
    command_injection: "na",
    credential_theft: "partial",
    prompt_injection: "na",
    jailbreak: "na",
    mcp_abuse: "na",
    patch_tampering: "na",
  },
  input_injection_capability: {
    file_exfiltration: "na",
    network_egress: "na",
    command_injection: "partial",
    credential_theft: "na",
    prompt_injection: "partial",
    jailbreak: "na",
    mcp_abuse: "na",
    patch_tampering: "na",
  },
  spider_sense: {
    file_exfiltration: "partial",
    network_egress: "partial",
    command_injection: "partial",
    credential_theft: "partial",
    prompt_injection: "partial",
    jailbreak: "partial",
    mcp_abuse: "partial",
    patch_tampering: "partial",
  },
};

// ---------------------------------------------------------------------------
// Computed matrix
// ---------------------------------------------------------------------------

export interface MatrixCell {
  guardId: GuardId;
  attackCategory: AttackCategory;
  /** Static coverage level from the mapping. */
  staticLevel: CoverageLevel;
  /** Effective level: degrades to "none" if the guard is disabled. */
  effectiveLevel: CoverageLevel;
  /** Whether the guard is enabled in the policy. */
  guardEnabled: boolean;
}

export interface MatrixRow {
  guardId: GuardId;
  guardName: string;
  cells: MatrixCell[];
}

export interface ThreatMatrixResult {
  rows: MatrixRow[];
  /** Per-category aggregate coverage: 0-100 */
  categoryCoverage: Record<AttackCategory, number>;
  /** Overall threat coverage score: 0-100 */
  overallScore: number;
  /** Critical gaps that need attention. */
  criticalGaps: CriticalGap[];
}

export interface CriticalGap {
  category: AttackCategory;
  categoryLabel: string;
  description: string;
  recommendation: string;
  severity: "high" | "medium";
}

// Note: threat-matrix uses shorter names for some guards (e.g. "RD Side-Channel")
// but we use the canonical display names from guard-registry for consistency.
const GUARD_NAMES = GUARD_DISPLAY_NAMES;

/**
 * Compute the threat matrix for a given policy.
 */
export function computeThreatMatrix(policy: WorkbenchPolicy): ThreatMatrixResult {
  const guards = policy.guards;

  const rows: MatrixRow[] = ALL_GUARD_IDS.map((guardId) => {
    const config = guards[guardId];
    const isEnabled = !!(config && (config as { enabled?: boolean }).enabled !== false && Object.keys(config).length > 0);

    const cells: MatrixCell[] = ATTACK_CATEGORIES.map((cat) => {
      const staticLevel = STATIC_COVERAGE[guardId][cat.id];
      let effectiveLevel: CoverageLevel;
      if (staticLevel === "na") {
        effectiveLevel = "na";
      } else if (!isEnabled) {
        effectiveLevel = "none";
      } else {
        effectiveLevel = staticLevel;
      }
      return {
        guardId,
        attackCategory: cat.id,
        staticLevel,
        effectiveLevel,
        guardEnabled: isEnabled,
      };
    });

    return {
      guardId,
      guardName: GUARD_NAMES[guardId],
      cells,
    };
  });

  // Compute per-category coverage
  const categoryCoverage: Record<AttackCategory, number> = {} as Record<AttackCategory, number>;
  for (const cat of ATTACK_CATEGORIES) {
    const relevantCells = rows
      .flatMap((r) => r.cells)
      .filter((c) => c.attackCategory === cat.id && c.staticLevel !== "na");

    if (relevantCells.length === 0) {
      categoryCoverage[cat.id] = 0;
      continue;
    }

    let score = 0;
    let maxScore = 0;
    for (const cell of relevantCells) {
      const weight = cell.staticLevel === "full" ? 2 : 1;
      maxScore += weight;
      if (cell.effectiveLevel === "full") score += weight;
      else if (cell.effectiveLevel === "partial") score += weight * 0.5;
    }
    categoryCoverage[cat.id] = maxScore > 0 ? Math.round((score / maxScore) * 100) : 0;
  }

  // Overall score
  const categoryScores = Object.values(categoryCoverage);
  const overallScore = categoryScores.length > 0
    ? Math.round(categoryScores.reduce((a, b) => a + b, 0) / categoryScores.length)
    : 0;

  // Identify critical gaps
  const criticalGaps: CriticalGap[] = [];

  for (const cat of ATTACK_CATEGORIES) {
    const coverage = categoryCoverage[cat.id];
    if (coverage < 30) {
      criticalGaps.push({
        category: cat.id,
        categoryLabel: cat.label,
        severity: "high",
        description: `${cat.label} coverage is critically low (${coverage}%)`,
        recommendation: getRecommendation(cat.id, guards),
      });
    } else if (coverage < 60) {
      criticalGaps.push({
        category: cat.id,
        categoryLabel: cat.label,
        severity: "medium",
        description: `${cat.label} coverage is below threshold (${coverage}%)`,
        recommendation: getRecommendation(cat.id, guards),
      });
    }
  }

  return { rows, categoryCoverage, overallScore, criticalGaps };
}

/** Generate actionable recommendations for a specific attack category. */
function getRecommendation(category: AttackCategory, guards: GuardConfigMap): string {
  switch (category) {
    case "file_exfiltration":
      if (!guards.forbidden_path?.enabled) return "Enable Forbidden Path guard with sensitive path patterns.";
      if (!guards.path_allowlist?.enabled) return "Enable Path Allowlist guard for fail-closed file access.";
      return "Review and expand forbidden path patterns.";
    case "network_egress":
      if (!guards.egress_allowlist?.enabled) return "Enable Egress Control guard with an allowlist of trusted domains.";
      return "Review egress allowlist — consider tightening default_action to 'block'.";
    case "command_injection":
      if (!guards.shell_command?.enabled) return "Enable Shell Command guard to block dangerous commands.";
      return "Add more forbidden patterns to the Shell Command guard.";
    case "credential_theft":
      if (!guards.secret_leak?.enabled) return "Enable Secret Leak guard to detect credentials in file writes.";
      if (!guards.forbidden_path?.enabled) return "Enable Forbidden Path guard to protect credential files.";
      return "Add credential file patterns to forbidden paths.";
    case "prompt_injection":
      if (!guards.prompt_injection?.enabled) return "Enable Prompt Injection guard to detect instruction override attempts.";
      return "Lower the block threshold on the Prompt Injection guard.";
    case "jailbreak":
      if (!guards.jailbreak?.enabled) return "Enable Jailbreak Detection guard for multi-layer analysis.";
      return "Lower the block threshold on the Jailbreak guard.";
    case "mcp_abuse":
      if (!guards.mcp_tool?.enabled) return "Enable MCP Tool guard with explicit allow/block lists.";
      return "Tighten MCP Tool default_action to 'block' and review allowed tools.";
    case "patch_tampering":
      if (!guards.patch_integrity?.enabled) return "Enable Patch Integrity guard with addition/deletion limits.";
      return "Review patch integrity limits and add forbidden patterns.";
  }
}

/**
 * Map scenarios to guard/attack cells for drill-down.
 */
export function findScenariosForCell(
  guardId: GuardId,
  attackCategory: AttackCategory,
  scenarios: TestScenario[],
  results: SimulationResult[],
): { scenario: TestScenario; result: SimulationResult | undefined }[] {
  const resultMap = new Map(results.map((r) => [r.scenarioId, r]));

  // Map attack categories to the action types and categories they test
  const relevantScenarios = scenarios.filter((s) => {
    // Must be an attack or edge case
    if (s.category === "benign") return false;

    // Check if scenario is relevant to this attack category
    const isRelevant = isScenarioRelevantToAttack(s, attackCategory);
    if (!isRelevant) return false;

    // Check if this guard would evaluate the scenario
    const result = resultMap.get(s.id);
    if (result) {
      return result.guardResults.some((gr) => gr.guardId === guardId);
    }

    // Heuristic match if no results yet
    return isGuardRelevantToAction(guardId, s.actionType);
  });

  return relevantScenarios.map((s) => ({
    scenario: s,
    result: resultMap.get(s.id),
  }));
}

function isScenarioRelevantToAttack(scenario: TestScenario, attack: AttackCategory): boolean {
  const mapping: Record<AttackCategory, TestActionType[]> = {
    file_exfiltration: ["file_access", "file_write"],
    network_egress: ["network_egress"],
    command_injection: ["shell_command"],
    credential_theft: ["file_access", "file_write"],
    prompt_injection: ["user_input"],
    jailbreak: ["user_input"],
    mcp_abuse: ["mcp_tool_call"],
    patch_tampering: ["patch_apply"],
  };
  return mapping[attack]?.includes(scenario.actionType) ?? false;
}

function isGuardRelevantToAction(guardId: GuardId, actionType: TestActionType): boolean {
  const mapping: Record<GuardId, TestActionType[]> = {
    forbidden_path: ["file_access", "file_write"],
    path_allowlist: ["file_access", "file_write", "patch_apply"],
    egress_allowlist: ["network_egress"],
    secret_leak: ["file_write"],
    patch_integrity: ["patch_apply"],
    shell_command: ["shell_command"],
    mcp_tool: ["mcp_tool_call"],
    prompt_injection: ["user_input"],
    jailbreak: ["user_input"],
    computer_use: [],
    remote_desktop_side_channel: [],
    input_injection_capability: [],
    spider_sense: [],
  };
  return mapping[guardId]?.includes(actionType) ?? false;
}
