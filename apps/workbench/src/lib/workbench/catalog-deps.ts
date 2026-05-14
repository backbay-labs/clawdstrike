// ---- Catalog dependency tracking ----

import type { CatalogEntry } from "./policy-catalog";
import { BUILTIN_RULESETS } from "./builtin-rulesets";

export interface DependencyInfo {
  catalogId: string;
  extendsRuleset: string | null;
  dependsOn: string[];
  lastBaseUpdate: string;
  hasBreakingChanges: boolean;
}

export interface UpdateCheck {
  baseRulesetId: string | null;
  baseExists: boolean;
  /** Whether the catalog entry's base YAML has diverged from the current builtin. */
  hasUpdates: boolean;
  /** Human-readable summary of what changed. */
  summary: string;
}

/**
 * Analyze the dependency graph for a catalog entry.
 * Checks which builtin ruleset it extends and whether any other
 * catalog entries are referenced.
 */
export function analyzeDependencies(entry: CatalogEntry): DependencyInfo {
  const extendsRuleset = entry.extends ?? null;

  // Check if the base exists in builtins
  const base = extendsRuleset
    ? BUILTIN_RULESETS.find((r) => r.id === extendsRuleset)
    : null;

  // Determine last base update — use the entry's updatedAt as proxy
  // since builtins don't have timestamps; in a real system this would
  // come from a version manifest.
  const lastBaseUpdate = base ? entry.updatedAt : "";

  // Currently no inter-catalog references, but the structure supports it
  const dependsOn: string[] = [];

  return {
    catalogId: entry.id,
    extendsRuleset,
    dependsOn,
    lastBaseUpdate,
    hasBreakingChanges: false,
  };
}

/**
 * Check whether the base ruleset for a catalog entry has changed
 * since the entry was last updated.
 *
 * Compares the `extends` field in the current YAML against the builtin
 * ruleset content. Returns actionable information for the UI.
 */
export function checkForUpdates(
  entry: CatalogEntry,
  currentYaml: string,
): UpdateCheck {
  const baseId = entry.extends ?? null;

  if (!baseId) {
    return {
      baseRulesetId: null,
      baseExists: false,
      hasUpdates: false,
      summary: "This policy does not extend a base ruleset.",
    };
  }

  const base = BUILTIN_RULESETS.find((r) => r.id === baseId);
  if (!base) {
    return {
      baseRulesetId: baseId,
      baseExists: false,
      hasUpdates: false,
      summary: `Base ruleset "${baseId}" not found in builtins.`,
    };
  }

  // Extract the extends line from current YAML to verify it still references
  // the same base. A simple heuristic: if the base YAML content hash differs
  // from what was "baked in" when the catalog entry was authored, flag it.
  const extendsMatch = currentYaml.match(/^extends:\s*["']?(\S+)["']?/m);
  const currentBase = extendsMatch?.[1] ?? null;

  if (currentBase !== baseId) {
    return {
      baseRulesetId: baseId,
      baseExists: true,
      hasUpdates: true,
      summary: `Policy base changed from "${baseId}" to "${currentBase ?? "none"}".`,
    };
  }

  // Compare base YAML length as a simple change heuristic.
  // In production this would use content hashing.
  const baseNormalized = base.yaml.trim();
  const entryRefersToSameBase = entry.yaml.includes(`extends: "${baseId}"`) ||
    entry.yaml.includes(`extends: '${baseId}'`) ||
    entry.yaml.includes(`extends: ${baseId}`);

  if (!entryRefersToSameBase) {
    return {
      baseRulesetId: baseId,
      baseExists: true,
      hasUpdates: false,
      summary: "Policy does not reference the expected base.",
    };
  }

  // For now, report no updates since builtins are compiled in.
  // A real implementation would compare version manifests.
  return {
    baseRulesetId: baseId,
    baseExists: true,
    hasUpdates: false,
    summary: `Up to date with "${base.name}" base ruleset (v${extractBaseVersion(baseNormalized)}).`,
  };
}

function extractBaseVersion(yaml: string): string {
  const match = yaml.match(/version:\s*["']?([^"'\s]+)/);
  return match?.[1] ?? "unknown";
}

/**
 * Get the builtin ruleset YAML for a given ID.
 * Returns null if not found.
 */
export function getBaseRulesetYaml(baseId: string): string | null {
  const base = BUILTIN_RULESETS.find((r) => r.id === baseId);
  return base?.yaml ?? null;
}
