import type { WorkbenchPolicy, GuardConfigMap, GuardId } from "./types";

// ---- Types ----

export interface VersionDiff {
  fromVersion: number;
  toVersion: number;
  changes: VersionChange[];
  summary: string;
}

export interface VersionChange {
  type: "added" | "removed" | "modified";
  category: "guard" | "setting" | "meta" | "origin" | "posture" | "extends";
  path: string;
  description: string;
  before?: unknown;
  after?: unknown;
}

// ---- Guard display names ----

const GUARD_NAMES: Record<string, string> = {
  forbidden_path: "Forbidden Path",
  path_allowlist: "Path Allowlist",
  egress_allowlist: "Egress Allowlist",
  secret_leak: "Secret Leak",
  patch_integrity: "Patch Integrity",
  shell_command: "Shell Command",
  mcp_tool: "MCP Tool",
  prompt_injection: "Prompt Injection",
  jailbreak: "Jailbreak",
  computer_use: "Computer Use",
  remote_desktop_side_channel: "Remote Desktop Side Channel",
  input_injection_capability: "Input Injection Capability",
  spider_sense: "Spider Sense",
};

function guardName(id: string): string {
  return GUARD_NAMES[id] ?? id;
}

// ---- Helpers ----

function stringify(val: unknown): string {
  if (val === undefined || val === null) return "(none)";
  if (typeof val === "boolean") return val ? "true" : "false";
  if (typeof val === "number") return String(val);
  if (typeof val === "string") return val;
  if (Array.isArray(val)) {
    if (val.length === 0) return "[]";
    // Show count for long arrays
    if (val.length > 3) return `[${val.length} items]`;
    return JSON.stringify(val);
  }
  return JSON.stringify(val);
}

/** @internal Exported for testing. */
export function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (a === undefined && b === undefined) return true;
  if (a === null && b === null) return true;
  if (typeof a !== typeof b) return false;
  if (typeof a !== "object" || a === null || b === null) return false;

  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    return a.every((item, i) => deepEqual(item, b[i]));
  }

  if (Array.isArray(a) !== Array.isArray(b)) return false;

  const keysA = Object.keys(a as Record<string, unknown>);
  const keysB = Object.keys(b as Record<string, unknown>);
  const allKeys = new Set([...keysA, ...keysB]);

  for (const key of allKeys) {
    if (!deepEqual((a as Record<string, unknown>)[key], (b as Record<string, unknown>)[key])) {
      return false;
    }
  }
  return true;
}

/** @internal Exported for testing. */
export function canonicalStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalStringify).join(",")}]`;
  const sorted = Object.keys(value as Record<string, unknown>).sort();
  return `{${sorted.map(k => `${JSON.stringify(k)}:${canonicalStringify((value as Record<string, unknown>)[k])}`).join(",")}}`;
}

/** @internal Exported for testing. */
export function countArrayDiff(before: unknown[] | undefined, after: unknown[] | undefined): { added: number; removed: number } {
  const b = before ?? [];
  const a = after ?? [];
  const bSet = new Set(b.map((v) => canonicalStringify(v)));
  const aSet = new Set(a.map((v) => canonicalStringify(v)));

  let added = 0;
  let removed = 0;

  for (const item of aSet) {
    if (!bSet.has(item)) added++;
  }
  for (const item of bSet) {
    if (!aSet.has(item)) removed++;
  }

  return { added, removed };
}

// ---- Diff engine ----

function diffGuards(from: GuardConfigMap, to: GuardConfigMap): VersionChange[] {
  const changes: VersionChange[] = [];
  const allGuardIds = new Set([
    ...Object.keys(from),
    ...Object.keys(to),
  ]);

  for (const gid of allGuardIds) {
    const fromConfig = from[gid as GuardId] as Record<string, unknown> | undefined;
    const toConfig = to[gid as GuardId] as Record<string, unknown> | undefined;

    const fromPresent = fromConfig !== undefined;
    const toPresent = toConfig !== undefined;

    if (!fromPresent && toPresent) {
      const enabled = toConfig?.enabled === true;
      changes.push({
        type: "added",
        category: "guard",
        path: `guards.${gid}`,
        description: `Added ${guardName(gid)} guard${enabled ? " (enabled)" : " (disabled)"}`,
        after: toConfig,
      });
      continue;
    }

    if (fromPresent && !toPresent) {
      changes.push({
        type: "removed",
        category: "guard",
        path: `guards.${gid}`,
        description: `Removed ${guardName(gid)} guard`,
        before: fromConfig,
      });
      continue;
    }

    if (fromPresent && toPresent && !deepEqual(fromConfig, toConfig)) {
      // Determine what changed within the guard
      const details: string[] = [];
      const allFields = new Set([
        ...Object.keys(fromConfig ?? {}),
        ...Object.keys(toConfig ?? {}),
      ]);

      for (const field of allFields) {
        const fv = fromConfig?.[field];
        const tv = toConfig?.[field];

        if (deepEqual(fv, tv)) continue;

        if (field === "enabled") {
          details.push(tv === true ? "enabled" : "disabled");
        } else if (Array.isArray(fv) || Array.isArray(tv)) {
          const diff = countArrayDiff(
            Array.isArray(fv) ? fv : undefined,
            Array.isArray(tv) ? tv : undefined,
          );
          const parts: string[] = [];
          if (diff.added > 0) parts.push(`+${diff.added}`);
          if (diff.removed > 0) parts.push(`-${diff.removed}`);
          details.push(`${field}: ${parts.join(", ")} entries`);
        } else {
          details.push(`${field}: ${stringify(fv)} -> ${stringify(tv)}`);
        }
      }

      changes.push({
        type: "modified",
        category: "guard",
        path: `guards.${gid}`,
        description: details.length > 0
          ? `${guardName(gid)}: ${details.join("; ")}`
          : `Modified ${guardName(gid)} guard`,
        before: fromConfig,
        after: toConfig,
      });
    }
  }

  return changes;
}

function diffSettings(from: WorkbenchPolicy, to: WorkbenchPolicy): VersionChange[] {
  const changes: VersionChange[] = [];
  const allKeys = new Set([
    ...Object.keys(from.settings),
    ...Object.keys(to.settings),
  ]);

  for (const key of allKeys) {
    const fv = (from.settings as Record<string, unknown>)[key];
    const tv = (to.settings as Record<string, unknown>)[key];
    if (!deepEqual(fv, tv)) {
      const isNew = fv === undefined;
      const isRemoved = tv === undefined;
      changes.push({
        type: isNew ? "added" : isRemoved ? "removed" : "modified",
        category: "setting",
        path: `settings.${key}`,
        description: `${key}: ${stringify(fv)} -> ${stringify(tv)}`,
        before: fv,
        after: tv,
      });
    }
  }

  return changes;
}

function diffMeta(from: WorkbenchPolicy, to: WorkbenchPolicy): VersionChange[] {
  const changes: VersionChange[] = [];

  if (from.name !== to.name) {
    changes.push({
      type: "modified",
      category: "meta",
      path: "name",
      description: `Name: "${from.name}" -> "${to.name}"`,
      before: from.name,
      after: to.name,
    });
  }

  if (from.version !== to.version) {
    changes.push({
      type: "modified",
      category: "meta",
      path: "version",
      description: `Schema version: ${from.version} -> ${to.version}`,
      before: from.version,
      after: to.version,
    });
  }

  if (from.description !== to.description) {
    changes.push({
      type: "modified",
      category: "meta",
      path: "description",
      description: "Description changed",
      before: from.description,
      after: to.description,
    });
  }

  if ((from.extends ?? "") !== (to.extends ?? "")) {
    const fromExt = from.extends;
    const toExt = to.extends;
    if (!fromExt && toExt) {
      changes.push({
        type: "added",
        category: "extends",
        path: "extends",
        description: `Base ruleset set to "${toExt}"`,
        after: toExt,
      });
    } else if (fromExt && !toExt) {
      changes.push({
        type: "removed",
        category: "extends",
        path: "extends",
        description: `Removed base ruleset "${fromExt}"`,
        before: fromExt,
      });
    } else {
      changes.push({
        type: "modified",
        category: "extends",
        path: "extends",
        description: `Base ruleset: "${fromExt}" -> "${toExt}"`,
        before: fromExt,
        after: toExt,
      });
    }
  }

  return changes;
}

function diffPosture(from: WorkbenchPolicy, to: WorkbenchPolicy): VersionChange[] {
  const changes: VersionChange[] = [];

  const hasFrom = from.posture !== undefined;
  const hasTo = to.posture !== undefined;

  if (!hasFrom && hasTo) {
    changes.push({
      type: "added",
      category: "posture",
      path: "posture",
      description: `Added posture config (initial: ${to.posture?.initial})`,
      after: to.posture,
    });
  } else if (hasFrom && !hasTo) {
    changes.push({
      type: "removed",
      category: "posture",
      path: "posture",
      description: "Removed posture config",
      before: from.posture,
    });
  } else if (hasFrom && hasTo && !deepEqual(from.posture, to.posture)) {
    changes.push({
      type: "modified",
      category: "posture",
      path: "posture",
      description: "Posture configuration modified",
      before: from.posture,
      after: to.posture,
    });
  }

  return changes;
}

function diffOrigins(from: WorkbenchPolicy, to: WorkbenchPolicy): VersionChange[] {
  const changes: VersionChange[] = [];

  const hasFrom = from.origins !== undefined;
  const hasTo = to.origins !== undefined;

  if (!hasFrom && hasTo) {
    const profileCount = to.origins?.profiles?.length ?? 0;
    changes.push({
      type: "added",
      category: "origin",
      path: "origins",
      description: `Added origin enforcement (${profileCount} profile${profileCount !== 1 ? "s" : ""})`,
      after: to.origins,
    });
  } else if (hasFrom && !hasTo) {
    changes.push({
      type: "removed",
      category: "origin",
      path: "origins",
      description: "Removed origin enforcement",
      before: from.origins,
    });
  } else if (hasFrom && hasTo && !deepEqual(from.origins, to.origins)) {
    const fromCount = from.origins?.profiles?.length ?? 0;
    const toCount = to.origins?.profiles?.length ?? 0;
    const details: string[] = [];
    if (fromCount !== toCount) {
      details.push(`profiles: ${fromCount} -> ${toCount}`);
    }
    if (from.origins?.default_behavior !== to.origins?.default_behavior) {
      details.push(`default: ${from.origins?.default_behavior ?? "unset"} -> ${to.origins?.default_behavior ?? "unset"}`);
    }

    changes.push({
      type: "modified",
      category: "origin",
      path: "origins",
      description: details.length > 0
        ? `Origin enforcement: ${details.join("; ")}`
        : "Origin enforcement modified",
      before: from.origins,
      after: to.origins,
    });
  }

  return changes;
}

// ---- Public API ----

export function diffVersions(
  from: WorkbenchPolicy,
  to: WorkbenchPolicy,
  fromVersionNum = 0,
  toVersionNum = 0,
): VersionDiff {
  const changes: VersionChange[] = [
    ...diffMeta(from, to),
    ...diffGuards(from.guards, to.guards),
    ...diffSettings(from, to),
    ...diffPosture(from, to),
    ...diffOrigins(from, to),
  ];

  return {
    fromVersion: fromVersionNum,
    toVersion: toVersionNum,
    changes,
    summary: generateChangeSummary({ fromVersion: fromVersionNum, toVersion: toVersionNum, changes, summary: "" }),
  };
}

export function generateChangeSummary(diff: VersionDiff): string {
  if (diff.changes.length === 0) return "No changes";

  const counts: Record<string, { added: number; removed: number; modified: number }> = {};

  for (const change of diff.changes) {
    if (!counts[change.category]) {
      counts[change.category] = { added: 0, removed: 0, modified: 0 };
    }
    counts[change.category][change.type]++;
  }

  const parts: string[] = [];

  for (const [category, c] of Object.entries(counts)) {
    const label = category === "guard" ? "guard" : category === "setting" ? "setting" : category;
    const items: string[] = [];
    if (c.added > 0) items.push(`+${c.added}`);
    if (c.removed > 0) items.push(`-${c.removed}`);
    if (c.modified > 0) items.push(`~${c.modified}`);

    const plural = (c.added + c.removed + c.modified) > 1 ? "s" : "";
    parts.push(`${items.join("")} ${label}${plural}`);
  }

  return parts.join(", ");
}

/**
 * Generate a compact one-line summary for a version entry in the timeline.
 * Example: "+2 guards, ~1 setting"
 */
export function compactChangeSummary(changes: VersionChange[]): string {
  if (changes.length === 0) return "";

  const guardAdded = changes.filter((c) => c.category === "guard" && c.type === "added").length;
  const guardRemoved = changes.filter((c) => c.category === "guard" && c.type === "removed").length;
  const guardModified = changes.filter((c) => c.category === "guard" && c.type === "modified").length;
  const settingChanges = changes.filter((c) => c.category === "setting").length;
  const metaChanges = changes.filter((c) => c.category === "meta" || c.category === "extends").length;
  const otherChanges = changes.filter(
    (c) => c.category === "origin" || c.category === "posture",
  ).length;

  const parts: string[] = [];

  if (guardAdded > 0 || guardRemoved > 0 || guardModified > 0) {
    const items: string[] = [];
    if (guardAdded > 0) items.push(`+${guardAdded}`);
    if (guardRemoved > 0) items.push(`-${guardRemoved}`);
    if (guardModified > 0) items.push(`~${guardModified}`);
    const total = guardAdded + guardRemoved + guardModified;
    parts.push(`${items.join("")} guard${total > 1 ? "s" : ""}`);
  }

  if (settingChanges > 0) {
    parts.push(`~${settingChanges} setting${settingChanges > 1 ? "s" : ""}`);
  }

  if (metaChanges > 0) {
    parts.push(`~${metaChanges} meta`);
  }

  if (otherChanges > 0) {
    parts.push(`~${otherChanges} other`);
  }

  return parts.join(", ");
}
