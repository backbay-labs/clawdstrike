import type { PolicyTab } from "@/features/policy/types/policy-tab";


export interface CrossRefMatch {
  /** JSON-path-like location, e.g. "guards.egress_allowlist.allow[2]" */
  path: string;
  /** The matched value as a string */
  value: string;
  /** Approximate 1-based line number in the YAML, if determinable */
  line?: number;
}

export interface CrossRefResult {
  tabId: string;
  tabName: string;
  matches: CrossRefMatch[];
}


/**
 * Recursively walk an object and emit (path, stringValue) pairs for every
 * leaf (string, number, boolean) and every array element.
 */
function* walkPaths(
  obj: unknown,
  prefix: string,
): Generator<{ path: string; value: string }> {
  if (obj === null || obj === undefined) return;

  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      yield* walkPaths(obj[i], `${prefix}[${i}]`);
    }
    return;
  }

  if (typeof obj === "object") {
    for (const [key, val] of Object.entries(obj as Record<string, unknown>)) {
      const childPath = prefix ? `${prefix}.${key}` : key;
      yield* walkPaths(val, childPath);
    }
    return;
  }

  // Leaf value
  yield { path: prefix, value: String(obj) };
}

/**
 * Given a YAML string and a value, try to find the approximate 1-based line
 * number where that value appears. Returns undefined if not found.
 */
function findLineInYaml(yaml: string, value: string): number | undefined {
  const lines = yaml.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes(value)) {
      return i + 1;
    }
  }
  return undefined;
}


/**
 * Full-text search across all open policies' structured data.
 * Matches against both paths and values (case-insensitive).
 */
export function searchAcrossPolicies(
  tabs: PolicyTab[],
  query: string,
): CrossRefResult[] {
  if (!query.trim()) return [];

  const lowerQuery = query.toLowerCase();
  const results: CrossRefResult[] = [];

  for (const tab of tabs) {
    const matches: CrossRefMatch[] = [];

    for (const entry of walkPaths(tab.policy, "")) {
      const pathMatch = entry.path.toLowerCase().includes(lowerQuery);
      const valueMatch = entry.value.toLowerCase().includes(lowerQuery);

      if (pathMatch || valueMatch) {
        matches.push({
          path: entry.path,
          value: entry.value,
          line: findLineInYaml(tab.yaml, entry.value),
        });
      }
    }

    // Also search raw YAML for query strings not found in structured walk
    if (matches.length === 0) {
      const lines = tab.yaml.split("\n");
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].toLowerCase().includes(lowerQuery)) {
          matches.push({
            path: `yaml:${i + 1}`,
            value: lines[i].trim(),
            line: i + 1,
          });
        }
      }
    }

    if (matches.length > 0) {
      results.push({
        tabId: tab.id,
        tabName: tab.name,
        matches,
      });
    }
  }

  return results;
}

/**
 * Find which policies use a specific guard (by guard ID).
 * Returns results with the guard's configuration path.
 */
export function findGuardUsage(
  tabs: PolicyTab[],
  guardId: string,
): CrossRefResult[] {
  const results: CrossRefResult[] = [];

  for (const tab of tabs) {
    const guardConfig = tab.policy.guards[guardId as keyof typeof tab.policy.guards];
    if (!guardConfig) continue;

    const matches: CrossRefMatch[] = [];
    const isEnabled =
      typeof guardConfig === "object" &&
      guardConfig !== null &&
      "enabled" in guardConfig &&
      guardConfig.enabled;

    matches.push({
      path: `guards.${guardId}`,
      value: isEnabled ? "enabled" : "configured (disabled)",
      line: findLineInYaml(tab.yaml, guardId),
    });

    // Walk the guard's sub-config for detail
    for (const entry of walkPaths(guardConfig, `guards.${guardId}`)) {
      matches.push({
        ...entry,
        line: findLineInYaml(tab.yaml, entry.value),
      });
    }

    results.push({
      tabId: tab.id,
      tabName: tab.name,
      matches,
    });
  }

  return results;
}

/**
 * Find which policies reference a specific domain pattern
 * (e.g. "*.amazonaws.com") in egress allowlists, origin profiles, etc.
 */
export function findDomainUsage(
  tabs: PolicyTab[],
  domain: string,
): CrossRefResult[] {
  if (!domain.trim()) return [];

  const lowerDomain = domain.toLowerCase();
  const results: CrossRefResult[] = [];

  for (const tab of tabs) {
    const matches: CrossRefMatch[] = [];

    // Check egress_allowlist
    const egress = tab.policy.guards.egress_allowlist;
    if (egress) {
      if (egress.allow) {
        for (let i = 0; i < egress.allow.length; i++) {
          if (egress.allow[i].toLowerCase().includes(lowerDomain)) {
            matches.push({
              path: `guards.egress_allowlist.allow[${i}]`,
              value: egress.allow[i],
              line: findLineInYaml(tab.yaml, egress.allow[i]),
            });
          }
        }
      }
      if (egress.block) {
        for (let i = 0; i < egress.block.length; i++) {
          if (egress.block[i].toLowerCase().includes(lowerDomain)) {
            matches.push({
              path: `guards.egress_allowlist.block[${i}]`,
              value: egress.block[i],
              line: findLineInYaml(tab.yaml, egress.block[i]),
            });
          }
        }
      }
    }

    // Check origin profiles for egress references
    if (tab.policy.origins?.profiles) {
      for (let pi = 0; pi < tab.policy.origins.profiles.length; pi++) {
        const profile = tab.policy.origins.profiles[pi];
        if (profile.egress?.allow) {
          for (let i = 0; i < profile.egress.allow.length; i++) {
            if (profile.egress.allow[i].toLowerCase().includes(lowerDomain)) {
              matches.push({
                path: `origins.profiles[${pi}].egress.allow[${i}]`,
                value: profile.egress.allow[i],
                line: findLineInYaml(tab.yaml, profile.egress.allow[i]),
              });
            }
          }
        }
        if (profile.egress?.block) {
          for (let i = 0; i < profile.egress.block.length; i++) {
            if (profile.egress.block[i].toLowerCase().includes(lowerDomain)) {
              matches.push({
                path: `origins.profiles[${pi}].egress.block[${i}]`,
                value: profile.egress.block[i],
                line: findLineInYaml(tab.yaml, profile.egress.block[i]),
              });
            }
          }
        }
      }
    }

    if (matches.length > 0) {
      results.push({
        tabId: tab.id,
        tabName: tab.name,
        matches,
      });
    }
  }

  return results;
}

/**
 * Find which policies reference a specific filesystem path pattern
 * (e.g. `**\/.ssh\/**`) in forbidden_path, path_allowlist, secret_leak skip, etc.
 */
export function findPathUsage(
  tabs: PolicyTab[],
  pathPattern: string,
): CrossRefResult[] {
  if (!pathPattern.trim()) return [];

  const lowerPattern = pathPattern.toLowerCase();
  const results: CrossRefResult[] = [];

  for (const tab of tabs) {
    const matches: CrossRefMatch[] = [];

    // forbidden_path patterns & exceptions
    const fp = tab.policy.guards.forbidden_path;
    if (fp) {
      if (fp.patterns) {
        for (let i = 0; i < fp.patterns.length; i++) {
          if (fp.patterns[i].toLowerCase().includes(lowerPattern)) {
            matches.push({
              path: `guards.forbidden_path.patterns[${i}]`,
              value: fp.patterns[i],
              line: findLineInYaml(tab.yaml, fp.patterns[i]),
            });
          }
        }
      }
      if (fp.exceptions) {
        for (let i = 0; i < fp.exceptions.length; i++) {
          if (fp.exceptions[i].toLowerCase().includes(lowerPattern)) {
            matches.push({
              path: `guards.forbidden_path.exceptions[${i}]`,
              value: fp.exceptions[i],
              line: findLineInYaml(tab.yaml, fp.exceptions[i]),
            });
          }
        }
      }
    }

    // path_allowlist
    const pa = tab.policy.guards.path_allowlist;
    if (pa) {
      for (const field of ["file_access_allow", "file_write_allow", "patch_allow"] as const) {
        const arr = pa[field];
        if (arr) {
          for (let i = 0; i < arr.length; i++) {
            if (arr[i].toLowerCase().includes(lowerPattern)) {
              matches.push({
                path: `guards.path_allowlist.${field}[${i}]`,
                value: arr[i],
                line: findLineInYaml(tab.yaml, arr[i]),
              });
            }
          }
        }
      }
    }

    // secret_leak skip_paths
    const sl = tab.policy.guards.secret_leak;
    if (sl?.skip_paths) {
      for (let i = 0; i < sl.skip_paths.length; i++) {
        if (sl.skip_paths[i].toLowerCase().includes(lowerPattern)) {
          matches.push({
            path: `guards.secret_leak.skip_paths[${i}]`,
            value: sl.skip_paths[i],
            line: findLineInYaml(tab.yaml, sl.skip_paths[i]),
          });
        }
      }
    }

    if (matches.length > 0) {
      results.push({
        tabId: tab.id,
        tabName: tab.name,
        matches,
      });
    }
  }

  return results;
}
