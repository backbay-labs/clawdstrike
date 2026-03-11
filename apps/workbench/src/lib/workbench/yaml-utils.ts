import YAML from "yaml";
import type { WorkbenchPolicy, ValidationResult, ValidationIssue, GuardConfigMap } from "./types";

export type ExportFormat = "yaml" | "json" | "toml";

/** Build a clean document object from a WorkbenchPolicy, omitting empty fields. */
function buildCleanDoc(policy: WorkbenchPolicy): Record<string, unknown> {
  const doc: Record<string, unknown> = {
    version: policy.version,
    name: policy.name,
    description: policy.description,
  };

  if (policy.extends) {
    doc.extends = policy.extends;
  }

  if (policy.merge_strategy && policy.merge_strategy !== "deep_merge") {
    doc.merge_strategy = policy.merge_strategy;
  }

  // Build guards object, omitting disabled/empty guards
  const guards: Record<string, unknown> = {};
  for (const [key, config] of Object.entries(policy.guards)) {
    if (config && typeof config === "object") {
      const cleaned = cleanObject(config as Record<string, unknown>);
      if (Object.keys(cleaned).length > 0) {
        guards[key] = cleaned;
      }
    }
  }
  if (Object.keys(guards).length > 0) {
    doc.guards = guards;
  }

  // Custom guards (plugin-shaped)
  if (policy.custom_guards && policy.custom_guards.length > 0) {
    doc.custom_guards = policy.custom_guards;
  }

  // Settings
  const settings = cleanObject(policy.settings as unknown as Record<string, unknown>);
  if (Object.keys(settings).length > 0) {
    doc.settings = settings;
  }

  // Posture
  if (policy.posture) {
    doc.posture = policy.posture;
  }

  // Origins (v1.4.0)
  if (policy.origins) {
    const origins: Record<string, unknown> = {};
    if (policy.origins.default_behavior) {
      origins.default_behavior = policy.origins.default_behavior;
    }
    if (policy.origins.profiles && policy.origins.profiles.length > 0) {
      origins.profiles = policy.origins.profiles.map((profile) => {
        const p: Record<string, unknown> = {
          id: profile.id,
          match_rules: cleanObject(profile.match_rules as unknown as Record<string, unknown>),
        };
        if (profile.posture) p.posture = profile.posture;
        if (profile.mcp) p.mcp = cleanObject(profile.mcp as unknown as Record<string, unknown>);
        if (profile.egress) p.egress = cleanObject(profile.egress as unknown as Record<string, unknown>);
        if (profile.data) p.data = cleanObject(profile.data as unknown as Record<string, unknown>);
        if (profile.budgets) p.budgets = cleanObject(profile.budgets as unknown as Record<string, unknown>);
        if (profile.bridge_policy) p.bridge_policy = cleanObject(profile.bridge_policy as unknown as Record<string, unknown>);
        if (profile.explanation) p.explanation = profile.explanation;
        return p;
      });
    }
    if (Object.keys(origins).length > 0) {
      doc.origins = origins;
    }
  }

  return doc;
}

export function policyToYaml(policy: WorkbenchPolicy): string {
  const doc = buildCleanDoc(policy);

  // NOTE: QUOTE_DOUBLE is intentionally kept over PLAIN to avoid ambiguity with
  // values that YAML would otherwise interpret as non-strings (e.g., "true", "null",
  // "1.0", bare timestamps). PLAIN would be more idiomatic but riskier for round-trips.
  return YAML.stringify(doc, {
    indent: 2,
    lineWidth: 120,
    defaultStringType: "QUOTE_DOUBLE",
    defaultKeyType: "PLAIN",
  });
}

export function policyToJson(policy: WorkbenchPolicy): string {
  const doc = buildCleanDoc(policy);
  return JSON.stringify(doc, null, 2);
}

export function policyToToml(policy: WorkbenchPolicy): string {
  const doc = buildCleanDoc(policy);
  return tomlSerialize(doc);
}

export function policyToFormat(policy: WorkbenchPolicy, format: ExportFormat): string {
  switch (format) {
    case "yaml":
      return policyToYaml(policy);
    case "json":
      return policyToJson(policy);
    case "toml":
      return policyToToml(policy);
  }
}

export function formatExtension(format: ExportFormat): string {
  switch (format) {
    case "yaml":
      return "yaml";
    case "json":
      return "json";
    case "toml":
      return "toml";
  }
}

export function formatMimeType(format: ExportFormat): string {
  switch (format) {
    case "yaml":
      return "text/yaml";
    case "json":
      return "application/json";
    case "toml":
      return "application/toml";
  }
}

function tomlEscapeString(s: string): string {
  return '"' + s
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\0/g, "\\u0000")
    .replace(/\x08/g, "\\b")
    .replace(/\f/g, "\\f")
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r")
    .replace(/\t/g, "\\t") + '"';
}

/** Quote a TOML key if it contains characters outside [a-zA-Z0-9_-]. */
function tomlQuoteKey(key: string): string {
  if (/^[a-zA-Z0-9_-]+$/.test(key)) return key;
  return '"' + key
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"') + '"';
}

function tomlValue(v: unknown): string {
  if (typeof v === "string") return tomlEscapeString(v);
  if (typeof v === "number") return Number.isInteger(v) ? String(v) : String(v);
  if (typeof v === "boolean") return v ? "true" : "false";
  if (Array.isArray(v)) {
    // Arrays of primitives
    const items = v.map((item) => {
      if (typeof item === "object" && item !== null && !Array.isArray(item)) {
        // Inline table for objects inside arrays (e.g., secret_leak patterns)
        return tomlInlineTable(item as Record<string, unknown>);
      }
      return tomlValue(item);
    });
    return "[" + items.join(", ") + "]";
  }
  return String(v);
}

function tomlInlineTable(obj: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null) continue;
    parts.push(`${tomlQuoteKey(k)} = ${tomlValue(v)}`);
  }
  return "{ " + parts.join(", ") + " }";
}

function isTable(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function shouldBeSection(v: unknown): boolean {
  return isTable(v);
}

/**
 * Best-effort TOML serializer. Handles up to 3 levels of nesting using TOML
 * sections and sub-sections. Arrays of objects use [[section.key]] array-of-tables
 * syntax where possible. For deeply nested values beyond 3 levels, falls back to
 * JSON representation. A proper TOML library (e.g., @iarna/toml) would be more robust.
 */
function tomlSerialize(doc: Record<string, unknown>): string {
  const lines: string[] = [];

  // First pass: emit top-level simple key = value pairs
  for (const [key, value] of Object.entries(doc)) {
    if (value === undefined || value === null) continue;
    if (isTable(value) && shouldBeSection(value)) continue; // handled in second pass
    lines.push(`${tomlQuoteKey(key)} = ${tomlValue(value)}`);
  }

  // Second pass: emit [section] tables
  for (const [key, value] of Object.entries(doc)) {
    if (value === undefined || value === null) continue;
    if (!isTable(value) || !shouldBeSection(value)) continue;

    lines.push("");
    lines.push(`[${tomlQuoteKey(key)}]`);
    const obj = value as Record<string, unknown>;

    // Simple keys first (non-table, non-array-of-tables)
    for (const [k, v] of Object.entries(obj)) {
      if (v === undefined || v === null) continue;
      if (isTable(v)) continue; // handled below as sub-section
      // Arrays of objects are handled below as [[array-of-tables]]
      if (Array.isArray(v) && v.length > 0 && v.every((item) => isTable(item))) continue;
      lines.push(`${tomlQuoteKey(k)} = ${tomlValue(v)}`);
    }

    // Arrays of objects as [[section.key]] (array-of-tables syntax)
    for (const [k, v] of Object.entries(obj)) {
      if (v === undefined || v === null) continue;
      if (!Array.isArray(v) || v.length === 0 || !v.every((item) => isTable(item))) continue;

      for (const item of v) {
        lines.push("");
        lines.push(`[[${tomlQuoteKey(key)}.${tomlQuoteKey(k)}]]`);
        const tableItem = item as Record<string, unknown>;
        for (const [ik, iv] of Object.entries(tableItem)) {
          if (iv === undefined || iv === null) continue;
          if (isTable(iv)) {
            // Depth 4+: fall back to JSON for deeply nested values
            lines.push(`${tomlQuoteKey(ik)} = ${JSON.stringify(iv)}`);
          } else {
            lines.push(`${tomlQuoteKey(ik)} = ${tomlValue(iv)}`);
          }
        }
      }
    }

    // Sub-tables as [section.subsection]
    for (const [k, v] of Object.entries(obj)) {
      if (v === undefined || v === null) continue;
      if (!isTable(v)) continue;

      lines.push("");
      lines.push(`[${tomlQuoteKey(key)}.${tomlQuoteKey(k)}]`);
      const subObj = v as Record<string, unknown>;

      for (const [sk, sv] of Object.entries(subObj)) {
        if (sv === undefined || sv === null) continue;
        if (isTable(sv)) {
          // Third level: inline table for simple objects, JSON fallback for deep nesting
          const nested = sv as Record<string, unknown>;
          const hasDeepNesting = Object.values(nested).some(
            (nv) => isTable(nv) || (Array.isArray(nv) && nv.some((item) => isTable(item)))
          );
          if (hasDeepNesting) {
            // Depth 4+: fall back to JSON to avoid lossy serialization
            lines.push(`${tomlQuoteKey(sk)} = ${JSON.stringify(sv)}`);
          } else {
            lines.push(`${tomlQuoteKey(sk)} = ${tomlInlineTable(nested)}`);
          }
        } else {
          lines.push(`${tomlQuoteKey(sk)} = ${tomlValue(sv)}`);
        }
      }
    }
  }

  return lines.join("\n") + "\n";
}

/** Parse YAML string to WorkbenchPolicy. Returns [policy, errors]. */
export function yamlToPolicy(
  yaml: string
): [WorkbenchPolicy | null, string[]] {
  try {
    const doc = YAML.parse(yaml, { maxAliasCount: 0, uniqueKeys: true });
    if (!doc || typeof doc !== "object") {
      return [null, ["YAML must be a mapping/object"]];
    }
    if (Array.isArray(doc)) {
      return [null, ["YAML must be a mapping/object, not an array"]];
    }

    const errors: string[] = [];

    // Runtime validation: ensure guard configs are objects, not primitives
    if (doc.guards && typeof doc.guards === "object") {
      for (const [guardId, config] of Object.entries(doc.guards)) {
        if (config !== null && typeof config !== "object") {
          errors.push(`Guard "${guardId}" config must be an object, got ${typeof config}`);
        }
        if (config && typeof config === "object") {
          const cfg = config as Record<string, unknown>;
          // Validate array fields are actually arrays
          for (const arrayField of ["patterns", "allow", "block", "forbidden_patterns", "forbidden_commands", "secret_patterns"]) {
            if (arrayField in cfg && cfg[arrayField] !== undefined && !Array.isArray(cfg[arrayField])) {
              errors.push(`Guard "${guardId}.${arrayField}" must be an array, got ${typeof cfg[arrayField]}`);
            }
          }
          // Validate string fields are actually strings
          for (const stringField of ["default_action", "mode"]) {
            if (stringField in cfg && cfg[stringField] !== undefined && typeof cfg[stringField] !== "string") {
              errors.push(`Guard "${guardId}.${stringField}" must be a string, got ${typeof cfg[stringField]}`);
            }
          }
        }
      }
    }

    const policy: WorkbenchPolicy = {
      version: doc.version || "1.2.0",
      name: doc.name || "",
      description: doc.description || "",
      extends: doc.extends || undefined,
      merge_strategy: doc.merge_strategy || undefined,
      guards: (doc.guards || {}) as GuardConfigMap,
      custom_guards: Array.isArray(doc.custom_guards) ? doc.custom_guards : undefined,
      settings: doc.settings || {},
      posture: doc.posture || undefined,
      origins: doc.origins || undefined,
    };

    // Return policy even with validation errors (for display purposes)
    return [policy, errors];
  } catch (e) {
    const msg = e instanceof Error ? e.message : "Invalid YAML";
    return [null, [msg]];
  }
}

export function validatePolicy(policy: WorkbenchPolicy): ValidationResult {
  const errors: ValidationIssue[] = [];
  const warnings: ValidationIssue[] = [];

  // Version check
  const validVersions = ["1.1.0", "1.2.0", "1.3.0", "1.4.0"];
  if (!validVersions.includes(policy.version)) {
    errors.push({
      path: "version",
      message: `Unsupported schema version "${policy.version}". Supported: ${validVersions.join(", ")}`,
      severity: "error",
    });
  }

  // Name check
  if (!policy.name || policy.name.trim() === "") {
    warnings.push({
      path: "name",
      message: "Policy name is empty",
      severity: "warning",
    });
  }

  // Circular / invalid extends check
  if (policy.extends) {
    const BUILTIN_RULESETS = new Set([
      "permissive",
      "default",
      "strict",
      "ai-agent",
      "cicd",
      "ai-agent-posture",
      "remote-desktop",
      "remote-desktop-permissive",
      "remote-desktop-strict",
      "spider-sense",
    ]);

    const extendsValue = policy.extends;
    // Self-reference check
    if (policy.name && extendsValue === policy.name) {
      warnings.push({
        path: "extends",
        message: `Policy extends itself ("${extendsValue}") — this will cause circular inheritance`,
        severity: "warning",
      });
    }
    // If extends is not a built-in, URL, or file path, warn about potential circular reference
    const isBuiltin = BUILTIN_RULESETS.has(extendsValue);
    const isUrl = /^https?:\/\//.test(extendsValue);
    const isFilePath = extendsValue.includes("/") || extendsValue.includes("\\") || extendsValue.endsWith(".yaml") || extendsValue.endsWith(".yml");
    const isGitRef = extendsValue.includes("@") || extendsValue.startsWith("git:");
    if (!isBuiltin && !isUrl && !isFilePath && !isGitRef && extendsValue !== policy.name) {
      warnings.push({
        path: "extends",
        message: `"${extendsValue}" is not a recognized built-in ruleset — verify it exists to avoid circular inheritance`,
        severity: "warning",
      });
    }
  }

  // Validate guard configs
  const guards = policy.guards;
  if (guards.forbidden_path?.patterns) {
    for (let i = 0; i < guards.forbidden_path.patterns.length; i++) {
      const p = guards.forbidden_path.patterns[i];
      if (!p || p.trim() === "") {
        errors.push({
          path: `guards.forbidden_path.patterns[${i}]`,
          message: "Empty pattern",
          severity: "error",
        });
      }
    }
  }

  if (guards.secret_leak?.patterns) {
    for (let i = 0; i < guards.secret_leak.patterns.length; i++) {
      const sp = guards.secret_leak.patterns[i];
      if (!sp.name || !sp.pattern) {
        errors.push({
          path: `guards.secret_leak.patterns[${i}]`,
          message: "Secret pattern must have name and pattern",
          severity: "error",
        });
      } else {
        try {
          new RegExp(sp.pattern);
        } catch {
          errors.push({
            path: `guards.secret_leak.patterns[${i}].pattern`,
            message: `Invalid regex: ${sp.pattern}`,
            severity: "error",
          });
        }
      }
    }
  }

  if (guards.patch_integrity) {
    const pi = guards.patch_integrity;
    if (pi.max_additions !== undefined && pi.max_additions < 0) {
      errors.push({ path: "guards.patch_integrity.max_additions", message: "Must be non-negative", severity: "error" });
    }
    if (pi.max_deletions !== undefined && pi.max_deletions < 0) {
      errors.push({ path: "guards.patch_integrity.max_deletions", message: "Must be non-negative", severity: "error" });
    }
    if (pi.forbidden_patterns) {
      for (let i = 0; i < pi.forbidden_patterns.length; i++) {
        try {
          new RegExp(pi.forbidden_patterns[i]);
        } catch {
          errors.push({
            path: `guards.patch_integrity.forbidden_patterns[${i}]`,
            message: `Invalid regex`,
            severity: "error",
          });
        }
      }
    }
  }

  if (guards.jailbreak?.detector) {
    const d = guards.jailbreak.detector;
    if (d.block_threshold !== undefined && d.warn_threshold !== undefined) {
      if (d.warn_threshold >= d.block_threshold) {
        warnings.push({
          path: "guards.jailbreak.detector",
          message: "warn_threshold should be less than block_threshold",
          severity: "warning",
        });
      }
    }
  }

  if (guards.egress_allowlist) {
    const eg = guards.egress_allowlist;
    if (eg.allow && eg.allow.length === 0 && eg.default_action === "block") {
      warnings.push({
        path: "guards.egress_allowlist",
        message: "All network egress will be blocked (empty allow list with default_action: block)",
        severity: "warning",
      });
    }
  }

  // Settings
  if (policy.settings.session_timeout_secs !== undefined) {
    if (policy.settings.session_timeout_secs < 60) {
      warnings.push({
        path: "settings.session_timeout_secs",
        message: "Session timeout is very short (< 60s)",
        severity: "warning",
      });
    }
  }

  // Posture requires v1.2.0+
  if (policy.posture && policy.version === "1.1.0") {
    errors.push({
      path: "posture",
      message: "Posture requires schema version 1.2.0 or later",
      severity: "error",
    });
  }

  // Origins requires v1.4.0+
  const originsSupportedVersions = ["1.4.0"];
  if (policy.origins && !originsSupportedVersions.includes(policy.version)) {
    errors.push({
      path: "origins",
      message: "Origin-aware enforcement requires schema version 1.4.0 or later",
      severity: "error",
    });
  }

  if (policy.origins) {
    const origins = policy.origins;
    if (origins.profiles) {
      const seenIds = new Set<string>();
      for (let i = 0; i < origins.profiles.length; i++) {
        const profile = origins.profiles[i];
        if (!profile.id || profile.id.trim() === "") {
          errors.push({
            path: `origins.profiles[${i}].id`,
            message: "Profile ID is required",
            severity: "error",
          });
        } else if (seenIds.has(profile.id)) {
          errors.push({
            path: `origins.profiles[${i}].id`,
            message: `Duplicate profile ID "${profile.id}"`,
            severity: "error",
          });
        } else {
          seenIds.add(profile.id);
        }
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

function cleanObject(obj: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (value === undefined || value === null) continue;
    // Preserve empty arrays for guard config fields where [] has semantic meaning
    // (e.g., allow: [] means "nothing allowed", distinct from absent field)
    if (Array.isArray(value) && value.length === 0) {
      const PRESERVE_EMPTY = [
        "allow", "block", "patterns", "forbidden_patterns", "forbidden_commands", "secret_patterns",
        "require_confirmation", "skip_paths", "exceptions", "file_access_allow", "file_write_allow",
        "patch_allow", "allowed_actions", "allowed_input_types", "forbidden_suffixes",
      ];
      if (!PRESERVE_EMPTY.includes(key)) continue;
    }
    result[key] = value;
  }
  return result;
}
