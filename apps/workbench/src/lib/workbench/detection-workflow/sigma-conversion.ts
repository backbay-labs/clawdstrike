/**
 * Sigma-to-ClawdStrike-Policy conversion service.
 *
 * Converts Sigma detection rules into ClawdStrike policy YAML suitable for
 * fleet deployment. Used by the sigma adapter's `buildPublication` path when
 * the publish target is `native_policy` or `fleet_deploy`.
 */

import { parseSigmaYaml } from "../sigma-types";
import type { SigmaRule, SigmaLevel, SigmaLogsource } from "../sigma-types";
import type {
  WorkbenchPolicy,
  GuardConfigMap,
  ShellCommandConfig,
  ForbiddenPathConfig,
  EgressAllowlistConfig,
  PolicySettings,
} from "../types";
import { policyToYaml } from "../yaml-utils";

// ---- Public types ----

export interface SigmaConversionDiagnostic {
  severity: "error" | "warning" | "info";
  message: string;
}

export interface SigmaFieldMapping {
  sigmaField: string;
  guardField: string;
  guardId: string;
}

export interface SigmaConversionResult {
  success: boolean;
  policyYaml: string | null;
  policy: WorkbenchPolicy | null;
  converterVersion: string;
  diagnostics: SigmaConversionDiagnostic[];
  fieldMappings: SigmaFieldMapping[];
}

export interface SigmaQueryConversionResult {
  success: boolean;
  output: string | null;
  converterId: string;
  converterVersion: string;
  diagnostics: SigmaConversionDiagnostic[];
}

// ---- Constants ----

const CONVERTER_VERSION = "1.0.0";

// ---- Logsource → guard mapping ----

type GuardTarget = "shell_command" | "forbidden_path" | "egress_allowlist";

/**
 * Determines which guard(s) a Sigma logsource should map to.
 * Returns the primary guard target for the logsource category.
 */
function logsourceToGuard(
  logsource: SigmaLogsource,
  diagnostics: SigmaConversionDiagnostic[],
): GuardTarget | null {
  const category = logsource.category?.toLowerCase();
  const product = logsource.product?.toLowerCase();
  const service = logsource.service?.toLowerCase();

  // Sysmon EventID-based routing for windows/sysmon
  if (product === "windows" && service === "sysmon") {
    // Default to shell_command for sysmon; callers refine per EventID
    return "shell_command";
  }

  switch (category) {
    case "process_creation":
    case "process_access":
    case "process_tampering":
      return "shell_command";

    case "file_event":
    case "file_access":
    case "file_change":
    case "file_delete":
    case "file_rename":
      return "forbidden_path";

    case "network_connection":
    case "dns":
    case "dns_query":
    case "firewall":
    case "proxy":
      return "egress_allowlist";

    case "registry_add":
    case "registry_delete":
    case "registry_event":
    case "registry_set":
      return "forbidden_path";

    default:
      if (category) {
        diagnostics.push({
          severity: "warning",
          message: `Unknown logsource category "${category}" — best-effort mapping applied`,
        });
      } else {
        diagnostics.push({
          severity: "warning",
          message: "No logsource category specified — defaulting to shell_command guard",
        });
      }
      return "shell_command";
  }
}

// ---- Sigma level → policy settings ----

interface PolicyMode {
  extends?: string;
  settings: PolicySettings;
}

function levelToPolicyMode(level: SigmaLevel): PolicyMode {
  switch (level) {
    case "critical":
    case "high":
      return {
        extends: "strict",
        settings: { fail_fast: true, verbose_logging: true },
      };
    case "medium":
      return {
        settings: { fail_fast: false, verbose_logging: false },
      };
    case "low":
    case "informational":
      return {
        extends: "permissive",
        settings: { fail_fast: false, verbose_logging: false },
      };
  }
}

// ---- Modifier handling ----

/**
 * Parse a Sigma detection field key into its base field name and modifiers.
 * E.g. "CommandLine|contains|all" → { field: "CommandLine", modifiers: ["contains", "all"] }
 */
function parseFieldKey(key: string): { field: string; modifiers: string[] } {
  const parts = key.split("|");
  return {
    field: parts[0],
    modifiers: parts.slice(1),
  };
}

/**
 * Apply Sigma modifiers to a pattern value.
 * Returns the transformed pattern string.
 */
function applyModifiers(value: string, modifiers: string[]): string {
  // |re — use as raw regex pattern (no wildcard wrapping)
  if (modifiers.includes("re")) {
    return value;
  }

  if (modifiers.includes("contains")) {
    return `*${value}*`;
  }
  if (modifiers.includes("endswith")) {
    return `*${value}`;
  }
  if (modifiers.includes("startswith")) {
    return `${value}*`;
  }

  // No modifier — exact match (keep as-is)
  return value;
}

/**
 * Normalize a raw detection field value to an array of strings.
 */
function normalizeValues(value: unknown): string[] {
  if (value == null) return [];
  if (Array.isArray(value)) return value.map(String);
  return [String(value)];
}

// ---- Field → guard config mapping ----

interface GuardAccumulator {
  shellCommand: ShellCommandConfig;
  forbiddenPath: ForbiddenPathConfig;
  egressAllowlist: EgressAllowlistConfig;
  fieldMappings: SigmaFieldMapping[];
}

/**
 * Map a single Sigma detection field (key + values + modifiers) into the
 * appropriate guard config accumulator.
 */
function mapDetectionField(
  key: string,
  values: unknown,
  primaryGuard: GuardTarget,
  acc: GuardAccumulator,
  diagnostics: SigmaConversionDiagnostic[],
): void {
  const { field, modifiers } = parseFieldKey(key);
  const rawValues = normalizeValues(values);

  if (rawValues.length === 0) return;

  const transformed = rawValues.map((v) => applyModifiers(v, modifiers));
  const fieldLower = field.toLowerCase();

  // CommandLine → shell_command.forbidden_patterns
  if (fieldLower === "commandline" || fieldLower === "command_line") {
    acc.shellCommand.enabled = true;
    acc.shellCommand.forbidden_patterns ??= [];
    acc.shellCommand.forbidden_patterns.push(...transformed);
    for (const v of rawValues) {
      acc.fieldMappings.push({
        sigmaField: key,
        guardField: "forbidden_patterns",
        guardId: "shell_command",
      });
    }
    return;
  }

  // Image / ParentImage → shell_command.forbidden_patterns (extract basename)
  if (fieldLower === "image" || fieldLower === "parentimage" || fieldLower === "parent_image") {
    acc.shellCommand.enabled = true;
    acc.shellCommand.forbidden_patterns ??= [];
    const basenames = rawValues.map((v) => {
      // Extract basename from path
      const parts = v.replace(/\\/g, "/").split("/");
      const base = parts[parts.length - 1] || v;
      return applyModifiers(base, modifiers);
    });
    acc.shellCommand.forbidden_patterns.push(...basenames);
    for (const v of rawValues) {
      acc.fieldMappings.push({
        sigmaField: key,
        guardField: "forbidden_patterns",
        guardId: "shell_command",
      });
    }
    return;
  }

  // TargetFilename / SourceFilename → forbidden_path.patterns
  if (
    fieldLower === "targetfilename" ||
    fieldLower === "target_filename" ||
    fieldLower === "sourcefilename" ||
    fieldLower === "source_filename"
  ) {
    acc.forbiddenPath.enabled = true;
    acc.forbiddenPath.patterns ??= [];
    acc.forbiddenPath.patterns.push(...transformed);
    for (const v of rawValues) {
      acc.fieldMappings.push({
        sigmaField: key,
        guardField: "patterns",
        guardId: "forbidden_path",
      });
    }
    return;
  }

  // DestinationHostname / DestinationIp → egress_allowlist.block
  if (
    fieldLower === "destinationhostname" ||
    fieldLower === "destination_hostname" ||
    fieldLower === "destinationip" ||
    fieldLower === "destination_ip"
  ) {
    acc.egressAllowlist.enabled = true;
    acc.egressAllowlist.block ??= [];
    acc.egressAllowlist.block.push(...transformed);
    for (const v of rawValues) {
      acc.fieldMappings.push({
        sigmaField: key,
        guardField: "block",
        guardId: "egress_allowlist",
      });
    }
    return;
  }

  // QueryName (DNS) → egress_allowlist.block
  if (fieldLower === "queryname" || fieldLower === "query_name" || fieldLower === "query") {
    acc.egressAllowlist.enabled = true;
    acc.egressAllowlist.block ??= [];
    acc.egressAllowlist.block.push(...transformed);
    for (const v of rawValues) {
      acc.fieldMappings.push({
        sigmaField: key,
        guardField: "block",
        guardId: "egress_allowlist",
      });
    }
    return;
  }

  // Fallback: route to the primary guard based on logsource
  switch (primaryGuard) {
    case "shell_command":
      acc.shellCommand.enabled = true;
      acc.shellCommand.forbidden_patterns ??= [];
      acc.shellCommand.forbidden_patterns.push(...transformed);
      for (const v of rawValues) {
        acc.fieldMappings.push({
          sigmaField: key,
          guardField: "forbidden_patterns",
          guardId: "shell_command",
        });
      }
      break;
    case "forbidden_path":
      acc.forbiddenPath.enabled = true;
      acc.forbiddenPath.patterns ??= [];
      acc.forbiddenPath.patterns.push(...transformed);
      for (const v of rawValues) {
        acc.fieldMappings.push({
          sigmaField: key,
          guardField: "patterns",
          guardId: "forbidden_path",
        });
      }
      break;
    case "egress_allowlist":
      acc.egressAllowlist.enabled = true;
      acc.egressAllowlist.block ??= [];
      acc.egressAllowlist.block.push(...transformed);
      for (const v of rawValues) {
        acc.fieldMappings.push({
          sigmaField: key,
          guardField: "block",
          guardId: "egress_allowlist",
        });
      }
      break;
  }

  diagnostics.push({
    severity: "info",
    message: `Field "${field}" mapped to ${primaryGuard} guard via fallback`,
  });
}

// ---- Selection extraction ----

/**
 * Extract all selection blocks from the Sigma detection section.
 * Sigma allows multiple named selection blocks (selection, selection_1, filter, etc.)
 * referenced by the condition string.
 */
function extractSelections(
  detection: Record<string, unknown>,
): Array<{ name: string; fields: Record<string, unknown> }> {
  const selections: Array<{ name: string; fields: Record<string, unknown> }> = [];

  for (const [key, value] of Object.entries(detection)) {
    if (key === "condition") continue;
    if (value != null && typeof value === "object" && !Array.isArray(value)) {
      selections.push({ name: key, fields: value as Record<string, unknown> });
    }
  }

  return selections;
}

type QueryTarget = "spl" | "kql" | "esql" | "json_export";

function escapeDoubleQuoted(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

function selectionFieldToQueryClause(
  field: string,
  value: string,
  modifier: string | undefined,
  target: QueryTarget,
): string {
  const escaped = escapeDoubleQuoted(value);

  switch (target) {
    case "spl":
      if (modifier === "contains") return `${field}="*${escaped}*"`;
      if (modifier === "startswith") return `${field}="${escaped}*"`;
      if (modifier === "endswith") return `${field}="*${escaped}"`;
      if (modifier === "re") return `match(${field}, "${escaped}")`;
      return `${field}="${escaped}"`;
    case "kql":
      if (modifier === "contains") return `${field} contains "${escaped}"`;
      if (modifier === "startswith") return `${field} startswith "${escaped}"`;
      if (modifier === "endswith") return `${field} endswith "${escaped}"`;
      if (modifier === "re") return `${field} matches regex @"${escaped}"`;
      return `${field} =~ "${escaped}"`;
    case "esql":
      if (modifier === "contains") return `${field} like "*${escaped}*"`;
      if (modifier === "startswith") return `${field} like "${escaped}*"`;
      if (modifier === "endswith") return `${field} like "*${escaped}"`;
      if (modifier === "re") return `${field} rlike "${escaped}"`;
      return `${field} == "${escaped}"`;
    default:
      return `${field}="${escaped}"`;
  }
}

function buildSelectionQueries(
  detection: Record<string, unknown>,
  target: QueryTarget,
): string[] {
  const selections = extractSelections(detection);
  return selections.flatMap((selection) => {
    const clauses = Object.entries(selection.fields).map(([key, rawValue]) => {
      const { field, modifiers } = parseFieldKey(key);
      const values = normalizeValues(rawValue);
      const operator = modifiers.find((modifier) =>
        ["contains", "startswith", "endswith", "re"].includes(modifier),
      );

      const disjunction = values.map((value) =>
        selectionFieldToQueryClause(field, value, operator, target),
      );

      if (disjunction.length === 1) {
        return disjunction[0];
      }

      const joiner = target === "spl" ? " OR " : " or ";
      return `(${disjunction.join(joiner)})`;
    });

    if (clauses.length === 0) {
      return [];
    }

    const joiner = target === "spl" ? " AND " : " and ";
    return [`(${clauses.join(joiner)})`];
  });
}

export function convertSigmaToQuery(
  sigmaYaml: string,
  target: QueryTarget,
): SigmaQueryConversionResult {
  const { rule, errors } = parseSigmaYaml(sigmaYaml);
  const diagnostics = errors.map((message) => ({ severity: "error" as const, message }));

  if (!rule) {
    return {
      success: false,
      output: null,
      converterId: `sigma-to-${target}`,
      converterVersion: CONVERTER_VERSION,
      diagnostics,
    };
  }

  if (target === "json_export") {
    // Produce a structured JSON export including rule metadata and detection
    // logic, not just the raw Sigma YAML parsed to JSON.
    const exportObj = {
      _meta: {
        converter: "sigma-to-json",
        converterVersion: CONVERTER_VERSION,
        exportedAt: new Date().toISOString(),
      },
      rule: {
        id: rule.id ?? null,
        title: rule.title,
        status: rule.status,
        level: rule.level,
        description: rule.description ?? null,
        author: rule.author ?? null,
        tags: rule.tags ?? [],
        logsource: rule.logsource,
        detection: rule.detection,
        falsepositives: rule.falsepositives ?? [],
      },
    };
    return {
      success: true,
      output: JSON.stringify(exportObj, null, 2),
      converterId: "sigma-to-json",
      converterVersion: CONVERTER_VERSION,
      diagnostics,
    };
  }

  const queryBlocks = buildSelectionQueries(rule.detection as Record<string, unknown>, target);
  if (queryBlocks.length === 0) {
    return {
      success: false,
      output: null,
      converterId: `sigma-to-${target}`,
      converterVersion: CONVERTER_VERSION,
      diagnostics: [
        ...diagnostics,
        {
          severity: "error",
          message: "Sigma rule has no convertible selection blocks",
        },
      ],
    };
  }

  const whereJoiner = target === "spl" ? " OR " : " or ";
  const whereClause = queryBlocks.join(whereJoiner);
  const heading = `// ${rule.title}`;
  const caveat =
    "// NOTE: Auto-generated from Sigma rule. Review field names and " +
    "syntax for your target platform before production use.";
  const output =
    target === "spl"
      ? `${heading}\n${caveat}\nsearch ${whereClause}`
      : target === "kql"
        ? `${heading}\n${caveat}\n${whereClause}`
        : `${heading}\n${caveat}\nfrom logs | where ${whereClause}`;

  return {
    success: true,
    output,
    converterId: `sigma-to-${target}`,
    converterVersion: CONVERTER_VERSION,
    diagnostics: [
      ...diagnostics,
      {
        severity: "info",
        message: `Generated ${target.toUpperCase()} query from Sigma selection blocks — field names may need adjustment for your SIEM`,
      },
    ],
  };
}

// ---- Main conversion function ----

export function convertSigmaToPolicy(sigmaYaml: string): SigmaConversionResult {
  const diagnostics: SigmaConversionDiagnostic[] = [];
  const fieldMappings: SigmaFieldMapping[] = [];

  // Step 1: Parse Sigma YAML
  const { rule, errors } = parseSigmaYaml(sigmaYaml);

  if (errors.length > 0) {
    for (const err of errors) {
      diagnostics.push({ severity: "error", message: `Sigma parse: ${err}` });
    }
  }

  if (!rule) {
    return {
      success: false,
      policyYaml: null,
      policy: null,
      converterVersion: CONVERTER_VERSION,
      diagnostics,
      fieldMappings,
    };
  }

  // Step 2: Check for missing detection section
  if (!rule.detection || typeof rule.detection !== "object") {
    diagnostics.push({
      severity: "error",
      message: "Sigma rule has no detection section — cannot generate guard configs",
    });
    return {
      success: false,
      policyYaml: null,
      policy: null,
      converterVersion: CONVERTER_VERSION,
      diagnostics,
      fieldMappings,
    };
  }

  // Step 3: Determine primary guard from logsource
  const primaryGuard = logsourceToGuard(rule.logsource, diagnostics) ?? "shell_command";

  // Step 4: Initialize guard config accumulators
  const acc: GuardAccumulator = {
    shellCommand: {},
    forbiddenPath: {},
    egressAllowlist: {},
    fieldMappings,
  };

  // Step 5: Extract and process all selection blocks
  const selections = extractSelections(rule.detection as Record<string, unknown>);

  if (selections.length === 0) {
    diagnostics.push({
      severity: "warning",
      message: "No selection blocks found in detection section",
    });
  }

  for (const selection of selections) {
    for (const [key, value] of Object.entries(selection.fields)) {
      mapDetectionField(key, value, primaryGuard, acc, diagnostics);
    }
  }

  // Step 6: Build guards config
  const guards: GuardConfigMap = {};

  if (acc.shellCommand.enabled && acc.shellCommand.forbidden_patterns?.length) {
    // Deduplicate patterns
    acc.shellCommand.forbidden_patterns = [...new Set(acc.shellCommand.forbidden_patterns)];
    guards.shell_command = acc.shellCommand;
  }

  if (acc.forbiddenPath.enabled && acc.forbiddenPath.patterns?.length) {
    acc.forbiddenPath.patterns = [...new Set(acc.forbiddenPath.patterns)];
    guards.forbidden_path = acc.forbiddenPath;
  }

  if (acc.egressAllowlist.enabled && acc.egressAllowlist.block?.length) {
    acc.egressAllowlist.block = [...new Set(acc.egressAllowlist.block)];
    acc.egressAllowlist.default_action = "block";
    guards.egress_allowlist = acc.egressAllowlist;
  }

  // If no guards were populated, add a warning and create a minimal policy
  const hasGuards = Object.keys(guards).length > 0;
  if (!hasGuards) {
    diagnostics.push({
      severity: "warning",
      message: "No guard configs could be derived from this Sigma rule — producing minimal policy",
    });
  }

  // Step 7: Map level to policy mode
  const mode = levelToPolicyMode(rule.level);

  // Step 8: Build description
  const descriptionParts: string[] = [];
  if (rule.description) {
    descriptionParts.push(rule.description);
  }
  descriptionParts.push("Converted from Sigma rule");
  if (rule.id) {
    descriptionParts.push(`(${rule.id})`);
  }
  const description = descriptionParts.join(" ");

  // Step 9: Construct WorkbenchPolicy
  const policy: WorkbenchPolicy = {
    version: "1.2.0",
    name: rule.title || "Converted Sigma Rule",
    description,
    extends: mode.extends,
    guards,
    settings: mode.settings,
  };

  // Step 10: Generate YAML
  const policyYaml = policyToYaml(policy);

  diagnostics.push({
    severity: "info",
    message: `Converted Sigma rule "${rule.title}" to policy with ${Object.keys(guards).length} guard(s)`,
  });

  return {
    success: true,
    policyYaml,
    policy,
    converterVersion: CONVERTER_VERSION,
    diagnostics,
    fieldMappings: acc.fieldMappings,
  };
}
