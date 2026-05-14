import type {
  TranslationProvider,
  TranslationResult,
  TranslationDiagnostic,
  FieldMapping,
} from "./shared-types";
import { registerTranslationProvider } from "./translations";
import { parseSigmaYaml } from "../sigma-types";
import type { SigmaLogsource, SigmaLevel } from "../sigma-types";
import { translateField, getAllFieldMappings } from "./field-mappings";
import { parseYaralRule } from "./yaral-adapter";
import type { YaralEventPredicate, ParsedYaralRule } from "./yaral-adapter";


function sigmaLevelToChronicle(level: SigmaLevel | undefined): string {
  switch (level) {
    case "critical":
      return "CRITICAL";
    case "high":
      return "HIGH";
    case "medium":
      return "MEDIUM";
    case "low":
      return "LOW";
    case "informational":
      return "INFORMATIONAL";
    default:
      return "MEDIUM";
  }
}


function chronicleSeverityToSigma(severity: string | undefined): string {
  switch (severity?.toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    case "INFORMATIONAL":
      return "informational";
    default:
      return "medium";
  }
}


function logsourceToEventType(logsource: SigmaLogsource | undefined): string {
  if (!logsource) return "GENERIC_EVENT";

  const category = logsource.category?.toLowerCase();
  switch (category) {
    case "process_creation":
      return "PROCESS_LAUNCH";
    case "file_event":
    case "file_access":
      return "FILE_CREATION";
    case "network_connection":
      return "NETWORK_CONNECTION";
    case "dns":
    case "dns_query":
      return "NETWORK_DNS";
    case "registry_add":
    case "registry_delete":
    case "registry_event":
    case "registry_set":
      return "REGISTRY_MODIFICATION";
    case "authentication":
      return "USER_LOGIN";
    default:
      return "GENERIC_EVENT";
  }
}


function eventTypeToLogsource(eventType: string): string {
  switch (eventType.toUpperCase()) {
    case "PROCESS_LAUNCH":
      return "process_creation";
    case "FILE_CREATION":
      return "file_event";
    case "NETWORK_CONNECTION":
      return "network_connection";
    case "NETWORK_DNS":
      return "dns_query";
    case "REGISTRY_MODIFICATION":
      return "registry_set";
    case "USER_LOGIN":
      return "authentication";
    default:
      return "process_creation";
  }
}


function normalizeRuleName(title: string): string {
  return title
    .toLowerCase()
    .replace(/[\s-]+/g, "_")
    .replace(/[^a-z0-9_]/g, "");
}


function extractTechniques(tags: string[] | undefined): string[] {
  if (!tags) return [];
  return tags
    .filter((t) => t.startsWith("attack.t") || t.startsWith("attack.T"))
    .map((t) => t.replace(/^attack\./, "").toUpperCase());
}


interface ParsedSigmaField {
  baseField: string;
  modifiers: string[];
}

function parseSigmaFieldKey(key: string): ParsedSigmaField {
  const parts = key.split("|");
  return {
    baseField: parts[0],
    modifiers: parts.slice(1),
  };
}

function normalizeDetectionValues(value: unknown): string[] {
  if (value == null) return [];
  if (Array.isArray(value)) return value.map(String);
  return [String(value)];
}


function sigmaToYaral(source: string): TranslationResult {
  const diagnostics: TranslationDiagnostic[] = [];
  const fieldMappings: FieldMapping[] = [];

  const { rule, errors } = parseSigmaYaml(source);

  if (!rule) {
    return {
      success: false,
      output: null,
      diagnostics: errors.map((e) => ({ severity: "error" as const, message: e })),
      fieldMappings: [],
      untranslatableFeatures: [],
    };
  }

  // Report parse warnings (non-fatal errors)
  for (const err of errors) {
    diagnostics.push({ severity: "warning", message: err });
  }

  const today = new Date().toISOString().slice(0, 10);
  const ruleName = normalizeRuleName(rule.title || "untitled_rule");
  const severity = sigmaLevelToChronicle(rule.level);
  const eventType = logsourceToEventType(rule.logsource);

  // Build meta section
  const metaLines: string[] = [
    `    author = "${rule.author || "Detection Lab"}"`,
    `    description = "${(rule.description || "").replace(/"/g, '\\"')}"`,
    `    severity = "${severity}"`,
    `    created = "${rule.date || today}"`,
  ];

  const techniques = extractTechniques(rule.tags);
  if (techniques.length > 0) {
    metaLines.push(`    mitre_attack = "${techniques.join(", ")}"`);
  }

  if (rule.id) {
    metaLines.push(`    sigma_id = "${rule.id}"`);
  }

  // Build events section from detection blocks
  const eventLines: string[] = [
    `    $e.metadata.event_type = "${eventType}"`,
  ];

  const detection = rule.detection;
  if (detection) {
    // Iterate over selection blocks (everything except "condition")
    for (const [blockName, blockValue] of Object.entries(detection)) {
      if (blockName === "condition") continue;

      if (blockValue != null && typeof blockValue === "object" && !Array.isArray(blockValue)) {
        const selectionFields = blockValue as Record<string, unknown>;

        for (const [fieldKey, fieldValue] of Object.entries(selectionFields)) {
          const { baseField, modifiers } = parseSigmaFieldKey(fieldKey);

          // Translate field to UDM path
          const udmPath = translateField(baseField, "udmPath");
          const targetField = udmPath || baseField;
          const confidence: FieldMapping["confidence"] = udmPath ? "exact" : "unmapped";

          fieldMappings.push({
            sigmaField: baseField,
            targetField,
            confidence,
          });

          if (!udmPath) {
            diagnostics.push({
              severity: "warning",
              message: `No UDM mapping for Sigma field "${baseField}" -- using raw field name`,
            });
          }

          // Convert values to YARA-L predicates
          const values = normalizeDetectionValues(fieldValue);
          for (const val of values) {
            const predicate = buildYaralPredicate(targetField, val, modifiers);
            eventLines.push(`    ${predicate}`);
          }
        }
      }
    }
  }

  // Build the YARA-L rule
  const output = [
    `rule ${ruleName} {`,
    `  meta:`,
    ...metaLines,
    ``,
    `  events:`,
    ...eventLines,
    ``,
    `  condition:`,
    `    $e`,
    `}`,
    ``,
  ].join("\n");

  return {
    success: true,
    output,
    diagnostics,
    fieldMappings,
    untranslatableFeatures: [],
  };
}

/**
 * Build a YARA-L event predicate string from a field path, value, and Sigma modifiers.
 */
function buildYaralPredicate(
  fieldPath: string,
  value: string,
  modifiers: string[],
): string {
  const escapedValue = value.replace(/\//g, "\\/");

  if (modifiers.includes("re")) {
    return `$e.${fieldPath} = /${escapedValue}/`;
  }
  if (modifiers.includes("contains")) {
    return `$e.${fieldPath} = /${escapedValue}/ nocase`;
  }
  if (modifiers.includes("startswith")) {
    return `$e.${fieldPath} = /^${escapedValue}/ nocase`;
  }
  if (modifiers.includes("endswith")) {
    return `$e.${fieldPath} = /${escapedValue}$/ nocase`;
  }

  // No modifier -- exact string match
  return `$e.${fieldPath} = "${value.replace(/"/g, '\\"')}"`;
}


function yaralToSigma(source: string): TranslationResult {
  const diagnostics: TranslationDiagnostic[] = [];
  const fieldMappings: FieldMapping[] = [];
  const untranslatableFeatures: string[] = [];

  const parsed = parseYaralRule(source);

  if (!parsed) {
    return {
      success: false,
      output: null,
      diagnostics: [{ severity: "error", message: "Failed to parse YARA-L rule" }],
      fieldMappings: [],
      untranslatableFeatures: [],
    };
  }

  // Detect unique event variable names
  const variableNames = new Set(parsed.events.map((e) => e.variable));

  // Multi-event detection
  const isMultiEvent = variableNames.size > 1;
  if (isMultiEvent) {
    const varList = [...variableNames].join(", ");
    untranslatableFeatures.push(
      `Multi-event correlation with ${variableNames.size} event variables (${varList}) -- only ${[...variableNames][0]} predicates translated`,
    );
    untranslatableFeatures.push(
      `Condition expression '${parsed.condition}' not preserved`,
    );
    if (parsed.hasMatchSection) {
      untranslatableFeatures.push(
        "Match section (grouping/aggregation) not preserved",
      );
    }
    if (parsed.hasOutcomeSection) {
      untranslatableFeatures.push(
        "Outcome section (risk scoring) not preserved",
      );
    }
  }

  // Select predicates from the first event variable only for multi-event rules
  const selectedVariable = [...variableNames][0] ?? "$e";
  const selectedPredicates = isMultiEvent
    ? parsed.events.filter((e) => e.variable === selectedVariable)
    : parsed.events;

  // Build reverse UDM -> Sigma mapping
  const reverseUdmMap = buildReverseUdmMap();

  // Determine event type from predicates
  let eventType = "GENERIC_EVENT";
  const nonEventTypePredicates: YaralEventPredicate[] = [];

  for (const pred of selectedPredicates) {
    if (pred.fieldPath === "metadata.event_type" && !pred.isRegex) {
      eventType = pred.value;
    } else {
      nonEventTypePredicates.push(pred);
    }
  }

  // Map event type to Sigma logsource
  const logsourceCategory = eventTypeToLogsource(eventType);

  // Build Sigma detection selection
  const selection: Record<string, unknown> = {};

  for (const pred of nonEventTypePredicates) {
    // Reverse-map UDM path to Sigma field
    const sigmaField = reverseUdmMap.get(pred.fieldPath) ?? pred.fieldPath;
    const isReverseMapped = reverseUdmMap.has(pred.fieldPath);

    if (!isReverseMapped) {
      diagnostics.push({
        severity: "warning",
        message: `No reverse mapping for UDM path "${pred.fieldPath}" -- using raw path as Sigma field`,
      });
    }

    fieldMappings.push({
      sigmaField,
      targetField: pred.fieldPath,
      confidence: isReverseMapped ? "exact" : "unmapped",
    });

    // Determine Sigma modifier from YARA-L predicate pattern
    const { modifier, cleanValue } = yaralPredicateToSigmaModifier(pred);
    const selectionKey = modifier ? `${sigmaField}${modifier}` : sigmaField;

    // Add to selection (merge multiple values for same key)
    const existing = selection[selectionKey];
    if (existing !== undefined) {
      if (Array.isArray(existing)) {
        (existing as string[]).push(cleanValue);
      } else {
        selection[selectionKey] = [existing as string, cleanValue];
      }
    } else {
      selection[selectionKey] = cleanValue;
    }
  }

  // Build Sigma YAML
  const today = new Date().toISOString().slice(0, 10).replace(/-/g, "/");

  // Extract MITRE tags from meta
  const tags: string[] = [];
  if (parsed.meta.mitre_attack) {
    const techniques = parsed.meta.mitre_attack.split(",").map((t) => t.trim());
    for (const tech of techniques) {
      tags.push(`attack.${tech.toLowerCase()}`);
    }
  }

  const sigmaRule: Record<string, unknown> = {
    title: normalizeRuleNameToTitle(parsed.ruleName),
    id: parsed.meta.sigma_id || crypto.randomUUID(),
    status: "test",
    description: `Translated from YARA-L rule: ${parsed.ruleName}`,
    author: parsed.meta.author || "Detection Lab",
    date: parsed.meta.created || today,
  };

  if (tags.length > 0) {
    sigmaRule.tags = tags;
  }

  sigmaRule.logsource = {
    category: logsourceCategory,
    product: "windows",
  };

  sigmaRule.detection = {
    selection,
    condition: "selection",
  };

  sigmaRule.falsepositives = ["Unknown"];
  sigmaRule.level = chronicleSeverityToSigma(parsed.meta.severity);

  // Render YAML manually for consistent output (no dependency on yaml library)
  const output = renderSigmaYaml(sigmaRule);

  if (untranslatableFeatures.length > 0) {
    diagnostics.push({
      severity: "warning",
      message: `${untranslatableFeatures.length} YARA-L feature(s) have no Sigma equivalent and were dropped`,
    });
  }

  return {
    success: true,
    output,
    diagnostics,
    fieldMappings,
    untranslatableFeatures,
  };
}


/**
 * Build a reverse lookup map: udmPath -> sigmaField.
 * Uses the full field mapping registry (built-in + plugin-registered).
 */
function buildReverseUdmMap(): Map<string, string> {
  const reverseMap = new Map<string, string>();
  const allMappings = getAllFieldMappings();

  for (const entry of allMappings) {
    if (entry.udmPath) {
      // First mapping wins (don't overwrite)
      if (!reverseMap.has(entry.udmPath)) {
        reverseMap.set(entry.udmPath, entry.sigmaField);
      }
    }
  }

  return reverseMap;
}


interface SigmaModifierResult {
  modifier: string | null;
  cleanValue: string;
}

function yaralPredicateToSigmaModifier(pred: YaralEventPredicate): SigmaModifierResult {
  if (!pred.isRegex) {
    // Exact string match -- no modifier
    return { modifier: null, cleanValue: pred.value };
  }

  const pattern = pred.value;

  // /^value/ -> |startswith
  if (pattern.startsWith("^") && !pattern.endsWith("$")) {
    return { modifier: "|startswith", cleanValue: pattern.slice(1) };
  }

  // /value$/ -> |endswith
  if (pattern.endsWith("$") && !pattern.startsWith("^")) {
    return { modifier: "|endswith", cleanValue: pattern.slice(0, -1) };
  }

  // /^value$/ -> exact match (anchored on both sides)
  if (pattern.startsWith("^") && pattern.endsWith("$")) {
    return { modifier: null, cleanValue: pattern.slice(1, -1) };
  }

  // /value/ with nocase -> |contains
  if (pred.nocase) {
    return { modifier: "|contains", cleanValue: pattern };
  }

  // Other regex -> |re
  return { modifier: "|re", cleanValue: pattern };
}


/**
 * Convert a snake_case YARA-L rule name to a human-readable title.
 */
function normalizeRuleNameToTitle(ruleName: string): string {
  return ruleName
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}


/**
 * Render a Sigma rule object to YAML string without depending on the yaml library.
 * Handles simple nested objects, arrays of strings, and scalar values.
 */
function renderSigmaYaml(obj: Record<string, unknown>, indent: number = 0): string {
  const lines: string[] = [];
  const prefix = "  ".repeat(indent);

  for (const [key, value] of Object.entries(obj)) {
    if (value === null || value === undefined) continue;

    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      lines.push(`${prefix}${key}: ${formatYamlScalar(value)}`);
    } else if (Array.isArray(value)) {
      lines.push(`${prefix}${key}:`);
      for (const item of value) {
        if (typeof item === "string" || typeof item === "number") {
          lines.push(`${prefix}  - ${formatYamlScalar(item)}`);
        }
      }
    } else if (typeof value === "object") {
      lines.push(`${prefix}${key}:`);
      lines.push(renderSigmaYaml(value as Record<string, unknown>, indent + 1));
    }
  }

  return lines.join("\n");
}

function formatYamlScalar(value: string | number | boolean): string {
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  // Quote strings that contain special characters or look like YAML values
  if (
    value.includes(":") ||
    value.includes("#") ||
    value.includes("{") ||
    value.includes("}") ||
    value.includes("[") ||
    value.includes("]") ||
    value.includes("'") ||
    value.includes('"') ||
    value.includes("\n") ||
    value === "true" ||
    value === "false" ||
    value === "null" ||
    value === "" ||
    /^\d+$/.test(value)
  ) {
    return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
  }
  return value;
}


const yaralTranslationProvider: TranslationProvider = {
  canTranslate(from, to): boolean {
    return (
      (from === "sigma_rule" && to === "yaral_rule") ||
      (from === "yaral_rule" && to === "sigma_rule")
    );
  },

  async translate(request): Promise<TranslationResult> {
    // Direction 1: sigma_rule -> yaral_rule
    if (request.sourceFileType === "sigma_rule" && request.targetFileType === "yaral_rule") {
      return sigmaToYaral(request.source);
    }

    // Direction 2: yaral_rule -> sigma_rule
    if (request.sourceFileType === "yaral_rule" && request.targetFileType === "sigma_rule") {
      return yaralToSigma(request.source);
    }

    return {
      success: false,
      output: null,
      diagnostics: [{ severity: "error", message: `Unsupported translation: ${request.sourceFileType} -> ${request.targetFileType}` }],
      fieldMappings: [],
      untranslatableFeatures: [],
    };
  },
};


registerTranslationProvider(yaralTranslationProvider);

export { yaralTranslationProvider };
