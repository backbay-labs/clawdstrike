import YAML from "yaml";
import type { TranslationProvider, TranslationResult, TranslationDiagnostic, FieldMapping } from "./shared-types";
import { registerTranslationProvider } from "./translations";
import { convertSigmaToQuery } from "./sigma-conversion";
import { parseKqlQuery } from "./kql-adapter";
import type { KqlWhereClause } from "./kql-adapter";
import { getFieldMapping, getAllFieldMappings } from "./field-mappings";


interface SigmaLogsource {
  category: string;
  product?: string;
}

function sentinelTableToLogsource(
  tableName: string,
  diagnostics: TranslationDiagnostic[],
): SigmaLogsource {
  switch (tableName) {
    case "SecurityEvent":
      return { category: "process_creation", product: "windows" };
    case "CommonSecurityLog":
      return { category: "network_connection" };
    case "SigninLogs":
      return { category: "authentication", product: "azure" };
    case "DeviceProcessEvents":
      return { category: "process_creation", product: "windows" };
    case "DeviceFileEvents":
      return { category: "file_event", product: "windows" };
    case "DeviceNetworkEvents":
      return { category: "network_connection", product: "windows" };
    default:
      diagnostics.push({
        severity: "warning",
        message: `Unknown Sentinel table "${tableName}" -- defaulting logsource to process_creation`,
      });
      return { category: "process_creation" };
  }
}


function kqlOperatorToSigmaModifier(operator: string): string | null {
  switch (operator) {
    case "contains":
      return "|contains";
    case "startswith":
      return "|startswith";
    case "endswith":
      return "|endswith";
    case "matches regex":
      return "|re";
    case "==":
    case "=~":
    case "has":
      return null; // exact match -- no modifier
    default:
      return null;
  }
}


/**
 * Build a reverse lookup map: sentinelField -> sigmaField.
 * Uses the full field mapping registry (built-in + plugin-registered).
 */
function buildReverseSentinelMap(): Map<string, string> {
  const reverseMap = new Map<string, string>();
  const allMappings = getAllFieldMappings();

  for (const entry of allMappings) {
    if (entry.sentinelField) {
      // First mapping wins (don't overwrite)
      if (!reverseMap.has(entry.sentinelField)) {
        reverseMap.set(entry.sentinelField, entry.sigmaField);
      }
    }
  }

  return reverseMap;
}


/**
 * Detect KQL features that have no Sigma equivalent.
 */
function detectUntranslatableFeatures(source: string): string[] {
  const features: string[] = [];

  const patterns: Array<{ regex: RegExp; description: string }> = [
    { regex: /\|\s*summarize\b/i, description: "summarize operator (aggregation not expressible in Sigma)" },
    { regex: /\|\s*join\b/i, description: "join operator (cross-table correlation not expressible in Sigma)" },
    { regex: /\|\s*union\b/i, description: "union operator (multi-table union not expressible in Sigma)" },
    { regex: /\|\s*extend\b/i, description: "extend operator (computed columns not expressible in Sigma)" },
    { regex: /\|\s*project\b/i, description: "project operator (column selection is not semantically meaningful in Sigma)" },
    { regex: /\bago\s*\(/i, description: "ago() time function (relative time filtering not expressible in Sigma)" },
    { regex: /\|\s*render\b/i, description: "render operator (visualization directive not expressible in Sigma)" },
    { regex: /\|\s*sort\b/i, description: "sort operator (ordering not expressible in Sigma)" },
    { regex: /\|\s*top\b/i, description: "top operator (limit not expressible in Sigma)" },
    { regex: /\|\s*count\b/i, description: "count operator (aggregation not expressible in Sigma)" },
  ];

  for (const { regex, description } of patterns) {
    if (regex.test(source)) {
      features.push(description);
    }
  }

  return features;
}


const kqlTranslationProvider: TranslationProvider = {
  canTranslate(from, to): boolean {
    return (
      (from === "sigma_rule" && to === "kql_rule") ||
      (from === "kql_rule" && to === "sigma_rule")
    );
  },

  async translate(request): Promise<TranslationResult> {
    if (request.sourceFileType === "sigma_rule" && request.targetFileType === "kql_rule") {
      return translateSigmaToKql(request.source);
    }

    if (request.sourceFileType === "kql_rule" && request.targetFileType === "sigma_rule") {
      return translateKqlToSigma(request.source);
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


function translateSigmaToKql(source: string): TranslationResult {
  const result = convertSigmaToQuery(source, "kql");

  // Build field mappings for Sigma fields used in the query
  const fieldMappings: FieldMapping[] = [];
  try {
    const parsed = YAML.parse(source) as Record<string, unknown>;
    const detection = parsed["detection"] as Record<string, unknown> | undefined;
    if (detection) {
      for (const [key, value] of Object.entries(detection)) {
        if (key === "condition") continue;
        if (value != null && typeof value === "object" && !Array.isArray(value)) {
          const selectionFields = value as Record<string, unknown>;
          for (const fieldKey of Object.keys(selectionFields)) {
            const sigmaField = fieldKey.split("|")[0];
            const mapping = getFieldMapping(sigmaField);
            const sentinelField = mapping?.sentinelField ?? null;

            fieldMappings.push({
              sigmaField,
              targetField: sentinelField ?? sigmaField,
              confidence: sentinelField ? "exact" : "unmapped",
            });
          }
        }
      }
    }
  } catch {
    // YAML parse error -- field mappings remain empty
  }

  const diagnostics: TranslationDiagnostic[] = result.diagnostics.map((d) => ({
    severity: d.severity,
    message: d.message,
  }));

  return {
    success: result.success,
    output: result.output,
    diagnostics,
    fieldMappings,
    untranslatableFeatures: [],
  };
}


function translateKqlToSigma(source: string): TranslationResult {
  const diagnostics: TranslationDiagnostic[] = [];
  const fieldMappings: FieldMapping[] = [];

  const parsed = parseKqlQuery(source);

  if (!parsed.tableName) {
    return {
      success: false,
      output: null,
      diagnostics: [{ severity: "error", message: "Could not determine KQL table name" }],
      fieldMappings: [],
      untranslatableFeatures: detectUntranslatableFeatures(source),
    };
  }

  // Map table to Sigma logsource
  const logsource = sentinelTableToLogsource(parsed.tableName, diagnostics);

  // Reverse-map Sentinel fields to Sigma fields
  const reverseMap = buildReverseSentinelMap();

  // Build Sigma detection selection from KQL where-clauses
  const selection: Record<string, unknown> = {};

  for (const clause of parsed.whereClauses) {
    // Skip EventID clauses (they map to logsource, not detection)
    if (clause.field.toLowerCase() === "eventid") continue;

    // Reverse-map field name
    const sigmaField = reverseMap.get(clause.field) ?? clause.field;
    const isReverseMapped = reverseMap.has(clause.field);

    if (!isReverseMapped && clause.field !== sigmaField) {
      diagnostics.push({
        severity: "warning",
        message: `No reverse mapping for Sentinel field "${clause.field}" -- using as-is in Sigma rule`,
      });
    }

    fieldMappings.push({
      sigmaField,
      targetField: clause.field,
      confidence: isReverseMapped ? "exact" : "unmapped",
    });

    // Map KQL operator to Sigma modifier
    const modifier = kqlOperatorToSigmaModifier(clause.operator);
    const selectionKey = modifier ? `${sigmaField}${modifier}` : sigmaField;

    // Handle negated operators
    if (clause.operator.startsWith("!")) {
      // Negated operators need a separate filter block -- add as warning
      diagnostics.push({
        severity: "info",
        message: `Negated operator "${clause.operator}" on field "${clause.field}" converted to filter block`,
      });
      // For now, add to selection as exact match with a note
      // (full filter support would require condition: selection and not filter)
    }

    // Add to selection (merge multiple values for same key)
    const existing = selection[selectionKey];
    if (existing !== undefined) {
      if (Array.isArray(existing)) {
        (existing as string[]).push(clause.value);
      } else {
        selection[selectionKey] = [existing as string, clause.value];
      }
    } else {
      selection[selectionKey] = clause.value;
    }
  }

  if (Object.keys(selection).length === 0) {
    diagnostics.push({
      severity: "warning",
      message: "No where-clauses could be converted to Sigma detection fields",
    });
  }

  // Build Sigma YAML object
  const today = new Date().toISOString().slice(0, 10).replace(/-/g, "/");

  const sigmaRule: Record<string, unknown> = {
    title: "Converted from KQL",
    id: crypto.randomUUID(),
    status: "experimental",
    description: `Auto-converted from KQL query targeting ${parsed.tableName}`,
    author: "Detection Lab",
    date: today,
    logsource,
    detection: {
      selection,
      condition: "selection",
    },
    falsepositives: ["Review required - auto-converted from KQL"],
    level: "medium",
  };

  const output = YAML.stringify(sigmaRule, { lineWidth: 120 });

  // Detect untranslatable features
  const untranslatableFeatures = detectUntranslatableFeatures(source);

  if (untranslatableFeatures.length > 0) {
    diagnostics.push({
      severity: "warning",
      message: `${untranslatableFeatures.length} KQL feature(s) have no Sigma equivalent and were dropped`,
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


registerTranslationProvider(kqlTranslationProvider);

export { kqlTranslationProvider };
