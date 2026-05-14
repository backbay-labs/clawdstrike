import YAML from "yaml";
import type {
  TranslationProvider,
  TranslationResult,
  TranslationDiagnostic,
  FieldMapping,
} from "./shared-types";
import { registerTranslationProvider } from "./translations";
import { parseSigmaYaml } from "../sigma-types";
import { parseEql, generateEql } from "./eql-parser";
import type { EqlCondition, EqlSingleQuery, EqlEventCategory } from "./eql-parser";
import { translateField, getAllFieldMappings } from "./field-mappings";


function sigmaLogsourceToEventCategory(
  category: string | undefined,
  diagnostics: TranslationDiagnostic[],
): EqlEventCategory {
  if (!category) {
    diagnostics.push({
      severity: "warning",
      message: "No logsource category specified -- defaulting to process event category",
    });
    return "process";
  }

  switch (category.toLowerCase()) {
    case "process_creation":
    case "process_access":
      return "process";
    case "file_event":
    case "file_access":
    case "file_change":
      return "file";
    case "network_connection":
      return "network";
    case "registry_add":
    case "registry_set":
    case "registry_event":
    case "registry_delete":
      return "registry";
    case "dns":
    case "dns_query":
      return "dns";
    default:
      diagnostics.push({
        severity: "warning",
        message: `Unknown logsource category "${category}" -- defaulting to process event category`,
      });
      return "process";
  }
}


interface SigmaLogsource {
  category: string;
  product?: string;
}

function eventCategoryToLogsource(
  eventCategory: EqlEventCategory,
  diagnostics: TranslationDiagnostic[],
): SigmaLogsource {
  switch (eventCategory) {
    case "process":
      return { category: "process_creation", product: "windows" };
    case "file":
      return { category: "file_event" };
    case "network":
      return { category: "network_connection" };
    case "registry":
      return { category: "registry_event" };
    case "dns":
      return { category: "dns_query" };
    case "any":
      diagnostics.push({
        severity: "warning",
        message: 'EQL "any" event category has no direct Sigma logsource -- defaulting to process_creation',
      });
      return { category: "process_creation" };
  }
}


/**
 * Parse a Sigma detection field key into its base field name and modifiers.
 * E.g. "CommandLine|contains|all" -> { field: "CommandLine", modifiers: ["contains", "all"] }
 */
function parseFieldKey(key: string): { field: string; modifiers: string[] } {
  const parts = key.split("|");
  return {
    field: parts[0],
    modifiers: parts.slice(1),
  };
}

/**
 * Normalize a raw detection field value to an array of strings.
 */
function normalizeValues(value: unknown): string[] {
  if (value == null) return [];
  if (Array.isArray(value)) return value.map(String);
  return [String(value)];
}


/**
 * Extract all selection blocks from the Sigma detection section.
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


/**
 * Map Sigma modifiers to an EQL operator and value transformation.
 */
function sigmaModifiersToEql(
  value: string,
  modifiers: string[],
): { operator: EqlCondition["operator"]; transformedValue: string } {
  if (modifiers.includes("re")) {
    return { operator: "~", transformedValue: value };
  }
  if (modifiers.includes("contains")) {
    return { operator: ":", transformedValue: `*${value}*` };
  }
  if (modifiers.includes("startswith")) {
    return { operator: ":", transformedValue: `${value}*` };
  }
  if (modifiers.includes("endswith")) {
    return { operator: ":", transformedValue: `*${value}` };
  }
  // No modifier -- exact match
  return { operator: "==", transformedValue: value };
}


/**
 * Determine the Sigma modifier string and cleaned value from an EQL condition.
 *
 * Returns the modifier suffix (e.g. "|contains") and the value with wildcards stripped.
 */
function eqlOperatorToSigmaModifier(
  operator: string,
  value: string,
): { modifier: string; cleanedValue: string } {
  if (operator === "~") {
    return { modifier: "|re", cleanedValue: value };
  }

  if (operator === ":") {
    // Wildcard match -- infer modifier from pattern
    if (value.startsWith("*") && value.endsWith("*") && value.length > 2) {
      return { modifier: "|contains", cleanedValue: value.slice(1, -1) };
    }
    if (value.endsWith("*") && !value.startsWith("*")) {
      return { modifier: "|startswith", cleanedValue: value.slice(0, -1) };
    }
    if (value.startsWith("*") && !value.endsWith("*")) {
      return { modifier: "|endswith", cleanedValue: value.slice(1) };
    }
    // Wildcard with no discernible pattern -- treat as contains
    return { modifier: "|contains", cleanedValue: value.replace(/^\*|\*$/g, "") };
  }

  if (operator === "!=") {
    // Negation -- no modifier, caller handles via separate filter block or not_ prefix
    return { modifier: "", cleanedValue: value };
  }

  // == or others -- exact match, no modifier
  return { modifier: "", cleanedValue: value };
}


/**
 * Build a reverse lookup map: ecsField -> sigmaField.
 * Uses the full field mapping registry (built-in + plugin-registered).
 */
function buildReverseEcsMap(): Map<string, string> {
  const reverseMap = new Map<string, string>();
  const allMappings = getAllFieldMappings();

  for (const entry of allMappings) {
    if (entry.ecsField) {
      // First mapping wins (don't overwrite)
      if (!reverseMap.has(entry.ecsField)) {
        reverseMap.set(entry.ecsField, entry.sigmaField);
      }
    }
  }

  return reverseMap;
}


const eqlTranslationProvider: TranslationProvider = {
  canTranslate(from, to): boolean {
    return (
      (from === "sigma_rule" && to === "eql_rule") ||
      (from === "eql_rule" && to === "sigma_rule")
    );
  },

  async translate(request): Promise<TranslationResult> {
    if (request.sourceFileType === "sigma_rule" && request.targetFileType === "eql_rule") {
      return translateSigmaToEql(request.source);
    }

    if (request.sourceFileType === "eql_rule" && request.targetFileType === "sigma_rule") {
      return translateEqlToSigma(request.source);
    }

    return {
      success: false,
      output: null,
      diagnostics: [
        {
          severity: "error",
          message: `Unsupported translation: ${request.sourceFileType} -> ${request.targetFileType}`,
        },
      ],
      fieldMappings: [],
      untranslatableFeatures: [],
    };
  },
};


function translateSigmaToEql(source: string): TranslationResult {
  const diagnostics: TranslationDiagnostic[] = [];
  const fieldMappings: FieldMapping[] = [];

  // Step 1: Parse Sigma YAML
  const { rule, errors } = parseSigmaYaml(source);
  if (errors.length > 0) {
    for (const err of errors) {
      diagnostics.push({ severity: "error", message: `Sigma parse: ${err}` });
    }
  }

  if (!rule) {
    return {
      success: false,
      output: null,
      diagnostics,
      fieldMappings,
      untranslatableFeatures: [],
    };
  }

  // Step 2: Map logsource category to EQL event category
  const eventCategory = sigmaLogsourceToEventCategory(rule.logsource.category, diagnostics);

  // Step 3: Extract selection blocks from detection
  const detection = rule.detection as Record<string, unknown>;
  const selections = extractSelections(detection);

  if (selections.length === 0) {
    diagnostics.push({
      severity: "warning",
      message: "No selection blocks found in detection section",
    });
    return {
      success: false,
      output: null,
      diagnostics,
      fieldMappings,
      untranslatableFeatures: [],
    };
  }

  // Step 4: Build EQL conditions from selection fields
  const conditions: EqlCondition[] = [];

  for (const selection of selections) {
    for (const [key, rawValue] of Object.entries(selection.fields)) {
      const { field, modifiers } = parseFieldKey(key);
      const values = normalizeValues(rawValue);

      if (values.length === 0) continue;

      // Translate Sigma field to ECS field
      const ecsField = translateField(field, "ecsField");
      const targetField = ecsField ?? field;
      const confidence: FieldMapping["confidence"] = ecsField ? "exact" : "unmapped";

      fieldMappings.push({
        sigmaField: field,
        targetField,
        confidence,
      });

      if (!ecsField) {
        diagnostics.push({
          severity: "info",
          message: `No ECS mapping for Sigma field "${field}" -- using as-is`,
        });
      }

      // Map modifiers to EQL operator and build conditions
      if (values.length === 1) {
        const { operator, transformedValue } = sigmaModifiersToEql(values[0], modifiers);
        conditions.push({
          field: targetField,
          operator,
          value: transformedValue,
          negated: false,
        });
      } else {
        // Multi-value: build one condition per value, combine with `or` via separate conditions
        // EQL doesn't have a built-in multi-value modifier like Sigma, so we use
        // individual conditions. For "contains|all", all must match; otherwise any must.
        const isAll = modifiers.includes("all");

        if (isAll) {
          // Each value produces its own condition (AND logic at top level)
          for (const v of values) {
            const { operator, transformedValue } = sigmaModifiersToEql(v, modifiers);
            conditions.push({
              field: targetField,
              operator,
              value: transformedValue,
              negated: false,
            });
          }
        } else {
          // Use `in` operator for exact-match multi-value, or individual `:` conditions
          const { operator } = sigmaModifiersToEql(values[0], modifiers);
          if (operator === "==") {
            // Exact match multi-value -> use "in" operator
            conditions.push({
              field: targetField,
              operator: "in",
              value: values,
              negated: false,
            });
          } else {
            // Wildcard/regex multi-value: produce individual conditions
            // These will be joined with OR logic
            for (const v of values) {
              const { operator: op, transformedValue } = sigmaModifiersToEql(v, modifiers);
              conditions.push({
                field: targetField,
                operator: op,
                value: transformedValue,
                negated: false,
              });
            }
          }
        }
      }
    }
  }

  if (conditions.length === 0) {
    diagnostics.push({
      severity: "warning",
      message: "No conditions could be built from Sigma detection fields",
    });
    return {
      success: false,
      output: null,
      diagnostics,
      fieldMappings,
      untranslatableFeatures: [],
    };
  }

  // Step 5: Build EQL AST
  // Determine logic operator from condition string
  const conditionStr = detection["condition"] as string | undefined;
  const hasOrLogic = conditionStr
    ? / or /i.test(conditionStr)
    : false;

  const ast: EqlSingleQuery = {
    type: "single",
    eventCategory,
    conditions,
    logicOperator: hasOrLogic ? "or" : "and",
  };

  // Step 6: Generate EQL text
  const eqlText = generateEql(ast);

  // Step 7: Add comment header
  const header = [
    `// Translated from Sigma: ${rule.title}`,
    "// NOTE: Review ECS field names for your Elastic deployment",
    "",
  ].join("\n");

  const output = header + eqlText + "\n";

  diagnostics.push({
    severity: "info",
    message: `Translated Sigma rule "${rule.title}" to EQL ${eventCategory} query with ${conditions.length} condition(s)`,
  });

  return {
    success: true,
    output,
    diagnostics,
    fieldMappings,
    untranslatableFeatures: [],
  };
}


function translateEqlToSigma(source: string): TranslationResult {
  const diagnostics: TranslationDiagnostic[] = [];
  const fieldMappings: FieldMapping[] = [];
  const untranslatableFeatures: string[] = [];

  // Step 1: Parse EQL
  const parseResult = parseEql(source);

  if (!parseResult.ast) {
    return {
      success: false,
      output: null,
      diagnostics: [
        {
          severity: "error",
          message: `EQL parse error: ${parseResult.errors.join("; ")}`,
        },
      ],
      fieldMappings,
      untranslatableFeatures,
    };
  }

  const ast = parseResult.ast;

  // Build reverse ECS -> Sigma field map
  const reverseMap = buildReverseEcsMap();

  // Step 2: Determine logsource and conditions based on query type
  let logsource: SigmaLogsource;
  let conditions: EqlCondition[];

  if (ast.type === "single") {
    logsource = eventCategoryToLogsource(ast.eventCategory, diagnostics);
    conditions = ast.conditions;
  } else {
    // Sequence query: use first step for Sigma conversion
    if (ast.steps.length === 0) {
      return {
        success: false,
        output: null,
        diagnostics: [{ severity: "error", message: "Sequence query has no steps" }],
        fieldMappings,
        untranslatableFeatures,
      };
    }

    const firstStep = ast.steps[0];
    logsource = eventCategoryToLogsource(firstStep.eventCategory, diagnostics);
    conditions = firstStep.conditions;

    // Populate untranslatable features for sequence queries
    untranslatableFeatures.push(
      `sequence correlation with ${ast.steps.length} events not preserved`,
    );

    if (ast.byFields.length > 0) {
      untranslatableFeatures.push(
        `sequence by ${ast.byFields.join(", ")} join not preserved`,
      );
    }

    if (ast.maxspan) {
      untranslatableFeatures.push(
        `maxspan=${ast.maxspan} temporal constraint not preserved`,
      );
    }

    if (ast.until) {
      untranslatableFeatures.push("until clause not preserved");
    }

    diagnostics.push({
      severity: "warning",
      message: `EQL sequence query degraded to single-event Sigma rule (only first step of ${ast.steps.length} preserved)`,
    });
  }

  // Step 3: Build Sigma detection selection
  const selection: Record<string, unknown> = {};

  for (const cond of conditions) {
    // Reverse-map ECS field to Sigma field
    const sigmaField = reverseMap.get(cond.field) ?? cond.field;
    const isReverseMapped = reverseMap.has(cond.field);

    if (!isReverseMapped) {
      diagnostics.push({
        severity: "warning",
        message: `No reverse mapping for ECS field "${cond.field}" -- using as-is in Sigma rule`,
      });
    }

    fieldMappings.push({
      sigmaField,
      targetField: cond.field,
      confidence: isReverseMapped ? "exact" : "unmapped",
    });

    // Map EQL operator to Sigma modifier
    const valueStr = Array.isArray(cond.value) ? cond.value[0] ?? "" : cond.value;
    const { modifier, cleanedValue } = eqlOperatorToSigmaModifier(cond.operator, valueStr);

    // Handle negation via not_ prefix
    const fieldPrefix = cond.negated ? "not_" : "";
    const selectionKey = `${fieldPrefix}${sigmaField}${modifier}`;

    // Handle multi-value (in operator)
    if (cond.operator === "in" && Array.isArray(cond.value)) {
      selection[selectionKey] = cond.value;
    } else {
      // Add to selection (merge multiple values for same key)
      const existing = selection[selectionKey];
      if (existing !== undefined) {
        if (Array.isArray(existing)) {
          (existing as string[]).push(cleanedValue);
        } else {
          selection[selectionKey] = [existing as string, cleanedValue];
        }
      } else {
        selection[selectionKey] = cleanedValue;
      }
    }
  }

  if (Object.keys(selection).length === 0) {
    diagnostics.push({
      severity: "warning",
      message: "No conditions could be converted to Sigma detection fields",
    });
  }

  // Step 4: Build Sigma YAML
  const today = new Date().toISOString().slice(0, 10).replace(/-/g, "/");

  const sigmaRule: Record<string, unknown> = {
    title: "EQL Translation",
    id: crypto.randomUUID(),
    status: "experimental",
    description: "Translated from EQL query",
    author: "Detection Lab",
    date: today,
    logsource,
    detection: {
      selection,
      condition: "selection",
    },
    falsepositives: ["Review required - auto-converted from EQL"],
    level: "medium",
  };

  const output = YAML.stringify(sigmaRule, { lineWidth: 120 });

  if (untranslatableFeatures.length > 0) {
    diagnostics.push({
      severity: "warning",
      message: `${untranslatableFeatures.length} EQL feature(s) have no Sigma equivalent and were dropped`,
    });
  }

  diagnostics.push({
    severity: "info",
    message: `Translated EQL ${ast.type} query to Sigma rule with ${Object.keys(selection).length} detection field(s)`,
  });

  return {
    success: true,
    output,
    diagnostics,
    fieldMappings,
    untranslatableFeatures,
  };
}


registerTranslationProvider(eqlTranslationProvider);

export { eqlTranslationProvider };
