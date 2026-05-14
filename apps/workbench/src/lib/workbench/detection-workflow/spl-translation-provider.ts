import YAML from "yaml";
import type {
  TranslationProvider,
  TranslationResult,
  TranslationDiagnostic,
  FieldMapping,
} from "./shared-types";
import { registerTranslationProvider } from "./translations";
import { convertSigmaToQuery } from "./sigma-conversion";
import { parseSplFieldConditions, parseSplPipeChain } from "./spl-parser";
import { getFieldMapping, getAllFieldMappings } from "./field-mappings";


interface SigmaLogsource {
  category: string;
  product?: string;
}

/**
 * Map SPL sourcetype to Sigma logsource fields.
 */
function sourcetypeToLogsource(
  sourcetype: string | null,
  diagnostics: TranslationDiagnostic[],
): SigmaLogsource {
  if (!sourcetype) {
    return { category: "process_creation" };
  }

  const lower = sourcetype.toLowerCase();

  if (lower.includes("wineventlog:security") || lower === "wineventlog:security") {
    return { category: "process_creation", product: "windows" };
  }
  if (lower.includes("wineventlog:sysmon") || lower === "wineventlog:sysmon") {
    return { category: "process_creation", product: "windows" };
  }
  if (lower === "firewall" || lower.includes("firewall")) {
    return { category: "network_connection" };
  }
  if (lower.includes("linux") || lower === "syslog") {
    return { category: "process_creation", product: "linux" };
  }
  if (lower.includes("dns") || lower === "stream:dns") {
    return { category: "dns_query" };
  }

  diagnostics.push({
    severity: "warning",
    message: `Unknown SPL sourcetype "${sourcetype}" -- defaulting logsource to process_creation`,
  });
  return { category: "process_creation" };
}


/**
 * Build a reverse lookup map: splunkCIM -> sigmaField.
 * Uses the full field mapping registry (built-in + plugin-registered).
 */
function buildReverseCimMap(): Map<string, string> {
  const reverseMap = new Map<string, string>();
  const allMappings = getAllFieldMappings();

  for (const entry of allMappings) {
    if (entry.splunkCIM) {
      // First mapping wins (don't overwrite)
      if (!reverseMap.has(entry.splunkCIM)) {
        reverseMap.set(entry.splunkCIM, entry.sigmaField);
      }
    }
  }

  return reverseMap;
}


function splModifierToSigmaModifier(modifier: string | null): string | null {
  switch (modifier) {
    case "contains":
      return "|contains";
    case "startswith":
      return "|startswith";
    case "endswith":
      return "|endswith";
    case "regex":
      return "|re";
    default:
      return null; // exact match -- no modifier
  }
}


/**
 * Detect SPL features that have no Sigma equivalent.
 */
function detectUntranslatableFeatures(source: string): string[] {
  const features: string[] = [];
  const commands = parseSplPipeChain(source);

  const untranslatableCommands: Record<string, string> = {
    stats: "stats command (aggregation not expressible in Sigma)",
    eval: "eval command (computed fields not expressible in Sigma)",
    lookup: "lookup command (enrichment join not expressible in Sigma)",
    subsearch: "subsearch (nested queries not expressible in Sigma)",
    append: "append command (union not expressible in Sigma)",
    join: "join command (cross-index join not expressible in Sigma)",
    transaction: "transaction command (multi-event grouping not expressible in Sigma)",
    chart: "chart command (visualization not expressible in Sigma)",
    timechart: "timechart command (time-series aggregation not expressible in Sigma)",
    eventstats: "eventstats command (inline aggregation not expressible in Sigma)",
    streamstats: "streamstats command (running aggregation not expressible in Sigma)",
  };

  for (const cmd of commands) {
    const desc = untranslatableCommands[cmd.command];
    if (desc) {
      features.push(desc);
    }
  }

  // Check for IN(...) lists in field conditions
  const conditions = parseSplFieldConditions(source);
  const hasInLists = conditions.some((c) => c.operator === "IN");
  if (hasInLists) {
    features.push("Multiple-value IN clauses simplified to individual conditions");
  }

  // Check for subsearch syntax [search ...]
  if (/\[search\s/i.test(source)) {
    if (!features.some((f) => f.includes("subsearch"))) {
      features.push("subsearch (nested queries not expressible in Sigma)");
    }
  }

  return features;
}


interface SplCommentMeta {
  title: string;
  author: string;
  description: string;
}

function extractCommentMeta(source: string): SplCommentMeta {
  const lines = source.split(/\r?\n/);
  let title = "";
  let author = "";
  let description = "";

  for (const line of lines) {
    const trimmed = line.trimStart();
    if (!trimmed.startsWith("//") && !trimmed.startsWith("#")) break;

    const stripped = trimmed.replace(/^\s*(?:\/\/|#)\s*/, "");

    const titleMatch = stripped.match(/^(?:Detection|Title):\s*(.+)/i);
    if (titleMatch) {
      title = titleMatch[1].trim();
      continue;
    }

    const authorMatch = stripped.match(/^Author:\s*(.+)/i);
    if (authorMatch) {
      author = authorMatch[1].trim();
      continue;
    }

    const descMatch = stripped.match(/^Description:\s*(.+)/i);
    if (descMatch) {
      description = descMatch[1].trim();
      continue;
    }
  }

  return { title, author, description };
}


function extractSourcetype(source: string): string | null {
  const commands = parseSplPipeChain(source);
  if (commands.length === 0) return null;

  const first = commands[0];
  if (first.command !== "search") return null;

  // Look for sourcetype=... in the search args
  const match = first.args.match(/sourcetype\s*=\s*(?:"([^"]+)"|'([^']+)'|(\S+))/i);
  if (match) {
    return match[1] ?? match[2] ?? match[3] ?? null;
  }
  return null;
}


const splTranslationProvider: TranslationProvider = {
  canTranslate(from, to): boolean {
    return (
      (from === "sigma_rule" && to === "splunk_spl") ||
      (from === "splunk_spl" && to === "sigma_rule")
    );
  },

  async translate(request): Promise<TranslationResult> {
    if (request.sourceFileType === "sigma_rule" && request.targetFileType === "splunk_spl") {
      return translateSigmaToSpl(request.source);
    }

    if (request.sourceFileType === "splunk_spl" && request.targetFileType === "sigma_rule") {
      return translateSplToSigma(request.source);
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


function translateSigmaToSpl(source: string): TranslationResult {
  const result = convertSigmaToQuery(source, "spl");

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
            const splunkField = mapping?.splunkCIM ?? null;

            fieldMappings.push({
              sigmaField,
              targetField: splunkField ?? sigmaField,
              confidence: splunkField ? "exact" : "unmapped",
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


function translateSplToSigma(source: string): TranslationResult {
  const diagnostics: TranslationDiagnostic[] = [];
  const fieldMappings: FieldMapping[] = [];

  // Parse field conditions from SPL
  const conditions = parseSplFieldConditions(source);

  if (conditions.length === 0) {
    return {
      success: false,
      output: null,
      diagnostics: [
        {
          severity: "error",
          message: "No field conditions found in SPL query -- cannot convert to Sigma",
        },
      ],
      fieldMappings: [],
      untranslatableFeatures: detectUntranslatableFeatures(source),
    };
  }

  // Extract sourcetype for logsource mapping
  const sourcetype = extractSourcetype(source);
  const logsource = sourcetypeToLogsource(sourcetype, diagnostics);

  // Build reverse CIM field map
  const reverseMap = buildReverseCimMap();

  // Build Sigma detection selection from SPL conditions
  const selection: Record<string, unknown> = {};

  for (const cond of conditions) {
    // Skip negated conditions (they'd need a filter block -- simplified here)
    if (cond.negated) {
      diagnostics.push({
        severity: "info",
        message: `Negated condition on field "${cond.field}" simplified to positive match (review required)`,
      });
    }

    // Reverse-map field name (case-insensitive CIM lookup)
    let sigmaField = cond.field;
    let isReverseMapped = false;

    // Try exact match first
    if (reverseMap.has(cond.field)) {
      sigmaField = reverseMap.get(cond.field)!;
      isReverseMapped = true;
    } else {
      // Try case-insensitive match
      const lowerField = cond.field.toLowerCase();
      for (const [cimField, sigma] of reverseMap) {
        if (cimField.toLowerCase() === lowerField) {
          sigmaField = sigma;
          isReverseMapped = true;
          break;
        }
      }
    }

    if (!isReverseMapped) {
      diagnostics.push({
        severity: "warning",
        message: `No reverse mapping for CIM field "${cond.field}" -- using as-is in Sigma rule`,
      });
    }

    fieldMappings.push({
      sigmaField,
      targetField: cond.field,
      confidence: isReverseMapped ? "exact" : "unmapped",
    });

    // Map SPL modifier to Sigma modifier
    const modifier = splModifierToSigmaModifier(cond.modifier);
    const selectionKey = modifier ? `${sigmaField}${modifier}` : sigmaField;

    // Add to selection (merge multiple values for same key)
    const existing = selection[selectionKey];
    if (existing !== undefined) {
      if (Array.isArray(existing)) {
        (existing as string[]).push(cond.value);
      } else {
        selection[selectionKey] = [existing as string, cond.value];
      }
    } else {
      selection[selectionKey] = cond.value;
    }
  }

  // Extract comment metadata
  const meta = extractCommentMeta(source);

  // Build Sigma YAML
  const today = new Date().toISOString().slice(0, 10).replace(/-/g, "/");

  const sigmaRule: Record<string, unknown> = {
    title: meta.title || "Converted SPL Rule",
    status: "experimental",
    description: meta.description || "Converted from SPL rule",
    author: meta.author || "Detection Lab",
    date: today,
    logsource,
    detection: {
      selection,
      condition: "selection",
    },
    falsepositives: ["Review converted rule"],
    level: "medium",
  };

  const output = YAML.stringify(sigmaRule, { lineWidth: 120 });

  // Detect untranslatable features
  const untranslatableFeatures = detectUntranslatableFeatures(source);

  if (untranslatableFeatures.length > 0) {
    diagnostics.push({
      severity: "warning",
      message: `${untranslatableFeatures.length} SPL feature(s) have no Sigma equivalent and were dropped`,
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


registerTranslationProvider(splTranslationProvider);

export { splTranslationProvider };
