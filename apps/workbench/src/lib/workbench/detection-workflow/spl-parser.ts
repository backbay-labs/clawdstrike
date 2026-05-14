import type { DraftSeed } from "./shared-types";


export interface SplCommand {
  /** Command name: "search", "where", "stats", "eval", "table", "fields", "sort", "head", "dedup", "rename", "rex", "lookup", etc. */
  command: string;
  /** The original text of this pipe segment. */
  rawText: string;
  /** Everything after the command keyword. */
  args: string;
}

export interface SplFieldCondition {
  /** Field name, e.g. "CommandLine", "process", "src_ip". */
  field: string;
  /** Comparison operator: "=", "!=", "LIKE", "IN", "match". */
  operator: string;
  /** The comparison value (without surrounding quotes). */
  value: string;
  /** Modifier derived from LIKE patterns / match(): "contains" | "startswith" | "endswith" | "regex" | null. */
  modifier: string | null;
  /** True if preceded by NOT. */
  negated: boolean;
}


/**
 * Split on `|` that is NOT inside quotes (single or double).
 * Returns the raw segments with leading/trailing whitespace trimmed.
 */
function splitPipeChain(source: string): string[] {
  const segments: string[] = [];
  let current = "";
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < source.length; i++) {
    const ch = source[i];

    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      current += ch;
    } else if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      current += ch;
    } else if (ch === "|" && !inSingle && !inDouble) {
      segments.push(current.trim());
      current = "";
    } else {
      current += ch;
    }
  }

  const last = current.trim();
  if (last) {
    segments.push(last);
  }

  return segments;
}

/**
 * Strip leading comment lines (lines starting with `//` or `#`).
 * Join remaining lines into a single string (multi-line SPL support).
 */
function stripComments(source: string): string {
  const lines = source.split(/\r?\n/);
  const nonComment = lines.filter((line) => {
    const trimmed = line.trimStart();
    return !trimmed.startsWith("//") && !trimmed.startsWith("#");
  });
  return nonComment.join(" ").trim();
}

const IMPLICIT_SEARCH_RE = /^(index\s*=|sourcetype\s*=|source\s*=|host\s*=|eventtype\s*=)/i;

/**
 * Parse SPL text into pipe-delimited commands.
 *
 * - Strips leading comment lines (lines starting with `//` or `#`).
 * - Splits on `|` that is NOT inside quotes.
 * - For the first segment, if it starts with `search` keyword, sets command
 *   to "search"; otherwise if it starts with `index=` or `sourcetype=`,
 *   treats it as an implicit "search" command.
 * - For subsequent segments, the first word is the command name, rest is args.
 * - Handles multi-line SPL (joins lines, preserves within-quote content).
 */
export function parseSplPipeChain(source: string): SplCommand[] {
  const cleaned = stripComments(source);
  if (!cleaned) return [];

  const segments = splitPipeChain(cleaned);
  const commands: SplCommand[] = [];

  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i];
    if (!segment) continue;

    if (i === 0) {
      // First segment: check if it starts with "search" keyword
      const searchMatch = segment.match(/^search\s+(.*)/i);
      if (searchMatch) {
        commands.push({
          command: "search",
          rawText: segment,
          args: searchMatch[1].trim(),
        });
      } else if (IMPLICIT_SEARCH_RE.test(segment)) {
        // Implicit search command (starts with index=, sourcetype=, etc.)
        commands.push({
          command: "search",
          rawText: segment,
          args: segment,
        });
      } else {
        // First segment is some other command
        const wordMatch = segment.match(/^(\S+)\s*(.*)/);
        if (wordMatch) {
          commands.push({
            command: wordMatch[1].toLowerCase(),
            rawText: segment,
            args: wordMatch[2].trim(),
          });
        } else {
          commands.push({
            command: segment.toLowerCase(),
            rawText: segment,
            args: "",
          });
        }
      }
    } else {
      // Subsequent segments: first word is the command
      const wordMatch = segment.match(/^(\S+)\s*(.*)/);
      if (wordMatch) {
        commands.push({
          command: wordMatch[1].toLowerCase(),
          rawText: segment,
          args: wordMatch[2].trim(),
        });
      } else {
        commands.push({
          command: segment.toLowerCase(),
          rawText: segment,
          args: "",
        });
      }
    }
  }

  return commands;
}


/**
 * Remove surrounding quotes (single or double) from a string.
 */
function unquote(value: string): string {
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }
  return value;
}

/**
 * Determine the modifier from a value with wildcard patterns.
 * - `*value*` -> "contains"
 * - `value*` -> "startswith"
 * - `*value` -> "endswith"
 * - no wildcards -> null (exact)
 */
function inferModifier(value: string): { modifier: string | null; cleanValue: string } {
  const startsWild = value.startsWith("*");
  const endsWild = value.endsWith("*");

  if (startsWild && endsWild && value.length > 2) {
    return { modifier: "contains", cleanValue: value.slice(1, -1) };
  }
  if (startsWild && value.length > 1) {
    return { modifier: "endswith", cleanValue: value.slice(1) };
  }
  if (endsWild && value.length > 1) {
    return { modifier: "startswith", cleanValue: value.slice(0, -1) };
  }
  return { modifier: null, cleanValue: value };
}

/**
 * Extract field=value conditions from SPL text.
 *
 * Parses:
 * - `field="value"`, `field=value` (unquoted)
 * - `field="*pattern*"` (LIKE contains), `field="pattern*"` (LIKE startswith),
 *   `field="*pattern"` (LIKE endswith)
 * - `match(field, "regex")` as regex modifier
 * - `where field LIKE "%value%"` / `where field="value"` forms
 * - `NOT` prefix for negation
 * - `IN ("val1", "val2")` by expanding to multiple conditions
 *
 * @returns Array of all extracted conditions.
 */
export function parseSplFieldConditions(source: string): SplFieldCondition[] {
  const conditions: SplFieldCondition[] = [];
  const cleaned = stripComments(source);

  // Pattern 1: match(field, "regex")
  const matchRegex = /\b(NOT\s+)?match\s*\(\s*(\w+)\s*,\s*"([^"]+)"\s*\)/gi;
  let m: RegExpExecArray | null;
  while ((m = matchRegex.exec(cleaned)) !== null) {
    conditions.push({
      field: m[2],
      operator: "match",
      value: m[3],
      modifier: "regex",
      negated: !!m[1],
    });
  }

  // Pattern 2: field IN ("val1", "val2", ...)
  const inRegex = /\b(NOT\s+)?(\w+)\s+IN\s*\(\s*("(?:[^"\\]|\\.)*"(?:\s*,\s*"(?:[^"\\]|\\.)*")*)\s*\)/gi;
  while ((m = inRegex.exec(cleaned)) !== null) {
    const negated = !!m[1];
    const field = m[2];
    const valuesStr = m[3];
    // Extract individual quoted values
    const valueRegex = /"([^"\\]|\\.)*"/g;
    let vm: RegExpExecArray | null;
    while ((vm = valueRegex.exec(valuesStr)) !== null) {
      const rawVal = unquote(vm[0]);
      const { modifier, cleanValue } = inferModifier(rawVal);
      conditions.push({
        field,
        operator: "IN",
        value: cleanValue,
        modifier,
        negated,
      });
    }
  }

  // Pattern 3: field LIKE "%value%" or field LIKE "value%"
  const likeRegex = /\b(NOT\s+)?(\w+)\s+LIKE\s+"([^"]+)"/gi;
  while ((m = likeRegex.exec(cleaned)) !== null) {
    const negated = !!m[1];
    const field = m[2];
    let rawVal = m[3];

    // Convert SQL LIKE wildcards (%) to SPL wildcards (*) for modifier inference
    rawVal = rawVal.replace(/%/g, "*");
    const { modifier, cleanValue } = inferModifier(rawVal);

    conditions.push({
      field,
      operator: "LIKE",
      value: cleanValue,
      modifier,
      negated,
    });
  }

  // Pattern 4: field="value" or field=value or field!="value" or field!=value
  // Must not match patterns already captured (match(), IN, LIKE)
  const fieldValueRegex = /\b(NOT\s+)?(\w+)\s*(!=|=)\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\S+)/gi;
  while ((m = fieldValueRegex.exec(cleaned)) !== null) {
    const prefix = m[1];
    const field = m[2];
    const op = m[3];
    let rawVal = unquote(m[4]);

    // Skip known SPL keywords that look like field=value
    const fieldLower = field.toLowerCase();
    if (
      fieldLower === "index" ||
      fieldLower === "sourcetype" ||
      fieldLower === "source" ||
      fieldLower === "host" ||
      fieldLower === "eventtype" ||
      fieldLower === "search" ||
      fieldLower === "where" ||
      fieldLower === "stats" ||
      fieldLower === "table" ||
      fieldLower === "fields" ||
      fieldLower === "sort" ||
      fieldLower === "head" ||
      fieldLower === "dedup" ||
      fieldLower === "rename" ||
      fieldLower === "rex" ||
      fieldLower === "lookup" ||
      fieldLower === "eval" ||
      fieldLower === "not" ||
      fieldLower === "and" ||
      fieldLower === "or" ||
      fieldLower === "in" ||
      fieldLower === "like" ||
      fieldLower === "match"
    ) {
      continue;
    }

    const negated = !!prefix || op === "!=";
    const { modifier, cleanValue } = inferModifier(rawVal);

    conditions.push({
      field,
      operator: op === "!=" ? "!=" : "=",
      value: cleanValue,
      modifier,
      negated,
    });
  }

  return conditions;
}


/**
 * Case-insensitive key lookup in a payload object.
 */
function getPayloadValue(
  payload: Record<string, unknown>,
  field: string,
): unknown | undefined {
  // Try exact match first
  if (field in payload) return payload[field];

  // Case-insensitive fallback
  const lowerField = field.toLowerCase();
  for (const key of Object.keys(payload)) {
    if (key.toLowerCase() === lowerField) {
      return payload[key];
    }
  }

  return undefined;
}

/**
 * Client-side matching of evidence payload against SPL conditions.
 *
 * - For each condition, looks up `payload[condition.field]` (case-insensitive).
 * - Applies modifier logic: null = exact match (case-insensitive),
 *   "contains" = string.includes, "startswith" = string.startsWith,
 *   "endswith" = string.endsWith, "regex" = new RegExp test.
 * - If `negated`, inverts the result.
 * - ALL conditions must match for overall `matched: true` (AND logic).
 *
 * @returns Overall match result and per-field match details.
 */
export function matchSplConditions(
  payload: Record<string, unknown>,
  conditions: SplFieldCondition[],
): {
  matched: boolean;
  matchedFields: Array<{ field: string; value: string; matched: boolean }>;
} {
  if (conditions.length === 0) {
    return { matched: false, matchedFields: [] };
  }

  const matchedFields: Array<{ field: string; value: string; matched: boolean }> = [];
  let allMatched = true;

  for (const cond of conditions) {
    const rawValue = getPayloadValue(payload, cond.field);
    const eventStr = rawValue !== undefined ? String(rawValue).toLowerCase() : "";
    const condValue = cond.value.toLowerCase();
    const hasField = rawValue !== undefined;

    let fieldMatched = false;

    if (!hasField) {
      fieldMatched = false;
    } else {
      switch (cond.modifier) {
        case "contains":
          fieldMatched = eventStr.includes(condValue);
          break;
        case "startswith":
          fieldMatched = eventStr.startsWith(condValue);
          break;
        case "endswith":
          fieldMatched = eventStr.endsWith(condValue);
          break;
        case "regex":
          try {
            fieldMatched = new RegExp(cond.value, "i").test(String(rawValue));
          } catch {
            fieldMatched = false;
          }
          break;
        default:
          // Exact match (case-insensitive)
          fieldMatched = eventStr === condValue;
          break;
      }
    }

    // Apply negation
    if (cond.negated) {
      fieldMatched = !fieldMatched;
    }

    matchedFields.push({
      field: cond.field,
      value: String(rawValue ?? ""),
      matched: fieldMatched,
    });

    if (!fieldMatched) {
      allMatched = false;
    }
  }

  return { matched: allMatched, matchedFields };
}


/**
 * Data source hint to SPL index/sourcetype mapping.
 */
interface SplSourceSpec {
  index: string;
  sourcetype: string;
}

function inferSplSource(dataSourceHints: string[]): SplSourceSpec {
  for (const hint of dataSourceHints) {
    const lower = hint.toLowerCase();
    if (lower === "process" || lower === "command") {
      return { index: "main", sourcetype: "WinEventLog:Security" };
    }
    if (lower === "file") {
      return { index: "main", sourcetype: "WinEventLog:Sysmon" };
    }
    if (lower === "network") {
      return { index: "main", sourcetype: "firewall" };
    }
    if (lower === "registry") {
      return { index: "main", sourcetype: "WinEventLog:Sysmon" };
    }
  }
  // Default
  return { index: "main", sourcetype: "WinEventLog:Security" };
}

/**
 * Generate SPL text from a DraftSeed.
 *
 * - Maps `seed.dataSourceHints` to `index=` and `sourcetype=` values.
 * - Maps `seed.extractedFields` to CIM field names using the provided
 *   `fieldMapper` function.
 * - Builds pipe chain: `index=... sourcetype=... | where <conditions> | table <fields>`.
 * - Adds comment header with title and technique hints.
 */
export function buildSplFromSeed(
  seed: DraftSeed,
  fieldMapper: (sigmaField: string) => string | null,
): string {
  const { index, sourcetype } = inferSplSource(seed.dataSourceHints);
  const lines: string[] = [];

  // Comment header
  lines.push(`// Detection: ${seed.kind} ${seed.id.slice(0, 8)}`);
  lines.push(`// Author: Detection Lab`);
  if (seed.techniqueHints.length > 0) {
    lines.push(`// Techniques: ${seed.techniqueHints.join(", ")}`);
  }

  // Build search base
  const searchBase = `index=${index} sourcetype=${sourcetype}`;

  // Build where conditions from extracted fields
  const whereClauses: string[] = [];
  const tableFields: string[] = ["_time"];

  for (const [key, value] of Object.entries(seed.extractedFields)) {
    if (value === undefined || value === null) continue;
    // Skip non-primitive values (objects, arrays used as metadata)
    if (typeof value === "object") continue;

    const cimField = fieldMapper(key) ?? key;
    const strValue = String(value);

    // Use contains semantics for string values
    if (typeof value === "string" && value.length > 0) {
      whereClauses.push(`${cimField}="*${escapeQuoted(strValue)}*"`);
    } else {
      whereClauses.push(`${cimField}="${escapeQuoted(strValue)}"`);
    }

    if (!tableFields.includes(cimField)) {
      tableFields.push(cimField);
    }
  }

  // Assemble the SPL query
  let spl = searchBase;

  if (whereClauses.length > 0) {
    spl += `\n| where ${whereClauses.join(" AND ")}`;
  }

  if (tableFields.length > 1) {
    spl += `\n| table ${tableFields.join(", ")}`;
  }

  lines.push(spl);
  return lines.join("\n");
}

/**
 * Escape characters for SPL double-quoted strings.
 */
function escapeQuoted(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}


/**
 * Find line numbers containing the given field names (for editor highlighting).
 *
 * @returns Sorted 1-based line numbers where any of the given fields appear.
 */
export function findSplSourceLineHints(source: string, fields: string[]): number[] {
  const lines = source.split(/\r?\n/);
  const lineHints = new Set<number>();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Skip comment lines
    const trimmed = line.trimStart();
    if (trimmed.startsWith("//") || trimmed.startsWith("#")) continue;

    for (const field of fields) {
      if (field && line.includes(field)) {
        lineHints.add(i + 1);
      }
    }
  }

  return [...lineHints].sort((a, b) => a - b);
}
