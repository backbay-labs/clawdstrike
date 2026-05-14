
export type EqlEventCategory = "process" | "file" | "network" | "registry" | "dns" | "any";

export interface EqlCondition {
  /** ECS dotted path, e.g. "process.name" */
  field: string;
  /** EQL comparison operator */
  operator: "==" | "!=" | ":" | "~" | ">=" | "<=" | ">" | "<" | "in";
  /** For "in" operator, value is string[]; otherwise string */
  value: string | string[];
  /** Whether the condition is negated with `not` */
  negated: boolean;
}

export interface EqlSingleQuery {
  type: "single";
  eventCategory: EqlEventCategory;
  conditions: EqlCondition[];
  /** How conditions are joined */
  logicOperator: "and" | "or";
}

export interface EqlSequenceStep {
  eventCategory: EqlEventCategory;
  conditions: EqlCondition[];
  logicOperator: "and" | "or";
}

export interface EqlSequenceQuery {
  type: "sequence";
  /** Fields in "sequence by X, Y" */
  byFields: string[];
  steps: EqlSequenceStep[];
  /** Optional time constraint, e.g. "5m", "1h" */
  maxspan?: string;
  /** Optional until clause */
  until?: EqlSingleQuery;
}

export type EqlAst = EqlSingleQuery | EqlSequenceQuery;

export interface EqlParseResult {
  ast: EqlAst | null;
  errors: string[];
}


const EVENT_CATEGORIES: Set<string> = new Set([
  "process",
  "file",
  "network",
  "registry",
  "dns",
  "any",
]);

function isEventCategory(s: string): s is EqlEventCategory {
  return EVENT_CATEGORIES.has(s);
}

/**
 * Strip // comments from each line.
 */
function stripComments(source: string): string {
  return source
    .split(/\r?\n/)
    .map((line) => {
      // Naively strip // comments not inside quotes
      let inQuote = false;
      for (let i = 0; i < line.length; i++) {
        if (line[i] === '"' && (i === 0 || line[i - 1] !== "\\")) {
          inQuote = !inQuote;
        }
        if (!inQuote && line[i] === "/" && i + 1 < line.length && line[i + 1] === "/") {
          return line.slice(0, i).trimEnd();
        }
      }
      return line;
    })
    .join("\n");
}

/**
 * Split a conditions string by ` and ` or ` or `, respecting parentheses nesting.
 * Returns the parts and the logic operator detected.
 */
function splitConditions(
  condStr: string,
): { parts: string[]; logicOp: "and" | "or" } {
  const trimmed = condStr.trim();
  if (!trimmed) {
    return { parts: [], logicOp: "and" };
  }

  // Find top-level ` and ` / ` or ` tokens
  const tokens: Array<{ index: number; length: number; op: "and" | "or" }> = [];
  let depth = 0;
  let inQuote = false;

  for (let i = 0; i < trimmed.length; i++) {
    const ch = trimmed[i];
    if (ch === '"' && (i === 0 || trimmed[i - 1] !== "\\")) {
      inQuote = !inQuote;
      continue;
    }
    if (inQuote) continue;
    if (ch === "(") {
      depth++;
      continue;
    }
    if (ch === ")") {
      depth--;
      continue;
    }
    if (depth > 0) continue;

    // Check for ` and ` (word boundary)
    if (
      i > 0 &&
      trimmed.slice(i).match(/^\s+and\s+/i)
    ) {
      const match = trimmed.slice(i).match(/^(\s+and\s+)/i);
      if (match) {
        tokens.push({ index: i, length: match[1].length, op: "and" });
      }
    }

    // Check for ` or `
    if (
      i > 0 &&
      trimmed.slice(i).match(/^\s+or\s+/i)
    ) {
      const match = trimmed.slice(i).match(/^(\s+or\s+)/i);
      if (match) {
        tokens.push({ index: i, length: match[1].length, op: "or" });
      }
    }
  }

  if (tokens.length === 0) {
    return { parts: [trimmed], logicOp: "and" };
  }

  // Determine dominant logic operator (first one wins)
  const logicOp = tokens[0].op;

  // Split by the tokens
  const parts: string[] = [];
  let lastEnd = 0;
  for (const token of tokens) {
    parts.push(trimmed.slice(lastEnd, token.index).trim());
    lastEnd = token.index + token.length;
  }
  parts.push(trimmed.slice(lastEnd).trim());

  return { parts: parts.filter((p) => p.length > 0), logicOp };
}

/**
 * Parse a single condition expression like:
 *   process.name == "powershell.exe"
 *   process.command_line : "*-encodedcommand*"
 *   not file.path != "/tmp"
 *   process.pid in (1, 2, 3)
 */
function parseCondition(expr: string): EqlCondition | null {
  let trimmed = expr.trim();
  if (!trimmed) return null;

  // Strip outer parens if fully wrapped
  if (trimmed.startsWith("(") && trimmed.endsWith(")")) {
    let depth = 0;
    let allWrapped = true;
    for (let i = 0; i < trimmed.length; i++) {
      if (trimmed[i] === "(") depth++;
      if (trimmed[i] === ")") depth--;
      if (depth === 0 && i < trimmed.length - 1) {
        allWrapped = false;
        break;
      }
    }
    if (allWrapped) {
      trimmed = trimmed.slice(1, -1).trim();
    }
  }

  // Check negation
  let negated = false;
  if (trimmed.startsWith("not ") || trimmed.startsWith("NOT ")) {
    negated = true;
    trimmed = trimmed.slice(4).trim();
  }

  // Try to match `field in (values)`
  const inMatch = trimmed.match(/^([\w.]+)\s+in\s*\(([^)]*)\)/i);
  if (inMatch) {
    const field = inMatch[1];
    const valuesStr = inMatch[2];
    const values = valuesStr
      .split(",")
      .map((v) => v.trim().replace(/^["']|["']$/g, ""))
      .filter((v) => v.length > 0);
    return { field, operator: "in", value: values, negated };
  }

  // Try to match `field operator value`
  // Operators in order of longest first to avoid partial matches
  const operators = [">=", "<=", "!=", "==", ">", "<", ":", "~"];
  for (const op of operators) {
    const opIndex = findOperator(trimmed, op);
    if (opIndex !== -1) {
      const field = trimmed.slice(0, opIndex).trim();
      const rawValue = trimmed.slice(opIndex + op.length).trim();
      const value = rawValue.replace(/^["']|["']$/g, "");
      if (field) {
        return {
          field,
          operator: op as EqlCondition["operator"],
          value,
          negated,
        };
      }
    }
  }

  return null;
}

/**
 * Find operator in expression, respecting quotes.
 */
function findOperator(expr: string, op: string): number {
  let inQuote = false;
  for (let i = 0; i < expr.length - op.length + 1; i++) {
    if (expr[i] === '"' && (i === 0 || expr[i - 1] !== "\\")) {
      inQuote = !inQuote;
      continue;
    }
    if (inQuote) continue;
    if (expr.slice(i, i + op.length) === op) {
      // Make sure it's not part of a longer operator
      if (op === ">" && i + 1 < expr.length && expr[i + 1] === "=") continue;
      if (op === "<" && i + 1 < expr.length && expr[i + 1] === "=") continue;
      if (op === "=" && i > 0 && (expr[i - 1] === "!" || expr[i - 1] === ">" || expr[i - 1] === "<")) continue;
      if (op === "=" && i + 1 < expr.length && expr[i + 1] === "=") continue;
      return i;
    }
  }
  return -1;
}

/**
 * Parse a single-event query from its category and where-clause body.
 */
function parseSingleQueryBody(
  category: EqlEventCategory,
  whereBody: string,
): EqlSingleQuery {
  const { parts, logicOp } = splitConditions(whereBody);
  const conditions: EqlCondition[] = [];

  for (const part of parts) {
    const cond = parseCondition(part);
    if (cond) {
      conditions.push(cond);
    }
  }

  return {
    type: "single",
    eventCategory: category,
    conditions,
    logicOperator: logicOp,
  };
}


/**
 * Parse EQL source text into an AST.
 *
 * Handles:
 * - Single-event queries: `process where process.name == "cmd.exe"`
 * - Sequence queries: `sequence by host.id [process where ...] [file where ...]`
 * - Comment stripping (// line comments)
 * - All EQL operators: == != : ~ >= <= > < in
 * - Negation via `not` prefix
 */
export function parseEql(source: string): EqlParseResult {
  const errors: string[] = [];
  const cleaned = stripComments(source).trim();

  if (!cleaned) {
    return { ast: null, errors: ["Empty EQL source"] };
  }

  // Detect sequence queries
  if (/^sequence\b/i.test(cleaned)) {
    return parseSequenceQuery(cleaned, errors);
  }

  // Single-event query: {category} where {conditions}
  return parseSingleQuery(cleaned, errors);
}

function parseSingleQuery(cleaned: string, errors: string[]): EqlParseResult {
  const whereIndex = cleaned.search(/\s+where\s+/i);
  if (whereIndex === -1) {
    errors.push("Expected 'where' keyword in single-event query");
    return { ast: null, errors };
  }

  const categoryStr = cleaned.slice(0, whereIndex).trim().toLowerCase();
  if (!isEventCategory(categoryStr)) {
    errors.push(
      `Unknown event category "${categoryStr}". Expected: process, file, network, registry, dns, any`,
    );
    return { ast: null, errors };
  }

  const whereMatch = cleaned.slice(whereIndex).match(/^\s+where\s+/i);
  const whereBodyStart = whereIndex + (whereMatch ? whereMatch[0].length : 6);
  const whereBody = cleaned.slice(whereBodyStart).trim();

  if (!whereBody) {
    errors.push("Empty where clause");
    return { ast: null, errors };
  }

  const ast = parseSingleQueryBody(categoryStr, whereBody);

  if (ast.conditions.length === 0) {
    errors.push("No conditions could be parsed from the where clause");
    return { ast: null, errors };
  }

  return { ast, errors };
}

function parseSequenceQuery(cleaned: string, errors: string[]): EqlParseResult {
  // Extract "sequence" header
  let rest = cleaned.replace(/^sequence\s*/i, "").trim();

  // Parse optional "by field1, field2"
  let byFields: string[] = [];
  const byMatch = rest.match(/^by\s+([^[\n]+?)(?=\s*\[|\s*$)/i);
  if (byMatch) {
    const byRaw = byMatch[1].trim();
    // Extract maxspan if it appears in the by clause area
    const maxspanInBy = byRaw.match(/\[?\s*maxspan\s*=\s*(\w+)\s*\]?/i);
    let byFieldsStr = byRaw;
    if (maxspanInBy) {
      byFieldsStr = byRaw.replace(maxspanInBy[0], "").trim();
    }
    byFields = byFieldsStr
      .split(",")
      .map((f) => f.trim())
      .filter((f) => f.length > 0);
    rest = rest.slice(byMatch[0].length).trim();
  }

  // Parse optional maxspan
  let maxspan: string | undefined;
  const maxspanMatch = rest.match(/^\[?\s*maxspan\s*=\s*(\w+)\s*\]?\s*/i);
  if (maxspanMatch) {
    maxspan = maxspanMatch[1];
    rest = rest.slice(maxspanMatch[0].length).trim();
  }

  // Also check the byMatch for maxspan
  if (!maxspan && byMatch) {
    const inlineMaxspan = byMatch[1].match(/\[?\s*maxspan\s*=\s*(\w+)\s*\]?/i);
    if (inlineMaxspan) {
      maxspan = inlineMaxspan[1];
    }
  }

  // Parse bracket blocks: [category where conditions]
  const steps: EqlSequenceStep[] = [];
  let until: EqlSingleQuery | undefined;

  // Find all bracket blocks
  const bracketRegex = /\[\s*([\s\S]*?)\s*\]/g;
  let bracketMatch: RegExpExecArray | null;

  // Check for "until" clause before parsing brackets
  const untilIndex = rest.search(/\buntil\b/i);
  let mainPart = rest;
  let untilPart: string | null = null;

  if (untilIndex !== -1) {
    mainPart = rest.slice(0, untilIndex).trim();
    untilPart = rest.slice(untilIndex).trim();
  }

  // Parse step brackets
  bracketRegex.lastIndex = 0;
  while ((bracketMatch = bracketRegex.exec(mainPart)) !== null) {
    const inner = bracketMatch[1].trim();

    // Skip maxspan brackets
    if (/^maxspan\s*=/i.test(inner)) {
      if (!maxspan) {
        const ms = inner.match(/^maxspan\s*=\s*(\w+)/i);
        if (ms) maxspan = ms[1];
      }
      continue;
    }

    const stepResult = parseStepFromInner(inner);
    if (stepResult) {
      steps.push(stepResult);
    } else {
      errors.push(`Could not parse sequence step: [${inner}]`);
    }
  }

  // Parse until clause
  if (untilPart) {
    const untilBracket = untilPart.match(/until\s*\[\s*([\s\S]*?)\s*\]/i);
    if (untilBracket) {
      const inner = untilBracket[1].trim();
      const whereIdx = inner.search(/\s+where\s+/i);
      if (whereIdx !== -1) {
        const cat = inner.slice(0, whereIdx).trim().toLowerCase();
        const wMatch = inner.slice(whereIdx).match(/^\s+where\s+/i);
        const bodyStart = whereIdx + (wMatch ? wMatch[0].length : 6);
        const body = inner.slice(bodyStart).trim();
        if (isEventCategory(cat) && body) {
          until = parseSingleQueryBody(cat, body);
        }
      }
    }
  }

  if (steps.length < 2) {
    errors.push("Sequence query must have at least 2 steps");
    if (steps.length === 0) {
      return { ast: null, errors };
    }
  }

  const ast: EqlSequenceQuery = {
    type: "sequence",
    byFields,
    steps,
    ...(maxspan ? { maxspan } : {}),
    ...(until ? { until } : {}),
  };

  return { ast, errors };
}

function parseStepFromInner(inner: string): EqlSequenceStep | null {
  const whereIdx = inner.search(/\s+where\s+/i);
  if (whereIdx === -1) return null;

  const cat = inner.slice(0, whereIdx).trim().toLowerCase();
  if (!isEventCategory(cat)) return null;

  const wMatch = inner.slice(whereIdx).match(/^\s+where\s+/i);
  const bodyStart = whereIdx + (wMatch ? wMatch[0].length : 6);
  const body = inner.slice(bodyStart).trim();
  if (!body) return null;

  const { parts, logicOp } = splitConditions(body);
  const conditions: EqlCondition[] = [];

  for (const part of parts) {
    const cond = parseCondition(part);
    if (cond) conditions.push(cond);
  }

  if (conditions.length === 0) return null;

  return {
    eventCategory: cat as EqlEventCategory,
    conditions,
    logicOperator: logicOp,
  };
}


/**
 * Generate syntactically valid EQL text from an AST node.
 */
export function generateEql(ast: EqlAst): string {
  if (ast.type === "single") {
    return generateSingleQuery(ast);
  }
  return generateSequenceQuery(ast);
}

function generateSingleQuery(query: EqlSingleQuery): string {
  const conditions = query.conditions.map(formatCondition);
  const joined = conditions.join(` ${query.logicOperator} `);
  return `${query.eventCategory} where ${joined}`;
}

function generateSequenceQuery(query: EqlSequenceQuery): string {
  const lines: string[] = [];

  // Header line
  let header = "sequence";
  if (query.byFields.length > 0) {
    header += ` by ${query.byFields.join(", ")}`;
  }
  if (query.maxspan) {
    header += ` [maxspan=${query.maxspan}]`;
  }
  lines.push(header);

  // Steps
  for (const step of query.steps) {
    const conditions = step.conditions.map(formatCondition);
    const joined = conditions.join(` ${step.logicOperator} `);
    lines.push(`  [${step.eventCategory} where ${joined}]`);
  }

  // Until clause
  if (query.until) {
    const conditions = query.until.conditions.map(formatCondition);
    const joined = conditions.join(` ${query.until.logicOperator} `);
    lines.push(`  until [${query.until.eventCategory} where ${joined}]`);
  }

  return lines.join("\n");
}

function formatCondition(cond: EqlCondition): string {
  const prefix = cond.negated ? "not " : "";

  if (cond.operator === "in" && Array.isArray(cond.value)) {
    const values = cond.value.map((v) => `"${v}"`).join(", ");
    return `${prefix}${cond.field} in (${values})`;
  }

  const valueStr = typeof cond.value === "string" ? cond.value : String(cond.value);
  // Wrap in quotes unless it looks like a number or boolean
  const needsQuotes = !/^\d+(\.\d+)?$/.test(valueStr) && valueStr !== "true" && valueStr !== "false";
  const formatted = needsQuotes ? `"${valueStr}"` : valueStr;

  return `${prefix}${cond.field} ${cond.operator} ${formatted}`;
}


/**
 * Extract all unique field names referenced in conditions across all steps.
 */
export function extractEqlFields(ast: EqlAst): string[] {
  const fields = new Set<string>();

  if (ast.type === "single") {
    for (const cond of ast.conditions) {
      fields.add(cond.field);
    }
  } else {
    // Sequence: collect from by-fields and all steps
    for (const byField of ast.byFields) {
      fields.add(byField);
    }
    for (const step of ast.steps) {
      for (const cond of step.conditions) {
        fields.add(cond.field);
      }
    }
    if (ast.until) {
      for (const cond of ast.until.conditions) {
        fields.add(cond.field);
      }
    }
  }

  return [...fields];
}

/**
 * Map a data source hint string to an EQL event category.
 */
export function getEventCategoryForHint(hint: string): EqlEventCategory {
  const lower = hint.toLowerCase();
  switch (lower) {
    case "process":
    case "command":
      return "process";
    case "file":
      return "file";
    case "network":
      return "network";
    case "registry":
      return "registry";
    case "dns":
      return "dns";
    default:
      return "process";
  }
}
