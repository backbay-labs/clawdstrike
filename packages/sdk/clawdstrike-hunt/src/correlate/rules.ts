import * as yaml from "js-yaml";
import * as fs from "node:fs/promises";
import { parseHumanDuration } from "../duration.js";
import { CorrelationError, ParseError } from "../errors.js";
import type { CorrelationRule, RuleCondition, RuleSeverity } from "../types.js";

const SUPPORTED_SCHEMA = "clawdstrike.hunt.correlation.v1";

interface RawCondition {
  source: string | string[];
  action_type?: string;
  verdict?: string;
  target_pattern?: string;
  not_target_pattern?: string;
  after?: string;
  within?: string;
  bind: string;
}

interface RawSequenceItem {
  bind: string;
  source: string | string[];
  action_type?: string;
  verdict?: string;
  target_pattern?: string;
  not_target_pattern?: string;
  after?: string;
  within?: string;
}

interface RawRule {
  schema: string;
  name: string;
  severity: string;
  description: string;
  window: string;
  conditions?: RawCondition[];
  sequence?: RawSequenceItem[];
  output: {
    title: string;
    evidence: string[];
  };
}

function toOptionalString(
  value: unknown,
  field: string,
  conditionIndex: number,
): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string") {
    throw new ParseError(
      `condition ${conditionIndex} has invalid '${field}' (expected string)`
    );
  }
  return value;
}

function parseCondition(raw: unknown, conditionIndex: number): RuleCondition {
  if (!raw || typeof raw !== "object") {
    throw new ParseError(`condition ${conditionIndex} must be an object`);
  }

  const record = raw as Record<string, unknown>;
  const sourceRaw = record.source;
  const sourceList = Array.isArray(sourceRaw) ? sourceRaw : [sourceRaw];
  if (
    sourceList.length === 0 ||
    !sourceList.every((s) => typeof s === "string" && s.trim().length > 0)
  ) {
    throw new ParseError(
      `condition ${conditionIndex} has invalid 'source' (expected string or array of strings)`
    );
  }
  const source = sourceList as string[];

  const bind = record.bind;
  if (typeof bind !== "string" || bind.trim().length === 0) {
    throw new ParseError(`condition ${conditionIndex} has invalid 'bind' (expected string)`);
  }

  const withinRaw = toOptionalString(record.within, "within", conditionIndex);
  let withinMs: number | undefined;
  if (withinRaw !== undefined) {
    withinMs = parseHumanDuration(withinRaw);
    if (withinMs === undefined) {
      throw new ParseError(`invalid duration: ${withinRaw}`);
    }
  }

  return {
    source,
    actionType: toOptionalString(record.action_type, "action_type", conditionIndex),
    verdict: toOptionalString(record.verdict, "verdict", conditionIndex),
    targetPattern: toOptionalString(record.target_pattern, "target_pattern", conditionIndex),
    notTargetPattern: toOptionalString(record.not_target_pattern, "not_target_pattern", conditionIndex),
    after: toOptionalString(record.after, "after", conditionIndex),
    within: withinMs,
    bind,
  };
}

function parseSeverity(s: string): RuleSeverity {
  const lower = s.toLowerCase();
  if (lower === "low" || lower === "medium" || lower === "high" || lower === "critical") {
    return lower as RuleSeverity;
  }
  throw new ParseError(`invalid severity '${s}'`);
}

/**
 * Transform a sequence shorthand into standard conditions.
 * Each item auto-wires its `after` to the previous item's `bind` unless overridden.
 */
function desugarSequence(items: RawSequenceItem[]): RawCondition[] {
  if (items.length === 0) {
    throw new ParseError("sequence must have at least one item");
  }

  const conditions: RawCondition[] = [];
  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    const cond: RawCondition = {
      bind: item.bind,
      source: item.source,
      action_type: item.action_type,
      verdict: item.verdict,
      target_pattern: item.target_pattern,
      not_target_pattern: item.not_target_pattern,
      within: item.within,
      after: item.after ?? (i > 0 ? items[i - 1].bind : undefined),
    };
    conditions.push(cond);
  }
  return conditions;
}

/**
 * Parse a YAML string into a CorrelationRule, then validate it.
 */
export function parseRule(yamlStr: string): CorrelationRule {
  let raw: RawRule;
  try {
    raw = yaml.load(yamlStr) as RawRule;
  } catch (e) {
    throw new ParseError(`YAML parse error: ${e instanceof Error ? e.message : String(e)}`);
  }

  if (!raw || typeof raw !== "object") {
    throw new ParseError("YAML did not produce a valid object");
  }

  if (typeof raw.schema !== "string") {
    throw new ParseError("missing or invalid 'schema' field");
  }
  if (typeof raw.name !== "string") {
    throw new ParseError("missing or invalid 'name' field");
  }
  if (typeof raw.severity !== "string") {
    throw new ParseError("missing or invalid 'severity' field");
  }
  if (typeof raw.description !== "string") {
    throw new ParseError("missing or invalid 'description' field");
  }
  if (typeof raw.window !== "string") {
    throw new ParseError("missing or invalid 'window' field (expected duration string)");
  }
  if (!raw.output || typeof raw.output !== "object") {
    throw new ParseError("missing or invalid 'output' field");
  }
  if (typeof raw.output.title !== "string") {
    throw new ParseError("output.title must be a string");
  }
  if (
    !Array.isArray(raw.output.evidence) ||
    !raw.output.evidence.every((e: unknown) => typeof e === "string")
  ) {
    throw new ParseError("output.evidence must be an array of strings");
  }

  if (raw.sequence && raw.conditions) {
    throw new ParseError("'sequence' and 'conditions' are mutually exclusive");
  }

  const windowMs = parseHumanDuration(raw.window);
  if (windowMs === undefined) {
    throw new ParseError(`invalid duration: ${raw.window}`);
  }

  let rawConditions: unknown[];
  if (raw.sequence !== undefined) {
    if (!Array.isArray(raw.sequence)) {
      throw new ParseError("'sequence' must be an array");
    }
    rawConditions = desugarSequence(raw.sequence);
  } else if (raw.conditions !== undefined) {
    if (!Array.isArray(raw.conditions)) {
      throw new ParseError("'conditions' must be an array");
    }
    rawConditions = raw.conditions;
  } else {
    rawConditions = [];
  }

  const conditions: RuleCondition[] = rawConditions.map((c, index) => parseCondition(c, index));

  const rule: CorrelationRule = {
    schema: raw.schema,
    name: raw.name,
    severity: parseSeverity(raw.severity),
    description: raw.description,
    window: windowMs,
    conditions,
    output: {
      title: raw.output.title,
      evidence: raw.output.evidence,
    },
  };

  validateRule(rule);
  return rule;
}

/**
 * Validate a parsed correlation rule.
 *
 * Checks:
 * 1. schema must be exactly "clawdstrike.hunt.correlation.v1"
 * 2. At least 1 condition
 * 3. All `after` references must exist in prior conditions' bind names
 * 4. All output.evidence entries reference valid bind names
 * 5. No duplicate bind names
 * 6. `within` requires `after`
 * 7. `within` duration <= global window
 */
export function validateRule(rule: CorrelationRule): void {
  if (rule.schema !== SUPPORTED_SCHEMA) {
    throw new CorrelationError(
      `unsupported schema '${rule.schema}', expected '${SUPPORTED_SCHEMA}'`
    );
  }

  if (rule.window <= 0) {
    throw new CorrelationError("window must be a positive duration");
  }

  if (rule.conditions.length === 0) {
    throw new CorrelationError("rule must have at least one condition");
  }

  const knownBinds: string[] = [];

  for (let i = 0; i < rule.conditions.length; i++) {
    const cond = rule.conditions[i];

    if (cond.after !== undefined) {
      if (!knownBinds.includes(cond.after)) {
        throw new CorrelationError(
          `condition ${i} references unknown bind '${cond.after}' in 'after'`
        );
      }
    }

    if (cond.within !== undefined && cond.within <= 0) {
      throw new CorrelationError(
        `condition ${i} 'within' must be a positive duration`
      );
    }

    if (cond.within !== undefined && cond.after === undefined) {
      throw new CorrelationError(
        `condition ${i} has 'within' but no 'after'; 'within' only makes sense with 'after'`
      );
    }

    if (cond.within !== undefined && cond.within > rule.window) {
      throw new CorrelationError(
        `condition ${i} 'within' exceeds global window`
      );
    }

    if (knownBinds.includes(cond.bind)) {
      throw new CorrelationError(
        `condition ${i} reuses bind name '${cond.bind}'; bind names must be unique`
      );
    }

    knownBinds.push(cond.bind);
  }

  for (const ev of rule.output.evidence) {
    if (!knownBinds.includes(ev)) {
      throw new CorrelationError(
        `output evidence references unknown bind '${ev}'`
      );
    }
  }
}

/**
 * Load and validate correlation rules from a list of YAML file paths.
 */
export async function loadRulesFromFiles(paths: string[]): Promise<CorrelationRule[]> {
  const rules: CorrelationRule[] = [];
  for (const path of paths) {
    const content = await fs.readFile(path, "utf-8");
    rules.push(parseRule(content));
  }
  return rules;
}
