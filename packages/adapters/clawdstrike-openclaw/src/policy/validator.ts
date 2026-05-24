/**
 * Legacy OpenClaw (clawdstrike-v1.0) policy validator.
 *
 * Delegates 1.1.0/1.2.0/1.3.0 inputs to the canonical validator in
 * `@clawdstrike/policy`. Legacy inputs are checked by `legacyPolicySchema`
 * (see schema.legacy.zod.ts), with `formatLegacyIssue` translating
 * `ZodIssue` back into the historical phrasing the existing tests assert
 * on. Warnings are collected post-parse and `${secrets.X}` placeholder
 * resolution remains a separate runtime pass.
 */

import { validatePolicy as validateCanonicalPolicy } from "@clawdstrike/policy";
import type { z } from "zod";
import type { PolicyLintResult } from "../types.js";
import {
  collectLegacyWarnings,
  legacyPolicySchema,
  POLICY_SCHEMA_VERSION,
  UNIMPLEMENTED_VIOLATION_ACTIONS,
  VALID_COMPUTER_USE_MODES,
  VALID_EGRESS_MODES,
  VALID_EXECUTION_MODES,
  VALID_TIMEOUT_BEHAVIORS,
  VALID_VIOLATION_ACTIONS,
} from "./schema.legacy.zod.js";

export { POLICY_SCHEMA_VERSION } from "./schema.legacy.zod.js";

const SUPPORTED_CANONICAL_VERSIONS = new Set(["1.1.0", "1.2.0", "1.3.0"]);
const PLACEHOLDER_RE = /\$\{([^}]+)\}/g;

export function validatePolicy(policy: unknown): PolicyLintResult {
  if (!isPlainObject(policy)) {
    return { valid: false, errors: ["Policy must be an object"], warnings: [] };
  }

  // Route canonical policies (1.1.0/1.2.0/1.3.0) to the canonical validator.
  const versionRaw = (policy as Record<string, unknown>).version;
  if (typeof versionRaw === "string" && SUPPORTED_CANONICAL_VERSIONS.has(versionRaw)) {
    return validateCanonicalPolicy(policy);
  }

  const errors: string[] = [];
  const warnings: string[] = [];

  const result = legacyPolicySchema.safeParse(policy);
  if (result.success) {
    warnings.push(...collectLegacyWarnings(result.data));
  } else {
    for (const issue of result.error.issues) {
      const msg = formatLegacyIssue(issue);
      if (msg) errors.push(msg);
    }
  }

  // Placeholder walker is a runtime side-effect, kept out of the schema.
  validatePlaceholders(policy, "policy", errors);

  return { valid: errors.length === 0, errors, warnings };
}

/**
 * Translate a `ZodIssue` into the historical openclaw validator phrasing.
 * Tests rely on substring matches, so the goal is to keep the field name
 * and the legacy error keyword close together (e.g. "egress.mode must be
 * one of: ...").
 */
function formatLegacyIssue(issue: z.ZodIssue): string {
  const path = issue.path.map(String).join(".");

  if (issue.code === "unrecognized_keys") {
    const keys = (issue as z.ZodUnrecognizedKeysIssue).keys;
    const parent = path === "" ? "policy" : path;
    return `${parent} contains unknown field: ${keys.join(", ")}`;
  }

  if (issue.code === "invalid_type") {
    const expected = (issue as z.ZodInvalidTypeIssue).expected;
    if (path === "") {
      return "Policy must be an object";
    }
    if (expected === "object") return `${path} must be an object`;
    if (expected === "array") return `${path} must be an array of strings`;
    if (expected === "boolean") return `${path} must be a boolean`;
    if (expected === "string") return `${path} must be a string`;
    if (expected === "number") return `${path} must be a finite number`;
    return `${path} ${issue.message}`;
  }

  if (issue.code === "invalid_enum_value") {
    return formatEnumIssue(path, issue as z.ZodInvalidEnumValueIssue);
  }

  if (issue.code === "invalid_union") {
    // `guards.spider_sense` is the only top-level union (boolean | object).
    return `${path} must be a boolean or object`;
  }

  // `custom` covers superRefine messages -- they already carry the full
  // human phrasing, e.g. the spider_sense legacy executability checks.
  if (issue.code === "custom") {
    return path === "" ? issue.message : `${path} ${issue.message}`;
  }

  return path === "" ? issue.message : `${path} ${issue.message}`;
}

function formatEnumIssue(path: string, issue: z.ZodInvalidEnumValueIssue): string {
  const opts = issue.options as readonly string[];
  // Maintain the legacy `field must be one of: a, b, c` template.
  // Special-cased phrasings:
  if (path === "egress.mode") {
    return `egress.mode must be one of: ${VALID_EGRESS_MODES.join(", ")}`;
  }
  if (path === "tools.default_action") {
    return "tools.default_action must be one of: allow, block";
  }
  if (path === "guards.computer_use.mode") {
    return `guards.computer_use.mode must be one of: ${VALID_COMPUTER_USE_MODES.join(", ")}`;
  }
  if (path.endsWith(".on_timeout")) {
    return `${path} must be one of: ${VALID_TIMEOUT_BEHAVIORS.join(", ")}`;
  }
  if (path.endsWith(".execution_mode")) {
    return `${path} must be one of: ${VALID_EXECUTION_MODES.join(", ")}`;
  }
  if (path === "on_violation") {
    return `on_violation must be one of: ${VALID_VIOLATION_ACTIONS.join(", ")}`;
  }
  return `${path} must be one of: ${opts.join(", ")}`;
}

function validatePlaceholders(value: unknown, base: string, errors: string[]): void {
  if (typeof value === "string") {
    for (const match of value.matchAll(PLACEHOLDER_RE)) {
      const raw = match[1] ?? "";
      const envName = envVarForPlaceholder(raw);
      if (!envName.ok) {
        errors.push(`${base}: ${envName.error}`);
        continue;
      }
      if (process.env[envName.value] === undefined) {
        errors.push(`${base}: missing environment variable ${envName.value}`);
      }
    }
    return;
  }

  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      validatePlaceholders(value[i], `${base}[${i}]`, errors);
    }
    return;
  }

  if (isPlainObject(value)) {
    for (const [k, v] of Object.entries(value)) {
      validatePlaceholders(v, `${base}.${k}`, errors);
    }
  }
}

function envVarForPlaceholder(
  raw: string,
): { ok: true; value: string } | { ok: false; error: string } {
  if (raw.startsWith("secrets.")) {
    const name = raw.slice("secrets.".length);
    if (!name) {
      return { ok: false, error: "placeholder ${secrets.} is invalid" };
    }
    return { ok: true, value: name };
  }
  if (!raw) {
    return { ok: false, error: "placeholder ${} is invalid" };
  }
  return { ok: true, value: raw };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// Keep unused-import suppression for re-exports consumed by other files.
void UNIMPLEMENTED_VIOLATION_ACTIONS;
