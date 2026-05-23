/**
 * Canonical Clawdstrike policy validator.
 *
 * Delegates shape checks to `policySchema` (see schema.zod.ts) and adapts
 * zod's `ZodIssue` output back to the historical string format that the
 * test suite asserts on. Warnings are collected via `collectWarnings` and
 * the `${secrets.X}` placeholder check is a separate post-parse pass --
 * neither fits inside a zod schema.
 */

import type { z } from "zod";
import {
  collectWarnings,
  DEFAULT_POLICY_VERSION,
  policySchema,
  SUPPORTED_POLICY_VERSIONS,
} from "./schema.zod.js";

export type PolicyLintResult = {
  valid: boolean;
  errors: string[];
  warnings: string[];
};

const PLACEHOLDER_RE = /\$\{([^}]+)\}/g;

export function validatePolicy(policy: unknown): PolicyLintResult {
  if (!isPlainObject(policy)) {
    return { valid: false, errors: ["Policy must be an object"], warnings: [] };
  }

  const errors: string[] = [];
  const warnings: string[] = [];

  // Version pre-check: the schema treats `version` as optional and validates
  // strict-semver shape via regex, but `unsupported policy version` must be
  // emitted with the same wording the legacy validator used (without a
  // leading `version: `).
  const rawVersion = (policy as Record<string, unknown>).version;
  if (rawVersion !== undefined) {
    if (typeof rawVersion !== "string" || !isStrictSemver(rawVersion)) {
      errors.push(`version must be a strict semver string (got: ${String(rawVersion)})`);
    } else if (!SUPPORTED_POLICY_VERSIONS.includes(rawVersion as never)) {
      errors.push(
        `unsupported policy version: ${rawVersion} (supported: ${SUPPORTED_POLICY_VERSIONS.join(", ")})`,
      );
    }
  }
  // Skip schema parse when version is malformed -- preserves the prior
  // "fail-fast on unsupported version" behavior.
  if (errors.length > 0) {
    return { valid: false, errors, warnings };
  }

  const result = policySchema.safeParse(policy);
  if (!result.success) {
    for (const issue of result.error.issues) {
      const msg = formatIssue(issue);
      if (msg) errors.push(msg);
    }
  } else {
    warnings.push(...collectWarnings(result.data));
  }

  // Placeholder walker -- runtime env check, not a shape check.
  validatePlaceholders(policy, "policy", errors);

  return { valid: errors.length === 0, errors, warnings };
}

/**
 * Translate a `ZodIssue` into the historical, test-asserted string form.
 *
 * The legacy validator emitted messages with the format
 *   `<path>: <human message>`     (placeholder errors)
 *   `<path> <human message>`      (most other errors)
 *
 * We reuse that shape by stitching the `issue.path` and `issue.message`
 * together. `superRefine`-based issues carry their already-final message;
 * other codes get a small mapping to the legacy phrasing.
 */
function formatIssue(issue: z.ZodIssue): string {
  const path = issue.path.map(String).join(".");
  const prefix = path === "" ? "" : path;

  switch (issue.code) {
    case "invalid_type": {
      const expected = (issue as { expected?: string }).expected ?? "value";
      if (expected === "object") {
        return prefix ? `${prefix} must be an object` : "must be an object";
      }
      if (expected === "array") {
        return prefix ? `${prefix} must be an array` : "must be an array";
      }
      if (expected === "boolean") {
        return prefix ? `${prefix} must be a boolean` : "must be a boolean";
      }
      if (expected === "string") {
        return prefix ? `${prefix} must be a string` : "must be a string";
      }
      if (expected === "number") {
        return prefix ? `${prefix} must be a number` : "must be a number";
      }
      return prefix ? `${prefix} ${issue.message}` : issue.message;
    }
    case "invalid_enum_value":
    case "invalid_union":
    case "invalid_literal":
      return prefix ? `${prefix} ${issue.message}` : issue.message;
    default:
      return prefix ? `${prefix} ${issue.message}` : issue.message;
  }
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

function isStrictSemver(version: string): boolean {
  const m = /^([0-9]|[1-9][0-9]*)\.([0-9]|[1-9][0-9]*)\.([0-9]|[1-9][0-9]*)$/.exec(version);
  return Boolean(m);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// Silence "unused import" when DEFAULT_POLICY_VERSION is exported only for
// downstream code that imports from `./validator.js`.
void DEFAULT_POLICY_VERSION;
