import { validatePolicy as validateCanonicalPolicy } from "@clawdstrike/policy";
import type { Policy, PolicyLintResult } from "../types.js";

export const POLICY_SCHEMA_VERSION = "clawdstrike-v1.0";
const SUPPORTED_CANONICAL_VERSIONS = new Set(["1.1.0", "1.2.0", "1.3.0"]);

const VALID_EGRESS_MODES = new Set(["allowlist", "denylist", "open", "deny_all"]);
const VALID_VIOLATION_ACTIONS = new Set(["cancel", "warn"]);
const UNIMPLEMENTED_VIOLATION_ACTIONS = new Set(["isolate", "escalate"]);
const VALID_TIMEOUT_BEHAVIORS = new Set(["allow", "deny", "warn", "defer"]);
const VALID_EXECUTION_MODES = new Set(["parallel", "sequential", "background"]);
const VALID_COMPUTER_USE_MODES = new Set(["observe", "guardrail", "fail_closed"]);

const PLACEHOLDER_RE = /\$\{([^}]+)\}/g;

const RESERVED_PACKAGES = new Set([
  "clawdstrike-virustotal",
  "clawdstrike-safe-browsing",
  "clawdstrike-snyk",
  "clawdstrike-spider-sense",
]);

const POLICY_KEYS = new Set([
  "version",
  "extends",
  "egress",
  "filesystem",
  "execution",
  "tools",
  "limits",
  "guards",
  "on_violation",
]);

const EGRESS_KEYS = new Set(["mode", "allowed_domains", "allowed_cidrs", "denied_domains"]);
const FILESYSTEM_KEYS = new Set(["allowed_write_roots", "allowed_read_paths", "forbidden_paths"]);
const EXECUTION_KEYS = new Set(["allowed_commands", "denied_patterns"]);
const TOOLS_KEYS = new Set(["allowed", "denied"]);
const LIMITS_KEYS = new Set(["max_execution_seconds", "max_memory_mb", "max_output_bytes"]);
const GUARDS_KEYS = new Set([
  "forbidden_path",
  "egress",
  "secret_leak",
  "patch_integrity",
  "mcp_tool",
  "custom",
  "computer_use",
  "remote_desktop_side_channel",
  "input_injection_capability",
  "spider_sense",
]);
const COMPUTER_USE_KEYS = new Set(["enabled", "mode", "allowed_actions"]);
const REMOTE_DESKTOP_SIDE_CHANNEL_KEYS = new Set([
  "enabled",
  "clipboard_enabled",
  "file_transfer_enabled",
  "audio_enabled",
  "drive_mapping_enabled",
  "printing_enabled",
  "session_share_enabled",
  "max_transfer_size_bytes",
]);
const INPUT_INJECTION_CAPABILITY_KEYS = new Set([
  "enabled",
  "allowed_input_types",
  "require_postcondition_probe",
]);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function ensureAllowedKeys(
  obj: Record<string, unknown>,
  field: string,
  allowed: Set<string>,
  errors: string[],
): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) {
      errors.push(`${field} contains unknown field: ${key}`);
    }
  }
}

function ensureBoolean(value: unknown, field: string, errors: string[]): void {
  if (value === undefined) return;
  if (typeof value !== "boolean") {
    errors.push(`${field} must be a boolean`);
  }
}

function ensureBooleanOrObject(value: unknown, field: string, errors: string[]): void {
  if (value === undefined) return;
  if (typeof value !== "boolean" && (typeof value !== "object" || value === null || Array.isArray(value))) {
    errors.push(`${field} must be a boolean or object`);
  }
}

function isSpiderSenseCustomGuard(value: unknown): boolean {
  if (!isPlainObject(value)) return false;
  const pkg = value.package;
  if (typeof pkg !== "string") return false;
  return pkg.trim().toLowerCase() === "clawdstrike-spider-sense";
}

function ensureStringArray(
  value: unknown,
  field: string,
  errors: string[],
  warnings?: string[],
): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) {
    errors.push(`${field} must be an array of strings`);
    return undefined;
  }
  const out: string[] = [];
  for (let i = 0; i < value.length; i++) {
    const item = value[i];
    if (typeof item !== "string") {
      errors.push(`${field}[${i}] must be a string`);
      continue;
    }
    if (item.includes("\u0000")) {
      errors.push(`${field}[${i}] contains a null byte`);
      continue;
    }
    out.push(item);
  }
  if (warnings && out.length === 0) {
    warnings.push(`${field} is empty`);
  }
  return out;
}

function ensurePositiveNumber(value: unknown, field: string, errors: string[]): void {
  if (value === undefined) return;
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    errors.push(`${field} must be a positive number`);
  }
}

function ensureFiniteNumber(value: unknown, field: string, errors: string[]): void {
  if (value === undefined) return;
  if (typeof value !== "number" || !Number.isFinite(value)) {
    errors.push(`${field} must be a finite number`);
  }
}

export function validatePolicy(policy: unknown): PolicyLintResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!isPlainObject(policy)) {
    return { valid: false, errors: ["Policy must be an object"], warnings: [] };
  }

  ensureAllowedKeys(policy, "policy", POLICY_KEYS, errors);

  const p = policy as Policy;

  if (p.version === undefined) {
    errors.push(`version is required (expected: ${POLICY_SCHEMA_VERSION})`);
  } else if (typeof p.version !== "string") {
    errors.push("version must be a string");
  } else if (SUPPORTED_CANONICAL_VERSIONS.has(p.version)) {
    const canonical = validateCanonicalPolicy(policy as any);
    return {
      valid: canonical.valid,
      errors: canonical.errors,
      warnings: canonical.warnings,
    };
  } else if (p.version !== POLICY_SCHEMA_VERSION) {
    errors.push(
      `unsupported policy version: ${p.version} (supported: ${POLICY_SCHEMA_VERSION}, 1.1.0, 1.2.0, 1.3.0)`,
    );
  }

  if (p.extends !== undefined && typeof p.extends !== "string") {
    errors.push("extends must be a string");
  }

  // Egress validation
  if (p.egress !== undefined) {
    if (!isPlainObject(p.egress)) {
      errors.push("egress must be an object");
    } else {
      ensureAllowedKeys(p.egress, "egress", EGRESS_KEYS, errors);
      const mode = (p.egress as any).mode;
      if (mode !== undefined && (!VALID_EGRESS_MODES.has(mode) || typeof mode !== "string")) {
        errors.push(`egress.mode must be one of: ${[...VALID_EGRESS_MODES].join(", ")}`);
      }

      const allowed = ensureStringArray(
        (p.egress as any).allowed_domains,
        "egress.allowed_domains",
        errors,
      );
      if (mode === "allowlist" && allowed && allowed.length === 0) {
        warnings.push("egress.allowlist with empty allowed_domains will deny all egress");
      }

      ensureStringArray((p.egress as any).denied_domains, "egress.denied_domains", errors);
      ensureStringArray((p.egress as any).allowed_cidrs, "egress.allowed_cidrs", errors);
    }
  }

  // Filesystem validation
  if (p.filesystem !== undefined) {
    if (!isPlainObject(p.filesystem)) {
      errors.push("filesystem must be an object");
    } else {
      ensureAllowedKeys(p.filesystem, "filesystem", FILESYSTEM_KEYS, errors);
      ensureStringArray(
        (p.filesystem as any).allowed_write_roots,
        "filesystem.allowed_write_roots",
        errors,
      );
      ensureStringArray(
        (p.filesystem as any).allowed_read_paths,
        "filesystem.allowed_read_paths",
        errors,
      );
      ensureStringArray(
        (p.filesystem as any).forbidden_paths,
        "filesystem.forbidden_paths",
        errors,
        warnings,
      );
    }
  }

  // Execution validation
  if (p.execution !== undefined) {
    if (!isPlainObject(p.execution)) {
      errors.push("execution must be an object");
    } else {
      ensureAllowedKeys(p.execution, "execution", EXECUTION_KEYS, errors);
      ensureStringArray(
        (p.execution as any).allowed_commands,
        "execution.allowed_commands",
        errors,
      );

      const patterns = ensureStringArray(
        (p.execution as any).denied_patterns,
        "execution.denied_patterns",
        errors,
      );
      if (patterns) {
        for (const pattern of patterns) {
          try {
            // eslint-disable-next-line no-new
            new RegExp(pattern);
          } catch (err) {
            errors.push(`execution.denied_patterns contains invalid regex: ${pattern}`);
          }
        }
      }
    }
  }

  // Tool policy validation
  if (p.tools !== undefined) {
    if (!isPlainObject(p.tools)) {
      errors.push("tools must be an object");
    } else {
      ensureAllowedKeys(p.tools, "tools", TOOLS_KEYS, errors);
      ensureStringArray((p.tools as any).allowed, "tools.allowed", errors);
      ensureStringArray((p.tools as any).denied, "tools.denied", errors);
    }
  }

  // Limits validation
  if (p.limits !== undefined) {
    if (!isPlainObject(p.limits)) {
      errors.push("limits must be an object");
    } else {
      ensureAllowedKeys(p.limits, "limits", LIMITS_KEYS, errors);
      ensurePositiveNumber(
        (p.limits as any).max_execution_seconds,
        "limits.max_execution_seconds",
        errors,
      );
      ensurePositiveNumber((p.limits as any).max_memory_mb, "limits.max_memory_mb", errors);
      ensurePositiveNumber((p.limits as any).max_output_bytes, "limits.max_output_bytes", errors);
    }
  }

  // Guard toggles validation
  if (p.guards !== undefined) {
    if (!isPlainObject(p.guards)) {
      errors.push("guards must be an object");
    } else {
      ensureAllowedKeys(p.guards, "guards", GUARDS_KEYS, errors);
      ensureBoolean((p.guards as any).forbidden_path, "guards.forbidden_path", errors);
      ensureBoolean((p.guards as any).egress, "guards.egress", errors);
      ensureBoolean((p.guards as any).secret_leak, "guards.secret_leak", errors);
      ensureBoolean((p.guards as any).patch_integrity, "guards.patch_integrity", errors);
      ensureBoolean((p.guards as any).mcp_tool, "guards.mcp_tool", errors);
      ensureBooleanOrObject((p.guards as any).spider_sense, "guards.spider_sense", errors);

      const computerUse = (p.guards as any).computer_use;
      if (computerUse !== undefined) {
        if (!isPlainObject(computerUse)) {
          errors.push("guards.computer_use must be an object");
        } else {
          ensureAllowedKeys(computerUse, "guards.computer_use", COMPUTER_USE_KEYS, errors);
          ensureBoolean((computerUse as any).enabled, "guards.computer_use.enabled", errors);

          const mode = (computerUse as any).mode;
          if (
            mode !== undefined &&
            (typeof mode !== "string" || !VALID_COMPUTER_USE_MODES.has(mode))
          ) {
            errors.push(
              `guards.computer_use.mode must be one of: ${[...VALID_COMPUTER_USE_MODES].join(", ")}`,
            );
          }

          const allowedActions = ensureStringArray(
            (computerUse as any).allowed_actions,
            "guards.computer_use.allowed_actions",
            errors,
          );
          if (allowedActions && allowedActions.length === 0) {
            warnings.push("guards.computer_use.allowed_actions is empty (all actions allowed)");
          }
        }
      }

      const remoteSideChannel = (p.guards as any).remote_desktop_side_channel;
      if (remoteSideChannel !== undefined) {
        if (!isPlainObject(remoteSideChannel)) {
          errors.push("guards.remote_desktop_side_channel must be an object");
        } else {
          ensureAllowedKeys(
            remoteSideChannel,
            "guards.remote_desktop_side_channel",
            REMOTE_DESKTOP_SIDE_CHANNEL_KEYS,
            errors,
          );
          ensureBoolean(
            (remoteSideChannel as any).enabled,
            "guards.remote_desktop_side_channel.enabled",
            errors,
          );
          ensureBoolean(
            (remoteSideChannel as any).clipboard_enabled,
            "guards.remote_desktop_side_channel.clipboard_enabled",
            errors,
          );
          ensureBoolean(
            (remoteSideChannel as any).file_transfer_enabled,
            "guards.remote_desktop_side_channel.file_transfer_enabled",
            errors,
          );
          ensureBoolean(
            (remoteSideChannel as any).audio_enabled,
            "guards.remote_desktop_side_channel.audio_enabled",
            errors,
          );
          ensureBoolean(
            (remoteSideChannel as any).drive_mapping_enabled,
            "guards.remote_desktop_side_channel.drive_mapping_enabled",
            errors,
          );
          ensureBoolean(
            (remoteSideChannel as any).printing_enabled,
            "guards.remote_desktop_side_channel.printing_enabled",
            errors,
          );
          ensureBoolean(
            (remoteSideChannel as any).session_share_enabled,
            "guards.remote_desktop_side_channel.session_share_enabled",
            errors,
          );
          ensureFiniteNumber(
            (remoteSideChannel as any).max_transfer_size_bytes,
            "guards.remote_desktop_side_channel.max_transfer_size_bytes",
            errors,
          );
          if (
            typeof (remoteSideChannel as any).max_transfer_size_bytes === "number" &&
            (remoteSideChannel as any).max_transfer_size_bytes < 0
          ) {
            errors.push("guards.remote_desktop_side_channel.max_transfer_size_bytes must be >= 0");
          }
        }
      }

      const inputInjection = (p.guards as any).input_injection_capability;
      if (inputInjection !== undefined) {
        if (!isPlainObject(inputInjection)) {
          errors.push("guards.input_injection_capability must be an object");
        } else {
          ensureAllowedKeys(
            inputInjection,
            "guards.input_injection_capability",
            INPUT_INJECTION_CAPABILITY_KEYS,
            errors,
          );
          ensureBoolean(
            (inputInjection as any).enabled,
            "guards.input_injection_capability.enabled",
            errors,
          );
          const inputTypes = ensureStringArray(
            (inputInjection as any).allowed_input_types,
            "guards.input_injection_capability.allowed_input_types",
            errors,
          );
          if (inputTypes && inputTypes.length === 0) {
            warnings.push(
              "guards.input_injection_capability.allowed_input_types is empty (all input types allowed)",
            );
          }
          ensureBoolean(
            (inputInjection as any).require_postcondition_probe,
            "guards.input_injection_capability.require_postcondition_probe",
            errors,
          );
        }
      }

      const custom = (p.guards as any).custom;
      if (custom !== undefined) {
        if (!Array.isArray(custom)) {
          errors.push("guards.custom must be an array");
        } else {
          for (let i = 0; i < custom.length; i++) {
            validateCustomGuardSpec(custom[i], `guards.custom[${i}]`, errors);
          }
        }
      }

      // In the legacy OpenClaw policy schema, Spider-Sense is executable only via
      // guards.custom package entries. Reject legacy-first-class wiring to avoid
      // silent security no-ops.
      if (p.version === POLICY_SCHEMA_VERSION) {
        const spiderSense = (p.guards as any).spider_sense;
        const hasSpiderSenseCustom = Array.isArray(custom) && custom.some(isSpiderSenseCustomGuard);
        if (typeof spiderSense === "object" && spiderSense !== null && !Array.isArray(spiderSense)) {
          errors.push(
            "guards.spider_sense object is not executable in clawdstrike-v1.0; use guards.custom package \"clawdstrike-spider-sense\" or canonical 1.3.0",
          );
        } else if (spiderSense === true && !hasSpiderSenseCustom) {
          errors.push(
            "guards.spider_sense: true is not executable in clawdstrike-v1.0 without guards.custom package \"clawdstrike-spider-sense\"",
          );
        }
      }
    }
  }

  // Validate placeholders across the entire policy tree (fail closed on missing env).
  validatePlaceholders(policy, "policy", errors);

  // on_violation validation
  if (p.on_violation !== undefined) {
    if (typeof p.on_violation !== "string") {
      errors.push(`on_violation must be one of: ${[...VALID_VIOLATION_ACTIONS].join(", ")}`);
    } else if (UNIMPLEMENTED_VIOLATION_ACTIONS.has(p.on_violation)) {
      warnings.push(
        `on_violation value '${p.on_violation}' is not yet implemented; use 'cancel' or 'warn'`,
      );
    } else if (!VALID_VIOLATION_ACTIONS.has(p.on_violation)) {
      errors.push(`on_violation must be one of: ${[...VALID_VIOLATION_ACTIONS].join(", ")}`);
    }
  }

  return { valid: errors.length === 0, errors, warnings };
}

function validateCustomGuardSpec(value: unknown, base: string, errors: string[]): void {
  if (!isPlainObject(value)) {
    errors.push(`${base} must be an object`);
    return;
  }

  const pkg = value.package;
  if (typeof pkg !== "string" || pkg.trim() === "") {
    errors.push(`${base}.package must be a non-empty string`);
    return;
  }

  if (!RESERVED_PACKAGES.has(pkg)) {
    errors.push(`${base}.package unsupported custom guard package: ${pkg}`);
    return;
  }

  const enabled = value.enabled;
  if (enabled !== undefined && typeof enabled !== "boolean") {
    errors.push(`${base}.enabled must be a boolean`);
  }

  const config = value.config;
  if (config !== undefined && !isPlainObject(config)) {
    errors.push(`${base}.config must be an object`);
    return;
  }

  const cfg = (isPlainObject(config) ? config : {}) as Record<string, unknown>;
  if (pkg === "clawdstrike-virustotal") {
    requireString(cfg, `${base}.config.api_key`, errors);
  } else if (pkg === "clawdstrike-safe-browsing") {
    requireString(cfg, `${base}.config.api_key`, errors);
    requireString(cfg, `${base}.config.client_id`, errors);
  } else if (pkg === "clawdstrike-snyk") {
    requireString(cfg, `${base}.config.api_token`, errors);
    requireString(cfg, `${base}.config.org_id`, errors);
  }

  const asyncCfg = (value as any).async;
  if (asyncCfg !== undefined) {
    validateAsyncConfig(asyncCfg, `${base}.async`, errors);
  }
}

function validateAsyncConfig(value: unknown, base: string, errors: string[]): void {
  if (!isPlainObject(value)) {
    errors.push(`${base} must be an object`);
    return;
  }

  const timeoutMs = (value as any).timeout_ms;
  if (
    timeoutMs !== undefined &&
    (!isFiniteNumber(timeoutMs) || timeoutMs < 100 || timeoutMs > 300_000)
  ) {
    errors.push(`${base}.timeout_ms must be between 100 and 300000`);
  }

  const onTimeout = (value as any).on_timeout;
  if (
    onTimeout !== undefined &&
    (typeof onTimeout !== "string" || !VALID_TIMEOUT_BEHAVIORS.has(onTimeout))
  ) {
    errors.push(`${base}.on_timeout must be one of: ${[...VALID_TIMEOUT_BEHAVIORS].join(", ")}`);
  }

  const mode = (value as any).execution_mode;
  if (mode !== undefined && (typeof mode !== "string" || !VALID_EXECUTION_MODES.has(mode))) {
    errors.push(`${base}.execution_mode must be one of: ${[...VALID_EXECUTION_MODES].join(", ")}`);
  }

  if ((value as any).rate_limit !== undefined) {
    if (!isPlainObject((value as any).rate_limit)) {
      errors.push(`${base}.rate_limit must be an object`);
    } else {
      const rl = (value as any).rate_limit as Record<string, unknown>;
      const rps = rl.requests_per_second;
      const rpm = rl.requests_per_minute;
      if (rps !== undefined && (!isFiniteNumber(rps) || rps <= 0)) {
        errors.push(`${base}.rate_limit.requests_per_second must be > 0`);
      }
      if (rpm !== undefined && (!isFiniteNumber(rpm) || rpm <= 0)) {
        errors.push(`${base}.rate_limit.requests_per_minute must be > 0`);
      }
      if (rps !== undefined && rpm !== undefined) {
        errors.push(
          `${base}.rate_limit must specify only one of requests_per_second or requests_per_minute`,
        );
      }
      const burst = rl.burst;
      if (
        burst !== undefined &&
        (typeof burst !== "number" || !Number.isInteger(burst) || burst < 1)
      ) {
        errors.push(`${base}.rate_limit.burst must be >= 1`);
      }
    }
  }

  if ((value as any).cache !== undefined) {
    if (!isPlainObject((value as any).cache)) {
      errors.push(`${base}.cache must be an object`);
    } else {
      const cache = (value as any).cache as Record<string, unknown>;
      const ttl = cache.ttl_seconds;
      if (ttl !== undefined && (typeof ttl !== "number" || !Number.isInteger(ttl) || ttl < 1)) {
        errors.push(`${base}.cache.ttl_seconds must be >= 1`);
      }
      const max = cache.max_size_mb;
      if (max !== undefined && (typeof max !== "number" || !Number.isInteger(max) || max < 1)) {
        errors.push(`${base}.cache.max_size_mb must be >= 1`);
      }
    }
  }

  if ((value as any).circuit_breaker !== undefined) {
    if (!isPlainObject((value as any).circuit_breaker)) {
      errors.push(`${base}.circuit_breaker must be an object`);
    } else {
      const cb = (value as any).circuit_breaker as Record<string, unknown>;
      const f = cb.failure_threshold;
      if (f !== undefined && (typeof f !== "number" || !Number.isInteger(f) || f < 1)) {
        errors.push(`${base}.circuit_breaker.failure_threshold must be >= 1`);
      }
      const reset = cb.reset_timeout_ms;
      if (
        reset !== undefined &&
        (typeof reset !== "number" || !Number.isInteger(reset) || reset < 1000)
      ) {
        errors.push(`${base}.circuit_breaker.reset_timeout_ms must be >= 1000`);
      }
      const s = cb.success_threshold;
      if (s !== undefined && (typeof s !== "number" || !Number.isInteger(s) || s < 1)) {
        errors.push(`${base}.circuit_breaker.success_threshold must be >= 1`);
      }
    }
  }

  if ((value as any).retry !== undefined) {
    if (!isPlainObject((value as any).retry)) {
      errors.push(`${base}.retry must be an object`);
    } else {
      const retry = (value as any).retry as Record<string, unknown>;
      const mult = retry.multiplier;
      if (mult !== undefined && (!isFiniteNumber(mult) || mult < 1)) {
        errors.push(`${base}.retry.multiplier must be >= 1`);
      }
      const init = retry.initial_backoff_ms;
      if (
        init !== undefined &&
        (typeof init !== "number" || !Number.isInteger(init) || init < 100)
      ) {
        errors.push(`${base}.retry.initial_backoff_ms must be >= 100`);
      }
      const max = retry.max_backoff_ms;
      if (max !== undefined && (typeof max !== "number" || !Number.isInteger(max) || max < 100)) {
        errors.push(`${base}.retry.max_backoff_ms must be >= 100`);
      }
      if (typeof init === "number" && typeof max === "number" && max < init) {
        errors.push(`${base}.retry.max_backoff_ms must be >= initial_backoff_ms`);
      }
    }
  }
}

function requireString(obj: Record<string, unknown>, field: string, errors: string[]): void {
  const key = field.split(".").slice(-1)[0] ?? "";
  const value = obj[key];
  if (typeof value !== "string" || value.trim() === "") {
    errors.push(`${field} missing/invalid required string`);
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

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}
