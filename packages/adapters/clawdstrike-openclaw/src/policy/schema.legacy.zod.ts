/**
 * Zod schemas mirroring the legacy OpenClaw policy schema (clawdstrike-v1.0).
 *
 * Replaces the body of `validatePolicy` in validator.ts for legacy inputs. The
 * canonical 1.1.0/1.2.0/1.3.0 path still delegates to @clawdstrike/policy's
 * canonical validator.
 *
 * Error messages are translated through `formatLegacyIssue` (see
 * validator.ts) so tests asserting on specific strings stay green.
 */

import { z } from "zod";

export const POLICY_SCHEMA_VERSION = "clawdstrike-v1.0";

export const VALID_EGRESS_MODES = ["allowlist", "denylist", "open", "deny_all"] as const;
export const VALID_VIOLATION_ACTIONS = ["cancel", "warn"] as const;
export const UNIMPLEMENTED_VIOLATION_ACTIONS = ["isolate", "escalate"] as const;
export const VALID_TIMEOUT_BEHAVIORS = ["allow", "deny", "warn", "defer"] as const;
export const VALID_EXECUTION_MODES = ["parallel", "sequential", "background"] as const;
export const VALID_COMPUTER_USE_MODES = ["observe", "guardrail", "fail_closed"] as const;

export const RESERVED_PACKAGES = [
  "clawdstrike-virustotal",
  "clawdstrike-safe-browsing",
  "clawdstrike-snyk",
  "clawdstrike-spider-sense",
] as const;

const integerAtLeast = (min: number) =>
  z
    .number()
    .int()
    .refine((v) => v >= min, { message: `must be >= ${min}` });

const positiveFinite = () =>
  z.number().refine((v) => Number.isFinite(v) && v > 0, { message: "must be > 0" });

const nullByteFreeString = z
  .string()
  .refine((v) => !v.includes("\u0000"), { message: "contains a null byte" });

const positiveNumberSchema = z
  .number()
  .refine((v) => Number.isFinite(v) && v > 0, { message: "must be a positive number" });

const finiteNumberSchema = z
  .number()
  .refine((v) => Number.isFinite(v), { message: "must be a finite number" });

// ---------------------------------------------------------------------------
// Async config (shared with custom guards)
// ---------------------------------------------------------------------------

const asyncRateLimitSchema = z
  .object({
    requests_per_second: positiveFinite().optional(),
    requests_per_minute: positiveFinite().optional(),
    burst: integerAtLeast(1).optional(),
  })
  .passthrough()
  .superRefine((val, ctx) => {
    if (val.requests_per_second !== undefined && val.requests_per_minute !== undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "must specify only one of requests_per_second or requests_per_minute",
        path: [],
      });
    }
  });

const asyncCacheSchema = z
  .object({
    ttl_seconds: integerAtLeast(1).optional(),
    max_size_mb: integerAtLeast(1).optional(),
  })
  .passthrough();

const asyncCircuitBreakerSchema = z
  .object({
    failure_threshold: integerAtLeast(1).optional(),
    reset_timeout_ms: integerAtLeast(1000).optional(),
    success_threshold: integerAtLeast(1).optional(),
  })
  .passthrough();

const asyncRetrySchema = z
  .object({
    initial_backoff_ms: integerAtLeast(100).optional(),
    max_backoff_ms: integerAtLeast(100).optional(),
    multiplier: z
      .number()
      .refine((v) => Number.isFinite(v) && v >= 1, { message: "must be >= 1" })
      .optional(),
  })
  .passthrough()
  .superRefine((val, ctx) => {
    if (
      typeof val.initial_backoff_ms === "number" &&
      typeof val.max_backoff_ms === "number" &&
      val.max_backoff_ms < val.initial_backoff_ms
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "must be >= initial_backoff_ms",
        path: ["max_backoff_ms"],
      });
    }
  });

const asyncConfigSchema = z
  .object({
    timeout_ms: z
      .number()
      .refine((v) => Number.isFinite(v) && v >= 100 && v <= 300_000, {
        message: "must be between 100 and 300000",
      })
      .optional(),
    on_timeout: z.enum(VALID_TIMEOUT_BEHAVIORS).optional(),
    execution_mode: z.enum(VALID_EXECUTION_MODES).optional(),
    cache: asyncCacheSchema.optional(),
    rate_limit: asyncRateLimitSchema.optional(),
    circuit_breaker: asyncCircuitBreakerSchema.optional(),
    retry: asyncRetrySchema.optional(),
  })
  .passthrough();

// ---------------------------------------------------------------------------
// Custom guard spec
// ---------------------------------------------------------------------------

const reservedPackageSchema = z.enum(RESERVED_PACKAGES);

export const customGuardSpecSchema = z
  .object({
    package: z.string().refine((v) => v.trim() !== "", { message: "must be a non-empty string" }),
    enabled: z.boolean().optional(),
    config: z.record(z.string(), z.unknown()).optional(),
    async: asyncConfigSchema.optional(),
  })
  .passthrough()
  .superRefine((val, ctx) => {
    if (!reservedPackageSchema.safeParse(val.package).success) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `unsupported custom guard package: ${val.package}`,
        path: ["package"],
      });
      return;
    }
    const cfg = (val.config ?? {}) as Record<string, unknown>;
    const requireCfgString = (key: string) => {
      const v = cfg[key];
      if (typeof v !== "string" || v.trim() === "") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "missing/invalid required string",
          path: ["config", key],
        });
      }
    };
    if (val.package === "clawdstrike-virustotal") {
      requireCfgString("api_key");
    } else if (val.package === "clawdstrike-safe-browsing") {
      requireCfgString("api_key");
      requireCfgString("client_id");
    } else if (val.package === "clawdstrike-snyk") {
      requireCfgString("api_token");
      requireCfgString("org_id");
    }
  });

// ---------------------------------------------------------------------------
// Policy sub-objects
// ---------------------------------------------------------------------------

export const egressPolicySchema = z
  .object({
    mode: z.enum(VALID_EGRESS_MODES).optional(),
    allowed_domains: z.array(nullByteFreeString).optional(),
    denied_domains: z.array(nullByteFreeString).optional(),
    allowed_cidrs: z.array(nullByteFreeString).optional(),
  })
  .strict();

export const filesystemPolicySchema = z
  .object({
    allowed_write_roots: z.array(nullByteFreeString).optional(),
    allowed_read_paths: z.array(nullByteFreeString).optional(),
    forbidden_paths: z.array(nullByteFreeString).optional(),
  })
  .strict();

export const executionPolicySchema = z
  .object({
    allowed_commands: z.array(nullByteFreeString).optional(),
    denied_patterns: z.array(nullByteFreeString).optional(),
  })
  .strict()
  .superRefine((val, ctx) => {
    if (Array.isArray(val.denied_patterns)) {
      val.denied_patterns.forEach((p, i) => {
        try {
          // eslint-disable-next-line no-new
          new RegExp(p);
        } catch {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `execution.denied_patterns contains invalid regex: ${p}`,
            path: ["denied_patterns", i],
          });
        }
      });
    }
  });

export const toolsPolicySchema = z
  .object({
    allowed: z.array(nullByteFreeString).optional(),
    denied: z.array(nullByteFreeString).optional(),
    require_confirmation: z.array(nullByteFreeString).optional(),
    default_action: z.enum(["allow", "block"]).optional(),
  })
  .strict();

export const limitsSchema = z
  .object({
    max_execution_seconds: positiveNumberSchema.optional(),
    max_memory_mb: positiveNumberSchema.optional(),
    max_output_bytes: positiveNumberSchema.optional(),
  })
  .strict();

export const computerUseGuardSchema = z
  .object({
    enabled: z.boolean().optional(),
    mode: z.enum(VALID_COMPUTER_USE_MODES).optional(),
    allowed_actions: z.array(nullByteFreeString).optional(),
  })
  .strict();

export const remoteDesktopSideChannelSchema = z
  .object({
    enabled: z.boolean().optional(),
    clipboard_enabled: z.boolean().optional(),
    file_transfer_enabled: z.boolean().optional(),
    audio_enabled: z.boolean().optional(),
    drive_mapping_enabled: z.boolean().optional(),
    printing_enabled: z.boolean().optional(),
    session_share_enabled: z.boolean().optional(),
    max_transfer_size_bytes: finiteNumberSchema.optional(),
  })
  .strict()
  .superRefine((val, ctx) => {
    if (typeof val.max_transfer_size_bytes === "number" && val.max_transfer_size_bytes < 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "must be >= 0",
        path: ["max_transfer_size_bytes"],
      });
    }
  });

export const inputInjectionCapabilityGuardSchema = z
  .object({
    enabled: z.boolean().optional(),
    allowed_input_types: z.array(nullByteFreeString).optional(),
    require_postcondition_probe: z.boolean().optional(),
  })
  .strict();

export const guardsLegacySchema = z
  .object({
    forbidden_path: z.boolean().optional(),
    egress: z.boolean().optional(),
    secret_leak: z.boolean().optional(),
    patch_integrity: z.boolean().optional(),
    mcp_tool: z.boolean().optional(),
    custom: z.array(customGuardSpecSchema).optional(),
    computer_use: computerUseGuardSchema.optional(),
    remote_desktop_side_channel: remoteDesktopSideChannelSchema.optional(),
    input_injection_capability: inputInjectionCapabilityGuardSchema.optional(),
    spider_sense: z.union([z.boolean(), z.record(z.string(), z.unknown())]).optional(),
  })
  .strict();

// ---------------------------------------------------------------------------
// Root policy
// ---------------------------------------------------------------------------

function isSpiderSenseCustomGuard(value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const pkg = (value as { package?: unknown }).package;
  return typeof pkg === "string" && pkg.trim().toLowerCase() === "clawdstrike-spider-sense";
}

export const legacyPolicySchema = z
  .object({
    version: z.string().optional(),
    extends: z.string().optional(),
    egress: egressPolicySchema.optional(),
    filesystem: filesystemPolicySchema.optional(),
    execution: executionPolicySchema.optional(),
    tools: toolsPolicySchema.optional(),
    limits: limitsSchema.optional(),
    guards: guardsLegacySchema.optional(),
    on_violation: z.string().optional(),
  })
  .strict()
  .superRefine((val, ctx) => {
    // version is required
    if (val.version === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `version is required (expected: ${POLICY_SCHEMA_VERSION})`,
        path: ["version"],
      });
    } else if (
      val.version !== POLICY_SCHEMA_VERSION &&
      !["1.1.0", "1.2.0", "1.3.0"].includes(val.version)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `unsupported policy version: ${val.version} (supported: ${POLICY_SCHEMA_VERSION}, 1.1.0, 1.2.0, 1.3.0)`,
        path: ["version"],
      });
    }

    // Legacy spider_sense executability checks
    if (val.version === POLICY_SCHEMA_VERSION && val.guards) {
      const spiderSense = val.guards.spider_sense;
      const custom = val.guards.custom;
      const hasSpiderSenseCustom =
        Array.isArray(custom) && custom.some((c) => isSpiderSenseCustomGuard(c));
      if (typeof spiderSense === "object" && spiderSense !== null && !Array.isArray(spiderSense)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            'guards.spider_sense object is not executable in clawdstrike-v1.0; use guards.custom package "clawdstrike-spider-sense" or canonical 1.3.0',
          path: ["guards", "spider_sense"],
        });
      } else if (spiderSense === true && !hasSpiderSenseCustom) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            'guards.spider_sense: true is not executable in clawdstrike-v1.0 without guards.custom package "clawdstrike-spider-sense"',
          path: ["guards", "spider_sense"],
        });
      }
    }

    // on_violation validation
    if (val.on_violation !== undefined) {
      const v = val.on_violation;
      if (
        !VALID_VIOLATION_ACTIONS.includes(v as never) &&
        !UNIMPLEMENTED_VIOLATION_ACTIONS.includes(v as never)
      ) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `on_violation must be one of: ${VALID_VIOLATION_ACTIONS.join(", ")}`,
          path: ["on_violation"],
        });
      }
    }
  });

// ---------------------------------------------------------------------------
// Warning collector (zod only emits errors)
// ---------------------------------------------------------------------------

type ParsedLegacyPolicy = z.infer<typeof legacyPolicySchema>;

export function collectLegacyWarnings(policy: ParsedLegacyPolicy): string[] {
  const warnings: string[] = [];

  if (policy.egress?.mode === "allowlist") {
    const allowed = policy.egress.allowed_domains ?? [];
    if (allowed.length === 0) {
      warnings.push("egress.allowlist with empty allowed_domains will deny all egress");
    }
  }

  if (policy.filesystem?.forbidden_paths !== undefined) {
    if (policy.filesystem.forbidden_paths.length === 0) {
      warnings.push("filesystem.forbidden_paths is empty");
    }
  }

  const cu = policy.guards?.computer_use;
  if (cu?.allowed_actions !== undefined && cu.allowed_actions.length === 0) {
    warnings.push("guards.computer_use.allowed_actions is empty (all actions allowed)");
  }

  const ii = policy.guards?.input_injection_capability;
  if (ii?.allowed_input_types !== undefined && ii.allowed_input_types.length === 0) {
    warnings.push(
      "guards.input_injection_capability.allowed_input_types is empty (all input types allowed)",
    );
  }

  if (typeof policy.on_violation === "string") {
    if (UNIMPLEMENTED_VIOLATION_ACTIONS.includes(policy.on_violation as never)) {
      warnings.push(
        `on_violation value '${policy.on_violation}' is not yet implemented; use 'cancel' or 'warn'`,
      );
    }
  }

  return warnings;
}
