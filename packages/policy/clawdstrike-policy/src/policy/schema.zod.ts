/**
 * Zod schemas mirroring the canonical Clawdstrike policy shape (versions 1.1.0,
 * 1.2.0, 1.3.0). These schemas are the single source of truth for the
 * `Policy` type and runtime validation. The previous hand-rolled validator
 * (validator.ts) is replaced by `validatePolicy(policy)` which delegates here.
 *
 * IMPORTANT: tests assert exact error message strings. `formatIssue` (see
 * validator.ts) translates `z.ZodIssue` to the historical message format. When
 * adjusting schemas, also update `formatIssue` accordingly.
 *
 * Zod cannot emit warnings, so non-fatal advisories (e.g. spider_sense 1.3
 * fields used in a 1.2 policy, empty allowed_domains lists) are collected in a
 * separate post-parse pass (`collectWarnings`).
 */

import { z } from "zod";

// ---------------------------------------------------------------------------
// Constants shared with validator helpers
// ---------------------------------------------------------------------------

export const SUPPORTED_POLICY_VERSIONS = ["1.1.0", "1.2.0", "1.3.0"] as const;
export const DEFAULT_POLICY_VERSION = "1.2.0";

export const RESERVED_PACKAGES = [
  "clawdstrike-virustotal",
  "clawdstrike-safe-browsing",
  "clawdstrike-snyk",
  "clawdstrike-spider-sense",
] as const;

export const SPIDER_SENSE_V13_FIELDS = [
  "llm_prompt_template_id",
  "llm_prompt_template_version",
  "pattern_db_manifest_path",
  "pattern_db_manifest_trust_store_path",
  "pattern_db_manifest_trusted_keys",
] as const;

export const KNOWN_POSTURE_CAPABILITIES = [
  "file_access",
  "file_write",
  "egress",
  "shell",
  "mcp_tool",
  "patch",
  "custom",
] as const;

export const KNOWN_POSTURE_BUDGETS = [
  "file_writes",
  "egress_calls",
  "shell_commands",
  "mcp_tool_calls",
  "patches",
  "custom_calls",
] as const;

const STRICT_SEMVER_RE = /^([0-9]|[1-9][0-9]*)\.([0-9]|[1-9][0-9]*)\.([0-9]|[1-9][0-9]*)$/;
const DURATION_RE = /^[0-9]+[smh]$/;

// ---------------------------------------------------------------------------
// Primitive / helper schemas
// ---------------------------------------------------------------------------

const nonEmptyStringSchema = z.string().refine((v) => v.trim() !== "", {
  message: "must be a non-empty string",
});

const stringArraySchema = z.array(z.string());

const strictSemverSchema = z.string().regex(STRICT_SEMVER_RE);

const durationSchema = z.string().regex(DURATION_RE);

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

export const policySchemaVersionSchema = z.enum(SUPPORTED_POLICY_VERSIONS);
export const timeoutBehaviorSchema = z.enum(["allow", "deny", "warn", "defer"]);
export const asyncExecutionModeSchema = z.enum(["parallel", "sequential", "background"]);
export const mergeStrategySchema = z.enum(["replace", "merge", "deep_merge"]);
export const transitionTriggerSchema = z.enum([
  "user_approval",
  "user_denial",
  "critical_violation",
  "any_violation",
  "timeout",
  "budget_exhausted",
  "pattern_match",
]);

// ---------------------------------------------------------------------------
// Async subsystem
// ---------------------------------------------------------------------------

const integerAtLeast = (min: number) =>
  z
    .number()
    .int()
    .refine((v) => v >= min, { message: `must be >= ${min}` });

const positiveFinite = () =>
  z.number().refine((v) => Number.isFinite(v) && v > 0, { message: "must be > 0" });

export const asyncCachePolicyConfigSchema = z
  .object({
    enabled: z.boolean().optional(),
    ttl_seconds: integerAtLeast(1).optional(),
    max_size_mb: integerAtLeast(1).optional(),
  })
  .passthrough();

export const asyncRateLimitPolicyConfigSchema = z
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

export const asyncCircuitBreakerPolicyConfigSchema = z
  .object({
    failure_threshold: integerAtLeast(1).optional(),
    reset_timeout_ms: integerAtLeast(1000).optional(),
    success_threshold: integerAtLeast(1).optional(),
  })
  .passthrough();

export const asyncRetryPolicyConfigSchema = z
  .object({
    max_retries: z.number().int().optional(),
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

export const asyncGuardPolicyConfigSchema = z
  .object({
    timeout_ms: z
      .number()
      .refine((v) => Number.isFinite(v) && v >= 100 && v <= 300_000, {
        message: "must be between 100 and 300000",
      })
      .optional(),
    on_timeout: timeoutBehaviorSchema.optional(),
    execution_mode: asyncExecutionModeSchema.optional(),
    cache: asyncCachePolicyConfigSchema.optional(),
    rate_limit: asyncRateLimitPolicyConfigSchema.optional(),
    circuit_breaker: asyncCircuitBreakerPolicyConfigSchema.optional(),
    retry: asyncRetryPolicyConfigSchema.optional(),
  })
  .passthrough();

// ---------------------------------------------------------------------------
// Custom guard specs (guards.custom)
// ---------------------------------------------------------------------------

const reservedPackageSchema = z.enum(RESERVED_PACKAGES);

// We split the "pkg must be string" vs "pkg must be reserved" checks so the
// historical messages can be reproduced by formatIssue.
const customGuardConfigSchema = z.record(z.string(), z.unknown());

export const customGuardSpecSchema = z
  .object({
    package: nonEmptyStringSchema,
    registry: z.string().optional(),
    version: z.string().optional(),
    enabled: z.boolean().optional(),
    config: customGuardConfigSchema.optional(),
    async: asyncGuardPolicyConfigSchema.optional(),
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
    // Per-package required config keys.
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
// Path allowlist guard config
// ---------------------------------------------------------------------------

export const pathAllowlistConfigSchema = z
  .object({
    enabled: z.boolean().optional(),
    file_access_allow: stringArraySchema.optional(),
    file_write_allow: stringArraySchema.optional(),
    patch_allow: stringArraySchema.optional(),
  })
  .passthrough();

// ---------------------------------------------------------------------------
// Spider-sense guard config
// ---------------------------------------------------------------------------

const spiderSenseRetrySchema = z
  .object({
    honor_retry_after: z.boolean().optional(),
    retry_after_cap_ms: integerAtLeast(1).optional(),
    honor_rate_limit_reset: z.boolean().optional(),
    rate_limit_reset_grace_ms: integerAtLeast(0).optional(),
  })
  .passthrough();

const spiderSenseAsyncSchema = asyncGuardPolicyConfigSchema.and(
  z.object({ retry: spiderSenseRetrySchema.optional() }).passthrough(),
);

export const spiderSenseConfigSchema = z
  .object({
    llm_prompt_template_id: nonEmptyStringSchema.optional(),
    llm_prompt_template_version: nonEmptyStringSchema.optional(),
    llm_api_url: z.string().optional(),
    llm_api_key: z.string().optional(),
    llm_model: z.string().optional(),
    pattern_db_manifest_path: z.string().optional(),
    pattern_db_manifest_trust_store_path: z.string().optional(),
    pattern_db_manifest_trusted_keys: z.array(z.unknown()).optional(),
    pattern_db_trust_store_path: z.string().optional(),
    pattern_db_trusted_keys: z.array(z.unknown()).optional(),
    async: spiderSenseAsyncSchema.optional(),
  })
  .passthrough()
  .superRefine((val, ctx) => {
    const templateId = val.llm_prompt_template_id;
    const templateVersion = val.llm_prompt_template_version;
    if ((templateId === undefined) !== (templateVersion === undefined)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "llm_prompt_template_id and llm_prompt_template_version must be set together",
        path: [],
      });
    }

    const hasStr = (v: unknown): v is string => typeof v === "string" && v.trim() !== "";
    const llmConfigured = hasStr(val.llm_api_url) || hasStr(val.llm_api_key) || hasStr(val.llm_model);
    if (llmConfigured && (templateId === undefined || templateVersion === undefined)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "deep-path configuration requires llm_prompt_template_id and llm_prompt_template_version",
        path: [],
      });
    }

    const manifestPath = val.pattern_db_manifest_path;
    const manifestRootsPath = val.pattern_db_manifest_trust_store_path;
    const manifestRootsInline = val.pattern_db_manifest_trusted_keys;
    const hasManifestPath = hasStr(manifestPath);
    const hasManifestRootsPath = hasStr(manifestRootsPath);
    const hasManifestRootsInline = Array.isArray(manifestRootsInline) && manifestRootsInline.length > 0;

    if (manifestPath !== undefined && !hasStr(manifestPath)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "must be a non-empty string",
        path: ["pattern_db_manifest_path"],
      });
    }
    if (manifestRootsPath !== undefined && !hasStr(manifestRootsPath)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "must be a non-empty string",
        path: ["pattern_db_manifest_trust_store_path"],
      });
    }

    if (hasManifestPath) {
      if (val.pattern_db_trust_store_path !== undefined || val.pattern_db_trusted_keys !== undefined) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "pattern_db_manifest_path cannot be combined with pattern_db_trust_store_path or pattern_db_trusted_keys",
          path: ["pattern_db_manifest_path"],
        });
      }
      if (!hasManifestRootsPath && !hasManifestRootsInline) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "pattern_db_manifest_path requires pattern_db_manifest_trust_store_path or pattern_db_manifest_trusted_keys",
          path: ["pattern_db_manifest_path"],
        });
      }
    } else if (manifestRootsPath !== undefined || manifestRootsInline !== undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "pattern_db_manifest_trust_store_path and pattern_db_manifest_trusted_keys require pattern_db_manifest_path",
        path: [],
      });
    }
  });

// guards.spider_sense accepts boolean shorthand OR object.
const spiderSenseGuardSchema = z.union([z.boolean(), spiderSenseConfigSchema]);

// ---------------------------------------------------------------------------
// guards.* — accept passthrough so non-validated child guards (forbidden_path,
// egress_allowlist, etc.) round-trip without loss.
// ---------------------------------------------------------------------------

export const guardConfigsSchema = z
  .object({
    path_allowlist: pathAllowlistConfigSchema.optional(),
    custom: z.array(customGuardSpecSchema).optional(),
    spider_sense: spiderSenseGuardSchema.optional(),
  })
  .passthrough();

// ---------------------------------------------------------------------------
// settings / posture
// ---------------------------------------------------------------------------

export const policySettingsSchema = z
  .object({
    fail_fast: z.boolean().optional(),
    verbose_logging: z.boolean().optional(),
    session_timeout_secs: z.number().optional(),
  })
  .passthrough();

export const postureStateSchema = z
  .object({
    description: z.string().optional(),
    capabilities: z.array(z.string()).optional(),
    budgets: z.record(z.string(), z.number()).optional(),
  })
  .passthrough();

const transitionRequirementSchema = z.object({ no_violations_in: durationSchema }).passthrough();

export const postureTransitionSchema = z
  .object({
    from: nonEmptyStringSchema,
    to: nonEmptyStringSchema,
    on: transitionTriggerSchema,
    after: z.string().optional(),
    requires: z.array(transitionRequirementSchema).optional(),
  })
  .passthrough()
  .superRefine((val, ctx) => {
    if (val.to === "*") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "wildcard in 'to' not allowed",
        path: ["to"],
      });
    }
    if (val.on === "timeout") {
      if (typeof val.after !== "string") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "timeout transition missing 'after' duration",
          path: ["after"],
        });
      } else if (!DURATION_RE.test(val.after)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `invalid duration format: '${val.after}'`,
          path: ["after"],
        });
      }
    }
  });

export const postureConfigSchema = z
  .object({
    initial: nonEmptyStringSchema,
    states: z.record(z.string(), postureStateSchema),
    transitions: z.array(postureTransitionSchema).optional(),
  })
  .passthrough()
  .superRefine((val, ctx) => {
    const stateNames = new Set(Object.keys(val.states ?? {}));
    if (stateNames.size === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "must be a non-empty object",
        path: ["states"],
      });
      return;
    }

    // Capability / budget allow-list checks.
    for (const [stateName, state] of Object.entries(val.states ?? {})) {
      const caps = (state as { capabilities?: unknown }).capabilities;
      if (Array.isArray(caps)) {
        caps.forEach((cap, i) => {
          if (typeof cap === "string" && !KNOWN_POSTURE_CAPABILITIES.includes(cap as never)) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              message: `unknown capability: '${cap}'`,
              path: ["states", stateName, "capabilities", i],
            });
          }
        });
      }
      const budgets = (state as { budgets?: unknown }).budgets;
      if (budgets && typeof budgets === "object" && !Array.isArray(budgets)) {
        for (const [budgetName, budgetValue] of Object.entries(budgets as Record<string, unknown>)) {
          if (!KNOWN_POSTURE_BUDGETS.includes(budgetName as never)) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              message: `unknown budget type: '${budgetName}'`,
              path: ["states", stateName, "budgets", budgetName],
            });
          }
          if (
            typeof budgetValue !== "number" ||
            !Number.isInteger(budgetValue) ||
            budgetValue < 0
          ) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              message: `budget '${budgetName}' cannot be negative`,
              path: ["states", stateName, "budgets", budgetName],
            });
          }
        }
      }
    }

    if (!stateNames.has(val.initial)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `posture.initial '${val.initial}' not found in states`,
        path: ["initial"],
      });
    }
    if (Array.isArray(val.transitions)) {
      val.transitions.forEach((t, i) => {
        if (typeof t.from === "string" && t.from !== "*" && !stateNames.has(t.from)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `transition references unknown state: '${t.from}'`,
            path: ["transitions", i, "from"],
          });
        }
        if (typeof t.to === "string" && t.to !== "*" && !stateNames.has(t.to)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `transition references unknown state: '${t.to}'`,
            path: ["transitions", i, "to"],
          });
        }
      });
    }
  });

// ---------------------------------------------------------------------------
// custom_guards (Policy-level, separate from guards.custom)
// ---------------------------------------------------------------------------

export const policyCustomGuardSpecSchema = z
  .object({
    id: nonEmptyStringSchema,
    enabled: z.boolean().optional(),
    config: z.record(z.string(), z.unknown()).optional(),
  })
  .passthrough();

// ---------------------------------------------------------------------------
// Root policy
// ---------------------------------------------------------------------------

export const policySchema = z
  .object({
    version: strictSemverSchema.optional(),
    name: z.string().optional(),
    description: z.string().optional(),
    extends: z.string().optional(),
    merge_strategy: mergeStrategySchema.optional(),
    guards: guardConfigsSchema.optional(),
    custom_guards: z.array(policyCustomGuardSpecSchema).optional(),
    settings: policySettingsSchema.optional(),
    posture: postureConfigSchema.optional(),
  })
  .passthrough()
  .superRefine((val, ctx) => {
    const version = val.version ?? DEFAULT_POLICY_VERSION;
    if (!SUPPORTED_POLICY_VERSIONS.includes(version as never)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `unsupported policy version: ${version} (supported: 1.1.0, 1.2.0, 1.3.0)`,
        path: ["version"],
      });
    }

    // path_allowlist requires >=1.2.0
    if (version === "1.1.0" && val.guards && val.guards.path_allowlist !== undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "path_allowlist requires policy version 1.2.0",
        path: ["guards", "path_allowlist"],
      });
    }

    // posture requires >=1.2.0
    if (version === "1.1.0" && val.posture !== undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "posture requires policy version 1.2.0",
        path: ["posture"],
      });
    }

    // Duplicate custom_guards[].id
    if (Array.isArray(val.custom_guards)) {
      const seen = new Set<string>();
      val.custom_guards.forEach((cg, i) => {
        const id = (cg as { id?: unknown }).id;
        if (typeof id === "string") {
          if (seen.has(id)) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              message: `duplicate custom guard id: ${id}`,
              path: ["custom_guards", i, "id"],
            });
          } else {
            seen.add(id);
          }
        }
      });
    }
  });

// ---------------------------------------------------------------------------
// Warning collector (zod only emits errors)
// ---------------------------------------------------------------------------

type ParsedPolicy = z.infer<typeof policySchema>;

export function collectWarnings(policy: ParsedPolicy): string[] {
  const warnings: string[] = [];
  const version = policy.version ?? DEFAULT_POLICY_VERSION;
  const spiderSense = (policy.guards as { spider_sense?: unknown } | undefined)?.spider_sense;
  if (
    version === "1.2.0" &&
    spiderSense &&
    typeof spiderSense === "object" &&
    !Array.isArray(spiderSense)
  ) {
    const ss = spiderSense as Record<string, unknown>;
    const usedV13Field = SPIDER_SENSE_V13_FIELDS.some((key) => ss[key] !== undefined);
    if (usedV13Field) {
      warnings.push(
        "guards.spider_sense uses 1.3.0 fields while policy version is 1.2.0; accepted for compatibility",
      );
    }
  }
  return warnings;
}
