/**
 * Plugin manifest types and parser.
 *
 * The runtime shape is defined in `manifest.zod.ts`; this file re-exports
 * the inferred types and provides `parsePluginManifest` -- a thin wrapper
 * that produces the prior error-message format from `ZodError.issues`.
 */

import { z } from "zod";

import {
  pluginCapabilitiesSchema,
  pluginGuardEntrySchema,
  pluginManifestSchema,
  pluginResourceLimitsSchema,
  pluginVersionCompatibilitySchema,
} from "./manifest.zod.js";

export type PluginTrustLevel = "trusted" | "untrusted";
export type PluginTrustSandbox = "node" | "wasm";
export type PluginGuardHandle =
  | "file_read"
  | "file_write"
  | "command_exec"
  | "network_egress"
  | "tool_call"
  | "patch_apply"
  | "secret_access"
  | "custom";

export type PluginGuardManifestEntry = z.infer<typeof pluginGuardEntrySchema>;
export type PluginVersionCompatibility = z.infer<typeof pluginVersionCompatibilitySchema>;
export type PluginCapabilities = z.infer<typeof pluginCapabilitiesSchema>;
export type PluginResourceLimits = z.infer<typeof pluginResourceLimitsSchema>;

export interface PluginManifest {
  schema?: string;
  version: string;
  name: string;
  displayName?: string;
  description?: string;
  author?: string;
  license?: string;
  clawdstrike?: PluginVersionCompatibility;
  guards: PluginGuardManifestEntry[];
  capabilities: PluginCapabilities;
  resources: PluginResourceLimits;
  trust: {
    level: PluginTrustLevel;
    sandbox: PluginTrustSandbox;
  };
}

const DEFAULT_CAPABILITIES: PluginCapabilities = {
  network: false,
  subprocess: false,
  filesystem: { read: [], write: false },
  secrets: { access: false },
};

const DEFAULT_RESOURCES: PluginResourceLimits = {
  maxMemoryMb: 64,
  maxCpuMs: 100,
  maxTimeoutMs: 5000,
};

export function parsePluginManifest(value: unknown): PluginManifest {
  if (!isPlainObject(value)) {
    throw new Error("plugin manifest must be an object");
  }

  const result = pluginManifestSchema.safeParse(value);
  if (!result.success) {
    throw new Error(formatManifestIssue(result.error.issues[0]));
  }

  const parsed = result.data;
  const schemaField =
    typeof value.$schema === "string" && value.$schema.trim() !== "" ? value.$schema : undefined;

  return {
    schema: schemaField,
    version: parsed.version,
    name: parsed.name,
    displayName: parsed.displayName,
    description: parsed.description,
    author: parsed.author,
    license: parsed.license,
    clawdstrike: parsed.clawdstrike,
    guards: parsed.guards.map((g) => ({
      name: g.name,
      entrypoint: g.entrypoint,
      handles: g.handles,
      configSchema: g.configSchema,
    })),
    capabilities: parsed.capabilities ?? DEFAULT_CAPABILITIES,
    resources: parsed.resources ?? DEFAULT_RESOURCES,
    trust: parsed.trust,
  };
}

/**
 * Translate a zod issue into the legacy `Error` message format. Existing
 * tests assert on phrases like `/duplicates guard/i` and
 * `/minVersion must be strict semver/i`, so the structure must roughly
 * mirror the old `parseXxx` helper messages.
 */
function formatManifestIssue(issue: z.ZodIssue | undefined): string {
  if (!issue) return "plugin manifest is invalid";

  const prefixParts = ["plugin manifest", ...issue.path.map((p) => String(p))];
  const prefix = prefixParts.join(".");

  switch (issue.code) {
    case "invalid_type":
      return prefixedExpected(prefix, issue);
    case "too_small": {
      const ts = issue as z.ZodTooSmallIssue;
      if (ts.type === "array") {
        return `${prefix} must be a non-empty array`;
      }
      return `${prefix} ${issue.message}`;
    }
    case "invalid_enum_value":
      if (issue.path.includes("level")) {
        return 'plugin manifest.trust.level must be "trusted" or "untrusted"';
      }
      if (issue.path.includes("sandbox")) {
        return 'plugin manifest.trust.sandbox must be "node" or "wasm"';
      }
      return `${prefix} ${issue.message}`;
    case "custom":
      // superRefine issues (e.g. duplicate guard names) carry their final
      // message; just re-emit them with the manifest prefix when useful.
      if (/^duplicates guard/.test(issue.message)) {
        return `${prefix} ${issue.message}`;
      }
      return `${prefix} ${issue.message}`;
    default:
      return `${prefix} ${issue.message}`;
  }
}

function prefixedExpected(prefix: string, issue: z.ZodIssue): string {
  if (issue.code !== "invalid_type") return `${prefix} ${issue.message}`;
  const expected = (issue as z.ZodInvalidTypeIssue).expected;
  if (expected === "object") {
    if (prefix === "plugin manifest") return "plugin manifest must be an object";
    return `${prefix} must be an object`;
  }
  if (expected === "array") return `${prefix} must be a non-empty array`;
  if (expected === "string") return `${prefix} must be a non-empty string`;
  if (expected === "boolean") return `${prefix} must be a boolean when provided`;
  if (expected === "number") return `${prefix} must be a positive integer when provided`;
  return `${prefix} ${issue.message}`;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
