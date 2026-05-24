/**
 * Zod schema for plugin manifests (clawdstrike.plugin.json).
 *
 * Replaces the hand-rolled `parsePluginManifest` body. Error messages are
 * translated by `manifest.ts` so historical exception strings remain stable.
 */

import { z } from "zod";

const STRICT_SEMVER_RE = /^(\d+)\.(\d+)\.(\d+)$/;
const SEMVER_WILDCARD_RE = /^(\d+)\.x$/;
const SEMVER_MINOR_WILDCARD_RE = /^(\d+)\.(\d+)\.x$/;

export const PLUGIN_GUARD_HANDLES = [
  "file_read",
  "file_write",
  "command_exec",
  "network_egress",
  "tool_call",
  "patch_apply",
  "secret_access",
  "custom",
] as const;

const nonEmptyStringSchema = z.string().refine((v) => v.trim() !== "", {
  message: "must be a non-empty string",
});

const optionalNonEmptyStringSchema = z
  .union([z.undefined(), nonEmptyStringSchema])
  .transform((v) => (v === undefined ? undefined : v));

const positiveIntSchema = z
  .number()
  .refine((v) => Number.isInteger(v) && v >= 1, { message: "must be a positive integer when provided" });

const strictSemverSchema = z.string().refine((v) => STRICT_SEMVER_RE.test(v), {
  message: "must be strict semver (x.y.z)",
});

const semverRangeSchema = z.string().refine(
  (v) => STRICT_SEMVER_RE.test(v) || SEMVER_WILDCARD_RE.test(v) || SEMVER_MINOR_WILDCARD_RE.test(v),
  { message: "must be semver or wildcard range (e.g. 1.x)" },
);

export const pluginGuardHandleSchema = z.enum(PLUGIN_GUARD_HANDLES);

export const pluginVersionCompatibilitySchema = z
  .object({
    minVersion: strictSemverSchema.optional(),
    maxVersion: semverRangeSchema.optional(),
  })
  .passthrough();

const filesystemReadSchema = z
  .union([z.literal(false), z.array(nonEmptyStringSchema)])
  .transform((v) => (v === false ? [] : v));

export const pluginCapabilitiesSchema = z
  .object({
    network: z.boolean().optional(),
    subprocess: z.boolean().optional(),
    filesystem: z
      .object({
        read: filesystemReadSchema.optional(),
        write: z.boolean().optional(),
      })
      .passthrough()
      .optional(),
    secrets: z
      .union([
        z.boolean(),
        z
          .object({
            access: z.boolean().optional(),
          })
          .passthrough(),
      ])
      .optional(),
  })
  .passthrough()
  .transform((val) => {
    const fs = val.filesystem ?? {};
    const read = (fs.read as string[] | undefined) ?? [];
    const write = fs.write ?? false;
    let secretsAccess = false;
    if (typeof val.secrets === "boolean") {
      secretsAccess = val.secrets;
    } else if (val.secrets && typeof val.secrets === "object") {
      secretsAccess = (val.secrets as { access?: boolean }).access ?? false;
    }
    return {
      network: val.network ?? false,
      subprocess: val.subprocess ?? false,
      filesystem: { read, write },
      secrets: { access: secretsAccess },
    };
  });

export const pluginResourceLimitsSchema = z
  .object({
    maxMemoryMb: positiveIntSchema.optional(),
    maxCpuMs: positiveIntSchema.optional(),
    maxTimeoutMs: positiveIntSchema.optional(),
  })
  .passthrough()
  .transform((val) => ({
    maxMemoryMb: val.maxMemoryMb ?? 64,
    maxCpuMs: val.maxCpuMs ?? 100,
    maxTimeoutMs: val.maxTimeoutMs ?? 5000,
  }));

export const pluginGuardEntrySchema = z
  .object({
    name: nonEmptyStringSchema,
    entrypoint: nonEmptyStringSchema,
    handles: z.array(pluginGuardHandleSchema).optional(),
    configSchema: optionalNonEmptyStringSchema,
  })
  .passthrough();

export const pluginTrustSchema = z
  .object({
    level: z.enum(["trusted", "untrusted"]),
    sandbox: z.enum(["node", "wasm"]).optional(),
  })
  .passthrough()
  .transform((val) => ({
    level: val.level,
    sandbox: (val.sandbox ?? "node") as "node" | "wasm",
  }));

export const pluginManifestSchema = z
  .object({
    $schema: z.string().optional(),
    version: nonEmptyStringSchema,
    name: nonEmptyStringSchema,
    displayName: optionalNonEmptyStringSchema,
    description: optionalNonEmptyStringSchema,
    author: optionalNonEmptyStringSchema,
    license: optionalNonEmptyStringSchema,
    clawdstrike: pluginVersionCompatibilitySchema.optional(),
    guards: z.array(pluginGuardEntrySchema).min(1),
    capabilities: pluginCapabilitiesSchema.optional(),
    resources: pluginResourceLimitsSchema.optional(),
    trust: pluginTrustSchema,
  })
  .passthrough()
  .superRefine((val, ctx) => {
    const names = new Set<string>();
    val.guards.forEach((g, i) => {
      if (names.has(g.name)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `duplicates guard: ${g.name}`,
          path: ["guards", i, "name"],
        });
      } else {
        names.add(g.name);
      }
    });
  });
