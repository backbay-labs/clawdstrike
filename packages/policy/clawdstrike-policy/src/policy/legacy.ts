import type { Policy } from "./schema.js";

export type LegacyOpenClawPolicyV1 = {
  version?: unknown;
  extends?: unknown;
  egress?: unknown;
  filesystem?: unknown;
  execution?: unknown;
  tools?: unknown;
  limits?: unknown;
  guards?: unknown;
  on_violation?: unknown;
  [key: string]: unknown;
};

/**
 * Subset of legacy fields we actually consume in the translator. Keeping a
 * narrow shape (instead of `any`) so the translator code reads the same
 * fields the legacy detector heuristically sniffs.
 */
interface NarrowedLegacy {
  version?: string;
  extends?: string;
  guards?: {
    custom?: unknown[];
  };
  filesystem?: {
    forbidden_paths?: string[];
  };
  egress?: {
    mode?: string;
    allowed_domains?: string[];
    denied_domains?: string[];
    allowed_cidrs?: string[];
  };
  tools?: {
    allowed?: string[];
    denied?: string[];
  };
}

export function isLegacyOpenClawPolicyV1(value: unknown): value is LegacyOpenClawPolicyV1 {
  if (!isPlainObject(value)) return false;

  const v = value.version;
  if (v === "clawdstrike-v1.0") return true;

  // Heuristic: common legacy-only keys present with a non-semver or missing version.
  const hasLegacyKeys =
    "filesystem" in value ||
    "egress" in value ||
    "execution" in value ||
    "tools" in value ||
    "limits" in value ||
    "on_violation" in value;

  if (!hasLegacyKeys) return false;

  if (typeof v !== "string") return true;
  return !isStrictSemver(v);
}

export function translateLegacyOpenClawPolicyV1(legacy: LegacyOpenClawPolicyV1): {
  policy: Policy;
  warnings: string[];
} {
  const warnings: string[] = [
    "Loaded legacy OpenClaw policy schema (version: clawdstrike-v1.0); translated to canonical (1.1.0).",
  ];

  const narrowed = narrow(legacy);

  const guards: Record<string, unknown> = {};
  const out: Policy = {
    version: "1.1.0",
    // Preserve extends so the canonical loader can resolve it.
    extends: typeof narrowed.extends === "string" ? narrowed.extends : undefined,
    guards,
  };

  // Preserve custom guards if present (canonical-only feature).
  if (Array.isArray(narrowed.guards?.custom)) {
    guards.custom = narrowed.guards.custom;
  }

  // Best-effort mapping for overlapping concepts.
  if (narrowed.filesystem) {
    const forbidden = narrowed.filesystem.forbidden_paths;
    if (Array.isArray(forbidden) && forbidden.every((x) => typeof x === "string")) {
      guards.forbidden_path = {
        patterns: forbidden,
      };
    }
  }

  if (narrowed.egress) {
    const mode = narrowed.egress.mode;
    const allowed_domains = narrowed.egress.allowed_domains;
    const denied_domains = narrowed.egress.denied_domains;
    const allowed_cidrs = narrowed.egress.allowed_cidrs;

    if (Array.isArray(allowed_cidrs) && allowed_cidrs.length > 0) {
      warnings.push(
        "Legacy field egress.allowed_cidrs is not supported in canonical schema and will be ignored.",
      );
    }

    const allow =
      Array.isArray(allowed_domains) && allowed_domains.every((x) => typeof x === "string")
        ? allowed_domains
        : [];
    const block =
      Array.isArray(denied_domains) && denied_domains.every((x) => typeof x === "string")
        ? denied_domains
        : [];

    if (mode === "allowlist") {
      guards.egress_allowlist = { allow, block, default_action: "block" };
    } else if (mode === "denylist") {
      guards.egress_allowlist = { allow: [], block, default_action: "allow" };
    } else if (mode === "open") {
      guards.egress_allowlist = { allow: [], block, default_action: "allow" };
    } else if (mode === "deny_all") {
      guards.egress_allowlist = { allow: [], block: [], default_action: "block" };
    }
  }

  if (narrowed.tools) {
    const allowed = narrowed.tools.allowed;
    const denied = narrowed.tools.denied;

    const allow =
      Array.isArray(allowed) && allowed.every((x) => typeof x === "string") ? allowed : [];
    const block = Array.isArray(denied) && denied.every((x) => typeof x === "string") ? denied : [];

    if (allow.length > 0 || block.length > 0) {
      guards.mcp_tool = {
        allow,
        block,
        default_action: allow.length > 0 ? "block" : "allow",
      };
    }
  }

  // Preserve unknown fields under a namespaced key for debugging. The
  // canonical Policy schema is `passthrough()` so extra keys round-trip
  // without complaint.
  attachDebugPassthrough(out, legacy);

  return { policy: out, warnings };
}

/**
 * Strip the broad `unknown` shape to the subset we actually read. Avoids
 * `as any` reads at the cost of a few `isPlainObject` checks.
 */
function narrow(legacy: LegacyOpenClawPolicyV1): NarrowedLegacy {
  const out: NarrowedLegacy = {};
  if (typeof legacy.version === "string") out.version = legacy.version;
  if (typeof legacy.extends === "string") out.extends = legacy.extends;

  if (isPlainObject(legacy.guards)) {
    const custom = (legacy.guards as Record<string, unknown>).custom;
    if (Array.isArray(custom)) out.guards = { custom };
  }

  if (isPlainObject(legacy.filesystem)) {
    const fp = (legacy.filesystem as Record<string, unknown>).forbidden_paths;
    out.filesystem = {
      forbidden_paths: stringArrayOrUndefined(fp),
    };
  }

  if (isPlainObject(legacy.egress)) {
    const e = legacy.egress as Record<string, unknown>;
    out.egress = {
      mode: typeof e.mode === "string" ? e.mode : undefined,
      allowed_domains: stringArrayOrUndefined(e.allowed_domains),
      denied_domains: stringArrayOrUndefined(e.denied_domains),
      allowed_cidrs: stringArrayOrUndefined(e.allowed_cidrs),
    };
  }

  if (isPlainObject(legacy.tools)) {
    const t = legacy.tools as Record<string, unknown>;
    out.tools = {
      allowed: stringArrayOrUndefined(t.allowed),
      denied: stringArrayOrUndefined(t.denied),
    };
  }

  return out;
}

function stringArrayOrUndefined(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  return value.filter((v): v is string => typeof v === "string");
}

function attachDebugPassthrough(policy: Policy, legacy: LegacyOpenClawPolicyV1): void {
  // Policy is `passthrough()` so this property survives the round-trip even
  // though it isn't part of the named schema. Use a typed accumulator to
  // avoid `as any`.
  const carrier = policy as Policy & { legacy_openclaw?: unknown };
  carrier.legacy_openclaw = legacy;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStrictSemver(version: string): boolean {
  // Strict X.Y.Z (no leading zeros except `0` itself). Mirrors the regex in
  // schema.zod.ts.
  return /^([0-9]|[1-9][0-9]*)\.([0-9]|[1-9][0-9]*)\.([0-9]|[1-9][0-9]*)$/.test(version);
}
