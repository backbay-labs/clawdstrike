import type { Policy } from './schema.js';

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

export function isLegacyOpenClawPolicyV1(value: unknown): value is LegacyOpenClawPolicyV1 {
  if (!isPlainObject(value)) return false;

  const v = (value as any).version;
  if (v === 'clawdstrike-v1.0') return true;

  // Heuristic: common legacy-only keys present with a non-semver or missing version.
  const hasLegacyKeys =
    'filesystem' in value ||
    'egress' in value ||
    'execution' in value ||
    'tools' in value ||
    'limits' in value ||
    'on_violation' in value;

  if (!hasLegacyKeys) return false;

  if (typeof v !== 'string') return true;
  return !isStrictSemver(v);
}

export function translateLegacyOpenClawPolicyV1(
  legacy: LegacyOpenClawPolicyV1,
): { policy: Policy; warnings: string[] } {
  const warnings: string[] = [
    'Loaded legacy OpenClaw policy schema (version: clawdstrike-v1.0); translated to canonical (1.1.0).',
  ];

  const out: Policy = {
    version: '1.1.0',
    // Preserve extends so the canonical loader can resolve it.
    extends: typeof legacy.extends === 'string' ? legacy.extends : undefined,
    guards: {},
  };

  // Preserve custom guards if present (canonical-only feature).
  if (isPlainObject(legacy.guards) && Array.isArray((legacy.guards as any).custom)) {
    (out.guards as any).custom = (legacy.guards as any).custom;
  }

  // Best-effort mapping for overlapping concepts.
  if (isPlainObject(legacy.filesystem)) {
    const forbidden = (legacy.filesystem as any).forbidden_paths;
    if (Array.isArray(forbidden) && forbidden.every((x) => typeof x === 'string')) {
      (out.guards as any).forbidden_path = {
        patterns: forbidden,
      };
    }
  }

  if (isPlainObject(legacy.egress)) {
    const mode = (legacy.egress as any).mode;
    const allowed_domains = (legacy.egress as any).allowed_domains;
    const denied_domains = (legacy.egress as any).denied_domains;
    const allowed_cidrs = (legacy.egress as any).allowed_cidrs;

    if (Array.isArray(allowed_cidrs) && allowed_cidrs.length > 0) {
      warnings.push('Legacy field egress.allowed_cidrs is not supported in canonical schema and will be ignored.');
    }

    const allow =
      Array.isArray(allowed_domains) && allowed_domains.every((x) => typeof x === 'string')
        ? allowed_domains
        : [];
    const block =
      Array.isArray(denied_domains) && denied_domains.every((x) => typeof x === 'string')
        ? denied_domains
        : [];

    if (mode === 'allowlist') {
      (out.guards as any).egress_allowlist = { allow, block, default_action: 'block' };
    } else if (mode === 'denylist') {
      (out.guards as any).egress_allowlist = { allow: [], block, default_action: 'allow' };
    } else if (mode === 'open') {
      (out.guards as any).egress_allowlist = { allow: [], block, default_action: 'allow' };
    } else if (mode === 'deny_all') {
      (out.guards as any).egress_allowlist = { allow: [], block: [], default_action: 'block' };
    }
  }

  if (isPlainObject(legacy.tools)) {
    const allowed = (legacy.tools as any).allowed;
    const denied = (legacy.tools as any).denied;

    const allow =
      Array.isArray(allowed) && allowed.every((x) => typeof x === 'string') ? allowed : [];
    const block =
      Array.isArray(denied) && denied.every((x) => typeof x === 'string') ? denied : [];

    if (allow.length > 0 || block.length > 0) {
      (out.guards as any).mcp_tool = {
        allow,
        block,
        default_action: allow.length > 0 ? 'block' : 'allow',
      };
    }
  }

  // Preserve unknown fields under a namespaced key for debugging, but do not
  // attempt to validate or execute them in the canonical engine.
  (out as any).legacy_openclaw = legacy;

  return { policy: out, warnings };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isStrictSemver(version: string): boolean {
  const m = /^([0-9]|[1-9][0-9]*)\\.([0-9]|[1-9][0-9]*)\\.([0-9]|[1-9][0-9]*)$/.exec(version);
  return Boolean(m);
}
