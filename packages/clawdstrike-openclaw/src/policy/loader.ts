import { load as loadYaml } from 'js-yaml';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Policy as CanonicalPolicy } from '@clawdstrike/policy';
import {
  loadPolicyFromFile as loadCanonicalPolicyFromFile,
  loadPolicyFromString as loadCanonicalPolicyFromString,
} from '@clawdstrike/policy';

import { resolveBuiltinPolicy } from '../config.js';
import type { Policy } from '../types.js';

import { validatePolicy } from './validator.js';

const RULESETS_DIR = fileURLToPath(new URL('../../rulesets/', import.meta.url));
const CANONICAL_RULESETS_DIR = fileURLToPath(new URL('../../../../rulesets/', import.meta.url));

export class PolicyLoadError extends Error {
  readonly cause?: unknown;

  constructor(message: string, opts?: { cause?: unknown }) {
    super(message);
    this.name = 'PolicyLoadError';
    this.cause = opts?.cause;
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isBuiltinRef(ref: string): string | null {
  if (!ref) return null;
  if (ref.startsWith('clawdstrike:')) return ref;
  const candidate = `clawdstrike:${ref}`;
  return resolveBuiltinPolicy(candidate) ? candidate : null;
}

function deepMerge(base: any, overlay: any): any {
  if (!isPlainObject(base) || !isPlainObject(overlay)) return overlay;

  const out: Record<string, unknown> = { ...base };

  for (const [key, value] of Object.entries(overlay)) {
    if (value === undefined) continue;

    const existing = (out as any)[key];

    if (isPlainObject(existing) && isPlainObject(value)) {
      (out as any)[key] = deepMerge(existing, value);
      continue;
    }

    // Arrays and scalars replace.
    (out as any)[key] = value;
  }

  return out;
}

export function loadPolicyFromString(content: string): Policy {
  const parsed = parseYamlObject(content);
  if (isCanonicalPolicy(parsed)) {
    const canonical = loadCanonicalPolicyFromString(content, {
      resolve: false,
      rulesetsDir: CANONICAL_RULESETS_DIR,
      onWarning: warnLegacyCompatibility,
    });
    return translateCanonicalPolicy(canonical);
  }

  const policy = parsed as Policy;
  if (policy.version === 'clawdstrike-v1.0') {
    warnLegacyCompatibility(
      'Loaded legacy OpenClaw policy schema (clawdstrike-v1.0); canonical 1.2.0 is preferred.',
    );
  }
  return policy;
}

function readPolicyFile(policyPath: string): string {
  try {
    return readFileSync(policyPath, 'utf-8');
  } catch (err) {
    throw new PolicyLoadError(`Failed to read policy file: ${policyPath}`, { cause: err });
  }
}

function resolvePolicyRef(ref: string, baseDir?: string): { id: string; path?: string; content: string; baseDir?: string } {
  const builtin = isBuiltinRef(ref);
  if (builtin) {
    const fileName = resolveBuiltinPolicy(builtin);
    if (!fileName) {
      throw new PolicyLoadError(`Unknown built-in policy: ${builtin}`);
    }

    const filePath = path.join(RULESETS_DIR, fileName);
    return {
      id: `builtin:${builtin}`,
      path: filePath,
      content: readPolicyFile(filePath),
      baseDir: path.dirname(filePath),
    };
  }

  const resolvedPath = baseDir ? path.resolve(baseDir, ref) : path.resolve(ref);
  return {
    id: `file:${resolvedPath}`,
    path: resolvedPath,
    content: readPolicyFile(resolvedPath),
    baseDir: path.dirname(resolvedPath),
  };
}

function normalizeExtendsRef(ref: string, baseDir?: string): string {
  const builtin = isBuiltinRef(ref);
  if (builtin) return builtin;
  if (baseDir) return path.resolve(baseDir, ref);
  return ref;
}

function loadPolicyRecursive(ref: string, stack: string[]): Policy {
  const resolved = resolvePolicyRef(ref, baseDirForRef(ref, stack));
  const { id, content, baseDir, path: policyPath } = resolved;

  if (stack.includes(id)) {
    throw new PolicyLoadError(`Circular policy extends detected: ${[...stack, id].join(' -> ')}`);
  }

  const nextStack = [...stack, id];
  const parsed = parseYamlObject(content);
  if (isCanonicalPolicy(parsed)) {
    const canonical = policyPath
      ? loadCanonicalPolicyFromFile(policyPath, {
        resolve: true,
        rulesetsDir: CANONICAL_RULESETS_DIR,
        onWarning: warnLegacyCompatibility,
      })
      : loadCanonicalPolicyFromString(content, {
        resolve: true,
        basePath: baseDir,
        rulesetsDir: CANONICAL_RULESETS_DIR,
        onWarning: warnLegacyCompatibility,
      });

    const translated = translateCanonicalPolicy(canonical);
    const report = validatePolicy(translated);
    if (!report.valid) {
      throw new PolicyLoadError(`Policy validation failed:\n- ${report.errors.join('\n- ')}`);
    }
    return translated;
  }

  const policy = parsed as Policy;
  if (policy.version === 'clawdstrike-v1.0') {
    warnLegacyCompatibility(
      'Loaded legacy OpenClaw policy schema (clawdstrike-v1.0); canonical 1.2.0 is preferred.',
    );
  }

  const extendsRef = typeof policy.extends === 'string' ? policy.extends.trim() : undefined;
  if (!extendsRef) {
    const report = validatePolicy(policy);
    if (!report.valid) {
      throw new PolicyLoadError(`Policy validation failed:\n- ${report.errors.join('\n- ')}`);
    }
    return policy;
  }

  const parentRef = normalizeExtendsRef(extendsRef, baseDir);
  const parent = loadPolicyRecursive(parentRef, nextStack);

  const merged = deepMerge(parent, { ...policy, extends: undefined });

  const report = validatePolicy(merged);
  if (!report.valid) {
    throw new PolicyLoadError(`Policy validation failed:\n- ${report.errors.join('\n- ')}`);
  }

  return merged;
}

function baseDirForRef(ref: string, stack: string[]): string | undefined {
  // If we're resolving an extends chain and the last frame was a file, resolve
  // relative paths from that file's directory.
  const last = stack[stack.length - 1];
  if (!last) return undefined;

  if (last.startsWith('file:')) {
    const lastPath = last.slice('file:'.length);
    return path.dirname(lastPath);
  }

  // Built-in policies don't define a baseDir for relative file extends.
  return undefined;
}

export function loadPolicy(ref: string): Policy {
  if (!ref) {
    throw new PolicyLoadError('Policy reference must be non-empty');
  }

  return loadPolicyRecursive(ref, []);
}

function parseYamlObject(content: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = loadYaml(content);
  } catch (err) {
    throw new PolicyLoadError('Failed to parse policy YAML', { cause: err });
  }

  if (!isPlainObject(parsed)) {
    throw new PolicyLoadError('Policy must be a YAML mapping/object');
  }

  return parsed as Record<string, unknown>;
}

function isCanonicalPolicy(policy: Record<string, unknown>): boolean {
  const version = policy.version;
  return typeof version === 'string' && /^(1\.1\.0|1\.2\.0)$/.test(version);
}

function warnLegacyCompatibility(message: string): void {
  // eslint-disable-next-line no-console
  console.warn(message);
}

function translateCanonicalPolicy(canonical: CanonicalPolicy): Policy {
  const out: Policy = {
    version: 'clawdstrike-v1.0',
  };

  const guards = canonical.guards as Record<string, any> | undefined;
  const toggles: Record<string, boolean> = {};
  if (guards) {
    if (typeof guards.forbidden_path === 'object') {
      const cfg = guards.forbidden_path as Record<string, unknown>;
      toggles.forbidden_path = cfg.enabled !== false;
      if (Array.isArray(cfg.patterns) && cfg.patterns.length > 0) {
        out.filesystem = out.filesystem ?? {};
        out.filesystem.forbidden_paths = cfg.patterns.filter((v): v is string => typeof v === 'string');
      }
    }

    if (typeof guards.path_allowlist === 'object') {
      const cfg = guards.path_allowlist as Record<string, unknown>;
      out.filesystem = out.filesystem ?? {};
      if (Array.isArray(cfg.file_access_allow)) {
        out.filesystem.allowed_read_paths = cfg.file_access_allow.filter((v): v is string => typeof v === 'string');
      }
      if (Array.isArray(cfg.file_write_allow)) {
        out.filesystem.allowed_write_roots = cfg.file_write_allow.filter((v): v is string => typeof v === 'string');
      }
    }

    if (typeof guards.egress_allowlist === 'object') {
      const cfg = guards.egress_allowlist as Record<string, unknown>;
      toggles.egress = cfg.enabled !== false;
      const allow = Array.isArray(cfg.allow) ? cfg.allow.filter((v): v is string => typeof v === 'string') : [];
      const block = Array.isArray(cfg.block) ? cfg.block.filter((v): v is string => typeof v === 'string') : [];
      const defaultAction = cfg.default_action === 'allow' ? 'allow' : 'block';
      out.egress = {
        mode: defaultAction === 'allow' && allow.includes('*') ? 'open' : allow.length === 0 && defaultAction === 'block' ? 'deny_all' : 'allowlist',
        allowed_domains: allow.filter((v) => v !== '*'),
        denied_domains: block,
      };
    }

    if (typeof guards.patch_integrity === 'object') {
      const cfg = guards.patch_integrity as Record<string, unknown>;
      toggles.patch_integrity = cfg.enabled !== false;
      if (Array.isArray(cfg.forbidden_patterns) && cfg.forbidden_patterns.length > 0) {
        out.execution = out.execution ?? {};
        out.execution.denied_patterns = cfg.forbidden_patterns.filter((v): v is string => typeof v === 'string');
      }
    }

    if (typeof guards.secret_leak === 'object') {
      const cfg = guards.secret_leak as Record<string, unknown>;
      toggles.secret_leak = cfg.enabled !== false;
    }

    if (typeof guards.mcp_tool === 'object') {
      const cfg = guards.mcp_tool as Record<string, unknown>;
      toggles.mcp_tool = cfg.enabled !== false;
      out.tools = {
        allowed: Array.isArray(cfg.allow) ? cfg.allow.filter((v): v is string => typeof v === 'string') : [],
        denied: Array.isArray(cfg.block) ? cfg.block.filter((v): v is string => typeof v === 'string') : [],
      };
    }

    if (Array.isArray((guards as any).custom)) {
      out.guards = {
        ...out.guards,
        custom: (guards as any).custom,
      };
    }
  }

  if (Object.keys(toggles).length > 0) {
    out.guards = {
      ...(out.guards ?? {}),
      ...toggles,
    };
  }

  return out;
}
