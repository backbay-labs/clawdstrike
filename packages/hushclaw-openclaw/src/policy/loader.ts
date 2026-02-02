import { load as loadYaml } from 'js-yaml';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { resolveBuiltinPolicy } from '../config.js';
import type { Policy } from '../types.js';

import { validatePolicy } from './validator.js';

const RULESETS_DIR = fileURLToPath(new URL('../../rulesets/', import.meta.url));

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
  if (ref.startsWith('hushclaw:')) return ref;
  const candidate = `hushclaw:${ref}`;
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
  let parsed: unknown;
  try {
    parsed = loadYaml(content);
  } catch (err) {
    throw new PolicyLoadError('Failed to parse policy YAML', { cause: err });
  }

  if (!isPlainObject(parsed)) {
    throw new PolicyLoadError('Policy must be a YAML mapping/object');
  }

  return parsed as Policy;
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
  const { id, content, baseDir } = resolvePolicyRef(ref, baseDirForRef(ref, stack));

  if (stack.includes(id)) {
    throw new PolicyLoadError(`Circular policy extends detected: ${[...stack, id].join(' -> ')}`);
  }

  const nextStack = [...stack, id];
  const policy = loadPolicyFromString(content);

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
