import fs from 'node:fs';
import path from 'node:path';

import { load as loadYaml } from 'js-yaml';

import type { GuardConfigs, MergeStrategy, Policy } from './schema.js';
import { isLegacyOpenClawPolicyV1, translateLegacyOpenClawPolicyV1 } from './legacy.js';
import { validatePolicy } from './validator.js';

export interface PolicyLoadOptions {
  resolve?: boolean;
  basePath?: string;
  rulesetsDir?: string;
  onWarning?: (message: string) => void;
}

const DEFAULT_RULESETS = new Set(['default', 'strict', 'ai-agent', 'cicd', 'permissive']);
const DEFAULT_POLICY_VERSION = '1.2.0';

export function loadPolicyFromFile(filePath: string, options: PolicyLoadOptions = {}): Policy {
  const absPath = path.resolve(filePath);
  const yaml = fs.readFileSync(absPath, 'utf8');
  const basePath = path.dirname(absPath);
  return loadPolicyFromString(yaml, { ...options, basePath });
}

export function loadPolicyFromString(yaml: string, options: PolicyLoadOptions = {}): Policy {
  const resolve = options.resolve !== false;
  const basePath = options.basePath ?? process.cwd();
  const rulesetsDir = options.rulesetsDir ?? path.join(process.cwd(), 'rulesets');
  const onWarning = options.onWarning;

  const visited = extractVisited(options) ?? new Set<string>();
  const policy = loadPolicyFromStringInternal(yaml, { resolve, basePath, rulesetsDir, onWarning, visited });

  const lint = validatePolicy(policy);
  if (!lint.valid) {
    const msg = lint.errors.join('; ') || 'policy validation failed';
    throw new Error(msg);
  }

  return policy;
}

function extractVisited(options: PolicyLoadOptions): Set<string> | null {
  const maybe = (options as any).visited as unknown;
  return maybe instanceof Set ? maybe : null;
}

function loadPolicyFromStringInternal(
  yaml: string,
  options: { resolve: boolean; basePath: string; rulesetsDir: string; onWarning?: (message: string) => void; visited: Set<string> },
): Policy {
  const parsed = loadYaml(yaml) as unknown;
  if (!isPlainObject(parsed)) {
    throw new Error('Policy must be an object');
  }

  const child = normalizeToCanonical(parsed, options.onWarning);
  if (!options.resolve || !child.extends) {
    return child;
  }

  const baseRef = String(child.extends);
  if (options.visited.has(baseRef)) {
    throw new Error(`Circular policy extension detected: ${baseRef}`);
  }
  options.visited.add(baseRef);

  const basePolicy = loadBasePolicy(baseRef, options);
  const merged = mergePolicy(basePolicy, child, child.merge_strategy ?? 'deep_merge');
  // Prevent re-processing.
  delete merged.extends;
  delete merged.merge_strategy;
  return merged;
}

function normalizeToCanonical(value: unknown, onWarning: ((message: string) => void) | undefined): Policy {
  if (isLegacyOpenClawPolicyV1(value)) {
    const { policy, warnings } = translateLegacyOpenClawPolicyV1(value);
    for (const w of warnings) {
      if (onWarning) {
        onWarning(w);
      } else {
        console.warn(w);
      }
    }
    return policy;
  }
  return value as Policy;
}

function loadBasePolicy(
  baseRef: string,
  options: { resolve: boolean; basePath: string; rulesetsDir: string; onWarning?: (message: string) => void; visited: Set<string> },
): Policy {
  // Built-in rulesets: clawdstrike:<id> or <id>.
  const id = baseRef.startsWith('clawdstrike:') ? baseRef.slice('clawdstrike:'.length) : baseRef;
  if (DEFAULT_RULESETS.has(id)) {
    const rulesetPath = path.join(options.rulesetsDir, `${id}.yaml`);
    if (fs.existsSync(rulesetPath)) {
      return loadPolicyFromFile(rulesetPath, options);
    }
  }

  const resolved = path.isAbsolute(baseRef) ? baseRef : path.join(options.basePath, baseRef);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Unknown ruleset or file not found: ${baseRef}`);
  }
  return loadPolicyFromFile(resolved, options);
}

function mergePolicy(base: Policy, child: Policy, strategy: MergeStrategy): Policy {
  if (strategy === 'replace') {
    return { ...child };
  }

  if (strategy === 'merge') {
    const out: Policy = { ...base };
    if (child.version && child.version !== DEFAULT_POLICY_VERSION) out.version = child.version;
    if (child.name) out.name = child.name;
    if (child.description) out.description = child.description;
    if (child.guards) out.guards = child.guards;
    if (Array.isArray((child as any).custom_guards) && (child as any).custom_guards.length > 0) {
      (out as any).custom_guards = (child as any).custom_guards;
    }
    if (child.settings) out.settings = child.settings;
    return out;
  }

  // deep_merge
  const out: Policy = { ...base };
  if (child.version && child.version !== DEFAULT_POLICY_VERSION) out.version = child.version;
  if (child.name) out.name = child.name;
  if (child.description) out.description = child.description;

  out.settings = {
    ...base.settings,
    ...child.settings,
  };

  out.guards = mergeGuards(base.guards, child.guards);
  (out as any).custom_guards = mergePolicyCustomGuards(
    (base as any).custom_guards,
    (child as any).custom_guards,
  );

  return out;
}

function mergeGuards(base: unknown, child: unknown): GuardConfigs | undefined {
  if (!isPlainObject(base) && !isPlainObject(child)) {
    return isPlainObject(child) ? (child as GuardConfigs) : isPlainObject(base) ? (base as GuardConfigs) : undefined;
  }

  const baseObj = (isPlainObject(base) ? base : {}) as GuardConfigs;
  const childObj = (isPlainObject(child) ? child : {}) as GuardConfigs;

  const out: GuardConfigs = { ...baseObj, ...childObj };

  const childCustom = Array.isArray(childObj.custom) ? childObj.custom : undefined;
  const baseCustom = Array.isArray(baseObj.custom) ? baseObj.custom : undefined;
  if (childCustom && childCustom.length > 0) {
    out.custom = childCustom;
  } else if (baseCustom) {
    out.custom = baseCustom;
  }

  return out;
}

function mergePolicyCustomGuards(base: unknown, child: unknown): unknown {
  const baseArr = Array.isArray(base) ? base : [];
  const childArr = Array.isArray(child) ? child : [];

  if (childArr.length === 0) return base;
  if (baseArr.length === 0) return child;

  const out = [...baseArr];
  const index = new Map<string, number>();

  for (let i = 0; i < out.length; i++) {
    const cg = out[i];
    const id = isPlainObject(cg) ? (cg as any).id : undefined;
    if (typeof id === 'string') {
      index.set(id, i);
    }
  }

  for (const cg of childArr) {
    const id = isPlainObject(cg) ? (cg as any).id : undefined;
    if (typeof id === 'string' && index.has(id)) {
      out[index.get(id)!] = cg;
    } else {
      if (typeof id === 'string') {
        index.set(id, out.length);
      }
      out.push(cg);
    }
  }

  return out;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
