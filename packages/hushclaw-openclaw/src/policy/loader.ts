/**
 * @hushclaw/openclaw - Policy Loader
 *
 * Load and parse YAML policy files.
 */

import { readFileSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { load as loadYaml } from 'js-yaml';
import type { Policy } from '../types.js';
import { isBuiltinPolicy, resolveBuiltinPolicy } from '../config.js';

// Get package root for resolving builtin policies
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PACKAGE_ROOT = resolve(__dirname, '..', '..');
const RULESETS_DIR = resolve(PACKAGE_ROOT, 'rulesets');

/**
 * Load a policy from a file path or built-in name
 *
 * @param policyPath - File path or built-in policy name (e.g., 'hushclaw:ai-agent-minimal')
 * @returns Parsed policy object
 */
export function loadPolicy(policyPath: string): Policy {
  const resolvedPath = resolvePolicyPath(policyPath);

  if (!existsSync(resolvedPath)) {
    throw new PolicyLoadError(`Policy file not found: ${resolvedPath}`);
  }

  try {
    const content = readFileSync(resolvedPath, 'utf-8');
    const policy = parseYaml(content);

    // Handle policy inheritance
    if (policy.extends) {
      const basePolicy = loadPolicy(policy.extends);
      return mergePolicy(basePolicy, policy);
    }

    return policy;
  } catch (error) {
    if (error instanceof PolicyLoadError) {
      throw error;
    }
    throw new PolicyLoadError(
      `Failed to load policy from ${resolvedPath}: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * Resolve a policy path or name to an absolute file path
 */
export function resolvePolicyPath(policyPath: string): string {
  // Handle built-in policies
  if (isBuiltinPolicy(policyPath)) {
    const filename = resolveBuiltinPolicy(policyPath);
    if (!filename) {
      throw new PolicyLoadError(`Unknown built-in policy: ${policyPath}`);
    }
    return resolve(RULESETS_DIR, filename);
  }

  // Handle relative/absolute paths
  if (policyPath.startsWith('/')) {
    return policyPath;
  }

  // Relative to current working directory
  return resolve(process.cwd(), policyPath);
}

/**
 * Parse YAML content into a Policy object
 */
function parseYaml(content: string): Policy {
  const parsed = loadYaml(content);

  if (!parsed || typeof parsed !== 'object') {
    throw new PolicyLoadError('Invalid policy format: expected object');
  }

  return parsed as Policy;
}

/**
 * Merge a base policy with an extending policy
 */
function mergePolicy(base: Policy, extension: Policy): Policy {
  return {
    version: extension.version ?? base.version,
    // Don't propagate extends from base
    egress: mergeEgress(base.egress, extension.egress),
    filesystem: mergeFilesystem(base.filesystem, extension.filesystem),
    execution: mergeExecution(base.execution, extension.execution),
    tools: mergeTools(base.tools, extension.tools),
    limits: { ...base.limits, ...extension.limits },
    guards: { ...base.guards, ...extension.guards },
    on_violation: extension.on_violation ?? base.on_violation,
  };
}

/**
 * Merge egress policies
 */
function mergeEgress(
  base: Policy['egress'],
  ext: Policy['egress'],
): Policy['egress'] {
  if (!base && !ext) return undefined;
  if (!base) return ext;
  if (!ext) return base;

  return {
    mode: ext.mode ?? base.mode,
    allowed_domains: [
      ...(base.allowed_domains ?? []),
      ...(ext.allowed_domains ?? []),
    ],
    allowed_cidrs: [
      ...(base.allowed_cidrs ?? []),
      ...(ext.allowed_cidrs ?? []),
    ],
    denied_domains: [
      ...(base.denied_domains ?? []),
      ...(ext.denied_domains ?? []),
    ],
  };
}

/**
 * Merge filesystem policies
 */
function mergeFilesystem(
  base: Policy['filesystem'],
  ext: Policy['filesystem'],
): Policy['filesystem'] {
  if (!base && !ext) return undefined;
  if (!base) return ext;
  if (!ext) return base;

  return {
    allowed_write_roots: [
      ...(base.allowed_write_roots ?? []),
      ...(ext.allowed_write_roots ?? []),
    ],
    forbidden_paths: [
      ...(base.forbidden_paths ?? []),
      ...(ext.forbidden_paths ?? []),
    ],
    allowed_read_paths: [
      ...(base.allowed_read_paths ?? []),
      ...(ext.allowed_read_paths ?? []),
    ],
  };
}

/**
 * Merge execution policies
 */
function mergeExecution(
  base: Policy['execution'],
  ext: Policy['execution'],
): Policy['execution'] {
  if (!base && !ext) return undefined;
  if (!base) return ext;
  if (!ext) return base;

  return {
    allowed_commands: [
      ...(base.allowed_commands ?? []),
      ...(ext.allowed_commands ?? []),
    ],
    denied_patterns: [
      ...(base.denied_patterns ?? []),
      ...(ext.denied_patterns ?? []),
    ],
  };
}

/**
 * Merge tool policies
 */
function mergeTools(
  base: Policy['tools'],
  ext: Policy['tools'],
): Policy['tools'] {
  if (!base && !ext) return undefined;
  if (!base) return ext;
  if (!ext) return base;

  return {
    allowed: [
      ...(base.allowed ?? []),
      ...(ext.allowed ?? []),
    ],
    denied: [
      ...(base.denied ?? []),
      ...(ext.denied ?? []),
    ],
  };
}

/**
 * Error thrown when policy loading fails
 */
export class PolicyLoadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PolicyLoadError';
  }
}
