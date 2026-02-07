/**
 * Unified Clawdstrike SDK entry point.
 *
 * This module provides the main `Clawdstrike` class that serves as a single
 * entry point for 80% of use cases. It offers:
 * - Simple check API for common security checks
 * - Session management for stateful operations
 * - Framework integration helpers
 *
 * @example Basic usage
 * ```typescript
 * import { Clawdstrike } from '@clawdstrike/sdk';
 *
 * const cs = await Clawdstrike.fromPolicy('./policy.yaml');
 *
 * const decision = await cs.checkFile('/etc/passwd', 'read');
 * if (decision.status === 'deny') {
 *   console.error('Access denied:', decision.message);
 * }
 * ```
 *
 * @example With defaults
 * ```typescript
 * const cs = Clawdstrike.withDefaults('strict');
 * ```
 *
 * @example Session-based usage
 * ```typescript
 * const session = cs.session({ userId: 'user-123' });
 * await session.check('read_file', { path: '/etc/passwd' });
 * const summary = session.getSummary();
 * ```
 *
 * @packageDocumentation
 */

import { EgressAllowlistGuard } from './guards/egress-allowlist.js';
import { ForbiddenPathGuard } from './guards/forbidden-path.js';
import { McpToolGuard } from './guards/mcp-tool.js';
import { PatchIntegrityGuard } from './guards/patch-integrity.js';
import { SecretLeakGuard } from './guards/secret-leak.js';
import { GuardAction, GuardContext, Severity } from './guards/types.js';
import type { Guard, GuardResult } from './guards/types.js';
import type { EgressAllowlistConfig } from './guards/egress-allowlist.js';
import type { ForbiddenPathConfig } from './guards/forbidden-path.js';
import type { McpToolConfig } from './guards/mcp-tool.js';
import type { PatchIntegrityConfig } from './guards/patch-integrity.js';
import type { SecretLeakConfig } from './guards/secret-leak.js';

// ============================================================
// Types
// ============================================================

/**
 * Decision status for security checks.
 */
export type DecisionStatus = 'allow' | 'warn' | 'deny';

/**
 * Severity level for security violations.
 */
export type { Severity };

/**
 * Decision returned from policy evaluation.
 */
export interface Decision {
  /** The decision status: 'allow', 'warn', or 'deny' */
  status: DecisionStatus;
  /** Name of the guard that made this decision */
  guard?: string;
  /** Severity level of the violation */
  severity?: Severity;
  /** Human-readable message describing the decision */
  message?: string;
  /** Additional reason for the decision */
  reason?: string;
  /** Additional structured details */
  details?: unknown;
}

/**
 * Options for creating a Clawdstrike session.
 */
export interface SessionOptions {
  /** Unique session identifier */
  sessionId?: string;
  /** User identifier */
  userId?: string;
  /** Agent identifier */
  agentId?: string;
  /** Working directory context */
  cwd?: string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Summary of a session's security activity.
 */
export interface SessionSummary {
  sessionId: string;
  checkCount: number;
  allowCount: number;
  warnCount: number;
  denyCount: number;
  blockedActions: string[];
  duration: number;
}

/**
 * Preset ruleset levels for common use cases.
 */
export type Ruleset = 'loose' | 'moderate' | 'strict' | 'enterprise';

/**
 * Configuration for Clawdstrike.
 */
export interface ClawdstrikeConfig {
  /** Policy object or path */
  policy?: PolicySpec;
  /** Guards to use */
  guards?: Guard[];
  /** Ruleset preset */
  ruleset?: Ruleset;
  /** Fail on first deny */
  failFast?: boolean;
  /** Working directory */
  cwd?: string;
  /** Optional daemon-backed evaluation */
  daemon?: DaemonConfig;
}

/**
 * Policy specification - can be a path, URL, or inline object.
 */
export type PolicySpec = string | Record<string, unknown>;

interface PolicySettings {
  fail_fast?: boolean;
}

interface PolicyDoc {
  extends?: string;
  guards?: Record<string, unknown>;
  settings?: PolicySettings;
  merge_strategy?: 'replace' | 'merge' | 'deep_merge';
}

interface DaemonConfig {
  url: string;
  apiKey?: string;
}

interface DaemonCheckRequest {
  action_type: string;
  target: string;
  content?: string;
  args?: Record<string, unknown>;
  session_id?: string;
  agent_id?: string;
}

interface DaemonCheckResponse {
  allowed: boolean;
  guard: string;
  severity: string;
  message: string;
  details?: unknown;
}

type BuiltinPolicyId = 'default' | 'strict' | 'ai-agent' | 'cicd' | 'permissive';

/**
 * Generic tool set type for framework integration.
 */
export type ToolSet = Record<string, unknown>;

/**
 * Tool interceptor for framework integration.
 */
export interface ToolInterceptor {
  beforeExecute(
    toolName: string,
    input: unknown,
    context: ClawdstrikeSession,
  ): Promise<{ proceed: boolean; decision: Decision }>;
  afterExecute(
    toolName: string,
    input: unknown,
    output: unknown,
    context: ClawdstrikeSession,
  ): Promise<{ output: unknown; modified: boolean }>;
}

// ============================================================
// Internal helpers
// ============================================================

function createId(prefix: string): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `${prefix}_${timestamp}_${random}`;
}

function guardResultToDecision(result: GuardResult): Decision {
  let status: DecisionStatus;
  if (!result.allowed) {
    status = 'deny';
  } else if (result.severity === Severity.WARNING) {
    status = 'warn';
  } else {
    status = 'allow';
  }

  return {
    status,
    guard: result.guard,
    severity: result.severity,
    message: result.message,
    details: result.details,
  };
}

function allowDecision(guard?: string): Decision {
  return {
    status: 'allow',
    guard,
    severity: Severity.INFO,
    message: 'Allowed',
  };
}

const RULESET_TO_POLICY: Record<Ruleset, BuiltinPolicyId> = {
  loose: 'permissive',
  moderate: 'default',
  strict: 'strict',
  enterprise: 'strict',
};

const BUILTIN_POLICIES: Record<BuiltinPolicyId, PolicyDoc> = {
  default: {
    guards: {
      forbidden_path: {
        patterns: [
          '**/.ssh/**',
          '**/id_rsa*',
          '**/id_ed25519*',
          '**/id_ecdsa*',
          '**/.aws/**',
          '**/.env',
          '**/.env.*',
          '**/.git-credentials',
          '**/.gitconfig',
          '**/.gnupg/**',
          '**/.kube/**',
          '**/.docker/**',
          '**/.npmrc',
          '**/.password-store/**',
          '**/pass/**',
          '**/.1password/**',
          '/etc/shadow',
          '/etc/passwd',
          '/etc/sudoers',
        ],
        exceptions: [],
      },
      egress_allowlist: {
        allow: [
          '*.openai.com',
          '*.anthropic.com',
          'api.github.com',
          'github.com',
          '*.githubusercontent.com',
          '*.npmjs.org',
          'registry.npmjs.org',
          'pypi.org',
          'files.pythonhosted.org',
          'crates.io',
          'static.crates.io',
        ],
        block: [],
        default_action: 'block',
      },
      patch_integrity: {
        max_additions: 1000,
        max_deletions: 500,
        require_balance: false,
        max_imbalance_ratio: 10,
        forbidden_patterns: [
          '(?i)disable[_\\-]?(security|auth|ssl|tls)',
          '(?i)skip[_\\-]?(verify|validation|check)',
          '(?i)rm\\s+-rf\\s+/',
          '(?i)chmod\\s+777',
        ],
      },
      mcp_tool: {
        allow: [],
        block: ['shell_exec', 'run_command', 'raw_file_write', 'raw_file_delete'],
        require_confirmation: ['file_write', 'file_delete', 'git_push'],
        default_action: 'allow',
        max_args_size: 1024 * 1024,
      },
    },
    settings: {
      fail_fast: false,
    },
  },
  strict: {
    guards: {
      forbidden_path: {
        patterns: [
          '**/.ssh/**',
          '**/id_rsa*',
          '**/id_ed25519*',
          '**/id_ecdsa*',
          '**/.aws/**',
          '**/.env',
          '**/.env.*',
          '**/.git-credentials',
          '**/.gitconfig',
          '**/.gnupg/**',
          '**/.kube/**',
          '**/.docker/**',
          '**/.npmrc',
          '**/.password-store/**',
          '**/pass/**',
          '**/.1password/**',
          '/etc/shadow',
          '/etc/passwd',
          '/etc/sudoers',
          '**/.vault/**',
          '**/.secrets/**',
          '**/credentials/**',
          '**/private/**',
        ],
        exceptions: [],
      },
      egress_allowlist: {
        allow: [],
        block: [],
        default_action: 'block',
      },
      patch_integrity: {
        max_additions: 500,
        max_deletions: 200,
        require_balance: true,
        max_imbalance_ratio: 5,
        forbidden_patterns: [
          '(?i)disable[_\\-]?(security|auth|ssl|tls)',
          '(?i)skip[_\\-]?(verify|validation|check)',
          '(?i)rm\\s+-rf\\s+/',
          '(?i)chmod\\s+777',
          '(?i)eval\\s*\\(',
          '(?i)exec\\s*\\(',
          '(?i)reverse[_\\-]?shell',
          '(?i)bind[_\\-]?shell',
        ],
      },
      mcp_tool: {
        allow: ['read_file', 'list_directory', 'search', 'grep'],
        block: [],
        require_confirmation: [],
        default_action: 'block',
        max_args_size: 512 * 1024,
      },
    },
    settings: {
      fail_fast: true,
    },
  },
  'ai-agent': {
    extends: 'clawdstrike:default',
    guards: {
      forbidden_path: {
        exceptions: ['**/.env.example', '**/.env.template'],
      },
      egress_allowlist: {
        allow: [
          '*.openai.com',
          '*.anthropic.com',
          'api.together.xyz',
          '*.fireworks.ai',
          'api.github.com',
          'github.com',
          '*.githubusercontent.com',
          'gitlab.com',
          'api.gitlab.com',
          'bitbucket.org',
          'api.bitbucket.org',
          '*.npmjs.org',
          'registry.npmjs.org',
          'registry.yarnpkg.com',
          'pypi.org',
          'files.pythonhosted.org',
          'crates.io',
          'static.crates.io',
          'rubygems.org',
          'packagist.org',
          'docs.rs',
          '*.readthedocs.io',
          '*.readthedocs.org',
          'developer.mozilla.org',
        ],
        block: [],
        default_action: 'block',
      },
      patch_integrity: {
        max_additions: 2000,
        max_deletions: 1000,
        require_balance: false,
        max_imbalance_ratio: 20,
        forbidden_patterns: [
          '(?i)disable[_\\-]?(security|auth|ssl|tls)',
          '(?i)rm\\s+-rf\\s+/',
          '(?i)chmod\\s+777',
          '(?i)reverse[_\\-]?shell',
        ],
      },
      mcp_tool: {
        allow: [],
        block: ['shell_exec', 'run_command'],
        require_confirmation: ['git_push', 'deploy', 'publish'],
        default_action: 'allow',
        max_args_size: 2 * 1024 * 1024,
      },
    },
    settings: {
      fail_fast: false,
    },
  },
  cicd: {
    extends: 'clawdstrike:default',
    guards: {
      forbidden_path: {
        patterns: [
          '**/.github/secrets/**',
          '**/.gitlab-ci-secrets/**',
          '**/.circleci/secrets/**',
          '**/.ssh/**',
          '**/id_rsa*',
          '**/id_ed25519*',
          '**/.aws/**',
          '**/.gnupg/**',
          '/etc/shadow',
          '/etc/passwd',
        ],
        exceptions: ['**/.github/workflows/**', '**/.gitlab-ci.yml', '**/.circleci/config.yml'],
      },
      egress_allowlist: {
        allow: [
          '*.npmjs.org',
          'registry.npmjs.org',
          'registry.yarnpkg.com',
          'pypi.org',
          'files.pythonhosted.org',
          'crates.io',
          'static.crates.io',
          'rubygems.org',
          'packagist.org',
          'proxy.golang.org',
          'storage.googleapis.com',
          '*.docker.io',
          '*.docker.com',
          '*.gcr.io',
          'ghcr.io',
          '*.ecr.aws',
          'github.com',
          'api.github.com',
          '*.githubusercontent.com',
          'gitlab.com',
          'api.gitlab.com',
          'gradle.org',
          'plugins.gradle.org',
          'repo.maven.apache.org',
        ],
        block: [],
        default_action: 'block',
      },
      patch_integrity: {
        max_additions: 5000,
        max_deletions: 2500,
        require_balance: false,
        max_imbalance_ratio: 50,
        forbidden_patterns: [
          '(?i)disable[_\\-]?(security|auth|ssl|tls)',
          '(?i)rm\\s+-rf\\s+/',
          '(?i)chmod\\s+777',
        ],
      },
      mcp_tool: {
        allow: ['read_file', 'write_file', 'list_directory', 'run_tests', 'build'],
        block: ['shell_exec', 'deploy_production'],
        require_confirmation: [],
        default_action: 'block',
        max_args_size: 5 * 1024 * 1024,
      },
    },
    settings: {
      fail_fast: true,
    },
  },
  permissive: {
    guards: {
      egress_allowlist: {
        allow: ['*'],
        block: [],
        default_action: 'allow',
      },
      patch_integrity: {
        max_additions: 10000,
        max_deletions: 5000,
        require_balance: false,
        max_imbalance_ratio: 50,
      },
    },
    settings: {
      fail_fast: false,
    },
  },
};

function daemonFailureDecision(message: string): Decision {
  return {
    status: 'deny',
    guard: 'daemon',
    severity: Severity.ERROR,
    message,
  };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function toStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) {
    return undefined;
  }
  return value.filter((item): item is string => typeof item === 'string');
}

function toBoolean(value: unknown): boolean | undefined {
  if (typeof value === 'boolean') {
    return value;
  }
  return undefined;
}

function toNumber(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  return undefined;
}

function compilePolicyRegex(pattern: string): RegExp {
  let source = pattern;
  let flags = '';

  const inlineFlags = source.match(/^\(\?([a-z]+)\)/i);
  if (inlineFlags) {
    const rawFlags = inlineFlags[1].toLowerCase();
    if (rawFlags.includes('i')) flags += 'i';
    if (rawFlags.includes('m')) flags += 'm';
    if (rawFlags.includes('s')) flags += 's';
    source = source.slice(inlineFlags[0].length);
  }

  return new RegExp(source, flags);
}

function toForbiddenPathConfig(value: unknown): ForbiddenPathConfig | undefined {
  if (!isPlainObject(value)) {
    return undefined;
  }
  return {
    patterns: toStringArray(value.patterns),
    exceptions: toStringArray(value.exceptions),
  };
}

function toEgressAllowlistConfig(value: unknown): EgressAllowlistConfig | undefined {
  if (!isPlainObject(value)) {
    return undefined;
  }
  const defaultAction = value.default_action === 'allow' ? 'allow' : value.default_action === 'block' ? 'block' : undefined;
  return {
    allow: toStringArray(value.allow),
    block: toStringArray(value.block),
    defaultAction,
  };
}

function toPatchIntegrityConfig(value: unknown): PatchIntegrityConfig | undefined {
  if (!isPlainObject(value)) {
    return undefined;
  }
  const forbiddenPatterns = Array.isArray(value.forbidden_patterns)
    ? value.forbidden_patterns
      .filter((pattern): pattern is string => typeof pattern === 'string')
      .map((pattern) => compilePolicyRegex(pattern))
    : undefined;
  return {
    maxAdditions: toNumber(value.max_additions),
    maxDeletions: toNumber(value.max_deletions),
    requireBalance: toBoolean(value.require_balance),
    maxImbalanceRatio: toNumber(value.max_imbalance_ratio),
    forbiddenPatterns,
  };
}

function toMcpToolConfig(value: unknown): McpToolConfig | undefined {
  if (!isPlainObject(value)) {
    return undefined;
  }
  const defaultAction = value.default_action === 'allow' ? 'allow' : value.default_action === 'block' ? 'block' : undefined;
  return {
    allow: toStringArray(value.allow),
    block: toStringArray(value.block),
    requireConfirmation: toStringArray(value.require_confirmation),
    defaultAction,
    maxArgsSize: toNumber(value.max_args_size),
  };
}

function toSecretLeakConfig(value: unknown): SecretLeakConfig | undefined {
  if (!isPlainObject(value)) {
    return undefined;
  }
  return {
    secrets: toStringArray(value.secrets),
    enabled: toBoolean(value.enabled),
  };
}

function isGuardEnabled(value: unknown): boolean {
  if (!isPlainObject(value)) {
    return false;
  }
  return value.enabled !== false;
}

function buildGuardsFromPolicy(policy: PolicyDoc): Guard[] {
  const guards: Guard[] = [];
  const guardConfigs = policy.guards;

  if (!guardConfigs) {
    return guards;
  }

  const forbiddenPathConfig = isGuardEnabled(guardConfigs.forbidden_path)
    ? toForbiddenPathConfig(guardConfigs.forbidden_path)
    : undefined;
  if (forbiddenPathConfig) {
    guards.push(new ForbiddenPathGuard(forbiddenPathConfig));
  }

  const egressAllowlistConfig = isGuardEnabled(guardConfigs.egress_allowlist)
    ? toEgressAllowlistConfig(guardConfigs.egress_allowlist)
    : undefined;
  if (egressAllowlistConfig) {
    guards.push(new EgressAllowlistGuard(egressAllowlistConfig));
  }

  const patchIntegrityConfig = isGuardEnabled(guardConfigs.patch_integrity)
    ? toPatchIntegrityConfig(guardConfigs.patch_integrity)
    : undefined;
  if (patchIntegrityConfig) {
    guards.push(new PatchIntegrityGuard(patchIntegrityConfig));
  }

  const mcpToolConfig = isGuardEnabled(guardConfigs.mcp_tool)
    ? toMcpToolConfig(guardConfigs.mcp_tool)
    : undefined;
  if (mcpToolConfig) {
    guards.push(new McpToolGuard(mcpToolConfig));
  }

  const secretLeakConfig = isGuardEnabled(guardConfigs.secret_leak)
    ? toSecretLeakConfig(guardConfigs.secret_leak)
    : undefined;
  if (secretLeakConfig) {
    guards.push(new SecretLeakGuard(secretLeakConfig));
  }

  return guards;
}

function parseSeverity(value: string): Severity {
  switch (value.toLowerCase()) {
    case 'warning':
      return Severity.WARNING;
    case 'error':
      return Severity.ERROR;
    case 'critical':
      return Severity.CRITICAL;
    default:
      return Severity.INFO;
  }
}

function isDaemonCheckResponse(value: unknown): value is DaemonCheckResponse {
  return (
    isPlainObject(value) &&
    typeof value.allowed === 'boolean' &&
    typeof value.guard === 'string' &&
    typeof value.severity === 'string' &&
    typeof value.message === 'string'
  );
}

function daemonResponseToDecision(response: DaemonCheckResponse): Decision {
  const severity = parseSeverity(response.severity);
  return {
    status: !response.allowed ? 'deny' : severity === Severity.WARNING ? 'warn' : 'allow',
    guard: response.guard,
    severity,
    message: response.message,
    details: response.details,
  };
}

function clonePolicy(policy: PolicyDoc): PolicyDoc {
  return JSON.parse(JSON.stringify(policy)) as PolicyDoc;
}

function mergePolicies(base: PolicyDoc, child: PolicyDoc): PolicyDoc {
  if (child.merge_strategy === 'replace') {
    return clonePolicy(child);
  }

  const merged: PolicyDoc = {
    ...base,
    ...child,
    settings: {
      ...(base.settings ?? {}),
      ...(child.settings ?? {}),
    },
  };

  if (child.merge_strategy === 'merge') {
    if (!child.guards && base.guards) {
      merged.guards = base.guards;
    }
    return merged;
  }

  const mergedGuards: Record<string, unknown> = {
    ...(base.guards ?? {}),
    ...(child.guards ?? {}),
  };

  merged.guards = mergedGuards;
  delete merged.extends;
  delete merged.merge_strategy;
  return merged;
}

function resolveBuiltinPolicyId(ref: string): BuiltinPolicyId | undefined {
  const trimmed = ref.trim().toLowerCase();
  const normalized = trimmed.startsWith('clawdstrike:') ? trimmed.slice('clawdstrike:'.length) : trimmed;
  const withoutExt = normalized.endsWith('.yaml') ? normalized.slice(0, -'.yaml'.length) : normalized;
  if (withoutExt === 'default') return 'default';
  if (withoutExt === 'strict') return 'strict';
  if (withoutExt === 'ai-agent') return 'ai-agent';
  if (withoutExt === 'cicd') return 'cicd';
  if (withoutExt === 'permissive') return 'permissive';
  return undefined;
}

async function loadPolicyFromSource(policyRefOrYaml: string): Promise<PolicyDoc> {
  const filePolicy = await tryLoadPolicyFromFile(policyRefOrYaml);
  if (filePolicy) {
    return filePolicy;
  }

  const builtinPolicyId = resolveBuiltinPolicyId(policyRefOrYaml);
  if (builtinPolicyId) {
    return resolvePolicyExtends(clonePolicy(BUILTIN_POLICIES[builtinPolicyId]), process.cwd(), new Set<string>());
  }

  const policy = await parsePolicyYaml(policyRefOrYaml, 'inline policy');
  return resolvePolicyExtends(policy, process.cwd(), new Set<string>());
}

async function parsePolicyYaml(yaml: string, source: string): Promise<PolicyDoc> {
  const { load } = await import('js-yaml');
  const parsed = load(yaml);
  if (!isPlainObject(parsed)) {
    throw new Error(`Invalid policy document in ${source}: expected an object`);
  }
  return parsed as PolicyDoc;
}

async function tryLoadPolicyFromFile(policyRef: string): Promise<PolicyDoc | null> {
  if (policyRef.includes('\n')) {
    return null;
  }

  const path = await import('node:path');
  const fs = await import('node:fs/promises');
  const absolutePath = path.resolve(policyRef);

  try {
    const yaml = await fs.readFile(absolutePath, 'utf8');
    const parsed = await parsePolicyYaml(yaml, absolutePath);
    const visited = new Set<string>([absolutePath]);
    return resolvePolicyExtends(parsed, path.dirname(absolutePath), visited);
  } catch (error) {
    if (isNodeErrorWithCode(error, 'ENOENT') || isNodeErrorWithCode(error, 'ENOTDIR')) {
      return null;
    }
    throw error;
  }
}

function isNodeErrorWithCode(error: unknown, code: string): boolean {
  return isPlainObject(error) && typeof error.code === 'string' && error.code === code;
}

async function resolvePolicyExtends(policy: PolicyDoc, basePath: string, visited: Set<string>): Promise<PolicyDoc> {
  if (!policy.extends) {
    return policy;
  }

  const baseRef = policy.extends;
  const builtinPolicyId = resolveBuiltinPolicyId(baseRef);
  let basePolicy: PolicyDoc;

  if (builtinPolicyId) {
    const key = `builtin:${builtinPolicyId}`;
    if (visited.has(key)) {
      throw new Error(`Circular policy extension detected: ${baseRef}`);
    }
    visited.add(key);
    basePolicy = clonePolicy(BUILTIN_POLICIES[builtinPolicyId]);
  } else {
    const path = await import('node:path');
    const fs = await import('node:fs/promises');
    const resolvedPath = path.isAbsolute(baseRef) ? baseRef : path.resolve(basePath, baseRef);
    if (visited.has(resolvedPath)) {
      throw new Error(`Circular policy extension detected: ${baseRef}`);
    }
    visited.add(resolvedPath);
    const yaml = await fs.readFile(resolvedPath, 'utf8');
    const parsed = await parsePolicyYaml(yaml, resolvedPath);
    basePolicy = await resolvePolicyExtends(parsed, path.dirname(resolvedPath), visited);
  }

  const merged = mergePolicies(basePolicy, policy);
  return merged;
}

function getPolicyForRuleset(ruleset: Ruleset): PolicyDoc {
  const policyId = RULESET_TO_POLICY[ruleset];
  return clonePolicy(BUILTIN_POLICIES[policyId]);
}

function toDaemonTarget(action: string, params: Record<string, unknown>): string {
  if (action === 'shell_command') {
    const command = params.command;
    if (typeof command === 'string' && command.length > 0) {
      return command;
    }
    throw new Error('shell_command requires params.command');
  }

  if (action === 'network_egress') {
    const host = params.host;
    const port = params.port;
    if (typeof host === 'string' && host.length > 0) {
      if (typeof port === 'number' && Number.isFinite(port)) {
        return `${host}:${Math.trunc(port)}`;
      }
      return host;
    }
    const url = params.url;
    if (typeof url === 'string' && url.length > 0) {
      return url;
    }
    throw new Error('network_egress requires params.host or params.url');
  }

  const path = params.path;
  if (typeof path === 'string' && path.length > 0) {
    return path;
  }

  const target = params.target;
  if (typeof target === 'string' && target.length > 0) {
    return target;
  }

  throw new Error(`${action} requires params.path or params.target`);
}

function toDaemonRequest(
  action: string,
  params: Record<string, unknown>,
  context: { sessionId?: string; agentId?: string } = {},
): DaemonCheckRequest {
  let actionType = action;
  if (action === 'file_read') actionType = 'file_access';
  if (action === 'network_egress') actionType = 'egress';
  if (action === 'shell_command') actionType = 'shell';

  if (!['file_access', 'file_write', 'egress', 'shell', 'mcp_tool', 'patch'].includes(actionType)) {
    throw new Error(`Unsupported action type for daemon mode: ${action}`);
  }

  const request: DaemonCheckRequest = {
    action_type: actionType,
    target: actionType === 'mcp_tool'
      ? (typeof params.tool === 'string' ? params.tool : toDaemonTarget(actionType, params))
      : toDaemonTarget(action, params),
  };

  if (actionType === 'file_write' || actionType === 'patch') {
    if (typeof params.content === 'string') {
      request.content = params.content;
    } else if (typeof params.diff === 'string') {
      request.content = params.diff;
    }
  }

  if (actionType === 'mcp_tool') {
    if (isPlainObject(params.args)) {
      request.args = params.args;
    } else if (isPlainObject(params)) {
      request.args = params;
    }
  }

  if (context.sessionId) {
    request.session_id = context.sessionId;
  }

  if (context.agentId) {
    request.agent_id = context.agentId;
  }

  return request;
}

async function evaluateViaDaemon(
  action: string,
  params: Record<string, unknown>,
  daemon: DaemonConfig,
  context: { sessionId?: string; agentId?: string } = {},
): Promise<Decision> {
  let request: DaemonCheckRequest;
  try {
    request = toDaemonRequest(action, params, context);
  } catch (error) {
    return daemonFailureDecision(error instanceof Error ? error.message : 'Invalid daemon request');
  }

  const headers: Record<string, string> = {
    'content-type': 'application/json',
    accept: 'application/json',
  };

  if (daemon.apiKey) {
    headers.authorization = `Bearer ${daemon.apiKey}`;
  }

  let response: Response;
  try {
    response = await fetch(`${daemon.url}/api/v1/check`, {
      method: 'POST',
      headers,
      body: JSON.stringify(request),
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'network error';
    return daemonFailureDecision(`Daemon check failed: ${message}`);
  }

  const responseBody = await response.text();
  if (!response.ok) {
    const detail = responseBody ? `: ${responseBody}` : '';
    return daemonFailureDecision(`Daemon check failed with HTTP ${response.status}${detail}`);
  }

  let parsed: unknown;
  try {
    parsed = responseBody ? JSON.parse(responseBody) : {};
  } catch {
    return daemonFailureDecision('Daemon returned invalid JSON');
  }

  if (!isDaemonCheckResponse(parsed)) {
    return daemonFailureDecision('Daemon returned malformed decision payload');
  }

  return daemonResponseToDecision(parsed);
}

// ============================================================
// ClawdstrikeSession
// ============================================================

/**
 * A stateful security session for tracking multiple checks.
 */
export class ClawdstrikeSession {
  readonly sessionId: string;
  readonly userId?: string;
  readonly agentId?: string;
  readonly cwd?: string;
  readonly metadata: Record<string, unknown>;
  readonly createdAt: Date;

  private readonly guards: Guard[];
  private readonly failFast: boolean;
  private readonly daemon?: DaemonConfig;
  private checkCount = 0;
  private allowCount = 0;
  private warnCount = 0;
  private denyCount = 0;
  private blockedActions: string[] = [];

  constructor(guards: Guard[], options: SessionOptions = {}, failFast = false, daemon?: DaemonConfig) {
    this.guards = guards;
    this.failFast = failFast;
    this.daemon = daemon;
    this.sessionId = options.sessionId ?? createId('sess');
    this.userId = options.userId;
    this.agentId = options.agentId;
    this.cwd = options.cwd;
    this.metadata = options.metadata ?? {};
    this.createdAt = new Date();
  }

  /**
   * Check an action against the policy.
   */
  async check(action: string, params: Record<string, unknown> = {}): Promise<Decision> {
    this.checkCount++;

    if (this.daemon) {
      const decision = await evaluateViaDaemon(action, params, this.daemon, {
        sessionId: this.sessionId,
        agentId: this.agentId,
      });
      this.recordDecision(action, decision);
      return decision;
    }

    const guardAction = this.createGuardAction(action, params);
    const guardContext = this.createGuardContext();
    let warningDecision: Decision | undefined;

    for (const guard of this.guards) {
      if (!guard.handles(guardAction)) {
        continue;
      }

      const result = guard.check(guardAction, guardContext);
      const decision = guardResultToDecision(result);

      if (decision.status === 'deny') {
        this.denyCount++;
        this.blockedActions.push(action);
        return decision;
      }

      if (decision.status === 'warn') {
        this.warnCount++;
        warningDecision ??= decision;
        if (this.failFast) {
          return decision;
        }
      }
    }

    if (warningDecision) {
      return warningDecision;
    }

    this.allowCount++;
    return allowDecision('session');
  }

  /**
   * Check file access.
   */
  async checkFile(path: string, operation: 'read' | 'write' = 'read'): Promise<Decision> {
    return this.check(operation === 'write' ? 'file_write' : 'file_access', { path });
  }

  /**
   * Check command execution.
   */
  async checkCommand(command: string, args: string[] = []): Promise<Decision> {
    return this.check('shell_command', { command, args });
  }

  /**
   * Check network egress.
   */
  async checkNetwork(url: string): Promise<Decision> {
    let host: string;
    let port: number;

    try {
      const parsed = new URL(url);
      host = parsed.hostname;
      port = parsed.port ? parseInt(parsed.port, 10) : (parsed.protocol === 'https:' ? 443 : 80);
    } catch {
      host = url;
      port = 443;
    }

    return this.check('network_egress', { host, port, url });
  }

  /**
   * Check a patch/diff operation.
   */
  async checkPatch(path: string, patch: string): Promise<Decision> {
    return this.check('patch', { path, diff: patch });
  }

  /**
   * Get session summary.
   */
  getSummary(): SessionSummary {
    return {
      sessionId: this.sessionId,
      checkCount: this.checkCount,
      allowCount: this.allowCount,
      warnCount: this.warnCount,
      denyCount: this.denyCount,
      blockedActions: [...this.blockedActions],
      duration: Date.now() - this.createdAt.getTime(),
    };
  }

  private createGuardAction(action: string, params: Record<string, unknown>): GuardAction {
    return new GuardAction(
      action,
      params.path as string | undefined,
      params.content as Uint8Array | undefined,
      params.host as string | undefined,
      params.port as number | undefined,
      params.tool as string | undefined,
      params.args as Record<string, unknown> | undefined,
      params.command as string | undefined,
      params.diff as string | undefined,
      params.customType as string | undefined,
      params.customData as Record<string, unknown> | undefined,
    );
  }

  private createGuardContext(): GuardContext {
    return new GuardContext({
      cwd: this.cwd,
      sessionId: this.sessionId,
      agentId: this.agentId,
      metadata: this.metadata,
    });
  }

  private recordDecision(action: string, decision: Decision): void {
    if (decision.status === 'deny') {
      this.denyCount++;
      this.blockedActions.push(action);
      return;
    }

    if (decision.status === 'warn') {
      this.warnCount++;
      return;
    }

    this.allowCount++;
  }
}

// ============================================================
// Clawdstrike (Main Entry Point)
// ============================================================

/**
 * Unified Clawdstrike SDK entry point.
 *
 * This class provides a simple, ergonomic API for security checks that
 * handles 80% of use cases. For advanced usage, see the Guards API.
 *
 * @example
 * ```typescript
 * // From policy file
 * const cs = await Clawdstrike.fromPolicy('./policy.yaml');
 *
 * // With preset ruleset
 * const cs = Clawdstrike.withDefaults('strict');
 *
 * // Simple checks
 * const decision = await cs.checkFile('/etc/passwd');
 * if (decision.status === 'deny') {
 *   throw new Error(`Access denied: ${decision.message}`);
 * }
 *
 * // Session-based usage
 * const session = cs.session({ userId: 'user-123' });
 * await session.checkCommand('rm', ['-rf', '/']);
 * console.log(session.getSummary());
 * ```
 */
export class Clawdstrike {
  private readonly guards: Guard[];
  private readonly config: ClawdstrikeConfig;
  private readonly defaultContext: GuardContext;
  private readonly daemon?: DaemonConfig;

  private constructor(config: ClawdstrikeConfig, guards: Guard[]) {
    this.config = config;
    this.guards = guards;
    this.defaultContext = new GuardContext({ cwd: config.cwd });
    this.daemon = config.daemon;
  }

  // ============================================================
  // Factory Methods
  // ============================================================

  /**
   * Create Clawdstrike instance from a policy file.
   *
   * @param yamlOrPath - Path to YAML policy file or inline YAML string
   * @returns Promise resolving to configured Clawdstrike instance
   *
   * @example
   * ```typescript
   * const cs = await Clawdstrike.fromPolicy('./clawdstrike.yaml');
   * ```
   */
  static async fromPolicy(yamlOrPath: string): Promise<Clawdstrike> {
    const policy = await loadPolicyFromSource(yamlOrPath);
    const guards = buildGuardsFromPolicy(policy);
    if (guards.length === 0) {
      throw new Error('Policy resolved to zero supported guards; refusing fail-open defaults.');
    }
    return new Clawdstrike(
      {
        policy: yamlOrPath,
        failFast: policy.settings?.fail_fast ?? false,
      },
      guards,
    );
  }

  /**
   * Create Clawdstrike instance connected to a daemon.
   *
   * @param url - Daemon URL (e.g., 'http://localhost:8080')
   * @param apiKey - Optional API key for authentication
   * @returns Promise resolving to configured Clawdstrike instance
   *
   * @example
   * ```typescript
   * const cs = await Clawdstrike.fromDaemon('http://localhost:8080', 'my-api-key');
   * ```
   */
  static async fromDaemon(url: string, apiKey?: string): Promise<Clawdstrike> {
    const daemonUrl = url.replace(/\/+$/, '');
    return new Clawdstrike(
      {
        policy: daemonUrl,
        daemon: { url: daemonUrl, apiKey },
      },
      [],
    );
  }

  /**
   * Create Clawdstrike instance with a preset ruleset.
   *
   * @param ruleset - Preset security level: 'loose', 'moderate', 'strict', or 'enterprise'
   * @returns Configured Clawdstrike instance
   *
   * @example
   * ```typescript
   * // Quick start with sensible defaults
   * const cs = Clawdstrike.withDefaults('strict');
   * ```
   */
  static withDefaults(ruleset: Ruleset = 'moderate'): Clawdstrike {
    const policy = getPolicyForRuleset(ruleset);
    const guards = buildGuardsFromPolicy(policy);
    return new Clawdstrike(
      {
        ruleset,
        failFast: policy.settings?.fail_fast ?? false,
      },
      guards,
    );
  }

  /**
   * Create Clawdstrike instance with custom configuration.
   *
   * @param config - Configuration options
   * @returns Configured Clawdstrike instance
   */
  static configure(config: ClawdstrikeConfig): Clawdstrike {
    const guards = config.guards ?? Clawdstrike.getDefaultGuards(config.ruleset ?? 'moderate');
    return new Clawdstrike(config, guards);
  }

  private static getDefaultGuards(ruleset: Ruleset): Guard[] {
    const policy = getPolicyForRuleset(ruleset);
    return buildGuardsFromPolicy(policy);
  }

  // ============================================================
  // Simple Check API
  // ============================================================

  /**
   * Check an action against the policy.
   *
   * @param action - Action type (e.g., 'read_file', 'exec_command')
   * @param params - Action parameters
   * @returns Decision indicating whether the action is allowed
   *
   * @example
   * ```typescript
   * const decision = await cs.check('read_file', { path: '/etc/passwd' });
   * ```
   */
  async check(action: string, params: Record<string, unknown> = {}): Promise<Decision> {
    if (this.daemon) {
      return evaluateViaDaemon(action, params, this.daemon);
    }

    const guardAction = this.createGuardAction(action, params);
    let warningDecision: Decision | undefined;

    for (const guard of this.guards) {
      if (!guard.handles(guardAction)) {
        continue;
      }

      const result = guard.check(guardAction, this.defaultContext);
      const decision = guardResultToDecision(result);

      if (decision.status === 'deny') {
        return decision;
      }

      if (decision.status === 'warn') {
        warningDecision ??= decision;
        if (this.config.failFast) {
          return decision;
        }
      }
    }

    return warningDecision ?? allowDecision();
  }

  /**
   * Check file access.
   *
   * @param path - File path to check
   * @param operation - Operation type: 'read' or 'write'
   * @returns Decision indicating whether access is allowed
   *
   * @example
   * ```typescript
   * const decision = await cs.checkFile('/etc/passwd', 'read');
   * ```
   */
  async checkFile(path: string, operation: 'read' | 'write' = 'read'): Promise<Decision> {
    return this.check(operation === 'write' ? 'file_write' : 'file_access', { path });
  }

  /**
   * Check command execution.
   *
   * @param command - Command to execute
   * @param args - Command arguments
   * @returns Decision indicating whether execution is allowed
   *
   * @example
   * ```typescript
   * const decision = await cs.checkCommand('rm', ['-rf', '/']);
   * ```
   */
  async checkCommand(command: string, args: string[] = []): Promise<Decision> {
    return this.check('shell_command', { command, args });
  }

  /**
   * Check network egress.
   *
   * @param url - Target URL
   * @returns Decision indicating whether egress is allowed
   *
   * @example
   * ```typescript
   * const decision = await cs.checkNetwork('https://api.example.com');
   * ```
   */
  async checkNetwork(url: string): Promise<Decision> {
    let host: string;
    let port: number;

    try {
      const parsed = new URL(url);
      host = parsed.hostname;
      port = parsed.port ? parseInt(parsed.port, 10) : (parsed.protocol === 'https:' ? 443 : 80);
    } catch {
      host = url;
      port = 443;
    }

    return this.check('network_egress', { host, port, url });
  }

  /**
   * Check a patch/diff operation.
   *
   * @param path - File path being patched
   * @param patch - Patch content (unified diff format)
   * @returns Decision indicating whether the patch is allowed
   *
   * @example
   * ```typescript
   * const decision = await cs.checkPatch('src/main.ts', unifiedDiff);
   * ```
   */
  async checkPatch(path: string, patch: string): Promise<Decision> {
    return this.check('patch', { path, diff: patch });
  }

  // ============================================================
  // Session Management
  // ============================================================

  /**
   * Create a new security session.
   *
   * Sessions track security checks over time and provide aggregated
   * statistics. Use sessions for request-scoped or conversation-scoped
   * security tracking.
   *
   * @param options - Session configuration
   * @returns New ClawdstrikeSession instance
   *
   * @example
   * ```typescript
   * const session = cs.session({ userId: 'user-123' });
   *
   * // Multiple checks in the session
   * await session.checkFile('/path/to/file');
   * await session.checkCommand('ls', ['-la']);
   *
   * // Get aggregated statistics
   * const summary = session.getSummary();
   * console.log(`Checks: ${summary.checkCount}, Denies: ${summary.denyCount}`);
   * ```
   */
  session(options: SessionOptions = {}): ClawdstrikeSession {
    return new ClawdstrikeSession(
      this.guards,
      { ...options, cwd: options.cwd ?? this.config.cwd },
      this.config.failFast,
      this.daemon,
    );
  }

  // ============================================================
  // Framework Integration
  // ============================================================

  /**
   * Wrap a tool set with security checks.
   *
   * This method wraps each tool in the set with security interception,
   * checking actions before execution and sanitizing outputs after.
   *
   * @param tools - Tool set to wrap
   * @returns Wrapped tool set with same interface
   *
   * @example
   * ```typescript
   * const tools = { readFile, writeFile, execCommand };
   * const secureTools = cs.wrapTools(tools);
   * ```
   */
  wrapTools<T extends ToolSet>(tools: T): T {
    const wrapped: Record<string, unknown> = {};

    for (const [name, tool] of Object.entries(tools)) {
      if (typeof tool === 'function') {
        wrapped[name] = this.wrapTool(name, tool as (...args: unknown[]) => unknown);
      } else if (typeof tool === 'object' && tool !== null && 'execute' in tool) {
        // Handle tool objects with execute method (common pattern)
        wrapped[name] = {
          ...tool,
          execute: this.wrapTool(name, (tool as { execute: (...args: unknown[]) => unknown }).execute),
        };
      } else {
        wrapped[name] = tool;
      }
    }

    return wrapped as T;
  }

  /**
   * Create a tool interceptor for manual integration.
   *
   * Use this for frameworks that require explicit interceptor setup.
   *
   * @returns ToolInterceptor instance
   *
   * @example
   * ```typescript
   * const interceptor = cs.createInterceptor();
   *
   * // In your framework's tool execution
   * const result = await interceptor.beforeExecute(toolName, input, session);
   * if (!result.proceed) {
   *   throw new Error(`Blocked: ${result.decision.message}`);
   * }
   * ```
   */
  createInterceptor(): ToolInterceptor {
    return {
      beforeExecute: async (
        toolName: string,
        input: unknown,
        context: ClawdstrikeSession,
      ): Promise<{ proceed: boolean; decision: Decision }> => {
        const params = typeof input === 'object' && input !== null
          ? input as Record<string, unknown>
          : { value: input };

        const decision = await context.check(toolName, params);
        return {
          proceed: decision.status !== 'deny',
          decision,
        };
      },
      afterExecute: async (
        _toolName: string,
        _input: unknown,
        output: unknown,
        _context: ClawdstrikeSession,
      ): Promise<{ output: unknown; modified: boolean }> => {
        // Output sanitization would be applied here
        return { output, modified: false };
      },
    };
  }

  // ============================================================
  // Internal Helpers
  // ============================================================

  private wrapTool(
    name: string,
    fn: (...args: unknown[]) => unknown,
  ): (...args: unknown[]) => Promise<unknown> {
    const self = this;
    return async function wrappedTool(...args: unknown[]): Promise<unknown> {
      const params = args[0] && typeof args[0] === 'object'
        ? args[0] as Record<string, unknown>
        : { args };

      const decision = await self.check(name, params);
      if (decision.status === 'deny') {
        throw new Error(`Clawdstrike blocked ${name}: ${decision.message}`);
      }

      return fn(...args);
    };
  }

  private createGuardAction(action: string, params: Record<string, unknown>): GuardAction {
    return new GuardAction(
      action,
      params.path as string | undefined,
      params.content as Uint8Array | undefined,
      params.host as string | undefined,
      params.port as number | undefined,
      params.tool as string | undefined,
      params.args as Record<string, unknown> | undefined,
      params.command as string | undefined,
      params.diff as string | undefined,
      params.customType as string | undefined,
      params.customData as Record<string, unknown> | undefined,
    );
  }

}

export default Clawdstrike;
