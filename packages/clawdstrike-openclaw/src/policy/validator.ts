import type { Policy, PolicyLintResult } from '../types.js';

export const POLICY_SCHEMA_VERSION = 'clawdstrike-v1.0';

const VALID_EGRESS_MODES = new Set(['allowlist', 'denylist', 'open', 'deny_all']);
const VALID_VIOLATION_ACTIONS = new Set(['cancel', 'warn', 'isolate', 'escalate']);

const POLICY_KEYS = new Set([
  'version',
  'extends',
  'egress',
  'filesystem',
  'execution',
  'tools',
  'limits',
  'guards',
  'on_violation',
]);

const EGRESS_KEYS = new Set(['mode', 'allowed_domains', 'allowed_cidrs', 'denied_domains']);
const FILESYSTEM_KEYS = new Set(['allowed_write_roots', 'allowed_read_paths', 'forbidden_paths']);
const EXECUTION_KEYS = new Set(['allowed_commands', 'denied_patterns']);
const TOOLS_KEYS = new Set(['allowed', 'denied']);
const LIMITS_KEYS = new Set(['max_execution_seconds', 'max_memory_mb', 'max_output_bytes']);
const GUARDS_KEYS = new Set(['forbidden_path', 'egress', 'secret_leak', 'patch_integrity', 'mcp_tool']);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function ensureAllowedKeys(
  obj: Record<string, unknown>,
  field: string,
  allowed: Set<string>,
  errors: string[],
): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) {
      errors.push(`${field} contains unknown field: ${key}`);
    }
  }
}

function ensureBoolean(
  value: unknown,
  field: string,
  errors: string[],
): void {
  if (value === undefined) return;
  if (typeof value !== 'boolean') {
    errors.push(`${field} must be a boolean`);
  }
}

function ensureStringArray(
  value: unknown,
  field: string,
  errors: string[],
  warnings?: string[],
): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) {
    errors.push(`${field} must be an array of strings`);
    return undefined;
  }
  const out: string[] = [];
  for (let i = 0; i < value.length; i++) {
    const item = value[i];
    if (typeof item !== 'string') {
      errors.push(`${field}[${i}] must be a string`);
      continue;
    }
    if (item.includes('\u0000')) {
      errors.push(`${field}[${i}] contains a null byte`);
      continue;
    }
    out.push(item);
  }
  if (warnings && out.length === 0) {
    warnings.push(`${field} is empty`);
  }
  return out;
}

function ensurePositiveNumber(
  value: unknown,
  field: string,
  errors: string[],
): void {
  if (value === undefined) return;
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    errors.push(`${field} must be a positive number`);
  }
}

export function validatePolicy(policy: unknown): PolicyLintResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!isPlainObject(policy)) {
    return { valid: false, errors: ['Policy must be an object'], warnings: [] };
  }

  ensureAllowedKeys(policy, 'policy', POLICY_KEYS, errors);

  const p = policy as Policy;

  if (p.version === undefined) {
    errors.push(`version is required (expected: ${POLICY_SCHEMA_VERSION})`);
  } else if (typeof p.version !== 'string') {
    errors.push('version must be a string');
  } else if (p.version !== POLICY_SCHEMA_VERSION) {
    errors.push(`unsupported policy version: ${p.version} (supported: ${POLICY_SCHEMA_VERSION})`);
  }

  if (p.extends !== undefined && typeof p.extends !== 'string') {
    errors.push('extends must be a string');
  }

  // Egress validation
  if (p.egress !== undefined) {
    if (!isPlainObject(p.egress)) {
      errors.push('egress must be an object');
    } else {
      ensureAllowedKeys(p.egress, 'egress', EGRESS_KEYS, errors);
      const mode = (p.egress as any).mode;
      if (mode !== undefined && (!VALID_EGRESS_MODES.has(mode) || typeof mode !== 'string')) {
        errors.push(`egress.mode must be one of: ${[...VALID_EGRESS_MODES].join(', ')}`);
      }

      const allowed = ensureStringArray((p.egress as any).allowed_domains, 'egress.allowed_domains', errors);
      if (mode === 'allowlist' && allowed && allowed.length === 0) {
        warnings.push('egress.allowlist with empty allowed_domains will deny all egress');
      }

      ensureStringArray((p.egress as any).denied_domains, 'egress.denied_domains', errors);
      ensureStringArray((p.egress as any).allowed_cidrs, 'egress.allowed_cidrs', errors);
    }
  }

  // Filesystem validation
  if (p.filesystem !== undefined) {
    if (!isPlainObject(p.filesystem)) {
      errors.push('filesystem must be an object');
    } else {
      ensureAllowedKeys(p.filesystem, 'filesystem', FILESYSTEM_KEYS, errors);
      ensureStringArray((p.filesystem as any).allowed_write_roots, 'filesystem.allowed_write_roots', errors);
      ensureStringArray((p.filesystem as any).allowed_read_paths, 'filesystem.allowed_read_paths', errors);
      ensureStringArray((p.filesystem as any).forbidden_paths, 'filesystem.forbidden_paths', errors, warnings);
    }
  }

  // Execution validation
  if (p.execution !== undefined) {
    if (!isPlainObject(p.execution)) {
      errors.push('execution must be an object');
    } else {
      ensureAllowedKeys(p.execution, 'execution', EXECUTION_KEYS, errors);
      ensureStringArray((p.execution as any).allowed_commands, 'execution.allowed_commands', errors);

      const patterns = ensureStringArray((p.execution as any).denied_patterns, 'execution.denied_patterns', errors);
      if (patterns) {
        for (const pattern of patterns) {
          try {
            // eslint-disable-next-line no-new
            new RegExp(pattern);
          } catch (err) {
            errors.push(`execution.denied_patterns contains invalid regex: ${pattern}`);
          }
        }
      }
    }
  }

  // Tool policy validation
  if (p.tools !== undefined) {
    if (!isPlainObject(p.tools)) {
      errors.push('tools must be an object');
    } else {
      ensureAllowedKeys(p.tools, 'tools', TOOLS_KEYS, errors);
      ensureStringArray((p.tools as any).allowed, 'tools.allowed', errors);
      ensureStringArray((p.tools as any).denied, 'tools.denied', errors);
    }
  }

  // Limits validation
  if (p.limits !== undefined) {
    if (!isPlainObject(p.limits)) {
      errors.push('limits must be an object');
    } else {
      ensureAllowedKeys(p.limits, 'limits', LIMITS_KEYS, errors);
      ensurePositiveNumber((p.limits as any).max_execution_seconds, 'limits.max_execution_seconds', errors);
      ensurePositiveNumber((p.limits as any).max_memory_mb, 'limits.max_memory_mb', errors);
      ensurePositiveNumber((p.limits as any).max_output_bytes, 'limits.max_output_bytes', errors);
    }
  }

  // Guard toggles validation
  if (p.guards !== undefined) {
    if (!isPlainObject(p.guards)) {
      errors.push('guards must be an object');
    } else {
      ensureAllowedKeys(p.guards, 'guards', GUARDS_KEYS, errors);
      ensureBoolean((p.guards as any).forbidden_path, 'guards.forbidden_path', errors);
      ensureBoolean((p.guards as any).egress, 'guards.egress', errors);
      ensureBoolean((p.guards as any).secret_leak, 'guards.secret_leak', errors);
      ensureBoolean((p.guards as any).patch_integrity, 'guards.patch_integrity', errors);
      ensureBoolean((p.guards as any).mcp_tool, 'guards.mcp_tool', errors);
    }
  }

  // on_violation validation
  if (p.on_violation !== undefined) {
    if (typeof p.on_violation !== 'string' || !VALID_VIOLATION_ACTIONS.has(p.on_violation)) {
      errors.push(`on_violation must be one of: ${[...VALID_VIOLATION_ACTIONS].join(', ')}`);
    }
  }

  return { valid: errors.length === 0, errors, warnings };
}
