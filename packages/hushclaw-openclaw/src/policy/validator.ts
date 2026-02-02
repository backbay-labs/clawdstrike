import type { Policy, PolicyLintResult } from '../types.js';

const VALID_EGRESS_MODES = new Set(['allowlist', 'denylist', 'open', 'deny_all']);
const VALID_VIOLATION_ACTIONS = new Set(['cancel', 'warn', 'isolate', 'escalate']);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
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

  const p = policy as Policy;

  if (p.version !== undefined && typeof p.version !== 'string') {
    errors.push('version must be a string');
  }

  if (p.extends !== undefined && typeof p.extends !== 'string') {
    errors.push('extends must be a string');
  }

  // Egress validation
  if (p.egress !== undefined) {
    if (!isPlainObject(p.egress)) {
      errors.push('egress must be an object');
    } else {
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
      ensureStringArray((p.tools as any).allowed, 'tools.allowed', errors);
      ensureStringArray((p.tools as any).denied, 'tools.denied', errors);
    }
  }

  // Limits validation
  if (p.limits !== undefined) {
    if (!isPlainObject(p.limits)) {
      errors.push('limits must be an object');
    } else {
      ensurePositiveNumber((p.limits as any).max_execution_seconds, 'limits.max_execution_seconds', errors);
      ensurePositiveNumber((p.limits as any).max_memory_mb, 'limits.max_memory_mb', errors);
      ensurePositiveNumber((p.limits as any).max_output_bytes, 'limits.max_output_bytes', errors);
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
