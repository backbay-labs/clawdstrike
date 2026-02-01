import type { PolicyConfig, ValidationResult } from './types.js';

const VALID_EGRESS_MODES = ['allowlist', 'denylist', 'open'];
const VALID_VIOLATION_ACTIONS = ['cancel', 'warn', 'log'];
const VALID_EXEC_MODES = ['allowlist', 'denylist'];

export function validatePolicy(policy: unknown): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (typeof policy !== 'object' || policy === null) {
    return { valid: false, errors: ['Policy must be an object'], warnings: [] };
  }

  const p = policy as PolicyConfig;

  // Validate egress
  if (p.egress) {
    if (p.egress.mode && !VALID_EGRESS_MODES.includes(p.egress.mode)) {
      errors.push(`egress.mode must be one of: ${VALID_EGRESS_MODES.join(', ')}`);
    }
    if (p.egress.allowed_domains && !Array.isArray(p.egress.allowed_domains)) {
      errors.push('egress.allowed_domains must be an array');
    }
    if (p.egress.denied_domains && !Array.isArray(p.egress.denied_domains)) {
      errors.push('egress.denied_domains must be an array');
    }
  }

  // Validate filesystem
  if (p.filesystem) {
    if (p.filesystem.forbidden_paths) {
      if (!Array.isArray(p.filesystem.forbidden_paths)) {
        errors.push('filesystem.forbidden_paths must be an array');
      } else if (p.filesystem.forbidden_paths.length === 0) {
        warnings.push('filesystem.forbidden_paths is empty - no paths will be protected');
      }
    }
    if (p.filesystem.allowed_write_roots && !Array.isArray(p.filesystem.allowed_write_roots)) {
      errors.push('filesystem.allowed_write_roots must be an array');
    }
  }

  // Validate execution
  if (p.execution) {
    if (p.execution.mode && !VALID_EXEC_MODES.includes(p.execution.mode)) {
      errors.push(`execution.mode must be one of: ${VALID_EXEC_MODES.join(', ')}`);
    }
  }

  // Validate on_violation
  if (p.on_violation && !VALID_VIOLATION_ACTIONS.includes(p.on_violation)) {
    errors.push(`on_violation must be one of: ${VALID_VIOLATION_ACTIONS.join(', ')}`);
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}
