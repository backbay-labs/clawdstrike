/**
 * @hushclaw/openclaw - Policy Validator
 *
 * Validate policy files for correctness and consistency.
 */

import type { Policy, PolicyLintResult, EgressMode, ViolationAction } from '../types.js';

/** Maximum number of entries in any list */
const MAX_LIST_ENTRIES = 1000;

/** Valid egress modes */
const VALID_EGRESS_MODES: EgressMode[] = ['allowlist', 'denylist', 'open', 'deny_all'];

/** Valid violation actions */
const VALID_VIOLATION_ACTIONS: ViolationAction[] = ['cancel', 'warn', 'isolate', 'escalate'];

/**
 * Validate a policy object
 *
 * @param policy - Policy to validate
 * @returns Validation result with errors and warnings
 */
export function validatePolicy(policy: Policy): PolicyLintResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Validate version
  if (policy.version && typeof policy.version !== 'string') {
    errors.push('version must be a string');
  }

  // Validate egress policy
  if (policy.egress) {
    validateEgressPolicy(policy.egress, errors, warnings);
  }

  // Validate filesystem policy
  if (policy.filesystem) {
    validateFilesystemPolicy(policy.filesystem, errors, warnings);
  }

  // Validate execution policy
  if (policy.execution) {
    validateExecutionPolicy(policy.execution, errors, warnings);
  }

  // Validate tool policy
  if (policy.tools) {
    validateToolPolicy(policy.tools, errors, warnings);
  }

  // Validate limits
  if (policy.limits) {
    validateLimits(policy.limits, errors, warnings);
  }

  // Validate on_violation
  if (policy.on_violation) {
    if (!VALID_VIOLATION_ACTIONS.includes(policy.on_violation)) {
      errors.push(
        `on_violation must be one of: ${VALID_VIOLATION_ACTIONS.join(', ')}`
      );
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

/**
 * Validate egress policy section
 */
function validateEgressPolicy(
  egress: Policy['egress'],
  errors: string[],
  warnings: string[],
): void {
  if (!egress) return;

  // Validate mode
  if (egress.mode && !VALID_EGRESS_MODES.includes(egress.mode)) {
    errors.push(`egress.mode must be one of: ${VALID_EGRESS_MODES.join(', ')}`);
  }

  // Validate allowed_domains
  if (egress.allowed_domains) {
    validateStringList('egress.allowed_domains', egress.allowed_domains, errors, warnings);
    validateDomainPatterns(egress.allowed_domains, 'egress.allowed_domains', errors);
  }

  // Validate denied_domains
  if (egress.denied_domains) {
    validateStringList('egress.denied_domains', egress.denied_domains, errors, warnings);
    validateDomainPatterns(egress.denied_domains, 'egress.denied_domains', errors);
  }

  // Validate allowed_cidrs
  if (egress.allowed_cidrs) {
    validateStringList('egress.allowed_cidrs', egress.allowed_cidrs, errors, warnings);
    for (const cidr of egress.allowed_cidrs) {
      if (!isValidCidr(cidr)) {
        errors.push(`egress.allowed_cidrs contains invalid CIDR: ${cidr}`);
      }
    }
  }

  // Warn about conflicting configurations
  if (egress.mode === 'allowlist' && (!egress.allowed_domains || egress.allowed_domains.length === 0)) {
    warnings.push('egress.mode is "allowlist" but no allowed_domains specified - all egress will be denied');
  }
}

/**
 * Validate filesystem policy section
 */
function validateFilesystemPolicy(
  fs: Policy['filesystem'],
  errors: string[],
  warnings: string[],
): void {
  if (!fs) return;

  // Validate forbidden_paths
  if (fs.forbidden_paths) {
    validateStringList('filesystem.forbidden_paths', fs.forbidden_paths, errors, warnings);
    validatePathPatterns(fs.forbidden_paths, 'filesystem.forbidden_paths', errors);
  }

  // Validate allowed_write_roots
  if (fs.allowed_write_roots) {
    validateStringList('filesystem.allowed_write_roots', fs.allowed_write_roots, errors, warnings);
    validatePathPatterns(fs.allowed_write_roots, 'filesystem.allowed_write_roots', errors);
  }
}

/**
 * Validate execution policy section
 */
function validateExecutionPolicy(
  exec: Policy['execution'],
  errors: string[],
  warnings: string[],
): void {
  if (!exec) return;

  // Validate denied_patterns
  if (exec.denied_patterns) {
    validateStringList('execution.denied_patterns', exec.denied_patterns, errors, warnings);
    for (const pattern of exec.denied_patterns) {
      try {
        new RegExp(pattern);
      } catch {
        errors.push(`execution.denied_patterns contains invalid regex: ${pattern}`);
      }
    }
  }
}

/**
 * Validate tool policy section
 */
function validateToolPolicy(
  tools: Policy['tools'],
  errors: string[],
  warnings: string[],
): void {
  if (!tools) return;

  if (tools.allowed) {
    validateStringList('tools.allowed', tools.allowed, errors, warnings);
  }

  if (tools.denied) {
    validateStringList('tools.denied', tools.denied, errors, warnings);
  }

  // Warn about overlap
  if (tools.allowed && tools.denied) {
    const overlap = tools.allowed.filter((t) => tools.denied?.includes(t));
    if (overlap.length > 0) {
      warnings.push(`tools.allowed and tools.denied overlap: ${overlap.join(', ')}`);
    }
  }
}

/**
 * Validate limits section
 */
function validateLimits(
  limits: Policy['limits'],
  errors: string[],
  _warnings: string[],
): void {
  if (!limits) return;

  if (limits.max_execution_seconds !== undefined) {
    if (typeof limits.max_execution_seconds !== 'number' || limits.max_execution_seconds < 0) {
      errors.push('limits.max_execution_seconds must be a positive number');
    }
  }

  if (limits.max_memory_mb !== undefined) {
    if (typeof limits.max_memory_mb !== 'number' || limits.max_memory_mb < 0) {
      errors.push('limits.max_memory_mb must be a positive number');
    }
  }

  if (limits.max_output_bytes !== undefined) {
    if (typeof limits.max_output_bytes !== 'number' || limits.max_output_bytes < 0) {
      errors.push('limits.max_output_bytes must be a positive number');
    }
  }
}

/**
 * Validate a string list (array of strings)
 */
function validateStringList(
  fieldName: string,
  list: unknown[],
  errors: string[],
  _warnings: string[],
): void {
  if (!Array.isArray(list)) {
    errors.push(`${fieldName} must be an array`);
    return;
  }

  if (list.length > MAX_LIST_ENTRIES) {
    errors.push(`${fieldName} has too many entries (${list.length} > ${MAX_LIST_ENTRIES})`);
  }

  for (let i = 0; i < list.length; i++) {
    if (typeof list[i] !== 'string') {
      errors.push(`${fieldName}[${i}] must be a string`);
    }
  }
}

/**
 * Validate domain patterns for security issues
 */
function validateDomainPatterns(
  patterns: string[],
  fieldName: string,
  errors: string[],
): void {
  for (const pattern of patterns) {
    // Check for null bytes
    if (pattern.includes('\0')) {
      errors.push(`${fieldName} contains null byte in pattern: ${pattern}`);
    }
    // Check for path traversal
    if (pattern.includes('..')) {
      errors.push(`${fieldName} contains path traversal: ${pattern}`);
    }
  }
}

/**
 * Validate path patterns for security issues
 */
function validatePathPatterns(
  patterns: string[],
  fieldName: string,
  errors: string[],
): void {
  for (const pattern of patterns) {
    // Check for null bytes
    if (pattern.includes('\0')) {
      errors.push(`${fieldName} contains null byte in pattern: ${pattern}`);
    }
  }
}

/**
 * Check if a string is a valid CIDR notation
 */
function isValidCidr(cidr: string): boolean {
  // Simple validation - accepts IP addresses and CIDR notation
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
  const ipv6Pattern = /^([0-9a-fA-F:]+)(\/\d{1,3})?$/;
  const wildcardPattern = /^(\d{1,3}\.){0,3}\*$/;

  return ipv4Pattern.test(cidr) || ipv6Pattern.test(cidr) || wildcardPattern.test(cidr);
}
