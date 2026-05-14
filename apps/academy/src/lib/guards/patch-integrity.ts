/**
 * Patch Integrity Guard Simulation
 *
 * Validates unified diff patches against addition/deletion thresholds and
 * forbidden patterns. Default thresholds from rulesets/default.yaml.
 */
import type { GuardAction, GuardResult } from './types';

const DEFAULT_MAX_ADDITIONS = 1000;
const DEFAULT_MAX_DELETIONS = 500;

/** Default forbidden patterns from rulesets/default.yaml */
const DEFAULT_FORBIDDEN_PATTERNS: string[] = [
  '(?i)disable[\\s_\\-]?(security|auth|ssl|tls)',
  '(?i)skip[\\s_\\-]?(verify|validation|check)',
  '(?i)rm\\s+-rf\\s+/',
  '(?i)chmod\\s+777',
];

/**
 * Compile a pattern string to a RegExp.
 * Handles (?i) prefix by converting to the 'i' flag.
 */
function compilePattern(pattern: string): RegExp {
  let flags = '';
  let src = pattern;
  if (src.startsWith('(?i)')) {
    flags = 'i';
    src = src.slice(4);
  }
  return new RegExp(src, flags);
}

/**
 * Parse a unified diff and extract addition/deletion counts and added lines.
 */
function parseDiff(diff: string): {
  additions: number;
  deletions: number;
  addedLines: string[];
} {
  const lines = diff.split('\n');
  let additions = 0;
  let deletions = 0;
  const addedLines: string[] = [];

  for (const line of lines) {
    if (line.startsWith('+++') || line.startsWith('---')) {
      // Skip file header lines
      continue;
    }
    if (line.startsWith('+')) {
      additions++;
      addedLines.push(line.slice(1)); // strip the leading '+'
    } else if (line.startsWith('-')) {
      deletions++;
    }
  }

  return { additions, deletions, addedLines };
}

export function evaluatePatchIntegrity(
  config: Record<string, unknown>,
  action: GuardAction,
): GuardResult {
  // Only evaluate patch actions
  if (action.type !== 'patch') {
    return {
      allowed: true,
      guard: 'patch_integrity',
      severity: 'info',
      message: 'Action type not evaluated by patch_integrity guard',
    };
  }

  const diff = action.diff;
  const maxAdditions =
    (config.max_additions as number | undefined) ?? DEFAULT_MAX_ADDITIONS;
  const maxDeletions =
    (config.max_deletions as number | undefined) ?? DEFAULT_MAX_DELETIONS;
  const forbiddenPatterns =
    (config.forbidden_patterns as string[] | undefined) ??
    DEFAULT_FORBIDDEN_PATTERNS;

  const { additions, deletions, addedLines } = parseDiff(diff);
  const violations: string[] = [];

  // Check thresholds
  if (additions > maxAdditions) {
    violations.push(
      `Additions (${additions}) exceed maximum (${maxAdditions})`,
    );
  }
  if (deletions > maxDeletions) {
    violations.push(
      `Deletions (${deletions}) exceed maximum (${maxDeletions})`,
    );
  }

  // Check forbidden patterns in added lines only
  for (const patternStr of forbiddenPatterns) {
    const regex = compilePattern(patternStr);
    for (const line of addedLines) {
      if (regex.test(line)) {
        violations.push(`Forbidden pattern matched: "${patternStr}" in added line`);
        break; // one match per pattern is enough
      }
    }
  }

  if (violations.length > 0) {
    return {
      allowed: false,
      guard: 'patch_integrity',
      severity: 'error',
      message: `Patch integrity violations: ${violations.join('; ')}`,
      details: {
        additions,
        deletions,
        violations,
        path: action.path,
      },
    };
  }

  return {
    allowed: true,
    guard: 'patch_integrity',
    severity: 'info',
    message: 'Patch integrity check passed',
    details: {
      additions,
      deletions,
      path: action.path,
    },
  };
}
