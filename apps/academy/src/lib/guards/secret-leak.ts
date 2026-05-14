/**
 * Secret Leak Guard Simulation
 *
 * Detects secrets in file writes using regex pattern matching.
 * Default patterns from rulesets/default.yaml.
 */
import type { GuardAction, GuardResult } from './types';

interface SecretPattern {
  name: string;
  pattern: string;
  severity: 'info' | 'warning' | 'error' | 'critical';
}

/** Default secret patterns from rulesets/default.yaml */
const DEFAULT_PATTERNS: SecretPattern[] = [
  {
    name: 'aws_access_key',
    pattern: 'AKIA[0-9A-Z]{16}',
    severity: 'critical',
  },
  {
    name: 'github_token',
    pattern: 'gh[ps]_[A-Za-z0-9]{36}',
    severity: 'critical',
  },
  {
    name: 'openai_key',
    pattern: 'sk-[A-Za-z0-9]{48}',
    severity: 'critical',
  },
  {
    name: 'private_key',
    pattern: '-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----',
    severity: 'critical',
  },
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

export function evaluateSecretLeak(
  config: Record<string, unknown>,
  action: GuardAction,
): GuardResult {
  // Only evaluate file_write actions
  if (action.type !== 'file_write') {
    return {
      allowed: true,
      guard: 'secret_leak',
      severity: 'info',
      message: 'Action type not evaluated by secret_leak guard',
    };
  }

  const content = action.content;
  const configPatterns = config.patterns as
    | Array<{ name: string; pattern: string; severity?: string }>
    | undefined;

  const patterns: SecretPattern[] = configPatterns
    ? configPatterns.map((p) => ({
        name: p.name,
        pattern: p.pattern,
        severity: (p.severity as SecretPattern['severity']) ?? 'critical',
      }))
    : DEFAULT_PATTERNS;

  const matchedPatterns: string[] = [];
  let worstSeverity: SecretPattern['severity'] = 'info';
  const severityRank: Record<string, number> = {
    info: 0,
    warning: 1,
    error: 2,
    critical: 3,
  };

  for (const pat of patterns) {
    const regex = compilePattern(pat.pattern);
    if (regex.test(content)) {
      matchedPatterns.push(pat.name);
      if (severityRank[pat.severity] > severityRank[worstSeverity]) {
        worstSeverity = pat.severity;
      }
    }
  }

  if (matchedPatterns.length > 0) {
    return {
      allowed: false,
      guard: 'secret_leak',
      severity: worstSeverity,
      message: `Secret detected: ${matchedPatterns.join(', ')}`,
      details: {
        matched_patterns: matchedPatterns,
        path: action.path,
      },
    };
  }

  return {
    allowed: true,
    guard: 'secret_leak',
    severity: 'info',
    message: 'No secrets detected',
    details: { path: action.path },
  };
}
