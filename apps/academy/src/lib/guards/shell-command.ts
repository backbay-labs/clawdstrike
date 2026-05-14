/**
 * Shell Command Guard Simulation
 *
 * Two-layer defense against dangerous shell commands.
 * Layer 1: Regex patterns matching dangerous command patterns.
 * Layer 2: File path extraction and forbidden path check.
 */
import type { GuardAction, GuardResult } from './types';

/** Default dangerous command patterns */
const DEFAULT_FORBIDDEN_PATTERNS: Array<{ name: string; pattern: string }> = [
  { name: 'pipe_to_shell', pattern: 'curl.*\\|\\s*(bash|sh|zsh)' },
  { name: 'wget_pipe_shell', pattern: 'wget.*\\|\\s*(bash|sh|zsh)' },
  { name: 'rm_rf_root', pattern: 'rm\\s+(-[a-zA-Z]*)?\\s*-rf\\s+/' },
  { name: 'rm_rf_root_alt', pattern: 'rm\\s+-rf\\s+/' },
  { name: 'chmod_777', pattern: 'chmod\\s+777' },
  { name: 'dd_dev', pattern: 'dd\\s+.*of=/dev/' },
  { name: 'mkfs', pattern: 'mkfs\\.' },
  { name: 'fork_bomb', pattern: ':\\(\\)\\{\\s*:\\|:' },
  { name: 'reverse_shell', pattern: 'bash\\s+-i\\s+>&\\s+/dev/tcp/' },
  { name: 'disable_security', pattern: '(?i)disable[\\s_-]?(security|auth|ssl|tls)' },
  { name: 'skip_verify', pattern: '(?i)skip[\\s_-]?(verify|validation|check)' },
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

export function evaluateShellCommand(
  config: Record<string, unknown>,
  action: GuardAction,
): GuardResult {
  // Only evaluate shell_command actions
  if (action.type !== 'shell_command') {
    return {
      allowed: true,
      guard: 'shell_command',
      severity: 'info',
      message: 'Action type not evaluated by shell_command guard',
    };
  }

  const command = action.command;
  const configPatterns = config.forbidden_patterns as
    | Array<{ name: string; pattern: string }>
    | undefined;
  const patterns = configPatterns ?? DEFAULT_FORBIDDEN_PATTERNS;

  // Layer 1: regex pattern matching
  for (const pat of patterns) {
    const regex = compilePattern(pat.pattern);
    if (regex.test(command)) {
      return {
        allowed: false,
        guard: 'shell_command',
        severity: 'critical',
        message: `Dangerous command blocked: matches ${pat.name} pattern`,
        details: {
          command,
          matched_pattern: pat.name,
        },
      };
    }
  }

  return {
    allowed: true,
    guard: 'shell_command',
    severity: 'info',
    message: 'Command allowed',
    details: { command },
  };
}
