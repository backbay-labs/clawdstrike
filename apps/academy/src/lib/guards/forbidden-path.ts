/**
 * Forbidden Path Guard Simulation
 *
 * Blocks access to sensitive filesystem paths using picomatch glob matching.
 * Patterns sourced from rulesets/default.yaml. Exceptions override forbidden
 * matches (checked first, same order as Rust implementation).
 */
import picomatch from 'picomatch';
import type { GuardAction, GuardResult } from './types';

/** Default forbidden patterns from rulesets/default.yaml */
const DEFAULT_PATTERNS: string[] = [
  // SSH keys
  '**/.ssh/**',
  '**/id_rsa*',
  '**/id_ed25519*',
  '**/id_ecdsa*',
  // AWS credentials
  '**/.aws/**',
  // Environment files
  '**/.env',
  '**/.env.*',
  // Git credentials
  '**/.git-credentials',
  '**/.gitconfig',
  // GPG keys
  '**/.gnupg/**',
  // Kubernetes
  '**/.kube/**',
  // Docker
  '**/.docker/**',
  // NPM tokens
  '**/.npmrc',
  // Password stores
  '**/.password-store/**',
  '**/pass/**',
  // 1Password
  '**/.1password/**',
  // System paths (Unix)
  '/etc/shadow',
  '/etc/passwd',
  '/etc/sudoers',
  // Windows credential stores
  '**/AppData/Roaming/Microsoft/Credentials/**',
  '**/AppData/Local/Microsoft/Credentials/**',
  '**/AppData/Roaming/Microsoft/Vault/**',
  // Windows registry hives
  '**/NTUSER.DAT',
  '**/Windows/System32/config/SAM',
  '**/Windows/System32/config/SECURITY',
  '**/Windows/System32/config/SYSTEM',
];

/** Normalize path separators to forward slashes. */
function normalizePath(p: string): string {
  return p.replace(/\\/g, '/');
}

export function evaluateForbiddenPath(
  config: Record<string, unknown>,
  action: GuardAction,
): GuardResult {
  // Only evaluate file_access and file_write actions
  if (action.type !== 'file_access' && action.type !== 'file_write') {
    return {
      allowed: true,
      guard: 'forbidden_path',
      severity: 'info',
      message: 'Action type not evaluated by forbidden_path guard',
    };
  }

  const rawPath = normalizePath(action.path);
  const patterns = (config.patterns as string[] | undefined) ?? DEFAULT_PATTERNS;
  const exceptions = (config.exceptions as string[] | undefined) ?? [];

  // Check exceptions first (same order as Rust impl)
  if (exceptions.length > 0) {
    const isException = picomatch(exceptions, { dot: true });
    if (isException(rawPath)) {
      return {
        allowed: true,
        guard: 'forbidden_path',
        severity: 'info',
        message: 'Path matched exception pattern',
        details: { path: rawPath, exception: true },
      };
    }
  }

  // Check forbidden patterns
  const isForbidden = picomatch(patterns, { dot: true });
  if (isForbidden(rawPath)) {
    return {
      allowed: false,
      guard: 'forbidden_path',
      severity: 'critical',
      message: `Access denied: path matches forbidden pattern`,
      details: { path: rawPath },
    };
  }

  return {
    allowed: true,
    guard: 'forbidden_path',
    severity: 'info',
    message: 'Path allowed',
    details: { path: rawPath },
  };
}
