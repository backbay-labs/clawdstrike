/**
 * Path Allowlist Guard Simulation
 *
 * Inverse of forbidden-path: deny-by-default, allow only paths matching
 * allowlist patterns. Uses picomatch with `{ dot: true }` for Rust parity.
 */
import picomatch from 'picomatch';
import type { GuardAction, GuardResult } from './types';

/** Normalize path separators to forward slashes. */
function normalizePath(p: string): string {
  return p.replace(/\\/g, '/');
}

export function evaluatePathAllowlist(
  config: Record<string, unknown>,
  action: GuardAction,
): GuardResult {
  // Only evaluate file_access and file_write actions
  if (action.type !== 'file_access' && action.type !== 'file_write') {
    return {
      allowed: true,
      guard: 'path_allowlist',
      severity: 'info',
      message: 'Action type not evaluated by path_allowlist guard',
    };
  }

  const rawPath = normalizePath(action.path);
  const allowPatterns = config.allow as string[] | undefined;

  if (!allowPatterns || allowPatterns.length === 0) {
    // No allowlist configured: deny all (fail-closed)
    return {
      allowed: false,
      guard: 'path_allowlist',
      severity: 'error',
      message: 'No allowlist configured; all paths denied',
      details: { path: rawPath },
    };
  }

  const isAllowed = picomatch(allowPatterns, { dot: true });
  if (isAllowed(rawPath)) {
    return {
      allowed: true,
      guard: 'path_allowlist',
      severity: 'info',
      message: 'Path matches allowlist',
      details: { path: rawPath },
    };
  }

  return {
    allowed: false,
    guard: 'path_allowlist',
    severity: 'error',
    message: 'Path not in allowlist',
    details: { path: rawPath },
  };
}
