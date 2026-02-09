/**
 * @clawdstrike/openclaw - Forbidden Path Guard
 *
 * Blocks access to sensitive filesystem paths.
 */

import { minimatch } from 'minimatch';
import { homedir } from 'os';
import { resolve, normalize } from 'path';
import type { PolicyEvent, Policy, GuardResult, EventType } from '../types.js';
import { BaseGuard } from './types.js';

/**
 * Default forbidden paths when no policy is specified
 */
const DEFAULT_FORBIDDEN_PATHS = [
  '~/.ssh',
  '~/.ssh/*',
  '~/.aws',
  '~/.aws/*',
  '~/.gnupg',
  '~/.gnupg/*',
  '~/.config/gcloud',
  '~/.config/gcloud/*',
  '/etc/shadow',
  '/etc/passwd',
  '.env',
  '**/.env',
  '**/.env.*',
  '*.pem',
  '**/*.pem',
  '*.key',
  '**/*.key',
  '**/id_rsa',
  '**/id_ed25519',
  '**/id_ecdsa',
];

/**
 * ForbiddenPathGuard - blocks access to sensitive paths
 */
export class ForbiddenPathGuard extends BaseGuard {
  name(): string {
    return 'forbidden_path';
  }

  handles(): EventType[] {
    return ['file_read', 'file_write'];
  }

  async check(event: PolicyEvent, policy: Policy): Promise<GuardResult> {
    return this.checkSync(event, policy);
  }

  checkSync(event: PolicyEvent, policy: Policy): GuardResult {
    const data = event.data;

    // Only handle file events
    if (data.type !== 'file') {
      return this.allow();
    }

    const path = data.path;
    const forbiddenPaths = policy.filesystem?.forbidden_paths ?? DEFAULT_FORBIDDEN_PATHS;

    // Check against forbidden paths
    const normalizedPath = normalizePath(path);
    const matchedPattern = this.matchesForbidden(normalizedPath, forbiddenPaths);

    if (matchedPattern) {
      return this.deny(
        `Access to forbidden path: ${path} (matches pattern: ${matchedPattern})`,
        'critical',
      );
    }

    return this.allow();
  }

  /**
   * Check if a path matches any forbidden pattern
   * Returns the matching pattern if found, null otherwise
   */
  private matchesForbidden(path: string, patterns: string[]): string | null {
    const home = homedir();

    for (const pattern of patterns) {
      // Expand ~ in pattern to actual home directory
      const expandedPattern = pattern.startsWith('~')
        ? pattern.replace(/^~/, home)
        : pattern;

      // Check exact match
      if (path === expandedPattern) {
        return pattern;
      }

      // Check if path is inside a forbidden directory
      // e.g., ~/.ssh should match /Users/test/.ssh/id_rsa
      if (!expandedPattern.includes('*') && !expandedPattern.includes('?')) {
        if (path.startsWith(expandedPattern + '/') || path === expandedPattern) {
          return pattern;
        }
      }

      // Check glob pattern match with full path
      if (minimatch(path, expandedPattern, { dot: true, matchBase: false })) {
        return pattern;
      }

      // Check basename match for patterns like ".env" or "*.pem"
      const basename = path.split('/').pop() ?? '';
      // Only apply basename matching for patterns without slashes
      if (!pattern.includes('/')) {
        if (minimatch(basename, pattern, { dot: true })) {
          return pattern;
        }
      }

      // For patterns starting with **/, match anywhere in path
      if (pattern.startsWith('**/')) {
        const patternSuffix = pattern.slice(3);
        if (minimatch(basename, patternSuffix, { dot: true })) {
          return pattern;
        }
        // Also try matching from any path component
        const pathParts = path.split('/');
        for (let i = 0; i < pathParts.length; i++) {
          const subPath = pathParts.slice(i).join('/');
          if (minimatch(subPath, patternSuffix, { dot: true })) {
            return pattern;
          }
        }
      }
    }

    return null;
  }
}

/**
 * Normalize a path, expanding ~ and resolving to absolute
 */
function normalizePath(path: string): string {
  // Expand ~
  if (path.startsWith('~')) {
    path = path.replace(/^~/, homedir());
  }

  // Resolve to absolute if not a glob pattern
  if (!path.includes('*') && !path.includes('?')) {
    path = resolve(path);
  }

  // Normalize slashes
  return normalize(path);
}
