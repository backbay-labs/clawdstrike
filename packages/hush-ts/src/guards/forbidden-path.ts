import { Guard, GuardAction, GuardContext, GuardResult, Severity } from "./types";

const DEFAULT_FORBIDDEN_PATTERNS = [
  // SSH keys
  "**/.ssh/**",
  "**/id_rsa*",
  "**/id_ed25519*",
  "**/id_ecdsa*",
  // AWS credentials
  "**/.aws/**",
  // Environment files
  "**/.env",
  "**/.env.*",
  // Git credentials
  "**/.git-credentials",
  "**/.gitconfig",
  // GPG keys
  "**/.gnupg/**",
  // Kubernetes
  "**/.kube/**",
  // Docker
  "**/.docker/**",
  // NPM tokens
  "**/.npmrc",
  // Password stores
  "**/.password-store/**",
  "**/pass/**",
  // 1Password
  "**/.1password/**",
  // System paths
  "/etc/shadow",
  "/etc/passwd",
  "/etc/sudoers",
];

export interface ForbiddenPathConfig {
  patterns?: string[];
  exceptions?: string[];
}

/**
 * Guard that blocks access to sensitive paths.
 */
export class ForbiddenPathGuard implements Guard {
  readonly name = "forbidden_path";
  private patterns: string[];
  private exceptions: string[];

  constructor(config: ForbiddenPathConfig = {}) {
    this.patterns = config.patterns ?? DEFAULT_FORBIDDEN_PATTERNS;
    this.exceptions = config.exceptions ?? [];
  }

  handles(action: GuardAction): boolean {
    return ["file_access", "file_write", "patch"].includes(action.actionType);
  }

  check(action: GuardAction, _context: GuardContext): GuardResult {
    if (!this.handles(action)) {
      return GuardResult.allow(this.name);
    }

    const path = action.path;
    if (!path) {
      return GuardResult.allow(this.name);
    }

    if (this.isForbidden(path)) {
      return GuardResult.block(
        this.name,
        Severity.CRITICAL,
        `Access to forbidden path: ${path}`
      ).withDetails({
        path,
        reason: "matches_forbidden_pattern",
      });
    }

    return GuardResult.allow(this.name);
  }

  private isForbidden(path: string): boolean {
    // Normalize path (handle Windows paths)
    const normalized = path.replace(/\\/g, "/");

    // Check exceptions first
    for (const exception of this.exceptions) {
      if (matchGlob(normalized, exception)) {
        return false;
      }
    }

    // Check forbidden patterns
    for (const pattern of this.patterns) {
      if (matchGlob(normalized, pattern)) {
        return true;
      }
    }

    return false;
  }
}

/**
 * Simple glob matcher supporting:
 * - * matches any characters except /
 * - ** matches any characters including /
 * - ? matches any single character
 */
function matchGlob(path: string, pattern: string): boolean {
  // Convert glob to regex
  let regex = pattern
    .replace(/\*\*/g, "\u0000") // Placeholder for **
    .replace(/\*/g, "[^/]*")
    .replace(/\u0000/g, ".*")
    .replace(/\?/g, ".");

  // Escape dots that aren't part of patterns
  regex = regex.replace(/\.(?!\*)/g, "\\.");

  // Anchor the pattern
  if (!regex.startsWith(".*") && !regex.startsWith("/")) {
    regex = "(^|.*/)" + regex;
  }
  regex = "^" + regex + "$";

  return new RegExp(regex).test(path);
}
