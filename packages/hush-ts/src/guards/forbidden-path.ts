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
  enabled?: boolean;
  patterns?: string[];
  exceptions?: string[];
}

/**
 * Guard that blocks access to sensitive paths.
 */
export class ForbiddenPathGuard implements Guard {
  readonly name = "forbidden_path";
  private enabled: boolean;
  private patterns: string[];
  private exceptions: string[];

  constructor(config: ForbiddenPathConfig = {}) {
    this.enabled = config.enabled ?? true;
    this.patterns = config.patterns ?? DEFAULT_FORBIDDEN_PATTERNS;
    this.exceptions = config.exceptions ?? [];
  }

  handles(action: GuardAction): boolean {
    return this.enabled && ["file_access", "file_write", "patch"].includes(action.actionType);
  }

  check(action: GuardAction, _context: GuardContext): GuardResult {
    if (!this.enabled) {
      return GuardResult.allow(this.name);
    }
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
 * Escape regex metacharacters in a string.
 */
function escapeRegex(str: string): string {
  return str.replace(/[.+^${}()|[\]\\]/g, "\\$&");
}

/**
 * Simple glob matcher supporting:
 * - * matches any characters except /
 * - ** matches any characters including /
 * - ? matches any single character
 */
function matchGlob(path: string, pattern: string): boolean {
  // Split pattern into segments, preserving glob operators
  let regex = "";
  let i = 0;

  while (i < pattern.length) {
    if (pattern[i] === "*") {
      if (pattern[i + 1] === "*") {
        // ** matches any characters including /
        regex += ".*";
        i += 2;
      } else {
        // * matches any characters except /
        regex += "[^/]*";
        i++;
      }
    } else if (pattern[i] === "?") {
      // ? matches any single character
      regex += ".";
      i++;
    } else {
      // Escape the character if it's a regex metacharacter
      regex += escapeRegex(pattern[i]);
      i++;
    }
  }

  // Anchor the pattern
  if (!regex.startsWith(".*") && !pattern.startsWith("/")) {
    regex = "(^|.*/)" + regex;
  }
  regex = "^" + regex + "$";

  try {
    return new RegExp(regex).test(path);
  } catch {
    // Invalid regex, treat as no match
    return false;
  }
}
