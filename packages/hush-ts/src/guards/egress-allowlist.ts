import { Guard, GuardAction, GuardContext, GuardResult, Severity } from "./types";

export interface EgressAllowlistConfig {
  allow?: string[];
  block?: string[];
  defaultAction?: "allow" | "block";
}

/**
 * Guard that controls outbound network access.
 */
export class EgressAllowlistGuard implements Guard {
  readonly name = "egress_allowlist";
  private allow: string[];
  private block: string[];
  private defaultAction: "allow" | "block";

  constructor(config: EgressAllowlistConfig = {}) {
    this.allow = config.allow ?? [];
    this.block = config.block ?? [];
    this.defaultAction = config.defaultAction ?? "block";
  }

  handles(action: GuardAction): boolean {
    return action.actionType === "network_egress";
  }

  check(action: GuardAction, _context: GuardContext): GuardResult {
    if (!this.handles(action)) {
      return GuardResult.allow(this.name);
    }

    const host = action.host;
    if (!host) {
      return GuardResult.allow(this.name);
    }

    // Check block list first (takes precedence)
    if (this.matchesAny(host, this.block)) {
      return GuardResult.block(
        this.name,
        Severity.ERROR,
        `Egress to blocked destination: ${host}`
      ).withDetails({
        host,
        port: action.port,
        reason: "explicitly_blocked",
      });
    }

    // Check allow list
    if (this.matchesAny(host, this.allow)) {
      return GuardResult.allow(this.name);
    }

    // Apply default action
    if (this.defaultAction === "allow") {
      return GuardResult.allow(this.name);
    }

    return GuardResult.block(
      this.name,
      Severity.ERROR,
      `Egress to unlisted destination: ${host}`
    ).withDetails({
      host,
      port: action.port,
      reason: "not_in_allowlist",
    });
  }

  private matchesAny(host: string, patterns: string[]): boolean {
    return patterns.some((p) => this.matchPattern(host, p));
  }

  private matchPattern(host: string, pattern: string): boolean {
    if (!pattern) return false;

    // Exact match
    if (host === pattern) return true;

    // Wildcard pattern: *.example.com
    if (pattern.startsWith("*.")) {
      const suffix = pattern.slice(1); // ".example.com"
      return host.endsWith(suffix);
    }

    // Subdomain matching: host ends with .pattern
    if (host.endsWith("." + pattern)) {
      return true;
    }

    return false;
  }
}
