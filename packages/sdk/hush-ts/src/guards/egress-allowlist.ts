import { Guard, GuardAction, GuardContext, GuardResult, Severity } from "./types";

export interface EgressAllowlistConfig {
  enabled?: boolean;
  allow?: string[];
  block?: string[];
  defaultAction?: "allow" | "block";
}

function escapeRegex(ch: string): string {
  return ch.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");
}

function globToRegExp(pattern: string): RegExp {
  if (!pattern) {
    throw new Error("glob pattern must be non-empty");
  }

  let out = "^";
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];

    if (ch === "\\") {
      const next = pattern[i + 1];
      if (next === undefined) {
        throw new Error("glob pattern ends with escape");
      }
      out += escapeRegex(next);
      i++;
      continue;
    }

    if (ch === "*") {
      out += ".*";
      continue;
    }

    if (ch === "?") {
      out += ".";
      continue;
    }

    if (ch === "[") {
      const end = pattern.indexOf("]", i + 1);
      if (end === -1) {
        throw new Error("glob pattern has unclosed character class");
      }
      let body = pattern.slice(i + 1, end);
      if (body.length === 0) {
        throw new Error("glob pattern has empty character class");
      }

      let negate = false;
      if (body.startsWith("!")) {
        negate = true;
        body = body.slice(1);
      }

      let classOut = "[";
      if (negate) classOut += "^";

      for (let j = 0; j < body.length; j++) {
        const c = body[j];
        if (c === "\\") {
          const next = body[j + 1];
          if (next === undefined) {
            throw new Error("glob character class ends with escape");
          }
          if (next === "\\") {
            classOut += "\\\\";
          } else if (next === "]") {
            classOut += "\\]";
          } else if (next === "^") {
            classOut += "\\^";
          } else if (next === "-") {
            classOut += "\\-";
          } else {
            classOut += next;
          }
          j++;
          continue;
        }
        if (c === "]") {
          classOut += "\\]";
          continue;
        }
        if (c === "^") {
          classOut += "\\^";
          continue;
        }
        if (c === "-" && (j === 0 || j === body.length - 1)) {
          classOut += "\\-";
          continue;
        }
        classOut += c;
      }

      classOut += "]";
      out += classOut;
      i = end;
      continue;
    }

    out += escapeRegex(ch);
  }

  out += "$";
  return new RegExp(out, "i");
}

/**
 * Guard that controls outbound network access.
 */
export class EgressAllowlistGuard implements Guard {
  readonly name = "egress_allowlist";
  private enabled: boolean;
  private allow: RegExp[];
  private block: RegExp[];
  private defaultAction: "allow" | "block";

  constructor(config: EgressAllowlistConfig = {}) {
    this.enabled = config.enabled ?? true;
    this.allow = (config.allow ?? []).map((p) => globToRegExp(p));
    this.block = (config.block ?? []).map((p) => globToRegExp(p));
    this.defaultAction = config.defaultAction ?? "block";
  }

  handles(action: GuardAction): boolean {
    return this.enabled && action.actionType === "network_egress";
  }

  check(action: GuardAction, _context: GuardContext): GuardResult {
    if (!this.enabled) {
      return GuardResult.allow(this.name);
    }
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

  private matchesAny(host: string, patterns: RegExp[]): boolean {
    return patterns.some((re) => re.test(host));
  }
}
