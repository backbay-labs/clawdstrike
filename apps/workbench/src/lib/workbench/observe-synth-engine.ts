/**
 * Observe & Synth Engine
 *
 * Client-side analysis of PolicyEvent JSONL streams to synthesize
 * candidate security policies. Part of the Observe -> Synth -> Tighten
 * workflow for ClawdStrike.
 */

import type {
  WorkbenchPolicy,
  GuardConfigMap,
  Verdict,
  TestActionType,
} from "./types";


export interface PolicyEvent {
  action_type: string;
  target: string;
  content?: string;
  verdict?: string;
  guard?: string;
  timestamp?: string;
  details?: Record<string, unknown>;
}

export type EventRiskLevel = "safe" | "suspicious" | "blocked";

export interface ParsedEvent extends PolicyEvent {
  /** Parsed timestamp or fallback to import time. */
  parsedTimestamp: Date;
  /** Normalized action type mapped to workbench TestActionType. */
  normalizedAction: TestActionType | null;
  /** Risk level derived from verdict and action. */
  riskLevel: EventRiskLevel;
  /** Original line index in the imported data. */
  lineIndex: number;
}


export interface SynthResult {
  /** The synthesized guard configuration. */
  guards: GuardConfigMap;
  /** Statistics about what was extracted. */
  stats: SynthStats;
  /** Coverage analysis — how each event maps to the synthesized policy. */
  coverage: EventCoverage[];
}

export interface SynthStats {
  totalEvents: number;
  uniquePaths: number;
  uniqueDomains: number;
  uniqueCommands: number;
  uniqueTools: number;
  forbiddenPathPatterns: number;
  allowedDomains: number;
  shellPatterns: number;
  mcpTools: number;
}

export interface EventCoverage {
  eventIndex: number;
  /** What the synthesized policy would do with this event. */
  synthVerdict: Verdict;
  /** Which guard would handle it. */
  guardId: string;
  /** Explanation. */
  reason: string;
}


/** Map common action_type strings from JSONL to TestActionType. */
function normalizeActionType(raw: string): TestActionType | null {
  const map: Record<string, TestActionType> = {
    file_access: "file_access",
    file_read: "file_access",
    read_file: "file_access",
    file_write: "file_write",
    write_file: "file_write",
    network: "network_egress",
    network_egress: "network_egress",
    egress: "network_egress",
    http: "network_egress",
    shell: "shell_command",
    shell_command: "shell_command",
    command: "shell_command",
    exec: "shell_command",
    mcp_tool: "mcp_tool_call",
    mcp_tool_call: "mcp_tool_call",
    tool_call: "mcp_tool_call",
    patch: "patch_apply",
    patch_apply: "patch_apply",
    user_input: "user_input",
    input: "user_input",
  };
  return map[raw.toLowerCase()] ?? null;
}

/** Determine risk level from verdict and context. */
function deriveRiskLevel(event: PolicyEvent): EventRiskLevel {
  if (event.verdict) {
    const v = event.verdict.toLowerCase();
    if (v === "deny" || v === "blocked" || v === "denied") return "blocked";
    if (v === "warn" || v === "warning" || v === "suspicious") return "suspicious";
    if (v === "allow" || v === "allowed" || v === "pass") return "safe";
  }
  // Heuristic: if no verdict, check for suspicious patterns
  const target = event.target.toLowerCase();
  if (
    target.includes(".ssh") ||
    target.includes(".aws") ||
    target.includes(".env") ||
    target.includes("passwd") ||
    target.includes("shadow") ||
    target.includes("credentials")
  ) {
    return "suspicious";
  }
  return "safe";
}

/**
 * Parse JSONL input into structured events.
 * Returns [parsed events, parse errors].
 */
export function parseEventLog(input: string): [ParsedEvent[], string[]] {
  const events: ParsedEvent[] = [];
  const errors: string[] = [];
  const lines = input.split("\n").filter((l) => l.trim().length > 0);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    try {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      if (!parsed.action_type || !parsed.target) {
        errors.push(`Line ${i + 1}: missing required fields (action_type, target)`);
        continue;
      }
      const event: PolicyEvent = {
        action_type: String(parsed.action_type),
        target: String(parsed.target),
        content: parsed.content ? String(parsed.content) : undefined,
        verdict: parsed.verdict ? String(parsed.verdict) : undefined,
        guard: parsed.guard ? String(parsed.guard) : undefined,
        timestamp: parsed.timestamp ? String(parsed.timestamp) : undefined,
        details: parsed.details && typeof parsed.details === "object"
          ? parsed.details as Record<string, unknown>
          : undefined,
      };
      events.push({
        ...event,
        parsedTimestamp: event.timestamp ? new Date(event.timestamp) : new Date(),
        normalizedAction: normalizeActionType(event.action_type),
        riskLevel: deriveRiskLevel(event),
        lineIndex: i,
      });
    } catch {
      errors.push(`Line ${i + 1}: invalid JSON`);
    }
  }

  return [events, errors];
}


/** Known sensitive path patterns. */
const SENSITIVE_PATH_PATTERNS = [
  "**/.ssh/**",
  "**/.aws/**",
  "**/.env",
  "**/.env.*",
  "**/.git-credentials",
  "**/.gnupg/**",
  "**/.kube/**",
  "/etc/shadow",
  "/etc/passwd",
  "**/credentials*",
  "**/*.pem",
  "**/*.key",
];

/** Known dangerous shell patterns. */
const DANGEROUS_SHELL_PATTERNS = [
  "rm\\s+-rf\\s+/",
  "mkfs\\.",
  "dd\\s+if=",
  ":(){ :|:& };:",
  ">/dev/sd",
  "chmod\\s+777",
  "curl.*\\|.*(?:bash|sh)",
  "wget.*\\|.*(?:bash|sh)",
  "nc\\s+-e",
  "bash\\s+-i\\s+>&",
  "/dev/tcp/",
  "\\beval\\b.*\\bbase64\\b",
];

/** Extract domain from a target that might be a URL or host:port. */
function extractDomain(target: string): string {
  let host = target;
  // Strip protocol
  if (host.includes("://")) {
    host = host.split("://")[1];
  }
  // Strip path
  if (host.includes("/")) {
    host = host.split("/")[0];
  }
  // Strip port
  if (host.includes(":")) {
    host = host.split(":")[0];
  }
  return host.toLowerCase();
}

/** Check if a path matches any sensitive pattern (simple heuristic). */
function isSensitivePath(path: string): boolean {
  const lower = path.toLowerCase();
  return (
    lower.includes(".ssh") ||
    lower.includes(".aws") ||
    lower.includes(".env") ||
    lower.includes(".gnupg") ||
    lower.includes(".kube") ||
    lower.includes("passwd") ||
    lower.includes("shadow") ||
    lower.includes("credentials") ||
    lower.includes(".pem") ||
    lower.includes(".key") ||
    lower.includes("id_rsa") ||
    lower.includes("id_ed25519")
  );
}

/**
 * Synthesize a candidate policy from observed events.
 *
 * The algorithm:
 * 1. Collect all file paths -> split into sensitive (forbidden) and normal (allowlist)
 * 2. Collect all domains -> build egress allowlist
 * 3. Collect all shell commands -> detect dangerous patterns
 * 4. Collect all MCP tools -> build allow/block lists based on verdicts
 */
export function synthesizePolicy(events: ParsedEvent[]): SynthResult {
  // Buckets
  const filePaths = new Set<string>();
  const sensitivePaths = new Set<string>();
  const domains = new Set<string>();
  const shellCommands = new Set<string>();
  const mcpToolsAllowed = new Set<string>();
  const mcpToolsBlocked = new Set<string>();

  for (const event of events) {
    const action = event.normalizedAction;
    if (!action) continue;

    switch (action) {
      case "file_access":
      case "file_write":
      case "patch_apply": {
        const path = event.target;
        if (isSensitivePath(path)) {
          sensitivePaths.add(path);
        } else {
          filePaths.add(path);
        }
        break;
      }
      case "network_egress": {
        const domain = extractDomain(event.target);
        if (domain) domains.add(domain);
        break;
      }
      case "shell_command": {
        shellCommands.add(event.target);
        break;
      }
      case "mcp_tool_call": {
        const tool = event.target;
        if (event.verdict?.toLowerCase() === "deny" || event.verdict?.toLowerCase() === "blocked") {
          mcpToolsBlocked.add(tool);
        } else {
          mcpToolsAllowed.add(tool);
        }
        break;
      }
      default:
        break;
    }
  }

  // Build guard configs
  const guards: GuardConfigMap = {};

  // Forbidden path guard
  if (sensitivePaths.size > 0 || filePaths.size > 0) {
    guards.forbidden_path = {
      enabled: true,
      patterns: [...SENSITIVE_PATH_PATTERNS],
      exceptions: [],
    };
  }

  // Path allowlist: build glob patterns from observed safe paths
  if (filePaths.size > 0) {
    const directories = new Set<string>();
    for (const p of filePaths) {
      const parts = p.split("/");
      if (parts.length > 2) {
        // Create directory-level glob patterns
        directories.add(parts.slice(0, -1).join("/") + "/**");
      } else {
        directories.add(p);
      }
    }
    guards.path_allowlist = {
      enabled: false, // Start disabled — user should review first
      file_access_allow: [...directories],
      file_write_allow: [...directories],
    };
  }

  // Egress allowlist
  if (domains.size > 0) {
    // Group domains by their root domain to create wildcard patterns
    const rootDomains = new Map<string, Set<string>>();
    for (const d of domains) {
      const parts = d.split(".");
      const root = parts.length >= 2 ? parts.slice(-2).join(".") : d;
      if (!rootDomains.has(root)) rootDomains.set(root, new Set());
      rootDomains.get(root)!.add(d);
    }

    const allowPatterns: string[] = [];
    for (const [root, subdomains] of rootDomains) {
      if (subdomains.size > 1) {
        // Multiple subdomains -> use wildcard
        allowPatterns.push(`*.${root}`);
      } else {
        // Single domain -> keep specific
        allowPatterns.push([...subdomains][0]);
      }
    }

    guards.egress_allowlist = {
      enabled: true,
      allow: allowPatterns.sort(),
      block: [],
      default_action: "block",
    };
  }

  // Shell command guard
  guards.shell_command = {
    enabled: true,
    forbidden_patterns: [...DANGEROUS_SHELL_PATTERNS],
  };

  // MCP tool guard
  if (mcpToolsAllowed.size > 0 || mcpToolsBlocked.size > 0) {
    guards.mcp_tool = {
      enabled: true,
      allow: [...mcpToolsAllowed].sort(),
      block: [...mcpToolsBlocked].sort(),
      default_action: mcpToolsAllowed.size > 0 ? "block" : "allow",
    };
  }

  // Secret leak guard (always recommended)
  guards.secret_leak = {
    enabled: true,
    patterns: [
      { name: "aws_access_key", pattern: "AKIA[0-9A-Z]{16}", severity: "critical" },
      { name: "github_token", pattern: "gh[ps]_[A-Za-z0-9]{36}", severity: "critical" },
      { name: "private_key", pattern: "-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----", severity: "critical" },
    ],
  };

  // Build coverage analysis — use lineIndex to match events back to their
  // original input line, which is how the UI looks them up.
  const coverage: EventCoverage[] = events.map((event) => {
    return computeEventCoverage(event, event.lineIndex, guards);
  });

  const stats: SynthStats = {
    totalEvents: events.length,
    uniquePaths: filePaths.size + sensitivePaths.size,
    uniqueDomains: domains.size,
    uniqueCommands: shellCommands.size,
    uniqueTools: mcpToolsAllowed.size + mcpToolsBlocked.size,
    forbiddenPathPatterns: guards.forbidden_path?.patterns?.length ?? 0,
    allowedDomains: guards.egress_allowlist?.allow?.length ?? 0,
    shellPatterns: guards.shell_command?.forbidden_patterns?.length ?? 0,
    mcpTools: (guards.mcp_tool?.allow?.length ?? 0) + (guards.mcp_tool?.block?.length ?? 0),
  };

  return { guards, stats, coverage };
}

/** Compute what the synthesized policy would do with a specific event. */
function computeEventCoverage(
  event: ParsedEvent,
  eventIndex: number,
  guards: GuardConfigMap,
): EventCoverage {
  const action = event.normalizedAction;

  if (!action) {
    return {
      eventIndex,
      synthVerdict: "allow",
      guardId: "unknown",
      reason: `Unknown action type "${event.action_type}" — not covered by synthesized policy`,
    };
  }

  switch (action) {
    case "file_access":
    case "file_write":
    case "patch_apply": {
      if (isSensitivePath(event.target)) {
        return {
          eventIndex,
          synthVerdict: "deny",
          guardId: "forbidden_path",
          reason: `Path "${event.target}" matches a sensitive pattern — would be blocked`,
        };
      }
      return {
        eventIndex,
        synthVerdict: "allow",
        guardId: "forbidden_path",
        reason: `Path "${event.target}" not in forbidden patterns — would be allowed`,
      };
    }
    case "network_egress": {
      const domain = extractDomain(event.target);
      const allowList = guards.egress_allowlist?.allow ?? [];
      const matched = allowList.some((pat) => {
        if (pat.startsWith("*.")) {
          const suffix = pat.slice(1);
          return domain.endsWith(suffix) || domain === pat.slice(2);
        }
        return domain === pat;
      });
      return {
        eventIndex,
        synthVerdict: matched ? "allow" : "deny",
        guardId: "egress_allowlist",
        reason: matched
          ? `Domain "${domain}" is in the generated allow list`
          : `Domain "${domain}" not in allow list — default action: block`,
      };
    }
    case "shell_command": {
      const cmd = event.target;
      const patterns = guards.shell_command?.forbidden_patterns ?? [];
      for (const pat of patterns) {
        try {
          if (new RegExp(pat, "i").test(cmd)) {
            return {
              eventIndex,
              synthVerdict: "deny",
              guardId: "shell_command",
              reason: `Command matches forbidden pattern "${pat}"`,
            };
          }
        } catch {
          // skip invalid regex
        }
      }
      return {
        eventIndex,
        synthVerdict: "allow",
        guardId: "shell_command",
        reason: "Command does not match any forbidden pattern",
      };
    }
    case "mcp_tool_call": {
      const tool = event.target;
      const blocked = guards.mcp_tool?.block ?? [];
      const allowed = guards.mcp_tool?.allow ?? [];
      if (blocked.includes(tool)) {
        return {
          eventIndex,
          synthVerdict: "deny",
          guardId: "mcp_tool",
          reason: `Tool "${tool}" is in the block list`,
        };
      }
      if (allowed.includes(tool)) {
        return {
          eventIndex,
          synthVerdict: "allow",
          guardId: "mcp_tool",
          reason: `Tool "${tool}" is in the allow list`,
        };
      }
      const defaultAction = guards.mcp_tool?.default_action ?? "allow";
      return {
        eventIndex,
        synthVerdict: defaultAction === "block" ? "deny" : "allow",
        guardId: "mcp_tool",
        reason: `Tool "${tool}" not in any list — default: ${defaultAction}`,
      };
    }
    case "user_input":
      return {
        eventIndex,
        synthVerdict: "allow",
        guardId: "prompt_injection",
        reason: "User input — prompt injection detection requires runtime analysis",
      };
    default:
      return {
        eventIndex,
        synthVerdict: "allow",
        guardId: "unknown",
        reason: "Action type not covered by synthesized policy",
      };
  }
}

/**
 * Merge synthesized guards into an existing policy.
 * The merge strategy: synthesized values extend (not replace) existing config.
 */
export function mergeSynthIntoPolicy(
  policy: WorkbenchPolicy,
  synthGuards: GuardConfigMap,
): WorkbenchPolicy {
  const merged = { ...policy, guards: { ...policy.guards } };

  // Forbidden path: merge patterns
  if (synthGuards.forbidden_path) {
    const existing = merged.guards.forbidden_path ?? { enabled: true, patterns: [] };
    const existingPatterns = new Set(existing.patterns ?? []);
    const newPatterns = (synthGuards.forbidden_path.patterns ?? []).filter(
      (p) => !existingPatterns.has(p),
    );
    merged.guards.forbidden_path = {
      ...existing,
      enabled: true,
      patterns: [...(existing.patterns ?? []), ...newPatterns],
    };
  }

  // Egress allowlist: merge allow lists
  if (synthGuards.egress_allowlist) {
    const existing = merged.guards.egress_allowlist ?? { enabled: true, allow: [] };
    const existingAllow = new Set(existing.allow ?? []);
    const newAllow = (synthGuards.egress_allowlist.allow ?? []).filter(
      (d) => !existingAllow.has(d),
    );
    merged.guards.egress_allowlist = {
      ...existing,
      enabled: true,
      allow: [...(existing.allow ?? []), ...newAllow],
      default_action: existing.default_action ?? "block",
    };
  }

  // Shell command: merge forbidden patterns
  if (synthGuards.shell_command) {
    const existing = merged.guards.shell_command ?? { enabled: true, forbidden_patterns: [] };
    const existingPats = new Set(existing.forbidden_patterns ?? []);
    const newPats = (synthGuards.shell_command.forbidden_patterns ?? []).filter(
      (p) => !existingPats.has(p),
    );
    merged.guards.shell_command = {
      ...existing,
      enabled: true,
      forbidden_patterns: [...(existing.forbidden_patterns ?? []), ...newPats],
    };
  }

  // MCP tool: merge allow/block lists
  if (synthGuards.mcp_tool) {
    const existing = merged.guards.mcp_tool ?? { enabled: true, allow: [], block: [] };
    const existingAllow = new Set(existing.allow ?? []);
    const existingBlock = new Set(existing.block ?? []);
    const newAllow = (synthGuards.mcp_tool.allow ?? []).filter(
      (t) => !existingAllow.has(t),
    );
    const newBlock = (synthGuards.mcp_tool.block ?? []).filter(
      (t) => !existingBlock.has(t),
    );
    merged.guards.mcp_tool = {
      ...existing,
      enabled: true,
      allow: [...(existing.allow ?? []), ...newAllow],
      block: [...(existing.block ?? []), ...newBlock],
    };
  }

  // Secret leak: ensure it's enabled
  if (synthGuards.secret_leak && !merged.guards.secret_leak) {
    merged.guards.secret_leak = synthGuards.secret_leak;
  }

  // Path allowlist: add if not present
  if (synthGuards.path_allowlist && !merged.guards.path_allowlist) {
    merged.guards.path_allowlist = synthGuards.path_allowlist;
  }

  return merged;
}
