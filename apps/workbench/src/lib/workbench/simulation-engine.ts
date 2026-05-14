import type {
  WorkbenchPolicy,
  TestScenario,
  SimulationResult,
  GuardSimResult,
  GuardId,
  Verdict,
  ForbiddenPathConfig,
  PathAllowlistConfig,
  EgressAllowlistConfig,
  SecretLeakConfig,
  PatchIntegrityConfig,
  ShellCommandConfig,
  McpToolConfig,
  PromptInjectionConfig,
  JailbreakConfig,
  ComputerUseConfig,
  RemoteDesktopSideChannelConfig,
  InputInjectionCapabilityConfig,
  SpiderSenseConfig,
} from "./types";
import { getGuardMeta } from "./guard-registry";
import { gradeSimulationResult } from "./redteam/grading";
import type { RedTeamGradingResult } from "./redteam/types";


const regexCache = new Map<string, RegExp>();
function cachedRegex(pattern: string, flags?: string): RegExp {
  const key = `${pattern}::${flags ?? ''}`;
  let re = regexCache.get(key);
  if (!re) {
    re = new RegExp(pattern, flags);
    regexCache.set(key, re);
    // Cap cache at 500 entries to prevent unbounded growth
    if (regexCache.size > 500) {
      const firstKey = regexCache.keys().next().value;
      if (firstKey !== undefined) regexCache.delete(firstKey);
    }
  }
  return re;
}


/** Max content size for regex testing (1 MB). Content exceeding this is not tested. */
const MAX_REGEX_CONTENT_BYTES = 1_048_576;

/** Reject regex patterns with nested quantifiers that can cause catastrophic backtracking. */
function isSafeRegex(pattern: string): boolean {
  // Reject patterns longer than 500 chars (Finding M14: reduced from 1000)
  if (pattern.length > 500) return false;
  // Reject nested quantifiers: (x+)+, (x*)+, (x+)*, etc.
  if (/(\+|\*|\{)\)?(\+|\*|\{)/.test(pattern)) return false;
  // Reject backreferences (\1, \2, etc.) (Finding M14)
  if (/\\[1-9]/.test(pattern)) return false;
  // Reject lookahead/lookbehind containing quantifiers (Finding M14)
  if (/\(\?[=!<][^)]*[+*{]/.test(pattern)) return false;
  // Reject deeply nested groups (>10 levels) (Finding M14)
  let maxDepth = 0;
  let depth = 0;
  for (const ch of pattern) {
    if (ch === "(") { depth++; maxDepth = Math.max(maxDepth, depth); }
    else if (ch === ")") { depth = Math.max(0, depth - 1); }
  }
  if (maxDepth > 10) return false;
  // Reject excessive alternation groups (>20)
  if ((pattern.match(/\|/g) || []).length > 20) return false;
  // Reject duplicate alternation branches (e.g. (a|a)) — backreference-style bypass
  const altGroups = pattern.match(/\(([^)]+)\)/g) || [];
  for (const group of altGroups) {
    const inner = group.slice(1, -1);
    const branches = inner.split("|");
    const unique = new Set(branches);
    if (unique.size < branches.length) return false;
  }
  // Reject excessive repetition quantifiers {n,m} where m > 1000
  const repMatches = pattern.matchAll(/\{(\d+)(?:,(\d+))?\}/g);
  for (const m of repMatches) {
    const upper = m[2] !== undefined ? parseInt(m[2], 10) : parseInt(m[1], 10);
    if (upper > 1000) return false;
  }
  return true;
}


/**
 * Normalize a filesystem path by resolving `.` and `..` segments and collapsing
 * multiple slashes. Relative paths are anchored under `/workspace/` so they
 * can be tested against absolute glob patterns.
 */
function normalizePath(p: string): string {
  if (!p || p.trim() === "") return "/";

  // Collapse multiple slashes
  let cleaned = p.replace(/\/\/+/g, "/");

  // Resolve . and .. segments
  const parts = cleaned.split("/");
  const resolved: string[] = [];
  for (const part of parts) {
    if (part === "." || part === "") {
      // Skip empty segments (from leading `/`) unless it's the first one
      if (resolved.length === 0 && cleaned.startsWith("/")) resolved.push("");
      continue;
    }
    if (part === "..") {
      // Don't pop past root
      if (resolved.length > 1 || (resolved.length === 1 && resolved[0] !== "")) {
        resolved.pop();
      }
      continue;
    }
    resolved.push(part);
  }

  let result = resolved.join("/") || "/";

  // Ensure we preserve the leading slash
  if (cleaned.startsWith("/") && !result.startsWith("/")) {
    result = "/" + result;
  }

  // If the path is still relative, anchor it so glob patterns can match.
  // Paths starting with parent traversal (../) indicate an attempt to reach
  // paths above the working directory — treat them as rooted at /.
  if (!result.startsWith("/") && !result.startsWith("~")) {
    result = "/" + result;
  }

  return result;
}


/** Convert a simple glob pattern to a RegExp. Supports `*` and `**`. */
function globToRegex(pattern: string): RegExp {
  let re = pattern
    // Escape regex meta-chars except * and ?
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    // ** matches any path segment(s)
    .replace(/\*\*/g, "__DOUBLESTAR__")
    // * matches anything except /
    .replace(/\*/g, "[^/]*")
    .replace(/__DOUBLESTAR__/g, ".*")
    // ? matches single char
    .replace(/\?/g, ".");

  // If pattern doesn't start with / or ~, treat as suffix match
  if (!pattern.startsWith("/") && !pattern.startsWith("~")) {
    re = "(?:^|/)" + re;
  }

  // Anchor patterns that start with / or ~ so they only match from the beginning
  if (pattern.startsWith("/") || pattern.startsWith("~")) {
    re = "^" + re;
  }

  // Case-sensitive to match Rust glob::Pattern::matches() semantics
  return cachedRegex(re + "$");
}

/** Wildcard domain match (e.g. *.openai.com matches api.openai.com). */
function domainMatches(pattern: string, host: string): boolean {
  if (pattern === host) return true;
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(1); // .openai.com
    return host.endsWith(suffix) || host === pattern.slice(2);
  }
  return false;
}


function simulateForbiddenPath(
  config: ForbiddenPathConfig,
  scenario: TestScenario,
): GuardSimResult | null {
  const { actionType, payload } = scenario;
  if (actionType !== "file_access" && actionType !== "file_write" && actionType !== "patch_apply") return null;

  const path = normalizePath((payload.path as string) || "");
  const patterns = config.patterns || [];
  const exceptions = config.exceptions || [];

  // Check exceptions first
  for (const exc of exceptions) {
    if (globToRegex(exc).test(path)) {
      return {
        guardId: "forbidden_path",
        guardName: "Forbidden Path",
        verdict: "allow",
        message: `Path "${path}" matched exception "${exc}"`,
        evidence: { path, matchedException: exc },
      };
    }
  }

  for (const pat of patterns) {
    if (globToRegex(pat).test(path)) {
      return {
        guardId: "forbidden_path",
        guardName: "Forbidden Path",
        verdict: "deny",
        message: `Path "${path}" matched forbidden pattern "${pat}"`,
        evidence: { path, matchedPattern: pat },
      };
    }
  }

  return {
    guardId: "forbidden_path",
    guardName: "Forbidden Path",
    verdict: "allow",
    message: `Path "${path}" not matched by any forbidden pattern`,
    evidence: { path },
  };
}

function simulateEgressAllowlist(
  config: EgressAllowlistConfig,
  scenario: TestScenario,
): GuardSimResult | null {
  if (scenario.actionType !== "network_egress") return null;

  const host = (scenario.payload.host as string) || "";
  const blockList = config.block || [];
  const allowList = config.allow || [];
  const defaultAction = config.default_action || "block";

  // Block list takes precedence
  for (const pat of blockList) {
    if (domainMatches(pat, host)) {
      return {
        guardId: "egress_allowlist",
        guardName: "Egress Control",
        verdict: "deny",
        message: `Host "${host}" matched block pattern "${pat}"`,
        evidence: { host, matchedBlock: pat },
      };
    }
  }

  // Allow list
  for (const pat of allowList) {
    if (domainMatches(pat, host)) {
      return {
        guardId: "egress_allowlist",
        guardName: "Egress Control",
        verdict: "allow",
        message: `Host "${host}" matched allow pattern "${pat}"`,
        evidence: { host, matchedAllow: pat },
      };
    }
  }

  // Default action
  const verdict: Verdict =
    defaultAction === "allow"
      ? "allow"
      : defaultAction === "log"
      ? "warn"
      : "deny";
  return {
    guardId: "egress_allowlist",
    guardName: "Egress Control",
    verdict,
    message: `Host "${host}" not matched; default action: ${defaultAction}`,
    evidence: { host, defaultAction },
  };
}

function secretSeverityRank(severity: string): number {
  switch (severity) {
    case "info":
      return 0;
    case "warning":
      return 1;
    case "error":
      return 2;
    case "critical":
      return 3;
    default:
      return -1;
  }
}

function simulateSecretLeak(
  config: SecretLeakConfig,
  scenario: TestScenario,
): GuardSimResult | null {
  if (scenario.actionType !== "file_write") return null;

  const content = (scenario.payload.content as string) || "";
  const path = normalizePath((scenario.payload.path as string) || "");
  const patterns = config.patterns || [];
  const skipPaths = config.skip_paths || [];
  const shouldRedact = config.redact !== false;
  const severityThreshold = config.severity_threshold || "error";

  // Content size cap: skip regex testing and deny if content exceeds 1 MB
  if (content.length > MAX_REGEX_CONTENT_BYTES) {
    return {
      guardId: "secret_leak",
      guardName: "Secret Leak",
      verdict: "deny",
      message: `Content size (${content.length} bytes) exceeds 1 MB cap — denied without regex testing`,
      evidence: { path, contentSize: content.length, cap: MAX_REGEX_CONTENT_BYTES },
    };
  }

  // Check skip paths
  for (const sp of skipPaths) {
    if (globToRegex(sp).test(path)) {
      return {
        guardId: "secret_leak",
        guardName: "Secret Leak",
        verdict: "allow",
        message: `Path "${path}" is in skip_paths`,
        evidence: { path, skippedBy: sp },
      };
    }
  }

  const matches: Array<{
    name: string;
    pattern: string;
    severity: string;
    matchLength: number;
  }> = [];
  const skippedPatterns: Array<{ name: string; pattern: string; reason: string }> = [];
  for (const sp of patterns) {
    if (!isSafeRegex(sp.pattern)) {
      skippedPatterns.push({
        name: sp.name,
        pattern: sp.pattern,
        reason: "skipped_unsafe_regex",
      });
      continue;
    }
    try {
      const re = cachedRegex(sp.pattern);
      const match = re.exec(content);
      if (match) {
        const matchedValue = match[0] ?? "";
        matches.push({
          name: sp.name,
          pattern: sp.pattern,
          severity: sp.severity,
          matchLength: matchedValue.length,
        });
      }
    } catch (e) {
      // Fail closed: invalid regex patterns deny access
      return {
        guardId: "secret_leak",
        guardName: "Secret Leak",
        verdict: "deny" as const,
        message: `Invalid pattern: ${e instanceof Error ? e.message : String(e)}`,
        evidence: { error: "invalid_regex_pattern" },
      };
    }
  }

  if (matches.length > 0) {
    const maxSeverity = matches.reduce<string>(
      (currentMax, match) =>
        secretSeverityRank(match.severity) > secretSeverityRank(currentMax)
          ? match.severity
          : currentMax,
      matches[0].severity,
    );
    const shouldBlock =
      secretSeverityRank(maxSeverity) >= secretSeverityRank(severityThreshold);

    return {
      guardId: "secret_leak",
      guardName: "Secret Leak",
      verdict: shouldBlock ? "deny" : "warn",
      message: shouldBlock
        ? `Detected ${matches.length} secret(s): ${matches.map((m) => m.name).join(", ")}`
        : `Detected ${matches.length} secret(s) below block threshold ${severityThreshold}: ${matches.map((m) => m.name).join(", ")}`,
      evidence: {
        path,
        redactionRequested: shouldRedact,
        severityThreshold,
        matches,
        skippedPatterns,
      },
    };
  }

  return {
    guardId: "secret_leak",
    guardName: "Secret Leak",
    verdict: skippedPatterns.length > 0 ? "warn" : "allow",
    message:
      skippedPatterns.length > 0
        ? "Skipped one or more unsafe secret detection patterns"
        : "No secrets detected in content",
    evidence: { path, skippedPatterns },
  };
}

function simulatePatchIntegrity(
  config: PatchIntegrityConfig,
  scenario: TestScenario,
): GuardSimResult | null {
  if (scenario.actionType !== "patch_apply") return null;

  const content = (scenario.payload.content as string) || "";

  // Content size cap: skip regex testing and deny if content exceeds 1 MB
  if (content.length > MAX_REGEX_CONTENT_BYTES) {
    return {
      guardId: "patch_integrity",
      guardName: "Patch Integrity",
      verdict: "deny",
      message: `Patch content size (${content.length} bytes) exceeds 1 MB cap — denied without regex testing`,
      evidence: { contentSize: content.length, cap: MAX_REGEX_CONTENT_BYTES },
    };
  }

  const lines = content.split("\n");
  const additions = lines.filter((l) => l.startsWith("+") && !l.startsWith("+++")).length;
  const deletions = lines.filter((l) => l.startsWith("-") && !l.startsWith("---")).length;

  const maxAdd = config.max_additions ?? 1000;
  const maxDel = config.max_deletions ?? 500;
  const forbiddenPatterns = config.forbidden_patterns || [];

  if (additions > maxAdd) {
    return {
      guardId: "patch_integrity",
      guardName: "Patch Integrity",
      verdict: "deny",
      message: `Patch has ${additions} additions, exceeding limit of ${maxAdd}`,
      evidence: { additions, deletions, maxAdd, maxDel },
    };
  }

  if (deletions > maxDel) {
    return {
      guardId: "patch_integrity",
      guardName: "Patch Integrity",
      verdict: "deny",
      message: `Patch has ${deletions} deletions, exceeding limit of ${maxDel}`,
      evidence: { additions, deletions, maxAdd, maxDel },
    };
  }

  for (const pat of forbiddenPatterns) {
    if (!isSafeRegex(pat)) {
      return {
        guardId: "patch_integrity",
        guardName: "Patch Integrity",
        verdict: "deny",
        message: `Unsafe regex pattern rejected: "${pat}"`,
        evidence: { additions, deletions, matchedPattern: pat, reason: "unsafe_regex" },
      };
    }
    try {
      const re = cachedRegex(pat);
      if (re.test(content)) {
        return {
          guardId: "patch_integrity",
          guardName: "Patch Integrity",
          verdict: "deny",
          message: `Patch content matches forbidden pattern "${pat}"`,
          evidence: { additions, deletions, matchedPattern: pat },
        };
      }
    } catch (e) {
      // Fail closed: invalid regex patterns deny access
      return {
        guardId: "patch_integrity",
        guardName: "Patch Integrity",
        verdict: "deny" as const,
        message: `Invalid pattern: ${e instanceof Error ? e.message : String(e)}`,
        evidence: { error: "invalid_regex_pattern" },
      };
    }
  }

  if (config.require_balance) {
    const ratio = config.max_imbalance_ratio ?? 10;
    const min = Math.min(additions, deletions) || 1;
    const max = Math.max(additions, deletions);
    if (max / min > ratio) {
      return {
        guardId: "patch_integrity",
        guardName: "Patch Integrity",
        verdict: "warn",
        message: `Patch imbalance ratio ${(max / min).toFixed(1)} exceeds limit ${ratio}`,
        evidence: { additions, deletions, ratio: max / min, maxRatio: ratio },
      };
    }
  }

  return {
    guardId: "patch_integrity",
    guardName: "Patch Integrity",
    verdict: "allow",
    message: `Patch OK (${additions} additions, ${deletions} deletions)`,
    evidence: { additions, deletions },
  };
}

function simulateShellCommand(
  config: ShellCommandConfig,
  scenario: TestScenario,
  forbiddenPathConfig?: ForbiddenPathConfig,
): GuardSimResult | null {
  if (scenario.actionType !== "shell_command") return null;

  const command = (scenario.payload.command as string) || "";
  const forbiddenPatterns = config.forbidden_patterns || [];

  // Default dangerous patterns — always included as a security baseline.
  // Custom forbidden_patterns are merged with (appended to) these defaults,
  // never replace them, to prevent accidental bypass of core protections.
  const defaultPatterns = [
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
  const patterns = [...defaultPatterns, ...forbiddenPatterns];

  for (const pat of patterns) {
    if (!isSafeRegex(pat)) {
      return {
        guardId: "shell_command",
        guardName: "Shell Command",
        verdict: "deny",
        message: `Unsafe regex pattern rejected: "${pat}"`,
        evidence: { command, matchedPattern: pat, reason: "unsafe_regex" },
      };
    }
    try {
      const re = cachedRegex(pat, "i");
      if (re.test(command)) {
        return {
          guardId: "shell_command",
          guardName: "Shell Command",
          verdict: "deny",
          message: `Command matches forbidden pattern "${pat}"`,
          evidence: { command, matchedPattern: pat },
        };
      }
    } catch (e) {
      // Fail closed: invalid regex patterns deny access
      return {
        guardId: "shell_command",
        guardName: "Shell Command",
        verdict: "deny" as const,
        message: `Invalid pattern: ${e instanceof Error ? e.message : String(e)}`,
        evidence: { error: "invalid_regex_pattern" },
      };
    }
  }

  // enforce_forbidden_paths: when enabled (default true), extract file paths from the
  // command string and check them against ForbiddenPathConfig patterns.
  if (config.enforce_forbidden_paths !== false && forbiddenPathConfig) {
    const fpPatterns = forbiddenPathConfig.patterns || [];
    const fpExceptions = forbiddenPathConfig.exceptions || [];
    // Simple path extraction: find tokens starting with / or ~/
    const rawTokens = command.match(/(?:~\/|\/)[^\s;|&"'`]+/g) || [];
    const pathTokens = rawTokens.map(normalizePath);
    for (const candidatePath of pathTokens) {
      // Check exceptions first
      const isExcepted = fpExceptions.some((exc) => globToRegex(exc).test(candidatePath));
      if (isExcepted) continue;
      for (const fpPat of fpPatterns) {
        if (globToRegex(fpPat).test(candidatePath)) {
          return {
            guardId: "shell_command",
            guardName: "Shell Command",
            verdict: "deny",
            message: `Command references forbidden path "${candidatePath}" (matched pattern "${fpPat}")`,
            evidence: { command, forbiddenPath: candidatePath, matchedPattern: fpPat },
          };
        }
      }
    }
  }

  return {
    guardId: "shell_command",
    guardName: "Shell Command",
    verdict: "allow",
    message: "Command does not match any forbidden pattern",
    evidence: { command },
  };
}

function simulateMcpTool(
  config: McpToolConfig,
  scenario: TestScenario,
): GuardSimResult | null {
  if (scenario.actionType !== "mcp_tool_call") return null;

  const tool = (scenario.payload.tool as string) || "";
  const blockList = config.block || [];
  const allowList = config.allow || [];
  const confirmList = config.require_confirmation || [];
  const defaultAction = config.default_action || "allow";

  // Block takes precedence
  // Rust McpToolGuard uses HashSet::contains(tool_name) — literal match only, no wildcard "*" support
  if (blockList.includes(tool)) {
    return {
      guardId: "mcp_tool",
      guardName: "MCP Tool",
      verdict: "deny",
      message: `Tool "${tool}" is in the block list`,
      evidence: { tool, blockList },
    };
  }

  // Confirmation list -> warn
  // Rust McpToolGuard uses HashSet::contains(tool_name) — literal match only, no wildcard "*" support
  if (confirmList.includes(tool)) {
    return {
      guardId: "mcp_tool",
      guardName: "MCP Tool",
      verdict: "warn",
      message: `Tool "${tool}" requires confirmation`,
      evidence: { tool, confirmList },
    };
  }

  // Allow list
  // Rust McpToolGuard uses HashSet::contains(tool_name) — literal match only, no wildcard "*" support
  if (allowList.length > 0) {
    if (allowList.includes(tool)) {
      return {
        guardId: "mcp_tool",
        guardName: "MCP Tool",
        verdict: "allow",
        message: `Tool "${tool}" is in the allow list`,
        evidence: { tool, allowList },
      };
    }
    // Non-empty allowlist acts as implicit deny — matches Rust McpToolGuard semantics
    return {
      guardId: "mcp_tool",
      guardName: "MCP Tool",
      verdict: "deny",
      message: `Tool "${tool}" not in allow list [${allowList.join(", ")}]`,
      evidence: { tool, reason: "not_in_allowlist" },
    };
  }

  const verdict: Verdict = defaultAction === "allow" ? "allow" : "deny";
  return {
    guardId: "mcp_tool",
    guardName: "MCP Tool",
    verdict,
    message: `Tool "${tool}" not in any list; default action: ${defaultAction}`,
    evidence: { tool, defaultAction },
  };
}

const INJECTION_KEYWORDS = [
  "ignore previous",
  "ignore all previous",
  "ignore above",
  "disregard previous",
  "disregard all previous",
  "forget your instructions",
  "system prompt",
  "reveal your prompt",
  "reveal the system",
  "override instructions",
  "new instructions",
  "act as",
  "pretend you are",
  "you are now",
  "jailbreak",
  "do anything now",
  "developer mode",
  "bypass",
  "ignore safety",
  "ignore your rules",
];

function simulatePromptInjection(
  config: PromptInjectionConfig,
  scenario: TestScenario,
): GuardSimResult | null {
  if (scenario.actionType !== "user_input") return null;

  const text = ((scenario.payload.text as string) || "").toLowerCase();
  const matchedKeywords: string[] = [];

  for (const kw of INJECTION_KEYWORDS) {
    if (text.includes(kw)) {
      matchedKeywords.push(kw);
    }
  }

  const levels = ["safe", "suspicious", "high", "critical"] as const;
  const warnLevel = levels.indexOf(config.warn_at_or_above || "suspicious");
  const blockLevel = levels.indexOf(config.block_at_or_above || "high");

  let detectedLevel: number;
  if (matchedKeywords.length === 0) detectedLevel = 0; // safe
  else if (matchedKeywords.length === 1) detectedLevel = 1; // suspicious
  else if (matchedKeywords.length <= 3) detectedLevel = 2; // high
  else detectedLevel = 3; // critical

  const levelName = levels[detectedLevel];

  let verdict: Verdict = "allow";
  if (detectedLevel >= blockLevel) verdict = "deny";
  else if (detectedLevel >= warnLevel) verdict = "warn";

  return {
    guardId: "prompt_injection",
    guardName: "Prompt Injection",
    verdict,
    message:
      matchedKeywords.length > 0
        ? `Detected ${matchedKeywords.length} injection keyword(s) — level: ${levelName}`
        : "No injection keywords detected",
    evidence: {
      text: text.slice(0, 200),
      matchedKeywords,
      level: levelName,
      engine: "approximate",
      note: "Client-side keyword matching only; production guard uses deeper analysis",
    },
  };
}

const JAILBREAK_KEYWORDS = [
  "do anything now",
  "dan mode",
  "developer mode",
  "jailbreak",
  "no restrictions",
  "unlimited mode",
  "evil mode",
  "unfiltered",
  "no censorship",
  "act as if you have no guidelines",
  "ignore your training",
  "pretend you have no limitations",
  "in the hypothetical",
  "for educational purposes",
  "roleplay as an ai without restrictions",
];

function simulateJailbreak(
  config: JailbreakConfig,
  scenario: TestScenario,
): GuardSimResult | null {
  if (scenario.actionType !== "user_input") return null;

  const text = ((scenario.payload.text as string) || "").toLowerCase();
  const detector = config.detector || {};
  const blockThreshold = detector.block_threshold ?? 70;
  const warnThreshold = detector.warn_threshold ?? 30;

  let score = 0;
  const matched: string[] = [];
  for (const kw of JAILBREAK_KEYWORDS) {
    if (text.includes(kw)) {
      score += 100 / JAILBREAK_KEYWORDS.length;
      matched.push(kw);
    }
  }

  // Clamp to 100
  score = Math.min(100, Math.round(score));

  let verdict: Verdict = "allow";
  if (score >= blockThreshold) verdict = "deny";
  else if (score >= warnThreshold) verdict = "warn";

  return {
    guardId: "jailbreak",
    guardName: "Jailbreak Detection",
    verdict,
    message:
      matched.length > 0
        ? `Jailbreak score: ${score}/100 (matched ${matched.length} indicator(s))`
        : `Jailbreak score: ${score}/100 — no indicators found`,
    evidence: {
      score,
      blockThreshold,
      warnThreshold,
      matched,
      engine: "approximate",
      note: "Client-side keyword matching only; production guard uses deeper analysis",
    },
  };
}


function stubPathAllowlist(
  config: PathAllowlistConfig,
  scenario: TestScenario,
): GuardSimResult {
  const { actionType, payload } = scenario;
  const path = normalizePath((payload.path as string) || "");

  let allowedPaths: string[] = [];
  if (actionType === "file_access") {
    allowedPaths = config.file_access_allow || [];
  } else if (actionType === "file_write") {
    allowedPaths = config.file_write_allow || [];
  } else if (actionType === "patch_apply") {
    allowedPaths = config.patch_allow || config.file_write_allow || [];
  }

  // If no allowlist configured for this action type, or action type is unrelated, allow
  if (allowedPaths.length === 0 && (actionType === "file_access" || actionType === "file_write" || actionType === "patch_apply")) {
    return {
      guardId: "path_allowlist",
      guardName: "Path Allowlist",
      verdict: "deny",
      message: `No allowed paths configured for ${actionType} — fail-closed`,
      evidence: { path, actionType },
      engine: "desktop_only",
    };
  }

  if (actionType !== "file_access" && actionType !== "file_write" && actionType !== "patch_apply") {
    return {
      guardId: "path_allowlist",
      guardName: "Path Allowlist",
      verdict: "allow",
      message: `Action type "${actionType}" not subject to path allowlist`,
      evidence: { actionType },
      engine: "desktop_only",
    };
  }

  // Basic string prefix/glob matching against allowed paths
  for (const allowed of allowedPaths) {
    if (globToRegex(allowed).test(path)) {
      return {
        guardId: "path_allowlist",
        guardName: "Path Allowlist",
        verdict: "allow",
        message: `Path "${path}" matched allowlist pattern "${allowed}"`,
        evidence: { path, matchedPattern: allowed },
        engine: "desktop_only",
      };
    }
  }

  return {
    guardId: "path_allowlist",
    guardName: "Path Allowlist",
    verdict: "deny",
    message: `Path "${path}" not in allowlist — denied (basic matching; run in desktop mode for full glob evaluation)`,
    evidence: { path, allowedPaths },
    engine: "desktop_only",
  };
}

function stubSpiderSense(
  _config: SpiderSenseConfig,
  _scenario: TestScenario,
): GuardSimResult {
  return {
    guardId: "spider_sense",
    guardName: "Spider Sense",
    verdict: "allow",
    engine: "desktop_only",
    message: "This guard requires the desktop runtime — run via Tauri or CLI for full evaluation",
    evidence: { note: "Embedding-based cosine similarity and hierarchical threat screening require native runtime" },
  };
}

function stubComputerUse(
  _config: ComputerUseConfig,
  _scenario: TestScenario,
): GuardSimResult {
  return {
    guardId: "computer_use",
    guardName: "Computer Use",
    verdict: "allow",
    engine: "desktop_only",
    message: "This guard requires the desktop runtime — run via Tauri or CLI for full evaluation",
    evidence: { note: "Requires CUA session state and screen capture context" },
  };
}

function stubRemoteDesktopSideChannel(
  _config: RemoteDesktopSideChannelConfig,
  _scenario: TestScenario,
): GuardSimResult {
  return {
    guardId: "remote_desktop_side_channel",
    guardName: "Remote Desktop Side-Channel",
    verdict: "allow",
    engine: "desktop_only",
    message: "This guard requires the desktop runtime — run via Tauri or CLI for full evaluation",
    evidence: { note: "Requires live session state for clipboard, audio, drive mapping checks" },
  };
}

function stubInputInjectionCapability(
  _config: InputInjectionCapabilityConfig,
  _scenario: TestScenario,
): GuardSimResult {
  return {
    guardId: "input_injection_capability",
    guardName: "Input Injection",
    verdict: "allow",
    engine: "desktop_only",
    message: "This guard requires the desktop runtime — run via Tauri or CLI for full evaluation",
    evidence: { note: "Requires active input device enumeration and capability probing" },
  };
}

/** Dispatch table for stubbed guards that need per-guard logic. */
const STUB_SIMULATORS: Partial<
  Record<
    GuardId,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (config: any, scenario: TestScenario) => GuardSimResult
  >
> = {
  path_allowlist: stubPathAllowlist,
  spider_sense: stubSpiderSense,
  computer_use: stubComputerUse,
  remote_desktop_side_channel: stubRemoteDesktopSideChannel,
  input_injection_capability: stubInputInjectionCapability,
};


type GuardSimulator = (
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  config: any,
  scenario: TestScenario,
) => GuardSimResult | null;

const SIMULATORS: Partial<Record<GuardId, GuardSimulator>> = {
  forbidden_path: simulateForbiddenPath,
  egress_allowlist: simulateEgressAllowlist,
  secret_leak: simulateSecretLeak,
  patch_integrity: simulatePatchIntegrity,
  shell_command: simulateShellCommand,
  mcp_tool: simulateMcpTool,
  prompt_injection: simulatePromptInjection,
  jailbreak: simulateJailbreak,
};


export function simulatePolicy(
  policy: WorkbenchPolicy,
  scenario: TestScenario,
): SimulationResult {
  const guardResults: GuardSimResult[] = [];

  for (const [guardId, config] of Object.entries(policy.guards)) {
    if (!config || typeof config !== "object") continue;

    const gid = guardId as GuardId;
    const isEnabled = (config as { enabled?: boolean }).enabled !== false;
    if (!isEnabled) continue;

    const simulator = SIMULATORS[gid];
    if (simulator) {
      let result: GuardSimResult | null;
      // Special-case: shell_command needs the forbidden_path config for enforce_forbidden_paths
      if (gid === "shell_command") {
        result = simulateShellCommand(config as ShellCommandConfig, scenario, policy.guards.forbidden_path);
      } else {
        result = simulator(config, scenario);
      }
      if (result) {
        guardResults.push({ ...result, engine: "client" });
      }
    } else {
      // Stubbed guard — use improved per-guard stub if available
      const stubSimulator = STUB_SIMULATORS[gid];
      if (stubSimulator) {
        guardResults.push(stubSimulator(config, scenario));
      } else {
                const meta = getGuardMeta(gid);
        guardResults.push({
          guardId: gid,
          guardName: meta?.name || gid,
          verdict: "deny",
          message: `Unknown guard '${gid}' cannot be simulated — defaulting to deny (fail-closed)`,
          evidence: { note: "Requires runtime evaluation" },
          engine: "stubbed",
        });
      }
    }
  }

  // Aggregate verdict
  let overallVerdict: Verdict = "allow";
  if (guardResults.some((r) => r.verdict === "deny")) {
    overallVerdict = "deny";
  } else if (guardResults.some((r) => r.verdict === "warn")) {
    overallVerdict = "warn";
  }

  const result: SimulationResult & { redteamGrade?: RedTeamGradingResult } = {
    scenarioId: scenario.id,
    overallVerdict,
    guardResults,
    executedAt: new Date().toISOString(),
  };

  // If this is a red-team scenario, attach grading information
  const rtScenario = scenario as { redteamPluginId?: string };
  if (rtScenario.redteamPluginId) {
    result.redteamGrade = gradeSimulationResult(scenario, result);
  }

  return result;
}
