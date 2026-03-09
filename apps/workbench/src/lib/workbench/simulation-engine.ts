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

// ---------------------------------------------------------------------------
// Regex safety helper
// ---------------------------------------------------------------------------

/** Reject regex patterns with nested quantifiers that can cause catastrophic backtracking. */
function isSafeRegex(pattern: string): boolean {
  // Reject patterns longer than 1000 chars
  if (pattern.length > 1000) return false;
  // Reject nested quantifiers: (x+)+, (x*)+, (x+)*, etc.
  if (/(\+|\*|\{)\)?(\+|\*|\{)/.test(pattern)) return false;
  // Reject excessive alternation groups (>20)
  if ((pattern.match(/\|/g) || []).length > 20) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Glob / wildcard helpers
// ---------------------------------------------------------------------------

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

  return new RegExp(re + "$", "i");
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

// ---------------------------------------------------------------------------
// Per-guard simulators
// ---------------------------------------------------------------------------

function simulateForbiddenPath(
  config: ForbiddenPathConfig,
  scenario: TestScenario,
): GuardSimResult | null {
  const { actionType, payload } = scenario;
  if (actionType !== "file_access" && actionType !== "file_write") return null;

  const path = (payload.path as string) || "";
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
  const verdict: Verdict = defaultAction === "allow" ? "allow" : "deny";
  return {
    guardId: "egress_allowlist",
    guardName: "Egress Control",
    verdict,
    message: `Host "${host}" not matched; default action: ${defaultAction}`,
    evidence: { host, defaultAction },
  };
}

function simulateSecretLeak(
  config: SecretLeakConfig,
  scenario: TestScenario,
): GuardSimResult | null {
  if (scenario.actionType !== "file_write") return null;

  const content = (scenario.payload.content as string) || "";
  const path = (scenario.payload.path as string) || "";
  const patterns = config.patterns || [];
  const skipPaths = config.skip_paths || [];

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

  const matches: Array<{ name: string; pattern: string; severity: string }> = [];
  for (const sp of patterns) {
    if (!isSafeRegex(sp.pattern)) {
      matches.push({ name: sp.name, pattern: sp.pattern, severity: "skipped_unsafe_regex" });
      continue;
    }
    try {
      const re = new RegExp(sp.pattern);
      if (re.test(content)) {
        matches.push({ name: sp.name, pattern: sp.pattern, severity: sp.severity });
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
    const hasCritical = matches.some((m) => m.severity === "critical" || m.severity === "error");
    return {
      guardId: "secret_leak",
      guardName: "Secret Leak",
      verdict: hasCritical ? "deny" : "warn",
      message: `Detected ${matches.length} secret(s): ${matches.map((m) => m.name).join(", ")}`,
      evidence: { path, matches },
    };
  }

  return {
    guardId: "secret_leak",
    guardName: "Secret Leak",
    verdict: "allow",
    message: "No secrets detected in content",
    evidence: { path },
  };
}

function simulatePatchIntegrity(
  config: PatchIntegrityConfig,
  scenario: TestScenario,
): GuardSimResult | null {
  if (scenario.actionType !== "patch_apply") return null;

  const content = (scenario.payload.content as string) || "";
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
      const re = new RegExp(pat);
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
): GuardSimResult | null {
  if (scenario.actionType !== "shell_command") return null;

  const command = (scenario.payload.command as string) || "";
  const forbiddenPatterns = config.forbidden_patterns || [];

  // Default dangerous patterns if none configured
  const patterns =
    forbiddenPatterns.length > 0
      ? forbiddenPatterns
      : [
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
      const re = new RegExp(pat, "i");
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
  if (blockList.includes(tool) || blockList.includes("*")) {
    return {
      guardId: "mcp_tool",
      guardName: "MCP Tool",
      verdict: "deny",
      message: `Tool "${tool}" is in the block list`,
      evidence: { tool, blockList },
    };
  }

  // Confirmation list -> warn
  if (confirmList.includes(tool) || confirmList.includes("*")) {
    return {
      guardId: "mcp_tool",
      guardName: "MCP Tool",
      verdict: "warn",
      message: `Tool "${tool}" requires confirmation`,
      evidence: { tool, confirmList },
    };
  }

  // Allow list
  if (allowList.length > 0) {
    if (allowList.includes(tool) || allowList.includes("*")) {
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
  const blockThreshold = detector.block_threshold ?? 50;
  const warnThreshold = detector.warn_threshold ?? 20;

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

// ---------------------------------------------------------------------------
// Partially-simulatable guard stubs (improved)
// ---------------------------------------------------------------------------

function stubPathAllowlist(
  config: PathAllowlistConfig,
  scenario: TestScenario,
): GuardSimResult {
  const { actionType, payload } = scenario;
  const path = (payload.path as string) || "";

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
      engine: "stubbed",
    };
  }

  if (actionType !== "file_access" && actionType !== "file_write" && actionType !== "patch_apply") {
    return {
      guardId: "path_allowlist",
      guardName: "Path Allowlist",
      verdict: "allow",
      message: `Action type "${actionType}" not subject to path allowlist`,
      evidence: { actionType },
      engine: "stubbed",
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
        engine: "stubbed",
      };
    }
  }

  return {
    guardId: "path_allowlist",
    guardName: "Path Allowlist",
    verdict: "deny",
    message: `Path "${path}" not in allowlist — denied (basic matching; run in desktop mode for full glob evaluation)`,
    evidence: { path, allowedPaths },
    engine: "stubbed",
  };
}

function stubSpiderSense(
  _config: SpiderSenseConfig,
  _scenario: TestScenario,
): GuardSimResult {
  return {
    guardId: "spider_sense",
    guardName: "Spider Sense",
    verdict: "warn",
    message: "Spider Sense requires embedding API — run in desktop mode for full evaluation",
    evidence: { note: "Embedding-based cosine similarity cannot run client-side" },
    engine: "stubbed",
  };
}

function stubComputerUse(
  config: ComputerUseConfig,
  _scenario: TestScenario,
): GuardSimResult {
  const mode = config.mode || "guardrail";
  return {
    guardId: "computer_use",
    guardName: "Computer Use",
    verdict: "allow",
    message: `CUA guard requires active desktop session context (mode: ${mode}) — run in desktop mode for real enforcement`,
    evidence: { note: "Requires CUA session state and screen capture context", mode, allowed_actions: config.allowed_actions },
    engine: "stubbed",
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
    message: "Side-channel guard requires active RDP/VNC session — run in desktop mode for real enforcement",
    evidence: { note: "Requires live session state for clipboard, audio, drive mapping checks" },
    engine: "stubbed",
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
    message: "Input injection guard requires CUA runtime context — run in desktop mode for real enforcement",
    evidence: { note: "Requires active input device enumeration and capability probing" },
    engine: "stubbed",
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

// ---------------------------------------------------------------------------
// Dispatch table
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

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
      const result = simulator(config, scenario);
      if (result) {
        guardResults.push({ ...result, engine: "client" });
      }
    } else {
      // Stubbed guard — use improved per-guard stub if available
      const stubSimulator = STUB_SIMULATORS[gid];
      if (stubSimulator) {
        guardResults.push(stubSimulator(config, scenario));
      } else {
        // Fallback generic stub for any unknown future guard
        const meta = getGuardMeta(gid);
        guardResults.push({
          guardId: gid,
          guardName: meta?.name || gid,
          verdict: "allow",
          message: "Not simulatable client-side — defaulting to allow",
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
