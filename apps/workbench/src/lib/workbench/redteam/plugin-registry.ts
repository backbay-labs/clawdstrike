/**
 * Static registry of promptfoo red-team plugins and strategies, vendored
 * from the promptfoo source tree with ClawdStrike guard mappings overlaid.
 *
 * Data sources:
 *   - promptfoo/src/redteam/constants/metadata.ts  (descriptions, severities)
 *   - promptfoo/src/redteam/constants/plugins.ts    (plugin definitions)
 *   - promptfoo/src/redteam/riskScoring.ts          (strategy metadata)
 */

import type { GuardId } from "../types.ts";
import type { RedTeamPlugin, RedTeamStrategy } from "./types.ts";
import type { ThreatSeverity } from "../types.ts";

// ---------------------------------------------------------------------------
// Helper — build a plugin entry
// ---------------------------------------------------------------------------

function p(
  id: string,
  description: string,
  severity: ThreatSeverity,
  category: string,
  guardMapping: GuardId[],
): RedTeamPlugin {
  return { id, description, severity, category, guardMapping };
}

// ---------------------------------------------------------------------------
// REDTEAM_PLUGINS — 38 most relevant plugins
// ---------------------------------------------------------------------------

export const REDTEAM_PLUGINS: Record<string, RedTeamPlugin> = {
  // -- Prompt injection & jailbreaking --
  "ascii-smuggling": p(
    "ascii-smuggling",
    "Tests vulnerability to Unicode tag-based instruction smuggling attacks",
    "low",
    "prompt_injection",
    ["prompt_injection"],
  ),
  "indirect-prompt-injection": p(
    "indirect-prompt-injection",
    "Tests for injection vulnerabilities via untrusted variables",
    "high",
    "prompt_injection",
    ["prompt_injection"],
  ),
  hijacking: p(
    "hijacking",
    "Tests for unauthorized resource usage and purpose deviation",
    "high",
    "prompt_injection",
    ["prompt_injection", "mcp_tool"],
  ),
  "system-prompt-override": p(
    "system-prompt-override",
    "Tests for system prompt override vulnerabilities",
    "high",
    "prompt_injection",
    ["prompt_injection"],
  ),
  "prompt-extraction": p(
    "prompt-extraction",
    "Tests for system prompt disclosure vulnerabilities",
    "medium",
    "prompt_injection",
    ["secret_leak", "forbidden_path", "path_allowlist"],
  ),
  cca: p(
    "cca",
    "Tests for vulnerability to Context Compliance Attacks using fabricated conversation history",
    "high",
    "prompt_injection",
    ["prompt_injection"],
  ),

  // -- Jailbreak datasets --
  beavertails: p(
    "beavertails",
    "Tests handling of malicious prompts from the BeaverTails dataset",
    "low",
    "jailbreak",
    ["jailbreak"],
  ),
  harmbench: p(
    "harmbench",
    "Tests for harmful content using the HarmBench dataset",
    "medium",
    "jailbreak",
    ["jailbreak"],
  ),
  pliny: p(
    "pliny",
    "Tests handling of Pliny prompt injections",
    "medium",
    "jailbreak",
    ["jailbreak"],
  ),
  donotanswer: p(
    "donotanswer",
    "Tests for vulnerabilities to Do Not Answer attacks",
    "medium",
    "jailbreak",
    ["jailbreak"],
  ),

  // -- PII / secrets --
  "pii:direct": p(
    "pii:direct",
    "Tests for direct PII exposure vulnerabilities",
    "high",
    "pii",
    ["secret_leak"],
  ),
  "pii:api-db": p(
    "pii:api-db",
    "Tests for PII exposure via API/database access",
    "high",
    "pii",
    ["secret_leak"],
  ),
  "pii:session": p(
    "pii:session",
    "Tests for PII exposure in session data",
    "high",
    "pii",
    ["secret_leak"],
  ),
  "pii:social": p(
    "pii:social",
    "Tests for PII exposure via social engineering",
    "high",
    "pii",
    ["secret_leak"],
  ),

  // -- Shell / code injection --
  "shell-injection": p(
    "shell-injection",
    "Tests for command injection vulnerabilities",
    "high",
    "injection",
    ["shell_command", "forbidden_path", "path_allowlist", "patch_integrity", "input_injection_capability"],
  ),
  "sql-injection": p(
    "sql-injection",
    "Tests for SQL injection vulnerabilities",
    "high",
    "injection",
    ["shell_command"],
  ),

  // -- Network / SSRF --
  ssrf: p(
    "ssrf",
    "Tests for server-side request forgery vulnerabilities",
    "high",
    "network",
    ["egress_allowlist", "remote_desktop_side_channel"],
  ),

  // -- Authorization --
  "excessive-agency": p(
    "excessive-agency",
    "Tests for unauthorized actions beyond defined system boundaries",
    "medium",
    "authorization",
    ["mcp_tool", "computer_use"],
  ),
  rbac: p(
    "rbac",
    "Tests role-based access control implementation",
    "high",
    "authorization",
    ["mcp_tool", "computer_use"],
  ),
  bfla: p(
    "bfla",
    "Tests for broken function-level authorization vulnerabilities (OWASP API 5)",
    "high",
    "authorization",
    ["mcp_tool"],
  ),
  bola: p(
    "bola",
    "Tests for broken object-level authorization vulnerabilities (OWASP API 1)",
    "high",
    "authorization",
    ["mcp_tool"],
  ),

  // -- Harmful content categories --
  "harmful:hate": p(
    "harmful:hate",
    "Tests handling of hate speech and discriminatory content",
    "critical",
    "harmful",
    ["spider_sense", "jailbreak"],
  ),
  "harmful:self-harm": p(
    "harmful:self-harm",
    "Tests handling of self-harm and suicide content",
    "critical",
    "harmful",
    ["spider_sense", "jailbreak"],
  ),
  "harmful:child-exploitation": p(
    "harmful:child-exploitation",
    "Tests handling of child exploitation content",
    "critical",
    "harmful",
    ["spider_sense", "jailbreak"],
  ),
  "harmful:violent-crime": p(
    "harmful:violent-crime",
    "Tests handling of violent crime content",
    "high",
    "harmful",
    ["spider_sense", "jailbreak"],
  ),
  "harmful:sex-crime": p(
    "harmful:sex-crime",
    "Tests handling of sexual crime content",
    "high",
    "harmful",
    ["spider_sense", "jailbreak"],
  ),
  "harmful:cybercrime": p(
    "harmful:cybercrime",
    "Tests handling of cybercrime-related content",
    "low",
    "harmful",
    ["spider_sense", "shell_command"],
  ),
  "harmful:chemical-biological-weapons": p(
    "harmful:chemical-biological-weapons",
    "Tests handling of WMD-related content",
    "high",
    "harmful",
    ["spider_sense"],
  ),
  "harmful:indiscriminate-weapons": p(
    "harmful:indiscriminate-weapons",
    "Tests handling of weapons-related content",
    "medium",
    "harmful",
    ["spider_sense"],
  ),
  "harmful:misinformation-disinformation": p(
    "harmful:misinformation-disinformation",
    "Tests handling of false information campaigns",
    "medium",
    "harmful",
    ["spider_sense"],
  ),
  "harmful:privacy": p(
    "harmful:privacy",
    "Tests handling of privacy violation attempts",
    "high",
    "harmful",
    ["secret_leak", "spider_sense"],
  ),
  "harmful:illegal-activities": p(
    "harmful:illegal-activities",
    "Tests handling of general illegal activities",
    "medium",
    "harmful",
    ["spider_sense"],
  ),
  "harmful:unsafe-practices": p(
    "harmful:unsafe-practices",
    "Tests handling of dangerous activity instructions",
    "low",
    "harmful",
    ["spider_sense"],
  ),

  // -- Hallucination / overreliance --
  hallucination: p(
    "hallucination",
    "Tests for fabrication of false or misleading information",
    "medium",
    "integrity",
    ["spider_sense"],
  ),
  overreliance: p(
    "overreliance",
    "Tests for overreliance on system assumptions",
    "low",
    "integrity",
    ["spider_sense"],
  ),

  // -- MCP --
  mcp: p(
    "mcp",
    "Tests for vulnerabilities to Model Context Protocol attacks",
    "high",
    "tools",
    ["mcp_tool"],
  ),

  // -- Data exfiltration --
  "data-exfil": p(
    "data-exfil",
    "Tests for data exfiltration via URL parameters, images, or markdown links",
    "high",
    "exfiltration",
    ["egress_allowlist", "secret_leak"],
  ),

  // -- Agentic --
  "agentic:memory-poisoning": p(
    "agentic:memory-poisoning",
    "Tests whether an agent is vulnerable to memory poisoning attacks",
    "high",
    "agentic",
    ["prompt_injection", "spider_sense"],
  ),
};

// ---------------------------------------------------------------------------
// GUARD_TO_PLUGINS — which promptfoo plugins exercise each guard
// ---------------------------------------------------------------------------

function buildGuardToPlugins(): Record<GuardId, string[]> {
  const map: Record<string, string[]> = {};
  for (const plugin of Object.values(REDTEAM_PLUGINS)) {
    for (const gid of plugin.guardMapping) {
      if (!map[gid]) map[gid] = [];
      if (!map[gid].includes(plugin.id)) map[gid].push(plugin.id);
    }
  }
  return map as Record<GuardId, string[]>;
}

export const GUARD_TO_PLUGINS: Record<GuardId, string[]> = buildGuardToPlugins();

// ---------------------------------------------------------------------------
// PLUGIN_TO_GUARDS — reverse mapping (convenience alias)
// ---------------------------------------------------------------------------

function buildPluginToGuards(): Record<string, GuardId[]> {
  const map: Record<string, GuardId[]> = {};
  for (const plugin of Object.values(REDTEAM_PLUGINS)) {
    map[plugin.id] = [...plugin.guardMapping];
  }
  return map;
}

export const PLUGIN_TO_GUARDS: Record<string, GuardId[]> = buildPluginToGuards();

// ---------------------------------------------------------------------------
// REDTEAM_STRATEGIES — strategy metadata (vendored from promptfoo riskScoring.ts)
// ---------------------------------------------------------------------------

function s(
  id: string,
  description: string,
  humanExploitable: boolean,
  humanComplexity: "low" | "medium" | "high",
): RedTeamStrategy {
  return { id, description, humanExploitable, humanComplexity };
}

export const REDTEAM_STRATEGIES: Record<string, RedTeamStrategy> = {
  basic: s("basic", "Original plugin tests without additional strategies", true, "low"),
  layer: s("layer", "Applies multiple strategies in a defined order", true, "medium"),
  "prompt-injection": s("prompt-injection", "Direct prompt injection", true, "low"),
  jailbreak: s("jailbreak", "Single-shot optimization of safety bypass techniques", true, "medium"),
  "jailbreak:composite": s("jailbreak:composite", "Combines multiple jailbreak techniques", true, "medium"),
  "jailbreak:likert": s("jailbreak:likert", "Likert scale-based prompts to bypass content filters", true, "medium"),
  "jailbreak:tree": s("jailbreak:tree", "Tree-based search for optimal safety bypass vectors", false, "high"),
  "jailbreak-templates": s("jailbreak-templates", "Known jailbreak templates (DAN, Skeleton Key, etc.)", true, "low"),
  base64: s("base64", "Base64-encoded malicious payloads", true, "low"),
  rot13: s("rot13", "ROT13-encoded malicious content", true, "low"),
  leetspeak: s("leetspeak", "Leetspeak-encoded malicious content", true, "low"),
  hex: s("hex", "Hex-encoded malicious payloads", true, "low"),
  "ascii-smuggling": s("ascii-smuggling", "Unicode tag-based instruction smuggling", false, "high"),
  multilingual: s("multilingual", "Attacks across multiple languages", true, "low"),
  crescendo: s("crescendo", "Multi-turn attack that gradually escalates intent", true, "high"),
  goat: s("goat", "Dynamic multi-turn adversarial attack generation", false, "high"),
  "math-prompt": s("math-prompt", "Mathematical notation-based attacks", true, "medium"),
  citation: s("citation", "Exploits academic authority bias", true, "medium"),
  homoglyph: s("homoglyph", "Visually similar Unicode characters to bypass filters", true, "medium"),
  custom: s("custom", "User-defined multi-turn conversation strategy", true, "high"),
  "best-of-n": s("best-of-n", "Jailbreak technique published by Anthropic and Stanford", false, "high"),
  retry: s("retry", "Regression testing with previously failed cases", true, "low"),
  gcg: s("gcg", "Greedy Coordinate Gradient adversarial suffix attack", false, "high"),
  pandamonium: s("pandamonium", "Pandamonium adversarial attack", false, "high"),
  "mischievous-user": s("mischievous-user", "Simulates a mischievous user in multi-turn conversation", true, "medium"),
  audio: s("audio", "Tests handling of audio content", true, "medium"),
  image: s("image", "Tests handling of image content", true, "medium"),
  video: s("video", "Tests handling of video content", true, "medium"),
  camelcase: s("camelcase", "CamelCase text transformation to bypass filters", true, "low"),
  morse: s("morse", "Morse code encoding to bypass filters", true, "low"),
  piglatin: s("piglatin", "Pig Latin translation to bypass filters", true, "low"),
  emoji: s("emoji", "Text hidden using emoji variation selectors", true, "low"),
};
