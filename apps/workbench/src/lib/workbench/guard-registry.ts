import type { GuardMeta } from "./types";

// ---- Internal storage ----

/** The mutable Map backing the guard registry. Keyed by guard ID. */
const guardMap = new Map<string, GuardMeta>();

/** Mutable category entries. Built-in categories are seeded below; plugins add more. */
const categoryEntries: Array<{ id: string; label: string; guards: string[] }> = [
  { id: "filesystem", label: "Filesystem", guards: ["forbidden_path", "path_allowlist"] },
  { id: "network", label: "Network", guards: ["egress_allowlist"] },
  { id: "content", label: "Content", guards: ["secret_leak", "patch_integrity"] },
  { id: "tools", label: "Tools", guards: ["shell_command", "mcp_tool"] },
  { id: "detection", label: "Detection", guards: ["prompt_injection", "jailbreak", "spider_sense"] },
  { id: "cua", label: "Computer Use", guards: ["computer_use", "remote_desktop_side_channel", "input_injection_capability"] },
];

// ---- Built-in guard definitions (seed data) ----

/** The 13 built-in guard definitions. Used to seed the registry at module load. */
export const BUILTIN_GUARDS: readonly GuardMeta[] = [
  {
    id: "forbidden_path",
    name: "Forbidden Path",
    technicalName: "ForbiddenPathGuard",
    description: "Blocks access to sensitive filesystem paths — SSH keys, AWS credentials, .env files, system configs.",
    category: "filesystem",
    defaultVerdict: "deny",
    icon: "IconLock",
    configFields: [
      { key: "enabled", label: "Enabled", type: "toggle", defaultValue: true },
      { key: "patterns", label: "Forbidden Patterns", type: "pattern_list", description: "Glob patterns for sensitive paths to block" },
      { key: "exceptions", label: "Exceptions", type: "string_list", description: "Paths exempted from blocking" },
    ],
  },
  {
    id: "path_allowlist",
    name: "Path Allowlist",
    technicalName: "PathAllowlistGuard",
    description: "Allowlist-based file access. Only explicitly approved paths are accessible. Fail-closed when enabled.",
    category: "filesystem",
    defaultVerdict: "deny",
    icon: "IconShieldCheck",
    configFields: [
      { key: "enabled", label: "Enabled", type: "toggle", defaultValue: true },
      { key: "file_access_allow", label: "Read Allow Patterns", type: "pattern_list", description: "Glob patterns for allowed read access" },
      { key: "file_write_allow", label: "Write Allow Patterns", type: "pattern_list", description: "Glob patterns for allowed write access" },
      { key: "patch_allow", label: "Patch Allow Patterns", type: "pattern_list", description: "Glob patterns for allowed patches (defaults to write patterns)" },
    ],
  },
  {
    id: "egress_allowlist",
    name: "Egress Control",
    technicalName: "EgressAllowlistGuard",
    description: "Controls network egress by domain. Block unknown endpoints, allow trusted APIs and registries.",
    category: "network",
    defaultVerdict: "deny",
    icon: "IconNetwork",
    configFields: [
      { key: "enabled", label: "Enabled", type: "toggle", defaultValue: true },
      { key: "allow", label: "Allowed Domains", type: "string_list", description: "Domain patterns to allow (supports wildcards like *.openai.com)" },
      { key: "block", label: "Blocked Domains", type: "string_list", description: "Domain patterns to block (takes precedence over allow)" },
      { key: "default_action", label: "Default Action", type: "select", defaultValue: "block", options: [{ value: "allow", label: "Allow" }, { value: "block", label: "Block" }, { value: "log", label: "Log" }] },
    ],
  },
  {
    id: "secret_leak",
    name: "Secret Leak",
    technicalName: "SecretLeakGuard",
    description: "Detects API keys, tokens, and private keys in file writes before they leak.",
    category: "content",
    defaultVerdict: "deny",
    icon: "IconEye",
    configFields: [
      { key: "enabled", label: "Enabled", type: "toggle", defaultValue: true },
      { key: "redact", label: "Redact Secrets", type: "toggle", defaultValue: true, description: "Redact matched secret values in logs and audit details" },
      { key: "severity_threshold", label: "Severity Threshold", type: "select", defaultValue: "error", options: [{ value: "info", label: "Info" }, { value: "warning", label: "Warning" }, { value: "error", label: "Error" }, { value: "critical", label: "Critical" }], description: "Block when matched severity is at or above this level" },
      { key: "patterns", label: "Detection Patterns", type: "secret_pattern_list", description: "Regex patterns for detecting leaked secrets" },
      { key: "skip_paths", label: "Skip Paths", type: "string_list", description: "Glob patterns for paths to skip scanning (e.g. test fixtures)" },
    ],
  },
  {
    id: "patch_integrity",
    name: "Patch Integrity",
    technicalName: "PatchIntegrityGuard",
    description: "Validates patch safety — limits additions/deletions, catches dangerous patterns like chmod 777.",
    category: "content",
    defaultVerdict: "allow",
    icon: "IconFileCheck",
    configFields: [
      { key: "enabled", label: "Enabled", type: "toggle", defaultValue: true },
      { key: "max_additions", label: "Max Additions", type: "number_slider", min: 100, max: 10000, step: 100, defaultValue: 1000 },
      { key: "max_deletions", label: "Max Deletions", type: "number_slider", min: 50, max: 5000, step: 50, defaultValue: 500 },
      { key: "require_balance", label: "Require Balance", type: "toggle", defaultValue: false },
      { key: "max_imbalance_ratio", label: "Max Imbalance Ratio", type: "number_slider", min: 1, max: 50, step: 1, defaultValue: 10 },
      { key: "forbidden_patterns", label: "Forbidden Patterns", type: "pattern_list", description: "Regex patterns for dangerous code changes" },
    ],
  },
  {
    id: "shell_command",
    name: "Shell Command",
    technicalName: "ShellCommandGuard",
    description: "Blocks dangerous shell commands (rm -rf /, reverse shells) before execution.",
    category: "tools",
    defaultVerdict: "deny",
    icon: "IconTerminal",
    configFields: [
      { key: "enabled", label: "Enabled", type: "toggle", defaultValue: true },
      { key: "forbidden_patterns", label: "Forbidden Patterns", type: "pattern_list", description: "Regex patterns for dangerous commands" },
      { key: "enforce_forbidden_paths", label: "Enforce Path Checks", type: "toggle", defaultValue: true, description: "Also check extracted paths against ForbiddenPathGuard" },
    ],
  },
  {
    id: "mcp_tool",
    name: "MCP Tool",
    technicalName: "McpToolGuard",
    description: "Restricts MCP tool invocations with allow/block/confirm lists and max argument sizes.",
    category: "tools",
    defaultVerdict: "warn",
    icon: "IconTool",
    configFields: [
      { key: "enabled", label: "Enabled", type: "toggle", defaultValue: true },
      { key: "allow", label: "Allow List", type: "string_list", description: "Tools explicitly allowed" },
      { key: "block", label: "Block List", type: "string_list", description: "Tools explicitly blocked" },
      { key: "require_confirmation", label: "Require Confirmation", type: "string_list", description: "Tools requiring user confirmation" },
      { key: "default_action", label: "Default Action", type: "select", defaultValue: "allow", options: [{ value: "allow", label: "Allow" }, { value: "block", label: "Block" }] },
      { key: "max_args_size", label: "Max Args Size (bytes)", type: "number_input", min: 1024, max: 10485760, defaultValue: 1048576 },
    ],
  },
  {
    id: "prompt_injection",
    name: "Prompt Injection",
    technicalName: "PromptInjectionGuard",
    description: "Detects prompt injection attempts in agent inputs with configurable thresholds.",
    category: "detection",
    defaultVerdict: "deny",
    icon: "IconBrain",
    configFields: [
      { key: "enabled", label: "Enabled", type: "toggle", defaultValue: true },
      { key: "warn_at_or_above", label: "Warn Level", type: "select", defaultValue: "suspicious", options: [{ value: "safe", label: "Safe" }, { value: "suspicious", label: "Suspicious" }, { value: "high", label: "High" }, { value: "critical", label: "Critical" }] },
      { key: "block_at_or_above", label: "Block Level", type: "select", defaultValue: "high", options: [{ value: "safe", label: "Safe" }, { value: "suspicious", label: "Suspicious" }, { value: "high", label: "High" }, { value: "critical", label: "Critical" }] },
      { key: "max_scan_bytes", label: "Max Scan Bytes", type: "number_input", min: 1000, max: 1000000, defaultValue: 200000 },
    ],
  },
  {
    id: "jailbreak",
    name: "Jailbreak Detection",
    technicalName: "JailbreakGuard",
    description: "4-layer detection: heuristic + statistical + ML + optional LLM-judge for jailbreak attempts.",
    category: "detection",
    defaultVerdict: "deny",
    icon: "IconSkull",
    configFields: [
      { key: "enabled", label: "Enabled", type: "toggle", defaultValue: true },
      // --- Detection layers ---
      { key: "detector.layers.heuristic", label: "Heuristic Layer", type: "toggle", defaultValue: true, description: "Pattern-based detection using regex signals (role changes, prompt extraction, policy override)" },
      { key: "detector.layers.statistical", label: "Statistical Layer", type: "toggle", defaultValue: true, description: "Entropy analysis, punctuation ratio, and symbol-run detection" },
      { key: "detector.layers.ml", label: "ML Layer", type: "toggle", defaultValue: true, description: "Lightweight linear model combining heuristic + statistical features" },
      { key: "detector.layers.llm_judge", label: "LLM Judge Layer", type: "toggle", defaultValue: false, description: "Optional LLM-based deep reasoning for ambiguous cases (requires API)" },
      // --- Thresholds ---
      { key: "detector.block_threshold", label: "Block Threshold", type: "number_slider", min: 0, max: 100, step: 5, defaultValue: 70, description: "Risk score at or above this value triggers a block verdict" },
      { key: "detector.warn_threshold", label: "Warn Threshold", type: "number_slider", min: 0, max: 100, step: 5, defaultValue: 30, description: "Risk score at or above this value triggers a warning" },
      { key: "detector.max_input_bytes", label: "Max Input Bytes", type: "number_input", min: 1000, max: 1000000, defaultValue: 100000, description: "Inputs exceeding this are truncated before analysis" },
      // --- Session tracking ---
      { key: "detector.session_aggregation", label: "Session Aggregation", type: "toggle", defaultValue: true, description: "Track risk across messages in the same session" },
      { key: "detector.session_max_entries", label: "Session Max Entries", type: "number_input", min: 1, max: 100000, defaultValue: 1024, description: "Maximum concurrent sessions retained in memory (LRU eviction)" },
      { key: "detector.session_ttl_seconds", label: "Session TTL (seconds)", type: "number_input", min: 60, max: 86400, defaultValue: 3600, description: "Sessions expire after this many seconds of inactivity" },
      { key: "detector.session_half_life_seconds", label: "Risk Decay Half-Life (seconds)", type: "number_input", min: 0, max: 86400, defaultValue: 900, description: "Rolling risk score decays with this half-life. Set to 0 to disable decay." },
    ],
  },
  {
    id: "computer_use",
    name: "Computer Use",
    technicalName: "ComputerUseGuard",
    description: "Controls CUA actions for remote desktop sessions — restrict mouse, keyboard, screenshots.",
    category: "cua",
    defaultVerdict: "warn",
    icon: "IconDeviceDesktop",
    configFields: [
      { key: "enabled", label: "Enabled", type: "toggle", defaultValue: true },
      { key: "mode", label: "Enforcement Mode", type: "select", defaultValue: "guardrail", options: [{ value: "observe", label: "Observe (log only)" }, { value: "guardrail", label: "Guardrail (warn)" }, { value: "fail_closed", label: "Fail Closed (deny)" }] },
      { key: "allowed_actions", label: "Allowed Actions", type: "string_list", description: "CUA action types to permit" },
    ],
  },
  {
    id: "remote_desktop_side_channel",
    name: "Remote Desktop Side-Channel",
    technicalName: "RemoteDesktopSideChannelGuard",
    description: "Side-channel controls for clipboard, audio, drive mapping, and file transfer.",
    category: "cua",
    defaultVerdict: "warn",
    icon: "IconPlugConnected",
    configFields: [
      { key: "enabled", label: "Enabled", type: "toggle", defaultValue: true },
      { key: "clipboard_enabled", label: "Clipboard", type: "toggle", defaultValue: true },
      { key: "file_transfer_enabled", label: "File Transfer", type: "toggle", defaultValue: true },
      { key: "audio_enabled", label: "Audio", type: "toggle", defaultValue: true },
      { key: "drive_mapping_enabled", label: "Drive Mapping", type: "toggle", defaultValue: true },
      { key: "printing_enabled", label: "Printing", type: "toggle", defaultValue: true },
      { key: "session_share_enabled", label: "Session Sharing", type: "toggle", defaultValue: true },
      { key: "max_transfer_size_bytes", label: "Max Transfer Size (bytes)", type: "number_input", min: 0, max: 1073741824, description: "0 or empty = unlimited" },
    ],
  },
  {
    id: "input_injection_capability",
    name: "Input Injection",
    technicalName: "InputInjectionCapabilityGuard",
    description: "Restricts input injection capabilities in CUA environments to prevent escalation.",
    category: "cua",
    defaultVerdict: "deny",
    icon: "IconKeyboard",
    configFields: [
      { key: "enabled", label: "Enabled", type: "toggle", defaultValue: true },
      { key: "allowed_input_types", label: "Allowed Input Types", type: "string_list", description: "e.g. keyboard, mouse, touch" },
      { key: "require_postcondition_probe", label: "Require Postcondition Probe", type: "toggle", defaultValue: false },
    ],
  },
  {
    id: "spider_sense",
    name: "Trustprint",
    technicalName: "SpiderSenseGuard",
    description: "Semantic behavioral fingerprinting — embedding-based cosine similarity screening with optional LLM deep reasoning for ambiguous cases.",
    category: "detection",
    defaultVerdict: "warn",
    icon: "IconFingerprint",
    configFields: [
      { key: "enabled", label: "Enabled", type: "toggle", defaultValue: false },
      { key: "similarity_threshold", label: "Trust Threshold", type: "number_slider", min: 0, max: 1, step: 0.01, defaultValue: 0.85 },
      { key: "ambiguity_band", label: "Ambiguity Band", type: "number_slider", min: 0, max: 0.5, step: 0.01, defaultValue: 0.1 },
      { key: "top_k", label: "Top-K Matches", type: "number_input", min: 1, max: 20, defaultValue: 5 },
      { key: "embedding_model", label: "Embedding Model", type: "select", defaultValue: "text-embedding-3-small", options: [{ value: "text-embedding-3-small", label: "text-embedding-3-small" }, { value: "text-embedding-3-large", label: "text-embedding-3-large" }] },
      { key: "pattern_db_path", label: "Trustprint Profile", type: "select", defaultValue: "builtin:s2bench-v1", options: [{ value: "builtin:s2bench-v1", label: "Trustprint Baseline (s2bench-v1)" }] },
    ],
  },
] as const;

// ---- Seed built-in guards into the map ----

for (const guard of BUILTIN_GUARDS) {
  guardMap.set(guard.id, guard as GuardMeta);
}

// ---- Registration API ----

/**
 * Register a guard in the registry. Returns a dispose function to unregister.
 * Throws if a guard with the same ID is already registered.
 */
export function registerGuard(meta: GuardMeta): () => void {
  if (guardMap.has(meta.id)) {
    throw new Error(`Guard "${meta.id}" is already registered`);
  }
  guardMap.set(meta.id, meta);

  // Auto-add to its category (create category if it doesn't exist)
  let cat = categoryEntries.find((c) => c.id === meta.category);
  if (!cat) {
    cat = { id: meta.category, label: meta.category, guards: [] };
    categoryEntries.push(cat);
  }
  if (!cat.guards.includes(meta.id)) {
    cat.guards.push(meta.id);
  }

  return () => {
    guardMap.delete(meta.id);
    // Remove from category
    const catEntry = categoryEntries.find((c) => c.id === meta.category);
    if (catEntry) {
      const idx = catEntry.guards.indexOf(meta.id);
      if (idx !== -1) catEntry.guards.splice(idx, 1);
      // Remove empty non-built-in categories
      if (catEntry.guards.length === 0 && !["filesystem", "network", "content", "tools", "detection", "cua"].includes(catEntry.id)) {
        const catIdx = categoryEntries.indexOf(catEntry);
        if (catIdx !== -1) categoryEntries.splice(catIdx, 1);
      }
    }
  };
}

/** Unregister a guard by ID. No-op if not found. */
export function unregisterGuard(id: string): void {
  const meta = guardMap.get(id);
  guardMap.delete(id);
  if (meta) {
    const catEntry = categoryEntries.find((c) => c.id === meta.category);
    if (catEntry) {
      const idx = catEntry.guards.indexOf(id);
      if (idx !== -1) catEntry.guards.splice(idx, 1);
      if (catEntry.guards.length === 0 && !["filesystem", "network", "content", "tools", "detection", "cua"].includes(catEntry.id)) {
        const catIdx = categoryEntries.indexOf(catEntry);
        if (catIdx !== -1) categoryEntries.splice(catIdx, 1);
      }
    }
  }
}

// ---- Query API ----

/** Returns all registered guards as an array. */
export function getAllGuards(): GuardMeta[] {
  return Array.from(guardMap.values());
}

/** Returns guard metadata by ID, or undefined if not registered. */
export function getGuardMeta(id: string): GuardMeta | undefined {
  return guardMap.get(id);
}

/** Returns all registered guard IDs. */
export function getAllGuardIds(): string[] {
  return Array.from(guardMap.keys());
}

/** Returns display name map for all registered guards. */
export function getGuardDisplayNames(): Record<string, string> {
  return Object.fromEntries(Array.from(guardMap.values()).map((g) => [g.id, g.name]));
}

/** Returns a live reference to the category entries array. */
export function getGuardCategories(): Array<{ id: string; label: string; guards: string[] }> {
  return categoryEntries;
}

/**
 * Register a new guard category. Returns a dispose function to unregister.
 * If the category already exists, returns a no-op dispose.
 */
export function registerGuardCategory(category: { id: string; label: string }): () => void {
  const existing = categoryEntries.find((c) => c.id === category.id);
  if (existing) {
    return () => {};
  }
  categoryEntries.push({ id: category.id, label: category.label, guards: [] });
  return () => {
    const idx = categoryEntries.findIndex((c) => c.id === category.id);
    if (idx !== -1 && categoryEntries[idx].guards.length === 0) {
      categoryEntries.splice(idx, 1);
    }
  };
}

// ---- Backward-compatible exports (Proxy-based live views) ----

function createArrayProxy<T>(getArray: () => T[]): T[] {
  return new Proxy([] as T[], {
    get(_target, prop, receiver) {
      const arr = getArray();
      if (prop === Symbol.iterator) return arr[Symbol.iterator].bind(arr);
      if (prop === "length") return arr.length;
      const value = Reflect.get(arr, prop, receiver);
      return typeof value === "function" ? value.bind(arr) : value;
    },
    has(_target, prop) {
      const arr = getArray();
      return Reflect.has(arr, prop);
    },
  });
}

/**
 * Live view of all registered guards. Supports .filter(), .map(), .find(), .length, etc.
 * Consumers should prefer getAllGuards() for new code.
 */
export const GUARD_REGISTRY: GuardMeta[] = createArrayProxy(() => Array.from(guardMap.values()));

/** All registered guard IDs, live. Backward-compatible export. */
export const ALL_GUARD_IDS: string[] = createArrayProxy(() => Array.from(guardMap.keys()));

/** Guard ID to display name mapping. Live proxy. */
export const GUARD_DISPLAY_NAMES: Record<string, string> = new Proxy({} as Record<string, string>, {
  get(_target, prop) {
    if (typeof prop === "symbol") return undefined;
    const guard = guardMap.get(prop);
    return guard ? guard.name : undefined;
  },
  has(_target, prop) {
    if (typeof prop === "symbol") return false;
    return guardMap.has(prop);
  },
  ownKeys() {
    return Array.from(guardMap.keys());
  },
  getOwnPropertyDescriptor(_target, prop) {
    if (typeof prop === "symbol") return undefined;
    const guard = guardMap.get(prop);
    if (!guard) return undefined;
    return { configurable: true, enumerable: true, value: guard.name };
  },
});

/** Live view of guard categories. Backward-compatible export. */
export const GUARD_CATEGORIES: Array<{ id: string; label: string; guards: string[] }> = createArrayProxy(() => categoryEntries);
