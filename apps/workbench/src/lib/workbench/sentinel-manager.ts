/**
 * Sentinel Manager — CRUD, lifecycle, scheduling, memory, identity, stats.
 *
 * Pure-function module for managing Sentinel objects. No side effects, no
 * React hooks, no network I/O. Takes state in, returns new state out.
 *
 * Follows the standalone-function pattern from hunt-engine.ts.
 */

import {
  generateOperatorKeypair,
  deriveFingerprint,
  toHex,
  deriveSigil,
  SIGILS,
  type SigilType,
} from "./operator-crypto";
import type { AgentBaseline, PatternStep } from "./hunt-types";
import type {
  Sentinel,
  SentinelMode,
  SentinelStatus,
  SentinelDriverKind,
  SentinelExecutionMode,
  SentinelRuntimeBinding,
  SentinelRuntimeEndpointType,
  SentinelRuntimeHealth,
  SentinelIdentity,
  SentinelMemory,
  SentinelStats,
  SentinelGoal,
  Severity,
  SwarmRole,
  SwarmMembership,
  PolicyRef,
  DataSource,
  PatternRef,
  EscalationPolicy,
  MemoryPattern,
} from "./sentinel-types";

// Re-export types so existing consumers of sentinel-manager continue to work.
export type {
  Sentinel,
  SentinelMode,
  SentinelStatus,
  SentinelDriverKind,
  SentinelExecutionMode,
  SentinelRuntimeBinding,
  SentinelRuntimeEndpointType,
  SentinelRuntimeHealth,
  SentinelIdentity,
  SentinelMemory,
  SentinelStats,
  SentinelGoal,
  Severity,
  SwarmRole,
  SwarmMembership,
  PolicyRef,
  DataSource,
  PatternRef,
  EscalationPolicy,
  MemoryPattern,
};

/**
 * Derive an HSL color from fingerprint bytes 4-7 (hex chars 8-15).
 * Returns a CSS `hsl()` string for consistent sentinel-specific coloring.
 */
export function deriveSigilColor(fingerprint: string): string {
  // Bytes 4-7 of the fingerprint (hex chars at positions 8-15)
  const byte4 = parseInt(fingerprint.slice(8, 10), 16);
  const byte5 = parseInt(fingerprint.slice(10, 12), 16);
  const byte6 = parseInt(fingerprint.slice(12, 14), 16);
  const byte7 = parseInt(fingerprint.slice(14, 16), 16);

  // Hue: full 0-360 range from bytes 4+5
  const hue = ((byte4 << 8) | byte5) % 360;
  // Saturation: 50-90% range from byte 6
  const saturation = 50 + (byte6 % 41);
  // Lightness: 40-65% range from byte 7
  const lightness = 40 + (byte7 % 26);

  return `hsl(${hue}, ${saturation}%, ${lightness}%)`;
}


export interface SentinelCapabilities {
  /** Can generate signals from continuous monitoring. */
  canMonitor: boolean;
  /** Can run exploratory hunts (on-demand or scheduled). */
  canHunt: boolean;
  /** Can group signals and write finding summaries. */
  canCurate: boolean;
  /** Can participate in swarms/speakeasies and exchange intel. */
  canLiaison: boolean;
  /** Can promote findings to intel artifacts. */
  canPromoteIntel: boolean;
  /** Can compute and update baselines. */
  canUpdateBaselines: boolean;
  /** Supports cron scheduling. */
  supportsSchedule: boolean;
}


export interface CreateSentinelConfig {
  name: string;
  mode: SentinelMode;
  owner: string;
  policy: PolicyRef;
  goals?: SentinelGoal[];
  schedule?: string | null;
  fleetAgentId?: string | null;
  runtime?: Partial<SentinelRuntimeBinding>;
  operatorPublicKey?: string;
  operatorSecretKey?: string;
}

export interface SentinelMutablePatch extends Partial<Pick<
  Sentinel,
  "name" | "goals" | "schedule" | "status" | "policy" | "mode" | "fleetAgentId"
>> {
  runtime?: Partial<SentinelRuntimeBinding>;
}


export interface SentinelDriverDefinition {
  kind: SentinelDriverKind;
  label: string;
  description: string;
  endpointType: SentinelRuntimeEndpointType;
  recommendedModes: SentinelMode[];
  defaultExecutionMode: SentinelExecutionMode;
  maxEnforcementTier: 0 | 1 | 2 | 3;
}

export interface SentinelExecutionModeConfig {
  mode: SentinelExecutionMode;
  label: string;
  description: string;
}

const DRIVER_DEFINITIONS: readonly SentinelDriverDefinition[] = [
  {
    kind: "claude_code",
    label: "Claude Code",
    description: "Repo-native code agent sessions with tool receipts and checks.",
    endpointType: "local",
    recommendedModes: ["curator", "liaison"],
    defaultExecutionMode: "assist",
    maxEnforcementTier: 1,
  },
  {
    kind: "openclaw",
    label: "OpenClaw Hunt Pod",
    description: "Browser and computer-use runtime on a gateway or node target.",
    endpointType: "gateway",
    recommendedModes: ["hunter", "watcher"],
    defaultExecutionMode: "enforce",
    maxEnforcementTier: 2,
  },
  {
    kind: "hushd_agent",
    label: "Hushd Agent",
    description: "Fleet-backed watcher or hunter runtime with policy-aware telemetry.",
    endpointType: "fleet",
    recommendedModes: ["watcher", "hunter"],
    defaultExecutionMode: "assist",
    maxEnforcementTier: 1,
  },
  {
    kind: "openai_agent",
    label: "OpenAI Agent",
    description: "Remote model-backed agent runtime with mediated tool execution.",
    endpointType: "remote",
    recommendedModes: ["curator", "liaison"],
    defaultExecutionMode: "assist",
    maxEnforcementTier: 1,
  },
  {
    kind: "mcp_worker",
    label: "MCP Worker",
    description: "Local or remote worker reachable through an MCP tool surface.",
    endpointType: "local",
    recommendedModes: ["liaison", "curator"],
    defaultExecutionMode: "enforce",
    maxEnforcementTier: 2,
  },
] as const;

const EXECUTION_MODE_CONFIGS: readonly SentinelExecutionModeConfig[] = [
  {
    mode: "observe",
    label: "Observe",
    description: "Capture receipts and emit signals without mediating side effects.",
  },
  {
    mode: "assist",
    label: "Assist",
    description: "Advisory or operator-mediated execution at the tool boundary.",
  },
  {
    mode: "enforce",
    label: "Enforce",
    description: "Runtime mediates side effects when the selected driver can do so safely.",
  },
] as const;

export function getSentinelDriverDefinitions(): readonly SentinelDriverDefinition[] {
  return DRIVER_DEFINITIONS;
}

export function getSentinelDriverDefinition(driver: SentinelDriverKind): SentinelDriverDefinition {
  const definition = DRIVER_DEFINITIONS.find((candidate) => candidate.kind === driver);
  if (!definition) {
    throw new Error(`Unknown sentinel driver: ${driver}`);
  }
  return definition;
}

export function getSentinelExecutionModes(): readonly SentinelExecutionModeConfig[] {
  return EXECUTION_MODE_CONFIGS;
}

export function getSentinelExecutionModeConfig(
  mode: SentinelExecutionMode,
): SentinelExecutionModeConfig {
  const config = EXECUTION_MODE_CONFIGS.find((candidate) => candidate.mode === mode);
  if (!config) {
    throw new Error(`Unknown sentinel execution mode: ${mode}`);
  }
  return config;
}

export function getRecommendedDriverForMode(mode: SentinelMode): SentinelDriverKind {
  switch (mode) {
    case "watcher":
      return "hushd_agent";
    case "hunter":
      return "openclaw";
    case "curator":
      return "claude_code";
    case "liaison":
      return "mcp_worker";
  }
}

export function getRecommendedGoalTypeForMode(mode: SentinelMode): SentinelGoal["type"] {
  switch (mode) {
    case "watcher":
      return "detect";
    case "hunter":
      return "hunt";
    case "curator":
      return "enrich";
    case "liaison":
      return "enrich";
  }
}

export function deriveEnforcementTier(
  driver: SentinelDriverKind,
  executionMode: SentinelExecutionMode,
): 0 | 1 | 2 | 3 {
  if (executionMode === "observe") return 0;
  if (executionMode === "assist") return 1;

  switch (driver) {
    case "openclaw":
    case "mcp_worker":
      return 2;
    case "claude_code":
    case "hushd_agent":
    case "openai_agent":
      return 1;
  }
}

export function createDefaultRuntimeBinding(
  mode: SentinelMode,
  runtime?: Partial<SentinelRuntimeBinding>,
  fleetAgentId?: string | null,
): SentinelRuntimeBinding {
  const driver = runtime?.driver ?? getRecommendedDriverForMode(mode);
  const definition = getSentinelDriverDefinition(driver);
  const executionMode = runtime?.executionMode ?? definition.defaultExecutionMode;

  return {
    driver,
    executionMode,
    enforcementTier: runtime?.enforcementTier ?? deriveEnforcementTier(driver, executionMode),
    endpointType: runtime?.endpointType ?? definition.endpointType,
    targetRef: runtime?.targetRef ?? fleetAgentId ?? null,
    runtimeRef: runtime?.runtimeRef ?? null,
    sessionRef: runtime?.sessionRef ?? null,
    health: runtime?.health ?? "planned",
    receiptsEnabled: runtime?.receiptsEnabled ?? true,
    emitsSignals: runtime?.emitsSignals ?? true,
    lastHeartbeatAt: runtime?.lastHeartbeatAt ?? null,
    notes: runtime?.notes,
  };
}


export type StatsEvent =
  | { type: "signal_generated" }
  | { type: "finding_created" }
  | { type: "intel_produced" }
  | { type: "false_positive_suppressed" }
  | { type: "swarm_intel_consumed" }
  | { type: "active_tick"; elapsedMs: number };


/**
 * Generate a sentinel ID with the `sen_` prefix.
 * Uses a ULID-like format: timestamp + random component.
 */
function generateSentinelId(): string {
  const timestamp = Date.now().toString(36);
  const random = Array.from(crypto.getRandomValues(new Uint8Array(10)))
    .map((b) => b.toString(36).padStart(2, "0"))
    .join("")
    .slice(0, 16);
  return `sen_${timestamp}${random}`;
}


// Re-export from operator-crypto for backward compatibility.
export { toHex, deriveSigil, SIGILS, type SigilType };

/**
 * Generate a sentinel identity with a real Ed25519 keypair.
 *
 * Uses generateOperatorKeypair() from operator-crypto for proper Ed25519
 * key generation and deriveFingerprint() for SHA-256-based fingerprinting.
 *
 * The secret key from this keygen is not stored — sentinel identity is
 * separate from operator identity. The ownershipProof links the sentinel
 * to the operator.
 */
export async function generateSentinelIdentity(name: string): Promise<SentinelIdentity> {
  const { publicKeyHex } = await generateOperatorKeypair();
  const fingerprint = await deriveFingerprint(publicKeyHex);
  const sigil = deriveSigil(fingerprint);
  const nickname = name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, "")
    .replace(/\s+/g, "-")
    .slice(0, 24);

  return { publicKey: publicKeyHex, fingerprint, sigil, nickname };
}


/**
 * Create a zeroed SentinelStats object.
 */
export function createInitialStats(): SentinelStats {
  return {
    signalsGenerated: 0,
    findingsCreated: 0,
    intelProduced: 0,
    falsePositivesSuppressed: 0,
    swarmIntelConsumed: 0,
    uptimeMs: 0,
    lastActiveAt: Date.now(),
  };
}

/**
 * Update stats by applying a stats event. Returns a new stats object.
 */
export function updateStats(stats: SentinelStats, event: StatsEvent): SentinelStats {
  const now = Date.now();
  switch (event.type) {
    case "signal_generated":
      return { ...stats, signalsGenerated: stats.signalsGenerated + 1, lastActiveAt: now };
    case "finding_created":
      return { ...stats, findingsCreated: stats.findingsCreated + 1, lastActiveAt: now };
    case "intel_produced":
      return { ...stats, intelProduced: stats.intelProduced + 1, lastActiveAt: now };
    case "false_positive_suppressed":
      return {
        ...stats,
        falsePositivesSuppressed: stats.falsePositivesSuppressed + 1,
        lastActiveAt: now,
      };
    case "swarm_intel_consumed":
      return { ...stats, swarmIntelConsumed: stats.swarmIntelConsumed + 1, lastActiveAt: now };
    case "active_tick":
      return { ...stats, uptimeMs: stats.uptimeMs + event.elapsedMs, lastActiveAt: now };
  }
}


/**
 * Create a new Sentinel with a generated ID, identity, and empty memory.
 * Returns the created Sentinel.
 */
export async function createSentinel(config: CreateSentinelConfig): Promise<Sentinel> {
  const now = Date.now();
  const id = generateSentinelId();
  const identity = await generateSentinelIdentity(config.name);
  const runtime = createDefaultRuntimeBinding(config.mode, config.runtime, config.fleetAgentId);

  let ownershipProof: import("./operator-crypto").OwnershipProof | null = null;
  if (config.operatorSecretKey) {
    const { signOwnershipProof } = await import("./operator-crypto");
    ownershipProof = await signOwnershipProof(identity.publicKey, config.operatorSecretKey);
  }

  const sentinel: Sentinel = {
    id,
    name: config.name,
    mode: config.mode,
    owner: config.owner,
    identity,
    policy: config.policy,
    goals: config.goals ?? [],
    memory: {
      knownPatterns: [],
      baselineProfiles: [],
      falsePositiveHashes: [],
      lastUpdated: now,
    },
    schedule: config.schedule ?? null,
    status: "paused",
    swarms: [],
    runtime,
    stats: createInitialStats(),
    fleetAgentId: config.fleetAgentId ?? null,
    ownerPublicKey: config.operatorPublicKey,
    ownershipProof,
    createdAt: now,
    updatedAt: now,
  };

  return sentinel;
}

/**
 * Update mutable fields on a sentinel. Returns a new Sentinel with the
 * patch applied and updatedAt bumped.
 */
export function updateSentinel(
  sentinel: Sentinel,
  patch: SentinelMutablePatch,
): Sentinel {
  const nextMode = patch.mode ?? sentinel.mode;
  const nextFleetAgentId =
    patch.fleetAgentId === undefined ? sentinel.fleetAgentId : patch.fleetAgentId;
  const runtimeNeedsNormalization =
    patch.mode !== undefined || patch.runtime !== undefined || patch.fleetAgentId !== undefined;
  const runtimeInput: Partial<SentinelRuntimeBinding> | undefined = runtimeNeedsNormalization
    ? { ...sentinel.runtime, ...patch.runtime }
    : undefined;

  if (runtimeInput) {
    if (patch.runtime?.driver !== undefined) {
      if (patch.runtime.endpointType === undefined) runtimeInput.endpointType = undefined;
      if (patch.runtime.enforcementTier === undefined) runtimeInput.enforcementTier = undefined;
      if (patch.runtime.runtimeRef === undefined) runtimeInput.runtimeRef = undefined;
      if (patch.runtime.sessionRef === undefined) runtimeInput.sessionRef = undefined;
      if (patch.runtime.lastHeartbeatAt === undefined) runtimeInput.lastHeartbeatAt = undefined;
      if (patch.runtime.health === undefined) runtimeInput.health = undefined;
    } else if (
      patch.runtime?.executionMode !== undefined &&
      patch.runtime.enforcementTier === undefined
    ) {
      runtimeInput.enforcementTier = undefined;
    }

    if (patch.fleetAgentId !== undefined && patch.runtime?.targetRef === undefined) {
      runtimeInput.targetRef = undefined;
    }
  }

  const runtime = runtimeNeedsNormalization
    ? createDefaultRuntimeBinding(
        nextMode,
        runtimeInput,
        nextFleetAgentId,
      )
    : sentinel.runtime;

  return {
    ...sentinel,
    ...patch,
    runtime,
    fleetAgentId: nextFleetAgentId,
    updatedAt: Date.now(),
  };
}

/**
 * Remove a sentinel from a list by ID. Returns the new array.
 */
export function deleteSentinel(sentinelId: string, sentinels: readonly Sentinel[]): Sentinel[] {
  return sentinels.filter((s) => s.id !== sentinelId);
}

/**
 * Look up a sentinel by ID. Returns the sentinel or undefined.
 */
export function getSentinel(
  sentinelId: string,
  sentinels: readonly Sentinel[],
): Sentinel | undefined {
  return sentinels.find((s) => s.id === sentinelId);
}


/**
 * Valid status transitions:
 *
 *   paused  -> active
 *   active  -> paused
 *   active  -> retired
 *   paused  -> retired
 *
 * "retired" is terminal — no transitions out.
 */
const VALID_TRANSITIONS: ReadonlyMap<SentinelStatus, readonly SentinelStatus[]> = new Map([
  ["paused", ["active", "retired"]],
  ["active", ["paused", "retired"]],
  ["retired", []],
]);

/**
 * Check whether a status transition is valid.
 */
export function validateStatusTransition(from: SentinelStatus, to: SentinelStatus): boolean {
  const allowed = VALID_TRANSITIONS.get(from);
  return allowed !== undefined && allowed.includes(to);
}

/**
 * Activate a sentinel. Returns a new Sentinel with status "active".
 * Throws if the transition is invalid.
 */
export function activateSentinel(sentinel: Sentinel): Sentinel {
  if (!validateStatusTransition(sentinel.status, "active")) {
    throw new Error(
      `Cannot activate sentinel: invalid transition from "${sentinel.status}" to "active"`,
    );
  }
  return { ...sentinel, status: "active", updatedAt: Date.now() };
}

/**
 * Pause a sentinel. Returns a new Sentinel with status "paused".
 * Throws if the transition is invalid.
 */
export function pauseSentinel(sentinel: Sentinel): Sentinel {
  if (!validateStatusTransition(sentinel.status, "paused")) {
    throw new Error(
      `Cannot pause sentinel: invalid transition from "${sentinel.status}" to "paused"`,
    );
  }
  return { ...sentinel, status: "paused", updatedAt: Date.now() };
}

/**
 * Retire a sentinel (terminal state). Returns a new Sentinel with status "retired".
 * Throws if the transition is invalid.
 */
export function retireSentinel(sentinel: Sentinel): Sentinel {
  if (!validateStatusTransition(sentinel.status, "retired")) {
    throw new Error(
      `Cannot retire sentinel: invalid transition from "${sentinel.status}" to "retired"`,
    );
  }
  return { ...sentinel, status: "retired", updatedAt: Date.now() };
}


/**
 * Add a MemoryPattern to sentinel memory. Deduplicates by pattern ID.
 * Returns a new SentinelMemory.
 */
export function addPattern(memory: SentinelMemory, pattern: MemoryPattern): SentinelMemory {
  // Check if pattern with the same ID already exists
  const exists = memory.knownPatterns.some((p) => p.id === pattern.id);
  if (exists) {
    // Update existing pattern in place (bump match count, refresh timestamp)
    return {
      ...memory,
      knownPatterns: memory.knownPatterns.map((p) =>
        p.id === pattern.id
          ? { ...pattern, localMatchCount: p.localMatchCount + pattern.localMatchCount }
          : p,
      ),
      lastUpdated: Date.now(),
    };
  }

  return {
    ...memory,
    knownPatterns: [...memory.knownPatterns, pattern],
    lastUpdated: Date.now(),
  };
}

/**
 * Add a false-positive hash to sentinel memory. Deduplicates.
 * Returns a new SentinelMemory.
 */
export function addFalsePositiveHash(memory: SentinelMemory, hash: string): SentinelMemory {
  if (memory.falsePositiveHashes.includes(hash)) {
    return memory;
  }

  return {
    ...memory,
    falsePositiveHashes: [...memory.falsePositiveHashes, hash],
    lastUpdated: Date.now(),
  };
}

/**
 * Prune memory to stay within limits. Evicts oldest patterns and oldest
 * false-positive hashes first.
 * Returns a new SentinelMemory.
 */
export function pruneMemory(
  memory: SentinelMemory,
  maxPatterns: number = 500,
  maxFPHashes: number = 10_000,
): SentinelMemory {
  let knownPatterns = memory.knownPatterns;
  let falsePositiveHashes = memory.falsePositiveHashes;

  if (knownPatterns.length > maxPatterns) {
    knownPatterns = [...knownPatterns]
      .sort((a, b) => b.addedAt - a.addedAt)
      .slice(0, maxPatterns);
  }

  if (falsePositiveHashes.length > maxFPHashes) {
    falsePositiveHashes = falsePositiveHashes.slice(-maxFPHashes);
  }

  if (
    knownPatterns === memory.knownPatterns &&
    falsePositiveHashes === memory.falsePositiveHashes
  ) {
    return memory;
  }

  return {
    ...memory,
    knownPatterns,
    falsePositiveHashes,
    lastUpdated: Date.now(),
  };
}

export function mergeSwarmPattern(
  memory: SentinelMemory,
  intelPattern: MemoryPattern,
  peerReputation: number,
  minReputation: number = 0.3,
): SentinelMemory {
  if (peerReputation < minReputation) {
    return memory;
  }

  const importedPattern: MemoryPattern = {
    ...intelPattern,
    source: "imported_intel",
    localMatchCount: 0,
    addedAt: Date.now(),
  };

  return addPattern(memory, importedPattern);
}


export function isScheduleDue(sentinel: Sentinel, now: Date = new Date()): boolean {
  if (sentinel.status !== "active") return false;
  if (!sentinel.schedule) return false;

  const schedule = sentinel.schedule.trim();

  // Handle special strings
  if (schedule === "@hourly") {
    return now.getMinutes() === 0;
  }
  if (schedule === "@daily") {
    return now.getHours() === 0 && now.getMinutes() === 0;
  }
  if (schedule === "@weekly") {
    return now.getDay() === 0 && now.getHours() === 0 && now.getMinutes() === 0;
  }

  // Parse standard 5-field cron: minute hour day month weekday
  const parts = schedule.split(/\s+/);
  if (parts.length < 2) return false;

  const [minuteField, hourField] = parts;

  const minuteMatch = matchCronField(minuteField, now.getMinutes());
  const hourMatch = matchCronField(hourField, now.getHours());

  return minuteMatch && hourMatch;
}

/**
 * Match a single cron field value against the current value.
 * Supports: "*", specific number, and step expressions ("*​/N").
 */
function matchCronField(field: string, value: number): boolean {
  if (field === "*") return true;

  // Step expression: */N
  if (field.startsWith("*/")) {
    const step = parseInt(field.slice(2), 10);
    if (Number.isNaN(step) || step <= 0) return false;
    return value % step === 0;
  }

  // Comma-separated values: 0,15,30,45
  if (field.includes(",")) {
    return field.split(",").some((v) => parseInt(v, 10) === value);
  }

  // Range: 1-5
  if (field.includes("-")) {
    const [start, end] = field.split("-").map((v) => parseInt(v, 10));
    if (Number.isNaN(start) || Number.isNaN(end)) return false;
    return value >= start && value <= end;
  }

  // Exact match
  const exact = parseInt(field, 10);
  return !Number.isNaN(exact) && exact === value;
}

/**
 * Calculate the next time a scheduled sentinel should run.
 * Returns a Date or null if the sentinel is not scheduled.
 *
 * This is a simplified calculation — walks forward minute by minute
 * up to 7 days. For production use, replace with a proper cron library.
 */
export function getNextRunTime(sentinel: Sentinel, from: Date = new Date()): Date | null {
  if (!sentinel.schedule) return null;

  // Walk forward minute by minute, up to 7 days (10080 minutes)
  const maxMinutes = 7 * 24 * 60;
  const candidate = new Date(from.getTime());
  // Start from the next minute
  candidate.setSeconds(0, 0);
  candidate.setMinutes(candidate.getMinutes() + 1);

  for (let i = 0; i < maxMinutes; i++) {
    if (isScheduleDue({ ...sentinel, status: "active" }, candidate)) {
      return candidate;
    }
    candidate.setMinutes(candidate.getMinutes() + 1);
  }

  return null; // No match within 7 days
}


/**
 * Get the capabilities for a given sentinel mode.
 *
 * From INDEX.md section 1:
 * - Watcher:  continuous monitoring/detection
 * - Hunter:   exploratory or recurring threat hunts
 * - Curator:  groups signals, writes summaries, promotes patterns
 * - Liaison:  participates in swarms/speakeasies and exchanges intel
 */
export function getSentinelCapabilities(mode: SentinelMode): SentinelCapabilities {
  switch (mode) {
    case "watcher":
      return {
        canMonitor: true,
        canHunt: false,
        canCurate: false,
        canLiaison: false,
        canPromoteIntel: false,
        canUpdateBaselines: true,
        supportsSchedule: false,
      };
    case "hunter":
      return {
        canMonitor: false,
        canHunt: true,
        canCurate: false,
        canLiaison: false,
        canPromoteIntel: false,
        canUpdateBaselines: true,
        supportsSchedule: true,
      };
    case "curator":
      return {
        canMonitor: true,
        canHunt: false,
        canCurate: true,
        canLiaison: false,
        canPromoteIntel: true,
        canUpdateBaselines: false,
        supportsSchedule: false,
      };
    case "liaison":
      return {
        canMonitor: false,
        canHunt: false,
        canCurate: false,
        canLiaison: true,
        canPromoteIntel: true,
        canUpdateBaselines: false,
        supportsSchedule: false,
      };
  }
}

/**
 * Validate that a set of goals is compatible with a sentinel mode.
 *
 * Rules:
 * - "detect" goals require canMonitor
 * - "hunt" goals require canHunt
 * - "monitor" goals require canMonitor
 * - "enrich" goals require canCurate or canLiaison
 *
 * Returns an array of validation error messages. Empty array = valid.
 */
export function validateGoalsForMode(mode: SentinelMode, goals: SentinelGoal[]): string[] {
  const caps = getSentinelCapabilities(mode);
  const errors: string[] = [];

  for (const goal of goals) {
    switch (goal.type) {
      case "detect":
        if (!caps.canMonitor) {
          errors.push(
            `Goal type "detect" is not supported by mode "${mode}". Use "watcher" or "curator" mode.`,
          );
        }
        break;
      case "hunt":
        if (!caps.canHunt) {
          errors.push(`Goal type "hunt" is not supported by mode "${mode}". Use "hunter" mode.`);
        }
        break;
      case "monitor":
        if (!caps.canMonitor) {
          errors.push(
            `Goal type "monitor" is not supported by mode "${mode}". Use "watcher" or "curator" mode.`,
          );
        }
        break;
      case "enrich":
        if (!caps.canCurate && !caps.canLiaison) {
          errors.push(
            `Goal type "enrich" is not supported by mode "${mode}". Use "curator" or "liaison" mode.`,
          );
        }
        break;
    }
  }

  return errors;
}
