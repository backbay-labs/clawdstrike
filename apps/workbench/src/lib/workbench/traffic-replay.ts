/**
 * Traffic Replay Engine
 *
 * Converts production audit events from hushd into test scenarios for
 * what-if analysis. Part of the Fleet-Aware Testing feature.
 */

import type {
  TestScenario,
  TestActionType,
  Verdict,
  WorkbenchPolicy,
  GuardId,
} from "./types";
import type { AuditEvent } from "./fleet-client";
import { ALL_GUARD_IDS, GUARD_DISPLAY_NAMES } from "./guard-registry";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface TrafficSummary {
  totalEvents: number;
  byActionType: Record<string, number>;
  byDecision: Record<string, number>;
  byGuard: Record<string, number>;
  timeRange: { earliest: string; latest: string } | null;
}

export interface CoverageGap {
  actionType: string;
  guardId: GuardId;
  guardName: string;
  eventCount: number;
  percentage: number;
  message: string;
  severity: "high" | "medium" | "low";
}

export interface WhatIfDelta {
  eventId: string;
  eventTarget: string;
  actionType: string;
  productionDecision: string;
  draftDecision: Verdict;
  changed: boolean;
}

export interface WhatIfSummary {
  totalScenarios: number;
  productionAllow: number;
  productionDeny: number;
  productionWarn: number;
  draftAllow: number;
  draftDeny: number;
  draftWarn: number;
  changedCount: number;
  deltas: WhatIfDelta[];
}

// ---------------------------------------------------------------------------
// Action type normalization
// ---------------------------------------------------------------------------

/** Map hushd action_type strings to workbench TestActionType. */
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
  const result = map[raw.toLowerCase()] ?? null;
  if (result === null) {
    console.warn(`[traffic-replay] normalizeActionType: unknown action type "${raw}"`);
  }
  return result;
}

/** Map a decision string from hushd to a Verdict. */
function normalizeDecision(raw: string): Verdict {
  const lower = raw.toLowerCase();
  if (lower === "allow" || lower === "allowed" || lower === "pass") return "allow";
  if (lower === "deny" || lower === "denied" || lower === "blocked" || lower === "block") return "deny";
  if (lower === "warn" || lower === "warning") return "warn";
  // Fail-closed: unknown decisions default to deny
  console.warn(`[traffic-replay] normalizeDecision: unknown decision "${raw}", defaulting to deny`);
  return "deny";
}

/** Derive category from decision. */
function categoryFromDecision(decision: string): "benign" | "attack" | "edge_case" {
  const v = normalizeDecision(decision);
  if (v === "deny") return "attack";
  if (v === "warn") return "edge_case";
  return "benign";
}

// ---------------------------------------------------------------------------
// Build payload from audit event
// ---------------------------------------------------------------------------

function buildPayload(
  actionType: TestActionType,
  event: AuditEvent,
): Record<string, unknown> {
  const target = event.target ?? "";
  switch (actionType) {
    case "file_access":
    case "file_write":
    case "patch_apply":
      return { path: target };
    case "network_egress": {
      // Target might be "host:port" or just "host"
      const parts = target.split(":");
      const host = parts[0] ?? target;
      const port = parts[1] ? Number(parts[1]) : 443;
      return { host, port };
    }
    case "shell_command":
      return { command: target };
    case "mcp_tool_call":
      return { tool: target, args: event.metadata?.args ?? {} };
    case "user_input":
      return { text: target };
    default:
      return { target };
  }
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/**
 * Convert audit events from hushd into TestScenarios.
 * Deterministic: same events in the same order produce the same scenarios.
 */
export function auditEventsToScenarios(events: AuditEvent[]): TestScenario[] {
  const MAX_EVENTS = 10_000;
  if (events.length > MAX_EVENTS) {
    console.warn(
      `[traffic-replay] auditEventsToScenarios: truncating ${events.length} events to ${MAX_EVENTS}`,
    );
    events = events.slice(0, MAX_EVENTS);
  }

  const scenarios: TestScenario[] = [];

  for (let i = 0; i < events.length; i++) {
    const event = events[i];
    const actionType = normalizeActionType(event.action_type);
    if (!actionType) continue;

    const decision = event.decision ?? "allow";
    const verdict = normalizeDecision(decision);
    const category = categoryFromDecision(decision);
    const target = event.target ?? "unknown";

    // Deterministic ID from index + event id
    const id = `fleet-${i}-${event.id}`;

    scenarios.push({
      id,
      name: `[Fleet] ${event.action_type}: ${truncate(target, 40)}`,
      description: `Production event from ${event.timestamp ?? "unknown time"}${event.agent_id ? ` (agent: ${event.agent_id})` : ""}${event.guard ? ` — guard: ${event.guard}` : ""}`,
      category,
      actionType,
      payload: buildPayload(actionType, event),
      expectedVerdict: verdict,
      severity: event.severity === "critical" ? "critical" : event.severity === "high" ? "high" : event.severity === "medium" ? "medium" : "low",
    });
  }

  return scenarios;
}

/**
 * Summarize traffic from audit events.
 */
export function summarizeTraffic(events: AuditEvent[]): TrafficSummary {
  const byActionType: Record<string, number> = {};
  const byDecision: Record<string, number> = {};
  const byGuard: Record<string, number> = {};
  let earliest = "";
  let latest = "";
  let earliestMs = Infinity;
  let latestMs = -Infinity;

  for (const event of events) {
    // Action type counts
    const at = event.action_type || "unknown";
    byActionType[at] = (byActionType[at] ?? 0) + 1;

    // Decision counts
    const dec = (event.decision || "unknown").toLowerCase();
    byDecision[dec] = (byDecision[dec] ?? 0) + 1;

    // Guard counts
    if (event.guard) {
      byGuard[event.guard] = (byGuard[event.guard] ?? 0) + 1;
    }

    // Time range (parse once, compare numeric ms values)
    if (event.timestamp) {
      const ms = new Date(event.timestamp).getTime();
      if (ms < earliestMs) {
        earliestMs = ms;
        earliest = event.timestamp;
      }
      if (ms > latestMs) {
        latestMs = ms;
        latest = event.timestamp;
      }
    }
  }

  return {
    totalEvents: events.length,
    byActionType,
    byDecision,
    byGuard,
    timeRange: earliest && latest ? { earliest, latest } : null,
  };
}

/**
 * Map action types from production traffic to the guards that handle them.
 */
function guardsForActionType(actionType: string): GuardId[] {
  const normalized = normalizeActionType(actionType);
  if (!normalized) return [];

  switch (normalized) {
    case "file_access":
      return ["forbidden_path", "path_allowlist"];
    case "file_write":
      return ["forbidden_path", "path_allowlist", "secret_leak"];
    case "network_egress":
      return ["egress_allowlist"];
    case "shell_command":
      return ["shell_command"];
    case "mcp_tool_call":
      return ["mcp_tool"];
    case "patch_apply":
      return ["patch_integrity", "path_allowlist"];
    case "user_input":
      return ["prompt_injection", "jailbreak", "spider_sense"];
    default:
      return [];
  }
}

/**
 * Identify gaps between production traffic and the current policy.
 * Finds action types in production that map to disabled guards.
 */
export function identifyCoverageGaps(
  events: AuditEvent[],
  policy: WorkbenchPolicy,
): CoverageGap[] {
  if (events.length === 0) return [];

  // Count events by action type
  const actionTypeCounts: Record<string, number> = {};
  for (const event of events) {
    const at = event.action_type || "unknown";
    actionTypeCounts[at] = (actionTypeCounts[at] ?? 0) + 1;
  }

  const gaps: CoverageGap[] = [];
  const totalEvents = events.length;

  // For each action type in production, check if the relevant guards are enabled
  for (const [actionType, count] of Object.entries(actionTypeCounts)) {
    const relevantGuards = guardsForActionType(actionType);
    const percentage = Math.round((count / totalEvents) * 100);

    for (const guardId of relevantGuards) {
      if (!ALL_GUARD_IDS.includes(guardId)) continue;

      const config = policy.guards[guardId];
      const isEnabled = !!(config && (config as { enabled?: boolean }).enabled !== false);

      if (!isEnabled) {
        const guardName = GUARD_DISPLAY_NAMES[guardId] ?? guardId;
        const severity: "high" | "medium" | "low" =
          percentage >= 20 ? "high" : percentage >= 5 ? "medium" : "low";

        gaps.push({
          actionType,
          guardId,
          guardName,
          eventCount: count,
          percentage,
          message: `${percentage}% of traffic is ${actionType} but ${guardName} guard is disabled`,
          severity,
        });
      }
    }
  }

  // Deduplicate by guardId, aggregating eventCount across action types
  const deduped = new Map<GuardId, CoverageGap>();
  for (const gap of gaps) {
    const existing = deduped.get(gap.guardId);
    if (existing) {
      existing.eventCount += gap.eventCount;
      existing.percentage = Math.round((existing.eventCount / totalEvents) * 100);
      existing.severity =
        existing.percentage >= 20 ? "high" : existing.percentage >= 5 ? "medium" : "low";
      existing.message = `${existing.percentage}% of traffic involves actions needing ${existing.guardName} but it is disabled`;
    } else {
      deduped.set(gap.guardId, { ...gap });
    }
  }

  const dedupedGaps = Array.from(deduped.values());

  // Sort by percentage descending (highest-impact gaps first)
  dedupedGaps.sort((a, b) => b.percentage - a.percentage);

  return dedupedGaps;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function truncate(s: string, maxLen: number): string {
  if (s.length <= maxLen) return s;
  return s.slice(0, maxLen - 3) + "...";
}
