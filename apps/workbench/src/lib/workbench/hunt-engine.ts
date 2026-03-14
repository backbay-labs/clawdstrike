/**
 * Hunt Lab engine — anomaly detection, baseline computation, pattern matching.
 *
 * All algorithms run client-side on fleet audit events. No server dependency
 * beyond the existing fleet-client fetchAuditEvents endpoint.
 */

import type { AuditEvent } from "./fleet-client";
import type {
  AgentEvent,
  AgentBaseline,
  DriftMetric,
  StreamStats,
  AnomalyResult,
  AnomalyFactor,
  HuntPattern,
  PatternStep,
  EventFlag,
} from "./hunt-types";
import type { TestActionType, Verdict, GuardSimResult } from "./types";


const ACTION_TYPE_MAP: Record<string, TestActionType> = {
  file_access: "file_access",
  file_write: "file_write",
  network: "network_egress",
  network_egress: "network_egress",
  shell: "shell_command",
  shell_command: "shell_command",
  mcp_tool: "mcp_tool_call",
  mcp_tool_call: "mcp_tool_call",
  patch: "patch_apply",
  patch_apply: "patch_apply",
  user_input: "user_input",
};

function mapActionType(raw: string): TestActionType {
  return ACTION_TYPE_MAP[raw] ?? "shell_command";
}

function mapVerdict(decision: string): Verdict {
  if (decision === "allow" || decision === "allowed") return "allow";
  if (decision === "deny" || decision === "denied") return "deny";
  return "warn";
}

export function auditEventToAgentEvent(ae: AuditEvent): AgentEvent {
  const guardResults: GuardSimResult[] = [];
  if (ae.guard) {
    guardResults.push({
      guardId: ae.guard as GuardSimResult["guardId"],
      guardName: ae.guard,
      verdict: mapVerdict(ae.decision),
      message: `Guard ${ae.guard} evaluated`,
    });
  }

  return {
    id: ae.id,
    timestamp: ae.timestamp,
    agentId: ae.agent_id ?? "unknown",
    agentName: ae.agent_id ?? "unknown-agent",
    teamId: (ae.metadata?.team_id as string) ?? undefined,
    sessionId: ae.session_id ?? ae.id,
    actionType: mapActionType(ae.action_type),
    target: ae.target ?? "",
    content: (ae.metadata?.content as string) ?? undefined,
    verdict: mapVerdict(ae.decision),
    guardResults,
    receiptId: (ae.metadata?.receipt_id as string) ?? undefined,
    policyVersion: (ae.metadata?.policy_version as string) ?? "unknown",
    flags: [],
  };
}


export function computeStreamStats(events: AgentEvent[]): StreamStats {
  const stats: StreamStats = {
    total: events.length,
    allowed: 0,
    denied: 0,
    warned: 0,
    anomalies: 0,
    byActionType: {},
  };

  for (const e of events) {
    if (e.verdict === "allow") stats.allowed++;
    else if (e.verdict === "deny") stats.denied++;
    else stats.warned++;

    if ((e.anomalyScore ?? 0) > 0.7) stats.anomalies++;

    const at = e.actionType;
    stats.byActionType[at] = (stats.byActionType[at] ?? 0) + 1;
  }

  return stats;
}


/**
 * Score how anomalous an event is relative to a baseline.
 * Uses z-score across multiple dimensions.
 */
export function scoreAnomaly(
  event: AgentEvent,
  baseline: AgentBaseline | null,
): AnomalyResult {
  if (!baseline) {
    return { score: 0, factors: [] };
  }

  const factors: AnomalyFactor[] = [];

  // Factor 1: Action type frequency deviation
  const actionFreq = baseline.actionDistribution[event.actionType] ?? 0;
  const totalActions = Object.values(baseline.actionDistribution).reduce((a, b) => a + b, 0);
  const expectedRate = totalActions > 0 ? actionFreq / totalActions : 0;
  if (expectedRate < 0.01) {
    factors.push({
      name: "rare_action_type",
      weight: 0.3,
      zScore: 3.0,
      description: `${event.actionType} is rarely seen for this agent (${(expectedRate * 100).toFixed(1)}% of baseline)`,
    });
  }

  // Factor 2: Target novelty — is this target in the top known targets?
  const knownTargets = new Set(baseline.topTargets.map((t) => t.target));
  if (!knownTargets.has(event.target) && event.target) {
    factors.push({
      name: "novel_target",
      weight: 0.25,
      zScore: 2.5,
      description: `Target "${event.target}" not in known target set`,
    });
  }

  // Factor 3: Time-of-day deviation
  const hour = new Date(event.timestamp).getHours();
  const hourlyActivity = baseline.hourlyActivity[hour] ?? 0;
  const avgHourly = baseline.hourlyActivity.reduce((a, b) => a + b, 0) / 24;
  if (avgHourly > 0 && hourlyActivity < avgHourly * 0.1) {
    factors.push({
      name: "unusual_time",
      weight: 0.2,
      zScore: 2.0,
      description: `Activity at ${hour}:00 is unusual (${hourlyActivity.toFixed(0)} vs avg ${avgHourly.toFixed(0)})`,
    });
  }

  // Factor 4: Denied actions (blocked by policy)
  if (event.verdict === "deny") {
    factors.push({
      name: "denied_action",
      weight: 0.25,
      zScore: 1.5,
      description: "Action was denied by policy enforcement",
    });
  }

  // Compute weighted score (0–1)
  if (factors.length === 0) return { score: 0, factors: [] };

  const totalWeight = factors.reduce((sum, f) => sum + f.weight, 0);
  const weightedSum = factors.reduce((sum, f) => sum + f.weight * Math.min(f.zScore / 3, 1), 0);
  const score = Math.min(weightedSum / Math.max(totalWeight, 1), 1);

  return { score, factors };
}

/**
 * Enrich events with anomaly scores and flags.
 */
export function enrichEvents(
  events: AgentEvent[],
  baselines: Map<string, AgentBaseline>,
): AgentEvent[] {
  return events.map((event) => {
    const baseline = baselines.get(event.agentId) ?? null;
    const anomaly = scoreAnomaly(event, baseline);
    const flags: EventFlag[] = [...event.flags];

    if (anomaly.score > 0.7) {
      flags.push({
        type: "anomaly",
        reason: anomaly.factors.map((f) => f.name).join(", "),
        score: anomaly.score,
      });
    }

    return { ...event, anomalyScore: anomaly.score, flags };
  });
}


/**
 * Compute a behavioral baseline from a set of events for a specific agent.
 */
export function computeBaseline(
  agentId: string,
  agentName: string,
  events: AgentEvent[],
  teamId?: string,
): AgentBaseline {
  const agentEvents = events.filter((e) => e.agentId === agentId);
  const timestamps = agentEvents.map((e) => new Date(e.timestamp));
  const start = timestamps.length > 0 ? new Date(Math.min(...timestamps.map((t) => t.getTime()))).toISOString() : new Date().toISOString();
  const end = timestamps.length > 0 ? new Date(Math.max(...timestamps.map((t) => t.getTime()))).toISOString() : new Date().toISOString();

  // Action distribution
  const actionDistribution: Record<string, number> = {};
  for (const e of agentEvents) {
    actionDistribution[e.actionType] = (actionDistribution[e.actionType] ?? 0) + 1;
  }

  // Hourly activity (24 buckets)
  const hourlyActivity = new Array(24).fill(0) as number[];
  for (const t of timestamps) {
    hourlyActivity[t.getHours()]++;
  }

  // Daily activity (7 buckets, Mon=0)
  const dailyActivity = new Array(7).fill(0) as number[];
  for (const t of timestamps) {
    const day = (t.getDay() + 6) % 7; // Mon=0
    dailyActivity[day]++;
  }

  // Top targets
  const targetCounts = new Map<string, { count: number; actionType: string }>();
  for (const e of agentEvents) {
    if (!e.target) continue;
    const existing = targetCounts.get(e.target);
    if (existing) {
      existing.count++;
    } else {
      targetCounts.set(e.target, { count: 1, actionType: e.actionType });
    }
  }
  const topTargets = Array.from(targetCounts.entries())
    .map(([target, { count, actionType }]) => ({ target, count, actionType }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);

  // Session lengths
  const sessionLengths = new Map<string, number>();
  for (const e of agentEvents) {
    sessionLengths.set(e.sessionId, (sessionLengths.get(e.sessionId) ?? 0) + 1);
  }
  const avgSessionLength = sessionLengths.size > 0
    ? Array.from(sessionLengths.values()).reduce((a, b) => a + b, 0) / sessionLengths.size
    : 0;

  // Daily average
  const daySpan = timestamps.length > 1
    ? Math.max(1, (new Date(end).getTime() - new Date(start).getTime()) / (1000 * 60 * 60 * 24))
    : 1;
  const avgDailyEvents = agentEvents.length / daySpan;

  return {
    agentId,
    agentName,
    teamId,
    period: { start, end },
    actionDistribution,
    hourlyActivity,
    dailyActivity,
    topTargets,
    avgSessionLength,
    avgDailyEvents,
    anomalyThreshold: 0.7,
    driftSensitivity: "medium",
    driftMetrics: [],
  };
}

/**
 * Compare two baselines and compute drift metrics.
 */
export function computeDrift(
  previous: AgentBaseline,
  current: AgentBaseline,
): DriftMetric[] {
  const metrics: DriftMetric[] = [];

  // Compare action distribution changes
  const allActions = new Set([
    ...Object.keys(previous.actionDistribution),
    ...Object.keys(current.actionDistribution),
  ]);

  for (const action of allActions) {
    const prev = previous.actionDistribution[action] ?? 0;
    const curr = current.actionDistribution[action] ?? 0;
    if (prev === 0 && curr === 0) continue;

    const pctChange = prev > 0 ? ((curr - prev) / prev) * 100 : curr > 0 ? 100 : 0;
    const significance: DriftMetric["significance"] =
      Math.abs(pctChange) > 200 ? "alert" : Math.abs(pctChange) > 50 ? "notable" : "normal";

    metrics.push({
      metric: `${action}_frequency`,
      baseline: prev,
      current: curr,
      percentChange: Math.round(pctChange),
      significance,
    });
  }

  // Compare daily event volume
  const prevAvg = previous.avgDailyEvents;
  const currAvg = current.avgDailyEvents;
  if (prevAvg > 0) {
    const pctChange = ((currAvg - prevAvg) / prevAvg) * 100;
    metrics.push({
      metric: "daily_event_volume",
      baseline: Math.round(prevAvg),
      current: Math.round(currAvg),
      percentChange: Math.round(pctChange),
      significance: Math.abs(pctChange) > 200 ? "alert" : Math.abs(pctChange) > 50 ? "notable" : "normal",
    });
  }

  // Compare unique targets
  const prevTargets = previous.topTargets.length;
  const currTargets = current.topTargets.length;
  if (prevTargets > 0) {
    const pctChange = ((currTargets - prevTargets) / prevTargets) * 100;
    metrics.push({
      metric: "unique_targets",
      baseline: prevTargets,
      current: currTargets,
      percentChange: Math.round(pctChange),
      significance: Math.abs(pctChange) > 100 ? "alert" : Math.abs(pctChange) > 30 ? "notable" : "normal",
    });
  }

  return metrics.sort((a, b) => Math.abs(b.percentChange) - Math.abs(a.percentChange));
}


/**
 * Check if a session's events match a pattern sequence.
 */
export function matchPatternInSession(
  sessionEvents: AgentEvent[],
  pattern: HuntPattern,
): boolean {
  const sorted = [...sessionEvents].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
  );

  let stepIdx = 0;
  let lastMatchTime = 0;

  for (const event of sorted) {
    const step = pattern.sequence[stepIdx];
    if (!step) break;

    // Check action type match
    if (event.actionType !== step.actionType) continue;

    // Check target pattern match (glob-style)
    if (step.targetPattern && !matchGlob(event.target, step.targetPattern)) continue;

    // Check time window constraint
    const eventTime = new Date(event.timestamp).getTime();
    if (stepIdx > 0 && step.timeWindow && eventTime - lastMatchTime > step.timeWindow) {
      // Timeout — reset
      stepIdx = 0;
      continue;
    }

    lastMatchTime = eventTime;
    stepIdx++;

    if (stepIdx >= pattern.sequence.length) return true;
  }

  return false;
}

/**
 * Discover recurring action sequences across sessions.
 * Uses a simple n-gram frequency analysis approach.
 */
export function discoverPatterns(
  events: AgentEvent[],
  minOccurrences: number = 3,
  sequenceLength: number = 3,
): HuntPattern[] {
  // Group events by session
  const sessions = new Map<string, AgentEvent[]>();
  for (const e of events) {
    const key = `${e.agentId}:${e.sessionId}`;
    const session = sessions.get(key);
    if (session) {
      session.push(e);
    } else {
      sessions.set(key, [e]);
    }
  }

  // Extract n-grams of action sequences
  const ngramCounts = new Map<string, {
    count: number;
    steps: PatternStep[];
    sessionIds: Set<string>;
    agentIds: Set<string>;
  }>();

  for (const [key, sessionEvents] of sessions) {
    const sorted = [...sessionEvents].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
    );

    const [agentId] = key.split(":");

    for (let i = 0; i <= sorted.length - sequenceLength; i++) {
      const window = sorted.slice(i, i + sequenceLength);
      const signature = window.map((e) => `${e.actionType}:${generalizeTarget(e.target)}`).join(" → ");

      const existing = ngramCounts.get(signature);
      if (existing) {
        existing.count++;
        existing.sessionIds.add(window[0].sessionId);
        if (agentId) existing.agentIds.add(agentId);
      } else {
        const steps: PatternStep[] = window.map((e, idx) => ({
          step: idx + 1,
          actionType: e.actionType,
          targetPattern: generalizeTarget(e.target),
          timeWindow: idx > 0
            ? new Date(e.timestamp).getTime() - new Date(window[idx - 1].timestamp).getTime()
            : undefined,
        }));

        ngramCounts.set(signature, {
          count: 1,
          steps,
          sessionIds: new Set([window[0].sessionId]),
          agentIds: new Set(agentId ? [agentId] : []),
        });
      }
    }
  }

  // Filter by minimum occurrences and convert to patterns
  const patterns: HuntPattern[] = [];
  let idx = 0;

  for (const [, data] of ngramCounts) {
    if (data.count < minOccurrences) continue;

    // Skip boring patterns (all same action type, common targets)
    const actionTypes = new Set(data.steps.map((s) => s.actionType));
    if (actionTypes.size === 1 && data.steps[0].targetPattern === "*") continue;

    patterns.push({
      id: `pattern-${++idx}`,
      name: generatePatternName(data.steps),
      description: `Recurring sequence observed ${data.count} times across ${data.sessionIds.size} sessions`,
      discoveredAt: new Date().toISOString(),
      status: "draft",
      sequence: data.steps,
      matchCount: data.count,
      exampleSessionIds: Array.from(data.sessionIds).slice(0, 5),
      agentIds: Array.from(data.agentIds),
    });
  }

  return patterns.sort((a, b) => b.matchCount - a.matchCount);
}


/** Simple glob matching (supports * and **) */
function matchGlob(value: string, pattern: string): boolean {
  if (pattern === "*") return true;
  const regex = new RegExp(
    "^" +
      pattern
        .replace(/[.+^${}()|[\]\\]/g, "\\$&")
        .replace(/\*\*/g, "⦿")
        .replace(/\*/g, "[^/]*")
        .replace(/⦿/g, ".*") +
      "$",
  );
  return regex.test(value);
}

/** Generalize a target to a pattern (e.g., /home/user/.ssh/id_rsa → ~/.ssh/*) */
function generalizeTarget(target: string): string {
  if (!target) return "*";
  // File paths: keep directory, wildcard filename
  if (target.startsWith("/") || target.startsWith("~")) {
    const parts = target.split("/");
    if (parts.length > 2) {
      return parts.slice(0, -1).join("/") + "/*";
    }
    return target;
  }
  // Network targets: keep hostname, wildcard port
  if (target.includes(":")) {
    const [host] = target.split(":");
    return `${host}:*`;
  }
  return target;
}

/** Generate a human-readable name for a pattern from its steps */
function generatePatternName(steps: PatternStep[]): string {
  const actionLabels: Record<string, string> = {
    file_access: "File Read",
    file_write: "File Write",
    network_egress: "Network",
    shell_command: "Shell",
    mcp_tool_call: "MCP Tool",
    patch_apply: "Patch",
    user_input: "Input",
  };

  const names = steps.map((s) => actionLabels[s.actionType] ?? s.actionType);
  return names.join(" → ") + " Chain";
}


/**
 * Detect clusters of anomalous events in the same session.
 * Returns session IDs with 3+ flagged events.
 */
export function detectAnomalyClusters(
  events: AgentEvent[],
  minEvents: number = 3,
  minScore: number = 0.7,
): Map<string, AgentEvent[]> {
  const sessionAnomalies = new Map<string, AgentEvent[]>();

  for (const e of events) {
    if ((e.anomalyScore ?? 0) < minScore) continue;
    const key = `${e.agentId}:${e.sessionId}`;
    const existing = sessionAnomalies.get(key);
    if (existing) {
      existing.push(e);
    } else {
      sessionAnomalies.set(key, [e]);
    }
  }

  // Filter to clusters meeting minimum threshold
  for (const [key, clusterEvents] of sessionAnomalies) {
    if (clusterEvents.length < minEvents) {
      sessionAnomalies.delete(key);
    }
  }

  return sessionAnomalies;
}


export function timeRangeToSince(range: "1h" | "6h" | "24h" | "7d"): string {
  const now = Date.now();
  const ms: Record<string, number> = {
    "1h": 60 * 60 * 1000,
    "6h": 6 * 60 * 60 * 1000,
    "24h": 24 * 60 * 60 * 1000,
    "7d": 7 * 24 * 60 * 60 * 1000,
  };
  return new Date(now - (ms[range] ?? ms["24h"])).toISOString();
}
