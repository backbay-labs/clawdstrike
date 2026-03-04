import { useMemo } from "react";
import type { SSEEvent } from "./useSSE";

export interface SessionInfo {
  sessionId: string;
  events: SSEEvent[];
  startTime: string;
  endTime: string;
  violationCount: number;
}

export interface RuntimeAgentInfo {
  runtimeAgentId: string;
  runtimeAgentKind: string;
  endpointAgentId: string;
  sessions: SessionInfo[];
  totalActions: number;
  violationCount: number;
  activeSessionCount: number;
  lastEvent: string;
  posture: "nominal" | "elevated" | "critical";
}

export interface EndpointAgentInfo {
  endpointAgentId: string;
  runtimeAgents: RuntimeAgentInfo[];
  desktopSessions: SessionInfo[];
  totalActions: number;
  violationCount: number;
  activeSessionCount: number;
  lastEvent: string;
  posture: "nominal" | "elevated" | "critical";
  unattributedRuntimeEvents: number;
}

type SessionBuckets = Map<string, SSEEvent[]>;

const UNKNOWN_ENDPOINT_ID = "desktop:unattributed";

function normalizeRuntimeKind(event: SSEEvent): string {
  if (event.runtime_agent_kind?.trim()) {
    return event.runtime_agent_kind.trim().toLowerCase();
  }
  if (event.action_type === "mcp_tool") {
    if (event.target?.startsWith("openclaw.")) return "openclaw";
    return "mcp";
  }
  return "unknown";
}

function toPosture(violations: number): "nominal" | "elevated" | "critical" {
  if (violations === 0) return "nominal";
  if (violations <= 3) return "elevated";
  return "critical";
}

function buildSessions(sessionMap: SessionBuckets): {
  sessions: SessionInfo[];
  totalActions: number;
  latestTs: string;
  violations: number;
} {
  const sessions: SessionInfo[] = [];
  let totalActions = 0;
  let latestTs = "";
  let violations = 0;

  for (const [sessionId, evts] of sessionMap) {
    const sorted = [...evts].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
    );
    const violationCount = sorted.filter(
      (event) => event.allowed === false || event.event_type === "violation",
    ).length;

    sessions.push({
      sessionId,
      events: sorted,
      startTime: sorted[0].timestamp,
      endTime: sorted[sorted.length - 1].timestamp,
      violationCount,
    });

    totalActions += sorted.length;
    violations += violationCount;
    const last = sorted[sorted.length - 1].timestamp;
    if (!latestTs || last > latestTs) latestTs = last;
  }

  sessions.sort((a, b) => new Date(b.endTime).getTime() - new Date(a.endTime).getTime());

  return { sessions, totalActions, latestTs, violations };
}

export function useAgentSessions(events: SSEEvent[]): EndpointAgentInfo[] {
  return useMemo(() => {
    const endpointMap = new Map<
      string,
      {
        desktopSessions: SessionBuckets;
        runtimeAgents: Map<string, { kind: string; sessions: SessionBuckets }>;
        unattributedRuntimeEvents: number;
      }
    >();

    for (const event of events) {
      const endpointId = event.endpoint_agent_id?.trim() || event.agent_id?.trim() || UNKNOWN_ENDPOINT_ID;
      if (!endpointMap.has(endpointId)) {
        endpointMap.set(endpointId, {
          desktopSessions: new Map(),
          runtimeAgents: new Map(),
          unattributedRuntimeEvents: 0,
        });
      }

      const endpoint = endpointMap.get(endpointId)!;
      const sessionId = event.session_id || "unknown";

      if (event.runtime_agent_id?.trim()) {
        const runtimeId = event.runtime_agent_id.trim();
        const runtimeKind = normalizeRuntimeKind(event);

        if (!endpoint.runtimeAgents.has(runtimeId)) {
          endpoint.runtimeAgents.set(runtimeId, { kind: runtimeKind, sessions: new Map() });
        }

        const runtime = endpoint.runtimeAgents.get(runtimeId)!;
        if (!runtime.sessions.has(sessionId)) runtime.sessions.set(sessionId, []);
        runtime.sessions.get(sessionId)!.push(event);
      } else {
        if (event.action_type === "mcp_tool") {
          endpoint.unattributedRuntimeEvents += 1;
        }
        if (!endpoint.desktopSessions.has(sessionId)) endpoint.desktopSessions.set(sessionId, []);
        endpoint.desktopSessions.get(sessionId)!.push(event);
      }
    }

    const endpoints: EndpointAgentInfo[] = [];

    for (const [endpointAgentId, buckets] of endpointMap) {
      const desktopSummary = buildSessions(buckets.desktopSessions);

      const runtimeAgents: RuntimeAgentInfo[] = [];
      let totalActions = desktopSummary.totalActions;
      let latestTs = desktopSummary.latestTs;
      let violations = desktopSummary.violations;

      for (const [runtimeAgentId, runtimeBucket] of buckets.runtimeAgents) {
        const summary = buildSessions(runtimeBucket.sessions);
        totalActions += summary.totalActions;
        violations += summary.violations;
        if (!latestTs || summary.latestTs > latestTs) {
          latestTs = summary.latestTs;
        }

        runtimeAgents.push({
          runtimeAgentId,
          runtimeAgentKind: runtimeBucket.kind,
          endpointAgentId,
          sessions: summary.sessions,
          totalActions: summary.totalActions,
          violationCount: summary.violations,
          activeSessionCount: summary.sessions.length,
          lastEvent: summary.latestTs,
          posture: toPosture(summary.violations),
        });
      }

      runtimeAgents.sort((a, b) => new Date(b.lastEvent).getTime() - new Date(a.lastEvent).getTime());

      endpoints.push({
        endpointAgentId,
        runtimeAgents,
        desktopSessions: desktopSummary.sessions,
        totalActions,
        violationCount: violations,
        activeSessionCount:
          desktopSummary.sessions.length +
          runtimeAgents.reduce((sum, runtime) => sum + runtime.activeSessionCount, 0),
        lastEvent: latestTs,
        posture: toPosture(violations),
        unattributedRuntimeEvents: buckets.unattributedRuntimeEvents,
      });
    }

    return endpoints.sort((a, b) => new Date(b.lastEvent).getTime() - new Date(a.lastEvent).getTime());
  }, [events]);
}
