import { useMemo } from "react";
import type { SSEEvent } from "./useSSE";

export interface SessionInfo {
  sessionId: string;
  events: SSEEvent[];
  startTime: string;
  endTime: string;
}

export interface AgentInfo {
  agentId: string;
  sessions: SessionInfo[];
  totalActions: number;
  lastEvent: string;
  posture: "nominal" | "elevated" | "critical";
}

export function useAgentSessions(events: SSEEvent[]): AgentInfo[] {
  return useMemo(() => {
    const agentMap = new Map<string, Map<string, SSEEvent[]>>();

    for (const e of events) {
      if (!e.agent_id) continue;
      if (!agentMap.has(e.agent_id)) agentMap.set(e.agent_id, new Map());
      const sessions = agentMap.get(e.agent_id)!;
      const sid = e.session_id || "unknown";
      if (!sessions.has(sid)) sessions.set(sid, []);
      sessions.get(sid)!.push(e);
    }

    const agents: AgentInfo[] = [];
    for (const [agentId, sessionMap] of agentMap) {
      const sessions: SessionInfo[] = [];
      let totalActions = 0;
      let latestTs = "";
      let violations = 0;

      for (const [sessionId, evts] of sessionMap) {
        const sorted = [...evts].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
        sessions.push({
          sessionId,
          events: sorted,
          startTime: sorted[0].timestamp,
          endTime: sorted[sorted.length - 1].timestamp,
        });
        totalActions += sorted.length;
        violations += sorted.filter((e) => e.allowed === false || e.event_type === "violation").length;
        const last = sorted[sorted.length - 1].timestamp;
        if (!latestTs || last > latestTs) latestTs = last;
      }

      const posture = violations === 0 ? "nominal" : violations <= 3 ? "elevated" : "critical";
      agents.push({ agentId, sessions, totalActions, lastEvent: latestTs, posture });
    }

    return agents.sort((a, b) => new Date(b.lastEvent).getTime() - new Date(a.lastEvent).getTime());
  }, [events]);
}
