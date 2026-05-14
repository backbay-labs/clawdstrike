// Fleet Event Reducer -- pure functions to merge SSE events into AgentInfo[] state.
//
// This module processes events from the hushd SSE stream and produces
// updated agent arrays. It has no side effects and no dependency on React
// or Zustand, making it easy to test independently.

import type { AgentInfo } from "@/features/fleet/fleet-client";

// ---- SSE Event Types ----

export interface HeartbeatEventData {
  endpoint_agent_id: string;
  runtime_agent_id?: string;
  runtime_agent_kind?: string;
  session_id?: string;
  posture?: string;
  policy_version?: string;
  daemon_version?: string;
  timestamp: string;
}

export interface CheckEventData {
  action_type: string;
  target: string;
  verdict: string;
  guard?: string;
  session_id?: string;
  agent_id?: string;
  evidence?: unknown;
}

export type FleetEvent =
  | { type: "agent_heartbeat"; data: HeartbeatEventData }
  | { type: "policy_updated" | "policy_reloaded" | "policy_bundle_update"; data: unknown }
  | { type: "check"; data: CheckEventData }
  | { type: string; data: unknown };

export interface ReduceResult {
  agents: AgentInfo[];
  refreshPolicy: boolean;
}

// ---- Reducer functions ----

/**
 * Merge a heartbeat event into the agents array.
 *
 * If an agent with the matching `endpoint_agent_id` exists, its fields are
 * updated from the heartbeat. If no match is found, a new agent entry is
 * appended with sensible defaults.
 *
 * Returns a new array (the original is never mutated).
 */
export function mergeHeartbeat(
  agents: AgentInfo[],
  heartbeat: HeartbeatEventData,
): AgentInfo[] {
  const idx = agents.findIndex(
    (a) => a.endpoint_agent_id === heartbeat.endpoint_agent_id,
  );

  if (idx >= 0) {
    // Update existing agent
    const updated = [...agents];
    updated[idx] = {
      ...updated[idx],
      last_heartbeat_at: heartbeat.timestamp,
      seconds_since_heartbeat: 0,
      online: true,
      ...(heartbeat.posture != null ? { posture: heartbeat.posture } : {}),
      ...(heartbeat.policy_version != null ? { policy_version: heartbeat.policy_version } : {}),
      ...(heartbeat.daemon_version != null ? { daemon_version: heartbeat.daemon_version } : {}),
      ...(heartbeat.session_id != null ? { last_session_id: heartbeat.session_id } : {}),
    };
    return updated;
  }

  // Append new agent with defaults
  const newAgent: AgentInfo = {
    endpoint_agent_id: heartbeat.endpoint_agent_id,
    last_heartbeat_at: heartbeat.timestamp,
    online: true,
    seconds_since_heartbeat: 0,
    posture: heartbeat.posture,
    policy_version: heartbeat.policy_version,
    daemon_version: heartbeat.daemon_version,
    last_session_id: heartbeat.session_id,
    drift: { policy_drift: false, daemon_drift: false, stale: false },
  };
  return [...agents, newAgent];
}

/**
 * Reduce a fleet SSE event into state changes.
 *
 * Returns the (possibly updated) agents array and a flag indicating whether
 * the remote policy info should be re-fetched.
 */
export function reduceFleetEvent(
  agents: AgentInfo[],
  event: FleetEvent,
): ReduceResult {
  switch (event.type) {
    case "agent_heartbeat":
      return {
        agents: mergeHeartbeat(agents, event.data as HeartbeatEventData),
        refreshPolicy: false,
      };

    case "policy_updated":
    case "policy_reloaded":
    case "policy_bundle_update":
      return {
        agents,
        refreshPolicy: true,
      };

    case "check":
      // Check events are informational for the fleet dashboard --
      // they don't change agent state (that comes via heartbeats).
      return { agents, refreshPolicy: false };

    default:
      // Unknown event type -- no-op
      return { agents, refreshPolicy: false };
  }
}
