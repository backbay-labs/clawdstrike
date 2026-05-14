import { describe, it, expect } from "vitest";
import type { AgentInfo } from "@/features/fleet/fleet-client";
import {
  mergeHeartbeat,
  reduceFleetEvent,
  type FleetEvent,
  type HeartbeatEventData,
} from "@/features/fleet/fleet-event-reducer";

function makeAgent(overrides: Partial<AgentInfo> = {}): AgentInfo {
  return {
    endpoint_agent_id: "agent-1",
    last_heartbeat_at: "2026-03-19T10:00:00Z",
    online: true,
    drift: { policy_drift: false, daemon_drift: false, stale: false },
    posture: "default",
    policy_version: "sha256:aaa",
    daemon_version: "0.2.6",
    seconds_since_heartbeat: 30,
    ...overrides,
  };
}

function makeHeartbeat(overrides: Partial<HeartbeatEventData> = {}): HeartbeatEventData {
  return {
    endpoint_agent_id: "agent-1",
    timestamp: "2026-03-19T10:05:00Z",
    posture: "strict",
    policy_version: "sha256:bbb",
    daemon_version: "0.2.7",
    ...overrides,
  };
}

describe("mergeHeartbeat", () => {
  it("updates an existing agent's fields when a matching heartbeat arrives", () => {
    const agents = [makeAgent()];
    const heartbeat = makeHeartbeat();
    const result = mergeHeartbeat(agents, heartbeat);

    expect(result).toHaveLength(1);
    const updated = result[0];
    expect(updated.posture).toBe("strict");
    expect(updated.policy_version).toBe("sha256:bbb");
    expect(updated.daemon_version).toBe("0.2.7");
    expect(updated.last_heartbeat_at).toBe("2026-03-19T10:05:00Z");
    expect(updated.seconds_since_heartbeat).toBe(0);
    expect(updated.online).toBe(true);
  });

  it("appends a new agent when endpoint_agent_id is unknown", () => {
    const agents = [makeAgent()];
    const heartbeat = makeHeartbeat({ endpoint_agent_id: "agent-new" });
    const result = mergeHeartbeat(agents, heartbeat);

    expect(result).toHaveLength(2);
    expect(result[1].endpoint_agent_id).toBe("agent-new");
    expect(result[1].online).toBe(true);
    expect(result[1].seconds_since_heartbeat).toBe(0);
    expect(result[1].posture).toBe("strict");
  });

  it("does not mutate the original agents array", () => {
    const agents = [makeAgent()];
    const original = [...agents];
    mergeHeartbeat(agents, makeHeartbeat());
    expect(agents).toEqual(original);
  });
});

describe("reduceFleetEvent", () => {
  it("agent_heartbeat event returns updated agents array with merged heartbeat", () => {
    const agents = [makeAgent()];
    const event: FleetEvent = {
      type: "agent_heartbeat",
      data: makeHeartbeat({ posture: "permissive" }),
    };
    const result = reduceFleetEvent(agents, event);

    expect(result.agents[0].posture).toBe("permissive");
    expect(result.refreshPolicy).toBe(false);
  });

  it("policy_updated event returns refreshPolicy: true", () => {
    const agents = [makeAgent()];
    const event: FleetEvent = {
      type: "policy_updated",
      data: { policy_hash: "sha256:ccc" },
    };
    const result = reduceFleetEvent(agents, event);

    expect(result.refreshPolicy).toBe(true);
    expect(result.agents).toEqual(agents);
  });

  it("policy_reloaded event returns refreshPolicy: true", () => {
    const agents = [makeAgent()];
    const event: FleetEvent = {
      type: "policy_reloaded",
      data: { before_hash: "sha256:aaa", after_hash: "sha256:bbb" },
    };
    const result = reduceFleetEvent(agents, event);

    expect(result.refreshPolicy).toBe(true);
    expect(result.agents).toEqual(agents);
  });

  it("unknown_type event returns agents unchanged (no-op)", () => {
    const agents = [makeAgent()];
    const event: FleetEvent = {
      type: "unknown_type" as any,
      data: {},
    };
    const result = reduceFleetEvent(agents, event);

    expect(result.agents).toEqual(agents);
    expect(result.refreshPolicy).toBe(false);
  });
});
