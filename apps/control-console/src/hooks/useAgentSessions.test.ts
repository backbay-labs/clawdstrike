import { renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { useAgentSessions } from "./useAgentSessions";
import type { SSEEvent } from "./useSSE";

function makeEvent(overrides: Partial<SSEEvent> = {}): SSEEvent {
  return {
    _id: 1,
    event_type: "check",
    timestamp: new Date().toISOString(),
    allowed: true,
    ...overrides,
  } as SSEEvent;
}

describe("useAgentSessions", () => {
  it("returns empty array for no events", () => {
    const { result } = renderHook(() => useAgentSessions([]));
    expect(result.current).toEqual([]);
  });

  it("groups events by agent_id", () => {
    const events = [
      makeEvent({ agent_id: "agent-1", session_id: "s1" }),
      makeEvent({ agent_id: "agent-1", session_id: "s1" }),
      makeEvent({ agent_id: "agent-2", session_id: "s2" }),
    ];
    const { result } = renderHook(() => useAgentSessions(events));
    expect(result.current).toHaveLength(2);
    expect(result.current.find((a) => a.agentId === "agent-1")?.totalActions).toBe(2);
    expect(result.current.find((a) => a.agentId === "agent-2")?.totalActions).toBe(1);
  });

  it("counts sessions per agent", () => {
    const events = [
      makeEvent({ agent_id: "agent-1", session_id: "s1" }),
      makeEvent({ agent_id: "agent-1", session_id: "s2" }),
    ];
    const { result } = renderHook(() => useAgentSessions(events));
    const agent = result.current.find((a) => a.agentId === "agent-1");
    expect(agent?.sessions).toHaveLength(2);
  });

  it("computes posture based on violations", () => {
    const events = [makeEvent({ agent_id: "a1", session_id: "s1", allowed: true })];
    const { result } = renderHook(() => useAgentSessions(events));
    expect(result.current[0].posture).toBe("nominal");
  });

  it("marks agent as critical with many violations", () => {
    const events = Array.from({ length: 5 }, (_, i) =>
      makeEvent({ _id: i, agent_id: "a1", session_id: "s1", allowed: false }),
    );
    const { result } = renderHook(() => useAgentSessions(events));
    expect(result.current[0].posture).toBe("critical");
  });

  it("skips events without agent_id", () => {
    const events = [makeEvent({ agent_id: undefined, session_id: "s1" })];
    const { result } = renderHook(() => useAgentSessions(events));
    expect(result.current).toHaveLength(0);
  });
});
