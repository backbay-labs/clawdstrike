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

  it("groups runtime agents under endpoint agents", () => {
    const events = [
      makeEvent({ _id: 1, agent_id: "desktop-1", session_id: "s1", runtime_agent_id: "claude-a" }),
      makeEvent({ _id: 2, agent_id: "desktop-1", session_id: "s1", runtime_agent_id: "claude-a" }),
      makeEvent({ _id: 3, agent_id: "desktop-1", session_id: "s2", runtime_agent_id: "openclaw-gw-1" }),
    ];

    const { result } = renderHook(() => useAgentSessions(events));
    expect(result.current).toHaveLength(1);
    expect(result.current[0].endpointAgentId).toBe("desktop-1");
    expect(result.current[0].runtimeAgents).toHaveLength(2);
    expect(result.current[0].desktopSessions).toHaveLength(0);
  });

  it("keeps non-runtime events in desktop session buckets", () => {
    const events = [
      makeEvent({ _id: 1, agent_id: "desktop-1", session_id: "s1", action_type: "file_access" }),
      makeEvent({ _id: 2, agent_id: "desktop-1", session_id: "s1", action_type: "shell" }),
    ];

    const { result } = renderHook(() => useAgentSessions(events));
    expect(result.current).toHaveLength(1);
    expect(result.current[0].runtimeAgents).toHaveLength(0);
    expect(result.current[0].desktopSessions).toHaveLength(1);
    expect(result.current[0].desktopSessions[0].events).toHaveLength(2);
  });

  it("tracks unattributed runtime events", () => {
    const events = [
      makeEvent({
        _id: 1,
        agent_id: "desktop-1",
        session_id: "s1",
        action_type: "mcp_tool",
        runtime_agent_id: undefined,
      }),
    ];

    const { result } = renderHook(() => useAgentSessions(events));
    expect(result.current[0].unattributedRuntimeEvents).toBe(1);
  });

  it("falls back to unattributed endpoint id", () => {
    const events = [makeEvent({ _id: 1, agent_id: undefined, session_id: "s1" })];
    const { result } = renderHook(() => useAgentSessions(events));
    expect(result.current).toHaveLength(1);
    expect(result.current[0].endpointAgentId).toBe("desktop:unattributed");
  });

  it("computes endpoint posture from violations", () => {
    const events = Array.from({ length: 5 }, (_, index) =>
      makeEvent({
        _id: index,
        agent_id: "desktop-1",
        session_id: "s1",
        allowed: false,
      }),
    );

    const { result } = renderHook(() => useAgentSessions(events));
    expect(result.current[0].posture).toBe("critical");
  });
});
