import { renderHook } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { APP_VERSION, useConsoleStatus } from "./useConsoleStatus";
import type { SSEEvent } from "./useSSE";

function makeEvent(overrides: Partial<SSEEvent> & { timestamp: string }): SSEEvent {
  return {
    _id: 1,
    event_type: "check",
    allowed: true,
    ...overrides,
  };
}

describe("useConsoleStatus", () => {
  it("APP_VERSION equals the package.json version", () => {
    expect(APP_VERSION).toBe("0.2.0");
  });

  it("build equals APP_VERSION", () => {
    const { result } = renderHook(() => useConsoleStatus([], false));
    expect(result.current.build).toBe(APP_VERSION);
  });

  it("sseLive reflects connected=true", () => {
    const { result } = renderHook(() => useConsoleStatus([], true));
    expect(result.current.sseLive).toBe(true);
  });

  it("sseLive reflects connected=false", () => {
    const { result } = renderHook(() => useConsoleStatus([], false));
    expect(result.current.sseLive).toBe(false);
  });

  it("violations is 0 with no events", () => {
    const { result } = renderHook(() => useConsoleStatus([], true));
    expect(result.current.violations).toBe(0);
  });

  it("counts events where allowed === false as violations", () => {
    const events = [
      makeEvent({ timestamp: "2026-01-01T00:00:00Z", allowed: false }),
      makeEvent({ timestamp: "2026-01-01T00:01:00Z", allowed: true }),
      makeEvent({ timestamp: "2026-01-01T00:02:00Z", allowed: false }),
    ];
    const { result } = renderHook(() => useConsoleStatus(events, true));
    expect(result.current.violations).toBe(2);
  });

  it("counts events where event_type === 'violation' as violations", () => {
    const events = [
      makeEvent({ timestamp: "2026-01-01T00:00:00Z", event_type: "violation", allowed: true }),
      makeEvent({ timestamp: "2026-01-01T00:01:00Z", event_type: "check", allowed: true }),
    ];
    const { result } = renderHook(() => useConsoleStatus(events, true));
    expect(result.current.violations).toBe(1);
  });

  it("does not double-count an event that is both allowed===false and event_type==='violation'", () => {
    const events = [
      makeEvent({
        timestamp: "2026-01-01T00:00:00Z",
        event_type: "violation",
        allowed: false,
      }),
    ];
    const { result } = renderHook(() => useConsoleStatus(events, true));
    // The filter is OR logic: allowed===false || event_type==="violation"
    // Each event counts once — this one matches both conditions but is one event.
    expect(result.current.violations).toBe(1);
  });

  it("uptime is 00:00:00 with no events", () => {
    const { result } = renderHook(() => useConsoleStatus([], true));
    expect(result.current.uptime).toBe("00:00:00");
  });

  it("uptime is derived from the oldest event (last in array, since newest-first)", () => {
    // useSSE prepends events: newest-first, so oldest is events[events.length - 1]
    const now = Date.now();
    const oldestTs = new Date(now - 90 * 1000).toISOString(); // 1m30s ago
    const newerTs = new Date(now - 10 * 1000).toISOString();

    const events = [
      makeEvent({ timestamp: newerTs, _id: 2 }),
      makeEvent({ timestamp: oldestTs, _id: 1 }),
    ];
    const { result } = renderHook(() => useConsoleStatus(events, true));
    // Uptime is computed from oldestTs; with 90s elapsed it should be "00:01:30" ± clock skew
    // We only assert format and rough magnitude
    expect(result.current.uptime).toMatch(/^\d{2}:\d{2}:\d{2}$/);
    const [h, m, s] = result.current.uptime.split(":").map(Number);
    const totalSeconds = h * 3600 + m * 60 + s;
    expect(totalSeconds).toBeGreaterThanOrEqual(85);
    expect(totalSeconds).toBeLessThan(200);
  });
});
