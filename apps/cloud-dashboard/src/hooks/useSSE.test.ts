import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { useSSE } from "./useSSE";

class MockEventSource {
  static instances: MockEventSource[] = [];

  url: string;
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onmessage: ((e: { data: string }) => void) | null = null;
  readyState = 0;
  private listeners: Record<string, ((e: { data: string }) => void)[]> = {};

  constructor(url: string) {
    this.url = url;
    MockEventSource.instances.push(this);
  }

  addEventListener(event: string, handler: (e: { data: string }) => void) {
    if (!this.listeners[event]) this.listeners[event] = [];
    this.listeners[event].push(handler);
  }

  removeEventListener() {}

  dispatchEvent(event: string, data: string) {
    const handlers = this.listeners[event] || [];
    for (const handler of handlers) {
      handler({ data });
    }
  }

  close() {
    this.readyState = 2;
  }

  simulateOpen() {
    this.readyState = 1;
    this.onopen?.();
  }

  simulateError() {
    this.onerror?.();
  }

  simulateMessage(data: string) {
    this.onmessage?.({ data });
  }
}

beforeEach(() => {
  MockEventSource.instances = [];
  vi.stubGlobal("EventSource", MockEventSource);
  localStorage.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("useSSE", () => {
  it("starts in connecting state", () => {
    const { result } = renderHook(() => useSSE("/api/v1/events"));
    expect(result.current.status).toBe("connecting");
    expect(result.current.connected).toBe(false);
  });

  it("transitions to connected on open", () => {
    const { result } = renderHook(() => useSSE("/api/v1/events"));
    const es = MockEventSource.instances[0];

    act(() => {
      es.simulateOpen();
    });

    expect(result.current.status).toBe("connected");
    expect(result.current.connected).toBe(true);
  });

  it("transitions to network_error on error", () => {
    const { result } = renderHook(() => useSSE("/api/v1/events"));
    const es = MockEventSource.instances[0];

    act(() => {
      es.simulateOpen();
    });

    act(() => {
      es.simulateError();
    });

    expect(result.current.status).toBe("network_error");
    expect(result.current.connected).toBe(false);
  });

  it("accumulates events from named event listeners", () => {
    const { result } = renderHook(() => useSSE("/api/v1/events"));
    const es = MockEventSource.instances[0];

    act(() => {
      es.simulateOpen();
    });

    act(() => {
      es.dispatchEvent("check", JSON.stringify({
        action_type: "file_access",
        target: "/tmp/test",
        allowed: true,
        timestamp: "2024-01-01T00:00:00Z",
      }));
    });

    expect(result.current.events).toHaveLength(1);
    expect(result.current.events[0].event_type).toBe("check");
    expect(result.current.events[0].target).toBe("/tmp/test");
    expect(result.current.events[0]._id).toBeGreaterThan(0);
  });

  it("filters ping messages", () => {
    const { result } = renderHook(() => useSSE("/api/v1/events"));
    const es = MockEventSource.instances[0];

    act(() => {
      es.simulateOpen();
    });

    act(() => {
      es.simulateMessage('"ping"');
    });

    expect(result.current.events).toHaveLength(0);
  });

  it("cleans up EventSource on unmount", () => {
    const { unmount } = renderHook(() => useSSE("/api/v1/events"));
    const es = MockEventSource.instances[0];

    unmount();

    expect(es.readyState).toBe(2);
  });

  it("reconnects when reconnect is called", () => {
    const { result } = renderHook(() => useSSE("/api/v1/events"));

    expect(MockEventSource.instances).toHaveLength(1);

    act(() => {
      result.current.reconnect();
    });

    expect(MockEventSource.instances).toHaveLength(2);
    expect(MockEventSource.instances[0].readyState).toBe(2);
  });
});
