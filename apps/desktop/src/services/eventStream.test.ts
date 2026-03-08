import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { EventStream } from "./eventStream";

describe("EventStream", () => {
  it("ignores empty and undefined payloads", () => {
    const onEvent = vi.fn();
    const stream = new EventStream("http://example.test", { onEvent });
    (
      stream as unknown as { emitIncomingEvent: (eventType: string, payload: string) => void }
    ).emitIncomingEvent("check", "");
    (
      stream as unknown as { emitIncomingEvent: (eventType: string, payload: string) => void }
    ).emitIncomingEvent("check", "undefined");
    expect(onEvent).not.toHaveBeenCalled();
  });

  it("passes through canonical daemon events", () => {
    const onEvent = vi.fn();
    const stream = new EventStream("http://example.test", { onEvent });
    const payload = JSON.stringify({
      type: "check",
      timestamp: "2025-01-01T00:00:00.000Z",
      data: { ok: true },
    });

    (
      stream as unknown as { emitIncomingEvent: (eventType: string, payload: string) => void }
    ).emitIncomingEvent("check", payload);

    expect(onEvent).toHaveBeenCalledWith({
      type: "check",
      timestamp: "2025-01-01T00:00:00.000Z",
      data: { ok: true },
    });
  });

  it("wraps non-canonical JSON payloads as daemon events", () => {
    const onEvent = vi.fn();
    const stream = new EventStream("http://example.test", { onEvent });
    const payload = JSON.stringify({ hello: "world" });

    (
      stream as unknown as { emitIncomingEvent: (eventType: string, payload: string) => void }
    ).emitIncomingEvent("policy_updated", payload);

    const event = onEvent.mock.calls[0]?.[0] as
      | { type: string; timestamp: string; data: unknown }
      | undefined;
    expect(event?.type).toBe("policy_updated");
    expect(event?.data).toEqual({ hello: "world" });
    expect(Number.isNaN(Date.parse(String(event?.timestamp)))).toBe(false);
  });

  it("wraps JSON primitives as string messages", () => {
    const onEvent = vi.fn();
    const stream = new EventStream("http://example.test", { onEvent });

    (
      stream as unknown as { emitIncomingEvent: (eventType: string, payload: string) => void }
    ).emitIncomingEvent("message", "123");

    const event = onEvent.mock.calls[0]?.[0] as
      | { type: string; data: { message: string } }
      | undefined;
    expect(event?.type).toBe("message");
    expect(event?.data).toEqual({ message: "123" });
  });

  it("preserves non-JSON payloads as string messages", () => {
    const onEvent = vi.fn();
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const stream = new EventStream("http://example.test", { onEvent });

    (
      stream as unknown as { emitIncomingEvent: (eventType: string, payload: string) => void }
    ).emitIncomingEvent("error", "plain text");

    expect(onEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "error",
        data: { message: "plain text" },
      }),
    );
    expect(warnSpy).toHaveBeenCalled();

    warnSpy.mockRestore();
  });

  describe("reconnect + cleanup", () => {
    type MessageEventLike = { data: string };

    class MockEventSource {
      static instances: MockEventSource[] = [];
      static CONNECTING = 0;
      static OPEN = 1;
      static CLOSED = 2;

      onopen: (() => void) | null = null;
      onmessage: ((ev: MessageEventLike) => void) | null = null;
      onerror: (() => void) | null = null;

      readyState = MockEventSource.CONNECTING;

      private listeners = new Map<string, Array<(ev: MessageEventLike) => void>>();

      constructor(readonly url: string) {
        MockEventSource.instances.push(this);
      }

      addEventListener(type: string, handler: (ev: unknown) => void) {
        const list = this.listeners.get(type) ?? [];
        list.push(handler as (ev: MessageEventLike) => void);
        this.listeners.set(type, list);
      }

      close() {
        this.readyState = MockEventSource.CLOSED;
      }

      emitOpen() {
        this.readyState = MockEventSource.OPEN;
        this.onopen?.();
      }

      emitError() {
        this.onerror?.();
      }

      emitMessage(data: string) {
        this.onmessage?.({ data });
      }

      emitNamed(type: string, data: string) {
        for (const handler of this.listeners.get(type) ?? []) handler({ data });
      }
    }

    const originalEventSource = globalThis.EventSource;

    beforeEach(() => {
      MockEventSource.instances = [];
      vi.useFakeTimers();
      Object.defineProperty(globalThis, "EventSource", {
        value: MockEventSource,
        configurable: true,
      });
    });

    afterEach(() => {
      vi.useRealTimers();
      Object.defineProperty(globalThis, "EventSource", {
        value: originalEventSource,
        configurable: true,
      });
    });

    it("dispatches named events via addEventListener", () => {
      const onEvent = vi.fn();
      const stream = new EventStream("http://example.test", { onEvent });

      stream.connect();
      expect(MockEventSource.instances).toHaveLength(1);

      const es = MockEventSource.instances[0]!;
      es.emitOpen();

      es.emitNamed(
        "check",
        JSON.stringify({
          type: "check",
          timestamp: "2025-01-01T00:00:00.000Z",
          data: { ok: true },
        }),
      );

      es.emitNamed("policy_updated", JSON.stringify({ hello: "world" }));

      expect(onEvent).toHaveBeenCalledWith({
        type: "check",
        timestamp: "2025-01-01T00:00:00.000Z",
        data: { ok: true },
      });

      const wrapped = onEvent.mock.calls[1]?.[0] as {
        type?: string;
        timestamp?: string;
        data?: unknown;
      };
      expect(wrapped.type).toBe("policy_updated");
      expect(wrapped.data).toEqual({ hello: "world" });
      expect(Number.isNaN(Date.parse(String(wrapped.timestamp)))).toBe(false);
    });

    it("reconnects with backoff and stops after max attempts", () => {
      const onEvent = vi.fn();
      const onDisconnect = vi.fn();
      const onError = vi.fn();
      const stream = new EventStream("http://example.test", {
        onEvent,
        onDisconnect,
        onError,
        reconnectDelay: 100,
        maxReconnectAttempts: 2,
      });

      stream.connect();
      expect(MockEventSource.instances).toHaveLength(1);

      MockEventSource.instances[0]!.emitError();
      expect(onDisconnect).toHaveBeenCalledTimes(1);

      vi.advanceTimersByTime(100);
      expect(MockEventSource.instances).toHaveLength(2);

      MockEventSource.instances[1]!.emitError();
      expect(onDisconnect).toHaveBeenCalledTimes(2);

      vi.advanceTimersByTime(150);
      expect(MockEventSource.instances).toHaveLength(3);

      MockEventSource.instances[2]!.emitError();
      expect(onDisconnect).toHaveBeenCalledTimes(3);
      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({ message: "Max reconnection attempts reached" }),
      );

      vi.advanceTimersByTime(1000);
      expect(MockEventSource.instances).toHaveLength(3);
    });

    it("cancels pending reconnect timers when manually disconnected", () => {
      const onEvent = vi.fn();
      const onDisconnect = vi.fn();
      const stream = new EventStream("http://example.test", {
        onEvent,
        onDisconnect,
        reconnectDelay: 100,
        maxReconnectAttempts: 2,
      });

      stream.connect();
      expect(MockEventSource.instances).toHaveLength(1);

      MockEventSource.instances[0]!.emitError();
      stream.disconnect();

      vi.advanceTimersByTime(1000);
      expect(MockEventSource.instances).toHaveLength(1);
      expect(onDisconnect).toHaveBeenCalled();
    });
  });
});
