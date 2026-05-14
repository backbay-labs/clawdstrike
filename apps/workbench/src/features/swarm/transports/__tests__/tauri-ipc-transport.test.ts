/**
 * Unit tests for TauriIpcTransport.
 *
 * Mocks Tauri APIs (listen, invoke) and window.__TAURI_INTERNALS__ to test all
 * TransportAdapter behaviors without a real Tauri runtime.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { SwarmEnvelope } from "@/features/swarm/swarm-coordinator";

// ---------------------------------------------------------------------------
// Tauri API mocks
// ---------------------------------------------------------------------------

const mockUnlisten = vi.fn();
type ListenCallback = (event: { payload: SwarmEnvelope }) => void;

const mockListen = vi.fn(
  (_topic: string, _handler: ListenCallback) => Promise.resolve(mockUnlisten),
);

const mockInvoke = vi.fn(
  (_command: string, _payload?: Record<string, unknown>) => Promise.resolve(),
);

vi.mock("@tauri-apps/api/event", () => ({
  listen: (...args: unknown[]) => mockListen(...(args as Parameters<typeof mockListen>)),
}));

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...(args as Parameters<typeof mockInvoke>)),
}));

// ---------------------------------------------------------------------------
// Import after mocks
// ---------------------------------------------------------------------------
import { TauriIpcTransport } from "../tauri-ipc-transport";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEnvelope(
  type: SwarmEnvelope["type"] = "intel",
): SwarmEnvelope {
  return {
    version: 1,
    type,
    payload: { foo: "bar" },
    ttl: 5,
    created: Date.now(),
  };
}

function getListenCallback(index: number): ListenCallback {
  const callback = mockListen.mock.calls[index]?.[1];
  expect(callback).toBeDefined();
  if (!callback) {
    throw new Error(`Missing listen callback at index ${index}`);
  }
  return callback;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("TauriIpcTransport", () => {
  let transport: TauriIpcTransport;

  beforeEach(() => {
    vi.clearAllMocks();
    transport = new TauriIpcTransport();
  });

  afterEach(() => {
    // Clean up __TAURI_INTERNALS__ between tests
    if ("__TAURI_INTERNALS__" in window) {
      delete (window as Record<string, unknown>).__TAURI_INTERNALS__;
    }
  });

  // -----------------------------------------------------------------------
  // isConnected
  // -----------------------------------------------------------------------
  describe("isConnected", () => {
    it("returns false when window.__TAURI_INTERNALS__ is not present", () => {
      expect(transport.isConnected()).toBe(false);
    });

    it("returns true when window.__TAURI_INTERNALS__ is present", () => {
      Object.defineProperty(window, "__TAURI_INTERNALS__", {
        value: {},
        writable: true,
        configurable: true,
      });
      expect(transport.isConnected()).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // subscribe / unsubscribe
  // -----------------------------------------------------------------------
  describe("subscribe/unsubscribe", () => {
    it("subscribe calls Tauri listen with the topic", async () => {
      transport.subscribe("swarm/intel");

      // listen is called asynchronously during subscribe
      await vi.waitFor(() => {
        expect(mockListen).toHaveBeenCalledWith(
          "swarm/intel",
          expect.any(Function),
        );
      });
    });

    it("subscribe is idempotent -- calling twice does not double-register", async () => {
      transport.subscribe("swarm/intel");
      transport.subscribe("swarm/intel");

      // Wait for any pending promises
      await new Promise((r) => setTimeout(r, 0));

      expect(mockListen).toHaveBeenCalledTimes(1);
    });

    it("unsubscribe calls the unlisten function returned by listen", async () => {
      transport.subscribe("swarm/intel");
      // Wait for listen promise to resolve
      await new Promise((r) => setTimeout(r, 0));

      transport.unsubscribe("swarm/intel");
      // Wait for unlisten promise chain to resolve
      await new Promise((r) => setTimeout(r, 0));

      expect(mockUnlisten).toHaveBeenCalledTimes(1);
    });

    it("rolls back the subscription marker when listen rejects so callers can retry", async () => {
      mockListen
        .mockRejectedValueOnce(new Error("listen failed"))
        .mockResolvedValueOnce(mockUnlisten);

      transport.subscribe("swarm/intel");
      await new Promise((r) => setTimeout(r, 0));

      transport.subscribe("swarm/intel");
      await new Promise((r) => setTimeout(r, 0));

      expect(mockListen).toHaveBeenCalledTimes(2);
    });

    it("unsubscribe on an unsubscribed topic is a no-op", () => {
      // Should not throw
      expect(() => transport.unsubscribe("nonexistent")).not.toThrow();
      expect(mockUnlisten).not.toHaveBeenCalled();
    });
  });

  // -----------------------------------------------------------------------
  // publish
  // -----------------------------------------------------------------------
  describe("publish", () => {
    it("calls Tauri invoke with swarm_publish command", async () => {
      Object.defineProperty(window, "__TAURI_INTERNALS__", {
        value: {},
        writable: true,
        configurable: true,
      });

      const envelope = makeEnvelope();
      await transport.publish("swarm/intel", envelope);

      expect(mockInvoke).toHaveBeenCalledWith("swarm_publish", {
        topic: "swarm/intel",
        envelope,
      });
    });

    it("rejects when isConnected() returns false", async () => {
      const envelope = makeEnvelope();
      await expect(
        transport.publish("swarm/intel", envelope),
      ).rejects.toThrow("TauriIpcTransport: not connected");
    });
  });

  // -----------------------------------------------------------------------
  // message handlers
  // -----------------------------------------------------------------------
  describe("message handlers", () => {
    it("onMessage registers a handler that receives messages", async () => {
      const handler = vi.fn();
      transport.onMessage(handler);
      transport.subscribe("swarm/intel");

      // Wait for listen to be called and get the callback
      await new Promise((r) => setTimeout(r, 0));

      // Simulate an incoming Tauri event by invoking the listen callback
      const listenCallback = getListenCallback(0);

      const envelope = makeEnvelope();
      listenCallback({ payload: envelope });

      expect(handler).toHaveBeenCalledWith("swarm/intel", envelope);
    });

    it("offMessage removes a previously registered handler", async () => {
      const handler = vi.fn();
      transport.onMessage(handler);
      transport.subscribe("swarm/intel");

      await new Promise((r) => setTimeout(r, 0));

      // Remove the handler
      transport.offMessage(handler);

      // Simulate incoming event
      const listenCallback = getListenCallback(0);
      const envelope = makeEnvelope();
      listenCallback({ payload: envelope });

      expect(handler).not.toHaveBeenCalled();
    });

    it("multiple handlers all receive the same incoming message", async () => {
      const handler1 = vi.fn();
      const handler2 = vi.fn();
      transport.onMessage(handler1);
      transport.onMessage(handler2);
      transport.subscribe("swarm/intel");

      await new Promise((r) => setTimeout(r, 0));

      const listenCallback = getListenCallback(0);
      const envelope = makeEnvelope();
      listenCallback({ payload: envelope });

      expect(handler1).toHaveBeenCalledWith("swarm/intel", envelope);
      expect(handler2).toHaveBeenCalledWith("swarm/intel", envelope);
    });

    it("subscribe routes incoming Tauri events to all registered handlers", async () => {
      const handler = vi.fn();
      transport.onMessage(handler);

      // Subscribe to two topics
      transport.subscribe("swarm/intel");
      transport.subscribe("swarm/signals");

      await new Promise((r) => setTimeout(r, 0));

      // Both listen calls should have been made
      expect(mockListen).toHaveBeenCalledTimes(2);

      // Simulate messages on both topics
      const intelCallback = getListenCallback(0);
      const signalCallback = getListenCallback(1);

      const intelEnvelope = makeEnvelope("intel");
      const signalEnvelope = makeEnvelope("signal");

      intelCallback({ payload: intelEnvelope });
      signalCallback({ payload: signalEnvelope });

      expect(handler).toHaveBeenCalledTimes(2);
      expect(handler).toHaveBeenCalledWith("swarm/intel", intelEnvelope);
      expect(handler).toHaveBeenCalledWith("swarm/signals", signalEnvelope);
    });
  });
});
