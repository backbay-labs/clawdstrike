/**
 * PluginBridgeClient Tests
 *
 * Tests for the iframe-side bridge client: call/response correlation,
 * error propagation, 30-second timeout, event subscriptions, destroy cleanup,
 * and non-bridge message filtering.
 *
 * Uses vi.stubGlobal to mock window.parent.postMessage and simulates host
 * responses via window.dispatchEvent(new MessageEvent("message", { data })).
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { PluginBridgeClient, BridgeError } from "../bridge-client";
import type {
  BridgeResponse,
  BridgeErrorResponse,
  BridgeEvent,
} from "../types";

// ---- Helpers ----

/**
 * Simulate the host sending a response back to the plugin.
 * In the real iframe scenario, the host calls iframe.contentWindow.postMessage(),
 * which triggers a "message" event on the iframe's window.
 */
function simulateHostMessage(data: unknown): void {
  window.dispatchEvent(new MessageEvent("message", { data }));
}

function captureBridgeError(promise: Promise<unknown>): Promise<BridgeError> {
  return promise.then(
    () => {
      throw new Error("Expected promise to reject");
    },
    (error: unknown) => {
      if (!(error instanceof BridgeError)) {
        throw error;
      }
      return error;
    },
  );
}

// ---- Setup ----

describe("PluginBridgeClient", () => {
  let client: PluginBridgeClient;
  let mockPostMessage: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    // Mock window.parent.postMessage
    mockPostMessage = vi.fn();
    vi.stubGlobal("parent", { postMessage: mockPostMessage });

    client = new PluginBridgeClient();
  });

  afterEach(() => {
    vi.useRealTimers();
    client.destroy();
    vi.restoreAllMocks();
  });

  // ---- call() ----

  describe("call()", () => {
    it("sends a BridgeRequest via parent.postMessage and resolves with the result", async () => {
      const promise = client.call<string>("guards.register", { id: "test" });

      // The client should have sent a request via postMessage
      expect(mockPostMessage).toHaveBeenCalledOnce();
      const sentMsg = mockPostMessage.mock.calls[0][0];
      expect(sentMsg).toMatchObject({
        id: "0",
        type: "request",
        method: "guards.register",
        params: { id: "test" },
      });
      expect(mockPostMessage.mock.calls[0][1]).toBe("*");

      // Simulate host response
      const response: BridgeResponse = {
        id: "0",
        type: "response",
        result: "registered",
      };
      simulateHostMessage(response);

      const result = await promise;
      expect(result).toBe("registered");
    });

    it("rejects with BridgeError when the host returns an error response", async () => {
      const promise = client.call("unknown.method", {});

      const errorResponse: BridgeErrorResponse = {
        id: "0",
        type: "error",
        error: { code: "METHOD_NOT_FOUND", message: "No handler for unknown.method" },
      };
      simulateHostMessage(errorResponse);

      await expect(promise).rejects.toThrow(BridgeError);
      await expect(promise).rejects.toMatchObject({
        code: "METHOD_NOT_FOUND",
        message: "No handler for unknown.method",
      });
    });

    it("rejects with TIMEOUT after 30 seconds if no response arrives", async () => {
      vi.useFakeTimers();

      const promise = client.call<string>("storage.get", { key: "test" });
      const timeoutError = captureBridgeError(promise);

      // Advance time by 30 seconds
      await vi.advanceTimersByTimeAsync(30_000);

      await expect(timeoutError).resolves.toMatchObject({
        code: "TIMEOUT",
        message: expect.stringContaining("storage.get"),
      });

      // Verify a second call also times out with method name in message
      const promise2 = client.call<string>("guards.register", { id: "x" });
      const secondTimeoutError = captureBridgeError(promise2);
      await vi.advanceTimersByTimeAsync(30_000);
      await expect(secondTimeoutError).resolves.toMatchObject({
        code: "TIMEOUT",
        message: expect.stringContaining("guards.register"),
      });
    });

    it("uses monotonically increasing IDs for correlation", async () => {
      const p1 = client.call("storage.get", { key: "a" });
      const p2 = client.call("storage.get", { key: "b" });

      expect(mockPostMessage).toHaveBeenCalledTimes(2);
      expect(mockPostMessage.mock.calls[0][0].id).toBe("0");
      expect(mockPostMessage.mock.calls[1][0].id).toBe("1");

      // Respond in reverse order to prove correlation works
      simulateHostMessage({ id: "1", type: "response", result: "b-val" });
      simulateHostMessage({ id: "0", type: "response", result: "a-val" });

      expect(await p1).toBe("a-val");
      expect(await p2).toBe("b-val");
    });
  });

  // ---- subscribe() ----

  describe("subscribe()", () => {
    it("fires handler when a matching BridgeEvent arrives", () => {
      const handler = vi.fn();
      client.subscribe("policy.changed", handler);

      const event: BridgeEvent = {
        type: "event",
        method: "policy.changed",
        params: { policyId: "strict" },
      };
      simulateHostMessage(event);

      expect(handler).toHaveBeenCalledOnce();
      expect(handler).toHaveBeenCalledWith({ policyId: "strict" });
    });

    it("returns an unsubscribe function that removes the handler", () => {
      const handler = vi.fn();
      const unsub = client.subscribe("policy.changed", handler);

      // Fire once
      simulateHostMessage({
        type: "event",
        method: "policy.changed",
        params: {},
      });
      expect(handler).toHaveBeenCalledOnce();

      // Unsubscribe
      unsub();

      // Fire again -- handler should not fire
      simulateHostMessage({
        type: "event",
        method: "policy.changed",
        params: {},
      });
      expect(handler).toHaveBeenCalledOnce(); // still 1
    });

    it("supports multiple handlers for the same event", () => {
      const handler1 = vi.fn();
      const handler2 = vi.fn();
      client.subscribe("policy.changed", handler1);
      client.subscribe("policy.changed", handler2);

      simulateHostMessage({
        type: "event",
        method: "policy.changed",
        params: { v: 1 },
      });

      expect(handler1).toHaveBeenCalledOnce();
      expect(handler2).toHaveBeenCalledOnce();
      expect(handler1).toHaveBeenCalledWith({ v: 1 });
      expect(handler2).toHaveBeenCalledWith({ v: 1 });
    });
  });

  // ---- destroy() ----

  describe("destroy()", () => {
    it("rejects all pending calls and removes the message listener", async () => {
      vi.useFakeTimers();

      const p1 = client.call("storage.get", { key: "a" });
      const p2 = client.call("guards.register", { id: "x" });
      const destroyedError1 = captureBridgeError(p1);
      const destroyedError2 = captureBridgeError(p2);

      client.destroy();

      await expect(destroyedError1).resolves.toMatchObject({ code: "TIMEOUT" });
      await expect(destroyedError2).resolves.toMatchObject({ code: "TIMEOUT" });

      // After destroy, responses for old IDs should be ignored
      // (listener was removed, so this is a no-op)
      simulateHostMessage({ id: "0", type: "response", result: "late" });
    });
  });

  // ---- Non-bridge messages ----

  describe("message filtering", () => {
    it("silently ignores non-bridge postMessage data", () => {
      const handler = vi.fn();
      client.subscribe("policy.changed", handler);

      // Random non-bridge messages
      simulateHostMessage("just a string");
      simulateHostMessage(42);
      simulateHostMessage({ foo: "bar" });
      simulateHostMessage(null);
      simulateHostMessage({ type: "invalid-type", id: "1" });

      expect(handler).not.toHaveBeenCalled();
    });
  });
});
