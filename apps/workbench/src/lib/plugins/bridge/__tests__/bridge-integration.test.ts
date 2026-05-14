/**
 * Bridge Integration Tests
 *
 * Proves the full client-host round-trip works in a single JS context.
 * Wires PluginBridgeClient and PluginBridgeHost together by simulating
 * the postMessage plumbing that normally flows through an iframe boundary.
 *
 * Client -> parentWindow.postMessage -> host.handleMessage ->
 *   registry dispatch -> targetWindow.postMessage -> window message event ->
 *   client resolves promise
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { BridgeErrorCode } from "../types";

// ---- Registry mocks (same as host tests) ----

vi.mock("../../../workbench/guard-registry", () => ({
  registerGuard: vi.fn(() => vi.fn()),
}));

vi.mock("../../../workbench/file-type-registry", () => ({
  registerFileType: vi.fn(() => vi.fn()),
}));

vi.mock("../../../workbench/status-bar-registry", () => ({
  statusBarRegistry: {
    register: vi.fn(() => vi.fn()),
  },
}));

// Import after mocks
import { PluginBridgeClient, BridgeError } from "../bridge-client";
import { PluginBridgeHost } from "../bridge-host";

// ---- Setup ----

describe("Bridge Integration (client <-> host round-trip)", () => {
  let client: PluginBridgeClient;
  let host: PluginBridgeHost;
  let targetWindow: Window;

  beforeEach(() => {
    // Wire the two sides together:
    // 1. "parentWindow" -- when client sends a request, the host's handleMessage fires
    // 2. "targetWindow" -- when host sends a response, dispatch a real window message
    //    event so the client's listener picks it up

    // targetWindow: host responses arrive on the global window as MessageEvents
    const hostTargetWindow: { postMessage: (data: unknown, origin: string) => void } = {
      postMessage(data: unknown) {
        // Dispatch a real MessageEvent on window so the client listener receives it
        window.dispatchEvent(new MessageEvent("message", { data }));
      },
    };
    targetWindow = hostTargetWindow as unknown as Window;

    // Create host first so we have a reference for parentWindow
    host = new PluginBridgeHost({
      pluginId: "integration-test",
      targetWindow,
      allowedOrigin: "null",
    });

    // parentWindow: client requests route to host.handleMessage
    const parentWindow: { postMessage: (data: unknown, origin: string) => void } = {
      postMessage(data: unknown) {
        // Simulate the MessageEvent the host would receive from the iframe
        host.handleMessage(
          new MessageEvent("message", { data, origin: "null", source: targetWindow }),
        );
      },
    };

    // Create client with our parentWindow proxy
    client = new PluginBridgeClient(parentWindow as unknown as Window);
  });

  afterEach(() => {
    client.destroy();
    host.destroy();
  });

  // ---- Round-trip tests ----

  it("guards.register round-trip: client call resolves with { registered: true }", async () => {
    const guardPayload = {
      id: "integration_guard",
      name: "Integration Guard",
      technicalName: "IntegrationGuard",
      description: "Test guard for integration",
      category: "detection",
      defaultVerdict: "deny",
      icon: "IconShield",
      configFields: [],
    };

    const result = await client.call<{ registered: boolean }>(
      "guards.register",
      guardPayload,
    );

    expect(result).toEqual({ registered: true });
  });

  it("storage round-trip: set then get returns the stored value", async () => {
    await client.call("storage.set", { key: "lang", value: "typescript" });

    const result = await client.call<string>("storage.get", { key: "lang" });

    expect(result).toBe("typescript");
  });

  it("event push: host.pushEvent delivers to client subscriber", async () => {
    const handler = vi.fn();
    client.subscribe("policy.changed", handler);

    host.pushEvent("policy.changed", { version: "2.0" });

    // pushEvent dispatches synchronously via the targetWindow proxy
    expect(handler).toHaveBeenCalledOnce();
    expect(handler).toHaveBeenCalledWith({ version: "2.0" });
  });

  it("unknown method: client.call rejects with BridgeError(METHOD_NOT_FOUND)", async () => {
    await expect(
      client.call("unknown.method", {}),
    ).rejects.toThrow(BridgeError);

    try {
      await client.call("unknown.method", {});
    } catch (err) {
      expect(err).toBeInstanceOf(BridgeError);
      expect((err as BridgeError).code).toBe(
        "METHOD_NOT_FOUND" as BridgeErrorCode,
      );
    }
  });
});
