import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const invokeMock = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: invokeMock,
}));

import { openclawGatewayDiscover, openclawGatewayProbe } from "./tauri";

describe("tauri openclaw helpers", () => {
  const originalWindowDescriptor = Object.getOwnPropertyDescriptor(globalThis, "window");
  const originalWindow = (globalThis as unknown as { window?: Record<string, unknown> }).window;
  const originalHasWindow = !!originalWindowDescriptor;
  const originalHasTauri = !!originalWindow && "__TAURI__" in originalWindow;
  const originalTauri = originalHasTauri ? originalWindow.__TAURI__ : undefined;

  beforeEach(() => {
    invokeMock.mockReset();
    if (originalWindow && typeof originalWindow === "object" && "__TAURI__" in originalWindow) {
      delete originalWindow.__TAURI__;
    }
    if (!originalHasWindow) delete (globalThis as unknown as { window?: unknown }).window;
  });

  afterEach(() => {
    if (originalWindow && typeof originalWindow === "object") {
      if (originalHasTauri) originalWindow.__TAURI__ = originalTauri;
      else if ("__TAURI__" in originalWindow) delete originalWindow.__TAURI__;
      return;
    }
    if (originalHasWindow) return;
    delete (globalThis as unknown as { window?: unknown }).window;
  });

  it("throws when not running in Tauri", async () => {
    await expect(openclawGatewayDiscover()).rejects.toThrow("OpenClaw discovery requires Tauri");
    await expect(openclawGatewayProbe()).rejects.toThrow("OpenClaw probe requires Tauri");
  });

  it("invokes openclaw gateway commands when in Tauri", async () => {
    const win =
      (globalThis as unknown as { window?: Record<string, unknown> }).window ??
      ((globalThis as unknown as { window?: Record<string, unknown> }).window = {});
    win.__TAURI__ = {};

    invokeMock.mockResolvedValueOnce({ count: 1, beacons: [{ wsUrl: "ws://127.0.0.1:18789" }] });
    await expect(openclawGatewayDiscover(2500)).resolves.toEqual({
      count: 1,
      beacons: [{ wsUrl: "ws://127.0.0.1:18789" }],
    });
    expect(invokeMock).toHaveBeenLastCalledWith("openclaw_gateway_discover", { timeout_ms: 2500 });

    invokeMock.mockResolvedValueOnce({ ok: true });
    await expect(openclawGatewayProbe()).resolves.toEqual({ ok: true });
    expect(invokeMock).toHaveBeenLastCalledWith("openclaw_gateway_probe", {});
  });
});
