import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const invokeMock = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: invokeMock,
}));

import { policyEvalEvent, policyLoad, policySave, policyValidate } from "./tauri";

describe("tauri policy helpers", () => {
  const originalWindow = (globalThis as unknown as { window?: Record<string, unknown> }).window;

  beforeEach(() => {
    invokeMock.mockReset();
    if (!originalWindow) {
      (globalThis as unknown as { window?: Record<string, unknown> }).window = {};
    }
  });

  afterEach(() => {
    const win = (globalThis as unknown as { window?: Record<string, unknown> }).window;
    if (win && "__TAURI__" in win) delete win.__TAURI__;
    if (!originalWindow) delete (globalThis as unknown as { window?: unknown }).window;
  });

  it("throws when Tauri is unavailable", async () => {
    await expect(policyLoad()).rejects.toThrow("policyLoad requires Tauri");
    await expect(policyValidate('version: "1.2.0"')).rejects.toThrow(
      "policyValidate requires Tauri",
    );
    await expect(policyEvalEvent({ eventId: "evt-1" })).rejects.toThrow(
      "policyEvalEvent requires Tauri",
    );
    await expect(policySave('version: "1.2.0"')).rejects.toThrow("policySave requires Tauri");
  });

  it("invokes policy bridge commands in Tauri mode", async () => {
    const win = (globalThis as unknown as { window?: Record<string, unknown> }).window!;
    win.__TAURI__ = {};

    invokeMock.mockResolvedValueOnce({
      name: "default",
      version: "1.2.0",
      description: "",
      policy_hash: "abc123",
      yaml: 'version: "1.2.0"',
    });
    await expect(policyLoad()).resolves.toMatchObject({ version: "1.2.0" });
    expect(invokeMock).toHaveBeenLastCalledWith("policy_load");

    invokeMock.mockResolvedValueOnce({ valid: true, errors: [], warnings: [] });
    await expect(policyValidate('version: "1.2.0"')).resolves.toMatchObject({ valid: true });
    expect(invokeMock).toHaveBeenLastCalledWith("policy_validate", { yaml: 'version: "1.2.0"' });

    invokeMock.mockResolvedValueOnce({ version: 1, command: "policy_eval" });
    await expect(policyEvalEvent({ eventId: "evt-1" })).resolves.toMatchObject({
      command: "policy_eval",
    });
    expect(invokeMock).toHaveBeenLastCalledWith("policy_eval_event", {
      event: { eventId: "evt-1" },
    });

    invokeMock.mockResolvedValueOnce({ success: true, message: "ok", policy_hash: "def456" });
    await expect(policySave('version: "1.2.0"')).resolves.toMatchObject({ success: true });
    expect(invokeMock).toHaveBeenLastCalledWith("policy_save", { yaml: 'version: "1.2.0"' });
  });
});
