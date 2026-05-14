import { beforeEach, describe, expect, it, vi } from "vitest";
import { cancelSearchInProjectNative, searchInProjectNative } from "../tauri-commands";

const bridgeMocks = vi.hoisted(() => ({
  invokeMock: vi.fn(),
  isDesktop: vi.fn(() => false),
  hasWorkbenchE2EInvoke: vi.fn(() => false),
  getWorkbenchE2EBridge: vi.fn(() => null),
}));

vi.mock("../tauri-bridge", () => ({
  isDesktop: bridgeMocks.isDesktop,
}));

vi.mock("@tauri-apps/api/core", () => ({
  invoke: bridgeMocks.invokeMock,
}));

vi.mock("@/lib/workbench/e2e-bridge", () => ({
  hasWorkbenchE2EInvoke: bridgeMocks.hasWorkbenchE2EInvoke,
  getWorkbenchE2EBridge: bridgeMocks.getWorkbenchE2EBridge,
}));

describe("searchInProjectNative", () => {
  beforeEach(() => {
    bridgeMocks.invokeMock.mockReset();
    bridgeMocks.isDesktop.mockReset();
    bridgeMocks.isDesktop.mockReturnValue(false);
    bridgeMocks.hasWorkbenchE2EInvoke.mockReset();
    bridgeMocks.hasWorkbenchE2EInvoke.mockReturnValue(false);
    bridgeMocks.getWorkbenchE2EBridge.mockReset();
    bridgeMocks.getWorkbenchE2EBridge.mockReturnValue(null);
  });

  it("returns null when neither desktop nor the E2E bridge is available", async () => {
    await expect(
      searchInProjectNative("/workspace/project", "needle", false, false, false),
    ).resolves.toBeNull();

    expect(bridgeMocks.invokeMock).not.toHaveBeenCalled();
  });

  it("rethrows search errors with the backend message intact", async () => {
    const invoke = vi.fn().mockRejectedValue("Invalid regex: unclosed character class");
    bridgeMocks.hasWorkbenchE2EInvoke.mockReturnValue(true);
    bridgeMocks.getWorkbenchE2EBridge.mockReturnValue({ invoke } as never);

    await expect(
      searchInProjectNative("/workspace/project", "[", false, false, true),
    ).rejects.toThrow("Invalid regex: unclosed character class");
  });
});

describe("cancelSearchInProjectNative", () => {
  beforeEach(() => {
    bridgeMocks.invokeMock.mockReset();
    bridgeMocks.isDesktop.mockReset();
    bridgeMocks.isDesktop.mockReturnValue(false);
    bridgeMocks.hasWorkbenchE2EInvoke.mockReset();
    bridgeMocks.hasWorkbenchE2EInvoke.mockReturnValue(false);
    bridgeMocks.getWorkbenchE2EBridge.mockReset();
    bridgeMocks.getWorkbenchE2EBridge.mockReturnValue(null);
  });

  it("returns early when neither desktop nor the E2E bridge is available", async () => {
    await expect(cancelSearchInProjectNative("search-1")).resolves.toBeUndefined();

    expect(bridgeMocks.invokeMock).not.toHaveBeenCalled();
  });

  it("uses the E2E invoke bridge when available", async () => {
    const invoke = vi.fn().mockResolvedValue(undefined);
    bridgeMocks.hasWorkbenchE2EInvoke.mockReturnValue(true);
    bridgeMocks.getWorkbenchE2EBridge.mockReturnValue({ invoke } as never);

    await expect(cancelSearchInProjectNative("search-1")).resolves.toBeUndefined();

    expect(invoke).toHaveBeenCalledWith("cancel_search_in_project", { searchId: "search-1" });
  });
});
