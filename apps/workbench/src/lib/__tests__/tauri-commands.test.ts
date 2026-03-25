import { beforeEach, describe, expect, it, vi } from "vitest";

const { invokeMock, isDesktopMock } = vi.hoisted(() => ({
  invokeMock: vi.fn(),
  isDesktopMock: vi.fn(),
}));

vi.mock("../tauri-bridge", () => ({
  isDesktop: isDesktopMock,
}));

vi.mock("@tauri-apps/api/core", () => ({
  invoke: invokeMock,
}));

import {
  configureSwarmFileWatcherNative,
  readAppPersistenceFileNative,
  respondToRpcFrontendRequestNative,
  searchInProjectNative,
  stopSwarmFileWatcherNative,
  writeAppPersistenceFileNative,
} from "../tauri-commands";

describe("searchInProjectNative", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    isDesktopMock.mockReset();
    isDesktopMock.mockReturnValue(true);
  });

  it("returns null outside desktop mode", async () => {
    isDesktopMock.mockReturnValue(false);

    await expect(
      searchInProjectNative("/workspace/alpha", "needle", false, false, false),
    ).resolves.toBeNull();

    expect(invokeMock).not.toHaveBeenCalled();
  });

  it("preserves tauri invocation errors for callers", async () => {
    const consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    invokeMock.mockRejectedValueOnce({ message: "invalid regex" });

    await expect(
      searchInProjectNative("/workspace/alpha", "needle(", false, false, true),
    ).rejects.toThrow("invalid regex");

    expect(consoleErrorSpy).toHaveBeenCalled();
    consoleErrorSpy.mockRestore();
  });
});

describe("app persistence commands", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    isDesktopMock.mockReset();
    isDesktopMock.mockReturnValue(true);
  });

  it("reads persistence files through the native command surface", async () => {
    invokeMock.mockResolvedValueOnce("{\"version\":1}");

    await expect(readAppPersistenceFileNative("swarm-board-state.v1.json")).resolves.toBe(
      "{\"version\":1}",
    );

    expect(invokeMock).toHaveBeenCalledWith("read_app_persistence_file", {
      filename: "swarm-board-state.v1.json",
    });
  });

  it("skips persistence writes outside desktop mode", async () => {
    isDesktopMock.mockReturnValue(false);

    await expect(
      writeAppPersistenceFileNative("swarm-board-state.v1.json", "{}"),
    ).resolves.toBe(false);

    expect(invokeMock).not.toHaveBeenCalled();
  });

  it("configures the backend file watcher with typed request payloads", async () => {
    await expect(
      configureSwarmFileWatcherNative({
        persistence_filenames: ["swarm-board-state.v1.json"],
        workspace_paths: ["/tmp/evidence/findings.json"],
      }),
    ).resolves.toBe(true);

    expect(invokeMock).toHaveBeenCalledWith("configure_swarm_file_watcher", {
      request: {
        persistence_filenames: ["swarm-board-state.v1.json"],
        workspace_paths: ["/tmp/evidence/findings.json"],
      },
    });
  });

  it("stops the backend file watcher when no watch scopes remain", async () => {
    await expect(stopSwarmFileWatcherNative()).resolves.toBe(true);
    expect(invokeMock).toHaveBeenCalledWith("stop_swarm_file_watcher", undefined);
  });

  it("acknowledges bridged frontend RPC requests through the native command surface", async () => {
    await expect(
      respondToRpcFrontendRequestNative("req-123", { ok: true }),
    ).resolves.toBe(true);

    expect(invokeMock).toHaveBeenCalledWith("rpc_frontend_respond", {
      requestId: "req-123",
      payload: { ok: true },
      error: null,
    });
  });
});
