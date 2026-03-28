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
  addWorkspaceRootNative,
  bootstrapWorkspaceRegistryNative,
  createWorkspaceDirectoryNative,
  createWorkspaceFileNative,
  configureSwarmFileWatcherNative,
  deleteWorkspaceEntryNative,
  readAppPersistenceFileNative,
  readWorkspaceTreeNative,
  renameWorkspaceEntryNative,
  revealWorkspaceEntryNative,
  removeWorkspaceRootNative,
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

  it("bootstraps the workspace registry through the native command surface", async () => {
    invokeMock.mockResolvedValueOnce({
      snapshot: {
        version: 1,
        defaultRootId: "root-default",
        orderedRootIds: ["root-default"],
        roots: [],
      },
      migratedLegacyRoots: ["/tmp/legacy"],
      droppedLegacyRoots: [],
    });

    await expect(bootstrapWorkspaceRegistryNative(["/tmp/legacy"])).resolves.toMatchObject({
      snapshot: {
        defaultRootId: "root-default",
      },
    });

    expect(invokeMock).toHaveBeenCalledWith("bootstrap_workspace_registry", {
      request: {
        legacyRoots: ["/tmp/legacy"],
      },
    });
  });

  it("adds a workspace root through the native command surface", async () => {
    invokeMock.mockResolvedValueOnce({
      version: 1,
      defaultRootId: "root-default",
      orderedRootIds: ["root-default", "root-user"],
      roots: [],
    });

    await expect(addWorkspaceRootNative("/tmp/repo")).resolves.toMatchObject({
      orderedRootIds: ["root-default", "root-user"],
    });

    expect(invokeMock).toHaveBeenCalledWith("add_workspace_root", {
      request: {
        path: "/tmp/repo",
      },
    });
  });

  it("removes a workspace root by rootId through the native command surface", async () => {
    invokeMock.mockResolvedValueOnce({
      version: 1,
      defaultRootId: "root-default",
      orderedRootIds: ["root-default"],
      roots: [],
    });

    await expect(removeWorkspaceRootNative("root-123")).resolves.toMatchObject({
      orderedRootIds: ["root-default"],
    });

    expect(invokeMock).toHaveBeenCalledWith("remove_workspace_root", {
      request: {
        rootId: "root-123",
      },
    });
  });

  it("returns null for workspace registry commands outside desktop mode", async () => {
    isDesktopMock.mockReturnValue(false);

    await expect(bootstrapWorkspaceRegistryNative(["/tmp/legacy"])).resolves.toBeNull();
    await expect(addWorkspaceRootNative("/tmp/repo")).resolves.toBeNull();
    await expect(removeWorkspaceRootNative("root-123")).resolves.toBeNull();
    await expect(readWorkspaceTreeNative("root-123")).resolves.toBeNull();
    await expect(createWorkspaceDirectoryNative("root-123", "workspace/policies")).resolves.toBeNull();
    await expect(createWorkspaceFileNative("root-123", "workspace/policies/default.yaml", "x")).resolves.toBeNull();
    await expect(renameWorkspaceEntryNative("root-123", "old.yaml", "new.yaml")).resolves.toBeNull();
    await expect(deleteWorkspaceEntryNative("root-123", "old.yaml")).resolves.toBeNull();
    await expect(revealWorkspaceEntryNative("root-123", "old.yaml")).resolves.toBeNull();

    expect(invokeMock).not.toHaveBeenCalled();
  });

  it("reads a workspace tree through the native command surface", async () => {
    invokeMock.mockResolvedValueOnce({
      ok: true,
      data: {
        entries: [{ path: "workspace", kind: "directory" }],
      },
    });

    await expect(readWorkspaceTreeNative("root-123")).resolves.toEqual({
      ok: true,
      data: {
        entries: [{ path: "workspace", kind: "directory" }],
      },
    });

    expect(invokeMock).toHaveBeenCalledWith("read_workspace_tree", {
      request: {
        rootId: "root-123",
        includeInternalEntries: false,
      },
    });
  });

  it("reads internal workspace entries when explicitly requested", async () => {
    invokeMock.mockResolvedValueOnce({
      ok: true,
      data: {
        entries: [{ path: "workspace/.clawdstrike", kind: "directory" }],
      },
    });

    await expect(readWorkspaceTreeNative("root-123", { includeInternalEntries: true })).resolves.toEqual({
      ok: true,
      data: {
        entries: [{ path: "workspace/.clawdstrike", kind: "directory" }],
      },
    });

    expect(invokeMock).toHaveBeenCalledWith("read_workspace_tree", {
      request: {
        rootId: "root-123",
        includeInternalEntries: true,
      },
    });
  });

  it("logs structured diagnostics when a workspace command invoke rejects", async () => {
    const consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    invokeMock.mockRejectedValueOnce({ message: "ipc unavailable" });

    await expect(readWorkspaceTreeNative("root-123")).resolves.toBeNull();

    expect(consoleErrorSpy).toHaveBeenCalledWith(
      "[workspace-command]",
      expect.objectContaining({
        command: "read_workspace_tree",
        rootId: "root-123",
        message: "ipc unavailable",
      }),
    );

    consoleErrorSpy.mockRestore();
  });

  it("routes workspace mutations through the native command surface", async () => {
    invokeMock
      .mockResolvedValueOnce({ ok: true, data: { relativePath: "workspace/policies" } })
      .mockResolvedValueOnce({
        ok: true,
        data: { oldRelativePath: "workspace/old.yaml", newRelativePath: "workspace/new.yaml" },
      })
      .mockResolvedValueOnce({
        ok: true,
        data: { relativePath: "workspace/new.yaml", kind: "file" },
      })
      .mockResolvedValueOnce({
        ok: true,
        data: { relativePath: "workspace/new.yaml" },
      });

    await expect(
      createWorkspaceDirectoryNative("root-123", "workspace/policies"),
    ).resolves.toMatchObject({ ok: true });
    await expect(
      renameWorkspaceEntryNative("root-123", "workspace/old.yaml", "workspace/new.yaml"),
    ).resolves.toMatchObject({ ok: true });
    await expect(
      deleteWorkspaceEntryNative("root-123", "workspace/new.yaml"),
    ).resolves.toMatchObject({ ok: true });
    await expect(
      revealWorkspaceEntryNative("root-123", "workspace/new.yaml"),
    ).resolves.toMatchObject({ ok: true });

    expect(invokeMock).toHaveBeenNthCalledWith(1, "create_workspace_directory", {
      request: {
        rootId: "root-123",
        relativePath: "workspace/policies",
      },
    });
    expect(invokeMock).toHaveBeenNthCalledWith(2, "rename_workspace_entry", {
      request: {
        rootId: "root-123",
        oldRelativePath: "workspace/old.yaml",
        newRelativePath: "workspace/new.yaml",
      },
    });
    expect(invokeMock).toHaveBeenNthCalledWith(3, "delete_workspace_entry", {
      request: {
        rootId: "root-123",
        relativePath: "workspace/new.yaml",
      },
    });
    expect(invokeMock).toHaveBeenNthCalledWith(4, "reveal_workspace_entry", {
      request: {
        rootId: "root-123",
        relativePath: "workspace/new.yaml",
      },
    });
  });

  it("creates a workspace file through the native command surface", async () => {
    invokeMock.mockResolvedValueOnce({
      ok: true,
      data: {
        relativePath: "workspace/policies/default.yaml",
      },
    });

    await expect(
      createWorkspaceFileNative("root-123", "workspace/policies/default.yaml", "name: test\n"),
    ).resolves.toMatchObject({
      ok: true,
      data: {
        relativePath: "workspace/policies/default.yaml",
      },
    });

    expect(invokeMock).toHaveBeenCalledWith("create_workspace_file", {
      request: {
        rootId: "root-123",
        relativePath: "workspace/policies/default.yaml",
        content: "name: test\n",
      },
    });
  });

  it("creates a workspace file from backend default content when requested", async () => {
    invokeMock.mockResolvedValueOnce({
      ok: true,
      data: {
        relativePath: "workspace/policies/generated.yaml",
      },
    });

    await expect(
      createWorkspaceFileNative("root-123", "workspace/policies/generated.yaml", {
        defaultContentFileType: "clawdstrike_policy",
      }),
    ).resolves.toMatchObject({
      ok: true,
      data: {
        relativePath: "workspace/policies/generated.yaml",
      },
    });

    expect(invokeMock).toHaveBeenCalledWith("create_workspace_file", {
      request: {
        rootId: "root-123",
        relativePath: "workspace/policies/generated.yaml",
        defaultContentFileType: "clawdstrike_policy",
      },
    });
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
