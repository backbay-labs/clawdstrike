import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type WorkspaceWatchEvent = {
  payload: {
    category: "workspace";
    paths: string[];
    filenames: string[];
  };
};

type PersistenceWatchEvent = {
  payload: {
    category: "persistence";
    paths: string[];
    filenames: string[];
  };
};

const {
  configureWatcherMock,
  stopWatcherMock,
  listenMock,
} = vi.hoisted(() => ({
  configureWatcherMock: vi.fn().mockResolvedValue(true),
  stopWatcherMock: vi.fn().mockResolvedValue(true),
  listenMock: vi.fn(),
}));

vi.mock("@/lib/tauri-commands", () => ({
  configureSwarmFileWatcherNative: configureWatcherMock,
  stopSwarmFileWatcherNative: stopWatcherMock,
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: listenMock,
}));

describe("swarm-file-watch", () => {
  beforeEach(() => {
    vi.resetModules();
    configureWatcherMock.mockClear();
    stopWatcherMock.mockClear();
    listenMock.mockReset();
    listenMock.mockResolvedValue(() => {});
    Object.defineProperty(window, "__TAURI_INTERNALS__", {
      value: {},
      configurable: true,
    });
  });

  it("aggregates scope configs before configuring the backend watcher", async () => {
    const {
      setSwarmFileWatchScope,
      clearSwarmFileWatchScope,
    } = await import("../swarm-file-watch");

    await setSwarmFileWatchScope("board", {
      persistenceFilenames: ["swarm-board-state.v1.json"],
      workspacePaths: ["/tmp/rules/policy.yaml"],
    });
    await setSwarmFileWatchScope("feed", {
      persistenceFilenames: ["swarm-feed-state.v1.json"],
      workspacePaths: ["/tmp/rules/policy.yaml", "/tmp/evidence/findings.json"],
    });

    expect(configureWatcherMock).toHaveBeenLastCalledWith({
      persistence_filenames: [
        "swarm-board-state.v1.json",
        "swarm-feed-state.v1.json",
      ],
      workspace_paths: [
        "/tmp/evidence/findings.json",
        "/tmp/rules/policy.yaml",
      ],
    });

    await clearSwarmFileWatchScope("board");
    await clearSwarmFileWatchScope("feed");
  });

  it("filters self-written workspace events before notifying subscribers", async () => {
    let capturedEventHandler: ((event: WorkspaceWatchEvent) => void) | undefined;
    listenMock.mockImplementationOnce(async (_event, handler) => {
      capturedEventHandler = handler as (event: WorkspaceWatchEvent) => void;
      return () => {};
    });

    const {
      markSwarmFileWatchSelfWrite,
      setSwarmFileWatchScope,
      clearSwarmFileWatchScope,
      subscribeSwarmFileWatchEvents,
    } = await import("../swarm-file-watch");

    const received = vi.fn();
    const unsubscribe = subscribeSwarmFileWatchEvents(received);
    await setSwarmFileWatchScope("board", {
      workspacePaths: ["/tmp/bundle/board.json", "/tmp/evidence/findings.json"],
    });

    markSwarmFileWatchSelfWrite("/tmp/bundle/board.json");
    const dispatchWorkspaceEvent = capturedEventHandler;
    if (!dispatchWorkspaceEvent) {
      throw new Error("Expected watcher event handler to be registered");
    }
    dispatchWorkspaceEvent({
      payload: {
        category: "workspace",
        paths: ["/tmp/bundle/board.json", "/tmp/evidence/findings.json"],
        filenames: ["board.json", "findings.json"],
      },
    });

    expect(received).toHaveBeenCalledWith({
      category: "workspace",
      paths: ["/tmp/evidence/findings.json"],
      filenames: ["findings.json"],
    });

    unsubscribe();
    await clearSwarmFileWatchScope("board");
  });

  it("normalizes Windows watch paths for backend matching and self-write filtering", async () => {
    Object.defineProperty(window.navigator, "platform", {
      value: "Win32",
      configurable: true,
    });

    const {
      normalizeSwarmFileWatchPath,
      markSwarmFileWatchSelfWrite,
      setSwarmFileWatchScope,
      clearSwarmFileWatchScope,
      subscribeSwarmFileWatchEvents,
    } = await import("../swarm-file-watch");

    expect(normalizeSwarmFileWatchPath("C:\\Repo\\Artifacts\\Result.JSON")).toBe(
      "c:/repo/artifacts/result.json",
    );

    let capturedEventHandler: ((event: WorkspaceWatchEvent) => void) | undefined;
    listenMock.mockImplementationOnce(async (_event, handler) => {
      capturedEventHandler = handler as (event: WorkspaceWatchEvent) => void;
      return () => {};
    });

    const received = vi.fn();
    const unsubscribe = subscribeSwarmFileWatchEvents(received);
    await setSwarmFileWatchScope("board", {
      workspacePaths: ["C:\\Repo\\Artifacts\\Result.JSON", "C:\\Repo\\Other\\Keep.md"],
    });

    markSwarmFileWatchSelfWrite("c:/repo/artifacts/result.json");
    const dispatchWorkspaceEvent = capturedEventHandler;
    if (!dispatchWorkspaceEvent) {
      throw new Error("Expected watcher event handler to be registered");
    }
    dispatchWorkspaceEvent({
      payload: {
        category: "workspace",
        paths: ["C:\\Repo\\Artifacts\\Result.JSON", "C:\\Repo\\Other\\Keep.md"],
        filenames: ["Result.JSON", "Keep.md"],
      },
    });

    expect(received).toHaveBeenCalledWith({
      category: "workspace",
      paths: ["C:\\Repo\\Other\\Keep.md"],
      filenames: ["Keep.md"],
    });

    unsubscribe();
    await clearSwarmFileWatchScope("board");
  });

  it("allows events through after self-write TTL expires", async () => {
    vi.useFakeTimers();

    let capturedEventHandler:
      | ((event: PersistenceWatchEvent) => void)
      | undefined;
    listenMock.mockImplementationOnce(async (_event: string, handler: unknown) => {
      capturedEventHandler = handler as (event: PersistenceWatchEvent) => void;
      return () => {};
    });

    const {
      markSwarmFileWatchSelfWrite,
      setSwarmFileWatchScope,
      clearSwarmFileWatchScope,
      subscribeSwarmFileWatchEvents,
    } = await import("../swarm-file-watch");

    const received = vi.fn();
    const unsubscribe = subscribeSwarmFileWatchEvents(received);
    await setSwarmFileWatchScope("swarms", {
      persistenceFilenames: ["swarms-state.v1.json"],
    });

    markSwarmFileWatchSelfWrite("/tmp/state/swarms-state.v1.json");

    // Advance past the 1500ms self-write TTL
    vi.advanceTimersByTime(1600);

    const dispatchEvent = capturedEventHandler;
    if (!dispatchEvent) {
      throw new Error("Expected watcher event handler to be registered");
    }

    dispatchEvent({
      payload: {
        category: "persistence",
        paths: ["/tmp/state/swarms-state.v1.json"],
        filenames: ["swarms-state.v1.json"],
      },
    });

    // Event should NOT be suppressed since TTL expired
    expect(received).toHaveBeenCalledTimes(1);
    expect(received).toHaveBeenCalledWith(
      expect.objectContaining({
        category: "persistence",
        paths: ["/tmp/state/swarms-state.v1.json"],
      }),
    );

    unsubscribe();
    await clearSwarmFileWatchScope("swarms");
    vi.useRealTimers();
  });

  it("aggregates three store scopes with distinct persistence filenames", async () => {
    const {
      setSwarmFileWatchScope,
      clearSwarmFileWatchScope,
    } = await import("../swarm-file-watch");

    await setSwarmFileWatchScope("board", {
      persistenceFilenames: ["swarm-board-state.v1.json"],
    });
    await setSwarmFileWatchScope("feed", {
      persistenceFilenames: ["swarm-feed-state.v1.json"],
    });
    await setSwarmFileWatchScope("swarms", {
      persistenceFilenames: ["swarms-state.v1.json"],
    });

    expect(configureWatcherMock).toHaveBeenLastCalledWith({
      persistence_filenames: [
        "swarm-board-state.v1.json",
        "swarm-feed-state.v1.json",
        "swarms-state.v1.json",
      ],
      workspace_paths: [],
    });

    await clearSwarmFileWatchScope("board");
    await clearSwarmFileWatchScope("feed");
    await clearSwarmFileWatchScope("swarms");
  });
});
