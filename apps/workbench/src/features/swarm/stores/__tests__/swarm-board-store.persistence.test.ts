import { beforeEach, describe, expect, it, vi } from "vitest";

const { readPayloadMock, writePayloadMock } = vi.hoisted(() => ({
  readPayloadMock: vi.fn(),
  writePayloadMock: vi.fn(),
}));

vi.mock("@/lib/workbench/terminal-service", () => ({
  terminalService: {
    getCwd: vi.fn().mockResolvedValue("/mock/cwd"),
    create: vi.fn().mockResolvedValue({
      id: "mock-session",
      branch: "main",
      shell: "zsh",
      persistence_mode: "tmux",
      recovery_state: "fresh",
    }),
    discover: vi.fn().mockResolvedValue([]),
    reconnect: vi.fn().mockResolvedValue({
      id: "mock-session",
      branch: "main",
      shell: "zsh",
      persistence_mode: "tmux",
      recovery_state: "recovered",
    }),
    preview: vi.fn().mockResolvedValue([]),
    write: vi.fn().mockResolvedValue(undefined),
    kill: vi.fn().mockResolvedValue(undefined),
    onExit: vi.fn().mockResolvedValue(() => {}),
  },
  worktreeService: {
    create: vi.fn().mockResolvedValue({ path: "/mock/worktree", branch: "test-branch" }),
    remove: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("@/lib/tauri-bridge", async () => {
  const actual = await vi.importActual<typeof import("@/lib/tauri-bridge")>("@/lib/tauri-bridge");
  return {
    ...actual,
    isDesktop: () => true,
  };
});

vi.mock("../swarm-persistence", () => ({
  SWARM_BOARD_PERSISTENCE_FILE: "swarm-board-state.v1.json",
  readSwarmPersistencePayload: readPayloadMock,
  writeSwarmPersistencePayload: writePayloadMock,
}));

import { useSwarmBoardStore } from "../swarm-board-store";

const STORAGE_KEY = "clawdstrike_workbench_swarm_board";

function seedLegacyBoard(): void {
  localStorage.setItem(
    STORAGE_KEY,
    JSON.stringify({
      boardId: "legacy-board",
      repoRoot: "/legacy/repo",
      nodes: [
        {
          id: "legacy-node",
          type: "note",
          position: { x: 24, y: 48 },
          data: { title: "Legacy", status: "idle", nodeType: "note", createdAt: 0 },
        },
      ],
      edges: [],
    }),
  );
}

function makeConversationHistory(count: number) {
  return Array.from({ length: count }, (_value, index) => ({
    id: `turn-${index + 1}`,
    kind: "response" as const,
    role: "assistant" as const,
    content: `turn ${index + 1}`,
    createdAt: index + 1,
  }));
}

describe("SwarmBoardStore desktop persistence", () => {
  beforeEach(() => {
    localStorage.clear();
    readPayloadMock.mockReset();
    writePayloadMock.mockReset();
    useSwarmBoardStore.setState(useSwarmBoardStore.getInitialState());
  });

  it("hydrates scratch boards from app-data persistence on desktop", async () => {
    readPayloadMock.mockResolvedValueOnce({
      boardId: "disk-board",
      repoRoot: "/disk/repo",
      nodes: [
        {
          id: "disk-node",
          type: "note",
          position: { x: 12, y: 18 },
          data: { title: "Disk", status: "idle", nodeType: "note", createdAt: 0 },
        },
      ],
      edges: [],
    });

    useSwarmBoardStore.reinitializeFromStorage();

    await vi.waitFor(() => {
      expect(useSwarmBoardStore.getState().boardId).toBe("disk-board");
    });

    expect(useSwarmBoardStore.getState().repoRoot).toBe("/disk/repo");
    expect(useSwarmBoardStore.getState().nodes).toHaveLength(1);
    expect(useSwarmBoardStore.getState().nodes[0]?.id).toBe("disk-node");
  });

  it("preserves tmux-backed session ids for recovery on hydration", async () => {
    readPayloadMock.mockResolvedValueOnce({
      boardId: "disk-board",
      repoRoot: "/disk/repo",
      nodes: [
        {
          id: "disk-node",
          type: "agentSession",
          position: { x: 12, y: 18 },
          data: {
            title: "Disk Session",
            status: "running",
            nodeType: "agentSession",
            sessionId: "tmux-session",
            sessionPersistence: "tmux",
            createdAt: 0,
          },
        },
      ],
      edges: [],
    });

    useSwarmBoardStore.reinitializeFromStorage();

    await vi.waitFor(() => {
      expect(useSwarmBoardStore.getState().nodes[0]?.data.sessionId).toBe("tmux-session");
    });

    const node = useSwarmBoardStore.getState().nodes[0];
    expect(node?.data.sessionId).toBe("tmux-session");
    expect(node?.data.terminalAttached).toBe(false);
    expect(node?.data.manualSession).toBe(true);
    expect(node?.data.sessionRecoveryState).toBe("recoverable");
  });

  it("migrates legacy localStorage state into app-data when no disk file exists", async () => {
    seedLegacyBoard();
    readPayloadMock.mockResolvedValueOnce(null);
    writePayloadMock.mockResolvedValueOnce(true);

    useSwarmBoardStore.reinitializeFromStorage();

    await vi.waitFor(() => {
      expect(writePayloadMock).toHaveBeenCalledTimes(1);
    });

    expect(writePayloadMock).toHaveBeenCalledWith(
      "swarm-board-state.v1.json",
      expect.objectContaining({
        boardId: "legacy-board",
        repoRoot: "/legacy/repo",
      }),
    );
  });

  it("truncates oversized conversation history during desktop hydration", async () => {
    readPayloadMock.mockResolvedValueOnce({
      boardId: "disk-board",
      repoRoot: "/disk/repo",
      nodes: [
        {
          id: "disk-node",
          type: "agentSession",
          position: { x: 12, y: 18 },
          data: {
            title: "Replay Session",
            status: "idle",
            nodeType: "agentSession",
            conversationHistory: makeConversationHistory(240),
            createdAt: 0,
          },
        },
      ],
      edges: [],
    });

    useSwarmBoardStore.reinitializeFromStorage();

    await vi.waitFor(() => {
      expect(useSwarmBoardStore.getState().nodes[0]?.data.conversationHistory).toHaveLength(200);
    });

    const history = useSwarmBoardStore.getState().nodes[0]?.data.conversationHistory;
    expect(history?.[0]?.id).toBe("turn-41");
    expect(history?.[history.length - 1]?.id).toBe("turn-240");
  });

  it("truncates oversized conversation history before desktop persistence writes", async () => {
    vi.useFakeTimers();
    try {
      writePayloadMock.mockResolvedValue(true);

      useSwarmBoardStore.getState().actions.addNodeDirect({
        id: "replay-node",
        type: "agentSession",
        position: { x: 10, y: 20 },
        data: {
          title: "Replay Session",
          status: "idle",
          nodeType: "agentSession",
          createdAt: 0,
        },
      });

      useSwarmBoardStore.getState().actions.updateNode("replay-node", {
        conversationHistory: makeConversationHistory(240),
      });

      await vi.advanceTimersByTimeAsync(500);

      expect(writePayloadMock).toHaveBeenCalled();
      const persistedPayload = writePayloadMock.mock.calls[
        writePayloadMock.mock.calls.length - 1
      ]?.[1] as {
        nodes: Array<{ data: { conversationHistory?: Array<{ id: string }> } }>;
      };
      const history = persistedPayload.nodes[0]?.data.conversationHistory;
      expect(history).toHaveLength(200);
      expect(history?.[0]?.id).toBe("turn-41");
      expect(history?.[history.length - 1]?.id).toBe("turn-240");
    } finally {
      vi.useRealTimers();
    }
  });
});
