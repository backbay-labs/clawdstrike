import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  publishMessageMock,
  getCoordinatorMock,
  viewportControllerMock,
} = vi.hoisted(() => ({
  publishMessageMock: vi.fn(),
  getCoordinatorMock: vi.fn(),
  viewportControllerMock: {
    getViewport: vi.fn(() => ({ x: 10, y: 20, zoom: 1.25 })),
    setViewport: vi.fn(async (viewport: unknown) => viewport),
  },
}));

vi.mock("@/features/swarm/coordinator-instance", () => ({
  getCoordinator: getCoordinatorMock,
}));

vi.mock("@/features/swarm/rpc/swarm-rpc-viewport", () => ({
  getSwarmRpcViewportController: () => viewportControllerMock,
}));

import { createSwarmRpcDispatcher } from "../swarm-rpc-bridge";
import { useSwarmBoardStore } from "@/features/swarm/stores/swarm-board-store";

function resetBoard(): void {
  useSwarmBoardStore.getState().actions.clearBoard();
}

describe("createSwarmRpcDispatcher", () => {
  beforeEach(() => {
    resetBoard();
    publishMessageMock.mockReset();
    viewportControllerMock.getViewport.mockClear();
    viewportControllerMock.setViewport.mockClear();
    getCoordinatorMock.mockReset();
    getCoordinatorMock.mockReturnValue({
      isConnected: true,
      outboxSize: 0,
      joinedSwarmIds: ["swm-alpha"],
      currentReconnectAttempts: 0,
      publishMessage: publishMessageMock,
    });
  });

  it("adds and updates board nodes using the live store actions", async () => {
    const dispatcher = createSwarmRpcDispatcher({
      getBoardStore: useSwarmBoardStore.getState,
      spawnSession: vi.fn(),
      spawnClaudeSession: vi.fn(),
      spawnWorktreeSession: vi.fn(),
      killSession: vi.fn(),
      terminal: {
        list: vi.fn(),
        discover: vi.fn(),
        preview: vi.fn(),
        kill: vi.fn(),
      },
    });

    const created = await dispatcher("board.nodeAdd", {
      nodeType: "note",
      title: "Ops note",
      position: { x: 42, y: 84 },
      data: { content: "watch auth latency" },
    });

    const createdNode = created as { id: string };
    expect(useSwarmBoardStore.getState().nodes).toHaveLength(1);
    expect(useSwarmBoardStore.getState().nodes[0]?.data.content).toBe("watch auth latency");

    const updated = await dispatcher("board.nodeUpdate", {
      nodeId: createdNode.id,
      position: { x: 100, y: 120 },
      data: { content: "watch auth latency and queue depth" },
    });

    expect((updated as { position: { x: number; y: number } }).position).toEqual({
      x: 100,
      y: 120,
    });
    expect(useSwarmBoardStore.getState().nodes[0]?.data.content).toBe(
      "watch auth latency and queue depth",
    );
  });

  it("routes session.kill through the board node when only sessionId is provided", async () => {
    const killSession = vi.fn().mockResolvedValue(undefined);
    const { actions } = useSwarmBoardStore.getState();
    const node = actions.addNode({
      nodeType: "agentSession",
      title: "Replay agent",
      position: { x: 0, y: 0 },
      data: {
        sessionId: "sess-rpc-1",
        status: "running",
      },
    });

    const dispatcher = createSwarmRpcDispatcher({
      getBoardStore: useSwarmBoardStore.getState,
      spawnSession: vi.fn(),
      spawnClaudeSession: vi.fn(),
      spawnWorktreeSession: vi.fn(),
      killSession,
      terminal: {
        list: vi.fn(),
        discover: vi.fn(),
        preview: vi.fn(),
        kill: vi.fn(),
      },
    });

    await dispatcher("session.kill", { sessionId: "sess-rpc-1" });

    expect(killSession).toHaveBeenCalledWith(node.id);
  });

  it("proxies viewport get/set through the registered viewport controller", async () => {
    const dispatcher = createSwarmRpcDispatcher({
      getBoardStore: useSwarmBoardStore.getState,
      spawnSession: vi.fn(),
      spawnClaudeSession: vi.fn(),
      spawnWorktreeSession: vi.fn(),
      killSession: vi.fn(),
      terminal: {
        list: vi.fn(),
        discover: vi.fn(),
        preview: vi.fn(),
        kill: vi.fn(),
      },
    });

    await expect(dispatcher("board.viewportGet", {})).resolves.toEqual({
      x: 10,
      y: 20,
      zoom: 1.25,
    });
    await expect(
      dispatcher("board.viewportSet", { viewport: { x: 1, y: 2, zoom: 0.9 }, duration: 250 }),
    ).resolves.toEqual({
      x: 1,
      y: 2,
      zoom: 0.9,
    });

    expect(viewportControllerMock.getViewport).toHaveBeenCalledTimes(1);
    expect(viewportControllerMock.setViewport).toHaveBeenCalledWith(
      { x: 1, y: 2, zoom: 0.9 },
      { duration: 250 },
    );
  });

  it("publishes coordinator payloads through the singleton coordinator", async () => {
    const dispatcher = createSwarmRpcDispatcher({
      getBoardStore: useSwarmBoardStore.getState,
      spawnSession: vi.fn(),
      spawnClaudeSession: vi.fn(),
      spawnWorktreeSession: vi.fn(),
      killSession: vi.fn(),
      terminal: {
        list: vi.fn(),
        discover: vi.fn(),
        preview: vi.fn(),
        kill: vi.fn(),
      },
    });

    await expect(
      dispatcher("coordinator.publish", {
        swarmId: "swm-alpha",
        channel: "coordination",
        payload: { action: "policy_evaluated", guard: "SecretsGuard" },
      }),
    ).resolves.toEqual({
      published: true,
      queued: false,
      swarmId: "swm-alpha",
      channel: "coordination",
    });

    expect(publishMessageMock).toHaveBeenCalledWith("swm-alpha", "coordination", {
      action: "policy_evaluated",
      guard: "SecretsGuard",
    });
  });

  it("session.list merges board nodes with backend-discovered sessions", async () => {
    const { actions } = useSwarmBoardStore.getState();
    const node = actions.addNode({
      nodeType: "agentSession",
      title: "Analysis Agent",
      position: { x: 0, y: 0 },
      data: {
        sessionId: "sess-1",
        status: "running",
      },
    });

    const listMock = vi.fn().mockResolvedValue([
      {
        id: "sess-1",
        cwd: "/tmp",
        branch: null,
        created_at: "2026-01-01",
        alive: true,
        exit_code: null,
        line_count: 10,
        shell: "zsh",
        persistence_mode: "direct",
        recovery_state: "fresh",
        cwd_valid: true,
      },
    ]);
    const discoverMock = vi.fn().mockResolvedValue([
      {
        id: "sess-2",
        cwd: "/tmp/work",
        branch: "main",
        created_at: "2026-01-02",
        alive: false,
        exit_code: null,
        line_count: 0,
        shell: "bash",
        persistence_mode: "tmux",
        recovery_state: "detached",
        cwd_valid: true,
      },
    ]);

    const dispatcher = createSwarmRpcDispatcher({
      getBoardStore: useSwarmBoardStore.getState,
      spawnSession: vi.fn(),
      spawnClaudeSession: vi.fn(),
      spawnWorktreeSession: vi.fn(),
      killSession: vi.fn(),
      terminal: {
        list: listMock,
        discover: discoverMock,
        preview: vi.fn(),
        kill: vi.fn(),
      },
    });

    const result = (await dispatcher("session.list", {})) as Array<Record<string, unknown>>;

    expect(result).toHaveLength(2);

    // Sorted by created_at: sess-1 (2026-01-01) comes first
    expect(result[0]).toMatchObject({
      nodeId: node.id,
      sessionId: "sess-1",
      title: "Analysis Agent",
      boardStatus: "running",
    });
    expect(result[1]).toMatchObject({
      nodeId: null,
      sessionId: "sess-2",
      title: null,
      boardStatus: null,
      sessionPersistence: "tmux",
      sessionRecoveryState: "detached",
    });

    // Verify sort order by created_at (lexicographic comparison)
    const date0 = String(result[0]?.created_at ?? "");
    const date1 = String(result[1]?.created_at ?? "");
    expect(date0.localeCompare(date1)).toBeLessThan(0);
  });

  it("board.edgeAdd creates edges with default and explicit types", async () => {
    const { actions } = useSwarmBoardStore.getState();
    const node1 = actions.addNode({
      nodeType: "agentSession",
      title: "Node A",
      position: { x: 0, y: 0 },
    });
    const node2 = actions.addNode({
      nodeType: "agentSession",
      title: "Node B",
      position: { x: 200, y: 0 },
    });

    const dispatcher = createSwarmRpcDispatcher({
      getBoardStore: useSwarmBoardStore.getState,
      spawnSession: vi.fn(),
      spawnClaudeSession: vi.fn(),
      spawnWorktreeSession: vi.fn(),
      killSession: vi.fn(),
      terminal: {
        list: vi.fn(),
        discover: vi.fn(),
        preview: vi.fn(),
        kill: vi.fn(),
      },
    });

    // Edge with no explicit type
    const edge1 = (await dispatcher("board.edgeAdd", {
      source: node1.id,
      target: node2.id,
    })) as { id: string; source: string; target: string };

    expect(edge1.source).toBe(node1.id);
    expect(edge1.target).toBe(node2.id);
    expect(edge1.id).toMatch(/^edge-/);

    const storeEdges = useSwarmBoardStore.getState().edges;
    expect(storeEdges.some((e) => e.id === edge1.id)).toBe(true);

    // Edge with explicit type and label
    const edge2 = (await dispatcher("board.edgeAdd", {
      source: node2.id,
      target: node1.id,
      type: "handoff",
      label: "escalation",
    })) as { id: string; type: string; label: string };

    expect(edge2.type).toBe("handoff");
    expect(edge2.label).toBe("escalation");
  });

  it("board.edgeAdd rejects unsupported edge types", async () => {
    const { actions } = useSwarmBoardStore.getState();
    const node1 = actions.addNode({
      nodeType: "note",
      title: "A",
      position: { x: 0, y: 0 },
    });
    const node2 = actions.addNode({
      nodeType: "note",
      title: "B",
      position: { x: 100, y: 0 },
    });

    const dispatcher = createSwarmRpcDispatcher({
      getBoardStore: useSwarmBoardStore.getState,
      spawnSession: vi.fn(),
      spawnClaudeSession: vi.fn(),
      spawnWorktreeSession: vi.fn(),
      killSession: vi.fn(),
      terminal: {
        list: vi.fn(),
        discover: vi.fn(),
        preview: vi.fn(),
        kill: vi.fn(),
      },
    });

    await expect(
      dispatcher("board.edgeAdd", {
        source: node1.id,
        target: node2.id,
        type: "invalid_type",
      }),
    ).rejects.toThrow("Unsupported edge type");
  });

  it("board.nodeUpdate throws for non-existent node", async () => {
    const dispatcher = createSwarmRpcDispatcher({
      getBoardStore: useSwarmBoardStore.getState,
      spawnSession: vi.fn(),
      spawnClaudeSession: vi.fn(),
      spawnWorktreeSession: vi.fn(),
      killSession: vi.fn(),
      terminal: {
        list: vi.fn(),
        discover: vi.fn(),
        preview: vi.fn(),
        kill: vi.fn(),
      },
    });

    await expect(
      dispatcher("board.nodeUpdate", {
        nodeId: "nonexistent-123",
        data: { title: "x" },
      }),
    ).rejects.toThrow("Node not found");
  });

  it("coordinator.publish rejects invalid channel", async () => {
    const dispatcher = createSwarmRpcDispatcher({
      getBoardStore: useSwarmBoardStore.getState,
      spawnSession: vi.fn(),
      spawnClaudeSession: vi.fn(),
      spawnWorktreeSession: vi.fn(),
      killSession: vi.fn(),
      terminal: {
        list: vi.fn(),
        discover: vi.fn(),
        preview: vi.fn(),
        kill: vi.fn(),
      },
    });

    await expect(
      dispatcher("coordinator.publish", {
        swarmId: "s1",
        channel: "bogus",
        payload: {},
      }),
    ).rejects.toThrow("Unsupported coordinator channel");
  });

  it("session.readOutput returns preview lines via terminal service", async () => {
    const { actions } = useSwarmBoardStore.getState();
    const node = actions.addNode({
      nodeType: "agentSession",
      title: "Build runner",
      position: { x: 0, y: 0 },
      data: {
        sessionId: "sess-preview",
        status: "running",
      },
    });

    const previewMock = vi
      .fn()
      .mockResolvedValue(["$ cargo test", "running 42 tests", "test result: ok"]);

    const dispatcher = createSwarmRpcDispatcher({
      getBoardStore: useSwarmBoardStore.getState,
      spawnSession: vi.fn(),
      spawnClaudeSession: vi.fn(),
      spawnWorktreeSession: vi.fn(),
      killSession: vi.fn(),
      terminal: {
        list: vi.fn(),
        discover: vi.fn(),
        preview: previewMock,
        kill: vi.fn(),
      },
    });

    const result = (await dispatcher("session.readOutput", {
      nodeId: node.id,
      lines: 3,
    })) as { sessionId: string; lines: string[]; lineCount: number };

    expect(result.sessionId).toBe("sess-preview");
    expect(result.lines).toEqual(["$ cargo test", "running 42 tests", "test result: ok"]);
    expect(result.lineCount).toBe(3);
    expect(previewMock).toHaveBeenCalledWith("sess-preview", 3);
  });
});
