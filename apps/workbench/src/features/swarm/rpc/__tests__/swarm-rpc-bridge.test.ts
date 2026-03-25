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
});
