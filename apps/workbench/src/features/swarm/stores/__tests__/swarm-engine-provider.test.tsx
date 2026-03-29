import { useEffect } from "react";
import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Node } from "@xyflow/react";
import { SwarmEngineProvider, useSwarmEngine } from "../swarm-engine-provider";
import type { SwarmBoardNodeData } from "../../swarm-board-types";
import type { SpawnSessionOptions } from "../swarm-board-store";

const mockInitialize = vi.fn();
const mockShutdown = vi.fn();
const mockTaskGraphConfig = vi.fn();
const mockEvaluateGuard = vi.fn();
const mockAddNode = vi.fn();
const mockGuardEvaluate = vi.fn();

vi.mock("../swarm-board-store", () => ({
  useSwarmBoardStore: {
    getState: () => ({
      repoRoot: "/test/repo",
      actions: {
        addNode: mockAddNode,
        guardEvaluate: mockGuardEvaluate,
      },
    }),
  },
}));

vi.mock("@clawdstrike/swarm-engine", () => {
  class MockSwarmOrchestrator {
    initialize = mockInitialize;
    shutdown = mockShutdown;
    evaluateGuard = mockEvaluateGuard;
  }

  class MockTypedEventEmitter {}
  class MockAgentRegistry {}
  class MockTaskGraph {
    constructor(
      _events: unknown,
      _registry: unknown,
      config?: unknown,
    ) {
      mockTaskGraphConfig(config);
    }
  }
  class MockTopologyManager {}

  return {
    SwarmOrchestrator: MockSwarmOrchestrator,
    TypedEventEmitter: MockTypedEventEmitter,
    AgentRegistry: MockAgentRegistry,
    TaskGraph: MockTaskGraph,
    TopologyManager: MockTopologyManager,
  };
});

function Probe() {
  const { mode, error } = useSwarmEngine();
  return <div data-testid="engine-state">{mode}:{error ?? "none"}</div>;
}

function GuardFailureProbe({
  spawnFn,
  onResolved,
}: {
  spawnFn: (opts: SpawnSessionOptions) => Promise<Node<SwarmBoardNodeData>>;
  onResolved: (nodeId: string) => void;
}) {
  const { isReady, spawnEngineSession } = useSwarmEngine();

  useEffect(() => {
    if (!isReady) {
      return;
    }
    void spawnEngineSession(
      spawnFn,
      { shell: "zsh", cwd: "/test/repo", position: { x: 40, y: 80 } },
    ).then((node) => onResolved(node.id));
  }, [isReady, onResolved, spawnEngineSession, spawnFn]);

  return null;
}

describe("SwarmEngineProvider", () => {
  let warnSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    mockInitialize.mockReset();
    mockShutdown.mockReset();
    mockTaskGraphConfig.mockReset();
    mockEvaluateGuard.mockReset();
    mockAddNode.mockReset();
    mockGuardEvaluate.mockReset();
    mockInitialize.mockImplementation(() => {
      throw new Error("engine exploded");
    });
    mockAddNode.mockImplementation((config: {
      position: { x: number; y: number };
      title: string;
      data: Record<string, unknown>;
    }) => ({
      id: "receipt-node",
      type: "receipt",
      position: config.position,
      data: {
        title: config.title,
        nodeType: "receipt",
        ...config.data,
      },
    }));
    warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  it("shuts down a partially initialized orchestrator when initialize throws", async () => {
    const { unmount } = render(
      <SwarmEngineProvider>
        <Probe />
      </SwarmEngineProvider>,
    );

    await waitFor(() => {
      expect(screen.getByTestId("engine-state").textContent).toBe("error:engine exploded");
    });

    expect(mockInitialize).toHaveBeenCalledTimes(1);
    expect(mockShutdown).toHaveBeenCalledTimes(1);
    expect(mockTaskGraphConfig).toHaveBeenCalledWith(
      expect.objectContaining({
        maxTasks: 200,
        defaultTimeoutMs: 300_000,
      }),
    );

    unmount();

    expect(mockShutdown).toHaveBeenCalledTimes(1);
  });

  it("fails closed with a deny receipt when guard evaluation throws", async () => {
    mockInitialize.mockImplementation(() => {});
    mockEvaluateGuard.mockRejectedValue(new Error("guard exploded"));
    const spawnFn = vi.fn<(opts: SpawnSessionOptions) => Promise<Node<SwarmBoardNodeData>>>()
      .mockResolvedValue({
      id: "spawned-node",
      type: "agentSession",
      position: { x: 0, y: 0 },
      data: { title: "Spawned", status: "idle", nodeType: "agentSession" },
    });
    const onResolved = vi.fn();

    render(
      <SwarmEngineProvider>
        <GuardFailureProbe spawnFn={spawnFn} onResolved={onResolved} />
      </SwarmEngineProvider>,
    );

    await waitFor(() => {
      expect(mockEvaluateGuard).toHaveBeenCalledTimes(1);
      expect(mockAddNode).toHaveBeenCalledTimes(1);
      expect(onResolved).toHaveBeenCalledWith("receipt-node");
    });

    expect(spawnFn).not.toHaveBeenCalled();
    expect(mockGuardEvaluate).not.toHaveBeenCalled();
    expect(mockAddNode).toHaveBeenCalledWith(expect.objectContaining({
      nodeType: "receipt",
      title: "Guard: DENY",
      data: expect.objectContaining({
        verdict: "deny",
        engineManaged: true,
        receiptData: expect.objectContaining({
          guard: "fail-closed",
          policyName: "guard-evaluation-error",
          valid: false,
        }),
      }),
    }));
  });
});
