import React from "react";
import { act, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { SwarmBoardPage } from "../swarm-board-page";

vi.mock("@xyflow/react", () => {
  const ReactFlowMock = ({ children }: { children?: React.ReactNode }) => (
    <div data-testid="react-flow-canvas">{children}</div>
  );

  return {
    ReactFlow: ReactFlowMock,
    ReactFlowProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
    MiniMap: () => <div data-testid="react-flow-minimap" />,
    useReactFlow: () => ({
      getViewport: () => ({ x: 0, y: 0, zoom: 1 }),
      fitView: vi.fn(),
      setViewport: vi.fn(),
      zoomIn: vi.fn(),
      zoomOut: vi.fn(),
    }),
    applyNodeChanges: (_changes: unknown[], nodes: unknown[]) => nodes,
    applyEdgeChanges: (_changes: unknown[], edges: unknown[]) => edges,
    MarkerType: { ArrowClosed: "arrowclosed" },
  };
});

vi.mock("@/features/swarm/hooks/use-coordinator-board-bridge", () => ({
  useCoordinatorBoardBridge: vi.fn(),
}));

vi.mock("@/features/swarm/hooks/use-policy-eval-board-bridge", () => ({
  usePolicyEvalBoardBridge: vi.fn(),
}));

vi.mock("@/features/swarm/hooks/use-trust-graph-bridge", () => ({
  useTrustGraphBridge: vi.fn(),
}));

vi.mock("@/features/swarm/hooks/use-receipt-flow-bridge", () => ({
  useReceiptFlowBridge: vi.fn(),
  receiptEdgeTimestamps: new Map(),
}));

vi.mock("@/features/swarm/hooks/use-engine-board-bridge", () => ({
  useEngineBoardBridge: vi.fn(),
}));

vi.mock("@/features/swarm/coordinator-instance", () => ({
  getCoordinator: () => ({
    isConnected: false,
    outboxSize: 0,
    joinedSwarmIds: [],
  }),
}));

vi.mock("@/features/swarm/stores/swarm-engine-provider", () => ({
  SwarmEngineProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  useOptionalSwarmEngine: () => null,
}));

vi.mock("../swarm-board-toolbar", () => ({
  SwarmBoardToolbar: () => <div data-testid="swarm-board-toolbar" />,
}));

vi.mock("../swarm-board-left-rail", () => ({
  SwarmBoardLeftRail: () => <div data-testid="swarm-board-left-rail" />,
}));

vi.mock("../swarm-board-inspector", () => ({
  SwarmBoardInspector: () => <div data-testid="swarm-board-inspector" />,
}));

vi.mock("../nodes", () => ({
  swarmBoardNodeTypes: {},
}));

vi.mock("../edges", () => ({
  swarmBoardEdgeTypes: {},
}));

vi.mock("@/lib/workbench/use-terminal-sessions", () => ({
  useTerminalSessionsFromBoard: () => ({
    spawnSession: vi.fn(),
    killSession: vi.fn(),
  }),
}));

vi.mock("@/lib/workbench/terminal-service", () => ({
  terminalService: {
    getCwd: vi.fn().mockResolvedValue("/mock/cwd"),
    create: vi.fn().mockResolvedValue({ id: "mock-session", branch: "main" }),
    write: vi.fn().mockResolvedValue(undefined),
    kill: vi.fn().mockResolvedValue(undefined),
    onExit: vi.fn().mockResolvedValue(() => {}),
  },
  worktreeService: {
    create: vi.fn().mockResolvedValue({ path: "/mock/worktree", branch: "test-branch" }),
    remove: vi.fn().mockResolvedValue(undefined),
  },
}));

describe("SwarmBoardPage provider safety", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("renders even when the engine context is unavailable", async () => {
    await act(async () => {
      render(
        <MemoryRouter initialEntries={["/workbench/swarm-board"]}>
          <SwarmBoardPage />
        </MemoryRouter>,
      );
      await Promise.resolve();
    });

    expect(screen.getByTestId("swarm-board-toolbar")).toBeInTheDocument();
    expect(screen.getByTestId("react-flow-canvas")).toBeInTheDocument();
  });
});
