import React from "react";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";

import SwarmBoardPage from "../swarm-board-page";

const fitViewMock = vi.fn(() => Promise.resolve(true));
const setViewportMock = vi.fn(() => Promise.resolve(true));
const setNodesMock = vi.fn();
const setEdgesMock = vi.fn();
const addEdgeMock = vi.fn();
const openAppMock = vi.fn();
let reactFlowProps: Record<string, unknown> | null = null;
let toolbarViewportController: Record<string, unknown> | null = null;
const mockStoreActions = {
  setNodes: setNodesMock,
  setEdges: setEdgesMock,
  addEdge: addEdgeMock,
};

vi.mock("@xyflow/react", () => ({
  ReactFlow: (props: Record<string, unknown> & { children?: React.ReactNode }) => {
    reactFlowProps = props;
    return <div data-testid="react-flow-mock">{props.children}</div>;
  },
  ReactFlowProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  Background: () => null,
  BackgroundVariant: { Dots: "dots" },
  MiniMap: () => null,
  useReactFlow: () => ({
    fitView: fitViewMock,
    setViewport: setViewportMock,
    viewportInitialized: true,
  }),
  applyNodeChanges: (changes: unknown, nodes: unknown) => nodes,
  applyEdgeChanges: (changes: unknown, edges: unknown) => edges,
}));

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

vi.mock("@/features/swarm/stores/swarm-engine-provider", () => ({
  SwarmEngineProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  useSwarmEngine: () => ({ engine: null, taskGraph: null }),
}));

vi.mock("@/features/swarm/coordinator-instance", () => ({
  getCoordinator: () => ({
    isConnected: false,
    outboxSize: 0,
    joinedSwarmIds: [],
  }),
}));

vi.mock("@/features/swarm/stores/swarm-board-store", () => ({
  SwarmBoardProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  useSwarmBoard: () => ({
    state: {
      nodes: [],
      edges: [],
      selectedNodeId: null,
      inspectorOpen: false,
      repoRoot: "",
    },
    selectNode: vi.fn(),
    removeNode: vi.fn(),
    addNode: vi.fn(),
    updateNode: vi.fn(),
    rfEdges: [],
    killSession: vi.fn(() => Promise.resolve()),
    spawnSession: vi.fn(() => Promise.resolve({ id: "session-1" })),
  }),
  useSwarmBoardStore: (selector: (state: { actions: typeof mockStoreActions }) => unknown) =>
    selector({ actions: mockStoreActions }),
  summarizeReceiptPosture: vi.fn(() => ({
    total: 0,
    allow: 0,
    warn: 0,
    deny: 0,
  })),
}));

vi.mock("@/features/panes/pane-store", () => ({
  usePaneStore: {
    getState: () => ({ openApp: openAppMock }),
  },
}));

vi.mock("../nodes", () => ({
  swarmBoardNodeTypes: {},
}));

vi.mock("../edges", () => ({
  swarmBoardEdgeTypes: {},
}));

vi.mock("../swarm-board-toolbar", () => ({
  SwarmBoardToolbar: ({ viewportController }: { viewportController: Record<string, unknown> }) => {
    toolbarViewportController = viewportController;
    return <div data-testid="swarm-board-toolbar-mock" />;
  },
}));

vi.mock("../swarm-board-left-rail", () => ({
  SwarmBoardLeftRail: () => <div data-testid="swarm-board-left-rail-mock" />,
}));

vi.mock("../swarm-board-inspector", () => ({
  SwarmBoardInspector: () => <div data-testid="swarm-board-inspector-mock" />,
}));

vi.mock("../swarm-board-atmosphere", () => ({
  buildSwarmBoardAtmosphere: () => ({
    state: "neutral",
    glow: "none",
    vignette: "none",
    noiseOpacity: 0.03,
  }),
}));

vi.mock("../swarm-board-canvas-controls", () => ({
  SWARM_BOARD_GRID_GAP: 20,
  SWARM_BOARD_GRID_MAJOR_GAP: 80,
  SWARM_BOARD_PAN_ON_DRAG_BUTTONS: [1],
  SWARM_BOARD_SHORTCUT_HINT: "F fit",
  nudgeSelectedBoardNodes: vi.fn(() => null),
}));

describe("SwarmBoardPage viewport wiring", () => {
  beforeEach(() => {
    reactFlowProps = null;
    toolbarViewportController = null;
    fitViewMock.mockClear();
    setViewportMock.mockClear();
    setNodesMock.mockClear();
    setEdgesMock.mockClear();
    addEdgeMock.mockClear();
    openAppMock.mockClear();
  });

  it("renders the real page in controlled viewport mode", () => {
    render(
      <MemoryRouter initialEntries={["/swarm-board"]}>
        <SwarmBoardPage />
      </MemoryRouter>,
    );

    expect(screen.getByTestId("react-flow-mock")).toBeInTheDocument();
    expect(screen.getByText("SwarmBoard")).toBeInTheDocument();
    expect(screen.getByTestId("swarm-board-toolbar-mock")).toBeInTheDocument();

    expect(toolbarViewportController).toEqual(
      expect.objectContaining({
        viewport: expect.objectContaining({ x: 0, y: 0, zoom: 1 }),
        fitBoard: expect.any(Function),
        fitNodes: expect.any(Function),
        zoomByFactor: expect.any(Function),
      }),
    );

    expect(reactFlowProps).toEqual(
      expect.objectContaining({
        viewport: expect.objectContaining({ x: 0, y: 0, zoom: 1 }),
        zoomOnScroll: false,
        zoomOnPinch: false,
        zoomOnDoubleClick: false,
        panOnScroll: false,
        minZoom: 0.08,
        maxZoom: 2,
        onViewportChange: expect.any(Function),
        onMoveStart: expect.any(Function),
        onMoveEnd: expect.any(Function),
      }),
    );
  });
});
