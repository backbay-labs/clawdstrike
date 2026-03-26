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
  Panel: ({ children }: { children?: React.ReactNode }) => <div>{children}</div>,
  useReactFlow: () => ({
    fitView: fitViewMock,
    setViewport: setViewportMock,
    getNodes: () => [],
    viewportInitialized: true,
  }),
  useViewport: () => ({ x: 0, y: 0, zoom: 1 }),
  useStore: (selector: (s: Record<string, unknown>) => unknown) =>
    selector({ transform: [0, 0, 1], nodeLookup: new Map() }),
  useOnSelectionChange: vi.fn(),
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

describe("resize recentering math", () => {
  it("shifts viewport by half the size delta", () => {
    // This tests the formula: x + (newW - oldW) / 2, y + (newH - oldH) / 2
    const viewport = { x: 100, y: 200, zoom: 1 };
    const oldW = 800, oldH = 600;
    const newW = 600, newH = 600; // sidebar opened, width reduced by 200

    const recentered = {
      x: viewport.x + (newW - oldW) / 2,  // 100 + (-200)/2 = 0
      y: viewport.y + (newH - oldH) / 2,  // 200 + 0 = 200
      zoom: viewport.zoom,
    };

    expect(recentered).toEqual({ x: 0, y: 200, zoom: 1 });
  });

  it("is a no-op when dimensions are unchanged", () => {
    const viewport = { x: 100, y: 200, zoom: 0.8 };
    const dw = 0, dh = 0;
    const recentered = {
      x: viewport.x + dw / 2,
      y: viewport.y + dh / 2,
      zoom: viewport.zoom,
    };
    expect(recentered).toEqual(viewport);
  });

  it("handles height-only resize (inspector toggle)", () => {
    const viewport = { x: 50, y: 100, zoom: 1.5 };
    const oldW = 1000, oldH = 800;
    const newW = 1000, newH = 600; // inspector opened, height reduced by 200

    const recentered = {
      x: viewport.x + (newW - oldW) / 2,  // 50 + 0 = 50
      y: viewport.y + (newH - oldH) / 2,  // 100 + (-200)/2 = 0
      zoom: viewport.zoom,
    };

    expect(recentered).toEqual({ x: 50, y: 0, zoom: 1.5 });
  });

  it("handles window grow (both dimensions increase)", () => {
    const viewport = { x: 0, y: 0, zoom: 1 };
    const oldW = 800, oldH = 600;
    const newW = 1200, newH = 900; // window maximized

    const recentered = {
      x: viewport.x + (newW - oldW) / 2,  // 0 + 400/2 = 200
      y: viewport.y + (newH - oldH) / 2,  // 0 + 300/2 = 150
      zoom: viewport.zoom,
    };

    expect(recentered).toEqual({ x: 200, y: 150, zoom: 1 });
  });
});
