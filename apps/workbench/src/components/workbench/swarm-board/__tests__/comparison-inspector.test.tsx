import React from "react";
import { act, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";

import {
  SwarmBoardProvider,
  useSwarmBoard,
  useSwarmBoardStore,
} from "@/features/swarm/stores/swarm-board-store";
import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";

// ---------------------------------------------------------------------------
// Mock @xyflow/react
// ---------------------------------------------------------------------------

vi.mock("@xyflow/react", () => ({
  ReactFlow: ({ children }: { children?: React.ReactNode }) => <div>{children}</div>,
  Background: () => null,
  Controls: () => null,
  MiniMap: () => null,
  Panel: ({ children }: { children?: React.ReactNode }) => <div>{children}</div>,
  ReactFlowProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  useNodesState: (initial: unknown[]) => [initial, vi.fn(), vi.fn()],
  useEdgesState: (initial: unknown[]) => [initial, vi.fn(), vi.fn()],
  useReactFlow: () => ({
    setViewport: vi.fn(),
    getViewport: () => ({ x: 0, y: 0, zoom: 1 }),
    fitView: vi.fn(),
    zoomIn: vi.fn(),
    zoomOut: vi.fn(),
    getNodes: () => [],
  }),
  useOnSelectionChange: vi.fn(),
  MarkerType: { ArrowClosed: "arrowclosed" },
  Position: { Left: "left", Right: "right", Top: "top", Bottom: "bottom" },
  Handle: () => null,
}));

// ---------------------------------------------------------------------------
// Mock motion/react
// ---------------------------------------------------------------------------

vi.mock("motion/react", () => {
  const MotionComponent = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
    (props, ref) => <div ref={ref} {...props} />,
  );
  MotionComponent.displayName = "MotionComponent";
  return {
    AnimatePresence: ({ children }: { children: React.ReactNode }) => <>{children}</>,
    motion: {
      aside: MotionComponent,
      div: MotionComponent,
    },
  };
});

vi.mock("@/lib/tauri-bridge", () => ({
  isDesktop: vi.fn(() => false),
  readTextFileFromDisk: vi.fn().mockResolvedValue(null),
}));

vi.mock("react-syntax-highlighter", () => ({
  Prism: ({ children }: { children?: React.ReactNode }) => <div>{children}</div>,
}));

vi.mock("react-syntax-highlighter/dist/cjs/styles/prism", () => ({
  atomDark: {},
}));

vi.mock("../artifact-preview-pane", () => ({
  ArtifactPreviewPane: () => <div data-testid="artifact-preview-pane">artifact-preview</div>,
}));

// ---------------------------------------------------------------------------
// Test data factories
// ---------------------------------------------------------------------------

function makeAgentNodeConfig(overrides?: Partial<SwarmBoardNodeData>) {
  return {
    nodeType: "agentSession" as const,
    title: "Agent Session",
    position: { x: 0, y: 0 },
    data: {
      status: "running" as const,
      risk: "medium" as const,
      agentModel: "opus-4.6",
      receiptCount: 5,
      ...overrides,
    },
  };
}

function makeReceiptNodeConfig(overrides?: Partial<SwarmBoardNodeData>) {
  return {
    nodeType: "receipt" as const,
    title: "Receipt",
    position: { x: 200, y: 0 },
    data: {
      status: "completed" as const,
      verdict: "allow" as const,
      guardResults: [
        { guard: "ForbiddenPathGuard", allowed: true, duration_ms: 2 },
      ],
      ...overrides,
    },
  };
}

// ---------------------------------------------------------------------------
// Harness for comparison mode testing
// ---------------------------------------------------------------------------

const STORAGE_KEY = "clawdstrike_workbench_swarm_board";

function ComparisonHarness() {
  const {
    state,
    addNode,
    selectNode,
    selectedNodes,
    comparisonMode,
  } = useSwarmBoard();

  return (
    <div>
      <pre data-testid="comparison-mode">{String(comparisonMode)}</pre>
      <pre data-testid="selected-count">{selectedNodes.length}</pre>
      <pre data-testid="inspector-open">{String(state.inspectorOpen)}</pre>
      <pre data-testid="selected-id">{state.selectedNodeId ?? "none"}</pre>
      <pre data-testid="node-count">{state.nodes.length}</pre>

      <button
        type="button"
        data-testid="add-agent-1"
        onClick={() =>
          addNode(makeAgentNodeConfig({ title: "Agent Alpha", risk: "high" }))
        }
      >
        add-agent-1
      </button>
      <button
        type="button"
        data-testid="add-agent-2"
        onClick={() =>
          addNode(makeAgentNodeConfig({ title: "Agent Beta", risk: "low" }))
        }
      >
        add-agent-2
      </button>
      <button
        type="button"
        data-testid="add-receipt-1"
        onClick={() =>
          addNode(makeReceiptNodeConfig({ title: "Receipt Alpha", verdict: "allow" }))
        }
      >
        add-receipt-1
      </button>
      <button
        type="button"
        data-testid="add-receipt-2"
        onClick={() =>
          addNode(makeReceiptNodeConfig({ title: "Receipt Beta", verdict: "deny" }))
        }
      >
        add-receipt-2
      </button>
      <button
        type="button"
        data-testid="add-diff-1"
        onClick={() =>
          addNode({
            nodeType: "diff" as const,
            title: "Diff One",
            position: { x: 400, y: 0 },
            data: {
              status: "idle" as const,
              diffSummary: { added: 3, removed: 1, files: ["src/main.rs"] },
            },
          })
        }
      >
        add-diff-1
      </button>
      <button
        type="button"
        data-testid="set-multi-select"
        onClick={() => {
          const ids = state.nodes.slice(0, 2).map((n) => n.id);
          useSwarmBoardStore.getState().actions.setSelectedNodeIds(ids);
        }}
      >
        set-multi-select
      </button>
      <button
        type="button"
        data-testid="select-first"
        onClick={() => {
          if (state.nodes.length > 0) {
            useSwarmBoardStore.getState().actions.setSelectedNodeIds([state.nodes[0].id]);
          }
        }}
      >
        select-first
      </button>
      <button
        type="button"
        data-testid="deselect-all"
        onClick={() => {
          useSwarmBoardStore.getState().actions.setSelectedNodeIds([]);
        }}
      >
        deselect-all
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function seedEmptyBoard(): void {
  localStorage.setItem(
    STORAGE_KEY,
    JSON.stringify({
      boardId: "b-test",
      repoRoot: "",
      nodes: [
        {
          id: "__placeholder__",
          type: "note",
          position: { x: 0, y: 0 },
          data: { title: "__placeholder__", status: "idle", nodeType: "note", createdAt: 0 },
        },
      ],
      edges: [],
    }),
  );
}

function renderHarness() {
  seedEmptyBoard();
  return render(
    <MemoryRouter>
      <SwarmBoardProvider>
        <ComparisonHarness />
      </SwarmBoardProvider>
    </MemoryRouter>,
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("multi-select store behavior", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("setSelectedNodeIds with 2+ IDs enables comparisonMode", () => {
    renderHarness();

    // Add two agent nodes
    act(() => {
      screen.getByTestId("add-agent-1").click();
    });
    act(() => {
      screen.getByTestId("add-agent-2").click();
    });

    // Multi-select both
    act(() => {
      screen.getByTestId("set-multi-select").click();
    });

    expect(screen.getByTestId("comparison-mode").textContent).toBe("true");
    expect(screen.getByTestId("selected-count").textContent).toBe("2");
  });

  it("setSelectedNodeIds with 1 ID keeps comparisonMode false", () => {
    renderHarness();

    // Add one node
    act(() => {
      screen.getByTestId("add-agent-1").click();
    });

    // Select only one
    act(() => {
      screen.getByTestId("select-first").click();
    });

    expect(screen.getByTestId("comparison-mode").textContent).toBe("false");
    expect(screen.getByTestId("selected-count").textContent).toBe("1");
  });

  it("setSelectedNodeIds with 0 IDs deselects all", () => {
    renderHarness();

    // Add two nodes and select them
    act(() => {
      screen.getByTestId("add-agent-1").click();
    });
    act(() => {
      screen.getByTestId("add-agent-2").click();
    });
    act(() => {
      screen.getByTestId("set-multi-select").click();
    });

    // Deselect all
    act(() => {
      screen.getByTestId("deselect-all").click();
    });

    expect(screen.getByTestId("comparison-mode").textContent).toBe("false");
    expect(screen.getByTestId("selected-count").textContent).toBe("0");
  });

  it("removeNode updates selectedNodeIds", () => {
    renderHarness();

    // Add two agent nodes
    act(() => {
      screen.getByTestId("add-agent-1").click();
    });
    act(() => {
      screen.getByTestId("add-agent-2").click();
    });

    // Multi-select both
    act(() => {
      screen.getByTestId("set-multi-select").click();
    });

    expect(screen.getByTestId("selected-count").textContent).toBe("2");

    // Get the first node's id from the store
    const firstNodeId = useSwarmBoardStore.getState().nodes[0].id;

    // Remove the first node
    act(() => {
      useSwarmBoardStore.getState().actions.removeNode(firstNodeId);
    });

    // The removed node should no longer be in selectedNodeIds
    const storeState = useSwarmBoardStore.getState();
    expect(storeState.selectedNodeIds).not.toContain(firstNodeId);
    expect(screen.getByTestId("selected-count").textContent).toBe("1");
    // With only 1 remaining, comparisonMode should be false
    expect(screen.getByTestId("comparison-mode").textContent).toBe("false");
  });
});

describe("backward compatibility", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("single-node selection still sets selectedNodeId", () => {
    renderHarness();

    // Add one agent node
    act(() => {
      screen.getByTestId("add-agent-1").click();
    });

    const nodeId = useSwarmBoardStore.getState().nodes[0].id;

    // Select single node via setSelectedNodeIds
    act(() => {
      screen.getByTestId("select-first").click();
    });

    expect(screen.getByTestId("selected-id").textContent).toBe(nodeId);
  });

  it("single-node selection opens inspector", () => {
    renderHarness();

    // Add one agent node
    act(() => {
      screen.getByTestId("add-agent-1").click();
    });

    // Select single node
    act(() => {
      screen.getByTestId("select-first").click();
    });

    expect(screen.getByTestId("inspector-open").textContent).toBe("true");
  });
});

describe("comparison mode UI switching (placeholder)", () => {
  it.todo("renders ComparisonInspector when comparisonMode is true");
  it.todo("renders existing InspectorContent when single node selected");
  it.todo("receipt comparison calls summarizeReceiptPosture with selected nodes");
  it.todo("mixed-type selection renders MixedComparison fallback");
});
