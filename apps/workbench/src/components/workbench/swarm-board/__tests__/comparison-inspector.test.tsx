import React from "react";
import { act, render, screen, fireEvent } from "@testing-library/react";
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
// Mock motion/react — AnimatePresence passes children, motion.aside renders
// as a <div> preserving style and aria props for width/label assertions.
// ---------------------------------------------------------------------------

vi.mock("motion/react", () => {
  const MotionAside = React.forwardRef<
    HTMLDivElement,
    React.HTMLAttributes<HTMLDivElement> & { style?: React.CSSProperties }
  >((props, ref) => <div ref={ref} {...props} />);
  MotionAside.displayName = "MotionAside";
  const MotionDiv = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
    (props, ref) => <div ref={ref} {...props} />,
  );
  MotionDiv.displayName = "MotionDiv";
  return {
    AnimatePresence: ({ children }: { children: React.ReactNode }) => <>{children}</>,
    motion: {
      aside: MotionAside,
      div: MotionDiv,
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
// Mock comparison-inspector for isolated UI switching tests
// ---------------------------------------------------------------------------

vi.mock("../comparison-inspector", () => ({
  ComparisonInspector: ({ nodes, onClose }: { nodes: unknown[]; onClose: () => void }) => (
    <div data-testid="comparison-inspector">
      <span data-testid="comparison-count">{nodes.length}</span>
      <button data-testid="comparison-close" onClick={onClose}>close</button>
    </div>
  ),
}));

// ---------------------------------------------------------------------------
// Import real component after mocks
// ---------------------------------------------------------------------------

import { SwarmBoardInspector } from "../swarm-board-inspector";

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

function ComparisonHarness({ withInspector = false }: { withInspector?: boolean } = {}) {
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

      {withInspector && <SwarmBoardInspector />}
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

function renderHarness(opts?: { withInspector?: boolean }) {
  seedEmptyBoard();
  return render(
    <MemoryRouter>
      <SwarmBoardProvider>
        <ComparisonHarness withInspector={opts?.withInspector} />
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

describe("comparison mode UI switching", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("renders ComparisonInspector when comparisonMode is true", () => {
    renderHarness({ withInspector: true });

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

    // Comparison inspector should be rendered (via mock)
    expect(screen.getByTestId("comparison-inspector")).toBeInTheDocument();
    expect(screen.getByTestId("comparison-count").textContent).toBe("2");
  });

  it("renders existing InspectorContent when single node selected", () => {
    renderHarness({ withInspector: true });

    // Add one agent node
    act(() => {
      screen.getByTestId("add-agent-1").click();
    });

    // Select the agent node (last added node -- use the store to get correct ID)
    act(() => {
      const nodes = useSwarmBoardStore.getState().nodes;
      const agentNode = nodes.find((n) => (n.data as SwarmBoardNodeData).title === "Agent Alpha");
      if (agentNode) {
        useSwarmBoardStore.getState().actions.setSelectedNodeIds([agentNode.id]);
      }
    });

    // Comparison inspector should NOT be rendered
    expect(screen.queryByTestId("comparison-inspector")).toBeNull();
    // Single-node inspector should be present
    expect(screen.getByLabelText("Node inspector")).toBeInTheDocument();
    // Should show the agent's title
    expect(screen.getByLabelText("Node inspector")).toHaveTextContent("Agent Alpha");
  });

  it("closes comparison mode on Escape key", () => {
    renderHarness({ withInspector: true });

    // Add two nodes and multi-select
    act(() => {
      screen.getByTestId("add-agent-1").click();
    });
    act(() => {
      screen.getByTestId("add-agent-2").click();
    });
    act(() => {
      screen.getByTestId("set-multi-select").click();
    });

    // Comparison inspector visible
    expect(screen.getByTestId("comparison-inspector")).toBeInTheDocument();

    // Press Escape
    act(() => {
      fireEvent.keyDown(window, { key: "Escape" });
    });

    // Comparison inspector should be gone
    expect(screen.queryByTestId("comparison-inspector")).toBeNull();
  });

  it("inspector widens to 680px in comparison mode", () => {
    renderHarness({ withInspector: true });

    // Add two nodes and multi-select
    act(() => {
      screen.getByTestId("add-agent-1").click();
    });
    act(() => {
      screen.getByTestId("add-agent-2").click();
    });
    act(() => {
      screen.getByTestId("set-multi-select").click();
    });

    // The motion.aside (rendered as div by mock) should have width 680
    const aside = screen.getByLabelText("Node comparison");
    expect(aside.style.width).toBe("680px");
  });

  it("mixed-type selection renders comparison inspector", () => {
    renderHarness({ withInspector: true });

    // Add one agent and one receipt
    act(() => {
      screen.getByTestId("add-agent-1").click();
    });
    act(() => {
      screen.getByTestId("add-receipt-1").click();
    });

    // Multi-select both (mixed types)
    act(() => {
      screen.getByTestId("set-multi-select").click();
    });

    // Comparison inspector should render (ComparisonInspector handles the mixed routing internally)
    expect(screen.getByTestId("comparison-inspector")).toBeInTheDocument();
    expect(screen.getByTestId("comparison-count").textContent).toBe("2");
  });
});
