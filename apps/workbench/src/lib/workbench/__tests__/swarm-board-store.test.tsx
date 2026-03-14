import React from "react";
import { act, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  SwarmBoardProvider,
  useSwarmBoard,
  createBoardNode,
  generateNodeId,
  createMockBoard,
  type SwarmBoardAction,
} from "../swarm-board-store";
import type {
  SwarmBoardNodeData,
  SwarmBoardEdge,
  SwarmBoardState,
  SwarmNodeType,
} from "../swarm-board-types";
import type { Node } from "@xyflow/react";

// ---------------------------------------------------------------------------
// Storage key must match the one in the store
// ---------------------------------------------------------------------------

const STORAGE_KEY = "clawdstrike_workbench_swarm_board";

/**
 * Seeds localStorage with a board that has a single placeholder node.
 * This is necessary because the store falls back to mock data when
 * persisted.nodes.length === 0. Tests that need an empty board should
 * call this, then use clearBoard after mount.
 */
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

// ---------------------------------------------------------------------------
// Test harness — exposes store state + dispatch to the test
// ---------------------------------------------------------------------------

function Harness() {
  const {
    state,
    dispatch,
    addNode,
    clearBoard,
    selectedNode,
    rfEdges,
  } = useSwarmBoard();

  return (
    <div>
      <pre data-testid="node-count">{state.nodes.length}</pre>
      <pre data-testid="edge-count">{state.edges.length}</pre>
      <pre data-testid="selected-id">{state.selectedNodeId ?? "none"}</pre>
      <pre data-testid="inspector-open">{String(state.inspectorOpen)}</pre>
      <pre data-testid="board-id">{state.boardId}</pre>
      <pre data-testid="repo-root">{state.repoRoot}</pre>
      <pre data-testid="rf-edge-count">{rfEdges.length}</pre>
      <pre data-testid="selected-node-title">
        {selectedNode?.data.title ?? "none"}
      </pre>
      <pre data-testid="node-ids">
        {state.nodes.map((n) => n.id).join(",")}
      </pre>
      <pre data-testid="edge-ids">
        {state.edges.map((e) => e.id).join(",")}
      </pre>
      <pre data-testid="node-data">
        {JSON.stringify(state.nodes.map((n) => n.data))}
      </pre>
      <button
        type="button"
        data-testid="add-agent"
        onClick={() =>
          addNode({
            nodeType: "agentSession",
            title: "Test Agent",
            position: { x: 0, y: 0 },
            data: {
              branch: "feat/test",
              status: "running",
              risk: "low",
              receiptCount: 3,
              previewLines: ["line1", "line2"],
            },
          })
        }
      >
        add-agent
      </button>
      <button
        type="button"
        data-testid="add-receipt"
        onClick={() =>
          addNode({
            nodeType: "receipt",
            title: "Receipt 1",
            position: { x: 200, y: 0 },
            data: {
              verdict: "allow",
              guardResults: [
                { guard: "ForbiddenPathGuard", allowed: true, duration_ms: 2 },
              ],
            },
          })
        }
      >
        add-receipt
      </button>
      <button
        type="button"
        data-testid="add-diff"
        onClick={() =>
          addNode({
            nodeType: "diff",
            title: "Diff 1",
            position: { x: 400, y: 0 },
            data: {
              diffSummary: {
                added: 10,
                removed: 5,
                files: ["src/main.rs", "Cargo.toml"],
              },
            },
          })
        }
      >
        add-diff
      </button>
      <button
        type="button"
        data-testid="add-note"
        onClick={() =>
          addNode({
            nodeType: "note",
            title: "Note 1",
            position: { x: 0, y: 200 },
            data: { content: "Hello world" },
          })
        }
      >
        add-note
      </button>
      <button
        type="button"
        data-testid="add-artifact"
        onClick={() =>
          addNode({
            nodeType: "artifact",
            title: "main.rs",
            position: { x: 200, y: 200 },
            data: { filePath: "src/main.rs", fileType: "rust" },
          })
        }
      >
        add-artifact
      </button>
      <button
        type="button"
        data-testid="clear-board"
        onClick={clearBoard}
      >
        clear
      </button>
      <button
        type="button"
        data-testid="set-repo-root"
        onClick={() => dispatch({ type: "SET_REPO_ROOT", repoRoot: "/home/user/project" })}
      >
        set-repo-root
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Extended harness that supports dynamic operations via data attributes
// ---------------------------------------------------------------------------

function DynamicHarness() {
  const {
    state,
    addNode,
    removeNode,
    updateNode,
    selectNode,
    addEdge,
    removeEdge,
    clearBoard,
    selectedNode,
  } = useSwarmBoard();

  const [lastNodeId, setLastNodeId] = React.useState<string>("");

  return (
    <div>
      <pre data-testid="node-count">{state.nodes.length}</pre>
      <pre data-testid="edge-count">{state.edges.length}</pre>
      <pre data-testid="selected-id">{state.selectedNodeId ?? "none"}</pre>
      <pre data-testid="inspector-open">{String(state.inspectorOpen)}</pre>
      <pre data-testid="last-node-id">{lastNodeId}</pre>
      <pre data-testid="node-ids">
        {state.nodes.map((n) => n.id).join(",")}
      </pre>
      <pre data-testid="edge-ids">
        {state.edges.map((e) => e.id).join(",")}
      </pre>
      <pre data-testid="node-data">
        {JSON.stringify(state.nodes.map((n) => n.data))}
      </pre>
      <pre data-testid="selected-node-title">
        {selectedNode?.data.title ?? "none"}
      </pre>
      <button
        type="button"
        data-testid="add-node-a"
        onClick={() => {
          const node = addNode({
            nodeType: "agentSession",
            title: "Agent A",
            position: { x: 0, y: 0 },
          });
          setLastNodeId(node.id);
        }}
      >
        add-a
      </button>
      <button
        type="button"
        data-testid="add-node-b"
        onClick={() => {
          const node = addNode({
            nodeType: "agentSession",
            title: "Agent B",
            position: { x: 200, y: 0 },
          });
          setLastNodeId(node.id);
        }}
      >
        add-b
      </button>
      <button
        type="button"
        data-testid="remove-first"
        onClick={() => {
          if (state.nodes.length > 0) {
            removeNode(state.nodes[0].id);
          }
        }}
      >
        remove-first
      </button>
      <button
        type="button"
        data-testid="update-first"
        onClick={() => {
          if (state.nodes.length > 0) {
            updateNode(state.nodes[0].id, { title: "Updated Title", status: "completed" });
          }
        }}
      >
        update-first
      </button>
      <button
        type="button"
        data-testid="select-first"
        onClick={() => {
          if (state.nodes.length > 0) {
            selectNode(state.nodes[0].id);
          }
        }}
      >
        select-first
      </button>
      <button
        type="button"
        data-testid="deselect"
        onClick={() => selectNode(null)}
      >
        deselect
      </button>
      <button
        type="button"
        data-testid="add-edge-first-second"
        onClick={() => {
          if (state.nodes.length >= 2) {
            addEdge({
              id: `edge-${state.nodes[0].id}-${state.nodes[1].id}`,
              source: state.nodes[0].id,
              target: state.nodes[1].id,
              type: "spawned",
              label: "spawned",
            });
          }
        }}
      >
        add-edge
      </button>
      <button
        type="button"
        data-testid="remove-first-edge"
        onClick={() => {
          if (state.edges.length > 0) {
            removeEdge(state.edges[0].id);
          }
        }}
      >
        remove-edge
      </button>
      <button
        type="button"
        data-testid="clear-board"
        onClick={clearBoard}
      >
        clear
      </button>
    </div>
  );
}

/**
 * Renders a harness with a clean empty board. Seeds localStorage with a
 * placeholder node (needed because the store falls back to mock data when
 * empty), then immediately clears the board after mount.
 */
function renderWithEmptyBoard(harness: React.ReactElement) {
  seedEmptyBoard();
  const result = render(
    <SwarmBoardProvider>{harness}</SwarmBoardProvider>,
  );
  act(() => {
    screen.getByTestId("clear-board").click();
  });
  return result;
}

beforeEach(() => {
  localStorage.clear();
});

// ---------------------------------------------------------------------------
// Initial state
// ---------------------------------------------------------------------------

describe("SwarmBoard initial state", () => {
  it("has a boardId and empty selection on first mount (with mock data)", () => {
    render(
      <SwarmBoardProvider>
        <Harness />
      </SwarmBoardProvider>,
    );

    // The store seeds mock data on first visit (no localStorage)
    const nodeCount = Number(screen.getByTestId("node-count").textContent);
    expect(nodeCount).toBeGreaterThan(0);
    expect(screen.getByTestId("selected-id").textContent).toBe("none");
    expect(screen.getByTestId("inspector-open").textContent).toBe("false");
    expect(screen.getByTestId("board-id").textContent).toBeTruthy();
  });

  it("restores state from localStorage when available", () => {
    const persisted = {
      boardId: "board-test123",
      repoRoot: "/home/user/project",
      nodes: [
        {
          id: "node-persisted-1",
          type: "agentSession",
          position: { x: 10, y: 20 },
          data: {
            title: "Persisted Agent",
            status: "idle",
            nodeType: "agentSession",
            createdAt: 1000,
          },
        },
      ],
      edges: [],
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(persisted));

    render(
      <SwarmBoardProvider>
        <Harness />
      </SwarmBoardProvider>,
    );

    expect(screen.getByTestId("node-count").textContent).toBe("1");
    expect(screen.getByTestId("board-id").textContent).toBe("board-test123");
    expect(screen.getByTestId("repo-root").textContent).toBe("/home/user/project");
    expect(screen.getByTestId("node-ids").textContent).toBe("node-persisted-1");
  });

  it("falls back to mock data when localStorage is empty", () => {
    render(
      <SwarmBoardProvider>
        <Harness />
      </SwarmBoardProvider>,
    );

    // Mock board has 7 nodes and 4 edges
    const mock = createMockBoard();
    expect(Number(screen.getByTestId("node-count").textContent)).toBe(mock.nodes.length);
    expect(Number(screen.getByTestId("edge-count").textContent)).toBe(mock.edges.length);
  });
});

// ---------------------------------------------------------------------------
// ADD_NODE
// ---------------------------------------------------------------------------

describe("addNode", () => {
  it("adds a node with correct defaults", () => {
    renderWithEmptyBoard(<Harness />);

    expect(screen.getByTestId("node-count").textContent).toBe("0");

    act(() => {
      screen.getByTestId("add-agent").click();
    });

    expect(screen.getByTestId("node-count").textContent).toBe("1");

    const nodeData = JSON.parse(screen.getByTestId("node-data").textContent!);
    expect(nodeData[0].title).toBe("Test Agent");
    expect(nodeData[0].status).toBe("running");
    expect(nodeData[0].nodeType).toBe("agentSession");
    expect(nodeData[0].branch).toBe("feat/test");
    expect(nodeData[0].risk).toBe("low");
    expect(nodeData[0].receiptCount).toBe(3);
    expect(nodeData[0].previewLines).toEqual(["line1", "line2"]);
    expect(nodeData[0].createdAt).toBeGreaterThan(0);
  });

  it("adds multiple nodes of different types", () => {
    renderWithEmptyBoard(<Harness />);

    act(() => {
      screen.getByTestId("add-agent").click();
      screen.getByTestId("add-receipt").click();
      screen.getByTestId("add-diff").click();
      screen.getByTestId("add-note").click();
      screen.getByTestId("add-artifact").click();
    });

    expect(screen.getByTestId("node-count").textContent).toBe("5");
  });

  it("prevents duplicate node IDs", () => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        boardId: "b1",
        repoRoot: "",
        nodes: [
          {
            id: "dup-node",
            type: "note",
            position: { x: 0, y: 0 },
            data: { title: "Existing", status: "idle", nodeType: "note", createdAt: 1 },
          },
        ],
        edges: [],
      }),
    );

    const DupHarness = () => {
      const { state, dispatch } = useSwarmBoard();
      return (
        <div>
          <pre data-testid="node-count">{state.nodes.length}</pre>
          <button
            type="button"
            data-testid="add-dup"
            onClick={() =>
              dispatch({
                type: "ADD_NODE",
                node: {
                  id: "dup-node",
                  type: "note",
                  position: { x: 50, y: 50 },
                  data: { title: "Duplicate", status: "idle", nodeType: "note", createdAt: 2 },
                },
              })
            }
          >
            add-dup
          </button>
        </div>
      );
    };

    render(
      <SwarmBoardProvider>
        <DupHarness />
      </SwarmBoardProvider>,
    );

    expect(screen.getByTestId("node-count").textContent).toBe("1");

    act(() => {
      screen.getByTestId("add-dup").click();
    });

    expect(screen.getByTestId("node-count").textContent).toBe("1");
  });
});

// ---------------------------------------------------------------------------
// REMOVE_NODE
// ---------------------------------------------------------------------------

describe("removeNode", () => {
  it("removes a node and its connected edges", () => {
    renderWithEmptyBoard(<DynamicHarness />);

    // Add two nodes and an edge between them
    act(() => {
      screen.getByTestId("add-node-a").click();
    });
    act(() => {
      screen.getByTestId("add-node-b").click();
    });
    act(() => {
      screen.getByTestId("add-edge-first-second").click();
    });

    expect(screen.getByTestId("node-count").textContent).toBe("2");
    expect(screen.getByTestId("edge-count").textContent).toBe("1");

    // Remove first node
    act(() => {
      screen.getByTestId("remove-first").click();
    });

    expect(screen.getByTestId("node-count").textContent).toBe("1");
    // Edge should also be removed because it was connected to the deleted node
    expect(screen.getByTestId("edge-count").textContent).toBe("0");
  });

  it("clears selection when the selected node is removed", () => {
    renderWithEmptyBoard(<DynamicHarness />);

    act(() => {
      screen.getByTestId("add-node-a").click();
    });
    act(() => {
      screen.getByTestId("select-first").click();
    });

    expect(screen.getByTestId("selected-id").textContent).not.toBe("none");
    expect(screen.getByTestId("inspector-open").textContent).toBe("true");

    act(() => {
      screen.getByTestId("remove-first").click();
    });

    expect(screen.getByTestId("selected-id").textContent).toBe("none");
    expect(screen.getByTestId("inspector-open").textContent).toBe("false");
  });
});

// ---------------------------------------------------------------------------
// UPDATE_NODE
// ---------------------------------------------------------------------------

describe("updateNode", () => {
  it("modifies node data via patch", () => {
    renderWithEmptyBoard(<DynamicHarness />);

    act(() => {
      screen.getByTestId("add-node-a").click();
    });

    const dataBefore = JSON.parse(screen.getByTestId("node-data").textContent!);
    expect(dataBefore[0].title).toBe("Agent A");
    expect(dataBefore[0].status).toBe("idle");

    act(() => {
      screen.getByTestId("update-first").click();
    });

    const dataAfter = JSON.parse(screen.getByTestId("node-data").textContent!);
    expect(dataAfter[0].title).toBe("Updated Title");
    expect(dataAfter[0].status).toBe("completed");
    // nodeType should be preserved (not overwritten)
    expect(dataAfter[0].nodeType).toBe("agentSession");
  });
});

// ---------------------------------------------------------------------------
// ADD_EDGE / REMOVE_EDGE
// ---------------------------------------------------------------------------

describe("addEdge / removeEdge", () => {
  it("creates an edge between two nodes", () => {
    renderWithEmptyBoard(<DynamicHarness />);

    act(() => {
      screen.getByTestId("add-node-a").click();
    });
    act(() => {
      screen.getByTestId("add-node-b").click();
    });

    expect(screen.getByTestId("edge-count").textContent).toBe("0");

    act(() => {
      screen.getByTestId("add-edge-first-second").click();
    });

    expect(screen.getByTestId("edge-count").textContent).toBe("1");
  });

  it("prevents duplicate edge IDs", () => {
    renderWithEmptyBoard(<DynamicHarness />);

    act(() => {
      screen.getByTestId("add-node-a").click();
    });
    act(() => {
      screen.getByTestId("add-node-b").click();
    });
    act(() => {
      screen.getByTestId("add-edge-first-second").click();
    });
    act(() => {
      screen.getByTestId("add-edge-first-second").click();
    });

    expect(screen.getByTestId("edge-count").textContent).toBe("1");
  });

  it("removes an edge by id", () => {
    renderWithEmptyBoard(<DynamicHarness />);

    act(() => {
      screen.getByTestId("add-node-a").click();
    });
    act(() => {
      screen.getByTestId("add-node-b").click();
    });
    act(() => {
      screen.getByTestId("add-edge-first-second").click();
    });

    expect(screen.getByTestId("edge-count").textContent).toBe("1");

    act(() => {
      screen.getByTestId("remove-first-edge").click();
    });

    expect(screen.getByTestId("edge-count").textContent).toBe("0");
  });
});

// ---------------------------------------------------------------------------
// SELECT_NODE / DESELECT
// ---------------------------------------------------------------------------

describe("selectNode / deselectNode", () => {
  it("sets selectedNodeId and opens inspector", () => {
    renderWithEmptyBoard(<DynamicHarness />);

    act(() => {
      screen.getByTestId("add-node-a").click();
    });
    act(() => {
      screen.getByTestId("select-first").click();
    });

    expect(screen.getByTestId("selected-id").textContent).not.toBe("none");
    expect(screen.getByTestId("inspector-open").textContent).toBe("true");
    expect(screen.getByTestId("selected-node-title").textContent).toBe("Agent A");
  });

  it("clears selection on deselect", () => {
    renderWithEmptyBoard(<DynamicHarness />);

    act(() => {
      screen.getByTestId("add-node-a").click();
    });
    act(() => {
      screen.getByTestId("select-first").click();
    });

    expect(screen.getByTestId("inspector-open").textContent).toBe("true");

    act(() => {
      screen.getByTestId("deselect").click();
    });

    expect(screen.getByTestId("selected-id").textContent).toBe("none");
    expect(screen.getByTestId("inspector-open").textContent).toBe("false");
    expect(screen.getByTestId("selected-node-title").textContent).toBe("none");
  });
});

// ---------------------------------------------------------------------------
// CLEAR_BOARD
// ---------------------------------------------------------------------------

describe("clearBoard", () => {
  it("removes all nodes, edges, and clears selection", () => {
    renderWithEmptyBoard(<DynamicHarness />);

    act(() => {
      screen.getByTestId("add-node-a").click();
    });
    act(() => {
      screen.getByTestId("add-node-b").click();
    });
    act(() => {
      screen.getByTestId("add-edge-first-second").click();
    });
    act(() => {
      screen.getByTestId("select-first").click();
    });

    expect(screen.getByTestId("node-count").textContent).toBe("2");
    expect(screen.getByTestId("edge-count").textContent).toBe("1");
    expect(screen.getByTestId("inspector-open").textContent).toBe("true");

    act(() => {
      screen.getByTestId("clear-board").click();
    });

    expect(screen.getByTestId("node-count").textContent).toBe("0");
    expect(screen.getByTestId("edge-count").textContent).toBe("0");
    expect(screen.getByTestId("selected-id").textContent).toBe("none");
    expect(screen.getByTestId("inspector-open").textContent).toBe("false");
  });
});

// ---------------------------------------------------------------------------
// SET_REPO_ROOT
// ---------------------------------------------------------------------------

describe("SET_REPO_ROOT", () => {
  it("sets the repo root path", () => {
    renderWithEmptyBoard(<Harness />);

    expect(screen.getByTestId("repo-root").textContent).toBe("");

    act(() => {
      screen.getByTestId("set-repo-root").click();
    });

    expect(screen.getByTestId("repo-root").textContent).toBe("/home/user/project");
  });
});

// ---------------------------------------------------------------------------
// Layout persistence (save/restore from localStorage)
// ---------------------------------------------------------------------------

describe("layout persistence", () => {
  it("persists board state to localStorage after changes", () => {
    vi.useFakeTimers();
    try {
      seedEmptyBoard();

      render(
        <SwarmBoardProvider>
          <Harness />
        </SwarmBoardProvider>,
      );

      // Clear the placeholder node, then add a real one
      act(() => {
        screen.getByTestId("clear-board").click();
      });

      act(() => {
        screen.getByTestId("add-agent").click();
      });

      // Advance past debounce timeout (500ms)
      act(() => {
        vi.advanceTimersByTime(600);
      });

      const raw = localStorage.getItem(STORAGE_KEY);
      expect(raw).not.toBeNull();
      const parsed = JSON.parse(raw!);
      expect(parsed.nodes).toHaveLength(1);
      expect(parsed.nodes[0].data.title).toBe("Test Agent");
    } finally {
      vi.useRealTimers();
    }
  });

  it("restores nodes and edges from localStorage", () => {
    const testNodes = [
      {
        id: "persist-n1",
        type: "agentSession",
        position: { x: 100, y: 200 },
        data: {
          title: "Persisted Agent 1",
          status: "running",
          nodeType: "agentSession",
          createdAt: 1000,
        },
      },
      {
        id: "persist-n2",
        type: "receipt",
        position: { x: 300, y: 200 },
        data: {
          title: "Persisted Receipt",
          status: "completed",
          nodeType: "receipt",
          verdict: "allow",
          createdAt: 2000,
        },
      },
    ];

    const testEdges = [
      {
        id: "persist-e1",
        source: "persist-n1",
        target: "persist-n2",
        type: "receipt",
      },
    ];

    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        boardId: "board-persisted",
        repoRoot: "/persisted/root",
        nodes: testNodes,
        edges: testEdges,
      }),
    );

    render(
      <SwarmBoardProvider>
        <Harness />
      </SwarmBoardProvider>,
    );

    expect(screen.getByTestId("node-count").textContent).toBe("2");
    expect(screen.getByTestId("edge-count").textContent).toBe("1");
    expect(screen.getByTestId("board-id").textContent).toBe("board-persisted");
    expect(screen.getByTestId("repo-root").textContent).toBe("/persisted/root");
    expect(screen.getByTestId("node-ids").textContent).toContain("persist-n1");
    expect(screen.getByTestId("node-ids").textContent).toContain("persist-n2");
    expect(screen.getByTestId("edge-ids").textContent).toContain("persist-e1");
  });
});

// ---------------------------------------------------------------------------
// Board state serialization/deserialization roundtrip
// ---------------------------------------------------------------------------

describe("board state serialization roundtrip", () => {
  it("roundtrips through JSON without data loss", () => {
    vi.useFakeTimers();
    try {
      seedEmptyBoard();

      const { unmount } = render(
        <SwarmBoardProvider>
          <Harness />
        </SwarmBoardProvider>,
      );

      // Clear the placeholder then add real nodes
      act(() => {
        screen.getByTestId("clear-board").click();
      });

      act(() => {
        screen.getByTestId("add-agent").click();
        screen.getByTestId("add-receipt").click();
      });

      // Wait for persistence
      act(() => {
        vi.advanceTimersByTime(600);
      });

      const savedRaw = localStorage.getItem(STORAGE_KEY);
      expect(savedRaw).not.toBeNull();

      unmount();

      // Re-render with the persisted data
      render(
        <SwarmBoardProvider>
          <Harness />
        </SwarmBoardProvider>,
      );

      expect(screen.getByTestId("node-count").textContent).toBe("2");
      const nodeData = JSON.parse(screen.getByTestId("node-data").textContent!);
      expect(nodeData.some((d: SwarmBoardNodeData) => d.title === "Test Agent")).toBe(true);
      expect(nodeData.some((d: SwarmBoardNodeData) => d.title === "Receipt 1")).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });
});

// ---------------------------------------------------------------------------
// TOGGLE_INSPECTOR
// ---------------------------------------------------------------------------

describe("TOGGLE_INSPECTOR", () => {
  it("toggles inspector open/closed", () => {
    seedEmptyBoard();

    const ToggleHarness = () => {
      const { state, dispatch } = useSwarmBoard();
      return (
        <div>
          <pre data-testid="inspector-open">{String(state.inspectorOpen)}</pre>
          <pre data-testid="selected-id">{state.selectedNodeId ?? "none"}</pre>
          <button
            type="button"
            data-testid="toggle"
            onClick={() => dispatch({ type: "TOGGLE_INSPECTOR" })}
          >
            toggle
          </button>
          <button
            type="button"
            data-testid="open"
            onClick={() => dispatch({ type: "TOGGLE_INSPECTOR", open: true })}
          >
            open
          </button>
          <button
            type="button"
            data-testid="close"
            onClick={() => dispatch({ type: "TOGGLE_INSPECTOR", open: false })}
          >
            close
          </button>
        </div>
      );
    };

    render(
      <SwarmBoardProvider>
        <ToggleHarness />
      </SwarmBoardProvider>,
    );

    expect(screen.getByTestId("inspector-open").textContent).toBe("false");

    act(() => {
      screen.getByTestId("open").click();
    });
    expect(screen.getByTestId("inspector-open").textContent).toBe("true");

    act(() => {
      screen.getByTestId("close").click();
    });
    expect(screen.getByTestId("inspector-open").textContent).toBe("false");
    // Closing inspector also clears selection
    expect(screen.getByTestId("selected-id").textContent).toBe("none");

    act(() => {
      screen.getByTestId("toggle").click();
    });
    expect(screen.getByTestId("inspector-open").textContent).toBe("true");

    act(() => {
      screen.getByTestId("toggle").click();
    });
    expect(screen.getByTestId("inspector-open").textContent).toBe("false");
  });
});

// ---------------------------------------------------------------------------
// rfEdges (React Flow edge conversion)
// ---------------------------------------------------------------------------

describe("rfEdges", () => {
  it("converts SwarmBoardEdge to React Flow Edge format", () => {
    // Use the mock board which has edges with labels and types
    render(
      <SwarmBoardProvider>
        <Harness />
      </SwarmBoardProvider>,
    );

    const rfEdgeCount = Number(screen.getByTestId("rf-edge-count").textContent);
    const edgeCount = Number(screen.getByTestId("edge-count").textContent);
    expect(rfEdgeCount).toBe(edgeCount);
    expect(rfEdgeCount).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// useSwarmBoard hook outside provider
// ---------------------------------------------------------------------------

describe("useSwarmBoard hook outside provider", () => {
  it("throws when used outside SwarmBoardProvider", () => {
    // Using a class-based error boundary
    class TestErrorBoundary extends React.Component<
      { children: React.ReactNode },
      { error: string | null }
    > {
      state = { error: null as string | null };
      static getDerivedStateFromError(error: Error) {
        return { error: error.message };
      }
      render() {
        if (this.state.error) return <pre data-testid="error">{this.state.error}</pre>;
        return this.props.children;
      }
    }

    const BadComponent = () => {
      useSwarmBoard();
      return null;
    };

    render(
      <TestErrorBoundary>
        <BadComponent />
      </TestErrorBoundary>,
    );

    expect(screen.getByTestId("error").textContent).toContain(
      "useSwarmBoard must be used within SwarmBoardProvider",
    );
  });
});

// ---------------------------------------------------------------------------
// createBoardNode factory
// ---------------------------------------------------------------------------

describe("createBoardNode", () => {
  it("creates a node with the correct type and default position", () => {
    const node = createBoardNode({
      nodeType: "agentSession",
      title: "Factory Test",
    });

    expect(node.type).toBe("agentSession");
    expect(node.data.title).toBe("Factory Test");
    expect(node.data.status).toBe("idle");
    expect(node.data.nodeType).toBe("agentSession");
    expect(node.data.createdAt).toBeGreaterThan(0);
    expect(node.position).toBeDefined();
    expect(node.id).toBeTruthy();
    expect(node.width).toBe(380);
    expect(node.height).toBe(280);
  });

  it("sets custom position when provided", () => {
    const node = createBoardNode({
      nodeType: "note",
      title: "Note",
      position: { x: 42, y: 84 },
    });

    expect(node.position).toEqual({ x: 42, y: 84 });
  });

  it("merges custom data with defaults", () => {
    const node = createBoardNode({
      nodeType: "receipt",
      title: "Receipt",
      data: { verdict: "deny", guardResults: [] },
    });

    expect(node.data.verdict).toBe("deny");
    expect(node.data.guardResults).toEqual([]);
    expect(node.data.title).toBe("Receipt");
    expect(node.data.status).toBe("idle");
  });

  it("creates different dimensions per node type", () => {
    const agent = createBoardNode({ nodeType: "agentSession", title: "A" });
    const artifact = createBoardNode({ nodeType: "artifact", title: "B" });
    const diff = createBoardNode({ nodeType: "diff", title: "C" });
    const note = createBoardNode({ nodeType: "note", title: "D" });
    const receipt = createBoardNode({ nodeType: "receipt", title: "E" });
    const task = createBoardNode({ nodeType: "terminalTask", title: "F" });

    expect(agent.width).toBe(380);
    expect(artifact.width).toBe(240);
    expect(diff.width).toBe(280);
    expect(note.width).toBe(260);
    expect(receipt.width).toBe(300);
    expect(task.width).toBe(300);
  });
});

// ---------------------------------------------------------------------------
// generateNodeId
// ---------------------------------------------------------------------------

describe("generateNodeId", () => {
  it("generates unique IDs with the given prefix", () => {
    const id1 = generateNodeId("test");
    const id2 = generateNodeId("test");

    expect(id1).not.toBe(id2);
    expect(id1).toMatch(/^test-/);
    expect(id2).toMatch(/^test-/);
  });

  it("uses default prefix when none provided", () => {
    const id = generateNodeId();
    expect(id).toMatch(/^sbn-/);
  });
});

// ---------------------------------------------------------------------------
// createMockBoard
// ---------------------------------------------------------------------------

describe("createMockBoard", () => {
  it("returns nodes and edges for a demo board", () => {
    const mock = createMockBoard();

    expect(mock.nodes.length).toBeGreaterThanOrEqual(5);
    expect(mock.edges.length).toBeGreaterThanOrEqual(3);

    // Should have at least one of each type
    const nodeTypes = mock.nodes.map((n) => n.data.nodeType);
    expect(nodeTypes).toContain("agentSession");
    expect(nodeTypes).toContain("receipt");
    expect(nodeTypes).toContain("diff");
    expect(nodeTypes).toContain("artifact");
    expect(nodeTypes).toContain("note");

    // All edges should reference existing nodes
    const nodeIds = new Set(mock.nodes.map((n) => n.id));
    for (const edge of mock.edges) {
      expect(nodeIds.has(edge.source)).toBe(true);
      expect(nodeIds.has(edge.target)).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// LOAD action
// ---------------------------------------------------------------------------

describe("LOAD action", () => {
  it("replaces state with provided data", () => {
    seedEmptyBoard();

    const LoadHarness = () => {
      const { state, dispatch } = useSwarmBoard();
      return (
        <div>
          <pre data-testid="node-count">{state.nodes.length}</pre>
          <pre data-testid="repo-root">{state.repoRoot}</pre>
          <button
            type="button"
            data-testid="load"
            onClick={() =>
              dispatch({
                type: "LOAD",
                state: {
                  repoRoot: "/loaded/root",
                  nodes: [
                    {
                      id: "loaded-1",
                      type: "note",
                      position: { x: 0, y: 0 },
                      data: { title: "Loaded", status: "idle", nodeType: "note", createdAt: 1 },
                    },
                  ],
                },
              })
            }
          >
            load
          </button>
        </div>
      );
    };

    render(
      <SwarmBoardProvider>
        <LoadHarness />
      </SwarmBoardProvider>,
    );

    act(() => {
      screen.getByTestId("load").click();
    });

    expect(screen.getByTestId("node-count").textContent).toBe("1");
    expect(screen.getByTestId("repo-root").textContent).toBe("/loaded/root");
  });
});

// ---------------------------------------------------------------------------
// Edge cases: rapid successive ADD_NODE dispatches
// ---------------------------------------------------------------------------

describe("edge case: rapid successive ADD_NODE", () => {
  it("handles rapid successive ADD_NODE dispatches correctly", () => {
    renderWithEmptyBoard(<DynamicHarness />);

    // Rapidly add multiple nodes in a single act
    act(() => {
      screen.getByTestId("add-node-a").click();
      screen.getByTestId("add-node-b").click();
    });

    expect(screen.getByTestId("node-count").textContent).toBe("2");
  });

  it("handles rapid add followed by remove", () => {
    renderWithEmptyBoard(<DynamicHarness />);

    act(() => {
      screen.getByTestId("add-node-a").click();
    });
    act(() => {
      screen.getByTestId("add-node-b").click();
    });
    act(() => {
      screen.getByTestId("remove-first").click();
    });

    expect(screen.getByTestId("node-count").textContent).toBe("1");
  });
});

// ---------------------------------------------------------------------------
// Edge cases: removing/updating non-existent nodes
// ---------------------------------------------------------------------------

describe("edge case: operations on non-existent nodes", () => {
  it("removing a node that does not exist is a no-op", () => {
    seedEmptyBoard();

    const NoOpHarness = () => {
      const { state, removeNode, addNode } = useSwarmBoard();
      return (
        <div>
          <pre data-testid="node-count">{state.nodes.length}</pre>
          <button
            type="button"
            data-testid="add"
            onClick={() =>
              addNode({
                nodeType: "note",
                title: "Note",
                position: { x: 0, y: 0 },
              })
            }
          >
            add
          </button>
          <button
            type="button"
            data-testid="remove-nonexistent"
            onClick={() => removeNode("node-does-not-exist")}
          >
            remove
          </button>
          <button
            type="button"
            data-testid="clear-board"
            onClick={() => {
              // clear via dispatch is available via the store
            }}
          >
            clear
          </button>
        </div>
      );
    };

    render(
      <SwarmBoardProvider>
        <NoOpHarness />
      </SwarmBoardProvider>,
    );

    // Add a node first
    act(() => {
      screen.getByTestId("add").click();
    });
    expect(screen.getByTestId("node-count").textContent).toBe("2"); // placeholder + new

    // Remove a non-existent node — count should remain the same
    act(() => {
      screen.getByTestId("remove-nonexistent").click();
    });
    expect(screen.getByTestId("node-count").textContent).toBe("2");
  });

  it("updating a node that does not exist is a no-op", () => {
    seedEmptyBoard();

    const UpdateNoOpHarness = () => {
      const { state, updateNode, addNode } = useSwarmBoard();
      return (
        <div>
          <pre data-testid="node-count">{state.nodes.length}</pre>
          <pre data-testid="node-data">
            {JSON.stringify(state.nodes.map((n) => n.data))}
          </pre>
          <button
            type="button"
            data-testid="add"
            onClick={() =>
              addNode({
                nodeType: "note",
                title: "Original",
                position: { x: 0, y: 0 },
              })
            }
          >
            add
          </button>
          <button
            type="button"
            data-testid="update-nonexistent"
            onClick={() =>
              updateNode("node-does-not-exist", { title: "Should Not Appear" })
            }
          >
            update
          </button>
        </div>
      );
    };

    render(
      <SwarmBoardProvider>
        <UpdateNoOpHarness />
      </SwarmBoardProvider>,
    );

    act(() => {
      screen.getByTestId("add").click();
    });

    const dataBefore = screen.getByTestId("node-data").textContent;

    act(() => {
      screen.getByTestId("update-nonexistent").click();
    });

    const dataAfter = screen.getByTestId("node-data").textContent;
    // Data should be unchanged since we tried to update a non-existent node
    expect(dataAfter).toBe(dataBefore);
  });
});

// ---------------------------------------------------------------------------
// Edge case: duplicate edge prevention
// ---------------------------------------------------------------------------

describe("edge case: duplicate edge prevention", () => {
  it("adding an edge with duplicate ID is prevented", () => {
    renderWithEmptyBoard(<DynamicHarness />);

    act(() => {
      screen.getByTestId("add-node-a").click();
    });
    act(() => {
      screen.getByTestId("add-node-b").click();
    });

    // Add edge twice
    act(() => {
      screen.getByTestId("add-edge-first-second").click();
    });
    expect(screen.getByTestId("edge-count").textContent).toBe("1");

    act(() => {
      screen.getByTestId("add-edge-first-second").click();
    });
    expect(screen.getByTestId("edge-count").textContent).toBe("1");
  });
});

// ---------------------------------------------------------------------------
// Edge case: board with many nodes (performance baseline)
// ---------------------------------------------------------------------------

describe("edge case: board with many nodes", () => {
  it("handles 20+ nodes correctly", () => {
    seedEmptyBoard();

    const ManyNodesHarness = () => {
      const { state, addNode, clearBoard } = useSwarmBoard();
      return (
        <div>
          <pre data-testid="node-count">{state.nodes.length}</pre>
          <button
            type="button"
            data-testid="add-many"
            onClick={() => {
              for (let i = 0; i < 25; i++) {
                addNode({
                  nodeType: "note",
                  title: `Node ${i}`,
                  position: { x: i * 50, y: 0 },
                });
              }
            }}
          >
            add-many
          </button>
          <button
            type="button"
            data-testid="clear-board"
            onClick={clearBoard}
          >
            clear
          </button>
        </div>
      );
    };

    render(
      <SwarmBoardProvider>
        <ManyNodesHarness />
      </SwarmBoardProvider>,
    );

    // Clear the placeholder
    act(() => {
      screen.getByTestId("clear-board").click();
    });

    act(() => {
      screen.getByTestId("add-many").click();
    });

    expect(Number(screen.getByTestId("node-count").textContent)).toBe(25);
  });
});

// ---------------------------------------------------------------------------
// Edge case: concurrent add + select + remove
// ---------------------------------------------------------------------------

describe("edge case: concurrent operations", () => {
  it("handles add while selecting while removing", () => {
    renderWithEmptyBoard(<DynamicHarness />);

    // Add two nodes
    act(() => {
      screen.getByTestId("add-node-a").click();
    });
    act(() => {
      screen.getByTestId("add-node-b").click();
    });

    // Select first, then remove it in one act
    act(() => {
      screen.getByTestId("select-first").click();
    });
    expect(screen.getByTestId("inspector-open").textContent).toBe("true");

    act(() => {
      screen.getByTestId("remove-first").click();
    });
    // Selection and inspector should be cleared
    expect(screen.getByTestId("selected-id").textContent).toBe("none");
    expect(screen.getByTestId("inspector-open").textContent).toBe("false");
    expect(screen.getByTestId("node-count").textContent).toBe("1");
  });
});

// ---------------------------------------------------------------------------
// Edge case: LOAD action with partial state
// ---------------------------------------------------------------------------

describe("edge case: LOAD with partial state", () => {
  it("LOAD with missing fields uses defaults", () => {
    seedEmptyBoard();

    const PartialLoadHarness = () => {
      const { state, dispatch, clearBoard } = useSwarmBoard();
      return (
        <div>
          <pre data-testid="node-count">{state.nodes.length}</pre>
          <pre data-testid="edge-count">{state.edges.length}</pre>
          <pre data-testid="repo-root">{state.repoRoot}</pre>
          <pre data-testid="board-id">{state.boardId}</pre>
          <button
            type="button"
            data-testid="clear-board"
            onClick={clearBoard}
          >
            clear
          </button>
          <button
            type="button"
            data-testid="load-partial"
            onClick={() =>
              dispatch({
                type: "LOAD",
                state: {
                  repoRoot: "/partial/root",
                  // Missing nodes and edges — should keep existing
                },
              })
            }
          >
            load-partial
          </button>
          <button
            type="button"
            data-testid="load-nodes-only"
            onClick={() =>
              dispatch({
                type: "LOAD",
                state: {
                  nodes: [
                    {
                      id: "loaded-1",
                      type: "note",
                      position: { x: 0, y: 0 },
                      data: { title: "Loaded Node", status: "idle", nodeType: "note", createdAt: 1 },
                    },
                  ],
                  // Missing edges — should keep existing
                },
              })
            }
          >
            load-nodes-only
          </button>
        </div>
      );
    };

    render(
      <SwarmBoardProvider>
        <PartialLoadHarness />
      </SwarmBoardProvider>,
    );

    // Clear the placeholder
    act(() => {
      screen.getByTestId("clear-board").click();
    });

    // LOAD with only repoRoot — nodes and edges should remain empty (kept from current state)
    act(() => {
      screen.getByTestId("load-partial").click();
    });
    expect(screen.getByTestId("repo-root").textContent).toBe("/partial/root");
    expect(screen.getByTestId("node-count").textContent).toBe("0");
    expect(screen.getByTestId("edge-count").textContent).toBe("0");

    // LOAD with only nodes — edges should remain empty
    act(() => {
      screen.getByTestId("load-nodes-only").click();
    });
    expect(screen.getByTestId("node-count").textContent).toBe("1");
    expect(screen.getByTestId("edge-count").textContent).toBe("0");
  });
});
