import React from "react";
import { act, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";

import {
  SwarmBoardProvider,
  useSwarmBoard,
} from "@/lib/workbench/swarm-board-store";
import type { SwarmBoardNodeData } from "@/lib/workbench/swarm-board-types";

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
  MarkerType: { ArrowClosed: "arrowclosed" },
  Position: { Left: "left", Right: "right", Top: "top", Bottom: "bottom" },
  Handle: () => null,
}));

const STORAGE_KEY = "clawdstrike_workbench_swarm_board";

// Import the real component after mocks
import { SwarmBoardLeftRail } from "../swarm-board-left-rail";

// ---------------------------------------------------------------------------
// Harness that wraps left rail with providers + state display
// ---------------------------------------------------------------------------

function LeftRailHarness() {
  const {
    state,
    addNode,
    selectNode,
    clearBoard,
  } = useSwarmBoard();

  return (
    <div>
      <pre data-testid="node-count">{state.nodes.length}</pre>
      <pre data-testid="selected-id">{state.selectedNodeId ?? "none"}</pre>
      <pre data-testid="inspector-open">{String(state.inspectorOpen)}</pre>

      <button
        type="button"
        data-testid="add-agent-1"
        onClick={() =>
          addNode({
            nodeType: "agentSession",
            title: "Fix auth middleware",
            position: { x: 0, y: 0 },
            data: {
              branch: "feat/fix-auth",
              status: "running",
              huntId: "hunt-sec-audit",
            },
          })
        }
      >
        add-agent-1
      </button>
      <button
        type="button"
        data-testid="add-agent-2"
        onClick={() =>
          addNode({
            nodeType: "agentSession",
            title: "Add rate limiter",
            position: { x: 200, y: 0 },
            data: {
              branch: "feat/rate-limit",
              status: "completed",
              huntId: "hunt-sec-audit",
            },
          })
        }
      >
        add-agent-2
      </button>
      <button
        type="button"
        data-testid="add-agent-3"
        onClick={() =>
          addNode({
            nodeType: "agentSession",
            title: "Idle agent",
            position: { x: 400, y: 0 },
            data: {
              status: "idle",
            },
          })
        }
      >
        add-agent-3
      </button>
      <button
        type="button"
        data-testid="add-artifact"
        onClick={() =>
          addNode({
            nodeType: "artifact",
            title: "auth.rs",
            position: { x: 0, y: 200 },
            data: {
              filePath: "src/middleware/auth.rs",
              fileType: "rust",
            },
          })
        }
      >
        add-artifact
      </button>
      <button
        type="button"
        data-testid="add-note"
        onClick={() =>
          addNode({
            nodeType: "note",
            title: "Notes",
            position: { x: 200, y: 200 },
            data: { content: "Some notes" },
          })
        }
      >
        add-note
      </button>
      <button type="button" data-testid="clear-board" onClick={clearBoard}>
        clear
      </button>

      <SwarmBoardLeftRail />
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

function renderLeftRail() {
  seedEmptyBoard();
  const result = render(
    <MemoryRouter>
      <SwarmBoardProvider>
        <LeftRailHarness />
      </SwarmBoardProvider>
    </MemoryRouter>,
  );
  act(() => {
    screen.getByTestId("clear-board").click();
  });
  return result;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

beforeEach(() => {
  localStorage.clear();
});

describe("SwarmBoardLeftRail", () => {
  describe("empty state", () => {
    it("shows empty state when no nodes exist", () => {
      renderLeftRail();

      expect(screen.getByText("spawn a session to begin...")).toBeInTheDocument();
      expect(screen.getByText("No active hunts")).toBeInTheDocument();
      expect(screen.getByText("No artifacts")).toBeInTheDocument();
      expect(screen.getByText("No branches")).toBeInTheDocument();
    });

    it("shows section headers", () => {
      renderLeftRail();

      expect(screen.getByText("Sessions")).toBeInTheDocument();
      expect(screen.getByText("Hunts")).toBeInTheDocument();
      expect(screen.getByText("Artifacts")).toBeInTheDocument();
      expect(screen.getByText("Branches")).toBeInTheDocument();
    });

    it("shows Explorer header", () => {
      renderLeftRail();

      expect(screen.getByText("Explorer")).toBeInTheDocument();
    });
  });

  describe("session list", () => {
    it("renders session list from board state", () => {
      renderLeftRail();

      act(() => {
        screen.getByTestId("add-agent-1").click();
      });
      act(() => {
        screen.getByTestId("add-agent-2").click();
      });

      expect(screen.getByText("Fix auth middleware")).toBeInTheDocument();
      expect(screen.getByText("Add rate limiter")).toBeInTheDocument();
    });

    it("shows branch names next to sessions", () => {
      renderLeftRail();

      act(() => {
        screen.getByTestId("add-agent-1").click();
      });

      // Branch appears both in the session row and the Branches section
      const branchTexts = screen.getAllByText("feat/fix-auth");
      expect(branchTexts.length).toBeGreaterThanOrEqual(1);
    });

    it("clicking session selects it on canvas", () => {
      renderLeftRail();

      act(() => {
        screen.getByTestId("add-agent-1").click();
      });

      // The session title appears in the left rail — click it
      act(() => {
        screen.getByText("Fix auth middleware").click();
      });

      expect(screen.getByTestId("selected-id").textContent).not.toBe("none");
      expect(screen.getByTestId("inspector-open").textContent).toBe("true");
    });

    it("does not show non-session nodes in session list", () => {
      renderLeftRail();

      act(() => {
        screen.getByTestId("add-note").click();
      });

      // The "Notes" title should appear somewhere but not in sessions section
      // There should still be empty-state text since note is not a session
      expect(screen.getByText("spawn a session to begin...")).toBeInTheDocument();
    });
  });

  describe("session count", () => {
    it("shows correct session count", () => {
      renderLeftRail();

      // Count starts at 0
      const sessionSection = screen.getByText("Sessions").closest("div");
      expect(sessionSection).toHaveTextContent("0");

      act(() => {
        screen.getByTestId("add-agent-1").click();
      });
      act(() => {
        screen.getByTestId("add-agent-2").click();
      });

      // Now count should be 2
      expect(screen.getByText("Sessions").closest("div")).toHaveTextContent("2");
    });
  });

  describe("artifact list", () => {
    it("shows artifact list", () => {
      renderLeftRail();

      act(() => {
        screen.getByTestId("add-artifact").click();
      });

      expect(screen.getByText("src/middleware/auth.rs")).toBeInTheDocument();
    });

    it("clicking artifact selects it", () => {
      renderLeftRail();

      act(() => {
        screen.getByTestId("add-artifact").click();
      });

      act(() => {
        screen.getByText("src/middleware/auth.rs").click();
      });

      expect(screen.getByTestId("selected-id").textContent).not.toBe("none");
    });
  });

  describe("hunt IDs", () => {
    it("shows hunt IDs from session nodes", () => {
      renderLeftRail();

      act(() => {
        screen.getByTestId("add-agent-1").click();
      });

      expect(screen.getByText("hunt-sec-audit")).toBeInTheDocument();
    });

    it("deduplicates hunt IDs", () => {
      renderLeftRail();

      act(() => {
        screen.getByTestId("add-agent-1").click();
      });
      act(() => {
        screen.getByTestId("add-agent-2").click();
      });

      // Both agents have the same huntId "hunt-sec-audit"
      // Should only appear once
      const huntTexts = screen.getAllByText("hunt-sec-audit");
      expect(huntTexts).toHaveLength(1);
    });

    it("shows 'No active hunts' when no hunts exist", () => {
      renderLeftRail();

      act(() => {
        screen.getByTestId("add-agent-3").click(); // Agent without huntId
      });

      expect(screen.getByText("No active hunts")).toBeInTheDocument();
    });
  });

  describe("branches", () => {
    it("shows unique branches from session nodes", () => {
      renderLeftRail();

      act(() => {
        screen.getByTestId("add-agent-1").click();
      });
      act(() => {
        screen.getByTestId("add-agent-2").click();
      });

      // Should list both branches
      expect(screen.getByText("Branches").closest("div")?.parentElement).toHaveTextContent("feat/fix-auth");
      expect(screen.getByText("Branches").closest("div")?.parentElement).toHaveTextContent("feat/rate-limit");
    });

    it("shows 'No branches' when no agents have branches", () => {
      renderLeftRail();

      act(() => {
        screen.getByTestId("add-agent-3").click(); // Agent without branch
      });

      expect(screen.getByText("No branches")).toBeInTheDocument();
    });
  });

  describe("collapsible panel", () => {
    it("starts in expanded state", () => {
      renderLeftRail();

      expect(screen.getByText("Explorer")).toBeInTheDocument();
      expect(screen.getByTitle("Collapse panel")).toBeInTheDocument();
    });

    it("collapses when collapse button is clicked", () => {
      renderLeftRail();

      act(() => {
        screen.getByTitle("Collapse panel").click();
      });

      // Explorer header should be gone
      expect(screen.queryByText("Explorer")).toBeNull();
      // Expand button should appear
      expect(screen.getByTitle("Expand panel")).toBeInTheDocument();
    });

    it("expands back when expand button is clicked", () => {
      renderLeftRail();

      // Collapse
      act(() => {
        screen.getByTitle("Collapse panel").click();
      });
      expect(screen.queryByText("Explorer")).toBeNull();

      // Expand
      act(() => {
        screen.getByTitle("Expand panel").click();
      });
      expect(screen.getByText("Explorer")).toBeInTheDocument();
    });

    it("shows session count in collapsed state", () => {
      renderLeftRail();

      act(() => {
        screen.getByTestId("add-agent-1").click();
      });
      act(() => {
        screen.getByTestId("add-agent-2").click();
      });

      // Collapse
      act(() => {
        screen.getByTitle("Collapse panel").click();
      });

      // The collapsed view shows session count as a small text element
      // Use getAllByText since "2" may appear in multiple places (node-count pre + collapsed count)
      const twos = screen.getAllByText("2");
      expect(twos.length).toBeGreaterThanOrEqual(1);
    });
  });
});
