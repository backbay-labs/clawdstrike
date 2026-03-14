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
// Mock @xyflow/react with spies for zoom/fit functions
// ---------------------------------------------------------------------------

const mockZoomIn = vi.fn();
const mockZoomOut = vi.fn();
const mockFitView = vi.fn();
const mockGetViewport = vi.fn(() => ({ x: 0, y: 0, zoom: 1 }));
const mockGetNodes = vi.fn(() => [] as Record<string, unknown>[]);

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
    getViewport: mockGetViewport,
    fitView: mockFitView,
    zoomIn: mockZoomIn,
    zoomOut: mockZoomOut,
    getNodes: mockGetNodes,
  }),
  MarkerType: { ArrowClosed: "arrowclosed" },
  Position: { Left: "left", Right: "right", Top: "top", Bottom: "bottom" },
  Handle: () => null,
}));

const STORAGE_KEY = "clawdstrike_workbench_swarm_board";

// Import the real component after mocks
import { SwarmBoardToolbar } from "../swarm-board-toolbar";

// ---------------------------------------------------------------------------
// Harness that wraps toolbar with providers + state display
// ---------------------------------------------------------------------------

function ToolbarHarness() {
  const { state } = useSwarmBoard();

  return (
    <div>
      <pre data-testid="node-count">{state.nodes.length}</pre>
      <pre data-testid="node-types">
        {state.nodes.map((n) => (n.data as SwarmBoardNodeData).nodeType).join(",")}
      </pre>
      <pre data-testid="edge-count">{state.edges.length}</pre>
      <SwarmBoardToolbar />
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

function renderToolbar() {
  seedEmptyBoard();
  const result = render(
    <MemoryRouter>
      <SwarmBoardProvider>
        <ToolbarHarness />
      </SwarmBoardProvider>
    </MemoryRouter>,
  );
  // Clear the placeholder to get a clean board
  const clearBtn = screen.getByLabelText("Clear board");
  act(() => {
    clearBtn.click();
  });
  return result;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

beforeEach(() => {
  localStorage.clear();
  mockZoomIn.mockClear();
  mockZoomOut.mockClear();
  mockFitView.mockClear();
  mockGetNodes.mockClear();
  mockGetViewport.mockClear();
  mockGetViewport.mockReturnValue({ x: 0, y: 0, zoom: 1 });
  mockGetNodes.mockReturnValue([]);
});

describe("SwarmBoardToolbar", () => {
  describe("New Terminal button", () => {
    it("dispatches ADD_NODE with agentSession type (fallback mock mode)", async () => {
      renderToolbar();

      expect(screen.getByTestId("node-count").textContent).toBe("0");

      await act(async () => {
        screen.getByLabelText("New Terminal").click();
        // Wait for the async fallback to mock node creation
        await new Promise((r) => setTimeout(r, 50));
      });

      expect(screen.getByTestId("node-count").textContent).toBe("1");
      const types = screen.getByTestId("node-types").textContent;
      expect(types).toBe("agentSession");
    });
  });

  describe("Add Note button", () => {
    it("dispatches ADD_NODE with note type", () => {
      renderToolbar();

      act(() => {
        screen.getByLabelText("Add Note").click();
      });

      expect(screen.getByTestId("node-count").textContent).toBe("1");
      const types = screen.getByTestId("node-types").textContent;
      expect(types).toBe("note");
    });
  });

  describe("Clear button", () => {
    it("dispatches CLEAR_BOARD", async () => {
      renderToolbar();

      // Add some nodes first
      await act(async () => {
        screen.getByLabelText("New Terminal").click();
        await new Promise((r) => setTimeout(r, 50));
      });
      act(() => {
        screen.getByLabelText("Add Note").click();
      });
      expect(screen.getByTestId("node-count").textContent).toBe("2");

      // Clear
      act(() => {
        screen.getByLabelText("Clear board").click();
      });

      expect(screen.getByTestId("node-count").textContent).toBe("0");
    });
  });

  describe("Auto Layout button", () => {
    it("repositions nodes in a grid layout", async () => {
      vi.useFakeTimers();
      try {
        renderToolbar();

        await act(async () => {
          screen.getByLabelText("New Terminal").click();
          await vi.advanceTimersByTimeAsync(50);
        });
        act(() => {
          screen.getByLabelText("Add Note").click();
        });

        act(() => {
          screen.getByLabelText("Auto Layout").click();
        });

        act(() => {
          vi.advanceTimersByTime(100);
        });

        expect(mockFitView).toHaveBeenCalled();
      } finally {
        vi.useRealTimers();
      }
    });

    it("does nothing when board is empty", () => {
      vi.useFakeTimers();
      try {
        renderToolbar();

        act(() => {
          screen.getByLabelText("Auto Layout").click();
        });

        act(() => {
          vi.advanceTimersByTime(100);
        });

        expect(mockFitView).not.toHaveBeenCalled();
      } finally {
        vi.useRealTimers();
      }
    });
  });

  describe("Gather button", () => {
    it("calls fitView to center all nodes", () => {
      renderToolbar();

      act(() => {
        screen.getByLabelText("Gather").click();
      });

      expect(mockFitView).toHaveBeenCalledWith(
        expect.objectContaining({ padding: 0.2, duration: 500 }),
      );
    });
  });

  describe("Follow Active button", () => {
    it("zooms to running nodes when present", () => {
      renderToolbar();

      const runningNode = {
        id: "running-1",
        data: { status: "running", nodeType: "agentSession", title: "Active" },
        position: { x: 100, y: 100 },
      };
      mockGetNodes.mockReturnValue([runningNode]);

      act(() => {
        screen.getByLabelText("Follow Active").click();
      });

      expect(mockFitView).toHaveBeenCalledWith(
        expect.objectContaining({
          nodes: [runningNode],
          padding: 0.5,
          duration: 400,
        }),
      );
    });

    it("does nothing when no running nodes", () => {
      renderToolbar();

      mockGetNodes.mockReturnValue([
        { id: "idle-1", data: { status: "idle" }, position: { x: 0, y: 0 } },
      ]);

      act(() => {
        screen.getByLabelText("Follow Active").click();
      });

      expect(mockFitView).not.toHaveBeenCalled();
    });
  });

  describe("button aria-labels", () => {
    it("all labeled buttons have correct aria-labels", () => {
      renderToolbar();

      const expectedLabels = [
        "New Claude Session",
        "New Terminal",
        "Add Note",
        "Auto Layout",
        "Gather",
        "Follow Active",
        "Clear board",
      ];

      for (const label of expectedLabels) {
        expect(screen.getByLabelText(label)).toBeInTheDocument();
      }
    });
  });

  describe("board title", () => {
    it("displays set workspace button when no repo root", () => {
      renderToolbar();

      expect(screen.getByLabelText("Set workspace root")).toBeInTheDocument();
    });

    it("displays repo root when set", () => {
      localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify({
          boardId: "b-test",
          repoRoot: "/home/user/project",
          nodes: [
            {
              id: "n1",
              type: "note",
              position: { x: 0, y: 0 },
              data: { title: "N", status: "idle", nodeType: "note", createdAt: 0 },
            },
          ],
          edges: [],
        }),
      );

      render(
        <MemoryRouter>
          <SwarmBoardProvider>
            <ToolbarHarness />
          </SwarmBoardProvider>
        </MemoryRouter>,
      );

      expect(screen.getByText("/home/user/project")).toBeInTheDocument();
    });
  });
});
