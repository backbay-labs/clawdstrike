import React from "react";
import { act, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";

import {
  SwarmBoardProvider,
  useSwarmBoard,
  useSwarmBoardStore,
} from "@/features/swarm/stores/swarm-board-store";
import * as swarmBoardStoreModule from "@/features/swarm/stores/swarm-board-store";
import * as tauriBridge from "@/lib/tauri-bridge";
import * as terminalSessionsModule from "@/lib/workbench/use-terminal-sessions";
import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";

// ---------------------------------------------------------------------------
// Mock @xyflow/react with spies for zoom/fit functions
// ---------------------------------------------------------------------------

const mockFitBoard = vi.fn();
const mockFitNodes = vi.fn();
const mockZoomByFactor = vi.fn();
const mockViewport = { x: 0, y: 0, zoom: 1 };

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
    getViewport: () => mockViewport,
    fitView: vi.fn(),
    zoomIn: vi.fn(),
    zoomOut: vi.fn(),
    getNodes: vi.fn(() => []),
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
      <SwarmBoardToolbar
        viewportController={{
          viewport: mockViewport,
          fitBoard: mockFitBoard,
          fitNodes: mockFitNodes,
          zoomByFactor: mockZoomByFactor,
        }}
      />
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
  mockFitBoard.mockClear();
  mockFitNodes.mockClear();
  mockZoomByFactor.mockClear();
  vi.restoreAllMocks();
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

    it("does not force /tmp when repoRoot is empty in desktop mode", async () => {
      const addNode = vi.fn();
      const dispatch = vi.fn();
      const spawnSession = vi.fn().mockResolvedValue({ id: "node-1" });

      vi.spyOn(tauriBridge, "isDesktop").mockReturnValue(true);
      vi.spyOn(swarmBoardStoreModule, "useSwarmBoard").mockReturnValue({
        addNode,
        clearBoard: vi.fn(),
        state: {
          boardId: "b-test",
          repoRoot: "",
          nodes: [],
          edges: [],
          selectedNodeId: null,
          selectedNodeIds: [],
          inspectorOpen: false,
          fileWatchRevision: 0,
          bundlePath: "",
        },
        dispatch,
      } as unknown as ReturnType<typeof swarmBoardStoreModule.useSwarmBoard>);
      vi.spyOn(terminalSessionsModule, "useTerminalSessions").mockReturnValue({
        spawnSession,
        spawnClaude: vi.fn(),
        spawnClaudeSession: vi.fn(),
        spawnWorktreeSession: vi.fn(),
        spawnTerminal: vi.fn(),
        spawnClaudeInWorktree: vi.fn(),
        spawnWorktree: vi.fn(),
        killSession: vi.fn(),
        removeNodeWithCleanup: vi.fn(),
        activeSessionCount: 0,
        totalSessionCount: 0,
        canSpawnMore: true,
        hasRepoRoot: false,
        repoRoot: "",
      } as ReturnType<typeof terminalSessionsModule.useTerminalSessions>);

      render(
        <MemoryRouter>
          <SwarmBoardToolbar
            viewportController={{
              viewport: mockViewport,
              fitBoard: mockFitBoard,
              fitNodes: mockFitNodes,
              zoomByFactor: mockZoomByFactor,
            }}
          />
        </MemoryRouter>,
      );

      await act(async () => {
        screen.getByLabelText("New Terminal").click();
        await Promise.resolve();
      });

      expect(spawnSession).toHaveBeenCalledWith(
        expect.objectContaining({
          cwd: undefined,
          title: "Terminal",
        }),
      );
      expect(addNode).not.toHaveBeenCalled();
      expect(dispatch).toHaveBeenCalledWith({ type: "SELECT_NODE", nodeId: "node-1" });
    });

    it("does not create an offline placeholder node in desktop mode when spawn fails", async () => {
      const addNode = vi.fn();
      const dispatch = vi.fn();

      vi.spyOn(tauriBridge, "isDesktop").mockReturnValue(true);
      vi.spyOn(swarmBoardStoreModule, "useSwarmBoard").mockReturnValue({
        addNode,
        clearBoard: vi.fn(),
        state: {
          boardId: "b-test",
          repoRoot: "",
          nodes: [],
          edges: [],
          selectedNodeId: null,
          selectedNodeIds: [],
          inspectorOpen: false,
          fileWatchRevision: 0,
          bundlePath: "",
        },
        dispatch,
      } as unknown as ReturnType<typeof swarmBoardStoreModule.useSwarmBoard>);
      vi.spyOn(terminalSessionsModule, "useTerminalSessions").mockReturnValue({
        spawnSession: vi.fn().mockRejectedValue(new Error("native create failed")),
        spawnClaude: vi.fn(),
        spawnClaudeSession: vi.fn(),
        spawnWorktreeSession: vi.fn(),
        spawnTerminal: vi.fn(),
        spawnClaudeInWorktree: vi.fn(),
        spawnWorktree: vi.fn(),
        killSession: vi.fn(),
        removeNodeWithCleanup: vi.fn(),
        activeSessionCount: 0,
        totalSessionCount: 0,
        canSpawnMore: true,
        hasRepoRoot: false,
        repoRoot: "",
      } as ReturnType<typeof terminalSessionsModule.useTerminalSessions>);

      render(
        <MemoryRouter>
          <SwarmBoardToolbar
            viewportController={{
              viewport: mockViewport,
              fitBoard: mockFitBoard,
              fitNodes: mockFitNodes,
              zoomByFactor: mockZoomByFactor,
            }}
          />
        </MemoryRouter>,
      );

      await act(async () => {
        screen.getByLabelText("New Terminal").click();
        await new Promise((r) => setTimeout(r, 50));
      });

      expect(addNode).not.toHaveBeenCalled();
      expect(dispatch).not.toHaveBeenCalled();
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

        expect(mockFitBoard).toHaveBeenCalledWith(
          expect.objectContaining({ padding: 0.15, duration: 400 }),
        );
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

        expect(mockFitBoard).not.toHaveBeenCalled();
      } finally {
        vi.useRealTimers();
      }
    });
  });

  describe("Gather button", () => {
    it("calls fitView to center all nodes", () => {
      renderToolbar();

      act(() => {
        screen.getByLabelText("Gather (F)").click();
      });

      expect(mockFitBoard).toHaveBeenCalledWith(
        expect.objectContaining({ padding: 0.2, duration: 500 }),
      );
    });
  });

  describe("Follow Active button", () => {
    it("zooms to running nodes when present", () => {
      renderToolbar();

      act(() => {
        useSwarmBoardStore.getState().actions.addNode({
          nodeType: "agentSession",
          title: "Active",
          position: { x: 100, y: 100 },
          data: { status: "running" },
        });
      });

      act(() => {
        screen.getByLabelText("Follow Active (Space)").click();
      });

      expect(mockFitNodes).toHaveBeenCalledWith(
        expect.objectContaining({
          0: expect.objectContaining({
            data: expect.objectContaining({ status: "running", title: "Active" }),
          }),
        }),
        expect.objectContaining({ padding: 0.5, duration: 400 }),
      );
    });

    it("does nothing when no running nodes", () => {
      renderToolbar();

      act(() => {
        useSwarmBoardStore.getState().actions.addNode({
          nodeType: "agentSession",
          title: "Idle",
          position: { x: 0, y: 0 },
          data: { status: "idle" },
        });
      });

      act(() => {
        screen.getByLabelText("Follow Active (Space)").click();
      });

      expect(mockFitNodes).not.toHaveBeenCalled();
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
        "Gather (F)",
        "Follow Active (Space)",
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
