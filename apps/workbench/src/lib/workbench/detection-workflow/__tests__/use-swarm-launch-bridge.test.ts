/**
 * Tests for the bidirectional editor <-> swarm-board bridge.
 *
 * Validates that useSwarmLaunch writes directly to the Zustand swarm-board
 * store (no DOM events, no localStorage fallback) and that navigation
 * targets point to /swarm-board.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { useSwarmBoardStore } from "@/features/swarm/stores/swarm-board-store";
import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";
import type { Node } from "@xyflow/react";

// ---------------------------------------------------------------------------
// We import the non-hook dispatch function and the SWARM_LAUNCH_EVENT
// constant from use-swarm-launch.ts. The dispatch function is the core
// logic we're testing; the hook is a thin React wrapper around it.
// ---------------------------------------------------------------------------

// Mock @xyflow/react (required by swarm-board-store transitive import)
vi.mock("@xyflow/react", () => ({
  MarkerType: { ArrowClosed: "arrowclosed" },
  Position: { Left: "left", Right: "right", Top: "top", Bottom: "bottom" },
}));

// ---------------------------------------------------------------------------
// Since dispatchSwarmNodes is a module-private function, we test it
// indirectly through the module. We need to use the actual store.
// We'll re-import after mocks are set.
// ---------------------------------------------------------------------------

import {
  type SwarmLaunchPayload,
} from "../use-swarm-launch";

// ---------------------------------------------------------------------------
// Helper to create a fake pre-built node (as buildPayload produces)
// ---------------------------------------------------------------------------

function makeFakeNode(id: string, title: string): Node<SwarmBoardNodeData> {
  return {
    id,
    type: "artifact",
    position: { x: 100, y: 100 },
    data: {
      title,
      status: "idle" as const,
      nodeType: "artifact" as const,
      createdAt: Date.now(),
      filePath: `/path/to/${id}.ts`,
    },
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("useSwarmLaunch Zustand bridge", () => {
  beforeEach(() => {
    // Reset the Zustand store to a clean state before each test
    useSwarmBoardStore.getState().actions.clearBoard();
  });

  describe("dispatchSwarmNodes writes to Zustand store", () => {
    it("Test 1: addNodeDirect is called for each node in payload", async () => {
      // We need to exercise dispatchSwarmNodes. Since it's not exported
      // directly, we spy on the store's addNodeDirect action.
      const addNodeDirectSpy = vi.spyOn(
        useSwarmBoardStore.getState().actions,
        "addNodeDirect",
      );

      // Dynamic import to get the module-level function
      // We use a workaround: call the hook's internal logic via the module
      const { _dispatchSwarmNodes } = await import("../use-swarm-launch");

      const node1 = makeFakeNode("node-1", "Rule A");
      const node2 = makeFakeNode("node-2", "Rule B");

      _dispatchSwarmNodes({ nodes: [node1, node2], edges: [] });

      expect(addNodeDirectSpy).toHaveBeenCalledTimes(2);
      expect(addNodeDirectSpy).toHaveBeenCalledWith(node1);
      expect(addNodeDirectSpy).toHaveBeenCalledWith(node2);

      addNodeDirectSpy.mockRestore();
    });

    it("Test 2: addEdge is called for each edge in payload", async () => {
      const addEdgeSpy = vi.spyOn(
        useSwarmBoardStore.getState().actions,
        "addEdge",
      );

      const { _dispatchSwarmNodes } = await import("../use-swarm-launch");

      const node1 = makeFakeNode("node-a", "Node A");
      const edge1 = {
        id: "edge-a-b",
        source: "node-a",
        target: "node-b",
        type: "artifact" as const,
        label: "evidence",
      };

      _dispatchSwarmNodes({ nodes: [node1], edges: [edge1] });

      expect(addEdgeSpy).toHaveBeenCalledTimes(1);
      expect(addEdgeSpy).toHaveBeenCalledWith(edge1);

      addEdgeSpy.mockRestore();
    });

    it("Test 7: Nodes dispatched via Zustand are immediately visible in store state", async () => {
      const { _dispatchSwarmNodes } = await import("../use-swarm-launch");

      const node = makeFakeNode("node-vis", "Visible Node");
      _dispatchSwarmNodes({ nodes: [node], edges: [] });

      const storeNodes = useSwarmBoardStore.getState().nodes;
      expect(storeNodes.some((n) => n.id === "node-vis")).toBe(true);
    });

    it("Test 8: No direct localStorage.setItem calls in dispatchSwarmNodes", async () => {
      const setItemSpy = vi.spyOn(Storage.prototype, "setItem");

      const { _dispatchSwarmNodes } = await import("../use-swarm-launch");

      const node = makeFakeNode("node-ls", "LS Test Node");
      _dispatchSwarmNodes({ nodes: [node], edges: [] });

      // The function itself should NOT call localStorage.setItem.
      // (The Zustand store's internal persistence is separate and uses
      // a debounced timer, so it won't fire synchronously.)
      const directCalls = setItemSpy.mock.calls.filter(
        ([key]) => key === "clawdstrike_workbench_swarm_board",
      );
      expect(directCalls).toHaveLength(0);

      setItemSpy.mockRestore();
    });
  });

  describe("navigation targets", () => {
    it("Test 3: openReviewSwarm navigates to /swarm-board (not /lab)", async () => {
      // Read the source file and check that all onNavigate calls use /swarm-board
      const fs = await import("fs");
      const path = await import("path");
      const srcPath = path.resolve(
        __dirname,
        "..",
        "use-swarm-launch.ts",
      );
      const source = fs.readFileSync(srcPath, "utf-8");

      // Should have /swarm-board navigation
      expect(source).toContain('"/swarm-board"');
    });

    it("Test 4: No /lab navigation targets remain in use-swarm-launch", async () => {
      const fs = await import("fs");
      const path = await import("path");
      const srcPath = path.resolve(
        __dirname,
        "..",
        "use-swarm-launch.ts",
      );
      const source = fs.readFileSync(srcPath, "utf-8");

      // The string "/lab" should NOT appear as a navigation target.
      // It might appear in comments or variable names (like labRun), but
      // not as a literal onNavigate("/lab") call.
      const navMatches = source.match(/onNavigate\?\.\("\/lab"\)/g);
      expect(navMatches).toBeNull();
    });

    it("Test 5: No window.dispatchEvent in dispatchSwarmNodes", async () => {
      const fs = await import("fs");
      const path = await import("path");
      const srcPath = path.resolve(
        __dirname,
        "..",
        "use-swarm-launch.ts",
      );
      const source = fs.readFileSync(srcPath, "utf-8");

      // The dispatch function should no longer use window.dispatchEvent
      // Check that the CustomEvent/dispatchEvent pattern is removed
      // from the dispatchSwarmNodes function body
      const dispatchFnMatch = source.match(
        /function\s+(?:_)?dispatchSwarmNodes[\s\S]*?^}/m,
      );
      if (dispatchFnMatch) {
        expect(dispatchFnMatch[0]).not.toContain("window.dispatchEvent");
        expect(dispatchFnMatch[0]).not.toContain("CustomEvent");
      }
    });

    it("Test 6: No localStorage direct writes in dispatchSwarmNodes", async () => {
      const fs = await import("fs");
      const path = await import("path");
      const srcPath = path.resolve(
        __dirname,
        "..",
        "use-swarm-launch.ts",
      );
      const source = fs.readFileSync(srcPath, "utf-8");

      // The dispatch function should no longer directly write to localStorage
      const dispatchFnMatch = source.match(
        /function\s+(?:_)?dispatchSwarmNodes[\s\S]*?^}/m,
      );
      if (dispatchFnMatch) {
        expect(dispatchFnMatch[0]).not.toContain("localStorage");
      }
    });
  });
});
