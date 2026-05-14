/**
 * Detection workflow backward compatibility tests -- verifies that
 * _dispatchSwarmNodes and the detection workflow pipeline are unaffected
 * by the swarm-engine integration.
 *
 * Requirements: BKWD-05
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Node } from "@xyflow/react";
import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";

import {
  useSwarmBoardStore,
  createBoardNode,
} from "../swarm-board-store";

import {
  _dispatchSwarmNodes,
  type SwarmLaunchPayload,
} from "@/lib/workbench/detection-workflow/use-swarm-launch";

// Mock Tauri terminal service
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

const STORAGE_KEY = "clawdstrike_workbench_swarm_board";

function seedEmptyBoard(): void {
  localStorage.setItem(
    STORAGE_KEY,
    JSON.stringify({
      boardId: "b-detect-test",
      repoRoot: "/test/repo",
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

function resetStore(): void {
  seedEmptyBoard();
  useSwarmBoardStore.setState(useSwarmBoardStore.getInitialState());
  useSwarmBoardStore.getState().actions.clearBoard();
}

beforeEach(() => {
  localStorage.clear();
  resetStore();
});

// ---------------------------------------------------------------------------
// _dispatchSwarmNodes works without engine
// ---------------------------------------------------------------------------

describe("_dispatchSwarmNodes works without engine", () => {
  it("dispatches nodes and edges to the store", () => {
    const node1 = createBoardNode({
      nodeType: "artifact",
      title: "Detection Rule 1",
      position: { x: 100, y: 100 },
      data: { artifactKind: "detection_rule", documentId: "doc-001" },
    });

    const node2 = createBoardNode({
      nodeType: "artifact",
      title: "Evidence Pack 1",
      position: { x: 400, y: 100 },
      data: { artifactKind: "evidence_pack", evidencePackId: "ep-001" },
    });

    const payload: SwarmLaunchPayload = {
      nodes: [node1, node2],
      edges: [
        {
          id: `edge-${node1.id}-${node2.id}`,
          source: node1.id,
          target: node2.id,
          type: "artifact",
          label: "evidence",
        },
      ],
    };

    _dispatchSwarmNodes(payload);

    const state = useSwarmBoardStore.getState();
    expect(state.nodes).toHaveLength(2);
    expect(state.edges).toHaveLength(1);
    expect(state.edges[0].type).toBe("artifact");
  });

  it("calls addNodeDirect for each node and addEdge for each edge", () => {
    const addNodeDirectSpy = vi.spyOn(
      useSwarmBoardStore.getState().actions,
      "addNodeDirect",
    );
    const addEdgeSpy = vi.spyOn(
      useSwarmBoardStore.getState().actions,
      "addEdge",
    );

    const node = createBoardNode({
      nodeType: "artifact",
      title: "Test",
      position: { x: 0, y: 0 },
    });

    const payload: SwarmLaunchPayload = {
      nodes: [node],
      edges: [{ id: "e1", source: "a", target: "b", type: "artifact" }],
    };

    _dispatchSwarmNodes(payload);

    expect(addNodeDirectSpy).toHaveBeenCalledWith(node);
    expect(addEdgeSpy).toHaveBeenCalledWith(payload.edges[0]);

    addNodeDirectSpy.mockRestore();
    addEdgeSpy.mockRestore();
  });
});

// ---------------------------------------------------------------------------
// Detection node types unaffected
// ---------------------------------------------------------------------------

describe("Detection node types unaffected", () => {
  it("creates a detection_rule artifact node via createBoardNode", () => {
    const node = createBoardNode({
      nodeType: "artifact",
      title: "Sigma Rule",
      position: { x: 0, y: 0 },
      data: {
        artifactKind: "detection_rule",
        documentId: "doc-sigma-001",
        fileType: "sigma",
      },
    });

    expect(node.data.artifactKind).toBe("detection_rule");
    expect(node.data.documentId).toBe("doc-sigma-001");
    expect(node.data.nodeType).toBe("artifact");
  });

  it("creates an evidence_pack artifact node via createBoardNode", () => {
    const node = createBoardNode({
      nodeType: "artifact",
      title: "Evidence Pack",
      position: { x: 0, y: 0 },
      data: {
        artifactKind: "evidence_pack",
        evidencePackId: "ep-test-001",
      },
    });

    expect(node.data.artifactKind).toBe("evidence_pack");
    expect(node.data.evidencePackId).toBe("ep-test-001");
    expect(node.data.nodeType).toBe("artifact");
  });
});

// ---------------------------------------------------------------------------
// _dispatchSwarmNodes is exported from use-swarm-launch.ts
// ---------------------------------------------------------------------------

describe("Detection workflow exports", () => {
  it("_dispatchSwarmNodes is a function", () => {
    expect(typeof _dispatchSwarmNodes).toBe("function");
  });

  it("SwarmLaunchPayload type is importable (compile-time check)", () => {
    // If this compiles, the type is still exported
    const payload: SwarmLaunchPayload = { nodes: [], edges: [] };
    expect(payload.nodes).toHaveLength(0);
    expect(payload.edges).toHaveLength(0);
  });
});
