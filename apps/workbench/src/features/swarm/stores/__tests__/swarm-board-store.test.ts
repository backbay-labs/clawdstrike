import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Node } from "@xyflow/react";
import type {
  SwarmBoardNodeData,
  SwarmBoardEdge,
} from "@/features/swarm/swarm-board-types";

// ---------------------------------------------------------------------------
// We import useSwarmBoardStore (the new Zustand store), plus the kept exports
// ---------------------------------------------------------------------------

import {
  useSwarmBoardStore,
  createBoardNode,
  createMockBoard,
  MAX_ACTIVE_TERMINALS,
  type CreateNodeConfig,
} from "../swarm-board-store";

// Mock Tauri terminal service to prevent real Tauri calls
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

/**
 * Seeds localStorage with a placeholder so the store loads from persistence
 * instead of seeding mock data. Tests that need a clean slate should call
 * this then call actions.clearBoard().
 */
function seedEmptyBoard(): void {
  localStorage.setItem(
    STORAGE_KEY,
    JSON.stringify({
      boardId: "b-test",
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

/**
 * Reset the Zustand store to a clean state for each test.
 * Because Zustand stores are singletons, we need to reset between tests.
 */
function resetStore(): void {
  seedEmptyBoard();
  // Destroy and re-create to pick up the seeded localStorage
  useSwarmBoardStore.setState(useSwarmBoardStore.getInitialState());
  useSwarmBoardStore.getState().actions.clearBoard();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

beforeEach(() => {
  localStorage.clear();
  resetStore();
});

describe("SwarmBoardStore (Zustand)", () => {
  // Test 1
  it("getState() returns SwarmBoardState shape", () => {
    const state = useSwarmBoardStore.getState();
    expect(state).toHaveProperty("boardId");
    expect(state).toHaveProperty("repoRoot");
    expect(state).toHaveProperty("nodes");
    expect(state).toHaveProperty("edges");
    expect(state).toHaveProperty("selectedNodeId");
    expect(state).toHaveProperty("inspectorOpen");
    expect(Array.isArray(state.nodes)).toBe(true);
    expect(Array.isArray(state.edges)).toBe(true);
  });

  // Test 2
  it("actions.addNode creates a node that appears in nodes", () => {
    const { actions } = useSwarmBoardStore.getState();
    const node = actions.addNode({
      nodeType: "agentSession",
      title: "Test Agent",
      position: { x: 100, y: 100 },
    });

    const state = useSwarmBoardStore.getState();
    expect(state.nodes).toHaveLength(1);
    expect(state.nodes[0].id).toBe(node.id);
    expect(state.nodes[0].data.title).toBe("Test Agent");
    expect(state.nodes[0].data.nodeType).toBe("agentSession");
  });

  // Test 3
  it("actions.addNode with duplicate ID is a no-op", () => {
    const { actions } = useSwarmBoardStore.getState();
    const node = actions.addNode({
      nodeType: "note",
      title: "Note 1",
      position: { x: 0, y: 0 },
    });

    // Try to add a node with the same ID by directly adding
    useSwarmBoardStore.getState().actions.addNodeDirect(node);

    const state = useSwarmBoardStore.getState();
    expect(state.nodes).toHaveLength(1);
  });

  // Test 4
  it("actions.removeNode removes the node AND connected edges", () => {
    const { actions } = useSwarmBoardStore.getState();
    const node1 = actions.addNode({
      nodeType: "agentSession",
      title: "Agent 1",
      position: { x: 0, y: 0 },
    });
    const node2 = actions.addNode({
      nodeType: "terminalTask",
      title: "Task 1",
      position: { x: 200, y: 0 },
    });

    actions.addEdge({
      id: "edge-1",
      source: node1.id,
      target: node2.id,
      type: "spawned",
    });

    expect(useSwarmBoardStore.getState().edges).toHaveLength(1);

    actions.removeNode(node1.id);

    const state = useSwarmBoardStore.getState();
    expect(state.nodes).toHaveLength(1);
    expect(state.nodes[0].id).toBe(node2.id);
    expect(state.edges).toHaveLength(0); // edge removed because source was deleted
  });

  // Test 5
  it("actions.removeNode clears selectedNodeId if the removed node was selected", () => {
    const { actions } = useSwarmBoardStore.getState();
    const node = actions.addNode({
      nodeType: "agentSession",
      title: "Agent 1",
      position: { x: 0, y: 0 },
    });
    actions.selectNode(node.id);
    expect(useSwarmBoardStore.getState().selectedNodeId).toBe(node.id);
    expect(useSwarmBoardStore.getState().inspectorOpen).toBe(true);

    actions.removeNode(node.id);

    const state = useSwarmBoardStore.getState();
    expect(state.selectedNodeId).toBeNull();
    expect(state.inspectorOpen).toBe(false);
  });

  // Test 6
  it("actions.updateNode patches data on the correct node", () => {
    const { actions } = useSwarmBoardStore.getState();
    const node = actions.addNode({
      nodeType: "agentSession",
      title: "Agent 1",
      position: { x: 0, y: 0 },
      data: { status: "idle", risk: "low" },
    });

    actions.updateNode(node.id, { status: "running", risk: "high" });

    const state = useSwarmBoardStore.getState();
    const updated = state.nodes.find((n) => n.id === node.id);
    expect(updated).toBeDefined();
    expect(updated!.data.status).toBe("running");
    expect(updated!.data.risk).toBe("high");
    expect(updated!.data.title).toBe("Agent 1"); // not overwritten
  });

  // Test 7
  it("actions.selectNode sets selectedNodeId and opens inspector", () => {
    const { actions } = useSwarmBoardStore.getState();
    const node = actions.addNode({
      nodeType: "note",
      title: "Note",
      position: { x: 0, y: 0 },
    });

    actions.selectNode(node.id);

    const state = useSwarmBoardStore.getState();
    expect(state.selectedNodeId).toBe(node.id);
    expect(state.inspectorOpen).toBe(true);
  });

  // Test 8
  it("actions.selectNode(null) clears selection and closes inspector", () => {
    const { actions } = useSwarmBoardStore.getState();
    const node = actions.addNode({
      nodeType: "note",
      title: "Note",
      position: { x: 0, y: 0 },
    });
    actions.selectNode(node.id);
    expect(useSwarmBoardStore.getState().inspectorOpen).toBe(true);

    actions.selectNode(null);

    const state = useSwarmBoardStore.getState();
    expect(state.selectedNodeId).toBeNull();
    expect(state.inspectorOpen).toBe(false);
  });

  // Test 9
  it("actions.addEdge creates an edge; duplicate is no-op", () => {
    const { actions } = useSwarmBoardStore.getState();
    const node1 = actions.addNode({
      nodeType: "agentSession",
      title: "A1",
      position: { x: 0, y: 0 },
    });
    const node2 = actions.addNode({
      nodeType: "terminalTask",
      title: "T1",
      position: { x: 100, y: 0 },
    });

    const edge: SwarmBoardEdge = {
      id: "edge-test",
      source: node1.id,
      target: node2.id,
      type: "spawned",
    };

    actions.addEdge(edge);
    expect(useSwarmBoardStore.getState().edges).toHaveLength(1);

    // Adding same edge ID is no-op
    actions.addEdge(edge);
    expect(useSwarmBoardStore.getState().edges).toHaveLength(1);
  });

  // Test 10
  it("actions.removeEdge removes the edge", () => {
    const { actions } = useSwarmBoardStore.getState();
    actions.addNode({
      nodeType: "agentSession",
      title: "A1",
      position: { x: 0, y: 0 },
    });
    actions.addNode({
      nodeType: "terminalTask",
      title: "T1",
      position: { x: 100, y: 0 },
    });

    actions.addEdge({
      id: "edge-rm",
      source: "a",
      target: "b",
      type: "handoff",
    });
    expect(useSwarmBoardStore.getState().edges).toHaveLength(1);

    actions.removeEdge("edge-rm");
    expect(useSwarmBoardStore.getState().edges).toHaveLength(0);
  });

  // Test 11
  it("actions.clearBoard empties nodes, edges, selection, inspector", () => {
    const { actions } = useSwarmBoardStore.getState();
    const node = actions.addNode({
      nodeType: "note",
      title: "Note",
      position: { x: 0, y: 0 },
    });
    actions.addEdge({ id: "e1", source: "a", target: "b" });
    actions.selectNode(node.id);

    actions.clearBoard();

    const state = useSwarmBoardStore.getState();
    expect(state.nodes).toHaveLength(0);
    expect(state.edges).toHaveLength(0);
    expect(state.selectedNodeId).toBeNull();
    expect(state.inspectorOpen).toBe(false);
  });

  // Test 12
  it("actions.setSessionStatus updates status on the node matching sessionId", () => {
    const { actions } = useSwarmBoardStore.getState();
    actions.addNode({
      nodeType: "agentSession",
      title: "Agent",
      position: { x: 0, y: 0 },
      data: { sessionId: "sess-123", status: "running" },
    });

    actions.setSessionStatus("sess-123", "completed", 0);

    const state = useSwarmBoardStore.getState();
    const node = state.nodes[0];
    expect(node.data.status).toBe("completed");
    expect(node.data.exitCode).toBe(0);
  });

  // Test 13
  it("actions.setSessionMetadata patches data on the node matching sessionId", () => {
    const { actions } = useSwarmBoardStore.getState();
    actions.addNode({
      nodeType: "agentSession",
      title: "Agent",
      position: { x: 0, y: 0 },
      data: { sessionId: "sess-456", status: "running", receiptCount: 0 },
    });

    actions.setSessionMetadata("sess-456", { receiptCount: 5, risk: "high" });

    const state = useSwarmBoardStore.getState();
    const node = state.nodes[0];
    expect(node.data.receiptCount).toBe(5);
    expect(node.data.risk).toBe("high");
    expect(node.data.sessionId).toBe("sess-456"); // not overwritten
  });

  // Test 14
  it("actions.setRepoRoot updates repoRoot", () => {
    const { actions } = useSwarmBoardStore.getState();
    actions.setRepoRoot("/new/repo/root");

    expect(useSwarmBoardStore.getState().repoRoot).toBe("/new/repo/root");
  });

  // Test 15
  it("actions.loadState merges partial state", () => {
    const { actions } = useSwarmBoardStore.getState();
    const mockNode: Node<SwarmBoardNodeData> = {
      id: "loaded-1",
      type: "note",
      position: { x: 0, y: 0 },
      data: { title: "Loaded", status: "idle", nodeType: "note" },
    };

    actions.loadState({
      nodes: [mockNode],
      repoRoot: "/loaded/root",
    });

    const state = useSwarmBoardStore.getState();
    expect(state.nodes).toHaveLength(1);
    expect(state.nodes[0].id).toBe("loaded-1");
    expect(state.repoRoot).toBe("/loaded/root");
    // boardId should remain from original
    expect(state.boardId).toBeDefined();
  });

  it("engineSync removes stale engine-managed agent and task nodes while preserving receipts", () => {
    const { actions } = useSwarmBoardStore.getState();

    actions.addNodeDirect({
      id: "agt_stale",
      type: "agentSession",
      position: { x: 0, y: 0 },
      data: {
        title: "Stale Agent",
        status: "idle",
        nodeType: "agentSession",
        agentId: "agt_stale",
        engineManaged: true,
      },
    });
    actions.addNodeDirect({
      id: "tsk_stale",
      type: "terminalTask",
      position: { x: 0, y: 200 },
      data: {
        title: "Stale Task",
        status: "idle",
        nodeType: "terminalTask",
        taskId: "tsk_stale",
        agentId: "agt_stale",
        engineManaged: true,
      },
    });
    actions.addNodeDirect({
      id: "receipt-keep",
      type: "receipt",
      position: { x: 0, y: 400 },
      data: {
        title: "Receipt",
        status: "completed",
        nodeType: "receipt",
        engineManaged: true,
      },
    });
    actions.addEdge({
      id: "edge-spawn-stale",
      source: "agt_stale",
      target: "tsk_stale",
      type: "spawned",
    });

    actions.engineSync(
      [
        {
          id: "agt_live",
          agentId: "agt_live",
          data: {
            nodeType: "agentSession",
            title: "Live Agent",
            status: "running",
          },
          position: { x: 100, y: 100 },
        },
      ],
      [],
    );

    const state = useSwarmBoardStore.getState();
    expect(state.nodes.find((node) => node.id === "agt_stale")).toBeUndefined();
    expect(state.nodes.find((node) => node.id === "tsk_stale")).toBeUndefined();
    expect(state.nodes.find((node) => node.id === "receipt-keep")).toBeDefined();
    expect(state.nodes.find((node) => node.id === "agt_live")?.data.title).toBe("Live Agent");
    expect(state.edges.find((edge) => edge.id === "edge-spawn-stale")).toBeUndefined();
  });

  it("engineSync drops stale snapshot-managed edges while keeping live nodes", () => {
    const { actions } = useSwarmBoardStore.getState();

    actions.addNodeDirect({
      id: "agt_alpha",
      type: "agentSession",
      position: { x: 0, y: 0 },
      data: {
        title: "Alpha",
        status: "running",
        nodeType: "agentSession",
        agentId: "agt_alpha",
        engineManaged: true,
      },
    });
    actions.addNodeDirect({
      id: "agt_beta",
      type: "agentSession",
      position: { x: 300, y: 0 },
      data: {
        title: "Beta",
        status: "running",
        nodeType: "agentSession",
        agentId: "agt_beta",
        engineManaged: true,
      },
    });
    actions.addEdge({
      id: "edge-topo-agt_alpha-agt_beta",
      source: "agt_alpha",
      target: "agt_beta",
      type: "topology",
    });

    actions.engineSync(
      [
        {
          id: "agt_alpha",
          agentId: "agt_alpha",
          data: {
            nodeType: "agentSession",
            title: "Alpha",
            status: "running",
          },
          position: { x: 0, y: 0 },
        },
        {
          id: "agt_beta",
          agentId: "agt_beta",
          data: {
            nodeType: "agentSession",
            title: "Beta",
            status: "running",
          },
          position: { x: 300, y: 0 },
        },
      ],
      [],
    );

    const state = useSwarmBoardStore.getState();
    expect(state.nodes.find((node) => node.id === "agt_alpha")).toBeDefined();
    expect(state.nodes.find((node) => node.id === "agt_beta")).toBeDefined();
    expect(state.edges.find((edge) => edge.id === "edge-topo-agt_alpha-agt_beta")).toBeUndefined();
  });

  // Test 16
  it("createBoardNode factory returns properly shaped node", () => {
    const node = createBoardNode({
      nodeType: "artifact",
      title: "test-file.rs",
      position: { x: 50, y: 50 },
      data: { filePath: "src/test-file.rs", fileType: "rust" },
    });

    expect(node.id).toMatch(/^artifact-/);
    expect(node.type).toBe("artifact");
    expect(node.position).toEqual({ x: 50, y: 50 });
    expect(node.data.title).toBe("test-file.rs");
    expect(node.data.nodeType).toBe("artifact");
    expect(node.data.status).toBe("idle");
    expect(node.data.filePath).toBe("src/test-file.rs");
  });

  // Test 17
  it("createMockBoard returns seeded nodes and edges", () => {
    const mock = createMockBoard();
    expect(mock.nodes.length).toBeGreaterThan(0);
    expect(mock.edges.length).toBeGreaterThan(0);
    // Should have agent sessions
    const agents = mock.nodes.filter((n) => n.data.nodeType === "agentSession");
    expect(agents.length).toBeGreaterThanOrEqual(3);
    // Edges should reference valid node IDs
    const nodeIds = new Set(mock.nodes.map((n) => n.id));
    for (const edge of mock.edges) {
      expect(nodeIds.has(edge.source)).toBe(true);
      expect(nodeIds.has(edge.target)).toBe(true);
    }
  });
});

describe("SwarmBoardStore derived state", () => {
  it("selectedNode is derived from selectedNodeId + nodes", () => {
    const { actions } = useSwarmBoardStore.getState();
    const node = actions.addNode({
      nodeType: "note",
      title: "Test Note",
      position: { x: 0, y: 0 },
    });
    actions.selectNode(node.id);

    const state = useSwarmBoardStore.getState();
    expect(state.selectedNode).toBeDefined();
    expect(state.selectedNode!.id).toBe(node.id);
    expect(state.selectedNode!.data.title).toBe("Test Note");
  });

  it("rfEdges converts SwarmBoardEdge[] to React Flow Edge[]", () => {
    const { actions } = useSwarmBoardStore.getState();
    const n1 = actions.addNode({ nodeType: "agentSession", title: "A1", position: { x: 0, y: 0 } });
    const n2 = actions.addNode({ nodeType: "terminalTask", title: "T1", position: { x: 100, y: 0 } });
    actions.addEdge({
      id: "e1",
      source: n1.id,
      target: n2.id,
      type: "spawned",
      label: "spawned",
    });

    const state = useSwarmBoardStore.getState();
    expect(state.rfEdges).toHaveLength(1);
    expect(state.rfEdges[0].id).toBe("e1");
    expect(state.rfEdges[0].source).toBe(n1.id);
    expect(state.rfEdges[0].target).toBe(n2.id);
    expect(state.rfEdges[0].animated).toBe(true); // spawned edges are animated
    expect(state.rfEdges[0].style).toMatchObject({ stroke: "#d4a84b" });
    expect(state.rfEdges[0].markerEnd).toMatchObject({ color: "#d4a84b" });
  });

  it("rfEdges applies topology edge styling consistently", () => {
    const { actions } = useSwarmBoardStore.getState();
    const n1 = actions.addNode({ nodeType: "agentSession", title: "A1", position: { x: 0, y: 0 } });
    const n2 = actions.addNode({ nodeType: "agentSession", title: "A2", position: { x: 100, y: 0 } });
    actions.addEdge({
      id: "topo-1",
      source: n1.id,
      target: n2.id,
      type: "topology",
    });

    const state = useSwarmBoardStore.getState();
    expect(state.rfEdges).toHaveLength(1);
    expect(state.rfEdges[0].style).toMatchObject({ stroke: "#3d4250" });
    expect(state.rfEdges[0].markerEnd).toBeUndefined();
  });

  it("MAX_ACTIVE_TERMINALS is exported and equals 8", () => {
    expect(MAX_ACTIVE_TERMINALS).toBe(8);
  });
});

describe("SwarmBoardStore setNodes/setEdges actions", () => {
  it("actions.setNodes replaces the nodes array", () => {
    const { actions } = useSwarmBoardStore.getState();
    actions.addNode({ nodeType: "note", title: "Original", position: { x: 0, y: 0 } });

    const replacement: Node<SwarmBoardNodeData>[] = [
      {
        id: "replaced-1",
        type: "artifact",
        position: { x: 100, y: 100 },
        data: { title: "Replaced", status: "idle", nodeType: "artifact" },
      },
    ];

    actions.setNodes(replacement);

    const state = useSwarmBoardStore.getState();
    expect(state.nodes).toHaveLength(1);
    expect(state.nodes[0].id).toBe("replaced-1");
  });

  it("actions.setEdges replaces the edges array", () => {
    const { actions } = useSwarmBoardStore.getState();
    actions.addEdge({ id: "old-edge", source: "a", target: "b" });

    const replacement: SwarmBoardEdge[] = [
      { id: "new-edge", source: "c", target: "d", type: "handoff" },
    ];

    actions.setEdges(replacement);

    const state = useSwarmBoardStore.getState();
    expect(state.edges).toHaveLength(1);
    expect(state.edges[0].id).toBe("new-edge");
  });
});

describe("SwarmBoardStore persistence", () => {
  it("persists to localStorage with debounced writes", () => {
    vi.useFakeTimers();
    try {
      const { actions } = useSwarmBoardStore.getState();
      actions.addNode({
        nodeType: "agentSession",
        title: "Persistent Agent",
        position: { x: 0, y: 0 },
      });

      // Not yet persisted (within debounce window)
      const beforeDebounce = localStorage.getItem(STORAGE_KEY);
      // After debounce
      vi.advanceTimersByTime(600);

      const raw = localStorage.getItem(STORAGE_KEY);
      expect(raw).not.toBeNull();
      const parsed = JSON.parse(raw!);
      expect(parsed.nodes).toHaveLength(1);
      expect(parsed.nodes[0].data.title).toBe("Persistent Agent");
    } finally {
      vi.useRealTimers();
    }
  });

  it("redacts sensitive engine-managed metadata before persistence", () => {
    vi.useFakeTimers();
    try {
      const { actions } = useSwarmBoardStore.getState();
      actions.addNode({
        nodeType: "agentSession",
        title: "Engine Agent",
        position: { x: 0, y: 0 },
        data: {
          engineManaged: true,
          branch: "feature/private-branch",
          worktreePath: "/tmp/private/worktree",
          filesTouched: ["src/secret.ts"],
          previewLines: ["token=super-secret"],
          taskPrompt: "exfiltrate secrets",
        },
      });

      vi.advanceTimersByTime(600);

      const raw = localStorage.getItem(STORAGE_KEY);
      expect(raw).not.toBeNull();

      const persistedNode = JSON.parse(raw!).nodes[0];
      expect(persistedNode.data.engineManaged).toBe(true);
      expect(persistedNode.data.branch).toBeUndefined();
      expect(persistedNode.data.worktreePath).toBeUndefined();
      expect(persistedNode.data.filesTouched).toBeUndefined();
      expect(persistedNode.data.previewLines).toBeUndefined();
      expect(persistedNode.data.taskPrompt).toBeUndefined();
    } finally {
      vi.useRealTimers();
    }
  });
});
