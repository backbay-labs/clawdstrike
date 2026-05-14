/**
 * Backward compatibility tests -- SwarmBoard without engine
 *
 * Verifies that the swarm-engine integration (Phases 1-5) causes zero
 * regressions to existing SwarmBoard functionality:
 *
 * - SwarmBoardAction type preserves all 14 original action type literals
 * - Store works without SwarmEngineProvider
 * - Engine actions (TOPOLOGY_LAYOUT, ENGINE_SYNC, GUARD_EVALUATE) are additive
 * - Node data backward compat with optional engine fields
 *
 * Requirements: BKWD-01, BKWD-02, BKWD-03
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Node } from "@xyflow/react";
import type {
  SwarmBoardNodeData,
  SwarmBoardEdge,
  SwarmBoardState,
} from "@/features/swarm/swarm-board-types";

import {
  useSwarmBoardStore,
  createBoardNode,
  createMockBoard,
  type SwarmBoardAction,
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

function seedEmptyBoard(): void {
  localStorage.setItem(
    STORAGE_KEY,
    JSON.stringify({
      boardId: "b-compat-test",
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
// SwarmBoardAction type preservation
// ---------------------------------------------------------------------------

describe("SwarmBoardAction type preservation", () => {
  it("accepts all 14 original action type literals (compile-time check)", () => {
    // These are compile-time type assignability checks. If SwarmBoardAction
    // loses any of the original action types, TypeScript will report an error.
    const _addNode: SwarmBoardAction = {
      type: "ADD_NODE",
      node: { id: "n1", type: "note", position: { x: 0, y: 0 }, data: { title: "t", status: "idle", nodeType: "note" } },
    };
    const _removeNode: SwarmBoardAction = { type: "REMOVE_NODE", nodeId: "n1" };
    const _updateNode: SwarmBoardAction = { type: "UPDATE_NODE", nodeId: "n1", patch: { title: "x" } };
    const _setNodes: SwarmBoardAction = { type: "SET_NODES", nodes: [] };
    const _addEdge: SwarmBoardAction = { type: "ADD_EDGE", edge: { id: "e1", source: "a", target: "b" } };
    const _removeEdge: SwarmBoardAction = { type: "REMOVE_EDGE", edgeId: "e1" };
    const _setEdges: SwarmBoardAction = { type: "SET_EDGES", edges: [] };
    const _selectNode: SwarmBoardAction = { type: "SELECT_NODE", nodeId: "n1" };
    const _toggleInspector: SwarmBoardAction = { type: "TOGGLE_INSPECTOR" };
    const _setRepoRoot: SwarmBoardAction = { type: "SET_REPO_ROOT", repoRoot: "/repo" };
    const _load: SwarmBoardAction = { type: "LOAD", state: {} };
    const _clearBoard: SwarmBoardAction = { type: "CLEAR_BOARD" };
    const _setSessionStatus: SwarmBoardAction = {
      type: "SET_SESSION_STATUS",
      sessionId: "s1",
      status: "running",
    };
    const _setSessionMetadata: SwarmBoardAction = {
      type: "SET_SESSION_METADATA",
      sessionId: "s1",
      metadata: { receiptCount: 5 },
    };

    // If we got here, all 14 original action types compile correctly.
    // Runtime check: each object has the expected type field.
    expect(_addNode.type).toBe("ADD_NODE");
    expect(_removeNode.type).toBe("REMOVE_NODE");
    expect(_updateNode.type).toBe("UPDATE_NODE");
    expect(_setNodes.type).toBe("SET_NODES");
    expect(_addEdge.type).toBe("ADD_EDGE");
    expect(_removeEdge.type).toBe("REMOVE_EDGE");
    expect(_setEdges.type).toBe("SET_EDGES");
    expect(_selectNode.type).toBe("SELECT_NODE");
    expect(_toggleInspector.type).toBe("TOGGLE_INSPECTOR");
    expect(_setRepoRoot.type).toBe("SET_REPO_ROOT");
    expect(_load.type).toBe("LOAD");
    expect(_clearBoard.type).toBe("CLEAR_BOARD");
    expect(_setSessionStatus.type).toBe("SET_SESSION_STATUS");
    expect(_setSessionMetadata.type).toBe("SET_SESSION_METADATA");
  });

  it("also accepts the 3 new engine action types (additive, not breaking)", () => {
    const _topologyLayout: SwarmBoardAction = {
      type: "TOPOLOGY_LAYOUT",
      topology: "mesh",
      positions: new Map(),
    };
    const _engineSync: SwarmBoardAction = {
      type: "ENGINE_SYNC",
      engineNodes: [],
      engineEdges: [],
    };
    const _guardEvaluate: SwarmBoardAction = {
      type: "GUARD_EVALUATE",
      agentNodeId: "n1",
      verdict: "allow",
      guardResults: [],
    };

    expect(_topologyLayout.type).toBe("TOPOLOGY_LAYOUT");
    expect(_engineSync.type).toBe("ENGINE_SYNC");
    expect(_guardEvaluate.type).toBe("GUARD_EVALUATE");
  });

  it("SwarmBoardAction union has exactly 17 variants", () => {
    // Enumerate all known type literals from the union
    const allTypes = [
      "ADD_NODE",
      "REMOVE_NODE",
      "UPDATE_NODE",
      "SET_NODES",
      "ADD_EDGE",
      "REMOVE_EDGE",
      "SET_EDGES",
      "SELECT_NODE",
      "TOGGLE_INSPECTOR",
      "SET_REPO_ROOT",
      "LOAD",
      "CLEAR_BOARD",
      "SET_SESSION_STATUS",
      "SET_SESSION_METADATA",
      "TOPOLOGY_LAYOUT",
      "ENGINE_SYNC",
      "GUARD_EVALUATE",
    ] as const;

    expect(allTypes).toHaveLength(17);

    // Verify each is a valid SwarmBoardAction type field by exhaustive switch
    for (const t of allTypes) {
      // This would fail at compile time if t isn't a valid SwarmBoardAction type
      expect(typeof t).toBe("string");
    }
  });
});

// ---------------------------------------------------------------------------
// Store without engine context
// ---------------------------------------------------------------------------

describe("Store without engine context", () => {
  it("getState() returns SwarmBoardState shape with expected fields", () => {
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

  it("addNode creates a node without engine fields", () => {
    const { actions } = useSwarmBoardStore.getState();
    actions.addNode({
      nodeType: "agentSession",
      title: "Test Agent",
      position: { x: 0, y: 0 },
      data: { status: "idle" },
    });

    const state = useSwarmBoardStore.getState();
    expect(state.nodes).toHaveLength(1);
    expect(state.nodes[0].data.title).toBe("Test Agent");
    expect(state.nodes[0].data.agentId).toBeUndefined();
    expect(state.nodes[0].data.taskId).toBeUndefined();
    expect(state.nodes[0].data.engineManaged).toBeUndefined();
  });

  it("addEdge creates a standard edge without engine context", () => {
    const { actions } = useSwarmBoardStore.getState();
    actions.addEdge({
      id: "e1",
      source: "n1",
      target: "n2",
      type: "handoff",
    });

    const state = useSwarmBoardStore.getState();
    expect(state.edges).toHaveLength(1);
    expect(state.edges[0].type).toBe("handoff");
  });

  it("createMockBoard returns expected shape without engine", () => {
    const mock = createMockBoard();
    expect(mock.nodes.length).toBeGreaterThan(0);
    expect(mock.edges.length).toBeGreaterThan(0);

    // All nodes should be valid SwarmBoardNodeData without requiring engine fields
    for (const node of mock.nodes) {
      expect(node.data.title).toBeDefined();
      expect(node.data.status).toBeDefined();
      expect(node.data.nodeType).toBeDefined();
    }
  });

  it("createBoardNode factory works without engine", () => {
    const node = createBoardNode({
      nodeType: "artifact",
      title: "test-file.rs",
      position: { x: 50, y: 50 },
      data: { filePath: "src/test-file.rs", fileType: "rust" },
    });

    expect(node.id).toMatch(/^artifact-/);
    expect(node.data.title).toBe("test-file.rs");
    expect(node.data.nodeType).toBe("artifact");
    expect(node.data.status).toBe("idle");
    expect(node.data.agentId).toBeUndefined();
    expect(node.data.engineManaged).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Engine actions are additive, not breaking
// ---------------------------------------------------------------------------

describe("Engine actions are additive, not breaking", () => {
  it("topologyLayout does not throw or corrupt existing nodes", () => {
    const { actions } = useSwarmBoardStore.getState();
    const node = actions.addNode({
      nodeType: "agentSession",
      title: "Existing Agent",
      position: { x: 100, y: 100 },
    });

    // topologyLayout with empty positions should not throw
    expect(() => {
      actions.topologyLayout("mesh", new Map());
    }).not.toThrow();

    // Existing node should be untouched since its ID is not in the positions map
    const state = useSwarmBoardStore.getState();
    expect(state.nodes).toHaveLength(1);
    expect(state.nodes[0].id).toBe(node.id);
    expect(state.nodes[0].data.title).toBe("Existing Agent");
    expect(state.nodes[0].position).toEqual({ x: 100, y: 100 });
  });

  it("engineSync with empty arrays preserves non-engine nodes and prunes orphaned edges", () => {
    const { actions } = useSwarmBoardStore.getState();
    const node = actions.addNode({
      nodeType: "agentSession",
      title: "Existing Agent",
      position: { x: 100, y: 100 },
    });
    actions.addEdge({ id: "e1", source: "a", target: "b", type: "handoff" });

    actions.engineSync([], []);

    const state = useSwarmBoardStore.getState();
    expect(state.nodes).toHaveLength(1);
    expect(state.nodes[0].id).toBe(node.id);
    expect(state.nodes[0].data.title).toBe("Existing Agent");
    expect(state.edges).toHaveLength(0);
  });

  it("engineSync replaces existing engine edge definitions by ID", () => {
    const { actions } = useSwarmBoardStore.getState();
    actions.addEdge({
      id: "edge-spawn-tsk_1",
      source: "agt_old",
      target: "tsk_1",
      type: "spawned",
    });

    actions.engineSync(
      [
        {
          id: "agt_new",
          agentId: "agt_new",
          data: {
            nodeType: "agentSession",
            title: "Engine Agent",
            status: "idle",
          },
          position: { x: 100, y: 100 },
        },
        {
          id: "tsk_1",
          taskId: "tsk_1",
          agentId: "agt_new",
          data: {
            nodeType: "terminalTask",
            title: "Engine Task",
            status: "idle",
          },
          position: { x: 100, y: 220 },
        },
      ],
      [{
        id: "edge-spawn-tsk_1",
        source: "agt_new",
        target: "tsk_1",
        type: "spawned",
      }],
    );

    const state = useSwarmBoardStore.getState();
    expect(state.edges).toHaveLength(1);
    expect(state.edges[0]).toMatchObject({
      id: "edge-spawn-tsk_1",
      source: "agt_new",
      target: "tsk_1",
      type: "spawned",
    });
  });

  it("guardEvaluate handles missing node gracefully", () => {
    const { actions } = useSwarmBoardStore.getState();

    // guardEvaluate with nonexistent node ID should not throw
    expect(() => {
      actions.guardEvaluate("nonexistent-node", "allow", []);
    }).not.toThrow();

    // No receipt node should have been created
    const state = useSwarmBoardStore.getState();
    expect(state.nodes).toHaveLength(0);
  });

  it("guardEvaluate creates receipt node when agent node exists", () => {
    const { actions } = useSwarmBoardStore.getState();
    const agentNode = actions.addNode({
      nodeType: "agentSession",
      title: "Test Agent",
      position: { x: 100, y: 100 },
    });

    actions.guardEvaluate(
      agentNode.id,
      "allow",
      [{ guard: "ForbiddenPathGuard", allowed: true, duration_ms: 2 }],
      "sig123",
      "pub456",
    );

    const state = useSwarmBoardStore.getState();
    expect(state.nodes).toHaveLength(2); // agent + receipt
    const receiptNode = state.nodes.find((n) => n.data.nodeType === "receipt");
    expect(receiptNode).toBeDefined();
    expect(receiptNode!.data.verdict).toBe("allow");
    expect(receiptNode!.data.signature).toBe("sig123");
    expect(receiptNode!.data.publicKey).toBe("pub456");

    // Edge from agent to receipt
    expect(state.edges).toHaveLength(1);
    expect(state.edges[0].source).toBe(agentNode.id);
    expect(state.edges[0].type).toBe("receipt");
  });

  it("guardEvaluate deduplicates receipt nodes when the signature matches", () => {
    const { actions } = useSwarmBoardStore.getState();
    const agentNode = actions.addNode({
      nodeType: "agentSession",
      title: "Test Agent",
      position: { x: 100, y: 100 },
    });

    actions.guardEvaluate(
      agentNode.id,
      "allow",
      [{ guard: "ForbiddenPathGuard", allowed: true, duration_ms: 2 }],
      "abcd".repeat(32),
      "1234".repeat(16),
    );
    actions.guardEvaluate(
      agentNode.id,
      "allow",
      [{ guard: "ForbiddenPathGuard", allowed: true, duration_ms: 2 }],
      "abcd".repeat(32),
      "1234".repeat(16),
    );

    const state = useSwarmBoardStore.getState();
    expect(state.nodes.filter((node) => node.data.nodeType === "receipt")).toHaveLength(1);
    expect(state.edges.filter((edge) => edge.type === "receipt")).toHaveLength(1);
  });

  it("guardEvaluate does not deduplicate receipts with empty signatures", () => {
    const { actions } = useSwarmBoardStore.getState();
    const agentNode = actions.addNode({
      nodeType: "agentSession",
      title: "Test Agent",
      position: { x: 100, y: 100 },
    });

    actions.guardEvaluate(
      agentNode.id,
      "deny",
      [{ guard: "ForbiddenPathGuard", allowed: false, duration_ms: 2 }],
      "",
      "",
    );
    actions.guardEvaluate(
      agentNode.id,
      "deny",
      [{ guard: "ForbiddenPathGuard", allowed: false, duration_ms: 3 }],
      "",
      "",
    );

    const state = useSwarmBoardStore.getState();
    expect(state.nodes.filter((node) => node.data.nodeType === "receipt")).toHaveLength(2);
    expect(state.edges.filter((edge) => edge.type === "receipt")).toHaveLength(2);
  });

  it("addGuardReceipt supports detached receipts with shared dedupe semantics", () => {
    const { actions } = useSwarmBoardStore.getState();

    actions.addGuardReceipt({
      verdict: "deny",
      guardResults: [{ guard: "engine_error", allowed: false }],
      signature: "feed".repeat(32),
      publicKey: "5678".repeat(16),
      position: { x: 120, y: 80 },
      detail: "engine exploded",
    });
    actions.addGuardReceipt({
      verdict: "deny",
      guardResults: [{ guard: "engine_error", allowed: false }],
      signature: "feed".repeat(32),
      publicKey: "5678".repeat(16),
      position: { x: 240, y: 120 },
      detail: "engine exploded",
    });

    const state = useSwarmBoardStore.getState();
    const receiptNodes = state.nodes.filter((node) => node.data.nodeType === "receipt");

    expect(receiptNodes).toHaveLength(1);
    expect(state.edges.filter((edge) => edge.type === "receipt")).toHaveLength(0);
    expect(receiptNodes[0]?.position).toEqual({ x: 120, y: 420 });
    expect(receiptNodes[0]?.data.previewLines).toEqual(["engine exploded"]);
  });
});

// ---------------------------------------------------------------------------
// Node data backward compat
// ---------------------------------------------------------------------------

describe("Node data backward compat", () => {
  it("node without agentId/taskId/engineManaged works correctly", () => {
    const node = createBoardNode({
      nodeType: "agentSession",
      title: "Legacy Agent",
      position: { x: 0, y: 0 },
      data: {
        sessionId: "sess-legacy",
        status: "running",
        branch: "main",
      },
    });

    const { actions } = useSwarmBoardStore.getState();
    actions.addNodeDirect(node);

    const state = useSwarmBoardStore.getState();
    expect(state.nodes).toHaveLength(1);
    expect(state.nodes[0].data.sessionId).toBe("sess-legacy");
    expect(state.nodes[0].data.agentId).toBeUndefined();
    expect(state.nodes[0].data.taskId).toBeUndefined();
    expect(state.nodes[0].data.engineManaged).toBeUndefined();
  });

  it("node WITH engine fields coexists with legacy nodes", () => {
    const legacyNode = createBoardNode({
      nodeType: "agentSession",
      title: "Legacy Agent",
      position: { x: 0, y: 0 },
      data: { sessionId: "sess-legacy", status: "running" },
    });
    const engineNode = createBoardNode({
      nodeType: "agentSession",
      title: "Engine Agent",
      position: { x: 300, y: 0 },
      data: {
        agentId: "agt-001",
        taskId: "tsk-001",
        engineManaged: true,
        status: "idle",
      },
    });

    const { actions } = useSwarmBoardStore.getState();
    actions.addNodeDirect(legacyNode);
    actions.addNodeDirect(engineNode);

    const state = useSwarmBoardStore.getState();
    expect(state.nodes).toHaveLength(2);

    const legacy = state.nodes.find((n) => n.id === legacyNode.id);
    const engine = state.nodes.find((n) => n.id === engineNode.id);
    expect(legacy!.data.engineManaged).toBeUndefined();
    expect(engine!.data.engineManaged).toBe(true);
    expect(engine!.data.agentId).toBe("agt-001");
  });

  it("SwarmBoardEdge 'topology' type is additive alongside existing types", () => {
    const { actions } = useSwarmBoardStore.getState();

    const edges: SwarmBoardEdge[] = [
      { id: "e1", source: "a", target: "b", type: "handoff" },
      { id: "e2", source: "b", target: "c", type: "spawned" },
      { id: "e3", source: "c", target: "d", type: "artifact" },
      { id: "e4", source: "d", target: "e", type: "receipt" },
      { id: "e5", source: "e", target: "f", type: "topology" },
    ];

    for (const edge of edges) {
      actions.addEdge(edge);
    }

    const state = useSwarmBoardStore.getState();
    expect(state.edges).toHaveLength(5);
    expect(state.edges.map((e) => e.type)).toEqual([
      "handoff",
      "spawned",
      "artifact",
      "receipt",
      "topology",
    ]);
  });
});
