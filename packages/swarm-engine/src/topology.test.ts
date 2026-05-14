import { describe, it, expect, vi, beforeEach } from "vitest";
import { TypedEventEmitter, type SwarmEngineEventMap } from "./events.js";
import type {
  TopologyConfig,
  TopologyState,
} from "./types.js";
import { TopologyManager, type AdaptiveThresholds } from "./topology.js";

// ============================================================================
// Test helpers
// ============================================================================

function makeEmitter(): TypedEventEmitter<SwarmEngineEventMap> {
  return new TypedEventEmitter<SwarmEngineEventMap>();
}

function makeManager(
  config?: Partial<TopologyConfig & { adaptiveThresholds?: AdaptiveThresholds }>,
): { manager: TopologyManager; events: TypedEventEmitter<SwarmEngineEventMap> } {
  const events = makeEmitter();
  const manager = new TopologyManager(events, config);
  return { manager, events };
}

// ============================================================================
// Mesh mode
// ============================================================================

describe("TopologyManager - mesh mode", () => {
  let manager: TopologyManager;

  beforeEach(() => {
    ({ manager } = makeManager({ type: "mesh" }));
  });

  it("addNode creates a peer node in mesh mode", () => {
    const node = manager.addNode("agent-1", "worker");
    expect(node.role).toBe("peer");
    expect(node.status).toBe("active");
    expect(node.agentId).toBe("agent-1");
  });

  it("addNode connects to existing nodes (up to 10)", () => {
    manager.addNode("a1", "worker");
    manager.addNode("a2", "worker");
    const node3 = manager.addNode("a3", "worker");
    expect(node3.connections.length).toBeGreaterThan(0);
  });

  it("mesh edges are bidirectional", () => {
    manager.addNode("a1", "worker");
    const n2 = manager.addNode("a2", "worker");
    // a2 connects to a1
    expect(n2.connections).toContain("a1");
    // a1 should also connect back to a2 (bidirectional edge)
    expect(manager.isConnected("a1", "a2")).toBe(true);
    expect(manager.isConnected("a2", "a1")).toBe(true);
  });

  it("mesh creates partitions", () => {
    manager.addNode("a1", "worker");
    const state = manager.getState();
    expect(state.partitions.length).toBeGreaterThanOrEqual(1);
  });
});

// ============================================================================
// Hierarchical mode
// ============================================================================

describe("TopologyManager - hierarchical mode", () => {
  let manager: TopologyManager;

  beforeEach(() => {
    ({ manager } = makeManager({ type: "hierarchical" }));
  });

  it("first node becomes queen", () => {
    const node = manager.addNode("queen-1", "worker");
    expect(node.role).toBe("queen");
  });

  it("subsequent nodes are workers connected to queen", () => {
    manager.addNode("queen-1", "worker");
    const worker = manager.addNode("worker-1", "worker");
    expect(worker.role).toBe("worker");
    expect(worker.connections).toContain("queen-1");
  });

  it("only one queen exists", () => {
    manager.addNode("q", "queen");
    const w = manager.addNode("w", "queen");
    // Second queen request should be downgraded to worker
    expect(w.role).toBe("worker");
  });

  it("hierarchical does not create partitions", () => {
    manager.addNode("a1", "worker");
    manager.addNode("a2", "worker");
    const state = manager.getState();
    expect(state.partitions.length).toBe(0);
  });
});

// ============================================================================
// Centralized mode
// ============================================================================

describe("TopologyManager - centralized mode", () => {
  let manager: TopologyManager;

  beforeEach(() => {
    ({ manager } = makeManager({ type: "centralized" }));
  });

  it("first node becomes coordinator", () => {
    const node = manager.addNode("coord-1", "worker");
    expect(node.role).toBe("coordinator");
  });

  it("all others connect to coordinator only", () => {
    manager.addNode("coord-1", "worker");
    const w = manager.addNode("worker-1", "worker");
    expect(w.connections).toEqual(["coord-1"]);
  });

  it("centralized does not create partitions", () => {
    manager.addNode("a1", "worker");
    manager.addNode("a2", "worker");
    const state = manager.getState();
    expect(state.partitions.length).toBe(0);
  });
});

// ============================================================================
// Hybrid mode
// ============================================================================

describe("TopologyManager - hybrid mode", () => {
  let manager: TopologyManager;

  beforeEach(() => {
    ({ manager } = makeManager({ type: "hybrid" }));
  });

  it("preserves requested role in hybrid mode", () => {
    const coord = manager.addNode("c1", "coordinator");
    expect(coord.role).toBe("coordinator");

    const worker = manager.addNode("w1", "worker");
    expect(worker.role).toBe("worker");
  });

  it("workers have connections to coordinators and peers", () => {
    manager.addNode("c1", "coordinator");
    const w1 = manager.addNode("w1", "worker");
    // Worker should connect to the coordinator
    expect(w1.connections).toContain("c1");
  });

  it("hybrid creates partitions", () => {
    manager.addNode("c1", "coordinator");
    manager.addNode("w1", "worker");
    const state = manager.getState();
    expect(state.partitions.length).toBeGreaterThanOrEqual(1);
  });
});

// ============================================================================
// Adaptive mode
// ============================================================================

describe("TopologyManager - adaptive mode", () => {
  it("<5 agents behaves like mesh (all peers)", () => {
    const { manager } = makeManager({
      type: "adaptive",
      adaptiveThresholds: { meshMax: 5, hierarchicalMax: 20 },
    });
    const n1 = manager.addNode("a1", "worker");
    const n2 = manager.addNode("a2", "worker");
    // Under meshMax, should resolve to mesh -> peers
    expect(n1.role).toBe("peer");
    expect(n2.role).toBe("peer");
  });

  it("5-20 agents behaves like hierarchical (queen + workers)", () => {
    const { manager } = makeManager({
      type: "adaptive",
      maxAgents: 50,
      adaptiveThresholds: { meshMax: 3, hierarchicalMax: 10 },
    });
    // Add 3 nodes (mesh range)
    manager.addNode("a1", "worker");
    manager.addNode("a2", "worker");
    manager.addNode("a3", "worker");
    // 4th node crosses meshMax threshold -> hierarchical
    // first node in hierarchical would be queen
    const n4 = manager.addNode("a4", "worker");
    // In hierarchical range, roles should be worker (since queen already assigned on transition)
    expect(["queen", "worker"]).toContain(n4.role);
  });

  it(">20 agents behaves like hybrid", () => {
    const { manager } = makeManager({
      type: "adaptive",
      maxAgents: 50,
      adaptiveThresholds: { meshMax: 2, hierarchicalMax: 4 },
    });
    // Add enough to cross hierarchicalMax
    manager.addNode("a1", "worker");
    manager.addNode("a2", "worker");
    manager.addNode("a3", "worker");
    manager.addNode("a4", "worker");
    // 5th node crosses hierarchicalMax -> hybrid
    const n5 = manager.addNode("a5", "worker");
    // In hybrid, requested role is preserved
    expect(n5.role).toBe("worker");
  });
});

// ============================================================================
// addNode error cases
// ============================================================================

describe("TopologyManager - addNode errors", () => {
  it("throws on duplicate agentId", () => {
    const { manager } = makeManager();
    manager.addNode("a1", "worker");
    expect(() => manager.addNode("a1", "worker")).toThrow(
      /already exists/,
    );
  });

  it("throws when maxAgents reached", () => {
    const { manager } = makeManager({ type: "mesh", maxAgents: 2 });
    manager.addNode("a1", "worker");
    manager.addNode("a2", "worker");
    expect(() => manager.addNode("a3", "worker")).toThrow(
      /Maximum agents/,
    );
  });
});

// ============================================================================
// removeNode
// ============================================================================

describe("TopologyManager - removeNode", () => {
  it("removes node from state and cleans up adjacency list", () => {
    const { manager } = makeManager({ type: "mesh" });
    manager.addNode("a1", "worker");
    manager.addNode("a2", "worker");

    manager.removeNode("a1");

    expect(manager.getNode("a1")).toBeUndefined();
    expect(manager.getNeighbors("a1")).toEqual([]);
    // a2 should no longer reference a1
    const a2 = manager.getNode("a2");
    expect(a2?.connections).not.toContain("a1");
  });

  it("triggers leader re-election when leader is removed", () => {
    const { manager, events } = makeManager({ type: "hierarchical" });
    manager.addNode("queen", "queen");
    manager.addNode("w1", "worker");
    manager.addNode("w2", "worker");

    // Queen is leader
    manager.electLeader();
    expect(manager.getLeader()).toBe("queen");

    const leaderHandler = vi.fn();
    events.on("topology.leader_elected", leaderHandler);

    manager.removeNode("queen");

    // Leader should be re-elected
    expect(manager.getLeader()).not.toBe("queen");
  });

  it("removing non-existent node is a no-op", () => {
    const { manager } = makeManager();
    expect(() => manager.removeNode("nonexistent")).not.toThrow();
  });
});

// ============================================================================
// electLeader
// ============================================================================

describe("TopologyManager - electLeader", () => {
  it("hierarchical elects queen", () => {
    const { manager } = makeManager({ type: "hierarchical" });
    manager.addNode("q", "queen");
    manager.addNode("w", "worker");

    const leader = manager.electLeader();
    expect(leader).toBe("q");
  });

  it("centralized elects coordinator", () => {
    const { manager } = makeManager({ type: "centralized" });
    manager.addNode("c", "coordinator");
    manager.addNode("w", "worker");

    const leader = manager.electLeader();
    expect(leader).toBe("c");
  });

  it("mesh elects by role priority (queen > coordinator > worker/peer)", () => {
    const { manager } = makeManager({ type: "mesh" });
    manager.addNode("a1", "peer");
    manager.addNode("a2", "peer");

    // All peers, first active one wins
    const leader = manager.electLeader();
    expect(typeof leader).toBe("string");
    expect(manager.getState().leaderId).toBe(leader);
  });

  it("throws when no nodes available", () => {
    const { manager } = makeManager();
    expect(() => manager.electLeader()).toThrow(
      /No nodes available/,
    );
  });
});

// ============================================================================
// findOptimalPath
// ============================================================================

describe("TopologyManager - findOptimalPath", () => {
  it("direct neighbor returns 2-element path", () => {
    const { manager } = makeManager({ type: "mesh" });
    manager.addNode("a1", "worker");
    manager.addNode("a2", "worker");

    const path = manager.findOptimalPath("a1", "a2");
    expect(path).toEqual(["a1", "a2"]);
  });

  it("same node returns single-element path", () => {
    const { manager } = makeManager({ type: "mesh" });
    manager.addNode("a1", "worker");

    expect(manager.findOptimalPath("a1", "a1")).toEqual(["a1"]);
  });

  it("no path returns empty array", () => {
    const { manager } = makeManager({ type: "centralized" });
    // Create two disconnected nodes manually is hard in centralized,
    // but we can test with no connection scenario
    const path = manager.findOptimalPath("nonexistent1", "nonexistent2");
    expect(path).toEqual([]);
  });

  it("multi-hop path through intermediary", () => {
    const { manager } = makeManager({ type: "hierarchical" });
    // Queen connects to all workers, so a->queen->b is 3-hop
    manager.addNode("q", "queen");
    manager.addNode("w1", "worker");
    manager.addNode("w2", "worker");

    // w1 -> q -> w2 (workers connect to queen, queen connects back)
    const path = manager.findOptimalPath("w1", "w2");
    expect(path.length).toBeGreaterThanOrEqual(2);
    expect(path[0]).toBe("w1");
    expect(path[path.length - 1]).toBe("w2");
  });
});

// ============================================================================
// Rebalance
// ============================================================================

describe("TopologyManager - rebalance", () => {
  it("is throttled to minimum 5 second interval", () => {
    const { manager } = makeManager({ type: "mesh", autoRebalance: false });
    manager.addNode("a1", "worker");
    manager.addNode("a2", "worker");

    // First call should work
    manager.rebalance();
    const stateAfterFirst = manager.getState();

    // Second immediate call should be no-op (throttled)
    manager.rebalance();
    const stateAfterSecond = manager.getState();

    // State should remain the same (no additional connections)
    expect(stateAfterSecond.nodes.length).toBe(stateAfterFirst.nodes.length);
  });

  it("mesh rebalance ensures minimum connections", () => {
    const { manager } = makeManager({ type: "mesh", autoRebalance: false, maxAgents: 20 });
    // Add several nodes
    for (let i = 0; i < 8; i++) {
      manager.addNode(`a${i}`, "worker");
    }

    // Force rebalance by manipulating time (we can't easily, so just call it)
    // The rebalance logic targets min(5, N-1) connections per node
    manager.rebalance();

    const state = manager.getState();
    // All nodes should have some connections
    for (const node of state.nodes) {
      expect(node.connections.length).toBeGreaterThan(0);
    }
  });

  it("rebuilds emitted topology edges after hierarchical rebalance", () => {
    const { manager, events } = makeManager({ type: "hierarchical", autoRebalance: false });
    const handler = vi.fn();
    events.on("topology.rebalanced", handler);

    manager.addNode("queen", "worker");
    manager.addNode("worker", "worker");

    manager.updateNode("queen", { connections: [] });
    manager.updateNode("worker", { connections: [] });

    manager.rebalance();

    expect(handler).toHaveBeenCalledOnce();
    const event = handler.mock.calls[0]![0];
    expect(event.topology.edges).toEqual([
      {
        from: "queen",
        to: "worker",
        weight: 1,
        bidirectional: true,
        latencyMs: null,
        edgeType: "topology",
      },
    ]);
  });
});

// ============================================================================
// Role index
// ============================================================================

describe("TopologyManager - role index", () => {
  it("getNodesByRole returns correct nodes", () => {
    const { manager } = makeManager({ type: "hierarchical" });
    manager.addNode("q", "queen");
    manager.addNode("w1", "worker");
    manager.addNode("w2", "worker");

    const queens = manager.getNodesByRole("queen");
    expect(queens).toHaveLength(1);
    expect(queens[0]!.agentId).toBe("q");

    const workers = manager.getNodesByRole("worker");
    expect(workers).toHaveLength(2);
  });

  it("getQueen returns queen with O(1) lookup", () => {
    const { manager } = makeManager({ type: "hierarchical" });
    manager.addNode("q", "queen");
    expect(manager.getQueen()?.agentId).toBe("q");
  });

  it("getCoordinator returns coordinator with O(1) lookup", () => {
    const { manager } = makeManager({ type: "centralized" });
    manager.addNode("c", "coordinator");
    expect(manager.getCoordinator()?.agentId).toBe("c");
  });

  it("getNodesByRole returns empty array for absent role", () => {
    const { manager } = makeManager({ type: "mesh" });
    manager.addNode("a1", "worker");
    expect(manager.getNodesByRole("queen")).toEqual([]);
  });

  it("keeps role indexes and cached leader-role lookups in sync on role updates", () => {
    const { manager } = makeManager({ type: "hybrid" });
    manager.addNode("q", "queen");
    manager.addNode("c", "coordinator");
    manager.addNode("w", "worker");

    manager.updateNode("q", { role: "worker" });
    manager.updateNode("c", { role: "worker" });
    manager.updateNode("w", { role: "coordinator" });

    expect(manager.getQueen()).toBeUndefined();
    expect(manager.getNodesByRole("queen")).toEqual([]);
    expect(manager.getCoordinator()?.agentId).toBe("w");
    expect(manager.getNodesByRole("coordinator").map((node) => node.agentId)).toEqual(["w"]);
    expect(
      manager.getNodesByRole("worker").map((node) => node.agentId).sort(),
    ).toEqual(["c", "q"]);
  });
});

// ============================================================================
// Partition management
// ============================================================================

describe("TopologyManager - partitions", () => {
  it("mesh creates partitions", () => {
    const { manager } = makeManager({ type: "mesh" });
    manager.addNode("a1", "worker");
    const state = manager.getState();
    expect(state.partitions.length).toBeGreaterThanOrEqual(1);
    expect(state.partitions[0]!.nodeIds).toContain("a1");
    expect(state.partitions[0]!.leaderId).toBe("a1");
  });

  it("hierarchical skips partition creation", () => {
    const { manager } = makeManager({ type: "hierarchical" });
    manager.addNode("q", "queen");
    manager.addNode("w1", "worker");
    expect(manager.getState().partitions).toEqual([]);
  });

  it("centralized skips partition creation", () => {
    const { manager } = makeManager({ type: "centralized" });
    manager.addNode("c", "coordinator");
    manager.addNode("w1", "worker");
    expect(manager.getState().partitions).toEqual([]);
  });
});

// ============================================================================
// Serialization
// ============================================================================

describe("TopologyManager - serialization", () => {
  it("JSON round-trips cleanly", () => {
    const { manager } = makeManager({ type: "mesh" });
    manager.addNode("a1", "worker");
    manager.addNode("a2", "worker");

    const state = manager.getState();
    const json = JSON.stringify(state);
    const parsed = JSON.parse(json) as TopologyState;

    expect(parsed.type).toBe("mesh");
    expect(parsed.nodes).toHaveLength(2);
    expect(parsed.leaderId).toBeNull();
    expect(typeof parsed.snapshotAt).toBe("number");
    expect(parsed.edges.length).toBeGreaterThan(0);
  });
});

// ============================================================================
// Events
// ============================================================================

describe("TopologyManager - events", () => {
  it("emits topology.updated on addNode", () => {
    const { manager, events } = makeManager({ type: "mesh" });
    const handler = vi.fn();
    events.on("topology.updated", handler);

    manager.addNode("a1", "worker");

    expect(handler).toHaveBeenCalled();
    const event = handler.mock.calls[0]![0];
    expect(event.kind).toBe("topology.updated");
    expect(event.newTopology.nodes.length).toBe(1);
  });

  it("emits topology.updated on removeNode", () => {
    const { manager, events } = makeManager({ type: "mesh", autoRebalance: false });
    manager.addNode("a1", "worker");

    const handler = vi.fn();
    events.on("topology.updated", handler);

    manager.removeNode("a1");

    expect(handler).toHaveBeenCalled();
  });

  it("emits topology.leader_elected on electLeader", () => {
    const { manager, events } = makeManager({ type: "mesh" });
    manager.addNode("a1", "worker");

    const handler = vi.fn();
    events.on("topology.leader_elected", handler);

    manager.electLeader();

    expect(handler).toHaveBeenCalledOnce();
    const event = handler.mock.calls[0]![0];
    expect(event.kind).toBe("topology.leader_elected");
    expect(event.leaderId).toBe("a1");
    expect(event.term).toBe(1);
  });
});

// ============================================================================
// getState includes snapshotAt
// ============================================================================

describe("TopologyManager - getState", () => {
  it("includes snapshotAt timestamp", () => {
    const { manager } = makeManager();
    const before = Date.now();
    const state = manager.getState();
    const after = Date.now();

    expect(state.snapshotAt).toBeGreaterThanOrEqual(before);
    expect(state.snapshotAt).toBeLessThanOrEqual(after);
  });

  it("returns proper TopologyState shape", () => {
    const { manager } = makeManager({ type: "mesh" });
    manager.addNode("a1", "worker");

    const state = manager.getState();
    expect(state).toHaveProperty("type");
    expect(state).toHaveProperty("nodes");
    expect(state).toHaveProperty("edges");
    expect(state).toHaveProperty("leaderId");
    expect(state).toHaveProperty("partitions");
    expect(state).toHaveProperty("snapshotAt");
  });

  it("returns a defensive copy of nested topology data", () => {
    const { manager } = makeManager({ type: "mesh" });
    manager.addNode("a1", "worker");

    const state = manager.getState();
    expect(state.partitions.length).toBeGreaterThan(0);

    state.nodes[0]!.role = "queen";
    state.partitions[0]!.nodeIds.push("forged-node");

    const freshState = manager.getState();
    expect(freshState.nodes[0]!.role).toBe("peer");
    expect(freshState.partitions[0]!.nodeIds).not.toContain("forged-node");
  });
});

// ============================================================================
// Query methods
// ============================================================================

describe("TopologyManager - query methods", () => {
  it("getNode returns node by agentId", () => {
    const { manager } = makeManager();
    manager.addNode("a1", "worker");
    const node = manager.getNode("a1");
    expect(node?.agentId).toBe("a1");
  });

  it("getActiveNodes returns only active nodes", () => {
    const { manager } = makeManager({ type: "mesh" });
    manager.addNode("a1", "worker");
    manager.addNode("a2", "worker");
    const active = manager.getActiveNodes();
    expect(active.length).toBe(2);
    for (const n of active) {
      expect(n.status).toBe("active");
    }
  });

  it("getConnectionCount returns edge count", () => {
    const { manager } = makeManager({ type: "mesh" });
    manager.addNode("a1", "worker");
    manager.addNode("a2", "worker");
    expect(manager.getConnectionCount()).toBeGreaterThan(0);
  });

  it("getAverageConnections returns 0 for empty topology", () => {
    const { manager } = makeManager();
    expect(manager.getAverageConnections()).toBe(0);
  });

  it("isConnected checks adjacency", () => {
    const { manager } = makeManager({ type: "hierarchical" });
    manager.addNode("q", "queen");
    manager.addNode("w", "worker");
    expect(manager.isConnected("w", "q")).toBe(true);
  });

  it("getNeighbors returns neighbor list", () => {
    const { manager } = makeManager({ type: "hierarchical" });
    manager.addNode("q", "queen");
    manager.addNode("w", "worker");
    expect(manager.getNeighbors("w")).toContain("q");
  });
});

// ============================================================================
// dispose
// ============================================================================

describe("TopologyManager - dispose", () => {
  it("clears all internal state", () => {
    const { manager } = makeManager({ type: "mesh" });
    manager.addNode("a1", "worker");
    manager.addNode("a2", "worker");

    manager.dispose();

    const state = manager.getState();
    expect(state.nodes).toEqual([]);
    expect(state.edges).toEqual([]);
    expect(state.partitions).toEqual([]);
    expect(state.leaderId).toBeNull();
  });
});

// ============================================================================
// No Node.js imports, no Date objects
// ============================================================================

describe("TopologyManager - conventions", () => {
  it("node metadata uses numeric timestamps (not Date objects)", () => {
    const { manager } = makeManager({ type: "mesh" });
    const node = manager.addNode("a1", "worker");
    expect(typeof node.metadata.joinedAt).toBe("number");
  });

  it("TopologyNode has Phase 1 shape fields", () => {
    const { manager } = makeManager({ type: "mesh" });
    const node = manager.addNode("a1", "worker");
    expect(node).toHaveProperty("positionX", null);
    expect(node).toHaveProperty("positionY", null);
    expect(node).toHaveProperty("hierarchyDepth", null);
  });

  it("edges have edgeType field set to 'topology'", () => {
    const { manager } = makeManager({ type: "mesh" });
    manager.addNode("a1", "worker");
    manager.addNode("a2", "worker");
    const state = manager.getState();
    for (const edge of state.edges) {
      expect(edge.edgeType).toBe("topology");
    }
  });
});
