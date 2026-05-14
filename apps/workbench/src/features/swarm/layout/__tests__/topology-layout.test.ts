/**
 * Tests for topology-layout -- pure-math layout algorithms for SwarmBoard
 * node positioning based on topology type.
 */
import { describe, it, expect } from "vitest";
import { computeLayout } from "../topology-layout";
import type { LayoutResult } from "../topology-layout";
import type { SwarmBoardNodeData, SwarmBoardEdge } from "@/features/swarm/swarm-board-types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type NodeType = SwarmBoardNodeData["nodeType"];

const mockNode = (
  id: string,
  nodeType: NodeType,
  pos?: { x: number; y: number },
) => ({
  id,
  position: pos ?? { x: 0, y: 0 },
  data: {
    title: id,
    status: "idle" as const,
    nodeType,
  } as SwarmBoardNodeData,
  type: "default" as const,
});

const mockEdge = (
  source: string,
  target: string,
  type?: SwarmBoardEdge["type"],
): SwarmBoardEdge => ({
  id: `edge-${source}-${target}`,
  source,
  target,
  type,
});

const viewport = { width: 800, height: 600 };

// ---------------------------------------------------------------------------
// Shared assertions
// ---------------------------------------------------------------------------

function assertAllPositionsFinite(result: LayoutResult, nodeCount: number) {
  expect(result.positions.size).toBe(nodeCount);
  for (const [, pos] of result.positions) {
    expect(Number.isFinite(pos.x)).toBe(true);
    expect(Number.isFinite(pos.y)).toBe(true);
  }
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

describe("computeLayout -- edge cases", () => {
  it("returns empty positions for empty node array", () => {
    const result = computeLayout([], [], "mesh", viewport);
    expect(result.positions.size).toBe(0);
  });

  it("returns single node positioned at viewport center", () => {
    const nodes = [mockNode("a", "agentSession")];
    const result = computeLayout(nodes, [], "mesh", viewport);
    expect(result.positions.size).toBe(1);
    const pos = result.positions.get("a")!;
    expect(pos.x).toBeCloseTo(400, 0);
    expect(pos.y).toBeCloseTo(300, 0);
  });
});

// ---------------------------------------------------------------------------
// Mesh (force-directed)
// ---------------------------------------------------------------------------

describe("computeLayout -- mesh", () => {
  it("returns positions for all 5 nodes within viewport bounds", () => {
    const nodes = [
      mockNode("a", "agentSession"),
      mockNode("b", "terminalTask"),
      mockNode("c", "terminalTask"),
      mockNode("d", "artifact"),
      mockNode("e", "receipt"),
    ];
    const edges = [
      mockEdge("a", "b"),
      mockEdge("a", "c"),
      mockEdge("b", "d"),
      mockEdge("a", "e"),
    ];

    const result = computeLayout(nodes, edges, "mesh", viewport);
    assertAllPositionsFinite(result, 5);

    // All positions within viewport bounds
    for (const [, pos] of result.positions) {
      expect(pos.x).toBeGreaterThanOrEqual(0);
      expect(pos.x).toBeLessThanOrEqual(viewport.width);
      expect(pos.y).toBeGreaterThanOrEqual(0);
      expect(pos.y).toBeLessThanOrEqual(viewport.height);
    }
  });

  it("no two nodes closer than 40px apart", () => {
    const nodes = [
      mockNode("a", "agentSession"),
      mockNode("b", "terminalTask"),
      mockNode("c", "terminalTask"),
      mockNode("d", "artifact"),
      mockNode("e", "receipt"),
    ];
    const edges = [
      mockEdge("a", "b"),
      mockEdge("a", "c"),
      mockEdge("b", "d"),
      mockEdge("a", "e"),
    ];

    const result = computeLayout(nodes, edges, "mesh", viewport);
    const positions = [...result.positions.values()];

    for (let i = 0; i < positions.length; i++) {
      for (let j = i + 1; j < positions.length; j++) {
        const dx = positions[i].x - positions[j].x;
        const dy = positions[i].y - positions[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        expect(dist).toBeGreaterThanOrEqual(40);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Hierarchical (Sugiyama-style)
// ---------------------------------------------------------------------------

describe("computeLayout -- hierarchical", () => {
  it("places agentSession.y < terminalTask.y < receipt.y", () => {
    const nodes = [
      mockNode("agent", "agentSession"),
      mockNode("task1", "terminalTask"),
      mockNode("task2", "terminalTask"),
      mockNode("receipt", "receipt"),
    ];
    const edges = [
      mockEdge("agent", "task1"),
      mockEdge("agent", "task2"),
      mockEdge("task1", "receipt"),
    ];

    const result = computeLayout(nodes, edges, "hierarchical", viewport);
    assertAllPositionsFinite(result, 4);

    const agentY = result.positions.get("agent")!.y;
    const task1Y = result.positions.get("task1")!.y;
    const task2Y = result.positions.get("task2")!.y;
    const receiptY = result.positions.get("receipt")!.y;

    expect(agentY).toBeLessThan(task1Y);
    expect(agentY).toBeLessThan(task2Y);
    expect(task1Y).toBeLessThan(receiptY);
  });

  it("centers layers horizontally within viewport", () => {
    const nodes = [
      mockNode("agent", "agentSession"),
      mockNode("task1", "terminalTask"),
      mockNode("task2", "terminalTask"),
    ];
    const edges = [
      mockEdge("agent", "task1"),
      mockEdge("agent", "task2"),
    ];

    const result = computeLayout(nodes, edges, "hierarchical", viewport);
    const agentX = result.positions.get("agent")!.x;
    // Single node in layer 0 should be centered horizontally
    expect(agentX).toBeCloseTo(400, -1);
  });
});

// ---------------------------------------------------------------------------
// Centralized (hub-spoke)
// ---------------------------------------------------------------------------

describe("computeLayout -- centralized", () => {
  it("places hub node near viewport center, spokes equidistant", () => {
    const nodes = [
      mockNode("hub", "agentSession"),
      mockNode("spoke1", "terminalTask"),
      mockNode("spoke2", "terminalTask"),
      mockNode("spoke3", "terminalTask"),
    ];
    const edges = [
      mockEdge("hub", "spoke1"),
      mockEdge("hub", "spoke2"),
      mockEdge("hub", "spoke3"),
    ];

    const result = computeLayout(nodes, edges, "centralized", viewport);
    assertAllPositionsFinite(result, 4);

    const hubPos = result.positions.get("hub")!;
    expect(hubPos.x).toBeCloseTo(400, 0);
    expect(hubPos.y).toBeCloseTo(300, 0);

    // All spokes should be equidistant from the hub
    const spokeDists = ["spoke1", "spoke2", "spoke3"].map((id) => {
      const pos = result.positions.get(id)!;
      const dx = pos.x - hubPos.x;
      const dy = pos.y - hubPos.y;
      return Math.sqrt(dx * dx + dy * dy);
    });

    // All spoke distances equal (within tolerance)
    expect(spokeDists[0]).toBeCloseTo(spokeDists[1], 0);
    expect(spokeDists[1]).toBeCloseTo(spokeDists[2], 0);
  });

  it("uses the highest-degree node as the hub when multiple agent sessions exist", () => {
    const nodes = [
      mockNode("agent-1", "agentSession"),
      mockNode("agent-2", "agentSession"),
      mockNode("task-1", "terminalTask"),
      mockNode("task-2", "terminalTask"),
    ];
    const edges = [
      mockEdge("agent-2", "task-1"),
      mockEdge("agent-2", "task-2"),
      mockEdge("agent-1", "task-1"),
    ];

    const result = computeLayout(nodes, edges, "centralized", viewport);
    const hubPos = result.positions.get("agent-2")!;

    expect(hubPos.x).toBeCloseTo(400, 0);
    expect(hubPos.y).toBeCloseTo(300, 0);
  });

  it("breaks equal-degree non-agent ties deterministically by node id", () => {
    const nodes = [
      mockNode("task-b", "terminalTask"),
      mockNode("task-a", "terminalTask"),
      mockNode("artifact-1", "artifact"),
      mockNode("receipt-1", "receipt"),
    ];
    const edges = [
      mockEdge("task-b", "artifact-1"),
      mockEdge("task-a", "receipt-1"),
    ];

    const result = computeLayout(nodes, edges, "centralized", viewport);
    const hubPos = result.positions.get("task-a")!;

    expect(hubPos.x).toBeCloseTo(400, 0);
    expect(hubPos.y).toBeCloseTo(300, 0);
  });
});

// ---------------------------------------------------------------------------
// Hybrid (Sugiyama backbone + force within ranks)
// ---------------------------------------------------------------------------

describe("computeLayout -- hybrid", () => {
  it("returns layered positions with valid coordinates", () => {
    const nodes = [
      mockNode("agent", "agentSession"),
      mockNode("task1", "terminalTask"),
      mockNode("task2", "terminalTask"),
      mockNode("artifact", "artifact"),
    ];
    const edges = [
      mockEdge("agent", "task1"),
      mockEdge("agent", "task2"),
      mockEdge("task1", "artifact"),
    ];

    const result = computeLayout(nodes, edges, "hybrid", viewport);
    assertAllPositionsFinite(result, 4);

    // Hierarchical backbone: agent above tasks above artifacts
    const agentY = result.positions.get("agent")!.y;
    const task1Y = result.positions.get("task1")!.y;
    const artifactY = result.positions.get("artifact")!.y;

    expect(agentY).toBeLessThan(task1Y);
    expect(task1Y).toBeLessThan(artifactY);
  });
});

// ---------------------------------------------------------------------------
// Adaptive (falls back to mesh)
// ---------------------------------------------------------------------------

describe("computeLayout -- adaptive", () => {
  it("falls back to mesh layout and returns valid positions", () => {
    const nodes = [
      mockNode("a", "agentSession"),
      mockNode("b", "terminalTask"),
      mockNode("c", "receipt"),
    ];
    const edges = [mockEdge("a", "b"), mockEdge("b", "c")];

    const result = computeLayout(nodes, edges, "adaptive", viewport);
    assertAllPositionsFinite(result, 3);

    // All within viewport (mesh property)
    for (const [, pos] of result.positions) {
      expect(pos.x).toBeGreaterThanOrEqual(0);
      expect(pos.x).toBeLessThanOrEqual(viewport.width);
      expect(pos.y).toBeGreaterThanOrEqual(0);
      expect(pos.y).toBeLessThanOrEqual(viewport.height);
    }
  });
});

// ---------------------------------------------------------------------------
// All positions finite (cross-topology)
// ---------------------------------------------------------------------------

describe("computeLayout -- all topologies produce finite positions", () => {
  const topologies = ["mesh", "hierarchical", "centralized", "hybrid", "adaptive"] as const;
  const nodes = [
    mockNode("a", "agentSession"),
    mockNode("b", "terminalTask"),
    mockNode("c", "artifact"),
  ];
  const edges = [mockEdge("a", "b"), mockEdge("b", "c")];

  for (const topo of topologies) {
    it(`${topo}: no NaN or Infinity in positions`, () => {
      const result = computeLayout(nodes, edges, topo, viewport);
      assertAllPositionsFinite(result, 3);
    });
  }
});
