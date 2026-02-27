import { describe, it, expect } from "vitest";
import { createSimulation, tickSimulation, type ForceNode, type ForceEdge } from "./forceLayout";

function makeNode(id: string, x = 50, y = 50): ForceNode {
  return { id, x, y, vx: 0, vy: 0, color: "#fff", label: id, radius: 10, type: "agent" };
}

describe("createSimulation", () => {
  it("creates a simulation with nodes and edges", () => {
    const nodes = [makeNode("a"), makeNode("b")];
    const edges: ForceEdge[] = [{ source: "a", target: "b" }];
    const sim = createSimulation(nodes, edges);
    expect(sim.nodes).toHaveLength(2);
    expect(sim.edges).toHaveLength(1);
  });
});

describe("tickSimulation", () => {
  it("moves nodes apart when near each other", () => {
    // Slightly offset to avoid exact-overlap degenerate case
    const nodes = [makeNode("a", 100, 100), makeNode("b", 101, 100)];
    const edges: ForceEdge[] = [];
    let sim = createSimulation(nodes, edges);

    // Tick multiple times
    for (let i = 0; i < 20; i++) {
      sim = tickSimulation(sim, 400, 400);
    }

    // Nodes should have moved apart due to charge repulsion
    const dist = Math.sqrt(
      (sim.nodes[0].x - sim.nodes[1].x) ** 2 +
      (sim.nodes[0].y - sim.nodes[1].y) ** 2,
    );
    expect(dist).toBeGreaterThan(5);
  });

  it("keeps nodes within bounds", () => {
    const nodes = [makeNode("a", 0, 0)];
    let sim = createSimulation(nodes, []);

    for (let i = 0; i < 50; i++) {
      sim = tickSimulation(sim, 200, 200);
    }

    for (const node of sim.nodes) {
      expect(node.x).toBeGreaterThanOrEqual(0);
      expect(node.x).toBeLessThanOrEqual(200);
      expect(node.y).toBeGreaterThanOrEqual(0);
      expect(node.y).toBeLessThanOrEqual(200);
    }
  });

  it("pulls connected nodes together", () => {
    const nodes = [makeNode("a", 10, 100), makeNode("b", 390, 100)];
    const edges: ForceEdge[] = [{ source: "a", target: "b" }];
    let sim = createSimulation(nodes, edges);

    for (let i = 0; i < 50; i++) {
      sim = tickSimulation(sim, 400, 200);
    }

    // Connected nodes should be closer than their starting distance
    const dist = Math.abs(sim.nodes[0].x - sim.nodes[1].x);
    expect(dist).toBeLessThan(380);
  });
});
