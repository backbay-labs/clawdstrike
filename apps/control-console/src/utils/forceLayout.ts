export interface ForceNode {
  id: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
  color: string;
  label: string;
  radius: number;
  type: "agent" | "session";
}

export interface ForceEdge {
  source: string;
  target: string;
}

export interface ForceSimulation {
  nodes: ForceNode[];
  edges: ForceEdge[];
}

export function createSimulation(nodes: ForceNode[], edges: ForceEdge[]): ForceSimulation {
  return { nodes: nodes.map((n) => ({ ...n })), edges: [...edges] };
}

export function tickSimulation(
  sim: ForceSimulation,
  width: number,
  height: number,
): ForceSimulation {
  const nodes = sim.nodes.map((n) => ({ ...n }));
  const nodeMap = new Map(nodes.map((n) => [n.id, n]));

  // Charge repulsion
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i],
        b = nodes[j];
      let dx = b.x - a.x,
        dy = b.y - a.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const force = 500 / (dist * dist);
      dx = (dx / dist) * force;
      dy = (dy / dist) * force;
      a.vx -= dx;
      a.vy -= dy;
      b.vx += dx;
      b.vy += dy;
    }
  }

  // Spring attraction
  for (const edge of sim.edges) {
    const a = nodeMap.get(edge.source),
      b = nodeMap.get(edge.target);
    if (!a || !b) continue;
    const dx = b.x - a.x,
      dy = b.y - a.y;
    const dist = Math.sqrt(dx * dx + dy * dy) || 1;
    const force = (dist - 80) * 0.01;
    const fx = (dx / dist) * force,
      fy = (dy / dist) * force;
    a.vx += fx;
    a.vy += fy;
    b.vx -= fx;
    b.vy -= fy;
  }

  // Center gravity
  const cx = width / 2,
    cy = height / 2;
  for (const n of nodes) {
    n.vx += (cx - n.x) * 0.001;
    n.vy += (cy - n.y) * 0.001;
  }

  // Damping + position update + bounds
  for (const n of nodes) {
    n.vx *= 0.9;
    n.vy *= 0.9;
    n.x += n.vx;
    n.y += n.vy;
    n.x = Math.max(n.radius, Math.min(width - n.radius, n.x));
    n.y = Math.max(n.radius, Math.min(height - n.radius, n.y));
  }

  return { nodes, edges: sim.edges };
}
