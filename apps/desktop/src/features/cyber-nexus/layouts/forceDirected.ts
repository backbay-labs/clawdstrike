import type { StrikecellConnection } from "../types";
import type { LayoutPosition, NexusLayoutNode } from "./types";

interface SimNode {
  id: NexusLayoutNode["id"];
  x: number;
  z: number;
  vx: number;
  vz: number;
  activity: number;
}

export interface ForceDirectedConfig {
  repulsion?: number;
  attraction?: number;
  linkDistance?: number;
  damping?: number;
  iterations?: number;
}

function orderedPairKey(a: string, b: string): string {
  return a < b ? `${a}|${b}` : `${b}|${a}`;
}

export function calculateForceDirectedLayout(
  nodes: NexusLayoutNode[],
  connections: StrikecellConnection[],
  config: ForceDirectedConfig = {}
): Map<NexusLayoutNode["id"], LayoutPosition> {
  const positions = new Map<NexusLayoutNode["id"], LayoutPosition>();
  if (nodes.length === 0) return positions;

  const repulsion = config.repulsion ?? 75;
  const attraction = config.attraction ?? 0.08;
  const linkDistance = config.linkDistance ?? 6.2;
  const damping = config.damping ?? 0.86;
  const iterations = config.iterations ?? 100;

  const orderedNodes = [...nodes].sort((a, b) => a.id.localeCompare(b.id));

  const simNodes: SimNode[] = orderedNodes.map((node, index) => {
    const angle = (Math.PI * 2 * index) / Math.max(orderedNodes.length, 1);
    const radius = 5 + (index % 3);
    return {
      id: node.id,
      x: Math.cos(angle) * radius,
      z: Math.sin(angle) * radius,
      vx: 0,
      vz: 0,
      activity: Math.max(0.2, Math.min(2, node.activityCount / 20)),
    };
  });

  const strengthByPair = new Map<string, number>();
  for (const edge of connections) {
    const key = orderedPairKey(edge.sourceId, edge.targetId);
    const previous = strengthByPair.get(key) ?? 0;
    strengthByPair.set(key, Math.max(previous, edge.strength));
  }

  for (let step = 0; step < iterations; step += 1) {
    for (let i = 0; i < simNodes.length; i += 1) {
      const a = simNodes[i];
      for (let j = i + 1; j < simNodes.length; j += 1) {
        const b = simNodes[j];
        const dx = b.x - a.x;
        const dz = b.z - a.z;
        const distance = Math.max(0.55, Math.sqrt(dx * dx + dz * dz));

        const repel = (repulsion * (a.activity + b.activity) * 0.5) / (distance * distance);
        const fx = (dx / distance) * repel;
        const fz = (dz / distance) * repel;
        a.vx -= fx;
        a.vz -= fz;
        b.vx += fx;
        b.vz += fz;

        const edgeStrength = strengthByPair.get(orderedPairKey(a.id, b.id));
        if (edgeStrength) {
          const displacement = distance - linkDistance;
          const spring = attraction * displacement * edgeStrength;
          const sx = (dx / distance) * spring;
          const sz = (dz / distance) * spring;
          a.vx += sx;
          a.vz += sz;
          b.vx -= sx;
          b.vz -= sz;
        }
      }
    }

    for (const node of simNodes) {
      node.vx -= node.x * 0.01;
      node.vz -= node.z * 0.01;
      node.x += node.vx;
      node.z += node.vz;
      node.vx *= damping;
      node.vz *= damping;
    }
  }

  simNodes.forEach((node, index) => {
    positions.set(node.id, {
      x: node.x,
      y: 1 + (index % 3) * 0.3,
      z: node.z,
      col: Math.round(node.x),
      row: Math.round(node.z),
    });
  });

  return positions;
}
