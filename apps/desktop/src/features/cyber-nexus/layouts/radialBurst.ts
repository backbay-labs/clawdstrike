import type { LayoutPosition, NexusLayoutNode } from "./types";

const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5));

export interface RadialBurstConfig {
  minRadius?: number;
  maxRadius?: number;
  startAngle?: number;
}

export function calculateRadialBurstLayout(
  nodes: NexusLayoutNode[],
  config: RadialBurstConfig = {}
): Map<NexusLayoutNode["id"], LayoutPosition> {
  const positions = new Map<NexusLayoutNode["id"], LayoutPosition>();
  if (nodes.length === 0) return positions;

  const minRadius = config.minRadius ?? 3.2;
  const maxRadius = config.maxRadius ?? 11.4;
  const startAngle = config.startAngle ?? -Math.PI / 2;

  const ordered = [...nodes].sort((a, b) => {
    if (b.activityCount !== a.activityCount) return b.activityCount - a.activityCount;
    return a.id.localeCompare(b.id);
  });

  if (ordered.length === 1) {
    positions.set(ordered[0].id, { x: 0, y: 0.7, z: 0, col: 0, row: 0 });
    return positions;
  }

  ordered.forEach((node, index) => {
    const rank = index / (ordered.length - 1);
    const radius = minRadius + rank * (maxRadius - minRadius);
    const angle = startAngle + index * GOLDEN_ANGLE;
    const yBias = node.status === "critical" ? 1.8 : node.status === "warning" ? 1.1 : 0.6;
    const x = Math.cos(angle) * radius;
    const z = Math.sin(angle) * radius;
    positions.set(node.id, {
      x,
      y: yBias,
      z,
      col: Math.round(x),
      row: Math.round(z),
    });
  });

  return positions;
}
