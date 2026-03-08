import type { LayoutPosition, NexusLayoutNode } from "./types";

const STATUS_ORDER: Array<NexusLayoutNode["status"]> = [
  "critical",
  "warning",
  "healthy",
  "offline",
];

export interface TypedLanesConfig {
  laneSpacing?: number;
  itemSpacing?: number;
}

export function calculateTypedLanesLayout(
  nodes: NexusLayoutNode[],
  config: TypedLanesConfig = {},
): Map<NexusLayoutNode["id"], LayoutPosition> {
  const positions = new Map<NexusLayoutNode["id"], LayoutPosition>();
  if (nodes.length === 0) return positions;

  const laneSpacing = config.laneSpacing ?? 3.8;
  const itemSpacing = config.itemSpacing ?? 3.6;

  const groups = new Map<NexusLayoutNode["status"], NexusLayoutNode[]>();
  for (const node of nodes) {
    if (!groups.has(node.status)) {
      groups.set(node.status, []);
    }
    groups.get(node.status)?.push(node);
  }

  const lanes = [...groups.keys()].sort(
    (a, b) => STATUS_ORDER.indexOf(a) - STATUS_ORDER.indexOf(b),
  );
  const totalDepth = (lanes.length - 1) * laneSpacing;
  const zStart = -totalDepth / 2;

  lanes.forEach((status, laneIndex) => {
    const laneNodes = [...(groups.get(status) ?? [])].sort((a, b) => {
      if (b.activityCount !== a.activityCount) return b.activityCount - a.activityCount;
      return a.id.localeCompare(b.id);
    });
    const width = (laneNodes.length - 1) * itemSpacing;
    const xStart = -width / 2;

    laneNodes.forEach((node, itemIndex) => {
      const x = xStart + itemIndex * itemSpacing;
      const z = zStart + laneIndex * laneSpacing;
      positions.set(node.id, {
        x,
        y: node.status === "critical" ? 1.9 : node.status === "warning" ? 1.2 : 0.65,
        z,
        col: itemIndex,
        row: laneIndex,
      });
    });
  });

  return positions;
}
