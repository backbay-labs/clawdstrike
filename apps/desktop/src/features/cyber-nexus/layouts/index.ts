import type { NexusLayoutMode, StrikecellConnection } from "../types";
import type { LayoutMeta, LayoutPosition, NexusLayoutNode } from "./types";
import { calculateForceDirectedLayout } from "./forceDirected";
import { calculateRadialBurstLayout } from "./radialBurst";
import { calculateTypedLanesLayout } from "./typedLanes";

export * from "./types";
export * from "./forceDirected";
export * from "./radialBurst";
export * from "./typedLanes";

export const LAYOUT_METADATA: Record<NexusLayoutMode, LayoutMeta> = {
  radial: {
    id: "radial",
    name: "Radial Burst",
    shortcut: "R",
    icon: "◎",
  },
  "typed-lanes": {
    id: "typed-lanes",
    name: "Typed Lanes",
    shortcut: "L",
    icon: "≡",
  },
  "force-directed": {
    id: "force-directed",
    name: "Force Directed",
    shortcut: "F",
    icon: "✶",
  },
};

export const ALL_LAYOUT_MODES: NexusLayoutMode[] = ["radial", "typed-lanes", "force-directed"];

export function getLayoutModeFromShortcut(key: string): NexusLayoutMode | null {
  const upper = key.toUpperCase();
  for (const mode of ALL_LAYOUT_MODES) {
    if (LAYOUT_METADATA[mode].shortcut === upper) return mode;
  }
  return null;
}

export function calculateLayoutPositions(
  mode: NexusLayoutMode,
  nodes: NexusLayoutNode[],
  connections: StrikecellConnection[]
): Map<NexusLayoutNode["id"], LayoutPosition> {
  switch (mode) {
    case "typed-lanes":
      return calculateTypedLanesLayout(nodes);
    case "force-directed":
      return calculateForceDirectedLayout(nodes, connections);
    case "radial":
    default:
      return calculateRadialBurstLayout(nodes);
  }
}
