import type { Node } from "@xyflow/react";
import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";

export const SWARM_BOARD_GRID_GAP = 20;
export const SWARM_BOARD_GRID_MAJOR_GAP = 80;
export const SWARM_BOARD_PAN_ON_DRAG_BUTTONS = [1];
export const SWARM_BOARD_ZOOM_ACTIVATION_KEY_CODE = ["Meta", "Control"] as const;
export const SWARM_BOARD_PAN_ON_SCROLL_SPEED = 1.15;
export const SWARM_BOARD_SHORTCUT_HINT = "1-6 add / arrows nudge / F fit / G follow";

export function nudgeSelectedBoardNodes(
  nodes: Array<Node<SwarmBoardNodeData>>,
  selectedNodeId: string | null,
  key: string,
  step: number = SWARM_BOARD_GRID_GAP,
): Array<Node<SwarmBoardNodeData>> | null {
  const delta = {
    ArrowUp: { x: 0, y: -step },
    ArrowDown: { x: 0, y: step },
    ArrowLeft: { x: -step, y: 0 },
    ArrowRight: { x: step, y: 0 },
  }[key];

  if (!delta) {
    return null;
  }

  const selectedIds = new Set(
    nodes.filter((node) => node.selected).map((node) => node.id),
  );

  if (selectedIds.size === 0 && selectedNodeId) {
    selectedIds.add(selectedNodeId);
  }

  if (selectedIds.size === 0) {
    return null;
  }

  return nodes.map((node) =>
    selectedIds.has(node.id)
      ? {
          ...node,
          position: {
            x: node.position.x + delta.x,
            y: node.position.y + delta.y,
          },
        }
      : node,
  );
}
