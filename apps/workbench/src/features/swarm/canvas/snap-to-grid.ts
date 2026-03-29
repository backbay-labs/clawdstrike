/**
 * Snap-to-grid pure functions for the swarm board canvas.
 *
 * Nodes snap to the nearest grid intersection on drop (free drag during
 * movement, snap on release). The grid size matches SWARM_BOARD_GRID_GAP.
 */

export const SNAP_GRID_SIZE = 20;

export function snapToGrid(value: number, grid: number = SNAP_GRID_SIZE): number {
  return Math.round(value / grid) * grid || 0;
}

export function snapPositionToGrid(
  position: { x: number; y: number },
  grid: number = SNAP_GRID_SIZE,
): { x: number; y: number } {
  return {
    x: snapToGrid(position.x, grid),
    y: snapToGrid(position.y, grid),
  };
}

export function positionNeedsSnap(
  position: { x: number; y: number },
  grid: number = SNAP_GRID_SIZE,
): boolean {
  const snapped = snapPositionToGrid(position, grid);
  return snapped.x !== position.x || snapped.y !== position.y;
}
