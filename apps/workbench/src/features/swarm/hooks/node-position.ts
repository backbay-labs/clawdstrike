/**
 * Calculate a position for a new auto-created node, placing it to the right
 * of the rightmost existing node with slight vertical jitter.
 */
export function nextNodePosition(
  nodes: Array<{ position: { x: number; y: number } }>,
): { x: number; y: number } {
  if (nodes.length === 0) return { x: 200, y: 200 };
  const maxX = Math.max(...nodes.map((n) => n.position.x));
  const avgY =
    nodes.reduce((sum, n) => sum + n.position.y, 0) / nodes.length;
  return { x: maxX + 320, y: avgY + (Math.random() - 0.5) * 100 };
}
