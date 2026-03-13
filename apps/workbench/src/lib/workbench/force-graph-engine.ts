/**
 * Hierarchical DAG layout engine for delegation graphs.
 *
 * Replaces the force-directed approach with a structured Sugiyama-style
 * layered layout that produces clean, readable top-to-bottom hierarchies.
 *
 * Algorithm:
 *   1. Detect & temporarily reverse back-edges (cycles)
 *   2. Assign layers via longest-path from roots
 *   3. Order nodes within layers (barycenter heuristic, 4 sweeps)
 *   4. Position nodes with even spacing
 */

import type {
  DelegationGraph,
  DelegationEdge,
} from "./delegation-types";

// ---------------------------------------------------------------------------
// Layout types
// ---------------------------------------------------------------------------

export interface LayoutNode {
  id: string;
  x: number;
  y: number;
  width: number;
  height: number;
  layer: number;
  order: number;
}

export interface LayoutEdge {
  id: string;
  from: string;
  to: string;
  /** SVG path `d` attribute for a smooth cubic bezier */
  path: string;
  /** True if this edge goes upward (back-edge in the DAG) */
  isBackEdge: boolean;
}

export interface GraphLayoutResult {
  nodes: Map<string, LayoutNode>;
  edges: LayoutEdge[];
  width: number;
  height: number;
}

export interface LayoutOptions {
  nodeWidth?: number;
  nodeHeight?: number;
  layerGap?: number;
  nodeGap?: number;
  padding?: number;
}

const DEFAULTS: Required<LayoutOptions> = {
  nodeWidth: 168,
  nodeHeight: 48,
  layerGap: 100,
  nodeGap: 32,
  padding: 60,
};

// ---------------------------------------------------------------------------
// Main layout function
// ---------------------------------------------------------------------------

export function computeHierarchicalLayout(
  graph: DelegationGraph,
  options?: LayoutOptions,
): GraphLayoutResult {
  const opts = { ...DEFAULTS, ...options };
  const { nodeWidth, nodeHeight, layerGap, nodeGap, padding } = opts;

  if (graph.nodes.length === 0) {
    return { nodes: new Map(), edges: [], width: 0, height: 0 };
  }

  // Build adjacency
  const children = new Map<string, string[]>();
  const parents = new Map<string, string[]>();

  for (const n of graph.nodes) {
    children.set(n.id, []);
    parents.set(n.id, []);
  }

  const nodeIds = new Set(graph.nodes.map((n) => n.id));
  const backEdgeIds = new Set<string>();

  // Step 1: Detect back-edges via DFS
  // Pre-build outgoing adjacency list so DFS is O(V+E) not O(V×E)
  const outgoing = new Map<string, DelegationEdge[]>();
  for (const n of graph.nodes) outgoing.set(n.id, []);
  for (const e of graph.edges) {
    if (nodeIds.has(e.from) && nodeIds.has(e.to)) {
      outgoing.get(e.from)!.push(e);
    }
  }

  const visited = new Set<string>();
  const inStack = new Set<string>();
  const forwardEdges: DelegationEdge[] = [];

  function dfs(startId: string) {
    // Iterative DFS with explicit stack to avoid stack overflow on deep chains.
    // Each frame tracks: the node id, its outgoing edges, and the current index
    // into those edges. When all edges are exhausted we "return" (pop + remove
    // from inStack), exactly mirroring the recursive version.
    const stack: { nodeId: string; edges: DelegationEdge[]; idx: number }[] = [];

    visited.add(startId);
    inStack.add(startId);
    stack.push({ nodeId: startId, edges: outgoing.get(startId) ?? [], idx: 0 });

    while (stack.length > 0) {
      const frame = stack[stack.length - 1];

      if (frame.idx < frame.edges.length) {
        const e = frame.edges[frame.idx++];
        if (inStack.has(e.to)) {
          backEdgeIds.add(e.id);
        } else if (!visited.has(e.to)) {
          visited.add(e.to);
          inStack.add(e.to);
          stack.push({ nodeId: e.to, edges: outgoing.get(e.to) ?? [], idx: 0 });
        }
      } else {
        // All edges explored — backtrack
        inStack.delete(frame.nodeId);
        stack.pop();
      }
    }
  }

  // Find roots (no incoming edges) to start DFS
  const hasIncoming = new Set<string>();
  for (const e of graph.edges) {
    if (nodeIds.has(e.from) && nodeIds.has(e.to)) {
      hasIncoming.add(e.to);
    }
  }
  const roots = graph.nodes.filter((n) => !hasIncoming.has(n.id));
  if (roots.length === 0) roots.push(graph.nodes[0]);

  for (const r of roots) {
    if (!visited.has(r.id)) dfs(r.id);
  }
  // Visit any remaining unvisited nodes
  for (const n of graph.nodes) {
    if (!visited.has(n.id)) dfs(n.id);
  }

  // Build forward-only adjacency (back-edges reversed for layering)
  for (const e of graph.edges) {
    if (!nodeIds.has(e.from) || !nodeIds.has(e.to)) continue;
    if (backEdgeIds.has(e.id)) {
      // Reverse for layout purposes
      forwardEdges.push({ ...e, from: e.to, to: e.from });
    } else {
      forwardEdges.push(e);
    }
  }

  for (const e of forwardEdges) {
    children.get(e.from)?.push(e.to);
    parents.get(e.to)?.push(e.from);
  }

  // Step 2: Assign layers via longest path from roots (BFS)
  const layers = new Map<string, number>();

  // Initialize all to 0
  for (const n of graph.nodes) layers.set(n.id, 0);

  // Topological order via Kahn's algorithm
  const inDegree = new Map<string, number>();
  for (const n of graph.nodes) inDegree.set(n.id, 0);
  for (const e of forwardEdges) {
    inDegree.set(e.to, (inDegree.get(e.to) ?? 0) + 1);
  }

  const queue: string[] = [];
  for (const n of graph.nodes) {
    if ((inDegree.get(n.id) ?? 0) === 0) queue.push(n.id);
  }

  const processed = new Set<string>();
  let qi = 0;
  while (qi < queue.length) {
    const cur = queue[qi++];
    processed.add(cur);
    const curLayer = layers.get(cur) ?? 0;
    for (const child of children.get(cur) ?? []) {
      const newLayer = curLayer + 1;
      if (newLayer > (layers.get(child) ?? 0)) {
        layers.set(child, newLayer);
      }
      const deg = (inDegree.get(child) ?? 1) - 1;
      inDegree.set(child, deg);
      if (deg === 0) queue.push(child);
    }
  }

  // Handle disconnected components or residual cycles: treat unprocessed
  // nodes as additional roots and re-run Kahn's from them.
  if (processed.size < graph.nodes.length) {
    const queue2: string[] = [];
    for (const n of graph.nodes) {
      if (!processed.has(n.id)) {
        queue2.push(n.id);
      }
    }
    let qi2 = 0;
    while (qi2 < queue2.length) {
      const cur = queue2[qi2++];
      if (processed.has(cur)) continue;
      processed.add(cur);
      const curLayer = layers.get(cur) ?? 0;
      for (const child of children.get(cur) ?? []) {
        const newLayer = curLayer + 1;
        if (newLayer > (layers.get(child) ?? 0)) {
          layers.set(child, newLayer);
        }
        if (!processed.has(child)) {
          queue2.push(child);
        }
      }
    }
  }

  // Group nodes by layer
  let maxLayer = 0;
  for (const v of layers.values()) {
    if (v > maxLayer) maxLayer = v;
  }
  const layerBuckets: string[][] = Array.from({ length: maxLayer + 1 }, () => []);
  for (const n of graph.nodes) {
    layerBuckets[layers.get(n.id) ?? 0].push(n.id);
  }

  // Step 3: Order within layers (barycenter heuristic)
  // Initialize order by insertion
  const order = new Map<string, number>();
  for (const bucket of layerBuckets) {
    bucket.forEach((id, i) => order.set(id, i));
  }

  // 4 sweeps (2 down, 2 up)
  for (let sweep = 0; sweep < 4; sweep++) {
    const topDown = sweep % 2 === 0;
    const start = topDown ? 1 : maxLayer - 1;
    const end = topDown ? maxLayer + 1 : -1;
    const step = topDown ? 1 : -1;

    for (let l = start; l !== end; l += step) {
      const bucket = layerBuckets[l];
      const barycenters = new Map<string, number>();

      for (const nodeId of bucket) {
        const neighbors = topDown
          ? (parents.get(nodeId) ?? [])
          : (children.get(nodeId) ?? []);
        if (neighbors.length === 0) {
          barycenters.set(nodeId, order.get(nodeId) ?? 0);
        } else {
          const avg =
            neighbors.reduce((sum, nId) => sum + (order.get(nId) ?? 0), 0) /
            neighbors.length;
          barycenters.set(nodeId, avg);
        }
      }

      bucket.sort((a, b) => (barycenters.get(a) ?? 0) - (barycenters.get(b) ?? 0));
      bucket.forEach((id, i) => order.set(id, i));
    }
  }

  // Step 4: Position nodes
  const layoutNodes = new Map<string, LayoutNode>();

  // Find the widest layer for centering
  let maxBucketWidth = 0;
  for (const b of layerBuckets) {
    const w = b.length * (nodeWidth + nodeGap) - nodeGap;
    if (w > maxBucketWidth) maxBucketWidth = w;
  }
  const totalWidth = maxBucketWidth + padding * 2;
  const totalHeight = (maxLayer + 1) * (nodeHeight + layerGap) - layerGap + padding * 2;

  for (let l = 0; l <= maxLayer; l++) {
    const bucket = layerBuckets[l];
    const bucketWidth = bucket.length * (nodeWidth + nodeGap) - nodeGap;
    const offsetX = (totalWidth - bucketWidth) / 2;
    const y = padding + l * (nodeHeight + layerGap);

    for (let i = 0; i < bucket.length; i++) {
      const id = bucket[i];
      const x = offsetX + i * (nodeWidth + nodeGap);
      layoutNodes.set(id, {
        id,
        x,
        y,
        width: nodeWidth,
        height: nodeHeight,
        layer: l,
        order: i,
      });
    }
  }

  // Step 5: Compute edge paths (cubic bezier)
  const layoutEdges: LayoutEdge[] = [];

  for (const e of graph.edges) {
    if (!nodeIds.has(e.from) || !nodeIds.has(e.to)) continue;
    const fromNode = layoutNodes.get(e.from);
    const toNode = layoutNodes.get(e.to);
    if (!fromNode || !toNode) continue;

    const isBack = backEdgeIds.has(e.id);

    // Source: bottom center of from node, Target: top center of to node
    const fromCx = fromNode.x + fromNode.width / 2;
    const fromBot = fromNode.y + fromNode.height;
    const toCx = toNode.x + toNode.width / 2;
    const toTop = toNode.y;

    let path: string;

    if (isBack) {
      // Back-edge: draw curving to the right side
      const fromTop = fromNode.y;
      const toBot = toNode.y + toNode.height;
      const rightOffset = Math.max(totalWidth * 0.06, 40);
      const rightX = Math.max(fromNode.x + fromNode.width, toNode.x + toNode.width) + rightOffset;
      path = `M ${fromCx} ${fromTop} C ${fromCx} ${fromTop - 30}, ${rightX} ${fromTop - 30}, ${rightX} ${(fromTop + toBot) / 2} S ${toCx} ${toBot + 30}, ${toCx} ${toBot}`;
    } else if (Math.abs(fromNode.layer - toNode.layer) <= 1) {
      // Normal single-layer-gap edge: smooth cubic
      const midY = (fromBot + toTop) / 2;
      path = `M ${fromCx} ${fromBot} C ${fromCx} ${midY}, ${toCx} ${midY}, ${toCx} ${toTop}`;
    } else {
      // Multi-layer gap: use a taller cubic
      const ctrl1Y = fromBot + (toTop - fromBot) * 0.3;
      const ctrl2Y = fromBot + (toTop - fromBot) * 0.7;
      path = `M ${fromCx} ${fromBot} C ${fromCx} ${ctrl1Y}, ${toCx} ${ctrl2Y}, ${toCx} ${toTop}`;
    }

    layoutEdges.push({
      id: e.id,
      from: e.from,
      to: e.to,
      path,
      isBackEdge: isBack,
    });
  }

  return {
    nodes: layoutNodes,
    edges: layoutEdges,
    width: totalWidth,
    height: totalHeight,
  };
}

// ---------------------------------------------------------------------------
// BFS path tracing (kept from previous implementation)
// ---------------------------------------------------------------------------

export interface TracedPath {
  nodeIds: string[];
  edgeIds: string[];
}

export function tracePath(
  graph: DelegationGraph,
  targetId: string,
): TracedPath | null {
  const root = graph.nodes.find(
    (n) => n.kind === "Principal" && n.trustLevel === "System",
  );
  const rootId = root?.id ?? graph.nodes[0]?.id;
  if (!rootId || rootId === targetId) {
    return { nodeIds: [targetId], edgeIds: [] };
  }

  const adj = new Map<string, { neighbor: string; edgeId: string }[]>();
  for (const edge of graph.edges) {
    if (!adj.has(edge.from)) adj.set(edge.from, []);
    adj.get(edge.from)!.push({ neighbor: edge.to, edgeId: edge.id });
    if (!adj.has(edge.to)) adj.set(edge.to, []);
    adj.get(edge.to)!.push({ neighbor: edge.from, edgeId: edge.id });
  }

  const visited = new Set<string>();
  const parent = new Map<string, { from: string; edgeId: string }>();
  const queue = [rootId];
  visited.add(rootId);

  let qi = 0;
  while (qi < queue.length) {
    const current = queue[qi++];
    if (current === targetId) break;
    for (const { neighbor, edgeId } of adj.get(current) ?? []) {
      if (!visited.has(neighbor)) {
        visited.add(neighbor);
        parent.set(neighbor, { from: current, edgeId });
        queue.push(neighbor);
      }
    }
  }

  if (!visited.has(targetId)) return null;

  const nodeIds: string[] = [];
  const edgeIds: string[] = [];
  let cur = targetId;
  while (cur !== rootId) {
    nodeIds.push(cur);
    const p = parent.get(cur);
    if (!p) break;
    edgeIds.push(p.edgeId);
    cur = p.from;
  }
  nodeIds.push(rootId);
  nodeIds.reverse();
  edgeIds.reverse();

  return { nodeIds, edgeIds };
}

// ---------------------------------------------------------------------------
// Fit-to-viewport helper
// ---------------------------------------------------------------------------

export function computeFitTransform(
  layout: GraphLayoutResult,
  viewportWidth: number,
  viewportHeight: number,
  padding: number = 40,
): { panX: number; panY: number; zoom: number } {
  if (layout.nodes.size === 0) {
    return { panX: 0, panY: 0, zoom: 1 };
  }

  const w = layout.width + padding * 2;
  const h = layout.height + padding * 2;
  const zoom = Math.min(viewportWidth / w, viewportHeight / h, 1.5);
  const panX = (viewportWidth - layout.width * zoom) / 2;
  const panY = (viewportHeight - layout.height * zoom) / 2;

  return { panX, panY, zoom };
}
