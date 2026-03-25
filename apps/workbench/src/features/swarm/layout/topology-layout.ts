// ---------------------------------------------------------------------------
// Topology Layout -- pure-math layout algorithms for SwarmBoard node
// positioning. No React/DOM imports. Dispatched by topology type.
// ---------------------------------------------------------------------------

import type { Node } from "@xyflow/react";
import type {
  SwarmBoardNodeData,
  SwarmBoardEdge,
  SwarmNodeType,
} from "@/features/swarm/swarm-board-types";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * Result of a layout computation -- a map from node ID to its computed
 * position within the viewport.
 */
export interface LayoutResult {
  positions: Map<string, { x: number; y: number }>;
}

/** Supported topology types (mirroring @clawdstrike/swarm-engine TopologyType). */
type TopologyType = "mesh" | "hierarchical" | "centralized" | "hybrid" | "adaptive";

// ---------------------------------------------------------------------------
// Constants -- ported verbatim from control-console/src/utils/forceLayout.ts
// ---------------------------------------------------------------------------

const CHARGE = 500;
const SPRING_REST_LENGTH = 80;
const SPRING_K = 0.01;
const CENTER_GRAVITY = 0.001;
const DAMPING = 0.9;

/** SwarmBoard node radius for bounds clamping. */
const NODE_RADIUS = 60;
/** Number of force simulation iterations (damping=0.9 converges well by 100). */
const MESH_ITERATIONS = 100;

/** Vertical gap between layers in hierarchical/hybrid layouts. */
const RANK_SEP = 120;
/** Horizontal gap between nodes within a layer. */
const NODE_SEP = 80;

/** Iterations for 1D intra-rank force pass in hybrid layout. */
const HYBRID_INTRA_RANK_ITERATIONS = 50;

/** Prefer operational nodes as centralized hubs before falling back to id order. */
const HUB_PRIORITY: Record<SwarmNodeType, number> = {
  agentSession: 0,
  terminalTask: 1,
  diff: 2,
  artifact: 3,
  note: 4,
  receipt: 5,
};

// ---------------------------------------------------------------------------
// Layer assignment for hierarchical/hybrid layouts
// ---------------------------------------------------------------------------

const NODE_TYPE_LAYER: Record<SwarmNodeType, number> = {
  agentSession: 0,
  terminalTask: 1,
  artifact: 2,
  diff: 2,
  note: 2,
  receipt: 2,
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Compute node positions for the given topology type.
 *
 * @param nodes - React Flow nodes with SwarmBoardNodeData
 * @param edges - Board edges describing connectivity
 * @param topology - Which layout algorithm to use
 * @param viewport - Available viewport dimensions
 * @returns A map from node ID to computed {x, y} position
 */
export function computeLayout(
  nodes: Node<SwarmBoardNodeData>[],
  edges: SwarmBoardEdge[],
  topology: TopologyType,
  viewport: { width: number; height: number },
): LayoutResult {
  if (nodes.length === 0) {
    return { positions: new Map() };
  }

  if (nodes.length === 1) {
    const positions = new Map<string, { x: number; y: number }>();
    positions.set(nodes[0].id, { x: viewport.width / 2, y: viewport.height / 2 });
    return { positions };
  }

  switch (topology) {
    case "mesh":
      return meshLayout(nodes, edges, viewport);
    case "hierarchical":
      return hierarchicalLayout(nodes, edges, viewport);
    case "centralized":
      return centralizedLayout(nodes, edges, viewport);
    case "hybrid":
      return hybridLayout(nodes, edges, viewport);
    case "adaptive":
      // Adaptive defaults to mesh
      return meshLayout(nodes, edges, viewport);
    default:
      return meshLayout(nodes, edges, viewport);
  }
}

/**
 * Compute a layered layout for the engine-managed task DAG subgraph only.
 *
 * This keeps task decomposition readable without forcing artifact/receipt
 * nodes into the same layout pass.
 */
export function computeTaskDagLayout(
  nodes: Node<SwarmBoardNodeData>[],
  edges: SwarmBoardEdge[],
  viewport: { width: number; height: number },
): LayoutResult {
  const dagNodes = nodes.filter((node) => {
    const data = node.data as SwarmBoardNodeData;
    return (
      data.engineManaged === true &&
      (data.nodeType === "agentSession" || data.nodeType === "terminalTask")
    );
  });

  if (dagNodes.length === 0) {
    return { positions: new Map() };
  }

  const dagNodeIds = new Set(dagNodes.map((node) => node.id));
  const dagEdges = edges.filter((edge) =>
    (edge.type === "spawned" || edge.type === "dependency") &&
    dagNodeIds.has(edge.source) &&
    dagNodeIds.has(edge.target),
  );

  return hierarchicalLayout(dagNodes, dagEdges, viewport);
}

// ---------------------------------------------------------------------------
// Mesh layout (force-directed)
// Ported from apps/control-console/src/utils/forceLayout.ts
// ---------------------------------------------------------------------------

interface SimNode {
  id: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
}

/**
 * Force-directed mesh layout.
 *
 * Complexity: O(n^2) per iteration due to all-pairs charge repulsion,
 * run for MESH_ITERATIONS (100) ticks. This is fine for typical board
 * sizes (<50 nodes). For >50 nodes, consider debouncing layout calls
 * or offloading the simulation to a Web Worker to avoid blocking the
 * main thread.
 */
function meshLayout(
  nodes: Node<SwarmBoardNodeData>[],
  edges: SwarmBoardEdge[],
  viewport: { width: number; height: number },
): LayoutResult {
  const { width, height } = viewport;

  // Initialize simulation nodes -- spread evenly if no existing position,
  // otherwise use current position as starting point.
  const simNodes: SimNode[] = nodes.map((n, i) => {
    const hasPosition = n.position.x !== 0 || n.position.y !== 0;
    return {
      id: n.id,
      x: hasPosition ? n.position.x : (width / (nodes.length + 1)) * (i + 1),
      y: hasPosition ? n.position.y : (height / (nodes.length + 1)) * (i + 1),
      vx: 0,
      vy: 0,
    };
  });

  const nodeMap = new Map(simNodes.map((n) => [n.id, n]));

  // Run simulation for MESH_ITERATIONS ticks
  for (let iter = 0; iter < MESH_ITERATIONS; iter++) {
    // Charge repulsion (verbatim from forceLayout.ts)
    for (let i = 0; i < simNodes.length; i++) {
      for (let j = i + 1; j < simNodes.length; j++) {
        const a = simNodes[i],
          b = simNodes[j];
        let dx = b.x - a.x,
          dy = b.y - a.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const force = CHARGE / (dist * dist);
        dx = (dx / dist) * force;
        dy = (dy / dist) * force;
        a.vx -= dx;
        a.vy -= dy;
        b.vx += dx;
        b.vy += dy;
      }
    }

    // Spring attraction (verbatim from forceLayout.ts)
    for (const edge of edges) {
      const a = nodeMap.get(edge.source),
        b = nodeMap.get(edge.target);
      if (!a || !b) continue;
      const dx = b.x - a.x,
        dy = b.y - a.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const force = (dist - SPRING_REST_LENGTH) * SPRING_K;
      const fx = (dx / dist) * force,
        fy = (dy / dist) * force;
      a.vx += fx;
      a.vy += fy;
      b.vx -= fx;
      b.vy -= fy;
    }

    // Center gravity (verbatim from forceLayout.ts)
    const cx = width / 2,
      cy = height / 2;
    for (const n of simNodes) {
      n.vx += (cx - n.x) * CENTER_GRAVITY;
      n.vy += (cy - n.y) * CENTER_GRAVITY;
    }

    // Damping + position update + bounds (verbatim from forceLayout.ts)
    for (const n of simNodes) {
      n.vx *= DAMPING;
      n.vy *= DAMPING;
      n.x += n.vx;
      n.y += n.vy;
      n.x = Math.max(NODE_RADIUS, Math.min(width - NODE_RADIUS, n.x));
      n.y = Math.max(NODE_RADIUS, Math.min(height - NODE_RADIUS, n.y));
    }
  }

  const positions = new Map<string, { x: number; y: number }>();
  for (const n of simNodes) {
    positions.set(n.id, { x: n.x, y: n.y });
  }
  return { positions };
}

// ---------------------------------------------------------------------------
// Hierarchical layout (Sugiyama-style)
// ---------------------------------------------------------------------------

function hierarchicalLayout(
  nodes: Node<SwarmBoardNodeData>[],
  edges: SwarmBoardEdge[],
  viewport: { width: number; height: number },
): LayoutResult {
  const layers = assignLayers(nodes, edges);
  return layeredPositions(layers, viewport);
}

/**
 * Assign each node to a layer based on nodeType and edge structure.
 * Uses BFS from root nodes (no incoming edges), taking the max of
 * (parent_layer + 1, type_layer) for each node.
 */
function assignLayers(
  nodes: Node<SwarmBoardNodeData>[],
  edges: SwarmBoardEdge[],
): Map<number, Node<SwarmBoardNodeData>[]> {
  // Build adjacency and incoming-edge sets
  const children = new Map<string, string[]>();
  const incoming = new Set<string>();

  for (const edge of edges) {
    const list = children.get(edge.source) ?? [];
    list.push(edge.target);
    children.set(edge.source, list);
    incoming.add(edge.target);
  }

  // Layer assignment: BFS from roots
  const nodeById = new Map(nodes.map((n) => [n.id, n]));
  const layerOf = new Map<string, number>();

  // Start with roots (nodes with no incoming edges)
  const roots = nodes.filter((n) => !incoming.has(n.id));
  // If no roots found (cycle), use all agentSession nodes as roots
  const startNodes = roots.length > 0 ? roots : nodes.filter((n) => n.data.nodeType === "agentSession");
  // Final fallback: use all nodes
  const queue = (startNodes.length > 0 ? startNodes : nodes).map((n) => n.id);

  for (const id of queue) {
    const node = nodeById.get(id);
    if (!node) continue;
    const typeLayer = NODE_TYPE_LAYER[node.data.nodeType] ?? 0;
    layerOf.set(id, typeLayer);
  }

  // BFS to propagate layers
  const visited = new Set<string>();
  const bfsQueue = [...queue];
  while (bfsQueue.length > 0) {
    const id = bfsQueue.shift()!;
    if (visited.has(id)) continue;
    visited.add(id);

    const parentLayer = layerOf.get(id) ?? 0;
    const childIds = children.get(id) ?? [];
    for (const childId of childIds) {
      const childNode = nodeById.get(childId);
      if (!childNode) continue;
      const typeLayer = NODE_TYPE_LAYER[childNode.data.nodeType] ?? 0;
      const newLayer = Math.max(parentLayer + 1, typeLayer);
      const currentLayer = layerOf.get(childId);
      if (currentLayer === undefined || newLayer > currentLayer) {
        layerOf.set(childId, newLayer);
      }
      if (!visited.has(childId)) {
        bfsQueue.push(childId);
      }
    }
  }

  // Assign any unvisited nodes by their type layer
  for (const n of nodes) {
    if (!layerOf.has(n.id)) {
      layerOf.set(n.id, NODE_TYPE_LAYER[n.data.nodeType] ?? 0);
    }
  }

  // Group by layer
  const layers = new Map<number, Node<SwarmBoardNodeData>[]>();
  for (const n of nodes) {
    const layer = layerOf.get(n.id) ?? 0;
    const list = layers.get(layer) ?? [];
    list.push(n);
    layers.set(layer, list);
  }

  return layers;
}

/**
 * Convert layer assignments to (x, y) positions.
 * Each layer is centered horizontally within the viewport.
 */
function layeredPositions(
  layers: Map<number, Node<SwarmBoardNodeData>[]>,
  viewport: { width: number; height: number },
): LayoutResult {
  const positions = new Map<string, { x: number; y: number }>();
  const sortedLayers = [...layers.entries()].sort(([a], [b]) => a - b);
  const layerCount = sortedLayers.length;

  // Vertical centering: compute total height and center in viewport
  const totalHeight = (layerCount - 1) * RANK_SEP;
  const startY = Math.max(NODE_RADIUS, (viewport.height - totalHeight) / 2);

  for (let li = 0; li < sortedLayers.length; li++) {
    const [, layerNodes] = sortedLayers[li];
    const y = startY + li * RANK_SEP;
    const layerWidth = (layerNodes.length - 1) * NODE_SEP;
    const startX = Math.max(NODE_RADIUS, (viewport.width - layerWidth) / 2);

    for (let ni = 0; ni < layerNodes.length; ni++) {
      positions.set(layerNodes[ni].id, {
        x: startX + ni * NODE_SEP,
        y,
      });
    }
  }

  return { positions };
}

// ---------------------------------------------------------------------------
// Centralized layout (hub-spoke)
// ---------------------------------------------------------------------------

function centralizedLayout(
  nodes: Node<SwarmBoardNodeData>[],
  edges: SwarmBoardEdge[],
  viewport: { width: number; height: number },
): LayoutResult {
  const { width, height } = viewport;
  const cx = width / 2;
  const cy = height / 2;

  const degreeById = new Map<string, number>();
  for (const node of nodes) {
    degreeById.set(node.id, 0);
  }
  for (const edge of edges) {
    degreeById.set(edge.source, (degreeById.get(edge.source) ?? 0) + 1);
    degreeById.set(edge.target, (degreeById.get(edge.target) ?? 0) + 1);
  }

  const hub = [...nodes].sort((a, b) => {
    const degreeDelta = (degreeById.get(b.id) ?? 0) - (degreeById.get(a.id) ?? 0);
    if (degreeDelta !== 0) {
      return degreeDelta;
    }

    const priorityDelta =
      (HUB_PRIORITY[a.data.nodeType] ?? Number.MAX_SAFE_INTEGER) -
      (HUB_PRIORITY[b.data.nodeType] ?? Number.MAX_SAFE_INTEGER);
    if (priorityDelta !== 0) {
      return priorityDelta;
    }

    return a.id.localeCompare(b.id);
  })[0];
  const spokes = nodes.filter((n) => n.id !== hub.id);

  const positions = new Map<string, { x: number; y: number }>();
  positions.set(hub.id, { x: cx, y: cy });

  if (spokes.length === 0) return { positions };

  // Spoke radius: 35% of min dimension
  const radius = Math.min(width, height) * 0.35;

  for (let i = 0; i < spokes.length; i++) {
    const angle = (2 * Math.PI * i) / spokes.length;
    positions.set(spokes[i].id, {
      x: cx + radius * Math.cos(angle),
      y: cy + radius * Math.sin(angle),
    });
  }

  return { positions };
}

// ---------------------------------------------------------------------------
// Hybrid layout (Sugiyama backbone + 1D force within ranks)
// ---------------------------------------------------------------------------

function hybridLayout(
  nodes: Node<SwarmBoardNodeData>[],
  edges: SwarmBoardEdge[],
  viewport: { width: number; height: number },
): LayoutResult {
  // Step 1: Hierarchical layer assignment and initial positions
  const layers = assignLayers(nodes, edges);
  const initial = layeredPositions(layers, viewport);

  // Step 2: Within each rank, run a 1D force pass on x-axis only
  const sortedLayers = [...layers.entries()].sort(([a], [b]) => a - b);

  for (const [, layerNodes] of sortedLayers) {
    if (layerNodes.length <= 1) continue;

    // Build 1D simulation state (x positions + velocities)
    const simX: { id: string; x: number; vx: number }[] = layerNodes.map((n) => ({
      id: n.id,
      x: initial.positions.get(n.id)?.x ?? viewport.width / 2,
      vx: 0,
    }));

    // Build intra-rank edge set (only edges between nodes in this rank)
    const rankIds = new Set(layerNodes.map((n) => n.id));
    const rankEdges = edges.filter((e) => rankIds.has(e.source) && rankIds.has(e.target));
    const simMap = new Map(simX.map((s) => [s.id, s]));

    for (let iter = 0; iter < HYBRID_INTRA_RANK_ITERATIONS; iter++) {
      // 1D charge repulsion
      for (let i = 0; i < simX.length; i++) {
        for (let j = i + 1; j < simX.length; j++) {
          const a = simX[i], b = simX[j];
          let dx = b.x - a.x;
          const dist = Math.abs(dx) || 1;
          const force = CHARGE / (dist * dist);
          dx = (dx / dist) * force;
          a.vx -= dx;
          b.vx += dx;
        }
      }

      // 1D spring attraction
      for (const edge of rankEdges) {
        const a = simMap.get(edge.source), b = simMap.get(edge.target);
        if (!a || !b) continue;
        const dx = b.x - a.x;
        const dist = Math.abs(dx) || 1;
        const force = (dist - SPRING_REST_LENGTH) * SPRING_K;
        const fx = (dx / dist) * force;
        a.vx += fx;
        b.vx -= fx;
      }

      // Center gravity (1D)
      const centerX = viewport.width / 2;
      for (const s of simX) {
        s.vx += (centerX - s.x) * CENTER_GRAVITY;
      }

      // Damping + update + bounds
      for (const s of simX) {
        s.vx *= DAMPING;
        s.x += s.vx;
        s.x = Math.max(NODE_RADIUS, Math.min(viewport.width - NODE_RADIUS, s.x));
      }
    }

    // Write back x positions (keep y from hierarchical)
    for (const s of simX) {
      const pos = initial.positions.get(s.id);
      if (pos) {
        pos.x = s.x;
      }
    }
  }

  return initial;
}
