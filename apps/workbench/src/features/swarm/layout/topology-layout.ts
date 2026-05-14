import type { Node } from "@xyflow/react";
import type {
  SwarmBoardNodeData,
  SwarmBoardEdge,
  SwarmNodeType,
} from "@/features/swarm/swarm-board-types";

export interface LayoutResult {
  positions: Map<string, { x: number; y: number }>;
}

type TopologyType = "mesh" | "hierarchical" | "centralized" | "hybrid" | "adaptive";

const CHARGE = 500;
const SPRING_REST_LENGTH = 80;
const SPRING_K = 0.01;
const CENTER_GRAVITY = 0.001;
const DAMPING = 0.9;

const NODE_RADIUS = 60;
const MESH_ITERATIONS = 100;
const RANK_SEP = 120;
const NODE_SEP = 80;
const HYBRID_INTRA_RANK_ITERATIONS = 50;

const NODE_TYPE_LAYER: Record<SwarmNodeType, number> = {
  agentSession: 0,
  terminalTask: 1,
  artifact: 2,
  diff: 2,
  note: 2,
  receipt: 2,
};

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
      return meshLayout(nodes, edges, viewport);
    default:
      return meshLayout(nodes, edges, viewport);
  }
}

interface SimNode {
  id: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
}

/** Force-directed mesh layout. O(n^2) per iteration, fine for <50 nodes. */
function meshLayout(
  nodes: Node<SwarmBoardNodeData>[],
  edges: SwarmBoardEdge[],
  viewport: { width: number; height: number },
): LayoutResult {
  const { width, height } = viewport;
  const originNodeCount = nodes.filter(
    (node) => node.position.x === 0 && node.position.y === 0,
  ).length;

  const simNodes: SimNode[] = nodes.map((n, i) => {
    // Preserve a single node intentionally placed at the origin; treat
    // duplicated (0, 0) positions as "unset" seeds that need spreading.
    const hasPosition =
      n.position.x !== 0 ||
      n.position.y !== 0 ||
      originNodeCount === 1;
    return {
      id: n.id,
      x: hasPosition ? n.position.x : (width / (nodes.length + 1)) * (i + 1),
      y: hasPosition ? n.position.y : (height / (nodes.length + 1)) * (i + 1),
      vx: 0,
      vy: 0,
    };
  });

  const nodeMap = new Map(simNodes.map((n) => [n.id, n]));

  for (let iter = 0; iter < MESH_ITERATIONS; iter++) {
    // Charge repulsion
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

    // Spring attraction
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

    const cx = width / 2,
      cy = height / 2;
    for (const n of simNodes) {
      n.vx += (cx - n.x) * CENTER_GRAVITY;
      n.vy += (cy - n.y) * CENTER_GRAVITY;
    }

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

function hierarchicalLayout(
  nodes: Node<SwarmBoardNodeData>[],
  edges: SwarmBoardEdge[],
  viewport: { width: number; height: number },
): LayoutResult {
  const layers = assignLayers(nodes, edges);
  return layeredPositions(layers, viewport);
}

function assignLayers(
  nodes: Node<SwarmBoardNodeData>[],
  edges: SwarmBoardEdge[],
): Map<number, Node<SwarmBoardNodeData>[]> {
  const children = new Map<string, string[]>();
  const incoming = new Set<string>();

  for (const edge of edges) {
    const list = children.get(edge.source) ?? [];
    list.push(edge.target);
    children.set(edge.source, list);
    incoming.add(edge.target);
  }

  const nodeById = new Map(nodes.map((n) => [n.id, n]));
  const layerOf = new Map<string, number>();

  const roots = nodes.filter((n) => !incoming.has(n.id));
  const startNodes = roots.length > 0 ? roots : nodes.filter((n) => n.data.nodeType === "agentSession");
  const queue = (startNodes.length > 0 ? startNodes : nodes).map((n) => n.id);

  for (const id of queue) {
    const node = nodeById.get(id);
    if (!node) continue;
    const typeLayer = NODE_TYPE_LAYER[node.data.nodeType] ?? 0;
    layerOf.set(id, typeLayer);
  }

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

  for (const n of nodes) {
    if (!layerOf.has(n.id)) {
      layerOf.set(n.id, NODE_TYPE_LAYER[n.data.nodeType] ?? 0);
    }
  }

  const layers = new Map<number, Node<SwarmBoardNodeData>[]>();
  for (const n of nodes) {
    const layer = layerOf.get(n.id) ?? 0;
    const list = layers.get(layer) ?? [];
    list.push(n);
    layers.set(layer, list);
  }

  return layers;
}

function layeredPositions(
  layers: Map<number, Node<SwarmBoardNodeData>[]>,
  viewport: { width: number; height: number },
): LayoutResult {
  const positions = new Map<string, { x: number; y: number }>();
  const sortedLayers = [...layers.entries()].sort(([a], [b]) => a - b);
  const layerCount = sortedLayers.length;

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

function centralizedLayout(
  nodes: Node<SwarmBoardNodeData>[],
  edges: SwarmBoardEdge[],
  viewport: { width: number; height: number },
): LayoutResult {
  const { width, height } = viewport;
  const cx = width / 2;
  const cy = height / 2;

  const degreeByNodeId = new Map<string, number>();
  for (const edge of edges) {
    degreeByNodeId.set(edge.source, (degreeByNodeId.get(edge.source) ?? 0) + 1);
    degreeByNodeId.set(edge.target, (degreeByNodeId.get(edge.target) ?? 0) + 1);
  }

  const connectedNodes = nodes.filter(
    (node) => (degreeByNodeId.get(node.id) ?? 0) > 0,
  );

  const hub = connectedNodes.reduce<Node<SwarmBoardNodeData> | null>(
    (best, node) => {
      if (!best) {
        return node;
      }

      const degree = degreeByNodeId.get(node.id) ?? 0;
      const bestDegree = degreeByNodeId.get(best.id) ?? 0;
      if (degree !== bestDegree) {
        return degree > bestDegree ? node : best;
      }

      const nodeIsAgent = node.data.nodeType === "agentSession";
      const bestIsAgent = best.data.nodeType === "agentSession";
      if (nodeIsAgent !== bestIsAgent) {
        return nodeIsAgent ? node : best;
      }

      const nodeLayer = NODE_TYPE_LAYER[node.data.nodeType] ?? Number.MAX_SAFE_INTEGER;
      const bestLayer = NODE_TYPE_LAYER[best.data.nodeType] ?? Number.MAX_SAFE_INTEGER;
      if (nodeLayer !== bestLayer) {
        return nodeLayer < bestLayer ? node : best;
      }

      return node.id.localeCompare(best.id) < 0 ? node : best;
    },
    null,
  ) ?? (nodes.find((n) => n.data.nodeType === "agentSession") ?? nodes[0]);
  const spokes = nodes.filter((n) => n.id !== hub.id);

  const positions = new Map<string, { x: number; y: number }>();
  positions.set(hub.id, { x: cx, y: cy });

  if (spokes.length === 0) return { positions };

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

function hybridLayout(
  nodes: Node<SwarmBoardNodeData>[],
  edges: SwarmBoardEdge[],
  viewport: { width: number; height: number },
): LayoutResult {
  const layers = assignLayers(nodes, edges);
  const initial = layeredPositions(layers, viewport);

  const sortedLayers = [...layers.entries()].sort(([a], [b]) => a - b);

  for (const [, layerNodes] of sortedLayers) {
    if (layerNodes.length <= 1) continue;

    const simX: { id: string; x: number; vx: number }[] = layerNodes.map((n) => ({
      id: n.id,
      x: initial.positions.get(n.id)?.x ?? viewport.width / 2,
      vx: 0,
    }));

    const rankIds = new Set(layerNodes.map((n) => n.id));
    const rankEdges = edges.filter((e) => rankIds.has(e.source) && rankIds.has(e.target));
    const simMap = new Map(simX.map((s) => [s.id, s]));

    for (let iter = 0; iter < HYBRID_INTRA_RANK_ITERATIONS; iter++) {
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

      const centerX = viewport.width / 2;
      for (const s of simX) {
        s.vx += (centerX - s.x) * CENTER_GRAVITY;
      }

      for (const s of simX) {
        s.vx *= DAMPING;
        s.x += s.vx;
        s.x = Math.max(NODE_RADIUS, Math.min(viewport.width - NODE_RADIUS, s.x));
      }
    }

    for (const s of simX) {
      const pos = initial.positions.get(s.id);
      if (pos) {
        pos.x = s.x;
      }
    }
  }

  return initial;
}
