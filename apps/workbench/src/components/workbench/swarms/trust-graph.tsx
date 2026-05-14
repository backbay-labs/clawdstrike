import {
  useRef,
  useEffect,
  useState,
  useCallback,
  useMemo,
  type MouseEvent as ReactMouseEvent,
} from "react";
import {
  IconZoomIn,
  IconZoomOut,
  IconFocus2,
  IconUser,
  IconNetwork,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import type {
  SwarmMember,
  TrustEdge,
  SwarmRole,
} from "@/lib/workbench/sentinel-types";
import type { TrustLevel } from "@/lib/workbench/delegation-types";
import {
  deriveSigil,
  deriveSigilColor,
  type SigilType,
} from "@/lib/workbench/sentinel-manager";

export interface TrustGraphProps {
  members: SwarmMember[];
  trustEdges: TrustEdge[];
  onSelectMember?: (memberId: string) => void;
  selectedMemberId?: string | null;
}

const TRUST_LEVEL_WEIGHT: Record<TrustLevel, number> = {
  System: 1.0,
  High: 0.85,
  Medium: 0.6,
  Low: 0.35,
  Untrusted: 0.1,
};

const ROLE_LABELS: Record<SwarmRole, string> = {
  admin: "Admin",
  contributor: "Contributor",
  observer: "Observer",
};

const ROLE_COLORS: Record<SwarmRole, string> = {
  admin: "#d4a84b",
  contributor: "#5b8def",
  observer: "#6f7f9a",
};

// Beyond this limit, O(n^2) simulation becomes too expensive for 60 fps.
const MAX_GRAPH_NODES = 100;

const NODE_MIN_R = 12;
const NODE_MAX_R = 24;

function trustWeight(edge: TrustEdge): number {
  return TRUST_LEVEL_WEIGHT[edge.trustLevel] ?? 0.5;
}

function edgeColor(weight: number): string {
  if (weight > 0.5) return "#3dbf84"; // green — positive trust
  if (weight < 0.3) return "#c45c5c"; // red — negative/low trust
  return "#6f7f9a"; // neutral gray
}

function nodeRadius(reputation: number): number {
  const clamped = Math.max(0, Math.min(1, reputation));
  return NODE_MIN_R + clamped * (NODE_MAX_R - NODE_MIN_R);
}

interface SimNode {
  id: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  pinned: boolean;
}

interface SimEdge {
  from: string;
  to: string;
  weight: number;
}

const SIM_ALPHA_DECAY = 0.02;
const SIM_VELOCITY_DECAY = 0.4;
const CHARGE_STRENGTH = -300;
const LINK_STRENGTH = 0.05;
const CENTER_STRENGTH = 0.01;
const COLLISION_PADDING = 4;

function initSimNodes(
  members: SwarmMember[],
  width: number,
  height: number,
): SimNode[] {
  const cx = width / 2;
  const cy = height / 2;
  return members.map((m, i) => {
    // Distribute nodes in a circle to start
    const angle = (2 * Math.PI * i) / Math.max(members.length, 1);
    const spread = Math.min(width, height) * 0.3;
    return {
      id: m.fingerprint,
      x: cx + Math.cos(angle) * spread,
      y: cy + Math.sin(angle) * spread,
      vx: 0,
      vy: 0,
      radius: nodeRadius(m.reputation.overall),
      pinned: false,
    };
  });
}

function initSimEdges(trustEdges: TrustEdge[]): SimEdge[] {
  return trustEdges.map((e) => ({
    from: e.from,
    to: e.to,
    weight: trustWeight(e),
  }));
}

function tickSimulation(
  nodes: SimNode[],
  edges: SimEdge[],
  alpha: number,
  width: number,
  height: number,
): void {
  const nodeMap = new Map<string, SimNode>();
  for (const n of nodes) nodeMap.set(n.id, n);

  // Charge repulsion (all-pairs, O(n^2) — fine for swarm sizes < ~200)
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i];
      const b = nodes[j];
      let dx = b.x - a.x;
      let dy = b.y - a.y;
      let dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < 1) {
        dx = (Math.random() - 0.5) * 2;
        dy = (Math.random() - 0.5) * 2;
        dist = Math.sqrt(dx * dx + dy * dy);
      }
      const force = (CHARGE_STRENGTH * alpha) / (dist * dist);
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      if (!a.pinned) {
        a.vx -= fx;
        a.vy -= fy;
      }
      if (!b.pinned) {
        b.vx += fx;
        b.vy += fy;
      }
    }
  }

  // Link attraction (spring force)
  for (const edge of edges) {
    const a = nodeMap.get(edge.from);
    const b = nodeMap.get(edge.to);
    if (!a || !b) continue;
    const dx = b.x - a.x;
    const dy = b.y - a.y;
    let dist = Math.sqrt(dx * dx + dy * dy);
    if (dist < 1) dist = 1;
    const targetDist = 120; // ideal rest length
    const displacement = dist - targetDist;
    const strength = LINK_STRENGTH * edge.weight * alpha;
    const fx = (dx / dist) * displacement * strength;
    const fy = (dy / dist) * displacement * strength;
    if (!a.pinned) {
      a.vx += fx;
      a.vy += fy;
    }
    if (!b.pinned) {
      b.vx -= fx;
      b.vy -= fy;
    }
  }

  // Center gravity
  const cx = width / 2;
  const cy = height / 2;
  for (const n of nodes) {
    if (n.pinned) continue;
    n.vx += (cx - n.x) * CENTER_STRENGTH * alpha;
    n.vy += (cy - n.y) * CENTER_STRENGTH * alpha;
  }

  // Collision avoidance
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i];
      const b = nodes[j];
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      const minDist = a.radius + b.radius + COLLISION_PADDING;
      if (dist < minDist && dist > 0) {
        const overlap = (minDist - dist) / 2;
        const nx = dx / dist;
        const ny = dy / dist;
        if (!a.pinned) {
          a.x -= nx * overlap;
          a.y -= ny * overlap;
        }
        if (!b.pinned) {
          b.x += nx * overlap;
          b.y += ny * overlap;
        }
      }
    }
  }

  // Apply velocity + decay
  for (const n of nodes) {
    if (n.pinned) {
      n.vx = 0;
      n.vy = 0;
      continue;
    }
    n.vx *= 1 - SIM_VELOCITY_DECAY;
    n.vy *= 1 - SIM_VELOCITY_DECAY;
    n.x += n.vx;
    n.y += n.vy;
  }
}

const SIGIL_CHARS: Record<SigilType, string> = {
  diamond: "\u25C7",
  eye: "\u25C9",
  wave: "\u223F",
  crown: "\u2655",
  spiral: "@",
  key: "\u2767",
  star: "\u2726",
  moon: "\u263E",
};

function SigilShape({
  sigil,
  size,
  color,
}: {
  sigil: SigilType;
  size: number;
  color: string;
}) {
  return (
    <text
      textAnchor="middle"
      dominantBaseline="central"
      fill={color}
      fontSize={Math.round(size * 0.5)}
      fontFamily="system-ui, sans-serif"
      style={{ pointerEvents: "none" }}
    >
      {SIGIL_CHARS[sigil]}
    </text>
  );
}

export function TrustGraph({
  members,
  trustEdges,
  onSelectMember,
  selectedMemberId,
}: TrustGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [containerEl, setContainerEl] = useState<HTMLDivElement | null>(null);

  // Viewport transform
  const [panX, setPanX] = useState(0);
  const [panY, setPanY] = useState(0);
  const [zoom, setZoom] = useState(1);
  const isPanningRef = useRef(false);
  const lastMouseRef = useRef({ x: 0, y: 0 });

  // Drag state
  const dragNodeRef = useRef<string | null>(null);
  const dragStartRef = useRef({ x: 0, y: 0 });

  // Hover / tooltip
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [tooltipPos, setTooltipPos] = useState<{ x: number; y: number } | null>(
    null,
  );

  // Legend collapse
  const [legendOpen, setLegendOpen] = useState(false);

  // Simulation state
  const simNodesRef = useRef<SimNode[]>([]);
  const simEdgesRef = useRef<SimEdge[]>([]);
  const alphaRef = useRef(1);
  const rafRef = useRef<number>(0);
  const [renderTick, setRenderTick] = useState(0);

  // Canvas dimensions
  const [canvasSize, setCanvasSize] = useState({ width: 800, height: 600 });

  // Refs for zoom handler (avoids stale closures)
  const zoomRef = useRef(zoom);
  const panXRef = useRef(panX);
  const panYRef = useRef(panY);
  useEffect(() => {
    zoomRef.current = zoom;
  }, [zoom]);
  useEffect(() => {
    panXRef.current = panX;
  }, [panX]);
  useEffect(() => {
    panYRef.current = panY;
  }, [panY]);

  const handleContainerRef = useCallback((node: HTMLDivElement | null) => {
    containerRef.current = node;
    setContainerEl(node);
  }, []);

  // Measure container
  useEffect(() => {
    if (!containerEl) return;
    const ro = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const { width, height } = entry.contentRect;
        if (width > 0 && height > 0) {
          setCanvasSize({ width, height });
        }
      }
    });
    ro.observe(containerEl);
    const rect = containerEl.getBoundingClientRect();
    if (rect.width > 0 && rect.height > 0) {
      setCanvasSize({ width: rect.width, height: rect.height });
    }
    return () => ro.disconnect();
  }, [containerEl]);

  // Guard: truncate to MAX_GRAPH_NODES to keep the O(n^2) simulation viable
  const nodeCountExceeded = members.length > MAX_GRAPH_NODES;
  const displayMembers = useMemo(
    () => (nodeCountExceeded ? members.slice(0, MAX_GRAPH_NODES) : members),
    [members, nodeCountExceeded],
  );

  // Build a set of fingerprints in the display list for edge filtering
  const displayFingerprintSet = useMemo(() => {
    const s = new Set<string>();
    for (const m of displayMembers) s.add(m.fingerprint);
    return s;
  }, [displayMembers]);

  // Filter edges to only include nodes in the display list
  const displayEdges = useMemo(
    () =>
      nodeCountExceeded
        ? trustEdges.filter(
            (e) => displayFingerprintSet.has(e.from) && displayFingerprintSet.has(e.to),
          )
        : trustEdges,
    [trustEdges, nodeCountExceeded, displayFingerprintSet],
  );

  // Member lookup map
  const memberMap = useMemo(() => {
    const m = new Map<string, SwarmMember>();
    for (const member of displayMembers) m.set(member.fingerprint, member);
    return m;
  }, [displayMembers]);

  // Initialize / reset simulation when members or edges change
  useEffect(() => {
    const { width, height } = canvasSize;
    simNodesRef.current = initSimNodes(displayMembers, width, height);
    simEdgesRef.current = initSimEdges(displayEdges);
    alphaRef.current = 1;
  }, [displayMembers, displayEdges, canvasSize]);

  // Run simulation loop
  useEffect(() => {
    let running = true;

    function loop() {
      if (!running) return;

      if (alphaRef.current > 0.001) {
        tickSimulation(
          simNodesRef.current,
          simEdgesRef.current,
          alphaRef.current,
          canvasSize.width,
          canvasSize.height,
        );
        alphaRef.current *= 1 - SIM_ALPHA_DECAY;
        setRenderTick((t) => t + 1);
      }

      rafRef.current = requestAnimationFrame(loop);
    }

    rafRef.current = requestAnimationFrame(loop);

    return () => {
      running = false;
      cancelAnimationFrame(rafRef.current);
    };
  }, [canvasSize]);

  // Snapshot node positions for rendering (avoids reading ref during render)
  const nodePositions = useMemo(() => {
    // renderTick dependency forces re-read on simulation tick
    void renderTick;
    const map = new Map<string, { x: number; y: number; radius: number }>();
    for (const n of simNodesRef.current) {
      map.set(n.id, { x: n.x, y: n.y, radius: n.radius });
    }
    return map;
  }, [renderTick]);

  // ---- Pan handlers (background drag) ----
  const onMouseDown = useCallback(
    (e: ReactMouseEvent) => {
      // If clicking a node, start node drag instead
      const nodeEl = (e.target as HTMLElement).closest("[data-node]");
      if (nodeEl) {
        const nodeId = nodeEl.getAttribute("data-node");
        if (nodeId) {
          dragNodeRef.current = nodeId;
          dragStartRef.current = { x: e.clientX, y: e.clientY };
          const simNode = simNodesRef.current.find((n) => n.id === nodeId);
          if (simNode) {
            simNode.pinned = true;
            alphaRef.current = Math.max(alphaRef.current, 0.3);
          }
          return;
        }
      }
      isPanningRef.current = true;
      lastMouseRef.current = { x: e.clientX, y: e.clientY };
    },
    [],
  );

  const onMouseMove = useCallback(
    (e: ReactMouseEvent) => {
      // Node dragging
      if (dragNodeRef.current) {
        const simNode = simNodesRef.current.find(
          (n) => n.id === dragNodeRef.current,
        );
        if (simNode) {
          const container = containerRef.current;
          if (container) {
            const rect = container.getBoundingClientRect();
            const svgX =
              (e.clientX - rect.left - panXRef.current) / zoomRef.current;
            const svgY =
              (e.clientY - rect.top - panYRef.current) / zoomRef.current;
            simNode.x = svgX;
            simNode.y = svgY;
            alphaRef.current = Math.max(alphaRef.current, 0.1);
            setRenderTick((t) => t + 1);
          }
        }
        return;
      }

      // Panning
      if (!isPanningRef.current) return;
      const dx = e.clientX - lastMouseRef.current.x;
      const dy = e.clientY - lastMouseRef.current.y;
      setPanX((p) => p + dx);
      setPanY((p) => p + dy);
      lastMouseRef.current = { x: e.clientX, y: e.clientY };
    },
    [],
  );

  const onMouseUp = useCallback(() => {
    if (dragNodeRef.current) {
      const simNode = simNodesRef.current.find(
        (n) => n.id === dragNodeRef.current,
      );
      if (simNode) simNode.pinned = false;
      dragNodeRef.current = null;
    }
    isPanningRef.current = false;
  }, []);

  // ---- Wheel zoom (native handler for passive: false) ----
  useEffect(() => {
    if (!containerEl) return;
    const container = containerEl;
    const handler = (e: WheelEvent) => {
      e.preventDefault();
      e.stopPropagation();
      const rect = container.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      const factor = e.deltaY < 0 ? 1.1 : 0.9;
      const curZoom = zoomRef.current;
      const curPanX = panXRef.current;
      const curPanY = panYRef.current;
      const newZoom = Math.min(Math.max(curZoom * factor, 0.15), 4);
      const wx = (x - curPanX) / curZoom;
      const wy = (y - curPanY) / curZoom;
      setPanX(x - wx * newZoom);
      setPanY(y - wy * newZoom);
      setZoom(newZoom);
    };
    container.addEventListener("wheel", handler, { passive: false });
    return () => container.removeEventListener("wheel", handler);
  }, [containerEl]);

  // ---- Node interactions ----
  const handleNodeClick = useCallback(
    (e: ReactMouseEvent, fingerprint: string) => {
      e.stopPropagation();
      onSelectMember?.(fingerprint);
    },
    [onSelectMember],
  );

  const handleNodeDoubleClick = useCallback(
    (fingerprint: string) => {
      // Center view on this node
      const pos = nodePositions.get(fingerprint);
      if (!pos || !containerRef.current) return;
      const rect = containerRef.current.getBoundingClientRect();
      setPanX(rect.width / 2 - pos.x * zoom);
      setPanY(rect.height / 2 - pos.y * zoom);
    },
    [nodePositions, zoom],
  );

  const handleNodeHover = useCallback(
    (fingerprint: string | null, e?: ReactMouseEvent) => {
      setHoveredNodeId(fingerprint);
      if (fingerprint && e) {
        const container = containerRef.current;
        if (container) {
          const rect = container.getBoundingClientRect();
          setTooltipPos({
            x: e.clientX - rect.left,
            y: e.clientY - rect.top,
          });
        }
      } else {
        setTooltipPos(null);
      }
    },
    [],
  );

  const onBackgroundClick = useCallback(
    (e: ReactMouseEvent) => {
      if ((e.target as HTMLElement).closest("[data-node]")) return;
      onSelectMember?.("");
    },
    [onSelectMember],
  );

  // ---- Toolbar actions ----
  const fitToScreen = useCallback(() => {
    if (simNodesRef.current.length === 0) return;
    let minX = Infinity,
      maxX = -Infinity,
      minY = Infinity,
      maxY = -Infinity;
    for (const n of simNodesRef.current) {
      minX = Math.min(minX, n.x - n.radius);
      maxX = Math.max(maxX, n.x + n.radius);
      minY = Math.min(minY, n.y - n.radius);
      maxY = Math.max(maxY, n.y + n.radius);
    }
    const container = containerRef.current;
    if (!container) return;
    const rect = container.getBoundingClientRect();
    const padding = 60;
    const gw = maxX - minX + padding * 2;
    const gh = maxY - minY + padding * 2;
    const newZoom = Math.min(rect.width / gw, rect.height / gh, 1.5);
    const cx = (minX + maxX) / 2;
    const cy = (minY + maxY) / 2;
    setPanX(rect.width / 2 - cx * newZoom);
    setPanY(rect.height / 2 - cy * newZoom);
    setZoom(newZoom);
  }, []);

  // Fit to screen on first render with data
  const didFitRef = useRef(false);
  useEffect(() => {
    if (displayMembers.length > 0 && !didFitRef.current && renderTick > 10) {
      didFitRef.current = true;
      fitToScreen();
    }
  }, [displayMembers.length, renderTick, fitToScreen]);

  // Reset fit flag when members change
  useEffect(() => {
    didFitRef.current = false;
  }, [displayMembers]);

  // ---- Stats (computed over displayed subset when truncated) ----
  const stats = useMemo(() => {
    const totalMembers = displayMembers.length;
    const avgReputation =
      totalMembers > 0
        ? displayMembers.reduce((s, m) => s + m.reputation.overall, 0) / totalMembers
        : 0;
    const totalEdges = displayEdges.length;
    const maxEdges = totalMembers * (totalMembers - 1); // directed graph
    const density = maxEdges > 0 ? totalEdges / maxEdges : 0;
    return { totalMembers, avgReputation, totalEdges, density };
  }, [displayMembers, displayEdges]);

  // ---- Connected edges for selection highlight ----
  const connectedEdgeSet = useMemo(() => {
    if (!selectedMemberId) return null;
    const set = new Set<string>();
    for (const e of displayEdges) {
      if (e.from === selectedMemberId || e.to === selectedMemberId) {
        set.add(`${e.from}->${e.to}`);
      }
    }
    return set;
  }, [selectedMemberId, displayEdges]);

  const connectedNodeSet = useMemo(() => {
    if (!selectedMemberId) return null;
    const set = new Set<string>();
    set.add(selectedMemberId);
    for (const e of displayEdges) {
      if (e.from === selectedMemberId) set.add(e.to);
      if (e.to === selectedMemberId) set.add(e.from);
    }
    return set;
  }, [selectedMemberId, displayEdges]);

  // ---- Tooltip content ----
  const hoveredMember = hoveredNodeId ? memberMap.get(hoveredNodeId) : null;

  // ---- Empty state ----
  if (members.length < 2) {
    return (
      <div className="flex h-full w-full flex-col items-center justify-center bg-zinc-950 text-center px-8">
        <div className="w-12 h-12 rounded-xl bg-[#55788b]/10 border border-[#55788b]/20 flex items-center justify-center mb-4">
          <IconNetwork size={24} stroke={1.5} className="text-[#55788b]" />
        </div>
        <h2 className="text-sm font-semibold text-[#ece7dc] mb-1">
          {members.length === 0
            ? "No swarm members"
            : "Not enough members for a trust graph"}
        </h2>
        <p className="text-[11px] text-[#6f7f9a] max-w-sm leading-relaxed">
          {members.length === 0
            ? "Add sentinels or operators to this swarm to visualize trust relationships."
            : "At least 2 members are needed to render trust edges. Invite more participants to see the graph."}
        </p>
      </div>
    );
  }

  return (
    <div className="relative flex h-full w-full flex-col bg-zinc-950">
      {/* Graph canvas */}
      <div
        ref={handleContainerRef}
        className="relative flex-1 cursor-grab active:cursor-grabbing overflow-hidden"
        onMouseDown={onMouseDown}
        onMouseMove={onMouseMove}
        onMouseUp={onMouseUp}
        onMouseLeave={onMouseUp}
        onClick={onBackgroundClick}
      >
        {/* Toolbar */}
        <div className="absolute left-3 top-3 z-10 flex items-center gap-0.5 rounded-md border border-[#1a1f2e] bg-[#0b0d13]/95 px-1.5 py-1 backdrop-blur-sm">
          <ToolbarBtn icon={IconFocus2} label="Fit" onClick={fitToScreen} />
          <ToolbarBtn
            icon={IconZoomIn}
            label="In"
            onClick={() => setZoom((z) => Math.min(z * 1.25, 4))}
            disabled={zoom >= 4}
          />
          <ToolbarBtn
            icon={IconZoomOut}
            label="Out"
            onClick={() => setZoom((z) => Math.max(z / 1.25, 0.15))}
            disabled={zoom <= 0.15}
          />
        </div>

        {/* Node-count warning */}
        {nodeCountExceeded && (
          <div className="absolute left-1/2 top-3 z-10 -translate-x-1/2 rounded-md border border-[#d4a84b]/30 bg-[#0b0d13]/95 px-3 py-1.5 text-[10px] text-[#d4a84b] backdrop-blur-sm">
            Showing {MAX_GRAPH_NODES} of {members.length} members. Zoom into a
            subgroup for full detail.
          </div>
        )}

        {/* Zoom percentage */}
        <div className="absolute bottom-3 left-3 z-10 rounded border border-[#1a1f2e] bg-[#0b0d13]/90 px-2 py-0.5 text-[10px] tabular-nums text-[#6f7f9a]/60">
          {Math.round(zoom * 100)}%
        </div>

        {/* Legend toggle */}
        <div className="absolute right-3 top-3 z-10">
          <button
            onClick={() => setLegendOpen((o) => !o)}
            className="rounded-md border border-[#1a1f2e] bg-[#0b0d13]/95 px-2.5 py-1 text-[9px] text-[#6f7f9a]/60 backdrop-blur-sm transition-colors hover:text-[#ece7dc]/80"
          >
            Legend {legendOpen ? "\u25B4" : "\u25BE"}
          </button>

          {legendOpen && (
            <div className="mt-1 rounded-lg border border-[#1a1f2e] bg-[#0b0d13]/95 px-3 py-2.5 backdrop-blur-sm">
              {/* Node size */}
              <LegendSection title="Node Size">
                <div className="flex items-center gap-2">
                  <svg width={16} height={16}>
                    <circle cx={8} cy={8} r={4} fill="#6f7f9a" opacity={0.5} />
                  </svg>
                  <span className="text-[9px] text-[#6f7f9a]/70">
                    Low reputation
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <svg width={16} height={16}>
                    <circle cx={8} cy={8} r={7} fill="#6f7f9a" opacity={0.5} />
                  </svg>
                  <span className="text-[9px] text-[#6f7f9a]/70">
                    High reputation
                  </span>
                </div>
              </LegendSection>

              {/* Edge color */}
              <LegendSection title="Edge Color">
                <div className="flex items-center gap-2">
                  <div className="h-0.5 w-4 rounded bg-[#3dbf84]" />
                  <span className="text-[9px] text-[#6f7f9a]/70">
                    Positive trust (&gt; 0.5)
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="h-0.5 w-4 rounded bg-[#6f7f9a]" />
                  <span className="text-[9px] text-[#6f7f9a]/70">
                    Neutral (0.3-0.5)
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="h-0.5 w-4 rounded bg-[#c45c5c]" />
                  <span className="text-[9px] text-[#6f7f9a]/70">
                    Low trust (&lt; 0.3)
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="h-0.5 w-4 rounded border border-dashed border-[#6f7f9a]" />
                  <span className="text-[9px] text-[#6f7f9a]/70">
                    Uncertain
                  </span>
                </div>
              </LegendSection>

              {/* Role badges */}
              <LegendSection title="Roles">
                {(["admin", "contributor", "observer"] as SwarmRole[]).map(
                  (role) => (
                    <div key={role} className="flex items-center gap-2">
                      <span
                        className="inline-block rounded px-1 py-0.5 text-[7px] font-semibold uppercase"
                        style={{
                          backgroundColor: ROLE_COLORS[role] + "20",
                          color: ROLE_COLORS[role],
                        }}
                      >
                        {ROLE_LABELS[role][0]}
                      </span>
                      <span className="text-[9px] text-[#6f7f9a]/70">
                        {ROLE_LABELS[role]}
                      </span>
                    </div>
                  ),
                )}
              </LegendSection>
            </div>
          )}
        </div>

        {/* Tooltip */}
        {hoveredMember && tooltipPos && (
          <div
            className="pointer-events-none absolute z-20 rounded-lg border border-[#1a1f2e] bg-[#0b0d13]/95 px-3 py-2 backdrop-blur-sm"
            style={{
              left: tooltipPos.x + 16,
              top: tooltipPos.y - 8,
              maxWidth: 240,
            }}
          >
            <div className="text-[11px] font-semibold text-[#ece7dc]">
              {hoveredMember.displayName}
            </div>
            <div className="mt-1 font-mono text-[9px] text-[#6f7f9a]/60">
              {formatFingerprint(hoveredMember.fingerprint)}
            </div>
            <div className="mt-1.5 flex flex-col gap-0.5 text-[9px] text-[#6f7f9a]">
              <span>
                Role:{" "}
                <span style={{ color: ROLE_COLORS[hoveredMember.role] }}>
                  {ROLE_LABELS[hoveredMember.role]}
                </span>
              </span>
              <span>
                Reputation:{" "}
                <span className="text-[#ece7dc]/80">
                  {(hoveredMember.reputation.overall * 100).toFixed(0)}%
                </span>
              </span>
              <span>
                Joined:{" "}
                <span className="text-[#ece7dc]/60">
                  {new Date(hoveredMember.joinedAt).toLocaleDateString()}
                </span>
              </span>
              <span>
                Type:{" "}
                <span className="text-[#ece7dc]/60">
                  {hoveredMember.type === "sentinel" ? "Sentinel" : "Operator"}
                </span>
              </span>
            </div>
          </div>
        )}

        {/* SVG Canvas */}
        <svg className="h-full w-full" style={{ background: "#09090b" }}>
          <defs>
            <pattern
              id="trust-grid-dot"
              width="24"
              height="24"
              patternUnits="userSpaceOnUse"
            >
              <circle cx="12" cy="12" r="0.5" fill="#1a1f2e" />
            </pattern>
          </defs>

          <rect width="100%" height="100%" fill="url(#trust-grid-dot)" />

          <g
            data-viewport=""
            transform={`translate(${panX},${panY}) scale(${zoom})`}
          >
            {/* Edges */}
            {displayEdges.map((edge) => {
              const fromPos = nodePositions.get(edge.from);
              const toPos = nodePositions.get(edge.to);
              if (!fromPos || !toPos) return null;

              const w = trustWeight(edge);
              const color = edgeColor(w);
              const thickness = 1 + w * 3; // 1px min, 4px max
              const edgeKey = `${edge.from}->${edge.to}`;
              const isConnected = connectedEdgeSet?.has(edgeKey);
              const isDimmed = connectedEdgeSet && !isConnected;
              const isUncertain = w < 0.3;

              return (
                <line
                  key={edgeKey}
                  x1={fromPos.x}
                  y1={fromPos.y}
                  x2={toPos.x}
                  y2={toPos.y}
                  stroke={isConnected ? "#d4a84b" : color}
                  strokeWidth={isConnected ? thickness + 0.5 : thickness}
                  strokeOpacity={isDimmed ? 0.08 : w * 0.6 + 0.15}
                  strokeDasharray={isUncertain ? "6 4" : undefined}
                  className="transition-opacity duration-200"
                />
              );
            })}

            {/* Nodes */}
            {displayMembers.map((member) => {
              const pos = nodePositions.get(member.fingerprint);
              if (!pos) return null;

              const isSelected = selectedMemberId === member.fingerprint;
              const isHovered = hoveredNodeId === member.fingerprint;
              const isDimmed =
                connectedNodeSet && !connectedNodeSet.has(member.fingerprint);
              const sigil = deriveSigil(member.fingerprint);
              const color = deriveSigilColor(member.fingerprint);
              const r = pos.radius;
              const rep = member.reputation.overall;
              const lowTrust = rep < 0.3;

              return (
                <g
                  key={member.fingerprint}
                  data-node={member.fingerprint}
                  transform={`translate(${pos.x},${pos.y})`}
                  opacity={isDimmed ? 0.12 : lowTrust ? 0.5 : 1}
                  className="cursor-pointer transition-opacity duration-200"
                  onMouseEnter={(e) => handleNodeHover(member.fingerprint, e)}
                  onMouseLeave={() => handleNodeHover(null)}
                  onClick={(e) => handleNodeClick(e, member.fingerprint)}
                  onDoubleClick={() =>
                    handleNodeDoubleClick(member.fingerprint)
                  }
                >
                  {/* Glow ring for selected node */}
                  {isSelected && (
                    <circle
                      r={r + 6}
                      fill="none"
                      stroke="#d4a84b"
                      strokeWidth={1}
                      opacity={0.3}
                      style={{ filter: "blur(4px)" }}
                    />
                  )}

                  {/* Node circle */}
                  <circle
                    r={r}
                    fill="#0f1219"
                    stroke={isSelected ? "#d4a84b" : isHovered ? "#2d3240" : color}
                    strokeWidth={isSelected ? 2 : 1.5}
                  />

                  {/* Colored fill ring (reputation proportional arc) */}
                  <circle
                    r={r - 2}
                    fill="none"
                    stroke={color}
                    strokeWidth={2}
                    strokeOpacity={0.15}
                  />

                  {/* Sigil icon */}
                  <SigilShape sigil={sigil} size={r * 2} color={color} />

                  {/* Role badge */}
                  <g transform={`translate(${r * 0.6},${-r * 0.6})`}>
                    <rect
                      x={-5}
                      y={-5}
                      width={10}
                      height={10}
                      rx={2}
                      fill={ROLE_COLORS[member.role]}
                      opacity={0.9}
                    />
                    <text
                      x={0}
                      y={0.5}
                      textAnchor="middle"
                      dominantBaseline="central"
                      fill="#0f1219"
                      fontSize={7}
                      fontWeight={700}
                      fontFamily="'JetBrains Mono', ui-monospace, monospace"
                    >
                      {ROLE_LABELS[member.role][0]}
                    </text>
                  </g>

                  {/* Member type indicator (operator = user icon badge) */}
                  {member.type === "operator" && (
                    <g transform={`translate(${-r * 0.6},${-r * 0.6})`}>
                      <foreignObject x={-5} y={-5} width={10} height={10}>
                        <IconUser
                          size={10}
                          className="pointer-events-none text-[#ece7dc]/60"
                        />
                      </foreignObject>
                    </g>
                  )}

                  {/* Name label below node */}
                  <text
                    y={r + 14}
                    textAnchor="middle"
                    fill={isSelected ? "#ece7dc" : "#c4c9d4"}
                    fontSize={10}
                    fontFamily="'JetBrains Mono', ui-monospace, monospace"
                    fontWeight={isSelected ? 600 : 400}
                    className="select-none"
                  >
                    {member.displayName.length > 14
                      ? member.displayName.slice(0, 13) + "\u2026"
                      : member.displayName}
                  </text>
                </g>
              );
            })}
          </g>
        </svg>
      </div>

      {/* Stats bar */}
      <div className="flex items-center gap-6 border-t border-[#1a1f2e] bg-[#0b0d13] px-4 py-2">
        <StatItem label="Members" value={String(stats.totalMembers)} />
        <StatItem
          label="Avg Reputation"
          value={`${(stats.avgReputation * 100).toFixed(0)}%`}
        />
        <StatItem label="Trust Edges" value={String(stats.totalEdges)} />
        <StatItem
          label="Density"
          value={`${(stats.density * 100).toFixed(1)}%`}
        />
      </div>
    </div>
  );
}

function ToolbarBtn({
  icon: Icon,
  label,
  onClick,
  active = false,
  disabled = false,
}: {
  icon: React.ComponentType<{ size?: number; stroke?: number }>;
  label: string;
  onClick: () => void;
  active?: boolean;
  disabled?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      title={label}
      disabled={disabled}
      className={cn(
        "flex h-6 items-center gap-1 rounded px-1.5 text-[9px] transition-colors",
        disabled
          ? "text-[#6f7f9a]/30 cursor-not-allowed"
          : active
            ? "bg-[#d4a84b]/10 text-[#d4a84b]"
            : "text-[#6f7f9a]/60 hover:bg-[#1a1f2e] hover:text-[#ece7dc]/80",
      )}
    >
      <Icon size={13} stroke={1.5} />
      <span className="hidden lg:inline">{label}</span>
    </button>
  );
}

function StatItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline gap-1.5">
      <span className="text-[9px] uppercase tracking-wider text-[#6f7f9a]/50">
        {label}
      </span>
      <span className="text-[11px] tabular-nums font-semibold text-[#ece7dc]/80">
        {value}
      </span>
    </div>
  );
}

function LegendSection({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="mb-2 last:mb-0">
      <h4 className="mb-1 text-[8px] font-semibold uppercase tracking-[0.1em] text-[#6f7f9a]/50">
        {title}
      </h4>
      <div className="flex flex-col gap-1">{children}</div>
    </div>
  );
}

function formatFingerprint(fp: string): string {
  const clean = fp.replace(/[^a-fA-F0-9]/g, "").slice(0, 16);
  return clean.replace(/(.{4})/g, "$1-").replace(/-$/, "");
}
