/**
 * GraphTab - Mini entity relationship graph for the ContextInspector.
 *
 * Renders a lightweight 2D force-directed graph on a <canvas> element showing
 * the selected entity (center node) and its relationships. This is NOT the full
 * 3D SwarmMap -- just a simple spring-force visualization for the inspector panel.
 */
import { useCallback, useEffect, useRef } from "react";
import { useSelection, useWorkbenchDispatch } from "@/shell/workbench/WorkbenchStateProvider";
import type { SelectionEntityType } from "@/shell/workbench/workbenchState";

// ── Color palette per entity type ────────────────────────────────────

const ENTITY_COLORS: Record<NonNullable<SelectionEntityType>, string> = {
  file: "#4ade80",
  receipt: "#c8a84e",
  policy: "#818cf8",
  agent: "#f472b6",
  session: "#38bdf8",
  guard: "#fb923c",
};

const GOLD_RING = "#c8a84e";
const EDGE_COLOR = "rgba(255,255,255,0.15)";
const LABEL_COLOR = "rgba(255,255,255,0.6)";

// ── Related-entity types ─────────────────────────────────────────────

interface RelatedEntity {
  entityType: NonNullable<SelectionEntityType>;
  entityId: string;
  label?: string;
}

/** Fallback mock relationships when metadata.relatedEntities is absent. */
const DEFAULT_RELATIONSHIPS: Record<NonNullable<SelectionEntityType>, RelatedEntity[]> = {
  file: [
    { entityType: "policy", entityId: "mock-policy-1", label: "policy" },
    { entityType: "guard", entityId: "mock-guard-1", label: "guard" },
  ],
  receipt: [
    { entityType: "policy", entityId: "mock-policy-1", label: "policy" },
    { entityType: "guard", entityId: "mock-guard-1", label: "guard" },
    { entityType: "agent", entityId: "mock-agent-1", label: "agent" },
  ],
  policy: [
    { entityType: "guard", entityId: "mock-guard-1", label: "guard-a" },
    { entityType: "guard", entityId: "mock-guard-2", label: "guard-b" },
  ],
  agent: [
    { entityType: "session", entityId: "mock-session-1", label: "session" },
    { entityType: "policy", entityId: "mock-policy-1", label: "policy" },
  ],
  session: [
    { entityType: "agent", entityId: "mock-agent-1", label: "agent" },
    { entityType: "receipt", entityId: "mock-receipt-1", label: "receipt" },
  ],
  guard: [
    { entityType: "policy", entityId: "mock-policy-1", label: "policy" },
    { entityType: "receipt", entityId: "mock-receipt-1", label: "receipt" },
  ],
};

// ── Simulation node ──────────────────────────────────────────────────

interface SimNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  color: string;
  label: string;
  isCenter: boolean;
  entityType: NonNullable<SelectionEntityType>;
  entityId: string;
}

// ── Force-directed helpers ───────────────────────────────────────────

const SPRING_LENGTH = 80;
const SPRING_K = 0.04;
const REPULSION = 2000;
const DAMPING = 0.85;
const CENTER_PULL = 0.01;
const MAX_ITERATIONS = 30;

function buildNodes(
  centerType: NonNullable<SelectionEntityType>,
  centerId: string,
  related: RelatedEntity[],
  cx: number,
  cy: number,
): SimNode[] {
  const nodes: SimNode[] = [
    {
      x: cx,
      y: cy,
      vx: 0,
      vy: 0,
      radius: 12,
      color: ENTITY_COLORS[centerType],
      label: centerId.length > 14 ? centerId.slice(0, 12) + "\u2026" : centerId,
      isCenter: true,
      entityType: centerType,
      entityId: centerId,
    },
  ];

  const count = related.length;
  for (let i = 0; i < count; i++) {
    const angle = (2 * Math.PI * i) / count - Math.PI / 2;
    const r = related[i];
    nodes.push({
      x: cx + Math.cos(angle) * SPRING_LENGTH,
      y: cy + Math.sin(angle) * SPRING_LENGTH,
      vx: 0,
      vy: 0,
      radius: 7,
      color: ENTITY_COLORS[r.entityType],
      label: r.label ?? r.entityType,
      isCenter: false,
      entityType: r.entityType,
      entityId: r.entityId,
    });
  }

  return nodes;
}

function stepSimulation(nodes: SimNode[], cx: number, cy: number): void {
  for (let i = 0; i < nodes.length; i++) {
    let fx = 0;
    let fy = 0;

    // Repulsion between all pairs
    for (let j = 0; j < nodes.length; j++) {
      if (i === j) continue;
      const dx = nodes[i].x - nodes[j].x;
      const dy = nodes[i].y - nodes[j].y;
      const distSq = dx * dx + dy * dy + 1; // +1 avoids division by zero
      const f = REPULSION / distSq;
      const dist = Math.sqrt(distSq);
      fx += (f * dx) / dist;
      fy += (f * dy) / dist;
    }

    // Spring toward center node (index 0) for non-center nodes
    if (!nodes[i].isCenter) {
      const dx = nodes[0].x - nodes[i].x;
      const dy = nodes[0].y - nodes[i].y;
      const dist = Math.sqrt(dx * dx + dy * dy + 1);
      const stretch = dist - SPRING_LENGTH;
      fx += SPRING_K * stretch * (dx / dist);
      fy += SPRING_K * stretch * (dy / dist);
    }

    // Gentle pull toward canvas center to avoid drift
    fx += (cx - nodes[i].x) * CENTER_PULL;
    fy += (cy - nodes[i].y) * CENTER_PULL;

    nodes[i].vx = (nodes[i].vx + fx) * DAMPING;
    nodes[i].vy = (nodes[i].vy + fy) * DAMPING;
  }

  // Apply velocities
  for (const node of nodes) {
    node.x += node.vx;
    node.y += node.vy;
  }
}

function drawGraph(
  ctx: CanvasRenderingContext2D,
  nodes: SimNode[],
  width: number,
  height: number,
): void {
  ctx.clearRect(0, 0, width, height);

  // Draw edges from center (index 0) to all other nodes
  ctx.strokeStyle = EDGE_COLOR;
  ctx.lineWidth = 1;
  for (let i = 1; i < nodes.length; i++) {
    ctx.beginPath();
    ctx.moveTo(nodes[0].x, nodes[0].y);
    ctx.lineTo(nodes[i].x, nodes[i].y);
    ctx.stroke();
  }

  // Draw nodes
  for (const node of nodes) {
    // Gold ring for center node
    if (node.isCenter) {
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.radius + 3, 0, Math.PI * 2);
      ctx.strokeStyle = GOLD_RING;
      ctx.lineWidth = 2;
      ctx.stroke();
    }

    // Filled circle
    ctx.beginPath();
    ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
    ctx.fillStyle = node.color;
    ctx.fill();

    // Label
    ctx.fillStyle = LABEL_COLOR;
    ctx.font = "9px monospace";
    ctx.textAlign = "center";
    ctx.textBaseline = "top";
    ctx.fillText(node.label, node.x, node.y + node.radius + 4);
  }
}

/** Hit-test: returns the first node whose circle contains (px, py), or null. */
function hitTest(nodes: SimNode[], px: number, py: number): SimNode | null {
  // Iterate in reverse so top-drawn nodes are tested first
  for (let i = nodes.length - 1; i >= 0; i--) {
    const n = nodes[i];
    const dx = px - n.x;
    const dy = py - n.y;
    const hitRadius = n.radius + 4; // generous hit area
    if (dx * dx + dy * dy <= hitRadius * hitRadius) {
      return n;
    }
  }
  return null;
}

// ── Component ────────────────────────────────────────────────────────

export function GraphTab() {
  const selection = useSelection();
  const dispatch = useWorkbenchDispatch();

  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const nodesRef = useRef<SimNode[]>([]);
  const iterRef = useRef(0);
  const rafRef = useRef<number>(0);

  // Resolve related entities
  const entityType = selection.entityType;
  const entityId = selection.entityId;
  const relatedRaw = selection.metadata?.relatedEntities as RelatedEntity[] | undefined;

  // ── Canvas resize via ResizeObserver ───────────────────────────────

  const resizeCanvas = useCallback(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;

    const rect = container.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    canvas.style.width = `${rect.width}px`;
    canvas.style.height = `${rect.height}px`;

    const ctx = canvas.getContext("2d");
    if (ctx) {
      ctx.scale(dpr, dpr);
    }
  }, []);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const observer = new ResizeObserver(() => {
      resizeCanvas();
    });
    observer.observe(container);

    // Initial sizing
    resizeCanvas();

    return () => observer.disconnect();
  }, [resizeCanvas]);

  // ── Build nodes & run simulation when selection changes ────────────

  useEffect(() => {
    // Cancel any running animation
    if (rafRef.current) {
      cancelAnimationFrame(rafRef.current);
      rafRef.current = 0;
    }

    if (!entityType || !entityId) {
      nodesRef.current = [];
      // Clear canvas
      const canvas = canvasRef.current;
      if (canvas) {
        const ctx = canvas.getContext("2d");
        if (ctx) {
          const dpr = window.devicePixelRatio || 1;
          ctx.clearRect(0, 0, canvas.width / dpr, canvas.height / dpr);
        }
      }
      return;
    }

    const container = containerRef.current;
    if (!container) return;

    const rect = container.getBoundingClientRect();
    const cx = rect.width / 2;
    const cy = rect.height / 2;

    const related: RelatedEntity[] =
      relatedRaw && Array.isArray(relatedRaw) && relatedRaw.length > 0
        ? relatedRaw
        : DEFAULT_RELATIONSHIPS[entityType] ?? [];

    nodesRef.current = buildNodes(entityType, entityId, related, cx, cy);
    iterRef.current = 0;

    function animate() {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const ctx = canvas.getContext("2d");
      if (!ctx) return;

      const cont = containerRef.current;
      if (!cont) return;
      const r = cont.getBoundingClientRect();
      const w = r.width;
      const h = r.height;
      const midX = w / 2;
      const midY = h / 2;

      const nodes = nodesRef.current;

      if (iterRef.current < MAX_ITERATIONS) {
        stepSimulation(nodes, midX, midY);
        iterRef.current++;
      }

      drawGraph(ctx, nodes, w, h);

      // Keep animating until settled, then do one final frame
      if (iterRef.current <= MAX_ITERATIONS) {
        rafRef.current = requestAnimationFrame(animate);
      } else {
        rafRef.current = 0;
      }
    }

    rafRef.current = requestAnimationFrame(animate);

    return () => {
      if (rafRef.current) {
        cancelAnimationFrame(rafRef.current);
        rafRef.current = 0;
      }
    };
  }, [entityType, entityId, relatedRaw]);

  // ── Click handler ──────────────────────────────────────────────────

  const handleCanvasClick = useCallback(
    (e: React.MouseEvent<HTMLCanvasElement>) => {
      const canvas = canvasRef.current;
      if (!canvas) return;

      const rect = canvas.getBoundingClientRect();
      const px = e.clientX - rect.left;
      const py = e.clientY - rect.top;

      const hit = hitTest(nodesRef.current, px, py);
      if (hit) {
        dispatch({
          type: "SET_SELECTION",
          payload: {
            entityType: hit.entityType,
            entityId: hit.entityId,
          },
        });
      }
    },
    [dispatch],
  );

  // ── Empty state ────────────────────────────────────────────────────

  if (!entityType || !entityId) {
    return (
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          gap: 8,
          color: "var(--color-text-muted, #6b7280)",
          fontFamily: "monospace",
          fontSize: 11,
          padding: 16,
          textAlign: "center",
        }}
      >
        Select an entity to view its relationships
      </div>
    );
  }

  // Derive whether we have relationships at all
  const hasRelated =
    (relatedRaw && Array.isArray(relatedRaw) && relatedRaw.length > 0) ||
    (DEFAULT_RELATIONSHIPS[entityType]?.length ?? 0) > 0;

  return (
    <div
      ref={containerRef}
      style={{
        position: "relative",
        width: "100%",
        height: "100%",
        overflow: "hidden",
      }}
    >
      <canvas
        ref={canvasRef}
        onClick={handleCanvasClick}
        style={{
          display: "block",
          width: "100%",
          height: "100%",
          cursor: "pointer",
          background: "transparent",
        }}
      />
      {!hasRelated && (
        <div
          style={{
            position: "absolute",
            bottom: 16,
            left: 0,
            right: 0,
            textAlign: "center",
            color: "var(--color-text-muted, #6b7280)",
            fontFamily: "monospace",
            fontSize: 10,
            pointerEvents: "none",
          }}
        >
          No relationships found
        </div>
      )}
    </div>
  );
}
