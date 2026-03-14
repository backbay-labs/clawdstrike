/**
 * SwarmEdge — custom edge renderer for the SwarmBoard.
 *
 * Renders differently based on the edge's `data.edgeType`:
 * - handoff:  Solid line with arrow, warm gold
 * - spawned:  Dashed line with arrow, steel blue (subtle pulse)
 * - artifact: Dotted line, muted green
 * - receipt:  Thin dotted line, dim gray
 *
 * Uses React Flow's BaseEdge + getSmoothStepPath.
 */

import { useEffect } from "react";
import {
  BaseEdge,
  EdgeLabelRenderer,
  getSmoothStepPath,
  type EdgeProps,
} from "@xyflow/react";

// Inject the keyframe animation once into the document head, not per-edge
let keyframeInjected = false;
function ensureKeyframes() {
  if (keyframeInjected) return;
  keyframeInjected = true;
  const style = document.createElement("style");
  style.textContent = `
    @keyframes swarmEdgePulse {
      0%, 100% { opacity: 0.12; }
      50% { opacity: 0.30; }
    }
  `;
  document.head.appendChild(style);
}

// ---------------------------------------------------------------------------
// Edge type visual config — restrained, functional colors
// ---------------------------------------------------------------------------

type SwarmEdgeType = "handoff" | "spawned" | "artifact" | "receipt";

interface EdgeStyleConfig {
  color: string;
  strokeWidth: number;
  strokeDasharray?: string;
  animated: boolean;
  dotSize: number;
}

const EDGE_STYLES: Record<SwarmEdgeType, EdgeStyleConfig> = {
  handoff: {
    color: "#c49a3c",
    strokeWidth: 1.5,
    animated: false,
    dotSize: 7,
  },
  spawned: {
    color: "#5580cc",
    strokeWidth: 1,
    strokeDasharray: "6 4",
    animated: true,
    dotSize: 6,
  },
  artifact: {
    color: "#38a876",
    strokeWidth: 0.75,
    strokeDasharray: "2 4",
    animated: false,
    dotSize: 5,
  },
  receipt: {
    color: "#5c6a80",
    strokeWidth: 0.5,
    strokeDasharray: "2 5",
    animated: false,
    dotSize: 4,
  },
};

const DEFAULT_STYLE: EdgeStyleConfig = {
  color: "#1a1e28",
  strokeWidth: 1,
  animated: false,
  dotSize: 4,
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function SwarmEdge({
  id,
  source,
  target,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
  markerEnd,
  selected,
}: EdgeProps) {
  // Ensure keyframe animation is injected once
  useEffect(() => { ensureKeyframes(); }, []);

  // Resolve edge type from data or fall back to label heuristic
  const edgeType = (data?.edgeType as SwarmEdgeType) ?? undefined;
  const config = edgeType ? EDGE_STYLES[edgeType] : DEFAULT_STYLE;

  // Hover-reveal: check if this edge connects to the hovered or selected node
  const hoveredNodeId = data?.hoveredNodeId as string | null | undefined;
  const selectedNodeId = data?.selectedNodeId as string | null | undefined;
  const isConnectedToHovered = hoveredNodeId != null && (source === hoveredNodeId || target === hoveredNodeId);
  const isConnectedToSelected = selectedNodeId != null && (source === selectedNodeId || target === selectedNodeId);
  const isHighlighted = selected || isConnectedToHovered || isConnectedToSelected;

  const [edgePath, labelX, labelY] = getSmoothStepPath({
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition,
    targetPosition,
    borderRadius: 12,
  });

  // Subtle pulse animation for spawned edges
  const animatedStyle = config.animated
    ? {
        strokeDashoffset: 0,
        animation: "swarmEdgePulse 3s ease-in-out infinite",
      }
    : {};

  // Determine opacity: very dim by default, bright when connected to hovered/selected node
  const edgeOpacity = isHighlighted ? 0.7 : 0.15;

  return (
    <>
      <BaseEdge
        id={id}
        path={edgePath}
        markerEnd={markerEnd}
        style={{
          stroke: config.color,
          strokeWidth: config.strokeWidth,
          strokeDasharray: config.strokeDasharray,
          opacity: edgeOpacity,
          transition: "opacity 0.25s ease, stroke 0.2s ease",
          filter: isHighlighted ? `drop-shadow(0 0 2px ${config.color}30)` : undefined,
          ...animatedStyle,
        }}
      />

      {/* Colored dot at midpoint — sized per edge type, subtle glow when highlighted */}
      {edgeType && (
        <EdgeLabelRenderer>
          <div
            className="nodrag nopan pointer-events-none"
            style={{
              position: "absolute",
              transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
              opacity: isHighlighted ? 0.85 : 0.2,
              transition: "opacity 0.25s ease",
            }}
          >
            <span
              className="block rounded-full"
              style={{
                width: config.dotSize,
                height: config.dotSize,
                backgroundColor: config.color,
                boxShadow: isHighlighted ? `0 0 6px ${config.color}40` : undefined,
              }}
            />
          </div>
        </EdgeLabelRenderer>
      )}

    </>
  );
}
