/**
 * SwarmEdge — custom edge renderer for the SwarmBoard.
 *
 * Renders differently based on the edge's `data.edgeType`:
 * - handoff:  Solid line with arrow, gold #d4a84b
 * - spawned:  Dashed line with arrow, blue #5b8def (subtle pulse animation)
 * - artifact: Dotted line, green #3dbf84
 * - receipt:  Thin dotted line, muted #6f7f9a
 *
 * Uses React Flow's BaseEdge + getSmoothStepPath.
 */

import {
  BaseEdge,
  EdgeLabelRenderer,
  getSmoothStepPath,
  type EdgeProps,
} from "@xyflow/react";

// ---------------------------------------------------------------------------
// Edge type visual config
// ---------------------------------------------------------------------------

type SwarmEdgeType = "handoff" | "spawned" | "artifact" | "receipt";

interface EdgeStyleConfig {
  color: string;
  strokeWidth: number;
  strokeDasharray?: string;
  animated: boolean;
  label: string;
}

const EDGE_STYLES: Record<SwarmEdgeType, EdgeStyleConfig> = {
  handoff: {
    color: "#d4a84b",
    strokeWidth: 1.5,
    animated: false,
    label: "handoff",
  },
  spawned: {
    color: "#5b8def",
    strokeWidth: 1,
    strokeDasharray: "6 4",
    animated: true,
    label: "spawned",
  },
  artifact: {
    color: "#3dbf84",
    strokeWidth: 1,
    strokeDasharray: "2 4",
    animated: false,
    label: "artifact",
  },
  receipt: {
    color: "#6f7f9a",
    strokeWidth: 0.75,
    strokeDasharray: "2 5",
    animated: false,
    label: "receipt",
  },
};

const DEFAULT_STYLE: EdgeStyleConfig = {
  color: "#1a1f2e",
  strokeWidth: 1,
  animated: false,
  label: "",
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
    borderRadius: 16,
  });

  // Subtle pulse animation for spawned edges
  const animatedStyle = config.animated
    ? {
        strokeDashoffset: 0,
        animation: "swarmEdgePulse 3s ease-in-out infinite",
      }
    : {};

  // Determine opacity: very dim by default, bright when connected to hovered/selected node
  const edgeOpacity = isHighlighted ? 0.8 : 0.18;

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
          transition: "opacity 0.3s ease, stroke 0.2s ease",
          filter: isHighlighted ? `drop-shadow(0 0 3px ${config.color}40)` : undefined,
          ...animatedStyle,
        }}
      />

      {/* Colored dot at midpoint instead of text label */}
      {edgeType && (
        <EdgeLabelRenderer>
          <div
            className="nodrag nopan pointer-events-none"
            style={{
              position: "absolute",
              transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
              opacity: isHighlighted ? 0.8 : 0.25,
              transition: "opacity 0.3s ease",
            }}
          >
            <span
              className="block w-[5px] h-[5px] rounded-full"
              style={{
                backgroundColor: config.color,
              }}
            />
          </div>
        </EdgeLabelRenderer>
      )}

      {/* CSS keyframe for spawned edge pulse */}
      {config.animated && (
        <style>{`
          @keyframes swarmEdgePulse {
            0%, 100% { opacity: 0.15; }
            50% { opacity: 0.35; }
          }
        `}</style>
      )}
    </>
  );
}
