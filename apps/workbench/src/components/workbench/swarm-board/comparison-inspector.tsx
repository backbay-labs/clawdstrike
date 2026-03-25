/**
 * ComparisonInspector -- root component for multi-node comparison.
 *
 * Routes to type-specific comparison views for homogeneous selections,
 * or to MixedComparison for heterogeneous selections. Enforces a cap
 * of MAX_COMPARISON_NODES with an overflow guard.
 */

import { useMemo } from "react";
import { IconX, IconAlertTriangle } from "@tabler/icons-react";
import type { Node } from "@xyflow/react";
import type { SwarmBoardNodeData, SwarmNodeType } from "@/features/swarm/swarm-board-types";
import { SessionComparison } from "./comparison/comparison-session";
import { ReceiptComparison } from "./comparison/comparison-receipt";
import { DiffComparison } from "./comparison/comparison-diff";
import { TaskComparison } from "./comparison/comparison-task";
import { ArtifactComparison } from "./comparison/comparison-artifact";
import { MixedComparison } from "./comparison/comparison-mixed";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const MAX_COMPARISON_NODES = 6;

// ---------------------------------------------------------------------------
// Root component
// ---------------------------------------------------------------------------

interface ComparisonInspectorProps {
  nodes: Node<SwarmBoardNodeData>[];
  onClose: () => void;
}

export function ComparisonInspector({ nodes, onClose }: ComparisonInspectorProps) {
  // Overflow guard
  if (nodes.length > MAX_COMPARISON_NODES) {
    return <ComparisonOverflow count={nodes.length} max={MAX_COMPARISON_NODES} onClose={onClose} />;
  }

  const nodeTypes = useMemo(
    () => new Set(nodes.map((n) => (n.data as SwarmBoardNodeData).nodeType)),
    [nodes],
  );

  // Homogeneous selection -> type-specific comparison
  if (nodeTypes.size === 1) {
    const type = [...nodeTypes][0] as SwarmNodeType;
    switch (type) {
      case "agentSession":
        return <SessionComparison nodes={nodes} onClose={onClose} />;
      case "receipt":
        return <ReceiptComparison nodes={nodes} onClose={onClose} />;
      case "diff":
        return <DiffComparison nodes={nodes} onClose={onClose} />;
      case "terminalTask":
        return <TaskComparison nodes={nodes} onClose={onClose} />;
      case "artifact":
        return <ArtifactComparison nodes={nodes} onClose={onClose} />;
      default:
        return <MixedComparison nodes={nodes} onClose={onClose} />;
    }
  }

  // Mixed selection -> grouped fallback
  return <MixedComparison nodes={nodes} onClose={onClose} />;
}

// ---------------------------------------------------------------------------
// Overflow component
// ---------------------------------------------------------------------------

function ComparisonOverflow({
  count,
  max,
  onClose,
}: {
  count: number;
  max: number;
  onClose: () => void;
}) {
  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-[#0e1018] shrink-0">
        <IconAlertTriangle size={12} stroke={1.5} className="text-[#c49a3c] shrink-0" />
        <span className="text-[12px] font-mono font-medium text-[#ece7dc] tracking-tight flex-1">
          Too many nodes
        </span>
        <button
          onClick={onClose}
          className="shrink-0 p-0.5 text-[#2a2f3a] hover:text-[#5c6a80] transition-colors"
          aria-label="Close comparison"
        >
          <IconX size={13} stroke={1.5} />
        </button>
      </div>
      <div className="flex-1 flex items-center justify-center px-6">
        <p className="text-[11px] font-mono text-[#5c6a80] text-center leading-relaxed">
          Select {max} or fewer nodes to compare ({count} selected)
        </p>
      </div>
    </div>
  );
}
