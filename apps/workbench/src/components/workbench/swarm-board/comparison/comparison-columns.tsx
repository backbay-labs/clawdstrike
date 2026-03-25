/**
 * ComparisonColumns -- shared layout for type-homogeneous comparison views.
 *
 * Renders a header bar (count + type label + icon + optional extra),
 * then maps each node into a scrollable column/card via renderNode.
 */

import type { ReactNode } from "react";
import { IconArrowsExchange, IconX } from "@tabler/icons-react";
import type { Icon } from "@tabler/icons-react";
import type { Node } from "@xyflow/react";
import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface ComparisonColumnsProps {
  nodes: Node<SwarmBoardNodeData>[];
  typeLabel: string;
  typeIcon: Icon;
  typeColor: string;
  onClose: () => void;
  renderNode: (node: Node<SwarmBoardNodeData>, index: number) => ReactNode;
  /** Extra content rendered below the header (e.g. posture summary bar). */
  headerExtra?: ReactNode;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function ComparisonColumns({
  nodes,
  typeLabel,
  typeIcon: TypeIcon,
  typeColor,
  onClose,
  renderNode,
  headerExtra,
}: ComparisonColumnsProps) {
  return (
    <div className="flex flex-col h-full">
      {/* Header bar */}
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-[#0e1018] shrink-0">
        <IconArrowsExchange size={12} stroke={1.5} className="text-[#5c6a80] shrink-0" />
        <TypeIcon size={12} stroke={1.5} style={{ color: typeColor }} className="shrink-0" />
        <span className="text-[12px] font-mono font-medium text-[#ece7dc] tracking-tight flex-1">
          Comparing {nodes.length} {typeLabel}s
        </span>
        <button
          onClick={onClose}
          className="shrink-0 p-0.5 text-[#2a2f3a] hover:text-[#5c6a80] transition-colors"
          aria-label="Close comparison"
        >
          <IconX size={13} stroke={1.5} />
        </button>
      </div>

      {/* Optional header extra (posture bar, etc.) */}
      {headerExtra && (
        <div className="px-4 py-2 border-b border-[#0e1018] shrink-0">
          {headerExtra}
        </div>
      )}

      {/* Scrollable body */}
      <div className="flex-1 overflow-y-auto flex flex-col gap-3 px-3 py-2">
        {nodes.map((node, index) => (
          <div
            key={node.id}
            className="border border-[#14181f] rounded px-3 py-2"
          >
            <div className="text-[11px] font-mono font-medium text-[#ece7dc] mb-1.5 truncate">
              {(node.data as SwarmBoardNodeData).title}
            </div>
            {renderNode(node, index)}
          </div>
        ))}
      </div>
    </div>
  );
}
