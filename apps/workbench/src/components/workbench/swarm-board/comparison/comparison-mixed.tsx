/**
 * MixedComparison -- heterogeneous fallback for mixed-type node selections.
 *
 * Groups nodes by nodeType, renders a group header with type icon/label/count,
 * then a compact summary row per node.
 */

import { useMemo } from "react";
import { IconArrowsExchange, IconX } from "@tabler/icons-react";
import type { Node } from "@xyflow/react";
import type { SwarmBoardNodeData, SwarmNodeType } from "@/features/swarm/swarm-board-types";
import { NODE_TYPE_META } from "../swarm-board-inspector";

// ---------------------------------------------------------------------------
// Status colors (compact badges)
// ---------------------------------------------------------------------------

const STATUS_COLORS: Record<string, string> = {
  idle: "#5c6a80",
  running: "#c49a3c",
  blocked: "#cc5555",
  completed: "#38a876",
  failed: "#cc5555",
  evaluating: "#7c5cbf",
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

interface MixedComparisonProps {
  nodes: Node<SwarmBoardNodeData>[];
  onClose: () => void;
}

export function MixedComparison({ nodes, onClose }: MixedComparisonProps) {
  const groups = useMemo(() => {
    const map = new Map<SwarmNodeType, Node<SwarmBoardNodeData>[]>();
    for (const node of nodes) {
      const d = node.data as SwarmBoardNodeData;
      const type = d.nodeType;
      const arr = map.get(type);
      if (arr) {
        arr.push(node);
      } else {
        map.set(type, [node]);
      }
    }
    return map;
  }, [nodes]);

  const nodeTypes = useMemo(() => new Set(nodes.map((n) => (n.data as SwarmBoardNodeData).nodeType)), [nodes]);

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-[#0e1018] shrink-0">
        <IconArrowsExchange size={12} stroke={1.5} className="text-[#5c6a80] shrink-0" />
        <span className="text-[12px] font-mono font-medium text-[#ece7dc] tracking-tight flex-1">
          Comparing {nodes.length} nodes ({nodeTypes.size} types)
        </span>
        <button
          onClick={onClose}
          className="shrink-0 p-0.5 text-[#2a2f3a] hover:text-[#5c6a80] transition-colors"
          aria-label="Close comparison"
        >
          <IconX size={13} stroke={1.5} />
        </button>
      </div>

      {/* Scrollable body */}
      <div className="flex-1 overflow-y-auto px-3 py-2 flex flex-col gap-3">
        {[...groups.entries()].map(([type, groupNodes]) => {
          const meta = NODE_TYPE_META[type];
          const TypeIcon = meta.icon;

          return (
            <div key={type}>
              {/* Group header */}
              <div className="flex items-center gap-1.5 mb-1.5">
                <TypeIcon size={11} stroke={1.5} style={{ color: meta.color }} />
                <span className="text-[10px] font-mono text-[#5c6a80]">
                  {meta.label} ({groupNodes.length})
                </span>
              </div>

              {/* Compact rows */}
              <div className="flex flex-col gap-1">
                {groupNodes.map((node) => {
                  const d = node.data as SwarmBoardNodeData;
                  return (
                    <div
                      key={node.id}
                      className="flex items-center gap-2 border border-[#14181f] rounded px-2 py-1"
                    >
                      <span className="text-[10px] font-mono text-[#ece7dc] truncate flex-1">
                        {d.title}
                      </span>
                      <span
                        className="text-[8px] font-mono px-1 py-0.5 rounded-sm shrink-0"
                        style={{
                          backgroundColor: `${STATUS_COLORS[d.status] ?? "#5c6a80"}18`,
                          color: STATUS_COLORS[d.status] ?? "#5c6a80",
                        }}
                      >
                        {d.status}
                      </span>
                      <MixedNodeMetrics data={d} />
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Compact per-type metric summary (1-2 key values)
// ---------------------------------------------------------------------------

function MixedNodeMetrics({ data }: { data: SwarmBoardNodeData }) {
  switch (data.nodeType) {
    case "agentSession":
      return (
        <span className="text-[8px] font-mono text-[#2a2f3a] shrink-0">
          {data.receiptCount ?? 0}r {data.changedFilesCount ?? 0}f
        </span>
      );
    case "receipt":
      return (
        <span
          className="text-[8px] font-mono shrink-0"
          style={{ color: data.verdict === "allow" ? "#38a876" : data.verdict === "deny" ? "#cc5555" : "#c49a3c" }}
        >
          {data.verdict ?? "allow"}
        </span>
      );
    case "diff":
      return (
        <span className="text-[8px] font-mono text-[#2a2f3a] shrink-0">
          {data.diffSummary ? `+${data.diffSummary.added}/-${data.diffSummary.removed}` : "--"}
        </span>
      );
    case "terminalTask":
      return (
        <span className="text-[8px] font-mono text-[#2a2f3a] shrink-0 truncate max-w-[60px]">
          {data.taskPrompt ? data.taskPrompt.slice(0, 20) : "--"}
        </span>
      );
    case "artifact":
      return (
        <span className="text-[8px] font-mono text-[#2a2f3a] shrink-0">
          {data.fileType ?? "--"}
        </span>
      );
    default:
      return null;
  }
}
