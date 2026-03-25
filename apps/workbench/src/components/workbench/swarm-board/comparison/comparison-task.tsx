/**
 * TaskComparison -- side-by-side comparison of terminalTask nodes.
 *
 * Shows status badge, task prompt (truncated), and session ID.
 */

import type { Node } from "@xyflow/react";
import { IconSubtask } from "@tabler/icons-react";
import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";
import { ComparisonColumns } from "./comparison-columns";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_PROMPT_LENGTH = 100;

// ---------------------------------------------------------------------------
// Status colors
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

interface TaskComparisonProps {
  nodes: Node<SwarmBoardNodeData>[];
  onClose: () => void;
}

export function TaskComparison({ nodes, onClose }: TaskComparisonProps) {
  return (
    <ComparisonColumns
      nodes={nodes}
      typeLabel="task"
      typeIcon={IconSubtask}
      typeColor="#5580cc"
      onClose={onClose}
      renderNode={(node) => {
        const d = node.data as SwarmBoardNodeData;
        const prompt = d.taskPrompt ?? "";
        const truncatedPrompt =
          prompt.length > MAX_PROMPT_LENGTH
            ? `${prompt.slice(0, MAX_PROMPT_LENGTH)}...`
            : prompt;

        return (
          <div className="flex flex-col gap-1">
            {/* Status badge */}
            <div>
              <span
                className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded-sm"
                style={{
                  backgroundColor: `${STATUS_COLORS[d.status] ?? "#5c6a80"}18`,
                  color: STATUS_COLORS[d.status] ?? "#5c6a80",
                }}
              >
                {d.status}
              </span>
            </div>

            {/* Task prompt */}
            {truncatedPrompt && (
              <div className="text-[9px] font-mono text-[#5c6a80] leading-relaxed">
                {truncatedPrompt}
              </div>
            )}

            {/* Session ID */}
            {d.sessionId && (
              <div className="text-[8px] font-mono text-[#2a2f3a] truncate">
                session: {d.sessionId}
              </div>
            )}
          </div>
        );
      }}
    />
  );
}
