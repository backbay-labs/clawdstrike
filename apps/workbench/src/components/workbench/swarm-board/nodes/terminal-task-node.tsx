/**
 * TerminalTaskNode — React Flow custom node for a spawned terminal task.
 *
 * Compact card showing task prompt, status badge, and elapsed time.
 */

import { memo, useMemo } from "react";
import { Handle, Position, NodeResizer, type NodeProps } from "@xyflow/react";
import { IconSubtask, IconClock } from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import type { SwarmBoardNodeData, SessionStatus } from "@/lib/workbench/swarm-board-types";

// ---------------------------------------------------------------------------
// Status styles
// ---------------------------------------------------------------------------

const STATUS_BADGE: Record<SessionStatus, { bg: string; text: string; label: string }> = {
  idle: { bg: "#6f7f9a18", text: "#6f7f9a", label: "Idle" },
  running: { bg: "#3dbf8418", text: "#3dbf84", label: "Running" },
  blocked: { bg: "#d4a84b18", text: "#d4a84b", label: "Blocked" },
  completed: { bg: "#5b8def18", text: "#5b8def", label: "Completed" },
  failed: { bg: "#e74c3c18", text: "#e74c3c", label: "Failed" },
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

function TerminalTaskNodeInner({ data, selected }: NodeProps) {
  const d = data as SwarmBoardNodeData;
  const status = d.status ?? "idle";
  const badge = STATUS_BADGE[status];

  const elapsed = useMemo(() => {
    if (!d.createdAt) return null;
    const secs = Math.floor((Date.now() - d.createdAt) / 1000);
    if (secs < 60) return `${secs}s`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
    return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
  }, [d.createdAt]);

  return (
    <div
      className={cn(
        "rounded-lg transition-all duration-200 overflow-hidden",
        selected
          ? "shadow-[0_0_0_1px_rgba(212,168,75,0.25)]"
          : "shadow-[0_2px_8px_rgba(0,0,0,0.4)]",
        !selected && "hover:bg-[#0f1219]",
      )}
      style={{ backgroundColor: selected ? "#11141c" : "#0c0e14", width: "100%", height: "100%", minWidth: 240, minHeight: 120 }}
    >
      <NodeResizer
        minWidth={240}
        minHeight={120}
        isVisible={selected}
        lineClassName="!border-[#d4a84b]/40"
        handleClassName="!w-2 !h-2 !bg-[#d4a84b] !border-[#0b0d13]"
      />
      <Handle
        type="target"
        position={Position.Top}
        className="!w-2 !h-2 !bg-[#2d3240] !border-[#0b0d13] !border-2 hover:!bg-[#d4a84b] transition-colors"
      />

      {/* Header */}
      <div className="flex items-center gap-2 px-3 py-2 border-b border-[#2d324060]">
        <IconSubtask size={14} stroke={1.5} className="text-[#d4a84b] shrink-0" />
        <span className="text-[12px] font-medium text-[#ece7dc] truncate flex-1">
          {d.title}
        </span>
        <span
          className="shrink-0 px-1.5 py-0.5 rounded text-[9px] font-semibold uppercase tracking-wide"
          style={{
            backgroundColor: badge.bg,
            color: badge.text,
          }}
        >
          {badge.label}
        </span>
      </div>

      {/* Body: task prompt */}
      <div className="px-3 py-2.5">
        <p className="text-[11px] text-[#8a96ab] leading-[1.5] line-clamp-3">
          {d.taskPrompt ?? "No task description"}
        </p>
      </div>

      {/* Footer */}
      <div className="flex items-center gap-3 px-3 py-1.5 border-t border-[#2d324060]">
        {elapsed && (
          <div className="flex items-center gap-1 text-[10px] text-[#6f7f9a]">
            <IconClock size={11} stroke={1.5} />
            <span>{elapsed}</span>
          </div>
        )}
        {d.sessionId && (
          <span className="text-[9px] text-[#3d4250] font-mono ml-auto truncate max-w-[120px]">
            {d.sessionId}
          </span>
        )}
      </div>

      <Handle
        type="source"
        position={Position.Bottom}
        className="!w-2 !h-2 !bg-[#2d3240] !border-[#0b0d13] !border-2 hover:!bg-[#d4a84b] transition-colors"
      />
    </div>
  );
}

export const TerminalTaskNode = memo(TerminalTaskNodeInner);
