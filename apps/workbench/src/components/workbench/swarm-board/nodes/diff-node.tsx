/**
 * DiffNode — shows +N / -N summary with changed file list.
 */

import { memo } from "react";
import { Handle, Position, NodeResizer, type NodeProps } from "@xyflow/react";
import { IconGitCommit, IconFileDiff } from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import type { SwarmBoardNodeData } from "@/lib/workbench/swarm-board-types";

function DiffNodeInner({ data, selected }: NodeProps) {
  const d = data as SwarmBoardNodeData;
  const summary = d.diffSummary;
  const added = summary?.added ?? 0;
  const removed = summary?.removed ?? 0;
  const files = summary?.files ?? [];

  return (
    <div
      className={cn(
        "rounded-lg transition-all duration-200 overflow-hidden",
        selected
          ? "shadow-[0_0_0_1px_rgba(212,168,75,0.25)]"
          : "shadow-[0_2px_8px_rgba(0,0,0,0.4)]",
        !selected && "hover:bg-[#0f1219]",
      )}
      style={{ backgroundColor: selected ? "#11141c" : "#0c0e14", width: "100%", height: "100%", minWidth: 220, minHeight: 120 }}
    >
      <NodeResizer
        minWidth={220}
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
        <IconGitCommit size={14} stroke={1.5} className="text-[#8b5cf6] shrink-0" />
        <span className="text-[12px] font-medium text-[#ece7dc] truncate flex-1">
          {d.title || "Diff"}
        </span>
        <span className="text-[10px] text-[#6f7f9a]">
          {files.length} file{files.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* +/- Summary */}
      <div className="flex items-center gap-4 px-3 py-2.5">
        <div className="flex items-center gap-1">
          <span className="text-[16px] font-bold text-[#3dbf84]">+{added}</span>
          <span className="text-[10px] text-[#3dbf8480]">added</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="text-[16px] font-bold text-[#e74c3c]">-{removed}</span>
          <span className="text-[10px] text-[#e74c3c80]">removed</span>
        </div>
      </div>

      {/* File list */}
      {files.length > 0 && (
        <div className="px-3 pb-2.5 flex flex-col gap-0.5">
          {files.slice(0, 5).map((file, i) => (
            <div key={i} className="flex items-center gap-1.5 min-w-0">
              <IconFileDiff size={10} stroke={1.5} className="text-[#3d4250] shrink-0" />
              <span className="text-[10px] text-[#6f7f9a] font-mono truncate">
                {file}
              </span>
            </div>
          ))}
          {files.length > 5 && (
            <span className="text-[9px] text-[#3d4250] ml-4">
              +{files.length - 5} more
            </span>
          )}
        </div>
      )}

      <Handle
        type="source"
        position={Position.Bottom}
        className="!w-2 !h-2 !bg-[#2d3240] !border-[#0b0d13] !border-2 hover:!bg-[#d4a84b] transition-colors"
      />
    </div>
  );
}

export const DiffNode = memo(DiffNodeInner);
