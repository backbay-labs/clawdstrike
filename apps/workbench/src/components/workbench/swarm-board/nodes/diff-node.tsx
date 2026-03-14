/**
 * DiffNode — code diff aesthetic.
 *
 * The +/- numbers are the visual hero. Split green/red treatment.
 * No rounded card wrapper — sharp, asymmetric, code-native.
 */

import { memo } from "react";
import { Handle, Position, NodeResizer, type NodeProps } from "@xyflow/react";
import { IconFileDiff } from "@tabler/icons-react";
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
        // No rounded corners — diffs are sharp, technical
        "rounded-none transition-all duration-150 overflow-hidden",
        selected
          ? "ring-1 ring-[#c49a3c]/20"
          : "shadow-[0_1px_4px_rgba(0,0,0,0.5)]",
      )}
      style={{
        backgroundColor: selected ? "#0e1018" : "#0a0c11",
        width: "100%",
        height: "100%",
        minWidth: 200,
        minHeight: 100,
      }}
    >
      <NodeResizer
        minWidth={200}
        minHeight={100}
        isVisible={selected}
        lineClassName="!border-[#c49a3c]/25"
        handleClassName="!w-1.5 !h-1.5 !bg-[#c49a3c] !border-[#0a0c11]"
      />
      <Handle
        type="target"
        position={Position.Top}
        className="!w-1.5 !h-1.5 !bg-[#2a2f3a] !border-[#0a0c11] !border-2 hover:!bg-[#c49a3c] transition-colors"
      />

      {/* Split +/- hero — asymmetric, the numbers dominate */}
      <div className="flex">
        {/* Additions side */}
        <div
          className="flex-1 py-2.5 px-3"
          style={{ borderRight: '1px solid #1a1e2830' }}
        >
          <span
            className="text-[22px] font-bold leading-none tracking-tight block"
            style={{ color: '#38a876', fontVariantNumeric: 'tabular-nums' }}
          >
            +{added}
          </span>
          <span className="text-[8px] font-mono text-[#38a876]/40 uppercase mt-1 block" style={{ letterSpacing: '0.1em' }}>
            added
          </span>
        </div>
        {/* Deletions side */}
        <div className="flex-1 py-2.5 px-3">
          <span
            className="text-[22px] font-bold leading-none tracking-tight block"
            style={{ color: '#b85450', fontVariantNumeric: 'tabular-nums' }}
          >
            -{removed}
          </span>
          <span className="text-[8px] font-mono text-[#b85450]/40 uppercase mt-1 block" style={{ letterSpacing: '0.1em' }}>
            removed
          </span>
        </div>
      </div>

      {/* File list — monospace, compact, left-aligned with gutter dots */}
      {files.length > 0 && (
        <div
          className="px-2.5 pb-2 pt-1.5 flex flex-col gap-px"
          style={{ borderTop: '1px solid #1a1e2830' }}
        >
          {files.slice(0, 5).map((file, i) => (
            <div key={i} className="flex items-center gap-1.5 min-w-0">
              <IconFileDiff size={9} stroke={1.5} className="text-[#2a2f3a] shrink-0" />
              <span className="text-[9px] text-[#4a5568] font-mono truncate">
                {file}
              </span>
            </div>
          ))}
          {files.length > 5 && (
            <span
              className="text-[8px] text-[#2a2f3a] ml-4 font-mono"
              style={{ fontVariantNumeric: 'tabular-nums' }}
            >
              +{files.length - 5} more
            </span>
          )}
        </div>
      )}

      {/* Minimal file count — bottom right, like a git stat line */}
      {files.length > 0 && (
        <div className="flex justify-end px-2.5 pb-1.5">
          <span
            className="text-[8px] font-mono text-[#2a2f3a]"
            style={{ fontVariantNumeric: 'tabular-nums' }}
          >
            {files.length} file{files.length !== 1 ? "s" : ""}
          </span>
        </div>
      )}

      <Handle
        type="source"
        position={Position.Bottom}
        className="!w-1.5 !h-1.5 !bg-[#2a2f3a] !border-[#0a0c11] !border-2 hover:!bg-[#c49a3c] transition-colors"
      />
    </div>
  );
}

export const DiffNode = memo(DiffNodeInner);
