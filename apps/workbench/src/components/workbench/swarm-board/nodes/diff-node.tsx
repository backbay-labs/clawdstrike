/**
 * DiffNode — code diff aesthetic.
 *
 * The +/- numbers are the visual hero. Split green/red treatment.
 * No rounded card wrapper — sharp, asymmetric, code-native.
 */

import { memo, useMemo } from "react";
import { Handle, Position, NodeResizer, type NodeProps } from "@xyflow/react";
import { cn } from "@/lib/utils";
import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";
import { summarizeUnifiedDiff } from "../diff-preview";
import { DiffPreviewPane } from "../diff-preview-pane";

function DiffNodeInner({ data, selected }: NodeProps) {
  const d = data as SwarmBoardNodeData;
  const summary = useMemo(
    () => d.diffSummary ?? summarizeUnifiedDiff(d.diffContent ?? ""),
    [d.diffContent, d.diffSummary],
  );
  const added = summary?.added ?? 0;
  const removed = summary?.removed ?? 0;
  const files = summary?.files ?? [];
  const hasPreviewSource = Boolean(d.diffContent?.trim() || d.diffPath);
  const fileCount = files.length;

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
        minHeight: selected && hasPreviewSource ? 144 : 88,
      }}
    >
      <NodeResizer
        minWidth={200}
        minHeight={88}
        isVisible={selected}
        lineClassName="!border-[#c49a3c]/25"
        handleClassName="!w-1.5 !h-1.5 !bg-[#c49a3c] !border-[#0a0c11]"
      />
      <Handle
        type="target"
        position={Position.Top}
        className="!w-1.5 !h-1.5 !bg-[#2a2f3a] !border-[#0a0c11] !border-2 hover:!bg-[#c49a3c] transition-colors"
      />

      {/* Split +/- hero — the counts stay board-visible, but quieter */}
      <div className="flex">
        {/* Additions side */}
        <div
          className="flex-1 py-2 px-3"
          style={{ borderRight: '1px solid #1a1e2830' }}
        >
          <span
            className="text-[14px] font-bold leading-none tracking-tight block"
            style={{ color: '#38a876', fontVariantNumeric: 'tabular-nums' }}
          >
            +{added}
          </span>
        </div>
        {/* Deletions side */}
        <div className="flex-1 py-2 px-3">
          <span
            className="text-[14px] font-bold leading-none tracking-tight block"
            style={{ color: '#b85450', fontVariantNumeric: 'tabular-nums' }}
          >
            -{removed}
          </span>
        </div>
      </div>

      <div
        className="flex items-center justify-between px-3 py-1.5"
        style={{ borderTop: "1px solid #1a1e2830" }}
      >
        <span
          className="text-[8px] font-mono text-[#4a5568]"
          style={{ fontVariantNumeric: "tabular-nums" }}
        >
          {fileCount} file{fileCount !== 1 ? "s" : ""}
        </span>
        {d.diffPath && (
          <span className="text-[8px] font-mono text-[#2a2f3a] truncate max-w-[120px]" title={d.diffPath}>
            {d.diffPath.split("/").pop()}
          </span>
        )}
      </div>

      {selected && hasPreviewSource && (
        <div className="px-2.5 pb-2" style={{ borderTop: "1px solid #1a1e2830" }}>
          <div className="py-1.5 text-[8px] font-mono uppercase tracking-[0.14em] text-[#4a5568]">
            preview
          </div>
          <DiffPreviewPane
            diffContent={d.diffContent}
            diffPath={d.diffPath}
            maxLines={10}
            maxHeight={132}
            emptyMessage="Diff preview unavailable"
          />
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
