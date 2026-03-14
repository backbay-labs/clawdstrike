/**
 * ArtifactNode — compact file card with icon, filename, and type badge.
 */

import { memo } from "react";
import { Handle, Position, NodeResizer, type NodeProps } from "@xyflow/react";
import {
  IconFile,
  IconFileCode,
  IconFileText,
  IconFileTypePdf,
  IconBrandRust,
  IconBrandTypescript,
  IconBrandPython,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import type { SwarmBoardNodeData } from "@/lib/workbench/swarm-board-types";

// ---------------------------------------------------------------------------
// File type config
// ---------------------------------------------------------------------------

const FILE_ICONS: Record<string, typeof IconFile> = {
  rust: IconBrandRust,
  rs: IconBrandRust,
  ts: IconBrandTypescript,
  tsx: IconBrandTypescript,
  typescript: IconBrandTypescript,
  py: IconBrandPython,
  python: IconBrandPython,
  pdf: IconFileTypePdf,
  md: IconFileText,
  txt: IconFileText,
  code: IconFileCode,
};

const FILE_COLORS: Record<string, string> = {
  rust: "#dea584",
  rs: "#dea584",
  ts: "#3178c6",
  tsx: "#3178c6",
  typescript: "#3178c6",
  py: "#3572a5",
  python: "#3572a5",
  pdf: "#e74c3c",
  md: "#6f7f9a",
  txt: "#6f7f9a",
};

function getFileIcon(fileType?: string): typeof IconFile {
  if (!fileType) return IconFileCode;
  return FILE_ICONS[fileType.toLowerCase()] ?? IconFileCode;
}

function getFileColor(fileType?: string): string {
  if (!fileType) return "#5b8def";
  return FILE_COLORS[fileType.toLowerCase()] ?? "#5b8def";
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

function ArtifactNodeInner({ data, selected }: NodeProps) {
  const d = data as SwarmBoardNodeData;
  const FileIcon = getFileIcon(d.fileType);
  const fileColor = getFileColor(d.fileType);

  const filename = d.filePath
    ? d.filePath.split("/").pop() ?? d.filePath
    : d.title;

  return (
    <div
      className={cn(
        "rounded-lg transition-all duration-200 flex items-center gap-2.5 px-3 py-2.5",
        selected
          ? "shadow-[0_0_0_1px_rgba(212,168,75,0.25)]"
          : "shadow-[0_2px_8px_rgba(0,0,0,0.4)]",
        !selected && "hover:bg-[#0f1219]",
      )}
      style={{ backgroundColor: selected ? "#11141c" : "#0c0e14", width: "100%", height: "100%", minWidth: 180, minHeight: 80 }}
    >
      <NodeResizer
        minWidth={180}
        minHeight={80}
        isVisible={selected}
        lineClassName="!border-[#d4a84b]/40"
        handleClassName="!w-2 !h-2 !bg-[#d4a84b] !border-[#0b0d13]"
      />
      <Handle
        type="target"
        position={Position.Top}
        className="!w-2 !h-2 !bg-[#2d3240] !border-[#0b0d13] !border-2 hover:!bg-[#d4a84b] transition-colors"
      />

      {/* File icon */}
      <div
        className="shrink-0 flex items-center justify-center w-7 h-7 rounded-md"
        style={{
          backgroundColor: `${fileColor}12`,
          border: `1px solid ${fileColor}20`,
        }}
      >
        <FileIcon size={14} stroke={1.5} style={{ color: fileColor }} />
      </div>

      {/* Filename + path */}
      <div className="min-w-0 flex-1">
        <div className="text-[12px] font-medium text-[#ece7dc] truncate">
          {filename}
        </div>
        {d.filePath && d.filePath !== filename && (
          <div className="text-[9px] text-[#3d4250] font-mono truncate mt-0.5">
            {d.filePath}
          </div>
        )}
      </div>

      {/* Type badge */}
      {d.fileType && (
        <span
          className="shrink-0 px-1.5 py-0.5 rounded text-[9px] font-semibold uppercase tracking-wide"
          style={{
            backgroundColor: `${fileColor}15`,
            color: fileColor,
            border: `1px solid ${fileColor}25`,
          }}
        >
          {d.fileType}
        </span>
      )}

      <Handle
        type="source"
        position={Position.Bottom}
        className="!w-2 !h-2 !bg-[#2d3240] !border-[#0b0d13] !border-2 hover:!bg-[#d4a84b] transition-colors"
      />
    </div>
  );
}

export const ArtifactNode = memo(ArtifactNodeInner);
