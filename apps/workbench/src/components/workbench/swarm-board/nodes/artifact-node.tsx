/**
 * ArtifactNode — desktop file icon aesthetic.
 *
 * TINY and ICONIC. Just a file icon + name. No card wrapper.
 * Think: a file icon floating on the canvas with a small label.
 */

import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
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
import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";
import { useZoomTier } from "../hooks/use-zoom-tier";

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
  rust: "#c88c6a",
  rs: "#c88c6a",
  ts: "#2e6db3",
  tsx: "#2e6db3",
  typescript: "#2e6db3",
  py: "#2e6196",
  python: "#2e6196",
  pdf: "#b85450",
  md: "#5c6a80",
  txt: "#5c6a80",
};

function getFileIcon(fileType?: string): typeof IconFile {
  if (!fileType) return IconFileCode;
  return FILE_ICONS[fileType.toLowerCase()] ?? IconFileCode;
}

function getFileColor(fileType?: string): string {
  if (!fileType) return "#5580cc";
  return FILE_COLORS[fileType.toLowerCase()] ?? "#5580cc";
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

function ArtifactNodeInner({ data, selected }: NodeProps) {
  const d = data as SwarmBoardNodeData;
  const tier = useZoomTier();
  const FileIcon = getFileIcon(d.fileType);
  const fileColor = getFileColor(d.fileType);

  const filename = d.filePath
    ? d.filePath.split("/").pop() ?? d.filePath
    : d.title;

  // ---------------------------------------------------------------------------
  // Dot tier — tiny file-colored dot
  // ---------------------------------------------------------------------------
  if (tier === "dot") {
    return (
      <div
        className="rounded-sm"
        style={{
          backgroundColor: "#0e1018",
          width: "100%",
          height: "100%",
          minWidth: 20,
          minHeight: 20,
          borderLeft: `2px solid ${fileColor}`,
        }}
      >
        <Handle type="target" position={Position.Top} className="!w-1 !h-1 !bg-transparent" />
        <Handle type="source" position={Position.Bottom} className="!w-1 !h-1 !bg-transparent" />
      </div>
    );
  }

  // ---------------------------------------------------------------------------
  // Chip tier — file icon + filename truncated, single row
  // ---------------------------------------------------------------------------
  if (tier === "chip") {
    return (
      <div
        className="flex items-center gap-1 px-1.5"
        style={{ minWidth: 60, minHeight: 22 }}
      >
        <Handle type="target" position={Position.Top} className="!w-1 !h-1 !bg-transparent" />
        <FileIcon size={12} stroke={1.2} style={{ color: fileColor }} />
        <span className="text-[7px] font-mono text-[#5c6a80] truncate flex-1">
          {filename}
        </span>
        <Handle type="source" position={Position.Bottom} className="!w-1 !h-1 !bg-transparent" />
      </div>
    );
  }

  // ---------------------------------------------------------------------------
  // Compact/Full — artifact nodes are already tiny and iconic, render same
  // ---------------------------------------------------------------------------

  return (
    <div
      className={cn(
        // No card background, no border, no padding — just floating content
        "flex flex-col items-center gap-1 transition-all duration-150",
        selected && "drop-shadow-[0_0_6px_rgba(196,154,60,0.15)]",
      )}
      style={{ minWidth: 64, maxWidth: 96 }}
    >
      <Handle
        type="target"
        position={Position.Top}
        className="!w-1 !h-1 !bg-[#2a2f3a] !border-[#0a0c11] !border hover:!bg-[#c49a3c] transition-colors"
      />

      {/* Icon — the primary visual */}
      <div
        className={cn(
          "flex items-center justify-center w-10 h-10 rounded-sm transition-colors",
          selected ? "bg-[#1a1e28]" : "bg-[#0e1018]",
        )}
      >
        <FileIcon size={20} stroke={1.2} style={{ color: fileColor }} />
      </div>

      {/* Filename label — small, underneath, like a desktop icon */}
      <span
        className={cn(
          "text-[9px] font-mono text-center leading-tight truncate w-full",
          selected ? "text-[#ece7dc]" : "text-[#5c6a80]",
        )}
        title={d.filePath ?? filename}
      >
        {filename}
      </span>

      <Handle
        type="source"
        position={Position.Bottom}
        className="!w-1 !h-1 !bg-[#2a2f3a] !border-[#0a0c11] !border hover:!bg-[#c49a3c] transition-colors"
      />
    </div>
  );
}

export const ArtifactNode = memo(ArtifactNodeInner);
