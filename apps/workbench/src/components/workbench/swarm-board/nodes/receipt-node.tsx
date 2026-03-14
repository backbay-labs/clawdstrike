/**
 * ReceiptNode — shows verdict badge, guard results, and signature hash.
 */

import { memo } from "react";
import { Handle, Position, NodeResizer, type NodeProps } from "@xyflow/react";
import { IconCertificate, IconCheck, IconX, IconAlertTriangle } from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import type { SwarmBoardNodeData } from "@/lib/workbench/swarm-board-types";

// ---------------------------------------------------------------------------
// Verdict styling
// ---------------------------------------------------------------------------

const VERDICT_STYLE: Record<
  "allow" | "deny" | "warn",
  { bg: string; text: string; border: string; icon: typeof IconCheck; label: string }
> = {
  allow: {
    bg: "#3dbf8415",
    text: "#3dbf84",
    border: "#3dbf8430",
    icon: IconCheck,
    label: "ALLOW",
  },
  deny: {
    bg: "#e74c3c15",
    text: "#e74c3c",
    border: "#e74c3c30",
    icon: IconX,
    label: "DENY",
  },
  warn: {
    bg: "#d4a84b15",
    text: "#d4a84b",
    border: "#d4a84b30",
    icon: IconAlertTriangle,
    label: "WARN",
  },
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

function ReceiptNodeInner({ data, selected }: NodeProps) {
  const d = data as SwarmBoardNodeData;
  const verdict = d.verdict ?? "allow";
  const vs = VERDICT_STYLE[verdict];
  const VerdictIcon = vs.icon;
  const guards = d.guardResults ?? [];

  // Generate a fake signature hash for display
  const sigHash = d.sessionId
    ? `0x${d.sessionId.replace(/[^a-f0-9]/gi, "").padEnd(40, "0").slice(0, 40)}`
    : "0x" + "0".repeat(40);

  const timeStr = d.createdAt
    ? new Date(d.createdAt).toLocaleTimeString(undefined, {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      })
    : null;

  return (
    <div
      className={cn(
        "rounded-lg transition-all duration-200 overflow-hidden",
        selected
          ? "shadow-[0_0_0_1px_rgba(212,168,75,0.25)]"
          : "shadow-[0_2px_8px_rgba(0,0,0,0.4)]",
        !selected && "hover:bg-[#0f1219]",
      )}
      style={{ backgroundColor: selected ? "#11141c" : "#0c0e14", width: "100%", height: "100%", minWidth: 260, minHeight: 160 }}
    >
      <NodeResizer
        minWidth={260}
        minHeight={160}
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
        <IconCertificate size={14} stroke={1.5} className="text-[#8b5cf6] shrink-0" />
        <span className="text-[12px] font-medium text-[#ece7dc] truncate flex-1">
          {d.title || "Receipt"}
        </span>

        {/* Verdict badge */}
        <span
          className="shrink-0 flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wide"
          style={{
            backgroundColor: vs.bg,
            color: vs.text,
            border: `1px solid ${vs.border}`,
          }}
        >
          <VerdictIcon size={10} stroke={2} />
          {vs.label}
        </span>
      </div>

      {/* Guard results */}
      <div className="px-3 py-2 flex flex-col gap-1">
        {guards.length > 0 ? (
          guards.slice(0, 6).map((gr, i) => (
            <div key={i} className="flex items-center gap-2">
              <span
                className="w-1.5 h-1.5 rounded-full shrink-0"
                style={{
                  backgroundColor: gr.allowed ? "#3dbf84" : "#e74c3c",
                }}
              />
              <span className="text-[10px] text-[#8a96ab] font-mono truncate flex-1">
                {gr.guard}
              </span>
              {gr.duration_ms != null && (
                <span className="text-[9px] text-[#3d4250] font-mono shrink-0">
                  {gr.duration_ms}ms
                </span>
              )}
            </div>
          ))
        ) : (
          <span className="text-[10px] text-[#3d4250] italic">No guard results</span>
        )}
        {guards.length > 6 && (
          <span className="text-[9px] text-[#3d4250] ml-3.5">
            +{guards.length - 6} more
          </span>
        )}
      </div>

      {/* Footer: signature + timestamp */}
      <div className="flex items-center gap-2 px-3 py-1.5 border-t border-[#2d324060]">
        <span
          className="text-[8px] text-[#3d4250] font-mono truncate flex-1"
          title={sigHash}
        >
          sig: {sigHash.slice(0, 18)}...
        </span>
        {timeStr && (
          <span className="text-[9px] text-[#3d4250] shrink-0">{timeStr}</span>
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

export const ReceiptNode = memo(ReceiptNodeInner);
