/**
 * ReceiptNode — legal document stamp aesthetic.
 *
 * The verdict (ALLOW/DENY) is the dominant visual element — large, bold,
 * impossible to miss. Guard details are secondary, quieter.
 */

import { memo } from "react";
import { Handle, Position, NodeResizer, type NodeProps } from "@xyflow/react";
import { IconCheck, IconX, IconAlertTriangle } from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import type { SwarmBoardNodeData } from "@/lib/workbench/swarm-board-types";

// ---------------------------------------------------------------------------
// Verdict styling — the verdict IS the node
// ---------------------------------------------------------------------------

const VERDICT_STYLE: Record<
  "allow" | "deny" | "warn",
  { accent: string; accentMuted: string; icon: typeof IconCheck; label: string }
> = {
  allow: {
    accent: "#38a876",
    accentMuted: "#38a87618",
    icon: IconCheck,
    label: "ALLOW",
  },
  deny: {
    accent: "#b85450",
    accentMuted: "#b8545018",
    icon: IconX,
    label: "DENY",
  },
  warn: {
    accent: "#c49a3c",
    accentMuted: "#c49a3c18",
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

  const passedCount = guards.filter(g => g.allowed).length;
  const failedCount = guards.filter(g => !g.allowed).length;

  return (
    <div
      className={cn(
        "rounded transition-all duration-150 overflow-hidden",
        selected
          ? "ring-1 ring-[#c49a3c]/20"
          : "shadow-[0_1px_4px_rgba(0,0,0,0.5)]",
      )}
      style={{
        backgroundColor: selected ? "#0e1018" : "#0a0c11",
        width: "100%",
        height: "100%",
        minWidth: 240,
        minHeight: 160,
        // Thin top accent line — the "seal" color
        borderTop: `2px solid ${vs.accent}30`,
      }}
    >
      <NodeResizer
        minWidth={240}
        minHeight={160}
        isVisible={selected}
        lineClassName="!border-[#c49a3c]/25"
        handleClassName="!w-1.5 !h-1.5 !bg-[#c49a3c] !border-[#0a0c11]"
      />
      <Handle
        type="target"
        position={Position.Top}
        className="!w-1.5 !h-1.5 !bg-[#2a2f3a] !border-[#0a0c11] !border-2 hover:!bg-[#c49a3c] transition-colors"
      />

      {/* Verdict hero — the FIRST thing you see */}
      <div className="flex items-center gap-3 px-3 pt-3 pb-2">
        <div
          className="shrink-0 flex items-center justify-center w-9 h-9 rounded"
          style={{ backgroundColor: vs.accentMuted }}
        >
          <VerdictIcon size={20} stroke={2.5} style={{ color: vs.accent }} />
        </div>
        <div className="min-w-0">
          <div
            className="text-[18px] font-bold tracking-tight leading-none"
            style={{ color: vs.accent, letterSpacing: '0.04em' }}
          >
            {vs.label}
          </div>
          <div
            className="text-[9px] font-mono mt-1"
            style={{ color: '#4a5568', fontVariantNumeric: 'tabular-nums' }}
          >
            {passedCount} passed{failedCount > 0 && <> / <span style={{ color: '#b85450' }}>{failedCount} failed</span></>}
          </div>
        </div>
        {timeStr && (
          <span
            className="ml-auto text-[8px] font-mono text-[#2a2f3a] self-start mt-0.5"
            style={{ fontVariantNumeric: 'tabular-nums' }}
          >
            {timeStr}
          </span>
        )}
      </div>

      {/* Guard results — secondary, compact */}
      {guards.length > 0 && (
        <div className="px-3 py-1.5">
          {guards.slice(0, 6).map((gr, i) => (
            <div key={i} className="flex items-center gap-1.5 py-[2px]">
              <span
                className="w-1 h-1 rounded-full shrink-0"
                style={{ backgroundColor: gr.allowed ? "#38a876" : "#b85450" }}
              />
              <span className="text-[9px] text-[#4a5568] font-mono truncate flex-1">
                {gr.guard}
              </span>
              {gr.duration_ms != null && (
                <span
                  className="text-[8px] text-[#2a2f3a] font-mono shrink-0"
                  style={{ fontVariantNumeric: 'tabular-nums' }}
                >
                  {gr.duration_ms}ms
                </span>
              )}
            </div>
          ))}
          {guards.length > 6 && (
            <span className="text-[8px] text-[#2a2f3a] ml-2.5">
              +{guards.length - 6} more
            </span>
          )}
        </div>
      )}

      {/* Signature footer — like a stamp seal */}
      <div
        className="flex items-center px-3 py-1.5 mt-auto"
        style={{ borderTop: '1px solid #1a1e2820' }}
      >
        <span
          className="text-[7px] text-[#2a2f3a] font-mono truncate"
          style={{ fontVariantNumeric: 'tabular-nums' }}
          title={sigHash}
        >
          sig {sigHash.slice(0, 18)}...
        </span>
      </div>

      <Handle
        type="source"
        position={Position.Bottom}
        className="!w-1.5 !h-1.5 !bg-[#2a2f3a] !border-[#0a0c11] !border-2 hover:!bg-[#c49a3c] transition-colors"
      />
    </div>
  );
}

export const ReceiptNode = memo(ReceiptNodeInner);
