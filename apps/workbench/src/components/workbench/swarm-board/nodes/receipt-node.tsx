/**
 * ReceiptNode — legal document stamp aesthetic.
 *
 * The verdict (ALLOW/DENY) is the dominant visual element — large, bold,
 * impossible to miss. Secondary verification detail lives in the inspector.
 */

import { memo } from "react";
import { Handle, Position, NodeResizer, type NodeProps } from "@xyflow/react";
import { IconCheck, IconX, IconAlertTriangle, IconShieldCheck, IconShieldOff, IconShieldQuestion } from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";

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

  const rawTimeSource = d.receiptData?.timestamp
    ? Date.parse(d.receiptData.timestamp)
    : d.createdAt;
  const timeSource =
    typeof rawTimeSource === "number" && Number.isFinite(rawTimeSource)
      ? rawTimeSource
      : null;
  const timeStr = timeSource != null
    ? new Date(timeSource).toLocaleTimeString(undefined, {
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
        minWidth: 220,
        minHeight: 96,
        // Thin top accent line — the "seal" color
        borderTop: `2px solid ${vs.accent}30`,
      }}
    >
      <NodeResizer
        minWidth={220}
        minHeight={96}
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
            {formatReceiptNodeTime(timeSource, timeStr)}
          </span>
        )}
      </div>

      {/* Verification footer — preserve board-level trust state, move raw detail to inspector */}
      <div
        className="flex items-center gap-2 px-3 py-1.5 mt-auto"
        style={{ borderTop: '1px solid #1a1e2820' }}
      >
        <span
          className="text-[8px] text-[#4a5568] font-mono"
          style={{ fontVariantNumeric: "tabular-nums" }}
        >
          {guards.length} guard{guards.length !== 1 ? "s" : ""}
        </span>
        {d.signatureVerified === true ? (
          <span className="flex items-center gap-0.5 shrink-0 ml-auto" title="Signature verified">
            <IconShieldCheck size={10} stroke={2} style={{ color: '#38a876' }} />
            <span className="text-[7px] font-mono" style={{ color: '#38a876' }}>Verified</span>
          </span>
        ) : d.signatureVerified === false ? (
          <span className="flex items-center gap-0.5 shrink-0 ml-auto" title="Signature verification failed">
            <IconShieldOff size={10} stroke={2} style={{ color: '#b85450' }} />
            <span className="text-[7px] font-mono" style={{ color: '#b85450' }}>Unverified</span>
          </span>
        ) : d.signature && d.publicKey ? (
          <span className="flex items-center gap-0.5 shrink-0 ml-auto" title="Verification pending">
            <IconShieldQuestion size={10} stroke={2} style={{ color: '#4a5568' }} />
            <span className="text-[7px] font-mono" style={{ color: '#4a5568' }}>Pending</span>
          </span>
        ) : null}
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

function formatReceiptNodeTime(timeSource: number | null, fallback: string): string {
  if (timeSource == null) {
    return fallback;
  }

  const deltaSeconds = Math.max(0, Math.floor((Date.now() - timeSource) / 1000));
  if (deltaSeconds < 60) return `${deltaSeconds}s ago`;
  if (deltaSeconds < 3600) return `${Math.floor(deltaSeconds / 60)}m ago`;
  if (deltaSeconds < 86_400) return `${Math.floor(deltaSeconds / 3600)}h ago`;
  return `${Math.floor(deltaSeconds / 86_400)}d ago`;
}
