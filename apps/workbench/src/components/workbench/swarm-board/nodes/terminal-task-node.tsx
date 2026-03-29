/**
 * TerminalTaskNode — task badge aesthetic.
 *
 * Compact, horizontal orientation. Status is the dominant element.
 * Not a card — more like a compact process indicator.
 */

import { memo, useState, useEffect, useRef, useMemo } from "react";
import { Handle, Position, NodeResizer, type NodeProps } from "@xyflow/react";
import { cn } from "@/lib/utils";
import type { SwarmBoardNodeData, SessionStatus } from "@/features/swarm/swarm-board-types";
import { useZoomTier } from "../hooks/use-zoom-tier";

// ---------------------------------------------------------------------------
// Status styles — restrained, functional colors
// ---------------------------------------------------------------------------

const STATUS_CONFIG: Record<SessionStatus, { color: string; label: string }> = {
  idle: { color: "#4a5568", label: "IDLE" },
  running: { color: "#38a876", label: "RUN" },
  blocked: { color: "#c49a3c", label: "WAIT" },
  completed: { color: "#5580cc", label: "DONE" },
  failed: { color: "#b85450", label: "FAIL" },
  evaluating: { color: "#d4a84b", label: "EVAL" },
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

function TerminalTaskNodeInner({ data, selected }: NodeProps) {
  const d = data as SwarmBoardNodeData;
  const tier = useZoomTier();
  const status = d.status ?? "idle";
  const cfg = STATUS_CONFIG[status];

  const [statusFlash, setStatusFlash] = useState(false);
  const previousStatusRef = useRef<SessionStatus | null>(null);

  useEffect(() => {
    if (previousStatusRef.current == null) {
      previousStatusRef.current = status;
      return;
    }
    if (previousStatusRef.current === status) return;
    previousStatusRef.current = status;
    setStatusFlash(true);
    const timeout = window.setTimeout(() => setStatusFlash(false), 500);
    return () => window.clearTimeout(timeout);
  }, [status]);

  const elapsed = useMemo(() => {
    if (!d.createdAt) return null;
    const secs = Math.floor((Date.now() - d.createdAt) / 1000);
    if (secs < 60) return `${secs}s`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
    return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
  }, [d.createdAt]);

  // ---------------------------------------------------------------------------
  // Dot tier — colored rectangle with status border
  // ---------------------------------------------------------------------------
  if (tier === "dot") {
    return (
      <div
        className="rounded-sm"
        style={{
          backgroundColor: "#0a0c11",
          width: "100%",
          height: "100%",
          minWidth: 30,
          minHeight: 16,
          borderLeft: `2px solid ${cfg.color}`,
          boxShadow: statusFlash
            ? `0 0 0 1px ${cfg.color}40, 0 0 12px ${cfg.color}18`
            : undefined,
        }}
      >
        <Handle type="target" position={Position.Top} className="!w-1 !h-1 !bg-transparent" />
        <Handle type="source" position={Position.Bottom} className="!w-1 !h-1 !bg-transparent" />
      </div>
    );
  }

  // ---------------------------------------------------------------------------
  // Chip tier — status dot + title + status label
  // ---------------------------------------------------------------------------
  if (tier === "chip") {
    return (
      <div
        className="rounded-sm flex items-center gap-1.5 px-2"
        style={{
          backgroundColor: "#0a0c11",
          borderLeft: `2px solid ${cfg.color}`,
          minWidth: 100,
          minHeight: 22,
          boxShadow: statusFlash
            ? `0 0 0 1px ${cfg.color}40, 0 0 12px ${cfg.color}18`
            : undefined,
        }}
      >
        <Handle type="target" position={Position.Top} className="!w-1 !h-1 !bg-transparent" />
        <span className="w-[5px] h-[5px] rounded-full shrink-0" style={{ backgroundColor: cfg.color }} />
        <span className="text-[8px] font-mono text-[#5c6a80] truncate flex-1">
          {d.title ?? "task"}
        </span>
        <span className="text-[7px] font-mono font-bold uppercase shrink-0" style={{ color: cfg.color, letterSpacing: "0.1em" }}>
          {cfg.label}
        </span>
        <Handle type="source" position={Position.Bottom} className="!w-1 !h-1 !bg-transparent" />
      </div>
    );
  }

  // ---------------------------------------------------------------------------
  // Compact tier — status dot + label + title (no elapsed time)
  // Full tier — unchanged
  // ---------------------------------------------------------------------------

  return (
    <div
      className={cn(
        // Compact rounded — badge-like, not card-like
        "rounded-sm transition-all duration-150 overflow-hidden",
        selected
          ? "ring-1 ring-[#c49a3c]/20"
          : "shadow-[0_1px_3px_rgba(0,0,0,0.4)]",
        status === 'completed' && 'opacity-70',
      )}
      style={{
        backgroundColor: selected ? "#0e1018" : "#0a0c11",
        width: "100%",
        height: "100%",
        minWidth: tier === "compact" ? 160 : 220,
        minHeight: tier === "compact" ? 36 : 72,
        // Left accent — status color as a 2px stripe
        borderLeft: `2px solid ${cfg.color}50`,
        boxShadow: statusFlash
          ? `0 0 0 1px ${cfg.color}40, 0 0 12px ${cfg.color}18`
          : undefined,
      }}
    >
      {tier === "full" && (
        <NodeResizer
          minWidth={220}
          minHeight={72}
          isVisible={selected}
          lineClassName="!border-[#c49a3c]/25"
          handleClassName="!w-1.5 !h-1.5 !bg-[#c49a3c] !border-[#0a0c11]"
        />
      )}
      <Handle
        type="target"
        position={Position.Top}
        className="!w-1.5 !h-1.5 !bg-[#2a2f3a] !border-[#0a0c11] !border-2 hover:!bg-[#c49a3c] transition-colors"
      />

      {/* Top line: status badge + title + elapsed (elapsed hidden in compact) */}
      <div className="flex items-center gap-2 px-2.5 pt-2 pb-1">
        {/* Status label — the dominant element */}
        <span
          className="shrink-0 text-[8px] font-mono font-bold uppercase"
          style={{
            color: cfg.color,
            letterSpacing: '0.14em',
          }}
        >
          {cfg.label}
        </span>
        <span className="text-[11px] font-medium text-[#8a96ab] truncate flex-1 tracking-tight">
          {d.title}
        </span>
        {tier === "full" && elapsed && (
          <span
            className="shrink-0 text-[8px] font-mono text-[#2a2f3a]"
            style={{ fontVariantNumeric: 'tabular-nums' }}
          >
            {elapsed}
          </span>
        )}
      </div>

      {/* Task description — full tier only */}
      {tier === "full" && (
        <div className="px-2.5 pb-2">
          <p className={cn(
            "text-[10px] text-[#4a5568] leading-[1.5]",
            selected ? "line-clamp-2" : "line-clamp-1",
          )}>
            {d.taskPrompt ?? "No task description"}
          </p>
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

export const TerminalTaskNode = memo(TerminalTaskNodeInner);
