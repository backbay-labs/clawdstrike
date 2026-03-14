/**
 * AgentSessionNode — React Flow custom node for an active agent coding session.
 *
 * Displays agent model, branch, status indicator, a LIVE xterm.js terminal
 * connected to the PTY backend, footer metrics, and a status bar.
 *
 * Styled as a premium operator terminal window — not a generic card.
 */

import { memo, useCallback } from "react";
import { Handle, Position, NodeResizer, type NodeProps } from "@xyflow/react";
import {
  IconFileCode,
  IconReceipt,
  IconShieldOff,
  IconActivity,
  IconX,
  IconMaximize,
  IconMinimize,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { useSwarmBoard } from "@/lib/workbench/swarm-board-store";
import { TerminalRenderer } from "../terminal-renderer";
import type { SwarmBoardNodeData, SessionStatus, RiskLevel } from "@/lib/workbench/swarm-board-types";

// ---------------------------------------------------------------------------
// Status dot colors
// ---------------------------------------------------------------------------

const STATUS_COLOR: Record<SessionStatus, string> = {
  idle: "#6f7f9a",
  running: "#3dbf84",
  blocked: "#d4a84b",
  completed: "#6f7f9a",
  failed: "#e74c3c",
};

/** Statuses that show a pulsing animation on the dot. */
const STATUS_PULSE: Partial<Record<SessionStatus, boolean>> = {
  running: true,
  blocked: true,
};

const STATUS_LABEL: Record<SessionStatus, string> = {
  idle: "idle",
  running: "running",
  blocked: "blocked",
  completed: "done",
  failed: "failed",
};

const RISK_COLORS: Record<RiskLevel, { bg: string; text: string }> = {
  low: { bg: "transparent", text: "#3dbf84" },
  medium: { bg: "transparent", text: "#d4a84b" },
  high: { bg: "transparent", text: "#e74c3c" },
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

function AgentSessionNodeInner({ id, data, selected }: NodeProps) {
  const d = data as SwarmBoardNodeData;
  const { updateNode, removeNode, killSession } = useSwarmBoard();
  const status = d.status ?? "idle";
  const statusColor = STATUS_COLOR[status];
  const risk = d.risk ?? "low";
  const riskStyle = RISK_COLORS[risk];
  const maximized = d.maximized ?? false;
  const hasSession = !!d.sessionId;

  const handleClose = useCallback(
    (e: React.MouseEvent) => {
      e.stopPropagation();
      if (hasSession) {
        killSession(id).catch(() => {});
      }
      removeNode(id);
    },
    [id, hasSession, killSession, removeNode],
  );

  const handleToggleMaximize = useCallback(
    (e: React.MouseEvent) => {
      e.stopPropagation();
      updateNode(id, { maximized: !maximized });
    },
    [id, maximized, updateNode],
  );

  // Build the compact status line pieces
  const statusLineParts: string[] = [];
  if (d.agentModel) statusLineParts.push(d.agentModel);
  if (d.branch) statusLineParts.push(d.branch);
  if (d.policyMode) statusLineParts.push(d.policyMode);

  // Status-driven visual classes
  const statusBorderClass = cn(
    status === 'running' && 'border-l-2 border-l-[#d4a84b]',
    status === 'blocked' && 'border-l-2 border-l-[#f59e0b]',
    status === 'failed' && 'border-l-2 border-l-[#c45c5c]',
  );

  const statusOpacityClass = cn(
    status === 'completed' && 'opacity-[0.75]',
    status === 'blocked' && 'opacity-95',
    status === 'failed' && 'opacity-90',
  );

  const statusAnimation = (() => {
    switch (status) {
      case 'running': return 'breathe-gold 3s ease-in-out infinite';
      case 'blocked': return 'breathe-amber 3s ease-in-out infinite';
      case 'failed': return 'breathe-red 3s ease-in-out infinite';
      default: return undefined;
    }
  })();

  return (
    <div
      className={cn(
        "rounded-lg transition-all duration-200 overflow-hidden flex flex-col relative",
        statusBorderClass,
        statusOpacityClass,
        selected
          ? "shadow-[0_0_0_1px_rgba(212,168,75,0.25)]"
          : "shadow-[0_2px_8px_rgba(0,0,0,0.4)]",
        !selected && "hover:bg-[#0f1219]",
        status === 'idle' && 'border-b border-b-[#1a1f2e20]',
      )}
      style={{
        backgroundColor: selected ? "#11141c" : "#0c0e14",
        width: "100%",
        height: "100%",
        minWidth: 320,
        minHeight: 240,
        animation: statusAnimation,
      }}
    >
      {/* Heartbeat radial pulse for running sessions */}
      {status === 'running' && (
        <div
          className="absolute inset-0 rounded-lg pointer-events-none"
          style={{
            animation: 'heartbeat 3s ease-in-out infinite',
            background: 'radial-gradient(circle at 50% 50%, rgba(212,168,75,0.04) 0%, transparent 70%)',
          }}
        />
      )}
      <NodeResizer
        minWidth={320}
        minHeight={240}
        isVisible={selected}
        lineClassName="!border-[#d4a84b]/30"
        handleClassName="!w-1.5 !h-1.5 !bg-[#d4a84b] !border-[#0c0e14]"
      />
      {/* Top handle */}
      <Handle
        type="target"
        position={Position.Top}
        className="!w-2 !h-2 !bg-[#2d3240] !border-[#0c0e14] !border-2 hover:!bg-[#d4a84b] transition-colors"
      />

      {/* Header — compact terminal status line */}
      <div
        className="flex items-center justify-between px-3 shrink-0 select-none"
        style={{ height: 32, backgroundColor: "#090b10" }}
      >
        {/* Left: status line */}
        <div className="flex items-center gap-1.5 min-w-0 flex-1">
          {/* Status dot */}
          <span
            className="w-[7px] h-[7px] rounded-full shrink-0"
            style={{
              backgroundColor: statusColor,
              boxShadow: STATUS_PULSE[status] ? `0 0 6px ${statusColor}80` : undefined,
              animation: STATUS_PULSE[status] ? "pulse 2s ease-in-out infinite" : undefined,
            }}
          />
          {/* Compact inline status: model . branch . policy . status */}
          <span className="text-[10px] font-mono text-[#6f7f9a] truncate">
            {statusLineParts.length > 0 && (
              <>
                {statusLineParts.map((part, i) => (
                  <span key={i}>
                    {i > 0 && <span className="text-[#2d3240] mx-1">&middot;</span>}
                    <span className={cn(
                      part === d.agentModel && "text-[#d4a84b]",
                      part === d.branch && "text-[#5b8def]",
                      part === d.policyMode && (d.policyMode === "strict" ? "text-[#e74c3c]" : "text-[#6f7f9a]"),
                    )}>
                      {part}
                    </span>
                  </span>
                ))}
                <span className="text-[#2d3240] mx-1">&middot;</span>
              </>
            )}
            <span style={{ color: statusColor }}>
              {STATUS_LABEL[status]}
            </span>
            {d.exitCode != null && status !== "running" && (
              <span className="text-[#3d4250] ml-0.5">({d.exitCode})</span>
            )}
          </span>
        </div>

        {/* Right: window controls */}
        <div className="flex items-center gap-0.5 shrink-0 ml-2">
          <button
            onClick={handleToggleMaximize}
            className="p-1 rounded hover:bg-[#ffffff08] text-[#3d4250] hover:text-[#6f7f9a] transition-colors"
            title={maximized ? "Minimize" : "Maximize"}
          >
            {maximized ? <IconMinimize size={10} stroke={1.5} /> : <IconMaximize size={10} stroke={1.5} />}
          </button>
          <button
            onClick={handleClose}
            className="p-1 rounded hover:bg-[#e74c3c15] text-[#3d4250] hover:text-[#e74c3c] transition-colors"
            title="Close session"
          >
            <IconX size={10} stroke={1.5} />
          </button>
        </div>
      </div>

      {/* Terminal body — flex-1 fills remaining space */}
      <div className="flex-1 min-h-0 relative">
        {hasSession ? (
          <TerminalRenderer
            sessionId={d.sessionId!}
            active={!!selected || maximized}
            fontSize={selected || maximized ? 11 : 8}
          />
        ) : (
          /* Fallback: static preview lines styled as a proper code block */
          <div
            className="w-full h-full overflow-auto"
            style={{ backgroundColor: "#080a0f" }}
          >
            <div className="py-2">
              {(d.previewLines ?? []).slice(maximized ? 0 : -8).map((line, i) => (
                <div
                  key={i}
                  className="flex hover:bg-[#ffffff03]"
                >
                  {/* Line gutter */}
                  <span className="shrink-0 w-8 text-right pr-2 text-[9px] font-mono text-[#1e2230] select-none leading-[1.7]">
                    {i + 1}
                  </span>
                  {/* Line content */}
                  <span
                    className={cn(
                      "flex-1 pl-2 font-mono text-[11px] leading-[1.7] whitespace-pre truncate",
                      line.startsWith("$")
                        ? "text-[#d4a84b]"
                        : line.includes("FAILED") || line.includes("error")
                          ? "text-[#e74c3c]"
                          : line.includes("ok") || line.includes("passed")
                            ? "text-[#3dbf84]"
                            : "text-[#6f7f9a]",
                    )}
                  >
                    {line}
                  </span>
                </div>
              ))}
              {(!d.previewLines || d.previewLines.length === 0) && (
                <div className="flex items-center justify-center h-full min-h-[60px]">
                  <span className="text-[10px] font-mono text-[#1e2230]">awaiting output...</span>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Footer metrics — compact icon+number pairs */}
      <div
        className="flex items-center gap-3 px-3 shrink-0 select-none"
        style={{ height: 26, backgroundColor: "#090b10" }}
      >
        <FooterMetric icon={IconFileCode} value={d.changedFilesCount ?? 0} color="#5b8def" />
        <FooterMetric icon={IconReceipt} value={d.receiptCount ?? 0} color="#8b5cf6" />
        <FooterMetric icon={IconShieldOff} value={d.blockedActionCount ?? 0} color={d.blockedActionCount ? "#e74c3c" : "#3d4250"} />
        {d.toolBoundaryEvents != null && (
          <FooterMetric icon={IconActivity} value={d.toolBoundaryEvents} color="#d4a84b" />
        )}

        {/* Risk indicator — minimal, right-aligned */}
        <span
          className="ml-auto text-[8px] font-mono font-medium uppercase tracking-widest"
          style={{ color: riskStyle.text }}
        >
          {risk}
        </span>
      </div>

      {/* Status bar — thin vim-like footer */}
      <div
        className="flex items-center gap-2.5 px-3 shrink-0 select-none"
        style={{ height: 20, backgroundColor: "#070910" }}
      >
        {d.worktreePath && (
          <span className="text-[8px] font-mono text-[#1e2230] truncate max-w-[120px]">
            {d.worktreePath.split("/").slice(-2).join("/")}
          </span>
        )}
        {d.policyMode && (
          <span
            className="ml-auto text-[8px] font-mono font-medium uppercase tracking-wider"
            style={{
              color: d.policyMode === "strict" ? "#e74c3c80" : "#3dbf8460",
            }}
          >
            {d.policyMode === "strict" ? "bypass off" : "bypass on"}
          </span>
        )}
      </div>

      {/* Bottom handle */}
      <Handle
        type="source"
        position={Position.Bottom}
        className="!w-2 !h-2 !bg-[#2d3240] !border-[#0c0e14] !border-2 hover:!bg-[#d4a84b] transition-colors"
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Footer metric helper — icon + number, tight and compact
// ---------------------------------------------------------------------------

function FooterMetric({
  icon: Icon,
  value,
  color,
}: {
  icon: typeof IconFileCode;
  value: number;
  color: string;
}) {
  return (
    <div className="flex items-center gap-1">
      <Icon size={11} stroke={1.5} style={{ color }} />
      <span className="text-[10px] font-mono font-medium tabular-nums" style={{ color }}>
        {value}
      </span>
    </div>
  );
}

export const AgentSessionNode = memo(AgentSessionNodeInner);
