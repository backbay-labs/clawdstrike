/**
 * AgentSessionNode — React Flow custom node for an active agent coding session.
 *
 * Visual language: Bloomberg terminal. Dark, dense, utilitarian.
 * Information density IS the aesthetic. No decorative elements.
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
// Status dot colors — slightly tinted, never neon
// ---------------------------------------------------------------------------

const STATUS_COLOR: Record<SessionStatus, string> = {
  idle: "#6b7a92",
  running: "#38a876",
  blocked: "#c49a3c",
  completed: "#6b7a92",
  failed: "#b85450",
};

/** Statuses that show a pulsing animation on the dot. */
const STATUS_PULSE: Partial<Record<SessionStatus, boolean>> = {
  running: true,
  blocked: true,
};

const STATUS_LABEL: Record<SessionStatus, string> = {
  idle: "IDLE",
  running: "RUN",
  blocked: "WAIT",
  completed: "DONE",
  failed: "FAIL",
};

const RISK_COLORS: Record<RiskLevel, string> = {
  low: "#38a876",
  medium: "#c49a3c",
  high: "#b85450",
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

  // Status-driven left border accent
  const statusBorderClass = cn(
    status === 'running' && 'border-l-2 border-l-[#c49a3c]',
    status === 'blocked' && 'border-l-2 border-l-[#d4a04a]',
    status === 'failed' && 'border-l-2 border-l-[#b85450]',
  );

  const statusOpacityClass = cn(
    status === 'completed' && 'opacity-[0.7]',
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
        // Sharp corners — this is a terminal, not a card
        "rounded-sm transition-all duration-150 overflow-hidden flex flex-col relative",
        statusBorderClass,
        statusOpacityClass,
        selected
          ? "ring-1 ring-[#c49a3c]/20"
          : "shadow-[0_1px_4px_rgba(0,0,0,0.5)]",
      )}
      style={{
        backgroundColor: selected ? "#0e1018" : "#0a0c11",
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
          className="absolute inset-0 rounded-sm pointer-events-none"
          style={{
            animation: 'heartbeat 3s ease-in-out infinite',
            background: 'radial-gradient(circle at 50% 50%, rgba(196,154,60,0.03) 0%, transparent 70%)',
          }}
        />
      )}
      <NodeResizer
        minWidth={320}
        minHeight={240}
        isVisible={selected}
        lineClassName="!border-[#c49a3c]/25"
        handleClassName="!w-1.5 !h-1.5 !bg-[#c49a3c] !border-[#0a0c11]"
      />
      {/* Top handle */}
      <Handle
        type="target"
        position={Position.Top}
        className="!w-1.5 !h-1.5 !bg-[#2a2f3a] !border-[#0a0c11] !border-2 hover:!bg-[#c49a3c] transition-colors"
      />

      {/* Title bar — dense, monospace, terminal chrome */}
      <div
        className="flex items-center justify-between px-2 shrink-0 select-none"
        style={{ height: 28, backgroundColor: "#07080c" }}
      >
        {/* Left: inline status segments separated by dim pipes */}
        <div className="flex items-center gap-0 min-w-0 flex-1">
          {/* Status dot — small, functional */}
          <span
            className="w-[6px] h-[6px] rounded-full shrink-0 mr-1.5"
            style={{
              backgroundColor: statusColor,
              boxShadow: STATUS_PULSE[status] ? `0 0 4px ${statusColor}60` : undefined,
              animation: STATUS_PULSE[status] ? "pulse 2s ease-in-out infinite" : undefined,
            }}
          />
          <span className="text-[9px] font-mono text-[#4a5568] truncate" style={{ fontVariantNumeric: 'tabular-nums' }}>
            {d.agentModel && (
              <span className="text-[#c49a3c]/80">{d.agentModel}</span>
            )}
            {d.agentModel && d.branch && <span className="text-[#252a35] mx-1">|</span>}
            {d.branch && (
              <span className="text-[#5580cc]">{d.branch}</span>
            )}
            {(d.agentModel || d.branch) && d.policyMode && <span className="text-[#252a35] mx-1">|</span>}
            {d.policyMode && (
              <span className={d.policyMode === "strict" ? "text-[#b85450]/70" : "text-[#4a5568]"}>
                {d.policyMode}
              </span>
            )}
            {(d.agentModel || d.branch || d.policyMode) && <span className="text-[#252a35] mx-1">|</span>}
            <span
              className="uppercase text-[8px] tracking-[0.12em] font-semibold"
              style={{ color: statusColor }}
            >
              {STATUS_LABEL[status]}
            </span>
            {d.exitCode != null && status !== "running" && (
              <span className="text-[#2a2f3a] ml-0.5">({d.exitCode})</span>
            )}
          </span>
        </div>

        {/* Right: window controls — tiny, flush */}
        <div className="flex items-center shrink-0 ml-2">
          <button
            onClick={handleToggleMaximize}
            className="p-0.5 text-[#2a2f3a] hover:text-[#6b7a92] transition-colors"
            title={maximized ? "Minimize" : "Maximize"}
            aria-label={maximized ? "Minimize session" : "Maximize session"}
          >
            {maximized ? <IconMinimize size={9} stroke={1.5} /> : <IconMaximize size={9} stroke={1.5} />}
          </button>
          <button
            onClick={handleClose}
            className="p-0.5 ml-0.5 text-[#2a2f3a] hover:text-[#b85450] transition-colors"
            title="Close session"
            aria-label="Close session"
          >
            <IconX size={9} stroke={1.5} />
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
          /* Fallback: static preview lines — no frills, just output */
          <div
            className="w-full h-full overflow-auto"
            style={{ backgroundColor: "#06070b" }}
          >
            <div className="py-1">
              {(d.previewLines ?? []).slice(maximized ? 0 : -8).map((line, i) => (
                <div
                  key={i}
                  className="flex hover:bg-[#ffffff02]"
                >
                  {/* Line gutter */}
                  <span
                    className="shrink-0 w-7 text-right pr-1.5 text-[8px] font-mono text-[#1a1e28] select-none leading-[1.7]"
                    style={{ fontVariantNumeric: 'tabular-nums' }}
                  >
                    {i + 1}
                  </span>
                  {/* Line content */}
                  <span
                    className={cn(
                      "flex-1 pl-1.5 font-mono text-[10px] leading-[1.7] whitespace-pre truncate",
                      line.startsWith("$")
                        ? "text-[#c49a3c]"
                        : line.includes("FAILED") || line.includes("error")
                          ? "text-[#b85450]"
                          : line.includes("ok") || line.includes("passed")
                            ? "text-[#38a876]"
                            : "text-[#5c6a80]",
                    )}
                  >
                    {line}
                  </span>
                </div>
              ))}
              {(!d.previewLines || d.previewLines.length === 0) && (
                <div className="flex items-center justify-center h-full min-h-[60px]">
                  <span className="text-[9px] font-mono text-[#1a1e28]">awaiting output</span>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Footer metrics — dense icon+number pairs, tabular numbers */}
      <div
        className="flex items-center gap-2.5 px-2 shrink-0 select-none"
        style={{ height: 24, backgroundColor: "#07080c" }}
      >
        <FooterMetric icon={IconFileCode} value={d.changedFilesCount ?? 0} color="#5580cc" />
        <FooterMetric icon={IconReceipt} value={d.receiptCount ?? 0} color="#7c5cbf" />
        <FooterMetric icon={IconShieldOff} value={d.blockedActionCount ?? 0} color={d.blockedActionCount ? "#b85450" : "#2a2f3a"} />
        {d.toolBoundaryEvents != null && (
          <FooterMetric icon={IconActivity} value={d.toolBoundaryEvents} color="#c49a3c" />
        )}

        {/* Risk indicator — right-aligned, understated */}
        <span
          className="ml-auto text-[7px] font-mono font-semibold uppercase"
          style={{ color: RISK_COLORS[risk], letterSpacing: '0.14em' }}
        >
          {risk}
        </span>
      </div>

      {/* Status bar — thin vim-like footer */}
      <div
        className="flex items-center gap-2 px-2 shrink-0 select-none"
        style={{ height: 18, backgroundColor: "#060710" }}
      >
        {d.worktreePath && (
          <span className="text-[7px] font-mono text-[#1a1e28] truncate max-w-[120px]">
            {d.worktreePath.split("/").slice(-2).join("/")}
          </span>
        )}
        {d.policyMode && (
          <span
            className="ml-auto text-[7px] font-mono font-medium uppercase"
            style={{
              color: d.policyMode === "strict" ? "#b8545060" : "#38a87640",
              letterSpacing: '0.12em',
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
        className="!w-1.5 !h-1.5 !bg-[#2a2f3a] !border-[#0a0c11] !border-2 hover:!bg-[#c49a3c] transition-colors"
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
    <div className="flex items-center gap-0.5">
      <Icon size={10} stroke={1.5} style={{ color }} />
      <span
        className="text-[9px] font-mono font-semibold"
        style={{ color, fontVariantNumeric: 'tabular-nums' }}
      >
        {value}
      </span>
    </div>
  );
}

export const AgentSessionNode = memo(AgentSessionNodeInner);
