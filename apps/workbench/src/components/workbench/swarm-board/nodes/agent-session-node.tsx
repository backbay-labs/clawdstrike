/**
 * AgentSessionNode — React Flow custom node for an active agent coding session.
 *
 * Visual language: Bloomberg terminal. Dark, dense, utilitarian.
 * Information density IS the aesthetic. No decorative elements.
 */

import React, { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Handle, Position, NodeResizer, type NodeProps } from "@xyflow/react";
import {
  IconX,
  IconMaximize,
  IconMinimize,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { useSwarmBoard } from "@/features/swarm/stores/swarm-board-store";
import { sanitizeTerminalPreviewLines } from "@/lib/workbench/terminal-preview";
import { TerminalRenderer } from "../terminal-renderer";
import type { SwarmBoardNodeData, SessionStatus, RiskLevel } from "@/features/swarm/swarm-board-types";
import { useZoomTier, type ZoomTier } from "../hooks/use-zoom-tier";

// ---------------------------------------------------------------------------
// Status dot colors — slightly tinted, never neon
// ---------------------------------------------------------------------------

const STATUS_COLOR: Record<SessionStatus, string> = {
  idle: "#6b7a92",
  running: "#38a876",
  blocked: "#c49a3c",
  completed: "#6b7a92",
  failed: "#b85450",
  evaluating: "#d4a84b",
};

const STATUS_LABEL: Record<SessionStatus, string> = {
  idle: "IDLE",
  running: "RUN",
  blocked: "WAIT",
  completed: "DONE",
  failed: "FAIL",
  evaluating: "EVAL",
};

const RISK_COLORS: Record<RiskLevel, string> = {
  low: "#38a876",
  medium: "#c49a3c",
  high: "#b85450",
};

interface TerminalTileErrorBoundaryProps {
  sessionId: string;
  active: boolean;
  fontSize: number;
  initialLines?: string[];
}

interface TerminalTileErrorBoundaryState {
  error: Error | null;
  attempt: number;
}

class TerminalTileErrorBoundary extends React.Component<
  TerminalTileErrorBoundaryProps,
  TerminalTileErrorBoundaryState
> {
  constructor(props: TerminalTileErrorBoundaryProps) {
    super(props);
    this.state = { error: null, attempt: 0 };
    this.handleRetry = this.handleRetry.bind(this);
  }

  static getDerivedStateFromError(error: Error): TerminalTileErrorBoundaryState {
    return { error, attempt: 0 };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo): void {
    console.error("[AgentSessionNode] terminal tile render error:", error, info.componentStack);
  }

  handleRetry(event: React.MouseEvent<HTMLButtonElement>): void {
    event.stopPropagation();
    this.setState((current) => ({
      error: null,
      attempt: current.attempt + 1,
    }));
  }

  render() {
    if (this.state.error) {
      return (
        <div
          className="flex h-full w-full flex-col items-center justify-center gap-2 px-4 text-center"
          style={{ backgroundColor: "#06070b" }}
        >
          <p className="text-[10px] font-mono uppercase tracking-[0.12em] text-[#b85450]">
            terminal tile isolated
          </p>
          <p className="text-[10px] font-mono text-[#7f8aa0]">
            {this.state.error.message}
          </p>
          <button
            type="button"
            className="rounded-sm border border-[#2a3040] px-2 py-1 text-[9px] font-mono uppercase tracking-[0.12em] text-[#d4a84b] hover:border-[#d4a84b]/40 hover:text-[#e8c06a]"
            onClick={this.handleRetry}
          >
            Reload terminal surface
          </button>
        </div>
      );
    }

    return (
      <TerminalRenderer
        key={`${this.props.sessionId}:${this.state.attempt}`}
        sessionId={this.props.sessionId}
        active={this.props.active}
        fontSize={this.props.fontSize}
        initialLines={this.props.initialLines}
      />
    );
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

function AgentSessionNodeInner({ id, data, selected }: NodeProps) {
  const d = data as SwarmBoardNodeData;
  const tier = useZoomTier();
  const { updateNode, removeNode, killSession } = useSwarmBoard();
  const status = d.status ?? "idle";
  const statusColor = STATUS_COLOR[status];
  const risk = d.risk ?? "low";
  const maximized = d.maximized ?? false;
  const hasSession = !!d.sessionId;
  const liveTerminalVisible = hasSession && !!d.terminalAttached && (!!selected || maximized);
  const sessionModeLabel = d.manualSession
    ? "MANUAL"
    : d.sessionPersistence === "tmux"
      ? "TMUX"
      : null;
  const recoveryLabel = d.sessionRecoveryState === "recoverable"
    ? "RECOVER"
    : d.sessionRecoveryState === "recovered"
      ? "LIVE"
      : null;
  const [statusFlash, setStatusFlash] = useState(false);
  const previousStatusRef = useRef<SessionStatus | null>(null);
  const previewLines = useMemo(
    () => sanitizeTerminalPreviewLines(d.previewLines),
    [d.previewLines],
  );

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
    status === 'evaluating' && 'border-l-2 border-l-[#d4a84b]',
  );

  const previewLineLimit = selected || maximized ? 10 : 6;

  useEffect(() => {
    if (previousStatusRef.current == null) {
      previousStatusRef.current = status;
      return;
    }
    if (previousStatusRef.current === status) {
      return;
    }
    previousStatusRef.current = status;
    setStatusFlash(true);
    const timeout = window.setTimeout(() => {
      setStatusFlash(false);
    }, 500);
    return () => window.clearTimeout(timeout);
  }, [status]);

  // ---------------------------------------------------------------------------
  // Dot tier — minimal colored rectangle, status border only
  // ---------------------------------------------------------------------------
  if (tier === "dot") {
    return (
      <div
        className="rounded-sm"
        style={{
          backgroundColor: "#0a0c11",
          width: "100%",
          height: "100%",
          minWidth: 40,
          minHeight: 20,
          borderLeft: `2px solid ${statusColor}`,
          boxShadow: statusFlash
            ? `0 0 0 1px ${statusColor}40, 0 0 18px ${statusColor}18`
            : undefined,
        }}
      >
        <Handle
          type="target"
          position={Position.Top}
          className="!w-1 !h-1 !bg-transparent"
        />
        <Handle
          type="source"
          position={Position.Bottom}
          className="!w-1 !h-1 !bg-transparent"
        />
      </div>
    );
  }

  // ---------------------------------------------------------------------------
  // Chip tier — status dot + title + status label, single compact row
  // ---------------------------------------------------------------------------
  if (tier === "chip") {
    return (
      <div
        className="rounded-sm flex items-center gap-1.5 px-2"
        style={{
          backgroundColor: "#0a0c11",
          borderLeft: `2px solid ${statusColor}`,
          minWidth: 120,
          minHeight: 28,
          boxShadow: statusFlash
            ? `0 0 0 1px ${statusColor}40, 0 0 12px ${statusColor}18`
            : undefined,
        }}
      >
        <Handle
          type="target"
          position={Position.Top}
          className="!w-1 !h-1 !bg-transparent"
        />
        {/* Status dot */}
        <span
          className="w-[5px] h-[5px] rounded-full shrink-0"
          style={{ backgroundColor: statusColor }}
        />
        {/* Title */}
        <span className="text-[8px] font-mono text-[#5c6a80] truncate flex-1">
          {d.title ?? d.agentModel ?? "session"}
        </span>
        {/* Status label */}
        <span
          className="text-[7px] font-mono font-bold uppercase shrink-0"
          style={{ color: statusColor, letterSpacing: "0.1em" }}
        >
          {STATUS_LABEL[status]}
        </span>
        <Handle
          type="source"
          position={Position.Bottom}
          className="!w-1 !h-1 !bg-transparent"
        />
      </div>
    );
  }

  // ---------------------------------------------------------------------------
  // Compact tier — title bar + condensed metrics (numbers only), no terminal
  // ---------------------------------------------------------------------------
  // Full tier — render everything as-is (no changes)
  // ---------------------------------------------------------------------------

  return (
    <div
      className={cn(
        // Sharp corners — this is a terminal, not a card
        "rounded-sm transition-all duration-150 overflow-hidden flex flex-col relative",
        statusBorderClass,
        status === "completed" && "opacity-[0.78]",
        selected
          ? "ring-1 ring-[#c49a3c]/20"
          : "shadow-[0_1px_4px_rgba(0,0,0,0.5)]",
      )}
      style={{
        backgroundColor: selected ? "#0e1018" : "#0a0c11",
        width: "100%",
        height: "100%",
        minWidth: tier === "compact" ? 240 : 320,
        minHeight: tier === "compact" ? 60 : 216,
        boxShadow: statusFlash
          ? `0 0 0 1px ${statusColor}40, 0 0 18px ${statusColor}18`
          : undefined,
      }}
    >
      {tier === "full" && (
        <NodeResizer
          minWidth={320}
          minHeight={216}
          isVisible={selected}
          lineClassName="!border-[#c49a3c]/25"
          handleClassName="!w-1.5 !h-1.5 !bg-[#c49a3c] !border-[#0a0c11]"
        />
      )}
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
              boxShadow: `0 0 4px ${statusColor}30`,
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
            {(d.agentModel || d.branch) && <span className="text-[#252a35] mx-1">|</span>}
            <span
              className="uppercase text-[8px] tracking-[0.12em] font-semibold"
              style={{ color: statusColor }}
            >
              {STATUS_LABEL[status]}
            </span>
            {sessionModeLabel && (
              <>
                <span className="text-[#252a35] mx-1">|</span>
                <span className="text-[#8a93a6]">{sessionModeLabel}</span>
              </>
            )}
            {recoveryLabel && (
              <>
                <span className="text-[#252a35] mx-1">|</span>
                <span className="text-[#c49a3c]/80">{recoveryLabel}</span>
              </>
            )}
            {d.exitCode != null && status !== "running" && (
              <span className="text-[#2a2f3a] ml-0.5">({d.exitCode})</span>
            )}
          </span>
        </div>

        {/* Right: window controls — tiny, flush (full tier only) */}
        {tier === "full" && (
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
        )}
      </div>

      {/* Terminal body — full tier only */}
      {tier === "full" && (
        <div className="flex-1 min-h-0 relative">
          {liveTerminalVisible ? (
            <TerminalTileErrorBoundary
              sessionId={d.sessionId!}
              active={!!selected || maximized}
              fontSize={selected || maximized ? 11 : 8}
              initialLines={previewLines}
            />
          ) : (
            /* Fallback: static preview lines — no frills, just output */
            <div
              className="w-full h-full overflow-auto"
              style={{ backgroundColor: "#06070b" }}
            >
              <div className="py-1">
                {previewLines.slice(-previewLineLimit).map((line, i) => (
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
                {previewLines.length === 0 && (
                  <div className="flex items-center justify-center h-full min-h-[60px]">
                    <span className="text-[9px] font-mono text-[#1a1e28]">
                      {hasSession && !d.terminalAttached
                        ? "select to attach recovered session"
                        : hasSession
                          ? "launching session..."
                          : "awaiting output"}
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Footer metrics — condensed in compact (numbers only, reduced height), full in full tier */}
      <div
        className="flex items-center gap-2 px-2 shrink-0 select-none"
        style={{ height: tier === "compact" ? 14 : 18, backgroundColor: "#07080c" }}
      >
        <FooterMetric label="files changed" value={d.changedFilesCount ?? 0} color="#6f97d8" />
        <FooterMetric label="receipts" value={d.receiptCount ?? 0} color="#9777cf" />
        <FooterMetric
          label="blocked actions"
          value={d.blockedActionCount ?? 0}
          color={d.blockedActionCount ? "#d06860" : "#4a5568"}
        />
        {d.toolBoundaryEvents != null && (
          <FooterMetric label="tool boundary events" value={d.toolBoundaryEvents} color="#d4a84b" />
        )}

        {/* Risk indicator — right-aligned, understated */}
        <span
          className="ml-auto text-[7px] font-mono font-semibold uppercase"
          style={{ color: RISK_COLORS[risk], letterSpacing: '0.14em' }}
          title={`risk ${risk}`}
        >
          {risk}
        </span>
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
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color: string;
}) {
  return (
    <div
      className="flex items-center"
      aria-label={`${value} ${label}`}
      title={`${value} ${label}`}
    >
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
