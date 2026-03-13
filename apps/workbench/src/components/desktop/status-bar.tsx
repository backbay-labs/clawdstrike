import { useState, useRef, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useWorkbench, useMultiPolicy } from "@/lib/workbench/multi-policy-store";
import { useFleetConnection } from "@/lib/workbench/use-fleet-connection";
import { useMcpStatus } from "@/lib/workbench/use-mcp-status";
import { isDesktop } from "@/lib/tauri-bridge";
import { GUARD_REGISTRY } from "@/lib/workbench/guard-registry";
import type { GuardId } from "@/lib/workbench/types";
import { cn } from "@/lib/utils";
import {
  IconPlugConnected,
  IconRefresh,
  IconPlayerStop,
  IconLoader2,
} from "@tabler/icons-react";

export function StatusBar() {
  const { state } = useWorkbench();
  const { tabs, activeTab: currentTab } = useMultiPolicy();
  const { connection } = useFleetConnection();
  const navigate = useNavigate();
  const { activePolicy, validation, filePath } = state;
  const desktop = isDesktop();

  // ---- Validation status ----
  const errorCount = validation.errors.length;
  const warningCount = validation.warnings.length;

  let statusIcon: string;
  let statusText: string;
  let statusColor: string;

  if (errorCount > 0) {
    statusIcon = "\u2718"; // heavy ballot X
    statusText = `${errorCount} error${errorCount !== 1 ? "s" : ""}`;
    statusColor = "#c45c5c";
  } else if (warningCount > 0) {
    statusIcon = "\u26a0"; // warning sign
    statusText = `${warningCount} warning${warningCount !== 1 ? "s" : ""}`;
    statusColor = "#d4a84b";
  } else {
    statusIcon = "\u2714"; // checkmark
    statusText = "Valid";
    statusColor = "#3dbf84";
  }

  // ---- Guard count ----
  const enabledGuards = GUARD_REGISTRY.filter((g) => {
    const cfg = activePolicy.guards[g.id as GuardId];
    return cfg && "enabled" in cfg && cfg.enabled;
  }).length;
  const totalGuards = GUARD_REGISTRY.length;

  return (
    <footer className="desktop-statusbar shrink-0 select-none">
      {/* ---- Left ---- */}
      <div className="flex items-center gap-4">
        {/* Validation */}
        <span className="flex items-center gap-1.5" style={{ color: statusColor }}>
          <span className="text-[9px] leading-none">{statusIcon}</span>
          <span>{statusText}</span>
        </span>

        {/* Separator */}
        <span className="w-px h-3 bg-[#2d3240]/60" />

        {/* Guard count */}
        <span className="text-[#6f7f9a]/80">
          {enabledGuards}/{totalGuards} guards
        </span>

        {/* Separator */}
        <span className="w-px h-3 bg-[#2d3240]/60" />

        {/* Schema version */}
        <span className="text-[#6f7f9a]/80">
          v{activePolicy.version}
        </span>

        {/* Separator */}
        <span className="w-px h-3 bg-[#2d3240]/60" />

        {/* Fleet connection status */}
        <button
          onClick={() => navigate("/settings")}
          className="flex items-center gap-1.5 hover:text-[#ece7dc] transition-colors"
          title={
            connection.connected
              ? `Connected to ${connection.hushdUrl}`
              : "Click to configure fleet connection"
          }
        >
          <span
            className="inline-block w-[6px] h-[6px] rounded-full"
            style={{
              backgroundColor: connection.connected ? "#3dbf84" : "#6f7f9a40",
            }}
          />
          <span className={connection.connected ? "text-[#6f7f9a]" : "text-[#6f7f9a]/50"}>
            {connection.connected
              ? `Fleet: ${connection.agentCount} agent${connection.agentCount !== 1 ? "s" : ""}`
              : "Local"}
          </span>
        </button>

        {/* MCP sidecar status (desktop only) */}
        {desktop && (
          <>
            <span className="w-px h-3 bg-[#2d3240]/60" />
            <McpStatusIndicator />
          </>
        )}
      </div>

      {/* ---- Right ---- */}
      <div className="flex items-center gap-3 min-w-0">
        {/* Tab count */}
        {tabs.length > 1 && (
          <>
            <span className="text-[#6f7f9a]/60">
              {tabs.length} tabs
            </span>
            <span className="w-px h-3 bg-[#2d3240]/60" />
          </>
        )}

        {/* Active policy name + dirty indicator */}
        <span className="text-[#ece7dc]/70 truncate max-w-[200px]">
          {currentTab?.name || activePolicy.name}
          {state.dirty && <span className="text-[#d4a84b] ml-1">*</span>}
        </span>

        <span className="w-px h-3 bg-[#2d3240]/60" />

        {filePath ? (
          <span className="text-[#6f7f9a]/70 truncate max-w-[400px]" title={filePath}>
            {filePath}
          </span>
        ) : (
          <span className="text-[#6f7f9a]/30 italic">unsaved</span>
        )}
      </div>
    </footer>
  );
}

// ---------------------------------------------------------------------------
// MCP Status Indicator — shown in the bottom bar with a click-to-manage popover
// ---------------------------------------------------------------------------

function McpStatusIndicator() {
  const {
    status,
    isRestarting,
    isStopping,
    handleRestart,
    handleStop,
  } = useMcpStatus();
  const [open, setOpen] = useState(false);
  const popoverRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);

  // Close on outside click
  useEffect(() => {
    if (!open) return;
    function onMouseDown(e: MouseEvent) {
      if (
        popoverRef.current &&
        !popoverRef.current.contains(e.target as Node) &&
        buttonRef.current &&
        !buttonRef.current.contains(e.target as Node)
      ) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", onMouseDown);
    return () => document.removeEventListener("mousedown", onMouseDown);
  }, [open]);

  const running = status?.running ?? false;

  return (
    <div className="relative">
      <button
        ref={buttonRef}
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-1.5 hover:text-[#ece7dc] transition-colors"
        title={running ? "MCP sidecar running — click to manage" : "MCP sidecar stopped — click to manage"}
      >
        <IconPlugConnected size={11} stroke={1.5} className={running ? "text-[#3dbf84]" : "text-[#6f7f9a]/40"} />
        <span className={running ? "text-[#6f7f9a]" : "text-[#6f7f9a]/50"}>
          {running ? "MCP" : "MCP off"}
        </span>
        <span
          className="inline-block w-[6px] h-[6px] rounded-full"
          style={{ backgroundColor: running ? "#3dbf84" : "#c45c5c" }}
        />
      </button>

      {open && (
        <div
          ref={popoverRef}
          className="absolute bottom-full left-0 mb-2 w-56 rounded-lg border border-[#2d3240] bg-[#0b0d13] shadow-xl z-50"
        >
          <div className="px-3 py-2.5 border-b border-[#2d3240]/60">
            <div className="flex items-center gap-2">
              <IconPlugConnected size={12} stroke={1.5} className="text-[#d4a84b]" />
              <span className="text-[11px] font-mono font-medium text-[#ece7dc]">MCP Sidecar</span>
              <span
                className={cn(
                  "ml-auto text-[9px] font-mono",
                  running ? "text-[#3dbf84]" : "text-[#c45c5c]",
                )}
              >
                {running ? "running" : "stopped"}
              </span>
            </div>
            {running && status?.url && (
              <div className="mt-1.5 text-[9px] font-mono text-[#6f7f9a]/60 truncate">
                {status.url}
              </div>
            )}
            {!running && status?.error && (
              <div className="mt-1.5 text-[9px] font-mono text-[#c45c5c]/80 truncate">
                {status.error}
              </div>
            )}
          </div>

          <div className="px-3 py-2 flex items-center gap-1.5">
            <button
              onClick={() => {
                handleRestart();
                setOpen(false);
              }}
              disabled={isRestarting || isStopping}
              className={cn(
                "flex-1 flex items-center justify-center gap-1 h-6 rounded text-[10px] font-medium border transition-colors",
                isRestarting
                  ? "text-[#6f7f9a] border-[#2d3240] bg-[#131721] cursor-wait"
                  : "text-[#ece7dc] border-[#2d3240] bg-[#131721] hover:border-[#d4a84b]/40 hover:text-[#d4a84b]",
              )}
            >
              {isRestarting ? (
                <IconLoader2 size={10} stroke={1.5} className="animate-spin" />
              ) : (
                <IconRefresh size={10} stroke={1.5} />
              )}
              {running ? "Restart" : "Start"}
            </button>
            {running && (
              <button
                onClick={() => {
                  handleStop();
                  setOpen(false);
                }}
                disabled={isRestarting || isStopping}
                className={cn(
                  "flex-1 flex items-center justify-center gap-1 h-6 rounded text-[10px] font-medium border transition-colors",
                  isStopping
                    ? "text-[#6f7f9a] border-[#2d3240] bg-[#131721] cursor-wait"
                    : "text-[#ece7dc] border-[#c45c5c]/30 bg-[#131721] hover:border-[#c45c5c]/60 hover:text-[#c45c5c]",
                )}
              >
                {isStopping ? (
                  <IconLoader2 size={10} stroke={1.5} className="animate-spin" />
                ) : (
                  <IconPlayerStop size={10} stroke={1.5} />
                )}
                Stop
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
