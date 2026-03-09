import { useNavigate } from "react-router-dom";
import { useWorkbench, useMultiPolicy } from "@/lib/workbench/multi-policy-store";
import { useFleetConnection } from "@/lib/workbench/use-fleet-connection";
import { GUARD_REGISTRY } from "@/lib/workbench/guard-registry";
import type { GuardId } from "@/lib/workbench/types";

export function StatusBar() {
  const { state } = useWorkbench();
  const { tabs, activeTab: currentTab } = useMultiPolicy();
  const { connection } = useFleetConnection();
  const navigate = useNavigate();
  const { activePolicy, validation, filePath } = state;

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
