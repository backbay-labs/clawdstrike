// AnalystRosterPanel — Sidebar panel listing all remote analysts currently
// online. Each row shows the analyst's sigil color dot, display name, current
// file, and an "online" badge. Clicking a row navigates to that analyst's
// current file via usePaneStore.openFile (per locked decision).

import { useMemo, useCallback } from "react";
import { usePresenceStore } from "../stores/presence-store";
import { usePaneStore } from "@/features/panes/pane-store";
import { useProjectStore } from "@/features/project/stores/project-store";
import { fromPresencePath } from "../presence-paths";
import type { AnalystPresence } from "../types";

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function AnalystRosterPanel() {
  const analysts = usePresenceStore((s) => s.analysts);
  const localAnalystId = usePresenceStore((s) => s.localAnalystId);
  const projectRoots = useProjectStore((s) => s.projectRoots);

  // Filter out the local analyst and sort remaining alphabetically by name.
  const remoteAnalysts = useMemo(() => {
    return [...analysts.values()]
      .filter((a) => a.fingerprint !== localAnalystId)
      .sort((a, b) => a.displayName.localeCompare(b.displayName));
  }, [analysts, localAnalystId]);

  // Navigate to the analyst's current file when their row is clicked.
  const handleAnalystClick = useCallback(
    (analyst: AnalystPresence) => {
      if (!analyst.activeFile) return; // No-op when analyst has no active file
      const filePath = fromPresencePath(analyst.activeFile, projectRoots);
      const label = filePath.split("/").pop() ?? filePath;
      usePaneStore.getState().openFile(filePath, label);
    },
    [projectRoots],
  );

  return (
    <div className="h-full flex flex-col">
      {/* Header bar */}
      <div className="h-[36px] shrink-0 flex items-center border-b border-[#202531] px-3">
        <span className="font-mono text-[10px] font-semibold uppercase tracking-wider text-[#6f7f9a]">
          People
        </span>
        <span className="ml-auto font-mono text-[9px] text-[#6f7f9a]/50">
          {remoteAnalysts.length}
        </span>
      </div>

      {/* Empty state */}
      {remoteAnalysts.length === 0 && (
        <div className="flex-1 flex items-center justify-center px-4">
          <p className="text-[11px] font-mono text-[#6f7f9a]/40 text-center">
            No other analysts connected
          </p>
        </div>
      )}

      {/* Analyst list */}
      {remoteAnalysts.length > 0 && (
        <div className="flex-1 overflow-y-auto">
          {remoteAnalysts.map((analyst) => (
            <button
              key={analyst.fingerprint}
              type="button"
              className={`w-full flex items-center gap-2.5 px-3 py-2 hover:bg-[#131721]/40 transition-colors text-left ${
                analyst.activeFile ? "cursor-pointer" : "cursor-default"
              }`}
              onClick={() => handleAnalystClick(analyst)}
              title={
                analyst.activeFile
                  ? `Go to ${analyst.activeFile}`
                  : `${analyst.displayName} — no file open`
              }
            >
              {/* Sigil dot */}
              <span
                className="shrink-0 w-2 h-2 rounded-full"
                style={{ backgroundColor: analyst.color }}
              />

              {/* Name + file */}
              <div className="min-w-0 flex-1">
                <div className="text-[11px] font-mono text-[#ece7dc] truncate">
                  {analyst.displayName}
                </div>
                <div className="text-[9px] font-mono text-[#6f7f9a]/60 truncate">
                  {analyst.activeFile ?? "No file open"}
                </div>
              </div>

              {/* Status badge */}
              <span className="shrink-0 text-[8px] font-mono text-[#3dbf84]/70 uppercase tracking-wider">
                online
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
