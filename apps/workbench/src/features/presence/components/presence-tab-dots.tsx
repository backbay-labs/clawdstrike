// PresenceTabDots — colored dots rendered inside pane tabs to indicate which
// remote analysts are viewing the same file. Max 3 dots with +N overflow.
// Clicking a dot navigates to that analyst's current file (locked decision).

import { useCallback } from "react";
import { usePresenceStore } from "../stores/presence-store";
import { usePaneStore } from "@/features/panes/pane-store";
import { useProjectStore } from "@/features/project/stores/project-store";
import { fromPresencePath, toPresencePath } from "../presence-paths";
import type { AnalystPresence } from "../types";

interface PresenceTabDotsProps {
  /** The pane view route, e.g. "/file/{absolutePath}" */
  route: string;
}

const MAX_VISIBLE_DOTS = 3;

export function PresenceTabDots({ route }: PresenceTabDotsProps) {
  // Derive file path (null for non-file tabs), normalized to match server format.
  const rawPath = route.startsWith("/file/") ? route.slice("/file/".length) : null;
  const filePath = rawPath ? toPresencePath(rawPath) : null;

  // Hooks must be called unconditionally (React rules of hooks).
  const viewerSet = usePresenceStore((s) => filePath ? s.viewersByFile.get(filePath) : undefined);
  const localAnalystId = usePresenceStore((s) => s.localAnalystId);
  const analysts = usePresenceStore((s) => s.analysts);
  const projectRoots = useProjectStore((s) => s.projectRoots);
  const handleDotClick = useCallback(
    (e: React.MouseEvent, analyst: AnalystPresence) => {
      e.stopPropagation(); // Prevent tab activation from the parent button
      if (!analyst.activeFile) return; // No-op when analyst has no active file
      const filePath = fromPresencePath(analyst.activeFile, projectRoots);
      const label = filePath.split("/").pop() ?? filePath;
      usePaneStore.getState().openFile(filePath, label);
    },
    [projectRoots],
  );

  // Presence dots only apply to file tabs.
  if (!filePath) return null;

  // Filter out the local analyst — only show REMOTE viewers.
  const remoteViewers: AnalystPresence[] = [];
  if (viewerSet) {
    for (const fingerprint of viewerSet) {
      if (fingerprint === localAnalystId) continue;
      const analyst = analysts.get(fingerprint);
      if (analyst) remoteViewers.push(analyst);
    }
  }

  if (remoteViewers.length === 0) return null;

  const overflow = Math.max(0, remoteViewers.length - MAX_VISIBLE_DOTS);
  return (
    <span className="flex items-center gap-0.5 ml-1 shrink-0">
      {remoteViewers.slice(0, MAX_VISIBLE_DOTS).map((analyst) => (
        <button
          key={analyst.fingerprint}
          type="button"
          className="inline-block w-[5px] h-[5px] rounded-full hover:ring-1 hover:ring-white/30 transition-shadow cursor-pointer"
          style={{ backgroundColor: analyst.color }}
          title={`${analyst.displayName} — click to open ${analyst.activeFile ?? "their file"}`}
          onClick={(e) => handleDotClick(e, analyst)}
        />
      ))}
      {overflow > 0 && (
        <span className="text-[8px] font-mono text-[#6f7f9a]/60 ml-0.5">
          +{overflow}
        </span>
      )}
    </span>
  );
}
