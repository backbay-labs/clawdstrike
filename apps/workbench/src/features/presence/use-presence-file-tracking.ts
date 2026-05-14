// usePresenceFileTracking -- React hook that sends view_file/leave_file to hushd
// when the analyst switches between file tabs.
//
// Called once in App.tsx WorkbenchBootstraps (alongside usePresenceConnection).
// Subscribes to the pane store for active-view changes and to the presence store
// for reconnect handling.

import { useEffect, useRef } from "react";
import { usePaneStore, getActivePane } from "@/features/panes/pane-store";
import { getPaneActiveView } from "@/features/panes/pane-tree";
import { getPresenceSocket } from "./use-presence-connection";
import { usePresenceStore } from "./stores/presence-store";
import { toPresencePath } from "./presence-paths";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Derive the active file path from current pane state. Returns null for non-file views. */
const DRAFT_FILE_ROUTE_PREFIX = "/file/__new__/";

export function getTrackedPresenceFilePath(route: string): string | null {
  if (!route.startsWith("/file/") || route.startsWith(DRAFT_FILE_ROUTE_PREFIX)) {
    return null;
  }

  return route.slice("/file/".length);
}

/** Derive the active file path from current pane state. Returns null for non-file views. */
function deriveActiveFilePath(): string | null {
  const state = usePaneStore.getState();
  const pane = getActivePane(state.root, state.activePaneId);
  const view = pane ? getPaneActiveView(pane) : null;
  return getTrackedPresenceFilePath(view?.route ?? "");
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Sends view_file/leave_file messages to hushd when the active file tab changes.
 * On reconnect, re-sends view_file for the currently active file.
 *
 * Must be called once in the bootstrap component (WorkbenchBootstraps).
 */
export function usePresenceFileTracking(): void {
  const connectionState = usePresenceStore((s) => s.connectionState);
  const lastSentFileRef = useRef<string | null>(null);

  // --- Effect 1: Subscribe to pane store and send view_file/leave_file ---
  useEffect(() => {
    // Only track when connected
    if (connectionState !== "connected") return;

    // Check current state immediately on mount / reconnect
    const currentFile = deriveActiveFilePath();
    if (currentFile && currentFile !== lastSentFileRef.current) {
      if (lastSentFileRef.current != null) {
        getPresenceSocket()?.send({
          type: "leave_file",
          file_path: toPresencePath(lastSentFileRef.current),
        });
      }
      getPresenceSocket()?.send({
        type: "view_file",
        file_path: toPresencePath(currentFile),
      });
      lastSentFileRef.current = currentFile;
    }

    const unsubscribe = usePaneStore.subscribe((state) => {
      const pane = getActivePane(state.root, state.activePaneId);
      const view = pane ? getPaneActiveView(pane) : null;
      const filePath = getTrackedPresenceFilePath(view?.route ?? "");

      if (filePath === lastSentFileRef.current) return;

      // Leave old file
      if (lastSentFileRef.current != null) {
        getPresenceSocket()?.send({
          type: "leave_file",
          file_path: toPresencePath(lastSentFileRef.current),
        });
      }

      // Join new file
      if (filePath != null) {
        getPresenceSocket()?.send({
          type: "view_file",
          file_path: toPresencePath(filePath),
        });
      }

      lastSentFileRef.current = filePath;
    });

    return () => {
      unsubscribe();
      // Send leave_file for the current file on cleanup
      if (lastSentFileRef.current != null) {
        getPresenceSocket()?.send({
          type: "leave_file",
          file_path: toPresencePath(lastSentFileRef.current),
        });
        lastSentFileRef.current = null;
      }
    };
  }, [connectionState]);
}
