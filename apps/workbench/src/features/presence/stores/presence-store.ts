// Presence Store — Zustand + immer for real-time analyst presence state.
//
// Holds the analyst roster, per-file viewer index, cursor/selection state,
// and connection lifecycle. Defaults to empty offline state so the workbench
// is fully functional without hushd.

import { create } from "zustand";
import { immer } from "zustand/middleware/immer";
import { enableMapSet } from "immer";
import { createSelectors } from "@/lib/create-selectors";
import type {
  AnalystPresence,
  PresenceConnectionState,
  ServerMessageRaw,
} from "../types";
import { parseAnalystInfo } from "../types";

// CRITICAL: Must be called before any store creation so immer can draft
// Map and Set instances. Without this, mutations silently produce broken state.
enableMapSet();

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface PresenceActions {
  /** Process a raw server message and update store state accordingly. */
  handleServerMessage: (msg: ServerMessageRaw) => void;
  /** Update connection state (called by PresenceSocket via onStateChange). */
  setConnectionState: (state: PresenceConnectionState) => void;
  /** Reset store to empty offline defaults. */
  reset: () => void;
}

export interface PresenceStoreState {
  /** Current WebSocket connection state. */
  connectionState: PresenceConnectionState;
  /** Connection error message, if any. */
  connectionError: string | null;
  /** This operator's assigned analyst ID (set on welcome). */
  localAnalystId: string | null;
  /** This operator's assigned color (set on welcome). */
  localColor: string | null;
  /** Connected analysts keyed by fingerprint. */
  analysts: Map<string, AnalystPresence>;
  /** Reverse index: file path -> Set of fingerprints viewing that file. */
  viewersByFile: Map<string, Set<string>>;

  actions: PresenceActions;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Remove a fingerprint from all viewersByFile entries and clean up empty Sets. */
function removeFromAllFiles(
  viewersByFile: Map<string, Set<string>>,
  fingerprint: string,
): void {
  for (const [filePath, viewers] of viewersByFile) {
    viewers.delete(fingerprint);
    if (viewers.size === 0) {
      viewersByFile.delete(filePath);
    }
  }
}

/** Remove a fingerprint from a specific file's viewer Set and clean up if empty. */
function removeFromFile(
  viewersByFile: Map<string, Set<string>>,
  filePath: string,
  fingerprint: string,
): void {
  const viewers = viewersByFile.get(filePath);
  if (viewers) {
    viewers.delete(fingerprint);
    if (viewers.size === 0) {
      viewersByFile.delete(filePath);
    }
  }
}

/** Add a fingerprint to a file's viewer Set, creating the Set if needed. */
function addToFile(
  viewersByFile: Map<string, Set<string>>,
  filePath: string,
  fingerprint: string,
): void {
  let viewers = viewersByFile.get(filePath);
  if (!viewers) {
    viewers = new Set();
    viewersByFile.set(filePath, viewers);
  }
  viewers.add(fingerprint);
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

const usePresenceStoreBase = create<PresenceStoreState>()(
  immer((set) => ({
    // Default state — offline degradation: all presence UI shows empty/hidden.
    connectionState: "idle",
    connectionError: null,
    localAnalystId: null,
    localColor: null,
    analysts: new Map(),
    viewersByFile: new Map(),

    actions: {
      handleServerMessage: (msg: ServerMessageRaw) => {
        set((state) => {
          switch (msg.type) {
            case "welcome": {
              state.localAnalystId = msg.analyst_id;
              state.localColor = msg.color;
              state.analysts.clear();
              state.viewersByFile.clear();

              for (const wireAnalyst of msg.roster) {
                const analyst = parseAnalystInfo(wireAnalyst);
                state.analysts.set(analyst.fingerprint, analyst);
                if (analyst.activeFile) {
                  addToFile(state.viewersByFile, analyst.activeFile, analyst.fingerprint);
                }
              }
              break;
            }

            case "analyst_joined": {
              const analyst = parseAnalystInfo(msg.analyst);
              state.analysts.set(analyst.fingerprint, analyst);
              if (analyst.activeFile) {
                addToFile(state.viewersByFile, analyst.activeFile, analyst.fingerprint);
              }
              break;
            }

            case "analyst_left": {
              const existing = state.analysts.get(msg.fingerprint);
              if (existing?.activeFile) {
                removeFromFile(state.viewersByFile, existing.activeFile, msg.fingerprint);
              }
              state.analysts.delete(msg.fingerprint);
              break;
            }

            case "analyst_viewing": {
              const analyst = state.analysts.get(msg.fingerprint);
              if (analyst) {
                // Remove from ALL files first (analyst may have been viewing another file)
                removeFromAllFiles(state.viewersByFile, msg.fingerprint);
                if (analyst.activeFile !== msg.file_path) {
                  analyst.cursor = null;
                  analyst.selection = null;
                }
                analyst.activeFile = msg.file_path;
                addToFile(state.viewersByFile, msg.file_path, msg.fingerprint);
              }
              break;
            }

            case "analyst_left_file": {
              const analyst = state.analysts.get(msg.fingerprint);
              if (analyst) {
                analyst.activeFile = null;
                analyst.cursor = null;
                analyst.selection = null;
                removeFromFile(state.viewersByFile, msg.file_path, msg.fingerprint);
              }
              break;
            }

            case "analyst_cursor": {
              const analyst = state.analysts.get(msg.fingerprint);
              if (analyst) {
                analyst.cursor = { line: msg.line, ch: msg.ch };
                analyst.lastSeen = Date.now();
              }
              break;
            }

            case "analyst_selection": {
              const analyst = state.analysts.get(msg.fingerprint);
              if (analyst) {
                analyst.selection = {
                  anchorLine: msg.anchor_line,
                  anchorCh: msg.anchor_ch,
                  headLine: msg.head_line,
                  headCh: msg.head_ch,
                };
                analyst.lastSeen = Date.now();
              }
              break;
            }

            case "heartbeat_ack": {
              // No-op — heartbeat acknowledged by server.
              break;
            }

            case "error": {
              state.connectionError = msg.message;
              console.warn("[presence-store] Server error:", msg.message);
              break;
            }
          }
        });
      },

      setConnectionState: (connState: PresenceConnectionState) => {
        set((state) => {
          state.connectionState = connState;
        });
      },

      reset: () => {
        set((state) => {
          state.connectionState = "idle";
          state.connectionError = null;
          state.localAnalystId = null;
          state.localColor = null;
          state.analysts = new Map();
          state.viewersByFile = new Map();
        });
      },
    },
  })),
);

export const usePresenceStore = createSelectors(usePresenceStoreBase);
