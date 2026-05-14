import { getAllPaneGroups } from "./pane-tree";
import type { PaneGroup, PaneNode, PaneSplit } from "./pane-types";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SavedSession {
  root: PaneNode;
  activePaneId: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const STORAGE_KEY = "clawdstrike_pane_layout";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Recursively strip the `dirty` flag from every view in a pane tree.
 * Dirty state is ephemeral -- the autosave/crash-recovery system handles
 * unsaved content independently from layout persistence.
 */
function stripDirtyFlags(node: PaneNode): PaneNode {
  if (node.type === "group") {
    return {
      ...node,
      views: node.views.map((v) => {
        if (v.dirty) {
          const { dirty: _, ...rest } = v;
          return rest;
        }
        return v;
      }),
    };
  }
  return {
    ...node,
    children: [
      stripDirtyFlags(node.children[0]),
      stripDirtyFlags(node.children[1]),
    ],
  } as PaneSplit;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Serialize the pane tree and active pane ID to localStorage.
 *
 * Strips `dirty` flags before saving -- dirty state is ephemeral and managed
 * by the autosave system separately.
 */
export function savePaneSession(root: PaneNode, activePaneId: string): void {
  try {
    const cleaned = stripDirtyFlags(root);
    const session: SavedSession = { root: cleaned, activePaneId };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
  } catch {
    // localStorage may be unavailable (e.g. storage quota exceeded).
  }
}

/**
 * Restore a previously saved pane session from localStorage.
 *
 * Returns `null` if no session is stored, the data is corrupt, or the
 * structure is invalid. Strips any lingering `dirty` flags as a safety net.
 */
export function loadPaneSession(): SavedSession | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;

    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;
    if (!parsed.root || !parsed.activePaneId) return null;

    // Basic structural validation: root must have a valid type field.
    const rootType = parsed.root.type;
    if (rootType !== "group" && rootType !== "split") return null;

    // Strip dirty flags as a safety net.
    const cleaned = stripDirtyFlags(parsed.root as PaneNode);

    return {
      root: cleaned,
      activePaneId: parsed.activePaneId as string,
    };
  } catch {
    return null;
  }
}

/**
 * Count the number of file views (routes starting with `/file/`) in a pane tree.
 * Used by the session restore toast to display "Restored N files".
 */
export function countFileViews(root: PaneNode): number {
  const groups = getAllPaneGroups(root);
  let count = 0;
  for (const group of groups) {
    for (const view of group.views) {
      if (view.route.startsWith("/file/")) {
        count++;
      }
    }
  }
  return count;
}

/**
 * Remove the saved pane session from localStorage.
 * Useful for resetting state or testing.
 */
export function clearPaneSession(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // localStorage may be unavailable.
  }
}
