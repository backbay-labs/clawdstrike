/**
 * Active Plugin View state - Lightweight external store for tracking which
 * plugin activity bar panel is currently active. Uses useSyncExternalStore
 * for tear-free reads, matching the ViewRegistry pattern.
 *
 * When a plugin activity bar item is clicked, activePluginViewId is set to
 * that view's ID. When a built-in Link is clicked, it's cleared to null,
 * restoring the normal <Outlet /> rendering.
 */
import { useSyncExternalStore } from "react";

// ---------------------------------------------------------------------------
// Module-level state
// ---------------------------------------------------------------------------

let activePluginViewId: string | null = null;
const listeners = new Set<() => void>();

function notify(): void {
  for (const listener of listeners) {
    listener();
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/** Set the active plugin view ID (or null to clear). */
export function setActivePluginView(id: string | null): void {
  if (activePluginViewId === id) return;
  activePluginViewId = id;
  notify();
}

/** Get the current active plugin view ID. */
export function getActivePluginView(): string | null {
  return activePluginViewId;
}

/** Subscribe to changes. Returns an unsubscribe function. */
export function onActivePluginViewChange(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/**
 * React hook that returns the active plugin view ID, re-rendering when it
 * changes. Uses useSyncExternalStore for tear-free reads.
 */
export function useActivePluginView(): string | null {
  return useSyncExternalStore(
    onActivePluginViewChange,
    getActivePluginView,
  );
}
