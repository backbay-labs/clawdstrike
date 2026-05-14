/**
 * PluginViewTabStore - State management for plugin editor tabs.
 *
 * Tracks which plugin views are open as editor tabs, which is active,
 * and handles LRU eviction of hidden tabs beyond MAX_KEPT_ALIVE.
 * Uses the same module-level Map + snapshot + listeners pattern as view-registry.ts.
 * React integration via useSyncExternalStore for tear-free reads.
 */
import { useSyncExternalStore } from "react";
import { getView } from "./view-registry";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A plugin view tab open in the editor area. */
export interface PluginViewTab {
  /** Same as the ViewRegistration id: "{pluginId}.{viewId}" */
  viewId: string;
  /** Display label (initially from ViewRegistration.label, updatable via setTitle) */
  label: string;
  /** Icon identifier (from ViewRegistration.icon) */
  icon?: string;
  /** Whether this tab has unsaved changes (set via setDirty) */
  dirty: boolean;
  /** Timestamp when this tab was opened (for ordering) */
  openedAt: number;
  /** Timestamp of last activation (for LRU eviction) */
  lastActiveAt: number;
}

// ---------------------------------------------------------------------------
// Module-level state (not a class, matching status-bar-registry pattern)
// ---------------------------------------------------------------------------

/** Frozen empty array shared for reference stability when no tabs are open. */
const EMPTY_TABS: PluginViewTab[] = [];
Object.freeze(EMPTY_TABS);

/** Maximum number of hidden (non-active) plugin tabs kept alive. */
const MAX_KEPT_ALIVE = 5;

const tabMap = new Map<string, PluginViewTab>();
let activeTabId: string | null = null;
const listeners = new Set<() => void>();
let tabsSnapshot: PluginViewTab[] = EMPTY_TABS;
let activeIdSnapshot: string | null = null;

/**
 * Monotonic counter to guarantee strictly increasing timestamps even when
 * monotonicNow() returns the same millisecond value for rapid sequential calls.
 */
let lastTimestamp = 0;

function monotonicNow(): number {
  const now = Date.now();
  lastTimestamp = now > lastTimestamp ? now : lastTimestamp + 1;
  return lastTimestamp;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function rebuildSnapshots(): void {
  if (tabMap.size === 0) {
    tabsSnapshot = EMPTY_TABS;
  } else {
    tabsSnapshot = Array.from(tabMap.values()).sort(
      (a, b) => a.openedAt - b.openedAt,
    );
  }
  activeIdSnapshot = activeTabId;
}

function notify(): void {
  rebuildSnapshots();
  for (const listener of listeners) {
    listener();
  }
}

function runLruEviction(): void {
  // Count hidden tabs (all open tabs minus the active one)
  const hiddenTabs = Array.from(tabMap.values()).filter(
    (t) => t.viewId !== activeTabId,
  );

  while (hiddenTabs.length > MAX_KEPT_ALIVE) {
    // Find the tab with the smallest lastActiveAt among hidden tabs
    let oldest = hiddenTabs[0];
    let oldestIdx = 0;
    for (let i = 1; i < hiddenTabs.length; i++) {
      if (hiddenTabs[i].lastActiveAt < oldest.lastActiveAt) {
        oldest = hiddenTabs[i];
        oldestIdx = i;
      }
    }
    // Remove from the map and the local array
    tabMap.delete(oldest.viewId);
    hiddenTabs.splice(oldestIdx, 1);
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Open a plugin view as an editor tab.
 * If the view is already open, just activates it.
 * Looks up the ViewRegistration via getView() to get label and icon.
 *
 * @throws {Error} if the viewId is not registered in the ViewRegistry.
 */
export function openPluginViewTab(viewId: string): void {
  // If already open, just activate
  if (tabMap.has(viewId)) {
    activatePluginViewTab(viewId);
    return;
  }

  // Look up registration
  const reg = getView(viewId);
  if (!reg) {
    throw new Error(`View "${viewId}" not registered`);
  }

  const now = monotonicNow();
  const tab: PluginViewTab = {
    viewId,
    label: reg.label,
    icon: reg.icon,
    dirty: false,
    openedAt: now,
    lastActiveAt: now,
  };

  tabMap.set(viewId, tab);
  activeTabId = viewId;

  // Run LRU eviction after opening (new tab is active, so it won't be evicted)
  runLruEviction();

  notify();
}

/**
 * Close a plugin view tab.
 * If it was the active tab, activates the most recently active remaining tab.
 */
export function closePluginViewTab(viewId: string): void {
  tabMap.delete(viewId);

  if (activeTabId === viewId) {
    // Find the remaining tab with the highest lastActiveAt
    let best: PluginViewTab | null = null;
    for (const tab of tabMap.values()) {
      if (!best || tab.lastActiveAt > best.lastActiveAt) {
        best = tab;
      }
    }
    activeTabId = best ? best.viewId : null;
  }

  notify();
}

/**
 * Activate a plugin view tab.
 * Pass null to clear the active plugin view tab (e.g., when switching to a policy tab).
 *
 * @throws {Error} if viewId is not null and not in the open tabs.
 */
export function activatePluginViewTab(viewId: string | null): void {
  if (viewId === null) {
    activeTabId = null;
    notify();
    return;
  }

  const tab = tabMap.get(viewId);
  if (!tab) {
    throw new Error(`Plugin view tab "${viewId}" is not open`);
  }

  tab.lastActiveAt = monotonicNow();
  activeTabId = viewId;

  // Run LRU eviction after activation
  runLruEviction();

  notify();
}

/**
 * Get a stable snapshot array of all open plugin view tabs,
 * sorted by openedAt ascending.
 */
export function getOpenPluginViewTabs(): PluginViewTab[] {
  return tabsSnapshot;
}

/**
 * Get the active plugin view tab ID, or null if no plugin tab is active.
 */
export function getActivePluginViewTabId(): string | null {
  return activeIdSnapshot;
}

/**
 * Subscribe to plugin view tab changes. The listener is called whenever
 * tabs are opened, closed, activated, or metadata changes.
 * Returns an unsubscribe function.
 */
export function onPluginViewTabChange(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/**
 * Update the display label of an open plugin view tab.
 *
 * @throws {Error} if the viewId is not open.
 */
export function setPluginViewTabTitle(viewId: string, title: string): void {
  const tab = tabMap.get(viewId);
  if (!tab) {
    throw new Error(`Plugin view tab "${viewId}" is not open`);
  }
  tab.label = title;
  notify();
}

/**
 * Update the dirty flag of an open plugin view tab.
 *
 * @throws {Error} if the viewId is not open.
 */
export function setPluginViewTabDirty(viewId: string, dirty: boolean): void {
  const tab = tabMap.get(viewId);
  if (!tab) {
    throw new Error(`Plugin view tab "${viewId}" is not open`);
  }
  tab.dirty = dirty;
  notify();
}

// ---------------------------------------------------------------------------
// React hooks (useSyncExternalStore)
// ---------------------------------------------------------------------------

/**
 * React hook returning all open plugin view tabs.
 * Re-renders the consuming component on any tab change.
 */
export function usePluginViewTabs(): PluginViewTab[] {
  return useSyncExternalStore(onPluginViewTabChange, getOpenPluginViewTabs);
}

/**
 * React hook returning the active plugin view tab ID (or null).
 * Re-renders the consuming component on any tab change.
 */
export function useActivePluginViewTabId(): string | null {
  return useSyncExternalStore(
    onPluginViewTabChange,
    getActivePluginViewTabId,
  );
}
