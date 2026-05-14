/**
 * StatusBarRegistry - Registry for status bar items.
 *
 * Allows plugins to register custom status bar segments without modifying
 * the StatusBar component. Items are sorted by priority within each side.
 */
import type { ReactNode } from "react";

export interface StatusBarItem {
  /** Unique identifier for this status bar item. */
  id: string;
  /** Which side of the status bar. */
  side: "left" | "right";
  /** Sort order within the side. Lower numbers render first. Built-in items use 10, 20, 30, etc. */
  priority: number;
  /** React render function for this status bar segment. */
  render: () => ReactNode;
}

const itemMap = new Map<string, StatusBarItem>();
const listeners = new Set<() => void>();

// Snapshot cache for useSyncExternalStore
let snapshotLeft: StatusBarItem[] = [];
let snapshotRight: StatusBarItem[] = [];
let registryRevision = 0;
let snapshotRevision = -1;

function rebuildSnapshots(): void {
  snapshotLeft = Array.from(itemMap.values())
    .filter((item) => item.side === "left")
    .sort((a, b) => a.priority - b.priority);
  snapshotRight = Array.from(itemMap.values())
    .filter((item) => item.side === "right")
    .sort((a, b) => a.priority - b.priority);
  snapshotRevision = registryRevision;
}

function notifyListeners(): void {
  rebuildSnapshots();
  for (const listener of listeners) {
    listener();
  }
}

/** Register a status bar item. Returns a dispose function. */
export function registerStatusBarItem(item: StatusBarItem): () => void {
  if (itemMap.has(item.id)) {
    throw new Error(`Status bar item "${item.id}" is already registered`);
  }
  itemMap.set(item.id, item);
  registryRevision += 1;
  notifyListeners();
  return () => {
    itemMap.delete(item.id);
    registryRevision += 1;
    notifyListeners();
  };
}

/** Unregister a status bar item by ID. No-op if not found. */
export function unregisterStatusBarItem(id: string): void {
  if (itemMap.delete(id)) {
    registryRevision += 1;
    notifyListeners();
  }
}

/** Get all items for a side, sorted by priority. Rebuilds if stale. */
export function getStatusBarItems(side: "left" | "right"): StatusBarItem[] {
  // Ensure snapshots are current even if called before any listener fires
  // (e.g., module-scope registrations before React mounts).
  if (snapshotRevision !== registryRevision) {
    rebuildSnapshots();
  }
  return side === "left" ? snapshotLeft : snapshotRight;
}

/** Subscribe to registry changes. Returns unsubscribe function. */
export function onStatusBarChange(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Convenience object for import ergonomics. */
export const statusBarRegistry = {
  register: registerStatusBarItem,
  unregister: unregisterStatusBarItem,
  getItems: getStatusBarItems,
  onChange: onStatusBarChange,
};
