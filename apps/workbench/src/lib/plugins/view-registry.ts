/**
 * ViewRegistry - Central registry for plugin-contributed views.
 *
 * Allows plugins to register views into any of 7 visual slots in the workbench.
 * Uses the Map + snapshot + listeners pattern matching status-bar-registry.ts.
 * React integration via useSyncExternalStore for tear-free reads.
 */
import { useSyncExternalStore } from "react";
import type { ComponentType } from "react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** All visual slots a plugin view can target. */
export type ViewSlot =
  | "editorTab"
  | "activityBarPanel"
  | "bottomPanelTab"
  | "rightSidebarPanel"
  | "statusBarWidget"
  | "gutterDecoration"
  | "contextMenuItem";

/** Props passed to every plugin view component by ViewContainer. */
export interface ViewProps {
  /** Qualified view ID ("{pluginId}.{viewId}"). */
  viewId: string;
  /** Whether this view is currently visible/active. */
  isActive: boolean;
  /** Per-view key/value storage. */
  storage: {
    get(key: string): unknown;
    set(key: string, value: unknown): void;
  };
}

/** A registration entry in the ViewRegistry. */
export interface ViewRegistration {
  /** Qualified view ID ("{pluginId}.{viewId}"). */
  id: string;
  /** Which UI slot this view targets. */
  slot: ViewSlot;
  /** Display label for tabs, headers, etc. */
  label: string;
  /** Optional icon identifier (Lucide name or custom). */
  icon?: string;
  /** The React component to render for this view. */
  component: ComponentType<any>;
  /** Sort order within the slot. Lower numbers render first. Default 100. */
  priority?: number;
  /** Arbitrary metadata for downstream consumers. */
  meta?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Module-level state (not a class, matching status-bar-registry pattern)
// ---------------------------------------------------------------------------

const viewMap = new Map<string, ViewRegistration>();
const listeners = new Set<() => void>();

/** Snapshot cache keyed by slot. Rebuilt on every mutation. */
let snapshotBySlot = new Map<ViewSlot, ViewRegistration[]>();

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function rebuildSnapshots(): void {
  const grouped = new Map<ViewSlot, ViewRegistration[]>();

  for (const reg of viewMap.values()) {
    let list = grouped.get(reg.slot);
    if (!list) {
      list = [];
      grouped.set(reg.slot, list);
    }
    list.push(reg);
  }

  // Sort each group by priority ascending (default 100)
  for (const list of grouped.values()) {
    list.sort((a, b) => (a.priority ?? 100) - (b.priority ?? 100));
  }

  snapshotBySlot = grouped;
}

function notify(): void {
  rebuildSnapshots();
  for (const listener of listeners) {
    listener();
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Register a view in the registry. Returns a dispose function that
 * removes the view and notifies listeners.
 *
 * @throws {Error} if a view with the same id is already registered.
 */
export function registerView(reg: ViewRegistration): () => void {
  if (viewMap.has(reg.id)) {
    throw new Error(`View "${reg.id}" already registered`);
  }
  viewMap.set(reg.id, reg);
  notify();

  return () => {
    viewMap.delete(reg.id);
    notify();
  };
}

/** Look up a single view registration by id. */
export function getView(id: string): ViewRegistration | undefined {
  return viewMap.get(id);
}

/**
 * Get all views registered for a given slot, sorted by priority ascending.
 * Returns a stable snapshot reference when no changes have occurred.
 */
export function getViewsBySlot(slot: ViewSlot): ViewRegistration[] {
  return snapshotBySlot.get(slot) ?? EMPTY;
}

/** Frozen empty array shared across all empty-slot queries for reference stability. */
const EMPTY: ViewRegistration[] = [];
Object.freeze(EMPTY);

/**
 * Subscribe to registry changes. The listener is called whenever a view
 * is registered or unregistered. Returns an unsubscribe function.
 */
export function onViewRegistryChange(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/**
 * React hook that returns all views for a slot, re-rendering the consuming
 * component whenever views are registered or unregistered.
 *
 * Uses useSyncExternalStore for tear-free reads.
 */
export function useViewsBySlot(slot: ViewSlot): ViewRegistration[] {
  return useSyncExternalStore(
    onViewRegistryChange,
    () => getViewsBySlot(slot),
  );
}

// ---------------------------------------------------------------------------
// Convenience object
// ---------------------------------------------------------------------------

/** Convenience object for import ergonomics. */
export const viewRegistry = {
  register: registerView,
  get: getView,
  getBySlot: getViewsBySlot,
  onChange: onViewRegistryChange,
};
