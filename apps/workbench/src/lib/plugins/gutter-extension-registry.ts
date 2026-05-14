/**
 * GutterExtensionRegistry - Central registry for plugin-contributed CodeMirror gutter extensions.
 *
 * Plugins register CodeMirror Extension objects (e.g., severity markers, coverage indicators,
 * breakpoints) that appear in the editor gutter. Extensions are added/removed dynamically
 * without recreating the editor via CodeMirror's Compartment mechanism.
 *
 * Uses the Map + snapshot + listeners pattern matching view-registry.ts.
 * React integration via useSyncExternalStore for tear-free reads.
 */
import { useSyncExternalStore } from "react";
import type { Extension } from "@codemirror/state";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A gutter extension entry in the registry. */
export interface GutterExtensionEntry {
  /** Qualified ID: "{pluginId}.{decorationId}" */
  id: string;
  /** The CodeMirror Extension object (result of calling the factory). */
  extension: Extension;
}

// ---------------------------------------------------------------------------
// Module-level state (not a class, matching view-registry pattern)
// ---------------------------------------------------------------------------

const gutterMap = new Map<string, GutterExtensionEntry>();
const listeners = new Set<() => void>();

/** Snapshot of all registered extensions as a flat array. Rebuilt on every mutation. */
const EMPTY_SNAPSHOT: Extension[] = [];
Object.freeze(EMPTY_SNAPSHOT);
let snapshot: Extension[] = EMPTY_SNAPSHOT;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function rebuildSnapshot(): void {
  if (gutterMap.size === 0) {
    snapshot = EMPTY_SNAPSHOT;
    return;
  }
  const extensions: Extension[] = [];
  for (const entry of gutterMap.values()) {
    extensions.push(entry.extension);
  }
  snapshot = extensions;
}

function notify(): void {
  rebuildSnapshot();
  for (const listener of listeners) {
    listener();
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Register a gutter extension in the registry. Returns a dispose function that
 * removes the extension and notifies listeners.
 *
 * @throws {Error} if an extension with the same id is already registered.
 */
export function registerGutterExtension(entry: GutterExtensionEntry): () => void {
  if (gutterMap.has(entry.id)) {
    throw new Error(`Gutter extension "${entry.id}" already registered`);
  }
  gutterMap.set(entry.id, entry);
  notify();

  return () => {
    gutterMap.delete(entry.id);
    notify();
  };
}

/**
 * Get all registered gutter extensions as a flat array.
 * Returns a stable snapshot reference when no changes have occurred.
 * Returns a frozen empty array when no extensions are registered.
 */
export function getGutterExtensions(): Extension[] {
  return snapshot;
}

/**
 * Subscribe to gutter extension registry changes. The listener is called
 * whenever a gutter extension is registered or unregistered.
 * Returns an unsubscribe function.
 */
export function onGutterExtensionChange(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/**
 * React hook that returns all registered gutter extensions, re-rendering the
 * consuming component whenever extensions are registered or unregistered.
 *
 * Uses useSyncExternalStore for tear-free reads.
 */
export function useGutterExtensions(): Extension[] {
  return useSyncExternalStore(onGutterExtensionChange, getGutterExtensions);
}
