/**
 * ContextMenuRegistry - Central registry for plugin-contributed context menu items.
 *
 * Plugins can register items that appear in right-click context menus throughout
 * the workbench (editor, sidebar, tab, finding, sentinel). Items support visibility
 * predicates (when-clauses) evaluated against workbench context and execute commands
 * from the command registry when clicked.
 *
 * Uses the Map + snapshot + listeners pattern matching view-registry.ts.
 * React integration via useSyncExternalStore for tear-free reads.
 */
import { useSyncExternalStore } from "react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** All context menu targets a plugin item can appear in. */
export type ContextMenuTarget = "editor" | "sidebar" | "tab" | "finding" | "sentinel";

/** A registered context menu item. */
export interface ContextMenuItemRegistration {
  /** Qualified ID: "{pluginId}.{itemId}". */
  id: string;
  /** Display label for the menu item. */
  label: string;
  /** Command ID to execute when clicked (looked up in command registry). */
  command: string;
  /** Optional icon identifier. */
  icon?: string;
  /** Visibility predicate expression -- evaluated against workbench context. */
  when?: string;
  /** Which context menu this item appears in. */
  menu: ContextMenuTarget;
  /** Sort priority within the menu (lower = higher, default 100). */
  priority?: number;
}

/** Context object for evaluating when-clause predicates. */
export interface WhenContext {
  [key: string]: string | boolean | number | undefined;
}

// ---------------------------------------------------------------------------
// Module-level state (not a class, matching view-registry pattern)
// ---------------------------------------------------------------------------

const menuMap = new Map<string, ContextMenuItemRegistration>();
const listeners = new Set<() => void>();

/** Snapshot cache keyed by menu target. Rebuilt on every mutation. */
let snapshotByMenu = new Map<ContextMenuTarget, ContextMenuItemRegistration[]>();

/** Frozen empty array shared across empty-menu queries for reference stability. */
const EMPTY: ContextMenuItemRegistration[] = [];
Object.freeze(EMPTY);

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function rebuildSnapshots(): void {
  const grouped = new Map<ContextMenuTarget, ContextMenuItemRegistration[]>();

  for (const item of menuMap.values()) {
    let list = grouped.get(item.menu);
    if (!list) {
      list = [];
      grouped.set(item.menu, list);
    }
    list.push(item);
  }

  // Sort each group by priority ascending (default 100)
  for (const list of grouped.values()) {
    list.sort((a, b) => (a.priority ?? 100) - (b.priority ?? 100));
  }

  snapshotByMenu = grouped;
}

function notify(): void {
  rebuildSnapshots();
  for (const listener of listeners) {
    listener();
  }
}

// ---------------------------------------------------------------------------
// When-clause evaluator
// ---------------------------------------------------------------------------

/**
 * Evaluate a when-clause predicate against a context object.
 *
 * Supported syntax (VS Code when-clause subset):
 * - Simple key existence: `"editorFocused"` -- true if context has that key and it's truthy
 * - Negation: `"!editorReadOnly"` -- true if key is falsy or absent
 * - Equality: `"fileType == 'clawdstrike_policy'"` -- true if context[key] equals value
 * - Inequality: `"fileType != 'yara_rule'"` -- true if not equal
 * - AND: `"editorFocused && fileType == 'clawdstrike_policy'"` -- both must be true
 *
 * If `when` is undefined or empty string, returns true (always visible).
 */
export function evaluateWhenClause(when: string | undefined, context: WhenContext): boolean {
  if (when === undefined || when === "") {
    return true;
  }

  // Split on && for AND logic
  const clauses = when.split("&&");

  for (const raw of clauses) {
    const clause = raw.trim();
    if (clause === "") continue;

    if (!evaluateSingleClause(clause, context)) {
      return false;
    }
  }

  return true;
}

/**
 * Evaluate a single clause (no && in it).
 */
function evaluateSingleClause(clause: string, context: WhenContext): boolean {
  // Check for inequality first (!=) before equality (==) to avoid partial match
  if (clause.includes("!=")) {
    const [keyPart, valuePart] = clause.split("!=", 2);
    const key = keyPart.trim();
    const expected = stripQuotes(valuePart.trim());
    return String(context[key] ?? "") !== expected;
  }

  if (clause.includes("==")) {
    const [keyPart, valuePart] = clause.split("==", 2);
    const key = keyPart.trim();
    const expected = stripQuotes(valuePart.trim());
    return String(context[key] ?? "") === expected;
  }

  // Negation: !key
  if (clause.startsWith("!")) {
    const key = clause.slice(1).trim();
    return !context[key];
  }

  // Simple key existence / truthy check
  return !!context[clause];
}

/** Strip surrounding single or double quotes from a value. */
function stripQuotes(value: string): string {
  if (
    (value.startsWith("'") && value.endsWith("'")) ||
    (value.startsWith('"') && value.endsWith('"'))
  ) {
    return value.slice(1, -1);
  }
  return value;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Register a context menu item. Returns a dispose function that removes
 * the item and notifies listeners.
 *
 * @throws {Error} if an item with the same id is already registered.
 */
export function registerContextMenuItem(item: ContextMenuItemRegistration): () => void {
  if (menuMap.has(item.id)) {
    throw new Error(`Context menu item "${item.id}" already registered`);
  }
  menuMap.set(item.id, item);
  notify();

  return () => {
    menuMap.delete(item.id);
    notify();
  };
}

/** Get all registered context menu items (across all menus). */
export function getContextMenuItems(): ContextMenuItemRegistration[] {
  const all: ContextMenuItemRegistration[] = [];
  for (const list of snapshotByMenu.values()) {
    all.push(...list);
  }
  return all;
}

/**
 * Get all context menu items for a specific menu target, sorted by priority ascending.
 * Returns a stable frozen empty array when no items exist for the menu.
 */
export function getContextMenuItemsByMenu(menu: ContextMenuTarget): ContextMenuItemRegistration[] {
  return snapshotByMenu.get(menu) ?? EMPTY;
}

/**
 * Subscribe to context menu registry changes. The listener is called whenever
 * an item is registered or unregistered. Returns an unsubscribe function.
 */
export function onContextMenuChange(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/**
 * React hook that returns all context menu items for a specific menu target,
 * re-rendering the consuming component whenever items are registered or unregistered.
 *
 * Uses useSyncExternalStore for tear-free reads.
 */
export function useContextMenuItems(menu: ContextMenuTarget): ContextMenuItemRegistration[] {
  return useSyncExternalStore(
    onContextMenuChange,
    () => getContextMenuItemsByMenu(menu),
  );
}
