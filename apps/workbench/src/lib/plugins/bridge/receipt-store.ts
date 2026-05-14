/**
 * Plugin Receipt Store
 *
 * Local storage for PluginActionReceipts following the local-audit.ts pattern.
 * Provides add/getAll/query/clear operations with filtering by pluginId,
 * actionType, result, and time range. Enforces a MAX_RECEIPTS cap with
 * oldest-eviction (newest-first ordering).
 *
 * Supports React reactivity via useSyncExternalStore (subscribe/getSnapshot).
 */

import { useCallback, useSyncExternalStore } from "react";
import type { PluginActionReceipt } from "./receipt-types";

// ---- Constants ----

const LS_KEY = "clawdstrike_plugin_receipts";

/** Maximum number of receipts retained locally. Oldest are evicted first. */
export const MAX_RECEIPTS = 5000;

// ---- Query Filter ----

/**
 * Filter criteria for querying the receipt store.
 * All fields are optional -- only provided fields are matched (AND logic).
 */
export interface ReceiptQueryFilter {
  /** Filter by plugin ID. */
  pluginId?: string;
  /** Filter by action type (e.g. "guards.register"). */
  actionType?: string;
  /** Filter by result. */
  result?: "allowed" | "denied" | "error";
  /** Include receipts at or after this ISO-8601 timestamp. */
  since?: string;
  /** Include receipts at or before this ISO-8601 timestamp. */
  until?: string;
}

// ---- Store ----

/**
 * Local receipt store backed by localStorage.
 *
 * Follows the same storage pattern as local-audit.ts:
 * - Newest-first ordering
 * - FIFO cap at MAX_RECEIPTS
 * - In-memory cache for fast reads
 * - useSyncExternalStore for React reactivity
 */
export class PluginReceiptStore {
  private cache: PluginActionReceipt[] | null = null;
  private listeners = new Set<() => void>();

  // ---- Read ----

  /** Return all stored receipts (newest first). */
  getAll(): PluginActionReceipt[] {
    return this.readFromStorage();
  }

  /**
   * Query receipts with filter criteria.
   * All filter fields use AND logic -- only provided fields are matched.
   */
  query(filter: ReceiptQueryFilter): PluginActionReceipt[] {
    let receipts = this.readFromStorage();

    if (filter.pluginId !== undefined) {
      receipts = receipts.filter(
        (r) => r.content.plugin.id === filter.pluginId,
      );
    }

    if (filter.actionType !== undefined) {
      receipts = receipts.filter(
        (r) => r.content.action.type === filter.actionType,
      );
    }

    if (filter.result !== undefined) {
      receipts = receipts.filter(
        (r) => r.content.action.result === filter.result,
      );
    }

    if (filter.since !== undefined) {
      const sinceTime = new Date(filter.since).getTime();
      receipts = receipts.filter(
        (r) => new Date(r.content.timestamp).getTime() >= sinceTime,
      );
    }

    if (filter.until !== undefined) {
      const untilTime = new Date(filter.until).getTime();
      receipts = receipts.filter(
        (r) => new Date(r.content.timestamp).getTime() <= untilTime,
      );
    }

    return receipts;
  }

  // ---- Write ----

  /** Add a receipt to the store (prepend, newest first). Enforces MAX_RECEIPTS cap. */
  add(receipt: PluginActionReceipt): void {
    const current = this.readFromStorage();
    const updated = [receipt, ...current].slice(0, MAX_RECEIPTS);
    this.writeToStorage(updated);
  }

  /** Clear all receipts from the store. */
  clear(): void {
    this.writeToStorage([]);
  }

  // ---- React Integration (useSyncExternalStore) ----

  /** Subscribe to store changes. Returns an unsubscribe function. */
  subscribe = (callback: () => void): (() => void) => {
    this.listeners.add(callback);
    return () => {
      this.listeners.delete(callback);
    };
  };

  /** Get the current snapshot for useSyncExternalStore. */
  getSnapshot = (): PluginActionReceipt[] => {
    return this.readFromStorage();
  };

  // ---- Private ----

  private readFromStorage(): PluginActionReceipt[] {
    if (this.cache !== null) return this.cache;
    try {
      const raw = localStorage.getItem(LS_KEY);
      if (!raw) {
        this.cache = [];
        return this.cache;
      }
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) {
        console.warn("[receipt-store] stored data is not an array, resetting");
        this.cache = [];
        return this.cache;
      }
      this.cache = parsed as PluginActionReceipt[];
      return this.cache;
    } catch (e) {
      console.warn("[receipt-store] localStorage read failed:", e);
      this.cache = [];
      return this.cache;
    }
  }

  private writeToStorage(receipts: PluginActionReceipt[]): void {
    this.cache = receipts;
    try {
      localStorage.setItem(LS_KEY, JSON.stringify(receipts));
    } catch (e) {
      console.warn("[receipt-store] localStorage write failed:", e);
    }
    this.notifyListeners();
  }

  private notifyListeners(): void {
    for (const fn of this.listeners) {
      fn();
    }
  }
}

// ---- Singleton ----

let singletonStore: PluginReceiptStore | null = null;

/**
 * Returns the singleton PluginReceiptStore instance.
 * Creates one on first call.
 */
export function getPluginReceiptStore(): PluginReceiptStore {
  if (!singletonStore) {
    singletonStore = new PluginReceiptStore();
  }
  return singletonStore;
}

// ---- React Hook ----

/**
 * React hook that provides the plugin receipt list and management functions.
 * Re-renders automatically when receipts are added or cleared.
 */
export function usePluginReceipts() {
  const store = getPluginReceiptStore();

  const receipts = useSyncExternalStore(
    store.subscribe,
    store.getSnapshot,
    store.getSnapshot,
  );

  const addReceipt = useCallback(
    (receipt: PluginActionReceipt) => {
      store.add(receipt);
    },
    [store],
  );

  const clearReceipts = useCallback(() => {
    store.clear();
  }, [store]);

  const queryReceipts = useCallback(
    (filter: ReceiptQueryFilter) => {
      return store.query(filter);
    },
    [store],
  );

  return { receipts, addReceipt, clearReceipts, queryReceipts } as const;
}
