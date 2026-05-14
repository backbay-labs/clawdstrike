/**
 * Plugin Revocation Store
 *
 * Local storage for plugin revocation entries. Provides revoke/isRevoked/lift/getAll/sync
 * operations with time-limited expiry support. Persists to localStorage for offline
 * resilience across workbench restarts.
 *
 * Follows the same localStorage + in-memory cache pattern as receipt-store.ts.
 * Plan 05-02 wires this to hushd SSE events for fleet-wide coordination.
 */

// ---- Constants ----

const LS_KEY = "clawdstrike_plugin_revocations";

// ---- Types ----

/**
 * A revocation entry for a single plugin.
 * Stored in localStorage and synced from remote hushd events.
 */
export interface PluginRevocationEntry {
  /** The ID of the revoked plugin. */
  pluginId: string;
  /** Human-readable reason for revocation. */
  reason: string;
  /** ISO-8601 timestamp when the revocation was created. */
  revokedAt: string;
  /** ISO-8601 timestamp when the revocation expires, or null for permanent. */
  until: string | null;
  /** Optional identifier of who/what initiated the revocation. */
  revokedBy?: string;
}

// ---- Options ----

/** Options for the revoke() method. */
export interface RevokeOptions {
  /** Human-readable reason for revocation. */
  reason?: string;
  /** Epoch ms timestamp when the revocation expires, or null for permanent. */
  until?: number | null;
  /** Optional identifier of who/what initiated the revocation. */
  revokedBy?: string;
}

// ---- Store ----

/**
 * Local revocation store backed by localStorage.
 *
 * Follows the same in-memory cache pattern as PluginReceiptStore:
 * - In-memory Map for fast reads
 * - Persisted to localStorage on every write
 * - Constructor reads from localStorage on first access
 */
export class PluginRevocationStore {
  private entries = new Map<string, PluginRevocationEntry>();

  constructor() {
    this.readFromStorage();
  }

  // ---- Public API ----

  /**
   * Revoke a plugin. Creates a revocation entry and persists to localStorage.
   */
  revoke(pluginId: string, options?: RevokeOptions): void {
    const entry: PluginRevocationEntry = {
      pluginId,
      reason: options?.reason ?? "Revoked",
      revokedAt: new Date().toISOString(),
      until:
        options?.until != null
          ? new Date(options.until).toISOString()
          : null,
      revokedBy: options?.revokedBy,
    };
    this.entries.set(pluginId, entry);
    this.writeToStorage();
  }

  /**
   * Check whether a plugin is currently revoked.
   * Returns false if the entry does not exist or has expired.
   */
  isRevoked(pluginId: string): boolean {
    const entry = this.entries.get(pluginId);
    if (!entry) return false;

    // Check time-limited expiry
    if (entry.until !== null) {
      const expiryTime = new Date(entry.until).getTime();
      if (Date.now() > expiryTime) {
        // Expired -- clean up
        this.entries.delete(pluginId);
        this.writeToStorage();
        return false;
      }
    }

    return true;
  }

  /**
   * Lift (remove) a revocation for a plugin.
   */
  lift(pluginId: string): void {
    this.entries.delete(pluginId);
    this.writeToStorage();
  }

  /**
   * Get all current (non-expired) revocation entries.
   */
  getAll(): PluginRevocationEntry[] {
    const now = Date.now();
    const result: PluginRevocationEntry[] = [];

    for (const [id, entry] of this.entries) {
      if (entry.until !== null) {
        const expiryTime = new Date(entry.until).getTime();
        if (now > expiryTime) {
          // Expired -- skip (and clean up)
          this.entries.delete(id);
          continue;
        }
      }
      result.push(entry);
    }

    // Persist any cleanup
    this.writeToStorage();
    return result;
  }

  /**
   * Sync remote revocation entries into the local store.
   *
   * - Adds new revocations from the remote list
   * - Skips entries whose time-limited revocations have already expired
   * - Returns a diff of what was added and what was removed
   */
  sync(
    remote: PluginRevocationEntry[],
  ): { added: string[]; removed: string[] } {
    const now = Date.now();
    const added: string[] = [];
    const removed: string[] = [];

    // Build a set of plugin IDs present in the remote snapshot (non-expired)
    const remoteIds = new Set<string>();

    for (const entry of remote) {
      // Skip expired entries
      if (entry.until !== null) {
        const expiryTime = new Date(entry.until).getTime();
        if (now > expiryTime) {
          // If we had it locally, remove it
          if (this.entries.has(entry.pluginId)) {
            this.entries.delete(entry.pluginId);
            removed.push(entry.pluginId);
          }
          continue;
        }
      }

      remoteIds.add(entry.pluginId);

      // Add new entries (don't overwrite existing local entries)
      if (!this.entries.has(entry.pluginId)) {
        this.entries.set(entry.pluginId, entry);
        added.push(entry.pluginId);
      }
    }

    // Remove local revocations that disappeared from the remote snapshot
    // (e.g., operator lifted a revocation server-side while client was offline)
    for (const localId of Array.from(this.entries.keys())) {
      if (!remoteIds.has(localId)) {
        this.entries.delete(localId);
        removed.push(localId);
      }
    }

    this.writeToStorage();
    return { added, removed };
  }

  // ---- Private ----

  private readFromStorage(): void {
    try {
      const raw = localStorage.getItem(LS_KEY);
      if (!raw) return;

      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) {
        console.warn(
          "[revocation-store] stored data is not an array, resetting",
        );
        return;
      }

      for (const entry of parsed as PluginRevocationEntry[]) {
        this.entries.set(entry.pluginId, entry);
      }
    } catch (e) {
      console.warn("[revocation-store] localStorage read failed:", e);
    }
  }

  private writeToStorage(): void {
    try {
      const arr = Array.from(this.entries.values());
      localStorage.setItem(LS_KEY, JSON.stringify(arr));
    } catch (e) {
      console.warn("[revocation-store] localStorage write failed:", e);
    }
  }
}

// ---- Singleton ----

let singletonStore: PluginRevocationStore | null = null;

/**
 * Returns the singleton PluginRevocationStore instance.
 * Creates one on first call.
 */
export function getPluginRevocationStore(): PluginRevocationStore {
  if (!singletonStore) {
    singletonStore = new PluginRevocationStore();
  }
  return singletonStore;
}
