/**
 * Secure credential storage abstraction.
 *
 * On desktop (Tauri): uses Stronghold encrypted vault via Tauri commands.
 * On web: falls back to localStorage with a console warning.
 *
 * All methods are async to accommodate the Tauri IPC round-trip.
 */

import { isDesktop } from "@/lib/tauri-bridge";

// ---------------------------------------------------------------------------
// Tauri invoke helper (lazy-loaded)
// ---------------------------------------------------------------------------

async function tauriInvoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<T>(cmd, args);
}

// ---------------------------------------------------------------------------
// Stronghold initialisation
// ---------------------------------------------------------------------------

let strongholdReady: Promise<boolean> | null = null;

/**
 * Ensure the Stronghold vault is initialised. Safe to call multiple times;
 * only the first call does real work.
 */
async function ensureStronghold(): Promise<boolean> {
  if (!isDesktop()) return false;

  if (!strongholdReady) {
    strongholdReady = tauriInvoke<boolean>("init_stronghold").catch((err) => {
      console.error("[secure-store] Stronghold init failed:", err);
      strongholdReady = null; // allow retry
      return false;
    });
  }

  return strongholdReady;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export const secureStore = {
  /**
   * Store a key-value credential.
   * Desktop: encrypted Stronghold vault. Web: localStorage.
   */
  async set(key: string, value: string): Promise<void> {
    if (isDesktop()) {
      const ok = await ensureStronghold();
      if (ok) {
        await tauriInvoke("store_credential", { key, value });
        return;
      }
    }

    // Fallback: sessionStorage (credentials cleared when tab closes)
    if (typeof window !== "undefined" && typeof sessionStorage !== "undefined") {
      console.warn("[secure-store] Using session storage (insecure fallback)");
      sessionStorage.setItem(`clawdstrike_${key}`, value);
    }
  },

  /**
   * Retrieve a credential by key.
   * Returns `null` if not found.
   */
  async get(key: string): Promise<string | null> {
    if (isDesktop()) {
      const ok = await ensureStronghold();
      if (ok) {
        return tauriInvoke<string | null>("get_credential", { key });
      }
    }

    // Fallback: sessionStorage
    if (typeof window !== "undefined" && typeof sessionStorage !== "undefined") {
      return sessionStorage.getItem(`clawdstrike_${key}`);
    }
    return null;
  },

  /**
   * Delete a credential by key.
   */
  async delete(key: string): Promise<void> {
    if (isDesktop()) {
      const ok = await ensureStronghold();
      if (ok) {
        await tauriInvoke("delete_credential", { key });
        return;
      }
    }

    // Fallback: sessionStorage
    if (typeof window !== "undefined" && typeof sessionStorage !== "undefined") {
      sessionStorage.removeItem(`clawdstrike_${key}`);
    }
  },

  /**
   * Check whether a credential exists.
   */
  async has(key: string): Promise<boolean> {
    if (isDesktop()) {
      const ok = await ensureStronghold();
      if (ok) {
        return tauriInvoke<boolean>("has_credential", { key });
      }
    }

    // Fallback: sessionStorage
    if (typeof window !== "undefined" && typeof sessionStorage !== "undefined") {
      return sessionStorage.getItem(`clawdstrike_${key}`) !== null;
    }
    return false;
  },

  /**
   * Whether the secure (Stronghold) backend is active.
   * Returns false on web or if Stronghold init failed.
   */
  async isSecure(): Promise<boolean> {
    if (!isDesktop()) return false;
    return ensureStronghold();
  },

  /**
   * Initialise Stronghold eagerly (e.g. at app startup).
   * No-op on web.
   */
  async init(): Promise<void> {
    await ensureStronghold();
  },
};

// ---------------------------------------------------------------------------
// One-time migration: localStorage -> Stronghold
// ---------------------------------------------------------------------------

const MIGRATION_FLAG = "clawdstrike_stronghold_migrated";

/**
 * Credential keys used by `fleet-client.ts` that should be migrated.
 */
const LEGACY_LS_KEYS: Record<string, string> = {
  clawdstrike_hushd_url: "hushd_url",
  clawdstrike_control_api_url: "control_api_url",
  clawdstrike_api_key: "api_key",
  clawdstrike_control_api_token: "control_api_token",
};

/**
 * Migrate any existing localStorage credentials into Stronghold.
 * Runs once; subsequent calls are no-ops (guarded by a migration flag).
 *
 * Should be called early in the app lifecycle (e.g. in the root layout).
 */
export async function migrateCredentialsToStronghold(): Promise<void> {
  // Only relevant on desktop with Stronghold available.
  if (!isDesktop()) return;

  // Check migration flag in localStorage.
  try {
    if (localStorage.getItem(MIGRATION_FLAG) === "1") return;
  } catch {
    return;
  }

  const ok = await ensureStronghold();
  if (!ok) return;

  let migrated = 0;

  for (const [lsKey, storeKey] of Object.entries(LEGACY_LS_KEYS)) {
    try {
      const value = localStorage.getItem(lsKey);
      if (value && value.length > 0) {
        await secureStore.set(storeKey, value);
        localStorage.removeItem(lsKey);
        migrated++;
      }
    } catch (err) {
      console.warn(
        `[secure-store] Migration failed for ${lsKey}:`,
        err,
      );
    }
  }

  if (migrated > 0) {
    console.info(
      `[secure-store] Migrated ${migrated} credential(s) from localStorage to Stronghold.`,
    );
  }

  // Set migration flag so we don't re-run.
  try {
    localStorage.setItem(MIGRATION_FLAG, "1");
  } catch {
    // Best-effort.
  }
}
