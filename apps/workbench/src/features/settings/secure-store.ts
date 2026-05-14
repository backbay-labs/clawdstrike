import { isDesktop } from "@/lib/tauri-bridge";

async function tauriInvoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<T>(cmd, args);
}

// ---------------------------------------------------------------------------
// Fallback storage — security implications
// ---------------------------------------------------------------------------
//
// When the Stronghold backend is unavailable (browser-only mode, init failure,
// or timeout), secrets and credentials fall back to one of two tiers:
//
// 1. **Sensitive keys** (tokens, passwords, private keys, API keys) are stored
//    in a per-tab in-memory Map and are NEVER written to sessionStorage.  They
//    are lost on tab close, which is the intended behavior — leaking secrets
//    into browser storage is a worse outcome than requiring re-entry.
//
// 2. **Non-sensitive keys** (e.g. hushd_url, display preferences) fall back to
//    sessionStorage.  This is acceptable because the values are not secret, but
//    callers should be aware they are stored in plaintext and visible to same-
//    origin scripts.
//
// A console.warn is emitted the first time any key hits either fallback path so
// that operators can diagnose missing Stronghold support in production.
// ---------------------------------------------------------------------------

const IN_MEMORY_FALLBACK = new Map<string, string>();
const warnedFallback = new Set<string>();

const EXPLICIT_SENSITIVE_KEYS = new Set<string>([
  "api_key",
  "control_api_token",
  "token",
  "secret",
  "password",
  "private_key",
  "signing_key",
]);
const SESSION_STORAGE_FALLBACK_KEYS = new Set<string>([
  "hushd_url",
  "control_api_url",
]);

function isSessionStorageAvailable(): boolean {
  return typeof window !== "undefined" && typeof sessionStorage !== "undefined";
}

function isSensitiveKey(key: string): boolean {
  const normalized = key.toLowerCase();
  if (EXPLICIT_SENSITIVE_KEYS.has(normalized)) return true;
  return (
    normalized.includes("token")
    || normalized.includes("secret")
    || normalized.includes("password")
    || normalized.includes("api_key")
    || normalized.includes("apikey")
    || normalized.includes("private_key")
  );
}

function canUseSessionStorageFallback(key: string): boolean {
  return SESSION_STORAGE_FALLBACK_KEYS.has(key.toLowerCase());
}

function storageKey(key: string): string {
  return `clawdstrike_${key}`;
}

function warnInMemoryFallback(key: string, sensitive: boolean): void {
  if (warnedFallback.has(key)) return;
  warnedFallback.add(key);
  if (sensitive) {
    console.warn(
      `[secure-store] Stronghold unavailable; sensitive key "${key}" is using in-memory fallback (not persisted). ` +
      `The value will be lost when this tab closes.`,
    );
  } else {
    console.warn(
      `[secure-store] Stronghold unavailable; key "${key}" is using in-memory fallback (not persisted).`,
    );
  }
}

function warnSessionStorageFallback(key: string): void {
  if (warnedFallback.has(key)) return;
  warnedFallback.add(key);
  console.warn(
    `[secure-store] Stronghold unavailable; key "${key}" is falling back to sessionStorage (plaintext, same-origin accessible).`,
  );
}

let strongholdReady: Promise<boolean> | null = null;
async function ensureStronghold(): Promise<boolean> {
  if (!isDesktop()) return false;

  if (!strongholdReady) {
    let timeoutId: ReturnType<typeof setTimeout> | null = null;
    strongholdReady = Promise.race([
      tauriInvoke<boolean>("init_stronghold"),
      new Promise<boolean>((resolve) => {
        timeoutId = setTimeout(() => {
          console.warn("[secure-store] Stronghold init timed out after 5s, using degraded fallback storage");
          resolve(false);
        }, 5000);
      }),
    ]).then((result) => {
      // Cancel the timeout if init resolved before it fired
      if (timeoutId !== null) clearTimeout(timeoutId);
      // If timed out (false), clear cache so next call retries
      if (!result) strongholdReady = null;
      return result;
    }).catch((err) => {
      if (timeoutId !== null) clearTimeout(timeoutId);
      console.error("[secure-store] Stronghold init failed:", err);
      strongholdReady = null;
      return false;
    });
  }

  return strongholdReady;
}

export const secureStore = {
  async set(key: string, value: string): Promise<void> {
    if (isDesktop()) {
      const ok = await ensureStronghold();
      if (ok) {
        await tauriInvoke("store_credential", { key, value });
        return;
      }
    }

    const sensitive = isSensitiveKey(key);
    // Deny-by-default fallback model: only explicitly allowlisted keys may use
    // sessionStorage. All others stay in ephemeral memory.
    if (!canUseSessionStorageFallback(key)) {
      warnInMemoryFallback(key, sensitive);
      IN_MEMORY_FALLBACK.set(key, value);
      return;
    }

    if (isSessionStorageAvailable()) {
      warnSessionStorageFallback(key);
      sessionStorage.setItem(storageKey(key), value);
      return;
    }
    warnInMemoryFallback(key, sensitive);
    IN_MEMORY_FALLBACK.set(key, value);
  },

  async get(key: string): Promise<string | null> {
    if (isDesktop()) {
      const ok = await ensureStronghold();
      if (ok) {
        return tauriInvoke<string | null>("get_credential", { key });
      }
    }

    if (!canUseSessionStorageFallback(key)) {
      return IN_MEMORY_FALLBACK.get(key) ?? null;
    }

    if (isSessionStorageAvailable()) {
      return sessionStorage.getItem(storageKey(key));
    }
    return IN_MEMORY_FALLBACK.get(key) ?? null;
  },

  async delete(key: string): Promise<void> {
    if (isDesktop()) {
      const ok = await ensureStronghold();
      if (ok) {
        await tauriInvoke("delete_credential", { key });
        return;
      }
    }

    IN_MEMORY_FALLBACK.delete(key);

    if (canUseSessionStorageFallback(key) && isSessionStorageAvailable()) {
      sessionStorage.removeItem(storageKey(key));
    }
  },

  async has(key: string): Promise<boolean> {
    if (isDesktop()) {
      const ok = await ensureStronghold();
      if (ok) {
        return tauriInvoke<boolean>("has_credential", { key });
      }
    }

    if (!canUseSessionStorageFallback(key)) {
      return IN_MEMORY_FALLBACK.has(key);
    }

    if (isSessionStorageAvailable()) {
      return sessionStorage.getItem(storageKey(key)) !== null;
    }
    return IN_MEMORY_FALLBACK.has(key);
  },

  async isSecure(): Promise<boolean> {
    if (!isDesktop()) return false;
    return ensureStronghold();
  },

  async init(): Promise<void> {
    await ensureStronghold();
  },
};

const MIGRATION_FLAG = "clawdstrike_stronghold_migrated";

const LEGACY_LS_KEYS: Record<string, string> = {
  clawdstrike_hushd_url: "hushd_url",
  clawdstrike_control_api_url: "control_api_url",
  clawdstrike_api_key: "api_key",
  clawdstrike_control_api_token: "control_api_token",
};

export async function migrateCredentialsToStronghold(): Promise<void> {
  if (!isDesktop()) return;

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

  try {
    localStorage.setItem(MIGRATION_FLAG, "1");
  } catch {}
}
