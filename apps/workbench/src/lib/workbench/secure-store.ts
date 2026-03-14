import { isDesktop } from "@/lib/tauri-bridge";

async function tauriInvoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<T>(cmd, args);
}

let strongholdReady: Promise<boolean> | null = null;
async function ensureStronghold(): Promise<boolean> {
  if (!isDesktop()) return false;

  if (!strongholdReady) {
    strongholdReady = tauriInvoke<boolean>("init_stronghold").catch((err) => {
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

    if (typeof window !== "undefined" && typeof sessionStorage !== "undefined") {
      sessionStorage.setItem(`clawdstrike_${key}`, value);
    }
  },

  async get(key: string): Promise<string | null> {
    if (isDesktop()) {
      const ok = await ensureStronghold();
      if (ok) {
        return tauriInvoke<string | null>("get_credential", { key });
      }
    }

    if (typeof window !== "undefined" && typeof sessionStorage !== "undefined") {
      return sessionStorage.getItem(`clawdstrike_${key}`);
    }
    return null;
  },

  async delete(key: string): Promise<void> {
    if (isDesktop()) {
      const ok = await ensureStronghold();
      if (ok) {
        await tauriInvoke("delete_credential", { key });
        return;
      }
    }

    if (typeof window !== "undefined" && typeof sessionStorage !== "undefined") {
      sessionStorage.removeItem(`clawdstrike_${key}`);
    }
  },

  async has(key: string): Promise<boolean> {
    if (isDesktop()) {
      const ok = await ensureStronghold();
      if (ok) {
        return tauriInvoke<boolean>("has_credential", { key });
      }
    }

    if (typeof window !== "undefined" && typeof sessionStorage !== "undefined") {
      return sessionStorage.getItem(`clawdstrike_${key}`) !== null;
    }
    return false;
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
