import { beforeEach, describe, expect, it } from "vitest";

import { SessionStore } from "./sessionStore";

class MemoryStorage {
  private store = new Map<string, string>();

  getItem(key: string): string | null {
    return this.store.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.store.set(key, value);
  }

  removeItem(key: string): void {
    this.store.delete(key);
  }

  clear(): void {
    this.store.clear();
  }
}

beforeEach(() => {
  (globalThis as unknown as { localStorage: MemoryStorage }).localStorage = new MemoryStorage();
});

describe("SessionStore", () => {
  it("creates and selects strikecell sessions", () => {
    const store = new SessionStore();
    const created = store.createSession("nexus", "Strikecell 1", null, {
      strikecellId: "nexus",
      strikecellKind: "experiment",
    });

    expect(created.strikecellKind).toBe("experiment");
    expect(store.getActiveSessionId()).toBe(created.id);

    store.setActiveSession(created.id);
    expect(store.getSession(created.id)?.title).toBe("Strikecell 1");
  });

  it("loads legacy sessions without strikecell metadata", () => {
    const storage = (globalThis as unknown as { localStorage: MemoryStorage }).localStorage;
    storage.setItem(
      "sdr:sessions",
      JSON.stringify({
        version: 1,
        activeSessionId: "sess_legacy",
        activeAppId: "nexus",
        sessions: [
          {
            id: "sess_legacy",
            appId: "nexus",
            title: "Legacy Session",
            pinned: false,
            archived: false,
            status: "running",
            data: null,
            createdAt: 1700000000000,
            updatedAt: 1700000000000,
            lastOpenedAt: 1700000000000,
          },
        ],
      }),
    );

    const store = new SessionStore();
    const loaded = store.getSession("sess_legacy");

    expect(loaded).toBeTruthy();
    expect(loaded?.strikecellKind).toBeUndefined();
    expect(loaded?.status).toBe("running");
    expect(store.getActiveSessionId()).toBe("sess_legacy");
  });
});
