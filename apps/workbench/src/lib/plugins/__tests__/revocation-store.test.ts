/**
 * PluginRevocationStore Tests
 *
 * Tests for the local revocation store: revoke/isRevoked/lift/getAll/sync,
 * time-limited revocations with expiry, localStorage persistence, and
 * the "revoked" PluginLifecycleState type.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { PluginLifecycleState } from "../types";

// ---- localStorage mock ----

const localStorageMock = (() => {
  let store: Record<string, string> = {};
  return {
    getItem: vi.fn((key: string) => store[key] ?? null),
    setItem: vi.fn((key: string, value: string) => {
      store[key] = value;
    }),
    removeItem: vi.fn((key: string) => {
      delete store[key];
    }),
    clear: vi.fn(() => {
      store = {};
    }),
    _getStore: () => store,
  };
})();

Object.defineProperty(globalThis, "localStorage", { value: localStorageMock });

// Import after localStorage mock
import {
  PluginRevocationStore,
  getPluginRevocationStore,
} from "../revocation-store";
import type { PluginRevocationEntry } from "../revocation-store";

// ---- Suite ----

describe("PluginRevocationStore", () => {
  let store: PluginRevocationStore;

  beforeEach(() => {
    vi.clearAllMocks();
    localStorageMock.clear();
    store = new PluginRevocationStore();
  });

  // Test 1: revoke stores entry; isRevoked returns true
  it("revoke(pluginId) stores entry and isRevoked(pluginId) returns true", () => {
    expect(store.isRevoked("bad-plugin")).toBe(false);

    store.revoke("bad-plugin", { reason: "Malware detected" });

    expect(store.isRevoked("bad-plugin")).toBe(true);
  });

  // Test 2: time-limited revocation with future timestamp
  it("revoke with until stores time-limited entry; isRevoked returns true before expiry", () => {
    const futureTimestamp = Date.now() + 60_000; // 1 minute from now
    store.revoke("temp-revoked", { until: futureTimestamp });

    expect(store.isRevoked("temp-revoked")).toBe(true);

    const entries = store.getAll();
    const entry = entries.find((e) => e.pluginId === "temp-revoked");
    expect(entry).toBeDefined();
    expect(entry!.until).not.toBeNull();
  });

  // Test 3: isRevoked returns false after time-limited revocation expires
  it("isRevoked returns false after a time-limited revocation expires", () => {
    vi.useFakeTimers();
    const now = Date.now();

    store.revoke("expiring-plugin", { until: now + 10_000 });
    expect(store.isRevoked("expiring-plugin")).toBe(true);

    // Advance time past expiry
    vi.setSystemTime(now + 15_000);
    expect(store.isRevoked("expiring-plugin")).toBe(false);

    vi.useRealTimers();
  });

  // Test 4: lift removes revocation
  it("lift(pluginId) removes revocation; isRevoked returns false", () => {
    store.revoke("lifted-plugin", { reason: "Temporary block" });
    expect(store.isRevoked("lifted-plugin")).toBe(true);

    store.lift("lifted-plugin");
    expect(store.isRevoked("lifted-plugin")).toBe(false);
  });

  // Test 5: getAll returns all current revocations
  it("getAll() returns all current non-expired revocations as PluginRevocationEntry[]", () => {
    store.revoke("plugin-a", { reason: "Reason A" });
    store.revoke("plugin-b", { reason: "Reason B" });

    const all = store.getAll();
    expect(all).toHaveLength(2);

    const ids = all.map((e) => e.pluginId);
    expect(ids).toContain("plugin-a");
    expect(ids).toContain("plugin-b");

    // Verify shape
    for (const entry of all) {
      expect(entry).toHaveProperty("pluginId");
      expect(entry).toHaveProperty("reason");
      expect(entry).toHaveProperty("revokedAt");
      expect(entry).toHaveProperty("until");
    }
  });

  // Test 6: persistence to localStorage; new store instance reads back
  it("revocations persist to localStorage; a new store instance reads them back", () => {
    store.revoke("persisted-plugin", { reason: "Persisted reason" });

    // Verify localStorage was written
    expect(localStorageMock.setItem).toHaveBeenCalled();

    // Create a new store instance -- it should read from localStorage
    const store2 = new PluginRevocationStore();
    expect(store2.isRevoked("persisted-plugin")).toBe(true);

    const all = store2.getAll();
    expect(all).toHaveLength(1);
    expect(all[0].pluginId).toBe("persisted-plugin");
    expect(all[0].reason).toBe("Persisted reason");
  });

  // Test 7: sync treats the remote list as a full snapshot
  it("sync(entries) adds remote revocations and removes local entries missing from the remote snapshot", () => {
    vi.useFakeTimers();
    const now = Date.now();

    // Local has one revocation
    store.revoke("local-only", { reason: "Local block" });

    // Remote has a new revocation and an expired one
    const remoteEntries: PluginRevocationEntry[] = [
      {
        pluginId: "remote-new",
        reason: "Remote block",
        revokedAt: new Date(now).toISOString(),
        until: null,
      },
      {
        pluginId: "remote-expired",
        reason: "Already expired",
        revokedAt: new Date(now - 20_000).toISOString(),
        until: new Date(now - 10_000).toISOString(), // expired 10s ago
      },
    ];

    const diff = store.sync(remoteEntries);

    // "remote-new" should have been added
    expect(diff.added).toContain("remote-new");
    expect(store.isRevoked("remote-new")).toBe(true);

    // "remote-expired" should not be added (expired)
    expect(store.isRevoked("remote-expired")).toBe(false);

    // "local-only" disappeared from the remote snapshot, so it should be lifted
    expect(diff.removed).toContain("local-only");
    expect(store.isRevoked("local-only")).toBe(false);

    vi.useRealTimers();
  });

  // Test 8: PluginLifecycleState includes "revoked" (type-level check)
  it("PluginLifecycleState type includes 'revoked'", () => {
    // This is a compile-time check -- if "revoked" is not in the union,
    // TypeScript will emit a type error on this assignment.
    const state: PluginLifecycleState = "revoked";
    expect(state).toBe("revoked");
  });
});

// ---- Singleton ----

describe("getPluginRevocationStore", () => {
  it("returns the same singleton instance on repeated calls", () => {
    const a = getPluginRevocationStore();
    const b = getPluginRevocationStore();
    expect(a).toBe(b);
  });
});
