/**
 * PluginReceiptStore Tests
 *
 * Tests for the local receipt store with query API, following the
 * local-audit.ts pattern. Verifies add/getAll/query/clear operations,
 * MAX_RECEIPTS cap with oldest-eviction, and singleton behavior.
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import type { PluginActionReceipt } from "../receipt-types";

// Mock localStorage
const localStorageMock = (() => {
  let store: Record<string, string> = {};
  return {
    getItem: vi.fn((key: string) => store[key] ?? null),
    setItem: vi.fn((key: string, val: string) => {
      store[key] = val;
    }),
    removeItem: vi.fn((key: string) => {
      delete store[key];
    }),
    clear: vi.fn(() => {
      store = {};
    }),
    _store: store,
    _reset: () => {
      store = {};
    },
  };
})();

vi.stubGlobal("localStorage", localStorageMock);

// Import after mock
import {
  PluginReceiptStore,
  getPluginReceiptStore,
} from "../receipt-store";

function makeReceipt(overrides?: {
  pluginId?: string;
  actionType?: string;
  result?: "allowed" | "denied" | "error";
  timestamp?: string;
}): PluginActionReceipt {
  return {
    content: {
      version: "1.0.0",
      receipt_id: crypto.randomUUID(),
      timestamp: overrides?.timestamp ?? new Date().toISOString(),
      plugin: {
        id: overrides?.pluginId ?? "plugin-a",
        version: "1.0.0",
        publisher: "pub",
        trust_tier: "community",
      },
      action: {
        type: overrides?.actionType ?? "guards.register",
        params_hash: "a".repeat(64),
        result: overrides?.result ?? "allowed",
        permission_checked: "guards:register",
        duration_ms: 10,
      },
    },
    signature: "sig-hex",
    signer_public_key: "pub-hex",
  };
}

describe("PluginReceiptStore", () => {
  let store: PluginReceiptStore;

  beforeEach(() => {
    localStorageMock._reset();
    localStorageMock.getItem.mockClear();
    localStorageMock.setItem.mockClear();
    store = new PluginReceiptStore();
  });

  it("add(receipt) stores it and getAll() returns it", () => {
    const receipt = makeReceipt();
    store.add(receipt);
    const all = store.getAll();

    expect(all).toHaveLength(1);
    expect(all[0].content.plugin.id).toBe("plugin-a");
  });

  it("query({ pluginId: 'plugin-a' }) returns only receipts for plugin-a", () => {
    store.add(makeReceipt({ pluginId: "plugin-a" }));
    store.add(makeReceipt({ pluginId: "plugin-b" }));
    store.add(makeReceipt({ pluginId: "plugin-a" }));

    const results = store.query({ pluginId: "plugin-a" });
    expect(results).toHaveLength(2);
    for (const r of results) {
      expect(r.content.plugin.id).toBe("plugin-a");
    }
  });

  it("query({ actionType: 'guards.register' }) returns only receipts with that action type", () => {
    store.add(makeReceipt({ actionType: "guards.register" }));
    store.add(makeReceipt({ actionType: "storage.set" }));
    store.add(makeReceipt({ actionType: "guards.register" }));

    const results = store.query({ actionType: "guards.register" });
    expect(results).toHaveLength(2);
    for (const r of results) {
      expect(r.content.action.type).toBe("guards.register");
    }
  });

  it("query({ result: 'denied' }) returns only denied receipts", () => {
    store.add(makeReceipt({ result: "allowed" }));
    store.add(makeReceipt({ result: "denied" }));
    store.add(makeReceipt({ result: "denied" }));

    const results = store.query({ result: "denied" });
    expect(results).toHaveLength(2);
    for (const r of results) {
      expect(r.content.action.result).toBe("denied");
    }
  });

  it("query({ since, until }) returns receipts in that time range", () => {
    const t1 = "2026-01-01T00:00:00.000Z";
    const t2 = "2026-01-02T00:00:00.000Z";
    const t3 = "2026-01-03T00:00:00.000Z";

    store.add(makeReceipt({ timestamp: t1 }));
    store.add(makeReceipt({ timestamp: t2 }));
    store.add(makeReceipt({ timestamp: t3 }));

    const results = store.query({
      since: "2026-01-01T12:00:00.000Z",
      until: "2026-01-02T12:00:00.000Z",
    });

    expect(results).toHaveLength(1);
    expect(results[0].content.timestamp).toBe(t2);
  });

  it("enforces MAX_RECEIPTS (5000) cap with oldest-eviction", () => {
    // Seed the store with 4999 receipts by writing directly to localStorage
    const seedReceipts: PluginActionReceipt[] = [];
    for (let i = 0; i < 4999; i++) {
      seedReceipts.push(makeReceipt({ pluginId: `old-${i}` }));
    }
    localStorageMock.setItem(
      "clawdstrike_plugin_receipts",
      JSON.stringify(seedReceipts),
    );

    // Create a fresh store that reads from seeded localStorage
    const cappedStore = new PluginReceiptStore();

    // Add 3 more (total would be 5002 without cap)
    cappedStore.add(makeReceipt({ pluginId: "new-0" }));
    cappedStore.add(makeReceipt({ pluginId: "new-1" }));
    cappedStore.add(makeReceipt({ pluginId: "new-2" }));

    const all = cappedStore.getAll();
    expect(all.length).toBeLessThanOrEqual(5000);
    // Newest receipts should be at the front
    expect(all[0].content.plugin.id).toBe("new-2");
    expect(all[1].content.plugin.id).toBe("new-1");
    expect(all[2].content.plugin.id).toBe("new-0");
  });

  it("clear() removes all receipts", () => {
    store.add(makeReceipt());
    store.add(makeReceipt());

    store.clear();

    expect(store.getAll()).toHaveLength(0);
  });
});

describe("getPluginReceiptStore", () => {
  it("returns a singleton instance", () => {
    // Reset module-level singleton by re-importing
    const store1 = getPluginReceiptStore();
    const store2 = getPluginReceiptStore();

    expect(store1).toBe(store2);
  });
});
