/**
 * Receipt Middleware Tests
 *
 * Tests for the receipt generation middleware that wraps bridge host dispatch.
 * Verifies that allowed/denied/error calls produce signed PluginActionReceipts
 * stored in the receipt store.
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import type { PluginActionReceipt } from "../receipt-types";
import { PluginReceiptStore } from "../receipt-store";

// Mock operator-crypto for Ed25519 signing
vi.mock("../../../workbench/operator-crypto", () => ({
  signCanonical: vi.fn(async () => "abcd1234".repeat(16)),
  canonicalizeJson: vi.fn((obj: unknown) => JSON.stringify(obj)),
  toHex: vi.fn((bytes: Uint8Array) =>
    Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(""),
  ),
}));

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
    _reset: () => {
      store = {};
    },
  };
})();

vi.stubGlobal("localStorage", localStorageMock);

import { createReceiptMiddleware } from "../receipt-middleware";

describe("createReceiptMiddleware", () => {
  let store: PluginReceiptStore;

  beforeEach(() => {
    vi.clearAllMocks();
    localStorageMock._reset();
    store = new PluginReceiptStore();
  });

  it("returns an object with recordAllowed, recordDenied, and recordError", () => {
    const mw = createReceiptMiddleware({
      pluginId: "plugin-a",
      pluginVersion: "1.0.0",
      publisher: "pub",
      trustTier: "community",
      secretKeyHex: "deadbeef".repeat(8),
      publicKeyHex: "cafebabe".repeat(8),
      store,
    });

    expect(typeof mw.recordAllowed).toBe("function");
    expect(typeof mw.recordDenied).toBe("function");
    expect(typeof mw.recordError).toBe("function");
  });

  it("recordAllowed creates a receipt with result 'allowed' and stores it", async () => {
    const mw = createReceiptMiddleware({
      pluginId: "plugin-a",
      pluginVersion: "1.0.0",
      publisher: "pub",
      trustTier: "community",
      secretKeyHex: "deadbeef".repeat(8),
      publicKeyHex: "cafebabe".repeat(8),
      store,
    });

    await mw.recordAllowed("guards.register", { id: "g1" }, 12);

    const all = store.getAll();
    expect(all).toHaveLength(1);
    expect(all[0].content.action.result).toBe("allowed");
    expect(all[0].content.action.type).toBe("guards.register");
    expect(all[0].content.action.duration_ms).toBe(12);
    expect(all[0].content.plugin.id).toBe("plugin-a");
  });

  it("recordDenied creates a receipt with result 'denied' and stores it", async () => {
    const mw = createReceiptMiddleware({
      pluginId: "plugin-a",
      pluginVersion: "1.0.0",
      publisher: "pub",
      trustTier: "community",
      secretKeyHex: "deadbeef".repeat(8),
      publicKeyHex: "cafebabe".repeat(8),
      store,
    });

    await mw.recordDenied("storage.set", { key: "x" }, "storage:write");

    const all = store.getAll();
    expect(all).toHaveLength(1);
    expect(all[0].content.action.result).toBe("denied");
    expect(all[0].content.action.permission_checked).toBe("storage:write");
  });

  it("recordDenied always stores regardless of any verbosity flag", async () => {
    // The contract: denials are ALWAYS recorded
    const mw = createReceiptMiddleware({
      pluginId: "plugin-a",
      pluginVersion: "1.0.0",
      publisher: "pub",
      trustTier: "community",
      secretKeyHex: "deadbeef".repeat(8),
      publicKeyHex: "cafebabe".repeat(8),
      store,
    });

    await mw.recordDenied("guards.register", {}, "guards:register");

    expect(store.getAll()).toHaveLength(1);
    expect(store.getAll()[0].content.action.result).toBe("denied");
  });

  it("when secretKeyHex is provided, receipts are Ed25519-signed (signature is non-empty hex)", async () => {
    const mw = createReceiptMiddleware({
      pluginId: "plugin-a",
      pluginVersion: "1.0.0",
      publisher: "pub",
      trustTier: "community",
      secretKeyHex: "deadbeef".repeat(8),
      publicKeyHex: "cafebabe".repeat(8),
      store,
    });

    await mw.recordAllowed("guards.register", {}, 5);

    const all = store.getAll();
    expect(all[0].signature).toBeTruthy();
    expect(all[0].signature.length).toBeGreaterThan(0);
  });

  it("when secretKeyHex is null, receipts have signature '' (unsigned, dev mode)", async () => {
    const mw = createReceiptMiddleware({
      pluginId: "plugin-a",
      pluginVersion: "1.0.0",
      publisher: "pub",
      trustTier: "community",
      secretKeyHex: null,
      publicKeyHex: "cafebabe".repeat(8),
      store,
    });

    await mw.recordAllowed("guards.register", {}, 5);

    const all = store.getAll();
    expect(all[0].signature).toBe("");
  });
});
