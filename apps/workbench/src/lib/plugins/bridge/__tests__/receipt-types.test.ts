/**
 * PluginActionReceipt Types Tests
 *
 * Tests for the receipt type definitions and createReceiptContent helper.
 * Verifies that receipt content has all required fields (plugin identity,
 * action type, params_hash via SHA-256, result, permission, duration).
 */

import { describe, it, expect } from "vitest";
import { createReceiptContent } from "../receipt-types";
import type {
  PluginActionReceipt,
  PluginActionReceiptContent,
} from "../receipt-types";

describe("createReceiptContent", () => {
  it("returns PluginActionReceiptContent with all fields populated", async () => {
    const content = await createReceiptContent(
      "plugin-a",
      "1.0.0",
      "pub",
      "community",
      "guards.register",
      { id: "g1" },
      "allowed",
      "guards:register",
      12,
    );

    expect(content.version).toBe("1.0.0");
    expect(content.receipt_id).toBeTruthy();
    expect(content.timestamp).toBeTruthy();
    expect(content.plugin.id).toBe("plugin-a");
    expect(content.plugin.version).toBe("1.0.0");
    expect(content.plugin.publisher).toBe("pub");
    expect(content.plugin.trust_tier).toBe("community");
    expect(content.action.type).toBe("guards.register");
    expect(content.action.result).toBe("allowed");
    expect(content.action.permission_checked).toBe("guards:register");
    expect(content.action.duration_ms).toBe(12);
  });

  it("produces a SHA-256 params_hash (64-char hex string), NOT the raw params", async () => {
    const content = await createReceiptContent(
      "plugin-a",
      "1.0.0",
      "pub",
      "community",
      "guards.register",
      { id: "g1" },
      "allowed",
      "guards:register",
      12,
    );

    // SHA-256 hex = 64 characters
    expect(content.action.params_hash).toMatch(/^[0-9a-f]{64}$/);
    // Should not be the JSON string of params
    expect(content.action.params_hash).not.toContain("{");
  });

  it("with result 'denied' populates the result field as 'denied'", async () => {
    const content = await createReceiptContent(
      "plugin-b",
      "2.0.0",
      "pub2",
      "community",
      "storage.set",
      { key: "x", value: "y" },
      "denied",
      "storage:write",
      0,
    );

    expect(content.action.result).toBe("denied");
  });
});

describe("PluginActionReceipt shape", () => {
  it("has content (PluginActionReceiptContent) + signature (hex string) + signer_public_key (hex string)", () => {
    // Type-level test: ensure the interface compiles with expected shape
    const receipt: PluginActionReceipt = {
      content: {
        version: "1.0.0",
        receipt_id: "abc-123",
        timestamp: new Date().toISOString(),
        plugin: {
          id: "plugin-a",
          version: "1.0.0",
          publisher: "pub",
          trust_tier: "community",
        },
        action: {
          type: "guards.register",
          params_hash: "a".repeat(64),
          result: "allowed",
          permission_checked: "guards:register",
          duration_ms: 12,
        },
      },
      signature: "deadbeef",
      signer_public_key: "cafebabe",
    };

    expect(receipt.content).toBeDefined();
    expect(receipt.signature).toBe("deadbeef");
    expect(receipt.signer_public_key).toBe("cafebabe");
    expect(receipt.content.plugin.id).toBe("plugin-a");
    expect(receipt.content.action.type).toBe("guards.register");
  });
});
