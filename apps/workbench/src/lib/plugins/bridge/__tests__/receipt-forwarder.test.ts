/**
 * PluginReceiptForwarder Tests
 *
 * Tests for the hushd receipt forwarding service that batches and sends
 * plugin action receipts to the hushd audit endpoint. Verifies forward,
 * queue, flush, retry, and local-only (null hushdUrl) behaviors.
 */

import { describe, it, expect, beforeEach, vi, type Mock } from "vitest";
import type { PluginActionReceipt } from "../receipt-types";

// ---- Test Helpers ----

function makeReceipt(overrides?: {
  pluginId?: string;
  actionType?: string;
  result?: "allowed" | "denied" | "error";
}): PluginActionReceipt {
  return {
    content: {
      version: "1.0.0",
      receipt_id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
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

// ---- Tests ----

import {
  PluginReceiptForwarder,
  createReceiptForwarder,
} from "../receipt-forwarder";

describe("PluginReceiptForwarder", () => {
  let fetchMock: Mock;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  describe("forward() with hushdUrl configured", () => {
    it("sends a POST request to the hushd audit endpoint on success", async () => {
      fetchMock.mockResolvedValueOnce({ ok: true, status: 200 });
      const forwarder = new PluginReceiptForwarder({
        hushdUrl: "http://localhost:9090",
        authToken: "test-token",
      });
      const receipt = makeReceipt();

      await forwarder.forward(receipt);

      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [url, opts] = fetchMock.mock.calls[0];
      expect(url).toBe(
        "http://localhost:9090/api/v1/audit/plugin-receipts",
      );
      expect(opts.method).toBe("POST");
      expect(opts.headers["Content-Type"]).toBe("application/json");
      expect(opts.headers["Authorization"]).toBe("Bearer test-token");
      expect(JSON.parse(opts.body)).toEqual(receipt);
    });

    it("queues receipt when fetch throws (network error)", async () => {
      fetchMock.mockRejectedValueOnce(new Error("Network error"));
      const forwarder = new PluginReceiptForwarder({
        hushdUrl: "http://localhost:9090",
      });
      const receipt = makeReceipt();

      await forwarder.forward(receipt);

      expect(forwarder.getQueueSize()).toBe(1);
    });

    it("queues receipt when hushd returns non-2xx status", async () => {
      fetchMock.mockResolvedValueOnce({ ok: false, status: 500 });
      const forwarder = new PluginReceiptForwarder({
        hushdUrl: "http://localhost:9090",
      });
      const receipt = makeReceipt();

      await forwarder.forward(receipt);

      expect(forwarder.getQueueSize()).toBe(1);
    });

    it("does not queue receipt on successful forward", async () => {
      fetchMock.mockResolvedValueOnce({ ok: true, status: 200 });
      const forwarder = new PluginReceiptForwarder({
        hushdUrl: "http://localhost:9090",
      });
      const receipt = makeReceipt();

      await forwarder.forward(receipt);

      expect(forwarder.getQueueSize()).toBe(0);
    });

    it("does not include Authorization header when authToken is not provided", async () => {
      fetchMock.mockResolvedValueOnce({ ok: true, status: 200 });
      const forwarder = new PluginReceiptForwarder({
        hushdUrl: "http://localhost:9090",
      });
      const receipt = makeReceipt();

      await forwarder.forward(receipt);

      const [, opts] = fetchMock.mock.calls[0];
      expect(opts.headers["Authorization"]).toBeUndefined();
    });
  });

  describe("forward() with hushdUrl = null (local-only mode)", () => {
    it("silently drops the receipt without making any fetch call", async () => {
      const forwarder = new PluginReceiptForwarder({ hushdUrl: null });
      const receipt = makeReceipt();

      await forwarder.forward(receipt);

      expect(fetchMock).not.toHaveBeenCalled();
      expect(forwarder.getQueueSize()).toBe(0);
    });
  });

  describe("flush()", () => {
    it("sends all queued receipts and returns { sent, failed } counts", async () => {
      // First call fails to queue 2 receipts
      fetchMock
        .mockRejectedValueOnce(new Error("offline"))
        .mockRejectedValueOnce(new Error("offline"));

      const forwarder = new PluginReceiptForwarder({
        hushdUrl: "http://localhost:9090",
      });

      await forwarder.forward(makeReceipt({ pluginId: "p1" }));
      await forwarder.forward(makeReceipt({ pluginId: "p2" }));
      expect(forwarder.getQueueSize()).toBe(2);

      // Now flush with hushd back online
      fetchMock.mockResolvedValue({ ok: true, status: 200 });

      const result = await forwarder.flush();

      expect(result.sent).toBe(2);
      expect(result.failed).toBe(0);
      expect(forwarder.getQueueSize()).toBe(0);
    });

    it("keeps failed receipts in queue during flush", async () => {
      // Queue 2 receipts
      fetchMock
        .mockRejectedValueOnce(new Error("offline"))
        .mockRejectedValueOnce(new Error("offline"));

      const forwarder = new PluginReceiptForwarder({
        hushdUrl: "http://localhost:9090",
      });

      await forwarder.forward(makeReceipt({ pluginId: "p1" }));
      await forwarder.forward(makeReceipt({ pluginId: "p2" }));

      // Flush: one succeeds, one fails
      fetchMock
        .mockResolvedValueOnce({ ok: true, status: 200 })
        .mockRejectedValueOnce(new Error("still offline"));

      const result = await forwarder.flush();

      expect(result.sent).toBe(1);
      expect(result.failed).toBe(1);
      expect(forwarder.getQueueSize()).toBe(1);
    });

    it("returns { sent: 0, failed: 0 } when queue is empty", async () => {
      const forwarder = new PluginReceiptForwarder({
        hushdUrl: "http://localhost:9090",
      });

      const result = await forwarder.flush();

      expect(result.sent).toBe(0);
      expect(result.failed).toBe(0);
    });
  });

  describe("getQueueSize()", () => {
    it("reflects the number of queued receipts", async () => {
      fetchMock.mockRejectedValue(new Error("offline"));
      const forwarder = new PluginReceiptForwarder({
        hushdUrl: "http://localhost:9090",
      });

      expect(forwarder.getQueueSize()).toBe(0);

      await forwarder.forward(makeReceipt());
      expect(forwarder.getQueueSize()).toBe(1);

      await forwarder.forward(makeReceipt());
      expect(forwarder.getQueueSize()).toBe(2);
    });
  });
});

describe("createReceiptForwarder", () => {
  it("returns a configured PluginReceiptForwarder instance", () => {
    const forwarder = createReceiptForwarder({
      hushdUrl: "http://localhost:9090",
      authToken: "tok",
    });

    expect(forwarder).toBeInstanceOf(PluginReceiptForwarder);
  });

  it("works with hushdUrl = null for local-only mode", () => {
    const forwarder = createReceiptForwarder({ hushdUrl: null });

    expect(forwarder).toBeInstanceOf(PluginReceiptForwarder);
    expect(forwarder.getQueueSize()).toBe(0);
  });
});
