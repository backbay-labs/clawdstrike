/**
 * Plugin Receipt Forwarder
 *
 * Forwards plugin action receipts to a hushd audit endpoint for fleet-wide
 * visibility. Supports queuing when hushd is unreachable and flushing
 * queued receipts on reconnect.
 *
 * Design: Forwarding is best-effort (fail-open). Receipt *generation* is
 * fail-closed (handled in receipt-middleware.ts), but forwarding to hushd
 * should never block the plugin bridge or crash on network errors.
 */

import type { PluginActionReceipt } from "./receipt-types";

// ---- Configuration ----

export interface ReceiptForwarderOptions {
  /** URL of the hushd instance (e.g. "http://localhost:9090"). Null for local-only mode. */
  hushdUrl: string | null;
  /** Optional Bearer token for hushd authentication. */
  authToken?: string;
}

// ---- Forwarder ----

const AUDIT_ENDPOINT = "/api/v1/audit/plugin-receipts";

/**
 * Forwards plugin action receipts to a hushd audit endpoint.
 *
 * When hushd is unreachable or returns non-2xx, receipts are queued
 * for retry via flush(). When hushdUrl is null, forward() is a no-op
 * (local-only mode -- receipts are still in the local receipt store).
 */
export class PluginReceiptForwarder {
  private readonly hushdUrl: string | null;
  private readonly authToken: string | undefined;
  private queue: PluginActionReceipt[] = [];

  constructor(options: ReceiptForwarderOptions) {
    this.hushdUrl = options.hushdUrl;
    this.authToken = options.authToken;
  }

  /**
   * Forward a receipt to hushd. On failure, queues for retry.
   * When hushdUrl is null, this is a silent no-op.
   */
  async forward(receipt: PluginActionReceipt): Promise<void> {
    if (this.hushdUrl === null) {
      return;
    }

    const success = await this.sendToHushd(receipt);
    if (!success) {
      this.queue.push(receipt);
    }
  }

  /**
   * Attempt to send all queued receipts to hushd.
   * Successfully sent receipts are removed from the queue.
   * Returns counts of sent and failed receipts.
   */
  async flush(): Promise<{ sent: number; failed: number }> {
    if (this.queue.length === 0) {
      return { sent: 0, failed: 0 };
    }

    const remaining: PluginActionReceipt[] = [];
    let sent = 0;

    for (const receipt of this.queue) {
      const success = await this.sendToHushd(receipt);
      if (success) {
        sent++;
      } else {
        remaining.push(receipt);
      }
    }

    this.queue = remaining;
    return { sent, failed: remaining.length };
  }

  /** Number of receipts currently queued for retry. */
  getQueueSize(): number {
    return this.queue.length;
  }

  // ---- Private ----

  /**
   * Attempt to POST a receipt to the hushd audit endpoint.
   * Returns true on success (2xx), false on any failure.
   * Never throws -- all errors are caught and result in false.
   */
  private async sendToHushd(receipt: PluginActionReceipt): Promise<boolean> {
    try {
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
      };

      if (this.authToken !== undefined) {
        headers["Authorization"] = `Bearer ${this.authToken}`;
      }

      const response = await fetch(`${this.hushdUrl}${AUDIT_ENDPOINT}`, {
        method: "POST",
        headers,
        body: JSON.stringify(receipt),
      });

      return response.ok;
    } catch {
      // Network error -- hushd unreachable
      return false;
    }
  }
}

// ---- Factory ----

/**
 * Create a configured PluginReceiptForwarder instance.
 */
export function createReceiptForwarder(
  options: ReceiptForwarderOptions,
): PluginReceiptForwarder {
  return new PluginReceiptForwarder(options);
}
