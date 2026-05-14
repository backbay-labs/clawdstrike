/**
 * Plugin Revocation Client
 *
 * Connects to hushd SSE at /api/v1/events and listens for plugin_revoked
 * events. On event, calls pluginLoader.revokePlugin() to deactivate the
 * plugin immediately. On reconnect (EventSource open), fetches the full
 * revocation list from GET /api/v1/plugins/revocations and diffs via
 * revocationStore.sync() to catch up on missed revocations.
 *
 * Time-limited revocations that expired while offline are lifted on reconnect,
 * setting their state back to "deactivated" so they can be reactivated.
 *
 * Each SSE-driven revocation generates a signed receipt via receipt middleware
 * (if configured) for audit trail compliance.
 */

import type { PluginLoader } from "./plugin-loader";
import type { PluginRevocationStore, PluginRevocationEntry } from "./revocation-store";
import type { PluginRegistry } from "./plugin-registry";
import type { ReceiptMiddleware } from "./bridge/receipt-middleware";

// ---- Constants ----

const SSE_EVENTS_PATH = "/api/v1/events";
const REVOCATIONS_LIST_PATH = "/api/v1/plugins/revocations";
const RECONNECT_DELAY_MS = 5000;

// ---- Types ----

/**
 * Configuration for PluginRevocationClient.
 */
export interface PluginRevocationClientOptions {
  /** URL of the hushd instance (e.g. "http://localhost:9090"). */
  hushdUrl: string;
  /** Optional Bearer token for hushd authentication. */
  authToken?: string;
  /** PluginLoader instance for revoking plugins. */
  pluginLoader: PluginLoader;
  /** Revocation store for syncing remote revocations. */
  revocationStore: PluginRevocationStore;
  /** Plugin registry for state management. */
  registry: PluginRegistry;
  /** Optional receipt middleware for audit trail. */
  receiptMiddleware?: ReceiptMiddleware | null;
}

/**
 * Shape of the plugin_revoked SSE event data.
 */
interface PluginRevokedEventData {
  plugin_id: string;
  reason?: string;
  until?: number | null;
}

// ---- Client ----

/**
 * SSE-based client that listens to hushd for plugin_revoked events and
 * syncs revocation state on reconnect.
 *
 * Usage:
 *   const client = new PluginRevocationClient(options);
 *   client.connect();    // Start listening
 *   client.disconnect(); // Stop listening
 */
export class PluginRevocationClient {
  private options: PluginRevocationClientOptions;
  private eventSource: EventSource | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(options: PluginRevocationClientOptions) {
    this.options = options;
  }

  /**
   * Open SSE connection to hushd and start listening for plugin_revoked events.
   * On EventSource open, calls syncOnReconnect() to catch up on missed events.
   * On error, logs warning and schedules reconnect after 5 seconds.
   */
  connect(): void {
    // Clean up existing connection
    this.closeEventSource();
    this.clearReconnectTimer();

    let url = `${this.options.hushdUrl}${SSE_EVENTS_PATH}`;
    if (this.options.authToken) {
      url += `?token=${encodeURIComponent(this.options.authToken)}`;
    }
    const es = new EventSource(url);

    es.addEventListener("open", () => {
      void this.syncOnReconnect();
    });

    es.addEventListener("plugin_revoked", (event: MessageEvent) => {
      try {
        const data = JSON.parse(event.data) as PluginRevokedEventData;
        void this.handleRevocationEvent(data);
      } catch (err) {
        console.warn("[revocation-client] failed to parse plugin_revoked event:", err);
      }
    });

    es.addEventListener("error", () => {
      console.warn("[revocation-client] SSE connection error, scheduling reconnect");
      this.closeEventSource();
      this.scheduleReconnect();
    });

    this.eventSource = es;
  }

  /**
   * Close SSE connection and clear any pending reconnect timer.
   */
  disconnect(): void {
    this.closeEventSource();
    this.clearReconnectTimer();
  }

  // ---- Private ----

  /**
   * Handle a plugin_revoked SSE event: revoke the plugin and optionally
   * generate a receipt.
   */
  private async handleRevocationEvent(data: PluginRevokedEventData): Promise<void> {
    await this.options.pluginLoader.revokePlugin(data.plugin_id, {
      reason: data.reason,
      until: data.until,
    });

    // Generate receipt fire-and-forget
    if (this.options.receiptMiddleware) {
      void this.options.receiptMiddleware.recordDenied(
        "revocation.sse",
        { plugin_id: data.plugin_id },
        "revocation",
      );
    }
  }

  /**
   * Sync revocation list from hushd on reconnect.
   * Fetches GET /api/v1/plugins/revocations, diffs via sync(),
   * revokes newly-added plugins, and lifts expired ones.
   */
  private async syncOnReconnect(): Promise<void> {
    try {
      const headers: Record<string, string> = {};
      if (this.options.authToken) {
        headers["Authorization"] = `Bearer ${this.options.authToken}`;
      }

      const response = await fetch(
        `${this.options.hushdUrl}${REVOCATIONS_LIST_PATH}`,
        { headers },
      );

      if (!response.ok) {
        console.warn(
          "[revocation-client] failed to fetch revocations:",
          response.status,
        );
        return;
      }

      const remoteEntries = (await response.json()) as PluginRevocationEntry[];
      const diff = this.options.revocationStore.sync(remoteEntries);

      // Revoke newly-added plugins
      for (const pluginId of diff.added) {
        const entry = remoteEntries.find((e) => e.pluginId === pluginId);
        await this.options.pluginLoader.revokePlugin(pluginId, {
          reason: entry?.reason,
          until: entry?.until != null ? new Date(entry.until).getTime() : undefined,
        });
      }

      // Lift expired revocations
      for (const pluginId of diff.removed) {
        this.options.revocationStore.lift(pluginId);
        this.options.registry.setState(pluginId, "deactivated");
      }
    } catch (err) {
      console.warn("[revocation-client] syncOnReconnect error:", err);
    }
  }

  /**
   * Schedule a reconnect attempt after RECONNECT_DELAY_MS.
   */
  private scheduleReconnect(): void {
    this.clearReconnectTimer();
    this.reconnectTimer = setTimeout(() => {
      this.connect();
    }, RECONNECT_DELAY_MS);
  }

  /**
   * Close the EventSource if open.
   */
  private closeEventSource(): void {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
  }

  /**
   * Clear the reconnect timer if pending.
   */
  private clearReconnectTimer(): void {
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }
}
