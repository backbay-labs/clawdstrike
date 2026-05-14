// Fleet Event Stream -- SSE connection lifecycle manager for hushd /api/v1/events.
//
// Uses fetch-based SSE (NOT EventSource) because hushd requires Bearer token
// authentication and the native EventSource API does not support custom headers.
//
// Follows the same streaming pattern proven in live-agent-tab.tsx but extracted
// into a standalone, non-React class so it can be driven by the Zustand store.

import {
  consumeSseMessages,
  resolveProxyBase,
} from "@/components/workbench/editor/live-agent-tab";
import type { FleetEvent, HeartbeatEventData, CheckEventData } from "./fleet-event-reducer";

// ---- Types ----

export type FleetSSEState = "idle" | "connecting" | "connected" | "disconnected" | "error";

export interface FleetEventStreamOptions {
  hushdUrl: string;
  getApiKey: () => string;
  onEvent: (event: FleetEvent) => void;
  onStateChange: (state: FleetSSEState) => void;
  /** Called after a successful reconnect so the store can do a full agent refresh. */
  onReconnect: () => void;
}

// ---- Constants ----

const SSE_EVENT_TYPES = [
  "agent_heartbeat",
  "check",
  "policy_updated",
  "policy_reloaded",
  "policy_bundle_update",
  "session_posture_transition",
].join(",");

const BACKOFF_DELAYS = [1000, 2000, 4000, 8000, 16000];

// ---- FleetEventStream ----

export class FleetEventStream {
  private opts: FleetEventStreamOptions;
  private abortController: AbortController | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private reconnectAttempt = 0;
  private isReconnect = false;

  constructor(opts: FleetEventStreamOptions) {
    this.opts = opts;
  }

  /**
   * Open the SSE connection to hushd. Fetches the event stream with Bearer
   * auth and begins parsing events as they arrive.
   */
  connect(): void {
    this.opts.onStateChange("connecting");

    const base = resolveProxyBase(this.opts.hushdUrl);
    const url = `${base}/api/v1/events?event_types=${encodeURIComponent(SSE_EVENT_TYPES)}`;
    const apiKey = this.opts.getApiKey();

    const controller = new AbortController();
    this.abortController = controller;

    void (async () => {
      try {
        const response = await fetch(url, {
          headers: {
            Authorization: `Bearer ${apiKey}`,
            Accept: "text/event-stream",
          },
          signal: controller.signal,
        });

        if (!response.ok || !response.body) {
          this.opts.onStateChange("disconnected");
          this.scheduleReconnect();
          return;
        }

        // Successful connection
        this.opts.onStateChange("connected");

        if (this.isReconnect) {
          this.opts.onReconnect();
        }

        this.reconnectAttempt = 0;
        this.isReconnect = false;

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        try {
          while (!controller.signal.aborted) {
            const { done, value } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });
            const parsed = consumeSseMessages(buffer);
            buffer = parsed.remainder;

            for (const message of parsed.messages) {
              if (message.data === "ping") continue;
              try {
                const data = JSON.parse(message.data) as Record<string, unknown>;
                const event = this.toFleetEvent(message.eventType, data);
                if (event) {
                  this.opts.onEvent(event);
                }
              } catch {
                // Skip malformed payloads without tearing down the stream
              }
            }
          }
        } finally {
          reader.releaseLock();
        }

        // Stream closed naturally (not aborted) -- reconnect
        if (!controller.signal.aborted) {
          this.opts.onStateChange("disconnected");
          this.scheduleReconnect();
        }
      } catch (err) {
        if (controller.signal.aborted) return;
        this.opts.onStateChange("disconnected");
        this.scheduleReconnect();
      }
    })();
  }

  /**
   * Disconnect from the SSE stream and cancel any pending reconnect timer.
   */
  disconnect(): void {
    if (this.reconnectTimer != null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.abortController) {
      this.abortController.abort();
      this.abortController = null;
    }
    this.reconnectAttempt = 0;
    this.isReconnect = false;
  }

  // ---- Private helpers ----

  private scheduleReconnect(): void {
    const delay = BACKOFF_DELAYS[Math.min(this.reconnectAttempt, BACKOFF_DELAYS.length - 1)];
    this.reconnectAttempt++;
    this.isReconnect = true;

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
  }

  private toFleetEvent(
    eventType: string,
    data: Record<string, unknown>,
  ): FleetEvent | null {
    switch (eventType) {
      case "agent_heartbeat":
        return {
          type: "agent_heartbeat",
          data: data as unknown as HeartbeatEventData,
        };
      case "check":
        return {
          type: "check",
          data: data as unknown as CheckEventData,
        };
      case "policy_updated":
        return { type: "policy_updated", data };
      case "policy_reloaded":
        return { type: "policy_reloaded", data };
      case "policy_bundle_update":
        return { type: "policy_bundle_update", data };
      case "session_posture_transition":
        return { type: "session_posture_transition", data };
      default:
        // Unknown event type -- pass through as generic
        return { type: eventType, data };
    }
  }
}
