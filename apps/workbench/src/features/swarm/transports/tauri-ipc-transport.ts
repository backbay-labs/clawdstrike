/**
 * TauriIpcTransport -- TransportAdapter backed by Tauri's IPC layer.
 *
 * Bridges the web frontend SwarmCoordinator to the Rust backend via
 * Tauri's `invoke` (publish) and `listen` (subscribe) APIs.
 *
 * Topic-agnostic: all existing and new channels work automatically.
 *
 * @see swarm-coordinator.ts -- TransportAdapter interface
 * @see PROTOCOL-SPEC.md -- section 6.4 (Tauri IPC transport design)
 */

import type {
  TransportAdapter,
  SwarmEnvelope,
} from "@/features/swarm/swarm-coordinator";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";

/**
 * Transport adapter for Tauri desktop applications.
 *
 * Uses Tauri's `listen()` for subscribing to topics and `invoke()` for
 * publishing envelopes to the Rust backend. Connection availability is
 * determined by the presence of `window.__TAURI__`.
 */
export class TauriIpcTransport implements TransportAdapter {
  /** Currently subscribed topics. */
  private readonly subscriptions = new Set<string>();

  /** Registered message handlers. */
  private readonly handlers = new Set<
    (topic: string, envelope: SwarmEnvelope) => void
  >();

  /**
   * Pending unlisten promises keyed by topic.
   *
   * Tauri's `listen()` is async (returns `Promise<UnlistenFn>`), but
   * `subscribe()` in TransportAdapter is synchronous. We store the promise
   * and await it in `unsubscribe()`.
   */
  private readonly unlistenPromises = new Map<
    string,
    Promise<() => void>
  >();

  // -----------------------------------------------------------------------
  // TransportAdapter implementation
  // -----------------------------------------------------------------------

  /**
   * Whether the Tauri runtime is available.
   *
   * Note: This performs a static check for `window.__TAURI__` presence.
   * It does NOT detect backend crashes, IPC channel failures, or the
   * Rust process being unresponsive. A `true` return only means the
   * Tauri JS bridge was injected at page load.
   */
  isConnected(): boolean {
    return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
  }

  /**
   * Subscribe to a topic. Idempotent -- calling twice with the same topic
   * does not double-register.
   */
  subscribe(topic: string): void {
    if (this.subscriptions.has(topic)) return;
    this.subscriptions.add(topic);

    const promise = listen<SwarmEnvelope>(topic, (event) => {
      for (const handler of this.handlers) {
        handler(topic, event.payload);
      }
    });
    this.unlistenPromises.set(topic, promise);
  }

  /**
   * Unsubscribe from a topic. Calls the unlisten function returned by
   * Tauri `listen()`. No-op if the topic is not subscribed.
   */
  unsubscribe(topic: string): void {
    this.subscriptions.delete(topic);
    const promise = this.unlistenPromises.get(topic);
    if (promise) {
      promise.then((unlisten) => unlisten()).catch(() => {});
      this.unlistenPromises.delete(topic);
    }
  }

  /**
   * Publish an envelope to a topic via Tauri `invoke`.
   * Rejects if the transport is not connected.
   */
  async publish(topic: string, envelope: SwarmEnvelope): Promise<void> {
    if (!this.isConnected()) {
      throw new Error("TauriIpcTransport: not connected");
    }
    await invoke("swarm_publish", { topic, envelope });
  }

  /** Register a handler for incoming messages on any subscribed topic. */
  onMessage(
    handler: (topic: string, envelope: SwarmEnvelope) => void,
  ): void {
    this.handlers.add(handler);
  }

  /** Remove a previously registered message handler. */
  offMessage(
    handler: (topic: string, envelope: SwarmEnvelope) => void,
  ): void {
    this.handlers.delete(handler);
  }
}
