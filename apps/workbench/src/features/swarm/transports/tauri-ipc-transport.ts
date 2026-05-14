/** TransportAdapter backed by Tauri IPC (invoke/listen). */

import type {
  TransportAdapter,
  SwarmEnvelope,
} from "@/features/swarm/swarm-coordinator";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";

export class TauriIpcTransport implements TransportAdapter {
  private readonly subscriptions = new Set<string>();
  private readonly handlers = new Set<
    (topic: string, envelope: SwarmEnvelope) => void
  >();

  /** Stores unlisten promises since Tauri listen() is async but subscribe() is sync. */
  private readonly unlistenPromises = new Map<
    string,
    Promise<() => void>
  >();

  /** Checks for `window.__TAURI_INTERNALS__` presence (does not detect backend health). */
  isConnected(): boolean {
    return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
  }

  subscribe(topic: string): void {
    if (this.subscriptions.has(topic)) return;
    this.subscriptions.add(topic);

    const promise = listen<SwarmEnvelope>(topic, (event) => {
      for (const handler of this.handlers) {
        handler(topic, event.payload);
      }
    });
    this.unlistenPromises.set(topic, promise);
    void promise.catch(() => {
      this.subscriptions.delete(topic);
      this.unlistenPromises.delete(topic);
    });
  }

  unsubscribe(topic: string): void {
    this.subscriptions.delete(topic);
    const promise = this.unlistenPromises.get(topic);
    if (promise) {
      promise.then((unlisten) => unlisten()).catch(() => {});
      this.unlistenPromises.delete(topic);
    }
  }

  async publish(topic: string, envelope: SwarmEnvelope): Promise<void> {
    if (!this.isConnected()) {
      throw new Error("TauriIpcTransport: not connected");
    }
    await invoke("swarm_publish", { topic, envelope });
  }

  onMessage(
    handler: (topic: string, envelope: SwarmEnvelope) => void,
  ): void {
    this.handlers.add(handler);
  }

  offMessage(
    handler: (topic: string, envelope: SwarmEnvelope) => void,
  ): void {
    this.handlers.delete(handler);
  }
}
