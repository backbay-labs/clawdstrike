/**
 * Plugin Bridge Client
 *
 * The iframe-side RPC client that community plugins use to communicate with the
 * host workbench. Provides `call(method, params)` for request/response RPC and
 * `subscribe(event, handler)` for host-pushed event subscriptions.
 *
 * Communication is exclusively via window.postMessage. The client uses
 * monotonically increasing IDs for request/response correlation and enforces
 * a 30-second timeout on all calls to prevent leaked promises.
 */

import type {
  BridgeRequest,
  BridgeErrorCode,
} from "./types";
import { BRIDGE_TIMEOUT_MS, isBridgeMessage } from "./types";

// ---- BridgeError ----

/**
 * Error class thrown by the bridge client when a call fails.
 * Extends Error with a `code` property matching BridgeErrorCode.
 */
export class BridgeError extends Error {
  /** Machine-readable error code from the bridge protocol. */
  readonly code: BridgeErrorCode;

  constructor(code: BridgeErrorCode, message: string) {
    super(message);
    this.name = "BridgeError";
    this.code = code;
  }
}

// ---- Pending Entry ----

interface PendingEntry {
  resolve: (value: unknown) => void;
  reject: (reason: unknown) => void;
  timer: ReturnType<typeof setTimeout>;
}

// ---- PluginBridgeClient ----

/**
 * The client half of the postMessage bridge, running inside the plugin's
 * sandboxed iframe. Provides typed RPC to the host workbench.
 *
 * Usage:
 * ```ts
 * const bridge = new PluginBridgeClient();
 * const disposable = await bridge.call("guards.register", guardContribution);
 * const unsub = bridge.subscribe("policy.changed", (params) => { ... });
 * ```
 */
export class PluginBridgeClient {
  /** Pending call entries keyed by correlation ID. */
  private pending = new Map<string, PendingEntry>();

  /** Event subscription handlers keyed by event method name. */
  private subscriptions = new Map<string, Set<(params: unknown) => void>>();

  /** Monotonically increasing ID counter for request correlation. */
  private nextId = 0;

  /** Bound message event listener (null after destroy). */
  private listener: ((event: MessageEvent) => void) | null;

  /**
   * Create a new bridge client.
   * @param target The window to send messages to (defaults to window.parent).
   */
  constructor(private target: Window = window.parent) {
    this.listener = this.handleMessage.bind(this);
    window.addEventListener("message", this.listener);
  }

  /**
   * Send a typed RPC call to the host and await the response.
   *
   * @param method Namespaced method name (e.g. "guards.register")
   * @param params Optional serialized arguments
   * @returns Promise that resolves with the host's result or rejects with BridgeError
   */
  call<T = unknown>(method: string, params?: unknown): Promise<T> {
    const id = String(this.nextId++);
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(
          new BridgeError(
            "TIMEOUT",
            `Bridge call "${method}" timed out after ${BRIDGE_TIMEOUT_MS}ms`,
          ),
        );
      }, BRIDGE_TIMEOUT_MS);

      this.pending.set(id, {
        resolve: resolve as (value: unknown) => void,
        reject,
        timer,
      });

      const msg: BridgeRequest = { id, type: "request", method, params };
      this.target.postMessage(msg, "*");
    });
  }

  /**
   * Subscribe to a host-pushed event.
   *
   * @param event Namespaced event name (e.g. "policy.changed")
   * @param handler Callback invoked with the event params
   * @returns Unsubscribe function that removes this handler
   */
  subscribe(event: string, handler: (params: unknown) => void): () => void {
    let handlers = this.subscriptions.get(event);
    if (!handlers) {
      handlers = new Set();
      this.subscriptions.set(event, handlers);
    }
    handlers.add(handler);

    return () => {
      this.subscriptions.get(event)?.delete(handler);
    };
  }

  /**
   * Tear down the client: remove the message listener, reject all pending
   * calls with a TIMEOUT error, and clear subscriptions.
   */
  destroy(): void {
    if (this.listener) {
      window.removeEventListener("message", this.listener);
      this.listener = null;
    }

    // Reject all pending calls
    for (const [, entry] of this.pending) {
      clearTimeout(entry.timer);
      entry.reject(new BridgeError("TIMEOUT", "Bridge destroyed"));
    }
    this.pending.clear();
    this.subscriptions.clear();
  }

  // ---- Private ----

  /**
   * Handle incoming message events on the window.
   * Dispatches to pending call entries or event subscription handlers.
   */
  private handleMessage(event: MessageEvent): void {
    const data = event.data;
    if (!isBridgeMessage(data)) return;

    if (data.type === "response") {
      const entry = this.pending.get(data.id);
      if (entry) {
        clearTimeout(entry.timer);
        this.pending.delete(data.id);
        entry.resolve(data.result);
      }
    }

    if (data.type === "error") {
      const entry = this.pending.get(data.id);
      if (entry) {
        clearTimeout(entry.timer);
        this.pending.delete(data.id);
        entry.reject(new BridgeError(data.error.code, data.error.message));
      }
    }

    if (data.type === "event") {
      const handlers = this.subscriptions.get(data.method);
      if (handlers) {
        for (const handler of handlers) {
          handler(data.params);
        }
      }
    }
  }
}
