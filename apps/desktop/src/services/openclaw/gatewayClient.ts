import type {
  GatewayConnectParams,
  GatewayEventFrame,
  GatewayFrame,
  GatewayResponseError,
} from "./gatewayProtocol";
import { createRequestId, GATEWAY_PROTOCOL_VERSION, safeParseGatewayFrame } from "./gatewayProtocol";

export type GatewayConnectionStatus = "disconnected" | "connecting" | "connected" | "error";

export type GatewayClientOptions = {
  clientId?: string;
  clientDisplayName?: string;
  clientPlatform?: string;
  /**
   * OpenClaw connect schema currently validates `client.mode` via literals.
   * In 2026.2.x, the only accepted operator client is `cli` (mode must also be `cli`).
   * Keep this configurable for future schema expansions.
   */
  clientMode?: string;
  protocolVersion?: number;
  scopes?: GatewayConnectParams["scopes"];
  token?: string;
  deviceToken?: string;
  instanceId?: string;
  autoReconnect?: boolean;
  reconnect?: {
    maxAttempts?: number;
    initialDelayMs?: number;
    maxDelayMs?: number;
    backoffFactor?: number;
    jitterRatio?: number;
  };
  connectTimeoutMs?: number;
  connectDelayMs?: number;
  /**
   * When `true`, a clean WebSocket close (code 1000) will still trigger
   * auto-reconnect.  Useful when the gateway sends 1000 during planned
   * restarts and the client should transparently reconnect.
   * Default: `false` (backward-compatible — clean close skips reconnect).
   */
  reconnectOnCleanClose?: boolean;
  /**
   * Maximum number of automatic retries for RPC requests that fail with a
   * retryable `GatewayRpcError`.  Set to `0` to disable retries.
   * Default: `2`.
   */
  maxRetries?: number;
};

export type GatewayStatusSnapshot = {
  status: GatewayConnectionStatus;
  lastError: string | null;
  connectedAtMs: number | null;
  lastMessageAtMs: number | null;
};

export class GatewayRpcError extends Error {
  readonly code?: string;
  readonly details?: unknown;
  readonly retryable?: boolean;
  readonly retryAfterMs?: number;

  constructor(message: string, opts?: { code?: string; details?: unknown; retryable?: boolean; retryAfterMs?: number }) {
    super(message);
    this.name = "GatewayRpcError";
    this.code = opts?.code;
    this.details = opts?.details;
    this.retryable = opts?.retryable;
    this.retryAfterMs = opts?.retryAfterMs;
  }
}

type PendingRequest = {
  resolve: (value: unknown) => void;
  reject: (reason: unknown) => void;
  timeoutId: ReturnType<typeof setTimeout>;
};

export class OpenClawGatewayClient {
  private ws: WebSocket | null = null;
  private status: GatewayConnectionStatus = "disconnected";
  private lastError: string | null = null;
  private connectedAtMs: number | null = null;
  private lastMessageAtMs: number | null = null;

  private pending = new Map<string, PendingRequest>();
  private eventListeners = new Set<(frame: GatewayEventFrame) => void>();
  private statusListeners = new Set<(snapshot: GatewayStatusSnapshot) => void>();
  private lastEmittedSnapshot: GatewayStatusSnapshot | null = null;

  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private reconnectAttempt = 0;
  private manualDisconnect = false;

  private connectInFlight: Promise<void> | null = null;
  private connectAbort: ((err: Error) => void) | null = null;
  private connectTimeoutId: ReturnType<typeof setTimeout> | null = null;
  private connectDelayId: ReturnType<typeof setTimeout> | null = null;
  private connectGeneration = 0;

  constructor(
    readonly gatewayUrl: string,
    private readonly options: GatewayClientOptions = {}
  ) {}

  getStatusSnapshot(): GatewayStatusSnapshot {
    return {
      status: this.status,
      lastError: this.lastError,
      connectedAtMs: this.connectedAtMs,
      lastMessageAtMs: this.lastMessageAtMs,
    };
  }

  onEvent(listener: (frame: GatewayEventFrame) => void): () => void {
    this.eventListeners.add(listener);
    return () => this.eventListeners.delete(listener);
  }

  onStatus(listener: (snapshot: GatewayStatusSnapshot) => void): () => void {
    this.statusListeners.add(listener);
    const snap = this.getStatusSnapshot();
    listener(snap);
    this.lastEmittedSnapshot = snap;
    return () => this.statusListeners.delete(listener);
  }

  private setStatus(status: GatewayConnectionStatus, lastError: string | null = this.lastError) {
    this.status = status;
    this.lastError = lastError;
    this.emitStatus();
  }

  private emitStatus() {
    const snap = this.getStatusSnapshot();
    const prev = this.lastEmittedSnapshot;
    if (
      prev &&
      prev.status === snap.status &&
      prev.lastError === snap.lastError &&
      prev.connectedAtMs === snap.connectedAtMs &&
      prev.lastMessageAtMs === snap.lastMessageAtMs
    ) {
      return;
    }

    this.lastEmittedSnapshot = snap;
    for (const listener of this.statusListeners) listener(snap);
  }

  private clearReconnectTimer() {
    if (this.reconnectTimer === null) return;
    clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
  }

  private clearConnectTimers() {
    if (this.connectTimeoutId !== null) {
      clearTimeout(this.connectTimeoutId);
      this.connectTimeoutId = null;
    }
    if (this.connectDelayId !== null) {
      clearTimeout(this.connectDelayId);
      this.connectDelayId = null;
    }
  }

  private abortConnect(err: Error) {
    const abort = this.connectAbort;
    this.connectAbort = null;
    abort?.(err);
  }

  private teardownSocket() {
    this.clearConnectTimers();
    const ws = this.ws;
    this.ws = null;

    if (ws) {
      ws.onopen = null;
      ws.onmessage = null;
      ws.onerror = null;
      ws.onclose = null;
      try {
        ws.close();
      } catch {
        // ignore
      }
    }

    for (const [, pending] of this.pending) {
      clearTimeout(pending.timeoutId);
      pending.reject(new Error("disconnected"));
    }
    this.pending.clear();

    this.connectedAtMs = null;
    this.lastMessageAtMs = null;
  }

  private scheduleReconnect(trigger: string) {
    if (!this.options.autoReconnect) return;
    if (this.manualDisconnect) return;

    const config = this.options.reconnect;
    const maxAttempts = Math.max(1, config?.maxAttempts ?? 12);
    if (this.reconnectAttempt >= maxAttempts) {
      this.setStatus("error", this.lastError ?? `reconnect attempts exhausted (${trigger})`);
      return;
    }

    this.clearReconnectTimer();

    const attempt = this.reconnectAttempt;
    this.reconnectAttempt += 1;

    const initialDelayMs = Math.max(25, config?.initialDelayMs ?? 350);
    const maxDelayMs = Math.max(initialDelayMs, config?.maxDelayMs ?? 15_000);
    const backoffFactor = Math.max(1.0, config?.backoffFactor ?? 1.6);
    const jitterRatio = Math.max(0, Math.min(1, config?.jitterRatio ?? 0.15));

    const expDelay = Math.min(maxDelayMs, Math.round(initialDelayMs * Math.pow(backoffFactor, attempt)));
    const jitterMs = jitterRatio ? Math.round(expDelay * jitterRatio * (Math.random() * 2 - 1)) : 0;
    const delayMs = Math.max(0, expDelay + jitterMs);

    this.setStatus("connecting", this.lastError);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      void this.connect().catch((err) => {
        const message = err instanceof Error ? err.message : String(err);
        this.lastError = message;
        this.emitStatus();
        this.scheduleReconnect("connect failed");
      });
    }, delayMs);
  }

  connect(): Promise<void> {
    if (this.status === "connected") return Promise.resolve();
    if (this.connectInFlight) return this.connectInFlight;

    let inFlight: Promise<void>;
    inFlight = this.connectInternal().finally(() => {
      if (this.connectInFlight === inFlight) this.connectInFlight = null;
    });
    this.connectInFlight = inFlight;
    return inFlight;
  }

  private async connectInternal(): Promise<void> {
    const generation = ++this.connectGeneration;

    this.manualDisconnect = false;
    this.clearReconnectTimer();
    this.teardownSocket();
    this.setStatus("connecting", null);

    const ws = new WebSocket(this.gatewayUrl);
    this.ws = ws;

    const abortPromise = new Promise<never>((_resolve, reject) => {
      this.connectAbort = (err: Error) => reject(err);
    });

    const connectReqId = createRequestId("connect");
    const connectPromise = new Promise<void>((resolve, reject) => {
      const clearTimeouts = () => this.clearConnectTimers();

      const openTimeoutMs = Math.max(1, this.options.connectTimeoutMs ?? 10_000);
      this.connectTimeoutId = setTimeout(() => {
        clearTimeouts();
        reject(new Error("connect timeout"));
      }, openTimeoutMs);

      const finishOk = () => {
        clearTimeouts();
        resolve();
      };
      const finishErr = (err: unknown) => {
        clearTimeouts();
        reject(err);
      };

      let connectSent = false;
      const sendConnect = () => {
        if (connectSent) return;
        if (this.manualDisconnect) return;
        if (this.ws !== ws) return;
        connectSent = true;
        if (this.connectDelayId !== null) {
          clearTimeout(this.connectDelayId);
          this.connectDelayId = null;
        }

        const protocol = this.options.protocolVersion ?? GATEWAY_PROTOCOL_VERSION;
        // When v4 ships, change to min_protocol: 3, max_protocol: 4 with
        // conditional v4 handling based on the negotiated version.
        const params: GatewayConnectParams = {
          minProtocol: protocol,
          maxProtocol: protocol,
          client: {
            // OpenClaw Gateway currently requires literal `cli` identifiers for operator clients.
            id: this.options.clientId ?? "cli",
            displayName: this.options.clientDisplayName ?? "SDR Desktop",
            version: import.meta.env?.VITE_APP_VERSION ?? "dev",
            platform: this.options.clientPlatform ?? "tauri",
            mode: this.options.clientMode ?? "cli",
            instanceId: this.options.instanceId,
          },
          role: "operator",
          scopes: this.options.scopes ?? ["operator.read", "operator.write", "operator.approvals", "operator.pairing"],
          auth: {
            token: this.options.token,
            deviceToken: this.options.deviceToken,
            password: this.options.deviceToken, // Rust protocol compatibility
          },
          locale: typeof navigator === "undefined" ? "en-US" : navigator.language,
          userAgent: typeof navigator === "undefined" ? "unknown" : navigator.userAgent,
        };

        // Strip empty auth to avoid schema rejects on some gateways.
        if (!params.auth?.token && !params.auth?.deviceToken) delete params.auth;

        try {
          ws.send(
            JSON.stringify({
              type: "req",
              id: connectReqId,
              method: "connect",
              params,
            })
          );
        } catch (err) {
          finishErr(err);
        }
      };

      ws.onopen = () => {
        // Some gateways send a pre-connect challenge; others wait for connect.
        // Delay a beat so we can catch a challenge first when present.
        const connectDelayMs = Math.max(0, this.options.connectDelayMs ?? 150);
        this.connectDelayId = setTimeout(() => {
          this.connectDelayId = null;
          sendConnect();
        }, connectDelayMs);
      };

      ws.onerror = () => {
        finishErr(new Error("websocket error"));
      };

      ws.onclose = (ev) => {
        const reason = ev.reason ? `: ${ev.reason}` : "";
        finishErr(new Error(`websocket closed (${ev.code})${reason}`));
      };

      ws.onmessage = (evt) => {
        const text = String(evt.data ?? "");
        const frame = safeParseGatewayFrame(text);
        if (!frame) return;

        this.lastMessageAtMs = Date.now();

        if (frame.type === "event") {
          if (frame.event === "connect.challenge") {
            // For now we rely on token-based auth. Signed challenges are supported
            // via device identity (future wave); still send connect promptly.
            sendConnect();
          }
          for (const listener of this.eventListeners) listener(frame);
          return;
        }

        if (frame.type === "res" && frame.id === connectReqId) {
          if (frame.ok) {
            finishOk();
            return;
          }

          const err = normalizeGatewayError(frame.error, "connect failed");
          this.setStatus("error", err.message);
          finishErr(err);
          return;
        }
      };
    });

    try {
      await Promise.race([connectPromise, abortPromise]);
      if (this.manualDisconnect) throw new Error("disconnected");
      if (this.ws !== ws) throw new Error("disconnected");
      if (generation !== this.connectGeneration) throw new Error("disconnected");
      if (typeof ws.readyState === "number" && ws.readyState !== 1) throw new Error("disconnected");
    } catch (err) {
      this.teardownSocket();
      const message = err instanceof Error ? err.message : String(err);
      if (this.manualDisconnect || generation !== this.connectGeneration) {
        this.setStatus("disconnected", this.lastError);
      } else {
        this.setStatus("error", message);
      }
      throw err;
    } finally {
      this.connectAbort = null;
    }

    this.reconnectAttempt = 0;

    // Promote message handler now that connect is complete.
    ws.onmessage = (evt) => {
      const text = String(evt.data ?? "");
      const frame = safeParseGatewayFrame(text);
      if (!frame) return;

      this.lastMessageAtMs = Date.now();
      if (frame.type === "event") {
        for (const listener of this.eventListeners) listener(frame);
        return;
      }

      if (frame.type === "res") {
        const pending = this.pending.get(frame.id);
        if (!pending) return;
        this.pending.delete(frame.id);
        clearTimeout(pending.timeoutId);
        if (frame.ok) pending.resolve(frame.payload);
        else pending.reject(normalizeGatewayError(frame.error, "request failed"));
      }
    };

    ws.onclose = (ev) => {
      this.ws = null;
      this.connectedAtMs = null;
      this.lastMessageAtMs = null;

      const reason = ev.reason ? `: ${ev.reason}` : "";
      const message = `websocket closed (${ev.code})${reason}`;
      this.lastError = this.manualDisconnect ? this.lastError : message;

      this.setStatus("disconnected", this.lastError);
      for (const [, pending] of this.pending) {
        clearTimeout(pending.timeoutId);
        pending.reject(new Error("disconnected"));
      }
      this.pending.clear();

      if (this.manualDisconnect) return;
      if (ev.code === 1000 && !this.options.reconnectOnCleanClose) return;
      this.scheduleReconnect("socket closed");
    };

    ws.onerror = () => {
      this.setStatus("error", "websocket error");
    };

    this.connectedAtMs = Date.now();
    this.setStatus("connected", null);
  }

  disconnect(): void {
    this.manualDisconnect = true;
    this.connectGeneration += 1;
    this.abortConnect(new Error("disconnected"));
    this.clearReconnectTimer();
    this.teardownSocket();
    this.setStatus("disconnected", this.lastError);
  }

  send(frame: GatewayFrame): void {
    if (!this.ws || this.status !== "connected") throw new Error("not connected");
    this.ws.send(JSON.stringify(frame));
  }

  async request<TPayload = unknown>(
    method: string,
    params?: unknown,
    opts?: { timeoutMs?: number; id?: string; retries?: number }
  ): Promise<TPayload> {
    const maxRetries = Math.max(0, opts?.retries ?? this.options.maxRetries ?? 2);

    let lastError: unknown;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const attemptOpts =
          attempt === 0 || !opts
            ? opts
            : { ...opts, id: undefined };
        return await this.requestOnce<TPayload>(method, params, attemptOpts);
      } catch (err) {
        lastError = err;

        // Only retry GatewayRpcErrors that are explicitly marked retryable.
        if (
          attempt < maxRetries &&
          err instanceof GatewayRpcError &&
          err.retryable === true
        ) {
          const delayMs = Math.min(err.retryAfterMs ?? 1000, 5000);
          await new Promise<void>((resolve) => setTimeout(resolve, delayMs));
          continue;
        }

        throw err;
      }
    }

    // Should be unreachable, but satisfies the compiler.
    throw lastError;
  }

  private requestOnce<TPayload = unknown>(
    method: string,
    params?: unknown,
    opts?: { timeoutMs?: number; id?: string }
  ): Promise<TPayload> {
    if (!this.ws || this.status !== "connected") {
      return Promise.reject(new Error("not connected"));
    }

    const id = opts?.id ?? createRequestId(method);
    const timeoutMs = Math.max(1, opts?.timeoutMs ?? 12_000);

    const frame: GatewayFrame = { type: "req", id, method, params };

    return new Promise<TPayload>((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`timeout after ${timeoutMs}ms`));
      }, timeoutMs);

      this.pending.set(id, {
        resolve: resolve as unknown as (value: unknown) => void,
        reject: reject as unknown as (reason: unknown) => void,
        timeoutId,
      });
      try {
        this.send(frame);
      } catch (err) {
        clearTimeout(timeoutId);
        this.pending.delete(id);
        reject(err);
      }
    });
  }
}

function normalizeGatewayError(error: GatewayResponseError | undefined, fallbackMessage: string): GatewayRpcError {
  if (!error) return new GatewayRpcError(fallbackMessage);
  return new GatewayRpcError(error.message || fallbackMessage, {
    code: error.code,
    details: error.details,
    retryable: error.retryable,
    retryAfterMs: error.retryAfterMs,
  });
}
