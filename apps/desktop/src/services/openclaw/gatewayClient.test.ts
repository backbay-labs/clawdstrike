import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { GatewayRpcError, OpenClawGatewayClient } from "./gatewayClient";

type MessageEventLike = { data: string };
type CloseEventLike = { code: number; reason?: string };

class MockWebSocket {
  static instances: MockWebSocket[] = [];

  onopen: ((ev?: unknown) => void) | null = null;
  onmessage: ((ev: MessageEventLike) => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: ((ev: CloseEventLike) => void) | null = null;

  sent: string[] = [];
  readyState = 0;

  constructor(readonly url: string) {
    MockWebSocket.instances.push(this);
  }

  send(data: string): void {
    this.sent.push(String(data));
  }

  close(): void {
    this.readyState = 3;
    this.onclose?.({ code: 1000 });
  }

  emitOpen(): void {
    this.readyState = 1;
    this.onopen?.({});
  }

  emitMessage(frame: unknown): void {
    this.onmessage?.({ data: JSON.stringify(frame) });
  }

  emitClose(code = 1006, reason = ""): void {
    this.readyState = 3;
    this.onclose?.({ code, reason });
  }
}

describe("OpenClawGatewayClient", () => {
  const originalWebSocket = globalThis.WebSocket;

  beforeEach(() => {
    MockWebSocket.instances = [];
    vi.useFakeTimers();
    Object.defineProperty(globalThis, "WebSocket", { value: MockWebSocket, configurable: true });
  });

  afterEach(() => {
    vi.useRealTimers();
    Object.defineProperty(globalThis, "WebSocket", { value: originalWebSocket, configurable: true });
  });

  it("connects, emits status updates, and handles request/response", async () => {
    const client = new OpenClawGatewayClient("ws://example.test", { token: "t", instanceId: "sdr:test" });
    const statuses: string[] = [];
    client.onStatus((snap) => statuses.push(snap.status));

    const onEvent = vi.fn();
    client.onEvent(onEvent);

    const connectPromise = client.connect();

    expect(MockWebSocket.instances).toHaveLength(1);
    const ws = MockWebSocket.instances[0]!;

    ws.emitOpen();
    vi.advanceTimersByTime(150);

    expect(ws.sent).toHaveLength(1);
    const connectFrame = JSON.parse(ws.sent[0]!) as Record<string, unknown>;
    expect(connectFrame.type).toBe("req");
    expect(connectFrame.method).toBe("connect");
    expect(connectFrame.params).toMatchObject({
      role: "operator",
      auth: { token: "t" },
      client: { instanceId: "sdr:test" },
    });
    const connectReqId = String(connectFrame.id);

    ws.emitMessage({ type: "res", id: connectReqId, ok: true });
    await connectPromise;

    expect(client.getStatusSnapshot().status).toBe("connected");
    const connectingIndex = statuses.indexOf("connecting");
    const connectedIndex = statuses.indexOf("connected");
    expect(connectingIndex).toBeGreaterThanOrEqual(0);
    expect(connectedIndex).toBeGreaterThan(connectingIndex);

    const presencePromise = client.request("system-presence");
    expect(ws.sent).toHaveLength(2);
    const reqFrame = JSON.parse(ws.sent[1]!) as Record<string, unknown>;
    expect(reqFrame.type).toBe("req");
    expect(reqFrame.method).toBe("system-presence");

    ws.emitMessage({ type: "res", id: String(reqFrame.id), ok: true, payload: [{ id: 1 }] });
    await expect(presencePromise).resolves.toEqual([{ id: 1 }]);

    ws.emitMessage({ type: "event", event: "presence", payload: [{ client: "test" }] });
    expect(onEvent).toHaveBeenCalledWith({ type: "event", event: "presence", payload: [{ client: "test" }] });
  });

  it("returns the in-flight connect promise when connect is called twice", async () => {
    const client = new OpenClawGatewayClient("ws://example.test");

    const p1 = client.connect();
    const p2 = client.connect();
    expect(p2).toBe(p1);
    expect(MockWebSocket.instances).toHaveLength(1);

    const ws = MockWebSocket.instances[0]!;
    ws.emitOpen();
    vi.advanceTimersByTime(150);

    const connectFrame = JSON.parse(ws.sent[0]!) as Record<string, unknown>;
    ws.emitMessage({ type: "res", id: String(connectFrame.id), ok: true });

    await expect(Promise.all([p1, p2])).resolves.toEqual([undefined, undefined]);
    expect(client.getStatusSnapshot().status).toBe("connected");
  });

  it("omits empty auth from connect params", async () => {
    const client = new OpenClawGatewayClient("ws://example.test");
    const connectPromise = client.connect();
    const ws = MockWebSocket.instances[0]!;

    ws.emitOpen();
    vi.advanceTimersByTime(150);

    const connectFrame = JSON.parse(ws.sent[0]!) as Record<string, unknown>;
    const params = connectFrame.params as Record<string, unknown>;
    expect(params).not.toHaveProperty("auth");

    ws.emitMessage({ type: "res", id: String(connectFrame.id), ok: true });
    await connectPromise;
    expect(client.getStatusSnapshot().status).toBe("connected");
  });

  it("sends connect immediately when a connect.challenge event arrives", async () => {
    const client = new OpenClawGatewayClient("ws://example.test");
    const connectPromise = client.connect();
    const ws = MockWebSocket.instances[0]!;

    ws.emitOpen();
    ws.emitMessage({ type: "event", event: "connect.challenge", payload: { nonce: "x" } });
    expect(ws.sent).toHaveLength(1);

    vi.advanceTimersByTime(200);
    expect(ws.sent).toHaveLength(1);

    const connectFrame = JSON.parse(ws.sent[0]!) as Record<string, unknown>;
    ws.emitMessage({ type: "res", id: String(connectFrame.id), ok: true });
    await connectPromise;
    expect(client.getStatusSnapshot().status).toBe("connected");
  });

  it("rejects connect on gateway error response", async () => {
    const client = new OpenClawGatewayClient("ws://example.test");
    const connectPromise = client.connect();
    const ws = MockWebSocket.instances[0]!;

    ws.emitOpen();
    vi.advanceTimersByTime(150);
    const connectFrame = JSON.parse(ws.sent[0]!) as Record<string, unknown>;

    ws.emitMessage({ type: "res", id: String(connectFrame.id), ok: false, error: { message: "bad token" } });
    await expect(connectPromise).rejects.toThrow("bad token");
    expect(client.getStatusSnapshot().status).toBe("error");
  });

  it("rejects pending requests when the socket closes", async () => {
    const client = new OpenClawGatewayClient("ws://example.test");
    const connectPromise = client.connect();
    const ws = MockWebSocket.instances[0]!;

    ws.emitOpen();
    vi.advanceTimersByTime(150);
    const connectFrame = JSON.parse(ws.sent[0]!) as Record<string, unknown>;
    ws.emitMessage({ type: "res", id: String(connectFrame.id), ok: true });
    await connectPromise;

    const promise = client.request("system-presence", undefined, { timeoutMs: 1000 });
    ws.emitClose();
    await expect(promise).rejects.toThrow("disconnected");
    expect(client.getStatusSnapshot().status).toBe("disconnected");
  });

  it("rejects with GatewayRpcError metadata on RPC failure", async () => {
    const client = new OpenClawGatewayClient("ws://example.test");
    const connectPromise = client.connect();
    const ws = MockWebSocket.instances[0]!;

    ws.emitOpen();
    vi.advanceTimersByTime(150);
    const connectFrame = JSON.parse(ws.sent[0]!) as Record<string, unknown>;
    ws.emitMessage({ type: "res", id: String(connectFrame.id), ok: true });
    await connectPromise;

    const promise = client.request("system-presence");
    const reqFrame = JSON.parse(ws.sent[1]!) as Record<string, unknown>;

    ws.emitMessage({
      type: "res",
      id: String(reqFrame.id),
      ok: false,
      error: {
        code: "unauthorized",
        message: "bad token",
        retryable: true,
        retryAfterMs: 250,
        details: { scope: "operator.read" },
      },
    });

    let err: unknown = null;
    try {
      await promise;
    } catch (e) {
      err = e;
    }

    expect(err).toBeInstanceOf(GatewayRpcError);
    const rpcErr = err as GatewayRpcError;
    expect(rpcErr.code).toBe("unauthorized");
    expect(rpcErr.retryable).toBe(true);
    expect(rpcErr.retryAfterMs).toBe(250);
    expect(rpcErr.details).toEqual({ scope: "operator.read" });
    expect(rpcErr.message).toBe("bad token");
  });

  it("times out connect when the socket never opens", async () => {
    const client = new OpenClawGatewayClient("ws://example.test", { connectTimeoutMs: 50 });
    const connectPromise = client.connect();

    expect(MockWebSocket.instances).toHaveLength(1);
    vi.advanceTimersByTime(50);

    await expect(connectPromise).rejects.toThrow("connect timeout");
    expect(client.getStatusSnapshot()).toMatchObject({ status: "error", lastError: "connect timeout" });
  });

  it("cancels connect when manually disconnected while connecting", async () => {
    const client = new OpenClawGatewayClient("ws://example.test", { connectTimeoutMs: 2500 });
    const connectPromise = client.connect();

    const ws = MockWebSocket.instances[0]!;
    ws.emitOpen();

    client.disconnect();
    vi.advanceTimersByTime(2500);

    expect(ws.sent).toHaveLength(0);
    await expect(connectPromise).rejects.toThrow("disconnected");
    expect(client.getStatusSnapshot().status).toBe("disconnected");
  });

  it("times out requests when no response arrives", async () => {
    const client = new OpenClawGatewayClient("ws://example.test");
    const connectPromise = client.connect();
    const ws = MockWebSocket.instances[0]!;

    ws.emitOpen();
    vi.advanceTimersByTime(150);
    const connectFrame = JSON.parse(ws.sent[0]!) as Record<string, unknown>;
    ws.emitMessage({ type: "res", id: String(connectFrame.id), ok: true });
    await connectPromise;

    const promise = client.request("system-presence", undefined, { timeoutMs: 100 });
    vi.advanceTimersByTime(100);
    await expect(promise).rejects.toThrow("timeout after 100ms");
  });

  it("cancels auto-reconnect when manually disconnected", async () => {
    const client = new OpenClawGatewayClient("ws://example.test", {
      autoReconnect: true,
      reconnect: { maxAttempts: 3, initialDelayMs: 50, maxDelayMs: 50, backoffFactor: 1, jitterRatio: 0 },
    });

    const connectPromise = client.connect();
    const ws1 = MockWebSocket.instances[0]!;

    ws1.emitOpen();
    vi.advanceTimersByTime(150);
    const connectFrame1 = JSON.parse(ws1.sent[0]!) as Record<string, unknown>;
    ws1.emitMessage({ type: "res", id: String(connectFrame1.id), ok: true });
    await connectPromise;

    ws1.emitClose(1006, "gateway restart");
    expect(client.getStatusSnapshot().status).toBe("connecting");

    client.disconnect();
    expect(client.getStatusSnapshot().status).toBe("disconnected");

    vi.advanceTimersByTime(500);
    expect(MockWebSocket.instances).toHaveLength(1);
  });

  it("auto-reconnects with backoff after unexpected close", async () => {
    const client = new OpenClawGatewayClient("ws://example.test", {
      autoReconnect: true,
      reconnect: { maxAttempts: 3, initialDelayMs: 50, maxDelayMs: 50, backoffFactor: 1, jitterRatio: 0 },
    });

    const connectPromise = client.connect();
    const ws1 = MockWebSocket.instances[0]!;

    ws1.emitOpen();
    vi.advanceTimersByTime(150);
    const connectFrame1 = JSON.parse(ws1.sent[0]!) as Record<string, unknown>;
    ws1.emitMessage({ type: "res", id: String(connectFrame1.id), ok: true });
    await connectPromise;
    const firstConnectedAt = client.getStatusSnapshot().connectedAtMs;

    const connectedAgain = new Promise<void>((resolve) => {
      let unsubscribe: (() => void) | null = null;
      unsubscribe = client.onStatus((snap) => {
        if (snap.status === "connected" && snap.connectedAtMs && snap.connectedAtMs !== firstConnectedAt) {
          unsubscribe?.();
          resolve();
        }
      });
    });

    ws1.emitClose(1006, "gateway restart");
    expect(client.getStatusSnapshot().status).toBe("connecting");

    vi.advanceTimersByTime(50);
    expect(MockWebSocket.instances).toHaveLength(2);

    const ws2 = MockWebSocket.instances[1]!;
    ws2.emitOpen();
    vi.advanceTimersByTime(150);
    const connectFrame2 = JSON.parse(ws2.sent[0]!) as Record<string, unknown>;
    ws2.emitMessage({ type: "res", id: String(connectFrame2.id), ok: true });

    await connectedAgain;
    expect(client.getStatusSnapshot().status).toBe("connected");
  });

  it("surfaces an error once reconnect attempts are exhausted", async () => {
    const client = new OpenClawGatewayClient("ws://example.test", {
      autoReconnect: true,
      reconnect: { maxAttempts: 1, initialDelayMs: 50, maxDelayMs: 50, backoffFactor: 1, jitterRatio: 0 },
    });

    const connectPromise = client.connect();
    const ws1 = MockWebSocket.instances[0]!;

    ws1.emitOpen();
    vi.advanceTimersByTime(150);
    const connectFrame1 = JSON.parse(ws1.sent[0]!) as Record<string, unknown>;
    ws1.emitMessage({ type: "res", id: String(connectFrame1.id), ok: true });
    await connectPromise;

    const exhausted = new Promise<void>((resolve) => {
      let unsubscribe: (() => void) | null = null;
      unsubscribe = client.onStatus((snap) => {
        if (snap.status === "error") {
          unsubscribe?.();
          resolve();
        }
      });
    });

    ws1.emitClose(1006, "gateway restart");
    expect(client.getStatusSnapshot().status).toBe("connecting");

    vi.advanceTimersByTime(50);
    expect(MockWebSocket.instances).toHaveLength(2);

    const ws2 = MockWebSocket.instances[1]!;
    ws2.emitOpen();
    vi.advanceTimersByTime(150);
    expect(ws2.sent).toHaveLength(1);
    ws2.emitClose(1006, "still down");

    await exhausted;
    expect(client.getStatusSnapshot()).toMatchObject({ status: "error" });
  });
});
