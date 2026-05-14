import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { FleetEventStream, type FleetSSEState } from "@/features/fleet/fleet-event-stream";
import type { FleetEvent } from "@/features/fleet/fleet-event-reducer";

// ---- Mocks ----

function mockReadableStream(chunks: string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  let index = 0;
  return new ReadableStream({
    pull(controller) {
      if (index < chunks.length) {
        controller.enqueue(encoder.encode(chunks[index]));
        index++;
      } else {
        controller.close();
      }
    },
  });
}

function createMockFetch(opts: {
  ok?: boolean;
  status?: number;
  body?: ReadableStream<Uint8Array> | null;
} = {}) {
  const { ok = true, status = 200, body = mockReadableStream([]) } = opts;
  return vi.fn().mockResolvedValue({
    ok,
    status,
    body,
  });
}

describe("FleetEventStream", () => {
  let originalFetch: typeof globalThis.fetch;
  let stateChanges: FleetSSEState[];
  let receivedEvents: FleetEvent[];
  let reconnectCalled: boolean;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    stateChanges = [];
    receivedEvents = [];
    reconnectCalled = false;
    vi.useFakeTimers();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.useRealTimers();
  });

  function createStream(overrides: Partial<ConstructorParameters<typeof FleetEventStream>[0]> = {}) {
    return new FleetEventStream({
      hushdUrl: "http://localhost:9876",
      getApiKey: () => "test-api-key",
      onEvent: (event) => receivedEvents.push(event),
      onStateChange: (state) => stateChanges.push(state),
      onReconnect: () => { reconnectCalled = true; },
      ...overrides,
    });
  }

  it("connect() calls fetch with correct URL including event_types filter", async () => {
    const mockFetch = createMockFetch({
      body: mockReadableStream([]),
    });
    globalThis.fetch = mockFetch;

    const stream = createStream();
    stream.connect();

    // Let the fetch resolve
    await vi.advanceTimersByTimeAsync(0);

    expect(mockFetch).toHaveBeenCalledOnce();
    const [url] = mockFetch.mock.calls[0];
    expect(url).toContain("/api/v1/events");
    expect(url).toContain("event_types=agent_heartbeat");
    expect(url).toContain("check");
    expect(url).toContain("policy_updated");
    expect(url).toContain("policy_reloaded");
  });

  it("connect() includes Bearer auth header from credential getter", async () => {
    const mockFetch = createMockFetch({
      body: mockReadableStream([]),
    });
    globalThis.fetch = mockFetch;

    const stream = createStream({ getApiKey: () => "my-secret-key" });
    stream.connect();

    await vi.advanceTimersByTimeAsync(0);

    expect(mockFetch).toHaveBeenCalledOnce();
    const [, options] = mockFetch.mock.calls[0];
    expect(options.headers).toBeDefined();
    expect(options.headers.Authorization).toBe("Bearer my-secret-key");
    expect(options.headers.Accept).toBe("text/event-stream");
  });

  it("disconnect() aborts the fetch controller", async () => {
    const abortSpy = vi.fn();
    const mockFetch = vi.fn().mockImplementation((_url: string, opts: RequestInit) => {
      // Spy on the abort signal
      opts.signal?.addEventListener("abort", abortSpy);
      // Return a stream that never ends
      return Promise.resolve({
        ok: true,
        status: 200,
        body: mockReadableStream([]),
      });
    });
    globalThis.fetch = mockFetch;

    const stream = createStream();
    stream.connect();
    await vi.advanceTimersByTimeAsync(0);

    stream.disconnect();
    expect(abortSpy).toHaveBeenCalled();
  });

  it("state transitions: idle -> connecting -> connected -> disconnected", async () => {
    const sseData = 'event: agent_heartbeat\ndata: {"endpoint_agent_id":"a1","timestamp":"2026-03-19T10:00:00Z"}\n\n';
    const mockFetch = createMockFetch({
      body: mockReadableStream([sseData]),
    });
    globalThis.fetch = mockFetch;

    const stream = createStream();

    // Initial state is not tracked (idle is the default before connect)
    stream.connect();

    // Should transition to connecting
    expect(stateChanges).toContain("connecting");

    // Let fetch and reading resolve
    await vi.advanceTimersByTimeAsync(0);

    // Should have connected
    expect(stateChanges).toContain("connected");

    // Stream ends (body fully read) -> disconnected
    await vi.advanceTimersByTimeAsync(100);
    expect(stateChanges).toContain("disconnected");
  });

  it("exponential backoff on connection failure (1s, 2s, 4s, 8s, 16s max)", async () => {
    let fetchCallCount = 0;
    const mockFetch = vi.fn().mockImplementation(() => {
      fetchCallCount++;
      return Promise.resolve({ ok: false, status: 500, body: null });
    });
    globalThis.fetch = mockFetch;

    const stream = createStream();
    stream.connect();

    // First call happens immediately
    await vi.advanceTimersByTimeAsync(0);
    expect(fetchCallCount).toBe(1);

    // After 1s backoff, second attempt
    await vi.advanceTimersByTimeAsync(1000);
    await vi.advanceTimersByTimeAsync(0);
    expect(fetchCallCount).toBe(2);

    // After 2s backoff, third attempt
    await vi.advanceTimersByTimeAsync(2000);
    await vi.advanceTimersByTimeAsync(0);
    expect(fetchCallCount).toBe(3);

    // After 4s backoff, fourth attempt
    await vi.advanceTimersByTimeAsync(4000);
    await vi.advanceTimersByTimeAsync(0);
    expect(fetchCallCount).toBe(4);

    // After 8s backoff, fifth attempt
    await vi.advanceTimersByTimeAsync(8000);
    await vi.advanceTimersByTimeAsync(0);
    expect(fetchCallCount).toBe(5);

    // After 16s backoff (max), sixth attempt
    await vi.advanceTimersByTimeAsync(16000);
    await vi.advanceTimersByTimeAsync(0);
    expect(fetchCallCount).toBe(6);

    // Cleanup
    stream.disconnect();
  });

  it("on SSE reconnect after disconnect, a full refresh callback is invoked", async () => {
    let fetchCallCount = 0;
    const mockFetch = vi.fn().mockImplementation(() => {
      fetchCallCount++;
      if (fetchCallCount === 1) {
        // First connection succeeds, then stream closes
        return Promise.resolve({
          ok: true,
          status: 200,
          body: mockReadableStream([]),
        });
      }
      // Second connection (reconnect) succeeds
      return Promise.resolve({
        ok: true,
        status: 200,
        body: mockReadableStream([
          'event: agent_heartbeat\ndata: {"endpoint_agent_id":"a1","timestamp":"2026-03-19T10:00:00Z"}\n\n',
        ]),
      });
    });
    globalThis.fetch = mockFetch;

    const stream = createStream();
    stream.connect();

    // Let first connection resolve and stream close
    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(100);

    // After backoff, reconnect happens
    await vi.advanceTimersByTimeAsync(1000);
    await vi.advanceTimersByTimeAsync(100);

    expect(reconnectCalled).toBe(true);

    stream.disconnect();
  });
});
