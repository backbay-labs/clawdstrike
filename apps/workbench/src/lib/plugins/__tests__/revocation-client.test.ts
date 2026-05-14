/**
 * PluginRevocationClient Tests
 *
 * Tests for the SSE-based revocation client that connects to hushd,
 * handles plugin_revoked events, syncs on reconnect, and generates
 * receipts for each SSE-driven revocation.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { PluginRevocationEntry } from "../revocation-store";

// ---- EventSource mock ----

type EventSourceListener = (event: MessageEvent) => void;
type EventSourceOpenListener = () => void;
type EventSourceErrorListener = (event: Event) => void;

class MockEventSource {
  static instances: MockEventSource[] = [];
  url: string;
  readyState = 0; // CONNECTING
  private listeners: Record<string, Array<EventSourceListener | EventSourceOpenListener | EventSourceErrorListener>> = {};

  constructor(url: string) {
    this.url = url;
    MockEventSource.instances.push(this);
  }

  addEventListener(
    type: string,
    callback: EventSourceListener | EventSourceOpenListener | EventSourceErrorListener,
  ): void {
    if (!this.listeners[type]) {
      this.listeners[type] = [];
    }
    this.listeners[type].push(callback);
  }

  close(): void {
    this.readyState = 2; // CLOSED
  }

  // Test helpers
  simulateOpen(): void {
    this.readyState = 1; // OPEN
    const callbacks = this.listeners["open"];
    if (callbacks) {
      for (const cb of callbacks) {
        (cb as EventSourceOpenListener)();
      }
    }
  }

  simulateMessage(type: string, data: unknown): void {
    const callbacks = this.listeners[type];
    if (callbacks) {
      const event = new MessageEvent(type, {
        data: JSON.stringify(data),
      });
      for (const cb of callbacks) {
        (cb as EventSourceListener)(event);
      }
    }
  }

  simulateError(): void {
    const callbacks = this.listeners["error"];
    if (callbacks) {
      const event = new Event("error");
      for (const cb of callbacks) {
        (cb as EventSourceErrorListener)(event);
      }
    }
  }
}

// ---- Mocks ----

const mockRevokePlugin = vi.fn().mockResolvedValue(undefined);
const mockDeactivatePlugin = vi.fn().mockResolvedValue(undefined);
const mockLoadPlugin = vi.fn().mockResolvedValue(undefined);

const mockRevoke = vi.fn();
const mockIsRevoked = vi.fn().mockReturnValue(false);
const mockLift = vi.fn();
const mockGetAll = vi.fn().mockReturnValue([]);
const mockSync = vi.fn().mockReturnValue({ added: [], removed: [] });

const mockSetState = vi.fn();

const mockRecordDenied = vi.fn().mockResolvedValue(undefined);

// ---- Globals ----

const originalEventSource = globalThis.EventSource;
const originalFetch = globalThis.fetch;

// ---- Tests ----

describe("PluginRevocationClient", () => {
  let PluginRevocationClient: typeof import("../revocation-client").PluginRevocationClient;

  beforeEach(async () => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    MockEventSource.instances = [];

    // Set up global EventSource mock
    (globalThis as Record<string, unknown>).EventSource = MockEventSource;

    // Set up global fetch mock
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve([]),
    }) as unknown as typeof fetch;

    // Fresh import to avoid module cache
    const mod = await import("../revocation-client");
    PluginRevocationClient = mod.PluginRevocationClient;
  });

  afterEach(() => {
    vi.useRealTimers();
    globalThis.EventSource = originalEventSource;
    globalThis.fetch = originalFetch;
  });

  function createClient(overrides?: { receiptMiddleware?: unknown }) {
    return new PluginRevocationClient({
      hushdUrl: "http://localhost:9090",
      authToken: "test-token",
      pluginLoader: {
        revokePlugin: mockRevokePlugin,
        deactivatePlugin: mockDeactivatePlugin,
        loadPlugin: mockLoadPlugin,
      } as never,
      revocationStore: {
        revoke: mockRevoke,
        isRevoked: mockIsRevoked,
        lift: mockLift,
        getAll: mockGetAll,
        sync: mockSync,
      } as never,
      registry: {
        setState: mockSetState,
      } as never,
      receiptMiddleware: (overrides?.receiptMiddleware ?? null) as never,
    });
  }

  // Test 1: Connects to hushd SSE at /api/v1/events
  it("connects to hushd SSE at /api/v1/events and listens for plugin_revoked events", () => {
    const client = createClient();
    client.connect();

    expect(MockEventSource.instances).toHaveLength(1);
    expect(MockEventSource.instances[0].url).toBe(
      "http://localhost:9090/api/v1/events?token=test-token",
    );
  });

  // Test 2: On plugin_revoked SSE event, calls pluginLoader.revokePlugin
  it("on plugin_revoked SSE event, calls pluginLoader.revokePlugin with correct args", async () => {
    const client = createClient();
    client.connect();

    const es = MockEventSource.instances[0];
    es.simulateMessage("plugin_revoked", {
      plugin_id: "bad-plugin",
      reason: "Malware detected",
      until: null,
    });

    // Let promises settle
    await vi.advanceTimersByTimeAsync(0);

    expect(mockRevokePlugin).toHaveBeenCalledWith("bad-plugin", {
      reason: "Malware detected",
      until: null,
    });
  });

  // Test 3: On reconnect, fetches revocations and syncs
  it("on reconnect, fetches GET /api/v1/plugins/revocations and calls sync for new revocations", async () => {
    const remoteEntries: PluginRevocationEntry[] = [
      {
        pluginId: "remote-revoked",
        reason: "Remote revocation",
        revokedAt: "2026-03-19T00:00:00Z",
        until: null,
      },
    ];

    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(remoteEntries),
    });

    mockSync.mockReturnValue({ added: ["remote-revoked"], removed: [] });

    const client = createClient();
    client.connect();

    const es = MockEventSource.instances[0];
    es.simulateOpen();

    // Let promises settle
    await vi.advanceTimersByTimeAsync(0);

    expect(globalThis.fetch).toHaveBeenCalledWith(
      "http://localhost:9090/api/v1/plugins/revocations",
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: "Bearer test-token",
        }),
      }),
    );

    expect(mockSync).toHaveBeenCalledWith(remoteEntries);
    expect(mockRevokePlugin).toHaveBeenCalledWith("remote-revoked", {
      reason: "Remote revocation",
      until: undefined,
    });
  });

  // Test 4: On reconnect, if sync reports removed (expired), calls lift and setState
  it("on reconnect, if sync reports removed entries, calls lift() and setState(deactivated)", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      json: () => Promise.resolve([]),
    });

    mockSync.mockReturnValue({ added: [], removed: ["expired-plugin"] });

    const client = createClient();
    client.connect();

    const es = MockEventSource.instances[0];
    es.simulateOpen();

    await vi.advanceTimersByTimeAsync(0);

    expect(mockLift).toHaveBeenCalledWith("expired-plugin");
    expect(mockSetState).toHaveBeenCalledWith("expired-plugin", "deactivated");
  });

  // Test 5: SSE connection errors do not throw, logs warning and schedules reconnect
  it("SSE connection errors do not throw; schedules reconnect after 5 seconds", async () => {
    const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    const client = createClient();
    client.connect();

    const es = MockEventSource.instances[0];

    // Simulate error -- should not throw
    expect(() => es.simulateError()).not.toThrow();

    // Should have logged warning
    expect(consoleSpy).toHaveBeenCalled();

    // Advance past reconnect timer (5 seconds)
    await vi.advanceTimersByTimeAsync(5000);

    // Should have created a new EventSource (reconnect)
    expect(MockEventSource.instances).toHaveLength(2);

    consoleSpy.mockRestore();
  });

  // Test 6: disconnect() closes EventSource and clears reconnect timer
  it("disconnect() closes EventSource and clears reconnect timer", () => {
    const client = createClient();
    client.connect();

    const es = MockEventSource.instances[0];
    expect(es.readyState).not.toBe(2);

    client.disconnect();

    expect(es.readyState).toBe(2); // CLOSED
  });

  // Test 7: Generates a receipt for each SSE-driven revocation
  it("generates a receipt for each SSE-driven revocation via receipt middleware", async () => {
    const client = createClient({
      receiptMiddleware: {
        recordDenied: mockRecordDenied,
        recordAllowed: vi.fn(),
        recordError: vi.fn(),
      },
    });
    client.connect();

    const es = MockEventSource.instances[0];
    es.simulateMessage("plugin_revoked", {
      plugin_id: "revoked-plugin",
      reason: "Security issue",
      until: null,
    });

    await vi.advanceTimersByTimeAsync(0);

    expect(mockRecordDenied).toHaveBeenCalledWith(
      "revocation.sse",
      { plugin_id: "revoked-plugin" },
      "revocation",
    );
  });
});
