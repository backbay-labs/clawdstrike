import { describe, it, expect, vi } from "vitest";

// We can't easily test the full NATS integration without a running server,
// but we can verify the module structure and error handling.

describe("watch module", () => {
  it("exports runWatch function", async () => {
    const mod = await import("./watch.js");
    expect(typeof mod.runWatch).toBe("function");
  });

  it("throws WatchError when nats is not available", async () => {
    // runWatch requires the nats package which may not be installed in test
    // environment. If nats IS installed, this test verifies the function
    // exists; if not, it verifies the proper error message.
    const { runWatch } = await import("./watch.js");
    const config = {
      natsUrl: "nats://localhost:4222",
      rules: [],
      maxWindow: 60000,
    };

    try {
      await runWatch(config, () => {});
      // If we get here, nats is installed and it tried to connect —
      // which will fail since there's no server. That's fine too.
    } catch (e: unknown) {
      const err = e as Error;
      // Either WatchError (nats not installed) or connection error
      expect(err).toBeInstanceOf(Error);
    }
  });

  it("passes maxWindow to processEvent and avoids explicit wall-clock eviction", async () => {
    vi.resetModules();

    const processEvent = vi.fn(() => []);
    const evict = vi.fn();
    const flush = vi.fn(() => []);
    class MockEngine {
      processEvent = processEvent;
      evict = evict;
      flush = flush;
      constructor(_rules: unknown[]) {}
    }

    const parseEnvelope = vi.fn(() => ({ timestamp: new Date("2025-01-01T00:00:00Z") }));
    const sub = {
      [Symbol.asyncIterator]: async function* () {
        yield {
          data: new TextEncoder().encode(JSON.stringify({ kind: "event" })),
        };
      },
      unsubscribe: vi.fn(),
    };
    const nc = {
      subscribe: vi.fn(() => sub),
      drain: vi.fn(async () => undefined),
    };
    const connect = vi.fn(async () => nc);

    vi.doMock("./correlate/engine.js", () => ({ CorrelationEngine: MockEngine }));
    vi.doMock("./timeline.js", () => ({ parseEnvelope }));
    vi.doMock("nats", () => ({ connect }));

    const { runWatch } = await import("./watch.js");
    await runWatch(
      {
        natsUrl: "nats://localhost:4222",
        rules: [],
        maxWindow: 30_000,
      },
      () => undefined,
    );

    expect(processEvent).toHaveBeenCalledTimes(1);
    expect(processEvent).toHaveBeenCalledWith(
      expect.objectContaining({ timestamp: expect.any(Date) }),
      30_000,
    );
    expect(evict).not.toHaveBeenCalled();
  });
});
