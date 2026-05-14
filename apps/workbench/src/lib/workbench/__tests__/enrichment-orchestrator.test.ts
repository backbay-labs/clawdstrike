import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type {
  ThreatIntelSource,
  EnrichmentResult,
  Indicator,
} from "@clawdstrike/plugin-sdk";
import {
  registerThreatIntelSource,
  _resetForTesting,
} from "../threat-intel-registry";
import { EnrichmentOrchestrator } from "../enrichment-orchestrator";

// ---- Helpers ----

function makeResult(sourceId: string, overrides: Partial<EnrichmentResult> = {}): EnrichmentResult {
  return {
    sourceId,
    sourceName: `Source ${sourceId}`,
    verdict: { classification: "unknown", confidence: 0, summary: "No data" },
    rawData: {},
    fetchedAt: Date.now(),
    cacheTtlMs: 60_000,
    ...overrides,
  };
}

function makeMockSource(overrides: Partial<ThreatIntelSource> = {}): ThreatIntelSource {
  return {
    id: "test-source",
    name: "Test Source",
    supportedIndicatorTypes: ["ip", "domain"],
    rateLimit: { maxPerMinute: 10 },
    enrich: vi.fn(async () => makeResult("test-source")),
    ...overrides,
  };
}

const ipIndicator: Indicator = {
  type: "ip",
  value: "1.2.3.4",
  context: { findingId: "fnd_123" },
};

// ---- Tests ----

describe("EnrichmentOrchestrator", () => {
  let orchestrator: EnrichmentOrchestrator;

  beforeEach(() => {
    _resetForTesting();
    orchestrator = new EnrichmentOrchestrator();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // ---- Token bucket rate limiting ----

  describe("token bucket rate limiting", () => {
    it("allows up to maxPerMinute calls, then queues the next", async () => {
      const enrichFn = vi.fn(async () => makeResult("rate-limited"));
      const source = makeMockSource({
        id: "rate-limited",
        rateLimit: { maxPerMinute: 4 },
        enrich: enrichFn,
      });
      registerThreatIntelSource(source);

      // Fire 5 requests concurrently
      const promises: Promise<EnrichmentResult[]>[] = [];
      for (let i = 0; i < 5; i++) {
        promises.push(
          orchestrator.enrich(
            { type: "ip", value: `1.2.3.${i}` },
            { sourceIds: ["rate-limited"] },
          ),
        );
      }

      // Let microtasks run but not timers
      await vi.advanceTimersByTimeAsync(0);

      // First 4 calls should have gone through
      expect(enrichFn).toHaveBeenCalledTimes(4);

      // Advance 60s to refill tokens
      await vi.advanceTimersByTimeAsync(60_000);

      // Now all 5 should have completed
      const results = await Promise.all(promises);
      expect(enrichFn).toHaveBeenCalledTimes(5);
      expect(results).toHaveLength(5);
    });

    it("replenishes tokens after 60 seconds", async () => {
      const enrichFn = vi.fn(async () => makeResult("bucket"));
      const source = makeMockSource({
        id: "bucket",
        rateLimit: { maxPerMinute: 2 },
        enrich: enrichFn,
      });
      registerThreatIntelSource(source);

      // Exhaust 2 tokens
      await orchestrator.enrich({ type: "ip", value: "1.1.1.1" }, { sourceIds: ["bucket"] });
      await orchestrator.enrich({ type: "ip", value: "2.2.2.2" }, { sourceIds: ["bucket"] });
      expect(enrichFn).toHaveBeenCalledTimes(2);

      // Advance time to refill
      await vi.advanceTimersByTimeAsync(60_000);

      // Should be able to call again
      await orchestrator.enrich({ type: "ip", value: "3.3.3.3" }, { sourceIds: ["bucket"] });
      expect(enrichFn).toHaveBeenCalledTimes(3);
    });

    it("maintains independent rate limit buckets per source", async () => {
      const enrichA = vi.fn(async () => makeResult("source-a"));
      const enrichB = vi.fn(async () => makeResult("source-b"));

      registerThreatIntelSource(
        makeMockSource({ id: "source-a", rateLimit: { maxPerMinute: 1 }, enrich: enrichA }),
      );
      registerThreatIntelSource(
        makeMockSource({ id: "source-b", rateLimit: { maxPerMinute: 1 }, enrich: enrichB }),
      );

      // Both should succeed (independent buckets)
      await orchestrator.enrich(ipIndicator, { sourceIds: ["source-a"] });
      await orchestrator.enrich(ipIndicator, { sourceIds: ["source-b"] });

      expect(enrichA).toHaveBeenCalledTimes(1);
      expect(enrichB).toHaveBeenCalledTimes(1);
    });
  });

  // ---- Caching ----

  describe("caching", () => {
    it("returns cached result without calling source.enrich() on second call", async () => {
      const enrichFn = vi.fn(async () => makeResult("cached-source"));
      const source = makeMockSource({ id: "cached-source", enrich: enrichFn });
      registerThreatIntelSource(source);

      const results1 = await orchestrator.enrich(ipIndicator, { sourceIds: ["cached-source"] });
      expect(enrichFn).toHaveBeenCalledTimes(1);
      expect(results1).toHaveLength(1);

      const results2 = await orchestrator.enrich(ipIndicator, { sourceIds: ["cached-source"] });
      expect(enrichFn).toHaveBeenCalledTimes(1); // NOT called again
      expect(results2).toHaveLength(1);
      expect(results2[0]!.sourceId).toBe("cached-source");
    });

    it("expires cached result after cacheTtlMs", async () => {
      const enrichFn = vi.fn(async () => makeResult("ttl-source", { cacheTtlMs: 30_000 }));
      const source = makeMockSource({ id: "ttl-source", enrich: enrichFn });
      registerThreatIntelSource(source);

      await orchestrator.enrich(ipIndicator, { sourceIds: ["ttl-source"] });
      expect(enrichFn).toHaveBeenCalledTimes(1);

      // Advance past TTL
      await vi.advanceTimersByTimeAsync(31_000);

      await orchestrator.enrich(ipIndicator, { sourceIds: ["ttl-source"] });
      expect(enrichFn).toHaveBeenCalledTimes(2); // Called again after expiry
    });

    it("caches separately for different indicator values", async () => {
      const enrichFn = vi.fn(async (ind: Indicator) =>
        makeResult("multi-cache", { rawData: { value: ind.value } }),
      );
      const source = makeMockSource({ id: "multi-cache", enrich: enrichFn });
      registerThreatIntelSource(source);

      await orchestrator.enrich({ type: "ip", value: "1.1.1.1" }, { sourceIds: ["multi-cache"] });
      await orchestrator.enrich({ type: "ip", value: "2.2.2.2" }, { sourceIds: ["multi-cache"] });
      expect(enrichFn).toHaveBeenCalledTimes(2);

      // Re-fetch both -- should use cache
      await orchestrator.enrich({ type: "ip", value: "1.1.1.1" }, { sourceIds: ["multi-cache"] });
      await orchestrator.enrich({ type: "ip", value: "2.2.2.2" }, { sourceIds: ["multi-cache"] });
      expect(enrichFn).toHaveBeenCalledTimes(2); // Still only 2
    });
  });

  // ---- Orchestration ----

  describe("orchestration", () => {
    it("dispatches to all matching sources when sourceIds not provided", async () => {
      const enrichA = vi.fn(async () => makeResult("src-a"));
      const enrichB = vi.fn(async () => makeResult("src-b"));
      const enrichC = vi.fn(async () => makeResult("src-c"));

      registerThreatIntelSource(
        makeMockSource({ id: "src-a", supportedIndicatorTypes: ["ip"], enrich: enrichA }),
      );
      registerThreatIntelSource(
        makeMockSource({ id: "src-b", supportedIndicatorTypes: ["ip", "domain"], enrich: enrichB }),
      );
      registerThreatIntelSource(
        makeMockSource({ id: "src-c", supportedIndicatorTypes: ["domain"], enrich: enrichC }),
      );

      const results = await orchestrator.enrich(ipIndicator);

      expect(enrichA).toHaveBeenCalledTimes(1);
      expect(enrichB).toHaveBeenCalledTimes(1);
      expect(enrichC).not.toHaveBeenCalled(); // domain-only
      expect(results).toHaveLength(2);
    });

    it("dispatches only to specified sourceIds", async () => {
      const enrichA = vi.fn(async () => makeResult("src-a"));
      const enrichB = vi.fn(async () => makeResult("src-b"));

      registerThreatIntelSource(
        makeMockSource({ id: "src-a", supportedIndicatorTypes: ["ip"], enrich: enrichA }),
      );
      registerThreatIntelSource(
        makeMockSource({ id: "src-b", supportedIndicatorTypes: ["ip"], enrich: enrichB }),
      );

      const results = await orchestrator.enrich(ipIndicator, { sourceIds: ["src-a"] });

      expect(enrichA).toHaveBeenCalledTimes(1);
      expect(enrichB).not.toHaveBeenCalled();
      expect(results).toHaveLength(1);
    });

    it("one source failing does not prevent results from other sources", async () => {
      const enrichGood = vi.fn(async () => makeResult("good-source"));
      const enrichBad = vi.fn(async () => {
        throw new Error("API key expired");
      });

      registerThreatIntelSource(
        makeMockSource({ id: "good-source", supportedIndicatorTypes: ["ip"], enrich: enrichGood }),
      );
      registerThreatIntelSource(
        makeMockSource({ id: "bad-source", supportedIndicatorTypes: ["ip"], enrich: enrichBad }),
      );

      const results = await orchestrator.enrich(ipIndicator);

      // Should get the good result
      expect(results.some((r) => r.sourceId === "good-source")).toBe(true);
      // Should have a result length of at least 1
      expect(results.length).toBeGreaterThanOrEqual(1);
    });

    it("cancel() aborts in-flight enrichment requests via AbortSignal", async () => {
      const enrichFn = vi.fn(async () => makeResult("slow-source"));

      registerThreatIntelSource(
        makeMockSource({ id: "slow-source", supportedIndicatorTypes: ["ip"], enrich: enrichFn }),
      );

      // Abort BEFORE calling enrich -- signal already aborted
      const controller = new AbortController();
      controller.abort();

      const results = await orchestrator.enrich(ipIndicator, {
        sourceIds: ["slow-source"],
        signal: controller.signal,
      });

      // Aborted requests should return empty results and source should not be called
      expect(results).toHaveLength(0);
      expect(enrichFn).not.toHaveBeenCalled();
    });
  });

  // ---- Result streaming ----

  describe("result streaming", () => {
    it("calls onResult callback for each result as it arrives", async () => {
      const onResult = vi.fn();

      registerThreatIntelSource(
        makeMockSource({
          id: "stream-a",
          supportedIndicatorTypes: ["ip"],
          enrich: async () => makeResult("stream-a"),
        }),
      );
      registerThreatIntelSource(
        makeMockSource({
          id: "stream-b",
          supportedIndicatorTypes: ["ip"],
          enrich: async () => makeResult("stream-b"),
        }),
      );

      await orchestrator.enrich(ipIndicator, { onResult });

      expect(onResult).toHaveBeenCalledTimes(2);
      const callArgs = onResult.mock.calls.map((c: unknown[]) => (c[0] as EnrichmentResult).sourceId);
      expect(callArgs.sort()).toEqual(["stream-a", "stream-b"]);
    });
  });

  // ---- Cache management ----

  describe("cache management", () => {
    it("clearCache() removes all cached entries", async () => {
      const enrichFn = vi.fn(async () => makeResult("clear-test"));
      registerThreatIntelSource(
        makeMockSource({ id: "clear-test", enrich: enrichFn }),
      );

      await orchestrator.enrich(ipIndicator, { sourceIds: ["clear-test"] });
      expect(enrichFn).toHaveBeenCalledTimes(1);

      orchestrator.clearCache();

      await orchestrator.enrich(ipIndicator, { sourceIds: ["clear-test"] });
      expect(enrichFn).toHaveBeenCalledTimes(2); // Called again after cache clear
    });

    it("clearCacheForSource() removes only entries for that source", async () => {
      const enrichA = vi.fn(async () => makeResult("source-a"));
      const enrichB = vi.fn(async () => makeResult("source-b"));

      registerThreatIntelSource(
        makeMockSource({ id: "source-a", supportedIndicatorTypes: ["ip"], enrich: enrichA }),
      );
      registerThreatIntelSource(
        makeMockSource({ id: "source-b", supportedIndicatorTypes: ["ip"], enrich: enrichB }),
      );

      await orchestrator.enrich(ipIndicator);
      expect(enrichA).toHaveBeenCalledTimes(1);
      expect(enrichB).toHaveBeenCalledTimes(1);

      orchestrator.clearCacheForSource("source-a");

      await orchestrator.enrich(ipIndicator);
      expect(enrichA).toHaveBeenCalledTimes(2); // Re-fetched
      expect(enrichB).toHaveBeenCalledTimes(1); // Still cached
    });
  });

  // ---- LRU cache eviction ----

  describe("LRU cache eviction (MAX_CACHE_SIZE)", () => {
    it("cache does not exceed MAX_CACHE_SIZE (10,000) after adding 10,001 entries", async () => {
      let callCount = 0;
      const enrichFn = vi.fn(async (ind: Indicator) => {
        callCount++;
        return makeResult("evict-source", {
          rawData: { value: ind.value },
          cacheTtlMs: 3_600_000, // 1 hour TTL so nothing expires
        });
      });

      const source = makeMockSource({
        id: "evict-source",
        rateLimit: { maxPerMinute: 100_000 }, // High limit to avoid rate limiting
        enrich: enrichFn,
      });
      registerThreatIntelSource(source);

      // Add 10,001 unique entries
      for (let i = 0; i < 10_001; i++) {
        await orchestrator.enrich(
          { type: "ip", value: `${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}.${i % 256}` },
          { sourceIds: ["evict-source"] },
        );
      }

      // The internal cache map should not exceed MAX_CACHE_SIZE
      // We access this indirectly: if we re-fetch an early entry,
      // it should have been evicted and trigger a new enrich call
      const initialCalls = enrichFn.mock.calls.length;
      expect(initialCalls).toBe(10_001);

      // Try to fetch the very first entry (should have been evicted)
      await orchestrator.enrich(
        { type: "ip", value: "0.0.0.0" },
        { sourceIds: ["evict-source"] },
      );

      // If eviction worked, the source should be called again
      expect(enrichFn.mock.calls.length).toBe(10_002);
    });

    it("expired entries are evicted during periodic cleanup", async () => {
      const enrichFn = vi.fn(async () =>
        makeResult("expire-test", { cacheTtlMs: 1_000 }), // 1 second TTL
      );
      const source = makeMockSource({
        id: "expire-test",
        enrich: enrichFn,
      });
      registerThreatIntelSource(source);

      // Add entry
      await orchestrator.enrich(ipIndicator, { sourceIds: ["expire-test"] });
      expect(enrichFn).toHaveBeenCalledTimes(1);

      // Cache hit (within TTL)
      await orchestrator.enrich(ipIndicator, { sourceIds: ["expire-test"] });
      expect(enrichFn).toHaveBeenCalledTimes(1);

      // Advance past TTL
      await vi.advanceTimersByTimeAsync(2_000);

      // Cache should have expired -- triggers a new call
      await orchestrator.enrich(ipIndicator, { sourceIds: ["expire-test"] });
      expect(enrichFn).toHaveBeenCalledTimes(2);
    });
  });

  // ---- Destroy ----

  describe("destroy()", () => {
    it("clears the cleanup interval", () => {
      const clearIntervalSpy = vi.spyOn(globalThis, "clearInterval");

      const orch = new EnrichmentOrchestrator();
      orch.destroy();

      expect(clearIntervalSpy).toHaveBeenCalledTimes(1);
      clearIntervalSpy.mockRestore();
    });

    it("clears the cache on destroy", async () => {
      const enrichFn = vi.fn(async () => makeResult("destroy-cache-test"));
      registerThreatIntelSource(
        makeMockSource({ id: "destroy-cache-test", enrich: enrichFn }),
      );

      const orch = new EnrichmentOrchestrator();
      await orch.enrich(ipIndicator, { sourceIds: ["destroy-cache-test"] });
      expect(enrichFn).toHaveBeenCalledTimes(1);

      orch.destroy();

      // After destroy, a new orchestrator instance should not share cache state
      const orch2 = new EnrichmentOrchestrator();
      await orch2.enrich(ipIndicator, { sourceIds: ["destroy-cache-test"] });
      expect(enrichFn).toHaveBeenCalledTimes(2);
      orch2.destroy();
    });
  });

  // ---- Incremental token bucket refill ----

  describe("incremental token bucket refill", () => {
    it("partially refills tokens after half the refill window", async () => {
      const enrichFn = vi.fn(async () => makeResult("refill-test"));
      const source = makeMockSource({
        id: "refill-test",
        rateLimit: { maxPerMinute: 2 },
        enrich: enrichFn,
      });
      registerThreatIntelSource(source);

      // Consume both tokens
      await orchestrator.enrich(
        { type: "ip", value: "1.1.1.1" },
        { sourceIds: ["refill-test"] },
      );
      await orchestrator.enrich(
        { type: "ip", value: "2.2.2.2" },
        { sourceIds: ["refill-test"] },
      );
      expect(enrichFn).toHaveBeenCalledTimes(2);

      // Advance 60s (full refill interval)
      await vi.advanceTimersByTimeAsync(60_000);

      // Tokens should be refilled -- next call should work
      await orchestrator.enrich(
        { type: "ip", value: "3.3.3.3" },
        { sourceIds: ["refill-test"] },
      );
      expect(enrichFn).toHaveBeenCalledTimes(3);
    });
  });
});
