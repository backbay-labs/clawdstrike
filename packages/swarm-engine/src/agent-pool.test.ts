/**
 * Tests for AgentPool -- ported from ruflo with browser-safe adaptations.
 *
 * Coverage: acquire/release, add/remove, auto-scaling (up/down with cooldown),
 * LRU eviction, health checks, initialize/shutdown/dispose, getState,
 * getUtilization, getPoolStats.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { AgentPool } from "./agent-pool.js";
import { TypedEventEmitter } from "./events.js";
import type { SwarmEngineEventMap } from "./events.js";
import type { AgentPoolConfig, AgentPoolState } from "./types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEvents(): TypedEventEmitter<SwarmEngineEventMap> {
  return new TypedEventEmitter<SwarmEngineEventMap>();
}

function makeConfig(
  overrides: Partial<AgentPoolConfig> = {},
): Partial<AgentPoolConfig> {
  return {
    name: "test-pool",
    minSize: 2,
    maxSize: 5,
    scaleUpThreshold: 0.8,
    scaleDownThreshold: 0.2,
    cooldownMs: 30_000,
    healthCheckIntervalMs: 10_000,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("AgentPool", () => {
  let events: TypedEventEmitter<SwarmEngineEventMap>;
  let pool: AgentPool;

  beforeEach(() => {
    vi.useFakeTimers();
    events = makeEvents();
    pool = new AgentPool(events, makeConfig());
  });

  afterEach(() => {
    pool.dispose();
    events.dispose();
    vi.useRealTimers();
  });

  // =========================================================================
  // Initialize / Shutdown / Dispose
  // =========================================================================

  describe("initialize", () => {
    it("creates minSize agents and starts health checks", () => {
      pool.initialize();
      const state = pool.getState();
      expect(Object.keys(state.agents)).toHaveLength(2); // minSize = 2
      expect(state.availableCount).toBe(2);
      expect(state.busyCount).toBe(0);
    });
  });

  describe("shutdown", () => {
    it("clears all agents and stops health checks", () => {
      pool.initialize();
      pool.shutdown();
      const state = pool.getState();
      expect(Object.keys(state.agents)).toHaveLength(0);
      expect(state.availableCount).toBe(0);
      expect(state.busyCount).toBe(0);
    });
  });

  describe("dispose", () => {
    it("stops timers without async cleanup", () => {
      pool.initialize();
      pool.dispose();
      // After dispose, advancing timers should NOT cause errors
      vi.advanceTimersByTime(30_000);
      // Pool is still technically alive but health checks are stopped
    });
  });

  // =========================================================================
  // Acquire / Release
  // =========================================================================

  describe("acquire", () => {
    it("returns agentId when pool has available agents", () => {
      pool.initialize();
      const agentId = pool.acquire();
      expect(agentId).toBeDefined();
      expect(typeof agentId).toBe("string");
      expect(agentId!.startsWith("agt_")).toBe(true);
    });

    it("returns undefined when pool is exhausted (at maxSize, all busy)", () => {
      pool = new AgentPool(events, makeConfig({ minSize: 2, maxSize: 2 }));
      pool.initialize();

      // Acquire both agents
      const a1 = pool.acquire();
      const a2 = pool.acquire();
      expect(a1).toBeDefined();
      expect(a2).toBeDefined();

      // Third acquire should fail
      const a3 = pool.acquire();
      expect(a3).toBeUndefined();
    });

    it("skips unhealthy agents when selecting from the available pool", () => {
      pool.initialize();
      const [staleAgentId, healthyAgentId] = Object.keys(pool.getState().agents);

      const staleAgent = (pool as any).pooledAgents.get(staleAgentId);
      staleAgent.lastHeartbeatAt = Date.now() - 40_000;

      vi.advanceTimersByTime(10_001);

      expect(pool.getState().agents[staleAgentId]?.status).toBe("unhealthy");

      const acquiredAgentId = pool.acquire();

      expect(acquiredAgentId).toBe(healthyAgentId);
      expect(pool.getState().agents[staleAgentId]?.status).toBe("unhealthy");
    });

    it("increments busy count and decrements available count", () => {
      pool.initialize();
      const before = pool.getState();
      expect(before.availableCount).toBe(2);
      expect(before.busyCount).toBe(0);

      pool.acquire();
      const after = pool.getState();
      expect(after.availableCount).toBe(1);
      expect(after.busyCount).toBe(1);
    });
  });

  describe("release", () => {
    it("moves agent from busy back to available", () => {
      pool.initialize();
      const agentId = pool.acquire()!;
      expect(pool.getState().busyCount).toBe(1);

      pool.release(agentId);
      expect(pool.getState().busyCount).toBe(0);
      expect(pool.getState().availableCount).toBe(2);
    });

    it("does nothing for unknown agent ID", () => {
      pool.initialize();
      pool.release("agt_nonexistent");
      expect(pool.getState().availableCount).toBe(2);
    });
  });

  // =========================================================================
  // Add / Remove
  // =========================================================================

  describe("add", () => {
    it("adds external agent to pool", () => {
      pool.initialize();
      const before = Object.keys(pool.getState().agents).length;
      pool.add("agt_external_001");
      expect(Object.keys(pool.getState().agents).length).toBe(before + 1);
      expect(pool.getState().availableCount).toBe(before + 1);
    });

    it("throws when pool is at max capacity", () => {
      pool = new AgentPool(events, makeConfig({ minSize: 5, maxSize: 5 }));
      pool.initialize();
      expect(() => pool.add("agt_extra")).toThrow("maximum capacity");
    });
  });

  describe("remove", () => {
    it("removes agent from pool", () => {
      pool.initialize();
      const agentId = Object.keys(pool.getState().agents)[0]!;
      pool.remove(agentId);
      expect(pool.getState().agents[agentId]).toBeUndefined();
    });

    it("does nothing for unknown agent ID", () => {
      pool.initialize();
      const before = Object.keys(pool.getState().agents).length;
      pool.remove("agt_nonexistent");
      expect(Object.keys(pool.getState().agents).length).toBe(before);
    });
  });

  // =========================================================================
  // Scale
  // =========================================================================

  describe("scale", () => {
    it("scale(+N) creates new agents up to maxSize", () => {
      pool.initialize(); // 2 agents
      pool.scale(2); // should create 2 more (total 4, max is 5)
      expect(Object.keys(pool.getState().agents)).toHaveLength(4);
    });

    it("scale(+N) caps at maxSize", () => {
      pool.initialize(); // 2 agents, maxSize 5
      pool.scale(10); // only 3 more can be created
      expect(Object.keys(pool.getState().agents)).toHaveLength(5);
    });

    it("scale(-N) removes LRU available agents down to minSize", () => {
      pool = new AgentPool(events, makeConfig({ minSize: 1, maxSize: 5 }));
      pool.initialize(); // 1 agent

      // Scale up first (bypass cooldown by setting cooldownMs: 0)
      pool = new AgentPool(events, makeConfig({ minSize: 1, maxSize: 5, cooldownMs: 0 }));
      pool.initialize();
      pool.scale(3); // now 4 agents

      pool.scale(-2); // should remove 2, leaving 2 (above minSize of 1)
      expect(Object.keys(pool.getState().agents)).toHaveLength(2);
    });

    it("scale(-N) does not go below minSize", () => {
      pool = new AgentPool(events, makeConfig({ minSize: 2, maxSize: 5, cooldownMs: 0 }));
      pool.initialize(); // 2 agents
      pool.scale(2); // 4 agents
      pool.scale(-10); // should stop at minSize 2
      expect(Object.keys(pool.getState().agents)).toHaveLength(2);
    });
  });

  // =========================================================================
  // Auto-Scaling (checkScaling)
  // =========================================================================

  describe("checkScaling", () => {
    it("auto-scales up when utilization >= scaleUpThreshold", () => {
      // Setup: 2 agents, scaleUpThreshold 0.8 => need utilization >= 0.8
      // With 2 agents, if both busy -> util = 1.0 which is >= 0.8
      pool = new AgentPool(events, makeConfig({ minSize: 2, maxSize: 5, cooldownMs: 0 }));
      pool.initialize();

      // Acquire both agents (utilization = 1.0)
      pool.acquire();
      pool.acquire();

      // checkScaling is called internally by acquire
      // With cooldownMs: 0, the scale should happen immediately
      // After acquiring both + auto-scale, a new agent should have been created
      const state = pool.getState();
      expect(Object.keys(state.agents).length).toBeGreaterThan(2);
    });

    it("auto-scales down when utilization <= scaleDownThreshold", () => {
      // Setup: create pool with low threshold, scale up, then release to trigger down-scale
      pool = new AgentPool(events, makeConfig({ minSize: 1, maxSize: 5, cooldownMs: 0, scaleDownThreshold: 0.3 }));
      pool.initialize(); // 1 agent

      pool.scale(3); // 4 agents
      // All 4 are available, utilization = 0 which is <= 0.3
      // Release triggers checkScaling -- but we need an acquire+release cycle
      const agentId = pool.acquire()!;
      pool.release(agentId);

      // After release, utilization should be low, triggering scale-down
      const state = pool.getState();
      expect(Object.keys(state.agents).length).toBeLessThan(4);
    });
  });

  // =========================================================================
  // Cooldown
  // =========================================================================

  describe("cooldown", () => {
    it("prevents rapid successive scale operations", () => {
      pool = new AgentPool(events, makeConfig({ minSize: 1, maxSize: 10, cooldownMs: 30_000 }));
      pool.initialize(); // 1 agent

      pool.scale(2); // now 3 agents, sets lastScaleOperation
      pool.scale(2); // should be blocked by cooldown
      expect(Object.keys(pool.getState().agents)).toHaveLength(3);

      // Advance time past cooldown
      vi.advanceTimersByTime(30_001);
      pool.scale(2); // now should work
      expect(Object.keys(pool.getState().agents)).toHaveLength(5);
    });
  });

  // =========================================================================
  // Health Checks
  // =========================================================================

  describe("health checks", () => {
    it("detect unhealthy agents (no heartbeat)", () => {
      pool.initialize();

      // Unhealthy threshold = 3 * healthCheckIntervalMs = 30000ms
      // Need to advance past the threshold AND trigger a health check after it
      // Health checks fire at 10000, 20000, 30000, 40000...
      // At T=40000: timeSinceLastHeartbeat = 40000 > 30000 -> unhealthy
      vi.advanceTimersByTime(40_001);

      // Health checks should have run and detected unhealthy agents
      const state = pool.getState();
      const agents = Object.values(state.agents);
      // At least one agent should have degraded health
      const hasLowHealth = agents.some((a) => a.health < 1.0);
      expect(hasLowHealth).toBe(true);
    });
  });

  describe("replaceUnhealthyAgent", () => {
    it("removes unhealthy agent and creates replacement", () => {
      pool.initialize();
      const initialIds = new Set(Object.keys(pool.getState().agents));

      // Health degrades by 0.2 each check after the threshold (30s).
      // First degradation at T=40000, then 50000, 60000, 70000, 80000.
      // 5 degradations * 0.2 = 1.0 -> health reaches 0 -> replacement triggered.
      // Need 8 health check intervals (80s) + a bit more.
      vi.advanceTimersByTime(90_001);

      // After replacement, pool should still have minSize agents
      const state = pool.getState();
      expect(Object.keys(state.agents).length).toBeGreaterThanOrEqual(
        pool.getState().config.minSize,
      );
      // Agent IDs should be different (replaced)
      const currentIds = new Set(Object.keys(state.agents));
      const replacedSome = [...initialIds].some((id) => !currentIds.has(id));
      expect(replacedSome).toBe(true);
    });
  });

  // =========================================================================
  // State Accessors
  // =========================================================================

  describe("getState", () => {
    it("returns Record-based AgentPoolState (not Map)", () => {
      pool.initialize();
      const state = pool.getState();

      // Must be a plain object, not a Map
      expect(state.agents).toBeDefined();
      expect(typeof state.agents).toBe("object");
      expect(state.agents instanceof Map).toBe(false);

      // Verify shape matches AgentPoolState
      expect(state.config).toBeDefined();
      expect(typeof state.availableCount).toBe("number");
      expect(typeof state.busyCount).toBe("number");
      expect(typeof state.utilization).toBe("number");
      expect(typeof state.pendingScale).toBe("number");
    });

    it("is JSON-serializable", () => {
      pool.initialize();
      const state = pool.getState();
      const json = JSON.stringify(state);
      const parsed = JSON.parse(json) as AgentPoolState;

      expect(parsed.config.name).toBe("test-pool");
      expect(Object.keys(parsed.agents).length).toBeGreaterThan(0);
    });
  });

  describe("getUtilization", () => {
    it("returns busy/total ratio", () => {
      // Use a pool where auto-scaling won't trigger (scaleUpThreshold: 1.0)
      pool = new AgentPool(events, makeConfig({ minSize: 2, maxSize: 2, scaleUpThreshold: 1.0 }));
      pool.initialize(); // 2 agents
      expect(pool.getUtilization()).toBe(0);

      pool.acquire();
      expect(pool.getUtilization()).toBe(0.5); // 1/2

      pool.acquire();
      expect(pool.getUtilization()).toBe(1.0); // 2/2
    });

    it("returns 0 for empty pool", () => {
      // Don't initialize -> 0 agents
      expect(pool.getUtilization()).toBe(0);
    });
  });

  describe("getPoolStats", () => {
    it("returns aggregate health and usage stats", () => {
      pool.initialize();
      pool.acquire();

      const stats = pool.getPoolStats();
      expect(stats.total).toBe(2);
      expect(stats.available).toBe(1);
      expect(stats.busy).toBe(1);
      expect(stats.utilization).toBe(0.5);
      expect(typeof stats.avgHealth).toBe("number");
      expect(typeof stats.avgUsageCount).toBe("number");
    });

    it("returns defaults for empty pool", () => {
      const stats = pool.getPoolStats();
      expect(stats.total).toBe(0);
      expect(stats.available).toBe(0);
      expect(stats.busy).toBe(0);
      expect(stats.utilization).toBe(0);
      expect(stats.avgHealth).toBe(1.0);
      expect(stats.avgUsageCount).toBe(0);
    });
  });

  // =========================================================================
  // Utility Methods
  // =========================================================================

  describe("updateAgentHeartbeat", () => {
    it("updates last heartbeat for known agent", () => {
      pool.initialize();
      const agentId = Object.keys(pool.getState().agents)[0]!;

      // Advance time so heartbeat differs
      vi.advanceTimersByTime(5_000);
      pool.updateAgentHeartbeat(agentId);

      const state = pool.getState();
      expect(state.agents[agentId]!.health).toBeGreaterThanOrEqual(1.0);
    });
  });
});
