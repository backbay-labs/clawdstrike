/**
 * Tests for AgentRegistry -- ported from ruflo with browser-safe adaptations.
 *
 * Coverage: registration, spawn, terminate, status, tasks, queries, health, serialization.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { AgentRegistry } from "./agent-registry.js";
import type { AgentRegistryConfig } from "./agent-registry.js";
import { TypedEventEmitter } from "./events.js";
import type { SwarmEngineEventMap } from "./events.js";
import type {
  AgentRegistration,
  AgentCapabilities,
  AgentSession,
  AgentSessionStatus,
} from "./types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeCapabilities(
  overrides: Partial<AgentCapabilities> = {},
): AgentCapabilities {
  return {
    codeGeneration: false,
    codeReview: false,
    testing: false,
    documentation: false,
    research: false,
    analysis: false,
    coordination: false,
    securityAnalysis: false,
    languages: [],
    frameworks: [],
    domains: [],
    tools: [],
    maxConcurrentTasks: 1,
    maxMemoryUsageBytes: 0,
    maxExecutionTimeMs: 0,
    ...overrides,
  };
}

function makeRegistration(
  overrides: Partial<AgentRegistration> = {},
): AgentRegistration {
  return {
    name: "test-agent",
    role: "worker",
    capabilities: makeCapabilities(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("AgentRegistry", () => {
  let events: TypedEventEmitter<SwarmEngineEventMap>;
  let registry: AgentRegistry;

  beforeEach(() => {
    vi.useFakeTimers();
    events = new TypedEventEmitter<SwarmEngineEventMap>();
    registry = new AgentRegistry(events);
  });

  afterEach(() => {
    registry.dispose();
    events.dispose();
    vi.useRealTimers();
  });

  // =========================================================================
  // Registration
  // =========================================================================

  describe("registration", () => {
    it("register returns a unique ID starting with agt_", () => {
      const id = registry.register(makeRegistration());
      expect(id).toMatch(/^agt_/);
    });

    it("getRegistration returns the stored registration", () => {
      const reg = makeRegistration({ name: "alpha" });
      const id = registry.register(reg);
      const stored = registry.getRegistration(id);
      expect(stored).toBeDefined();
      expect(stored!.name).toBe("alpha");
      expect(stored!.role).toBe("worker");
    });

    it("registering two agents with same name gives different IDs", () => {
      const id1 = registry.register(makeRegistration({ name: "same" }));
      const id2 = registry.register(makeRegistration({ name: "same" }));
      expect(id1).not.toBe(id2);
    });

    it("register throws if name is empty", () => {
      expect(() => registry.register(makeRegistration({ name: "" }))).toThrow();
    });

    it("unregister removes the registration", () => {
      const id = registry.register(makeRegistration());
      expect(registry.unregister(id)).toBe(true);
      expect(registry.getRegistration(id)).toBeUndefined();
    });

    it("unregister returns false for non-existent ID", () => {
      expect(registry.unregister("agt_nonexistent")).toBe(false);
    });

    it("unregister throws if agent has active session", () => {
      const id = registry.register(makeRegistration());
      registry.spawn(id);
      expect(() => registry.unregister(id)).toThrow("Cannot unregister active agent");
    });

    it("getAllRegistrations returns all registrations", () => {
      registry.register(makeRegistration({ name: "a" }));
      registry.register(makeRegistration({ name: "b" }));
      const all = registry.getAllRegistrations();
      expect(all).toHaveLength(2);
    });
  });

  // =========================================================================
  // Spawn
  // =========================================================================

  describe("spawn", () => {
    it("creates a full AgentSession with all fields initialized", () => {
      const id = registry.register(
        makeRegistration({
          name: "spawner",
          role: "coder",
          capabilities: makeCapabilities({ codeGeneration: true }),
        }),
      );

      const session = registry.spawn(id);

      // Identity
      expect(session.id).toBe(id);
      expect(session.name).toBe("spawner");
      expect(session.role).toBe("coder");
      expect(session.status).toBe("idle");

      // Orchestration defaults
      expect(session.currentTaskId).toBeNull();
      expect(session.workload).toBe(0);
      expect(session.health).toBe(1.0);
      expect(session.lastHeartbeatAt).toBeGreaterThan(0);
      expect(session.topologyRole).toBeNull();
      expect(session.connections).toEqual([]);
      expect(session.exitCode).toBeNull();

      // Capabilities passed through
      expect(session.capabilities.codeGeneration).toBe(true);

      // Metrics initialized to zeros/defaults
      expect(session.metrics.tasksCompleted).toBe(0);
      expect(session.metrics.tasksFailed).toBe(0);
      expect(session.metrics.averageExecutionTimeMs).toBe(0);
      expect(session.metrics.successRate).toBe(0);
      expect(session.metrics.health).toBe(1.0);

      // Quality defaults
      expect(session.quality.reliability).toBe(0.5);
      expect(session.quality.speed).toBe(0.5);
      expect(session.quality.quality).toBe(0.5);

      // Board fields all null/zero/empty
      expect(session.worktreePath).toBeNull();
      expect(session.branch).toBeNull();
      expect(session.risk).toBe("low");
      expect(session.policyMode).toBeNull();
      expect(session.agentModel).toBeNull();
      expect(session.receiptCount).toBe(0);
      expect(session.blockedActionCount).toBe(0);
      expect(session.changedFilesCount).toBe(0);
      expect(session.filesTouched).toEqual([]);
      expect(session.toolBoundaryEvents).toBe(0);
      expect(session.confidence).toBeNull();
      expect(session.guardResults).toEqual([]);
      expect(session.receipt).toBeNull();
      expect(session.sentinelId).toBeNull();

      // Timestamps
      expect(session.createdAt).toBeGreaterThan(0);
      expect(session.updatedAt).toBeGreaterThan(0);
    });

    it("emits agent.spawned event", () => {
      const id = registry.register(makeRegistration());
      const emitted: unknown[] = [];
      events.on("agent.spawned", (e) => emitted.push(e));

      registry.spawn(id);

      expect(emitted).toHaveLength(1);
      const evt = emitted[0] as { kind: string; agent: AgentSession };
      expect(evt.kind).toBe("agent.spawned");
      expect(evt.agent.id).toBe(id);
    });

    it("spawn non-registered throws", () => {
      expect(() => registry.spawn("agt_nonexistent")).toThrow("not registered");
    });

    it("spawn already-spawned throws", () => {
      const id = registry.register(makeRegistration());
      registry.spawn(id);
      expect(() => registry.spawn(id)).toThrow("already spawned");
    });

    it("respects quality overrides in registration", () => {
      const id = registry.register(
        makeRegistration({
          quality: { reliability: 0.9, speed: 0.8 },
        }),
      );
      const session = registry.spawn(id);
      expect(session.quality.reliability).toBe(0.9);
      expect(session.quality.speed).toBe(0.8);
      expect(session.quality.quality).toBe(0.5); // default
    });

    it("respects policyMode and agentModel from registration", () => {
      const id = registry.register(
        makeRegistration({
          policyMode: "strict",
          agentModel: "claude-3.5-sonnet",
        }),
      );
      const session = registry.spawn(id);
      expect(session.policyMode).toBe("strict");
      expect(session.agentModel).toBe("claude-3.5-sonnet");
    });
  });

  // =========================================================================
  // Terminate
  // =========================================================================

  describe("terminate", () => {
    it("removes session and emits agent.terminated", () => {
      const id = registry.register(makeRegistration());
      registry.spawn(id);
      const emitted: unknown[] = [];
      events.on("agent.terminated", (e) => emitted.push(e));

      const result = registry.terminate(id);

      expect(result).toBe(true);
      expect(registry.getAgentSession(id)).toBeUndefined();
      expect(emitted).toHaveLength(1);
      const evt = emitted[0] as { kind: string; agentId: string; reason: string };
      expect(evt.kind).toBe("agent.terminated");
      expect(evt.agentId).toBe(id);
      expect(evt.reason).toBe("terminated");
    });

    it("returns false for non-existent agent", () => {
      expect(registry.terminate("agt_nonexistent")).toBe(false);
    });

    it("throws if agent has active task", () => {
      const id = registry.register(makeRegistration());
      registry.spawn(id);
      registry.assignTask(id, "tsk_test123");
      expect(() => registry.terminate(id)).toThrow(
        /Cannot terminate agent .+ with active task/,
      );
    });
  });

  // =========================================================================
  // Status
  // =========================================================================

  describe("updateStatus", () => {
    it("emits agent.status_changed with previous and new status", () => {
      const id = registry.register(makeRegistration());
      registry.spawn(id);
      const emitted: unknown[] = [];
      events.on("agent.status_changed", (e) => emitted.push(e));

      registry.updateStatus(id, "running");

      expect(emitted).toHaveLength(1);
      const evt = emitted[0] as {
        kind: string;
        agentId: string;
        previousStatus: AgentSessionStatus;
        newStatus: AgentSessionStatus;
      };
      expect(evt.kind).toBe("agent.status_changed");
      expect(evt.agentId).toBe(id);
      expect(evt.previousStatus).toBe("idle");
      expect(evt.newStatus).toBe("running");
    });

    it("throws for non-spawned agent", () => {
      expect(() => registry.updateStatus("agt_nope", "running")).toThrow(
        "not spawned",
      );
    });

    it("updates session.updatedAt", () => {
      const id = registry.register(makeRegistration());
      const session = registry.spawn(id);
      const before = session.updatedAt;

      vi.advanceTimersByTime(100);
      registry.updateStatus(id, "running");

      const after = registry.getAgentSession(id)!.updatedAt;
      expect(after).toBeGreaterThan(before);
    });
  });

  // =========================================================================
  // Tasks
  // =========================================================================

  describe("task assignment", () => {
    it("assignTask sets currentTaskId and status to running", () => {
      const id = registry.register(makeRegistration());
      registry.spawn(id);

      registry.assignTask(id, "tsk_abc");

      const session = registry.getAgentSession(id)!;
      expect(session.currentTaskId).toBe("tsk_abc");
      expect(session.status).toBe("running");
    });

    it("completeTask increments metrics and clears task", () => {
      const id = registry.register(makeRegistration());
      registry.spawn(id);
      registry.assignTask(id, "tsk_abc");

      registry.completeTask(id, "tsk_abc", 1000);

      const session = registry.getAgentSession(id)!;
      expect(session.currentTaskId).toBeNull();
      expect(session.status).toBe("idle");
      expect(session.metrics.tasksCompleted).toBe(1);
      expect(session.metrics.successRate).toBeGreaterThan(0);
      expect(session.metrics.averageExecutionTimeMs).toBe(1000);
    });

    it("completeTask recalculates successRate correctly", () => {
      const id = registry.register(makeRegistration());
      registry.spawn(id);

      // Complete two tasks
      registry.assignTask(id, "tsk_1");
      registry.completeTask(id, "tsk_1");
      registry.assignTask(id, "tsk_2");
      registry.completeTask(id, "tsk_2");

      const session = registry.getAgentSession(id)!;
      expect(session.metrics.tasksCompleted).toBe(2);
      expect(session.metrics.tasksFailed).toBe(0);
      expect(session.metrics.successRate).toBe(1.0);
    });

    it("completeTask throws if taskId does not match", () => {
      const id = registry.register(makeRegistration());
      registry.spawn(id);
      registry.assignTask(id, "tsk_abc");
      expect(() => registry.completeTask(id, "tsk_wrong")).toThrow();
    });

    it("failTask increments tasksFailed and recalculates successRate", () => {
      const id = registry.register(makeRegistration());
      registry.spawn(id);
      registry.assignTask(id, "tsk_abc");

      registry.failTask(id, "tsk_abc");

      const session = registry.getAgentSession(id)!;
      expect(session.currentTaskId).toBeNull();
      expect(session.status).toBe("idle");
      expect(session.metrics.tasksFailed).toBe(1);
      expect(session.metrics.successRate).toBe(0);
    });

    it("failTask throws if taskId does not match", () => {
      const id = registry.register(makeRegistration());
      registry.spawn(id);
      registry.assignTask(id, "tsk_abc");
      expect(() => registry.failTask(id, "tsk_wrong")).toThrow();
    });

    it("successRate reflects mix of completed and failed", () => {
      const id = registry.register(makeRegistration());
      registry.spawn(id);

      // 2 successes, 1 failure
      registry.assignTask(id, "tsk_1");
      registry.completeTask(id, "tsk_1");
      registry.assignTask(id, "tsk_2");
      registry.completeTask(id, "tsk_2");
      registry.assignTask(id, "tsk_3");
      registry.failTask(id, "tsk_3");

      const session = registry.getAgentSession(id)!;
      expect(session.metrics.tasksCompleted).toBe(2);
      expect(session.metrics.tasksFailed).toBe(1);
      // successRate = 2 / (2 + 1) = 0.666...
      expect(session.metrics.successRate).toBeCloseTo(2 / 3, 5);
    });
  });

  // =========================================================================
  // Queries
  // =========================================================================

  describe("queries", () => {
    it("getState returns Record<string, AgentSession> (not Map)", () => {
      const id = registry.register(makeRegistration());
      registry.spawn(id);

      const state = registry.getState();

      expect(typeof state).toBe("object");
      expect(state).not.toBeInstanceOf(Map);
      expect(state[id]).toBeDefined();
      expect(state[id]!.id).toBe(id);
    });

    it("getActiveAgents returns only running agents", () => {
      const id1 = registry.register(makeRegistration({ name: "a" }));
      const id2 = registry.register(makeRegistration({ name: "b" }));
      registry.spawn(id1);
      registry.spawn(id2);
      registry.assignTask(id1, "tsk_x"); // sets to "running"

      const active = registry.getActiveAgents();
      expect(active).toHaveLength(1);
      expect(active[0]!.id).toBe(id1);
    });

    it("getIdleAgents returns only idle agents", () => {
      const id1 = registry.register(makeRegistration({ name: "a" }));
      const id2 = registry.register(makeRegistration({ name: "b" }));
      registry.spawn(id1);
      registry.spawn(id2);
      registry.assignTask(id1, "tsk_x"); // sets to "running"

      const idle = registry.getIdleAgents();
      expect(idle).toHaveLength(1);
      expect(idle[0]!.id).toBe(id2);
    });

    it("getAgentsByCapability('coding') returns agents with codeGeneration", () => {
      const id1 = registry.register(
        makeRegistration({
          name: "coder",
          capabilities: makeCapabilities({ codeGeneration: true }),
        }),
      );
      const id2 = registry.register(
        makeRegistration({
          name: "researcher",
          capabilities: makeCapabilities({ research: true }),
        }),
      );
      registry.spawn(id1);
      registry.spawn(id2);

      const coders = registry.getAgentsByCapability("coding");
      expect(coders).toHaveLength(1);
      expect(coders[0]!.id).toBe(id1);
    });

    it("getAgentsByCapability('research') returns agents with research", () => {
      const id = registry.register(
        makeRegistration({
          name: "researcher",
          capabilities: makeCapabilities({ research: true }),
        }),
      );
      registry.spawn(id);

      const result = registry.getAgentsByCapability("research");
      expect(result).toHaveLength(1);
      expect(result[0]!.id).toBe(id);
    });

    it("getAgentsByCapability('detection') returns agents with securityAnalysis", () => {
      const id = registry.register(
        makeRegistration({
          name: "sentinel",
          capabilities: makeCapabilities({ securityAnalysis: true }),
        }),
      );
      registry.spawn(id);

      const result = registry.getAgentsByCapability("detection");
      expect(result).toHaveLength(1);
    });

    it("getAgentsByCapability('custom') checks tools array", () => {
      const id = registry.register(
        makeRegistration({
          name: "specialist",
          capabilities: makeCapabilities({ tools: ["custom"] }),
        }),
      );
      registry.spawn(id);

      const result = registry.getAgentsByCapability("custom");
      expect(result).toHaveLength(1);
    });

    it("getAgentSession returns single session or undefined", () => {
      const id = registry.register(makeRegistration());
      expect(registry.getAgentSession(id)).toBeUndefined(); // not spawned
      registry.spawn(id);
      expect(registry.getAgentSession(id)).toBeDefined();
      expect(registry.getAgentSession(id)!.id).toBe(id);
    });

    it("getAgentCount returns number of active sessions", () => {
      expect(registry.getAgentCount()).toBe(0);
      const id = registry.register(makeRegistration());
      registry.spawn(id);
      expect(registry.getAgentCount()).toBe(1);
    });
  });

  // =========================================================================
  // Health
  // =========================================================================

  describe("health checks", () => {
    it("heartbeat resets consecutiveMisses and updates lastHeartbeatAt", () => {
      const id = registry.register(makeRegistration());
      registry.spawn(id);

      vi.advanceTimersByTime(5000);
      registry.heartbeat(id);

      const health = registry.getHealthStatus();
      expect(health[id]).toBeDefined();
      expect(health[id]!.consecutiveMisses).toBe(0);
      expect(health[id]!.healthy).toBe(true);
    });

    it("heartbeat emits agent.heartbeat event", () => {
      const id = registry.register(makeRegistration());
      registry.spawn(id);
      const emitted: unknown[] = [];
      events.on("agent.heartbeat", (e) => emitted.push(e));

      registry.heartbeat(id);

      expect(emitted).toHaveLength(1);
      const evt = emitted[0] as { kind: string; agentId: string };
      expect(evt.kind).toBe("agent.heartbeat");
      expect(evt.agentId).toBe(id);
    });

    it("health check detects missed heartbeats and sets status to failed", () => {
      const config: AgentRegistryConfig = {
        healthCheckIntervalMs: 1000,
        maxMissedHeartbeats: 2,
      };
      const reg = new AgentRegistry(events, config);
      const id = reg.register(makeRegistration());
      reg.spawn(id);

      reg.startHealthChecks();

      // Advance past 3 intervals (need >= 2 misses)
      vi.advanceTimersByTime(3000);

      const session = reg.getAgentSession(id)!;
      expect(session.status).toBe("failed");

      const health = reg.getHealthStatus();
      expect(health[id]!.healthy).toBe(false);

      reg.dispose();
    });

    it("health check emits status_changed when agent fails", () => {
      const config: AgentRegistryConfig = {
        healthCheckIntervalMs: 1000,
        maxMissedHeartbeats: 2,
      };
      const reg = new AgentRegistry(events, config);
      const id = reg.register(makeRegistration());
      reg.spawn(id);

      const statusChanges: unknown[] = [];
      events.on("agent.status_changed", (e) => statusChanges.push(e));

      reg.startHealthChecks();
      vi.advanceTimersByTime(3000);

      // Should have emitted status_changed to "failed"
      const failEvent = statusChanges.find(
        (e) => (e as { newStatus: string }).newStatus === "failed",
      );
      expect(failEvent).toBeDefined();

      reg.dispose();
    });

    it("emits the failed transition only once after the threshold is crossed", () => {
      const config: AgentRegistryConfig = {
        healthCheckIntervalMs: 1000,
        maxMissedHeartbeats: 2,
      };
      const reg = new AgentRegistry(events, config);
      const id = reg.register(makeRegistration());
      reg.spawn(id);

      const statusChanges: Array<{ newStatus: string }> = [];
      events.on("agent.status_changed", (e) =>
        statusChanges.push({ newStatus: e.newStatus }),
      );

      reg.startHealthChecks();
      vi.advanceTimersByTime(5000);

      expect(
        statusChanges.filter((event) => event.newStatus === "failed"),
      ).toHaveLength(1);

      reg.dispose();
    });

    it("startHealthChecks is idempotent", () => {
      registry.startHealthChecks();
      registry.startHealthChecks(); // should not throw or create duplicate timers
      registry.stopHealthChecks();
    });

    it("getHealthStatus returns Record not Map", () => {
      const health = registry.getHealthStatus();
      expect(typeof health).toBe("object");
      expect(health).not.toBeInstanceOf(Map);
    });
  });

  // =========================================================================
  // Dispose
  // =========================================================================

  describe("dispose", () => {
    it("clears health check timer", () => {
      registry.startHealthChecks();
      registry.dispose();
      // After dispose, advancing timers should not trigger health checks
      const id = registry.register(makeRegistration());
      registry.spawn(id);
      vi.advanceTimersByTime(100_000);
      // Agent should still be healthy (no health check ran)
      const session = registry.getAgentSession(id)!;
      expect(session.status).toBe("idle");
    });

    it("does NOT call events.dispose()", () => {
      const disposeSpy = vi.spyOn(events, "dispose");
      registry.dispose();
      expect(disposeSpy).not.toHaveBeenCalled();
      disposeSpy.mockRestore();
    });
  });

  // =========================================================================
  // Serialization
  // =========================================================================

  describe("serialization", () => {
    it("getState returns a defensive copy", () => {
      const id = registry.register(
        makeRegistration({
          name: "original-agent",
          capabilities: makeCapabilities({ languages: ["typescript"] }),
        }),
      );
      registry.spawn(id);

      const state = registry.getState();
      state[id]!.name = "mutated-agent";
      state[id]!.capabilities.languages.push("rust");

      const live = registry.getAgentSession(id);
      expect(live?.name).toBe("original-agent");
      expect(live?.capabilities.languages).toEqual(["typescript"]);
    });

    it("JSON round-trip of getState() works cleanly", () => {
      const id = registry.register(
        makeRegistration({
          name: "serializable",
          role: "sentinel",
          capabilities: makeCapabilities({ securityAnalysis: true }),
        }),
      );
      registry.spawn(id);

      const state = registry.getState();
      const json = JSON.stringify(state);
      const parsed = JSON.parse(json) as Record<string, AgentSession>;

      expect(parsed[id]).toBeDefined();
      expect(parsed[id]!.name).toBe("serializable");
      expect(parsed[id]!.role).toBe("sentinel");
      expect(parsed[id]!.capabilities.securityAnalysis).toBe(true);
    });
  });
});
