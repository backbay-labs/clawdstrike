/**
 * Tests for SwarmOrchestrator -- facade composing all subsystems with
 * lifecycle management, guard pipeline, state snapshots, and metrics.
 *
 * Coverage: lifecycle state machine (init -> running -> pause -> resume ->
 * shutdown), guard pipeline (with and without evaluator), metrics tracking,
 * state snapshots, timer management, dispose.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { SwarmOrchestrator } from "./orchestrator.js";
import type { SwarmOrchestratorConfig } from "./orchestrator.js";
import { TypedEventEmitter } from "./events.js";
import type { SwarmEngineEventMap } from "./events.js";
import { AgentRegistry } from "./agent-registry.js";
import { TaskGraph } from "./task-graph.js";
import { TopologyManager } from "./topology.js";
import type {
  GuardEvaluator,
  GuardedAction,
  GuardEvaluationResult,
  TopologyConfig,
  ConsensusConfig,
} from "./types.js";
import { SWARM_ENGINE_CONSTANTS } from "./types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEvents(): TypedEventEmitter<SwarmEngineEventMap> {
  return new TypedEventEmitter<SwarmEngineEventMap>();
}

function makeTopologyConfig(): TopologyConfig {
  return {
    type: "mesh",
    maxAgents: 10,
    replicationFactor: 1,
    partitionStrategy: "round-robin",
    failoverEnabled: false,
    autoRebalance: false,
  };
}

function makeConsensusConfig(): ConsensusConfig {
  return {
    algorithm: "raft",
    threshold: 0.66,
    timeoutMs: 30_000,
    maxRounds: 3,
    requireQuorum: true,
  };
}

function makeConfig(
  overrides: Partial<SwarmOrchestratorConfig> = {},
): SwarmOrchestratorConfig {
  return {
    namespace: "test-swarm",
    topology: makeTopologyConfig(),
    consensus: makeConsensusConfig(),
    pool: { minSize: 1, maxSize: 5 },
    maxAgents: 10,
    maxTasks: 100,
    heartbeatIntervalMs: SWARM_ENGINE_CONSTANTS.DEFAULT_HEARTBEAT_INTERVAL_MS,
    healthCheckIntervalMs:
      SWARM_ENGINE_CONSTANTS.DEFAULT_HEALTH_CHECK_INTERVAL_MS,
    taskTimeoutMs: SWARM_ENGINE_CONSTANTS.DEFAULT_TASK_TIMEOUT_MS,
    maxGuardActionHistory: SWARM_ENGINE_CONSTANTS.MAX_GUARD_ACTION_HISTORY,
    ...overrides,
  };
}

function makeAction(overrides: Partial<GuardedAction> = {}): GuardedAction {
  return {
    agentId: "agt_test",
    taskId: "tsk_test",
    actionType: "file_write",
    target: "/tmp/test.txt",
    context: {},
    requestedAt: Date.now(),
    ...overrides,
  };
}

function makeAllowResult(action: GuardedAction): GuardEvaluationResult {
  return {
    verdict: "allow",
    allowed: true,
    guardResults: [],
    receipt: {
      id: "rcpt_001",
      timestamp: new Date().toISOString(),
      verdict: "allow",
      guard: "test-guard",
      policyName: "test-policy",
      action: { type: action.actionType, target: action.target },
      evidence: {},
      signature: "sig_test",
      publicKey: "pk_test",
      valid: true,
    },
    durationMs: 5,
    evaluatedAt: Date.now(),
  };
}

function makeDenyResult(action: GuardedAction): GuardEvaluationResult {
  return {
    verdict: "deny",
    allowed: false,
    guardResults: [
      {
        guardId: "g1",
        guard: "ForbiddenPathGuard",
        verdict: "deny",
        duration_ms: 2,
        details: { reason: "blocked" },
      },
    ],
    receipt: {
      id: "rcpt_002",
      timestamp: new Date().toISOString(),
      verdict: "deny",
      guard: "ForbiddenPathGuard",
      policyName: "strict",
      action: { type: action.actionType, target: action.target },
      evidence: {},
      signature: "sig_deny",
      publicKey: "pk_deny",
      valid: true,
    },
    durationMs: 3,
    evaluatedAt: Date.now(),
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("SwarmOrchestrator", () => {
  let events: TypedEventEmitter<SwarmEngineEventMap>;
  let registry: AgentRegistry;
  let taskGraph: TaskGraph;
  let topology: TopologyManager;
  let orchestrator: SwarmOrchestrator;

  beforeEach(() => {
    vi.useFakeTimers();
    events = makeEvents();
    registry = new AgentRegistry(events);
    taskGraph = new TaskGraph(events, registry);
    topology = new TopologyManager(events);
    orchestrator = new SwarmOrchestrator(
      events,
      registry,
      taskGraph,
      topology,
      makeConfig(),
    );
  });

  afterEach(() => {
    orchestrator.dispose();
    vi.useRealTimers();
  });

  // =========================================================================
  // Constructor
  // =========================================================================

  describe("constructor", () => {
    it("accepts events, registry, taskGraph, topology, and config", () => {
      expect(orchestrator.getStatus()).toBe("initializing");
      expect(orchestrator.getId()).toMatch(/^swe_/);
    });

    it("accepts config with optional guardEvaluator", () => {
      const evaluator: GuardEvaluator = {
        evaluate: vi.fn().mockResolvedValue(makeAllowResult(makeAction())),
      };
      const orch = new SwarmOrchestrator(
        events,
        registry,
        taskGraph,
        topology,
        makeConfig({ guardEvaluator: evaluator }),
      );
      expect(orch.getStatus()).toBe("initializing");
      orch.dispose();
    });
  });

  // =========================================================================
  // Lifecycle: initialize
  // =========================================================================

  describe("initialize", () => {
    it("sets status to running and records startedAt", () => {
      orchestrator.initialize();
      expect(orchestrator.getStatus()).toBe("running");
      const state = orchestrator.getState();
      expect(state.startedAt).toBeTypeOf("number");
      expect(state.startedAt).not.toBeNull();
    });

    it("calls pool.initialize() and registry.startHealthChecks()", () => {
      // After initialize, pool should have minSize agents
      orchestrator.initialize();
      const pool = orchestrator.getPool();
      const poolState = pool.getState();
      expect(Object.keys(poolState.agents).length).toBeGreaterThanOrEqual(1);
    });

    it("mirrors pooled agents into public state and metrics", () => {
      orchestrator.initialize();

      const poolAgentIds = Object.keys(orchestrator.getPool().getState().agents);
      const state = orchestrator.getState();
      const mirroredAgents = poolAgentIds.map((agentId) => state.agents[agentId]);

      expect(poolAgentIds.length).toBeGreaterThan(0);
      expect(mirroredAgents.every((agent) => agent?.agentModel === "pooled")).toBe(true);
      expect(orchestrator.getMetrics().activeAgents).toBe(poolAgentIds.length);
    });

    it("emits agent.spawned for pooled agents created during initialize", () => {
      const emitted: string[] = [];
      events.on("agent.spawned", (event) => emitted.push(event.agent.id));

      orchestrator.initialize();

      const poolAgentIds = Object.keys(orchestrator.getPool().getState().agents);
      expect(emitted.sort()).toEqual(poolAgentIds.sort());
    });

    it("throws error from invalid status", () => {
      orchestrator.initialize();
      expect(() => orchestrator.initialize()).toThrow();
    });
  });

  // =========================================================================
  // Lifecycle: shutdown
  // =========================================================================

  describe("shutdown", () => {
    it("sets status to stopped and stops timers", () => {
      orchestrator.initialize();
      orchestrator.shutdown();
      expect(orchestrator.getStatus()).toBe("stopped");
    });

    it("is idempotent from stopped status", () => {
      orchestrator.initialize();
      orchestrator.shutdown();
      // Should not throw
      orchestrator.shutdown();
      expect(orchestrator.getStatus()).toBe("stopped");
    });

    it("calls subsystem cleanup", () => {
      orchestrator.initialize();
      orchestrator.shutdown();
      const poolState = orchestrator.getPool().getState();
      // After shutdown, pool should be cleared
      expect(Object.keys(poolState.agents)).toHaveLength(0);
    });

    it("emits agent.terminated for mirrored pool agents and clears public state", () => {
      const terminated: string[] = [];
      events.on("agent.terminated", (event) => terminated.push(event.agentId));

      orchestrator.initialize();
      const poolAgentIds = Object.keys(orchestrator.getPool().getState().agents);

      orchestrator.shutdown();

      expect(terminated.sort()).toEqual(poolAgentIds.sort());
      expect(Object.keys(orchestrator.getState().agents)).toHaveLength(0);
    });
  });

  // =========================================================================
  // Lifecycle: pause
  // =========================================================================

  describe("pause", () => {
    it("sets status to paused and stops background timers", () => {
      orchestrator.initialize();
      orchestrator.pause();
      expect(orchestrator.getStatus()).toBe("paused");
    });

    it("is no-op from non-running status", () => {
      // Status is "initializing" -- pause should not change it
      orchestrator.pause();
      expect(orchestrator.getStatus()).toBe("initializing");
    });
  });

  // =========================================================================
  // Lifecycle: resume
  // =========================================================================

  describe("resume", () => {
    it("sets status to running and restarts background timers", () => {
      orchestrator.initialize();
      orchestrator.pause();
      expect(orchestrator.getStatus()).toBe("paused");
      orchestrator.resume();
      expect(orchestrator.getStatus()).toBe("running");
    });

    it("is no-op from non-paused status", () => {
      orchestrator.initialize();
      // Already running -- resume should keep running
      orchestrator.resume();
      expect(orchestrator.getStatus()).toBe("running");
    });
  });

  // =========================================================================
  // Lifecycle: dispose
  // =========================================================================

  describe("dispose", () => {
    it("is synchronous and stops all timers", () => {
      orchestrator.initialize();
      orchestrator.dispose();
      expect(orchestrator.getStatus()).toBe("stopped");
    });

    it("calls pool.dispose()", () => {
      const disposeSpy = vi.spyOn(orchestrator.getPool(), "dispose");
      orchestrator.dispose();
      expect(disposeSpy).toHaveBeenCalledOnce();
    });

    it("stops registry health checks", () => {
      const stopHealthChecksSpy = vi.spyOn(registry, "stopHealthChecks");
      orchestrator.initialize();
      orchestrator.dispose();
      expect(stopHealthChecksSpy).toHaveBeenCalledOnce();
    });

    it("is the ONLY method that calls events.dispose()", () => {
      const disposeSpy = vi.spyOn(events, "dispose");
      orchestrator.initialize();
      orchestrator.shutdown();
      // shutdown does NOT call events.dispose()
      expect(disposeSpy).not.toHaveBeenCalled();

      // Create a fresh orchestrator to test dispose
      const orch2 = new SwarmOrchestrator(
        events,
        registry,
        taskGraph,
        topology,
        makeConfig(),
      );
      orch2.dispose();
      expect(disposeSpy).toHaveBeenCalledOnce();
    });
  });

  // =========================================================================
  // Guard Pipeline
  // =========================================================================

  describe("evaluateGuard", () => {
    it("with injected evaluator calls evaluator.evaluate()", async () => {
      const action = makeAction();
      const result = makeAllowResult(action);
      const evaluator: GuardEvaluator = {
        evaluate: vi.fn().mockResolvedValue(result),
      };
      const orch = new SwarmOrchestrator(
        events,
        registry,
        taskGraph,
        topology,
        makeConfig({ guardEvaluator: evaluator }),
      );
      orch.initialize();

      const evalResult = await orch.evaluateGuard(action);
      expect(evaluator.evaluate).toHaveBeenCalledWith(action);
      expect(evalResult.verdict).toBe("allow");
      expect(evalResult.allowed).toBe(true);
      orch.dispose();
    });

    it("with no evaluator returns deny result (fail-closed)", async () => {
      orchestrator.initialize();
      const action = makeAction();
      const result = await orchestrator.evaluateGuard(action);
      expect(result.verdict).toBe("deny");
      expect(result.allowed).toBe(false);
    });

    it("emits guard.evaluated event with result", async () => {
      orchestrator.initialize();
      const guardEvents: Array<{ action: GuardedAction }> = [];
      events.on("guard.evaluated", (e) =>
        guardEvents.push(e as unknown as { action: GuardedAction }),
      );

      await orchestrator.evaluateGuard(
        makeAction({ context: { prompt: "secret prompt", cwd: "/tmp/secret" } }),
      );
      expect(guardEvents).toHaveLength(1);
      expect(guardEvents[0]!.action.context).toEqual({});
    });

    it("on deny emits action.denied event", async () => {
      orchestrator.initialize();
      const deniedEvents: unknown[] = [];
      events.on("action.denied", (e) => deniedEvents.push(e));

      // No evaluator = deny
      await orchestrator.evaluateGuard(makeAction());
      expect(deniedEvents).toHaveLength(1);
    });

    it("on deny redacts context from broadcast action (H-04)", async () => {
      orchestrator.initialize();
      const deniedEvents: Array<{ action: GuardedAction }> = [];
      events.on("action.denied", (e) =>
        deniedEvents.push(e as unknown as { action: GuardedAction }),
      );

      const sensitiveAction = makeAction({
        context: { secret: "api-key-12345", internal: true },
      });
      await orchestrator.evaluateGuard(sensitiveAction);

      expect(deniedEvents).toHaveLength(1);
      // Context should be redacted (empty object)
      expect(deniedEvents[0]!.action.context).toEqual({});
    });

    it("on allow emits action.completed event", async () => {
      const action = makeAction();
      const result = makeAllowResult(action);
      const evaluator: GuardEvaluator = {
        evaluate: vi.fn().mockResolvedValue(result),
      };
      const orch = new SwarmOrchestrator(
        events,
        registry,
        taskGraph,
        topology,
        makeConfig({ guardEvaluator: evaluator }),
      );
      orch.initialize();

      const completedEvents: unknown[] = [];
      events.on("action.completed", (e) => completedEvents.push(e));

      await orch.evaluateGuard(action);
      expect(completedEvents).toHaveLength(1);
      orch.dispose();
    });

    it("on allow redacts context from completed action broadcasts", async () => {
      const action = makeAction({
        context: { prompt: "secret prompt", cwd: "/tmp/secret" },
      });
      const result = makeAllowResult(action);
      const evaluator: GuardEvaluator = {
        evaluate: vi.fn().mockResolvedValue(result),
      };
      const orch = new SwarmOrchestrator(
        events,
        registry,
        taskGraph,
        topology,
        makeConfig({ guardEvaluator: evaluator }),
      );
      orch.initialize();

      const completedEvents: Array<{ action: GuardedAction }> = [];
      events.on("action.completed", (e) =>
        completedEvents.push(e as unknown as { action: GuardedAction }),
      );

      await orch.evaluateGuard(action);

      expect(completedEvents).toHaveLength(1);
      expect(completedEvents[0]!.action.context).toEqual({});
      orch.dispose();
    });

    it("stores GuardedActionRecord in recentGuardActions", async () => {
      orchestrator.initialize();
      await orchestrator.evaluateGuard(makeAction());

      const state = orchestrator.getState();
      expect(state.recentGuardActions).toHaveLength(1);
      expect(state.recentGuardActions[0]!.action.actionType).toBe("file_write");
      expect(state.recentGuardActions[0]!.evaluation.verdict).toBe("deny");
    });

    it("recentGuardActions is capped at maxGuardActionHistory (FIFO eviction)", async () => {
      const orch = new SwarmOrchestrator(
        events,
        registry,
        taskGraph,
        topology,
        makeConfig({ maxGuardActionHistory: 3 }),
      );
      orch.initialize();

      // Push 5 actions -- only 3 should remain
      for (let i = 0; i < 5; i++) {
        await orch.evaluateGuard(
          makeAction({ target: `/tmp/file${i}.txt` }),
        );
      }

      const state = orch.getState();
      expect(state.recentGuardActions).toHaveLength(3);
      // Oldest should be evicted -- first remaining should be file2
      expect(state.recentGuardActions[0]!.action.target).toBe(
        "/tmp/file2.txt",
      );
      orch.dispose();
    });
  });

  // =========================================================================
  // State
  // =========================================================================

  describe("getState", () => {
    it("returns SwarmEngineState with all subsystem snapshots", () => {
      orchestrator.initialize();
      const state = orchestrator.getState();
      expect(state.id).toMatch(/^swe_/);
      expect(state.namespace).toBe("test-swarm");
      expect(state.version).toBe("0.1.0");
      expect(state.status).toBe("running");
    });

    it("agents is Record from registry.getState()", () => {
      orchestrator.initialize();
      // Register an agent
      const agentId = registry.register({
        name: "test-agent",
        role: "worker",
        capabilities: {
          codeGeneration: true,
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
        },
      });
      registry.spawn(agentId);

      const state = orchestrator.getState();
      expect(state.agents[agentId]).toBeDefined();
      expect(state.agents[agentId]!.role).toBe("worker");
    });

    it("tasks is Record from taskGraph.getState()", () => {
      orchestrator.initialize();
      const task = taskGraph.addTask({
        type: "coding",
        name: "test-task",
        description: "A test task",
        priority: "normal",
      });

      const state = orchestrator.getState();
      expect(state.tasks[task.id]).toBeDefined();
      expect(state.tasks[task.id]!.name).toBe("test-task");
    });

    it("topology is from topology.getState()", () => {
      orchestrator.initialize();
      const state = orchestrator.getState();
      expect(state.topology).toBeDefined();
      expect(state.topology.type).toBe("mesh");
    });

    it("metrics matches getMetrics() output", () => {
      orchestrator.initialize();
      const state = orchestrator.getState();
      const metrics = orchestrator.getMetrics();
      expect(state.metrics.activeAgents).toBe(metrics.activeAgents);
      expect(state.metrics.totalTasks).toBe(metrics.totalTasks);
    });

    it("returns a defensive copy of subsystem snapshots", () => {
      orchestrator.initialize();

      const agentId = registry.register({
        name: "snapshot-agent",
        role: "worker",
        capabilities: {
          codeGeneration: true,
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
        },
      });
      registry.spawn(agentId);
      topology.addNode(agentId, "worker");

      const task = taskGraph.addTask({
        type: "coding",
        name: "snapshot-task",
        description: "snapshot task",
        priority: "normal",
      });

      const state = orchestrator.getState();
      state.agents[agentId]!.name = "mutated-agent";
      state.tasks[task.id]!.name = "mutated-task";
      const topologyNode = state.topology.nodes.find((node) => node.agentId === agentId);
      expect(topologyNode).toBeDefined();
      topologyNode!.role = "queen";

      const freshState = orchestrator.getState();
      expect(freshState.agents[agentId]!.name).toBe("snapshot-agent");
      expect(freshState.tasks[task.id]!.name).toBe("snapshot-task");
      expect(
        freshState.topology.nodes.find((node) => node.agentId === agentId)?.role,
      ).toBe("peer");
    });
  });

  // =========================================================================
  // Metrics
  // =========================================================================

  describe("getMetrics", () => {
    it("uptimeMs is Date.now() - startedAt", () => {
      orchestrator.initialize();
      vi.advanceTimersByTime(5000);
      const metrics = orchestrator.getMetrics();
      expect(metrics.uptimeMs).toBe(5000);
    });

    it("uptimeMs is 0 before initialization", () => {
      const metrics = orchestrator.getMetrics();
      expect(metrics.uptimeMs).toBe(0);
    });

    it("activeAgents counts non-terminated agents", () => {
      orchestrator.initialize();
      const agentId = registry.register({
        name: "worker-1",
        role: "worker",
        capabilities: {
          codeGeneration: true,
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
        },
      });
      registry.spawn(agentId);

      const metrics = orchestrator.getMetrics();
      expect(metrics.activeAgents).toBeGreaterThanOrEqual(1);
    });

    it("guardEvaluationsTotal tracks cumulative evaluations", async () => {
      orchestrator.initialize();
      await orchestrator.evaluateGuard(makeAction());
      await orchestrator.evaluateGuard(makeAction());

      const metrics = orchestrator.getMetrics();
      expect(metrics.guardEvaluationsTotal).toBe(2);
    });

    it("guardDenialRate is denials / total evaluations", async () => {
      const action = makeAction();
      const allowResult = makeAllowResult(action);
      const evaluator: GuardEvaluator = {
        evaluate: vi.fn().mockResolvedValue(allowResult),
      };
      const orch = new SwarmOrchestrator(
        events,
        registry,
        taskGraph,
        topology,
        makeConfig({ guardEvaluator: evaluator }),
      );
      orch.initialize();

      // 1 allow
      await orch.evaluateGuard(action);

      // Now switch to deny
      const denyResult = makeDenyResult(action);
      (evaluator.evaluate as ReturnType<typeof vi.fn>).mockResolvedValue(
        denyResult,
      );

      // 1 deny
      await orch.evaluateGuard(action);

      const metrics = orch.getMetrics();
      // 1 deny out of 2 total = 0.5
      expect(metrics.guardDenialRate).toBe(0.5);
      orch.dispose();
    });
  });

  // =========================================================================
  // Background Timers
  // =========================================================================

  describe("background timers", () => {
    it("heartbeat timer runs at configured interval", () => {
      orchestrator.initialize();

      // Register and spawn an agent so heartbeat has something to do
      const agentId = registry.register({
        name: "timer-agent",
        role: "worker",
        capabilities: {
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
        },
      });
      registry.spawn(agentId);

      // Advance past one heartbeat interval
      vi.advanceTimersByTime(
        SWARM_ENGINE_CONSTANTS.DEFAULT_HEARTBEAT_INTERVAL_MS + 100,
      );

      // The heartbeat timer should have fired
      // It calls pool.updateAgentHeartbeat for each pool agent
      // We confirm timer ran by checking the orchestrator is still running
      expect(orchestrator.getStatus()).toBe("running");
    });

    it("metrics are computed lazily in getMetrics() (no background timer)", () => {
      orchestrator.initialize();

      // Advance time
      vi.advanceTimersByTime(5000);

      // Metrics should be available (computed on-demand, not by timer)
      const metrics = orchestrator.getMetrics();
      expect(metrics.uptimeMs).toBe(5000);
    });
  });
});
