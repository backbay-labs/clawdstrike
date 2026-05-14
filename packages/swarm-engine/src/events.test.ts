import { describe, it, expect, vi } from "vitest";
import {
  TypedEventEmitter,
  type SwarmEngineEventMap,
  type SwarmEngineEvent,
  type AgentSpawnedEvent,
  type TaskCreatedEvent,
  type HookTriggeredEvent,
} from "./events.js";
import type {
  AgentSession,
  AgentMetrics,
  Task,
} from "./types.js";

// ============================================================================
// Test Fixtures
// ============================================================================

function makeAgentMetrics(): AgentMetrics {
  return {
    tasksCompleted: 0,
    tasksFailed: 0,
    averageExecutionTimeMs: 0,
    successRate: 1,
    cpuUsage: 0.1,
    memoryUsageBytes: 1024,
    messagesProcessed: 0,
    lastActivityAt: Date.now(),
    responseTimeMs: 50,
    health: 1,
  };
}

function makeAgentSession(overrides?: Partial<AgentSession>): AgentSession {
  return {
    id: "agt_01HXKTEST000000000000000",
    name: "test-agent",
    role: "worker",
    status: "idle",
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
      maxMemoryUsageBytes: 1024 * 1024,
      maxExecutionTimeMs: 60_000,
    },
    metrics: makeAgentMetrics(),
    quality: { reliability: 1, speed: 1, quality: 1 },
    currentTaskId: null,
    workload: 0,
    health: 1,
    lastHeartbeatAt: Date.now(),
    topologyRole: null,
    connections: [],
    worktreePath: null,
    branch: null,
    risk: "low",
    policyMode: null,
    agentModel: null,
    receiptCount: 0,
    blockedActionCount: 0,
    changedFilesCount: 0,
    filesTouched: [],
    toolBoundaryEvents: 0,
    confidence: null,
    guardResults: [],
    receipt: null,
    sentinelId: null,
    createdAt: Date.now(),
    updatedAt: Date.now(),
    exitCode: null,
    ...overrides,
  };
}

function makeTask(overrides?: Partial<Task>): Task {
  return {
    id: "tsk_01HXKTEST000000000000000",
    swarmEngineId: "swe_01HXKTEST000000000000000",
    type: "coding",
    name: "test-task",
    description: "A test task",
    priority: "normal",
    status: "created",
    sequence: 1,
    assignedTo: null,
    dependencies: [],
    input: {},
    output: null,
    timeoutMs: 300_000,
    retries: 0,
    maxRetries: 3,
    taskPrompt: null,
    previewLines: [],
    huntId: null,
    artifactIds: [],
    receipt: null,
    metadata: {},
    createdAt: Date.now(),
    startedAt: null,
    completedAt: null,
    updatedAt: Date.now(),
    ...overrides,
  };
}

// ============================================================================
// All 23 event kind strings
// ============================================================================

const ALL_EVENT_KINDS = [
  "agent.spawned",
  "agent.status_changed",
  "agent.heartbeat",
  "agent.terminated",
  "task.created",
  "task.assigned",
  "task.status_changed",
  "task.completed",
  "task.failed",
  "task.progress",
  "topology.updated",
  "topology.rebalanced",
  "topology.leader_elected",
  "consensus.proposed",
  "consensus.vote_cast",
  "consensus.resolved",
  "memory.store",
  "memory.search",
  "hooks.triggered",
  "hooks.completed",
  "guard.evaluated",
  "action.denied",
  "action.completed",
] as const;

// ============================================================================
// TypedEventEmitter Tests
// ============================================================================

describe("TypedEventEmitter", () => {
  // Simple event map for basic tests
  type TestEvents = {
    ping: { value: number };
    pong: { reply: string };
  };

  describe("on/emit", () => {
    it("registers handler and receives correct data on emit", () => {
      const emitter = new TypedEventEmitter<TestEvents>();
      const handler = vi.fn();

      emitter.on("ping", handler);
      emitter.emit("ping", { value: 42 });

      expect(handler).toHaveBeenCalledOnce();
      expect(handler).toHaveBeenCalledWith({ value: 42 });
    });

    it("emits typed events via SwarmEngineEventMap", () => {
      const emitter = new TypedEventEmitter<SwarmEngineEventMap>();
      const handler = vi.fn();

      const agent = makeAgentSession();
      const event: AgentSpawnedEvent = {
        kind: "agent.spawned",
        agent,
        receipt: null,
        sourceAgentId: null,
        timestamp: Date.now(),
      };

      emitter.on("agent.spawned", handler);
      emitter.emit("agent.spawned", event);

      expect(handler).toHaveBeenCalledOnce();
      const received = handler.mock.calls[0][0] as AgentSpawnedEvent;
      expect(received.kind).toBe("agent.spawned");
      expect(received.agent.id).toBe("agt_01HXKTEST000000000000000");
    });

    it("emit returns void and does not throw", () => {
      const emitter = new TypedEventEmitter<TestEvents>();
      const result = emitter.emit("ping", { value: 1 });
      expect(result).toBeUndefined();
    });

    it("delivers multiple emits in order", () => {
      const emitter = new TypedEventEmitter<TestEvents>();
      const values: number[] = [];

      emitter.on("ping", (data) => values.push(data.value));
      emitter.emit("ping", { value: 1 });
      emitter.emit("ping", { value: 2 });
      emitter.emit("ping", { value: 3 });

      expect(values).toEqual([1, 2, 3]);
    });
  });

  describe("per-event cleanup", () => {
    it("removeAllListeners(event) removes only that event's listeners (Pitfall 1)", () => {
      const emitter = new TypedEventEmitter<SwarmEngineEventMap>();
      const spawnedHandler = vi.fn();
      const taskCreatedHandler = vi.fn();

      emitter.on("agent.spawned", spawnedHandler);
      emitter.on("task.created", taskCreatedHandler);

      // Remove only agent.spawned listeners
      emitter.removeAllListeners("agent.spawned");

      // Emit both events
      emitter.emit("agent.spawned", {
        kind: "agent.spawned",
        agent: makeAgentSession(),
        receipt: null,
        sourceAgentId: null,
        timestamp: Date.now(),
      });
      emitter.emit("task.created", {
        kind: "task.created",
        task: makeTask(),
        sourceAgentId: null,
        timestamp: Date.now(),
      });

      // Only task.created handler should have fired
      expect(spawnedHandler).not.toHaveBeenCalled();
      expect(taskCreatedHandler).toHaveBeenCalledOnce();
    });

    it("cleanup function removes only the specific listener", () => {
      const emitter = new TypedEventEmitter<TestEvents>();
      const handler1 = vi.fn();
      const handler2 = vi.fn();

      const cleanup1 = emitter.on("ping", handler1);
      emitter.on("ping", handler2);

      cleanup1();
      emitter.emit("ping", { value: 99 });

      expect(handler1).not.toHaveBeenCalled();
      expect(handler2).toHaveBeenCalledOnce();
      expect(handler2).toHaveBeenCalledWith({ value: 99 });
    });

    it("tracks duplicate registrations of the same handler independently", () => {
      const emitter = new TypedEventEmitter<TestEvents>();
      const handler = vi.fn();

      const cleanup1 = emitter.on("ping", handler);
      const cleanup2 = emitter.on("ping", handler);

      expect(emitter.listenerCount("ping")).toBe(2);

      cleanup1();
      emitter.emit("ping", { value: 99 });

      expect(handler).toHaveBeenCalledOnce();
      expect(handler).toHaveBeenCalledWith({ value: 99 });
      expect(emitter.listenerCount("ping")).toBe(1);

      cleanup2();
      expect(emitter.listenerCount("ping")).toBe(0);
    });
  });

  describe("cross-listener isolation", () => {
    it("each listener receives its own deep clone (Pitfall 2)", () => {
      const emitter = new TypedEventEmitter<TestEvents>();
      let listenerAData: Record<string, unknown> | undefined;
      let listenerBData: Record<string, unknown> | undefined;

      emitter.on("ping", (data) => {
        // Listener A mutates its copy
        (data as Record<string, unknown>).mutated = true;
        listenerAData = data as Record<string, unknown>;
      });

      emitter.on("ping", (data) => {
        // Listener B should see the original data, unmodified
        listenerBData = data as Record<string, unknown>;
      });

      emitter.emit("ping", { value: 42 });

      expect(listenerAData!.mutated).toBe(true);
      expect(listenerBData!.mutated).toBeUndefined();
      expect(listenerBData!.value).toBe(42);
    });

    it("each listener gets a distinct object reference", () => {
      const emitter = new TypedEventEmitter<TestEvents>();
      const refs: unknown[] = [];

      emitter.on("ping", (data) => {
        refs.push(data);
      });
      emitter.on("ping", (data) => {
        refs.push(data);
      });

      emitter.emit("ping", { value: 7 });
      expect(refs).toHaveLength(2);
      expect(refs[0]).not.toBe(refs[1]);
    });
  });

  describe("listenerCount", () => {
    it("returns accurate count after adding listeners", () => {
      const emitter = new TypedEventEmitter<TestEvents>();

      emitter.on("ping", () => {});
      emitter.on("ping", () => {});
      emitter.on("ping", () => {});

      expect(emitter.listenerCount("ping")).toBe(3);
    });

    it("decrements count when cleanup function is called", () => {
      const emitter = new TypedEventEmitter<TestEvents>();

      const cleanup1 = emitter.on("ping", () => {});
      emitter.on("ping", () => {});
      emitter.on("ping", () => {});

      expect(emitter.listenerCount("ping")).toBe(3);
      cleanup1();
      expect(emitter.listenerCount("ping")).toBe(2);
    });

    it("returns 0 for unregistered event", () => {
      const emitter = new TypedEventEmitter<TestEvents>();
      expect(emitter.listenerCount("pong")).toBe(0);
    });

    it("returns 0 for event with no registered listeners (never used)", () => {
      const emitter = new TypedEventEmitter<SwarmEngineEventMap>();
      expect(emitter.listenerCount("task.created")).toBe(0);
    });
  });

  describe("dispose", () => {
    it("removes all listeners across all events", () => {
      const emitter = new TypedEventEmitter<SwarmEngineEventMap>();
      const handler1 = vi.fn();
      const handler2 = vi.fn();
      const handler3 = vi.fn();

      emitter.on("agent.spawned", handler1);
      emitter.on("task.created", handler2);
      emitter.on("topology.updated", handler3);

      emitter.dispose();

      expect(emitter.listenerCount("agent.spawned")).toBe(0);
      expect(emitter.listenerCount("task.created")).toBe(0);
      expect(emitter.listenerCount("topology.updated")).toBe(0);
    });

    it("emitting after dispose does not call any handler", () => {
      const emitter = new TypedEventEmitter<SwarmEngineEventMap>();
      const handler = vi.fn();

      emitter.on("agent.spawned", handler);
      emitter.dispose();

      emitter.emit("agent.spawned", {
        kind: "agent.spawned",
        agent: makeAgentSession(),
        receipt: null,
        sourceAgentId: null,
        timestamp: Date.now(),
      });

      expect(handler).not.toHaveBeenCalled();
    });
  });

  describe("removeAllListeners no-arg", () => {
    it("removes all listeners across all events when called without argument", () => {
      const emitter = new TypedEventEmitter<TestEvents>();
      const pingHandler = vi.fn();
      const pongHandler = vi.fn();

      emitter.on("ping", pingHandler);
      emitter.on("pong", pongHandler);

      emitter.removeAllListeners();

      emitter.emit("ping", { value: 1 });
      emitter.emit("pong", { reply: "hi" });

      expect(pingHandler).not.toHaveBeenCalled();
      expect(pongHandler).not.toHaveBeenCalled();
      expect(emitter.listenerCount("ping")).toBe(0);
      expect(emitter.listenerCount("pong")).toBe(0);
    });
  });
});

// ============================================================================
// SwarmEngineEvent Tests
// ============================================================================

describe("SwarmEngineEvent", () => {
  it("discriminated union narrows correctly in switch/case on kind field", () => {
    function getEventCategory(event: SwarmEngineEvent): string {
      switch (event.kind) {
        case "agent.spawned":
        case "agent.status_changed":
        case "agent.heartbeat":
        case "agent.terminated":
          return "agent";
        case "task.created":
        case "task.assigned":
        case "task.status_changed":
        case "task.completed":
        case "task.failed":
        case "task.progress":
          return "task";
        case "topology.updated":
        case "topology.rebalanced":
        case "topology.leader_elected":
          return "topology";
        case "consensus.proposed":
        case "consensus.vote_cast":
        case "consensus.resolved":
          return "consensus";
        case "memory.store":
        case "memory.search":
          return "memory";
        case "hooks.triggered":
        case "hooks.completed":
          return "hooks";
        case "guard.evaluated":
        case "action.denied":
        case "action.completed":
          return "guard";
        default: {
          const _exhaustive: never = event;
          return _exhaustive;
        }
      }
    }

    // Runtime test: AgentSpawnedEvent narrows correctly
    const spawnedEvent: AgentSpawnedEvent = {
      kind: "agent.spawned",
      agent: makeAgentSession(),
      receipt: null,
      sourceAgentId: null,
      timestamp: Date.now(),
    };
    expect(getEventCategory(spawnedEvent)).toBe("agent");

    // Runtime test: TaskCreatedEvent narrows correctly
    const taskEvent: TaskCreatedEvent = {
      kind: "task.created",
      task: makeTask(),
      sourceAgentId: null,
      timestamp: Date.now(),
    };
    expect(getEventCategory(taskEvent)).toBe("task");

    // Runtime test: HookTriggeredEvent narrows correctly
    const hookEvent: HookTriggeredEvent = {
      kind: "hooks.triggered",
      hookName: "pre_action",
      hookCategory: "core",
      triggerContext: {},
      sourceAgentId: null,
      timestamp: Date.now(),
    };
    expect(getEventCategory(hookEvent)).toBe("hooks");
  });

  it("SwarmEngineEventMap has 23 entries (all distinct)", () => {
    expect(ALL_EVENT_KINDS.length).toBe(23);
    expect(new Set(ALL_EVENT_KINDS).size).toBe(23);
  });

  it("all 23 kind strings match known event categories", () => {
    const categories = {
      agent: ALL_EVENT_KINDS.filter((k) => k.startsWith("agent.")),
      task: ALL_EVENT_KINDS.filter((k) => k.startsWith("task.")),
      topology: ALL_EVENT_KINDS.filter((k) => k.startsWith("topology.")),
      consensus: ALL_EVENT_KINDS.filter((k) => k.startsWith("consensus.")),
      memory: ALL_EVENT_KINDS.filter((k) => k.startsWith("memory.")),
      hooks: ALL_EVENT_KINDS.filter((k) => k.startsWith("hooks.")),
      guard: ALL_EVENT_KINDS.filter((k) => k.startsWith("guard.") || k.startsWith("action.")),
    };

    expect(categories.agent).toHaveLength(4);
    expect(categories.task).toHaveLength(6);
    expect(categories.topology).toHaveLength(3);
    expect(categories.consensus).toHaveLength(3);
    expect(categories.memory).toHaveLength(2);
    expect(categories.hooks).toHaveLength(2);
    expect(categories.guard).toHaveLength(3);
  });
});
