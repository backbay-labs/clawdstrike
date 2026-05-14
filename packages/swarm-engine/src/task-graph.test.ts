/**
 * Tests for TaskGraph -- ported from ruflo's TaskOrchestrator with
 * swarm-engine adaptations: PriorityQueue scheduling, AgentRegistry
 * capability matching, categorized errors, progress reporting.
 *
 * Coverage: creation, dependencies, cycles, topological order, queue,
 * priority, assignment, failure/retry, cancel, timeout, progress,
 * auto-assignment, unblocking, serialization.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { TaskGraph } from "./task-graph.js";
import { TypedEventEmitter } from "./events.js";
import type { SwarmEngineEventMap } from "./events.js";
import { AgentRegistry } from "./agent-registry.js";
import type { AgentCapabilities, AgentRegistration, Task, TaskSubmission } from "./types.js";

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

function makeSubmission(
  overrides: Partial<TaskSubmission> = {},
): TaskSubmission {
  return {
    type: "coding",
    name: "Test Task",
    description: "A test task",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("TaskGraph", () => {
  let emitter: TypedEventEmitter<SwarmEngineEventMap>;
  let registry: AgentRegistry;
  let graph: TaskGraph;

  beforeEach(() => {
    emitter = new TypedEventEmitter<SwarmEngineEventMap>();
    registry = new AgentRegistry(emitter);
    graph = new TaskGraph(emitter, registry);
  });

  // =========================================================================
  // Task Creation
  // =========================================================================

  describe("addTask", () => {
    it("returns Task with generated tsk_ ID and correct defaults", () => {
      const task = graph.addTask(makeSubmission({ name: "Alpha" }));

      expect(task.id).toMatch(/^tsk_/);
      expect(task.name).toBe("Alpha");
      expect(task.type).toBe("coding");
      expect(task.status).toBe("created");
      expect(task.priority).toBe("normal");
      expect(task.sequence).toBe(1);
      expect(task.assignedTo).toBeNull();
      expect(task.dependencies).toEqual([]);
      expect(task.input).toEqual({});
      expect(task.output).toBeNull();
      expect(task.retries).toBe(0);
      expect(task.maxRetries).toBe(3);
      expect(task.timeoutMs).toBe(300_000);
      expect(task.taskPrompt).toBeNull();
      expect(task.previewLines).toEqual([]);
      expect(task.huntId).toBeNull();
      expect(task.artifactIds).toEqual([]);
      expect(task.receipt).toBeNull();
      expect(task.createdAt).toBeTypeOf("number");
      expect(task.startedAt).toBeNull();
      expect(task.completedAt).toBeNull();
    });

    it("emits task.created event", () => {
      const events: unknown[] = [];
      emitter.on("task.created", (e) => events.push(e));

      const task = graph.addTask(makeSubmission());

      expect(events).toHaveLength(1);
      expect((events[0] as { kind: string }).kind).toBe("task.created");
      expect((events[0] as { task: Task }).task.id).toBe(task.id);
    });

    it("respects custom priority, timeout, maxRetries", () => {
      const task = graph.addTask(
        makeSubmission({
          priority: "critical",
          timeoutMs: 5000,
          maxRetries: 10,
        }),
      );

      expect(task.priority).toBe("critical");
      expect(task.timeoutMs).toBe(5000);
      expect(task.maxRetries).toBe(10);
    });

    it("stores tags in metadata", () => {
      const task = graph.addTask(
        makeSubmission({ tags: ["fast", "important"] }),
      );

      expect(task.metadata).toEqual({ tags: ["fast", "important"] });
    });

    it("increments sequence for each task", () => {
      const t1 = graph.addTask(makeSubmission());
      const t2 = graph.addTask(makeSubmission());
      const t3 = graph.addTask(makeSubmission());

      expect(t1.sequence).toBe(1);
      expect(t2.sequence).toBe(2);
      expect(t3.sequence).toBe(3);
    });
  });

  // =========================================================================
  // Dependencies
  // =========================================================================

  describe("dependencies", () => {
    it("addTask with dependencies tracks them", () => {
      const t1 = graph.addTask(makeSubmission({ name: "A" }));
      const t2 = graph.addTask(
        makeSubmission({ name: "B", dependencies: [t1.id] }),
      );

      expect(t2.dependencies).toEqual([t1.id]);
      expect(graph.getDependencies(t2.id)).toEqual([t1.id]);
      expect(graph.getDependents(t1.id)).toEqual([t2.id]);
    });

    it("addTask with non-existent dependency throws", () => {
      expect(() =>
        graph.addTask(makeSubmission({ dependencies: ["tsk_nonexistent"] })),
      ).toThrow("dependency not found");
    });

    it("addDependency works and is queryable", () => {
      const t1 = graph.addTask(makeSubmission({ name: "A" }));
      const t2 = graph.addTask(makeSubmission({ name: "B" }));

      graph.addDependency(t2.id, t1.id);

      expect(graph.getDependencies(t2.id)).toContain(t1.id);
      expect(graph.getDependents(t1.id)).toContain(t2.id);
    });

    it("removeDependency removes the edge", () => {
      const t1 = graph.addTask(makeSubmission({ name: "A" }));
      const t2 = graph.addTask(
        makeSubmission({ name: "B", dependencies: [t1.id] }),
      );

      graph.removeDependency(t2.id, t1.id);

      expect(graph.getDependencies(t2.id)).toEqual([]);
      expect(graph.getDependents(t1.id)).toEqual([]);
    });
  });

  // =========================================================================
  // Cycle Detection
  // =========================================================================

  describe("cycle detection", () => {
    it("detects A -> B -> C -> A cycle", () => {
      const a = graph.addTask(makeSubmission({ name: "A" }));
      const b = graph.addTask(
        makeSubmission({ name: "B", dependencies: [a.id] }),
      );
      const c = graph.addTask(
        makeSubmission({ name: "C", dependencies: [b.id] }),
      );

      expect(() => graph.addDependency(a.id, c.id)).toThrow("cycle");
    });

    it("allows A -> B (no cycle)", () => {
      const a = graph.addTask(makeSubmission({ name: "A" }));
      const b = graph.addTask(makeSubmission({ name: "B" }));

      expect(() => graph.addDependency(b.id, a.id)).not.toThrow();
    });

    it("detects self-dependency", () => {
      const a = graph.addTask(makeSubmission({ name: "A" }));

      expect(() => graph.addDependency(a.id, a.id)).toThrow("cycle");
    });

    it("detects cycle during addTask with dependencies", () => {
      const a = graph.addTask(makeSubmission({ name: "A" }));
      const b = graph.addTask(
        makeSubmission({ name: "B", dependencies: [a.id] }),
      );

      // C depends on B, and if we add A depending on C, that would be a cycle
      // But addTask creates C then checks; let's create C depending on B
      const c = graph.addTask(
        makeSubmission({ name: "C", dependencies: [b.id] }),
      );

      // Now try to make A depend on C -- would create A -> B -> C -> A cycle
      expect(() => graph.addDependency(a.id, c.id)).toThrow("cycle");
    });
  });

  // =========================================================================
  // Topological Order
  // =========================================================================

  describe("getTopologicalOrder", () => {
    it("returns tasks in dependency-safe order for diamond graph", () => {
      // Diamond: A -> B, A -> C, B -> D, C -> D
      const a = graph.addTask(makeSubmission({ name: "A" }));
      const b = graph.addTask(
        makeSubmission({ name: "B", dependencies: [a.id] }),
      );
      const c = graph.addTask(
        makeSubmission({ name: "C", dependencies: [a.id] }),
      );
      const d = graph.addTask(
        makeSubmission({ name: "D", dependencies: [b.id, c.id] }),
      );

      const order = graph.getTopologicalOrder();
      const ids = order.map((t) => t.id);

      // A must come before B and C; B and C must come before D
      expect(ids.indexOf(a.id)).toBeLessThan(ids.indexOf(b.id));
      expect(ids.indexOf(a.id)).toBeLessThan(ids.indexOf(c.id));
      expect(ids.indexOf(b.id)).toBeLessThan(ids.indexOf(d.id));
      expect(ids.indexOf(c.id)).toBeLessThan(ids.indexOf(d.id));
    });

    it("returns all tasks", () => {
      graph.addTask(makeSubmission({ name: "A" }));
      graph.addTask(makeSubmission({ name: "B" }));
      graph.addTask(makeSubmission({ name: "C" }));

      const order = graph.getTopologicalOrder();
      expect(order).toHaveLength(3);
    });
  });

  // =========================================================================
  // Queue and Priority
  // =========================================================================

  describe("queueTask", () => {
    it("moves task to 'queued' status when not blocked", () => {
      const task = graph.addTask(makeSubmission());
      graph.queueTask(task.id);

      expect(graph.getTask(task.id)?.status).toBe("queued");
    });

    it("keeps task 'created' when dependencies are incomplete", () => {
      const a = graph.addTask(makeSubmission({ name: "A" }));
      const b = graph.addTask(
        makeSubmission({ name: "B", dependencies: [a.id] }),
      );

      graph.queueTask(b.id);

      // B is blocked by A, so stays created
      expect(graph.getTask(b.id)?.status).toBe("created");
    });

    it("emits task.status_changed on successful queue", () => {
      const events: unknown[] = [];
      emitter.on("task.status_changed", (e) => events.push(e));

      const task = graph.addTask(makeSubmission());
      graph.queueTask(task.id);

      expect(events).toHaveLength(1);
      expect(
        (events[0] as { newStatus: string }).newStatus,
      ).toBe("queued");
    });
  });

  describe("priority ordering", () => {
    it("dequeues tasks in priority order", () => {
      const low = graph.addTask(
        makeSubmission({ name: "Low", priority: "low" }),
      );
      const critical = graph.addTask(
        makeSubmission({ name: "Critical", priority: "critical" }),
      );
      const normal = graph.addTask(
        makeSubmission({ name: "Normal", priority: "normal" }),
      );

      graph.queueTask(low.id);
      graph.queueTask(critical.id);
      graph.queueTask(normal.id);

      const first = graph.getNextTask();
      const second = graph.getNextTask();
      const third = graph.getNextTask();

      expect(first?.id).toBe(critical.id);
      expect(second?.id).toBe(normal.id);
      expect(third?.id).toBe(low.id);
    });
  });

  // =========================================================================
  // Assignment and Lifecycle
  // =========================================================================

  describe("assignTask", () => {
    it("sets agent and status 'assigned'", () => {
      const agentId = registry.register(makeRegistration());
      registry.spawn(agentId);

      const task = graph.addTask(makeSubmission());
      graph.queueTask(task.id);
      graph.assignTask(task.id, agentId);

      const t = graph.getTask(task.id);
      expect(t?.assignedTo).toBe(agentId);
      expect(t?.status).toBe("assigned");
    });

    it("emits task.assigned event", () => {
      const agentId = registry.register(makeRegistration());
      registry.spawn(agentId);
      const events: unknown[] = [];
      emitter.on("task.assigned", (e) => events.push(e));

      const task = graph.addTask(makeSubmission());
      graph.queueTask(task.id);
      graph.assignTask(task.id, agentId);

      expect(events).toHaveLength(1);
      expect((events[0] as { agentId: string }).agentId).toBe(agentId);
    });

    it("throws if task is not queued", () => {
      const agentId = registry.register(makeRegistration());
      registry.spawn(agentId);
      const task = graph.addTask(makeSubmission());

      expect(() => graph.assignTask(task.id, agentId)).toThrow("not queued");
    });

    it("leaves the task queued when registry assignment fails", () => {
      const agentId = registry.register(makeRegistration());
      const task = graph.addTask(makeSubmission());
      graph.queueTask(task.id);

      expect(() => graph.assignTask(task.id, agentId)).toThrow("not spawned");

      const stored = graph.getTask(task.id);
      expect(stored?.assignedTo).toBeNull();
      expect(stored?.status).toBe("queued");
      expect(graph.getTasksByStatus("queued").map((queued) => queued.id)).toContain(
        task.id,
      );
    });
  });

  describe("startTask", () => {
    it("sets status 'running' and startedAt", () => {
      const agentId = registry.register(makeRegistration());
      registry.spawn(agentId);
      const task = graph.addTask(makeSubmission());
      graph.queueTask(task.id);
      graph.assignTask(task.id, agentId);
      graph.startTask(task.id);

      const t = graph.getTask(task.id);
      expect(t?.status).toBe("running");
      expect(t?.startedAt).toBeTypeOf("number");
    });

    it("throws if task is not assigned", () => {
      const task = graph.addTask(makeSubmission());

      expect(() => graph.startTask(task.id)).toThrow("not assigned");
    });
  });

  describe("completeTask", () => {
    it("sets status 'completed' and output", () => {
      const agentId = registry.register(makeRegistration());
      registry.spawn(agentId);
      const task = graph.addTask(makeSubmission());
      graph.queueTask(task.id);
      graph.assignTask(task.id, agentId);
      graph.startTask(task.id);
      graph.completeTask(task.id, { result: "done" });

      const t = graph.getTask(task.id);
      expect(t?.status).toBe("completed");
      expect(t?.output).toEqual({ result: "done" });
      expect(t?.completedAt).toBeTypeOf("number");
    });

    it("emits task.completed event with durationMs", () => {
      const agentId = registry.register(makeRegistration());
      registry.spawn(agentId);
      const events: unknown[] = [];
      emitter.on("task.completed", (e) => events.push(e));

      const task = graph.addTask(makeSubmission());
      graph.queueTask(task.id);
      graph.assignTask(task.id, agentId);
      graph.startTask(task.id);
      graph.completeTask(task.id, { result: "ok" });

      expect(events).toHaveLength(1);
      expect((events[0] as { durationMs: number }).durationMs).toBeTypeOf(
        "number",
      );
    });

    it("throws if task is not running", () => {
      const task = graph.addTask(makeSubmission());

      expect(() => graph.completeTask(task.id, {})).toThrow("not running");
    });
  });

  // =========================================================================
  // Failure and Retry
  // =========================================================================

  describe("failTask", () => {
    it("retries if under maxRetries", () => {
      const agentId = registry.register(makeRegistration());
      registry.spawn(agentId);
      const task = graph.addTask(makeSubmission({ maxRetries: 3 }));
      graph.queueTask(task.id);
      graph.assignTask(task.id, agentId);
      graph.startTask(task.id);

      const events: unknown[] = [];
      emitter.on("task.failed", (e) => events.push(e));

      graph.failTask(task.id, "some error", "runtime_error");

      const t = graph.getTask(task.id);
      expect(t?.retries).toBe(1);
      expect(t?.status).toBe("queued");
      expect(t?.assignedTo).toBeNull();
      expect((events[0] as { retryable: boolean }).retryable).toBe(true);
    });

    it("permanently fails when maxRetries exhausted", () => {
      const agentId = registry.register(makeRegistration());
      registry.spawn(agentId);
      const task = graph.addTask(makeSubmission({ maxRetries: 2 }));

      // First attempt
      graph.queueTask(task.id);
      graph.assignTask(task.id, agentId);
      graph.startTask(task.id);
      graph.failTask(task.id, "error 1");

      // Now task is re-queued with retries=1, maxRetries=1
      // Re-assign and run again
      graph.assignTask(task.id, agentId);
      graph.startTask(task.id);

      const events: unknown[] = [];
      emitter.on("task.failed", (e) => events.push(e));

      graph.failTask(task.id, "error 2");

      const t = graph.getTask(task.id);
      expect(t?.status).toBe("failed");
      expect((events[0] as { retryable: boolean }).retryable).toBe(false);
    });

    it("emits task.failed with error category", () => {
      const agentId = registry.register(makeRegistration());
      registry.spawn(agentId);
      const task = graph.addTask(makeSubmission({ maxRetries: 0 }));
      graph.queueTask(task.id);
      graph.assignTask(task.id, agentId);
      graph.startTask(task.id);

      const events: unknown[] = [];
      emitter.on("task.failed", (e) => events.push(e));

      graph.failTask(task.id, "guard blocked it", "guard_denied");

      expect(events).toHaveLength(1);
      expect((events[0] as { error: string }).error).toBe("guard blocked it");
    });
  });

  // =========================================================================
  // Cancel
  // =========================================================================

  describe("cancelTask", () => {
    it("cancels a queued task", () => {
      const task = graph.addTask(makeSubmission());
      graph.queueTask(task.id);
      graph.cancelTask(task.id);

      expect(graph.getTask(task.id)?.status).toBe("cancelled");
    });

    it("cancels an assigned task and releases agent", () => {
      const agentId = registry.register(makeRegistration());
      registry.spawn(agentId);
      const task = graph.addTask(makeSubmission());
      graph.queueTask(task.id);
      graph.assignTask(task.id, agentId);
      graph.cancelTask(task.id);

      expect(graph.getTask(task.id)?.status).toBe("cancelled");
    });

    it("throws for completed task", () => {
      const agentId = registry.register(makeRegistration());
      registry.spawn(agentId);
      const task = graph.addTask(makeSubmission());
      graph.queueTask(task.id);
      graph.assignTask(task.id, agentId);
      graph.startTask(task.id);
      graph.completeTask(task.id, {});

      expect(() => graph.cancelTask(task.id)).toThrow();
    });

    it("throws for failed task", () => {
      const agentId = registry.register(makeRegistration());
      registry.spawn(agentId);
      const task = graph.addTask(makeSubmission({ maxRetries: 0 }));
      graph.queueTask(task.id);
      graph.assignTask(task.id, agentId);
      graph.startTask(task.id);
      graph.failTask(task.id, "error");

      expect(() => graph.cancelTask(task.id)).toThrow();
    });
  });

  // =========================================================================
  // Timeout
  // =========================================================================

  describe("timeoutTask", () => {
    it("sets status 'timeout' and emits task.failed with category 'timeout'", () => {
      const agentId = registry.register(makeRegistration());
      registry.spawn(agentId);
      const task = graph.addTask(makeSubmission());
      graph.queueTask(task.id);
      graph.assignTask(task.id, agentId);
      graph.startTask(task.id);

      const events: unknown[] = [];
      emitter.on("task.failed", (e) => events.push(e));

      graph.timeoutTask(task.id);

      expect(graph.getTask(task.id)?.status).toBe("timeout");
      expect(events).toHaveLength(1);
      expect((events[0] as { error: string }).error).toContain("timeout");
    });

    it("ignores stale timeout callbacks once a task has already completed", () => {
      const agentId = registry.register(makeRegistration());
      registry.spawn(agentId);
      const task = graph.addTask(makeSubmission());
      graph.queueTask(task.id);
      graph.assignTask(task.id, agentId);
      graph.startTask(task.id);
      graph.completeTask(task.id, { ok: true });

      const events: unknown[] = [];
      emitter.on("task.failed", (e) => events.push(e));

      graph.timeoutTask(task.id);

      expect(graph.getTask(task.id)?.status).toBe("completed");
      expect(events).toHaveLength(0);
    });
  });

  // =========================================================================
  // Progress
  // =========================================================================

  describe("reportProgress", () => {
    it("emits task.progress event", () => {
      const agentId = registry.register(makeRegistration());
      registry.spawn(agentId);
      const task = graph.addTask(makeSubmission());
      graph.queueTask(task.id);
      graph.assignTask(task.id, agentId);
      graph.startTask(task.id);

      const events: unknown[] = [];
      emitter.on("task.progress", (e) => events.push(e));

      graph.reportProgress(task.id, {
        percent: 50,
        currentStep: "Processing",
        stepIndex: 1,
        totalSteps: 3,
      });

      expect(events).toHaveLength(1);
      const evt = events[0] as {
        kind: string;
        percent: number;
        currentStep: string;
      };
      expect(evt.kind).toBe("task.progress");
      expect(evt.percent).toBe(50);
      expect(evt.currentStep).toBe("Processing");
    });
  });

  // =========================================================================
  // Auto-assignment via AgentRegistry
  // =========================================================================

  describe("getNextTask with agentId (capability filtering)", () => {
    it("returns task matching agent capabilities", () => {
      const coderId = registry.register(
        makeRegistration({
          name: "coder",
          capabilities: makeCapabilities({ codeGeneration: true }),
        }),
      );
      registry.spawn(coderId);

      const researcherId = registry.register(
        makeRegistration({
          name: "researcher",
          capabilities: makeCapabilities({ research: true }),
        }),
      );
      registry.spawn(researcherId);

      const codingTask = graph.addTask(makeSubmission({ type: "coding", name: "Code It" }));
      const researchTask = graph.addTask(
        makeSubmission({ type: "research", name: "Research It" }),
      );

      graph.queueTask(codingTask.id);
      graph.queueTask(researchTask.id);

      // Coder should get coding task
      const coderNext = graph.getNextTask(coderId);
      expect(coderNext?.type).toBe("coding");

      // Researcher should get research task
      const researcherNext = graph.getNextTask(researcherId);
      expect(researcherNext?.type).toBe("research");
    });

    it("does not double-assign: getNextTask(agentId) removes task from PriorityQueue", () => {
      const coderId = registry.register(
        makeRegistration({
          name: "coder",
          capabilities: makeCapabilities({ codeGeneration: true }),
        }),
      );
      registry.spawn(coderId);

      const task = graph.addTask(makeSubmission({ type: "coding", name: "Only Task" }));
      graph.queueTask(task.id);

      // Capability-filtered dequeue should return the task
      const first = graph.getNextTask(coderId);
      expect(first?.id).toBe(task.id);

      // A subsequent plain dequeue must NOT return the same task
      const second = graph.getNextTask();
      expect(second).toBeUndefined();
    });

    it("returns undefined when no tasks match capabilities", () => {
      const agentId = registry.register(
        makeRegistration({
          name: "tester",
          capabilities: makeCapabilities({ testing: true }),
        }),
      );
      registry.spawn(agentId);

      const task = graph.addTask(makeSubmission({ type: "coding" }));
      graph.queueTask(task.id);

      const next = graph.getNextTask(agentId);
      expect(next).toBeUndefined();
    });
  });

  // =========================================================================
  // Unblocking dependents
  // =========================================================================

  describe("unblocking dependent tasks", () => {
    it("completing a dependency makes dependent queueable", () => {
      const agentId = registry.register(makeRegistration());
      registry.spawn(agentId);

      const a = graph.addTask(makeSubmission({ name: "A" }));
      const b = graph.addTask(
        makeSubmission({ name: "B", dependencies: [a.id] }),
      );

      graph.queueTask(a.id);
      graph.queueTask(b.id); // B blocked, stays "created"

      expect(graph.isBlocked(b.id)).toBe(true);

      graph.assignTask(a.id, agentId);
      graph.startTask(a.id);
      graph.completeTask(a.id, {});

      // B should now be unblocked
      expect(graph.isBlocked(b.id)).toBe(false);
    });
  });

  // =========================================================================
  // Query Methods
  // =========================================================================

  describe("queries", () => {
    it("getTask returns task by ID", () => {
      const task = graph.addTask(makeSubmission());
      expect(graph.getTask(task.id)?.id).toBe(task.id);
    });

    it("getTask returns undefined for unknown ID", () => {
      expect(graph.getTask("tsk_nonexistent")).toBeUndefined();
    });

    it("getTasksByStatus filters correctly", () => {
      const a = graph.addTask(makeSubmission({ name: "A" }));
      graph.addTask(makeSubmission({ name: "B" }));
      graph.queueTask(a.id);

      expect(graph.getTasksByStatus("queued")).toHaveLength(1);
      expect(graph.getTasksByStatus("created")).toHaveLength(1);
    });

    it("getTasksByAgent filters by assignedTo", () => {
      const agentId = registry.register(makeRegistration());
      registry.spawn(agentId);
      const task = graph.addTask(makeSubmission());
      graph.queueTask(task.id);
      graph.assignTask(task.id, agentId);

      expect(graph.getTasksByAgent(agentId)).toHaveLength(1);
      expect(graph.getTasksByAgent("nobody")).toHaveLength(0);
    });

    it("isBlocked returns true when dependencies incomplete", () => {
      const a = graph.addTask(makeSubmission({ name: "A" }));
      const b = graph.addTask(
        makeSubmission({ name: "B", dependencies: [a.id] }),
      );

      expect(graph.isBlocked(b.id)).toBe(true);
      expect(graph.isBlocked(a.id)).toBe(false);
    });

    it("getBlockingTasks returns incomplete dependencies", () => {
      const a = graph.addTask(makeSubmission({ name: "A" }));
      const b = graph.addTask(
        makeSubmission({ name: "B", dependencies: [a.id] }),
      );

      expect(graph.getBlockingTasks(b.id)).toEqual([a.id]);
    });
  });

  // =========================================================================
  // Serialization
  // =========================================================================

  describe("serialization", () => {
    it("getState returns Record<string, Task>", () => {
      graph.addTask(makeSubmission({ name: "X" }));
      graph.addTask(makeSubmission({ name: "Y" }));

      const state = graph.getState();
      expect(typeof state).toBe("object");
      expect(Object.keys(state)).toHaveLength(2);
    });

    it("getState returns a defensive copy", () => {
      const task = graph.addTask(makeSubmission({ name: "Original" }));

      const state = graph.getState();
      state[task.id]!.name = "Mutated";
      state[task.id]!.dependencies.push("tsk_fake");

      const liveTask = graph.getTask(task.id);
      expect(liveTask?.name).toBe("Original");
      expect(liveTask?.dependencies).toEqual([]);
    });

    it("JSON round-trips cleanly", () => {
      const a = graph.addTask(makeSubmission({ name: "A" }));
      const b = graph.addTask(
        makeSubmission({ name: "B", dependencies: [a.id] }),
      );

      const state = graph.getState();
      const json = JSON.stringify(state);
      const parsed = JSON.parse(json);

      expect(parsed[a.id].name).toBe("A");
      expect(parsed[b.id].dependencies).toEqual([a.id]);
    });
  });

  // =========================================================================
  // Dispose
  // =========================================================================

  describe("dispose", () => {
    it("clears all internal state", () => {
      graph.addTask(makeSubmission({ name: "A" }));
      graph.addTask(makeSubmission({ name: "B" }));
      graph.dispose();

      expect(Object.keys(graph.getState())).toHaveLength(0);
    });
  });
});
