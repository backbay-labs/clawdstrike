/** DAG-based task lifecycle engine with cycle detection and priority scheduling. */

import type { TypedEventEmitter, SwarmEngineEventMap } from "./events.js";
import type { AgentRegistry } from "./agent-registry.js";
import { PriorityQueue } from "./collections.js";
import { generateSwarmId } from "./ids.js";
import type {
  Task,
  TaskErrorCategory,
  TaskPriority,
  TaskStatus,
  TaskSubmission,
} from "./types.js";
import { SWARM_ENGINE_CONSTANTS } from "./types.js";

export interface TaskGraphConfig {
  /** Maximum tasks allowed in the graph. */
  maxTasks?: number;
  /** Default timeout for tasks in milliseconds. */
  defaultTimeoutMs?: number;
  /** Default maximum retry count. */
  defaultMaxRetries?: number;
  /** Swarm engine instance ID for tagging tasks. */
  swarmEngineId?: string;
}

export class TaskGraph {
  private readonly tasks = new Map<string, Task>();
  private readonly dependencyGraph = new Map<string, Set<string>>();
  private readonly dependentGraph = new Map<string, Set<string>>();
  private readonly priorityQueue: PriorityQueue<string>;

  private taskSequence = 0;
  private readonly maxTasks: number;
  private readonly defaultTimeoutMs: number;
  private readonly defaultMaxRetries: number;
  private readonly swarmEngineId: string;

  constructor(
    private readonly events: TypedEventEmitter<SwarmEngineEventMap>,
    private readonly agentRegistry: AgentRegistry,
    config: TaskGraphConfig = {},
  ) {
    this.priorityQueue = new PriorityQueue<string>();
    this.maxTasks =
      config.maxTasks ?? SWARM_ENGINE_CONSTANTS.DEFAULT_MAX_TASKS;
    this.defaultTimeoutMs =
      config.defaultTimeoutMs ??
      SWARM_ENGINE_CONSTANTS.DEFAULT_TASK_TIMEOUT_MS;
    this.defaultMaxRetries =
      config.defaultMaxRetries ?? SWARM_ENGINE_CONSTANTS.MAX_RETRIES;
    this.swarmEngineId = config.swarmEngineId ?? "";
  }

  /** @throws If a dependency is not found or adding would create a cycle. */
  addTask(submission: TaskSubmission): Task {
    if (this.tasks.size >= this.maxTasks) {
      throw new Error(
        `TaskGraph is at capacity (${this.maxTasks} tasks)`,
      );
    }

    const deps = submission.dependencies ?? [];

    for (const dep of deps) {
      if (!this.tasks.has(dep)) {
        throw new Error(
          `Task dependency not found: ${dep}`,
        );
      }
    }

    const id = generateSwarmId("tsk");

    // Temporarily insert into dependencyGraph so DFS can discover back-edges
    // to `id`. Rolled back on cycle detection.
    this.dependencyGraph.set(id, new Set(deps));
    this.dependentGraph.set(id, new Set());

    for (const dep of deps) {
      if (this.wouldCreateCycle(id, dep)) {
        this.dependencyGraph.delete(id);
        this.dependentGraph.delete(id);
        throw new Error(
          `Adding dependency ${dep} to ${id} would create a cycle`,
        );
      }
    }

    const now = Date.now();

    const task: Task = {
      id,
      swarmEngineId: this.swarmEngineId,
      type: submission.type,
      name: submission.name,
      description: submission.description,
      priority: submission.priority ?? "normal",
      status: "created",
      sequence: ++this.taskSequence,
      assignedTo: null,
      dependencies: [...deps],
      input: submission.input ?? {},
      output: null,
      timeoutMs:
        submission.timeoutMs ?? this.defaultTimeoutMs,
      retries: 0,
      maxRetries:
        submission.maxRetries ?? this.defaultMaxRetries,
      taskPrompt: null,
      previewLines: [],
      huntId: null,
      artifactIds: [],
      receipt: null,
      metadata: { tags: submission.tags ?? [] },
      createdAt: now,
      startedAt: null,
      completedAt: null,
      updatedAt: now,
    };

    this.tasks.set(id, task);

    for (const dep of deps) {
      this.dependentGraph.get(dep)?.add(id);
    }

    this.events.emit("task.created", {
      kind: "task.created",
      task,
      sourceAgentId: null,
      timestamp: now,
    });

    return task;
  }

  /** @throws If either task doesn't exist or adding would create a cycle. */
  addDependency(taskId: string, dependsOn: string): void {
    this.getTaskOrThrow(taskId);
    this.getTaskOrThrow(dependsOn);

    if (this.wouldCreateCycle(taskId, dependsOn)) {
      throw new Error(
        `Adding dependency ${dependsOn} to ${taskId} would create a cycle`,
      );
    }

    const task = this.tasks.get(taskId)!;
    if (!task.dependencies.includes(dependsOn)) {
      task.dependencies.push(dependsOn);
    }
    this.dependencyGraph.get(taskId)!.add(dependsOn);
    this.dependentGraph.get(dependsOn)!.add(taskId);
  }

  removeDependency(taskId: string, dependsOn: string): void {
    const task = this.getTaskOrThrow(taskId);

    const index = task.dependencies.indexOf(dependsOn);
    if (index > -1) {
      task.dependencies.splice(index, 1);
    }

    this.dependencyGraph.get(taskId)?.delete(dependsOn);
    this.dependentGraph.get(dependsOn)?.delete(taskId);
  }

  getDependencies(taskId: string): string[] {
    return Array.from(this.dependencyGraph.get(taskId) ?? []);
  }

  getDependents(taskId: string): string[] {
    return Array.from(this.dependentGraph.get(taskId) ?? []);
  }

  isBlocked(taskId: string): boolean {
    return this.getBlockingTasks(taskId).length > 0;
  }

  getBlockingTasks(taskId: string): string[] {
    const dependencies = this.dependencyGraph.get(taskId);
    if (!dependencies) {
      return [];
    }

    return Array.from(dependencies).filter((depId) => {
      const depTask = this.tasks.get(depId);
      return depTask && depTask.status !== "completed";
    });
  }

  /** If blocked by dependencies, stays "created" and is not enqueued. */
  queueTask(taskId: string): void {
    this.getTaskOrThrow(taskId);

    if (this.isBlocked(taskId)) {
      return;
    }

    this.updateTaskStatus(taskId, "queued");
    const task = this.tasks.get(taskId)!;
    this.priorityQueue.enqueue(taskId, task.priority);
  }

  /** @throws If task is not queued or is blocked. */
  assignTask(taskId: string, agentId: string): void {
    const task = this.getTaskOrThrow(taskId);

    if (task.status !== "queued") {
      throw new Error(
        `Task ${taskId} is not queued (status: ${task.status})`,
      );
    }

    if (this.isBlocked(taskId)) {
      throw new Error(`Task ${taskId} is blocked by dependencies`);
    }

    this.agentRegistry.assignTask(agentId, taskId);
    const previousAssignedTo = task.assignedTo;
    const previousStatus = task.status;

    try {
      task.assignedTo = agentId;
      this.updateTaskStatus(taskId, "assigned");

      this.events.emit("task.assigned", {
        kind: "task.assigned",
        taskId,
        agentId,
        receipt: null,
        sourceAgentId: null,
        timestamp: Date.now(),
      });
    } catch (error) {
      task.assignedTo = previousAssignedTo;
      task.status = previousStatus;
      task.updatedAt = Date.now();
      try {
        this.agentRegistry.unassignTask(agentId, taskId);
      } catch {
        // Preserve the original failure; caller already gets the thrown error.
      }
      throw error;
    }
  }

  /** @throws If task is not assigned. */
  startTask(taskId: string): void {
    const task = this.getTaskOrThrow(taskId);

    if (task.status !== "assigned") {
      throw new Error(
        `Task ${taskId} is not assigned (status: ${task.status})`,
      );
    }

    task.startedAt = Date.now();
    this.updateTaskStatus(taskId, "running");
  }

  /** @throws If task is not running. */
  completeTask(taskId: string, output: Record<string, unknown>): void {
    const task = this.getTaskOrThrow(taskId);

    if (task.status !== "running") {
      throw new Error(
        `Task ${taskId} is not running (status: ${task.status})`,
      );
    }

    const now = Date.now();
    task.completedAt = now;
    task.output = output;
    this.updateTaskStatus(taskId, "completed");

    const durationMs = task.startedAt ? now - task.startedAt : 0;

    if (task.assignedTo) {
      this.agentRegistry.completeTask(task.assignedTo, taskId, durationMs);
    }

    this.events.emit("task.completed", {
      kind: "task.completed",
      taskId,
      agentId: task.assignedTo ?? "",
      output,
      durationMs,
      receipt: null,
      sourceAgentId: null,
      timestamp: now,
    });

    this.unblockDependentTasks(taskId);
  }

  /** Retries if under maxRetries; otherwise permanently fails. */
  failTask(
    taskId: string,
    error: string,
    category: TaskErrorCategory = "runtime_error",
  ): void {
    const task = this.getTaskOrThrow(taskId);

    // Capture before mutations so events reference the correct agent.
    const previousAgent = task.assignedTo;

    task.metadata.lastErrorCategory = category;
    task.retries++;

    if (task.retries < task.maxRetries) {
      if (previousAgent) {
        this.agentRegistry.failTask(previousAgent, taskId);
      }
      task.assignedTo = null;
      this.updateTaskStatus(taskId, "queued");
      this.priorityQueue.enqueue(taskId, task.priority);

      this.events.emit("task.failed", {
        kind: "task.failed",
        taskId,
        agentId: previousAgent,
        error,
        retryable: true,
        sourceAgentId: null,
        timestamp: Date.now(),
      });
    } else {
      if (previousAgent) {
        this.agentRegistry.failTask(previousAgent, taskId);
      }
      this.updateTaskStatus(taskId, "failed");

      this.events.emit("task.failed", {
        kind: "task.failed",
        taskId,
        agentId: previousAgent,
        error,
        retryable: false,
        sourceAgentId: null,
        timestamp: Date.now(),
      });
    }
  }

  /** @throws If task is completed or failed. */
  cancelTask(taskId: string): void {
    const task = this.getTaskOrThrow(taskId);

    if (task.status === "completed" || task.status === "failed") {
      throw new Error(
        `Cannot cancel ${task.status} task ${taskId}`,
      );
    }

    if (task.assignedTo) {
      const session = this.agentRegistry.getAgentSession(task.assignedTo);
      if (session && session.currentTaskId === taskId) {
        this.agentRegistry.failTask(task.assignedTo, taskId);
      }
    }

    this.updateTaskStatus(taskId, "cancelled");
  }

  /** Timeout a running task. */
  timeoutTask(taskId: string): void {
    const task = this.getTaskOrThrow(taskId);

    if (task.status !== "running") {
      return;
    }

    if (task.assignedTo) {
      const session = this.agentRegistry.getAgentSession(task.assignedTo);
      if (session && session.currentTaskId === taskId) {
        this.agentRegistry.failTask(task.assignedTo, taskId);
      }
    }

    this.updateTaskStatus(taskId, "timeout");

    this.events.emit("task.failed", {
      kind: "task.failed",
      taskId,
      agentId: task.assignedTo,
      error: `Task ${taskId} timeout after ${task.timeoutMs}ms`,
      retryable: false,
      sourceAgentId: null,
      timestamp: Date.now(),
    });
  }

  /** Report progress on a running task. */
  reportProgress(
    taskId: string,
    progress: {
      percent: number;
      currentStep: string;
      stepIndex: number;
      totalSteps: number;
    },
  ): void {
    const task = this.getTaskOrThrow(taskId);

    this.events.emit("task.progress", {
      kind: "task.progress",
      taskId,
      agentId: task.assignedTo ?? "",
      percent: progress.percent,
      currentStep: progress.currentStep,
      stepIndex: progress.stepIndex,
      totalSteps: progress.totalSteps,
      sourceAgentId: null,
      timestamp: Date.now(),
    });
  }

  /**
   * Dequeue the next task. When agentId is provided, filters by agent capabilities.
   */
  getNextTask(agentId?: string): Task | undefined {
    if (!agentId) {
      while (this.priorityQueue.length > 0) {
        const taskId = this.priorityQueue.dequeue();
        if (!taskId) break;

        const task = this.tasks.get(taskId);
        if (!task || task.status !== "queued") continue;
        if (this.isBlocked(taskId)) {
          this.priorityQueue.enqueue(taskId, task.priority);
          continue;
        }
        return task;
      }
      return undefined;
    }

    const session = this.agentRegistry.getAgentSession(agentId);
    if (!session) {
      return this.getNextTask();
    }

    const capableAgentTypes = new Set<string>();
    const allQueuedTasks = this.getTasksByStatus("queued").filter(
      (t) => !this.isBlocked(t.id),
    );

    for (const task of allQueuedTasks) {
      const agents = this.agentRegistry.getAgentsByCapability(task.type);
      if (agents.some((a) => a.id === agentId)) {
        capableAgentTypes.add(task.type);
      }
    }

    const priorityOrder: Record<TaskPriority, number> = {
      critical: 0,
      high: 1,
      normal: 2,
      low: 3,
      background: 4,
    };

    const matchingTasks = allQueuedTasks
      .filter((t) => capableAgentTypes.has(t.type))
      .sort((a, b) => {
        const diff =
          priorityOrder[a.priority] - priorityOrder[b.priority];
        if (diff !== 0) return diff;
        return a.createdAt - b.createdAt;
      });

    const matched = matchingTasks[0];
    if (!matched) {
      return undefined;
    }

    // Remove matched task from queue to prevent double-assignment.
    const requeue: Array<{ id: string; priority: TaskPriority }> = [];
    while (this.priorityQueue.length > 0) {
      const dequeuedId = this.priorityQueue.dequeue();
      if (dequeuedId === matched.id) {
        break;
      }
      if (dequeuedId !== undefined) {
        const t = this.tasks.get(dequeuedId);
        if (t) {
          requeue.push({ id: dequeuedId, priority: t.priority });
        }
      }
    }
    for (const item of requeue) {
      this.priorityQueue.enqueue(item.id, item.priority);
    }

    return matched;
  }

  getTask(taskId: string): Task | undefined {
    return this.tasks.get(taskId);
  }

  getState(): Record<string, Task> {
    return globalThis.structuredClone(Object.fromEntries(this.tasks));
  }

  getTasksByStatus(status: TaskStatus): Task[] {
    return Array.from(this.tasks.values()).filter(
      (t) => t.status === status,
    );
  }

  getTasksByAgent(agentId: string): Task[] {
    return Array.from(this.tasks.values()).filter(
      (t) => t.assignedTo === agentId,
    );
  }

  /** Kahn's algorithm topological sort. */
  getTopologicalOrder(): Task[] {
    const inDegree = new Map<string, number>();
    for (const taskId of this.tasks.keys()) {
      inDegree.set(taskId, 0);
    }

    for (const [taskId, deps] of this.dependencyGraph) {
      inDegree.set(taskId, deps.size);
    }

    const queue: string[] = [];
    for (const [taskId, degree] of inDegree) {
      if (degree === 0) {
        queue.push(taskId);
      }
    }

    const result: Task[] = [];

    while (queue.length > 0) {
      const current = queue.shift()!;
      const task = this.tasks.get(current);
      if (task) {
        result.push(task);
      }

      const dependents = this.dependentGraph.get(current);
      if (dependents) {
        for (const dep of dependents) {
          const newDegree = (inDegree.get(dep) ?? 0) - 1;
          inDegree.set(dep, newDegree);
          if (newDegree === 0) {
            queue.push(dep);
          }
        }
      }
    }

    return result;
  }

  /** Clear all internal state. Does not dispose the shared emitter. */
  dispose(): void {
    this.priorityQueue.clear();
    this.tasks.clear();
    this.dependencyGraph.clear();
    this.dependentGraph.clear();
  }

  private getTaskOrThrow(taskId: string): Task {
    const task = this.tasks.get(taskId);
    if (!task) {
      throw new Error(`Task ${taskId} not found`);
    }
    return task;
  }

  private updateTaskStatus(
    taskId: string,
    status: TaskStatus,
    reason?: string,
  ): void {
    const task = this.getTaskOrThrow(taskId);
    const previousStatus = task.status;
    task.status = status;
    task.updatedAt = Date.now();

    this.events.emit("task.status_changed", {
      kind: "task.status_changed",
      taskId,
      previousStatus,
      newStatus: status,
      reason: reason ?? null,
      sourceAgentId: null,
      timestamp: Date.now(),
    });
  }

  private unblockDependentTasks(taskId: string): void {
    const dependents = this.getDependents(taskId);

    for (const dependentId of dependents) {
      if (!this.isBlocked(dependentId)) {
        const task = this.tasks.get(dependentId);
        if (task && task.status === "created") {
          this.updateTaskStatus(dependentId, "queued");
          this.priorityQueue.enqueue(dependentId, task.priority);
        }
      }
    }
  }

  /** Iterative DFS: checks if newDependency can reach taskId. */
  private wouldCreateCycle(
    taskId: string,
    newDependency: string,
  ): boolean {
    const visited = new Set<string>();
    const stack = [newDependency];

    while (stack.length > 0) {
      const current = stack.pop()!;

      if (current === taskId) {
        return true;
      }

      if (visited.has(current)) {
        continue;
      }

      visited.add(current);

      const deps = this.dependencyGraph.get(current);
      if (deps) {
        stack.push(...deps);
      }
    }

    return false;
  }
}
