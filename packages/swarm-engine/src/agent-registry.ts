/** Agent lifecycle management for the swarm engine. */

import type { TypedEventEmitter, SwarmEngineEventMap } from "./events.js";
import { generateSwarmId } from "./ids.js";
import type {
  AgentCapabilities,
  AgentMetrics,
  AgentQualityScores,
  AgentRegistration,
  AgentSession,
  AgentSessionStatus,
  HealthCheckStatus,
  TaskType,
} from "./types.js";
import { SWARM_ENGINE_CONSTANTS } from "./types.js";

export interface AgentRegistryConfig {
  /** Interval between health checks in milliseconds. */
  healthCheckIntervalMs?: number;
  /** Number of consecutive missed heartbeats before marking agent as failed. */
  maxMissedHeartbeats?: number;
}

const TASK_TYPE_TO_CAPABILITY: Partial<Record<TaskType, keyof AgentCapabilities>> = {
  coding: "codeGeneration",
  review: "codeReview",
  testing: "testing",
  documentation: "documentation",
  research: "research",
  analysis: "analysis",
  coordination: "coordination",
  detection: "securityAnalysis",
  hunt: "securityAnalysis",
  consensus: "coordination",
  guard_evaluation: "securityAnalysis",
};

export class AgentRegistry {
  private readonly registrations = new Map<string, AgentRegistration>();
  private readonly sessions = new Map<string, AgentSession>();
  private readonly healthChecks = new Map<string, HealthCheckStatus>();
  private healthCheckTimer: ReturnType<typeof setInterval> | null = null;

  private readonly healthCheckIntervalMs: number;
  private readonly maxMissedHeartbeats: number;

  constructor(
    private readonly events: TypedEventEmitter<SwarmEngineEventMap>,
    config: AgentRegistryConfig = {},
  ) {
    this.healthCheckIntervalMs =
      config.healthCheckIntervalMs ??
      SWARM_ENGINE_CONSTANTS.DEFAULT_HEALTH_CHECK_INTERVAL_MS;
    this.maxMissedHeartbeats = config.maxMissedHeartbeats ?? 3;
  }

  /** Register an agent definition. Returns the generated agent ID. */
  register(registration: AgentRegistration): string {
    if (!registration.name) {
      throw new Error("Agent registration name must not be empty");
    }

    const id = generateSwarmId("agt");

    this.registrations.set(id, registration);

    this.healthChecks.set(id, {
      agentId: id,
      healthy: false,
      lastHeartbeatAt: 0,
      consecutiveMisses: 0,
      status: "idle",
    });

    return id;
  }

  /** @throws If the agent has an active session. */
  unregister(agentId: string): boolean {
    if (this.sessions.has(agentId)) {
      throw new Error(
        `Cannot unregister active agent ${agentId}`,
      );
    }

    this.healthChecks.delete(agentId);
    return this.registrations.delete(agentId);
  }

  getRegistration(agentId: string): AgentRegistration | undefined {
    return this.registrations.get(agentId);
  }

  getAllRegistrations(): AgentRegistration[] {
    return Array.from(this.registrations.values());
  }

  /** @throws If agent is not registered or already spawned. */
  spawn(agentId: string): AgentSession {
    const registration = this.registrations.get(agentId);
    if (!registration) {
      throw new Error(`Agent ${agentId} is not registered`);
    }

    if (this.sessions.has(agentId)) {
      throw new Error(`Agent ${agentId} is already spawned`);
    }

    const session = createDefaultAgentSession(agentId, registration);
    this.sessions.set(agentId, session);

    const healthStatus = this.healthChecks.get(agentId);
    if (healthStatus) {
      healthStatus.healthy = true;
      healthStatus.lastHeartbeatAt = session.lastHeartbeatAt;
      healthStatus.status = "idle";
    }

    this.events.emit("agent.spawned", {
      kind: "agent.spawned",
      agent: session,
      receipt: null,
      sourceAgentId: null,
      timestamp: Date.now(),
    });

    return session;
  }

  /** @throws If the agent has an active task. */
  terminate(agentId: string): boolean {
    const session = this.sessions.get(agentId);
    if (!session) {
      return false;
    }

    if (session.currentTaskId !== null) {
      throw new Error(
        `Cannot terminate agent ${agentId} with active task ${session.currentTaskId}`,
      );
    }

    this.sessions.delete(agentId);

    const healthStatus = this.healthChecks.get(agentId);
    if (healthStatus) {
      healthStatus.healthy = false;
      healthStatus.status = "idle";
    }

    this.events.emit("agent.terminated", {
      kind: "agent.terminated",
      agentId,
      exitCode: session.exitCode,
      reason: "terminated",
      finalMetrics: session.metrics,
      sourceAgentId: null,
      timestamp: Date.now(),
    });

    return true;
  }

  /** @throws If the agent is not spawned. */
  updateStatus(
    agentId: string,
    status: AgentSessionStatus,
    reason?: string,
  ): void {
    const session = this.sessions.get(agentId);
    if (!session) {
      throw new Error(`Agent ${agentId} is not spawned`);
    }

    const previousStatus = session.status;
    session.status = status;
    session.updatedAt = Date.now();

    const healthStatus = this.healthChecks.get(agentId);
    if (healthStatus) {
      healthStatus.status = status;
    }

    this.events.emit("agent.status_changed", {
      kind: "agent.status_changed",
      agentId,
      previousStatus,
      newStatus: status,
      reason: reason ?? null,
      sourceAgentId: null,
      timestamp: Date.now(),
    });
  }

  /** @throws If the agent is not spawned or already has a task. */
  assignTask(agentId: string, taskId: string): void {
    const session = this.sessions.get(agentId);
    if (!session) {
      throw new Error(`Agent ${agentId} is not spawned`);
    }

    if (session.currentTaskId !== null) {
      throw new Error(
        `Agent ${agentId} already has task ${session.currentTaskId}`,
      );
    }

    session.currentTaskId = taskId;
    this.updateStatus(agentId, "running");
  }

  /** Roll back an assignment without counting it as a task failure. */
  unassignTask(agentId: string, taskId: string): void {
    const session = this.sessions.get(agentId);
    if (!session) {
      throw new Error(`Agent ${agentId} is not spawned`);
    }

    if (session.currentTaskId !== taskId) {
      throw new Error(
        `Agent ${agentId} current task is ${session.currentTaskId}, not ${taskId}`,
      );
    }

    session.currentTaskId = null;
    this.updateStatus(agentId, "idle");
  }

  /** @throws If the agent is not spawned or taskId doesn't match. */
  completeTask(agentId: string, taskId: string, durationMs?: number): void {
    const session = this.sessions.get(agentId);
    if (!session) {
      throw new Error(`Agent ${agentId} is not spawned`);
    }

    if (session.currentTaskId !== taskId) {
      throw new Error(
        `Agent ${agentId} current task is ${session.currentTaskId}, not ${taskId}`,
      );
    }

    const metrics = session.metrics;
    metrics.tasksCompleted++;

    const total = metrics.tasksCompleted + metrics.tasksFailed;
    metrics.successRate = total > 0 ? metrics.tasksCompleted / total : 0;

    if (durationMs !== undefined) {
      const prevTotal =
        metrics.averageExecutionTimeMs * (metrics.tasksCompleted - 1);
      metrics.averageExecutionTimeMs =
        (prevTotal + durationMs) / metrics.tasksCompleted;
    }

    metrics.health = Math.max(
      0,
      Math.min(1, 0.5 + metrics.successRate * 0.5),
    );

    metrics.lastActivityAt = Date.now();

    session.currentTaskId = null;
    this.updateStatus(agentId, "idle");
  }

  /** @throws If the agent is not spawned or taskId doesn't match. */
  failTask(agentId: string, taskId: string): void {
    const session = this.sessions.get(agentId);
    if (!session) {
      throw new Error(`Agent ${agentId} is not spawned`);
    }

    if (session.currentTaskId !== taskId) {
      throw new Error(
        `Agent ${agentId} current task is ${session.currentTaskId}, not ${taskId}`,
      );
    }

    const metrics = session.metrics;
    metrics.tasksFailed++;

    const total = metrics.tasksCompleted + metrics.tasksFailed;
    metrics.successRate = total > 0 ? metrics.tasksCompleted / total : 0;

    metrics.lastActivityAt = Date.now();

    session.currentTaskId = null;
    this.updateStatus(agentId, "idle");
  }

  getAgentSession(agentId: string): AgentSession | undefined {
    return this.sessions.get(agentId);
  }

  getState(): Record<string, AgentSession> {
    return globalThis.structuredClone(Object.fromEntries(this.sessions));
  }

  getActiveAgents(): AgentSession[] {
    return Array.from(this.sessions.values()).filter(
      (s) => s.status === "running",
    );
  }

  getIdleAgents(): AgentSession[] {
    return Array.from(this.sessions.values()).filter(
      (s) => s.status === "idle",
    );
  }

  /** Returns agents whose capabilities match the given task type. */
  getAgentsByCapability(taskType: TaskType): AgentSession[] {
    const capKey = TASK_TYPE_TO_CAPABILITY[taskType];

    return Array.from(this.sessions.values()).filter((s) => {
      if (capKey) {
        return s.capabilities[capKey] === true;
      }
      return s.capabilities.tools.includes(taskType);
    });
  }

  getAgentCount(): number {
    return this.sessions.size;
  }

  /** Record a heartbeat from an agent. */
  heartbeat(agentId: string): void {
    const now = Date.now();

    const session = this.sessions.get(agentId);
    if (session) {
      session.lastHeartbeatAt = now;
    }

    const healthStatus = this.healthChecks.get(agentId);
    if (healthStatus) {
      healthStatus.lastHeartbeatAt = now;
      healthStatus.consecutiveMisses = 0;
      healthStatus.healthy = true;
    }

    if (session) {
      this.events.emit("agent.heartbeat", {
        kind: "agent.heartbeat",
        agentId,
        health: session.health,
        workload: session.workload,
        metricsSnapshot: session.metrics,
        sourceAgentId: null,
        timestamp: now,
      });
    }
  }

  /** Start periodic health checks. Idempotent. */
  startHealthChecks(): void {
    if (this.healthCheckTimer) {
      return;
    }

    this.healthCheckTimer = setInterval(
      () => this.performHealthCheck(),
      this.healthCheckIntervalMs,
    );
  }

  stopHealthChecks(): void {
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
      this.healthCheckTimer = null;
    }
  }

  getHealthStatus(): Record<string, HealthCheckStatus> {
    return Object.fromEntries(this.healthChecks);
  }

  /** Stops health checks. Does not dispose the shared emitter. */
  dispose(): void {
    this.stopHealthChecks();
  }

  private performHealthCheck(): void {
    const now = Date.now();

    for (const [agentId, healthStatus] of this.healthChecks) {
      const session = this.sessions.get(agentId);
      if (!session) {
        continue;
      }

      const timeSinceHeartbeat = now - healthStatus.lastHeartbeatAt;

      if (timeSinceHeartbeat > this.healthCheckIntervalMs) {
        healthStatus.consecutiveMisses++;

        if (healthStatus.consecutiveMisses >= this.maxMissedHeartbeats) {
          healthStatus.healthy = false;
          if (session.status !== "failed") {
            this.updateStatus(agentId, "failed");
          }
        }
      }
    }
  }
}

function createDefaultAgentSession(
  id: string,
  registration: AgentRegistration,
): AgentSession {
  const now = Date.now();

  const quality: AgentQualityScores = {
    reliability: registration.quality?.reliability ?? 0.5,
    speed: registration.quality?.speed ?? 0.5,
    quality: registration.quality?.quality ?? 0.5,
  };

  const metrics: AgentMetrics = {
    tasksCompleted: 0,
    tasksFailed: 0,
    averageExecutionTimeMs: 0,
    successRate: 0,
    cpuUsage: 0,
    memoryUsageBytes: 0,
    messagesProcessed: 0,
    lastActivityAt: now,
    responseTimeMs: 0,
    health: 1.0,
  };

  return {
    id,
    name: registration.name,
    role: registration.role,
    status: "idle",

    capabilities: registration.capabilities,
    metrics,
    quality,
    currentTaskId: null,
    workload: 0,
    health: 1.0,
    lastHeartbeatAt: now,
    topologyRole: null,
    connections: [],

    worktreePath: null,
    branch: null,
    risk: "low",
    policyMode: registration.policyMode ?? null,
    agentModel: registration.agentModel ?? null,
    receiptCount: 0,
    blockedActionCount: 0,
    changedFilesCount: 0,
    filesTouched: [],
    toolBoundaryEvents: 0,
    confidence: null,
    guardResults: [],

    receipt: null,
    sentinelId: null,
    createdAt: now,
    updatedAt: now,
    exitCode: null,
  };
}
