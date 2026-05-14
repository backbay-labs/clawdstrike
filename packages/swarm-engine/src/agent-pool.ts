/** Agent pooling with auto-scaling and health checks. */

import type { TypedEventEmitter } from "./events.js";
import type { SwarmEngineEventMap } from "./events.js";
import { generateSwarmId } from "./ids.js";
import type { AgentPoolConfig, AgentPoolState } from "./types.js";
import { SWARM_ENGINE_CONSTANTS } from "./types.js";

interface PooledAgent {
  agentId: string;
  status: "available" | "busy" | "unhealthy";
  lastUsed: number;
  usageCount: number;
  health: number;
  lastHeartbeatAt: number;
}

export class AgentPool {
  private readonly events: TypedEventEmitter<SwarmEngineEventMap>;
  private config: AgentPoolConfig;
  private pooledAgents = new Map<string, PooledAgent>();
  private available = new Set<string>();
  private busy = new Set<string>();
  private pendingScale = 0;
  private lastScaleOperation: number | null = null;
  private healthCheckInterval: ReturnType<typeof setInterval> | null = null;

  constructor(
    events: TypedEventEmitter<SwarmEngineEventMap>,
    config: Partial<AgentPoolConfig> = {},
  ) {
    this.events = events;
    this.config = {
      name: config.name ?? "default-pool",
      minSize: config.minSize ?? 1,
      maxSize: config.maxSize ?? 10,
      scaleUpThreshold: config.scaleUpThreshold ?? 0.8,
      scaleDownThreshold: config.scaleDownThreshold ?? 0.2,
      cooldownMs: config.cooldownMs ?? 30_000,
      healthCheckIntervalMs:
        config.healthCheckIntervalMs ??
        SWARM_ENGINE_CONSTANTS.DEFAULT_HEALTH_CHECK_INTERVAL_MS,
    };
  }

  /** Create minSize agents and start the health check timer. */
  initialize(): void {
    for (let i = 0; i < this.config.minSize; i++) {
      this.createPooledAgent();
    }
    this.startHealthChecks();
  }

  /** Clear all agents and stop health checks. */
  shutdown(): void {
    this.stopHealthChecks();

    this.pooledAgents.clear();
    this.available.clear();
    this.busy.clear();
  }

  /** Timer cleanup only. Does not clear agents or dispose the shared emitter. */
  dispose(): void {
    this.stopHealthChecks();
  }

  /**
   * Acquire an available agent. Creates a new one if the pool has capacity.
   * Returns undefined when the pool is fully exhausted.
   */
  acquire(): string | undefined {
    for (const availableId of this.available) {
      const pooled = this.pooledAgents.get(availableId);
      if (!pooled) {
        this.available.delete(availableId);
        continue;
      }

      if (pooled.status !== "available" || pooled.health <= 0) {
        this.available.delete(availableId);
        continue;
      }

      this.available.delete(availableId);
      this.busy.add(availableId);
      pooled.status = "busy";
      pooled.usageCount++;
      pooled.lastUsed = Date.now();

      this.checkScaling();
      return availableId;
    }

    if (this.pooledAgents.size < this.config.maxSize) {
      const agentId = this.createPooledAgent();
      if (agentId) {
        const pooled = this.pooledAgents.get(agentId);
        if (pooled) {
          this.available.delete(agentId);
          this.busy.add(agentId);
          pooled.status = "busy";
          pooled.usageCount++;
          pooled.lastUsed = Date.now();

          return agentId;
        }
      }
    }

    return undefined;
  }

  /** Release an acquired agent back to the available pool. */
  release(agentId: string): void {
    const pooled = this.pooledAgents.get(agentId);
    if (!pooled) return;

    this.busy.delete(agentId);
    pooled.lastUsed = Date.now();

    if (pooled.status !== "unhealthy" && pooled.health > 0) {
      this.available.add(agentId);
      pooled.status = "available";
    }

    this.checkScaling();
  }

  /** Add an external agent to the pool by ID. */
  add(agentId: string): void {
    if (this.pooledAgents.size >= this.config.maxSize) {
      throw new Error(
        `Pool ${this.config.name} is at maximum capacity (${this.config.maxSize})`,
      );
    }

    const pooled: PooledAgent = {
      agentId,
      status: "available",
      lastUsed: Date.now(),
      usageCount: 0,
      health: 1.0,
      lastHeartbeatAt: Date.now(),
    };

    this.pooledAgents.set(agentId, pooled);
    this.available.add(agentId);
  }

  /** Remove an agent from the pool. */
  remove(agentId: string): void {
    if (!this.pooledAgents.has(agentId)) return;

    this.pooledAgents.delete(agentId);
    this.available.delete(agentId);
    this.busy.delete(agentId);
  }

  /**
   * Scale the pool by delta. Positive creates agents (up to maxSize),
   * negative removes LRU available agents (down to minSize).
   */
  scale(delta: number): void {
    const now = Date.now();

    if (this.lastScaleOperation !== null) {
      const timeSinceLastScale = now - this.lastScaleOperation;
      if (timeSinceLastScale < this.config.cooldownMs) {
        return;
      }
    }

    if (delta > 0) {
      const targetSize = Math.min(
        this.pooledAgents.size + delta,
        this.config.maxSize,
      );
      const toCreate = targetSize - this.pooledAgents.size;

      for (let i = 0; i < toCreate; i++) {
        this.createPooledAgent();
      }
    } else if (delta < 0) {
      const targetSize = Math.max(
        this.pooledAgents.size + delta,
        this.config.minSize,
      );
      const toRemove = this.pooledAgents.size - targetSize;

      const sortedAvailable = Array.from(this.available)
        .map((id) => this.pooledAgents.get(id))
        .filter((p): p is PooledAgent => p !== undefined)
        .sort((a, b) => a.lastUsed - b.lastUsed);

      const agentsToRemove = sortedAvailable.slice(0, toRemove);
      for (const pooled of agentsToRemove) {
        this.remove(pooled.agentId);
      }
    }

    this.lastScaleOperation = now;
  }

  /** Returns a serializable snapshot of the pool state. */
  getState(): AgentPoolState {
    const agents: AgentPoolState["agents"] = {};
    for (const [id, pooled] of this.pooledAgents) {
      agents[id] = {
        agentId: pooled.agentId,
        status: pooled.status,
        lastUsed: pooled.lastUsed,
        usageCount: pooled.usageCount,
        health: pooled.health,
      };
    }

    return {
      config: { ...this.config },
      agents,
      availableCount: this.available.size,
      busyCount: this.busy.size,
      utilization: this.getUtilization(),
      pendingScale: this.pendingScale,
      lastScaleOperation: this.lastScaleOperation,
    };
  }

  /** Returns the current utilization ratio (busy / total). */
  getUtilization(): number {
    if (this.pooledAgents.size === 0) return 0;
    return this.busy.size / this.pooledAgents.size;
  }

  /** Returns aggregate pool statistics. */
  getPoolStats(): {
    total: number;
    available: number;
    busy: number;
    utilization: number;
    avgHealth: number;
    avgUsageCount: number;
  } {
    const agents = Array.from(this.pooledAgents.values());
    const avgHealth =
      agents.length > 0
        ? agents.reduce((sum, p) => sum + p.health, 0) / agents.length
        : 1.0;
    const avgUsageCount =
      agents.length > 0
        ? agents.reduce((sum, p) => sum + p.usageCount, 0) / agents.length
        : 0;

    return {
      total: this.pooledAgents.size,
      available: this.available.size,
      busy: this.busy.size,
      utilization: this.getUtilization(),
      avgHealth,
      avgUsageCount,
    };
  }

  /** Returns the shared event emitter. */
  getEvents(): TypedEventEmitter<SwarmEngineEventMap> {
    return this.events;
  }

  /** Update the heartbeat timestamp for an agent. */
  updateAgentHeartbeat(agentId: string): void {
    const pooled = this.pooledAgents.get(agentId);
    if (pooled) {
      pooled.lastHeartbeatAt = Date.now();
      pooled.health = Math.min(1.0, pooled.health + 0.05);
    }
  }

  /** Get a single pooled agent entry by ID. */
  getAgent(
    agentId: string,
  ):
    | { agentId: string; status: string; health: number; usageCount: number }
    | undefined {
    const pooled = this.pooledAgents.get(agentId);
    if (!pooled) return undefined;
    return {
      agentId: pooled.agentId,
      status: pooled.status,
      health: pooled.health,
      usageCount: pooled.usageCount,
    };
  }

  private createPooledAgent(): string | undefined {
    if (this.pooledAgents.size >= this.config.maxSize) {
      return undefined;
    }

    const agentId = generateSwarmId("agt");
    const now = Date.now();

    const pooled: PooledAgent = {
      agentId,
      status: "available",
      lastUsed: now,
      usageCount: 0,
      health: 1.0,
      lastHeartbeatAt: now,
    };

    this.pooledAgents.set(agentId, pooled);
    this.available.add(agentId);

    return agentId;
  }

  /** Check utilization and auto-scale if thresholds are breached. */
  private checkScaling(): void {
    const utilization = this.getUtilization();

    if (
      utilization >= this.config.scaleUpThreshold &&
      this.pooledAgents.size < this.config.maxSize
    ) {
      this.pendingScale = 1;
      this.scale(1);
      this.pendingScale = 0;
    } else if (
      utilization <= this.config.scaleDownThreshold &&
      this.pooledAgents.size > this.config.minSize
    ) {
      this.pendingScale = -1;
      this.scale(-1);
      this.pendingScale = 0;
    }
  }

  private startHealthChecks(): void {
    this.healthCheckInterval = setInterval(() => {
      this.performHealthChecks();
    }, this.config.healthCheckIntervalMs);
  }

  private stopHealthChecks(): void {
    if (this.healthCheckInterval !== null) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = null;
    }
  }

  /** Degrade agents missing heartbeats; replace those at health <= 0. */
  private performHealthChecks(): void {
    const now = Date.now();
    const unhealthyThresholdMs = this.config.healthCheckIntervalMs * 3;

    for (const [agentId, pooled] of this.pooledAgents) {
      const timeSinceLastHeartbeat = now - pooled.lastHeartbeatAt;

      if (timeSinceLastHeartbeat > unhealthyThresholdMs) {
        pooled.health = Math.max(0, pooled.health - 0.2);
        pooled.status = "unhealthy";
        this.available.delete(agentId);

        if (pooled.health <= 0) {
          this.replaceUnhealthyAgent(agentId);
        }
      } else {
        pooled.health = Math.min(1.0, pooled.health + 0.1);
        if (pooled.status === "unhealthy") {
          if (this.busy.has(agentId)) {
            pooled.status = "busy";
          } else {
            pooled.status = "available";
            this.available.add(agentId);
          }
        }
      }
    }
  }

  /** Remove an unhealthy agent and create a replacement if needed. */
  private replaceUnhealthyAgent(agentId: string): void {
    const wasBusy = this.busy.has(agentId);
    this.remove(agentId);

    if (this.pooledAgents.size < this.config.minSize || wasBusy) {
      this.createPooledAgent();
    }
  }
}
