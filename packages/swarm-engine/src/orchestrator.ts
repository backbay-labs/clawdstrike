/**
 * SwarmOrchestrator -- facade composing all subsystems under a single
 * lifecycle with guard pipeline integration.
 *
 * The orchestrator is the main entry point for the swarm engine. It wires
 * AgentRegistry, TaskGraph, TopologyManager, and AgentPool together with:
 * - Lifecycle management (init / shutdown / pause / resume / dispose)
 * - Guard pipeline evaluation via injected GuardEvaluator (fail-closed)
 * - State snapshots (getState) and live metrics (getMetrics)
 * - Background timers (heartbeat, metrics)
 *
 * Design:
 * - Constructor injection for events, registry, taskGraph, topology
 * - AgentPool is constructed internally from config.pool
 * - dispose() is the ONLY method that calls events.dispose()
 * - No Node.js imports -- all timers use setInterval/clearInterval
 *
 * @module
 */

import type { TypedEventEmitter, SwarmEngineEventMap } from "./events.js";
import type { AgentRegistry } from "./agent-registry.js";
import type { TaskGraph } from "./task-graph.js";
import type { TopologyManager } from "./topology.js";
import { AgentPool } from "./agent-pool.js";
import { generateSwarmId } from "./ids.js";
import { SWARM_ENGINE_CONSTANTS } from "./types.js";
import type {
  AgentConversationTurn,
  AgentPoolConfig,
  ConsensusConfig,
  EnvelopeReceipt,
  GuardedAction,
  GuardedActionRecord,
  GuardEvaluationResult,
  GuardEvaluator,
  Receipt,
  SwarmEngineMetrics,
  SwarmEngineState,
  SwarmEngineStatus,
  TopologyConfig,
} from "./types.js";

// ============================================================================
// Configuration
// ============================================================================

/**
 * Configuration for the SwarmOrchestrator.
 */
export interface SwarmOrchestratorConfig {
  /** Swarm namespace for ID scoping. */
  namespace: string;
  /** Topology config for the topology manager. */
  topology: TopologyConfig;
  /** Consensus config (placeholder for Phase 4). */
  consensus: ConsensusConfig;
  /** Agent pool config. */
  pool: Partial<AgentPoolConfig>;
  /** Max agents. */
  maxAgents: number;
  /** Max tasks. */
  maxTasks: number;
  /** Heartbeat interval in ms. Default: SWARM_ENGINE_CONSTANTS.DEFAULT_HEARTBEAT_INTERVAL_MS */
  heartbeatIntervalMs: number;
  /** Health check interval in ms. Default: SWARM_ENGINE_CONSTANTS.DEFAULT_HEALTH_CHECK_INTERVAL_MS */
  healthCheckIntervalMs: number;
  /** Task timeout in ms. Default: SWARM_ENGINE_CONSTANTS.DEFAULT_TASK_TIMEOUT_MS */
  taskTimeoutMs: number;
  /** Guard evaluator injected by host. If absent, all guarded actions are denied (fail-closed). */
  guardEvaluator?: GuardEvaluator;
  /** Max guard action records retained. Default: SWARM_ENGINE_CONSTANTS.MAX_GUARD_ACTION_HISTORY */
  maxGuardActionHistory: number;
}

// ============================================================================
// SwarmOrchestrator
// ============================================================================

/**
 * Facade composing all swarm engine subsystems.
 *
 * **Security invariant:** Subsystem references (registry, taskGraph, topology,
 * pool) MUST only be accessed through orchestrator methods so that all
 * mutations pass through the guard pipeline. Direct access to the subsystems
 * bypasses guard enforcement and violates the fail-closed contract.
 *
 * Usage:
 * ```ts
 * const events = new TypedEventEmitter<SwarmEngineEventMap>();
 * const registry = new AgentRegistry(events);
 * const taskGraph = new TaskGraph(events, registry);
 * const topology = new TopologyManager(events);
 * const orchestrator = new SwarmOrchestrator(events, registry, taskGraph, topology, config);
 * orchestrator.initialize();
 * ```
 */
export class SwarmOrchestrator {
  private readonly pool: AgentPool;
  private status: SwarmEngineStatus = "initializing";
  private startedAt: number | null = null;
  private readonly createdAt: number = Date.now();
  private readonly id: string;
  private readonly recentGuardActions: GuardedActionRecord[] = [];
  private readonly conversationHistory = new Map<string, AgentConversationTurn[]>();
  private guardEvaluationsTotal = 0;
  private guardDenialsTotal = 0;

  // Background timers
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;

  constructor(
    private readonly events: TypedEventEmitter<SwarmEngineEventMap>,
    private readonly registry: AgentRegistry,
    private readonly taskGraph: TaskGraph,
    private readonly topology: TopologyManager,
    private readonly config: SwarmOrchestratorConfig,
  ) {
    this.id = generateSwarmId("swe");
    this.pool = new AgentPool(events, config.pool);
  }

  // =========================================================================
  // Lifecycle
  // =========================================================================

  /**
   * Initialize the orchestrator. Sets status to "running", creates pool
   * agents, starts health checks, and begins background timers.
   *
   * Must be called from "initializing" or "stopped" status.
   */
  initialize(): void {
    if (this.status !== "initializing" && this.status !== "stopped") {
      throw new Error(
        `Cannot initialize from status "${this.status}". Expected "initializing" or "stopped".`,
      );
    }

    // Initialize pool first (creates minSize agents)
    this.pool.initialize();

    // Start registry health checks
    this.registry.startHealthChecks();

    // Start background processes
    this.startBackgroundProcesses();

    // Update status
    this.startedAt = Date.now();
    this.status = "running";
  }

  /**
   * Shut down the orchestrator gracefully. Sets status to "stopped",
   * stops all background timers, and cleans up subsystems.
   *
   * Idempotent: calling from "stopped" is a no-op.
   */
  shutdown(): void {
    if (this.status === "stopped") {
      return;
    }

    this.status = "shutting_down";

    // Stop background timers
    this.stopBackgroundProcesses();

    // Shut down pool (clears agents, stops its health checks)
    this.pool.shutdown();

    // Stop registry health checks
    this.registry.stopHealthChecks();

    this.status = "stopped";
  }

  /**
   * Pause the orchestrator. Stops background timers but retains state.
   *
   * No-op if not in "running" status.
   */
  pause(): void {
    if (this.status !== "running") {
      return;
    }

    this.stopBackgroundProcesses();
    this.status = "paused";
  }

  /**
   * Resume the orchestrator from "paused" status. Restarts background timers.
   *
   * No-op if not in "paused" status.
   */
  resume(): void {
    if (this.status !== "paused") {
      return;
    }

    this.startBackgroundProcesses();
    this.status = "running";
  }

  /**
   * Synchronous disposal. Stops all timers, disposes the pool, and disposes
   * the shared event emitter.
   *
   * This is the ONLY method that calls events.dispose().
   */
  dispose(): void {
    // Stop all timers (safe with null)
    this.stopBackgroundProcesses();

    // Dispose pool (stops its health check timer)
    this.pool.dispose();

    // Dispose the shared emitter -- ONLY here
    this.events.dispose();

    this.status = "stopped";
  }

  // =========================================================================
  // Guard Pipeline
  // =========================================================================

  /**
   * Evaluate a guarded action through the guard pipeline.
   *
   * If no GuardEvaluator was injected, returns a deny result (fail-closed).
   * Emits "guard.evaluated" on every evaluation, "action.denied" on deny,
   * and "action.completed" on allow/warn.
   */
  async evaluateGuard(action: GuardedAction): Promise<GuardEvaluationResult> {
    const startMs = Date.now();
    let result: GuardEvaluationResult;

    if (!this.config.guardEvaluator) {
      // Fail-closed: no evaluator means deny all guarded actions
      result = {
        verdict: "deny",
        allowed: false,
        guardResults: [],
        receipt: this.createDenyReceipt(action),
        durationMs: 0,
        evaluatedAt: startMs,
      };
    } else {
      result = await this.config.guardEvaluator.evaluate(action);
    }

    const durationMs = Date.now() - startMs;

    // Track metrics
    this.guardEvaluationsTotal++;
    if (result.verdict === "deny") {
      this.guardDenialsTotal++;
    }

    // Store in audit log (FIFO eviction)
    const record: GuardedActionRecord = {
      action,
      evaluation: result,
      executed: result.allowed,
      executionError: null,
    };
    this.recentGuardActions.push(record);
    if (this.recentGuardActions.length > this.config.maxGuardActionHistory) {
      this.recentGuardActions.shift();
    }

    // Emit guard.evaluated event
    this.events.emit("guard.evaluated", {
      kind: "guard.evaluated",
      sourceAgentId: action.agentId,
      timestamp: Date.now(),
      action,
      result,
      durationMs,
    });

    if (result.verdict === "deny") {
      // Redact context to prevent sensitive data leaking via broadcast
      const redactedAction: GuardedAction = { ...action, context: {} };
      this.events.emit("action.denied", {
        kind: "action.denied",
        sourceAgentId: action.agentId,
        timestamp: Date.now(),
        action: redactedAction,
        receipt: this.envelopeReceiptFromReceipt(result.receipt),
        reason:
          result.guardResults.length > 0
            ? `Denied by guard: ${result.guardResults[0]?.guard ?? "unknown"}`
            : "no_evaluator",
      });
    } else {
      this.events.emit("action.completed", {
        kind: "action.completed",
        sourceAgentId: action.agentId,
        timestamp: Date.now(),
        action,
        receipt: this.envelopeReceiptFromReceipt(result.receipt),
        durationMs,
      });
    }

    return result;
  }

  // =========================================================================
  // State & Metrics
  // =========================================================================

  /**
   * Returns a complete snapshot of the swarm engine state.
   *
   * Aggregates state from all subsystems into a single serializable object.
   */
  getState(): SwarmEngineState {
    // Agent sessions from registry
    const agents = this.registry.getState();

    // Tasks from task graph
    const tasks = this.taskGraph.getState();

    return {
      id: this.id,
      namespace: this.config.namespace,
      version: "0.1.0",
      status: this.status,
      topologyConfig: this.config.topology,
      topology: this.topology.getState(),
      consensusConfig: this.config.consensus,
      agents,
      tasks,
      conversationHistory: this.getConversationHistorySnapshot(),
      activeProposals: {}, // Phase 4
      metrics: this.getMetrics(),
      recentGuardActions: [...this.recentGuardActions],
      maxGuardActionHistory: this.config.maxGuardActionHistory,
      createdAt: this.createdAt,
      startedAt: this.startedAt,
      updatedAt: Date.now(),
    };
  }

  /**
   * Returns live swarm engine metrics.
   *
   * Computed on-demand from subsystem state. Not cached.
   */
  getMetrics(): SwarmEngineMetrics {
    const now = Date.now();
    const agentSessions = Object.values(this.registry.getState());
    const allTasks = Object.values(this.taskGraph.getState());
    const activeSessions = agentSessions.filter(
      (s) => s.status !== "terminated" && s.status !== "offline",
    );
    const completedTasks = allTasks.filter((t) => t.status === "completed");
    const failedTasks = allTasks.filter((t) => t.status === "failed");
    const avgDuration =
      completedTasks.length > 0
        ? completedTasks.reduce(
            (sum, t) =>
              sum + ((t.completedAt ?? now) - (t.startedAt ?? now)),
            0,
          ) / completedTasks.length
        : 0;

    return {
      uptimeMs: this.startedAt ? now - this.startedAt : 0,
      activeAgents: activeSessions.length,
      totalTasks: allTasks.length,
      completedTasks: completedTasks.length,
      failedTasks: failedTasks.length,
      avgTaskDurationMs: avgDuration,
      messagesPerSecond: 0, // Populated by protocol bridge in Phase 5
      consensusSuccessRate: 0, // Populated in Phase 4
      coordinationLatencyMs: 0,
      memoryUsageBytes: 0, // Populated in Phase 4
      guardEvaluationsTotal: this.guardEvaluationsTotal,
      guardDenialRate:
        this.guardEvaluationsTotal > 0
          ? this.guardDenialsTotal / this.guardEvaluationsTotal
          : 0,
    };
  }

  // =========================================================================
  // Convenience Accessors
  // =========================================================================

  /** Returns the internal agent pool. */
  getPool(): AgentPool {
    return this.pool;
  }

  /** Returns the current engine status. */
  getStatus(): SwarmEngineStatus {
    return this.status;
  }

  /** Returns the engine instance ID. */
  getId(): string {
    return this.id;
  }

  /** Returns the shared event emitter for external subscriptions. */
  getEvents(): TypedEventEmitter<SwarmEngineEventMap> {
    return this.events;
  }

  /**
   * Record a replayable conversation turn for the given agent and emit
   * an `agent.message` event for live consumers such as the workbench board.
   */
  recordConversationTurn(
    agentId: string,
    turn: AgentConversationTurn,
  ): AgentConversationTurn {
    const history = this.conversationHistory.get(agentId) ?? [];
    history.push(structuredClone(turn));
    if (history.length > SWARM_ENGINE_CONSTANTS.MAX_CONVERSATION_HISTORY_TURNS) {
      history.splice(
        0,
        history.length - SWARM_ENGINE_CONSTANTS.MAX_CONVERSATION_HISTORY_TURNS,
      );
    }
    this.conversationHistory.set(agentId, history);

    this.events.emit("agent.message", {
      kind: "agent.message",
      sourceAgentId: agentId,
      timestamp: turn.createdAt,
      correlationId: turn.id,
      agentId,
      turn,
    });

    return structuredClone(turn);
  }

  /**
   * Return the recorded conversation history for one agent.
   */
  getConversationHistory(agentId: string): AgentConversationTurn[] {
    return structuredClone(this.conversationHistory.get(agentId) ?? []);
  }

  /**
   * Return the full conversation history map keyed by agent ID.
   */
  getConversationHistorySnapshot(): Record<string, AgentConversationTurn[]> {
    return Object.fromEntries(
      Array.from(this.conversationHistory.entries()).map(
        ([agentId, turns]) => [agentId, structuredClone(turns)] as const,
      ),
    );
  }

  // =========================================================================
  // Private: Background Processes
  // =========================================================================

  /**
   * Start heartbeat background timer.
   * Metrics are computed lazily in getMetrics() -- no periodic timer needed.
   */
  private startBackgroundProcesses(): void {
    // Heartbeat timer: update pool agent heartbeats
    this.heartbeatTimer = setInterval(() => {
      this.performHeartbeat();
    }, this.config.heartbeatIntervalMs);
  }

  /**
   * Stop all background timers. Safe to call with null timers.
   */
  private stopBackgroundProcesses(): void {
    if (this.heartbeatTimer !== null) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  /**
   * Heartbeat tick: update pool agent heartbeats.
   */
  private performHeartbeat(): void {
    const poolState = this.pool.getState();
    for (const agentId of Object.keys(poolState.agents)) {
      this.pool.updateAgentHeartbeat(agentId);
    }
  }

  // =========================================================================
  // Private: Guard Helpers
  // =========================================================================

  /**
   * Create a minimal deny receipt for fail-closed evaluation.
   */
  private createDenyReceipt(action: GuardedAction): Receipt {
    return {
      id: generateSwarmId("rct" as import("./ids.js").SwarmEngineIdPrefix),
      timestamp: new Date().toISOString(),
      verdict: "deny",
      guard: "fail-closed",
      policyName: "no-evaluator",
      action: { type: action.actionType, target: action.target },
      evidence: {},
      signature: "",
      publicKey: "",
      valid: false,
    };
  }

  /**
   * Project a full Receipt to a compact EnvelopeReceipt for transport.
   */
  private envelopeReceiptFromReceipt(receipt: Receipt): EnvelopeReceipt {
    return {
      receiptId: receipt.id,
      verdict: receipt.verdict,
      decidingGuard: receipt.guard,
      policyHash: "",
      evaluationMs: 0,
      signature: receipt.signature,
      publicKey: receipt.publicKey,
      evaluatedAt: Date.now(),
    };
  }
}
