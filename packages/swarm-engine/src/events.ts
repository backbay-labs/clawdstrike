/**
 * SwarmEngineEvent discriminated union, TypedEventEmitter runtime class,
 * and SwarmEngineEnvelope wire type.
 *
 * The TypedEventEmitter wraps EventTarget with per-event listener tracking,
 * deep cloning (prevents cross-listener mutation), dispose(), and
 * listenerCount(). It is the communication backbone for every subsystem.
 *
 * @module
 */

import type {
  AgentSession,
  AgentSessionStatus,
  AgentMetrics,
  AgentConversationTurn,
  Task,
  TaskStatus,
  TopologyType,
  TopologyState,
  ConsensusProposal,
  ConsensusVote,
  ConsensusResult,
  Receipt,
  GuardedAction,
  GuardEvaluationResult,
  EnvelopeReceipt,
} from "./types.js";

// ============================================================================
// TypedEventEmitter
// ============================================================================

/**
 * Type-safe event emitter wrapping the browser-native EventTarget.
 *
 * Design choices (see PITFALLS.md):
 * - Per-event listener tracking via Map<string, Map<handler, Set<EventListener>>> (Pitfall 1 prevention)
 * - structuredClone(detail) per listener for cross-listener isolation (Pitfall 2 prevention)
 * - dispose() removes ALL listeners across ALL event names
 * - listenerCount(event) returns accurate count after add/remove
 */
export class TypedEventEmitter<Events extends Record<string, unknown>> {
  private target = new EventTarget();
  private listeners = new Map<
    string,
    Map<(data: any) => void, Set<EventListener>>
  >();

  /**
   * Register a handler for the given event. Returns a cleanup function
   * that removes this specific listener when called.
   */
  on<K extends keyof Events & string>(
    event: K,
    handler: (data: Events[K]) => void,
  ): () => void {
    const listener = ((e: Event) =>
      handler(structuredClone((e as CustomEvent).detail))) as EventListener;
    this.target.addEventListener(event, listener);

    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Map());
    }

    const listenersForEvent = this.listeners.get(event)!;
    const listenersForHandler = listenersForEvent.get(handler) ?? new Set();
    listenersForHandler.add(listener);
    listenersForEvent.set(handler, listenersForHandler);

    // Return cleanup function
    return () => {
      this.target.removeEventListener(event, listener);
      const activeListeners = this.listeners.get(event)?.get(handler);
      activeListeners?.delete(listener);

      if (activeListeners && activeListeners.size === 0) {
        this.listeners.get(event)?.delete(handler);
      }

      if (this.listeners.get(event)?.size === 0) {
        this.listeners.delete(event);
      }
    };
  }

  /**
   * Emit an event to all registered listeners.
   *
   * CRITICAL: Each listener receives its own structuredClone of the detail
   * to prevent cross-listener mutation (PITFALLS.md Pitfall 2).
   */
  emit<K extends keyof Events & string>(event: K, data: Events[K]): void {
    const cloned = structuredClone(data);
    this.target.dispatchEvent(new CustomEvent(event, { detail: cloned }));
  }

  /**
   * Returns the number of listeners registered for the given event.
   */
  listenerCount<K extends keyof Events & string>(event: K): number {
    return (
      [...(this.listeners.get(event)?.values() ?? [])].reduce(
        (total, listenersForHandler) => total + listenersForHandler.size,
        0,
      ) ?? 0
    );
  }

  /**
   * Remove all listeners for a specific event, or all listeners across
   * all events if no event name is provided.
   */
  removeAllListeners<K extends keyof Events & string>(event?: K): void {
    if (event) {
      const map = this.listeners.get(event);
      if (map) {
        for (const listenersForHandler of map.values()) {
          for (const listener of listenersForHandler) {
            this.target.removeEventListener(event, listener);
          }
        }
        map.clear();
        this.listeners.delete(event);
      }
    } else {
      for (const [name, map] of this.listeners) {
        for (const listenersForHandler of map.values()) {
          for (const listener of listenersForHandler) {
            this.target.removeEventListener(name, listener);
          }
        }
        map.clear();
      }
      this.listeners.clear();
    }
  }

  /**
   * Remove all listeners and release internal references.
   * Call this when the emitter is no longer needed.
   */
  dispose(): void {
    this.removeAllListeners();
  }
}

// ============================================================================
// SwarmEngineEvent Base
// ============================================================================

/**
 * Base fields shared by all swarm engine events.
 * Not exported -- consumers use the concrete event interfaces.
 */
interface SwarmEngineEventBase {
  sourceAgentId: string | null;
  timestamp: number;
  correlationId?: string;
}

// ============================================================================
// Agent Lifecycle Events
// ============================================================================

export interface AgentSpawnedEvent extends SwarmEngineEventBase {
  kind: "agent.spawned";
  agent: AgentSession;
  /** Receipt from the guard check that approved agent creation. */
  receipt: Receipt | null;
}

export interface AgentStatusChangedEvent extends SwarmEngineEventBase {
  kind: "agent.status_changed";
  agentId: string;
  previousStatus: AgentSessionStatus;
  newStatus: AgentSessionStatus;
  reason: string | null;
}

export interface AgentHeartbeatEvent extends SwarmEngineEventBase {
  kind: "agent.heartbeat";
  agentId: string;
  health: number;
  workload: number;
  metricsSnapshot: AgentMetrics;
}

export interface AgentTerminatedEvent extends SwarmEngineEventBase {
  kind: "agent.terminated";
  agentId: string;
  exitCode: number | null;
  reason: string | null;
  finalMetrics: AgentMetrics;
}

export interface AgentMessageEvent extends SwarmEngineEventBase {
  kind: "agent.message";
  agentId: string;
  turn: AgentConversationTurn;
}

// ============================================================================
// Task Orchestration Events
// ============================================================================

export interface TaskCreatedEvent extends SwarmEngineEventBase {
  kind: "task.created";
  task: Task;
}

export interface TaskAssignedEvent extends SwarmEngineEventBase {
  kind: "task.assigned";
  taskId: string;
  agentId: string;
  /** Receipt from the guard check that approved this assignment. */
  receipt: Receipt | null;
}

export interface TaskStatusChangedEvent extends SwarmEngineEventBase {
  kind: "task.status_changed";
  taskId: string;
  previousStatus: TaskStatus;
  newStatus: TaskStatus;
  reason: string | null;
}

export interface TaskCompletedEvent extends SwarmEngineEventBase {
  kind: "task.completed";
  taskId: string;
  agentId: string;
  output: Record<string, unknown>;
  durationMs: number;
  /** Receipt attesting to the completed work. */
  receipt: Receipt | null;
}

export interface TaskFailedEvent extends SwarmEngineEventBase {
  kind: "task.failed";
  taskId: string;
  agentId: string | null;
  error: string;
  retryable: boolean;
}

// ============================================================================
// Task Progress Events
// ============================================================================

/**
 * Task progress report event (TASK-06).
 *
 * Emitted by agents to report incremental progress on a task.
 * Guard-exempt: progress reporting does not trigger guard evaluation.
 */
export interface TaskProgressEvent extends SwarmEngineEventBase {
  kind: "task.progress";
  taskId: string;
  agentId: string;
  /** Completion percentage (0-100). */
  percent: number;
  /** Human-readable description of the current step. */
  currentStep: string;
  /** Zero-based index of the current step. */
  stepIndex: number;
  /** Total number of steps in the task. */
  totalSteps: number;
}

// ============================================================================
// Topology Events
// ============================================================================

export interface TopologyUpdatedEvent extends SwarmEngineEventBase {
  kind: "topology.updated";
  previousType: TopologyType;
  newTopology: TopologyState;
}

export interface TopologyRebalancedEvent extends SwarmEngineEventBase {
  kind: "topology.rebalanced";
  movedAgents: Array<{
    agentId: string;
    fromPartition: string;
    toPartition: string;
  }>;
  topology: TopologyState;
}

export interface LeaderElectedEvent extends SwarmEngineEventBase {
  kind: "topology.leader_elected";
  leaderId: string;
  term: number;
  electionDurationMs: number;
}

// ============================================================================
// Consensus Events
// ============================================================================

export interface ConsensusProposedEvent extends SwarmEngineEventBase {
  kind: "consensus.proposed";
  proposal: ConsensusProposal;
}

export interface ConsensusVoteCastEvent extends SwarmEngineEventBase {
  kind: "consensus.vote_cast";
  proposalId: string;
  vote: ConsensusVote;
}

export interface ConsensusResolvedEvent extends SwarmEngineEventBase {
  kind: "consensus.resolved";
  result: ConsensusResult;
}

// ============================================================================
// Memory Events
// ============================================================================

export interface MemoryStoreEvent extends SwarmEngineEventBase {
  kind: "memory.store";
  namespace: string;
  key: string;
  /** Byte size of the stored value. */
  sizeBytes: number;
}

export interface MemorySearchEvent extends SwarmEngineEventBase {
  kind: "memory.search";
  namespace: string;
  query: string;
  resultCount: number;
  durationMs: number;
}

// ============================================================================
// Hook Events
// ============================================================================

export interface HookTriggeredEvent extends SwarmEngineEventBase {
  kind: "hooks.triggered";
  hookName: string;
  hookCategory:
    | "core"
    | "session"
    | "intelligence"
    | "learning"
    | "agent_teams";
  triggerContext: Record<string, unknown>;
}

export interface HookCompletedEvent extends SwarmEngineEventBase {
  kind: "hooks.completed";
  hookName: string;
  success: boolean;
  durationMs: number;
  result: Record<string, unknown> | null;
}

// ============================================================================
// Guard Pipeline Events
// ============================================================================

/**
 * Emitted after the guard pipeline evaluates an agent action.
 * Contains the full evaluation result including individual guard verdicts.
 */
export interface GuardEvaluatedEvent extends SwarmEngineEventBase {
  kind: "guard.evaluated";
  action: GuardedAction;
  result: GuardEvaluationResult;
  durationMs: number;
}

/**
 * Emitted when an agent action is denied by the guard pipeline.
 * The receipt contains the deny verdict and deciding guard.
 */
export interface ActionDeniedEvent extends SwarmEngineEventBase {
  kind: "action.denied";
  action: GuardedAction;
  receipt: EnvelopeReceipt;
  reason: string;
}

/**
 * Emitted when an agent action is allowed and completes execution.
 * The receipt contains the allow/warn verdict.
 */
export interface ActionCompletedEvent extends SwarmEngineEventBase {
  kind: "action.completed";
  action: GuardedAction;
  receipt: EnvelopeReceipt;
  durationMs: number;
}

// ============================================================================
// SwarmEngineEvent Discriminated Union
// ============================================================================

/**
 * All swarm engine events. Discriminated by `kind`.
 *
 * Every event includes:
 * - `kind`: discriminator for narrowing
 * - `sourceAgentId`: the agent that originated the event (or null for system events)
 * - `timestamp`: Unix ms when the event occurred
 * - `correlationId`: optional ID for tracing related events
 */
export type SwarmEngineEvent =
  // Agent lifecycle
  | AgentSpawnedEvent
  | AgentStatusChangedEvent
  | AgentHeartbeatEvent
  | AgentTerminatedEvent
  | AgentMessageEvent
  // Task orchestration
  | TaskCreatedEvent
  | TaskAssignedEvent
  | TaskStatusChangedEvent
  | TaskCompletedEvent
  | TaskFailedEvent
  | TaskProgressEvent
  // Topology
  | TopologyUpdatedEvent
  | TopologyRebalancedEvent
  | LeaderElectedEvent
  // Consensus
  | ConsensusProposedEvent
  | ConsensusVoteCastEvent
  | ConsensusResolvedEvent
  // Memory
  | MemoryStoreEvent
  | MemorySearchEvent
  // Hooks
  | HookTriggeredEvent
  | HookCompletedEvent
  // Guard pipeline
  | GuardEvaluatedEvent
  | ActionDeniedEvent
  | ActionCompletedEvent;

// ============================================================================
// SwarmEngineEventMap
// ============================================================================

/**
 * Maps event kind strings to their typed payloads.
 * Used as the generic parameter for TypedEventEmitter<SwarmEngineEventMap>.
 */
export type SwarmEngineEventMap = {
  "agent.spawned": AgentSpawnedEvent;
  "agent.status_changed": AgentStatusChangedEvent;
  "agent.heartbeat": AgentHeartbeatEvent;
  "agent.terminated": AgentTerminatedEvent;
  "agent.message": AgentMessageEvent;
  "task.created": TaskCreatedEvent;
  "task.assigned": TaskAssignedEvent;
  "task.status_changed": TaskStatusChangedEvent;
  "task.completed": TaskCompletedEvent;
  "task.failed": TaskFailedEvent;
  "task.progress": TaskProgressEvent;
  "topology.updated": TopologyUpdatedEvent;
  "topology.rebalanced": TopologyRebalancedEvent;
  "topology.leader_elected": LeaderElectedEvent;
  "consensus.proposed": ConsensusProposedEvent;
  "consensus.vote_cast": ConsensusVoteCastEvent;
  "consensus.resolved": ConsensusResolvedEvent;
  "memory.store": MemoryStoreEvent;
  "memory.search": MemorySearchEvent;
  "hooks.triggered": HookTriggeredEvent;
  "hooks.completed": HookCompletedEvent;
  "guard.evaluated": GuardEvaluatedEvent;
  "action.denied": ActionDeniedEvent;
  "action.completed": ActionCompletedEvent;
};

// ============================================================================
// SwarmEngineEnvelope
// ============================================================================

/**
 * Extended envelope type for the swarm engine.
 *
 * Compatible with ClawdStrike's SwarmEnvelope but adds orchestration channels.
 * The `type` field is the discriminator used by routers.
 */
export interface SwarmEngineEnvelope {
  /** Protocol version. */
  version: 1;

  /** Envelope type for routing. */
  type:
    | "intel"
    | "signal"
    | "detection"
    | "coordination"
    | "status"
    | "agent_lifecycle"
    | "task_orchestration"
    | "topology"
    | "consensus"
    | "memory"
    | "hooks";

  /** Typed event payload. Discriminated by `kind` inside the payload. */
  payload: SwarmEngineEvent;

  /** TTL in Gossipsub hops. */
  ttl: number;

  /** Timestamp when envelope was created (Unix ms). */
  created: number;
}
