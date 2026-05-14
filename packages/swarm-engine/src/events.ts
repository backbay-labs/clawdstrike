/**
 * Swarm engine event types, TypedEventEmitter, and envelope wire type.
 *
 * @module
 */

import type {
  AgentSession,
  AgentSessionStatus,
  AgentMetrics,
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

/**
 * Type-safe event emitter wrapping EventTarget.
 * Each listener receives a structuredClone of the detail for cross-listener isolation.
 */
export class TypedEventEmitter<Events extends Record<string, unknown>> {
  private target = new EventTarget();
  private listeners = new Map<
    string,
    Array<{ handler: (data: any) => void; listener: EventListener }>
  >();

  /** Register a handler. Returns a cleanup function. */
  on<K extends keyof Events & string>(
    event: K,
    handler: (data: Events[K]) => void,
  ): () => void {
    const listener = ((e: Event) =>
      handler(structuredClone((e as CustomEvent).detail))) as EventListener;
    this.target.addEventListener(event, listener);

    if (!this.listeners.has(event)) {
      this.listeners.set(event, []);
    }
    this.listeners.get(event)!.push({ handler, listener });

    return () => {
      this.target.removeEventListener(event, listener);
      const registrations = this.listeners.get(event);
      if (!registrations) {
        return;
      }

      const registrationIndex = registrations.findIndex(
        (registration) =>
          registration.handler === handler &&
          registration.listener === listener,
      );
      if (registrationIndex !== -1) {
        registrations.splice(registrationIndex, 1);
      }
      if (registrations.length === 0) {
        this.listeners.delete(event);
      }
    };
  }

  emit<K extends keyof Events & string>(event: K, data: Events[K]): void {
    const cloned = structuredClone(data);
    this.target.dispatchEvent(new CustomEvent(event, { detail: cloned }));
  }

  listenerCount<K extends keyof Events & string>(event: K): number {
    return this.listeners.get(event)?.length ?? 0;
  }

  removeAllListeners<K extends keyof Events & string>(event?: K): void {
    if (event) {
      const registrations = this.listeners.get(event);
      if (registrations) {
        for (const { listener } of registrations) {
          this.target.removeEventListener(event, listener);
        }
        this.listeners.delete(event);
      }
    } else {
      for (const [name, registrations] of this.listeners) {
        for (const { listener } of registrations) {
          this.target.removeEventListener(name, listener);
        }
      }
      this.listeners.clear();
    }
  }

  dispose(): void {
    this.removeAllListeners();
  }
}

/** Base fields shared by all swarm engine events. */
interface SwarmEngineEventBase {
  sourceAgentId: string | null;
  timestamp: number;
  correlationId?: string;
}


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

/** Guard-exempt: does not trigger guard evaluation. */
export interface TaskProgressEvent extends SwarmEngineEventBase {
  kind: "task.progress";
  taskId: string;
  agentId: string;
  /** 0-100. */
  percent: number;
  currentStep: string;
  stepIndex: number;
  totalSteps: number;
}


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

export interface GuardEvaluatedEvent extends SwarmEngineEventBase {
  kind: "guard.evaluated";
  action: GuardedAction;
  result: GuardEvaluationResult;
  durationMs: number;
}

export interface ActionDeniedEvent extends SwarmEngineEventBase {
  kind: "action.denied";
  action: GuardedAction;
  receipt: EnvelopeReceipt;
  reason: string;
}

export interface ActionCompletedEvent extends SwarmEngineEventBase {
  kind: "action.completed";
  action: GuardedAction;
  receipt: EnvelopeReceipt;
  durationMs: number;
}

/** All swarm engine events. Discriminated by `kind`. */
export type SwarmEngineEvent =
  | AgentSpawnedEvent
  | AgentStatusChangedEvent
  | AgentHeartbeatEvent
  | AgentTerminatedEvent
  | TaskCreatedEvent
  | TaskAssignedEvent
  | TaskStatusChangedEvent
  | TaskCompletedEvent
  | TaskFailedEvent
  | TaskProgressEvent
  | TopologyUpdatedEvent
  | TopologyRebalancedEvent
  | LeaderElectedEvent
  | ConsensusProposedEvent
  | ConsensusVoteCastEvent
  | ConsensusResolvedEvent
  | MemoryStoreEvent
  | MemorySearchEvent
  | HookTriggeredEvent
  | HookCompletedEvent
  | GuardEvaluatedEvent
  | ActionDeniedEvent
  | ActionCompletedEvent;

/** Maps event kind to typed payload for TypedEventEmitter. */
export type SwarmEngineEventMap = {
  "agent.spawned": AgentSpawnedEvent;
  "agent.status_changed": AgentStatusChangedEvent;
  "agent.heartbeat": AgentHeartbeatEvent;
  "agent.terminated": AgentTerminatedEvent;
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

/** Compatible with ClawdStrike's SwarmEnvelope, plus orchestration channels. */
export interface SwarmEngineEnvelope {
  version: 1;
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

  payload: SwarmEngineEvent;
  ttl: number;
  created: number;
}
