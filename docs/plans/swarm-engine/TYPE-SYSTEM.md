# Swarm Engine Unified Type System

**Status:** Proposed
**Date:** 2026-03-24
**Author:** Architecture team
**Scope:** `packages/swarm-engine/src/types.ts`

---

## 1. Design Principles

1. **ClawdStrike types are the foundation.** Where both systems define the same concept, ClawdStrike's shape, naming, and conventions win. Ruflo types adapt.
2. **Prefixed ULID IDs.** ClawdStrike uses `{prefix}_{ulid}` (e.g., `sen_01HXK...`). Ruflo entities adopt the same scheme: agents use `agt_`, tasks use `tsk_`, swarm engines use `swe_`.
3. **Receipt on every action.** Every type that represents a mutation or agent action carries a `receipt: Receipt | null` field, tying the action to a guard evaluation result.
4. **Serializable everywhere.** All types must be JSON-serializable (no `Map`, no `Date` objects, no functions, no circular references). Timestamps are Unix milliseconds (`number`). Collections are arrays or `Record<string, T>`.
5. **Discriminated unions for events.** All envelope event payloads use a `kind` discriminator field so consumers can narrow with a single switch.
6. **No import of ruflo runtime types.** This package does not depend on `@claude-flow/swarm`. It defines its own types that are *structurally compatible* with ruflo's orchestration engine but owned by ClawdStrike.

---

## 2. ID Prefixes

Extends the existing `IdPrefix` type from `sentinel-types.ts`.

```typescript
/**
 * ID prefixes for swarm engine entities.
 * Extends sentinel-types.ts IdPrefix ("sen" | "sig" | "fnd" | "int" | "swm" | "spk" | "enr" | "msn").
 */
export type SwarmEngineIdPrefix =
  | "agt"   // AgentSession
  | "tsk"   // Task
  | "swe"   // SwarmEngine instance
  | "top"   // Topology snapshot
  | "csn"   // Consensus proposal
  | "msg";  // Internal message

/**
 * Combined prefix type for generateId() calls within swarm-engine.
 */
export type AllIdPrefix = import("@/lib/workbench/sentinel-types").IdPrefix | SwarmEngineIdPrefix;
```

---

## 3. Agent Types

### 3.1 Unified AgentSession

The agent IS the session. This type merges:
- Ruflo's `AgentState` (orchestration: capabilities, metrics, workload, topology role)
- ClawdStrike's `SwarmBoardNodeData` where `nodeType === "agentSession"` (UI rendering: status, risk, policy, branch)
- ClawdStrike's session concept (sessionId, worktreePath, receipts)

```typescript
import type { Receipt, Verdict, GuardId } from "@/lib/workbench/types";

// ---------------------------------------------------------------------------
// Agent role — superset of ruflo's AgentType and ClawdStrike's sentinel modes
// ---------------------------------------------------------------------------

/**
 * Agent role within the swarm engine.
 *
 * Ruflo origin: coordinator, researcher, coder, analyst, architect, tester,
 *   reviewer, optimizer, documenter, monitor, specialist, queen, worker.
 * ClawdStrike addition: sentinel (bridges to SentinelMode behavior).
 */
export type AgentRole =
  | "coordinator"
  | "researcher"
  | "coder"
  | "analyst"
  | "architect"
  | "tester"
  | "reviewer"
  | "optimizer"
  | "documenter"
  | "monitor"
  | "specialist"
  | "queen"
  | "worker"
  | "sentinel";

// ---------------------------------------------------------------------------
// Agent session status — ClawdStrike's SessionStatus extended with ruflo states
// ---------------------------------------------------------------------------

/**
 * Lifecycle status for an agent session.
 *
 * ClawdStrike base: "idle" | "running" | "blocked" | "completed" | "failed" | "evaluating"
 * Added from ruflo: "initializing" | "paused" | "terminating" | "terminated"
 * Added for engine: "offline"
 */
export type AgentSessionStatus =
  | "initializing"
  | "idle"
  | "running"
  | "blocked"
  | "paused"
  | "evaluating"
  | "completed"
  | "failed"
  | "terminating"
  | "terminated"
  | "offline";

// ---------------------------------------------------------------------------
// Risk level — from ClawdStrike's SwarmBoard
// ---------------------------------------------------------------------------

export type RiskLevel = "low" | "medium" | "high";

// ---------------------------------------------------------------------------
// Agent capabilities — from ruflo, serializable
// ---------------------------------------------------------------------------

export interface AgentCapabilities {
  codeGeneration: boolean;
  codeReview: boolean;
  testing: boolean;
  documentation: boolean;
  research: boolean;
  analysis: boolean;
  coordination: boolean;
  securityAnalysis: boolean;
  languages: string[];
  frameworks: string[];
  domains: string[];
  tools: string[];
  maxConcurrentTasks: number;
  maxMemoryUsageBytes: number;
  maxExecutionTimeMs: number;
}

// ---------------------------------------------------------------------------
// Agent metrics — from ruflo, timestamps as Unix ms
// ---------------------------------------------------------------------------

export interface AgentMetrics {
  tasksCompleted: number;
  tasksFailed: number;
  averageExecutionTimeMs: number;
  successRate: number;
  cpuUsage: number;
  memoryUsageBytes: number;
  messagesProcessed: number;
  lastActivityAt: number;
  responseTimeMs: number;
  health: number;
}

// ---------------------------------------------------------------------------
// Agent quality scores — from ruflo
// ---------------------------------------------------------------------------

export interface AgentQualityScores {
  reliability: number;
  speed: number;
  quality: number;
}

// ---------------------------------------------------------------------------
// Guard receipt summary — lightweight version for board rendering
// ---------------------------------------------------------------------------

export interface GuardReceiptSummary {
  guard: string;
  allowed: boolean;
  durationMs?: number;
}

// ---------------------------------------------------------------------------
// The unified AgentSession
// ---------------------------------------------------------------------------

/**
 * Unified agent session type.
 *
 * This is the single type that represents an agent on both the SwarmBoard
 * (React Flow rendering) and the orchestration engine (task assignment,
 * topology, consensus).
 *
 * The agent IS the session. A running agent always has a session. A
 * completed/failed agent retains its session data for audit.
 */
export interface AgentSession {
  /** Unique agent session ID. Format: `agt_{ulid}`. */
  id: string;

  /** Human-readable name. */
  name: string;

  /** Agent role within the swarm. */
  role: AgentRole;

  /** Current lifecycle status. */
  status: AgentSessionStatus;

  // -- Orchestration fields (from ruflo AgentState) --

  /** Agent capabilities for task assignment. */
  capabilities: AgentCapabilities;

  /** Lifetime performance metrics. */
  metrics: AgentMetrics;

  /** Quality scores for task routing. */
  quality: AgentQualityScores;

  /** ID of the currently assigned task, or null. Format: `tsk_{ulid}`. */
  currentTaskId: string | null;

  /** Workload factor 0.0-1.0. Used by the scheduler. */
  workload: number;

  /** Health score 0.0-1.0. Below threshold triggers failover. */
  health: number;

  /** Last heartbeat timestamp (Unix ms). */
  lastHeartbeatAt: number;

  /** Topology role, if assigned. */
  topologyRole: TopologyNodeRole | null;

  /** IDs of connected peer agents. */
  connections: string[];

  // -- ClawdStrike board fields (from SwarmBoardNodeData) --

  /** Worktree path for git-based agents. */
  worktreePath: string | null;

  /** Git branch name. */
  branch: string | null;

  /** Assessed risk level of current activity. */
  risk: RiskLevel;

  /** Policy mode this agent is running under (e.g., "strict", "permissive"). */
  policyMode: string | null;

  /** Agent model identifier (e.g., "claude-3.5-sonnet", "gpt-4"). */
  agentModel: string | null;

  /** Number of guard receipts generated in this session. */
  receiptCount: number;

  /** Count of blocked actions (guard denials). */
  blockedActionCount: number;

  /** Count of files modified in this session. */
  changedFilesCount: number;

  /** Files touched during this session. */
  filesTouched: string[];

  /** Tool boundary events observed. */
  toolBoundaryEvents: number;

  /** Overall confidence score 0-100 for current work. */
  confidence: number | null;

  /** Guard results from the most recent evaluation. */
  guardResults: GuardReceiptSummary[];

  // -- Guard integration --

  /**
   * Receipt from the most recent guard evaluation on this agent's action.
   * Null if no evaluation has occurred yet or the agent has not acted.
   */
  receipt: Receipt | null;

  // -- Sentinel bridge --

  /**
   * If this agent is backed by a Sentinel, the sentinel ID.
   * Format: `sen_{ulid}`. Null for pure orchestration agents.
   */
  sentinelId: string | null;

  // -- Timestamps --

  /** Session creation timestamp (Unix ms). */
  createdAt: number;

  /** Last update timestamp (Unix ms). */
  updatedAt: number;

  /** Exit code if completed/failed. */
  exitCode: number | null;
}
```

### 3.2 SwarmBoard Adapter

To render an `AgentSession` on the React Flow board, the SwarmBoard maps it to a `Node<SwarmBoardNodeData>`. The mapping is one-directional and lossy -- the board only needs display fields.

```typescript
/**
 * Convert an AgentSession to SwarmBoardNodeData for React Flow rendering.
 * This is a pure function with no side effects.
 */
export function agentSessionToBoardData(agent: AgentSession): SwarmBoardNodeData {
  return {
    title: agent.name,
    status: agentSessionStatusToSessionStatus(agent.status),
    nodeType: "agentSession" as const,
    sessionId: agent.id,
    worktreePath: agent.worktreePath ?? undefined,
    branch: agent.branch ?? undefined,
    risk: agent.risk,
    policyMode: agent.policyMode ?? undefined,
    agentModel: agent.agentModel ?? undefined,
    receiptCount: agent.receiptCount,
    blockedActionCount: agent.blockedActionCount,
    changedFilesCount: agent.changedFilesCount,
    filesTouched: agent.filesTouched,
    toolBoundaryEvents: agent.toolBoundaryEvents,
    confidence: agent.confidence ?? undefined,
    guardResults: agent.guardResults.map((gr) => ({
      guard: gr.guard,
      allowed: gr.allowed,
      duration_ms: gr.durationMs,
    })),
    exitCode: agent.exitCode,
    createdAt: agent.createdAt,
  };
}

/**
 * Map AgentSessionStatus to the narrower SwarmBoard SessionStatus.
 * States that have no board equivalent collapse to the closest match.
 */
function agentSessionStatusToSessionStatus(
  status: AgentSessionStatus,
): SessionStatus {
  switch (status) {
    case "initializing":
    case "paused":
    case "offline":
      return "idle";
    case "idle":
      return "idle";
    case "running":
      return "running";
    case "blocked":
      return "blocked";
    case "evaluating":
      return "evaluating";
    case "completed":
    case "terminated":
      return "completed";
    case "terminating":
      return "running";
    case "failed":
      return "failed";
  }
}
```

---

## 4. Task Types

### 4.1 Unified Task

Merges ruflo's `TaskDefinition` with ClawdStrike's `terminalTask` board node concept.

```typescript
// ---------------------------------------------------------------------------
// Task priority — from ruflo, unchanged
// ---------------------------------------------------------------------------

export type TaskPriority = "critical" | "high" | "normal" | "low" | "background";

// ---------------------------------------------------------------------------
// Task status — from ruflo, serializable
// ---------------------------------------------------------------------------

export type TaskStatus =
  | "created"
  | "queued"
  | "assigned"
  | "running"
  | "paused"
  | "completed"
  | "failed"
  | "cancelled"
  | "timeout";

// ---------------------------------------------------------------------------
// Task type — from ruflo, extended for ClawdStrike domain
// ---------------------------------------------------------------------------

export type TaskType =
  | "research"
  | "analysis"
  | "coding"
  | "testing"
  | "review"
  | "documentation"
  | "coordination"
  | "consensus"
  | "detection"       // ClawdStrike: detection rule authoring
  | "hunt"            // ClawdStrike: threat hunt execution
  | "guard_evaluation" // ClawdStrike: policy guard simulation
  | "custom";

// ---------------------------------------------------------------------------
// The unified Task
// ---------------------------------------------------------------------------

/**
 * A unit of work assigned to an agent in the swarm engine.
 *
 * Merges ruflo TaskDefinition (orchestration: priority, dependencies,
 * timeout, retries) with ClawdStrike terminal task (board rendering:
 * prompt, preview lines, hunt association).
 */
export interface Task {
  /** Unique task ID. Format: `tsk_{ulid}`. */
  id: string;

  /** Swarm engine instance this task belongs to. Format: `swe_{ulid}`. */
  swarmEngineId: string;

  /** Task classification. */
  type: TaskType;

  /** Human-readable task name. */
  name: string;

  /** Detailed description or prompt for the agent. */
  description: string;

  /** Execution priority. */
  priority: TaskPriority;

  /** Current lifecycle status. */
  status: TaskStatus;

  /** Sequence number within the swarm for ordering. */
  sequence: number;

  // -- Assignment --

  /** ID of the assigned agent. Format: `agt_{ulid}`. Null if unassigned. */
  assignedTo: string | null;

  /**
   * Task IDs that must complete before this task can start.
   * Format: `tsk_{ulid}[]`.
   */
  dependencies: string[];

  // -- Input / Output --

  /** Input data for the task. Must be JSON-serializable. */
  input: Record<string, unknown>;

  /** Output data produced by the task. Null until completed. */
  output: Record<string, unknown> | null;

  // -- Execution --

  /** Timeout in milliseconds. 0 means no timeout. */
  timeoutMs: number;

  /** Current retry count. */
  retries: number;

  /** Maximum retry attempts before permanent failure. */
  maxRetries: number;

  // -- ClawdStrike board fields --

  /** The prompt text shown in the terminal task node. */
  taskPrompt: string | null;

  /** Preview lines for board rendering. */
  previewLines: string[];

  /** Associated hunt ID, if this task is part of a threat hunt. */
  huntId: string | null;

  /** Artifact IDs produced by this task. */
  artifactIds: string[];

  // -- Guard integration --

  /**
   * Receipt from the guard evaluation of this task's action.
   * Every task that performs a guarded action must attach the receipt.
   * Null if the task has not yet triggered a guard evaluation.
   */
  receipt: Receipt | null;

  // -- Metadata --

  /** Arbitrary metadata. Must be JSON-serializable. */
  metadata: Record<string, unknown>;

  // -- Timestamps (Unix ms) --

  createdAt: number;
  startedAt: number | null;
  completedAt: number | null;
  updatedAt: number;
}
```

---

## 5. Topology Types

Adapted from ruflo's `TopologyConfig`, `TopologyState`, `TopologyNode`, `TopologyEdge` for React Flow layout rendering.

```typescript
// ---------------------------------------------------------------------------
// Topology type — from ruflo, adding "adaptive" from ClawdStrike hive-mind
// ---------------------------------------------------------------------------

export type TopologyType = "mesh" | "hierarchical" | "centralized" | "hybrid" | "adaptive";

// ---------------------------------------------------------------------------
// Topology node role — from ruflo
// ---------------------------------------------------------------------------

export type TopologyNodeRole = "queen" | "worker" | "coordinator" | "peer";

// ---------------------------------------------------------------------------
// Topology node status
// ---------------------------------------------------------------------------

export type TopologyNodeStatus = "active" | "inactive" | "syncing" | "failed";

// ---------------------------------------------------------------------------
// Topology configuration
// ---------------------------------------------------------------------------

export interface TopologyConfig {
  type: TopologyType;
  maxAgents: number;
  replicationFactor: number;
  partitionStrategy: "hash" | "range" | "round-robin";
  failoverEnabled: boolean;
  autoRebalance: boolean;
}

// ---------------------------------------------------------------------------
// Topology node — enriched for React Flow rendering
// ---------------------------------------------------------------------------

/**
 * A node in the topology graph.
 *
 * Carries enough data for both:
 * - Orchestration: connections, role, status for routing decisions
 * - React Flow: position, dimensions, visual metadata for layout
 */
export interface TopologyNode {
  /** Topology node ID. Format: `top_{ulid}` or matches the agent ID. */
  id: string;

  /** Agent session ID. Format: `agt_{ulid}`. */
  agentId: string;

  /** Role in the topology. */
  role: TopologyNodeRole;

  /** Current status. */
  status: TopologyNodeStatus;

  /** IDs of connected topology nodes. */
  connections: string[];

  /** Arbitrary metadata for layout engines. */
  metadata: Record<string, unknown>;

  // -- React Flow layout hints --

  /** Suggested X position for React Flow. Null if auto-layout. */
  positionX: number | null;

  /** Suggested Y position for React Flow. Null if auto-layout. */
  positionY: number | null;

  /** Depth in the hierarchy (0 = root/queen). Null for mesh topologies. */
  hierarchyDepth: number | null;
}

// ---------------------------------------------------------------------------
// Topology edge — from ruflo, compatible with SwarmBoardEdge
// ---------------------------------------------------------------------------

/**
 * An edge in the topology graph.
 *
 * Compatible with SwarmBoardEdge for board rendering:
 * - `from` maps to `source`
 * - `to` maps to `target`
 */
export interface TopologyEdge {
  /** Source topology node ID. */
  from: string;

  /** Target topology node ID. */
  to: string;

  /** Edge weight for routing (lower = preferred). */
  weight: number;

  /** Whether communication flows both directions. */
  bidirectional: boolean;

  /** Measured latency in milliseconds. Null if unmeasured. */
  latencyMs: number | null;

  /**
   * Edge type for React Flow rendering.
   * Maps to SwarmBoardEdge.type.
   */
  edgeType: "handoff" | "spawned" | "artifact" | "receipt" | "topology";
}

// ---------------------------------------------------------------------------
// Topology partition — from ruflo
// ---------------------------------------------------------------------------

export interface TopologyPartition {
  id: string;
  nodeIds: string[];
  leaderId: string;
  replicaCount: number;
}

// ---------------------------------------------------------------------------
// Topology state snapshot — the full graph at a point in time
// ---------------------------------------------------------------------------

/**
 * Complete topology state. Serializable snapshot for persistence and
 * transport via SwarmEnvelope.
 */
export interface TopologyState {
  type: TopologyType;
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  leaderId: string | null;
  partitions: TopologyPartition[];
  /** Snapshot timestamp (Unix ms). */
  snapshotAt: number;
}
```

### 5.1 React Flow Conversion

```typescript
import type { Node, Edge } from "@xyflow/react";

/**
 * Convert a TopologyState to React Flow nodes and edges.
 * Agents are looked up to populate display data.
 */
export function topologyToReactFlow(
  topology: TopologyState,
  agents: Record<string, AgentSession>,
): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = topology.nodes.map((tn) => {
    const agent = agents[tn.agentId];
    return {
      id: tn.id,
      type: "agentSession",
      position: {
        x: tn.positionX ?? 0,
        y: tn.positionY ?? 0,
      },
      data: agent
        ? agentSessionToBoardData(agent)
        : { title: tn.agentId, status: "idle", nodeType: "agentSession" as const },
    };
  });

  const edges: Edge[] = topology.edges.map((te, idx) => ({
    id: `edge-${te.from}-${te.to}-${idx}`,
    source: te.from,
    target: te.to,
    type: te.edgeType,
    label: te.latencyMs != null ? `${te.latencyMs}ms` : undefined,
  }));

  return { nodes, edges };
}
```

---

## 6. Consensus Types

From ruflo, made serializable (no `Map`, no `Date`).

```typescript
export type ConsensusAlgorithm = "raft" | "byzantine" | "gossip" | "paxos";

export interface ConsensusConfig {
  algorithm: ConsensusAlgorithm;
  /** Fraction of votes needed for approval (0.0-1.0). */
  threshold: number;
  timeoutMs: number;
  maxRounds: number;
  requireQuorum: boolean;
}

export type ConsensusProposalStatus = "pending" | "accepted" | "rejected" | "expired";

export interface ConsensusVote {
  voterId: string;
  approve: boolean;
  confidence: number;
  timestamp: number;
  reason?: string;
}

/**
 * A consensus proposal. Serializable -- votes stored as array, not Map.
 */
export interface ConsensusProposal {
  /** Proposal ID. Format: `csn_{ulid}`. */
  id: string;
  proposerId: string;
  value: Record<string, unknown>;
  term: number;
  timestamp: number;
  votes: ConsensusVote[];
  status: ConsensusProposalStatus;
}

export interface ConsensusResult {
  proposalId: string;
  approved: boolean;
  approvalRate: number;
  participationRate: number;
  finalValue: Record<string, unknown>;
  rounds: number;
  durationMs: number;
  /** Receipt proving the consensus outcome was guard-evaluated. */
  receipt: Receipt | null;
}
```

---

## 7. Event Naming Glossary

The swarm engine uses two parallel naming conventions for events. These are deliberate and serve different purposes:

### 7.1 Protocol Actions (imperative, dot notation)

Used in `GuardedPayload.action` fields on `SwarmEnvelope` payloads (see PROTOCOL-SPEC.md). These represent **commands or requests** — something an agent wants to do. The guard pipeline evaluates these before they are forwarded.

| Action | Channel | Guarded | Description |
|--------|---------|---------|-------------|
| `agent.spawn` | `agent_lifecycle` | Yes | Request to create a new agent |
| `agent.terminate` | `agent_lifecycle` | Yes | Request to terminate an agent |
| `agent.heartbeat` | `agent_lifecycle` | No | Agent liveness ping |
| `agent.status_change` | `agent_lifecycle` | No | Agent status transition report |
| `agent.health` | `agent_lifecycle` | No | Agent health check report |
| `task.create` | `task_orchestration` | Yes | Request to create a task |
| `task.assign` | `task_orchestration` | Yes | Request to assign a task to an agent |
| `task.progress` | `task_orchestration` | No | Task progress update |
| `task.complete` | `task_orchestration` | No | Task completion report |
| `task.fail` | `task_orchestration` | No | Task failure report |
| `task.dependency_resolved` | `task_orchestration` | No | Dependency unblocked |
| `topology.init` | `topology` | Yes | Initialize topology layout |
| `topology.rebalance` | `topology` | Yes | Rebalance agent assignments |
| `topology.node_join` | `topology` | Yes | Agent joining topology |
| `topology.node_leave` | `topology` | Yes | Agent leaving topology |
| `topology.role_change` | `topology` | Yes | Agent role promotion/demotion |
| `consensus.propose` | `consensus` | Yes | Submit a consensus proposal |
| `consensus.vote` | `consensus` | No | Cast a vote |
| `consensus.commit` | `consensus` | No | Consensus achieved |
| `consensus.abort` | `consensus` | No | Consensus failed |
| `memory.store` | `memory` | Yes | Write to shared memory |
| `memory.search_result` | `memory` | No | Search results returned |
| `memory.namespace_sync` | `memory` | No | Namespace sync metadata |
| `hook.pre_edit` | `hooks` | Yes | Pre-edit file gate |
| `hook.post_edit` | `hooks` | Yes | Post-edit file confirmation |
| `hook.pre_task` | `hooks` | Yes | Pre-task execution gate |
| `hook.post_task` | `hooks` | No | Post-task completion report |
| `hook.session_event` | `hooks` | No | Session lifecycle event |

### 7.2 Engine Events (past tense, dot notation)

Used in `SwarmEngineEvent.kind` fields within the swarm-engine package. These represent **things that already happened** — emitted by the orchestrator after state transitions. Consumed by the `SwarmEngineProvider` bridge to update the SwarmBoard.

| Event `kind` | Triggered by | Board effect |
|---|---|---|
| `agent.spawned` | Agent successfully registered | New agentSession node |
| `agent.status_changed` | Agent status transition | Status dot color change |
| `agent.heartbeat` | Periodic liveness ping | Metrics update on node |
| `agent.terminated` | Agent shutdown complete | Node fades to completed |
| `task.created` | Task added to graph | New terminalTask node |
| `task.assigned` | Task assigned to agent | Spawned edge appears |
| `task.status_changed` | Task status transition | Node color change |
| `task.completed` | Task finished successfully | Green node + artifact |
| `task.failed` | Task errored | Red node |
| `topology.updated` | Topology structure changed | Full re-layout |
| `topology.rebalanced` | Agents repositioned | Animated re-layout |
| `topology.leader_elected` | Raft/consensus elected leader | Leader badge on node |
| `consensus.proposed` | Proposal submitted | Note node |
| `consensus.vote_cast` | Vote recorded | (internal) |
| `consensus.resolved` | Consensus reached | Note node updated |
| `memory.store` | Memory written | (internal) |
| `memory.search` | Search completed | (internal) |
| `hooks.triggered` | Hook fired | (internal) |
| `hooks.completed` | Hook finished | (internal) |

### 7.3 Convention Summary

- **Protocol actions** = imperative present tense (`agent.spawn`, `task.create`)
- **Engine events** = past tense (`agent.spawned`, `task.created`)
- **Existing coordination actions** use `underscore_case` (`policy_evaluated`, `member_joined`) — these are unchanged and coexist with the new dot notation layer.
- The `action` field discriminates protocol payloads; the `kind` field discriminates engine events. These never collide because they appear in different type hierarchies.

---

## 8. Envelope Event Types

Discriminated union for all event payloads transported via `SwarmEnvelope`. These extend ClawdStrike's existing envelope types (`"intel" | "signal" | "detection" | "coordination" | "status"`) with orchestration-specific channels.

### 8.1 New Channels

The swarm engine adds these channels to the existing SwarmEnvelope type system:

```typescript
/**
 * Swarm engine envelope channels.
 * New channels for the swarm engine, used alongside ClawdStrike's existing
 * SwarmChannel ("intel" | "signals" | "detections" | "coordination") and
 * SwarmEnvelope.type ("intel" | "signal" | "detection" | "coordination" | "status").
 * Note: SwarmChannel uses plural forms; SwarmEnvelope.type uses singular forms.
 */
export type SwarmEngineChannel =
  | "agent_lifecycle"
  | "task_orchestration"
  | "topology"
  | "consensus"
  | "memory"
  | "hooks";
```

### 8.2 Extended Envelope

```typescript
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
```

### 8.3 Discriminated Event Union

```typescript
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
  // Task orchestration
  | TaskCreatedEvent
  | TaskAssignedEvent
  | TaskStatusChangedEvent
  | TaskCompletedEvent
  | TaskFailedEvent
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
  | HookCompletedEvent;

// ---------------------------------------------------------------------------
// Base fields shared by all events
// ---------------------------------------------------------------------------

interface SwarmEngineEventBase {
  sourceAgentId: string | null;
  timestamp: number;
  correlationId?: string;
}

// ---------------------------------------------------------------------------
// Agent lifecycle events
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Task orchestration events
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Topology events
// ---------------------------------------------------------------------------

export interface TopologyUpdatedEvent extends SwarmEngineEventBase {
  kind: "topology.updated";
  previousType: TopologyType;
  newTopology: TopologyState;
}

export interface TopologyRebalancedEvent extends SwarmEngineEventBase {
  kind: "topology.rebalanced";
  movedAgents: Array<{ agentId: string; fromPartition: string; toPartition: string }>;
  topology: TopologyState;
}

export interface LeaderElectedEvent extends SwarmEngineEventBase {
  kind: "topology.leader_elected";
  leaderId: string;
  term: number;
  electionDurationMs: number;
}

// ---------------------------------------------------------------------------
// Consensus events
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Memory events
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Hook events
// ---------------------------------------------------------------------------

export interface HookTriggeredEvent extends SwarmEngineEventBase {
  kind: "hooks.triggered";
  hookName: string;
  hookCategory: "core" | "session" | "intelligence" | "learning" | "agent_teams";
  triggerContext: Record<string, unknown>;
}

export interface HookCompletedEvent extends SwarmEngineEventBase {
  kind: "hooks.completed";
  hookName: string;
  success: boolean;
  durationMs: number;
  result: Record<string, unknown> | null;
}
```

---

## 9. Guard Integration Types

Every agent action flows through ClawdStrike's guard system. These types define how guard results attach to the orchestration layer.

```typescript
import type { Receipt, Verdict, GuardSimResult, GuardId } from "@/lib/workbench/types";

/**
 * Result of a guard evaluation on an agent action.
 *
 * This is the bridge between ClawdStrike's policy enforcement engine
 * and the swarm orchestration layer. The orchestrator checks `allowed`
 * before permitting any agent action to proceed.
 */
export interface GuardEvaluationResult {
  /** Overall verdict. */
  verdict: Verdict;

  /** Whether the action is allowed to proceed. Derived from verdict !== "deny". */
  allowed: boolean;

  /** Individual guard results. */
  guardResults: GuardSimResult[];

  /** The signed receipt for this evaluation. */
  receipt: Receipt;

  /** Total evaluation duration in milliseconds. */
  durationMs: number;

  /** Timestamp of evaluation (Unix ms). */
  evaluatedAt: number;
}

/**
 * Guard-gated action request.
 *
 * Before an agent performs any action (file write, shell command, network
 * egress, MCP tool call), the orchestrator wraps it in a GuardedAction
 * and submits it to the guard pipeline. The pipeline returns a
 * GuardEvaluationResult.
 */
export interface GuardedAction {
  /** The agent requesting the action. */
  agentId: string;

  /** The task context for this action. */
  taskId: string | null;

  /** Action type matching ClawdStrike's TestActionType. */
  actionType:
    | "file_access"
    | "file_write"
    | "network_egress"
    | "shell_command"
    | "mcp_tool_call"
    | "patch_apply"
    | "user_input";

  /** Target of the action (file path, URL, command, etc.). */
  target: string;

  /** Additional context for guard evaluation. */
  context: Record<string, unknown>;

  /** Timestamp of the request (Unix ms). */
  requestedAt: number;
}

/**
 * A completed guarded action with its evaluation result attached.
 *
 * This is the audit record: what was requested, what the guards decided,
 * and the cryptographic receipt proving the decision.
 */
export interface GuardedActionRecord {
  /** The original action request. */
  action: GuardedAction;

  /** The guard evaluation result. */
  evaluation: GuardEvaluationResult;

  /** Whether the action was actually executed (may be false even if allowed). */
  executed: boolean;

  /** If the action produced an error after being allowed. */
  executionError: string | null;
}
```

---

## 10. Swarm Engine State

Top-level state type for the swarm engine instance, combining all the above.

```typescript
/**
 * Swarm engine status — from ruflo's SwarmStatus.
 */
export type SwarmEngineStatus =
  | "initializing"
  | "running"
  | "paused"
  | "recovering"
  | "shutting_down"
  | "stopped"
  | "failed";

/**
 * Swarm engine metrics — from ruflo's CoordinatorMetrics.
 */
export interface SwarmEngineMetrics {
  uptimeMs: number;
  activeAgents: number;
  totalTasks: number;
  completedTasks: number;
  failedTasks: number;
  avgTaskDurationMs: number;
  messagesPerSecond: number;
  consensusSuccessRate: number;
  coordinationLatencyMs: number;
  memoryUsageBytes: number;
  guardEvaluationsTotal: number;
  guardDenialRate: number;
}

/**
 * Complete swarm engine state.
 *
 * This is the serializable root object persisted to disk and transported
 * over SwarmEnvelope for state sync. All collections are arrays or Records
 * (not Maps) for JSON compatibility.
 */
export interface SwarmEngineState {
  /** Swarm engine instance ID. Format: `swe_{ulid}`. */
  id: string;

  /** Namespace for scoping (matches ruflo's SwarmId.namespace). */
  namespace: string;

  /** Version string. */
  version: string;

  /** Current engine status. */
  status: SwarmEngineStatus;

  /** Topology configuration. */
  topologyConfig: TopologyConfig;

  /** Current topology state. */
  topology: TopologyState;

  /** Consensus configuration. */
  consensusConfig: ConsensusConfig;

  /** All agent sessions, keyed by agent ID. */
  agents: Record<string, AgentSession>;

  /** All tasks, keyed by task ID. */
  tasks: Record<string, Task>;

  /** Active consensus proposals, keyed by proposal ID. */
  activeProposals: Record<string, ConsensusProposal>;

  /** Engine-level metrics. */
  metrics: SwarmEngineMetrics;

  /** Guarded action audit log (most recent N entries). */
  recentGuardActions: GuardedActionRecord[];

  /** Maximum guarded actions to retain in the audit log. */
  maxGuardActionHistory: number;

  // -- Timestamps (Unix ms) --

  createdAt: number;
  startedAt: number | null;
  updatedAt: number;
}
```

---

## 11. Message Bus Types

Internal message bus for agent-to-agent communication within a swarm engine instance. Adapted from ruflo, made serializable.

```typescript
export type InternalMessagePriority = "urgent" | "high" | "normal" | "low";

export type InternalMessageType =
  | "task_assign"
  | "task_complete"
  | "task_fail"
  | "heartbeat"
  | "status_update"
  | "consensus_propose"
  | "consensus_vote"
  | "consensus_commit"
  | "topology_update"
  | "agent_join"
  | "agent_leave"
  | "broadcast"
  | "direct";

/**
 * Internal message between agents.
 * Format: `msg_{ulid}`.
 */
export interface InternalMessage {
  id: string;
  type: InternalMessageType;
  from: string;
  to: string | "broadcast";
  payload: Record<string, unknown>;
  timestamp: number;
  priority: InternalMessagePriority;
  requiresAck: boolean;
  ttlMs: number;
  correlationId?: string;
}

export interface InternalMessageAck {
  messageId: string;
  from: string;
  received: boolean;
  processedAt: number;
  error?: string;
}
```

---

## 12. Type Guards

```typescript
export function isAgentSession(value: unknown): value is AgentSession {
  return (
    typeof value === "object" &&
    value !== null &&
    "id" in value &&
    typeof (value as AgentSession).id === "string" &&
    (value as AgentSession).id.startsWith("agt_") &&
    "role" in value &&
    "status" in value &&
    "capabilities" in value
  );
}

export function isTask(value: unknown): value is Task {
  return (
    typeof value === "object" &&
    value !== null &&
    "id" in value &&
    typeof (value as Task).id === "string" &&
    (value as Task).id.startsWith("tsk_") &&
    "type" in value &&
    "status" in value
  );
}

export function isSwarmEngineEvent(value: unknown): value is SwarmEngineEvent {
  return (
    typeof value === "object" &&
    value !== null &&
    "kind" in value &&
    typeof (value as SwarmEngineEvent).kind === "string" &&
    "timestamp" in value
  );
}

export function isSwarmEngineEnvelope(value: unknown): value is SwarmEngineEnvelope {
  return (
    typeof value === "object" &&
    value !== null &&
    "version" in value &&
    (value as SwarmEngineEnvelope).version === 1 &&
    "type" in value &&
    "payload" in value &&
    "ttl" in value &&
    "created" in value
  );
}
```

---

## 13. Constants

```typescript
export const SWARM_ENGINE_CONSTANTS = {
  /** Internal heartbeat interval for agent liveness checks (orchestrator loop). */
  DEFAULT_HEARTBEAT_INTERVAL_MS: 5_000,
  /** Protocol-level heartbeat envelope interval (local swarms). Networked: 30_000. */
  PROTOCOL_HEARTBEAT_INTERVAL_MS: 10_000,
  /** Health check interval for degraded agent detection. */
  DEFAULT_HEALTH_CHECK_INTERVAL_MS: 10_000,
  /** Default task timeout. */
  DEFAULT_TASK_TIMEOUT_MS: 300_000,
  /** Default consensus timeout. */
  DEFAULT_CONSENSUS_TIMEOUT_MS: 30_000,
  /** Default internal message TTL. */
  DEFAULT_MESSAGE_TTL_MS: 60_000,
  /** Max agents per swarm engine instance. */
  DEFAULT_MAX_AGENTS: 100,
  /** Max tasks per swarm engine instance. */
  DEFAULT_MAX_TASKS: 1_000,
  /** Consensus approval threshold. */
  DEFAULT_CONSENSUS_THRESHOLD: 0.66,
  /** Internal message queue max depth. */
  MAX_QUEUE_SIZE: 10_000,
  /** Max retries for failed tasks. */
  MAX_RETRIES: 3,
  /** Coordination latency target. */
  COORDINATION_LATENCY_TARGET_MS: 100,
  /** Internal message throughput target. */
  MESSAGES_PER_SECOND_TARGET: 1_000,
  /** Max guard action records retained in state. */
  MAX_GUARD_ACTION_HISTORY: 500,
  /** Health score threshold below which failover triggers. */
  HEALTH_FAILOVER_THRESHOLD: 0.3,
} as const;
```

---

## 14. Type Mapping Table

How each ruflo type maps to its ClawdStrike equivalent and the resolution in the unified system.

| Ruflo Type | ClawdStrike Equivalent | Unified Type | Resolution |
|---|---|---|---|
| `AgentStatus` | `SessionStatus` | `AgentSessionStatus` | Curated merge (not a strict superset). ClawdStrike's `"evaluating"` kept; ruflo's `"initializing"`, `"paused"`, `"terminating"`, `"terminated"`, `"offline"` added. Ruflo's `"busy"` maps to `"running"`, `"error"` maps to `"failed"`. |
| `AgentType` | No direct equivalent (sentinel modes: `SentinelMode`) | `AgentRole` | Renamed to `AgentRole`. Ruflo's full list kept; `"sentinel"` added to bridge ClawdStrike sentinels. |
| `AgentState` | `SwarmBoardNodeData` (nodeType: "agentSession") | `AgentSession` | Merged. Orchestration fields from ruflo, rendering fields from ClawdStrike. `receipt` field added. |
| `AgentCapabilities` | No equivalent | `AgentCapabilities` | Kept from ruflo. Added `securityAnalysis`. Removed `reliability`/`speed`/`quality` (moved to `AgentQualityScores`). |
| `AgentMetrics` | `SentinelStats` | `AgentMetrics` | Ruflo's structure kept (operational metrics). `SentinelStats` remains separate for sentinel-specific counters. `Date` fields replaced with `number` (Unix ms). |
| `AgentId` (compound object) | Prefixed string (`sen_{ulid}`) | `string` (`agt_{ulid}`) | ClawdStrike convention wins. Flat prefixed ULID string, not compound object. Swarm association tracked on `AgentSession` directly. |
| `TaskDefinition` | `SwarmBoardNodeData` (nodeType: "terminalTask") | `Task` | Merged. Ruflo's scheduling fields (priority, dependencies, timeout, retries) combined with ClawdStrike board fields (taskPrompt, huntId, artifactIds). `receipt` added. |
| `TaskId` (compound object) | No equivalent | `string` (`tsk_{ulid}`) | Flat prefixed ULID. Sequence number moved to `Task.sequence`. |
| `TaskStatus` | No direct equivalent | `TaskStatus` | Kept from ruflo unchanged. |
| `TaskPriority` | No equivalent | `TaskPriority` | Kept from ruflo unchanged. |
| `TaskType` | No equivalent | `TaskType` | Extended with ClawdStrike-specific types: `"detection"`, `"hunt"`, `"guard_evaluation"`. |
| `TopologyType` | No equivalent | `TopologyType` | Ruflo's list kept; `"adaptive"` added from ClawdStrike hive-mind concept. |
| `TopologyConfig` | No equivalent | `TopologyConfig` | Kept from ruflo. Optional fields made required with sensible defaults. |
| `TopologyNode` | React Flow `Node` | `TopologyNode` | Ruflo base kept. `positionX`/`positionY`/`hierarchyDepth` added for React Flow layout. |
| `TopologyEdge` | `SwarmBoardEdge` | `TopologyEdge` | Ruflo base kept. `edgeType` added mapping to `SwarmBoardEdge.type`. |
| `TopologyState` | No equivalent | `TopologyState` | Ruflo kept. `leader` renamed to `leaderId` for consistency. `snapshotAt` added. |
| `ConsensusAlgorithm` | No equivalent | `ConsensusAlgorithm` | Kept from ruflo unchanged. |
| `ConsensusConfig` | No equivalent | `ConsensusConfig` | Kept from ruflo unchanged. |
| `ConsensusProposal` | No equivalent | `ConsensusProposal` | Ruflo base adapted. `Map<string, ConsensusVote>` changed to `ConsensusVote[]` for serializability. `Date` to `number`. |
| `ConsensusVote` | No equivalent | `ConsensusVote` | Kept from ruflo. `Date` to `number`. |
| `ConsensusResult` | No equivalent | `ConsensusResult` | Kept from ruflo. `receipt` added. `Date` to `number`. `unknown` to `Record<string, unknown>`. |
| `MessageType` | `SwarmEnvelope.type` | `InternalMessageType` + `SwarmEngineEnvelope.type` | Split. Internal agent messages use `InternalMessageType` (ruflo). Cross-swarm transport uses `SwarmEngineEnvelope.type` (extends ClawdStrike `SwarmEnvelope`). |
| `Message` | `SwarmEnvelope` | `InternalMessage` + `SwarmEngineEnvelope` | Split. Ruflo's `Message` becomes `InternalMessage` (intra-engine). ClawdStrike's `SwarmEnvelope` extended to `SwarmEngineEnvelope` (inter-engine). |
| `SwarmEventType` | No equivalent (events implicit in SwarmEnvelope routing) | `SwarmEngineEvent.kind` | Ruflo's string union replaced with discriminated union. Each event type is a separate interface with a `kind` discriminator. |
| `SwarmEvent` | No equivalent | `SwarmEngineEvent` (union) | Ruflo's generic `data: Record<string, unknown>` replaced with typed discriminated union per event category. |
| `CoordinatorConfig` | No equivalent | Fields distributed across `TopologyConfig` + `ConsensusConfig` + `SwarmEngineState` | Flattened. No single config object; configuration is composed from subsystem configs. |
| `CoordinatorState` | No equivalent | `SwarmEngineState` | Ruflo base adapted. `Map<string, T>` changed to `Record<string, T>`. `Date` to `number`. Guard audit log added. |
| `CoordinatorMetrics` | No equivalent | `SwarmEngineMetrics` | Extended with `guardEvaluationsTotal` and `guardDenialRate`. |
| `SwarmStatus` | No equivalent | `SwarmEngineStatus` | Kept from ruflo unchanged. |
| `SwarmId` (compound object) | No equivalent | Fields on `SwarmEngineState` | Dissolved. `id`, `namespace`, `version`, `createdAt` are top-level fields on `SwarmEngineState`. |
| `AgentPoolConfig` | No equivalent | Not included in v1 | Deferred. Agent pooling is an optimization to add after the core engine stabilizes. |
| No equivalent | `Receipt` | `Receipt` (re-exported from types.ts) | ClawdStrike's `Receipt` used as-is. Referenced by `AgentSession.receipt`, `Task.receipt`, `ConsensusResult.receipt`, `GuardEvaluationResult.receipt`. |
| No equivalent | `GuardSimResult` | `GuardSimResult` (re-exported from types.ts) | ClawdStrike's type used as-is. |
| No equivalent | `SwarmBoardNodeData` | Computed via `agentSessionToBoardData()` | Board data is derived from `AgentSession`, not stored separately. |
| No equivalent | `SwarmBoardEdge` | Computed via `topologyToReactFlow()` | Board edges derived from `TopologyEdge`. |
| No equivalent | `SwarmBoardState` | Computed at render time | Board state is a projection of `SwarmEngineState` through conversion functions. Not persisted. |
| No equivalent | `RiskLevel` | `RiskLevel` | ClawdStrike's type used as-is. |

---

## 15. Design Decisions

### ADR-001: Flat ULID strings instead of compound ID objects

**Context:** Ruflo uses compound ID objects (`AgentId`, `TaskId`, `SwarmId`) with nested fields. ClawdStrike uses flat prefixed ULID strings.

**Decision:** Use flat prefixed ULID strings.

**Rationale:** (1) ClawdStrike convention is the foundation. (2) Flat strings are trivially serializable. (3) Foreign key references become simple string comparisons. (4) The `generateId()` function from sentinel-types.ts already implements this pattern.

### ADR-002: Record instead of Map for collections

**Context:** Ruflo uses `Map<string, T>` for agent and task collections. Maps are not JSON-serializable.

**Decision:** Use `Record<string, T>` for all collections in serializable state types.

**Rationale:** SwarmEnvelope transport requires JSON serializability. `Record<string, T>` serializes natively. Runtime implementations may use `Map` internally but must serialize to `Record` at the boundary.

### ADR-003: Unix milliseconds instead of Date objects

**Context:** Ruflo uses `Date` objects for timestamps. `Date` objects serialize to ISO strings via `JSON.stringify()` but lose type information on deserialization.

**Decision:** Use `number` (Unix milliseconds) for all timestamp fields.

**Rationale:** ClawdStrike already uses Unix ms throughout sentinel-types.ts. Numbers round-trip through JSON without loss. Arithmetic (duration computation, TTL expiry) is simpler with numbers.

### ADR-004: Discriminated unions with `kind` field

**Context:** ClawdStrike's signal data uses `kind` as the discriminator (e.g., `SignalData`). Ruflo's events use dotted string types.

**Decision:** Use `kind` as the discriminator field name for all union types. Use dotted strings (e.g., `"agent.spawned"`) as discriminator values for events to maintain hierarchical grouping.

**Rationale:** `kind` is established in ClawdStrike's codebase. Dotted event names enable prefix-based filtering (e.g., `event.kind.startsWith("agent.")`).

### ADR-005: Receipt on every action type

**Context:** ClawdStrike's guard system produces receipts for every policy evaluation. Ruflo has no concept of guard receipts.

**Decision:** Add `receipt: Receipt | null` to `AgentSession`, `Task`, `ConsensusResult`, and all action-bearing event types.

**Rationale:** The receipt is the cryptographic proof that a guard evaluation occurred. Without it, there is no audit trail. The `null` case covers states where no evaluation has occurred yet.

### ADR-006: Board data is computed, not stored

**Context:** ClawdStrike's `SwarmBoardNodeData` is a UI rendering type. Ruflo's `AgentState` is an orchestration type.

**Decision:** `SwarmBoardNodeData` and `SwarmBoardEdge` are computed from `AgentSession` and `TopologyEdge` via pure conversion functions. They are never stored in the engine state.

**Rationale:** Single source of truth. The engine state (`SwarmEngineState`) is the canonical representation. Board data is a lossy projection that exists only at render time. This prevents stale UI state from diverging from engine state.
