# ClawdStrike Swarm Engine -- Protocol Specification

> **Version**: 2.0-draft
> **Date**: 2026-03-24
> **Status**: Proposal
> **Authors**: Swarm Engine Team
> **Supersedes**: SwarmEnvelope v1 (swarm-coordinator.ts, envelope version 1)
>
> **Canonical type source**: [TYPE-SYSTEM.md](./TYPE-SYSTEM.md) is the single
> authority for all shared types (`AgentRole`, `AgentSessionStatus`, `TaskStatus`,
> `TaskPriority`, `TopologyType`, `ConsensusAlgorithm`, ID prefixes, etc.).
> This document references those types but does not redefine them. Where this
> document previously contained inline type definitions that overlap with
> TYPE-SYSTEM.md, the TYPE-SYSTEM.md definitions take precedence.

## 1. Introduction

The ClawdStrike Swarm Engine Protocol extends the existing `SwarmEnvelope` transport
with six new channel types that absorb AI agent orchestration capabilities from
ruflo/claude-flow. The key architectural insight: **every agent action is a
SwarmEnvelope that passes through ClawdStrike's guard pipeline before execution,
and the guard receipt is attached to the envelope before it is forwarded.**

This means orchestration and security enforcement share a single wire format, a
single transport abstraction, and a single audit trail. There is no "orchestration
bus" separate from the "security bus" -- they are the same bus.

### 1.1 Design Goals

1. **Unified wire format** -- All orchestration messages use `SwarmEnvelope`.
2. **Guard-first execution** -- Every mutable action envelope is evaluated by the
   guard pipeline. The receipt is attached before forwarding.
3. **Transport-agnostic** -- New channels work identically over `InProcessEventBus`,
   Gossipsub (Speakeasy), and `TauriIpcTransport`.
4. **Backward compatible** -- Existing channels (`intel`, `signals`, `detections`,
   `coordination`, `status`) are unchanged. Existing consumers see no breaking changes.
5. **Typed payloads** -- Every channel defines a discriminated union of message types
   so that consumers can exhaustively match on `payload.action`.

### 1.2 Terminology

| Term | Definition |
|------|------------|
| **Envelope** | A `SwarmEnvelope` -- the unit of transport across all channels. |
| **Channel** | A logical message category. Maps to a Gossipsub topic suffix. |
| **Guard pipeline** | The ordered chain of ClawdStrike guards that evaluate an action. |
| **Receipt** | A signed `Receipt` proving the guard pipeline evaluated an action. |
| **Sentinel** | A persistent autonomous defender (existing ClawdStrike concept). |
| **Agent** | A spawned AI worker within a swarm (new orchestration concept). |
| **Swarm** | A coordination layer grouping agents/sentinels under a shared policy. |

---

## 2. Existing Protocol (Reference)

The following types are defined in `features/swarm/swarm-coordinator.ts` and
`features/swarm/swarm-board-types.ts` (re-exported via `lib/workbench/` barrel shims). They are **not modified** by this specification.

### 2.1 SwarmEnvelope

```typescript
interface SwarmEnvelope {
  /** Protocol version. Always 1 for existing channels. */
  version: 1;
  /** Envelope type for routing. */
  type: "intel" | "signal" | "detection" | "coordination" | "status";
  /** Signed message payload. Opaque to the transport layer. */
  payload: unknown;
  /** TTL in Gossipsub hops. */
  ttl: number;
  /** Timestamp when envelope was created (Unix ms). */
  created: number;
}
```

### 2.2 TransportAdapter

```typescript
interface TransportAdapter {
  subscribe(topic: string): void;
  unsubscribe(topic: string): void;
  publish(topic: string, envelope: SwarmEnvelope): Promise<void>;
  onMessage(handler: (topic: string, envelope: SwarmEnvelope) => void): void;
  offMessage(handler: (topic: string, envelope: SwarmEnvelope) => void): void;
  isConnected(): boolean;
}
```

Implementations:
- **`InProcessEventBus`** -- Uses `EventTarget` for same-process delivery. Always
  connected. Used by personal swarms.
- **Speakeasy Gossipsub adapter** -- Wraps `@backbay/speakeasy` libp2p transport for
  networked swarms. Supports offline queuing via `MessageOutbox`.

### 2.3 Existing Channels

| Channel | Topic suffix | Envelope type | TTL | Payload |
|---------|-------------|---------------|-----|---------|
| Intel | `/intel` | `"intel"` | 10 | `Intel` (sentinel-types.ts) |
| Signals | `/signals` | `"signal"` | 3 | `Signal` (sentinel-types.ts) |
| Detections | `/detections` | `"detection"` | 10 | `DetectionMessage` |
| Coordination | `/coordination` | `"coordination"` | 5 | Polymorphic (`action` field) |
| Status | per-sentinel (`/sentinel/{id}/status`) | `"status"` | -- | Heartbeat/status. **Note**: `"status"` is a valid `SwarmEnvelope.type` but is NOT a member of the `SwarmChannel` union (`"intel" | "signals" | "detections" | "coordination"`). It uses per-sentinel topics, not per-swarm topics, and is not routed through `routeMessage()`. |

### 2.4 Existing Receipt Type

```typescript
// From lib/workbench/types.ts
type Verdict = "allow" | "deny" | "warn";

interface Receipt {
  id: string;
  timestamp: string;
  verdict: Verdict;
  guard: string;
  policyName: string;
  action: { type: TestActionType; target: string };
  evidence: Record<string, unknown>;
  signature: string;    // Hex-encoded Ed25519 signature
  publicKey: string;    // Hex-encoded Ed25519 public key
  valid: boolean;
  keyType?: "persistent" | "ephemeral";
  imported?: boolean;
}

type TestActionType =
  | "file_access"
  | "file_write"
  | "network_egress"
  | "shell_command"
  | "mcp_tool_call"
  | "patch_apply"
  | "user_input";
```

### 2.5 Topic Naming

All topics follow the pattern established by `@backbay/speakeasy`:

```
/baychat/v1/swarm/{swarmId}/{channel}
/baychat/v1/sentinel/{sentinelId}/status
```

The `TOPIC_PREFIX` constant is `/baychat/v1`.

---

## 3. Protocol Extension: SwarmEnvelope v2

### 3.1 Extended Envelope Type

The `SwarmEnvelope.type` field is extended with new channel discriminators.
Existing values are preserved. The version field remains `1` -- the envelope
wire format is unchanged, only the type union grows.

```typescript
interface SwarmEnvelope {
  version: 1;
  type:
    // Existing channels (unchanged)
    | "intel"
    | "signal"
    | "detection"
    | "coordination"
    | "status"
    // New orchestration channels
    | "agent_lifecycle"
    | "task_orchestration"
    | "topology"
    | "consensus"
    | "memory"
    | "hooks";
  payload: unknown;
  ttl: number;
  created: number;
}
```

### 3.2 Extended SwarmChannel Type

```typescript
type SwarmChannel =
  // Existing
  | "intel"
  | "signals"
  | "detections"
  | "coordination"
  // New
  | "agents"
  | "tasks"
  | "topology"
  | "consensus"
  | "memory"
  | "hooks";
```

### 3.3 New Topic Map

| Channel | Topic | Envelope `type` | Default TTL |
|---------|-------|-----------------|-------------|
| Agent lifecycle | `/baychat/v1/swarm/{id}/agents` | `"agent_lifecycle"` | 5 |
| Task orchestration | `/baychat/v1/swarm/{id}/tasks` | `"task_orchestration"` | 5 |
| Topology | `/baychat/v1/swarm/{id}/topology` | `"topology"` | 5 |
| Consensus | `/baychat/v1/swarm/{id}/consensus` | `"consensus"` | 3 |
| Memory | `/baychat/v1/swarm/{id}/memory` | `"memory"` | 5 |
| Hooks | `/baychat/v1/swarm/{id}/hooks` | `"hooks"` | 3 |

Topic builder functions:

```typescript
function swarmAgentsTopic(swarmId: string): string {
  return `${TOPIC_PREFIX}/swarm/${swarmId}/agents`;
}
function swarmTasksTopic(swarmId: string): string {
  return `${TOPIC_PREFIX}/swarm/${swarmId}/tasks`;
}
function swarmTopologyTopic(swarmId: string): string {
  return `${TOPIC_PREFIX}/swarm/${swarmId}/topology`;
}
function swarmConsensusTopic(swarmId: string): string {
  return `${TOPIC_PREFIX}/swarm/${swarmId}/consensus`;
}
function swarmMemoryTopic(swarmId: string): string {
  return `${TOPIC_PREFIX}/swarm/${swarmId}/memory`;
}
function swarmHooksTopic(swarmId: string): string {
  return `${TOPIC_PREFIX}/swarm/${swarmId}/hooks`;
}
```

---

## 4. Guarded Envelope Pattern

This is the core innovation. Every envelope on the new orchestration channels
carries an optional `receipt` field attached by the guard pipeline. The receipt
proves that the action described in the payload was evaluated against the active
policy before the envelope was forwarded to subscribers.

### 4.1 GuardedPayload Base

All payloads on orchestration channels extend this base:

```typescript
/**
 * Base for all orchestration payloads. The `action` field is the discriminant.
 * The `receipt` field is attached by the guard pipeline after evaluation.
 * If `receipt` is absent, the envelope has not yet been evaluated.
 */
interface GuardedPayload {
  /** Discriminated action type. Used for routing and guard mapping. */
  action: string;
  /** Guard pipeline receipt. Attached after evaluation. Absent = unevaluated. */
  receipt?: EnvelopeReceipt;
  /** Fingerprint of the agent/sentinel that originated this envelope. */
  sender: string;
  /** Correlation ID for tracing a chain of related envelopes. */
  correlationId?: string;
}
```

### 4.2 EnvelopeReceipt

The receipt is a compact projection of the full `Receipt` type, optimized for
inline transport. The full `Receipt` (with evidence and signature bytes) is
stored in the local receipt ledger and can be retrieved by `receiptId`.

```typescript
interface EnvelopeReceipt {
  /** Receipt ID for ledger lookup. */
  receiptId: string;
  /** Final verdict from the guard pipeline. */
  verdict: Verdict;                          // "allow" | "deny" | "warn"
  /** Which guard produced the verdict (empty string if no guard matched). */
  decidingGuard: string;
  /** SHA-256 of the policy that was evaluated. */
  policyHash: string;
  /** Evaluation duration in milliseconds. */
  evaluationMs: number;
  /** Ed25519 signature over (receiptId + verdict + policyHash). Hex-encoded. */
  signature: string;
  /** Signer public key. Hex-encoded. */
  publicKey: string;
  /** Timestamp of evaluation (Unix ms). */
  evaluatedAt: number;
}
```

### 4.3 Guard Integration Flow

```
                         Orchestration Channel
                         =====================

  Agent/Coordinator                Guard Pipeline               Subscribers
  ─────────────────               ──────────────               ───────────
         │                              │                            │
         │  1. Create envelope          │                            │
         │  (receipt = undefined)       │                            │
         │─────────────────────────────>│                            │
         │                              │                            │
         │                  2. Extract action from                   │
         │                     payload, map to                      │
         │                     TestActionType                       │
         │                              │                            │
         │                  3. Evaluate all guards                   │
         │                     in pipeline order                    │
         │                              │                            │
         │                  4. Produce Receipt,                     │
         │                     store in ledger                      │
         │                              │                            │
         │                  5. Attach EnvelopeReceipt               │
         │                     to payload.receipt                   │
         │                              │                            │
         │                  ┌───────────┴───────────┐               │
         │                  │                       │               │
         │            verdict = allow          verdict = deny        │
         │                  │                       │               │
         │                  │  6a. Forward          │  6b. Log      │
         │                  │  to transport         │  to audit     │
         │                  │                       │  trail.       │
         │                  │                       │  DO NOT       │
         │                  │                       │  forward.     │
         │                  │                       │               │
         │                  │──────────────────────>│               │
         │                  │                       │               │
         │                  │                 7. Emit denied        │
         │                  │                    event to           │
         │                  │                    coordination       │
         │                  │                    channel for        │
         │                  │                    observability.     │
         │                  │                                       │
         │                  │                                       │
         │                  └───────────────────────────────────────>│
         │                                                          │
         │                  8. Subscriber receives                  │
         │                     envelope with receipt                │
         │                     attached. Can verify                 │
         │                     signature locally.                   │
```

### 4.4 Action-to-Guard Mapping

Each orchestration action maps to a `TestActionType` for guard evaluation:

| Envelope action | TestActionType | Rationale |
|----------------|----------------|-----------|
| `agent.spawn` | `mcp_tool_call` | Spawning an agent is a tool invocation |
| `agent.terminate` | `mcp_tool_call` | Terminating an agent is a tool invocation |
| `task.create` | `mcp_tool_call` | Task creation drives agent execution |
| `task.assign` | `mcp_tool_call` | Assigning work to an agent |
| `memory.store` | `file_write` | Writing to shared memory is a write operation |
| `hook.pre_edit` | `file_access` | Pre-edit hooks observe file state |
| `hook.post_edit` | `file_write` | Post-edit hooks confirm file mutations |
| `topology.init` | `mcp_tool_call` | Topology changes affect agent capabilities |
| `topology.rebalance` | `mcp_tool_call` | Rebalancing changes agent assignments |
| `topology.node_join` | `mcp_tool_call` | Adding a node changes swarm capabilities |
| `topology.node_leave` | `mcp_tool_call` | Removing a node affects availability |
| `topology.role_change` | `mcp_tool_call` | Role changes affect agent permissions |
| `consensus.propose` | `mcp_tool_call` | Proposals may trigger state changes |
| `hook.pre_task` | `mcp_tool_call` | Pre-task hooks may gate task execution |

Read-only actions (`agent.heartbeat`, `agent.health`, `task.progress`,
`memory.search_result`, `consensus.vote`, `agent.status_change`) are
**guard-exempt** -- they carry no receipt and are forwarded immediately.
The `guardExempt` flag in the payload schema indicates this.

### 4.5 Denied Envelope Handling

When the guard pipeline returns `verdict: "deny"`:

1. The envelope is **not** forwarded to the channel topic.
2. The full `Receipt` is stored in the local receipt ledger.
3. A **deny notification** is published to the `coordination` channel:

```typescript
interface DenyNotification {
  action: "envelope_denied";
  originalChannel: SwarmChannel;
  originalAction: string;
  receiptId: string;
  verdict: "deny";
  decidingGuard: string;
  sender: string;
  timestamp: number;
}
```

4. The originating agent receives the deny via its coordination subscription
   and can react (retry with different parameters, escalate, or abort).

---

## 5. Channel Payload Specifications

All payloads extend `GuardedPayload` (section 4.1). The `action` field is the
discriminant for each channel's union type.

### 5.1 `agent_lifecycle` Channel

Topic: `/baychat/v1/swarm/{swarmId}/agents`

```typescript
// --- Discriminated union for agent_lifecycle payloads ---

type AgentLifecyclePayload =
  | AgentSpawnPayload
  | AgentHeartbeatPayload
  | AgentStatusChangePayload
  | AgentTerminatePayload
  | AgentHealthPayload;

// AgentRole — see TYPE-SYSTEM.md section 3.1 (canonical definition)
// AgentSessionStatus — see TYPE-SYSTEM.md section 3.1 (canonical definition)
// On the wire, payloads use the full AgentSessionStatus, not the narrower SessionStatus.

/** Model tier for 3-tier routing (from ruflo ADR-026). */
type ModelTier = "booster" | "haiku" | "sonnet" | "opus";

interface AgentSpawnPayload extends GuardedPayload {
  action: "agent.spawn";
  /** Unique agent ID. Format: agt_{ulid}. */
  agentId: string;
  /** Agent role within the swarm. */
  role: AgentRole;
  /** Capabilities this agent is authorized to use. */
  capabilities: string[];
  /** Model tier for LLM routing. */
  modelTier: ModelTier;
  /** Policy mode the agent runs under (e.g., "strict", "ai-agent"). */
  policyMode: string;
  /** Maximum concurrent tasks this agent can handle. */
  maxConcurrency: number;
  /** Parent agent ID, if spawned by another agent. Null for root agents. */
  parentAgentId: string | null;
}

interface AgentHeartbeatPayload extends GuardedPayload {
  action: "agent.heartbeat";
  agentId: string;
  /** Current status. */
  status: AgentStatus;
  /** Number of active tasks. */
  activeTaskCount: number;
  /** Current task ID, if any. */
  currentTaskId: string | null;
  /** CPU/memory/token usage snapshot. */
  workload: {
    cpuPercent: number;
    memoryMb: number;
    tokensConsumedTotal: number;
    tokensConsumedLastMinute: number;
  };
  /** Guard-exempt: heartbeats are read-only and never denied. */
  guardExempt: true;
}

interface AgentStatusChangePayload extends GuardedPayload {
  action: "agent.status_change";
  agentId: string;
  previousStatus: AgentStatus;
  newStatus: AgentStatus;
  /** Reason for the transition. */
  reason: string;
  /** Task ID that triggered the transition, if any. */
  triggerTaskId?: string;
  /** Guard-exempt: status reports are observational. */
  guardExempt: true;
}

interface AgentTerminatePayload extends GuardedPayload {
  action: "agent.terminate";
  agentId: string;
  /** Why the agent is being terminated. */
  reason: "completed" | "error" | "timeout" | "user_request" | "policy_violation" | "rebalance";
  /** Process exit code, if applicable. */
  exitCode: number | null;
  /** Final metrics snapshot. */
  finalMetrics: {
    tasksCompleted: number;
    tasksFailed: number;
    totalTokensConsumed: number;
    uptimeMs: number;
  };
}

interface AgentHealthPayload extends GuardedPayload {
  action: "agent.health";
  agentId: string;
  /** Overall health assessment. */
  health: "healthy" | "degraded" | "unhealthy";
  /** Individual check results. */
  checks: Array<{
    name: string;
    status: "pass" | "fail" | "warn";
    message?: string;
    durationMs: number;
  }>;
  /** Receipts generated in the last reporting interval. */
  recentReceiptCount: number;
  /** Denied actions in the last reporting interval. */
  recentDenyCount: number;
  /** Guard-exempt: health reports are read-only. */
  guardExempt: true;
}
```

### 5.2 `task_orchestration` Channel

Topic: `/baychat/v1/swarm/{swarmId}/tasks`

```typescript
type TaskOrchestrationPayload =
  | TaskCreatePayload
  | TaskAssignPayload
  | TaskProgressPayload
  | TaskCompletePayload
  | TaskFailPayload
  | TaskDependencyResolvedPayload;

// TaskPriority — see TYPE-SYSTEM.md section 4.1 (canonical definition)
// TaskStatus — see TYPE-SYSTEM.md section 4.1 (canonical definition)

interface TaskCreatePayload extends GuardedPayload {
  action: "task.create";
  /** Unique task ID. Format: tsk_{ulid}. */
  taskId: string;
  /** Human-readable task description / prompt. */
  prompt: string;
  /** Task IDs that must complete before this task can start. */
  dependencies: string[];
  /** Execution priority. */
  priority: TaskPriority;
  /** Agent ID to assign to, or null for auto-assignment. */
  assignedAgentId: string | null;
  /** Maximum execution time in milliseconds. Null = no limit. */
  timeoutMs: number | null;
  /** Tags for categorization and routing. */
  tags: string[];
  /** Parent task ID for sub-task hierarchies. */
  parentTaskId?: string;
}

interface TaskAssignPayload extends GuardedPayload {
  action: "task.assign";
  taskId: string;
  /** Agent receiving the assignment. */
  agentId: string;
  /** Previous assignee, if reassignment. */
  previousAgentId?: string;
  /** Reason for assignment or reassignment. */
  reason: string;
}

interface TaskProgressPayload extends GuardedPayload {
  action: "task.progress";
  taskId: string;
  agentId: string;
  /** Completion percentage (0-100). */
  percent: number;
  /** Description of the current step. */
  currentStep: string;
  /** Structured step metadata, if available. */
  stepIndex?: number;
  totalSteps?: number;
  /** Guard-exempt: progress reports are observational. */
  guardExempt: true;
}

interface TaskCompletePayload extends GuardedPayload {
  action: "task.complete";
  taskId: string;
  agentId: string;
  /** Result summary. */
  result: string;
  /** Artifact IDs produced by this task (files, diffs, receipts). */
  artifacts: string[];
  /** Total tokens consumed for this task. */
  tokensConsumed: number;
  /** Wall-clock execution time in milliseconds. */
  durationMs: number;
  /** Guard-exempt: completion reports are observational. */
  guardExempt: true;
}

interface TaskFailPayload extends GuardedPayload {
  action: "task.fail";
  taskId: string;
  agentId: string;
  /** Error message. */
  error: string;
  /** Error category for automated retry decisions. */
  errorCategory: "guard_denied" | "timeout" | "runtime_error" | "dependency_failed" | "cancelled";
  /** Number of retry attempts so far. */
  retryCount: number;
  /** Whether the task is eligible for retry. */
  retriable: boolean;
  /** Guard-exempt: failure reports are observational. */
  guardExempt: true;
}

interface TaskDependencyResolvedPayload extends GuardedPayload {
  action: "task.dependency_resolved";
  /** The dependency task that just completed. */
  resolvedTaskId: string;
  /** Tasks that are now unblocked. */
  unblockedTaskIds: string[];
  /** Guard-exempt: dependency resolution is observational. */
  guardExempt: true;
}
```

### 5.3 `topology` Channel

Topic: `/baychat/v1/swarm/{swarmId}/topology`

```typescript
type TopologyPayload =
  | TopologyInitPayload
  | TopologyRebalancePayload
  | TopologyNodeJoinPayload
  | TopologyNodeLeavePayload
  | TopologyNodeRoleChangePayload;

// TopologyType — see TYPE-SYSTEM.md section 5 (canonical definition, includes "adaptive")
// TopologyNodeRole — see TYPE-SYSTEM.md section 5 (canonical definition)

interface TopologyInitPayload extends GuardedPayload {
  action: "topology.init";
  /** Topology type being initialized. */
  topologyType: TopologyType;
  /** Maximum agents this topology supports. */
  maxAgents: number;
  /** Initial agent layout. Maps agentId -> role. */
  layout: Record<string, TopologyNodeRole>;
  /** Orchestration strategy. */
  strategy: "specialized" | "balanced" | "adaptive";
  /** Consensus algorithm for the topology. See TYPE-SYSTEM.md section 6. */
  consensusAlgorithm: ConsensusAlgorithm;
}

interface TopologyRebalancePayload extends GuardedPayload {
  action: "topology.rebalance";
  /** Reason for rebalancing. */
  reason: "load" | "failure" | "join" | "leave" | "manual";
  /** Previous layout. */
  previousLayout: Record<string, TopologyNodeRole>;
  /** New layout after rebalance. */
  newLayout: Record<string, TopologyNodeRole>;
  /** Agents affected by the rebalance. */
  affectedAgentIds: string[];
}

interface TopologyNodeJoinPayload extends GuardedPayload {
  action: "topology.node_join";
  /** Agent joining the topology. */
  agentId: string;
  /** Role assigned to the joining agent. */
  assignedRole: TopologyNodeRole;
  /** Agent model (e.g., "claude-sonnet-4", "gpt-4"). */
  agentModel?: string;
  /** Policy mode the agent runs under. */
  policyMode?: string;
}

interface TopologyNodeLeavePayload extends GuardedPayload {
  action: "topology.node_leave";
  agentId: string;
  /** Reason for leaving. */
  reason: "completed" | "failed" | "timeout" | "user_request" | "evicted";
  /** Whether the agent's tasks need reassignment. */
  tasksOrphaned: number;
}

interface TopologyNodeRoleChangePayload extends GuardedPayload {
  action: "topology.role_change";
  agentId: string;
  previousRole: TopologyNodeRole;
  newRole: TopologyNodeRole;
  /** What triggered the role change. */
  trigger: "election" | "promotion" | "demotion" | "rebalance" | "manual";
}
```

### 5.4 `consensus` Channel

Topic: `/baychat/v1/swarm/{swarmId}/consensus`

```typescript
type ConsensusPayload =
  | ConsensusProposalPayload
  | ConsensusVotePayload
  | ConsensusCommitPayload
  | ConsensusAbortPayload;

interface ConsensusProposalPayload extends GuardedPayload {
  action: "consensus.propose";
  /** Unique proposal ID. Format: csn_{ulid}. */
  proposalId: string;
  /** The value being proposed (JSON-serializable). */
  value: unknown;
  /** Agent that originated the proposal. */
  proposer: string;
  /** What kind of decision this proposal represents. */
  proposalType: "task_assignment" | "topology_change" | "policy_update" | "memory_write" | "custom";
  /** Deadline for votes (Unix ms). Null = no deadline. */
  votingDeadline: number | null;
  /** Quorum required (fraction, 0.0-1.0). Null = simple majority. */
  quorumThreshold: number | null;
}

interface ConsensusVotePayload extends GuardedPayload {
  action: "consensus.vote";
  proposalId: string;
  /** Vote decision. */
  vote: "accept" | "reject" | "abstain";
  /** Agent casting the vote. */
  voter: string;
  /** Optional reason for the vote. */
  reason?: string;
  /** Guard-exempt: votes are read-only expressions of intent. */
  guardExempt: true;
}

interface ConsensusCommitPayload extends GuardedPayload {
  action: "consensus.commit";
  proposalId: string;
  /** The committed value. Must match the proposed value. */
  committedValue: unknown;
  /** Votes received before commit. */
  voteSummary: {
    accept: number;
    reject: number;
    abstain: number;
    total: number;
  };
  /** Guard-exempt: commits report the outcome of a completed vote. */
  guardExempt: true;
}

interface ConsensusAbortPayload extends GuardedPayload {
  action: "consensus.abort";
  proposalId: string;
  /** Why the proposal was aborted. */
  reason: "quorum_not_reached" | "deadline_expired" | "proposer_withdrew" | "superseded" | "guard_denied";
  /** Guard-exempt: aborts are observational. */
  guardExempt: true;
}
```

### 5.5 `memory` Channel

Topic: `/baychat/v1/swarm/{swarmId}/memory`

```typescript
type MemoryPayload =
  | MemoryStorePayload
  | MemorySearchResultPayload
  | MemoryNamespaceSyncPayload;

interface MemoryStorePayload extends GuardedPayload {
  action: "memory.store";
  /** Memory namespace (e.g., "collaboration", "patterns", "swarm"). */
  namespace: string;
  /** Key within the namespace. */
  key: string;
  /** Value to store (JSON-serializable). */
  value: unknown;
  /** Tags for search indexing. */
  tags: string[];
  /** TTL in milliseconds. Null = no expiry. */
  ttlMs: number | null;
  /** Agent that wrote this entry. */
  authorAgentId: string;
}

interface MemorySearchResultPayload extends GuardedPayload {
  action: "memory.search_result";
  /** Original search query. */
  query: string;
  /** Namespace searched. */
  namespace: string;
  /** Ordered results with relevance scores. */
  results: Array<{
    key: string;
    value: unknown;
    score: number;           // 0.0-1.0 relevance
    tags: string[];
    authorAgentId: string;
    storedAt: number;        // Unix ms
  }>;
  /** Total matches (may exceed returned results). */
  totalMatches: number;
  /** Search latency in milliseconds. */
  searchMs: number;
  /** Guard-exempt: search results are read-only. */
  guardExempt: true;
}

interface MemoryNamespaceSyncPayload extends GuardedPayload {
  action: "memory.namespace_sync";
  /** Namespace being synced. */
  namespace: string;
  /** All keys in the namespace with their current version hashes. */
  entries: Array<{
    key: string;
    versionHash: string;     // SHA-256 of the value
    updatedAt: number;       // Unix ms
  }>;
  /** Agent performing the sync. */
  syncAgentId: string;
  /** Whether this is a full sync or delta. */
  syncType: "full" | "delta";
  /** Guard-exempt: sync metadata is observational. */
  guardExempt: true;
}
```

### 5.6 `hooks` Channel

Topic: `/baychat/v1/swarm/{swarmId}/hooks`

```typescript
type HooksPayload =
  | HookPreEditPayload
  | HookPostEditPayload
  | HookPreTaskPayload
  | HookPostTaskPayload
  | HookSessionEventPayload;

interface HookPreEditPayload extends GuardedPayload {
  action: "hook.pre_edit";
  /** Absolute file path being edited. */
  filePath: string;
  /** Agent performing the edit. */
  agentId: string;
  /** Type of edit operation. */
  editType: "create" | "modify" | "delete" | "rename";
  /** Old content hash (SHA-256), for modify/delete. */
  oldContentHash?: string;
  /** Proposed new content hash (SHA-256), for create/modify. */
  newContentHash?: string;
  /** Number of lines changed. */
  linesChanged?: number;
}

interface HookPostEditPayload extends GuardedPayload {
  action: "hook.post_edit";
  filePath: string;
  agentId: string;
  editType: "create" | "modify" | "delete" | "rename";
  /** Whether the edit was successfully applied. */
  success: boolean;
  /** New content hash after edit (SHA-256). */
  resultContentHash?: string;
  /** Diff summary. */
  diffSummary?: { added: number; removed: number };
  /** Whether neural pattern training should be triggered. */
  trainPatterns: boolean;
}

interface HookPreTaskPayload extends GuardedPayload {
  action: "hook.pre_task";
  taskId: string;
  agentId: string;
  /** Task description for pre-flight analysis. */
  description: string;
  /** Estimated complexity (0.0-1.0). Used for model tier routing. */
  estimatedComplexity?: number;
  /** Recommended model tier from the hooks route system. */
  recommendedTier?: ModelTier;
}

interface HookPostTaskPayload extends GuardedPayload {
  action: "hook.post_task";
  taskId: string;
  agentId: string;
  /** Whether the task succeeded. */
  success: boolean;
  /** Duration in milliseconds. */
  durationMs: number;
  /** Tokens consumed. */
  tokensConsumed: number;
  /** Whether to train neural patterns from this result. */
  trainPatterns: boolean;
  /** Guard-exempt: post-task reports are observational. */
  guardExempt: true;
}

interface HookSessionEventPayload extends GuardedPayload {
  action: "hook.session_event";
  /** Session lifecycle event type. */
  eventType: "session_start" | "session_end" | "session_restore";
  /** Session ID. */
  sessionId: string;
  /** Agent associated with this session. */
  agentId: string;
  /** Metrics at time of event (for session_end). */
  metrics?: {
    totalTasks: number;
    totalTokens: number;
    totalDurationMs: number;
    receiptsGenerated: number;
    deniedActions: number;
  };
  /** Guard-exempt: session lifecycle events are observational. */
  guardExempt: true;
}
```

---

## 6. Transport Compatibility

### 6.1 Transport Requirements

All three transport implementations MUST support the new channels without
modification to the `TransportAdapter` interface. The interface is already
channel-agnostic -- it operates on `(topic: string, envelope: SwarmEnvelope)` pairs.

| Transport | Backing | Scope | Notes |
|-----------|---------|-------|-------|
| `InProcessEventBus` | `EventTarget` | Personal/local swarms | Always connected. No TTL enforcement. |
| Speakeasy Gossipsub | libp2p Gossipsub | Networked/federated swarms | TTL enforced by hop decrement. |
| `TauriIpcTransport` | Tauri IPC (`invoke`/`listen`) | Desktop app | Bridges web frontend to Rust backend. |

### 6.2 InProcessEventBus

No changes required. The `InProcessEventBus` dispatches `CustomEvent` instances
keyed by topic string. New topics (e.g., `/baychat/v1/swarm/{id}/agents`) work
automatically because the bus is topic-string-agnostic.

### 6.3 Speakeasy Gossipsub Adapter

The Gossipsub adapter wraps `@backbay/speakeasy` transport. New topics follow the
same `/baychat/v1/...` prefix and are subscribed/published identically to existing
topics. TTL hop-decrement logic applies uniformly.

**Consideration**: Orchestration channels (especially `agent.heartbeat` and
`task.progress`) can be high-volume. The `consensus` channel TTL is set to 3
(same as signals) to prevent flooding in large meshes.

### 6.4 TauriIpcTransport (New)

```typescript
/**
 * Tauri IPC transport for desktop swarm communication.
 * Bridges the web frontend SwarmCoordinator to the Rust backend via
 * Tauri's invoke (publish) and listen (subscribe) APIs.
 */
class TauriIpcTransport implements TransportAdapter {
  private subscriptions = new Set<string>();
  private handlers = new Set<(topic: string, envelope: SwarmEnvelope) => void>();
  private unlistenFns = new Map<string, () => void>();

  subscribe(topic: string): void {
    if (this.subscriptions.has(topic)) return;
    this.subscriptions.add(topic);
    // Register Tauri event listener for this topic
    // listen<SwarmEnvelope>(topic, (event) => { ... })
  }

  unsubscribe(topic: string): void {
    this.subscriptions.delete(topic);
    const unlisten = this.unlistenFns.get(topic);
    if (unlisten) {
      unlisten();
      this.unlistenFns.delete(topic);
    }
  }

  async publish(topic: string, envelope: SwarmEnvelope): Promise<void> {
    // invoke("swarm_publish", { topic, envelope })
  }

  onMessage(handler: (topic: string, envelope: SwarmEnvelope) => void): void {
    this.handlers.add(handler);
  }

  offMessage(handler: (topic: string, envelope: SwarmEnvelope) => void): void {
    this.handlers.delete(handler);
  }

  isConnected(): boolean {
    // Check if Tauri IPC bridge is available
    return typeof window !== "undefined" && "__TAURI__" in window;
  }
}
```

---

## 7. Subscription Model

### 7.1 Default Subscriptions

When a swarm is joined via `SwarmCoordinator.joinSwarm()`, the following topics
are subscribed by default:

**Existing (unchanged)**:
- `/baychat/v1/swarm/{id}/intel`
- `/baychat/v1/swarm/{id}/detections`
- `/baychat/v1/swarm/{id}/coordination`

**New (always subscribed)**:
- `/baychat/v1/swarm/{id}/agents`
- `/baychat/v1/swarm/{id}/tasks`
- `/baychat/v1/swarm/{id}/topology`

**Opt-in (high volume, same as signals)**:
- `/baychat/v1/swarm/{id}/signals` (existing, unchanged)
- `/baychat/v1/swarm/{id}/consensus`
- `/baychat/v1/swarm/{id}/memory`
- `/baychat/v1/swarm/{id}/hooks`

### 7.2 Extended getSwarmTopics

> **Breaking change mitigated**: The current signature is `getSwarmTopics(swarmId: string, includeSignals?: boolean)`.
> This proposal changes the second parameter from `boolean` to an options object.
> To avoid a hard break, the implementation includes a **runtime backward-compat shim**
> that detects a `boolean` second argument and converts it to `{ includeSignals: arg }`.
> Existing call sites continue to work but should be migrated. A `console.warn` deprecation
> notice is emitted when the boolean path is taken.
> The return value also changes: the default now includes 6 topics (was 3), so downstream
> code that assumes a fixed topic count must be updated.

```typescript
function getSwarmTopics(
  swarmId: string,
  optionsOrLegacyBoolean?: boolean | {
    includeSignals?: boolean;     // default: false
    includeConsensus?: boolean;   // default: false
    includeMemory?: boolean;      // default: false
    includeHooks?: boolean;       // default: false
  },
): string[] {
  // Backward-compat shim: support old boolean signature
  let options: { includeSignals?: boolean; includeConsensus?: boolean; includeMemory?: boolean; includeHooks?: boolean } | undefined;
  if (typeof optionsOrLegacyBoolean === "boolean") {
    console.warn("[getSwarmTopics] boolean arg is deprecated, use options object");
    options = { includeSignals: optionsOrLegacyBoolean };
  } else {
    options = optionsOrLegacyBoolean;
  }
  const topics = [
    // Existing
    swarmIntelTopic(swarmId),
    swarmDetectionTopic(swarmId),
    swarmCoordinationTopic(swarmId),
    // New (always included)
    swarmAgentsTopic(swarmId),
    swarmTasksTopic(swarmId),
    swarmTopologyTopic(swarmId),
  ];
  if (options?.includeSignals) topics.push(swarmSignalTopic(swarmId));
  if (options?.includeConsensus) topics.push(swarmConsensusTopic(swarmId));
  if (options?.includeMemory) topics.push(swarmMemoryTopic(swarmId));
  if (options?.includeHooks) topics.push(swarmHooksTopic(swarmId));
  return topics;
}
```

---

## 8. Router Extension

The `SwarmCoordinator.routeMessage()` private method is extended to handle
new channels. The existing `switch (parsed.channel)` block gains new cases:

```typescript
private routeMessage(topic: string, envelope: SwarmEnvelope): void {
  const parsed = parseSwarmTopic(topic);
  if (!parsed) return;
  if (!this.activeSwarms.has(parsed.swarmId)) return;

  switch (parsed.channel) {
    // ... existing cases (intel, signals, detections, coordination) unchanged ...

    case "agents":
      if (envelope.type === "agent_lifecycle") {
        for (const handler of this.agentLifecycleHandlers) {
          try { handler(parsed.swarmId, envelope.payload as AgentLifecyclePayload); }
          catch { /* swallow */ }
        }
      }
      break;

    case "tasks":
      if (envelope.type === "task_orchestration") {
        for (const handler of this.taskOrchestrationHandlers) {
          try { handler(parsed.swarmId, envelope.payload as TaskOrchestrationPayload); }
          catch { /* swallow */ }
        }
      }
      break;

    case "topology":
      if (envelope.type === "topology") {
        for (const handler of this.topologyHandlers) {
          try { handler(parsed.swarmId, envelope.payload as TopologyPayload); }
          catch { /* swallow */ }
        }
      }
      break;

    case "consensus":
      if (envelope.type === "consensus") {
        for (const handler of this.consensusHandlers) {
          try { handler(parsed.swarmId, envelope.payload as ConsensusPayload); }
          catch { /* swallow */ }
        }
      }
      break;

    case "memory":
      if (envelope.type === "memory") {
        for (const handler of this.memoryHandlers) {
          try { handler(parsed.swarmId, envelope.payload as MemoryPayload); }
          catch { /* swallow */ }
        }
      }
      break;

    case "hooks":
      if (envelope.type === "hooks") {
        for (const handler of this.hooksHandlers) {
          try { handler(parsed.swarmId, envelope.payload as HooksPayload); }
          catch { /* swallow */ }
        }
      }
      break;
  }
}
```

---

## 9. Envelope Lifecycle

### 9.1 Complete Lifecycle (Guarded Action)

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │                        ENVELOPE LIFECYCLE                          │
  │                        (Guarded Action)                            │
  └─────────────────────────────────────────────────────────────────────┘

  1. ORIGINATE         Agent creates payload (receipt = undefined)
       │
  2. GUARD             Guard pipeline evaluates action:
       │                 - Maps payload.action to TestActionType
       │                 - Runs guards in pipeline order
       │                 - Produces Receipt, stores in ledger
       │
       ├── ALLOW ──> 3a. ATTACH     Attach EnvelopeReceipt to payload
       │                   │
       │              4a. WRAP       Wrap in SwarmEnvelope (type, ttl, created)
       │                   │
       │              5a. PUBLISH    safePublish(topic, envelope)
       │                   │          ├── Connected: transport.publish()
       │                   │          └── Disconnected: outbox.enqueue()
       │                   │
       │              6a. ROUTE      routeMessage() dispatches to typed handlers
       │                   │
       │              7a. CONSUME    Handler processes payload + receipt
       │
       └── DENY ───> 3b. LOG        Store Receipt in ledger
                           │
                      4b. NOTIFY     Publish DenyNotification to coordination
                           │
                      5b. REACT      Originating agent receives deny via
                                     coordination subscription
```

### 9.2 Complete Lifecycle (Guard-Exempt)

```
  1. ORIGINATE         Agent creates payload (guardExempt = true)
       │
  2. WRAP              Wrap in SwarmEnvelope (no guard evaluation)
       │
  3. PUBLISH           safePublish(topic, envelope)
       │
  4. ROUTE             routeMessage() dispatches to typed handlers
       │
  5. CONSUME           Handler processes payload (no receipt)
```

---

## 10. Backward Compatibility

### 10.1 Guarantees

1. **Existing `SwarmEnvelope.type` values** are unchanged. Code that switches on
   `type === "intel" | "signal" | "detection" | "coordination" | "status"` will
   continue to work. New types are additive.

2. **Existing `SwarmChannel` values** are unchanged. The `parseSwarmTopic()`
   function is extended to recognize new suffixes but continues to return `null`
   for unrecognized suffixes (no false positives for old code).

3. **`TransportAdapter` interface** is unchanged. No new methods. All transports
   that implement the current interface work with new channels automatically.

4. **`MessageOutbox`** handles new envelope types without modification (it is
   already type-agnostic).

5. **`InProcessEventBus`** handles new topics without modification (it is
   already topic-agnostic).

6. **Existing handler types** (`IntelHandler`, `SignalHandler`, `DetectionHandler`,
   `PolicyEvaluatedHandler`, `MemberJoinedHandler`, `MemberLeftHandler`) are
   unchanged and continue to function.

### 10.2 Migration Path

Phase 1 (this spec): Add new types, channels, and guard integration. Existing
code paths are not modified.

Phase 2 (future): Gradually migrate `coordination` channel's polymorphic
`action` field payloads (`policy_evaluated`, `member_joined`, `member_left`)
to the appropriate new typed channels. The `coordination` channel becomes
a catch-all for messages that do not fit other channels.

### 10.3 parseSwarmTopic Extension

```typescript
type SwarmChannel =
  | "intel" | "signals" | "detections" | "coordination"   // existing
  | "agents" | "tasks" | "topology" | "consensus"         // new
  | "memory" | "hooks";                                    // new

function parseSwarmTopic(topic: string): ParsedSwarmTopic | null {
  const prefix = `${TOPIC_PREFIX}/swarm/`;
  if (!topic.startsWith(prefix)) return null;

  const remainder = topic.slice(prefix.length);
  const slashIdx = remainder.indexOf("/");
  if (slashIdx === -1) return null;

  const swarmId = remainder.slice(0, slashIdx);
  const channel = remainder.slice(slashIdx + 1);

  const validChannels: SwarmChannel[] = [
    "intel", "signals", "detections", "coordination",
    "agents", "tasks", "topology", "consensus",
    "memory", "hooks",
  ];

  if (!validChannels.includes(channel as SwarmChannel)) return null;

  return { swarmId, channel: channel as SwarmChannel };
}
```

---

## 11. SwarmBoard Node Integration

The existing `SwarmBoardNodeData` type (from `swarm-board-types.ts`) already
supports the metadata needed for orchestration visualization:

| Existing field | Orchestration use |
|---------------|-------------------|
| `status: SessionStatus` | Maps directly to `AgentStatus` |
| `policyMode?: string` | From `AgentSpawnPayload.policyMode` |
| `agentModel?: string` | From `TopologyNodeJoinPayload.agentModel` |
| `taskPrompt?: string` | From `TaskCreatePayload.prompt` |
| `receiptCount?: number` | Incremented on each `EnvelopeReceipt` |
| `blockedActionCount?: number` | Incremented on each deny |
| `verdict?: Verdict` | From latest `EnvelopeReceipt.verdict` |
| `guardResults?: Array<...>` | From receipt ledger |
| `toolBoundaryEvents?: number` | Count of guarded envelope actions |
| `confidence?: number` | From `AgentHealthPayload` checks |
| `exitCode?: number` | From `AgentTerminatePayload.exitCode` |

New fields may be added to `SwarmBoardNodeData` as optional extensions, but
the existing superset pattern handles most orchestration metadata already.

---

## 12. Security Considerations

### 12.1 Guard Pipeline as Single Gate

The guard pipeline is the ONLY path for mutable orchestration actions. There is
no bypass. An agent cannot spawn a sub-agent, create a task, write to memory,
or change the topology without a guard evaluation.

### 12.2 Receipt Verification

Any consumer can verify an `EnvelopeReceipt.signature` using the `publicKey`
field without contacting the guard pipeline. This enables offline verification
and cross-swarm trust.

### 12.3 Denied Envelope Audit Trail

Denied envelopes are never forwarded to subscribers, but the full `Receipt` is
stored in the local ledger. The `DenyNotification` on the coordination channel
ensures observability without leaking the denied payload content.

### 12.4 Replay Protection

The `SwarmEnvelope.created` timestamp combined with the `EnvelopeReceipt.evaluatedAt`
and `receiptId` provide replay detection. Consumers SHOULD reject envelopes where
`created` is more than 5 minutes in the past (configurable per swarm policy).

### 12.5 Sentinel-Agent Bridge

When a ClawdStrike sentinel operates as an agent within a swarm (role = `"sentinel"`),
its `SentinelIdentity` keypair is used for both Speakeasy message signing and
`EnvelopeReceipt` verification. This unifies the identity model.

---

## 13. Open Questions

1. **Heartbeat interval**: ~~What is the default heartbeat interval for
   `agent.heartbeat`? Proposed: 30 seconds for local, 60 seconds for networked.~~
   **Resolved:** TYPE-SYSTEM.md section 13 defines `DEFAULT_HEARTBEAT_INTERVAL_MS: 5_000` (5s)
   for the internal engine health-check loop. The *protocol-level* heartbeat envelope on
   `agent_lifecycle` channel should be **10 seconds for local, 30 seconds for networked** to
   avoid flooding Gossipsub. The internal check runs at 5s; the external envelope is sampled
   at the lower rate. Add `PROTOCOL_HEARTBEAT_INTERVAL_MS: 10_000` to constants.

2. **Memory channel encryption**: Should `memory.store` payloads be encrypted
   at rest in transit for federated swarms? The existing Speakeasy transport
   provides message-level encryption, but the memory content itself is plaintext
   within the envelope.

3. **Consensus quorum defaults**: For `raft` consensus, the quorum threshold
   should be `> n/2`. For `byzantine`, it should be `> 2n/3`. Should these be
   enforced at the protocol level or left to the topology coordinator?

4. **Hook channel volume**: Pre/post-edit hooks in a multi-agent coding swarm
   can be extremely high volume. Should hooks be batched or rate-limited at
   the envelope level?

---

## Appendix A: Complete Type Index

| Type | Channel | Guarded | Section |
|------|---------|---------|---------|
| `AgentSpawnPayload` | `agent_lifecycle` | Yes | 5.1 |
| `AgentHeartbeatPayload` | `agent_lifecycle` | No | 5.1 |
| `AgentStatusChangePayload` | `agent_lifecycle` | No | 5.1 |
| `AgentTerminatePayload` | `agent_lifecycle` | Yes | 5.1 |
| `AgentHealthPayload` | `agent_lifecycle` | No | 5.1 |
| `TaskCreatePayload` | `task_orchestration` | Yes | 5.2 |
| `TaskAssignPayload` | `task_orchestration` | Yes | 5.2 |
| `TaskProgressPayload` | `task_orchestration` | No | 5.2 |
| `TaskCompletePayload` | `task_orchestration` | No | 5.2 |
| `TaskFailPayload` | `task_orchestration` | No | 5.2 |
| `TaskDependencyResolvedPayload` | `task_orchestration` | No | 5.2 |
| `TopologyInitPayload` | `topology` | Yes | 5.3 |
| `TopologyRebalancePayload` | `topology` | Yes | 5.3 |
| `TopologyNodeJoinPayload` | `topology` | Yes | 5.3 |
| `TopologyNodeLeavePayload` | `topology` | Yes | 5.3 |
| `TopologyNodeRoleChangePayload` | `topology` | Yes | 5.3 |
| `ConsensusProposalPayload` | `consensus` | Yes | 5.4 |
| `ConsensusVotePayload` | `consensus` | No | 5.4 |
| `ConsensusCommitPayload` | `consensus` | No | 5.4 |
| `ConsensusAbortPayload` | `consensus` | No | 5.4 |
| `MemoryStorePayload` | `memory` | Yes | 5.5 |
| `MemorySearchResultPayload` | `memory` | No | 5.5 |
| `MemoryNamespaceSyncPayload` | `memory` | No | 5.5 |
| `HookPreEditPayload` | `hooks` | Yes | 5.6 |
| `HookPostEditPayload` | `hooks` | Yes | 5.6 |
| `HookPreTaskPayload` | `hooks` | Yes | 5.6 |
| `HookPostTaskPayload` | `hooks` | No | 5.6 |
| `HookSessionEventPayload` | `hooks` | No | 5.6 |
| `GuardedPayload` | (base) | -- | 4.1 |
| `EnvelopeReceipt` | (inline) | -- | 4.2 |
| `DenyNotification` | `coordination` | -- | 4.5 |

## Appendix B: Source File References

| File | Contents referenced |
|------|-------------------|
| `features/swarm/swarm-coordinator.ts` | `SwarmEnvelope`, `TransportAdapter`, `InProcessEventBus`, `MessageOutbox`, `SwarmCoordinator`, `SwarmChannel`, `ParsedSwarmTopic`, topic builders, router |
| `features/swarm/swarm-board-types.ts` | `SwarmBoardNodeData`, `SessionStatus`, `SwarmNodeType`, `RiskLevel` |
| `lib/workbench/sentinel-types.ts` | `Swarm`, `SwarmMember`, `SwarmPolicy`, `SwarmStats`, `SwarmType`, `SentinelIdentity`, `Signal`, `Intel` |
| `lib/workbench/types.ts` | `Receipt`, `Verdict`, `GuardId`, `TestActionType`, `GuardSimResult` |
