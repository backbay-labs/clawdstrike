/**
 * Unified type system for the @clawdstrike/swarm-engine package.
 *
 * Transcribed from TYPE-SYSTEM.md sections 2-13 and PROTOCOL-SPEC.md
 * sections 4.1-4.2. All types are JSON-serializable: no Map, no Date,
 * no functions, no circular references. Timestamps are Unix milliseconds
 * (number). Collections are arrays or Record<string, T>.
 *
 * @module
 */

// Re-export the ID prefix type for consumers
export type { SwarmEngineIdPrefix } from "./ids.js";

// ============================================================================
// Locally redefined ClawdStrike types
// SYNC: lib/workbench/types.ts
// These types are structurally identical to the workbench types but are
// independently owned by this package. They must be kept in sync manually.
// ============================================================================

/**
 * Guard evaluation verdict.
 * SYNC: lib/workbench/types.ts
 */
export type Verdict = "allow" | "deny" | "warn";

/**
 * Action types recognized by the guard pipeline.
 * SYNC: lib/workbench/types.ts
 */
export type TestActionType =
  | "file_access"
  | "file_write"
  | "network_egress"
  | "shell_command"
  | "mcp_tool_call"
  | "patch_apply"
  | "user_input";

/**
 * Ed25519-signed receipt from a guard evaluation.
 * SYNC: lib/workbench/types.ts
 */
export interface Receipt {
  id: string;
  timestamp: string;
  verdict: Verdict;
  guard: string;
  policyName: string;
  action: { type: TestActionType; target: string };
  evidence: Record<string, unknown>;
  signature: string;
  publicKey: string;
  valid: boolean;
  keyType?: "persistent" | "ephemeral";
  imported?: boolean;
}

/**
 * Individual guard simulation result.
 * SYNC: lib/workbench/types.ts
 */
export interface GuardSimResult {
  guardId: string;
  guard: string;
  verdict: Verdict;
  duration_ms: number;
  details: Record<string, unknown>;
}

// ============================================================================
// Section 2: ID Prefixes (re-exported from ids.ts)
// ============================================================================

// SwarmEngineIdPrefix is re-exported via the `export type` at the top.

// ============================================================================
// Section 3: Agent Types
// ============================================================================

// ---------------------------------------------------------------------------
// Agent role -- superset of ruflo's AgentType and ClawdStrike's sentinel modes
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
// Agent session status
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
// Risk level
// ---------------------------------------------------------------------------

export type RiskLevel = "low" | "medium" | "high";

// ---------------------------------------------------------------------------
// Agent capabilities
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
// Agent metrics
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
// Agent quality scores
// ---------------------------------------------------------------------------

export interface AgentQualityScores {
  reliability: number;
  speed: number;
  quality: number;
}

// ---------------------------------------------------------------------------
// Agent conversation replay
// ---------------------------------------------------------------------------

/**
 * Structured conversation turn captured for agent replay surfaces.
 *
 * The host is expected to record prompt/tool/response activity as it happens.
 * Turns are JSON-serializable so they can be persisted or transported as-is.
 */
export type AgentConversationTurnKind =
  | "system"
  | "prompt"
  | "tool_call"
  | "tool_result"
  | "response";

/**
 * Single replayable turn in an agent conversation.
 */
export interface AgentConversationTurn {
  /** Stable turn identifier. */
  id: string;
  /** High-level turn classification. */
  kind: AgentConversationTurnKind;
  /** Speaker role for rendering transcript semantics. */
  role: "system" | "user" | "assistant" | "tool";
  /** Primary human-readable or serialized content. */
  content: string;
  /** Unix ms timestamp for chronological ordering. */
  createdAt: number;
  /** Optional tool name for tool_call/tool_result turns. */
  toolName?: string | null;
  /** Optional machine-readable metadata for richer replay surfaces. */
  metadata?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Agent registration (input to AgentRegistry.register)
// ---------------------------------------------------------------------------

/**
 * Input for registering an agent with the AgentRegistry.
 *
 * Provides the minimal required information to create an AgentSession
 * when the agent is spawned. The registry generates the agent ID.
 */
export interface AgentRegistration {
  /** Human-readable name for the agent. */
  name: string;
  /** Agent role within the swarm. */
  role: AgentRole;
  /** Agent capabilities for task assignment. */
  capabilities: AgentCapabilities;
  /** Optional quality score overrides (defaults to 0.5 for each). */
  quality?: Partial<AgentQualityScores>;
  /** Policy mode for the agent (e.g., "strict", "permissive"). */
  policyMode?: string | null;
  /** Agent model identifier (e.g., "claude-3.5-sonnet"). */
  agentModel?: string | null;
}

// ---------------------------------------------------------------------------
// Health check status
// ---------------------------------------------------------------------------

/**
 * Health check status for a registered agent.
 * Tracked by the AgentRegistry health check loop.
 */
export interface HealthCheckStatus {
  /** Agent ID. */
  agentId: string;
  /** Whether the agent is currently considered healthy. */
  healthy: boolean;
  /** Timestamp of last heartbeat (Unix ms). */
  lastHeartbeatAt: number;
  /** Number of consecutive missed heartbeats. */
  consecutiveMisses: number;
  /** Current agent session status. */
  status: AgentSessionStatus;
}

// ---------------------------------------------------------------------------
// Task error categorization
// ---------------------------------------------------------------------------

/** Error categorization for failed tasks (TASK-05). */
export type TaskErrorCategory =
  | "guard_denied"
  | "timeout"
  | "runtime_error"
  | "dependency_failed"
  | "cancelled";

// ---------------------------------------------------------------------------
// Task submission (input to TaskGraph.submit)
// ---------------------------------------------------------------------------

/** Task submission input for TaskGraph. */
export interface TaskSubmission {
  /** Task classification. */
  type: TaskType;
  /** Human-readable task name. */
  name: string;
  /** Detailed description or prompt for the agent. */
  description: string;
  /** Execution priority. Defaults to "normal". */
  priority?: TaskPriority;
  /** Task IDs that must complete before this task can start. */
  dependencies?: string[];
  /** Input data for the task. */
  input?: Record<string, unknown>;
  /** Timeout in milliseconds. 0 means no timeout. */
  timeoutMs?: number;
  /** Maximum retry attempts before permanent failure. */
  maxRetries?: number;
  /** Arbitrary tags for filtering and routing. */
  tags?: string[];
}

// ---------------------------------------------------------------------------
// Guard receipt summary
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

// ============================================================================
// Section 4: Task Types
// ============================================================================

// ---------------------------------------------------------------------------
// Task priority
// ---------------------------------------------------------------------------

export type TaskPriority = "critical" | "high" | "normal" | "low" | "background";

// ---------------------------------------------------------------------------
// Task status
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
// Task type
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
  | "detection"
  | "hunt"
  | "guard_evaluation"
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

// ============================================================================
// Section 5: Topology Types
// ============================================================================

// ---------------------------------------------------------------------------
// Topology type
// ---------------------------------------------------------------------------

export type TopologyType = "mesh" | "hierarchical" | "centralized" | "hybrid" | "adaptive";

// ---------------------------------------------------------------------------
// Topology node role
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
// Topology node
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
// Topology edge
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
// Topology partition
// ---------------------------------------------------------------------------

export interface TopologyPartition {
  id: string;
  nodeIds: string[];
  leaderId: string;
  replicaCount: number;
}

// ---------------------------------------------------------------------------
// Topology state snapshot
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

// ============================================================================
// Section 6: Consensus Types
// ============================================================================

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

// ============================================================================
// Section 8.1: Swarm Engine Channel
// ============================================================================

/**
 * Swarm engine envelope channels.
 * New channels for the swarm engine, used alongside ClawdStrike's existing
 * SwarmChannel ("intel" | "signals" | "detections" | "coordination") and
 * SwarmEnvelope.type ("intel" | "signal" | "detection" | "coordination" | "status").
 */
export type SwarmEngineChannel =
  | "agent_lifecycle"
  | "task_orchestration"
  | "topology"
  | "consensus"
  | "memory"
  | "hooks";

// ============================================================================
// Section 9: Guard Integration Types
// ============================================================================

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
  actionType: TestActionType;

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

// ============================================================================
// Section 9a: Guard Evaluator Interface
// ============================================================================

/**
 * Guard evaluator interface for host injection.
 *
 * The host application (or test harness) injects a GuardEvaluator into the
 * SwarmOrchestrator. When missing, the orchestrator falls back to a deny-all
 * evaluator (fail-closed).
 *
 * @see ARCHITECTURE.md section 2.1
 */
export interface GuardEvaluator {
  evaluate(action: GuardedAction): Promise<GuardEvaluationResult>;
}

// ============================================================================
// Section 9b: Agent Pool Types
// ============================================================================

/**
 * Configuration for the AgentPool.
 *
 * Ported from ruflo's AgentPoolConfig with browser-safe adaptations.
 */
export interface AgentPoolConfig {
  /** Pool name identifier. */
  name: string;
  /** Minimum number of agents to maintain. */
  minSize: number;
  /** Maximum number of agents allowed. */
  maxSize: number;
  /** Utilization ratio (0-1) above which auto-scale-up triggers. Default: 0.8. */
  scaleUpThreshold: number;
  /** Utilization ratio (0-1) below which auto-scale-down triggers. Default: 0.2. */
  scaleDownThreshold: number;
  /** Cooldown period in ms between scale operations. Default: 30000. */
  cooldownMs: number;
  /** Interval in ms between health checks. Default: 10000. */
  healthCheckIntervalMs: number;
}

/**
 * Serializable snapshot of the AgentPool state.
 *
 * Uses Record instead of Map for JSON compatibility. The pool's internal
 * state uses Map for O(1) lookups, but getState() converts to this shape.
 */
export interface AgentPoolState {
  /** Current pool configuration. */
  config: AgentPoolConfig;
  /** All pooled agents, keyed by agent ID. */
  agents: Record<
    string,
    {
      agentId: string;
      status: "available" | "busy" | "unhealthy";
      lastUsed: number;
      usageCount: number;
      health: number;
    }
  >;
  /** Number of available (idle) agents. */
  availableCount: number;
  /** Number of busy (acquired) agents. */
  busyCount: number;
  /** Current utilization ratio (busy / total). */
  utilization: number;
  /** Pending scale operation delta. */
  pendingScale: number;
  /** Timestamp of last scale operation, or null. */
  lastScaleOperation: number | null;
}

// ============================================================================
// Section 9c: Deny Notification
// ============================================================================

/**
 * Deny notification published to the coordination channel when an envelope
 * is denied by the guard pipeline.
 *
 * @see PROTOCOL-SPEC.md section 4.5
 */
export interface DenyNotification {
  /** Always "envelope_denied". */
  action: "envelope_denied";
  /** Channel the denied envelope was targeting. */
  originalChannel: SwarmEngineChannel;
  /** Action type from the denied envelope's payload. */
  originalAction: string;
  /** Receipt ID for ledger lookup. */
  receiptId: string;
  /** Always "deny". */
  verdict: "deny";
  /** Guard that produced the deny verdict. */
  decidingGuard: string;
  /** Fingerprint of the agent that originated the denied envelope. */
  sender: string;
  /** Timestamp of the denial (Unix ms). */
  timestamp: number;
}

// ============================================================================
// Section 10: Swarm Engine State
// ============================================================================

/**
 * Swarm engine status -- from ruflo's SwarmStatus.
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
 * Swarm engine metrics -- from ruflo's CoordinatorMetrics.
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

  /** Replayable conversation history keyed by agent session ID. */
  conversationHistory: Record<string, AgentConversationTurn[]>;

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

// ============================================================================
// Section 11: Message Bus Types
// ============================================================================

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

// ============================================================================
// Section 12: Type Guards
// ============================================================================

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

export function isSwarmEngineEvent(
  value: unknown,
): value is import("./events.js").SwarmEngineEvent {
  return (
    typeof value === "object" &&
    value !== null &&
    "kind" in value &&
    typeof (value as { kind: unknown }).kind === "string" &&
    "timestamp" in value &&
    typeof (value as { timestamp: unknown }).timestamp === "number"
  );
}

export function isSwarmEngineEnvelope(
  value: unknown,
): value is import("./events.js").SwarmEngineEnvelope {
  return (
    typeof value === "object" &&
    value !== null &&
    "version" in value &&
    (value as { version: unknown }).version === 1 &&
    "type" in value &&
    typeof (value as { type: unknown }).type === "string" &&
    "payload" in value &&
    typeof (value as { payload: unknown }).payload === "object" &&
    "ttl" in value &&
    typeof (value as { ttl: unknown }).ttl === "number" &&
    "created" in value &&
    typeof (value as { created: unknown }).created === "number"
  );
}

// ============================================================================
// Section 13: Constants
// ============================================================================

export const SWARM_ENGINE_CONSTANTS = Object.freeze({
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
  /** Max replay turns retained per agent conversation history. */
  MAX_CONVERSATION_HISTORY_TURNS: 200,
  /** Health score threshold below which failover triggers. */
  HEALTH_FAILOVER_THRESHOLD: 0.3,
});

// ============================================================================
// Protocol Types (from PROTOCOL-SPEC.md sections 4.1-4.2)
// ============================================================================

/**
 * Base for all orchestration payloads. The `action` field is the discriminant.
 * The `receipt` field is attached by the guard pipeline after evaluation.
 * If `receipt` is absent, the envelope has not yet been evaluated.
 */
export interface GuardedPayload {
  /** Discriminated action type. Used for routing and guard mapping. */
  action: string;
  /** Guard pipeline receipt. Attached after evaluation. Absent = unevaluated. */
  receipt?: EnvelopeReceipt;
  /** Fingerprint of the agent/sentinel that originated this envelope. */
  sender: string;
  /** Correlation ID for tracing a chain of related envelopes. */
  correlationId?: string;
}

/**
 * Compact receipt projection for inline transport.
 *
 * The full Receipt (with evidence and signature bytes) is stored in the
 * local receipt ledger and can be retrieved by receiptId.
 */
export interface EnvelopeReceipt {
  /** Receipt ID for ledger lookup. */
  receiptId: string;
  /** Final verdict from the guard pipeline. */
  verdict: Verdict;
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
