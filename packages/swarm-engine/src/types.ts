/**
 * Unified type system for the swarm engine. All types are JSON-serializable.
 * Timestamps are Unix milliseconds.
 *
 * @module
 */

export type { SwarmEngineIdPrefix } from "./ids.js";

// Mirrors ClawdStrike workbench types — must be kept in sync manually.

export type Verdict = "allow" | "deny" | "warn";

export type TestActionType =
  | "file_access"
  | "file_write"
  | "network_egress"
  | "shell_command"
  | "mcp_tool_call"
  | "patch_apply"
  | "user_input";

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

export interface GuardSimResult {
  guardId: string;
  guard: string;
  verdict: Verdict;
  duration_ms: number;
  details: Record<string, unknown>;
}

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

export type RiskLevel = "low" | "medium" | "high";

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

export interface AgentQualityScores {
  reliability: number;
  speed: number;
  quality: number;
}

export interface AgentRegistration {
  name: string;
  role: AgentRole;
  capabilities: AgentCapabilities;
  /** Defaults to 0.5 for each if omitted. */
  quality?: Partial<AgentQualityScores>;
  policyMode?: string | null;
  agentModel?: string | null;
}

export interface HealthCheckStatus {
  agentId: string;
  healthy: boolean;
  lastHeartbeatAt: number;
  consecutiveMisses: number;
  status: AgentSessionStatus;
}

export type TaskErrorCategory =
  | "guard_denied"
  | "timeout"
  | "runtime_error"
  | "dependency_failed"
  | "cancelled";

export interface TaskSubmission {
  type: TaskType;
  name: string;
  description: string;
  priority?: TaskPriority;
  dependencies?: string[];
  input?: Record<string, unknown>;
  /** 0 means no timeout. */
  timeoutMs?: number;
  maxRetries?: number;
  tags?: string[];
}

export interface GuardReceiptSummary {
  guard: string;
  allowed: boolean;
  durationMs?: number;
}

/**
 * Unified agent session. Represents an agent on both the SwarmBoard
 * (React Flow) and the orchestration engine (task assignment, topology, consensus).
 */
export interface AgentSession {
  /** Format: `agt_{ulid}`. */
  id: string;
  name: string;
  role: AgentRole;
  status: AgentSessionStatus;

  capabilities: AgentCapabilities;
  metrics: AgentMetrics;
  quality: AgentQualityScores;
  currentTaskId: string | null;
  /** 0.0-1.0. Used by the scheduler. */
  workload: number;
  /** 0.0-1.0. Below threshold triggers failover. */
  health: number;
  lastHeartbeatAt: number;
  topologyRole: TopologyNodeRole | null;
  connections: string[];

  worktreePath: string | null;
  branch: string | null;
  risk: RiskLevel;
  policyMode: string | null;
  agentModel: string | null;
  receiptCount: number;
  blockedActionCount: number;
  changedFilesCount: number;
  filesTouched: string[];
  toolBoundaryEvents: number;
  /** 0-100. */
  confidence: number | null;
  guardResults: GuardReceiptSummary[];

  receipt: Receipt | null;

  /** Sentinel ID if backed by one. Format: `sen_{ulid}`. */
  sentinelId: string | null;

  createdAt: number;
  updatedAt: number;
  exitCode: number | null;
}

export type TaskPriority = "critical" | "high" | "normal" | "low" | "background";

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

/** A unit of work assigned to an agent in the swarm engine. */
export interface Task {
  /** Format: `tsk_{ulid}`. */
  id: string;
  swarmEngineId: string;
  type: TaskType;
  name: string;
  description: string;
  priority: TaskPriority;
  status: TaskStatus;
  sequence: number;

  assignedTo: string | null;
  dependencies: string[];

  input: Record<string, unknown>;
  output: Record<string, unknown> | null;

  /** 0 means no timeout. */
  timeoutMs: number;
  retries: number;
  maxRetries: number;

  taskPrompt: string | null;
  previewLines: string[];
  huntId: string | null;
  artifactIds: string[];

  receipt: Receipt | null;

  metadata: Record<string, unknown>;

  createdAt: number;
  startedAt: number | null;
  completedAt: number | null;
  updatedAt: number;
}

export type TopologyType = "mesh" | "hierarchical" | "centralized" | "hybrid" | "adaptive";

export type TopologyNodeRole = "queen" | "worker" | "coordinator" | "peer";

export type TopologyNodeStatus = "active" | "inactive" | "syncing" | "failed";

export interface TopologyConfig {
  type: TopologyType;
  maxAgents: number;
  replicationFactor: number;
  partitionStrategy: "hash" | "range" | "round-robin";
  failoverEnabled: boolean;
  autoRebalance: boolean;
}

/** Used for both orchestration routing and React Flow layout. */
export interface TopologyNode {
  id: string;
  agentId: string;
  role: TopologyNodeRole;
  status: TopologyNodeStatus;
  connections: string[];
  metadata: Record<string, unknown>;

  /** Null if auto-layout. */
  positionX: number | null;
  /** Null if auto-layout. */
  positionY: number | null;
  /** 0 = root/queen. Null for mesh topologies. */
  hierarchyDepth: number | null;
}

export interface TopologyEdge {
  from: string;
  to: string;
  /** Lower = preferred. */
  weight: number;
  bidirectional: boolean;
  latencyMs: number | null;
  edgeType: "handoff" | "spawned" | "artifact" | "receipt" | "topology";
}

export interface TopologyPartition {
  id: string;
  nodeIds: string[];
  leaderId: string;
  replicaCount: number;
}

/** Serializable topology snapshot. */
export interface TopologyState {
  type: TopologyType;
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  leaderId: string | null;
  partitions: TopologyPartition[];
  snapshotAt: number;
}

export type ConsensusAlgorithm = "raft" | "byzantine" | "gossip" | "paxos";

export interface ConsensusConfig {
  algorithm: ConsensusAlgorithm;
  /** 0.0-1.0 */
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

export interface ConsensusProposal {
  /** Format: `csn_{ulid}`. */
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
  receipt: Receipt | null;
}

export type SwarmEngineChannel =
  | "agent_lifecycle"
  | "task_orchestration"
  | "topology"
  | "consensus"
  | "memory"
  | "hooks";

export interface GuardEvaluationResult {
  verdict: Verdict;
  /** Derived from verdict !== "deny". */
  allowed: boolean;
  guardResults: GuardSimResult[];
  receipt: Receipt;
  durationMs: number;
  evaluatedAt: number;
}

export interface GuardedAction {
  agentId: string;
  taskId: string | null;
  actionType: TestActionType;
  /** File path, URL, command, etc. */
  target: string;
  context: Record<string, unknown>;
  requestedAt: number;
}

/** Audit record: request + guard decision + execution outcome. */
export interface GuardedActionRecord {
  action: GuardedAction;
  evaluation: GuardEvaluationResult;
  /** May be false even if allowed. */
  executed: boolean;
  executionError: string | null;
}

/**
 * Injected by the host into the SwarmOrchestrator.
 * When missing, the orchestrator falls back to deny-all (fail-closed).
 */
export interface GuardEvaluator {
  evaluate(action: GuardedAction): Promise<GuardEvaluationResult>;
}

export interface AgentPoolConfig {
  name: string;
  minSize: number;
  maxSize: number;
  scaleUpThreshold: number;
  scaleDownThreshold: number;
  cooldownMs: number;
  healthCheckIntervalMs: number;
}

export interface AgentPoolState {
  config: AgentPoolConfig;
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
  availableCount: number;
  busyCount: number;
  utilization: number;
  pendingScale: number;
  lastScaleOperation: number | null;
}

/** Published to coordination channel when an envelope is denied. */
export interface DenyNotification {
  action: "envelope_denied";
  originalChannel: SwarmEngineChannel;
  originalAction: string;
  receiptId: string;
  verdict: "deny";
  decidingGuard: string;
  sender: string;
  timestamp: number;
}

export type SwarmEngineStatus =
  | "initializing"
  | "running"
  | "paused"
  | "recovering"
  | "shutting_down"
  | "stopped"
  | "failed";

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

/** Serializable root state for persistence and transport. */
export interface SwarmEngineState {
  /** Format: `swe_{ulid}`. */
  id: string;
  namespace: string;
  version: string;
  status: SwarmEngineStatus;
  topologyConfig: TopologyConfig;
  topology: TopologyState;
  consensusConfig: ConsensusConfig;
  agents: Record<string, AgentSession>;
  tasks: Record<string, Task>;
  activeProposals: Record<string, ConsensusProposal>;
  metrics: SwarmEngineMetrics;
  recentGuardActions: GuardedActionRecord[];
  maxGuardActionHistory: number;

  createdAt: number;
  startedAt: number | null;
  updatedAt: number;
}

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

export const SWARM_ENGINE_CONSTANTS = Object.freeze({
  DEFAULT_HEARTBEAT_INTERVAL_MS: 5_000,
  PROTOCOL_HEARTBEAT_INTERVAL_MS: 10_000,
  DEFAULT_HEALTH_CHECK_INTERVAL_MS: 10_000,
  DEFAULT_TASK_TIMEOUT_MS: 300_000,
  DEFAULT_CONSENSUS_TIMEOUT_MS: 30_000,
  DEFAULT_MESSAGE_TTL_MS: 60_000,
  DEFAULT_MAX_AGENTS: 100,
  DEFAULT_MAX_TASKS: 1_000,
  DEFAULT_CONSENSUS_THRESHOLD: 0.66,
  MAX_QUEUE_SIZE: 10_000,
  MAX_RETRIES: 3,
  COORDINATION_LATENCY_TARGET_MS: 100,
  MESSAGES_PER_SECOND_TARGET: 1_000,
  MAX_GUARD_ACTION_HISTORY: 500,
  HEALTH_FAILOVER_THRESHOLD: 0.3,
});

/** Base for all orchestration payloads. `receipt` is absent until guard evaluation. */
export interface GuardedPayload {
  action: string;
  receipt?: EnvelopeReceipt;
  sender: string;
  correlationId?: string;
}

/** Compact receipt for inline transport. Full receipt retrievable by receiptId from the ledger. */
export interface EnvelopeReceipt {
  receiptId: string;
  verdict: Verdict;
  /** Empty string if no guard matched. */
  decidingGuard: string;
  policyHash: string;
  evaluationMs: number;
  /** Ed25519 signature over (receiptId + verdict + policyHash). Hex-encoded. */
  signature: string;
  /** Hex-encoded. */
  publicKey: string;
  evaluatedAt: number;
}
