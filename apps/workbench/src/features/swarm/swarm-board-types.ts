// ---------------------------------------------------------------------------
// SwarmBoard Types — node/edge/state definitions for the React Flow board
// ---------------------------------------------------------------------------

import type { Node } from "@xyflow/react";
import type { AgentConversationTurn } from "@clawdstrike/swarm-engine";
import type { FileType } from "@/lib/workbench/file-type-registry";
import type { Receipt } from "@/lib/workbench/types";

// ---------------------------------------------------------------------------
// Enums / tagged unions
// ---------------------------------------------------------------------------

export type SwarmNodeType =
  | "agentSession"
  | "terminalTask"
  | "artifact"
  | "diff"
  | "note"
  | "receipt";

export type SessionStatus = "idle" | "running" | "blocked" | "completed" | "failed" | "evaluating";
export type RiskLevel = "low" | "medium" | "high";
export type SessionPersistenceMode = "direct" | "tmux";
export type SessionRecoveryState = "fresh" | "recoverable" | "recovered";

// ---------------------------------------------------------------------------
// Node data payload — a single superset shared across all node types.
// Each node type uses the subset of fields relevant to it.
// ---------------------------------------------------------------------------

export interface SwarmBoardNodeData {
  /** Index signature required by React Flow's Record<string, unknown> constraint */
  [key: string]: unknown;
  title: string;
  status: SessionStatus;
  nodeType: SwarmNodeType;
  sessionId?: string;
  sessionPersistence?: SessionPersistenceMode;
  sessionRecoveryState?: SessionRecoveryState;
  terminalAttached?: boolean;
  manualSession?: boolean;
  sessionShell?: string;
  worktreePath?: string;
  branch?: string;
  previewLines?: string[];
  receiptCount?: number;
  blockedActionCount?: number;
  changedFilesCount?: number;
  risk?: RiskLevel;
  policyMode?: string;
  agentModel?: string;
  taskPrompt?: string;
  dependencyTaskIds?: string[];
  blockingTaskIds?: string[];
  huntId?: string;
  artifactIds?: string[];
  createdAt?: number;
  // Clawdstrike-native metadata (Section 8.5)
  toolBoundaryEvents?: number;
  filesTouched?: string[];
  confidence?: number; // 0-100
  conversationHistory?: AgentConversationTurn[];
  // Receipt nodes
  verdict?: "allow" | "deny" | "warn";
  guardResults?: Array<{ guard: string; allowed: boolean; duration_ms?: number }>;
  /** Hex-encoded Ed25519 signature from the receipt. */
  signature?: string;
  /** Hex-encoded Ed25519 public key from the receipt signer. */
  publicKey?: string;
  /** Verification status: true = verified, false = failed, undefined = not yet checked. */
  signatureVerified?: boolean;
  /** Full receipt payload retained so the inspector can verify the exact signed content. */
  receiptData?: Receipt;
  // Diff nodes
  diffSummary?: { added: number; removed: number; files: string[] };
  diffContent?: string;
  diffPath?: string;
  // Artifact nodes
  filePath?: string;
  fileType?: string;
  // Note nodes
  content?: string;
  // Session lifecycle
  exitCode?: number | null;
  // UI state
  maximized?: boolean;
  editing?: boolean;
  // Detection workflow metadata — optional extensions
  artifactKind?: "detection_rule" | "evidence_pack" | "lab_run" | "conversion_output" | "publication_manifest";
  documentId?: string;
  evidencePackId?: string;
  labRunId?: string;
  publicationId?: string;
  /** Engine-managed agent ID (from @clawdstrike/swarm-engine AgentRegistry). */
  agentId?: string;
  /** Engine-managed task ID (from @clawdstrike/swarm-engine TaskGraph). */
  taskId?: string;
  /** True if this node was created by the engine bridge (not manual). */
  engineManaged?: boolean;
  format?: FileType;
  publishState?: "draft" | "validated" | "published" | "deployed";
  coverageDelta?: { added: string[]; removed: string[] };
}

/** The set of detection artifact kinds a SwarmBoardNode can represent. */
export type DetectionArtifactKind = NonNullable<SwarmBoardNodeData["artifactKind"]>;

// ---------------------------------------------------------------------------
// Edge types
// ---------------------------------------------------------------------------

export interface SwarmBoardEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  type?: "handoff" | "spawned" | "artifact" | "receipt" | "topology" | "dependency";
}

// ---------------------------------------------------------------------------
// Board state
// ---------------------------------------------------------------------------

export interface SwarmBoardState {
  boardId: string;
  repoRoot: string;
  nodes: Node<SwarmBoardNodeData>[];
  edges: SwarmBoardEdge[];
  selectedNodeId: string | null;
  selectedNodeIds: string[];
  inspectorOpen: boolean;
  fileWatchRevision: number;
  /** Absolute path to the .swarm bundle directory, or empty string for scratch boards. */
  bundlePath: string;
}
