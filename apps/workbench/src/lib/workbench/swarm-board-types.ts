// ---------------------------------------------------------------------------
// SwarmBoard Types — node/edge/state definitions for the React Flow board
// ---------------------------------------------------------------------------

import type { Node } from "@xyflow/react";

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

export type SessionStatus = "idle" | "running" | "blocked" | "completed" | "failed";
export type RiskLevel = "low" | "medium" | "high";

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
  huntId?: string;
  artifactIds?: string[];
  createdAt?: number;
  // Clawdstrike-native metadata (Section 8.5)
  toolBoundaryEvents?: number;
  filesTouched?: string[];
  confidence?: number; // 0-100
  // Receipt nodes
  verdict?: "allow" | "deny" | "warn";
  guardResults?: Array<{ guard: string; allowed: boolean; duration_ms?: number }>;
  // Diff nodes
  diffSummary?: { added: number; removed: number; files: string[] };
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
}

// ---------------------------------------------------------------------------
// Edge types
// ---------------------------------------------------------------------------

export interface SwarmBoardEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  type?: "handoff" | "spawned" | "artifact" | "receipt";
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
  inspectorOpen: boolean;
}
