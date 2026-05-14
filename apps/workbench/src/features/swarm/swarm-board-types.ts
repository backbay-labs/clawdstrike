import type { Node } from "@xyflow/react";
import type { FileType } from "@/lib/workbench/file-type-registry";

export type SwarmNodeType =
  | "agentSession"
  | "terminalTask"
  | "artifact"
  | "diff"
  | "note"
  | "receipt";

export type SessionStatus = "idle" | "running" | "blocked" | "completed" | "failed" | "evaluating";
export type RiskLevel = "low" | "medium" | "high";

export interface SwarmBoardNodeData {
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
  toolBoundaryEvents?: number;
  filesTouched?: string[];
  confidence?: number;
  verdict?: "allow" | "deny" | "warn";
  guardResults?: Array<{ guard: string; allowed: boolean; duration_ms?: number }>;
  signature?: string;
  publicKey?: string;
  signatureVerified?: boolean;
  diffSummary?: { added: number; removed: number; files: string[] };
  filePath?: string;
  fileType?: string;
  content?: string;
  exitCode?: number | null;
  maximized?: boolean;
  editing?: boolean;
  artifactKind?: "detection_rule" | "evidence_pack" | "lab_run" | "conversion_output" | "publication_manifest";
  documentId?: string;
  evidencePackId?: string;
  labRunId?: string;
  publicationId?: string;
  agentId?: string;
  taskId?: string;
  engineManaged?: boolean;
  format?: FileType;
  publishState?: "draft" | "validated" | "published" | "deployed";
  coverageDelta?: { added: string[]; removed: string[] };
}

export type DetectionArtifactKind = NonNullable<SwarmBoardNodeData["artifactKind"]>;

export interface SwarmBoardEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  type?: "handoff" | "spawned" | "artifact" | "receipt" | "topology";
}

export interface SwarmBoardState {
  boardId: string;
  repoRoot: string;
  nodes: Node<SwarmBoardNodeData>[];
  edges: SwarmBoardEdge[];
  selectedNodeId: string | null;
  inspectorOpen: boolean;
  bundlePath: string;
}
