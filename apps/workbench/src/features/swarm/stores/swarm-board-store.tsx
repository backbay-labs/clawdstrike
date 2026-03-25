// ---------------------------------------------------------------------------
// SwarmBoard Store — Zustand store with createSelectors for board CRUD
//
// Migrated from React Context + useReducer to Zustand, matching the
// swarm-store.tsx / swarm-feed-store.tsx pattern. The Zustand store is
// globally accessible (no provider tree required for read-only access).
//
// SwarmBoardProvider is kept as a thin wrapper that manages:
// - Auto-detect repoRoot on mount (terminalService.getCwd)
// - Session spawn/kill lifecycle (PTY refs, exit monitoring, worktrees)
// - Session context (spawn/kill methods via SwarmBoardSessionContext)
//
// The existing useSwarmBoard() hook composes Zustand store + session context
// for backward compatibility.
// ---------------------------------------------------------------------------
import {
  createContext,
  useContext,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  type ReactNode,
} from "react";
import { create } from "zustand";
import { useShallow } from "zustand/react/shallow";
import { createSelectors } from "@/lib/create-selectors";
import { MarkerType, type Node, type Edge } from "@xyflow/react";
import { isDesktop } from "@/lib/tauri-bridge";
import type {
  SwarmBoardNodeData,
  SwarmBoardEdge,
  SwarmBoardState,
  SwarmNodeType,
  SessionStatus,
  RiskLevel,
} from "@/features/swarm/swarm-board-types";
import type { Receipt } from "@/lib/workbench/types";
import { terminalService, worktreeService } from "@/lib/workbench/terminal-service";
import type { UnlistenFn } from "@tauri-apps/api/event";
import {
  SWARM_BOARD_PERSISTENCE_FILE,
  readSwarmPersistencePayload,
  writeSwarmPersistencePayload,
} from "./swarm-persistence";
import {
  clearSwarmFileWatchScope,
  normalizeSwarmFileWatchPath,
  setSwarmFileWatchScope,
  subscribeSwarmFileWatchEvents,
} from "./swarm-file-watch";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum number of live xterm terminals to keep active simultaneously. */
export const MAX_ACTIVE_TERMINALS = 8;
/** Maximum number of total persistent sessions to keep on the board. */
export const MAX_TOTAL_SESSIONS = 64;
/** Keep persisted replay history bounded so board snapshots stay durable. */
const MAX_PERSISTED_AGENT_CONVERSATION_TURNS = 200;

export type ReceiptPostureState = "neutral" | "allow" | "warn" | "deny";

export interface ReceiptPostureSummary {
  totalReceipts: number;
  totalSignals: number;
  allowCount: number;
  warnCount: number;
  denyCount: number;
  allowRatio: number;
  warnRatio: number;
  denyRatio: number;
  dominantState: ReceiptPostureState;
}

export interface GuardPolicySummary {
  guard: string;
  receiptCount: number;
  totalEvaluations: number;
  allowCount: number;
  warnCount: number;
  denyCount: number;
  allowRatio: number;
  warnRatio: number;
  denyRatio: number;
  averageLatencyMs: number | null;
  maxLatencyMs: number | null;
}

export interface GuardPolicyHeatmapSummary {
  totalReceipts: number;
  receiptsWithGuards: number;
  totalEvaluations: number;
  uniqueGuards: number;
  allowCount: number;
  warnCount: number;
  denyCount: number;
  guards: GuardPolicySummary[];
}

// ---------------------------------------------------------------------------
// Legacy Action type — kept for backward compat type exports
// ---------------------------------------------------------------------------

export type SwarmBoardAction =
  | { type: "ADD_NODE"; node: Node<SwarmBoardNodeData> }
  | { type: "REMOVE_NODE"; nodeId: string }
  | { type: "UPDATE_NODE"; nodeId: string; patch: Partial<SwarmBoardNodeData> }
  | { type: "SET_NODES"; nodes: Node<SwarmBoardNodeData>[] }
  | { type: "ADD_EDGE"; edge: SwarmBoardEdge }
  | { type: "REMOVE_EDGE"; edgeId: string }
  | { type: "SET_EDGES"; edges: SwarmBoardEdge[] }
  | { type: "SELECT_NODE"; nodeId: string | null }
  | { type: "TOGGLE_INSPECTOR"; open?: boolean }
  | { type: "SET_REPO_ROOT"; repoRoot: string }
  | { type: "LOAD"; state: Partial<SwarmBoardState> }
  | { type: "CLEAR_BOARD" }
  | { type: "SET_SESSION_STATUS"; sessionId: string; status: SessionStatus; exitCode?: number }
  | { type: "SET_SESSION_METADATA"; sessionId: string; metadata: Partial<SwarmBoardNodeData> }
  | { type: "TOPOLOGY_LAYOUT"; topology: string; positions: Map<string, { x: number; y: number }> }
  | { type: "ENGINE_SYNC"; engineNodes: Array<{ id: string; agentId?: string; taskId?: string; data: Partial<SwarmBoardNodeData>; position?: { x: number; y: number } }>; engineEdges: SwarmBoardEdge[] }
  | { type: "GUARD_EVALUATE"; agentNodeId: string; verdict: string; guardResults: Array<{ guard: string; allowed: boolean; duration_ms?: number }>; receipt?: Receipt };

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

const STORAGE_KEY = "clawdstrike_workbench_swarm_board";
let boardPersistenceReady = typeof window === "undefined" || !isDesktop();
let boardHydratePromise: Promise<void> | null = null;

function isAbsoluteFilePath(path: string): boolean {
  return path.startsWith("/") || /^[A-Za-z]:[\\/]/.test(path);
}

function joinFilePath(root: string, path: string): string {
  const safeRoot = root.replace(/[\\/]+$/, "");
  const safePath = path.replace(/^[\\/]+/, "");
  return `${safeRoot}/${safePath}`;
}

export function resolveBoardWatchFilePath(
  filePath: string | undefined,
  repoRoot: string,
): string | null {
  if (!filePath) {
    return null;
  }
  const trimmed = filePath.trim();
  if (!trimmed) {
    return null;
  }
  if (isAbsoluteFilePath(trimmed)) {
    return normalizeSwarmFileWatchPath(trimmed);
  }
  if (!repoRoot) {
    return null;
  }
  return normalizeSwarmFileWatchPath(joinFilePath(repoRoot, trimmed));
}

export function collectBoardWatchWorkspacePaths(
  nodes: Array<Node<SwarmBoardNodeData>>,
  repoRoot: string,
  bundlePath: string,
): string[] {
  const paths = new Set<string>();

  if (bundlePath) {
    paths.add(normalizeSwarmFileWatchPath(`${bundlePath}/board.json`));
  }

  for (const node of nodes) {
    const data = node.data as SwarmBoardNodeData;
    const artifactPath = resolveBoardWatchFilePath(
      typeof data.filePath === "string" ? data.filePath : undefined,
      repoRoot,
    );
    if (artifactPath) {
      paths.add(artifactPath);
    }

    const diffPath = resolveBoardWatchFilePath(
      typeof data.diffPath === "string" ? data.diffPath : undefined,
      repoRoot,
    );
    if (diffPath) {
      paths.add(diffPath);
    }
  }

  return Array.from(paths).sort();
}

interface PersistedBoardPayload {
  boardId: string;
  repoRoot: string;
  nodes: Node<SwarmBoardNodeData>[];
  edges: SwarmBoardEdge[];
}

function truncateConversationHistory(
  history: SwarmBoardNodeData["conversationHistory"],
): SwarmBoardNodeData["conversationHistory"] {
  if (!Array.isArray(history)) {
    return undefined;
  }
  if (history.length <= MAX_PERSISTED_AGENT_CONVERSATION_TURNS) {
    return history;
  }
  return history.slice(-MAX_PERSISTED_AGENT_CONVERSATION_TURNS);
}

function sanitizePersistedNode(
  node: Node<SwarmBoardNodeData>,
): Node<SwarmBoardNodeData> {
  const data: SwarmBoardNodeData = {
    ...node.data,
    conversationHistory: truncateConversationHistory(node.data?.conversationHistory),
  };

  if (data.engineManaged) {
    data.branch = undefined;
    data.worktreePath = undefined;
    data.filesTouched = undefined;
    data.previewLines = undefined;
    data.taskPrompt = undefined;
  }

  return {
    ...node,
    data,
  };
}

function isRecoverableTmuxNode(data: SwarmBoardNodeData | undefined): boolean {
  return Boolean(data?.sessionId && data.sessionPersistence === "tmux");
}

function buildSessionMetadataPatch(
  session: {
    branch: string | null;
    shell: string;
    persistence_mode: "direct" | "tmux";
    recovery_state: "fresh" | "recoverable" | "recovered";
  },
  options?: {
    manualSession?: boolean;
    terminalAttached?: boolean;
  },
): Partial<SwarmBoardNodeData> {
  return {
    branch: session.branch ?? undefined,
    sessionShell: session.shell,
    sessionPersistence: session.persistence_mode,
    sessionRecoveryState: session.recovery_state,
    ...(options?.manualSession !== undefined
      ? { manualSession: options.manualSession }
      : {}),
    ...(options?.terminalAttached !== undefined
      ? { terminalAttached: options.terminalAttached }
      : {}),
  };
}

function normalizePersistedBoard(parsed: unknown): Partial<SwarmBoardState> | null {
  if (
    !parsed ||
    typeof parsed !== "object" ||
    !Array.isArray((parsed as { nodes?: unknown }).nodes) ||
    !Array.isArray((parsed as { edges?: unknown }).edges)
  ) {
    return null;
  }

  const record = parsed as PersistedBoardPayload;

  const validNodes = record.nodes.filter(
    (n): n is Node<SwarmBoardNodeData> =>
      typeof n === "object" &&
      n !== null &&
      typeof (n as Record<string, unknown>).id === "string" &&
      typeof (n as Record<string, unknown>).position === "object" &&
      typeof (n as Record<string, unknown>).data === "object",
  );

  const validEdges = record.edges.filter(
    (e): e is SwarmBoardEdge =>
      typeof e === "object" &&
      e !== null &&
      typeof (e as unknown as Record<string, unknown>).id === "string" &&
      typeof (e as unknown as Record<string, unknown>).source === "string" &&
      typeof (e as unknown as Record<string, unknown>).target === "string",
  );

  if (validNodes.length === 0) return null;

  const sanitizedNodes = validNodes.map((n) => {
    const sanitizedNode = sanitizePersistedNode(n);
    if (!sanitizedNode.data?.sessionId) {
      return sanitizedNode;
    }

    if (isRecoverableTmuxNode(sanitizedNode.data)) {
      return {
        ...sanitizedNode,
        data: {
          ...sanitizedNode.data,
          terminalAttached: false,
          manualSession: true,
          sessionRecoveryState: "recoverable",
        },
      } as Node<SwarmBoardNodeData>;
    }

    return {
      ...sanitizedNode,
      data: {
        ...sanitizedNode.data,
        sessionId: undefined,
        terminalAttached: false,
        sessionPersistence: "direct",
        sessionRecoveryState: "fresh",
        status:
          sanitizedNode.data.status === "running"
            ? "idle"
            : sanitizedNode.data.status,
      },
    } as Node<SwarmBoardNodeData>;
  });

  return {
    boardId: typeof record.boardId === "string" ? record.boardId : generateBoardId(),
    repoRoot: typeof record.repoRoot === "string" ? record.repoRoot : "",
    nodes: sanitizedNodes,
    edges: validEdges,
  };
}

function serializePersistedBoard(state: SwarmBoardState): PersistedBoardPayload {
  return {
    boardId: state.boardId,
    repoRoot: state.repoRoot,
    nodes: state.nodes.map((node) => sanitizePersistedNode(node)),
    edges: state.edges,
  };
}

function persistBoard(state: SwarmBoardState): void {
  try {
    const persisted = serializePersistedBoard(state);
    if (isDesktop()) {
      void writeSwarmPersistencePayload(SWARM_BOARD_PERSISTENCE_FILE, persisted).then((ok) => {
        if (!ok) {
          console.error("[swarm-board-store] disk persist failed");
        }
      });
    } else {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(persisted));
    }

    // File-backed persistence for .swarm bundles
    if (state.bundlePath) {
      import("@/lib/tauri-bridge").then(({ writeSwarmBoardJson }) => {
        writeSwarmBoardJson(
          state.bundlePath,
          persisted as unknown as Record<string, unknown>,
        ).catch((err: unknown) => {
          console.error("[swarm-board-store] file persist failed:", err);
        });
      }).catch(() => {
        // Not in Tauri environment
      });
    }
  } catch (e) {
    console.error("[swarm-board-store] persistBoard failed:", e);
  }
}

function loadPersistedBoard(): Partial<SwarmBoardState> | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    return normalizePersistedBoard(JSON.parse(raw));
  } catch (e) {
    console.warn("[swarm-board-store] loadPersistedBoard failed:", e);
    return null;
  }
}

// ---------------------------------------------------------------------------
// ID generators
// ---------------------------------------------------------------------------

let nodeCounter = 0;

const AUTH_CHANGES_DIFF = `diff --git a/src/middleware/auth.rs b/src/middleware/auth.rs
index 91c8f76..5f14219 100644
--- a/src/middleware/auth.rs
+++ b/src/middleware/auth.rs
@@ -1,7 +1,13 @@
 use crate::middleware::token::TokenClaims;
+use crate::middleware::rate_limit::RateLimitContext;

 pub fn validate_token(token: &str) -> Result<TokenClaims, AuthError> {
-    decode_token(token)
+    let claims = decode_token(token)?;
+    if claims.expired() {
+        return Err(AuthError::ExpiredToken);
+    }
+
+    Ok(claims)
 }
diff --git a/tests/auth_test.rs b/tests/auth_test.rs
index 321aa77..611ae21 100644
--- a/tests/auth_test.rs
+++ b/tests/auth_test.rs
@@ -12,3 +12,7 @@ fn validates_token() {}

 #[test]
 fn validates_token() {}
+
+#[test]
+fn rejects_expired_token() {}
`;

function resolveReceiptPosture(data: SwarmBoardNodeData): Exclude<ReceiptPostureState, "neutral"> | null {
  if (data.verdict === "allow" || data.verdict === "warn" || data.verdict === "deny") {
    return data.verdict;
  }

  const guardResults = data.guardResults ?? [];
  if (guardResults.some((guard) => !guard.allowed)) {
    return "deny";
  }
  if (guardResults.length > 0) {
    return "allow";
  }

  return null;
}

function resolveGuardPolicyVerdict(
  receipt: SwarmBoardNodeData,
  guardResult: { allowed: boolean },
): Exclude<ReceiptPostureState, "neutral"> {
  if (!guardResult.allowed) {
    return "deny";
  }

  // Board-level guard results do not encode warn directly, so warning receipts
  // treat otherwise-allowed guard evaluations as warning posture.
  return receipt.verdict === "warn" ? "warn" : "allow";
}

export function summarizeReceiptPosture(
  nodes: Array<Node<SwarmBoardNodeData>>,
): ReceiptPostureSummary {
  let totalReceipts = 0;
  let allowCount = 0;
  let warnCount = 0;
  let denyCount = 0;

  for (const node of nodes) {
    const data = node.data as SwarmBoardNodeData;
    if (data.nodeType !== "receipt") {
      continue;
    }

    totalReceipts += 1;
    const posture = resolveReceiptPosture(data);
    if (posture === "allow") {
      allowCount += 1;
    } else if (posture === "warn") {
      warnCount += 1;
    } else if (posture === "deny") {
      denyCount += 1;
    }
  }

  const totalSignals = allowCount + warnCount + denyCount;
  const dominantState: ReceiptPostureState =
    denyCount > 0 && denyCount >= warnCount && denyCount >= allowCount
      ? "deny"
      : warnCount > 0 && warnCount >= allowCount
        ? "warn"
        : allowCount > 0
          ? "allow"
          : "neutral";

  return {
    totalReceipts,
    totalSignals,
    allowCount,
    warnCount,
    denyCount,
    allowRatio: totalSignals > 0 ? allowCount / totalSignals : 0,
    warnRatio: totalSignals > 0 ? warnCount / totalSignals : 0,
    denyRatio: totalSignals > 0 ? denyCount / totalSignals : 0,
    dominantState,
  };
}

export function summarizeGuardPolicyHeatmap(
  nodes: Array<Node<SwarmBoardNodeData>>,
): GuardPolicyHeatmapSummary {
  const guardMap = new Map<
    string,
    {
      receiptIds: Set<string>;
      totalEvaluations: number;
      allowCount: number;
      warnCount: number;
      denyCount: number;
      latencyTotalMs: number;
      latencySamples: number;
      maxLatencyMs: number | null;
    }
  >();

  let totalReceipts = 0;
  let receiptsWithGuards = 0;
  let totalEvaluations = 0;
  let allowCount = 0;
  let warnCount = 0;
  let denyCount = 0;

  for (const node of nodes) {
    const data = node.data as SwarmBoardNodeData;
    if (data.nodeType !== "receipt") {
      continue;
    }

    totalReceipts += 1;
    const guardResults = data.guardResults ?? [];
    if (guardResults.length === 0) {
      continue;
    }

    receiptsWithGuards += 1;

    for (const guardResult of guardResults) {
      const entry = guardMap.get(guardResult.guard) ?? {
        receiptIds: new Set<string>(),
        totalEvaluations: 0,
        allowCount: 0,
        warnCount: 0,
        denyCount: 0,
        latencyTotalMs: 0,
        latencySamples: 0,
        maxLatencyMs: null,
      };

      entry.receiptIds.add(node.id);
      entry.totalEvaluations += 1;
      totalEvaluations += 1;

      const verdict = resolveGuardPolicyVerdict(data, guardResult);
      if (verdict === "allow") {
        entry.allowCount += 1;
        allowCount += 1;
      } else if (verdict === "warn") {
        entry.warnCount += 1;
        warnCount += 1;
      } else {
        entry.denyCount += 1;
        denyCount += 1;
      }

      if (typeof guardResult.duration_ms === "number") {
        entry.latencyTotalMs += guardResult.duration_ms;
        entry.latencySamples += 1;
        entry.maxLatencyMs =
          entry.maxLatencyMs == null
            ? guardResult.duration_ms
            : Math.max(entry.maxLatencyMs, guardResult.duration_ms);
      }

      guardMap.set(guardResult.guard, entry);
    }
  }

  const guards = Array.from(guardMap.entries())
    .map(([guard, entry]): GuardPolicySummary => ({
      guard,
      receiptCount: entry.receiptIds.size,
      totalEvaluations: entry.totalEvaluations,
      allowCount: entry.allowCount,
      warnCount: entry.warnCount,
      denyCount: entry.denyCount,
      allowRatio: entry.totalEvaluations > 0 ? entry.allowCount / entry.totalEvaluations : 0,
      warnRatio: entry.totalEvaluations > 0 ? entry.warnCount / entry.totalEvaluations : 0,
      denyRatio: entry.totalEvaluations > 0 ? entry.denyCount / entry.totalEvaluations : 0,
      averageLatencyMs:
        entry.latencySamples > 0 ? entry.latencyTotalMs / entry.latencySamples : null,
      maxLatencyMs: entry.maxLatencyMs,
    }))
    .sort((left, right) => {
      if (right.totalEvaluations !== left.totalEvaluations) {
        return right.totalEvaluations - left.totalEvaluations;
      }
      if (right.denyCount !== left.denyCount) {
        return right.denyCount - left.denyCount;
      }
      if (right.warnCount !== left.warnCount) {
        return right.warnCount - left.warnCount;
      }
      return left.guard.localeCompare(right.guard);
    });

  return {
    totalReceipts,
    receiptsWithGuards,
    totalEvaluations,
    uniqueGuards: guards.length,
    allowCount,
    warnCount,
    denyCount,
    guards,
  };
}

function generateBoardId(): string {
  return `board-${Date.now().toString(36)}`;
}

export function generateNodeId(prefix: string = "sbn"): string {
  nodeCounter += 1;
  return `${prefix}-${Date.now().toString(36)}-${nodeCounter}`;
}

// ---------------------------------------------------------------------------
// Node factory
// ---------------------------------------------------------------------------

export interface CreateNodeConfig {
  nodeType: SwarmNodeType;
  title: string;
  position?: { x: number; y: number };
  data?: Partial<SwarmBoardNodeData>;
}

export function createBoardNode(config: CreateNodeConfig): Node<SwarmBoardNodeData> {
  const id = generateNodeId(config.nodeType);
  const position = config.position ?? {
    x: 100 + Math.random() * 400,
    y: 100 + Math.random() * 300,
  };

  const defaults: SwarmBoardNodeData = {
    title: config.title,
    status: "idle",
    nodeType: config.nodeType,
    createdAt: Date.now(),
  };

  // Dimension defaults per node type
  const dimensions: Record<SwarmNodeType, { width?: number; height?: number }> = {
    agentSession: { width: 380, height: 280 },
    terminalTask: { width: 300, height: 180 },
    artifact: { width: 240, height: 100 },
    diff: { width: 280, height: 180 },
    note: { width: 260, height: 160 },
    receipt: { width: 300, height: 220 },
  };

  const dims = dimensions[config.nodeType];

  return {
    id,
    type: config.nodeType,
    position,
    data: { ...defaults, ...config.data },
    ...(dims.width ? { width: dims.width } : {}),
    ...(dims.height ? { height: dims.height } : {}),
  };
}

// ---------------------------------------------------------------------------
// Mock data seeder
// ---------------------------------------------------------------------------

export function createMockBoard(): {
  nodes: Node<SwarmBoardNodeData>[];
  edges: SwarmBoardEdge[];
} {
  const agent1 = createBoardNode({
    nodeType: "agentSession",
    title: "Fix auth middleware",
    position: { x: 80, y: 60 },
    data: {
      agentModel: "opus-4.6",
      branch: "feat/fix-auth",
      status: "running",
      worktreePath: "/home/user/project/.worktrees/fix-auth",
      previewLines: [
        "$ cargo test -p auth-middleware",
        "running 12 tests...",
        "test middleware::validate_token ... ok",
        "test middleware::refresh_expired ... ok",
        "test middleware::reject_malformed ... FAILED",
        "--- analyzing failure ---",
      ],
      receiptCount: 7,
      blockedActionCount: 1,
      changedFilesCount: 4,
      risk: "medium",
      policyMode: "strict",
      toolBoundaryEvents: 23,
      filesTouched: [
        "src/middleware/auth.rs",
        "src/middleware/token.rs",
        "tests/auth_test.rs",
        "Cargo.toml",
      ],
      confidence: 72,
      huntId: "hunt-sec-audit",
    },
  });

  const agent2 = createBoardNode({
    nodeType: "agentSession",
    title: "Add rate limiter",
    position: { x: 560, y: 60 },
    data: {
      agentModel: "sonnet-4",
      branch: "feat/rate-limit",
      status: "completed",
      worktreePath: "/home/user/project/.worktrees/rate-limit",
      previewLines: [
        "$ cargo clippy --workspace",
        "Checking rate-limiter v0.1.0",
        'Finished `dev` profile target(s)',
        "All checks passed.",
      ],
      receiptCount: 12,
      blockedActionCount: 0,
      changedFilesCount: 6,
      risk: "low",
      policyMode: "default",
      toolBoundaryEvents: 41,
      filesTouched: [
        "src/rate_limiter/mod.rs",
        "src/rate_limiter/sliding_window.rs",
        "src/rate_limiter/config.rs",
        "tests/rate_limiter_test.rs",
        "Cargo.toml",
        "docs/rate-limiting.md",
      ],
      confidence: 95,
      huntId: "hunt-sec-audit",
    },
  });

  const agent3 = createBoardNode({
    nodeType: "agentSession",
    title: "Investigate CVE-2026-1234",
    position: { x: 1040, y: 60 },
    data: {
      agentModel: "opus-4.6",
      branch: "security/cve-2026-1234",
      status: "blocked",
      worktreePath: "/home/user/project/.worktrees/cve-fix",
      previewLines: [
        "$ clawdstrike check --action-type file --ruleset strict",
        "DENIED: write to /etc/shadow blocked by ForbiddenPathGuard",
        "Waiting for operator approval...",
      ],
      receiptCount: 3,
      blockedActionCount: 2,
      changedFilesCount: 1,
      risk: "high",
      policyMode: "strict",
      toolBoundaryEvents: 8,
      confidence: 35,
    },
  });

  const task1 = createBoardNode({
    nodeType: "terminalTask",
    title: "Run integration tests",
    position: { x: 80, y: 400 },
    data: {
      status: "running",
      taskPrompt: "Execute the full integration test suite and report failures",
    },
  });

  const receipt1 = createBoardNode({
    nodeType: "receipt",
    title: "File write check",
    position: { x: 560, y: 400 },
    data: {
      status: "completed",
      verdict: "allow",
      guardResults: [
        { guard: "ForbiddenPathGuard", allowed: true, duration_ms: 2 },
        { guard: "SecretLeakGuard", allowed: true, duration_ms: 8 },
        { guard: "PatchIntegrityGuard", allowed: true, duration_ms: 3 },
      ],
      receiptCount: 1,
    },
  });

  const receipt2 = createBoardNode({
    nodeType: "receipt",
    title: "Shell exec denied",
    position: { x: 1040, y: 400 },
    data: {
      status: "completed",
      verdict: "deny",
      guardResults: [
        { guard: "ShellCommandGuard", allowed: false, duration_ms: 1 },
        { guard: "ForbiddenPathGuard", allowed: false, duration_ms: 2 },
        { guard: "SpiderSenseGuard", allowed: true, duration_ms: 15 },
      ],
      receiptCount: 1,
    },
  });

  const diff1 = createBoardNode({
    nodeType: "diff",
    title: "Auth changes",
    position: { x: 340, y: 400 },
    data: {
      status: "idle",
      diffSummary: {
        added: 8,
        removed: 1,
        files: [
          "src/middleware/auth.rs",
          "tests/auth_test.rs",
        ],
      },
      diffContent: AUTH_CHANGES_DIFF,
    },
  });

  const artifact1 = createBoardNode({
    nodeType: "artifact",
    title: "auth.rs",
    position: { x: 340, y: 220 },
    data: {
      status: "idle",
      filePath: "src/middleware/auth.rs",
      fileType: "rust",
    },
  });

  const artifact2 = createBoardNode({
    nodeType: "artifact",
    title: "sliding_window.rs",
    position: { x: 860, y: 340 },
    data: {
      status: "idle",
      filePath: "src/rate_limiter/sliding_window.rs",
      fileType: "rust",
    },
  });

  const note1 = createBoardNode({
    nodeType: "note",
    title: "Coordination notes",
    position: { x: 860, y: 120 },
    data: {
      status: "idle",
      content:
        "Agent 1 owns auth middleware changes.\nAgent 2 owns rate limiter.\nAgent 3 investigating CVE — blocked, needs operator review.\n\nMerge order: rate-limiter first, then auth.",
    },
  });

  const nodes = [agent1, agent2, agent3, task1, receipt1, receipt2, diff1, artifact1, artifact2, note1];

  const edges: SwarmBoardEdge[] = [
    {
      id: `edge-${agent1.id}-${task1.id}`,
      source: agent1.id,
      target: task1.id,
      type: "spawned",
      label: "spawned",
    },
    {
      id: `edge-${agent1.id}-${artifact1.id}`,
      source: agent1.id,
      target: artifact1.id,
      type: "artifact",
      label: "produces",
    },
    {
      id: `edge-${agent1.id}-${diff1.id}`,
      source: agent1.id,
      target: diff1.id,
      type: "artifact",
    },
    {
      id: `edge-${agent2.id}-${receipt1.id}`,
      source: agent2.id,
      target: receipt1.id,
      type: "receipt",
      label: "receipt",
    },
    {
      id: `edge-${agent2.id}-${artifact2.id}`,
      source: agent2.id,
      target: artifact2.id,
      type: "artifact",
      label: "produces",
    },
    {
      id: `edge-${agent3.id}-${receipt2.id}`,
      source: agent3.id,
      target: receipt2.id,
      type: "receipt",
      label: "denied",
    },
    {
      id: `edge-${agent1.id}-${agent2.id}`,
      source: agent1.id,
      target: agent2.id,
      type: "handoff",
      label: "handoff",
    },
  ];

  return { nodes, edges };
}

// ---------------------------------------------------------------------------
// Edge color helper
// ---------------------------------------------------------------------------

function edgeColor(type?: SwarmBoardEdge["type"]): string {
  switch (type) {
    case "handoff":
      return "#5b8def";
    case "spawned":
      return "#d4a84b";
    case "dependency":
      return "#7085ad";
    case "artifact":
      return "#3dbf84";
    case "receipt":
      return "#8b5cf6";
    case "topology":
      return "#3d4250";
    default:
      return "#2d3240";
  }
}

// ---------------------------------------------------------------------------
// Convert SwarmBoardEdge[] to React Flow Edge[]
// ---------------------------------------------------------------------------

function toRfEdges(edges: SwarmBoardEdge[]): Edge[] {
  return edges.map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    label: e.label,
    type: "swarmEdge",
    data: { edgeType: e.type },
    animated: e.type === "spawned",
    style: { stroke: edgeColor(e.type) },
    markerEnd:
      e.type === "handoff" || e.type === "spawned" || e.type === "dependency"
        ? { type: MarkerType.ArrowClosed, color: edgeColor(e.type) }
        : undefined,
  }));
}

// ---------------------------------------------------------------------------
// Debounced persistence
// ---------------------------------------------------------------------------

let _persistTimer: ReturnType<typeof setTimeout> | null = null;

function schedulePersist(state: SwarmBoardState): void {
  if (!boardPersistenceReady) {
    return;
  }
  if (_persistTimer) clearTimeout(_persistTimer);
  _persistTimer = setTimeout(() => {
    persistBoard(state);
    _persistTimer = null;
  }, 500);
}

// ---------------------------------------------------------------------------
// Initial state
// ---------------------------------------------------------------------------

function getInitialState(): SwarmBoardState {
  const persisted = loadPersistedBoard();
  if (persisted && persisted.nodes && persisted.nodes.length > 0) {
    return {
      boardId: persisted.boardId ?? generateBoardId(),
      repoRoot: persisted.repoRoot ?? "",
      nodes: persisted.nodes as Node<SwarmBoardNodeData>[],
      edges: (persisted.edges ?? []) as SwarmBoardEdge[],
      selectedNodeId: null,
      selectedNodeIds: [],
      inspectorOpen: false,
      fileWatchRevision: 0,
      bundlePath: "",
    };
  }

  // Start with an empty board — users create real sessions via "Launch Swarm"
  return {
    boardId: generateBoardId(),
    repoRoot: "",
    nodes: [],
    edges: [],
    selectedNodeId: null,
    selectedNodeIds: [],
    inspectorOpen: false,
    fileWatchRevision: 0,
    bundlePath: "",
  };
}

// ---------------------------------------------------------------------------
// Zustand store type
// ---------------------------------------------------------------------------

interface SwarmBoardStoreState extends SwarmBoardState {
  // Derived state
  selectedNode: Node<SwarmBoardNodeData> | undefined;
  selectedNodes: Node<SwarmBoardNodeData>[];
  comparisonMode: boolean;
  rfEdges: Edge[];

  // Actions namespace (matching swarm-store.tsx pattern)
  actions: {
    addNode: (config: CreateNodeConfig) => Node<SwarmBoardNodeData>;
    addNodeDirect: (node: Node<SwarmBoardNodeData>) => void;
    removeNode: (nodeId: string) => void;
    updateNode: (nodeId: string, patch: Partial<SwarmBoardNodeData>) => void;
    updateNodeRecord: (
      nodeId: string,
      patch: Omit<Partial<Node<SwarmBoardNodeData>>, "id" | "data"> & {
        data?: Partial<SwarmBoardNodeData>;
      },
    ) => Node<SwarmBoardNodeData> | undefined;
    selectNode: (nodeId: string | null) => void;
    setSelectedNodeIds: (ids: string[]) => void;
    addEdge: (edge: SwarmBoardEdge) => void;
    removeEdge: (edgeId: string) => void;
    clearBoard: () => void;
    setRepoRoot: (repoRoot: string) => void;
    loadState: (state: Partial<SwarmBoardState>) => void;
    setSessionStatus: (sessionId: string, status: SessionStatus, exitCode?: number) => void;
    setSessionMetadata: (sessionId: string, metadata: Partial<SwarmBoardNodeData>) => void;
    setNodes: (nodes: Node<SwarmBoardNodeData>[]) => void;
    setEdges: (edges: SwarmBoardEdge[]) => void;
    toggleInspector: (open?: boolean) => void;
    loadFromBundle: (bundlePath: string) => Promise<void>;
    topologyLayout: (topology: string, positions: Map<string, { x: number; y: number }>) => void;
    engineSync: (engineNodes: Array<{ id: string; agentId?: string; taskId?: string; data: Partial<SwarmBoardNodeData>; position?: { x: number; y: number } }>, engineEdges: SwarmBoardEdge[]) => void;
    guardEvaluate: (agentNodeId: string, verdict: string, guardResults: Array<{ guard: string; allowed: boolean; duration_ms?: number }>, receipt?: Receipt) => void;
  };
}

// ---------------------------------------------------------------------------
// Derived helpers
// ---------------------------------------------------------------------------

function deriveSelectedNode(
  nodes: Node<SwarmBoardNodeData>[],
  selectedNodeId: string | null,
): Node<SwarmBoardNodeData> | undefined {
  return selectedNodeId ? nodes.find((n) => n.id === selectedNodeId) : undefined;
}

function deriveSelectedNodes(
  nodes: Node<SwarmBoardNodeData>[],
  selectedNodeIds: string[],
): Node<SwarmBoardNodeData>[] {
  if (selectedNodeIds.length === 0) return [];
  const idSet = new Set(selectedNodeIds);
  return nodes.filter((n) => idSet.has(n.id));
}

function receiptCreatedAt(receipt: Receipt | undefined): number | undefined {
  if (!receipt) {
    return undefined;
  }

  const timestamp = Date.parse(receipt.timestamp);
  return Number.isFinite(timestamp) ? timestamp : undefined;
}

// ---------------------------------------------------------------------------
// Zustand store
// ---------------------------------------------------------------------------

const initialState = getInitialState();

const useSwarmBoardStoreBase = create<SwarmBoardStoreState>()((set, get) => ({
  ...initialState,
  selectedNode: deriveSelectedNode(initialState.nodes, initialState.selectedNodeId),
  selectedNodes: deriveSelectedNodes(initialState.nodes, initialState.selectedNodeIds),
  comparisonMode: initialState.selectedNodeIds.length > 1,
  rfEdges: toRfEdges(initialState.edges),

  actions: {
    addNode: (config: CreateNodeConfig): Node<SwarmBoardNodeData> => {
      const node = createBoardNode(config);
      const current = get();
      // Prevent duplicates
      if (current.nodes.some((n) => n.id === node.id)) return node;
      const nodes = [...current.nodes, node];
      set({
        nodes,
        selectedNode: deriveSelectedNode(nodes, current.selectedNodeId),
        selectedNodes: deriveSelectedNodes(nodes, current.selectedNodeIds),
        comparisonMode: current.selectedNodeIds.length > 1,
      });
      schedulePersist({ ...get() });
      return node;
    },

    addNodeDirect: (node: Node<SwarmBoardNodeData>): void => {
      const current = get();
      if (current.nodes.some((n) => n.id === node.id)) return;
      const nodes = [...current.nodes, node];
      set({
        nodes,
        selectedNode: deriveSelectedNode(nodes, current.selectedNodeId),
        selectedNodes: deriveSelectedNodes(nodes, current.selectedNodeIds),
        comparisonMode: current.selectedNodeIds.length > 1,
      });
      schedulePersist({ ...get() });
    },

    removeNode: (nodeId: string): void => {
      const current = get();
      const nodes = current.nodes.filter((n) => n.id !== nodeId);
      const edges = current.edges.filter(
        (e) => e.source !== nodeId && e.target !== nodeId,
      );
      const selectedNodeId = current.selectedNodeId === nodeId ? null : current.selectedNodeId;
      const inspectorOpen = current.selectedNodeId === nodeId ? false : current.inspectorOpen;
      const selectedNodeIds = current.selectedNodeIds.filter((id) => id !== nodeId);
      set({
        nodes,
        edges,
        selectedNodeId,
        selectedNodeIds,
        inspectorOpen,
        selectedNode: deriveSelectedNode(nodes, selectedNodeId),
        selectedNodes: deriveSelectedNodes(nodes, selectedNodeIds),
        comparisonMode: selectedNodeIds.length > 1,
        rfEdges: toRfEdges(edges),
      });
      schedulePersist({ ...get() });
    },

    updateNode: (nodeId: string, patch: Partial<SwarmBoardNodeData>): void => {
      const current = get();
      const nodes = current.nodes.map((n) =>
        n.id === nodeId ? { ...n, data: { ...n.data, ...patch } } : n,
      );
      set({
        nodes,
        selectedNode: deriveSelectedNode(nodes, current.selectedNodeId),
        selectedNodes: deriveSelectedNodes(nodes, current.selectedNodeIds),
        comparisonMode: current.selectedNodeIds.length > 1,
      });
      schedulePersist({ ...get() });
    },

    updateNodeRecord: (
      nodeId: string,
      patch: Omit<Partial<Node<SwarmBoardNodeData>>, "id" | "data"> & {
        data?: Partial<SwarmBoardNodeData>;
      },
    ): Node<SwarmBoardNodeData> | undefined => {
      const current = get();
      let updatedNode: Node<SwarmBoardNodeData> | undefined;
      const nodes = current.nodes.map((node) => {
        if (node.id !== nodeId) {
          return node;
        }

        updatedNode = {
          ...node,
          ...patch,
          data: patch.data ? { ...node.data, ...patch.data } : node.data,
          id: node.id,
        };
        return updatedNode;
      });

      if (!updatedNode) {
        return undefined;
      }

      set({
        nodes,
        selectedNode: deriveSelectedNode(nodes, current.selectedNodeId),
        selectedNodes: deriveSelectedNodes(nodes, current.selectedNodeIds),
        comparisonMode: current.selectedNodeIds.length > 1,
      });
      schedulePersist({ ...get() });
      return updatedNode;
    },

    selectNode: (nodeId: string | null): void => {
      const current = get();
      const nodes = current.nodes;
      set({
        selectedNodeId: nodeId,
        inspectorOpen: nodeId !== null,
        selectedNode: deriveSelectedNode(nodes, nodeId),
      });
    },

    setSelectedNodeIds: (ids: string[]): void => {
      const current = get();
      const nodes = current.nodes;
      const selectedNodes = deriveSelectedNodes(nodes, ids);
      const comparisonMode = ids.length > 1;

      // Backward compat: sync selectedNodeId for single selection
      const selectedNodeId = ids.length === 1 ? ids[0] : (ids.length === 0 ? null : current.selectedNodeId);
      const inspectorOpen = ids.length > 0;

      set({
        selectedNodeIds: ids,
        selectedNodes,
        comparisonMode,
        selectedNodeId,
        inspectorOpen,
        selectedNode: deriveSelectedNode(nodes, selectedNodeId),
      });
    },

    addEdge: (edge: SwarmBoardEdge): void => {
      const current = get();
      if (current.edges.some((e) => e.id === edge.id)) return;
      const edges = [...current.edges, edge];
      set({
        edges,
        rfEdges: toRfEdges(edges),
      });
      schedulePersist({ ...get() });
    },

    removeEdge: (edgeId: string): void => {
      const current = get();
      const edges = current.edges.filter((e) => e.id !== edgeId);
      set({
        edges,
        rfEdges: toRfEdges(edges),
      });
      schedulePersist({ ...get() });
    },

    clearBoard: (): void => {
      set({
        nodes: [],
        edges: [],
        selectedNodeId: null,
        selectedNodeIds: [],
        inspectorOpen: false,
        selectedNode: undefined,
        selectedNodes: [],
        comparisonMode: false,
        rfEdges: [],
      });
      schedulePersist({ ...get() });
    },

    setRepoRoot: (repoRoot: string): void => {
      set({ repoRoot });
      schedulePersist({ ...get() });
    },

    loadState: (partial: Partial<SwarmBoardState>): void => {
      const current = get();
      const nodes = partial.nodes ?? current.nodes;
      const edges = partial.edges ?? current.edges;
      const selectedNodeIds = partial.selectedNodeIds ?? current.selectedNodeIds;
      set({
        ...partial,
        nodes,
        edges,
        selectedNodeIds,
        selectedNode: deriveSelectedNode(nodes, partial.selectedNodeId ?? current.selectedNodeId),
        selectedNodes: deriveSelectedNodes(nodes, selectedNodeIds),
        comparisonMode: selectedNodeIds.length > 1,
        rfEdges: toRfEdges(edges),
      });
      schedulePersist({ ...get() });
    },

    setSessionStatus: (sessionId: string, status: SessionStatus, exitCode?: number): void => {
      const current = get();
      const nodes = current.nodes.map((n) => {
        const d = n.data as SwarmBoardNodeData;
        if (d.sessionId === sessionId) {
          return {
            ...n,
            data: {
              ...d,
              status,
              ...(exitCode !== undefined ? { exitCode } : {}),
            },
          };
        }
        return n;
      });
      set({
        nodes,
        selectedNode: deriveSelectedNode(nodes, current.selectedNodeId),
        selectedNodes: deriveSelectedNodes(nodes, current.selectedNodeIds),
        comparisonMode: current.selectedNodeIds.length > 1,
      });
      schedulePersist({ ...get() });
    },

    setSessionMetadata: (sessionId: string, metadata: Partial<SwarmBoardNodeData>): void => {
      const current = get();
      const nodes = current.nodes.map((n) => {
        const d = n.data as SwarmBoardNodeData;
        if (d.sessionId === sessionId) {
          return { ...n, data: { ...d, ...metadata } };
        }
        return n;
      });
      set({
        nodes,
        selectedNode: deriveSelectedNode(nodes, current.selectedNodeId),
        selectedNodes: deriveSelectedNodes(nodes, current.selectedNodeIds),
        comparisonMode: current.selectedNodeIds.length > 1,
      });
      schedulePersist({ ...get() });
    },

    setNodes: (nodes: Node<SwarmBoardNodeData>[]): void => {
      const current = get();
      set({
        nodes,
        selectedNode: deriveSelectedNode(nodes, current.selectedNodeId),
        selectedNodes: deriveSelectedNodes(nodes, current.selectedNodeIds),
        comparisonMode: current.selectedNodeIds.length > 1,
      });
      schedulePersist({ ...get() });
    },

    setEdges: (edges: SwarmBoardEdge[]): void => {
      set({
        edges,
        rfEdges: toRfEdges(edges),
      });
      schedulePersist({ ...get() });
    },

    toggleInspector: (open?: boolean): void => {
      const current = get();
      const isOpen = open ?? !current.inspectorOpen;
      set({
        inspectorOpen: isOpen,
        selectedNodeId: isOpen ? current.selectedNodeId : null,
        selectedNode: isOpen
          ? deriveSelectedNode(current.nodes, current.selectedNodeId)
          : undefined,
      });
    },

    loadFromBundle: async (bundlePath: string): Promise<void> => {
      boardPersistenceReady = false;
      try {
        const { readSwarmBundle } = await import("@/lib/tauri-bridge");
        const data = await readSwarmBundle(bundlePath);
        if (!data?.board) {
          // Empty bundle — just set the path, keep empty board
          set({ bundlePath, fileWatchRevision: 0 });
          boardPersistenceReady = true;
          return;
        }
        const board = data.board as Record<string, unknown>;
        const normalized = normalizePersistedBoard({
          boardId: typeof board.boardId === "string" ? board.boardId : generateBoardId(),
          repoRoot: typeof board.repoRoot === "string" ? board.repoRoot : "",
          nodes: Array.isArray(board.nodes) ? board.nodes as Node<SwarmBoardNodeData>[] : [],
          edges: Array.isArray(board.edges) ? board.edges as SwarmBoardEdge[] : [],
        });
        const nodes = (normalized?.nodes ?? []) as Node<SwarmBoardNodeData>[];
        const edges = (normalized?.edges ?? []) as SwarmBoardEdge[];
        const boardId = normalized?.boardId ?? generateBoardId();
        const repoRoot = normalized?.repoRoot ?? "";
        set({
          bundlePath,
          boardId,
          repoRoot,
          nodes,
          edges,
          selectedNodeId: null,
          selectedNodeIds: [],
          inspectorOpen: false,
          fileWatchRevision: 0,
          selectedNode: undefined,
          selectedNodes: [],
          comparisonMode: false,
          rfEdges: toRfEdges(edges),
        });
        boardPersistenceReady = true;
      } catch (err) {
        console.error("[swarm-board-store] loadFromBundle failed:", err);
        set({ bundlePath, fileWatchRevision: 0 });
        boardPersistenceReady = true;
      }
    },

    topologyLayout: (_topology: string, positions: Map<string, { x: number; y: number }>): void => {
      const current = get();
      const nodes = current.nodes.map((n) => {
        const pos = positions.get(n.id);
        return pos ? { ...n, position: pos } : n;
      });
      set({
        nodes,
        selectedNode: deriveSelectedNode(nodes, current.selectedNodeId),
        selectedNodes: deriveSelectedNodes(nodes, current.selectedNodeIds),
        comparisonMode: current.selectedNodeIds.length > 1,
      });
      schedulePersist({ ...get() });
    },

    engineSync: (
      engineNodes: Array<{ id: string; agentId?: string; taskId?: string; data: Partial<SwarmBoardNodeData>; position?: { x: number; y: number } }>,
      engineEdges: SwarmBoardEdge[],
    ): void => {
      const current = get();
      const lookup = new Map(engineNodes.map((en) => [en.id, en]));
      const nodes = current.nodes
        .filter((n) => {
          const data = n.data as SwarmBoardNodeData;
          return !(data.engineManaged && data.nodeType !== "receipt" && !lookup.has(n.id));
        })
        .map((n) => {
        const d = n.data as SwarmBoardNodeData;
        const eng = lookup.get(n.id);
        if (d.engineManaged && eng) {
          return {
            ...n,
            data: { ...d, ...eng.data, agentId: eng.agentId, taskId: eng.taskId },
            position: eng.position ?? n.position,
          };
        }
        return n;
      });

      // Add new engine nodes that are not already present
      const existingIds = new Set(nodes.map((n) => n.id));
      for (const en of engineNodes) {
        if (!existingIds.has(en.id)) {
          const newNode = createBoardNode({
            nodeType: (en.data.nodeType as SwarmBoardNodeData["nodeType"]) ?? "agentSession",
            title: (en.data.title as string) ?? en.id,
            position: en.position,
            data: { ...en.data, agentId: en.agentId, taskId: en.taskId, engineManaged: true },
          });
          // Override the generated id with the engine-provided id
          nodes.push({ ...newNode, id: en.id });
        }
      }

      const snapshotManagedEdgeTypes = new Set<SwarmBoardEdge["type"]>([
        "spawned",
        "dependency",
        "topology",
      ]);
      const preservedEdges = current.edges.filter(
        (edge) => !snapshotManagedEdgeTypes.has(edge.type ?? "handoff"),
      );
      const nodeIds = new Set(nodes.map((node) => node.id));
      const edgesById = new Map<string, SwarmBoardEdge>();
      for (const edge of preservedEdges) {
        edgesById.set(edge.id, edge);
      }
      for (const edge of engineEdges) {
        edgesById.set(edge.id, edge);
      }
      const edges = Array.from(edgesById.values()).filter(
        (edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target),
      );
      const selectedNodeId = current.selectedNodeId && nodes.some((n) => n.id === current.selectedNodeId)
        ? current.selectedNodeId
        : null;
      const nodeIdSet = new Set(nodes.map((n) => n.id));
      const selectedNodeIds = current.selectedNodeIds.filter((id) => nodeIdSet.has(id));

      set({
        nodes,
        edges,
        rfEdges: toRfEdges(edges),
        selectedNodeId,
        selectedNodeIds,
        selectedNode: deriveSelectedNode(nodes, selectedNodeId),
        selectedNodes: deriveSelectedNodes(nodes, selectedNodeIds),
        comparisonMode: selectedNodeIds.length > 1,
      });
      schedulePersist({ ...get() });
    },

    guardEvaluate: (
      agentNodeId: string,
      verdict: string,
      guardResults: Array<{ guard: string; allowed: boolean; duration_ms?: number }>,
      receipt?: Receipt,
    ): void => {
      const current = get();
      const agentNode = current.nodes.find((n) => n.id === agentNodeId);
      if (!agentNode) return;

      // Dedup: skip if a receipt with the same signature already exists
      if (receipt?.signature) {
        const duplicate = current.nodes.some(
          (n) => (n.data as SwarmBoardNodeData).nodeType === "receipt" &&
                 (n.data as SwarmBoardNodeData).signature === receipt.signature,
        );
        if (duplicate) return;
      }

      const receiptNode = createBoardNode({
        nodeType: "receipt",
        title: `Guard: ${verdict.toUpperCase()}`,
        position: { x: agentNode.position.x, y: agentNode.position.y + 340 },
        data: {
          ...(receiptCreatedAt(receipt) != null
            ? { createdAt: receiptCreatedAt(receipt) }
            : {}),
          verdict: verdict as "allow" | "deny" | "warn",
          guardResults,
          signature: receipt?.signature,
          publicKey: receipt?.publicKey,
          receiptData: receipt,
          status: "completed",
          engineManaged: true,
        },
      });

      const nodes = [...current.nodes, receiptNode];
      const receiptEdge: SwarmBoardEdge = {
        id: `edge-receipt-${receiptNode.id}-${agentNodeId}`,
        source: agentNodeId,
        target: receiptNode.id,
        type: "receipt",
        label: verdict,
      };
      const edges = [...current.edges, receiptEdge];

      set({
        nodes,
        edges,
        rfEdges: toRfEdges(edges),
        selectedNode: deriveSelectedNode(nodes, current.selectedNodeId),
        selectedNodes: deriveSelectedNodes(nodes, current.selectedNodeIds),
        comparisonMode: current.selectedNodeIds.length > 1,
      });
      schedulePersist({ ...get() });
    },
  },
}));

// Expose getInitialState and reinitialize for test reset / provider mount
function reinitializeFromStorage(): void {
  boardPersistenceReady = !isDesktop();
  const fresh = getInitialState();
  useSwarmBoardStoreBase.setState({
    ...fresh,
    selectedNodeId: null,
    selectedNodeIds: [],
    selectedNode: deriveSelectedNode(fresh.nodes, fresh.selectedNodeId),
    selectedNodes: [],
    comparisonMode: false,
    rfEdges: toRfEdges(fresh.edges),
  });
  if (isDesktop()) {
    void hydrateSwarmBoardFromDisk(true);
  }
}

const storeWithInitialState = Object.assign(useSwarmBoardStoreBase, {
  getInitialState,
  reinitializeFromStorage,
});

export const useSwarmBoardStore = createSelectors(storeWithInitialState);

async function hydrateSwarmBoardFromDisk(force = false): Promise<void> {
  if (!isDesktop()) {
    boardPersistenceReady = true;
    return;
  }
  if (boardHydratePromise && !force) {
    return boardHydratePromise;
  }

  boardHydratePromise = (async () => {
    const legacy = loadPersistedBoard();
    const payload = await readSwarmPersistencePayload(SWARM_BOARD_PERSISTENCE_FILE);
    const restored = normalizePersistedBoard(payload) ?? legacy;

    if (restored?.nodes && restored.nodes.length > 0) {
      const edges = (restored.edges ?? []) as SwarmBoardEdge[];
      const nodes = restored.nodes as Node<SwarmBoardNodeData>[];
      useSwarmBoardStoreBase.setState({
        boardId: restored.boardId ?? generateBoardId(),
        repoRoot: restored.repoRoot ?? "",
        nodes,
        edges,
        selectedNodeId: null,
        selectedNodeIds: [],
        inspectorOpen: false,
        fileWatchRevision: 0,
        bundlePath: "",
        selectedNode: undefined,
        selectedNodes: [],
        comparisonMode: false,
        rfEdges: toRfEdges(edges),
      });
    }

    boardPersistenceReady = true;

    if (!payload && legacy) {
      schedulePersist(useSwarmBoardStoreBase.getState());
    }
  })().finally(() => {
    boardHydratePromise = null;
  });

  return boardHydratePromise;
}

// ---------------------------------------------------------------------------
// Session context (spawn/kill — needs mutable refs + Tauri callbacks)
// ---------------------------------------------------------------------------

export interface SpawnSessionOptions {
  cwd: string;
  position?: { x: number; y: number };
  launchClaude?: boolean;
  title?: string;
  shell?: string;
  command?: string;
}

export interface SpawnClaudeSessionOptions {
  cwd?: string;
  position?: { x: number; y: number };
  prompt?: string;
  worktree?: boolean;
  branch?: string;
  title?: string;
}

export interface SpawnWorktreeSessionOptions {
  position?: { x: number; y: number };
  branch?: string;
  title?: string;
  shell?: string;
}

interface SwarmBoardSessionContextValue {
  spawnSession: (opts: SpawnSessionOptions) => Promise<Node<SwarmBoardNodeData>>;
  spawnClaudeSession: (opts: SpawnClaudeSessionOptions) => Promise<Node<SwarmBoardNodeData>>;
  spawnWorktreeSession: (opts: SpawnWorktreeSessionOptions) => Promise<Node<SwarmBoardNodeData>>;
  killSession: (nodeId: string) => Promise<void>;
}

const SwarmBoardSessionContext = createContext<SwarmBoardSessionContextValue | null>(null);

// ---------------------------------------------------------------------------
// Backward-compatible context value shape
// ---------------------------------------------------------------------------

interface SwarmBoardContextValue {
  state: SwarmBoardState;
  dispatch: (action: SwarmBoardAction) => void;
  addNode: (config: CreateNodeConfig) => Node<SwarmBoardNodeData>;
  removeNode: (nodeId: string) => void;
  updateNode: (nodeId: string, patch: Partial<SwarmBoardNodeData>) => void;
  selectNode: (nodeId: string | null) => void;
  addEdge: (edge: SwarmBoardEdge) => void;
  removeEdge: (edgeId: string) => void;
  clearBoard: () => void;
  selectedNode: Node<SwarmBoardNodeData> | undefined;
  selectedNodes: Node<SwarmBoardNodeData>[];
  comparisonMode: boolean;
  rfEdges: Edge[];
  spawnSession: (opts: SpawnSessionOptions) => Promise<Node<SwarmBoardNodeData>>;
  spawnClaudeSession: (opts: SpawnClaudeSessionOptions) => Promise<Node<SwarmBoardNodeData>>;
  spawnWorktreeSession: (opts: SpawnWorktreeSessionOptions) => Promise<Node<SwarmBoardNodeData>>;
  killSession: (nodeId: string) => Promise<void>;
}

// ---------------------------------------------------------------------------
// Dispatch shim — routes legacy dispatch calls to Zustand actions
// ---------------------------------------------------------------------------

function createDispatchShim(): (action: SwarmBoardAction) => void {
  return (action: SwarmBoardAction) => {
    const { actions } = useSwarmBoardStore.getState();
    switch (action.type) {
      case "ADD_NODE":
        actions.addNodeDirect(action.node);
        break;
      case "REMOVE_NODE":
        actions.removeNode(action.nodeId);
        break;
      case "UPDATE_NODE":
        actions.updateNode(action.nodeId, action.patch);
        break;
      case "SET_NODES":
        actions.setNodes(action.nodes);
        break;
      case "ADD_EDGE":
        actions.addEdge(action.edge);
        break;
      case "REMOVE_EDGE":
        actions.removeEdge(action.edgeId);
        break;
      case "SET_EDGES":
        actions.setEdges(action.edges);
        break;
      case "SELECT_NODE":
        actions.selectNode(action.nodeId);
        break;
      case "TOGGLE_INSPECTOR":
        actions.toggleInspector(action.open);
        break;
      case "SET_REPO_ROOT":
        actions.setRepoRoot(action.repoRoot);
        break;
      case "LOAD":
        actions.loadState(action.state);
        break;
      case "CLEAR_BOARD":
        actions.clearBoard();
        break;
      case "SET_SESSION_STATUS":
        actions.setSessionStatus(action.sessionId, action.status, action.exitCode);
        break;
      case "SET_SESSION_METADATA":
        actions.setSessionMetadata(action.sessionId, action.metadata);
        break;
      case "TOPOLOGY_LAYOUT":
        actions.topologyLayout(action.topology, action.positions);
        break;
      case "ENGINE_SYNC":
        actions.engineSync(action.engineNodes, action.engineEdges);
        break;
      case "GUARD_EVALUATE":
        actions.guardEvaluate(action.agentNodeId, action.verdict, action.guardResults, action.receipt);
        break;
    }
  };
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useSwarmBoard(): SwarmBoardContextValue {
  const state = useSwarmBoardStore(
    useShallow((s) => ({
      boardId: s.boardId,
      repoRoot: s.repoRoot,
      nodes: s.nodes,
      edges: s.edges,
      selectedNodeId: s.selectedNodeId,
      inspectorOpen: s.inspectorOpen,
      fileWatchRevision: s.fileWatchRevision,
      bundlePath: s.bundlePath,
    })),
  );
  const selectedNode = useSwarmBoardStore((s) => s.selectedNode);
  const selectedNodes = useSwarmBoardStore((s) => s.selectedNodes);
  const comparisonMode = useSwarmBoardStore((s) => s.comparisonMode);
  const rfEdges = useSwarmBoardStore((s) => s.rfEdges);
  const actions = useSwarmBoardStore((s) => s.actions);

  // Session context (may be null if called outside SwarmBoardProvider)
  const sessionCtx = useContext(SwarmBoardSessionContext);

  const dispatch = useMemo(() => createDispatchShim(), []);

  const noopSession = useMemo(
    () => ({
      spawnSession: () =>
        Promise.reject(new Error("useSwarmBoard must be used within SwarmBoardProvider for session management")),
      spawnClaudeSession: () =>
        Promise.reject(new Error("useSwarmBoard must be used within SwarmBoardProvider for session management")),
      spawnWorktreeSession: () =>
        Promise.reject(new Error("useSwarmBoard must be used within SwarmBoardProvider for session management")),
      killSession: () =>
        Promise.reject(new Error("useSwarmBoard must be used within SwarmBoardProvider for session management")),
    }),
    [],
  );

  const sessionMethods = sessionCtx ?? noopSession;

  return useMemo(
    () => ({
      state,
      dispatch,
      addNode: actions.addNode,
      removeNode: actions.removeNode,
      updateNode: actions.updateNode,
      selectNode: actions.selectNode,
      addEdge: actions.addEdge,
      removeEdge: actions.removeEdge,
      clearBoard: actions.clearBoard,
      selectedNode,
      selectedNodes,
      comparisonMode,
      rfEdges,
      ...sessionMethods,
    }),
    [state, dispatch, actions, selectedNode, selectedNodes, comparisonMode, rfEdges, sessionMethods],
  );
}

// ---------------------------------------------------------------------------
// Provider — thin wrapper for session lifecycle
// ---------------------------------------------------------------------------

export function SwarmBoardProvider({ children, bundlePath }: { children: ReactNode; bundlePath?: string }) {
  const boardNodes = useSwarmBoardStore((s) => s.nodes);
  const repoRoot = useSwarmBoardStore((s) => s.repoRoot);
  const activeBundlePath = useSwarmBoardStore((s) => s.bundlePath);
  const selectedNode = useSwarmBoardStore((s) => s.selectedNode);
  const watchScopeIdRef = useRef(`swarm-board-${Math.random().toString(36).slice(2)}`);
  const workspaceWatchPaths = useMemo(
    () => collectBoardWatchWorkspacePaths(boardNodes, repoRoot, activeBundlePath),
    [activeBundlePath, boardNodes, repoRoot],
  );
  const persistenceWatchFilenames = useMemo(
    () => (activeBundlePath ? [] : [SWARM_BOARD_PERSISTENCE_FILE]),
    [activeBundlePath],
  );
  const workspaceWatchSignature = workspaceWatchPaths.join("\n");
  const persistenceWatchSignature = persistenceWatchFilenames.join("\n");
  const recoverableSessionSignature = useMemo(
    () =>
      boardNodes
        .filter((node) => {
          const data = node.data as SwarmBoardNodeData;
          return data.nodeType === "agentSession" && isRecoverableTmuxNode(data) && !data.terminalAttached;
        })
        .map((node) => {
          const data = node.data as SwarmBoardNodeData;
          return `${node.id}:${data.sessionId ?? ""}:${data.sessionRecoveryState ?? ""}`;
        })
        .sort()
        .join("\n"),
    [boardNodes],
  );

  // Re-initialize store from localStorage on mount (scratch boards),
  // or load from .swarm bundle when bundlePath is provided.
  useEffect(() => {
    if (bundlePath) {
      useSwarmBoardStore.getState().actions.loadFromBundle(bundlePath);
    } else {
      useSwarmBoardStore.reinitializeFromStorage();
    }
  }, [bundlePath]);

  // Auto-detect repoRoot on mount if empty
  useEffect(() => {
    const state = useSwarmBoardStore.getState();
    if (state.repoRoot) return;
    terminalService
      .getCwd()
      .then((cwd) => {
        if (cwd) {
          useSwarmBoardStore.getState().actions.setRepoRoot(cwd);
        }
      })
      .catch(() => {
        // Not in Tauri or command failed
      });
  }, []);

  useEffect(() => {
    if (!isDesktop()) {
      return;
    }

    const scopeId = watchScopeIdRef.current;
    void setSwarmFileWatchScope(scopeId, {
      persistenceFilenames: persistenceWatchFilenames,
      workspacePaths: workspaceWatchPaths,
    });

    return () => {
      void clearSwarmFileWatchScope(scopeId);
    };
  }, [persistenceWatchSignature, workspaceWatchSignature]);

  useEffect(() => {
    if (!isDesktop()) {
      return;
    }

    return subscribeSwarmFileWatchEvents((event) => {
      const current = useSwarmBoardStore.getState();

      if (
        event.category === "persistence" &&
        !current.bundlePath &&
        event.filenames.includes(SWARM_BOARD_PERSISTENCE_FILE)
      ) {
        void hydrateSwarmBoardFromDisk(true);
        return;
      }

      const bundleBoardPath = current.bundlePath
        ? normalizeSwarmFileWatchPath(`${current.bundlePath}/board.json`)
        : null;
      if (
        bundleBoardPath &&
        event.paths.some((path) => normalizeSwarmFileWatchPath(path) === bundleBoardPath)
      ) {
        void current.actions.loadFromBundle(current.bundlePath);
        return;
      }

      if (event.category !== "workspace") {
        return;
      }

      const watchedPaths = new Set(
        collectBoardWatchWorkspacePaths(current.nodes, current.repoRoot, current.bundlePath),
      );
      const hasRelevantWorkspaceChange = event.paths.some((path) =>
        watchedPaths.has(normalizeSwarmFileWatchPath(path)),
      );

      if (hasRelevantWorkspaceChange) {
        useSwarmBoardStoreBase.setState((state) => ({
          fileWatchRevision: state.fileWatchRevision + 1,
        }));
      }
    });
  }, []);

  // Track exit listeners and worktree paths for cleanup
  const exitListenersRef = useRef<Map<string, UnlistenFn>>(new Map());
  const worktreeMapRef = useRef<Map<string, string>>(new Map());
  const closedSessionsRef = useRef<Set<string>>(new Set());
  const killingRef = useRef<Set<string>>(new Set());
  const reconnectingRef = useRef<Set<string>>(new Set());

  const cleanupSessionTracking = useCallback((sessionId: string): string | undefined => {
    closedSessionsRef.current.add(sessionId);
    const unlisten = exitListenersRef.current.get(sessionId);
    if (unlisten) {
      try {
        unlisten();
      } catch {
        // best-effort cleanup
      }
    }
    exitListenersRef.current.delete(sessionId);
    const wtPath = worktreeMapRef.current.get(sessionId);
    worktreeMapRef.current.delete(sessionId);
    return wtPath;
  }, []);

  const refreshSessionPreview = useCallback(
    async (nodeId: string, sessionId: string, fallback?: string[]) => {
      try {
        const previewLines = await terminalService.preview(sessionId, 24);
        useSwarmBoardStore.getState().actions.updateNode(nodeId, { previewLines });
      } catch {
        if (fallback) {
          useSwarmBoardStore.getState().actions.updateNode(nodeId, { previewLines: fallback });
        }
      }
    },
    [],
  );

  const monitorSessionExit = useCallback(
    (sessionId: string) => {
      closedSessionsRef.current.delete(sessionId);
      terminalService
        .onExit(sessionId, (exitCode) => {
          const status: SessionStatus =
            exitCode === null ? "completed" : exitCode === 0 ? "completed" : "failed";
          const { actions } = useSwarmBoardStore.getState();
          actions.setSessionStatus(sessionId, status, exitCode ?? undefined);
          actions.setSessionMetadata(sessionId, {
            sessionId: undefined,
            terminalAttached: false,
            sessionRecoveryState: "fresh",
          });
          cleanupSessionTracking(sessionId);
        })
        .then((unlisten) => {
          if (closedSessionsRef.current.has(sessionId)) {
            unlisten();
            return;
          }
          const existing = exitListenersRef.current.get(sessionId);
          if (existing) {
            try {
              existing();
            } catch {
              // best-effort cleanup
            }
          }
          exitListenersRef.current.set(sessionId, unlisten);
        })
        .catch((err) => {
          console.error("[swarm-board-store] Failed to monitor exit:", err);
        });
    },
    [cleanupSessionTracking],
  );

  useEffect(() => {
    if (!isDesktop()) {
      return;
    }

    const recoverableNodes = useSwarmBoardStore
      .getState()
      .nodes.filter((node) => {
        const data = node.data as SwarmBoardNodeData;
        return data.nodeType === "agentSession" && isRecoverableTmuxNode(data) && !data.terminalAttached;
      });

    if (recoverableNodes.length === 0) {
      return;
    }

    let cancelled = false;
    void terminalService
      .discover()
      .then(async (sessions) => {
        if (cancelled) {
          return;
        }

        const sessionMap = new Map(sessions.map((session) => [session.id, session]));
        for (const node of recoverableNodes) {
          if (cancelled) {
            return;
          }

          const data = node.data as SwarmBoardNodeData;
          const sessionId = data.sessionId;
          if (!sessionId) {
            continue;
          }

          const session = sessionMap.get(sessionId);
          if (!session) {
            useSwarmBoardStore.getState().actions.updateNode(node.id, {
              sessionId: undefined,
              terminalAttached: false,
              sessionRecoveryState: "fresh",
              status: data.status === "running" ? "failed" : data.status,
            });
            continue;
          }

          useSwarmBoardStore.getState().actions.updateNode(node.id, {
            ...buildSessionMetadataPatch(session, {
              manualSession: true,
              terminalAttached: false,
            }),
            status: data.status === "blocked" ? "blocked" : "running",
          });

          await refreshSessionPreview(node.id, session.id, data.previewLines);
        }
      })
      .catch((err) => {
        console.error("[swarm-board-store] Failed to discover tmux sessions:", err);
      });

    return () => {
      cancelled = true;
    };
  }, [recoverableSessionSignature, refreshSessionPreview]);

  useEffect(() => {
    if (!isDesktop() || !selectedNode) {
      return;
    }

    const data = selectedNode.data as SwarmBoardNodeData;
    if (
      data.nodeType !== "agentSession" ||
      !data.sessionId ||
      data.sessionPersistence !== "tmux" ||
      data.terminalAttached
    ) {
      return;
    }

    const sessionId = data.sessionId;
    if (reconnectingRef.current.has(sessionId)) {
      return;
    }

    reconnectingRef.current.add(sessionId);
    let cancelled = false;

    void terminalService
      .reconnect(sessionId)
      .then(async (session) => {
        if (cancelled) {
          return;
        }

        monitorSessionExit(session.id);
        useSwarmBoardStore.getState().actions.updateNode(selectedNode.id, {
          ...buildSessionMetadataPatch(session, {
            manualSession: true,
            terminalAttached: true,
          }),
          status: data.status === "blocked" ? "blocked" : "running",
        });
        await refreshSessionPreview(selectedNode.id, session.id, data.previewLines);
      })
      .catch((err) => {
        if (!cancelled) {
          console.error("[swarm-board-store] Failed to reconnect session:", err);
          useSwarmBoardStore.getState().actions.updateNode(selectedNode.id, {
            terminalAttached: false,
            manualSession: true,
            sessionRecoveryState: "recoverable",
          });
        }
      })
      .finally(() => {
        reconnectingRef.current.delete(sessionId);
      });

    return () => {
      cancelled = true;
    };
  }, [monitorSessionExit, refreshSessionPreview, selectedNode]);

  const spawnSession = useCallback(
    async (opts: SpawnSessionOptions): Promise<Node<SwarmBoardNodeData>> => {
      let cwd = opts.cwd;
      if (!cwd) {
        try {
          cwd = await terminalService.getCwd();
          if (cwd) {
            useSwarmBoardStore.getState().actions.setRepoRoot(cwd);
          }
        } catch {
          // Not in Tauri
        }
      }
      if (!cwd) {
        cwd = "/tmp";
        console.warn("[swarm-board-store] No working directory for session; falling back to /tmp");
      }

      const sessionInfo = await terminalService.create(cwd, opts.shell);
      const node = createBoardNode({
        nodeType: "agentSession",
        title: opts.title ?? (opts.launchClaude ? "Claude Session" : "Terminal"),
        position: opts.position,
        data: {
          agentModel: opts.launchClaude ? "claude" : "shell",
          status: "running",
          sessionId: sessionInfo.id,
          previewLines: [],
          receiptCount: 0,
          blockedActionCount: 0,
          changedFilesCount: 0,
          risk: "low",
          policyMode: "default",
          ...buildSessionMetadataPatch(sessionInfo, {
            manualSession: false,
            terminalAttached: true,
          }),
        },
      });

      useSwarmBoardStore.getState().actions.addNodeDirect(node);
      monitorSessionExit(sessionInfo.id);

      if (opts.launchClaude) {
        setTimeout(() => {
          terminalService.write(sessionInfo.id, "claude\n").catch((err) => {
            console.error("[swarm-board-store] Failed to launch claude:", err);
          });
        }, 500);
      }

      if (opts.command && !opts.launchClaude) {
        const cmd = opts.command;
        setTimeout(() => {
          terminalService.write(sessionInfo.id, cmd).catch((err) => {
            console.error("[swarm-board-store] Failed to write initial command:", err);
          });
        }, 500);
      }

      return node;
    },
    [monitorSessionExit],
  );

  const spawnClaudeSession = useCallback(
    async (opts: SpawnClaudeSessionOptions): Promise<Node<SwarmBoardNodeData>> => {
      let cwd = opts.cwd || useSwarmBoardStore.getState().repoRoot;

      if (!cwd) {
        try {
          cwd = await terminalService.getCwd();
          if (cwd) {
            useSwarmBoardStore.getState().actions.setRepoRoot(cwd);
          }
        } catch {
          // Not in Tauri
        }
      }

      if (!cwd) {
        cwd = "/tmp";
        console.warn("[swarm-board-store] No working directory available; falling back to /tmp");
      }

      let worktreePath: string | undefined;
      let branchName = opts.branch;

      if (opts.worktree) {
        if (!branchName) {
          branchName = `swarm-${Date.now().toString(36)}`;
        }
        try {
          const wtInfo = await worktreeService.create(cwd, branchName);
          worktreePath = wtInfo.path;
          cwd = wtInfo.path;
          branchName = wtInfo.branch;
        } catch (err) {
          const errMsg = err instanceof Error ? err.message : String(err);
          throw new Error(`Failed to create worktree for branch "${branchName}": ${errMsg}`);
        }
      }

      const sessionInfo = await terminalService.create(cwd);

      if (worktreePath) {
        worktreeMapRef.current.set(sessionInfo.id, worktreePath);
      }

      const node = createBoardNode({
        nodeType: "agentSession",
        title: opts.title || `Claude: ${branchName || "session"}`,
        position: opts.position,
        data: {
          agentModel: "claude",
          worktreePath,
          status: "running",
          sessionId: sessionInfo.id,
          previewLines: [],
          receiptCount: 0,
          blockedActionCount: 0,
          changedFilesCount: 0,
          risk: "low",
          policyMode: "default",
          ...buildSessionMetadataPatch(
            {
              ...sessionInfo,
              branch: branchName || sessionInfo.branch,
            },
            {
              manualSession: false,
              terminalAttached: true,
            },
          ),
        },
      });

      useSwarmBoardStore.getState().actions.addNodeDirect(node);
      monitorSessionExit(sessionInfo.id);

      setTimeout(() => {
        terminalService.write(sessionInfo.id, "claude\n").catch((err) => {
          console.error("[swarm-board-store] Failed to launch claude:", err);
          useSwarmBoardStore.getState().actions.setSessionStatus(sessionInfo.id, "failed");
        });

        if (opts.prompt) {
          const prompt = opts.prompt;
          setTimeout(() => {
            terminalService.write(sessionInfo.id, prompt + "\n").catch((err) => {
              console.error("[swarm-board-store] Failed to send prompt:", err);
            });
          }, 2000);
        }
      }, 500);

      return node;
    },
    [monitorSessionExit],
  );

  const spawnWorktreeSession = useCallback(
    async (opts: SpawnWorktreeSessionOptions): Promise<Node<SwarmBoardNodeData>> => {
      const repoRoot = useSwarmBoardStore.getState().repoRoot;
      if (!repoRoot) {
        throw new Error("repoRoot is not set. Configure the repository root in SwarmBoard settings.");
      }

      const branchName = opts.branch || `swarm-${Date.now().toString(36)}`;
      const wtInfo = await worktreeService.create(repoRoot, branchName);
      const sessionInfo = await terminalService.create(wtInfo.path, opts.shell);

      worktreeMapRef.current.set(sessionInfo.id, wtInfo.path);

      const node = createBoardNode({
        nodeType: "agentSession",
        title: opts.title || `Worktree: ${branchName}`,
        position: opts.position,
        data: {
          agentModel: "shell",
          worktreePath: wtInfo.path,
          status: "running",
          sessionId: sessionInfo.id,
          previewLines: [],
          receiptCount: 0,
          blockedActionCount: 0,
          changedFilesCount: 0,
          risk: "low",
          policyMode: "default",
          ...buildSessionMetadataPatch(
            {
              ...sessionInfo,
              branch: branchName,
            },
            {
              manualSession: false,
              terminalAttached: true,
            },
          ),
        },
      });

      useSwarmBoardStore.getState().actions.addNodeDirect(node);
      monitorSessionExit(sessionInfo.id);

      return node;
    },
    [monitorSessionExit],
  );

  const killSession = useCallback(
    async (nodeId: string) => {
      if (killingRef.current.has(nodeId)) return;

      const state = useSwarmBoardStore.getState();
      const node = state.nodes.find((n) => n.id === nodeId);
      if (!node) return;
      const d = node.data as SwarmBoardNodeData;
      if (!d.sessionId) {
        state.actions.updateNode(nodeId, { status: "completed" });
        return;
      }

      const sessionId = d.sessionId;
      killingRef.current.add(nodeId);

      const wtPath = cleanupSessionTracking(sessionId);
      let finalStatus: SessionStatus = "completed";

      try {
        try {
          await terminalService.kill(sessionId);
        } catch (err) {
          console.warn("[swarm-board-store] Failed to kill session:", err);
          finalStatus = "failed";
        }

        if (wtPath && state.repoRoot) {
          try {
            await worktreeService.remove(state.repoRoot, wtPath);
          } catch (err) {
            console.warn("[swarm-board-store] Worktree cleanup failed:", err);
            finalStatus = "failed";
          }
        }
      } finally {
        useSwarmBoardStore.getState().actions.updateNode(nodeId, {
          status: finalStatus,
          sessionId: undefined,
          terminalAttached: false,
          sessionRecoveryState: "fresh",
          ...(wtPath ? { worktreePath: undefined } : {}),
        });
        killingRef.current.delete(nodeId);
      }
    },
    [cleanupSessionTracking],
  );

  // Clean up all listeners on unmount
  useEffect(() => {
    return () => {
      for (const unlisten of exitListenersRef.current.values()) {
        unlisten();
      }
      exitListenersRef.current.clear();
      worktreeMapRef.current.clear();
      closedSessionsRef.current.clear();
    };
  }, []);

  const sessionValue = useMemo(
    () => ({
      spawnSession,
      spawnClaudeSession,
      spawnWorktreeSession,
      killSession,
    }),
    [spawnSession, spawnClaudeSession, spawnWorktreeSession, killSession],
  );

  return (
    <SwarmBoardSessionContext.Provider value={sessionValue}>
      {children}
    </SwarmBoardSessionContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// Type re-exports
// ---------------------------------------------------------------------------

export type { SwarmBoardState, SwarmBoardNodeData, SwarmBoardEdge, SwarmNodeType, SessionStatus, RiskLevel };
