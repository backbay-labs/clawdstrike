// ---------------------------------------------------------------------------
// SwarmBoard Persistence — pure helpers for path resolution, serialization,
// normalization, sanitization, and persistence I/O.
//
// This module is extracted from swarm-board-store.tsx to isolate persistence
// concerns. Dependency flows one way: store -> persistence. This module
// must NEVER import from swarm-board-store.
// ---------------------------------------------------------------------------
import type { Node } from "@xyflow/react";
import type {
  SwarmBoardNodeData,
  SwarmBoardEdge,
  SwarmBoardState,
} from "@/features/swarm/swarm-board-types";
import { isDesktop } from "@/lib/tauri-bridge";
import { normalizeSwarmFileWatchPath } from "./swarm-file-watch";
import {
  SWARM_BOARD_PERSISTENCE_FILE,
  readSwarmPersistencePayload,
  writeSwarmPersistencePayload,
} from "./swarm-persistence";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const STORAGE_KEY = "clawdstrike_workbench_swarm_board";

/** Keep persisted replay history bounded so board snapshots stay durable. */
const MAX_PERSISTED_AGENT_CONVERSATION_TURNS = 200;

// ---------------------------------------------------------------------------
// Board ID generator (used by normalizePersistedBoard fallback)
// ---------------------------------------------------------------------------

export function generateBoardId(): string {
  return `board-${Date.now().toString(36)}`;
}

// ---------------------------------------------------------------------------
// Internal path helpers
// ---------------------------------------------------------------------------

function isAbsoluteFilePath(path: string): boolean {
  return path.startsWith("/") || /^[A-Za-z]:[\\/]/.test(path);
}

function joinFilePath(root: string, path: string): string {
  const safeRoot = root.replace(/[\\/]+$/, "");
  const safePath = path.replace(/^[\\/]+/, "");
  return `${safeRoot}/${safePath}`;
}

// ---------------------------------------------------------------------------
// Exported public API (re-exported via store facade)
// ---------------------------------------------------------------------------

export function resolveBoardWatchFilePath(
  filePath: string | undefined,
  repoRoot: string,
  normalizeAbsolutePath: (path: string) => string = (path) => path,
): string | null {
  if (!filePath) {
    return null;
  }
  const trimmed = filePath.trim();
  if (!trimmed) {
    return null;
  }
  if (isAbsoluteFilePath(trimmed)) {
    return normalizeAbsolutePath(normalizeSwarmFileWatchPath(trimmed));
  }
  if (!repoRoot) {
    return null;
  }
  return normalizeAbsolutePath(normalizeSwarmFileWatchPath(joinFilePath(repoRoot, trimmed)));
}

export function collectBoardWatchWorkspacePaths(
  nodes: Array<Node<SwarmBoardNodeData>>,
  repoRoot: string,
  bundlePath: string,
  normalizeAbsolutePath: (path: string) => string = (path) => path,
): string[] {
  const paths = new Set<string>();

  if (bundlePath) {
    paths.add(normalizeAbsolutePath(normalizeSwarmFileWatchPath(`${bundlePath}/board.json`)));
  }

  for (const node of nodes) {
    const data = node.data as SwarmBoardNodeData;
    const artifactPath = resolveBoardWatchFilePath(
      typeof data.filePath === "string" ? data.filePath : undefined,
      repoRoot,
      normalizeAbsolutePath,
    );
    if (artifactPath) {
      paths.add(artifactPath);
    }

    const diffPath = resolveBoardWatchFilePath(
      typeof data.diffPath === "string" ? data.diffPath : undefined,
      repoRoot,
      normalizeAbsolutePath,
    );
    if (diffPath) {
      paths.add(diffPath);
    }
  }

  return Array.from(paths).sort();
}

// ---------------------------------------------------------------------------
// Persisted payload type
// ---------------------------------------------------------------------------

export interface PersistedBoardPayload {
  boardId: string;
  repoRoot: string;
  nodes: Node<SwarmBoardNodeData>[];
  edges: SwarmBoardEdge[];
}

// ---------------------------------------------------------------------------
// Serialization / sanitization helpers
// ---------------------------------------------------------------------------

export function truncateConversationHistory(
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

export function sanitizePersistedNode(
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

// ---------------------------------------------------------------------------
// Session recovery helpers
// ---------------------------------------------------------------------------

export function isRecoverableTmuxNode(data: SwarmBoardNodeData | undefined): boolean {
  return Boolean(data?.sessionId && data.sessionPersistence === "tmux");
}

export function buildSessionMetadataPatch(
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

// ---------------------------------------------------------------------------
// Board normalization (validates + sanitizes persisted data)
// ---------------------------------------------------------------------------

export function normalizePersistedBoard(parsed: unknown): Partial<SwarmBoardState> | null {
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

// ---------------------------------------------------------------------------
// Board serialization
// ---------------------------------------------------------------------------

export function serializePersistedBoard(state: SwarmBoardState): PersistedBoardPayload {
  return {
    boardId: state.boardId,
    repoRoot: state.repoRoot,
    nodes: state.nodes.map((node) => sanitizePersistedNode(node)),
    edges: state.edges,
  };
}

// ---------------------------------------------------------------------------
// Persistence I/O
// ---------------------------------------------------------------------------

export function persistBoard(state: SwarmBoardState): void {
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

export function loadPersistedBoard(): Partial<SwarmBoardState> | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    return normalizePersistedBoard(JSON.parse(raw));
  } catch (e) {
    console.warn("[swarm-board-store] loadPersistedBoard failed:", e);
    return null;
  }
}
