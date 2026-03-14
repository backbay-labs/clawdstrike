// ---------------------------------------------------------------------------
// SwarmBoard Store — React Context + useReducer for board CRUD
//
// Follows the swarm-store.tsx / sentinel-store.tsx pattern: State, Action
// union, reducer, Provider with localStorage persistence, and a typed hook.
// ---------------------------------------------------------------------------
import {
  createContext,
  useContext,
  useReducer,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  type ReactNode,
} from "react";
import { MarkerType, type Node, type Edge } from "@xyflow/react";
import type {
  SwarmBoardNodeData,
  SwarmBoardEdge,
  SwarmBoardState,
  SwarmNodeType,
  SessionStatus,
  RiskLevel,
} from "./swarm-board-types";
import { terminalService, worktreeService } from "./terminal-service";
import type { UnlistenFn } from "@tauri-apps/api/event";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum number of live xterm terminals to keep active simultaneously. */
export const MAX_ACTIVE_TERMINALS = 8;

// ---------------------------------------------------------------------------
// Actions
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
  | { type: "SET_SESSION_METADATA"; sessionId: string; metadata: Partial<SwarmBoardNodeData> };

// ---------------------------------------------------------------------------
// Reducer
// ---------------------------------------------------------------------------

function boardReducer(
  state: SwarmBoardState,
  action: SwarmBoardAction,
): SwarmBoardState {
  switch (action.type) {
    case "ADD_NODE": {
      // Prevent duplicates
      if (state.nodes.some((n) => n.id === action.node.id)) return state;
      return { ...state, nodes: [...state.nodes, action.node] };
    }

    case "REMOVE_NODE": {
      return {
        ...state,
        nodes: state.nodes.filter((n) => n.id !== action.nodeId),
        // Remove edges connected to the deleted node
        edges: state.edges.filter(
          (e) => e.source !== action.nodeId && e.target !== action.nodeId,
        ),
        selectedNodeId:
          state.selectedNodeId === action.nodeId ? null : state.selectedNodeId,
        inspectorOpen:
          state.selectedNodeId === action.nodeId ? false : state.inspectorOpen,
      };
    }

    case "UPDATE_NODE": {
      return {
        ...state,
        nodes: state.nodes.map((n) =>
          n.id === action.nodeId
            ? { ...n, data: { ...n.data, ...action.patch } }
            : n,
        ),
      };
    }

    case "SET_NODES": {
      return { ...state, nodes: action.nodes };
    }

    case "ADD_EDGE": {
      if (state.edges.some((e) => e.id === action.edge.id)) return state;
      return { ...state, edges: [...state.edges, action.edge] };
    }

    case "REMOVE_EDGE": {
      return {
        ...state,
        edges: state.edges.filter((e) => e.id !== action.edgeId),
      };
    }

    case "SET_EDGES": {
      return { ...state, edges: action.edges };
    }

    case "SELECT_NODE": {
      return {
        ...state,
        selectedNodeId: action.nodeId,
        inspectorOpen: action.nodeId !== null,
      };
    }

    case "TOGGLE_INSPECTOR": {
      const open = action.open ?? !state.inspectorOpen;
      return {
        ...state,
        inspectorOpen: open,
        selectedNodeId: open ? state.selectedNodeId : null,
      };
    }

    case "SET_REPO_ROOT": {
      return { ...state, repoRoot: action.repoRoot };
    }

    case "LOAD": {
      return {
        ...state,
        ...action.state,
        nodes: action.state.nodes ?? state.nodes,
        edges: action.state.edges ?? state.edges,
      };
    }

    case "CLEAR_BOARD": {
      return {
        ...state,
        nodes: [],
        edges: [],
        selectedNodeId: null,
        inspectorOpen: false,
      };
    }

    case "SET_SESSION_STATUS": {
      return {
        ...state,
        nodes: state.nodes.map((n) => {
          const d = n.data as SwarmBoardNodeData;
          if (d.sessionId === action.sessionId) {
            return {
              ...n,
              data: {
                ...d,
                status: action.status,
                ...(action.exitCode !== undefined ? { exitCode: action.exitCode } : {}),
              },
            };
          }
          return n;
        }),
      };
    }

    case "SET_SESSION_METADATA": {
      return {
        ...state,
        nodes: state.nodes.map((n) => {
          const d = n.data as SwarmBoardNodeData;
          if (d.sessionId === action.sessionId) {
            return { ...n, data: { ...d, ...action.metadata } };
          }
          return n;
        }),
      };
    }

    default:
      return state;
  }
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

const STORAGE_KEY = "clawdstrike_workbench_swarm_board";

function persistBoard(state: SwarmBoardState): void {
  try {
    const persisted = {
      boardId: state.boardId,
      repoRoot: state.repoRoot,
      nodes: state.nodes,
      edges: state.edges,
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(persisted));
  } catch (e) {
    console.error("[swarm-board-store] persistBoard failed:", e);
  }
}

function loadPersistedBoard(): Partial<SwarmBoardState> | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (
      !parsed ||
      typeof parsed !== "object" ||
      !Array.isArray(parsed.nodes) ||
      !Array.isArray(parsed.edges)
    ) {
      return null;
    }

    // Validate each node has the minimum required shape to prevent
    // runtime errors from corrupted localStorage data.
    const validNodes = (parsed.nodes as unknown[]).filter(
      (n): n is Node<SwarmBoardNodeData> =>
        typeof n === "object" &&
        n !== null &&
        typeof (n as Record<string, unknown>).id === "string" &&
        typeof (n as Record<string, unknown>).position === "object" &&
        typeof (n as Record<string, unknown>).data === "object",
    );

    // Validate each edge has required source/target
    const validEdges = (parsed.edges as unknown[]).filter(
      (e): e is SwarmBoardEdge =>
        typeof e === "object" &&
        e !== null &&
        typeof (e as Record<string, unknown>).id === "string" &&
        typeof (e as Record<string, unknown>).source === "string" &&
        typeof (e as Record<string, unknown>).target === "string",
    );

    if (validNodes.length === 0) return null;

    // Strip sessionId from persisted nodes — PTY sessions don't survive
    // page reloads, so stale sessionIds would cause the TerminalRenderer
    // to mount and connect to a non-existent backend, producing garbled output.
    const sanitizedNodes = validNodes.map((n) => {
      if (n.data?.sessionId) {
        return {
          ...n,
          data: {
            ...n.data,
            sessionId: undefined,
            status: n.data.status === "running" ? "idle" : n.data.status,
          },
        } as Node<SwarmBoardNodeData>;
      }
      return n;
    });

    return {
      boardId: typeof parsed.boardId === "string" ? parsed.boardId : generateBoardId(),
      repoRoot: typeof parsed.repoRoot === "string" ? parsed.repoRoot : "",
      nodes: sanitizedNodes,
      edges: validEdges,
    };
  } catch (e) {
    console.warn("[swarm-board-store] loadPersistedBoard failed:", e);
    return null;
  }
}

// ---------------------------------------------------------------------------
// ID generators
// ---------------------------------------------------------------------------

let nodeCounter = 0;

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
// Mock data seeder — provides a demo board for first-time users
// ---------------------------------------------------------------------------

export function createMockBoard(): {
  nodes: Node<SwarmBoardNodeData>[];
  edges: SwarmBoardEdge[];
} {
  // --- Agent Session nodes ---

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
        "Finished `dev` profile target(s)",
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

  // --- Terminal Task nodes ---

  const task1 = createBoardNode({
    nodeType: "terminalTask",
    title: "Run integration tests",
    position: { x: 80, y: 400 },
    data: {
      status: "running",
      taskPrompt: "Execute the full integration test suite and report failures",
    },
  });

  // --- Receipt nodes ---

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

  // --- Diff nodes ---

  const diff1 = createBoardNode({
    nodeType: "diff",
    title: "Auth changes",
    position: { x: 340, y: 400 },
    data: {
      status: "idle",
      diffSummary: {
        added: 47,
        removed: 12,
        files: [
          "src/middleware/auth.rs",
          "src/middleware/token.rs",
          "tests/auth_test.rs",
          "Cargo.toml",
        ],
      },
    },
  });

  // --- Artifact nodes ---

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

  // --- Note nodes ---

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
    // Agent1 spawned task1
    {
      id: `edge-${agent1.id}-${task1.id}`,
      source: agent1.id,
      target: task1.id,
      type: "spawned",
      label: "spawned",
    },
    // Agent1 produces artifact1
    {
      id: `edge-${agent1.id}-${artifact1.id}`,
      source: agent1.id,
      target: artifact1.id,
      type: "artifact",
      label: "produces",
    },
    // Agent1 produces diff1
    {
      id: `edge-${agent1.id}-${diff1.id}`,
      source: agent1.id,
      target: diff1.id,
      type: "artifact",
    },
    // Agent2 receipt (allow)
    {
      id: `edge-${agent2.id}-${receipt1.id}`,
      source: agent2.id,
      target: receipt1.id,
      type: "receipt",
      label: "receipt",
    },
    // Agent2 produces artifact2
    {
      id: `edge-${agent2.id}-${artifact2.id}`,
      source: agent2.id,
      target: artifact2.id,
      type: "artifact",
      label: "produces",
    },
    // Agent3 receipt (deny)
    {
      id: `edge-${agent3.id}-${receipt2.id}`,
      source: agent3.id,
      target: receipt2.id,
      type: "receipt",
      label: "denied",
    },
    // Handoff edge: Agent1 -> Agent2 (coordination)
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
      inspectorOpen: false,
    };
  }

  // Seed with mock data on first visit
  const mock = createMockBoard();
  return {
    boardId: generateBoardId(),
    repoRoot: "",
    nodes: mock.nodes,
    edges: mock.edges,
    selectedNodeId: null,
    inspectorOpen: false,
  };
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

interface SwarmBoardContextValue {
  state: SwarmBoardState;
  dispatch: React.Dispatch<SwarmBoardAction>;
  // Convenience helpers
  addNode: (config: CreateNodeConfig) => Node<SwarmBoardNodeData>;
  removeNode: (nodeId: string) => void;
  updateNode: (nodeId: string, patch: Partial<SwarmBoardNodeData>) => void;
  selectNode: (nodeId: string | null) => void;
  addEdge: (edge: SwarmBoardEdge) => void;
  removeEdge: (edgeId: string) => void;
  clearBoard: () => void;
  selectedNode: Node<SwarmBoardNodeData> | undefined;
  // React Flow compatible edges
  rfEdges: Edge[];
  // Live session management
  spawnSession: (opts: SpawnSessionOptions) => Promise<Node<SwarmBoardNodeData>>;
  spawnClaudeSession: (opts: SpawnClaudeSessionOptions) => Promise<Node<SwarmBoardNodeData>>;
  spawnWorktreeSession: (opts: SpawnWorktreeSessionOptions) => Promise<Node<SwarmBoardNodeData>>;
  killSession: (nodeId: string) => Promise<void>;
}

export interface SpawnSessionOptions {
  /** Working directory for the PTY shell */
  cwd: string;
  /** Position on the canvas */
  position?: { x: number; y: number };
  /** If true, run `claude` CLI after shell starts */
  launchClaude?: boolean;
  /** Custom title */
  title?: string;
  /** Shell binary (defaults to $SHELL) */
  shell?: string;
  /** Optional initial command to write after spawn */
  command?: string;
}

export interface SpawnClaudeSessionOptions {
  /** Working directory. Defaults to repoRoot. */
  cwd?: string;
  /** Position on the canvas */
  position?: { x: number; y: number };
  /** Optional initial prompt to send to Claude Code */
  prompt?: string;
  /** If true, create an isolated git worktree first */
  worktree?: boolean;
  /** Branch name for worktree (auto-generated if omitted) */
  branch?: string;
  /** Custom title */
  title?: string;
}

export interface SpawnWorktreeSessionOptions {
  /** Position on the canvas */
  position?: { x: number; y: number };
  /** Branch name for the worktree */
  branch?: string;
  /** Custom title */
  title?: string;
  /** Shell binary */
  shell?: string;
}

const SwarmBoardContext = createContext<SwarmBoardContextValue | null>(null);

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useSwarmBoard(): SwarmBoardContextValue {
  const ctx = useContext(SwarmBoardContext);
  if (!ctx) throw new Error("useSwarmBoard must be used within SwarmBoardProvider");
  return ctx;
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export function SwarmBoardProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(boardReducer, undefined, getInitialState);

  // Debounced persistence
  const persistRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (persistRef.current) clearTimeout(persistRef.current);
    persistRef.current = setTimeout(() => {
      persistBoard(state);
    }, 500);
    return () => {
      if (persistRef.current) clearTimeout(persistRef.current);
    };
  }, [state.nodes, state.edges, state.boardId, state.repoRoot]);

  // Auto-detect repoRoot on mount if it is empty
  useEffect(() => {
    if (state.repoRoot) return;
    terminalService
      .getCwd()
      .then((cwd) => {
        if (cwd) {
          dispatch({ type: "SET_REPO_ROOT", repoRoot: cwd });
        }
      })
      .catch(() => {
        // Not in Tauri or command failed — leave repoRoot empty.
        // The user can set it manually via the toolbar.
      });
    // Only run on mount (repoRoot is read once)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Derive selected node (memoized to avoid unnecessary re-renders of inspector)
  const selectedNode = useMemo(
    () =>
      state.selectedNodeId
        ? state.nodes.find((n) => n.id === state.selectedNodeId)
        : undefined,
    [state.selectedNodeId, state.nodes],
  );

  // Convert SwarmBoardEdge[] to React Flow Edge[] (memoized to keep React Flow stable)
  const rfEdges: Edge[] = useMemo(
    () =>
      state.edges.map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        label: e.label,
        type: "swarmEdge",
        data: { edgeType: e.type },
        animated: e.type === "spawned",
        markerEnd: e.type === "handoff" || e.type === "spawned"
          ? { type: MarkerType.ArrowClosed, color: edgeColor(e.type) }
          : undefined,
      })),
    [state.edges],
  );

  // Action helpers
  const addNode = useCallback(
    (config: CreateNodeConfig): Node<SwarmBoardNodeData> => {
      const node = createBoardNode(config);
      dispatch({ type: "ADD_NODE", node });
      return node;
    },
    [],
  );

  const removeNode = useCallback((nodeId: string) => {
    dispatch({ type: "REMOVE_NODE", nodeId });
  }, []);

  const updateNode = useCallback(
    (nodeId: string, patch: Partial<SwarmBoardNodeData>) => {
      dispatch({ type: "UPDATE_NODE", nodeId, patch });
    },
    [],
  );

  const selectNode = useCallback((nodeId: string | null) => {
    dispatch({ type: "SELECT_NODE", nodeId });
  }, []);

  const addEdge = useCallback((edge: SwarmBoardEdge) => {
    dispatch({ type: "ADD_EDGE", edge });
  }, []);

  const removeEdge = useCallback((edgeId: string) => {
    dispatch({ type: "REMOVE_EDGE", edgeId });
  }, []);

  const clearBoard = useCallback(() => {
    dispatch({ type: "CLEAR_BOARD" });
  }, []);

  // -----------------------------------------------------------------------
  // Live session management — exit monitoring, worktree tracking, cleanup
  // -----------------------------------------------------------------------

  // Track exit listeners and worktree paths for cleanup
  const exitListenersRef = useRef<Map<string, UnlistenFn>>(new Map());
  const worktreeMapRef = useRef<Map<string, string>>(new Map()); // sessionId -> worktreePath
  const closedSessionsRef = useRef<Set<string>>(new Set());

  // Idempotent cleanup for all in-memory session tracking artifacts.
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

  // Monitor a session for exit events
  const monitorSessionExit = useCallback(
    (sessionId: string) => {
      closedSessionsRef.current.delete(sessionId);
      terminalService.onExit(sessionId, (exitCode) => {
        const status: SessionStatus =
          exitCode === null ? "completed" : exitCode === 0 ? "completed" : "failed";
        dispatch({
          type: "SET_SESSION_STATUS",
          sessionId,
          status,
          exitCode: exitCode ?? undefined,
        });
        // Clear node-session linkage + tracking to avoid stale in-memory mappings.
        dispatch({
          type: "SET_SESSION_METADATA",
          sessionId,
          metadata: { sessionId: undefined },
        });
        cleanupSessionTracking(sessionId);
      }).then((unlisten) => {
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
      }).catch((err) => {
        console.error("[swarm-board-store] Failed to monitor exit:", err);
      });
    },
    [cleanupSessionTracking],
  );

  const spawnSession = useCallback(
    async (opts: SpawnSessionOptions): Promise<Node<SwarmBoardNodeData>> => {
      // If cwd is empty, try to auto-detect
      let cwd = opts.cwd;
      if (!cwd) {
        try {
          cwd = await terminalService.getCwd();
          if (cwd) {
            dispatch({ type: "SET_REPO_ROOT", repoRoot: cwd });
          }
        } catch {
          // Not in Tauri — fall through
        }
      }
      if (!cwd) {
        cwd = "/tmp";
        console.warn(
          "[swarm-board-store] No working directory for session; falling back to /tmp",
        );
      }

      // Create a real PTY via the Rust backend
      const sessionInfo = await terminalService.create(cwd, opts.shell);

      // Create the node with the real sessionId
      const node = createBoardNode({
        nodeType: "agentSession",
        title: opts.title ?? (opts.launchClaude ? "Claude Session" : "Terminal"),
        position: opts.position,
        data: {
          agentModel: opts.launchClaude ? "claude" : "shell",
          branch: sessionInfo.branch ?? undefined,
          status: "running",
          sessionId: sessionInfo.id,
          previewLines: [],
          receiptCount: 0,
          blockedActionCount: 0,
          changedFilesCount: 0,
          risk: "low",
          policyMode: "default",
        },
      });

      dispatch({ type: "ADD_NODE", node });

      // Monitor for exit
      monitorSessionExit(sessionInfo.id);

      // If launching Claude CLI, write the command after a short delay
      // to let the shell initialize
      if (opts.launchClaude) {
        setTimeout(() => {
          terminalService.write(sessionInfo.id, "claude\n").catch((err) => {
            console.error("[swarm-board-store] Failed to launch claude:", err);
          });
        }, 500);
      }

      // If an initial command was provided, write it after shell init
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
    [monitorSessionExit, dispatch],
  );

  const spawnClaudeSession = useCallback(
    async (opts: SpawnClaudeSessionOptions): Promise<Node<SwarmBoardNodeData>> => {
      let cwd = opts.cwd || state.repoRoot;

      // If cwd is still empty, attempt to auto-detect via the Tauri backend
      if (!cwd) {
        try {
          cwd = await terminalService.getCwd();
          if (cwd) {
            dispatch({ type: "SET_REPO_ROOT", repoRoot: cwd });
          }
        } catch {
          // Not in Tauri — fall through
        }
      }

      // Last resort: use a safe default rather than throwing
      if (!cwd) {
        cwd = "/tmp";
        console.warn(
          "[swarm-board-store] No working directory available; falling back to /tmp",
        );
      }

      let worktreePath: string | undefined;
      let branchName = opts.branch;

      // Create a worktree if requested
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

      // Create the PTY session
      const sessionInfo = await terminalService.create(cwd);

      // Track worktree for cleanup
      if (worktreePath) {
        worktreeMapRef.current.set(sessionInfo.id, worktreePath);
      }

      // Create board node
      const node = createBoardNode({
        nodeType: "agentSession",
        title: opts.title || `Claude: ${branchName || "session"}`,
        position: opts.position,
        data: {
          agentModel: "claude",
          branch: branchName || sessionInfo.branch || undefined,
          worktreePath,
          status: "running",
          sessionId: sessionInfo.id,
          previewLines: [],
          receiptCount: 0,
          blockedActionCount: 0,
          changedFilesCount: 0,
          risk: "low",
          policyMode: "default",
        },
      });

      dispatch({ type: "ADD_NODE", node });

      // Monitor exit
      monitorSessionExit(sessionInfo.id);

      // Start Claude Code after shell initializes
      setTimeout(() => {
        terminalService.write(sessionInfo.id, "claude\n").catch((err) => {
          console.error("[swarm-board-store] Failed to launch claude:", err);
          dispatch({
            type: "SET_SESSION_STATUS",
            sessionId: sessionInfo.id,
            status: "failed",
          });
        });

        // If a prompt was provided, send it after Claude has time to start
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
    [state.repoRoot, monitorSessionExit, dispatch],
  );

  const spawnWorktreeSession = useCallback(
    async (opts: SpawnWorktreeSessionOptions): Promise<Node<SwarmBoardNodeData>> => {
      const repoRoot = state.repoRoot;
      if (!repoRoot) {
        throw new Error("repoRoot is not set. Configure the repository root in SwarmBoard settings.");
      }

      const branchName = opts.branch || `swarm-${Date.now().toString(36)}`;

      // Create the worktree
      const wtInfo = await worktreeService.create(repoRoot, branchName);

      // Create the PTY in the worktree
      const sessionInfo = await terminalService.create(wtInfo.path, opts.shell);

      // Track worktree for cleanup
      worktreeMapRef.current.set(sessionInfo.id, wtInfo.path);

      const node = createBoardNode({
        nodeType: "agentSession",
        title: opts.title || `Worktree: ${branchName}`,
        position: opts.position,
        data: {
          agentModel: "shell",
          branch: branchName,
          worktreePath: wtInfo.path,
          status: "running",
          sessionId: sessionInfo.id,
          previewLines: [],
          receiptCount: 0,
          blockedActionCount: 0,
          changedFilesCount: 0,
          risk: "low",
          policyMode: "default",
        },
      });

      dispatch({ type: "ADD_NODE", node });

      // Monitor exit
      monitorSessionExit(sessionInfo.id);

      return node;
    },
    [state.repoRoot, monitorSessionExit],
  );

  // Track sessions that are currently being killed to make killSession
  // idempotent — concurrent or repeated calls for the same node are no-ops.
  const killingRef = useRef<Set<string>>(new Set());

  const killSession = useCallback(
    async (nodeId: string) => {
      // Idempotency: if we're already tearing down this node, bail out.
      if (killingRef.current.has(nodeId)) return;

      // Find the session ID from the node
      const node = state.nodes.find((n) => n.id === nodeId);
      if (!node) return;
      const d = node.data as SwarmBoardNodeData;
      if (!d.sessionId) {
        dispatch({
          type: "UPDATE_NODE",
          nodeId,
          patch: { status: "completed" },
        });
        return;
      }

      const sessionId = d.sessionId;
      killingRef.current.add(nodeId);

      // Always clean up tracking first — even if the kill IPC fails, we don't
      // want stale listeners or worktree mappings lingering in memory.
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
        // Always update node state, even on unexpected errors — the node
        // should never be left in a "running" limbo with a dead session.
        dispatch({
          type: "UPDATE_NODE",
          nodeId,
          patch: {
            status: finalStatus,
            sessionId: undefined,
            ...(wtPath ? { worktreePath: undefined } : {}),
          },
        });
        killingRef.current.delete(nodeId);
      }
    },
    [state.nodes, state.repoRoot, cleanupSessionTracking],
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

  const value: SwarmBoardContextValue = useMemo(
    () => ({
      state,
      dispatch,
      addNode,
      removeNode,
      updateNode,
      selectNode,
      addEdge,
      removeEdge,
      clearBoard,
      selectedNode,
      rfEdges,
      spawnSession,
      spawnClaudeSession,
      spawnWorktreeSession,
      killSession,
    }),
    [state, dispatch, addNode, removeNode, updateNode, selectNode, addEdge, removeEdge, clearBoard, selectedNode, rfEdges, spawnSession, spawnClaudeSession, spawnWorktreeSession, killSession],
  );

  return (
    <SwarmBoardContext.Provider value={value}>
      {children}
    </SwarmBoardContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function edgeColor(type?: SwarmBoardEdge["type"]): string {
  switch (type) {
    case "handoff":
      return "#5b8def";
    case "spawned":
      return "#d4a84b";
    case "artifact":
      return "#3dbf84";
    case "receipt":
      return "#8b5cf6";
    default:
      return "#2d3240";
  }
}

export type { SwarmBoardState, SwarmBoardNodeData, SwarmBoardEdge, SwarmNodeType, SessionStatus, RiskLevel };
