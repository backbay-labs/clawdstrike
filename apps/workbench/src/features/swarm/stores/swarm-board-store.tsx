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
import type {
  SwarmBoardNodeData,
  SwarmBoardEdge,
  SwarmBoardState,
  SwarmNodeType,
  SessionStatus,
  RiskLevel,
} from "@/features/swarm/swarm-board-types";
import { terminalService, worktreeService } from "@/lib/workbench/terminal-service";
import type { UnlistenFn } from "@tauri-apps/api/event";

export const MAX_ACTIVE_TERMINALS = 8;

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
  | { type: "GUARD_EVALUATE"; agentNodeId: string; verdict: string; guardResults: Array<{ guard: string; allowed: boolean; duration_ms?: number }>; signature?: string; publicKey?: string };

const STORAGE_KEY = "clawdstrike_workbench_swarm_board";

function sanitizePersistedNode(
  node: Node<SwarmBoardNodeData>,
): Node<SwarmBoardNodeData> {
  if (!node.data?.engineManaged) {
    return node;
  }

  const {
    branch: _branch,
    worktreePath: _worktreePath,
    filesTouched: _filesTouched,
    previewLines: _previewLines,
    taskPrompt: _taskPrompt,
    ...restData
  } = node.data;

  return {
    ...node,
    data: restData,
  };
}

function persistBoard(state: SwarmBoardState): void {
  try {
    const persisted = {
      boardId: state.boardId,
      repoRoot: state.repoRoot,
      nodes: state.nodes.map(sanitizePersistedNode),
      edges: state.edges,
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(persisted));

    // File-backed persistence for .swarm bundles (Tauri only)
    if (state.bundlePath) {
      import("@/lib/tauri-bridge").then(({ writeSwarmBoardJson }) => {
        writeSwarmBoardJson(state.bundlePath, persisted).catch((err: unknown) => {
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
    const parsed = JSON.parse(raw);
    if (
      !parsed ||
      typeof parsed !== "object" ||
      !Array.isArray(parsed.nodes) ||
      !Array.isArray(parsed.edges)
    ) {
      return null;
    }

    const validNodes = (parsed.nodes as unknown[]).filter(
      (n): n is Node<SwarmBoardNodeData> =>
        typeof n === "object" &&
        n !== null &&
        typeof (n as Record<string, unknown>).id === "string" &&
        typeof (n as Record<string, unknown>).position === "object" &&
        typeof (n as Record<string, unknown>).data === "object",
    );

    const validEdges = (parsed.edges as unknown[]).filter(
      (e): e is SwarmBoardEdge =>
        typeof e === "object" &&
        e !== null &&
        typeof (e as Record<string, unknown>).id === "string" &&
        typeof (e as Record<string, unknown>).source === "string" &&
        typeof (e as Record<string, unknown>).target === "string",
    );

    if (validNodes.length === 0) return null;

    // PTY sessions don't survive reloads
    const sanitizedNodes = validNodes.map((n) => {
      const persistedNode = sanitizePersistedNode(n);
      if (n.data?.sessionId) {
        return {
          ...persistedNode,
          data: {
            ...persistedNode.data,
            sessionId: undefined,
            status:
              persistedNode.data.status === "running"
                ? "idle"
                : persistedNode.data.status,
          },
        } as Node<SwarmBoardNodeData>;
      }
      return persistedNode;
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

let nodeCounter = 0;

function generateBoardId(): string {
  return `board-${Date.now().toString(36)}`;
}

export function generateNodeId(prefix: string = "sbn"): string {
  nodeCounter += 1;
  return `${prefix}-${Date.now().toString(36)}-${nodeCounter}`;
}

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
    case "topology":
      return "#3d4250";
    default:
      return "#2d3240";
  }
}

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
      e.type === "handoff" || e.type === "spawned"
        ? { type: MarkerType.ArrowClosed, color: edgeColor(e.type) }
        : undefined,
  }));
}

let _persistTimer: ReturnType<typeof setTimeout> | null = null;

function schedulePersist(state: SwarmBoardState): void {
  if (_persistTimer) clearTimeout(_persistTimer);
  _persistTimer = setTimeout(() => {
    persistBoard(state);
    _persistTimer = null;
  }, 500);
}

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
      bundlePath: "",
    };
  }

  return {
    boardId: generateBoardId(),
    repoRoot: "",
    nodes: [],
    edges: [],
    selectedNodeId: null,
    inspectorOpen: false,
    bundlePath: "",
  };
}

interface SwarmBoardStoreState extends SwarmBoardState {
  selectedNode: Node<SwarmBoardNodeData> | undefined;
  rfEdges: Edge[];
  actions: {
    addNode: (config: CreateNodeConfig) => Node<SwarmBoardNodeData>;
    addNodeDirect: (node: Node<SwarmBoardNodeData>) => void;
    removeNode: (nodeId: string) => void;
    updateNode: (nodeId: string, patch: Partial<SwarmBoardNodeData>) => void;
    selectNode: (nodeId: string | null) => void;
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
    applyTopologyLayout: (topologyEdges: SwarmBoardEdge[], positions: Map<string, { x: number; y: number }>) => void;
    engineSync: (engineNodes: Array<{ id: string; agentId?: string; taskId?: string; data: Partial<SwarmBoardNodeData>; position?: { x: number; y: number } }>, engineEdges: SwarmBoardEdge[]) => void;
    addGuardReceipt: (config: {
      verdict: "allow" | "deny" | "warn";
      guardResults: Array<{ guard: string; allowed: boolean; duration_ms?: number }>;
      signature?: string;
      publicKey?: string;
      agentNodeId?: string;
      position?: { x: number; y: number };
      detail?: string;
    }) => Node<SwarmBoardNodeData>;
    guardEvaluate: (agentNodeId: string, verdict: string, guardResults: Array<{ guard: string; allowed: boolean; duration_ms?: number }>, signature?: string, publicKey?: string) => void;
  };
}

function deriveSelectedNode(
  nodes: Node<SwarmBoardNodeData>[],
  selectedNodeId: string | null,
): Node<SwarmBoardNodeData> | undefined {
  return selectedNodeId ? nodes.find((n) => n.id === selectedNodeId) : undefined;
}

const initialState = getInitialState();

const useSwarmBoardStoreBase = create<SwarmBoardStoreState>()((set, get) => ({
  ...initialState,
  selectedNode: deriveSelectedNode(initialState.nodes, initialState.selectedNodeId),
  rfEdges: toRfEdges(initialState.edges),

  actions: {
    addNode: (config: CreateNodeConfig): Node<SwarmBoardNodeData> => {
      const node = createBoardNode(config);
      const current = get();
      if (current.nodes.some((n) => n.id === node.id)) return node;
      const nodes = [...current.nodes, node];
      set({
        nodes,
        selectedNode: deriveSelectedNode(nodes, current.selectedNodeId),
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
      set({
        nodes,
        edges,
        selectedNodeId,
        inspectorOpen,
        selectedNode: deriveSelectedNode(nodes, selectedNodeId),
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
      });
      schedulePersist({ ...get() });
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
        inspectorOpen: false,
        selectedNode: undefined,
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
      set({
        ...partial,
        nodes,
        edges,
        selectedNode: deriveSelectedNode(nodes, partial.selectedNodeId ?? current.selectedNodeId),
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
      });
      schedulePersist({ ...get() });
    },

    setNodes: (nodes: Node<SwarmBoardNodeData>[]): void => {
      const current = get();
      set({
        nodes,
        selectedNode: deriveSelectedNode(nodes, current.selectedNodeId),
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
      try {
        const { readSwarmBundle } = await import("@/lib/tauri-bridge");
        const data = await readSwarmBundle(bundlePath);
        if (!data?.board) {
          // Empty bundle: just set the path
          set({ bundlePath });
          return;
        }
        const board = data.board as Record<string, unknown>;
        const nodes = Array.isArray(board.nodes) ? board.nodes as Node<SwarmBoardNodeData>[] : [];
        const edges = Array.isArray(board.edges) ? board.edges as SwarmBoardEdge[] : [];
        const boardId = typeof board.boardId === "string" ? board.boardId : generateBoardId();
        const repoRoot = typeof board.repoRoot === "string" ? board.repoRoot : "";
        set({
          bundlePath,
          boardId,
          repoRoot,
          nodes,
          edges,
          selectedNodeId: null,
          inspectorOpen: false,
          selectedNode: undefined,
          rfEdges: toRfEdges(edges),
        });
      } catch (err) {
        console.error("[swarm-board-store] loadFromBundle failed:", err);
        set({ bundlePath });
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
      });
      schedulePersist({ ...get() });
    },

    applyTopologyLayout: (
      topologyEdges: SwarmBoardEdge[],
      positions: Map<string, { x: number; y: number }>,
    ): void => {
      set((current) => {
        const nodes = current.nodes.map((node) => {
          const nextPosition = positions.get(node.id);
          return nextPosition ? { ...node, position: nextPosition } : node;
        });
        const edges = [
          ...current.edges.filter((edge) => edge.type !== "topology"),
          ...topologyEdges,
        ];

        return {
          nodes,
          edges,
          rfEdges: toRfEdges(edges),
          selectedNode: deriveSelectedNode(nodes, current.selectedNodeId),
        };
      });
      schedulePersist({ ...get() });
    },

    engineSync: (
      engineNodes: Array<{ id: string; agentId?: string; taskId?: string; data: Partial<SwarmBoardNodeData>; position?: { x: number; y: number } }>,
      engineEdges: SwarmBoardEdge[],
    ): void => {
      const current = get();
      const lookupById = new Map(engineNodes.map((en) => [en.id, en]));
      const lookupByAgentId = new Map(
        engineNodes
          .filter((en) => en.agentId)
          .map((en) => [en.agentId!, en]),
      );
      const lookupByTaskId = new Map(
        engineNodes
          .filter((en) => en.taskId)
          .map((en) => [en.taskId!, en]),
      );
      const isSnapshotManagedNode = (node: Node<SwarmBoardNodeData>): boolean => {
        const data = node.data as SwarmBoardNodeData;
        return (
          data.engineManaged === true &&
          (data.nodeType === "agentSession" || data.nodeType === "terminalTask")
        );
      };
      const findMatchingEngineNode = (
        node: Node<SwarmBoardNodeData>,
      ): (typeof engineNodes)[number] | undefined => {
        const data = node.data as SwarmBoardNodeData;
        return (
          lookupById.get(node.id) ??
          (data.agentId ? lookupByAgentId.get(data.agentId) : undefined) ??
          (data.taskId ? lookupByTaskId.get(data.taskId) : undefined)
        );
      };

      const preservedNodes = current.nodes.filter(
        (node) => !isSnapshotManagedNode(node),
      );
      const reconciledNodes = engineNodes.map((engineNode) => {
        const existingNode = current.nodes.find((node) => {
          if (!isSnapshotManagedNode(node)) {
            return false;
          }

          return findMatchingEngineNode(node)?.id === engineNode.id;
        });

        if (existingNode) {
          const existingData = existingNode.data as SwarmBoardNodeData;
          return {
            ...existingNode,
            id: engineNode.id,
            type:
              (engineNode.data.nodeType as SwarmBoardNodeData["nodeType"]) ??
              existingNode.type,
            data: {
              ...existingData,
              ...engineNode.data,
              agentId: engineNode.agentId,
              taskId: engineNode.taskId,
              engineManaged: true,
            },
            position: engineNode.position ?? existingNode.position,
          };
        }

        const newNode = createBoardNode({
          nodeType:
            (engineNode.data.nodeType as SwarmBoardNodeData["nodeType"]) ??
            "agentSession",
          title: (engineNode.data.title as string) ?? engineNode.id,
          position: engineNode.position,
          data: {
            ...engineNode.data,
            agentId: engineNode.agentId,
            taskId: engineNode.taskId,
            engineManaged: true,
          },
        });

        return { ...newNode, id: engineNode.id };
      });
      const nodes = [...preservedNodes, ...reconciledNodes];
      const nodeIds = new Set(nodes.map((node) => node.id));
      const isSnapshotManagedEdge = (edge: SwarmBoardEdge): boolean =>
        edge.type === "spawned" || edge.type === "topology";

      const edgesById = new Map(
        current.edges
          .filter((edge) => !isSnapshotManagedEdge(edge))
          .map((edge) => [edge.id, edge]),
      );
      for (const engineEdge of engineEdges) {
        edgesById.set(engineEdge.id, engineEdge);
      }
      const edges = Array.from(edgesById.values()).filter(
        (edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target),
      );

      set({
        nodes,
        edges,
        rfEdges: toRfEdges(edges),
        selectedNode: deriveSelectedNode(nodes, current.selectedNodeId),
      });
      schedulePersist({ ...get() });
    },

    addGuardReceipt: ({
      verdict,
      guardResults,
      signature,
      publicKey,
      agentNodeId,
      position,
      detail,
    }): Node<SwarmBoardNodeData> => {
      const current = get();

      if (signature && signature.length > 0) {
        const duplicate = current.nodes.find(
          (n) => (n.data as SwarmBoardNodeData).nodeType === "receipt" &&
                 (n.data as SwarmBoardNodeData).signature === signature,
        );
        if (duplicate) return duplicate;
      }

      const agentNode = agentNodeId
        ? current.nodes.find((n) => n.id === agentNodeId)
        : undefined;
      const anchor = agentNode?.position ?? position ?? {
        x: 100 + Math.random() * 400,
        y: 100 + Math.random() * 300,
      };

      const receiptNode = createBoardNode({
        nodeType: "receipt",
        title: `Guard: ${verdict.toUpperCase()}`,
        position: { x: anchor.x, y: anchor.y + 340 },
        data: {
          verdict,
          guardResults,
          signature,
          publicKey,
          status: "completed",
          engineManaged: true,
          ...(detail ? { previewLines: [detail] } : {}),
        },
      });

      const edges = agentNode
        ? [
          ...current.edges,
          {
            id: `edge-receipt-${receiptNode.id}-${agentNode.id}`,
            source: agentNode.id,
            target: receiptNode.id,
            type: "receipt" as const,
            label: verdict,
          },
        ]
        : current.edges;
      const nodes = [...current.nodes, receiptNode];

      set({
        nodes,
        edges,
        rfEdges: toRfEdges(edges),
        selectedNode: deriveSelectedNode(nodes, current.selectedNodeId),
      });
      schedulePersist({ ...get() });
      return receiptNode;
    },

    guardEvaluate: (
      agentNodeId: string,
      verdict: string,
      guardResults: Array<{ guard: string; allowed: boolean; duration_ms?: number }>,
      signature?: string,
      publicKey?: string,
    ): void => {
      const current = get();
      const agentNode = current.nodes.find((n) => n.id === agentNodeId);
      if (!agentNode) return;

      get().actions.addGuardReceipt({
        agentNodeId: agentNode.id,
        verdict: verdict as "allow" | "deny" | "warn",
        guardResults,
        signature,
        publicKey,
      });
    },
  },
}));

// Used for test reset and provider mount
function reinitializeFromStorage(): void {
  const fresh = getInitialState();
  useSwarmBoardStoreBase.setState({
    ...fresh,
    selectedNode: deriveSelectedNode(fresh.nodes, fresh.selectedNodeId),
    rfEdges: toRfEdges(fresh.edges),
  });
}

const storeWithInitialState = Object.assign(useSwarmBoardStoreBase, {
  getInitialState,
  reinitializeFromStorage,
});

export const useSwarmBoardStore = createSelectors(storeWithInitialState);

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

export interface SwarmBoardSessionContextValue {
  spawnSession: (opts: SpawnSessionOptions) => Promise<Node<SwarmBoardNodeData>>;
  spawnClaudeSession: (opts: SpawnClaudeSessionOptions) => Promise<Node<SwarmBoardNodeData>>;
  spawnWorktreeSession: (opts: SpawnWorktreeSessionOptions) => Promise<Node<SwarmBoardNodeData>>;
  killSession: (nodeId: string) => Promise<void>;
}

const SwarmBoardSessionContext = createContext<SwarmBoardSessionContextValue | null>(null);

const NOOP_SESSION_METHODS: SwarmBoardSessionContextValue = {
  spawnSession: () =>
    Promise.reject(new Error("useSwarmBoard must be used within SwarmBoardProvider for session management")),
  spawnClaudeSession: () =>
    Promise.reject(new Error("useSwarmBoard must be used within SwarmBoardProvider for session management")),
  spawnWorktreeSession: () =>
    Promise.reject(new Error("useSwarmBoard must be used within SwarmBoardProvider for session management")),
  killSession: () =>
    Promise.reject(new Error("useSwarmBoard must be used within SwarmBoardProvider for session management")),
};

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
  rfEdges: Edge[];
  spawnSession: (opts: SpawnSessionOptions) => Promise<Node<SwarmBoardNodeData>>;
  spawnClaudeSession: (opts: SpawnClaudeSessionOptions) => Promise<Node<SwarmBoardNodeData>>;
  spawnWorktreeSession: (opts: SpawnWorktreeSessionOptions) => Promise<Node<SwarmBoardNodeData>>;
  killSession: (nodeId: string) => Promise<void>;
}

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
        actions.guardEvaluate(action.agentNodeId, action.verdict, action.guardResults, action.signature, action.publicKey);
        break;
    }
  };
}

export function useSwarmBoard(): SwarmBoardContextValue {
  const state = useSwarmBoardStore(
    useShallow((s) => ({
      boardId: s.boardId,
      repoRoot: s.repoRoot,
      nodes: s.nodes,
      edges: s.edges,
      selectedNodeId: s.selectedNodeId,
      inspectorOpen: s.inspectorOpen,
      bundlePath: s.bundlePath,
    })),
  );
  const selectedNode = useSwarmBoardStore((s) => s.selectedNode);
  const rfEdges = useSwarmBoardStore((s) => s.rfEdges);
  const actions = useSwarmBoardStore((s) => s.actions);

  const dispatch = useMemo(() => createDispatchShim(), []);
  const sessionMethods = useSwarmBoardSession();

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
      rfEdges,
      ...sessionMethods,
    }),
    [state, dispatch, actions, selectedNode, rfEdges, sessionMethods],
  );
}

export function useSwarmBoardSession(): SwarmBoardSessionContextValue {
  return useContext(SwarmBoardSessionContext) ?? NOOP_SESSION_METHODS;
}

export function SwarmBoardProvider({ children, bundlePath }: { children: ReactNode; bundlePath?: string }) {
  useEffect(() => {
    if (bundlePath) {
      useSwarmBoardStore.getState().actions.loadFromBundle(bundlePath);
    } else {
      useSwarmBoardStore.reinitializeFromStorage();
    }
  }, [bundlePath]);

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

  const exitListenersRef = useRef<Map<string, UnlistenFn>>(new Map());
  const worktreeMapRef = useRef<Map<string, string>>(new Map());
  const closedSessionsRef = useRef<Set<string>>(new Set());
  const killingRef = useRef<Set<string>>(new Set());

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

  const monitorSessionExit = useCallback(
    (sessionId: string) => {
      closedSessionsRef.current.delete(sessionId);
      terminalService
        .onExit(sessionId, (exitCode) => {
          const status: SessionStatus =
            exitCode === null ? "completed" : exitCode === 0 ? "completed" : "failed";
          const { actions } = useSwarmBoardStore.getState();
          actions.setSessionStatus(sessionId, status, exitCode ?? undefined);
          actions.setSessionMetadata(sessionId, { sessionId: undefined });
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
          ...(wtPath ? { worktreePath: undefined } : {}),
        });
        killingRef.current.delete(nodeId);
      }
    },
    [cleanupSessionTracking],
  );

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

export type { SwarmBoardState, SwarmBoardNodeData, SwarmBoardEdge, SwarmNodeType, SessionStatus, RiskLevel };
