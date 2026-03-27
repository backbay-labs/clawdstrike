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
import { type Node, type Edge } from "@xyflow/react";
import { isDesktop } from "@/lib/tauri-bridge";
import { useProjectStore } from "@/features/project/stores/project-store";
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
import {
  appendTerminalPreviewChunk,
  sanitizeTerminalPreviewLines,
} from "@/lib/workbench/terminal-preview";
import type { UnlistenFn } from "@tauri-apps/api/event";
import {
  SWARM_BOARD_PERSISTENCE_FILE,
  readSwarmPersistencePayload,
} from "./swarm-persistence";
import {
  clearSwarmFileWatchScope,
  normalizeSwarmFileWatchPath,
  setSwarmFileWatchScope,
  subscribeSwarmFileWatchEvents,
} from "./swarm-file-watch";
import {
  bootstrapDefaultWorkspace,
  getDefaultWorkspacePath,
} from "@/features/project/workspace-bootstrap";
import {
  createBoardNode,
  toRfEdges,
  type CreateNodeConfig,
} from "./swarm-board-node-factory";
import {
  resolveBoardWatchFilePath,
  collectBoardWatchWorkspacePaths,
  normalizePersistedBoard,
  persistBoard,
  loadPersistedBoard,
  isRecoverableTmuxNode,
  buildSessionMetadataPatch,
  generateBoardId,
} from "./swarm-board-persistence";
// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum number of live xterm terminals to keep active simultaneously. */
export const MAX_ACTIVE_TERMINALS = 8;
/** Maximum number of total persistent sessions to keep on the board. */
export const MAX_TOTAL_SESSIONS = 64;
const SESSION_PREVIEW_MAX_LINES = 200;

function getPrimaryWorkspaceRoot(): string | undefined {
  return useProjectStore
    .getState()
    .projectRoots
    .find((root) => typeof root === "string" && root.trim().length > 0)
    ?.trim();
}

async function resolveDefaultWorkspaceRoot(): Promise<string | undefined> {
  if (!isDesktop()) {
    return undefined;
  }

  try {
    return (await bootstrapDefaultWorkspace()) ?? (await getDefaultWorkspacePath());
  } catch (err) {
    console.error("[swarm-board-store] Failed to resolve default workspace root:", err);
    return undefined;
  }
}

async function resolveBoardRepoRoot(preferred?: string): Promise<string | undefined> {
  const preferredRoot = preferred?.trim();
  if (preferredRoot) {
    return preferredRoot;
  }

  const boardRoot = useSwarmBoardStore.getState().repoRoot.trim();
  if (boardRoot) {
    return boardRoot;
  }

  const workspaceRoot = getPrimaryWorkspaceRoot();
  if (workspaceRoot) {
    return workspaceRoot;
  }

  const defaultWorkspaceRoot = await resolveDefaultWorkspaceRoot();
  if (defaultWorkspaceRoot) {
    return defaultWorkspaceRoot;
  }

  try {
    const cwd = await terminalService.getCwd();
    return cwd?.trim() || undefined;
  } catch {
    return undefined;
  }
}

function rememberBoardRepoRoot(repoRoot: string | undefined): void {
  const resolvedRoot = repoRoot?.trim();
  if (!resolvedRoot) {
    return;
  }

  if (useSwarmBoardStore.getState().repoRoot.trim()) {
    return;
  }

  useSwarmBoardStore.getState().actions.setRepoRoot(resolvedRoot);
}

function seedPreviewLines(startupInput?: string): string[] {
  const trimmed = startupInput?.trim();
  if (!trimmed) {
    return [];
  }

  return trimmed
    .split(/\r?\n/)
    .filter((line) => line.trim().length > 0)
    .slice(-4)
    .map((line) => (line.startsWith("$") ? line : `$ ${line}`));
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
// Persistence state
// ---------------------------------------------------------------------------

let boardPersistenceReady = typeof window === "undefined" || !isDesktop();
let boardHydratePromise: Promise<void> | null = null;

// ---------------------------------------------------------------------------
// Debounced persistence
// ---------------------------------------------------------------------------

let _persistTimer: ReturnType<typeof setTimeout> | null = null;

function schedulePersist(getState: () => SwarmBoardState): void {
  if (!boardPersistenceReady) {
    return;
  }
  if (_persistTimer) clearTimeout(_persistTimer);
  _persistTimer = setTimeout(() => {
    persistBoard(getState());
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
      schedulePersist(get);
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
      schedulePersist(get);
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
      schedulePersist(get);
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
      schedulePersist(get);
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
      schedulePersist(get);
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
      schedulePersist(get);
    },

    removeEdge: (edgeId: string): void => {
      const current = get();
      const edges = current.edges.filter((e) => e.id !== edgeId);
      set({
        edges,
        rfEdges: toRfEdges(edges),
      });
      schedulePersist(get);
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
      schedulePersist(get);
    },

    setRepoRoot: (repoRoot: string): void => {
      set({ repoRoot });
      schedulePersist(get);
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
      schedulePersist(get);
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
      schedulePersist(get);
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
      schedulePersist(get);
    },

    setNodes: (nodes: Node<SwarmBoardNodeData>[]): void => {
      const current = get();
      set({
        nodes,
        selectedNode: deriveSelectedNode(nodes, current.selectedNodeId),
        selectedNodes: deriveSelectedNodes(nodes, current.selectedNodeIds),
        comparisonMode: current.selectedNodeIds.length > 1,
      });
      schedulePersist(get);
    },

    setEdges: (edges: SwarmBoardEdge[]): void => {
      set({
        edges,
        rfEdges: toRfEdges(edges),
      });
      schedulePersist(get);
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
      schedulePersist(get);
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
      schedulePersist(get);
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
      schedulePersist(get);
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
      schedulePersist(() => useSwarmBoardStoreBase.getState());
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
  cwd?: string;
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
      selectedNodeIds: s.selectedNodeIds,
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
  const projectRoots = useProjectStore((s) => s.projectRoots);
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
  const projectRootsSignature = projectRoots.join("\n");
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

  // Seed repoRoot from the mounted workspace roots, default workspace, or CWD.
  useEffect(() => {
    const state = useSwarmBoardStore.getState();
    if (state.repoRoot) return;

    let cancelled = false;
    void resolveBoardRepoRoot().then((resolvedRoot) => {
      if (cancelled || !resolvedRoot) {
        return;
      }
      rememberBoardRepoRoot(resolvedRoot);
    });

    return () => {
      cancelled = true;
    };
  }, [projectRootsSignature]);

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
  const outputListenersRef = useRef<Map<string, UnlistenFn>>(new Map());
  const previewCarryRef = useRef<Map<string, string>>(new Map());
  const worktreeMapRef = useRef<Map<string, string>>(new Map());
  const closedSessionsRef = useRef<Set<string>>(new Set());
  const killingRef = useRef<Set<string>>(new Set());
  const reconnectingRef = useRef<Set<string>>(new Set());

  const cleanupSessionTracking = useCallback((sessionId: string): string | undefined => {
    closedSessionsRef.current.add(sessionId);
    const exitUnlisten = exitListenersRef.current.get(sessionId);
    if (exitUnlisten) {
      try {
        exitUnlisten();
      } catch {
        // best-effort cleanup
      }
    }
    exitListenersRef.current.delete(sessionId);
    const outputUnlisten = outputListenersRef.current.get(sessionId);
    if (outputUnlisten) {
      try {
        outputUnlisten();
      } catch {
        // best-effort cleanup
      }
    }
    outputListenersRef.current.delete(sessionId);
    previewCarryRef.current.delete(sessionId);
    const wtPath = worktreeMapRef.current.get(sessionId);
    worktreeMapRef.current.delete(sessionId);
    return wtPath;
  }, []);

  const subscribeSessionOutput = useCallback((nodeId: string, sessionId: string) => {
    closedSessionsRef.current.delete(sessionId);
    const subscribe = terminalService.onOutput?.bind(terminalService);
    if (!subscribe) {
      return;
    }

    subscribe(sessionId, (chunk) => {
      const state = useSwarmBoardStore.getState();
      const node = state.nodes.find((candidate) => candidate.id === nodeId);
      if (!node) {
        return;
      }
      const data = node.data as SwarmBoardNodeData;
      const { lines, carry } = appendTerminalPreviewChunk(data.previewLines, chunk, {
        carry: previewCarryRef.current.get(sessionId),
        maxLines: SESSION_PREVIEW_MAX_LINES,
      });

      if (carry) {
        previewCarryRef.current.set(sessionId, carry);
      } else {
        previewCarryRef.current.delete(sessionId);
      }

      state.actions.updateNode(nodeId, {
        previewLines: lines,
      });
    })
      .then((unlisten) => {
        if (closedSessionsRef.current.has(sessionId)) {
          unlisten();
          return;
        }
        const existing = outputListenersRef.current.get(sessionId);
        if (existing) {
          try {
            existing();
          } catch {
            // best-effort cleanup
          }
        }
        outputListenersRef.current.set(sessionId, unlisten);
      })
      .catch((err) => {
        console.error("[swarm-board-store] Failed to monitor output:", err);
      });
  }, []);

  const refreshSessionPreview = useCallback(
    async (nodeId: string, sessionId: string, fallback?: string[]) => {
      try {
        const previewLines = await terminalService.preview(sessionId, 24);
        useSwarmBoardStore.getState().actions.updateNode(nodeId, {
          previewLines: sanitizeTerminalPreviewLines(previewLines, SESSION_PREVIEW_MAX_LINES),
        });
      } catch {
        if (fallback) {
          useSwarmBoardStore.getState().actions.updateNode(nodeId, {
            previewLines: sanitizeTerminalPreviewLines(fallback, SESSION_PREVIEW_MAX_LINES),
          });
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

  // -----------------------------------------------------------------------
  // ORCHESTRATOR RECOVERY POLICY (Phase 26 / SESS-03)
  //
  // Recovered tmux sessions operate in "manual mode" only. The
  // SwarmOrchestrator's AgentRegistry, TaskGraph, and TopologyManager are
  // in-memory-only and are NOT persisted or recoverable. On restart, the
  // orchestrator creates fresh state with no knowledge of prior agents.
  //
  // Recovered sessions get `manualSession: true` (set below),
  // which means:
  //   - The guard pipeline is NOT evaluated for actions in these sessions
  //   - The task graph does NOT track these sessions
  //   - The operator can still interact with the shell and view output
  //
  // This is the pragmatic stance: orchestrator state persistence would
  // require inventing a serialization format for AgentRegistry and
  // TaskGraph, which is deferred to a future phase if engine-level
  // recovery becomes a product requirement.
  //
  // See: apps/workbench/docs/collab-upgrades/reviews/02-tmux-persistent-sessions-review.md
  //      Section 3.1 "Swarm Engine Orchestrator Integration"
  // -----------------------------------------------------------------------
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
            cwdMissing: session.cwd_valid === false,
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
        subscribeSessionOutput(selectedNode.id, session.id);
        useSwarmBoardStore.getState().actions.updateNode(selectedNode.id, {
          ...buildSessionMetadataPatch(session, {
            manualSession: true,
            terminalAttached: true,
          }),
          status: data.status === "blocked" ? "blocked" : "running",
          cwdMissing: session.cwd_valid === false,
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
  }, [monitorSessionExit, refreshSessionPreview, selectedNode, subscribeSessionOutput]);

  const spawnSession = useCallback(
    async (opts: SpawnSessionOptions): Promise<Node<SwarmBoardNodeData>> => {
      let cwd = await resolveBoardRepoRoot(opts.cwd);
      rememberBoardRepoRoot(cwd);
      if (!cwd) {
        cwd = "/tmp";
        console.warn("[swarm-board-store] No working directory for session; falling back to /tmp");
      }

      const startupInput = opts.launchClaude ? "claude\n" : opts.command;
      const initialPreviewLines = seedPreviewLines(startupInput);
      const sessionInfo = await terminalService.create(cwd, opts.shell, undefined, startupInput);
      const node = createBoardNode({
        nodeType: "agentSession",
        title: opts.title ?? (opts.launchClaude ? "Claude Session" : "Terminal"),
        position: opts.position,
        data: {
          agentModel: opts.launchClaude ? "claude" : "shell",
          status: "running",
          sessionId: sessionInfo.id,
          previewLines: initialPreviewLines,
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
      subscribeSessionOutput(node.id, sessionInfo.id);

      return node;
    },
    [monitorSessionExit, subscribeSessionOutput],
  );

  const spawnClaudeSession = useCallback(
    async (opts: SpawnClaudeSessionOptions): Promise<Node<SwarmBoardNodeData>> => {
      let cwd = await resolveBoardRepoRoot(opts.cwd);
      rememberBoardRepoRoot(cwd);

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

      const startupInput = "claude\n";
      const sessionInfo = await terminalService.create(cwd, undefined, undefined, startupInput);

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
          previewLines: seedPreviewLines(startupInput),
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
      subscribeSessionOutput(node.id, sessionInfo.id);

      if (opts.prompt) {
        const prompt = opts.prompt;
        setTimeout(() => {
          terminalService.write(sessionInfo.id, prompt + "\n").catch((err) => {
            console.error("[swarm-board-store] Failed to send prompt:", err);
          });
        }, 750);
      }

      return node;
    },
    [monitorSessionExit, subscribeSessionOutput],
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
      subscribeSessionOutput(node.id, sessionInfo.id);

      return node;
    },
    [monitorSessionExit, subscribeSessionOutput],
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
// Facade re-exports (extracted modules)
// ---------------------------------------------------------------------------

export {
  summarizeReceiptPosture,
  summarizeGuardPolicyHeatmap,
  type ReceiptPostureState,
  type ReceiptPostureSummary,
  type GuardPolicySummary,
  type GuardPolicyHeatmapSummary,
} from "./swarm-board-analytics";

export {
  createBoardNode,
  createMockBoard,
  generateNodeId,
  type CreateNodeConfig,
} from "./swarm-board-node-factory";

export {
  resolveBoardWatchFilePath,
  collectBoardWatchWorkspacePaths,
} from "./swarm-board-persistence";

// ---------------------------------------------------------------------------
// Type re-exports
// ---------------------------------------------------------------------------

export type { SwarmBoardState, SwarmBoardNodeData, SwarmBoardEdge, SwarmNodeType, SessionStatus, RiskLevel };
