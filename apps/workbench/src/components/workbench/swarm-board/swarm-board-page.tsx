/**
 * SwarmBoardPage — full-page React Flow canvas for multi-agent coordination.
 *
 * This is the core SwarmBoard view. It renders the React Flow graph with
 * custom node types, a toolbar, minimap, controls, and an inspector drawer.
 *
 * Architecture: ReactFlowProvider wraps everything so the toolbar can access
 * `useReactFlow()` for zoom/layout controls. SwarmBoardProvider sits outside
 * to manage node/edge state.
 */

import { forwardRef, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ReactFlow,
  ReactFlowProvider,
  MiniMap,
  useReactFlow,
  type Node,
  type OnConnect,
  type OnNodesChange,
  type OnEdgesChange,
  type NodeMouseHandler,
  applyNodeChanges,
  applyEdgeChanges,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
// ghostty-web uses canvas rendering — no external CSS needed
import {
  IconSearch,
  IconCopy,
  IconTrash,
  IconLink,
  IconCommand,
} from "@tabler/icons-react";

import { SwarmBoardProvider, useSwarmBoard } from "@/lib/workbench/swarm-board-store";
import { swarmBoardNodeTypes } from "./nodes";
import { swarmBoardEdgeTypes } from "./edges";
import { SwarmBoardToolbar } from "./swarm-board-toolbar";
import { SwarmBoardLeftRail } from "./swarm-board-left-rail";
import { SwarmBoardInspector } from "./swarm-board-inspector";
import type { SwarmBoardNodeData, SwarmNodeType } from "@/lib/workbench/swarm-board-types";

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

/** Override React Flow's default background/chrome to match dark theme */
const RF_STYLE: React.CSSProperties = {
  backgroundColor: "#05060a",
};

const MINIMAP_STYLE: React.CSSProperties = {
  backgroundColor: "#05060a",
  border: "none",
  borderRadius: 4,
  opacity: 0.6,
};

const FIT_VIEW_OPTIONS = { padding: 0.2 };
const DEFAULT_EDGE_OPTIONS = {
  style: { stroke: "#1a1f2e", strokeWidth: 1 },
  type: "swarmEdge" as const,
};
const CONNECTION_LINE_STYLE = { stroke: "#d4a84b60", strokeWidth: 1.5 };
const PRO_OPTIONS = { hideAttribution: true };
const DELETE_KEY_CODE = ["Backspace", "Delete"];
const SELECTION_KEY_CODE = ["Shift"];

// Minimap node color by type
function minimapNodeColor(node: Node): string {
  const data = node.data as SwarmBoardNodeData | undefined;
  switch (data?.nodeType) {
    case "agentSession":
      return "#d4a84b80";
    case "terminalTask":
      return "#5b8def60";
    case "artifact":
      return "#3dbf8460";
    case "diff":
      return "#8b5cf660";
    case "note":
      return "#d4a84b30";
    case "receipt":
      return "#8b5cf640";
    default:
      return "#1a1f2e";
  }
}

// ---------------------------------------------------------------------------
// Context menu state
// ---------------------------------------------------------------------------

interface NodeContextMenuState {
  nodeId: string;
  x: number;
  y: number;
}

// ---------------------------------------------------------------------------
// Inner canvas component (needs both SwarmBoardProvider and ReactFlowProvider)
// ---------------------------------------------------------------------------

function SwarmBoardCanvas() {
  const { state, dispatch, selectNode, removeNode, addNode, updateNode, rfEdges, killSession, spawnSession } = useSwarmBoard();
  const { nodes, edges } = state;
  const reactFlow = useReactFlow();

  // Context menu
  const [contextMenu, setContextMenu] = useState<NodeContextMenuState | null>(null);
  const contextMenuRef = useRef<HTMLDivElement>(null);

  // Follow-active toggle
  const [followActive, setFollowActive] = useState(false);

  // Hovered node tracking for edge hover-reveal
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);

  // Use refs to avoid stale closures in callbacks — React Flow calls these
  // handlers rapidly during drag operations and the callback identity must
  // stay stable to avoid unnecessary re-subscriptions.
  const nodesRef = useRef(nodes);
  nodesRef.current = nodes;
  const rfEdgesRef = useRef(rfEdges);
  rfEdgesRef.current = rfEdges;
  const edgesRef = useRef(edges);
  edgesRef.current = edges;

  // Handle React Flow's built-in node changes (drag, resize, select, remove)
  const onNodesChange: OnNodesChange = useCallback(
    (changes) => {
      // Intercept removals to clean up live PTY sessions before the node is deleted
      for (const change of changes) {
        if (change.type === "remove") {
          const node = nodesRef.current.find((n) => n.id === change.id);
          if (node) {
            const d = node.data as SwarmBoardNodeData;
            if (d.sessionId && (d.status === "running" || d.status === "blocked")) {
              // Fire-and-forget: kill session + worktree cleanup
              killSession(change.id).catch(() => {});
            }
          }
        }
      }
      const updated = applyNodeChanges(changes, nodesRef.current);
      dispatch({ type: "SET_NODES", nodes: updated as Node<SwarmBoardNodeData>[] });
    },
    [dispatch, killSession],
  );

  // Handle React Flow's built-in edge changes (remove)
  const onEdgesChange: OnEdgesChange = useCallback(
    (changes) => {
      const updated = applyEdgeChanges(changes, rfEdgesRef.current);
      // Convert back to our edge format
      const newEdges = updated.map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        label: typeof e.label === "string" ? e.label : undefined,
        type: findEdgeType(e.id, edgesRef.current),
      }));
      dispatch({ type: "SET_EDGES", edges: newEdges });
    },
    [dispatch],
  );

  // Handle new connections drawn by the user
  const onConnect: OnConnect = useCallback(
    (params) => {
      if (!params.source || !params.target) return;
      const edgeId = `edge-${params.source}-${params.target}-${Date.now().toString(36)}`;
      dispatch({
        type: "ADD_EDGE",
        edge: {
          id: edgeId,
          source: params.source,
          target: params.target,
          type: "handoff",
        },
      });
    },
    [dispatch],
  );

  // Node click -> select & open inspector
  const onNodeClick: NodeMouseHandler = useCallback(
    (_event, node) => {
      selectNode(node.id);
      setContextMenu(null);
    },
    [selectNode],
  );

  // Double-click on node -> type-specific behavior
  const onNodeDoubleClick: NodeMouseHandler = useCallback(
    (_event, node) => {
      const d = node.data as SwarmBoardNodeData;
      selectNode(node.id);

      if (d.nodeType === "agentSession") {
        // Open inspector AND expand terminal preview
        updateNode(node.id, { maximized: true });
      } else if (d.nodeType === "note") {
        // Enter edit mode
        updateNode(node.id, { editing: true });
      }
      // For all other types, just opening inspector (via selectNode) is sufficient
    },
    [selectNode, updateNode],
  );

  // Right-click on node -> context menu
  const onNodeContextMenu: NodeMouseHandler = useCallback(
    (event, node) => {
      event.preventDefault();
      setContextMenu({
        nodeId: node.id,
        x: event.clientX,
        y: event.clientY,
      });
    },
    [],
  );

  // Click on empty canvas -> deselect
  const onPaneClick = useCallback(() => {
    selectNode(null);
    setContextMenu(null);
    setHoveredNodeId(null);
  }, [selectNode]);

  // Track hovered node for edge hover-reveal behavior
  const onNodeMouseEnter: NodeMouseHandler = useCallback(
    (_event, node) => {
      setHoveredNodeId(node.id);
    },
    [],
  );

  const onNodeMouseLeave: NodeMouseHandler = useCallback(
    () => {
      setHoveredNodeId(null);
    },
    [],
  );

  // Close context menu on click-outside
  useEffect(() => {
    if (!contextMenu) return;
    function handleClickOutside(e: MouseEvent) {
      if (contextMenuRef.current && !contextMenuRef.current.contains(e.target as HTMLElement)) {
        setContextMenu(null);
      }
    }
    function handleEsc(e: KeyboardEvent) {
      if (e.key === "Escape") setContextMenu(null);
    }
    document.addEventListener("mousedown", handleClickOutside);
    document.addEventListener("keydown", handleEsc);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("keydown", handleEsc);
    };
  }, [contextMenu]);

  // Get viewport center for new nodes
  const getDropPosition = useCallback(() => {
    try {
      const viewport = reactFlow.getViewport();
      const centerX = (-viewport.x + window.innerWidth / 2) / viewport.zoom;
      const centerY = (-viewport.y + window.innerHeight / 2) / viewport.zoom;
      return {
        x: centerX + (Math.random() - 0.5) * 100,
        y: centerY + (Math.random() - 0.5) * 100,
      };
    } catch {
      return { x: 200 + Math.random() * 300, y: 200 + Math.random() * 200 };
    }
  }, [reactFlow]);

  // ------- Keyboard shortcuts -------
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      // Don't intercept when typing in an input, textarea, contentEditable,
      // or inside an xterm terminal container
      const target = e.target as HTMLElement;
      if (
        target.tagName === "INPUT" ||
        target.tagName === "TEXTAREA" ||
        target.isContentEditable ||
        target.closest(".nodrag")
      ) {
        return;
      }

      const isMeta = e.metaKey || e.ctrlKey;

      // Escape -> deselect all and close inspector
      if (e.key === "Escape") {
        selectNode(null);
        setContextMenu(null);
        return;
      }

      // Cmd/Ctrl+A -> select all nodes
      if (isMeta && e.key === "a") {
        e.preventDefault();
        const allNodes = nodesRef.current.map((n) => ({
          ...n,
          selected: true,
        }));
        dispatch({ type: "SET_NODES", nodes: allNodes as Node<SwarmBoardNodeData>[] });
        return;
      }

      // Cmd/Ctrl+Shift+N -> new session node (real PTY with fallback)
      if (isMeta && e.shiftKey && e.key === "N") {
        e.preventDefault();
        const cwd = state.repoRoot || "/tmp";
        spawnSession({ cwd, position: getDropPosition(), title: "Terminal" }).catch(() => {
          // Fallback to mock node if Tauri is not available
          addNode({
            nodeType: "agentSession",
            title: "Session (offline)",
            position: getDropPosition(),
            data: {
              agentModel: "shell",
              status: "idle",
              previewLines: ["[Tauri desktop required for live sessions]"],
              receiptCount: 0,
              blockedActionCount: 0,
              changedFilesCount: 0,
              risk: "low",
              policyMode: "default",
            },
          });
        });
        return;
      }

      // Cmd/Ctrl+Shift+M -> new note node
      if (isMeta && e.shiftKey && e.key === "M") {
        e.preventDefault();
        addNode({
          nodeType: "note",
          title: "Note",
          position: getDropPosition(),
          data: { content: "" },
        });
        return;
      }

      // Number keys 1-6: quick-add node types
      if (!isMeta && !e.shiftKey && !e.altKey) {
        const quickAddMap: Record<string, { nodeType: SwarmNodeType; title: string }> = {
          "1": { nodeType: "agentSession", title: "New Session" },
          "2": { nodeType: "terminalTask", title: "New Task" },
          "3": { nodeType: "artifact", title: "New Artifact" },
          "4": { nodeType: "diff", title: "New Diff" },
          "5": { nodeType: "note", title: "New Note" },
          "6": { nodeType: "receipt", title: "New Receipt" },
        };
        const quickAdd = quickAddMap[e.key];
        if (quickAdd) {
          e.preventDefault();
          addNode({
            ...quickAdd,
            position: getDropPosition(),
          });
          return;
        }

        // F -> fit view (gather)
        if (e.key === "f" || e.key === "F") {
          e.preventDefault();
          reactFlow.fitView({ padding: 0.2, duration: 500 });
          return;
        }

        // Space -> toggle follow active
        if (e.key === " ") {
          e.preventDefault();
          setFollowActive((prev) => !prev);
          return;
        }
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [selectNode, dispatch, addNode, getDropPosition, reactFlow, spawnSession, state.repoRoot]);

  // Follow active — auto-zoom to running node
  useEffect(() => {
    if (!followActive) return;
    const interval = setInterval(() => {
      const runningNode = nodesRef.current.find(
        (n) => (n.data as SwarmBoardNodeData).status === "running",
      );
      if (runningNode) {
        reactFlow.fitView({
          nodes: [runningNode],
          padding: 0.5,
          duration: 400,
        });
      }
    }, 2000);
    return () => clearInterval(interval);
  }, [followActive, reactFlow]);

  // Context menu actions
  const handleContextInspect = useCallback(() => {
    if (contextMenu) {
      selectNode(contextMenu.nodeId);
      setContextMenu(null);
    }
  }, [contextMenu, selectNode]);

  const handleContextDuplicate = useCallback(() => {
    if (!contextMenu) return;
    const sourceNode = nodesRef.current.find((n) => n.id === contextMenu.nodeId);
    if (!sourceNode) return;
    const d = sourceNode.data as SwarmBoardNodeData;
    addNode({
      nodeType: d.nodeType,
      title: `${d.title} (copy)`,
      position: {
        x: sourceNode.position.x + 40,
        y: sourceNode.position.y + 40,
      },
      data: { ...d, title: `${d.title} (copy)` },
    });
    setContextMenu(null);
  }, [contextMenu, addNode]);

  const handleContextDelete = useCallback(() => {
    if (contextMenu) {
      // Kill the PTY session if this is a live terminal node
      const node = nodesRef.current.find((n) => n.id === contextMenu.nodeId);
      if (node) {
        const d = node.data as SwarmBoardNodeData;
        if (d.sessionId) {
          killSession(contextMenu.nodeId).catch(() => {});
        }
      }
      removeNode(contextMenu.nodeId);
      setContextMenu(null);
    }
  }, [contextMenu, removeNode, killSession]);

  const handleContextConnect = useCallback(() => {
    if (contextMenu) {
      // Connection picker not yet implemented (tracked in swarm-board backlog)
      setContextMenu(null);
    }
  }, [contextMenu]);

  // Memoize the type maps (must be stable references)
  const nodeTypes = useMemo(() => swarmBoardNodeTypes, []);
  const edgeTypes = useMemo(() => swarmBoardEdgeTypes, []);

  // Enrich edges with hoveredNodeId for hover-reveal behavior
  const enrichedEdges = useMemo(() => {
    const selectedId = state.selectedNodeId;
    return rfEdges.map((e) => ({
      ...e,
      data: {
        ...e.data,
        hoveredNodeId: hoveredNodeId,
        selectedNodeId: selectedId,
      },
    }));
  }, [rfEdges, hoveredNodeId, state.selectedNodeId]);

  // Stats
  const totalNodes = nodes.length;
  const runningSessions = nodes.filter(
    (n) => (n.data as SwarmBoardNodeData).nodeType === "agentSession" &&
           (n.data as SwarmBoardNodeData).status === "running",
  ).length;
  const blockedSessions = nodes.filter(
    (n) => (n.data as SwarmBoardNodeData).nodeType === "agentSession" &&
           (n.data as SwarmBoardNodeData).status === "blocked",
  ).length;
  const totalReceipts = nodes.filter(
    (n) => (n.data as SwarmBoardNodeData).nodeType === "receipt",
  ).length;
  const totalEdges = edges.length;
  const isEmpty = totalNodes === 0;

  return (
    <div className="flex flex-col h-full w-full" style={{ backgroundColor: "#05060a" }}>
      {/* Toolbar (uses useReactFlow) */}
      <SwarmBoardToolbar />

      {/* Main area: left rail + canvas */}
      <div className="flex flex-1 min-h-0">
        {/* Left rail — workspace explorer (Section 9) */}
        <SwarmBoardLeftRail />

        {/* Canvas */}
        <div className="flex-1 relative flex flex-col">
          <div className="flex-1 relative">
            {/* Global keyframe animations for node breathing effects */}
            <style>{`
              @keyframes breathe-gold {
                0%, 100% { box-shadow: 0 0 12px 0 rgba(212,168,75,0.05); }
                50% { box-shadow: 0 0 24px 4px rgba(212,168,75,0.1); }
              }
              @keyframes breathe-amber {
                0%, 100% { box-shadow: 0 0 12px 0 rgba(245,158,11,0.05); }
                50% { box-shadow: 0 0 24px 4px rgba(245,158,11,0.1); }
              }
              @keyframes breathe-red {
                0%, 100% { box-shadow: 0 0 12px 0 rgba(196,92,92,0.05); }
                50% { box-shadow: 0 0 24px 4px rgba(196,92,92,0.08); }
              }
              @keyframes heartbeat {
                0%, 100% { opacity: 0.3; transform: scale(1); }
                50% { opacity: 1; transform: scale(1.015); }
              }
            `}</style>

            <ReactFlow
              nodes={nodes}
              edges={enrichedEdges}
              nodeTypes={nodeTypes}
              edgeTypes={edgeTypes}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onConnect={onConnect}
              onNodeClick={onNodeClick}
              onNodeDoubleClick={onNodeDoubleClick}
              onNodeContextMenu={onNodeContextMenu}
              onNodeMouseEnter={onNodeMouseEnter}
              onNodeMouseLeave={onNodeMouseLeave}
              onPaneClick={onPaneClick}
              nodesDraggable
              nodesConnectable
              fitView
              fitViewOptions={FIT_VIEW_OPTIONS}
              minZoom={0.1}
              maxZoom={2}
              defaultEdgeOptions={DEFAULT_EDGE_OPTIONS}
              connectionLineStyle={CONNECTION_LINE_STYLE}
              proOptions={PRO_OPTIONS}
              style={RF_STYLE}
              deleteKeyCode={DELETE_KEY_CODE}
              selectionKeyCode={SELECTION_KEY_CODE}
            >
              {/* MiniMap — subtle, blends into bottom-right corner */}
              <MiniMap
                style={MINIMAP_STYLE}
                nodeColor={minimapNodeColor}
                maskColor="rgba(5,6,10,0.85)"
                position="bottom-right"
                pannable
                zoomable
              />
              {/* No Controls component — toolbar provides zoom */}
            </ReactFlow>

            {/* Canvas atmosphere — radial vignette */}
            <div
              className="absolute inset-0 pointer-events-none"
              style={{
                background: 'radial-gradient(ellipse at 50% 50%, rgba(12,14,20,0.0) 0%, rgba(5,6,10,0.6) 70%, rgba(2,3,5,0.9) 100%)',
                zIndex: 0,
              }}
            />
            {/* Subtle noise texture overlay */}
            <div
              className="absolute inset-0 pointer-events-none"
              style={{
                backgroundImage: `url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.03'/%3E%3C/svg%3E")`,
                backgroundRepeat: 'repeat',
                backgroundSize: '256px 256px',
                zIndex: 0,
                opacity: 0.4,
              }}
            />

            {/* Empty board state */}
            {isEmpty && (
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none z-10">
                <h1 className="text-[32px] font-syne font-bold text-[#1a1f2e] tracking-tight">
                  SwarmBoard
                </h1>
                <p className="text-[13px] text-[#1a1f2e] font-mono mt-2">
                  spawn a session to start operating
                </p>
                <div className="flex items-center gap-3 mt-6">
                  <kbd className="inline-flex items-center gap-1 px-2 py-1 rounded text-[9px] font-mono text-[#1e2230] bg-[#0a0c12]">
                    <IconCommand size={10} stroke={1.5} />
                    <span>Shift+N</span>
                  </kbd>
                  <span className="text-[9px] text-[#1e2230] font-mono">new session</span>
                  <span className="text-[#0d1018] mx-1">|</span>
                  <kbd className="inline-flex items-center gap-1 px-2 py-1 rounded text-[9px] font-mono text-[#1e2230] bg-[#0a0c12]">
                    <span>1-6</span>
                  </kbd>
                  <span className="text-[9px] text-[#1e2230] font-mono">quick add</span>
                </div>
              </div>
            )}

            {/* Inspector overlay */}
            <SwarmBoardInspector />

            {/* Node context menu */}
            {contextMenu && (
              <NodeContextMenu
                ref={contextMenuRef}
                menu={contextMenu}
                onInspect={handleContextInspect}
                onDuplicate={handleContextDuplicate}
                onDelete={handleContextDelete}
                onConnect={handleContextConnect}
              />
            )}
          </div>

          {/* Stats bar */}
          <SwarmBoardStatsBar
            totalNodes={totalNodes}
            runningSessions={runningSessions}
            blockedSessions={blockedSessions}
            totalReceipts={totalReceipts}
            totalEdges={totalEdges}
            followActive={followActive}
          />
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Node Context Menu
// ---------------------------------------------------------------------------

const NodeContextMenu = forwardRef<
  HTMLDivElement,
  {
    menu: NodeContextMenuState;
    onInspect: () => void;
    onDuplicate: () => void;
    onDelete: () => void;
    onConnect: () => void;
  }
>(({ menu, onInspect, onDuplicate, onDelete, onConnect }, ref) => {
  const items = [
    { label: "Inspect", icon: IconSearch, action: onInspect },
    { label: "Duplicate", icon: IconCopy, action: onDuplicate },
    { label: "Delete", icon: IconTrash, action: onDelete, danger: true },
    { type: "separator" as const },
    { label: "Connect to...", icon: IconLink, action: onConnect, disabled: true },
  ];

  return (
    <div
      ref={ref}
      className="fixed z-[100] min-w-[140px] bg-[#0c0e14] border border-[#1a1f2e] rounded-md shadow-[0_8px_32px_rgba(0,0,0,0.6)] py-1"
      style={{ left: menu.x, top: menu.y }}
    >
      {items.map((item, i) => {
        if ("type" in item && item.type === "separator") {
          return <div key={i} className="h-px bg-[#0f1119] my-1" />;
        }
        const Icon = "icon" in item ? item.icon : null;
        const isDanger = "danger" in item && item.danger;
        const isDisabled = "disabled" in item && item.disabled;
        return (
          <button
            key={i}
            type="button"
            className={`flex items-center gap-2 w-full px-3 py-1.5 text-[10px] font-mono transition-colors text-left ${
              isDisabled
                ? "text-[#1e2230] cursor-default"
                : isDanger
                  ? "text-[#6f7f9a] hover:text-[#e74c3c] hover:bg-[#e74c3c08]"
                  : "text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#ffffff06]"
            }`}
            onClick={() => {
              if (!isDisabled && "action" in item) item.action();
            }}
            disabled={isDisabled}
            aria-label={"label" in item ? item.label : undefined}
          >
            {Icon && <Icon size={12} stroke={1.5} />}
            {"label" in item && item.label}
          </button>
        );
      })}
    </div>
  );
});

NodeContextMenu.displayName = "NodeContextMenu";

// ---------------------------------------------------------------------------
// Stats Bar
// ---------------------------------------------------------------------------

const STATS_BAR_HEIGHT = 20;

function SwarmBoardStatsBar({
  totalNodes,
  runningSessions,
  blockedSessions,
  totalReceipts,
  totalEdges,
  followActive,
}: {
  totalNodes: number;
  runningSessions: number;
  blockedSessions: number;
  totalReceipts: number;
  totalEdges: number;
  followActive: boolean;
}) {
  // Build stat segments, then join with dot separator
  const segments: Array<{ text: string; color?: string }> = [
    { text: `${totalNodes} nodes` },
  ];
  if (runningSessions > 0) segments.push({ text: `${runningSessions} running`, color: "#3dbf84" });
  if (blockedSessions > 0) segments.push({ text: `${blockedSessions} blocked`, color: "#d4a84b" });
  if (totalReceipts > 0) segments.push({ text: `${totalReceipts} receipts` });
  if (totalEdges > 0) segments.push({ text: `${totalEdges} edges` });
  if (followActive) segments.push({ text: "following", color: "#3dbf84" });

  return (
    <div
      className="flex items-center px-3 shrink-0 select-none"
      style={{ height: STATS_BAR_HEIGHT, backgroundColor: "#070910", borderTop: "1px solid #0a0c12" }}
    >
      <span className="text-[9px] font-mono text-[#1e2230] tabular-nums">
        {segments.map((seg, i) => (
          <span key={i}>
            {i > 0 && <span className="mx-1">&middot;</span>}
            <span style={seg.color ? { color: seg.color } : undefined}>{seg.text}</span>
          </span>
        ))}
      </span>
      <span className="ml-auto text-[8px] text-[#0f1119] font-mono">
        1-6 add / F fit / Space follow
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page wrapper — sets up providers in correct order
// ---------------------------------------------------------------------------

export function SwarmBoardPage() {
  return (
    <SwarmBoardProvider>
      <ReactFlowProvider>
        <SwarmBoardCanvas />
      </ReactFlowProvider>
    </SwarmBoardProvider>
  );
}

// Default export for lazy loading in App.tsx
export default SwarmBoardPage;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function findEdgeType(
  edgeId: string,
  edges: Array<{ id: string; type?: string }>,
): "handoff" | "spawned" | "artifact" | "receipt" | undefined {
  const found = edges.find((e) => e.id === edgeId);
  return found?.type as "handoff" | "spawned" | "artifact" | "receipt" | undefined;
}
