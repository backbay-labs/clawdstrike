/**
 * SwarmBoardPage — full-page React Flow canvas for multi-agent coordination.
 *
 * This is the core SwarmBoard view. It renders the React Flow graph with
 * custom node types, a toolbar, minimap, controls, and an inspector drawer.
 *
 * Architecture: ReactFlowProvider wraps the canvas, while the page keeps
 * viewport state in controlled mode so toolbar actions and wheel gestures
 * share one source of truth. SwarmBoardProvider sits outside to manage
 * node/edge state.
 */

import React, { forwardRef, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useLocation } from "react-router-dom";
import { useCoordinatorBoardBridge } from "@/features/swarm/hooks/use-coordinator-board-bridge";
import { usePolicyEvalBoardBridge } from "@/features/swarm/hooks/use-policy-eval-board-bridge";
import { useTrustGraphBridge } from "@/features/swarm/hooks/use-trust-graph-bridge";
import { useReceiptFlowBridge, receiptEdgeTimestamps } from "@/features/swarm/hooks/use-receipt-flow-bridge";
import { SwarmEngineProvider, useSwarmEngine } from "@/features/swarm/stores/swarm-engine-provider";
import { useEngineBoardBridge } from "@/features/swarm/hooks/use-engine-board-bridge";
import { getCoordinator } from "@/features/swarm/coordinator-instance";
import { useSwarmRpcBridge } from "@/features/swarm/rpc/swarm-rpc-bridge";
import { registerSwarmRpcViewportController } from "@/features/swarm/rpc/swarm-rpc-viewport";
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  BackgroundVariant,
  MiniMap,
  useReactFlow,
  useOnSelectionChange,
  type Node,
  type Edge,
  type Viewport,
  type OnConnect,
  type OnNodesChange,
  type OnEdgesChange,
  type NodeMouseHandler,
  type OnNodeDrag,
  type SelectionDragHandler,
  applyNodeChanges,
  applyEdgeChanges,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
// ghostty-web uses canvas rendering — no external CSS needed
import {
  IconSearch,
  IconCopy,
  IconTrash,
  IconCommand,
  IconLink,
} from "@tabler/icons-react";

import {
  SwarmBoardProvider,
  useSwarmBoard,
  useSwarmBoardStore,
  summarizeReceiptPosture,
} from "@/features/swarm/stores/swarm-board-store";
import { usePaneStore } from "@/features/panes/pane-store";
import { swarmBoardNodeTypes } from "./nodes";
import { swarmBoardEdgeTypes } from "./edges";
import { SwarmBoardToolbar } from "./swarm-board-toolbar";
import { SwarmBoardLeftRail } from "./swarm-board-left-rail";
import { SwarmBoardInspector } from "./swarm-board-inspector";
import { buildSwarmBoardAtmosphere } from "./swarm-board-atmosphere";
import { EdgeIndicators } from "./components/edge-indicators";
import {
  SWARM_BOARD_GRID_GAP,
  SWARM_BOARD_GRID_MAJOR_GAP,
  SWARM_BOARD_PAN_ON_DRAG_BUTTONS,
  SWARM_BOARD_SHORTCUT_HINT,
  nudgeSelectedBoardNodes,
} from "./swarm-board-canvas-controls";
import { snapPositionToGrid, positionNeedsSnap } from "@/features/swarm/canvas/snap-to-grid";
import {
  SWARM_VIEWPORT_HARD_MAX_ZOOM,
  SWARM_VIEWPORT_HARD_MIN_ZOOM,
  SWARM_VIEWPORT_SNAPBACK_DELAY_MS,
  SWARM_VIEWPORT_TARGET_MAX_ZOOM,
  SWARM_VIEWPORT_TARGET_MIN_ZOOM,
  applyViewportWheelPan,
  applyViewportWheelZoom,
  areViewportsEqual,
  getZoomIndicatorLabel,
  shouldSyncControlledViewport,
  shouldZoomCanvasWheel,
  stepViewportSnapback,
  viewportNeedsSnapback,
  zoomViewportAroundPoint,
  type SwarmViewportPoint,
  type SwarmViewportSource,
} from "@/features/swarm/canvas/viewport-controller";
import type { SwarmBoardNodeData, SwarmBoardEdge, SwarmNodeType } from "@/features/swarm/swarm-board-types";

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
const DEFAULT_VIEWPORT: Viewport = { x: 0, y: 0, zoom: 1 };
const ZOOM_INDICATOR_HIDE_MS = 1200;

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

/** Returns true when the event target is a text input or inside a .nodrag zone. */
function isInputTarget(e: KeyboardEvent): boolean {
  const target = e.target as HTMLElement;
  return (
    target.tagName === "INPUT" ||
    target.tagName === "TEXTAREA" ||
    target.isContentEditable ||
    !!target.closest(".nodrag")
  );
}

// ---------------------------------------------------------------------------
// Inner canvas component (needs both SwarmBoardProvider and ReactFlowProvider)
// ---------------------------------------------------------------------------

function SwarmBoardCanvas() {
  const {
    state,
    removeNode,
    addNode,
    updateNode,
    rfEdges,
    killSession,
    spawnSession,
    spawnClaudeSession,
    spawnWorktreeSession,
  } = useSwarmBoard();
  const { nodes, edges } = state;
  const storeActions = useSwarmBoardStore((s) => s.actions);
  const reactFlow = useReactFlow();

  // Bridge SwarmCoordinator messages to board store (live intel/detection nodes)
  const coordinator = useMemo(() => getCoordinator(), []);
  useCoordinatorBoardBridge(coordinator);
  usePolicyEvalBoardBridge(coordinator);
  useTrustGraphBridge(coordinator);

  // Bridge feed store findings to receipt nodes on the board
  useReceiptFlowBridge();

  // Bridge engine events to board store (live engine-managed nodes)
  const engineCtx = useSwarmEngine();
  useEngineBoardBridge(engineCtx.engine, engineCtx.taskGraph);
  useSwarmRpcBridge({
    spawnSession,
    spawnClaudeSession,
    spawnWorktreeSession,
    killSession,
  });

  // Coordinator status for stats bar
  const coordinatorConnected = coordinator?.isConnected ?? false;
  const outboxSize = coordinator?.outboxSize ?? 0;
  const joinedSwarms = coordinator?.joinedSwarmIds?.length ?? 0;

  // Context menu
  const [contextMenu, setContextMenu] = useState<NodeContextMenuState | null>(null);
  const contextMenuRef = useRef<HTMLDivElement>(null);

  // Manual edge-creation: two-phase "Connect to..." workflow
  const [connectingFrom, setConnectingFrom] = useState<{
    nodeId: string;
    edgeType: SwarmBoardEdge["type"];
  } | null>(null);

  // Follow-active toggle
  const [followActive, setFollowActive] = useState(false);

  // Space+drag pan mode
  const [spaceHeld, setSpaceHeld] = useState(false);

  // Hovered node tracking for edge hover-reveal
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [viewport, setViewport] = useState<Viewport>(DEFAULT_VIEWPORT);
  const [zoomIndicator, setZoomIndicator] = useState<string | null>(null);
  const canvasViewportRef = useRef<HTMLDivElement>(null);
  const viewportRef = useRef(viewport);
  viewportRef.current = viewport;
  const viewportSourceRef = useRef<SwarmViewportSource>("idle");
  const snapbackTimerRef = useRef<number | null>(null);
  const snapbackFrameRef = useRef<number | null>(null);
  const zoomIndicatorTimerRef = useRef<number | null>(null);
  const lastViewportFocusRef = useRef<SwarmViewportPoint | null>(null);
  const hasInitialFitRef = useRef(false);
  const isMacLikeRef = useRef(
    typeof navigator !== "undefined"
      ? /Mac|iPhone|iPad|iPod/i.test(navigator.platform)
      : false,
  );

  // Use refs to avoid stale closures in callbacks — React Flow calls these
  // handlers rapidly during drag operations and the callback identity must
  // stay stable to avoid unnecessary re-subscriptions.
  const nodesRef = useRef(nodes);
  nodesRef.current = nodes;
  const rfEdgesRef = useRef(rfEdges);
  rfEdgesRef.current = rfEdges;
  const edgesRef = useRef(edges);
  edgesRef.current = edges;

  const cancelSnapback = useCallback(() => {
    if (snapbackTimerRef.current != null) {
      window.clearTimeout(snapbackTimerRef.current);
      snapbackTimerRef.current = null;
    }
    if (snapbackFrameRef.current != null) {
      window.cancelAnimationFrame(snapbackFrameRef.current);
      snapbackFrameRef.current = null;
    }
  }, []);

  const setControlledViewport = useCallback((nextViewport: Viewport, source: SwarmViewportSource) => {
    viewportSourceRef.current = source;
    viewportRef.current = nextViewport;
    setViewport((current) => (areViewportsEqual(current, nextViewport) ? current : nextViewport));
  }, []);

  const showZoomIndicatorLabel = useCallback((zoom: number) => {
    setZoomIndicator(getZoomIndicatorLabel(zoom));
    if (zoomIndicatorTimerRef.current != null) {
      window.clearTimeout(zoomIndicatorTimerRef.current);
    }
    zoomIndicatorTimerRef.current = window.setTimeout(() => {
      setZoomIndicator(null);
      zoomIndicatorTimerRef.current = null;
    }, ZOOM_INDICATOR_HIDE_MS);
  }, []);

  const scheduleSnapback = useCallback(() => {
    cancelSnapback();
    if (!viewportNeedsSnapback(viewportRef.current)) {
      viewportSourceRef.current = "idle";
      return;
    }

    snapbackTimerRef.current = window.setTimeout(() => {
      const tick = () => {
        const rect = canvasViewportRef.current?.getBoundingClientRect();
        const focalPoint = lastViewportFocusRef.current ?? {
          x: rect ? rect.width / 2 : window.innerWidth / 2,
          y: rect ? rect.height / 2 : window.innerHeight / 2,
        };
        const nextViewport = stepViewportSnapback(viewportRef.current, focalPoint);
        const done = !viewportNeedsSnapback(nextViewport);

        setControlledViewport(nextViewport, done ? "idle" : "snapback");

        if (done) {
          snapbackFrameRef.current = null;
          return;
        }

        snapbackFrameRef.current = window.requestAnimationFrame(tick);
      };

      setControlledViewport(viewportRef.current, "snapback");
      snapbackFrameRef.current = window.requestAnimationFrame(tick);
      snapbackTimerRef.current = null;
    }, SWARM_VIEWPORT_SNAPBACK_DELAY_MS);
  }, [cancelSnapback, setControlledViewport]);

  const fitBoard = useCallback(
    (options?: { padding?: number; duration?: number }) => {
      if (nodesRef.current.length === 0) {
        return;
      }
      cancelSnapback();
      viewportSourceRef.current = "imperative";
      void reactFlow.fitView({
        padding: options?.padding ?? FIT_VIEW_OPTIONS.padding,
        duration: options?.duration ?? 0,
      });
    },
    [cancelSnapback, reactFlow],
  );

  const fitNodesInViewport = useCallback(
    (
      nodesToFit: Array<Node<SwarmBoardNodeData>>,
      options?: { padding?: number; duration?: number },
    ) => {
      if (nodesToFit.length === 0) {
        return;
      }
      cancelSnapback();
      viewportSourceRef.current = "imperative";
      void reactFlow.fitView({
        nodes: nodesToFit,
        padding: options?.padding ?? FIT_VIEW_OPTIONS.padding,
        duration: options?.duration ?? 0,
      });
    },
    [cancelSnapback, reactFlow],
  );

  const zoomViewportByFactor = useCallback(
    (factor: number, options?: { duration?: number }) => {
      const rect = canvasViewportRef.current?.getBoundingClientRect();
      const focalPoint = {
        x: rect ? rect.width / 2 : window.innerWidth / 2,
        y: rect ? rect.height / 2 : window.innerHeight / 2,
      };
      lastViewportFocusRef.current = focalPoint;
      cancelSnapback();

      const currentViewport = viewportRef.current;
      const targetZoom = Math.min(
        SWARM_VIEWPORT_TARGET_MAX_ZOOM,
        Math.max(SWARM_VIEWPORT_TARGET_MIN_ZOOM, currentViewport.zoom * factor),
      );
      const targetViewport = zoomViewportAroundPoint(
        currentViewport,
        targetZoom,
        focalPoint,
      );

      viewportSourceRef.current = "imperative";
      showZoomIndicatorLabel(targetZoom);
      void reactFlow.setViewport(targetViewport, { duration: options?.duration ?? 0 });
    },
    [cancelSnapback, reactFlow, showZoomIndicatorLabel],
  );

  const setViewportFromRpc = useCallback(
    async (nextViewport: Viewport, options?: { duration?: number }) => {
      cancelSnapback();
      viewportSourceRef.current = "imperative";
      viewportRef.current = nextViewport;
      setViewport((current) => (areViewportsEqual(current, nextViewport) ? current : nextViewport));
      await reactFlow.setViewport(nextViewport, { duration: options?.duration ?? 0 });
      return viewportRef.current;
    },
    [cancelSnapback, reactFlow],
  );

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
      storeActions.setNodes(updated as Node<SwarmBoardNodeData>[]);
    },
    [storeActions, killSession],
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
      storeActions.setEdges(newEdges);
    },
    [storeActions],
  );

  // Handle new connections drawn by the user
  const onConnect: OnConnect = useCallback(
    (params) => {
      if (!params.source || !params.target) return;
      const edgeId = `edge-${params.source}-${params.target}-${Date.now().toString(36)}`;
      storeActions.addEdge({
        id: edgeId,
        source: params.source,
        target: params.target,
        type: "handoff",
      });
    },
    [storeActions],
  );

  // Snap single node to grid on drag end
  const onNodeDragStop: OnNodeDrag = useCallback(
    (_event, node) => {
      if (!positionNeedsSnap(node.position)) return;
      const snapped = snapPositionToGrid(node.position);
      storeActions.setNodes(
        nodesRef.current.map((n) =>
          n.id === node.id ? { ...n, position: snapped } : n,
        ),
      );
    },
    [storeActions],
  );

  // Snap all dragged nodes to grid on multi-selection drag end
  const onSelectionDragStop: SelectionDragHandler = useCallback(
    (_event, draggedNodes) => {
      const needsSnap = draggedNodes.some((d) => positionNeedsSnap(d.position));
      if (!needsSnap) return;
      const draggedIds = new Set(draggedNodes.map((d) => d.id));
      storeActions.setNodes(
        nodesRef.current.map((n) => {
          if (!draggedIds.has(n.id)) return n;
          return { ...n, position: snapPositionToGrid(n.position) };
        }),
      );
    },
    [storeActions],
  );

  // Node click -> dismiss context menu, or complete connecting-from workflow
  const onNodeClick: NodeMouseHandler = useCallback(
    (_event, node) => {
      setContextMenu(null);
      if (connectingFrom && node.id !== connectingFrom.nodeId) {
        const edgeId = `edge-${connectingFrom.nodeId}-${node.id}-${Date.now().toString(36)}`;
        storeActions.addEdge({
          id: edgeId,
          source: connectingFrom.nodeId,
          target: node.id,
          type: connectingFrom.edgeType ?? "handoff",
        });
        setConnectingFrom(null);
      } else if (connectingFrom && node.id === connectingFrom.nodeId) {
        // Self-loop: do nothing, stay in connecting mode
      }
    },
    [connectingFrom, storeActions],
  );

  // Double-click on node -> type-specific behavior (node already selected by mousedown)
  const onNodeDoubleClick: NodeMouseHandler = useCallback(
    (_event, node) => {
      const d = node.data as SwarmBoardNodeData;
      if (d.nodeType === "agentSession") {
        updateNode(node.id, { maximized: true });
      } else if (d.nodeType === "note") {
        updateNode(node.id, { editing: true });
      }
    },
    [updateNode],
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

  // Click on empty canvas -> deselect and cancel connecting-from
  const onPaneClick = useCallback(() => {
    storeActions.setSelectedNodeIds([]);
    setContextMenu(null);
    setConnectingFrom(null);
    setHoveredNodeId(null);
  }, [storeActions]);

  // Sync React Flow multi-selection to Zustand store
  const onSelectionChangeHandler = useCallback(
    ({ nodes: selectedNodes }: { nodes: Node[]; edges: Edge[] }) => {
      const ids = selectedNodes.map((n) => n.id);
      storeActions.setSelectedNodeIds(ids);
    },
    [storeActions],
  );

  useOnSelectionChange({ onChange: onSelectionChangeHandler });

  // Click on edge -> open receipt detail for receipt-type edges
  const onEdgeClick = useCallback(
    (_event: React.MouseEvent, edge: Edge) => {
      // Only handle receipt-type edges
      const edgeType = (edge.data?.edgeType as string) ?? findEdgeType(edge.id, edgesRef.current);
      if (edgeType !== "receipt") return;
      // Find the receipt node (target of the receipt edge)
      const receiptNode = nodesRef.current.find((n) => n.id === edge.target);
      if (!receiptNode) return;
      const shortId = receiptNode.id.slice(0, 8);
      usePaneStore.getState().openApp(`/receipt/${receiptNode.id}`, `Receipt ${shortId}`);
    },
    [],
  );

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
      if (e.key === "Escape") {
        setContextMenu(null);
        setConnectingFrom(null);
      }
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
      const currentViewport = viewportRef.current;
      const centerX = (-currentViewport.x + window.innerWidth / 2) / currentViewport.zoom;
      const centerY = (-currentViewport.y + window.innerHeight / 2) / currentViewport.zoom;
      return {
        x: centerX + (Math.random() - 0.5) * 100,
        y: centerY + (Math.random() - 0.5) * 100,
      };
    } catch {
      return { x: 200 + Math.random() * 300, y: 200 + Math.random() * 200 };
    }
  }, []);

  const handleViewportChange = useCallback((nextViewport: Viewport) => {
    if (!shouldSyncControlledViewport(viewportSourceRef.current)) {
      return;
    }

    viewportRef.current = nextViewport;
    setViewport((current) => (areViewportsEqual(current, nextViewport) ? current : nextViewport));
  }, []);

  const handleMoveStart = useCallback(
    (event: MouseEvent | TouchEvent | null, nextViewport: Viewport) => {
      viewportSourceRef.current = event == null ? "imperative" : "pointer";
      if (shouldSyncControlledViewport(viewportSourceRef.current)) {
        viewportRef.current = nextViewport;
        setViewport((current) => (areViewportsEqual(current, nextViewport) ? current : nextViewport));
      }
    },
    [],
  );

  const handleMoveEnd = useCallback(
    (event: MouseEvent | TouchEvent | null, nextViewport: Viewport) => {
      if (shouldSyncControlledViewport(viewportSourceRef.current)) {
        viewportRef.current = nextViewport;
        setViewport((current) => (areViewportsEqual(current, nextViewport) ? current : nextViewport));
      }
      viewportSourceRef.current = "idle";
    },
    [],
  );

  useEffect(() => {
    if (nodes.length === 0) {
      hasInitialFitRef.current = false;
      return;
    }
    const viewportReady = (reactFlow as { viewportInitialized?: boolean }).viewportInitialized ?? true;
    if (!viewportReady) {
      return;
    }
    if (hasInitialFitRef.current) {
      return;
    }

    hasInitialFitRef.current = true;
    fitBoard();
  }, [nodes.length, fitBoard, reactFlow]);

  useEffect(() => {
    return registerSwarmRpcViewportController({
      getViewport: () => viewportRef.current,
      setViewport: setViewportFromRpc,
    });
  }, [setViewportFromRpc]);

  useEffect(() => {
    const canvasEl = canvasViewportRef.current;
    if (!canvasEl) {
      return;
    }

    const handleWheel = (event: WheelEvent) => {
      const target = event.target as HTMLElement | null;
      if (
        !target ||
        target.closest(".nowheel") ||
        target.closest(".react-flow__controls") ||
        target.closest(".react-flow__panel") ||
        target.closest("input, textarea, select, [contenteditable='true']") ||
        target.closest(".react-flow__minimap")
      ) {
        return;
      }

      event.preventDefault();
      event.stopPropagation();
      cancelSnapback();

      if (viewportSourceRef.current === "imperative") {
        void reactFlow.setViewport(viewportRef.current, { duration: 0 });
      }

      const rect = canvasEl.getBoundingClientRect();
      const focalPoint = {
        x: event.clientX - rect.left,
        y: event.clientY - rect.top,
      };
      lastViewportFocusRef.current = focalPoint;

      const nextViewport = shouldZoomCanvasWheel(event, isMacLikeRef.current)
        ? applyViewportWheelZoom(viewportRef.current, event.deltaY, focalPoint)
        : applyViewportWheelPan(viewportRef.current, event.deltaX, event.deltaY);

      setControlledViewport(nextViewport, "wheel");

      if (shouldZoomCanvasWheel(event, isMacLikeRef.current)) {
        showZoomIndicatorLabel(nextViewport.zoom);
        scheduleSnapback();
      } else {
        viewportSourceRef.current = "idle";
      }
    };

    const handleGesture = (event: Event) => {
      event.preventDefault();
    };

    canvasEl.addEventListener("wheel", handleWheel, { capture: true, passive: false });
    canvasEl.addEventListener("gesturestart", handleGesture as EventListener, { capture: true, passive: false });
    canvasEl.addEventListener("gesturechange", handleGesture as EventListener, { capture: true, passive: false });
    canvasEl.addEventListener("gestureend", handleGesture as EventListener, { capture: true, passive: false });

    return () => {
      canvasEl.removeEventListener("wheel", handleWheel, true);
      canvasEl.removeEventListener("gesturestart", handleGesture as EventListener, true);
      canvasEl.removeEventListener("gesturechange", handleGesture as EventListener, true);
      canvasEl.removeEventListener("gestureend", handleGesture as EventListener, true);
    };
  }, [cancelSnapback, reactFlow, scheduleSnapback, setControlledViewport, showZoomIndicatorLabel]);

  useEffect(() => {
    return () => {
      cancelSnapback();
      if (zoomIndicatorTimerRef.current != null) {
        window.clearTimeout(zoomIndicatorTimerRef.current);
      }
    };
  }, [cancelSnapback]);

  // Resize recentering — shift viewport by half the size delta to keep
  // content visually centered when the canvas container changes size
  // (sidebar toggle, inspector open/close, window resize).
  useEffect(() => {
    const el = canvasViewportRef.current;
    if (!el) return;
    let prevW = el.clientWidth;
    let prevH = el.clientHeight;

    const observer = new ResizeObserver(() => {
      const w = el.clientWidth;
      const h = el.clientHeight;
      if (w === prevW && h === prevH) return;

      const dw = (w - prevW) / 2;
      const dh = (h - prevH) / 2;
      prevW = w;
      prevH = h;

      setControlledViewport(
        {
          x: viewportRef.current.x + dw,
          y: viewportRef.current.y + dh,
          zoom: viewportRef.current.zoom,
        },
        "imperative",
      );
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, [setControlledViewport]);

  // ------- Keyboard shortcuts -------
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      // Don't intercept when typing in an input, textarea, contentEditable,
      // or inside an xterm terminal container
      if (isInputTarget(e)) return;

      const isMeta = e.metaKey || e.ctrlKey;

      // Escape -> deselect all and close inspector
      if (e.key === "Escape") {
        storeActions.setSelectedNodeIds([]);
        setContextMenu(null);
        setConnectingFrom(null);
        return;
      }

      // Cmd/Ctrl+A -> select all nodes
      if (isMeta && e.key === "a") {
        e.preventDefault();
        const allNodes = nodesRef.current.map((n) => ({
          ...n,
          selected: true,
        }));
        storeActions.setNodes(allNodes as Node<SwarmBoardNodeData>[]);
        return;
      }

      if (!isMeta && !e.altKey && !(e.target as HTMLElement).closest?.(".react-flow__node")) {
        const step = e.shiftKey ? SWARM_BOARD_GRID_MAJOR_GAP : SWARM_BOARD_GRID_GAP;
        const nudgedNodes = nudgeSelectedBoardNodes(
          nodesRef.current,
          state.selectedNodeId,
          e.key,
          step,
        );
        if (nudgedNodes) {
          e.preventDefault();
          storeActions.setNodes(nudgedNodes);
          return;
        }
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
          fitBoard({ padding: 0.2, duration: 500 });
          return;
        }

        // G -> toggle follow active (moved from Space to avoid conflict with Space+drag pan)
        if (e.key === "g" || e.key === "G") {
          e.preventDefault();
          setFollowActive((prev) => !prev);
          return;
        }
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [storeActions, addNode, fitBoard, getDropPosition, spawnSession, state.repoRoot, state.selectedNodeId]);

  // Space+drag pan — hold Space to enable left-click pan mode
  useEffect(() => {
    function handleSpaceDown(e: KeyboardEvent) {
      if (e.key !== " " || e.repeat || isInputTarget(e)) return;
      e.preventDefault();
      setSpaceHeld(true);
    }
    function handleSpaceUp(e: KeyboardEvent) {
      if (e.key !== " ") return;
      setSpaceHeld(false);
    }
    // Also reset on blur (user switches window while holding Space)
    function handleBlur() {
      setSpaceHeld(false);
    }

    window.addEventListener("keydown", handleSpaceDown);
    window.addEventListener("keyup", handleSpaceUp);
    window.addEventListener("blur", handleBlur);
    return () => {
      window.removeEventListener("keydown", handleSpaceDown);
      window.removeEventListener("keyup", handleSpaceUp);
      window.removeEventListener("blur", handleBlur);
    };
  }, []);

  // Follow active — auto-zoom to running node
  useEffect(() => {
    if (!followActive) return;
    const interval = setInterval(() => {
      const runningNode = nodesRef.current.find(
        (n) => (n.data as SwarmBoardNodeData).status === "running",
      );
      if (runningNode) {
        fitNodesInViewport([runningNode], {
          padding: 0.5,
          duration: 400,
        });
      }
    }, 2000);
    return () => clearInterval(interval);
  }, [fitNodesInViewport, followActive]);

  // Context menu actions
  const handleContextInspect = useCallback(() => {
    if (contextMenu) {
      storeActions.setSelectedNodeIds([contextMenu.nodeId]);
      setContextMenu(null);
    }
  }, [contextMenu, storeActions]);

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
    if (!contextMenu) return;
    setConnectingFrom({ nodeId: contextMenu.nodeId, edgeType: "handoff" });
    setContextMenu(null);
  }, [contextMenu]);

  // Memoize the type maps (must be stable references)
  const nodeTypes = useMemo(() => swarmBoardNodeTypes, []);
  const edgeTypes = useMemo(() => swarmBoardEdgeTypes, []);

  // Enrich edges with hoveredNodeId for hover-reveal behavior + receipt activity timestamps
  const enrichedEdges = useMemo(() => {
    const selectedId = state.selectedNodeId;
    const now = Date.now();
    const RECEIPT_ACTIVITY_MS = 3000;

    return rfEdges.map((e) => {
      // Check for receipt edge activity timestamp (bright pulse for 3s after creation)
      const receiptTs = receiptEdgeTimestamps.get(e.id);
      const receiptActivityAt = receiptTs != null && (now - receiptTs) < RECEIPT_ACTIVITY_MS
        ? receiptTs
        : undefined;

      return {
        ...e,
        data: {
          ...e.data,
          hoveredNodeId: hoveredNodeId,
          selectedNodeId: selectedId,
          ...(receiptActivityAt != null ? { lastActivityAt: receiptActivityAt } : {}),
        },
      };
    });
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
  const receiptPosture = useMemo(() => summarizeReceiptPosture(nodes), [nodes]);
  const boardAtmosphere = useMemo(
    () => buildSwarmBoardAtmosphere(receiptPosture),
    [receiptPosture],
  );

  const activePanOnDrag = useMemo(
    () => (spaceHeld ? [0, 1] : SWARM_BOARD_PAN_ON_DRAG_BUTTONS),
    [spaceHeld],
  );

  return (
    <div className="flex flex-col h-full w-full" style={{ backgroundColor: "#05060a" }}>
      {/* Toolbar (uses useReactFlow) */}
      <SwarmBoardToolbar
        viewportController={{
          viewport,
          fitBoard,
          fitNodes: fitNodesInViewport,
          zoomByFactor: zoomViewportByFactor,
        }}
      />

      {/* Main area: left rail + canvas */}
      <div className="flex flex-1 min-h-0">
        {/* Left rail — workspace explorer (Section 9) */}
        <SwarmBoardLeftRail />

        {/* Canvas */}
        <div ref={canvasViewportRef} className={`flex-1 relative flex flex-col${spaceHeld ? " space-held" : ""}`}>
          <div className="flex-1 relative">
            {/* Global keyframe animations for node transitions */}
            <style>{`
              @keyframes nodeEnter {
                from { opacity: 0; transform: scale(0.85); }
                to { opacity: 1; transform: scale(1); }
              }
              .react-flow__selection {
                background: rgba(212, 168, 75, 0.05);
                border: 1px solid rgba(212, 168, 75, 0.28);
                border-radius: 4px;
                box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.02);
              }
              .react-flow__node {
                animation: nodeEnter 0.3s ease-out;
              }
              .space-held .react-flow__pane { cursor: grab; }
              .space-held .react-flow__pane:active { cursor: grabbing; }
            `}</style>

            <ReactFlow
              nodes={nodes}
              edges={enrichedEdges}
              viewport={viewport}
              nodeTypes={nodeTypes}
              edgeTypes={edgeTypes}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onConnect={onConnect}
              onViewportChange={handleViewportChange}
              onMoveStart={handleMoveStart}
              onMoveEnd={handleMoveEnd}
              onNodeClick={onNodeClick}
              onNodeDoubleClick={onNodeDoubleClick}
              onNodeContextMenu={onNodeContextMenu}
              onEdgeClick={onEdgeClick}
              onNodeMouseEnter={onNodeMouseEnter}
              onNodeMouseLeave={onNodeMouseLeave}
              onPaneClick={onPaneClick}
              onNodeDragStop={onNodeDragStop}
              onSelectionDragStop={onSelectionDragStop}
              nodesDraggable
              nodesConnectable
              fitViewOptions={FIT_VIEW_OPTIONS}
              minZoom={SWARM_VIEWPORT_HARD_MIN_ZOOM}
              maxZoom={SWARM_VIEWPORT_HARD_MAX_ZOOM}
              panOnDrag={activePanOnDrag}
              zoomOnScroll={false}
              zoomOnPinch={false}
              zoomOnDoubleClick={false}
              panOnScroll={false}
              zoomActivationKeyCode={null}
              panActivationKeyCode={null}
              defaultEdgeOptions={DEFAULT_EDGE_OPTIONS}
              connectionLineStyle={CONNECTION_LINE_STYLE}
              proOptions={PRO_OPTIONS}
              style={RF_STYLE}
              deleteKeyCode={DELETE_KEY_CODE}
              selectionKeyCode={SELECTION_KEY_CODE}
            >
              <Background
                id="swarm-grid-minor"
                variant={BackgroundVariant.Dots}
                gap={SWARM_BOARD_GRID_GAP}
                size={1}
                color="rgba(255,255,255,0.06)"
              />
              <Background
                id="swarm-grid-major"
                variant={BackgroundVariant.Dots}
                gap={SWARM_BOARD_GRID_MAJOR_GAP}
                size={1.4}
                color="rgba(255,255,255,0.12)"
              />
              {/* MiniMap — subtle, blends into bottom-right corner */}
              <MiniMap
                style={MINIMAP_STYLE}
                nodeColor={minimapNodeColor}
                maskColor="rgba(5,6,10,0.85)"
                position="bottom-right"
                pannable
                zoomable
              />
              {/* Off-screen node indicators -- arrows on canvas edge */}
              <EdgeIndicators />
              {/* No Controls component — toolbar provides zoom */}
            </ReactFlow>

            {zoomIndicator && (
              <div
                className="absolute top-3 left-1/2 -translate-x-1/2 pointer-events-none z-20 rounded-sm border border-[#1a1f2e] bg-[#0b0d13]/90 px-2 py-1 text-[10px] font-mono text-[#c3cfdf]"
                data-testid="canvas-zoom-indicator"
              >
                {zoomIndicator}
              </div>
            )}

            {/* Canvas atmosphere — radial vignette */}
            <div
              className="absolute inset-0 pointer-events-none"
              data-testid="canvas-atmosphere-glow"
              data-atmosphere-state={boardAtmosphere.state}
              style={{
                background: boardAtmosphere.glow,
                zIndex: 0,
                opacity: 0.7,
              }}
            />
            <div
              className="absolute inset-0 pointer-events-none"
              data-testid="canvas-atmosphere-vignette"
              data-atmosphere-state={boardAtmosphere.state}
              style={{
                background: boardAtmosphere.vignette,
                zIndex: 0,
              }}
            />
            {/* Subtle noise texture overlay */}
            <div
              className="absolute inset-0 pointer-events-none"
              data-testid="canvas-atmosphere-noise"
              data-atmosphere-state={boardAtmosphere.state}
              style={{
                backgroundImage: `url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.03'/%3E%3C/svg%3E")`,
                backgroundRepeat: 'repeat',
                backgroundSize: '256px 256px',
                zIndex: 0,
                opacity: boardAtmosphere.noiseOpacity,
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
                onConnect={handleContextConnect}
                onDuplicate={handleContextDuplicate}
                onDelete={handleContextDelete}
              />
            )}

            {/* Connecting-from indicator */}
            {connectingFrom && (
              <div
                data-testid="connecting-indicator"
                className="absolute bottom-8 left-1/2 -translate-x-1/2 z-50 flex items-center gap-2 px-3 py-1.5 rounded bg-[#0c0e14] border border-[#c49a3c]/30 shadow-lg"
              >
                <span className="text-[10px] font-mono text-[#c49a3c]">
                  Click a target node to connect
                </span>
                <button
                  type="button"
                  onClick={() => setConnectingFrom(null)}
                  className="text-[9px] font-mono text-[#6f7f9a] hover:text-[#ece7dc] ml-2"
                >
                  Cancel (Esc)
                </button>
              </div>
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
            coordinatorConnected={coordinatorConnected}
            outboxSize={outboxSize}
            joinedSwarms={joinedSwarms}
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
    onConnect: () => void;
    onDuplicate: () => void;
    onDelete: () => void;
  }
>(({ menu, onInspect, onConnect, onDuplicate, onDelete }, ref) => {
  const items: Array<{ label: string; icon: typeof IconSearch; action: () => void; danger?: boolean }> = [
    { label: "Inspect", icon: IconSearch, action: onInspect },
    { label: "Connect to\u2026", icon: IconLink, action: onConnect },
    { label: "Duplicate", icon: IconCopy, action: onDuplicate },
    { label: "Delete", icon: IconTrash, action: onDelete, danger: true },
  ];

  return (
    <div
      ref={ref}
      className="fixed z-[100] min-w-[140px] bg-[#0c0e14] border border-[#1a1f2e] rounded-md shadow-[0_8px_32px_rgba(0,0,0,0.6)] py-1"
      style={{ left: menu.x, top: menu.y }}
    >
      {items.map((item, i) => (
        <button
          key={i}
          type="button"
          className={`flex items-center gap-2 w-full px-3 py-1.5 text-[10px] font-mono transition-colors text-left ${
            item.danger
              ? "text-[#6f7f9a] hover:text-[#e74c3c] hover:bg-[#e74c3c08]"
              : "text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#ffffff06]"
          }`}
          onClick={item.action}
          aria-label={item.label}
        >
          <item.icon size={12} stroke={1.5} />
          {item.label}
        </button>
      ))}
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
  coordinatorConnected,
  outboxSize,
  joinedSwarms,
}: {
  totalNodes: number;
  runningSessions: number;
  blockedSessions: number;
  totalReceipts: number;
  totalEdges: number;
  followActive: boolean;
  coordinatorConnected: boolean;
  outboxSize: number;
  joinedSwarms: number;
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

  // Coordinator status segments
  if (coordinatorConnected && joinedSwarms > 0) {
    segments.push({ text: `${joinedSwarms} swarm${joinedSwarms !== 1 ? "s" : ""}`, color: "#3dbf84" });
  }
  if (outboxSize > 0) {
    segments.push({ text: `${outboxSize} queued`, color: "#d4a84b" });
  }
  if (!coordinatorConnected) {
    segments.push({ text: "offline", color: "#b85450" });
  }

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
        {SWARM_BOARD_SHORTCUT_HINT}
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Error Boundary — catches render errors in the engine-dependent subtree
// ---------------------------------------------------------------------------

interface SwarmBoardErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

class SwarmBoardErrorBoundary extends React.Component<
  { children: React.ReactNode },
  SwarmBoardErrorBoundaryState
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): SwarmBoardErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo): void {
    console.error("[SwarmBoardErrorBoundary] Render error:", error, info.componentStack);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div
          className="flex flex-col items-center justify-center h-full w-full gap-2"
          style={{ backgroundColor: "#05060a" }}
        >
          <p className="text-[13px] font-mono text-[#6f7f9a]">
            SwarmBoard encountered an error. Refresh to retry.
          </p>
          <p className="text-[10px] font-mono text-[#2a3040]">
            {this.state.error?.message ?? "Unknown error"}
          </p>
        </div>
      );
    }
    return this.props.children;
  }
}

// ---------------------------------------------------------------------------
// Page wrapper — sets up providers in correct order
// ---------------------------------------------------------------------------

export function SwarmBoardPage() {
  // Extract bundlePath from the wildcard route segment.
  // Route is "swarm-board/*" so location.pathname looks like "/swarm-board/encoded%2Fpath"
  // For the plain "/swarm-board" route (scratch board), bundlePath will be undefined.
  const location = useLocation();
  const bundlePath = useMemo(() => {
    const prefix = "/swarm-board/";
    if (!location.pathname.startsWith(prefix)) return undefined;
    const encoded = location.pathname.slice(prefix.length);
    if (!encoded) return undefined;
    try {
      return decodeURIComponent(encoded);
    } catch {
      return undefined;
    }
  }, [location.pathname]);

  return (
    <SwarmEngineProvider>
      <SwarmBoardProvider bundlePath={bundlePath}>
        <ReactFlowProvider>
          <SwarmBoardErrorBoundary>
            <SwarmBoardCanvas />
          </SwarmBoardErrorBoundary>
        </ReactFlowProvider>
      </SwarmBoardProvider>
    </SwarmEngineProvider>
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
) : "handoff" | "spawned" | "artifact" | "receipt" | "topology" | "dependency" | undefined {
  const found = edges.find((e) => e.id === edgeId);
  return found?.type as "handoff" | "spawned" | "artifact" | "receipt" | "topology" | "dependency" | undefined;
}
