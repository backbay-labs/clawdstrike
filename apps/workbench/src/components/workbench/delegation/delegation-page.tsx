import {
  useRef,
  useEffect,
  useLayoutEffect,
  useState,
  useCallback,
  useMemo,
  type MouseEvent as ReactMouseEvent,
} from "react";
import {
  IconZoomIn,
  IconZoomOut,
  IconFocus2,
  IconDownload,
  IconRoute,
  IconX,
  IconSearch,
  IconDatabase,
  IconTestPipe,
  IconRefresh,
  IconUser,
  IconClock,
  IconKey,
  IconShieldCheck,
  IconAlertTriangle,
  IconBolt,
  IconPlugConnected,
  IconSelector,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import type {
  DelegationGraph,
  DelegationNode,
  DelegationEdge,
  NodeKind,
  TrustLevel,
  Capability,
} from "@/lib/workbench/delegation-types";
import { DEMO_DELEGATION_GRAPH } from "@/lib/workbench/delegation-demo-data";
import {
  fleetClient,
  fetchDelegationGraphSnapshot as apiFetchDelegationGraphSnapshot,
  fetchPrincipals as apiFetchPrincipals,
  type FleetConnection,
  type PrincipalInfo,
} from "@/lib/workbench/fleet-client";
import { useFleetConnection } from "@/lib/workbench/use-fleet-connection";
import {
  computeHierarchicalLayout,
  computeFitTransform,
  tracePath,
  type GraphLayoutResult,
  type TracedPath,
} from "@/lib/workbench/force-graph-engine";
import { sanitizeDelegationSvgForExport } from "./svg-export";

const ALL_NODE_KINDS: NodeKind[] = [
  "Principal",
  "Session",
  "Grant",
  "Approval",
  "Event",
  "ResponseAction",
];

const ALL_TRUST_LEVELS: TrustLevel[] = [
  "System",
  "High",
  "Medium",
  "Low",
  "Untrusted",
];

const TRUST_COLORS: Record<TrustLevel, string> = {
  System: "#d4a84b",
  High: "#3dbf84",
  Medium: "#5b8def",
  Low: "#f59e0b",
  Untrusted: "#c45c5c",
};

const NODE_KIND_ACCENT: Record<NodeKind, string> = {
  Principal: "#5b8def",
  Session: "#6f7f9a",
  Grant: "#d4a84b",
  Approval: "#3dbf84",
  Event: "#c45c5c",
  ResponseAction: "#f59e0b",
};

const NODE_KIND_LABELS: Record<NodeKind, string> = {
  Principal: "Principal",
  Session: "Session",
  Grant: "Grant",
  Approval: "Approval",
  Event: "Event",
  ResponseAction: "Response",
};

const NODE_KIND_ICON: Record<NodeKind, React.ComponentType<{ size?: number; className?: string }>> =
  {
    Principal: IconUser,
    Session: IconClock,
    Grant: IconKey,
    Approval: IconShieldCheck,
    Event: IconAlertTriangle,
    ResponseAction: IconBolt,
  };

const EDGE_COLORS: Record<string, string> = {
  IssuedGrant: "#d4a84b",
  ReceivedGrant: "#d4a84b",
  DerivedFromGrant: "#d4a84b",
  SpawnedPrincipal: "#5b8def",
  ApprovedBy: "#3dbf84",
  RevokedBy: "#c45c5c",
  ExercisedInSession: "#6f7f9a",
  ExercisedInEvent: "#6f7f9a",
  TriggeredResponseAction: "#f59e0b",
};

const MAX_GRAPH_SIZE = 5000;

function validateGraph(raw: DelegationGraph): {
  graph: DelegationGraph;
  truncationMessage: string | null;
} {
  const validNodes = raw.nodes.filter(
    (n) => typeof n.id === "string" && typeof n.kind === "string" && typeof n.label === "string",
  );

  if (validNodes.length > MAX_GRAPH_SIZE) {
    const truncated = validNodes.slice(0, MAX_GRAPH_SIZE);
    const ids = new Set(truncated.map((n) => n.id));
    return {
      graph: {
        nodes: truncated,
        edges: raw.edges.filter((e) => ids.has(e.from) && ids.has(e.to)),
      },
      truncationMessage: `Graph truncated: ${validNodes.length} nodes exceeds max of ${MAX_GRAPH_SIZE}`,
    };
  }

  const nodeIds = new Set(validNodes.map((n) => n.id));
  return {
    graph: {
      nodes: validNodes,
      edges: raw.edges.filter((e) => nodeIds.has(e.from) && nodeIds.has(e.to)),
    },
    truncationMessage: null,
  };
}

const DASHED_EDGES = new Set([
  "DerivedFromGrant",
  "RevokedBy",
  "ApprovedBy",
]);

const CAPABILITY_SHORT: Record<Capability, string> = {
  FileRead: "FR",
  FileWrite: "FW",
  NetworkEgress: "NE",
  CommandExec: "CE",
  SecretAccess: "SA",
  McpTool: "MT",
  DeployApproval: "DA",
  AgentAdmin: "AA",
  Custom: "CU",
};

export function DelegationPage() {
  const { connection } = useFleetConnection();
  const fleetConnected = connection.connected;

  const containerRef = useRef<HTMLDivElement>(null);
  const [containerElement, setContainerElement] = useState<HTMLDivElement | null>(null);

  const [graph, setGraph] = useState<DelegationGraph>(DEMO_DELEGATION_GRAPH);
  const [isLiveData, setIsLiveData] = useState(false);
  const [liveAvailable, setLiveAvailable] = useState(false);
  const [liveFetchError, setLiveFetchError] = useState<string | null>(null);
  const [isLoadingGraph, setIsLoadingGraph] = useState(false);
  const autoSwitchedRef = useRef(false);

  // Principals list for the snapshot endpoint
  const [principals, setPrincipals] = useState<PrincipalInfo[]>([]);
  const [selectedPrincipalId, setSelectedPrincipalId] = useState<string | null>(null);
  const [principalDropdownOpen, setPrincipalDropdownOpen] = useState(false);
  const [isLoadingPrincipal, setIsLoadingPrincipal] = useState(false);

  const [panX, setPanX] = useState(0);
  const [panY, setPanY] = useState(0);
  const [zoom, setZoom] = useState(1);
  const isPanningRef = useRef(false);
  const lastMouseRef = useRef({ x: 0, y: 0 });

  const [selectedNode, setSelectedNode] = useState<DelegationNode | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [tracedPath, setTracedPath] = useState<TracedPath | null>(null);

  const [visibleKinds, setVisibleKinds] = useState<Set<NodeKind>>(new Set(ALL_NODE_KINDS));
  const [visibleTrust, setVisibleTrust] = useState<Set<TrustLevel>>(new Set(ALL_TRUST_LEVELS));
  const [searchQuery, setSearchQuery] = useState("");
  const [debouncedSearchQuery, setDebouncedSearchQuery] = useState("");
  const handleContainerRef = useCallback((node: HTMLDivElement | null) => {
    containerRef.current = node;
    setContainerElement(node);
  }, []);

  // Debounce search input (300ms)
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearchQuery(searchQuery), 300);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  // Fetch live delegation graph — tries the snapshot endpoint first, falls back to grants
  const fetchLiveGraph = useCallback(
    async (conn: FleetConnection, principalId: string | null): Promise<DelegationGraph | null> => {
      try {
        // If we have a principal selected, try the snapshot endpoint
        if (principalId) {
          const snapshot = await apiFetchDelegationGraphSnapshot(conn, principalId);
          if (snapshot && snapshot.nodes.length > 0) {
            const validated = validateGraph(snapshot);
            setLiveFetchError(validated.truncationMessage);
            return validated.graph;
          }
        }
        // Fallback to the older grants-based graph
        const grantsGraph = await fleetClient.fetchDelegationGraph();
        if (grantsGraph && grantsGraph.nodes.length > 0) {
          const validated = validateGraph(grantsGraph);
          setLiveFetchError(validated.truncationMessage);
          return validated.graph;
        }
        setLiveFetchError("No delegation data returned from fleet");
        return null;
      } catch (e) {
        console.warn("[delegation-page] fetchLiveGraph failed:", e);
        setLiveFetchError("Failed to fetch delegation graph from fleet");
        return null;
      }
    },
    [],
  );

  // Auto-switch to live data when fleet is connected
  useEffect(() => {
    if (!fleetConnected) {
      setLiveAvailable(false);
      autoSwitchedRef.current = false;
      return;
    }
    if (autoSwitchedRef.current) return;
    let cancelled = false;
    (async () => {
      try {
        setLiveAvailable(true);
        setIsLoadingGraph(true);
        // Load principals list
        const principalsList = await apiFetchPrincipals(connection);
        if (cancelled) return;
        setPrincipals(principalsList);

        // Pick the first principal as default if available
        const defaultId = principalsList.length > 0 ? principalsList[0].id : null;
        if (defaultId) setSelectedPrincipalId(defaultId);

        // Try to fetch live graph
        const liveGraph = await fetchLiveGraph(connection, defaultId);
        if (cancelled) return;
        if (liveGraph) {
          setGraph(liveGraph);
          setIsLiveData(true);
          autoSwitchedRef.current = true;
        }
      } catch (err) {
        if (cancelled) return;
        console.warn("[delegation-page] auto-switch effect failed:", err);
        setLiveFetchError("Failed to initialize live data");
      } finally {
        if (!cancelled) setIsLoadingGraph(false);
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fleetConnected]);

  const refreshLiveData = useCallback(async () => {
    if (!fleetConnected) return;
    setIsLoadingGraph(true);
    try {
      // Refresh principals list
      const principalsList = await apiFetchPrincipals(connection);
      setPrincipals(principalsList);

      const liveGraph = await fetchLiveGraph(connection, selectedPrincipalId);
      if (liveGraph) {
        setGraph(liveGraph);
      }
    } catch (err) {
      console.warn("[delegation-page] refreshLiveData failed:", err);
      setLiveFetchError(String(err));
    } finally {
      setIsLoadingGraph(false);
    }
  }, [fleetConnected, connection, selectedPrincipalId, fetchLiveGraph]);

  // Re-fetch graph when principal selection changes (while in live mode)
  const handlePrincipalChange = useCallback(
    async (principalId: string) => {
      setSelectedPrincipalId(principalId);
      setPrincipalDropdownOpen(false);
      if (!isLiveData || !fleetConnected) return;
      setIsLoadingPrincipal(true);
      try {
        const liveGraph = await fetchLiveGraph(connection, principalId);
        if (liveGraph) {
          setGraph(liveGraph);
        } else {
          setGraph({ nodes: [], edges: [] });
          setLiveFetchError("No delegation data for selected principal");
        }
      } catch (err) {
        console.warn("[delegation-page] principal change fetch failed:", err);
        setGraph({ nodes: [], edges: [] });
        setLiveFetchError("Failed to fetch delegation graph");
      } finally {
        setIsLoadingPrincipal(false);
      }
    },
    [isLiveData, fleetConnected, connection, fetchLiveGraph],
  );

  const toggleDataSource = useCallback(async () => {
    if (isLiveData) {
      setGraph(DEMO_DELEGATION_GRAPH);
      setIsLiveData(false);
      setLiveFetchError(null);
    } else if (fleetConnected) {
      setIsLiveData(true);
      const liveGraph = await fetchLiveGraph(connection, selectedPrincipalId);
      if (liveGraph) {
        setGraph(liveGraph);
      }
    }
    setSelectedNode(null);
    setTracedPath(null);
  }, [isLiveData, fleetConnected, connection, selectedPrincipalId, fetchLiveGraph]);

  const filteredGraph = useMemo<DelegationGraph>(() => {
    const q = debouncedSearchQuery.toLowerCase().trim();
    const filtered = graph.nodes.filter((n) => {
      if (!visibleKinds.has(n.kind)) return false;
      if (n.kind === "Principal" && n.trustLevel && !visibleTrust.has(n.trustLevel)) return false;
      if (q && !n.label.toLowerCase().includes(q)) return false;
      return true;
    });
    const ids = new Set(filtered.map((n) => n.id));
    return {
      nodes: filtered,
      edges: graph.edges.filter((e) => ids.has(e.from) && ids.has(e.to)),
    };
  }, [graph, debouncedSearchQuery, visibleKinds, visibleTrust]);

  const layout = useMemo<GraphLayoutResult>(
    () => computeHierarchicalLayout(filteredGraph),
    [filteredGraph],
  );

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const rect = container.getBoundingClientRect();
    const fit = computeFitTransform(layout, rect.width, rect.height);
    setPanX(fit.panX);
    setPanY(fit.panY);
    setZoom(fit.zoom);
  }, [layout]);

  const nodeMap = useMemo(() => {
    const m = new Map<string, DelegationNode>();
    for (const n of filteredGraph.nodes) m.set(n.id, n);
    return m;
  }, [filteredGraph]);

  const edgeMap = useMemo(() => {
    const m = new Map<string, DelegationEdge>();
    for (const e of filteredGraph.edges) m.set(e.id, e);
    return m;
  }, [filteredGraph]);

  const onMouseDown = useCallback((e: ReactMouseEvent) => {
    if ((e.target as HTMLElement).closest("[data-node]")) return;
    isPanningRef.current = true;
    lastMouseRef.current = { x: e.clientX, y: e.clientY };
  }, []);

  const onMouseMove = useCallback((e: ReactMouseEvent) => {
    if (!isPanningRef.current) return;
    const dx = e.clientX - lastMouseRef.current.x;
    const dy = e.clientY - lastMouseRef.current.y;
    setPanX((p) => p + dx);
    setPanY((p) => p + dy);
    lastMouseRef.current = { x: e.clientX, y: e.clientY };
  }, []);

  const onMouseUp = useCallback(() => {
    isPanningRef.current = false;
  }, []);

  // Keep wheel zoom/pan reads on one coherent snapshot between renders.
  const viewportRef = useRef({ zoom, panX, panY });
  useLayoutEffect(() => {
    viewportRef.current = { zoom, panX, panY };
  }, [zoom, panX, panY]);

  // Native wheel listener with { passive: false } so we can preventDefault
  useEffect(() => {
    if (!containerElement) return;
    const container = containerElement;
    const handler = (e: WheelEvent) => {
      e.preventDefault();
      e.stopPropagation();
      const rect = container.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      const factor = e.deltaY < 0 ? 1.1 : 0.9;
      const { zoom: curZoom, panX: curPanX, panY: curPanY } = viewportRef.current;
      const newZoom = Math.min(Math.max(curZoom * factor, 0.15), 4);
      const wx = (x - curPanX) / curZoom;
      const wy = (y - curPanY) / curZoom;
      setPanX(x - wx * newZoom);
      setPanY(y - wy * newZoom);
      setZoom(newZoom);
    };
    container.addEventListener("wheel", handler, { passive: false });
    return () => container.removeEventListener("wheel", handler);
  }, [containerElement]);

  const onBackgroundClick = useCallback((e: ReactMouseEvent) => {
    if ((e.target as HTMLElement).closest("[data-node]")) return;
    setSelectedNode(null);
    setTracedPath(null);
  }, []);

  const fitToScreen = useCallback(() => {
    const container = containerRef.current;
    if (!container) return;
    const rect = container.getBoundingClientRect();
    const fit = computeFitTransform(layout, rect.width, rect.height);
    setPanX(fit.panX);
    setPanY(fit.panY);
    setZoom(fit.zoom);
  }, [layout]);

  const exportSvg = useCallback(() => {
    const container = containerRef.current;
    if (!container) return;
    const svgEl = container.querySelector("svg");
    if (!svgEl) return;
    const clone = sanitizeDelegationSvgForExport(svgEl);
    clone.setAttribute("width", String(layout.width));
    clone.setAttribute("height", String(layout.height));
    clone.querySelector("[data-viewport]")?.setAttribute("transform", "");

    // Add metadata desc element
    const desc = document.createElementNS("http://www.w3.org/2000/svg", "desc");
    const ts = new Date().toISOString();
    const pid = selectedPrincipalId;
    desc.textContent = pid
      ? `Delegation graph for principal ${pid} exported at ${ts}`
      : `Delegation graph for the current view exported at ${ts}`;
    clone.insertBefore(desc, clone.firstChild);

    const data = new XMLSerializer().serializeToString(clone);
    const blob = new Blob([data], { type: "image/svg+xml" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    const safePid = pid ? pid.replace(/[^a-zA-Z0-9_-]/g, "_") : "current-view";
    link.download = `delegation-graph-${safePid}.svg`;
    link.href = url;
    link.click();
    URL.revokeObjectURL(url);
  }, [layout, selectedPrincipalId]);

  const handleTracePath = useCallback(() => {
    if (!selectedNode) return;
    const path = tracePath(filteredGraph, selectedNode.id);
    setTracedPath(path);
  }, [selectedNode, filteredGraph]);

  const highlightedNodes = useMemo(
    () => (tracedPath ? new Set(tracedPath.nodeIds) : null),
    [tracedPath],
  );
  const highlightedEdges = useMemo(
    () => (tracedPath ? new Set(tracedPath.edgeIds) : null),
    [tracedPath],
  );

  const incomingEdges = useMemo(
    () => (selectedNode ? filteredGraph.edges.filter((e) => e.to === selectedNode.id) : []),
    [selectedNode, filteredGraph],
  );
  const outgoingEdges = useMemo(
    () => (selectedNode ? filteredGraph.edges.filter((e) => e.from === selectedNode.id) : []),
    [selectedNode, filteredGraph],
  );

  const pathSteps = useMemo(() => {
    if (!tracedPath) return [];
    return tracedPath.nodeIds
      .map((nodeId, i) => ({
        node: nodeMap.get(nodeId),
        edge: i > 0 ? edgeMap.get(tracedPath.edgeIds[i - 1]) : undefined,
      }))
      .filter((step): step is { node: DelegationNode; edge: DelegationEdge | undefined } =>
        step.node != null,
      );
  }, [tracedPath, nodeMap, edgeMap]);

  const toggleKind = useCallback((kind: NodeKind) => {
    setVisibleKinds((prev) => {
      const next = new Set(prev);
      if (next.has(kind)) next.delete(kind);
      else next.add(kind);
      return next;
    });
  }, []);

  const toggleTrust = useCallback((level: TrustLevel) => {
    setVisibleTrust((prev) => {
      const next = new Set(prev);
      if (next.has(level)) next.delete(level);
      else next.add(level);
      return next;
    });
  }, []);

  const resetFilters = useCallback(() => {
    setVisibleKinds(new Set(ALL_NODE_KINDS));
    setVisibleTrust(new Set(ALL_TRUST_LEVELS));
    setSearchQuery("");
  }, []);

  return (
    <div className="flex h-full w-full overflow-hidden bg-[#05060a]">
      <div className="flex w-52 shrink-0 flex-col border-r border-[#1a1f2e] bg-[#0b0d13]">
        <div className="border-b border-[#1a1f2e] px-4 py-3">
          <h2 className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]">
            Filters
          </h2>
        </div>

        <div className="border-b border-[#1a1f2e] px-3 py-3">
          <div className="relative">
            <IconSearch
              size={13}
              className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[#6f7f9a]/50"
            />
            <input
              type="text"
              placeholder="Search nodes..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full rounded border border-[#1a1f2e] bg-[#05060a] py-1.5 pl-8 pr-3 text-[11px] text-[#ece7dc] placeholder-[#6f7f9a]/40 outline-none transition-colors focus:border-[#2d3240]"
            />
          </div>
        </div>

        <div className="border-b border-[#1a1f2e] px-4 py-3">
          <h3 className="mb-2.5 text-[9px] font-semibold uppercase tracking-[0.1em] text-[#6f7f9a]/70">
            Node Kind
          </h3>
          <div className="flex flex-col gap-2">
            {ALL_NODE_KINDS.map((kind) => {
              const Icon = NODE_KIND_ICON[kind];
              return (
                <label
                  key={kind}
                  className="flex cursor-pointer items-center gap-2 text-[11px] text-[#ece7dc]/70 transition-colors hover:text-[#ece7dc]"
                >
                  <input
                    type="checkbox"
                    checked={visibleKinds.has(kind)}
                    onChange={() => toggleKind(kind)}
                    className="accent-[#d4a84b] h-3 w-3"
                  />
                  <Icon size={12} className="opacity-50" />
                  {NODE_KIND_LABELS[kind]}
                </label>
              );
            })}
          </div>
        </div>

        <div className="border-b border-[#1a1f2e] px-4 py-3">
          <h3 className="mb-2.5 text-[9px] font-semibold uppercase tracking-[0.1em] text-[#6f7f9a]/70">
            Trust Level
          </h3>
          <div className="flex flex-col gap-2">
            {ALL_TRUST_LEVELS.map((level) => (
              <label
                key={level}
                className="flex cursor-pointer items-center gap-2 text-[11px] text-[#ece7dc]/70 transition-colors hover:text-[#ece7dc]"
              >
                <input
                  type="checkbox"
                  checked={visibleTrust.has(level)}
                  onChange={() => toggleTrust(level)}
                  className="accent-[#d4a84b] h-3 w-3"
                />
                <span
                  className="inline-block h-1.5 w-1.5 rounded-full"
                  style={{ backgroundColor: TRUST_COLORS[level] }}
                />
                {level}
              </label>
            ))}
          </div>
        </div>

        <div className="border-b border-[#1a1f2e] px-4 py-2">
          <button
            onClick={resetFilters}
            className="w-full rounded border border-[#1a1f2e] bg-[#05060a] px-2 py-1 text-[9px] text-[#6f7f9a]/60 transition-colors hover:border-[#2d3240] hover:text-[#6f7f9a]"
          >
            Reset Filters
          </button>
        </div>

        <div className="mt-auto border-t border-[#1a1f2e] px-4 py-3">
          <div className="flex flex-col gap-1 text-[10px] text-[#6f7f9a]/60">
            <span>{filteredGraph.nodes.length} nodes</span>
            <span>{filteredGraph.edges.length} edges</span>
            <span>{new Set(filteredGraph.nodes.filter((n) => n.kind === "Principal").map((n) => n.trustLevel)).size} trust levels</span>
          </div>
        </div>
      </div>

      <div
        ref={handleContainerRef}
        className="relative flex-1 cursor-grab active:cursor-grabbing"
        onMouseDown={onMouseDown}
        onMouseMove={onMouseMove}
        onMouseUp={onMouseUp}
        onMouseLeave={onMouseUp}
        onClick={onBackgroundClick}
      >
        <div className="absolute right-3 top-3 z-10 flex items-center gap-1.5">
          <span
            className={cn(
              "rounded px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wider",
              isLiveData
                ? "bg-[#3dbf84]/15 text-[#3dbf84]"
                : "bg-[#6f7f9a]/10 text-[#6f7f9a]/60",
            )}
          >
            {isLiveData ? "LIVE" : "DEMO"}
          </span>
          {!fleetConnected && !isLiveData && (
            <span className="flex items-center gap-1 rounded px-2 py-0.5 text-[9px] text-[#6f7f9a]/40">
              <IconPlugConnected size={10} />
              Disconnected
            </span>
          )}
        </div>

        <div className="absolute left-3 top-3 z-10 flex items-center gap-0.5 rounded-md border border-[#1a1f2e] bg-[#0b0d13]/95 px-1.5 py-1 backdrop-blur-sm">
          <ToolbarBtn
            icon={isLiveData ? IconDatabase : IconTestPipe}
            label={isLiveData ? "Live" : "Demo"}
            onClick={toggleDataSource}
            active={isLiveData}
            disabled={!isLiveData && !fleetConnected}
          />
          {liveAvailable && !isLiveData && fleetConnected && (
            <span className="ml-0.5 h-1.5 w-1.5 rounded-full bg-[#3dbf84]" />
          )}
          {isLiveData && fleetConnected && (
            <ToolbarBtn
              icon={IconRefresh}
              label="Refresh"
              onClick={refreshLiveData}
            />
          )}
          {isLiveData && principals.length > 0 && (
            <>
              <Sep />
              <PrincipalSelector
                principals={principals}
                selectedId={selectedPrincipalId}
                isOpen={principalDropdownOpen}
                onToggle={() => setPrincipalDropdownOpen((p) => !p)}
                onClose={() => setPrincipalDropdownOpen(false)}
                onSelect={handlePrincipalChange}
                disabled={isLoadingPrincipal}
              />
            </>
          )}
          <Sep />
          <ToolbarBtn icon={IconFocus2} label="Fit" onClick={fitToScreen} />
          <ToolbarBtn
            icon={IconZoomIn}
            label="In"
            onClick={() => setZoom((z) => Math.min(z * 1.25, 4))}
            disabled={zoom >= 4}
          />
          <ToolbarBtn
            icon={IconZoomOut}
            label="Out"
            onClick={() => setZoom((z) => Math.max(z / 1.25, 0.15))}
            disabled={zoom <= 0.15}
          />
          <Sep />
          <ToolbarBtn icon={IconDownload} label="SVG" onClick={exportSvg} />
        </div>

        {isLiveData && liveFetchError && (
          <div className="absolute bottom-3 right-3 z-10 flex items-center gap-2 rounded border border-[#2d3240] bg-[#131721]/90 px-3 py-1.5 backdrop-blur-sm">
            <IconPlugConnected size={12} className="text-[#6f7f9a] shrink-0" />
            <span className="text-[10px] text-[#6f7f9a]">{liveFetchError}</span>
          </div>
        )}

        <div className="absolute bottom-3 left-3 z-10 rounded border border-[#1a1f2e] bg-[#0b0d13]/90 px-2 py-0.5 text-[10px] tabular-nums text-[#6f7f9a]/60">
          {Math.round(zoom * 100)}%
        </div>

        {isLoadingGraph && (
          <div className="absolute inset-0 z-20 flex items-center justify-center bg-[#05060a]/60 backdrop-blur-sm">
            <div className="flex flex-col items-center gap-2">
              <div className="h-6 w-6 animate-spin rounded-full border-2 border-[#d4a84b]/30 border-t-[#d4a84b]" />
              <span className="text-[10px] text-[#6f7f9a]/60">Loading graph data...</span>
            </div>
          </div>
        )}

        <svg className="h-full w-full" style={{ background: "#05060a" }}>
          <defs>
            <pattern id="grid-dot" width="24" height="24" patternUnits="userSpaceOnUse">
              <circle cx="12" cy="12" r="0.5" fill="#1a1f2e" />
            </pattern>
            <marker
              id="arrow"
              markerWidth="6"
              markerHeight="6"
              refX="5"
              refY="3"
              orient="auto"
            >
              <path d="M 0 0 L 6 3 L 0 6 Z" fill="#2d3240" />
            </marker>
            <marker
              id="arrow-gold"
              markerWidth="6"
              markerHeight="6"
              refX="5"
              refY="3"
              orient="auto"
            >
              <path d="M 0 0 L 6 3 L 0 6 Z" fill="#d4a84b" />
            </marker>
            <marker
              id="arrow-revoked"
              markerWidth="6"
              markerHeight="6"
              refX="5"
              refY="3"
              orient="auto"
            >
              <path d="M 0 0 L 6 3 L 0 6 Z" fill="#c45c5c" />
            </marker>
          </defs>

          <rect width="100%" height="100%" fill="url(#grid-dot)" />

          <g data-viewport="" transform={`translate(${panX},${panY}) scale(${zoom})`}>
            {layout.edges.map((le) => {
              const edge = edgeMap.get(le.id);
              if (!edge) return null;
              const isHL = highlightedEdges?.has(le.id);
              const isDimmed = highlightedEdges && !isHL;
              const color = EDGE_COLORS[edge.kind] ?? "#2d3240";
              const isDashed = DASHED_EDGES.has(edge.kind);
              const isRevoked = edge.kind === "RevokedBy";

              return (
                <path
                  key={le.id}
                  d={le.path}
                  fill="none"
                  stroke={isHL ? "#d4a84b" : color}
                  strokeWidth={isHL ? 1.5 : 1}
                  strokeDasharray={isDashed ? "6 4" : undefined}
                  opacity={isDimmed ? 0.08 : isHL ? 1 : 0.35}
                  markerEnd={
                    isRevoked
                      ? "url(#arrow-revoked)"
                      : isHL
                        ? "url(#arrow-gold)"
                        : "url(#arrow)"
                  }
                  className="transition-opacity duration-200"
                />
              );
            })}

            {filteredGraph.nodes.map((node) => {
              const ln = layout.nodes.get(node.id);
              if (!ln) return null;
              const isSelected = selectedNode?.id === node.id;
              const isHovered = hoveredNodeId === node.id;
              const isHL = highlightedNodes?.has(node.id);
              const isDimmed = highlightedNodes && !isHL && !isSelected;
              const accent = NODE_KIND_ACCENT[node.kind];
              const trustColor = node.trustLevel ? TRUST_COLORS[node.trustLevel] : null;
              const KindIcon = NODE_KIND_ICON[node.kind];

              return (
                <g
                  key={node.id}
                  data-node={node.id}
                  transform={`translate(${ln.x},${ln.y})`}
                  opacity={isDimmed ? 0.12 : 1}
                  className="cursor-pointer transition-opacity duration-200"
                  onMouseEnter={() => setHoveredNodeId(node.id)}
                  onMouseLeave={() => setHoveredNodeId(null)}
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedNode(node);
                  }}
                >
                  <rect
                    width={ln.width}
                    height={ln.height}
                    rx={6}
                    ry={6}
                    fill="#0f1219"
                    stroke={isSelected ? "#d4a84b" : isHovered ? "#2d3240" : "#1a1f2e"}
                    strokeWidth={isSelected ? 1.5 : 1}
                  />

                  <rect
                    x={0}
                    y={8}
                    width={2.5}
                    height={ln.height - 16}
                    rx={1.25}
                    fill={isSelected ? "#d4a84b" : accent}
                    opacity={isSelected ? 1 : 0.6}
                  />

                  <foreignObject x={12} y={(ln.height - 16) / 2} width={16} height={16}>
                    <KindIcon size={14} className="text-[#6f7f9a] opacity-50" />
                  </foreignObject>

                  <text
                    x={32}
                    y={node.trustLevel ? ln.height / 2 - 3 : ln.height / 2}
                    dominantBaseline={node.trustLevel ? "auto" : "central"}
                    className="select-none"
                    fill={isSelected ? "#ece7dc" : "#c4c9d4"}
                    fontSize={11}
                    fontFamily="'JetBrains Mono', ui-monospace, monospace"
                    fontWeight={500}
                  >
                    {node.label.length > 16 ? node.label.slice(0, 15) + "…" : node.label}
                  </text>

                  {trustColor && (
                    <g>
                      <circle
                        cx={36}
                        cy={ln.height / 2 + 9}
                        r={2.5}
                        fill={trustColor}
                        opacity={0.8}
                      />
                      <text
                        x={42}
                        y={ln.height / 2 + 9}
                        dominantBaseline="central"
                        fill={trustColor}
                        fontSize={8}
                        fontFamily="'JetBrains Mono', ui-monospace, monospace"
                        opacity={0.6}
                      >
                        {node.trustLevel}
                      </text>
                    </g>
                  )}

                  {isSelected && (
                    <rect
                      width={ln.width}
                      height={ln.height}
                      rx={6}
                      ry={6}
                      fill="none"
                      stroke="#d4a84b"
                      strokeWidth={0.5}
                      opacity={0.3}
                      style={{ filter: "blur(4px)" }}
                    />
                  )}
                </g>
              );
            })}
          </g>
        </svg>
      </div>

      {selectedNode && (
        <div className="flex w-64 shrink-0 flex-col border-l border-[#1a1f2e] bg-[#0b0d13]">
          <div className="flex items-center justify-between border-b border-[#1a1f2e] px-4 py-3">
            <h2 className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]">
              Details
            </h2>
            <button
              onClick={() => {
                setSelectedNode(null);
                setTracedPath(null);
              }}
              className="text-[#6f7f9a]/50 transition-colors hover:text-[#ece7dc]"
            >
              <IconX size={13} />
            </button>
          </div>

          <div className="flex-1 overflow-y-auto">
            <div className="border-b border-[#1a1f2e] px-4 py-3">
              <div className="text-[13px] font-semibold text-[#ece7dc]">
                {selectedNode.label}
              </div>
              <div className="mt-2 flex flex-wrap gap-1.5">
                <DetailBadge text={selectedNode.kind} accent={NODE_KIND_ACCENT[selectedNode.kind]} />
                {selectedNode.role && <DetailBadge text={selectedNode.role} />}
                {selectedNode.trustLevel && (
                  <DetailBadge
                    text={selectedNode.trustLevel}
                    accent={TRUST_COLORS[selectedNode.trustLevel]}
                  />
                )}
              </div>
            </div>

            {selectedNode.capabilities && selectedNode.capabilities.length > 0 && (
              <div className="border-b border-[#1a1f2e] px-4 py-3">
                <SectionLabel text="Capabilities" />
                <div className="flex flex-wrap gap-1">
                  {selectedNode.capabilities.map((cap) => (
                    <span
                      key={cap}
                      className="rounded border border-[#d4a84b]/15 bg-[#d4a84b]/5 px-1.5 py-0.5 text-[9px] text-[#d4a84b]/80"
                    >
                      {cap}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {incomingEdges.length > 0 && (
              <div className="border-b border-[#1a1f2e] px-4 py-3">
                <SectionLabel text={`Incoming (${incomingEdges.length})`} />
                <div className="flex flex-col gap-1">
                  {incomingEdges.map((edge) => (
                    <EdgeRow
                      key={edge.id}
                      label={nodeMap.get(edge.from)?.label ?? edge.from}
                      kind={edge.kind}
                    />
                  ))}
                </div>
              </div>
            )}

            {outgoingEdges.length > 0 && (
              <div className="border-b border-[#1a1f2e] px-4 py-3">
                <SectionLabel text={`Outgoing (${outgoingEdges.length})`} />
                <div className="flex flex-col gap-1">
                  {outgoingEdges.map((edge) => (
                    <EdgeRow
                      key={edge.id}
                      label={nodeMap.get(edge.to)?.label ?? edge.to}
                      kind={edge.kind}
                    />
                  ))}
                </div>
              </div>
            )}

            {selectedNode.metadata && Object.keys(selectedNode.metadata).length > 0 && (
              <div className="border-b border-[#1a1f2e] px-4 py-3">
                <SectionLabel text="Metadata" />
                <div className="flex flex-col gap-1">
                  {Object.entries(selectedNode.metadata).map(([key, value]) => (
                    <div key={key} className="flex items-baseline justify-between gap-2 text-[10px]">
                      <span className="text-[#6f7f9a]/60 shrink-0">{key}</span>
                      <span className="text-[#ece7dc]/50 truncate text-right">{renderMetadataValue(value)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="px-4 py-3">
              <button
                onClick={handleTracePath}
                className="flex w-full items-center justify-center gap-1.5 rounded-md border border-[#d4a84b]/20 bg-[#d4a84b]/5 px-3 py-2 text-[11px] text-[#d4a84b]/80 transition-colors hover:bg-[#d4a84b]/10 hover:text-[#d4a84b]"
              >
                <IconRoute size={13} />
                Trace from Root
              </button>
            </div>

            {tracedPath && (
              <div className="border-t border-[#1a1f2e] px-4 py-3">
                <SectionLabel text="Delegation Chain" />
                <div className="flex flex-col">
                  {pathSteps.map(({ node, edge }) => (
                    <div key={node.id}>
                      {edge && (
                        <div className="ml-2 flex items-center gap-1 border-l border-[#d4a84b]/20 py-1 pl-3">
                          <span className="text-[8px] text-[#d4a84b]/50">{edge.kind}</span>
                          {edge.capabilities && edge.capabilities.length > 0 && (
                            <span className="text-[7px] text-[#6f7f9a]/40">
                              [{edge.capabilities.map((c) => CAPABILITY_SHORT[c]).join(",")}]
                            </span>
                          )}
                        </div>
                      )}
                      <div
                        className={cn(
                          "flex items-center gap-1.5 rounded px-2 py-0.5",
                          node.id === selectedNode?.id ? "bg-[#d4a84b]/8" : "",
                        )}
                      >
                        <span className="h-1 w-1 rounded-full bg-[#d4a84b]/60 shrink-0" />
                        <span className="text-[10px] text-[#ece7dc]/80">
                          {node.label}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
                <button
                  onClick={() => setTracedPath(null)}
                  className="mt-2 flex w-full items-center justify-center gap-1 rounded border border-[#1a1f2e] px-2 py-1 text-[9px] text-[#6f7f9a]/50 transition-colors hover:text-[#6f7f9a]"
                >
                  <IconX size={9} />
                  Clear
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function ToolbarBtn({
  icon: Icon,
  label,
  onClick,
  active = false,
  disabled = false,
}: {
  icon: React.ComponentType<{ size?: number; stroke?: number }>;
  label: string;
  onClick: () => void;
  active?: boolean;
  disabled?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      title={label}
      disabled={disabled}
      className={cn(
        "flex h-6 items-center gap-1 rounded px-1.5 text-[9px] transition-colors",
        disabled
          ? "text-[#6f7f9a]/30 cursor-not-allowed"
          : active
            ? "bg-[#d4a84b]/10 text-[#d4a84b]"
            : "text-[#6f7f9a]/60 hover:bg-[#1a1f2e] hover:text-[#ece7dc]/80",
      )}
    >
      <Icon size={13} stroke={1.5} />
      <span className="hidden lg:inline">{label}</span>
    </button>
  );
}

function PrincipalSelector({
  principals,
  selectedId,
  isOpen,
  onToggle,
  onClose,
  onSelect,
  disabled = false,
}: {
  principals: PrincipalInfo[];
  selectedId: string | null;
  isOpen: boolean;
  onToggle: () => void;
  onClose: () => void;
  onSelect: (id: string) => void;
  disabled?: boolean;
}) {
  const dropdownRef = useRef<HTMLDivElement>(null);
  const selected = principals.find((p) => p.id === selectedId);
  const displayName = selected?.name ?? selected?.id ?? "Select principal";

  // Close dropdown on outside click
  useEffect(() => {
    if (!isOpen) return;
    const handler = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        onClose();
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [isOpen, onClose]);

  return (
    <div ref={dropdownRef} className="relative">
      <button
        onClick={onToggle}
        disabled={disabled}
        className={cn(
          "flex h-6 items-center gap-1 rounded px-1.5 text-[9px] transition-colors",
          disabled
            ? "text-[#6f7f9a]/30 cursor-not-allowed"
            : "text-[#6f7f9a]/60 hover:bg-[#1a1f2e] hover:text-[#ece7dc]/80",
        )}
        title="Select principal for graph"
      >
        <IconSelector size={13} stroke={1.5} />
        <span className="max-w-[120px] truncate hidden lg:inline">
          {displayName.length > 18 ? displayName.slice(0, 17) + "\u2026" : displayName}
        </span>
      </button>

      {isOpen && (
        <div className="absolute left-0 top-full z-30 mt-1 max-h-60 w-56 overflow-y-auto rounded-lg border border-[#1a1f2e] bg-[#0b0d13] py-1 shadow-xl">
          {principals.map((p) => (
            <button
              key={p.id}
              onClick={() => onSelect(p.id)}
              className={cn(
                "flex w-full flex-col px-3 py-1.5 text-left transition-colors hover:bg-[#1a1f2e]",
                p.id === selectedId && "bg-[#d4a84b]/8",
              )}
            >
              <span className="text-[10px] font-medium text-[#ece7dc] truncate">
                {p.name ?? p.id}
              </span>
              {p.name && (
                <span className="text-[8px] font-mono text-[#6f7f9a]/50 truncate">
                  {p.id}
                </span>
              )}
              {p.role && (
                <span className="text-[8px] text-[#6f7f9a]/40">{p.role}</span>
              )}
            </button>
          ))}
          {principals.length === 0 && (
            <div className="px-3 py-2 text-[10px] text-[#6f7f9a]/50">
              No principals available
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Sep() {
  return <div className="mx-0.5 h-3 w-px bg-[#1a1f2e]" />;
}

function SectionLabel({ text }: { text: string }) {
  return (
    <h3 className="mb-2 text-[9px] font-semibold uppercase tracking-[0.1em] text-[#6f7f9a]/50">
      {text}
    </h3>
  );
}

function DetailBadge({ text, accent }: { text: string; accent?: string }) {
  return (
    <span
      className="rounded px-1.5 py-0.5 text-[9px]"
      style={{
        backgroundColor: accent ? accent + "12" : "#1a1f2e",
        color: accent ?? "#6f7f9a",
      }}
    >
      {text}
    </span>
  );
}

const MAX_METADATA_LEN = 200;

// Strip Unicode control characters that could interfere with display
// Keeps tab (U+0009), newline (U+000A), and carriage return (U+000D)
// eslint-disable-next-line no-control-regex
const CONTROL_CHAR_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;

function stripControlChars(s: string): string {
  return s.replace(CONTROL_CHAR_RE, "");
}

function renderMetadataValue(value: unknown): string {
  if (value == null) return "";
  let str: string;
  if (typeof value === "object") {
    str = JSON.stringify(value);
  } else {
    str = String(value);
  }
  str = stripControlChars(str);
  return str.length > MAX_METADATA_LEN ? str.slice(0, MAX_METADATA_LEN) + "\u2026" : str;
}

function EdgeRow({ label, kind }: { label: string; kind: string }) {
  return (
    <div className="rounded border border-[#1a1f2e] bg-[#05060a]/50 px-2 py-1.5">
      <div className="text-[10px] text-[#ece7dc]/60 truncate">{label}</div>
      <div className="text-[8px] text-[#6f7f9a]/40">{kind}</div>
    </div>
  );
}
