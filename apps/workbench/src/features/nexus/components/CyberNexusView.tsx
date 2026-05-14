// Ported verbatim from huntronomer CyberNexusView.tsx.
// Adaptations:
//   - useConnection/useSocData/useWorkbench removed (workbench has no live backend)
//   - useNavigate replaced with usePaneStore.openApp
//   - dispatchShellOpenCommandPalette replaced with inline noop
//   - Spirit snapshot/runtime set to null (no live spirit signal in workbench yet)
//   - Strikecells come from props (NexusTab passes DEMO_STRIKECELLS from Zustand store)

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { usePaneStore } from "@/features/panes/pane-store";
import type { HuntStationId } from "@/features/observatory/world/types";
import { HUNT_STATION_LABELS } from "@/features/observatory/world/stations";
import { NexusAppRail } from "./NexusAppRail";
import { NexusCanvas } from "./NexusCanvas";
import { NexusControlStrip } from "./NexusControlStrip";
import { NexusHeroOverlay } from "./NexusHeroOverlay";
import { NexusOverlayDrawer } from "./NexusOverlayDrawer";
import { StrikecellCarousel } from "./StrikecellCarousel";
import {
  buildNexusNodesAndConnections,
} from "../data/strikecellAdapter";
import { CYBER_NEXUS_COMMAND_EVENT, type CyberNexusCommand } from "../events";
import { getLayoutModeFromShortcut } from "../layouts";
import {
  CYBER_NEXUS_MODE_EVENT,
  getNexusModeDescriptor,
  getNexusOperationMode,
  setNexusOperationMode,
} from "../mode";
import {
  deriveNexusSpiritSceneActor,
  detectNexusSpiritCue,
  type NexusSpiritCueEvent,
} from "../scene/spirits/runtime";
import {
  buildNexusAtlasRead,
  NEXUS_ATLAS_GROUP_ORDER,
  getNexusStationLabel,
  resolveNexusObservatoryStationId,
} from "../observatory";
import {
  type NexusContextMenuState,
  NexusStateProvider,
  useEscClosePriority,
  useNexusState,
} from "../state/NexusStateContext";
import type { NexusLayoutMode, NexusOperationMode, Strikecell, StrikecellDomainId } from "../types";

const NEXUS_FOCUS_STORAGE_KEY = "sdr:cyber-nexus:lastFocus";
const NEXUS_HERO_DISMISSED_KEY = "sdr:cyber-nexus:heroDismissed";
const SEARCH_GROUP_ORDER = NEXUS_ATLAS_GROUP_ORDER;

// Workbench noop: no shell command palette dispatch yet
function dispatchShellOpenCommandPalette() {
  // noop in workbench context
}

function statusChipClass(status: Strikecell["status"]) {
  switch (status) {
    case "healthy":
      return "text-sdr-accent-green";
    case "warning":
      return "text-sdr-accent-amber";
    case "critical":
      return "text-sdr-accent-red";
    default:
      return "text-sdr-text-muted";
  }
}

const ATLAS_RAIL_STRIKECELLS: Strikecell[] = [
  {
    id: "security-overview",
    name: "Horizon",
    routeId: "nexus/scene",
    description: "",
    status: "healthy",
    activityCount: 0,
    nodeCount: 0,
    nodes: [],
    tags: [],
  },
  {
    id: "attack-graph",
    name: "Subjects",
    routeId: "nexus/scene",
    description: "",
    status: "healthy",
    activityCount: 0,
    nodeCount: 0,
    nodes: [],
    tags: [],
  },
  {
    id: "network-map",
    name: "Operations",
    routeId: "nexus/scene",
    description: "",
    status: "healthy",
    activityCount: 0,
    nodeCount: 0,
    nodes: [],
    tags: [],
  },
  {
    id: "forensics-river",
    name: "Evidence",
    routeId: "nexus/scene",
    description: "",
    status: "healthy",
    activityCount: 0,
    nodeCount: 0,
    nodes: [],
    tags: [],
  },
  {
    id: "policies",
    name: "Judgment",
    routeId: "nexus/scene",
    description: "",
    status: "healthy",
    activityCount: 0,
    nodeCount: 0,
    nodes: [],
    tags: [],
  },
  {
    id: "threat-radar",
    name: "Watchfield",
    routeId: "nexus/scene",
    description: "",
    status: "healthy",
    activityCount: 0,
    nodeCount: 0,
    nodes: [],
    tags: [],
  },
];

function CyberNexusInner({ strikecells }: { strikecells: Strikecell[] }) {
  const {
    state,
    syncStrikecells,
    setActiveStrikecell,
    toggleExpanded,
    setLayoutMode,
    setViewMode,
    toggleFieldVisibility,
    setLayoutDropdownOpen,
    setDrawerApp,
    setSearchOpen,
    setContextMenu,
    setCarouselVisible,
    setCarouselFocused,
    navigateCarousel,
    setKeyboardHighlight,
    toggleNodeSelection,
    setFocusedNode,
    clearSelection,
    requestCameraReset,
    pinStrikecell,
    reorderStrikecell,
  } = useNexusState();

  const escClose = useEscClosePriority();
  const [searchQuery, setSearchQuery] = useState("");
  const [operationMode, setOperationModeState] = useState<NexusOperationMode>(() =>
    getNexusOperationMode(),
  );
  const [heroVisible, setHeroVisible] = useState(() => {
    try {
      return localStorage.getItem(NEXUS_HERO_DISMISSED_KEY) !== "1";
    } catch {
      return true;
    }
  });

  const dismissHero = useCallback(() => {
    setHeroVisible(false);
    try {
      localStorage.setItem(NEXUS_HERO_DISMISSED_KEY, "1");
    } catch {
      // Ignore
    }
  }, []);
  const heroOverlayVisible = heroVisible;

  useEffect(() => {
    const listener = (event: Event) => {
      const nextMode = (event as CustomEvent<NexusOperationMode>).detail;
      if (!nextMode) return;
      setOperationModeState(nextMode);
    };

    window.addEventListener(CYBER_NEXUS_MODE_EVENT, listener);
    return () => window.removeEventListener(CYBER_NEXUS_MODE_EVENT, listener);
  }, []);

  const graph = useMemo(() => buildNexusNodesAndConnections(strikecells), [strikecells]);
  const activeStrikecell = useMemo(
    () =>
      strikecells.find((strikecell) => strikecell.id === state.selection.activeStrikecellId) ??
      null,
    [state.selection.activeStrikecellId, strikecells],
  );
  const operationModeDescriptor = useMemo(
    () => getNexusModeDescriptor(operationMode),
    [operationMode],
  );
  const drawerStrikecell = useMemo(
    () => strikecells.find((strikecell) => strikecell.id === state.drawerAppId) ?? null,
    [state.drawerAppId, strikecells],
  );

  // Spirit is null in workbench (no live spirit signal yet)
  const activeSpiritSnapshot = null;
  const activeSpiritRuntime = null;
  const [activeSpiritCue, setActiveSpiritCue] = useState<NexusSpiritCueEvent | null>(null);
  const previousCameraResetRef = useRef(state.cameraResetToken);

  const activateStrikecell = useCallback(
    (id: StrikecellDomainId, options?: { closeSearch?: boolean }) => {
      if (state.selection.activeStrikecellId === id) {
        requestCameraReset();
      }
      setActiveStrikecell(id);
      setKeyboardHighlight(id);
      if (options?.closeSearch) {
        setSearchOpen(false);
        setSearchQuery("");
      }
    },
    [
      requestCameraReset,
      setActiveStrikecell,
      setKeyboardHighlight,
      setSearchOpen,
      state.selection.activeStrikecellId,
    ],
  );

  const filteredStrikecells = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    if (!query) return strikecells;
    return strikecells.filter((strikecell) => {
      return (
        strikecell.name.toLowerCase().includes(query) ||
        strikecell.description.toLowerCase().includes(query) ||
        strikecell.tags.some((tag) => tag.toLowerCase().includes(query))
      );
    });
  }, [searchQuery, strikecells]);

  const groupedStrikecells = useMemo(() => {
    const buckets = Object.fromEntries(
      SEARCH_GROUP_ORDER.map((stationId) => [stationId, [] as Strikecell[]]),
    ) as Record<(typeof SEARCH_GROUP_ORDER)[number], Strikecell[]>;

    filteredStrikecells.forEach((strikecell) => {
      const stationId = resolveNexusObservatoryStationId(strikecell.id);
      if (!stationId) return;
      buckets[stationId].push(strikecell);
    });

    return SEARCH_GROUP_ORDER.map((groupId) => ({
      id: groupId,
      label: getNexusStationLabel(groupId),
      items: buckets[groupId],
    })).filter((group) => group.items.length > 0);
  }, [filteredStrikecells]);

  useEffect(() => {
    syncStrikecells(strikecells.map((strikecell) => strikecell.id));
  }, [strikecells, syncStrikecells]);

  useEffect(() => {
    if (!state.selection.activeStrikecellId) return;

    try {
      localStorage.setItem(NEXUS_FOCUS_STORAGE_KEY, state.selection.activeStrikecellId);
    } catch {
      // Ignore
    }
  }, [state.selection.activeStrikecellId]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement;
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) {
        return;
      }

      if (heroOverlayVisible) return;

      const isMeta = event.metaKey || event.ctrlKey;

      if (event.key === "Escape") {
        event.preventDefault();
        if (state.searchOpen) {
          setSearchQuery("");
        }
        escClose();
        return;
      }

      if (isMeta && event.key.toLowerCase() === "k") {
        event.preventDefault();
        dispatchShellOpenCommandPalette();
        return;
      }

      if (isMeta && event.key.toLowerCase() === "f") {
        event.preventDefault();
        setSearchOpen(true);
        return;
      }

      if (event.key === "Tab") {
        event.preventDefault();
        if (event.shiftKey) {
          setCarouselFocused(false);
          setCarouselVisible(false);
          return;
        }

        setCarouselVisible(true);
        setCarouselFocused(true);
        return;
      }

      if (state.carouselFocused && (event.key === "ArrowUp" || event.key === "ArrowLeft")) {
        event.preventDefault();
        navigateCarousel("prev");
        return;
      }

      if (state.carouselFocused && (event.key === "ArrowDown" || event.key === "ArrowRight")) {
        event.preventDefault();
        navigateCarousel("next");
        return;
      }

      if (state.carouselFocused && event.key === "Enter" && state.keyboardHighlightedStrikecellId) {
        event.preventDefault();
        activateStrikecell(state.keyboardHighlightedStrikecellId);
        return;
      }

      if (!isMeta) {
        const layoutMode = getLayoutModeFromShortcut(event.key);
        if (layoutMode) {
          event.preventDefault();
          setLayoutMode(layoutMode);
          setLayoutDropdownOpen(false);
          return;
        }
      }

      if (!isMeta && event.key.toLowerCase() === "v") {
        event.preventDefault();
        setViewMode(state.hud.viewMode === "galaxy" ? "grid" : "galaxy");
        return;
      }

      if (!isMeta && event.key.toLowerCase() === "b") {
        event.preventDefault();
        toggleFieldVisibility();
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [
    activateStrikecell,
    escClose,
    navigateCarousel,
    setCarouselFocused,
    setCarouselVisible,
    setLayoutDropdownOpen,
    setLayoutMode,
    setSearchOpen,
    setViewMode,
    heroOverlayVisible,
    state.carouselFocused,
    state.searchOpen,
    state.hud.viewMode,
    state.keyboardHighlightedStrikecellId,
    toggleFieldVisibility,
  ]);

  useEffect(() => {
    const listener = (event: Event) => {
      const payload = (event as CustomEvent<CyberNexusCommand>).detail;
      if (!payload) return;

      switch (payload.type) {
        case "focus-strikecell":
          activateStrikecell(payload.strikecellId);
          break;
        case "reset-camera":
          requestCameraReset();
          break;
        case "open-drawer":
          setDrawerApp(payload.strikecellId);
          break;
        case "open-search":
          setSearchOpen(true);
          break;
        case "set-layout":
          setLayoutMode(payload.layoutMode);
          setLayoutDropdownOpen(false);
          break;
        case "set-view-mode":
          setViewMode(payload.viewMode);
          break;
        case "set-operation-mode":
          setNexusOperationMode(payload.mode);
          setOperationModeState(payload.mode);
          break;
        case "toggle-field":
          toggleFieldVisibility();
          break;
        case "focus-next":
          navigateCarousel("next");
          break;
        case "focus-prev":
          navigateCarousel("prev");
          break;
        default:
          break;
      }
    };

    window.addEventListener(CYBER_NEXUS_COMMAND_EVENT, listener);
    return () => window.removeEventListener(CYBER_NEXUS_COMMAND_EVENT, listener);
  }, [
    activateStrikecell,
    navigateCarousel,
    requestCameraReset,
    setDrawerApp,
    setLayoutDropdownOpen,
    setLayoutMode,
    setSearchOpen,
    setViewMode,
    toggleFieldVisibility,
  ]);

  const handleOpenFullView = useCallback(
    (routeId: string) => {
      usePaneStore.getState().openApp(`/${routeId}`);
    },
    [],
  );

  const handleSearchSelect = useCallback(
    (id: StrikecellDomainId) => {
      activateStrikecell(id, { closeSearch: true });
    },
    [activateStrikecell],
  );

  const handleSelectObservatoryStation = useCallback(
    (stationId: HuntStationId) => {
      const candidates = strikecells.filter(
        (strikecell) => resolveNexusObservatoryStationId(strikecell.id) === stationId,
      );
      if (candidates.length === 0) return;
      const next =
        candidates.find((strikecell) => strikecell.id === state.selection.activeStrikecellId)
        ?? [...candidates].sort((left, right) => right.activityCount - left.activityCount)[0];
      if (!next) return;
      activateStrikecell(next.id);
    },
    [activateStrikecell, state.selection.activeStrikecellId, strikecells],
  );

  const handleContextAction = useCallback(
    (action: "focus" | "expand" | "pin-left" | "pin-right" | "unpin" | "open" | "clear") => {
      const menu = state.contextMenu;
      if (!menu) return;

      const strikecellId =
        menu.strikecellId ??
        (menu.targetType === "strikecell" ? (menu.targetId as StrikecellDomainId) : null);

      if (action === "focus" && strikecellId) {
        activateStrikecell(strikecellId);
      }
      if (action === "expand" && strikecellId) toggleExpanded(strikecellId);
      if (action === "pin-left" && strikecellId) pinStrikecell(strikecellId, "left");
      if (action === "pin-right" && strikecellId) pinStrikecell(strikecellId, "right");
      if (action === "unpin" && strikecellId) pinStrikecell(strikecellId, null);
      if (action === "open" && strikecellId) {
        const strikecell = strikecells.find((entry) => entry.id === strikecellId);
        if (strikecell) handleOpenFullView(strikecell.routeId);
      }
      if (action === "clear") clearSelection();

      setContextMenu(null);
    },
    [
      activateStrikecell,
      clearSelection,
      handleOpenFullView,
      pinStrikecell,
      setContextMenu,
      state.contextMenu,
      strikecells,
      toggleExpanded,
    ],
  );

  // Spirit actor is null in workbench (no live spirit signal)
  const activeSpiritActor = null;

  const empty = strikecells.length === 0;
  const observatorySceneState = null;
  const observatoryAtlasRead = useMemo(
    () =>
      buildNexusAtlasRead({
        sceneState: null,
        activeStrikecell,
        activeSpiritActor: null,
      }),
    [activeStrikecell],
  );
  const activeRailStrikecellId = useMemo(() => {
    const activeStationId = resolveNexusObservatoryStationId(state.selection.activeStrikecellId);
    return (
      ATLAS_RAIL_STRIKECELLS.find(
        (strikecell) => resolveNexusObservatoryStationId(strikecell.id) === activeStationId,
      )?.id ?? null
    );
  }, [state.selection.activeStrikecellId]);

  return (
    <div className="origin-shell-bg relative flex h-full flex-col overflow-hidden">
      <NexusControlStrip
        connectionStatus="disconnected"
        layoutMode={state.layoutMode}
        activeStrikecell={activeStrikecell}
        brandSubline="Observatory Atlas"
        atlasLabel={observatoryAtlasRead.label}
        atlasCode={observatoryAtlasRead.code}
        atlasReason={observatoryAtlasRead.reason}
        commandQuery={searchQuery}
        layoutDropdownOpen={state.hud.layoutDropdownOpen}
        onOpenSearch={() => setSearchOpen(true)}
        onCommandQueryChange={setSearchQuery}
        onOpenCommandPalette={dispatchShellOpenCommandPalette}
        onToggleLayoutDropdown={() => setLayoutDropdownOpen(!state.hud.layoutDropdownOpen)}
        onCloseLayoutDropdown={() => setLayoutDropdownOpen(false)}
        onSelectLayout={(mode: NexusLayoutMode) => {
          setLayoutMode(mode);
          setLayoutDropdownOpen(false);
        }}
        onOpenOperations={() => usePaneStore.getState().openApp("/lab")}
        onOpenConnectionSettings={() => usePaneStore.getState().openApp("/settings")}
      />

      <div className="relative flex-1 overflow-hidden">
        {empty ? (
          <div className="absolute inset-0 flex items-center justify-center text-sdr-text-muted text-sm">
            Huntronomer is waiting for live hunt data.
          </div>
        ) : (
          <NexusCanvas
            strikecells={strikecells}
            connections={graph.connections}
            activeStrikecellId={state.selection.activeStrikecellId}
            expandedStrikecellIds={state.selection.expandedStrikecellIds}
            selectedNodeIds={state.selection.selectedNodeIds}
            focusedNodeId={state.selection.focusedNodeId}
            layoutMode={state.layoutMode}
            viewMode={state.hud.viewMode}
            fieldVisible={state.hud.fieldVisible}
            cameraResetToken={state.cameraResetToken}
            activeSpiritActor={activeSpiritActor}
            observatorySceneState={observatorySceneState}
            onSelectStrikecell={(id) => activateStrikecell(id)}
            onToggleExpandedStrikecell={toggleExpanded}
            onToggleNodeSelection={toggleNodeSelection}
            onFocusNode={setFocusedNode}
            onBackgroundClick={() => {
              clearSelection();
              setContextMenu(null);
            }}
            onContextMenu={(targetId, targetType, event, strikecellId) => {
              setContextMenu({
                x: event.clientX,
                y: event.clientY,
                targetId,
                targetType,
                strikecellId,
              } satisfies NexusContextMenuState);
            }}
          />
        )}

        {state.carouselVisible ? (
          <StrikecellCarousel
            strikecells={strikecells}
            strikecellOrder={state.strikecellOrder}
            activeStrikecellId={state.selection.activeStrikecellId}
            keyboardHighlightedId={state.keyboardHighlightedStrikecellId}
            carouselFocused={state.carouselFocused}
            pinned={state.pinnedStrikecells}
            onFocusChange={setCarouselFocused}
            onNavigate={navigateCarousel}
            onActivate={(id) => {
              activateStrikecell(id);
            }}
            onHighlight={setKeyboardHighlight}
            onToggleExpanded={toggleExpanded}
            onPin={pinStrikecell}
            onReorder={reorderStrikecell}
          />
        ) : null}

        <NexusAppRail
          strikecells={ATLAS_RAIL_STRIKECELLS}
          openAppId={activeRailStrikecellId}
          onToggleApp={(id) => {
            const stationId = resolveNexusObservatoryStationId(id);
            if (!stationId) return;
            handleSelectObservatoryStation(stationId);
          }}
          mode="station"
          title="Atlas"
        />

        <NexusOverlayDrawer
          open={Boolean(state.drawerAppId)}
          strikecell={drawerStrikecell}
          onClose={() => setDrawerApp(null)}
          onOpenFullView={handleOpenFullView}
        />

        {state.searchOpen ? (
          <div className="absolute inset-0 z-50 flex items-start justify-center bg-[rgba(2,3,7,0.76)] pt-20 backdrop-blur-md">
            <div className="premium-panel premium-panel--lens w-full max-w-[760px] overflow-hidden rounded-2xl">
              <div className="flex items-center gap-3 px-4 py-3">
                <span
                  className="origin-glyph-orb origin-glyph-orb--small shrink-0"
                  aria-hidden="true"
                />

                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <input
                      autoFocus
                      value={searchQuery}
                      onChange={(event) => setSearchQuery(event.target.value)}
                      placeholder="Search atlas stations..."
                      className="premium-input w-full px-3 py-2 text-sm text-sdr-text-primary placeholder:text-sdr-text-muted outline-none"
                    />
                    <span className="premium-chip px-2 py-1 text-[9px] font-mono uppercase tracking-[0.12em] text-sdr-text-secondary">
                      Cmd+F
                    </span>
                  </div>
                  <div className="mt-2 flex items-center gap-2">
                    <span className="origin-label text-[9px] tracking-[0.16em] text-[color:rgba(213,173,87,0.86)]">
                      Atlas Lens
                    </span>
                    <span className="premium-chip px-1.5 py-0.5 text-[8px] font-mono uppercase tracking-[0.12em] text-sdr-text-secondary">
                      Mode: {operationModeDescriptor.label}
                    </span>
                    <span className="premium-chip px-1.5 py-0.5 text-[8px] font-mono uppercase text-sdr-text-muted">
                      {filteredStrikecells.length} results
                    </span>
                    <span className="premium-separator h-px flex-1" />
                  </div>
                </div>

                <span className="premium-chip px-2 py-1 text-[9px] font-mono uppercase tracking-[0.12em] text-sdr-text-secondary">
                  Esc
                </span>
                <button
                  type="button"
                  onClick={() => {
                    setSearchOpen(false);
                    setSearchQuery("");
                  }}
                  className="origin-focus-ring premium-chip premium-chip--control px-2.5 py-1 text-[10px] font-mono uppercase tracking-[0.1em]"
                >
                  Close
                </button>
              </div>
              <div className="premium-separator h-px w-full" />
              <div className="max-h-[430px] overflow-y-auto px-2 py-2">
                {groupedStrikecells.map((group) => (
                  <section key={`search-group:${group.id}`} className="mb-2 last:mb-0">
                    <div className="flex items-center gap-2 px-2 py-1">
                      <span className="origin-label text-[9px] tracking-[0.16em] text-[color:rgba(213,173,87,0.84)]">
                        {group.label}
                      </span>
                      <span className="premium-separator h-px flex-1" />
                    </div>

                    <div className="space-y-1 px-1">
                      {group.items.map((strikecell) => (
                        <button
                          key={`search:${strikecell.id}`}
                          type="button"
                          onClick={() => handleSearchSelect(strikecell.id)}
                          className="premium-result-row origin-focus-ring block w-full px-3 py-2 text-left"
                        >
                          <div className="flex items-center justify-between gap-3">
                            <div className="text-[15px] leading-snug text-sdr-text-primary">
                              {strikecell.name}
                            </div>
                            <span
                              className={[
                                "premium-chip px-2 py-0.5 text-[8px] font-mono uppercase tracking-[0.12em]",
                                statusChipClass(strikecell.status),
                              ].join(" ")}
                            >
                              {strikecell.status}
                            </span>
                          </div>
                          <div className="mt-0.5 text-xs text-sdr-text-muted">
                            {strikecell.description}
                          </div>
                        </button>
                      ))}
                    </div>
                  </section>
                ))}

                {filteredStrikecells.length === 0 ? (
                  <div className="px-4 py-7 text-center text-sm text-sdr-text-muted">
                    No strikecells match this query.
                  </div>
                ) : null}
              </div>
            </div>
          </div>
        ) : null}

        {state.contextMenu ? (
          <div className="fixed inset-0 z-[70]" onClick={() => setContextMenu(null)}>
            <div
              className="origin-chrome-panel absolute min-w-[176px] rounded-md p-1"
              style={{ left: state.contextMenu.x, top: state.contextMenu.y }}
              onClick={(event) => event.stopPropagation()}
            >
              <ContextMenuAction label="Focus" onClick={() => handleContextAction("focus")} />
              <ContextMenuAction
                label="Toggle Expand"
                onClick={() => handleContextAction("expand")}
              />
              <ContextMenuAction
                label="Open Full View"
                onClick={() => handleContextAction("open")}
              />
              <div className="my-1 h-px bg-[color:color-mix(in_srgb,var(--origin-panel-border-muted)_55%,transparent)]" />
              <ContextMenuAction label="Pin Left" onClick={() => handleContextAction("pin-left")} />
              <ContextMenuAction
                label="Pin Right"
                onClick={() => handleContextAction("pin-right")}
              />
              <ContextMenuAction label="Unpin" onClick={() => handleContextAction("unpin")} />
              <div className="my-1 h-px bg-[color:color-mix(in_srgb,var(--origin-panel-border-muted)_55%,transparent)]" />
              <ContextMenuAction
                label="Clear Selection"
                destructive
                onClick={() => handleContextAction("clear")}
              />
            </div>
          </div>
        ) : null}
      </div>

      <NexusHeroOverlay visible={heroOverlayVisible} onDismiss={dismissHero} />
    </div>
  );
}

function ContextMenuAction({
  label,
  destructive,
  onClick,
}: {
  label: string;
  destructive?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={[
        "origin-focus-ring block w-full rounded px-2 py-1.5 text-left text-xs font-mono transition-colors",
        destructive
          ? "text-sdr-accent-red hover:bg-sdr-accent-red/10"
          : "text-sdr-text-secondary hover:bg-sdr-bg-tertiary/70 hover:text-sdr-text-primary",
      ].join(" ")}
    >
      {label}
    </button>
  );
}

export function CyberNexusView({ strikecells }: { strikecells: Strikecell[] }) {
  return (
    <NexusStateProvider>
      <CyberNexusInner strikecells={strikecells} />
    </NexusStateProvider>
  );
}
