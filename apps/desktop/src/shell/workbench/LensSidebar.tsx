/**
 * LensSidebar — 304px Lens Drawer with scope-aware content.
 *
 * The drawer now consumes the shared anticipation context so drag/phase
 * behaviors are physically reflected in the sidebar instead of staying trapped
 * in disconnected hooks.
 */
import { AnimatePresence, motion } from "motion/react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  useWorkbench,
  useWorkbenchDispatch,
  useActiveHunt,
  useHuntStore,
  useBucketSummaryCollapsed,
} from "@/shell/workbench/WorkbenchStateProvider";
import type { LensId, ShellMode } from "@/shell/workbench/workbenchState";
import {
  ScopesLens,
  HistoryLens,
  FilesLens,
  SandboxesLens,
  EntitiesLens,
  SwarmsLens,
  NotesLens,
} from "./lenses";
import type { ArtifactKind, Hunt, HuntStore } from "./huntTypes";
import { LiveContextSection } from "./LiveContextSection";
import { SuggestedSection } from "./SuggestedSection";
import { useLiveContext, useSuggested } from "./useSidebarIntelligence";
import {
  PathBreadcrumbs,
  SHELL_DEFAULT_LENS,
  SidebarGhostPeek,
  SmartBucketHeader,
  TIMING,
  useAnticipationContext,
  useSidebarDirector,
  useSidebarWakeController,
} from "./anticipation";
import { useDragSemanticSelection, useDragState, useDropTarget } from "./DragDropContext";
import type { OpenTabMode } from "./workbenchState";

const MAX_WIDTH = 400;
const COLLAPSED_HOTZONE_WIDTH = 0;
const SIDEBAR_AUTO_RETRACT_MS = 260;
const SIDEBAR_MOTION = {
  open: {
    widthMs: 150,
    glassMs: 140,
    contentDelayMs: 88,
    contentMs: 142,
    hotzoneMs: 90,
  },
  close: {
    contentMs: 72,
    widthDelayMs: 96,
    widthMs: 148,
    glassDelayMs: 76,
    glassMs: 112,
    hotzoneDelayMs: 144,
    hotzoneMs: 96,
  },
  easing: {
    open: [0.33, 0.01, 0.18, 0.99],
    close: [0.33, 0, 0.2, 1],
  },
} as const;

const ms = (milliseconds: number) => milliseconds / 1000;

const KIND_LENS_HINTS: Partial<Record<string, LensId[]>> = {
  entity: ["entities", "notes"],
  file: ["files", "sandboxes"],
  receipt: ["notes", "history"],
  signal: ["scopes", "entities"],
  "signal-thread": ["scopes", "entities"],
  note: ["notes", "files"],
  query: ["history", "files"],
  snapshot: ["history", "files"],
  evidence: ["notes", "files"],
};

type SidebarBlockId = "intent" | "path" | "live" | "suggested" | "content";

interface SidebarBlock {
  id: SidebarBlockId;
  priority: number;
  promoted: boolean;
  element: React.JSX.Element;
}

export interface LensSidebarProps {
  onOpenPath?: (
    relativePath: string,
    options?: { openMode?: OpenTabMode; reason?: string | null },
  ) => void;
}

export function LensSidebar({ onOpenPath }: LensSidebarProps) {
  const { state } = useWorkbench();
  const anticipation = useAnticipationContext();
  const dispatch = useWorkbenchDispatch();
  const activeHunt = useActiveHunt();
  const huntStore = useHuntStore();
  const bucketCollapsed = useBucketSummaryCollapsed();
  const liveContext = useLiveContext();
  const suggested = useSuggested(anticipation.currentLens);
  const sidebarDirector = useSidebarDirector();
  const sidebarWake = useSidebarWakeController();
  const dragState = useDragState();
  const { selectedSemantic, setSelectedSemantic } = useDragSemanticSelection();
  const { sidebarCollapsed, sidebarWidth } = state;
  const bucketDropTarget = useDropTarget(activeHunt?.id ?? "__inactive-hunt__");

  const sidebarFrameRef = useRef<HTMLElement | null>(null);
  const dragStartRef = useRef<{ startX: number; startWidth: number } | null>(null);
  const autoOpenedRef = useRef(false);
  const edgePeekRef = useRef(false);
  const edgeCloseTimerRef = useRef<number | null>(null);
  const [sidebarViewportLeft, setSidebarViewportLeft] = useState(0);

  const handleSelectTab = useCallback((tabId: string) => {
    dispatch({ type: "SET_ACTIVE_TAB", payload: { groupId: "main", tabId } });
  }, [dispatch]);

  const clearEdgeCloseTimer = useCallback(() => {
    if (edgeCloseTimerRef.current !== null) {
      window.clearTimeout(edgeCloseTimerRef.current);
      edgeCloseTimerRef.current = null;
    }
  }, []);

  const measureSidebarViewportLeft = useCallback(() => {
    if (!sidebarFrameRef.current) return;
    const nextLeft = sidebarFrameRef.current.getBoundingClientRect().left;
    setSidebarViewportLeft((current) => (
      Math.abs(current - nextLeft) > 0.5
        ? nextLeft
        : current
    ));
  }, []);

  const requestSidebarOpen = useCallback(
    (source: "edge" | "auto" | "manual") => {
      clearEdgeCloseTimer();
      if (source === "edge") {
        edgePeekRef.current = true;
        autoOpenedRef.current = false;
      } else {
        edgePeekRef.current = false;
        autoOpenedRef.current = source === "auto";
      }
      if (sidebarCollapsed) {
        dispatch({ type: "SET_SIDEBAR_COLLAPSED", payload: false });
      }
    },
    [clearEdgeCloseTimer, dispatch, sidebarCollapsed],
  );

  const requestSidebarClose = useCallback(
    (_reason: "edge" | "auto" | "manual") => {
      clearEdgeCloseTimer();
      if (sidebarCollapsed) {
        dispatch({ type: "SET_SIDEBAR_COLLAPSED", payload: true });
        edgePeekRef.current = false;
        autoOpenedRef.current = false;
        return;
      }

      edgePeekRef.current = false;
      autoOpenedRef.current = false;
      dispatch({ type: "SET_SIDEBAR_COLLAPSED", payload: true });
    },
    [clearEdgeCloseTimer, dispatch, sidebarCollapsed],
  );

  const handleCollapse = useCallback(() => {
    edgePeekRef.current = false;
    requestSidebarClose("manual");
  }, [requestSidebarClose]);

  const scheduleTransientClose = useCallback(() => {
    if (!edgePeekRef.current || anticipation.isAttachMode || dragState.active) {
      return;
    }
    if (edgeCloseTimerRef.current !== null) return;
    edgeCloseTimerRef.current = window.setTimeout(() => {
      edgeCloseTimerRef.current = null;
      if (!edgePeekRef.current) return;
      requestSidebarClose("edge");
    }, SIDEBAR_AUTO_RETRACT_MS);
  }, [
    anticipation.isAttachMode,
    dragState.active,
    requestSidebarClose,
  ]);

  const commitSidebarOpen = useCallback(() => {
    clearEdgeCloseTimer();
    edgePeekRef.current = false;
    autoOpenedRef.current = false;
  }, [clearEdgeCloseTimer]);

  useEffect(() => {
    return () => {
      clearEdgeCloseTimer();
    };
  }, [clearEdgeCloseTimer]);

  useEffect(() => {
    let frameId: number | null = window.requestAnimationFrame(measureSidebarViewportLeft);
    const element = sidebarFrameRef.current;
    const resizeObserver = typeof ResizeObserver === "undefined" || !element
      ? null
      : new ResizeObserver(() => measureSidebarViewportLeft());
    if (resizeObserver && element) {
      resizeObserver.observe(element);
    }
    window.addEventListener("resize", measureSidebarViewportLeft);
    return () => {
      if (frameId !== null) {
        window.cancelAnimationFrame(frameId);
        frameId = null;
      }
      resizeObserver?.disconnect();
      window.removeEventListener("resize", measureSidebarViewportLeft);
    };
  }, [measureSidebarViewportLeft, sidebarCollapsed, sidebarWidth]);

  useEffect(() => {
    if (sidebarDirector.shouldOpenSidebar && sidebarCollapsed) {
      requestSidebarOpen("auto");
    }
  }, [requestSidebarOpen, sidebarDirector.shouldOpenSidebar, sidebarCollapsed]);

  useEffect(() => {
    if (!autoOpenedRef.current || !sidebarDirector.shouldAutoCollapseSidebar) {
      return undefined;
    }
    const timer = window.setTimeout(() => {
      requestSidebarClose("auto");
      autoOpenedRef.current = false;
    }, SIDEBAR_AUTO_RETRACT_MS);
    return () => window.clearTimeout(timer);
  }, [requestSidebarClose, sidebarDirector.shouldAutoCollapseSidebar]);

  useEffect(() => {
    if (
      !sidebarDirector.shouldSwitchLens ||
      !sidebarDirector.targetLens ||
      sidebarDirector.targetLens === anticipation.currentLens
    ) {
      return undefined;
    }

    const timer = window.setTimeout(() => {
      dispatch({ type: "SET_LENS", payload: sidebarDirector.targetLens as LensId });
    }, sidebarDirector.autoSwitchDelayMs ?? TIMING.SPRING_LOAD_MS);
    return () => window.clearTimeout(timer);
  }, [
    sidebarDirector.shouldSwitchLens,
    sidebarDirector.targetLens,
    sidebarDirector.autoSwitchDelayMs,
    anticipation.currentLens,
    dispatch,
  ]);

  useEffect(() => {
    if (
      !selectedSemantic ||
      (dragState.active
        && dragState.overDropTargetId === activeHunt?.id
        && dragState.overDropTargetType === "hunt")
    ) {
      return;
    }

    setSelectedSemantic(null);
  }, [
    dragState.active,
    dragState.overDropTargetId,
    dragState.overDropTargetType,
    activeHunt?.id,
    selectedSemantic,
    setSelectedSemantic,
  ]);

  const handleOpenPath = useCallback(
    (relativePath: string, options?: { openMode?: OpenTabMode; reason?: string | null }) => {
      onOpenPath?.(relativePath, {
        openMode: options?.openMode ?? anticipation.suggestedOpenMode,
        reason: options?.reason ?? anticipation.openModeReason,
      });
    },
    [anticipation.openModeReason, anticipation.suggestedOpenMode, onOpenPath],
  );

  const handleSuggestedAction = useCallback(() => {
    const suggestion = anticipation.pathSuggestedAction;
    if (!suggestion) return;

    if (suggestion.action === "navigate-back") {
      dispatch({ type: "NAVIGATE_TAB_BACK", payload: { groupId: "main" } });
      return;
    }

    if (suggestion.action === "open-note") {
      dispatch({ type: "SET_LENS", payload: "notes" });
      return;
    }

    if (suggestion.action === "open-hunt" && activeHunt) {
      dispatch({ type: "SET_SHELL", payload: "hunt" });
      dispatch({
        type: "OPEN_TAB",
        payload: {
          groupId: "main",
          tab: {
            kind: "hunt",
            title: activeHunt.title,
            subtitle: `${activeHunt.artifactIds.length} artifacts`,
            sourceUri: activeHunt.id,
            isPreview: false,
            isPinned: false,
            isDirty: false,
          },
        },
      });
    }
  }, [anticipation.pathSuggestedAction, activeHunt, dispatch]);

  const handleResizeStart = (event: React.PointerEvent) => {
    event.preventDefault();
    dragStartRef.current = { startX: event.clientX, startWidth: sidebarWidth };

    const onMove = (moveEvent: PointerEvent) => {
      if (!dragStartRef.current) return;
      const delta = moveEvent.clientX - dragStartRef.current.startX;
      const next = dragStartRef.current.startWidth + delta;
      dispatch({ type: "SET_SIDEBAR_WIDTH", payload: next });
    };

    const onUp = () => {
      dragStartRef.current = null;
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
    };

    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
  };

  const sidebarBlocks = useMemo(() => {
    const sectionMap = new Map(
      anticipation.sidebarSections.map((section) => [section.id, section]),
    );

    const resolveBlockMeta = (
      ids: string[],
      fallbackPriority: number,
    ): { visible: boolean; priority: number; promoted: boolean } => {
      type SidebarSection = (typeof anticipation.sidebarSections)[number];
      const matches = ids
        .map((id) => sectionMap.get(id))
        .filter((section): section is SidebarSection => section !== undefined);
      if (matches.length === 0) {
        return { visible: true, priority: fallbackPriority, promoted: false };
      }
      const visibleMatches = matches.filter((section) => section.visible);
      if (visibleMatches.length === 0) {
        return { visible: false, priority: fallbackPriority, promoted: false };
      }
      return {
        visible: true,
        priority: Math.min(...visibleMatches.map((section) => section.priority)),
        promoted: visibleMatches.some((section) => section.promoted),
      };
    };

    const blocks: SidebarBlock[] = [];
    const liveMeta = resolveBlockMeta(
      ["current-hunt", "active-run", "inputs", "recent-receipts"],
      18,
    );
    const suggestedMeta = resolveBlockMeta(
      ["suggested-targets", "suggested-related", "watchlists", "quick-actions"],
      24,
    );
    const pathMeta = resolveBlockMeta(
      ["related-notes", "citations", "case-link"],
      30,
    );

    const shouldShowIntent =
      anticipation.isAttachMode || anticipation.confidence !== "low";
    if (shouldShowIntent) {
      blocks.push({
        id: "intent",
        priority: anticipation.isAttachMode ? 1 : 8,
        promoted: anticipation.confidence === "high",
        element: (
          <IntentGravityPanel
            anticipation={anticipation}
            director={sidebarDirector}
            onSpringLoadLens={(nextLens) => dispatch({ type: "SET_LENS", payload: nextLens })}
          />
        ),
      });
    }

    if (anticipation.pathBreadcrumbs.length > 0 && pathMeta.visible) {
      blocks.push({
        id: "path",
        priority: pathMeta.priority,
        promoted: pathMeta.promoted,
        element: (
          <PathBreadcrumbs
            breadcrumbs={anticipation.pathBreadcrumbs}
            suggestedAction={anticipation.pathSuggestedAction}
            onSuggestedAction={handleSuggestedAction}
          />
        ),
      });
    }

    if (!liveContext.isEmpty && liveMeta.visible) {
      blocks.push({
        id: "live",
        priority: liveMeta.priority,
        promoted: liveMeta.promoted,
        element: (
          <SurfaceCard promoted={liveMeta.promoted}>
            <LiveContextSection data={liveContext} onSelectTab={handleSelectTab} />
          </SurfaceCard>
        ),
      });
    }

    if (suggested.length > 0 && suggestedMeta.visible) {
      blocks.push({
        id: "suggested",
        priority: suggestedMeta.priority,
        promoted: suggestedMeta.promoted,
        element: (
          <SurfaceCard promoted={suggestedMeta.promoted}>
            <SuggestedSection items={suggested} />
          </SurfaceCard>
        ),
      });
    }

    blocks.push({
      id: "content",
      priority: 90,
      promoted: false,
      element: (
        <LensContent
          lens={anticipation.currentLens}
          shell={anticipation.currentShell}
          activeHunt={activeHunt}
          huntStore={huntStore}
          onOpenPath={handleOpenPath}
          entitiesDirective={sidebarDirector.lensSections.entities}
          notesDirective={sidebarDirector.lensSections.notes}
          filesDirective={sidebarDirector.lensSections.files}
          scopesDirective={sidebarDirector.lensSections.scopes}
          historyDirective={sidebarDirector.lensSections.history}
          sandboxesDirective={sidebarDirector.lensSections.sandboxes}
          swarmsDirective={sidebarDirector.lensSections.swarms}
        />
      ),
    });

    return blocks.sort((a, b) => a.priority - b.priority);
  }, [
    anticipation,
    activeHunt,
    huntStore,
    handleOpenPath,
    liveContext,
    suggested,
    dispatch,
    handleSelectTab,
    handleSuggestedAction,
    sidebarDirector,
  ]);
  const panelWidth = sidebarCollapsed ? COLLAPSED_HOTZONE_WIDTH : sidebarWidth;
  const panelTransition = useMemo(
    () => ({
      width: {
        duration: ms(sidebarCollapsed ? SIDEBAR_MOTION.close.widthMs : SIDEBAR_MOTION.open.widthMs),
        ease: sidebarCollapsed ? SIDEBAR_MOTION.easing.close : SIDEBAR_MOTION.easing.open,
        delay: ms(sidebarCollapsed ? SIDEBAR_MOTION.close.widthDelayMs : 0),
      },
    }),
    [sidebarCollapsed],
  );
  const glassTransition = useMemo(
    () => ({
      backgroundColor: {
        duration: ms(sidebarCollapsed ? SIDEBAR_MOTION.close.glassMs : SIDEBAR_MOTION.open.glassMs),
        ease: sidebarCollapsed ? SIDEBAR_MOTION.easing.close : SIDEBAR_MOTION.easing.open,
        delay: ms(sidebarCollapsed ? SIDEBAR_MOTION.close.glassDelayMs : 0),
      },
      borderRightColor: {
        duration: ms(sidebarCollapsed ? SIDEBAR_MOTION.close.glassMs : SIDEBAR_MOTION.open.glassMs),
        ease: sidebarCollapsed ? SIDEBAR_MOTION.easing.close : SIDEBAR_MOTION.easing.open,
        delay: ms(sidebarCollapsed ? SIDEBAR_MOTION.close.glassDelayMs : 0),
      },
      boxShadow: {
        duration: ms(sidebarCollapsed ? SIDEBAR_MOTION.close.glassMs : SIDEBAR_MOTION.open.glassMs),
        ease: sidebarCollapsed ? SIDEBAR_MOTION.easing.close : SIDEBAR_MOTION.easing.open,
        delay: ms(sidebarCollapsed ? SIDEBAR_MOTION.close.glassDelayMs : 0),
      },
    }),
    [sidebarCollapsed],
  );
  const contentTransition = useMemo(
    () => ({
      opacity: {
        duration: ms(sidebarCollapsed ? SIDEBAR_MOTION.close.contentMs : SIDEBAR_MOTION.open.contentMs),
        ease: sidebarCollapsed ? SIDEBAR_MOTION.easing.close : SIDEBAR_MOTION.easing.open,
        delay: ms(sidebarCollapsed ? 0 : SIDEBAR_MOTION.open.contentDelayMs),
      },
      x: {
        duration: ms(sidebarCollapsed ? SIDEBAR_MOTION.close.contentMs : SIDEBAR_MOTION.open.contentMs),
        ease: sidebarCollapsed ? SIDEBAR_MOTION.easing.close : SIDEBAR_MOTION.easing.open,
        delay: ms(sidebarCollapsed ? 0 : SIDEBAR_MOTION.open.contentDelayMs),
      },
    }),
    [sidebarCollapsed],
  );

  return (
    <motion.aside
      ref={sidebarFrameRef}
      className="relative z-20 flex h-full shrink-0 flex-col overflow-visible"
      onPointerEnter={clearEdgeCloseTimer}
      onPointerLeave={scheduleTransientClose}
      onPointerDownCapture={commitSidebarOpen}
      initial={false}
      animate={{ width: panelWidth }}
      transition={panelTransition}
      style={{
        willChange: "width",
        minWidth: 0,
        maxWidth: MAX_WIDTH,
      }}
    >
      <motion.div
        className="absolute inset-0 overflow-hidden"
        initial={false}
        animate={{
          backgroundColor: sidebarCollapsed
            ? "rgba(6,8,13,0)"
            : anticipation.isAttachMode
              ? "rgba(14,11,6,0.72)"
              : "rgba(6,8,13,0.62)",
          borderRightColor: sidebarCollapsed
            ? "rgba(213,173,87,0)"
            : "rgba(213,173,87,0.16)",
          boxShadow: sidebarCollapsed
            ? "none"
            : anticipation.isAttachMode
              ? "inset -1px 0 0 rgba(213,173,87,0.16), 0 0 28px rgba(213,173,87,0.05)"
              : "inset -1px 0 0 rgba(213,173,87,0.16), 0 0 24px rgba(0,0,0,0.12)",
        }}
        transition={glassTransition}
        style={{
          pointerEvents: "none",
          backdropFilter: sidebarCollapsed ? "blur(0px)" : "blur(14px)",
        }}
      />

      <AnimatePresence>
        {sidebarCollapsed && sidebarWake.shouldShowSeam && (
          <motion.div
            key="sidebar-seam"
            className="pointer-events-none fixed z-20 rounded-full"
            initial={{ opacity: 0, scaleX: 0.78 }}
            animate={{ opacity: 1, scaleX: 1 }}
            exit={{ opacity: 0, scaleX: 0.84 }}
            transition={{
              opacity: { duration: 0.12, ease: [0.33, 0.01, 0.18, 0.99] },
              scaleX: { duration: 0.18, ease: [0.33, 0.01, 0.18, 0.99] },
            }}
            style={{
              top: sidebarWake.anchorTop + 32,
              left: sidebarViewportLeft + sidebarWake.seamLeft,
              width: sidebarWake.seamWidth,
              height: 4,
              transformOrigin: "left center",
              background: sidebarWake.peekVariant === "row-card"
                ? "linear-gradient(90deg, rgba(114,186,175,0.12), rgba(114,186,175,0.72))"
                : sidebarWake.peekVariant === "dock-icon-chip"
                  ? "linear-gradient(90deg, rgba(122,146,212,0.12), rgba(122,146,212,0.68))"
                  : "linear-gradient(90deg, rgba(213,173,87,0.12), rgba(213,173,87,0.74))",
              boxShadow: sidebarWake.peekVariant === "row-card"
                ? "0 0 14px rgba(114,186,175,0.18)"
                : sidebarWake.peekVariant === "dock-icon-chip"
                  ? "0 0 14px rgba(122,146,212,0.16)"
                  : "0 0 16px rgba(213,173,87,0.22)",
            }}
          />
        )}
      </AnimatePresence>

      <AnimatePresence>
        {sidebarCollapsed && sidebarWake.shouldShowGhostPeek && (
          <SidebarGhostPeek
            key="sidebar-ghost-peek"
            label={sidebarWake.predictedActionLabel}
            reason={sidebarWake.predictedReason}
            anchorLens={sidebarWake.anchorLens}
            top={sidebarWake.anchorTop}
            left={sidebarViewportLeft + sidebarWake.peekLeft}
            width={sidebarWake.peekWidth}
            variant={sidebarWake.peekVariant}
            sourceKind={sidebarWake.sourceKind}
            sourceLabel={sidebarWake.sourceLabel}
            sourceObjectType={sidebarWake.sourceObjectType}
            onCommitOpen={() => requestSidebarOpen("edge")}
          />
        )}
      </AnimatePresence>

      <motion.div
        className="relative z-20 flex h-full min-h-0 flex-col"
        initial={false}
        animate={{
          opacity: sidebarCollapsed ? 0 : 1,
          x: sidebarCollapsed ? -14 : 0,
        }}
        transition={contentTransition}
        style={{
          pointerEvents: sidebarCollapsed ? "none" : "auto",
          willChange: "opacity, transform",
        }}
      >
        <DrawerHeader
          shell={anticipation.currentShell}
          lens={anticipation.currentLens}
          onCollapse={handleCollapse}
        />

        {activeHunt && (
          <SmartBucketHeader
            hunt={activeHunt}
            huntStore={huntStore}
            collapsed={bucketCollapsed}
            onToggleCollapse={() => dispatch({ type: "HUNT_BUCKET_TOGGLE_COLLAPSE" })}
            isDragOver={bucketDropTarget.isOver}
            draggedKind={anticipation.draggedObjectKind as ArtifactKind | null}
            dropRoles={anticipation.dropRoles}
            defaultDropRole={anticipation.defaultDropRole}
            selectedSemantic={selectedSemantic}
            dropTargetProps={bucketDropTarget.dropTargetProps}
            onSemanticDrop={setSelectedSemantic}
            onSemanticPreview={setSelectedSemantic}
          />
        )}

        <div
          className="min-h-0 flex-1 overflow-y-auto"
          style={{
            scrollbarWidth: "thin",
            scrollbarColor: "rgba(213,173,87,0.25) transparent",
          }}
        >
          {sidebarBlocks.map((block, index) => (
            <div key={block.id}>
              {block.id === "content" && index > 0 && (
                <div
                  className="mx-[10px] my-1"
                  style={{ borderTop: "1px solid rgba(213,173,87,0.08)" }}
                />
              )}
              {block.element}
            </div>
          ))}
        </div>

        <div
          className="absolute right-0 top-0 h-full w-1 cursor-col-resize hover:bg-[rgba(213,173,87,0.2)] active:bg-[rgba(213,173,87,0.3)]"
          role="separator"
          aria-label="Resize sidebar"
          onPointerDown={handleResizeStart}
        />
      </motion.div>
    </motion.aside>
  );
}

function DrawerHeader({
  shell,
  lens,
  onCollapse,
}: {
  shell: ShellMode;
  lens: LensId;
  onCollapse: () => void;
}) {
  return (
    <div
      className="flex h-[44px] shrink-0 items-center justify-between border-b px-[10px]"
      style={{ borderBottomColor: "rgba(213,173,87,0.12)" }}
    >
      <div className="flex items-baseline gap-1.5">
        <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-[rgba(213,173,87,0.75)]">
          {shell.toUpperCase()}
        </span>
        <span className="font-mono text-[11px] text-[rgba(182,183,193,0.3)]">/</span>
        <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-[rgba(232,230,222,0.8)]">
          {LENS_LABELS[lens]}
        </span>
      </div>
      <button
        type="button"
        className="origin-focus-ring flex h-6 w-6 items-center justify-center rounded text-[rgba(182,183,193,0.45)] transition-colors hover:text-[rgba(232,230,222,0.8)]"
        title="Collapse sidebar (Cmd+Shift+B)"
        aria-label="Collapse sidebar"
        onClick={onCollapse}
      >
        <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" aria-hidden="true">
          <path d="M10 3L5 8l5 5" />
        </svg>
      </button>
    </div>
  );
}

function SurfaceCard({
  promoted,
  children,
}: {
  promoted: boolean;
  children: React.ReactNode;
}) {
  return (
    <div
      className="mx-[8px] my-1 overflow-hidden rounded-[8px]"
      style={{
        border: promoted
          ? "1px solid rgba(213,173,87,0.16)"
          : "1px solid rgba(213,173,87,0.06)",
        background: promoted
          ? "rgba(213,173,87,0.04)"
          : "rgba(255,255,255,0.01)",
      }}
    >
      {children}
    </div>
  );
}

function IntentGravityPanel({
  anticipation,
  director,
  onSpringLoadLens,
}: {
  anticipation: ReturnType<typeof useAnticipationContext>;
  director: ReturnType<typeof useSidebarDirector>;
  onSpringLoadLens: (lens: LensId) => void;
}) {
  const [hoverLens, setHoverLens] = useState<LensId | null>(null);
  const lensTargets = useMemo(() => {
    const ordered = [
      anticipation.currentLens,
      anticipation.suggestedLens,
      ...SHELL_DEFAULT_LENS[anticipation.currentShell],
      ...(anticipation.draggedObjectKind
        ? (KIND_LENS_HINTS[anticipation.draggedObjectKind] ?? [])
        : []),
    ];

    const seen = new Set<LensId>();
    return ordered.filter((candidate): candidate is LensId => {
      if (!candidate || seen.has(candidate)) return false;
      seen.add(candidate);
      return true;
    }).slice(0, 4);
  }, [
    anticipation.currentLens,
    anticipation.suggestedLens,
    anticipation.currentShell,
    anticipation.draggedObjectKind,
  ]);

  useEffect(() => {
    if (!hoverLens || !anticipation.isAttachMode || anticipation.confidence !== "high") {
      return undefined;
    }
    const timer = window.setTimeout(() => {
      if (hoverLens !== anticipation.currentLens) {
        onSpringLoadLens(hoverLens);
      }
    }, TIMING.SPRING_LOAD_MS);
    return () => window.clearTimeout(timer);
  }, [
    hoverLens,
    anticipation.isAttachMode,
    anticipation.confidence,
    anticipation.currentLens,
    onSpringLoadLens,
  ]);

  const defaultLabel = anticipation.dropPrediction?.defaultLabel
    ?? anticipation.defaultDropRole?.label
    ?? "Anticipating next move";
  const reason = anticipation.dropPrediction?.reason
    ?? director.globalReason
    ?? (anticipation.defaultDropRole
      ? `ranked from ${anticipation.draggedObjectKind ?? "current"} context`
      : "context signals are still weak");

  return (
    <div
      className="mx-[10px] mt-2 rounded-[10px] border px-[10px] py-[8px]"
      style={{
        borderColor: anticipation.confidence === "high"
          ? "rgba(213,173,87,0.22)"
          : "rgba(213,173,87,0.1)",
        background: anticipation.isAttachMode
          ? "rgba(213,173,87,0.07)"
          : "rgba(255,255,255,0.015)",
      }}
    >
      <div className="flex items-center gap-1.5">
        <span
          className="inline-block h-[5px] w-[5px] rounded-full"
          style={{
            background: anticipation.confidence === "high"
              ? "rgba(213,173,87,0.75)"
              : "rgba(213,173,87,0.36)",
          }}
        />
        <span className="font-mono text-[9px] uppercase tracking-[0.12em] text-[rgba(213,173,87,0.8)]">
          {anticipation.phase}
        </span>
        <span className="font-mono text-[9px] uppercase tracking-[0.12em] text-[rgba(182,183,193,0.35)]">
          {anticipation.confidence}
        </span>
      </div>

      <div className="mt-1 flex items-center gap-2">
        <span className="text-[13px] text-[rgba(232,230,222,0.84)]">{defaultLabel}</span>
        {anticipation.modifierOverride && (
          <span
            className="rounded px-1.5 py-[1px] font-mono text-[9px] uppercase tracking-[0.08em]"
            style={{
              background: "rgba(213,173,87,0.12)",
              color: "rgba(213,173,87,0.9)",
            }}
          >
            {anticipation.modifierOverride}
          </span>
        )}
      </div>

      <div className="font-mono text-[10px] text-[rgba(182,183,193,0.45)]">
        {reason}
      </div>

      {anticipation.compatibleTargets.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {anticipation.compatibleTargets.slice(0, 4).map((target) => (
            <span
              key={target.id}
              className="rounded px-1.5 py-[2px] font-mono text-[9px] uppercase tracking-[0.08em]"
              style={{
                background: target.emphasis === "primary"
                  ? "rgba(213,173,87,0.12)"
                  : "rgba(213,173,87,0.04)",
                color: target.emphasis === "primary"
                  ? "rgba(213,173,87,0.88)"
                  : "rgba(182,183,193,0.5)",
              }}
            >
              {target.label}
            </span>
          ))}
        </div>
      )}

      {lensTargets.length > 1 && (
        <div className="mt-2 flex flex-wrap items-center gap-1">
          <span className="font-mono text-[9px] uppercase tracking-[0.12em] text-[rgba(182,183,193,0.35)]">
            Focus
          </span>
          {lensTargets.map((candidate) => (
            <button
              key={candidate}
              type="button"
              className="rounded px-1.5 py-[2px] font-mono text-[9px] uppercase tracking-[0.08em]"
              style={{
                border: candidate === anticipation.currentLens
                  ? "1px solid rgba(213,173,87,0.22)"
                  : "1px solid rgba(213,173,87,0.08)",
                background: candidate === anticipation.currentLens
                  ? "rgba(213,173,87,0.1)"
                  : "rgba(213,173,87,0.03)",
                color: candidate === anticipation.currentLens
                  ? "rgba(213,173,87,0.88)"
                  : "rgba(232,230,222,0.56)",
              }}
              onPointerEnter={() => setHoverLens(candidate)}
              onPointerLeave={() => setHoverLens((current) => (current === candidate ? null : current))}
              onClick={() => onSpringLoadLens(candidate)}
            >
              {LENS_LABELS[candidate]}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

const LENS_LABELS: Record<LensId, string> = {
  scopes: "SCOPES",
  history: "HISTORY",
  files: "FILES",
  sandboxes: "SANDBOXES",
  entities: "ENTITIES",
  swarms: "SWARMS",
  notes: "NOTES",
};

function LensContent({
  lens,
  shell,
  activeHunt,
  huntStore,
  onOpenPath,
  entitiesDirective,
  notesDirective,
  filesDirective,
  scopesDirective,
  historyDirective,
  sandboxesDirective,
  swarmsDirective,
}: {
  lens: LensId;
  shell: ShellMode;
  activeHunt: Hunt | null;
  huntStore: HuntStore;
  onOpenPath?: (
    relativePath: string,
    options?: { openMode?: OpenTabMode; reason?: string | null },
  ) => void;
  entitiesDirective?: ReturnType<typeof useSidebarDirector>["lensSections"]["entities"];
  notesDirective?: ReturnType<typeof useSidebarDirector>["lensSections"]["notes"];
  filesDirective?: ReturnType<typeof useSidebarDirector>["lensSections"]["files"];
  scopesDirective?: ReturnType<typeof useSidebarDirector>["lensSections"]["scopes"];
  historyDirective?: ReturnType<typeof useSidebarDirector>["lensSections"]["history"];
  sandboxesDirective?: ReturnType<typeof useSidebarDirector>["lensSections"]["sandboxes"];
  swarmsDirective?: ReturnType<typeof useSidebarDirector>["lensSections"]["swarms"];
}) {
  const lensProps = { activeHunt, huntStore };

  switch (lens) {
    case "files":
      return <FilesLens {...lensProps} onOpenPath={onOpenPath} directive={filesDirective} />;
    case "notes":
      return <NotesLens {...lensProps} shell={shell} directive={notesDirective} />;
    case "scopes":
      return <ScopesLens {...lensProps} directive={scopesDirective} />;
    case "history":
      return <HistoryLens {...lensProps} directive={historyDirective} />;
    case "sandboxes":
      return <SandboxesLens {...lensProps} directive={sandboxesDirective} />;
    case "entities":
      return <EntitiesLens {...lensProps} directive={entitiesDirective} />;
    case "swarms":
      return <SwarmsLens {...lensProps} directive={swarmsDirective} />;
    default:
      return null;
  }
}

export default LensSidebar;
