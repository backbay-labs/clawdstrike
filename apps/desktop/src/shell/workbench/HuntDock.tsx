/**
 * HuntDock — 40px vertical dock strip for hunt management.
 *
 * Anatomy (top -> bottom):
 *   New Hunt button (+)
 *   Pinned hunt pills (gold border)
 *   Divider (gold gradient)
 *   Recent hunt pills (MRU ordered)
 *
 * Enrichments (v2):
 *   - 100ms hover delay before flyout
 *   - 3-line flyout: title, artifact breakdown, run/status
 *   - Drop-target glow when dragging artifacts over
 *   - Post-drop flash animation
 *
 * Active indicator: 2px left bar matching ActivitySpine pattern.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useWorkbenchDispatch } from "./WorkbenchStateProvider";
import { useHuntStore, useActiveHunt, useHuntDock } from "./WorkbenchStateProvider";
import type { Hunt } from "./huntTypes";
import { groupArtifactsByKind, formatArtifactBreakdown } from "./huntTypes";
import { useDropTarget, useDragState } from "./DragDropContext";
import { useHoverAnticipation, ProximalAffordance, DRAG_ROLE_MAP, useSidebarWakeAnchor } from "./anticipation";
import type { DropRole } from "./anticipation";
import {
  SpiritActionButton,
  SpiritGlyph,
  getSpiritActionLabel,
  getSpiritBiasLine,
  getSpiritDetailLine,
  getSpiritSecondaryActionLabel,
} from "./spirit/components";

const PILL_SIZE = 32;
const HOVER_DELAY_MS = 100;

const HUNT_ICON_PATHS: Record<string, string> = {
  crosshair: "M7 2v2M7 10v2M2 7h2M10 7h2M7 4.5a2.5 2.5 0 100 5 2.5 2.5 0 000-5z",
  shield: "M7 2L2.5 4v3.5c0 2.5 1.8 4.8 4.5 5.5 2.7-.7 4.5-3 4.5-5.5V4L7 2z",
  search: "M6 3a3 3 0 100 6 3 3 0 000-6zM9 9l3 3",
  alert: "M7 3L2 11h10L7 3zM7 7v2M7 10v.5",
  radar: "M7 7m-1 0a1 1 0 102 0 1 1 0 10-2 0M4 10a4.5 4.5 0 016.5-6M2.5 11.5a7 7 0 0110-9.5",
  bug: "M5 5a2 2 0 014 0v2a2 2 0 01-4 0V5zM3 6H1M13 6h-2M3 9H1M13 9h-2M5 10v1a2 2 0 004 0v-1",
  lock: "M4 7V5a3 3 0 016 0v2M3 7h8v5H3V7z",
  target: "M7 3a4 4 0 100 8 4 4 0 000-8zM7 5.5a1.5 1.5 0 100 3 1.5 1.5 0 000-3z",
};

function HuntPillIcon({ icon, color }: { icon: string; color: string }) {
  const path = HUNT_ICON_PATHS[icon];
  if (!path) {
    return (
      <span
        className="flex h-full w-full items-center justify-center font-mono text-[11px] font-bold"
        style={{ color }}
      >
        {icon.charAt(0).toUpperCase()}
      </span>
    );
  }
  return (
    <svg viewBox="0 0 14 14" width="16" height="16" fill="none" stroke={color} strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round">
      <path d={path} />
    </svg>
  );
}

const SPRING_EXPAND_MS = 300;
const SPRING_RETRACT_MS = 200;

const SEMANTIC_LABELS: Record<string, string> = {
  target: "Target",
  evidence: "Evidence",
  "run-input": "Run Input",
  notes: "Notes",
  watch: "Watch",
  mount: "Mount",
  cite: "Cite",
  compare: "Compare",
};

function HuntPill({
  hunt,
  huntStore,
  isActive,
  isPinned,
  onSelect,
  onContextMenu,
}: {
  hunt: Hunt;
  huntStore: { artifacts: Record<string, import("./huntTypes").Artifact>; runs: Record<string, import("./huntTypes").Run> };
  isActive: boolean;
  isPinned: boolean;
  onSelect: () => void;
  onContextMenu: (e: React.MouseEvent) => void;
}) {
  const [hovered, setHovered] = useState(false);
  const [dropFlash, setDropFlash] = useState(false);
  const [springExpanded, setSpringExpanded] = useState(false);
  const hoverTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const springTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pillRef = useRef<HTMLButtonElement>(null);

  // Drag state — for spring-loaded expansion
  const dragState = useDragState();
  const isDragging = dragState.active;
  const draggedKind = dragState.payload?.artifact.kind ?? null;
  const { setAnchorFromElement, clearAnchor } = useSidebarWakeAnchor();
  const wakeAnchorId = `hunt-pill:${hunt.id}`;

  // Hover anticipation — for proximal affordances
  const { hoverIntent, onHoverStart, onHoverEnd, isActivated } = useHoverAnticipation();

  // Drop target
  const { dropTargetProps, isOver, canDrop } = useDropTarget(hunt.id);
  const isDropHighlight = isOver && canDrop;

  // Post-drop flash: detect when isOver transitions from true→false (drop happened)
  const wasOverRef = useRef(false);
  useEffect(() => {
    if (wasOverRef.current && !isOver) {
      setDropFlash(true);
      const timer = setTimeout(() => setDropFlash(false), 400);
      return () => clearTimeout(timer);
    }
    wasOverRef.current = isOver;
  }, [isOver]);

  // Spring-loaded expansion: when dragging over this pill for 300ms, expand subtargets
  useEffect(() => {
    if (isOver && isDragging) {
      springTimerRef.current = setTimeout(() => setSpringExpanded(true), SPRING_EXPAND_MS);
    } else if (!isOver && springExpanded) {
      // Retract after leaving
      const t = setTimeout(() => setSpringExpanded(false), SPRING_RETRACT_MS);
      return () => clearTimeout(t);
    }
    return () => {
      if (springTimerRef.current) {
        clearTimeout(springTimerRef.current);
        springTimerRef.current = null;
      }
    };
  }, [isOver, isDragging, springExpanded]);

  // 100ms hover delay + anticipation activation
  const handleMouseEnter = useCallback(() => {
    if (hoverTimerRef.current) clearTimeout(hoverTimerRef.current);
    hoverTimerRef.current = setTimeout(() => setHovered(true), HOVER_DELAY_MS);
    if (pillRef.current) {
      setAnchorFromElement({
        id: wakeAnchorId,
        kind: "hunt-pill",
        element: pillRef.current,
        label: hunt.title,
        objectType: "hunt",
        source: isDragging ? "drag" : "hover",
      });
    }
    onHoverStart(hunt.id, "hunt-pill");
  }, [hunt.id, hunt.title, isDragging, onHoverStart, setAnchorFromElement, wakeAnchorId]);

  const handleMouseLeave = useCallback(() => {
    if (hoverTimerRef.current) {
      clearTimeout(hoverTimerRef.current);
      hoverTimerRef.current = null;
    }
    setHovered(false);
    clearAnchor(wakeAnchorId);
    onHoverEnd();
  }, [clearAnchor, onHoverEnd, wakeAnchorId]);

  const handleDropTargetPointerEnter = useCallback(() => {
    dropTargetProps.onPointerEnter?.();
    if (pillRef.current) {
      setAnchorFromElement({
        id: wakeAnchorId,
        kind: "hunt-pill",
        element: pillRef.current,
        label: hunt.title,
        objectType: draggedKind ?? "hunt",
        source: isDragging ? "drag" : "hover",
      });
    }
  }, [
    draggedKind,
    dropTargetProps,
    hunt.title,
    isDragging,
    setAnchorFromElement,
    wakeAnchorId,
  ]);

  const handleDropTargetPointerLeave = useCallback(() => {
    dropTargetProps.onPointerLeave?.();
    clearAnchor(wakeAnchorId);
  }, [clearAnchor, dropTargetProps, wakeAnchorId]);

  // Richer flyout content
  const counts = groupArtifactsByKind(hunt.artifactIds, huntStore.artifacts);
  const breakdown = formatArtifactBreakdown(counts);
  const activeRun = hunt.runIds
    .map((id) => huntStore.runs[id])
    .find((r) => r?.status === "running") ?? null;
  const spiritBias = getSpiritBiasLine(hunt);
  const spiritDetail = getSpiritDetailLine(hunt);
  const spiritPrimaryAction = getSpiritActionLabel(hunt);
  const spiritSecondaryAction = getSpiritSecondaryActionLabel(hunt);

  // Semantic drop roles for spring-loaded state
  const dropRoles: DropRole[] = (springExpanded && draggedKind)
    ? (DRAG_ROLE_MAP[draggedKind] ?? []).map((semantic, i) => ({
        id: `${hunt.id}-${semantic}`,
        label: SEMANTIC_LABELS[semantic] ?? semantic,
        semantic,
        isDefault: i === 0,
        confidence: 100 - i * 15,
      }))
    : [];

  const isCompatibleTarget = isDragging && dragState.payload?.sourceHuntId !== hunt.id;

  const pillClass = [
    "hunt-dock__pill",
    isActive ? "hunt-dock__pill--active" : "",
    isPinned ? "hunt-dock__pill--pinned" : "",
    isDropHighlight ? "hunt-dock__pill--drop-target" : "",
    dropFlash ? "hunt-dock__pill--drop-flash" : "",
    isCompatibleTarget ? "hunt-dock__pill--compatible" : "",
  ]
    .filter(Boolean)
    .join(" ");

  // Compute pill position for proximal affordance
  const [pillRect, setPillRect] = useState<{ x: number; y: number } | null>(null);
  useEffect(() => {
    if (isActivated && !isDragging && pillRef.current) {
      const rect = pillRef.current.getBoundingClientRect();
      setPillRect({ x: rect.right + 8, y: rect.top + rect.height / 2 });
    } else {
      setPillRect(null);
    }
  }, [isActivated, isDragging]);

  const shouldShowSummaryFlyout =
    pillRef.current
    && (
      springExpanded
      || (hovered && !isDragging && !isActivated)
    );

  return (
    <div className="hunt-dock__pill-wrapper" style={{ position: "relative" }}>
      {/* Active indicator — 2px left bar */}
      {isActive && (
        <div
          className="hunt-dock__active-bar"
          style={{
            position: "absolute",
            left: 0,
            top: 4,
            bottom: 4,
            width: 2,
            borderRadius: 1,
            background: hunt.color,
          }}
        />
      )}

      <button
        ref={pillRef}
        type="button"
        className={pillClass}
        style={{
          width: PILL_SIZE,
          height: PILL_SIZE,
          borderRadius: 8,
          border: isPinned
            ? `1.5px solid rgba(213,173,87,0.5)`
            : isDropHighlight
              ? "1.5px solid rgba(213,173,87,0.4)"
              : isCompatibleTarget
                ? "1.5px solid rgba(213,173,87,0.2)"
                : "1.5px solid transparent",
          background: isActive
            ? `${hunt.color}18`
            : isDropHighlight
              ? "rgba(213,173,87,0.08)"
              : hovered
                ? "rgba(232,230,222,0.06)"
                : "rgba(232,230,222,0.03)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          cursor: "pointer",
          transition: "background 150ms ease, border-color 150ms ease, box-shadow 150ms ease",
          position: "relative",
          boxShadow: isDropHighlight
            ? "0 0 8px rgba(213,173,87,0.15)"
            : isCompatibleTarget
              ? "0 0 6px rgba(213,173,87,0.08)"
              : undefined,
        }}
        onClick={onSelect}
        onContextMenu={onContextMenu}
        onMouseEnter={handleMouseEnter}
        onMouseMove={() => {
          if (pillRef.current) {
            setAnchorFromElement({
              id: wakeAnchorId,
              kind: "hunt-pill",
              element: pillRef.current,
              label: hunt.title,
              objectType: draggedKind ?? "hunt",
              source: isDragging ? "drag" : "hover",
            });
          }
        }}
        onMouseLeave={handleMouseLeave}
        onPointerEnter={handleDropTargetPointerEnter}
        onPointerLeave={handleDropTargetPointerLeave}
      >
        {hunt.spirit ? (
          <SpiritGlyph hunt={hunt} size={18} glow={isActive || hovered || isDropHighlight} />
        ) : (
          <HuntPillIcon icon={hunt.icon} color={hunt.color} />
        )}
      </button>

      {/* Hover flyout — rendered as portal to escape overflow clipping */}
      {shouldShowSummaryFlyout && pillRef.current && createPortal(
        <div
          className="hunt-dock__flyout"
          style={{
            position: "fixed",
            left: pillRef.current.getBoundingClientRect().right + 8,
            top: pillRef.current.getBoundingClientRect().top + pillRef.current.getBoundingClientRect().height / 2,
            transform: "translateY(-50%)",
            whiteSpace: "nowrap",
            zIndex: 9999,
            background: "rgba(10,12,18,0.95)",
            border: `1px solid ${springExpanded ? "rgba(213,173,87,0.3)" : "rgba(213,173,87,0.15)"}`,
            borderRadius: 6,
            padding: "6px 10px",
            pointerEvents: springExpanded ? "auto" : "none",
            transition: "border-color 150ms ease",
          }}
        >
          <div className="flex items-center gap-2">
            <SpiritGlyph hunt={hunt} size={18} glow={Boolean(hunt.spirit)} />
            <div className="font-mono text-[11px] text-[rgba(232,230,222,0.85)]">{hunt.title}</div>
          </div>
          <div className="mt-1 font-mono text-[10px] text-[rgba(213,173,87,0.72)]">
            {hunt.spirit ? spiritBias : spiritDetail}
          </div>
          <div className="font-mono text-[10px] text-[rgba(182,183,193,0.5)]">
            {breakdown || `${hunt.artifactIds.length} artifacts`}
          </div>
          <div className="flex items-center gap-1.5 font-mono text-[10px]">
            {activeRun ? (
              <>
                <span
                  className="inline-block h-[5px] w-[5px] rounded-full"
                  style={{
                    background: "#3dbf84",
                    boxShadow: "0 0 4px rgba(61,191,132,0.5)",
                  }}
                />
                <span className="text-[rgba(61,191,132,0.7)]">{activeRun.label}</span>
              </>
            ) : (
              <span className="text-[rgba(182,183,193,0.35)]">{hunt.status}</span>
            )}
          </div>
          {!springExpanded && (
            <div
              className="mt-1.5 flex items-center gap-2 pt-1.5"
              style={{ borderTop: "1px solid rgba(213,173,87,0.1)" }}
            >
              <SpiritActionButton label={spiritPrimaryAction} disabled />
              <SpiritActionButton label={spiritSecondaryAction} disabled />
            </div>
          )}

          {/* Spring-loaded semantic drop slots — appear after 300ms drag hover */}
          {springExpanded && dropRoles.length > 0 && (
            <div
              className="flex gap-1 pt-1.5 mt-1.5"
              style={{ borderTop: "1px solid rgba(213,173,87,0.1)" }}
            >
              {dropRoles.map((role) => (
                <button
                  key={role.id}
                  type="button"
                  className="rounded-md font-mono text-[10px] transition-colors hover:bg-[rgba(213,173,87,0.15)]"
                  style={{
                    padding: "2px 6px",
                    background: role.isDefault ? "rgba(213,173,87,0.12)" : "rgba(213,173,87,0.04)",
                    border: `1px solid ${role.isDefault ? "rgba(213,173,87,0.3)" : "rgba(213,173,87,0.1)"}`,
                    color: role.isDefault ? "rgba(213,173,87,0.9)" : "rgba(232,230,222,0.5)",
                    cursor: "pointer",
                  }}
                >
                  {role.label}
                </button>
              ))}
            </div>
          )}
        </div>,
        document.body,
      )}

      {/* Proximal affordance — tiny action strip on hover (non-drag) */}
      {isActivated && !isDragging && hoverIntent && pillRect && (
        <ProximalAffordance
          actions={hoverIntent.subtargets}
          position={pillRect}
          visible={true}
          onAction={(actionId) => {
            if (actionId === "open") onSelect();
            onHoverEnd();
          }}
          onMouseLeave={onHoverEnd}
        />
      )}
    </div>
  );
}

export function HuntDock() {
  const dispatch = useWorkbenchDispatch();
  const huntStore = useHuntStore();
  const activeHunt = useActiveHunt();
  const dock = useHuntDock();
  const dragState = useDragState();
  const isDragging = dragState.active;
  const [contextMenu, setContextMenu] = useState<{ huntId: string; x: number; y: number } | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const dockRef = useRef<HTMLDivElement>(null);

  const pinnedHunts = dock.pinnedHuntIds
    .map((id) => huntStore.hunts[id])
    .filter(Boolean);

  const recentHunts = dock.recentHuntIds
    .filter((id) => !dock.pinnedHuntIds.includes(id))
    .map((id) => huntStore.hunts[id])
    .filter(Boolean);

  const handleNewHunt = useCallback(() => {
    dispatch({
      type: "HUNT_CREATE",
      payload: { title: `Hunt ${Object.keys(huntStore.hunts).length + 1}` },
    });
  }, [dispatch, huntStore.hunts]);

  const handleSelect = useCallback(
    (huntId: string) => {
      dispatch({ type: "HUNT_SET_ACTIVE", payload: { id: huntId } });
    },
    [dispatch],
  );

  const handleContextMenu = useCallback((huntId: string, e: React.MouseEvent) => {
    e.preventDefault();
    setContextMenu({ huntId, x: e.clientX, y: e.clientY });
  }, []);

  const closeContextMenu = useCallback(() => setContextMenu(null), []);

  const handleContextAction = useCallback(
    (action: string) => {
      if (!contextMenu) return;
      const { huntId } = contextMenu;
      switch (action) {
        case "pin":
          dispatch({ type: "HUNT_DOCK_PIN", payload: { huntId } });
          break;
        case "unpin":
          dispatch({ type: "HUNT_DOCK_UNPIN", payload: { huntId } });
          break;
        case "close":
          if (dock.activeHuntId === huntId) {
            dispatch({ type: "HUNT_SET_ACTIVE", payload: { id: null } });
          }
          break;
        case "promote": {
          const hunt = huntStore.hunts[huntId];
          if (hunt) {
            dispatch({ type: "HUNT_PROMOTE_TO_CASE", payload: { huntId, caseTitle: hunt.title } });
          }
          break;
        }
        case "delete":
          dispatch({ type: "HUNT_DELETE", payload: { id: huntId } });
          break;
      }
      closeContextMenu();
    },
    [contextMenu, dispatch, dock.activeHuntId, huntStore.hunts, closeContextMenu],
  );

  if (dock.collapsed) return null;

  const isPinned = (id: string) => dock.pinnedHuntIds.includes(id);
  const hasPinned = pinnedHunts.length > 0;
  const hasRecent = recentHunts.length > 0;

  const pillStoreSlice = { artifacts: huntStore.artifacts, runs: huntStore.runs };

  return (
    <div
      ref={dockRef}
      className="hunt-dock"
      style={{
        width: 40,
        height: "100%",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        gap: 4,
        paddingTop: 8,
        paddingBottom: 8,
        background: isDragging
          ? "rgba(213,173,87,0.03)"
          : "rgba(6,8,13,0.4)",
        borderRight: isDragging
          ? "1px solid rgba(213,173,87,0.2)"
          : "1px solid rgba(213,173,87,0.08)",
        overflowY: "auto",
        overflowX: "hidden",
        scrollbarWidth: "none",
      }}
    >
      {/* New Hunt button */}
      <button
        type="button"
        className="hunt-dock__new-btn"
        style={{
          width: PILL_SIZE,
          height: PILL_SIZE,
          borderRadius: 8,
          border: "1.5px dashed rgba(213,173,87,0.3)",
          background: "transparent",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          cursor: "pointer",
          color: "rgba(213,173,87,0.5)",
          transition: "border-color 150ms ease, color 150ms ease",
          flexShrink: 0,
        }}
        title="New hunt (Cmd+Shift+H)"
        onClick={handleNewHunt}
      >
        <svg viewBox="0 0 14 14" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
          <path d="M7 3v8M3 7h8" />
        </svg>
      </button>

      {isDragging && dockRef.current && createPortal(
        <div
          style={{
            position: "fixed",
            left: dockRef.current.getBoundingClientRect().right + 10,
            top: dockRef.current.getBoundingClientRect().top + 18,
            zIndex: 9997,
            pointerEvents: "none",
            maxWidth: 180,
            borderRadius: 8,
            border: "1px solid rgba(213,173,87,0.16)",
            background: "rgba(10,12,18,0.94)",
            boxShadow: "0 6px 18px rgba(0,0,0,0.28)",
            padding: "8px 10px",
          }}
        >
          <div
            className="font-mono text-[10px] uppercase tracking-[0.12em]"
            style={{ color: "rgba(213,173,87,0.8)" }}
          >
            Drop On A Hunt
          </div>
          <div
            className="mt-1 font-mono text-[10px]"
            style={{ color: "rgba(232,230,222,0.7)", lineHeight: 1.35 }}
          >
            Hunt pills are live drop targets. Hold on a pill to reveal Target, Evidence, Run Input,
            and other roles.
          </div>
        </div>,
        document.body,
      )}

      {/* Pinned hunts */}
      {pinnedHunts.map((hunt) => (
        <HuntPill
          key={hunt.id}
          hunt={hunt}
          huntStore={pillStoreSlice}
          isActive={dock.activeHuntId === hunt.id}
          isPinned={true}
          onSelect={() => handleSelect(hunt.id)}
          onContextMenu={(e) => handleContextMenu(hunt.id, e)}
        />
      ))}

      {/* Divider */}
      {hasPinned && hasRecent && (
        <div
          style={{
            width: 20,
            height: 1,
            background: "linear-gradient(90deg, transparent, rgba(213,173,87,0.25), transparent)",
            flexShrink: 0,
          }}
        />
      )}

      {/* Recent hunts */}
      {recentHunts.map((hunt) => (
        <HuntPill
          key={hunt.id}
          hunt={hunt}
          huntStore={pillStoreSlice}
          isActive={dock.activeHuntId === hunt.id}
          isPinned={false}
          onSelect={() => handleSelect(hunt.id)}
          onContextMenu={(e) => handleContextMenu(hunt.id, e)}
        />
      ))}

      {/* Context menu */}
      {contextMenu && (
        <>
          {/* Backdrop */}
          <div
            style={{ position: "fixed", inset: 0, zIndex: 100 }}
            onClick={closeContextMenu}
            onContextMenu={(e) => {
              e.preventDefault();
              closeContextMenu();
            }}
          />
          <div
            ref={menuRef}
            className="hunt-dock__context-menu"
            style={{
              position: "fixed",
              left: contextMenu.x,
              top: contextMenu.y,
              zIndex: 101,
              background: "rgba(10,12,18,0.97)",
              border: "1px solid rgba(213,173,87,0.15)",
              borderRadius: 6,
              padding: "4px 0",
              minWidth: 160,
            }}
          >
            {isPinned(contextMenu.huntId) ? (
              <ContextMenuItem label="Unpin" onClick={() => handleContextAction("unpin")} />
            ) : (
              <ContextMenuItem label="Pin" onClick={() => handleContextAction("pin")} />
            )}
            <ContextMenuItem label="Close" onClick={() => handleContextAction("close")} />
            <ContextMenuItem label="Promote to Case" onClick={() => handleContextAction("promote")} />
            <div style={{ height: 1, margin: "4px 8px", background: "rgba(182,183,193,0.1)" }} />
            <ContextMenuItem label="Delete" onClick={() => handleContextAction("delete")} danger />
          </div>
        </>
      )}
    </div>
  );
}

function ContextMenuItem({
  label,
  onClick,
  danger,
}: {
  label: string;
  onClick: () => void;
  danger?: boolean;
}) {
  return (
    <button
      type="button"
      className="flex h-[28px] w-full items-center px-3 text-left font-mono text-[11px] transition-colors hover:bg-[rgba(213,173,87,0.06)]"
      style={{ color: danger ? "rgba(196,92,92,0.8)" : "rgba(232,230,222,0.7)" }}
      onClick={onClick}
    >
      {label}
    </button>
  );
}
