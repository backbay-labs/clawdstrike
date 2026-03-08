/**
 * TabBar - Horizontal tab strip for a workbench pane.
 *
 * Features: preview (italic), pin, dirty indicator, drag-to-reorder,
 * middle-click close, right-click context menu, overflow scroll + chevron dropdown.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { clsx } from "clsx";
import { useTabGroup, useWorkbenchDispatch } from "./WorkbenchStateProvider";
import { getTabRegistryEntry } from "./tabRegistry";
import type { TabState } from "./workbenchState";

interface TabBarProps {
  groupId: string;
}

interface ContextMenuState {
  tabId: string;
  x: number;
  y: number;
}

export function TabBar({ groupId }: TabBarProps) {
  const group = useTabGroup(groupId);
  const dispatch = useWorkbenchDispatch();
  const scrollRef = useRef<HTMLDivElement>(null);
  const [overflowLeft, setOverflowLeft] = useState(false);
  const [overflowRight, setOverflowRight] = useState(false);
  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null);
  const [showDropdown, setShowDropdown] = useState(false);
  const [dragTabId, setDragTabId] = useState<string | null>(null);
  const [dragOverIndex, setDragOverIndex] = useState<number | null>(null);
  const dragStartX = useRef(0);
  const dragStartIndex = useRef(0);

  const tabs = group?.tabs ?? [];
  const activeTabId = group?.activeTabId ?? null;

  // -- Overflow detection --
  const checkOverflow = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    setOverflowLeft(el.scrollLeft > 0);
    setOverflowRight(el.scrollLeft + el.clientWidth < el.scrollWidth - 1);
  }, []);

  useEffect(() => {
    checkOverflow();
    const el = scrollRef.current;
    if (!el) return;
    el.addEventListener("scroll", checkOverflow, { passive: true });
    const observer = new ResizeObserver(checkOverflow);
    observer.observe(el);
    return () => {
      el.removeEventListener("scroll", checkOverflow);
      observer.disconnect();
    };
  }, [checkOverflow, tabs.length]);

  // -- Close context menu on outside click --
  useEffect(() => {
    if (!contextMenu) return;
    const close = () => setContextMenu(null);
    window.addEventListener("pointerdown", close);
    return () => window.removeEventListener("pointerdown", close);
  }, [contextMenu]);

  // -- Close dropdown on outside click --
  useEffect(() => {
    if (!showDropdown) return;
    const close = () => setShowDropdown(false);
    window.addEventListener("pointerdown", close);
    return () => window.removeEventListener("pointerdown", close);
  }, [showDropdown]);

  // -- Actions --
  const activateTab = useCallback(
    (tabId: string) => {
      dispatch({ type: "SET_ACTIVE_TAB", payload: { groupId, tabId } });
    },
    [dispatch, groupId],
  );

  const closeTab = useCallback(
    (tab: TabState) => {
      if (tab.isDirty) {
        const proceed = globalThis.confirm?.(`"${tab.title}" has unsaved changes. Close anyway?`);
        if (!proceed) return;
      }
      dispatch({ type: "CLOSE_TAB", payload: { groupId, tabId: tab.id } });
    },
    [dispatch, groupId],
  );

  const pinTab = useCallback(
    (tabId: string) => {
      dispatch({ type: "PIN_TAB", payload: { groupId, tabId } });
    },
    [dispatch, groupId],
  );

  const unpinTab = useCallback(
    (tabId: string) => {
      dispatch({ type: "UNPIN_TAB", payload: { groupId, tabId } });
    },
    [dispatch, groupId],
  );

  // -- Drag-to-reorder (pointer events) --
  const handlePointerDown = useCallback(
    (e: React.PointerEvent, tabId: string, index: number) => {
      if (e.button !== 0) return;
      dragStartX.current = e.clientX;
      dragStartIndex.current = index;
      setDragTabId(tabId);

      const handleMove = (me: PointerEvent) => {
        const dx = me.clientX - dragStartX.current;
        const step = 120; // approx tab width
        const offset = Math.round(dx / step);
        const newIndex = Math.max(0, Math.min(tabs.length - 1, dragStartIndex.current + offset));
        setDragOverIndex(newIndex);
      };

      const handleUp = () => {
        window.removeEventListener("pointermove", handleMove);
        window.removeEventListener("pointerup", handleUp);
        setDragTabId(null);
        setDragOverIndex((finalIndex) => {
          if (finalIndex !== null && finalIndex !== dragStartIndex.current) {
            dispatch({
              type: "REORDER_TAB",
              payload: { groupId, tabId, toIndex: finalIndex },
            });
          }
          return null;
        });
      };

      window.addEventListener("pointermove", handleMove);
      window.addEventListener("pointerup", handleUp);
    },
    [dispatch, groupId, tabs.length],
  );

  // -- Context menu actions --
  const handleCloseOthers = useCallback(
    (keepTabId: string) => {
      const toClose = tabs.filter((t) => t.id !== keepTabId);
      const dirtyCount = toClose.filter((t) => t.isDirty).length;
      if (dirtyCount > 0) {
        const proceed = globalThis.confirm?.(
          `${dirtyCount} tab(s) have unsaved changes. Close them anyway?`,
        );
        if (!proceed) return;
      }
      for (const t of toClose) {
        dispatch({ type: "CLOSE_TAB", payload: { groupId, tabId: t.id } });
      }
    },
    [dispatch, groupId, tabs],
  );

  const handleCloseAll = useCallback(() => {
    const dirtyCount = tabs.filter((t) => t.isDirty).length;
    if (dirtyCount > 0) {
      const proceed = globalThis.confirm?.(
        `${dirtyCount} tab(s) have unsaved changes. Close them anyway?`,
      );
      if (!proceed) return;
    }
    for (const t of tabs) {
      dispatch({ type: "CLOSE_TAB", payload: { groupId, tabId: t.id } });
    }
  }, [dispatch, groupId, tabs]);

  const handleMoveToSplit = useCallback(
    (tabId: string) => {
      const newGroupId = `split-${Date.now()}`;
      dispatch({ type: "CREATE_TAB_GROUP", payload: { groupId: newGroupId } });
      dispatch({
        type: "MOVE_TAB_TO_GROUP",
        payload: { fromGroupId: groupId, toGroupId: newGroupId, tabId },
      });
    },
    [dispatch, groupId],
  );

  // -- Scroll buttons --
  const scrollLeft = useCallback(() => {
    scrollRef.current?.scrollBy({ left: -200, behavior: "smooth" });
  }, []);

  const scrollRight = useCallback(() => {
    scrollRef.current?.scrollBy({ left: 200, behavior: "smooth" });
  }, []);

  if (tabs.length === 0) return null;

  return (
    <div className="relative flex h-8 shrink-0 items-stretch border-b" style={{ borderColor: "var(--color-sdr-border-subtle, #212634)", background: "var(--color-sdr-bg-secondary, #0b0d13)" }}>
      {/* Left scroll indicator */}
      {overflowLeft && (
        <button
          type="button"
          className="absolute left-0 z-10 flex h-full w-6 items-center justify-center bg-gradient-to-r from-[var(--color-sdr-bg-secondary,#0b0d13)] to-transparent"
          onClick={scrollLeft}
          aria-label="Scroll tabs left"
        >
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M8 2L4 6l4 4" /></svg>
        </button>
      )}

      {/* Tab strip */}
      <div
        ref={scrollRef}
        role="tablist"
        aria-label={`${groupId} tabs`}
        className="flex flex-1 items-stretch overflow-x-auto scrollbar-none"
      >
        {tabs.map((tab, index) => {
          const isActive = tab.id === activeTabId;
          const isDragging = tab.id === dragTabId;
          const isDragTarget = dragOverIndex === index && dragTabId !== null && dragTabId !== tab.id;
          const entry = getTabRegistryEntry(tab.kind);

          return (
            <div
              key={tab.id}
              role="tab"
              aria-selected={isActive}
              tabIndex={isActive ? 0 : -1}
              className={clsx(
                "origin-focus-ring group relative flex h-full max-w-[180px] min-w-[80px] cursor-pointer select-none items-center gap-1.5 px-3 transition-colors",
                isActive
                  ? "border-b-2 text-sdr-text-primary"
                  : "border-b-2 border-transparent text-sdr-text-muted hover:text-sdr-text-secondary",
                isDragging && "opacity-50",
                isDragTarget && "border-l-2 border-l-[var(--origin-gold,#d5ad57)]",
              )}
              style={isActive ? { borderBottomColor: "rgba(213,173,87,0.8)" } : undefined}
              onClick={() => activateTab(tab.id)}
              onDoubleClick={() => {
                if (tab.isPreview) {
                  dispatch({ type: "SET_TAB_PREVIEW", payload: { groupId, tabId: tab.id } });
                }
              }}
              onAuxClick={(e) => {
                if (e.button === 1) closeTab(tab);
              }}
              onContextMenu={(e) => {
                e.preventDefault();
                e.stopPropagation();
                setContextMenu({ tabId: tab.id, x: e.clientX, y: e.clientY });
              }}
              onPointerDown={(e) => handlePointerDown(e, tab.id, index)}
            >
              {/* Icon */}
              {entry && (
                <span className="shrink-0 text-[10px] opacity-60">{tab.icon ?? entry.icon.charAt(0).toUpperCase()}</span>
              )}

              {/* Title */}
              <span
                className={clsx(
                  "truncate text-[11px] tracking-[0.06em]",
                  tab.isPreview && "italic",
                )}
                style={{ fontFamily: "var(--font-mono)" }}
              >
                {tab.title}
              </span>

              {/* Dirty indicator */}
              {tab.isDirty && (
                <span
                  className="ml-0.5 h-1.5 w-1.5 shrink-0 rounded-full"
                  style={{ background: "rgba(238,220,166,0.96)" }}
                  aria-label="Unsaved changes"
                />
              )}

              {/* Pin icon (for pinned tabs) */}
              {tab.isPinned && !tab.isDirty && (
                <svg className="ml-0.5 h-2.5 w-2.5 shrink-0 opacity-40" viewBox="0 0 12 12" fill="currentColor" aria-hidden="true">
                  <path d="M8 1L4 5l-2-1-1 1 3 3-1 2h1l2-1 3 3 1-1-1-2 4-4z" />
                </svg>
              )}

              {/* Close button */}
              <button
                type="button"
                className={clsx(
                  "ml-auto flex h-4 w-4 shrink-0 items-center justify-center rounded-sm opacity-0 transition-opacity hover:bg-white/10 group-hover:opacity-70",
                  isActive && "opacity-70",
                )}
                onClick={(e) => {
                  e.stopPropagation();
                  closeTab(tab);
                }}
                aria-label={`Close ${tab.title}`}
                tabIndex={-1}
              >
                <svg width="8" height="8" viewBox="0 0 8 8" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
                  <path d="M1 1l6 6M7 1l-6 6" />
                </svg>
              </button>
            </div>
          );
        })}
      </div>

      {/* Right scroll indicator */}
      {overflowRight && (
        <button
          type="button"
          className="flex h-full w-6 shrink-0 items-center justify-center bg-gradient-to-l from-[var(--color-sdr-bg-secondary,#0b0d13)] to-transparent"
          onClick={scrollRight}
          aria-label="Scroll tabs right"
        >
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M4 2l4 4-4 4" /></svg>
        </button>
      )}

      {/* All-tabs dropdown chevron */}
      <div className="relative flex shrink-0">
        <button
          type="button"
          className="flex h-full w-6 items-center justify-center border-l text-sdr-text-muted hover:text-sdr-text-secondary"
          style={{ borderColor: "var(--color-sdr-border-subtle, #212634)" }}
          onClick={(e) => {
            e.stopPropagation();
            setShowDropdown((prev) => !prev);
          }}
          aria-label="Show all tabs"
          aria-expanded={showDropdown}
        >
          <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M2 3.5l3 3 3-3" /></svg>
        </button>

        {showDropdown && (
          <div
            className="absolute right-0 top-full z-50 mt-1 min-w-[180px] rounded-md border py-1 shadow-lg"
            style={{
              background: "var(--color-sdr-bg-secondary, #0b0d13)",
              borderColor: "var(--color-sdr-border, #2d3240)",
            }}
            onPointerDown={(e) => e.stopPropagation()}
          >
            {/* Pinned first, then unpinned */}
            {[...tabs.filter((t) => t.isPinned), ...tabs.filter((t) => !t.isPinned)].map((tab) => (
              <button
                key={tab.id}
                type="button"
                className={clsx(
                  "flex w-full items-center gap-2 px-3 py-1 text-left text-[11px] hover:bg-white/5",
                  tab.id === activeTabId ? "text-sdr-text-primary" : "text-sdr-text-muted",
                )}
                style={{ fontFamily: "var(--font-mono)" }}
                onClick={() => {
                  activateTab(tab.id);
                  setShowDropdown(false);
                }}
              >
                {tab.isPinned && (
                  <svg className="h-2 w-2 shrink-0 opacity-40" viewBox="0 0 12 12" fill="currentColor"><path d="M8 1L4 5l-2-1-1 1 3 3-1 2h1l2-1 3 3 1-1-1-2 4-4z" /></svg>
                )}
                <span className={clsx("truncate", tab.isPreview && "italic")}>{tab.title}</span>
                {tab.isDirty && (
                  <span className="ml-auto h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: "rgba(238,220,166,0.96)" }} />
                )}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Right-click context menu */}
      {contextMenu && (
        <ContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          tab={tabs.find((t) => t.id === contextMenu.tabId)!}
          onClose={() => setContextMenu(null)}
          onCloseTab={(tab) => { closeTab(tab); setContextMenu(null); }}
          onCloseOthers={(tabId) => { handleCloseOthers(tabId); setContextMenu(null); }}
          onCloseAll={() => { handleCloseAll(); setContextMenu(null); }}
          onPin={(tabId) => { pinTab(tabId); setContextMenu(null); }}
          onUnpin={(tabId) => { unpinTab(tabId); setContextMenu(null); }}
          onMoveToSplit={(tabId) => { handleMoveToSplit(tabId); setContextMenu(null); }}
        />
      )}
    </div>
  );
}

// -- Context menu sub-component --

interface ContextMenuProps {
  x: number;
  y: number;
  tab: TabState;
  onClose: () => void;
  onCloseTab: (tab: TabState) => void;
  onCloseOthers: (tabId: string) => void;
  onCloseAll: () => void;
  onPin: (tabId: string) => void;
  onUnpin: (tabId: string) => void;
  onMoveToSplit: (tabId: string) => void;
}

function ContextMenu({ x, y, tab, onCloseTab, onCloseOthers, onCloseAll, onPin, onUnpin, onMoveToSplit }: ContextMenuProps) {
  if (!tab) return null;

  const items = [
    { label: "Close", action: () => onCloseTab(tab) },
    { label: "Close Others", action: () => onCloseOthers(tab.id) },
    { label: "Close All", action: () => onCloseAll() },
    { label: "---", action: () => {} },
    tab.isPinned
      ? { label: "Unpin", action: () => onUnpin(tab.id) }
      : { label: "Pin", action: () => onPin(tab.id) },
    { label: "Move to Split", action: () => onMoveToSplit(tab.id) },
  ];

  return (
    <div
      className="fixed z-50 min-w-[160px] rounded-md border py-1 shadow-lg"
      style={{
        left: x,
        top: y,
        background: "var(--color-sdr-bg-secondary, #0b0d13)",
        borderColor: "var(--color-sdr-border, #2d3240)",
      }}
      onPointerDown={(e) => e.stopPropagation()}
    >
      {items.map((item, i) =>
        item.label === "---" ? (
          <div
            key={`sep-${i}`}
            className="my-1 h-px"
            style={{ background: "var(--color-sdr-border-subtle, #212634)" }}
          />
        ) : (
          <button
            key={item.label}
            type="button"
            className="flex w-full px-3 py-1 text-left text-[11px] text-sdr-text-secondary hover:bg-white/5 hover:text-sdr-text-primary"
            style={{ fontFamily: "var(--font-mono)" }}
            onClick={item.action}
          >
            {item.label}
          </button>
        ),
      )}
    </div>
  );
}
