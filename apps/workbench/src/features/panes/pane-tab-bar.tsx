import { useState, useRef, useEffect, useCallback } from "react";
import {
  IconArrowBarRight,
  IconChecks,
  IconChevronLeft,
  IconChevronRight,
  IconLayoutColumns,
  IconLayoutRows,
  IconPlus,
  IconTrash,
  IconX,
  IconXboxX,
} from "@tabler/icons-react";
import { usePaneStore } from "./pane-store";
import { findPaneGroup, getAllPaneGroups } from "./pane-tree";
import { PaneTab } from "./pane-tab";
import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import type { PaneGroup } from "./pane-types";

/* ---- Context Menu ---- */

interface PaneTabContextMenuState {
  viewId: string;
  paneId: string;
  x: number;
  y: number;
}

function PaneTabContextMenu({
  menu,
  onClose,
}: {
  menu: PaneTabContextMenuState;
  onClose: () => void;
}) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        onClose();
      }
    }
    function handleEsc(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("mousedown", handleClickOutside);
    document.addEventListener("keydown", handleEsc);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("keydown", handleEsc);
    };
  }, [onClose]);

  const store = usePaneStore.getState();

  const items: Array<
    | { label: string; icon: typeof IconX; action: () => void }
    | { type: "separator" }
  > = [
    {
      label: "Close",
      icon: IconX,
      action: () => store.closeView(menu.paneId, menu.viewId),
    },
    {
      label: "Close Others",
      icon: IconXboxX,
      action: () => store.closeOtherViews(menu.paneId, menu.viewId),
    },
    {
      label: "Close to the Right",
      icon: IconArrowBarRight,
      action: () => store.closeViewsToRight(menu.paneId, menu.viewId),
    },
    { type: "separator" },
    {
      label: "Close Saved",
      icon: IconChecks,
      action: () => store.closeSavedViews(menu.paneId),
    },
    {
      label: "Close All",
      icon: IconTrash,
      action: () => {
        const root = usePaneStore.getState().root;
        const pane = findPaneGroup(root, menu.paneId);
        if (pane) {
          const views = [...pane.views];
          for (let i = views.length - 1; i >= 0; i--) {
            usePaneStore.getState().closeView(menu.paneId, views[i].id);
          }
        }
      },
    },
  ];

  return (
    <div
      ref={ref}
      className="fixed z-[100] min-w-[160px] bg-[#131721] border border-[#2d3240] rounded-md shadow-xl py-1"
      style={{ left: menu.x, top: menu.y }}
    >
      {items.map((item, i) => {
        if ("type" in item && item.type === "separator") {
          return <div key={i} className="h-px bg-[#2d3240] my-1" />;
        }
        const Icon = "icon" in item ? item.icon : null;
        return (
          <button
            key={i}
            type="button"
            className="flex items-center gap-2 w-full px-3 py-1.5 text-[11px] font-mono text-[#ece7dc] hover:bg-[#d4a84b]/10 hover:text-[#d4a84b] transition-colors text-left"
            onClick={() => {
              if ("action" in item) item.action();
              onClose();
            }}
          >
            {Icon && <Icon size={12} stroke={1.5} />}
            {"label" in item && item.label}
          </button>
        );
      })}
    </div>
  );
}

export function PaneTabBar({
  pane,
  active,
}: {
  pane: PaneGroup;
  active: boolean;
}) {
  const paneCount = usePaneStore((state) => getAllPaneGroups(state.root).length);
  const scrollRef = useRef<HTMLDivElement>(null);
  const [canScrollLeft, setCanScrollLeft] = useState(false);
  const [canScrollRight, setCanScrollRight] = useState(false);
  const [contextMenu, setContextMenu] = useState<PaneTabContextMenuState | null>(null);

  const handleContextMenu = useCallback(
    (viewId: string, e: React.MouseEvent) => {
      e.preventDefault();
      setContextMenu({ viewId, paneId: pane.id, x: e.clientX, y: e.clientY });
    },
    [pane.id],
  );

  const checkOverflow = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    setCanScrollLeft(el.scrollLeft > 0);
    setCanScrollRight(el.scrollLeft + el.clientWidth < el.scrollWidth - 1);
  }, []);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;

    const observer = new ResizeObserver(() => checkOverflow());
    observer.observe(el);
    el.addEventListener("scroll", checkOverflow);

    // Initial check
    checkOverflow();

    return () => {
      observer.disconnect();
      el.removeEventListener("scroll", checkOverflow);
    };
  }, [checkOverflow]);

  const handleWheel = useCallback((e: React.WheelEvent<HTMLDivElement>) => {
    const el = scrollRef.current;
    if (!el) return;
    if (el.scrollWidth <= el.clientWidth) return;
    e.preventDefault();
    el.scrollLeft += e.deltaY;
  }, []);

  return (
    <>
      <div
        role="tablist"
        aria-label="Open editors"
        aria-orientation="horizontal"
        className="flex h-[36px] shrink-0 items-stretch border-b border-[#202531] bg-[#0b0d13]"
      >
        {canScrollLeft && (
          <button
            type="button"
            className="shrink-0 flex items-center justify-center w-6 text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#131721] transition-colors border-r border-[#202531]"
            onClick={() =>
              scrollRef.current?.scrollBy({ left: -120, behavior: "smooth" })
            }
            title="Scroll tabs left"
            aria-label="Scroll tabs left"
          >
            <IconChevronLeft size={14} stroke={1.8} />
          </button>
        )}

        <div
          ref={scrollRef}
          className="flex min-w-0 flex-1 items-stretch overflow-x-auto scrollbar-hide"
          onWheel={handleWheel}
        >
          {pane.views.map((view) => (
            <PaneTab
              key={view.id}
              view={view}
              isActive={view.id === pane.activeViewId}
              paneId={pane.id}
              onContextMenu={(e) => handleContextMenu(view.id, e)}
            />
          ))}
        </div>

        {canScrollRight && (
          <button
            type="button"
            className="shrink-0 flex items-center justify-center w-6 text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#131721] transition-colors border-l border-[#202531]"
            onClick={() =>
              scrollRef.current?.scrollBy({ left: 120, behavior: "smooth" })
            }
            title="Scroll tabs right"
            aria-label="Scroll tabs right"
          >
            <IconChevronRight size={14} stroke={1.8} />
          </button>
        )}

        <div className="flex shrink-0 items-center gap-1 px-2">
          <button
            type="button"
            className="rounded-md p-1.5 text-[#6f7f9a] transition-colors hover:bg-[#131721] hover:text-[#ece7dc]"
            onClick={() => {
              const tabId = usePolicyTabsStore.getState().newTab();
              if (tabId) {
                const tab = usePolicyTabsStore.getState().tabs.find(t => t.id === tabId);
                if (tab) {
                  const route = `/file/__new__/${tabId}`;
                  usePaneStore.getState().openApp(route, tab.name);
                }
              }
            }}
            title="New file"
            aria-label="New file"
          >
            <IconPlus size={14} stroke={1.8} />
          </button>
          <button
            type="button"
            className="rounded-md p-1.5 text-[#6f7f9a] transition-colors hover:bg-[#131721] hover:text-[#ece7dc]"
            onClick={() =>
              usePaneStore.getState().splitPane(pane.id, "vertical")
            }
            title="Split vertically"
            aria-label="Split vertically"
          >
            <IconLayoutColumns size={14} stroke={1.8} />
          </button>
          <button
            type="button"
            className="rounded-md p-1.5 text-[#6f7f9a] transition-colors hover:bg-[#131721] hover:text-[#ece7dc]"
            onClick={() =>
              usePaneStore.getState().splitPane(pane.id, "horizontal")
            }
            title="Split horizontally"
            aria-label="Split horizontally"
          >
            <IconLayoutRows size={14} stroke={1.8} />
          </button>
          {paneCount > 1 && (
            <button
              type="button"
              className="rounded-md p-1.5 text-[#6f7f9a] transition-colors hover:bg-[#2a1115] hover:text-[#ffb8b8]"
              onClick={() => usePaneStore.getState().closePane(pane.id)}
              title="Close pane"
              aria-label="Close pane"
            >
              <IconX size={14} stroke={1.8} />
            </button>
          )}
        </div>
      </div>

      {contextMenu && (
        <PaneTabContextMenu
          menu={contextMenu}
          onClose={() => setContextMenu(null)}
        />
      )}
    </>
  );
}
