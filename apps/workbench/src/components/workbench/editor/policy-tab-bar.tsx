import { useState, useCallback, useRef, useEffect } from "react";
import { useMultiPolicy } from "@/lib/workbench/multi-policy-store";
import type { PolicyTab } from "@/lib/workbench/multi-policy-store";
import { cn } from "@/lib/utils";
import {
  IconPlus,
  IconX,
  IconCopy,
  IconEdit,
  IconTrash,
} from "@tabler/icons-react";

// ---------------------------------------------------------------------------
// Context Menu
// ---------------------------------------------------------------------------

interface ContextMenuState {
  tabId: string;
  x: number;
  y: number;
}

function TabContextMenu({
  menu,
  onClose,
  onCloseTab,
  onCloseOthers,
  onCloseAll,
  onDuplicate,
  onRename,
}: {
  menu: ContextMenuState;
  onClose: () => void;
  onCloseTab: (tabId: string) => void;
  onCloseOthers: (tabId: string) => void;
  onCloseAll: () => void;
  onDuplicate: (tabId: string) => void;
  onRename: (tabId: string) => void;
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

  const items = [
    { label: "Close", icon: IconX, action: () => onCloseTab(menu.tabId) },
    { label: "Close Others", icon: IconTrash, action: () => onCloseOthers(menu.tabId) },
    { label: "Close All", icon: IconTrash, action: () => onCloseAll() },
    { type: "separator" as const },
    { label: "Duplicate", icon: IconCopy, action: () => onDuplicate(menu.tabId) },
    { label: "Rename", icon: IconEdit, action: () => onRename(menu.tabId) },
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

// ---------------------------------------------------------------------------
// Rename Input
// ---------------------------------------------------------------------------

function RenameInput({
  tabId,
  currentName,
  onDone,
}: {
  tabId: string;
  currentName: string;
  onDone: (tabId: string, newName: string) => void;
}) {
  const [value, setValue] = useState(currentName);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.select();
  }, []);

  function commit() {
    const trimmed = value.trim();
    onDone(tabId, trimmed || currentName);
  }

  return (
    <input
      ref={inputRef}
      type="text"
      value={value}
      onChange={(e) => setValue(e.target.value)}
      onBlur={commit}
      onKeyDown={(e) => {
        if (e.key === "Enter") commit();
        if (e.key === "Escape") onDone(tabId, currentName);
      }}
      className="bg-[#0b0d13] border border-[#d4a84b]/40 rounded px-1.5 py-0.5 text-[11px] font-mono text-[#ece7dc] outline-none focus:border-[#d4a84b] w-full max-w-[160px]"
    />
  );
}

// ---------------------------------------------------------------------------
// Single Tab
// ---------------------------------------------------------------------------

function TabItem({
  tab,
  isActive,
  isSplit,
  isDragging,
  dropPosition,
  renamingId,
  onSwitch,
  onClose,
  onDragStart,
  onDragOver,
  onDrop,
  onDragEnd,
  onRename,
}: {
  tab: PolicyTab;
  isActive: boolean;
  isSplit: boolean;
  isDragging: boolean;
  dropPosition: "left" | "right" | null;
  renamingId: string | null;
  onSwitch: () => void;
  onClose: () => void;
  onDragStart: (e: React.DragEvent<HTMLDivElement>) => void;
  onDragOver: (e: React.DragEvent<HTMLDivElement>) => void;
  onDrop: (e: React.DragEvent<HTMLDivElement>) => void;
  onDragEnd: () => void;
  onRename: (tabId: string, name: string) => void;
}) {
  const isRenaming = renamingId === tab.id;

  return (
    <div
      draggable={!isRenaming}
      onDragStart={onDragStart}
      onDragOver={onDragOver}
      onDrop={onDrop}
      onDragEnd={onDragEnd}
      onClick={onSwitch}
      onMouseDown={(e) => {
        // Middle-click to close
        if (e.button === 1) {
          e.preventDefault();
          onClose();
        }
      }}
      className={cn(
        "group relative flex items-center gap-1.5 px-3 py-1.5 min-w-[80px] max-w-[200px] cursor-pointer select-none transition-all",
        "border-r border-[#2d3240]/50",
        isActive
          ? "bg-[#131721] text-[#ece7dc]"
          : "bg-[#0b0d13]/60 text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#131721]/50",
        isDragging && "opacity-40",
        // Drop indicators
        dropPosition === "left" && "border-l-2 border-l-[#d4a84b]",
        dropPosition === "right" && "border-r-2 border-r-[#d4a84b]",
      )}
    >
      {/* Active indicator — gold bottom border */}
      {isActive && (
        <div className="absolute bottom-0 left-0 right-0 h-[2px] bg-[#d4a84b]" />
      )}

      {/* Split indicator */}
      {isSplit && !isActive && (
        <div className="absolute bottom-0 left-0 right-0 h-[2px] bg-[#6f7f9a]/40" />
      )}

      {/* Dirty dot */}
      {tab.dirty && (
        <span className="w-1.5 h-1.5 rounded-full bg-[#d4a84b] shrink-0" />
      )}

      {/* Tab name */}
      <span className="truncate text-[11px] font-mono flex-1">
        {isRenaming ? (
          <RenameInput tabId={tab.id} currentName={tab.name} onDone={onRename} />
        ) : (
          tab.name || "Untitled"
        )}
      </span>

      {/* Close button */}
      {!isRenaming && (
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onClose();
          }}
          className={cn(
            "shrink-0 p-0.5 rounded hover:bg-[#c45c5c]/20 hover:text-[#c45c5c] transition-colors",
            "opacity-0 group-hover:opacity-100",
            isActive && "opacity-60",
          )}
          title="Close tab"
        >
          <IconX size={11} stroke={1.5} />
        </button>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// PolicyTabBar
// ---------------------------------------------------------------------------

export function PolicyTabBar() {
  const { multiState, multiDispatch, tabs, canAddTab } = useMultiPolicy();
  const { activeTabId, splitTabId } = multiState;

  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null);
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [draggedTabId, setDraggedTabId] = useState<string | null>(null);
  const [dropTarget, setDropTarget] = useState<{ tabId: string; position: "left" | "right" } | null>(null);

  const scrollRef = useRef<HTMLDivElement>(null);

  // ---- Handlers ----

  const handleSwitch = useCallback(
    (tabId: string) => {
      multiDispatch({ type: "SWITCH_TAB", tabId });
    },
    [multiDispatch],
  );

  const handleClose = useCallback(
    (tabId: string) => {
      const tab = tabs.find((t) => t.id === tabId);
      if (tab?.dirty) {
        const confirmed = window.confirm(
          `"${tab.name}" has unsaved changes. Close anyway?`,
        );
        if (!confirmed) return;
      }
      multiDispatch({ type: "CLOSE_TAB", tabId });
    },
    [tabs, multiDispatch],
  );

  const handleCloseOthers = useCallback(
    (tabId: string) => {
      const dirtyOthers = tabs.filter((t) => t.id !== tabId && t.dirty);
      if (dirtyOthers.length > 0) {
        const confirmed = window.confirm(
          `${dirtyOthers.length} other tab(s) have unsaved changes. Close them?`,
        );
        if (!confirmed) return;
      }
      const toClose = tabs.filter((t) => t.id !== tabId).map((t) => t.id);
      for (const id of toClose) {
        multiDispatch({ type: "CLOSE_TAB", tabId: id });
      }
    },
    [tabs, multiDispatch],
  );

  const handleCloseAll = useCallback(() => {
    const dirtyTabs = tabs.filter((t) => t.dirty);
    if (dirtyTabs.length > 0) {
      const confirmed = window.confirm(
        `${dirtyTabs.length} tab(s) have unsaved changes. Close all?`,
      );
      if (!confirmed) return;
    }
    for (const tab of tabs) {
      multiDispatch({ type: "CLOSE_TAB", tabId: tab.id });
    }
  }, [tabs, multiDispatch]);

  const handleDuplicate = useCallback(
    (tabId: string) => {
      multiDispatch({ type: "DUPLICATE_TAB", tabId });
    },
    [multiDispatch],
  );

  const handleRenameStart = useCallback((tabId: string) => {
    setRenamingId(tabId);
  }, []);

  const handleRenameDone = useCallback(
    (tabId: string, newName: string) => {
      multiDispatch({ type: "RENAME_TAB", tabId, name: newName });
      setRenamingId(null);
    },
    [multiDispatch],
  );

  const handleNewTab = useCallback(() => {
    multiDispatch({ type: "NEW_TAB" });
  }, [multiDispatch]);

  const handleContextMenu = useCallback(
    (tabId: string) => (e: React.MouseEvent) => {
      e.preventDefault();
      setContextMenu({ tabId, x: e.clientX, y: e.clientY });
    },
    [],
  );

  // ---- Drag and drop ----

  const handleDragStart = useCallback(
    (tabId: string) => (e: React.DragEvent<HTMLDivElement>) => {
      e.dataTransfer.effectAllowed = "move";
      e.dataTransfer.setData("text/plain", tabId);
      requestAnimationFrame(() => setDraggedTabId(tabId));
    },
    [],
  );

  const handleDragOver = useCallback(
    (tabId: string) => (e: React.DragEvent<HTMLDivElement>) => {
      if (!draggedTabId || draggedTabId === tabId) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = "move";

      const rect = e.currentTarget.getBoundingClientRect();
      const midX = rect.left + rect.width / 2;
      const position = e.clientX < midX ? "left" : "right";

      setDropTarget((prev) => {
        if (prev?.tabId === tabId && prev?.position === position) return prev;
        return { tabId, position };
      });
    },
    [draggedTabId],
  );

  const handleDrop = useCallback(
    (tabId: string) => (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      const sourceId = e.dataTransfer.getData("text/plain");
      if (!sourceId || sourceId === tabId) return;

      const fromIndex = tabs.findIndex((t) => t.id === sourceId);
      let toIndex = tabs.findIndex((t) => t.id === tabId);

      if (fromIndex < 0 || toIndex < 0) return;

      const rect = e.currentTarget.getBoundingClientRect();
      const dropRight = e.clientX >= rect.left + rect.width / 2;
      if (dropRight) toIndex += 1;
      if (fromIndex < toIndex) toIndex -= 1;

      multiDispatch({ type: "REORDER_TABS", fromIndex, toIndex });
      setDraggedTabId(null);
      setDropTarget(null);
    },
    [tabs, multiDispatch],
  );

  const handleDragEnd = useCallback(() => {
    setDraggedTabId(null);
    setDropTarget(null);
  }, []);

  return (
    <>
      <div className="flex items-center bg-[#0b0d13] shrink-0">
        {/* Scrollable tab list */}
        <div
          ref={scrollRef}
          className="flex items-stretch flex-1 min-w-0 overflow-x-auto scrollbar-thin scrollbar-thumb-[#2d3240] scrollbar-track-transparent"
          onDragOver={(e) => e.preventDefault()}
        >
          {tabs.map((tab) => (
            <div key={tab.id} onContextMenu={handleContextMenu(tab.id)}>
              <TabItem
                tab={tab}
                isActive={tab.id === activeTabId}
                isSplit={tab.id === splitTabId}
                isDragging={draggedTabId === tab.id}
                dropPosition={
                  dropTarget?.tabId === tab.id ? dropTarget.position : null
                }
                renamingId={renamingId}
                onSwitch={() => handleSwitch(tab.id)}
                onClose={() => handleClose(tab.id)}
                onDragStart={handleDragStart(tab.id)}
                onDragOver={handleDragOver(tab.id)}
                onDrop={handleDrop(tab.id)}
                onDragEnd={handleDragEnd}
                onRename={handleRenameDone}
              />
            </div>
          ))}
        </div>

        {/* New tab button */}
        <button
          type="button"
          onClick={handleNewTab}
          disabled={!canAddTab}
          className={cn(
            "shrink-0 p-2 transition-colors",
            canAddTab
              ? "text-[#6f7f9a] hover:text-[#d4a84b] hover:bg-[#d4a84b]/10"
              : "text-[#6f7f9a]/30 cursor-not-allowed",
          )}
          title={canAddTab ? "New tab" : "Maximum tabs reached (10)"}
        >
          <IconPlus size={14} stroke={1.5} />
        </button>
      </div>

      {/* Context menu */}
      {contextMenu && (
        <TabContextMenu
          menu={contextMenu}
          onClose={() => setContextMenu(null)}
          onCloseTab={handleClose}
          onCloseOthers={handleCloseOthers}
          onCloseAll={handleCloseAll}
          onDuplicate={handleDuplicate}
          onRename={handleRenameStart}
        />
      )}
    </>
  );
}
