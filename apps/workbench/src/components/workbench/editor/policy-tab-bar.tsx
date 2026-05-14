import { useState, useCallback, useRef, useEffect } from "react";
import { usePolicyTabs } from "@/features/policy/hooks/use-policy-actions";
import type { PolicyTab } from "@/features/policy/types/policy-tab";
import { FILE_TYPE_REGISTRY } from "@/lib/workbench/file-type-registry";
import type { FileType } from "@/lib/workbench/file-type-registry";
import {
  usePluginViewTabs,
  useActivePluginViewTabId,
  activatePluginViewTab,
  closePluginViewTab,
  openPluginViewTab,
} from "@/lib/plugins/plugin-view-tab-store";
import { useViewsBySlot } from "@/lib/plugins/view-registry";
import { PluginContextMenuItems } from "@/components/plugins/plugin-context-menu";
import type { WhenContext } from "@/lib/plugins/context-menu-registry";
import { cn } from "@/lib/utils";
import {
  IconPlus,
  IconX,
  IconCopy,
  IconEdit,
  IconTrash,
  IconHome,
  IconChevronDown,
} from "@tabler/icons-react";


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
      <PluginContextMenuItems
        menu="tab"
        context={{ tabId: menu.tabId } as WhenContext}
        onExecuteCommand={(commandId) => {
          console.log(`[TabContextMenu] Execute command: ${commandId}`);
          onClose();
        }}
      />
    </div>
  );
}


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
  const iconColor = FILE_TYPE_REGISTRY[tab.fileType ?? "clawdstrike_policy"].iconColor;

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
      style={isActive ? { backgroundColor: `${iconColor}08` } : undefined}
    >
      {/* Active indicator — format-colored top border */}
      {isActive && (
        <div
          className="absolute top-0 left-0 right-0 h-[3px]"
          style={{ backgroundColor: FILE_TYPE_REGISTRY[tab.fileType ?? "clawdstrike_policy"].iconColor }}
        />
      )}

      {/* Split indicator */}
      {isSplit && !isActive && (
        <div className="absolute bottom-0 left-0 right-0 h-[2px] bg-[#6f7f9a]/40" />
      )}

      {/* Format indicator dot */}
      <span
        className="inline-block w-2.5 h-2.5 rounded-full flex-shrink-0"
        style={{ backgroundColor: FILE_TYPE_REGISTRY[tab.fileType ?? "clawdstrike_policy"].iconColor }}
        title={FILE_TYPE_REGISTRY[tab.fileType ?? "clawdstrike_policy"].label}
        aria-label={FILE_TYPE_REGISTRY[tab.fileType ?? "clawdstrike_policy"].label}
      />

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
            "shrink-0 p-1 rounded hover:bg-[#c45c5c]/20 hover:text-[#c45c5c] transition-colors",
            isActive ? "opacity-60 group-hover:opacity-100" : "opacity-0 group-hover:opacity-100",
          )}
          title="Close tab"
        >
          <IconX size={11} stroke={1.5} />
        </button>
      )}
    </div>
  );
}


interface PolicyTabBarProps {
  isHomeActive?: boolean;
  onHomeClick?: () => void;
  onTabSwitch?: () => void;
}

export function PolicyTabBar({ isHomeActive, onHomeClick, onTabSwitch }: PolicyTabBarProps = {}) {
  const { multiState, multiDispatch, tabs, canAddTab } = usePolicyTabs();
  const { activeTabId, splitTabId } = multiState;

  // Plugin view tabs integration
  const pluginViewTabs = usePluginViewTabs();
  const activePluginViewTabId = useActivePluginViewTabId();
  const availableEditorViews = useViewsBySlot("editorTab");

  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null);
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [draggedTabId, setDraggedTabId] = useState<string | null>(null);
  const [dropTarget, setDropTarget] = useState<{ tabId: string; position: "left" | "right" } | null>(null);
  const [confirmingClose, setConfirmingClose] = useState<string | null>(null);

  const scrollRef = useRef<HTMLDivElement>(null);
  const confirmTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Auto-cancel close confirmation after 3 seconds
  useEffect(() => {
    if (confirmTimerRef.current) clearTimeout(confirmTimerRef.current);
    if (confirmingClose) {
      confirmTimerRef.current = setTimeout(() => setConfirmingClose(null), 3000);
    }
    return () => {
      if (confirmTimerRef.current) clearTimeout(confirmTimerRef.current);
    };
  }, [confirmingClose]);

  // ---- Handlers ----

  const handleSwitch = useCallback(
    (tabId: string) => {
      multiDispatch({ type: "SWITCH_TAB", tabId });
      activatePluginViewTab(null);
      onTabSwitch?.();
    },
    [multiDispatch, onTabSwitch],
  );

  const handleClose = useCallback(
    (tabId: string) => {
      const tab = tabs.find((t) => t.id === tabId);
      if (tab?.dirty && confirmingClose !== tabId) {
        // First click on a dirty tab: show inline confirmation
        setConfirmingClose(tabId);
        return;
      }
      setConfirmingClose(null);
      multiDispatch({ type: "CLOSE_TAB", tabId });
    },
    [tabs, multiDispatch, confirmingClose],
  );

  const handleCancelClose = useCallback(() => {
    setConfirmingClose(null);
  }, []);

  const handleCloseOthers = useCallback(
    (tabId: string) => {
      const toClose = tabs.filter((t) => t.id !== tabId).map((t) => t.id);
      for (const id of toClose) {
        multiDispatch({ type: "CLOSE_TAB", tabId: id });
      }
    },
    [tabs, multiDispatch],
  );

  const handleCloseAll = useCallback(() => {
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

  const [newTabDropdownOpen, setNewTabDropdownOpen] = useState(false);
  const newTabDropdownRef = useRef<HTMLDivElement>(null);

  // Close dropdown on click outside or Escape
  useEffect(() => {
    if (!newTabDropdownOpen) return;
    function handleClickOutside(e: MouseEvent) {
      if (newTabDropdownRef.current && !newTabDropdownRef.current.contains(e.target as Node)) {
        setNewTabDropdownOpen(false);
      }
    }
    function handleEsc(e: KeyboardEvent) {
      if (e.key === "Escape") setNewTabDropdownOpen(false);
    }
    document.addEventListener("mousedown", handleClickOutside);
    document.addEventListener("keydown", handleEsc);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("keydown", handleEsc);
    };
  }, [newTabDropdownOpen]);

  const handleNewTab = useCallback(() => {
    multiDispatch({ type: "NEW_TAB" });
  }, [multiDispatch]);

  const handleNewTabWithType = useCallback(
    (fileType: FileType) => {
      const descriptor = FILE_TYPE_REGISTRY[fileType];
      if (fileType === "clawdstrike_policy") {
        multiDispatch({ type: "NEW_TAB" });
      } else {
        multiDispatch({
          type: "NEW_TAB",
          fileType,
          yaml: descriptor.defaultContent,
        });
      }
      setNewTabDropdownOpen(false);
    },
    [multiDispatch],
  );

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
        {/* Home tab button */}
        <button
          type="button"
          onClick={() => onHomeClick?.()}
          className={cn(
            "shrink-0 flex items-center justify-center w-8 h-full border-r border-[#2d3240] transition-colors",
            isHomeActive
              ? "bg-[#131721] text-[#d4a84b]"
              : "text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#131721]/50",
          )}
          title="Policy workspace"
        >
          <IconHome size={14} stroke={1.5} />
        </button>

        {/* Scrollable tab list */}
        <div
          ref={scrollRef}
          className="flex items-stretch flex-1 min-w-0 overflow-x-auto scrollbar-thin scrollbar-thumb-[#2d3240] scrollbar-track-transparent"
          onDragOver={(e) => e.preventDefault()}
        >
          {tabs.map((tab) => (
            <div key={tab.id} className="relative" onContextMenu={handleContextMenu(tab.id)}>
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
              {/* Inline close confirmation for dirty tabs */}
              {confirmingClose === tab.id && (
                <div className="absolute top-full left-0 z-50 mt-0.5 flex items-center gap-1.5 px-2.5 py-1.5 bg-[#0b0d13] border border-[#2d3240] rounded-md shadow-lg shadow-black/40 whitespace-nowrap">
                  <span className="text-[10px] font-mono text-[#6f7f9a]">Unsaved changes</span>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleClose(tab.id);
                    }}
                    className="px-2 py-0.5 text-[10px] font-mono font-medium text-[#c45c5c] bg-[#c45c5c]/10 border border-[#c45c5c]/20 rounded hover:bg-[#c45c5c]/20 transition-colors"
                  >
                    Discard
                  </button>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleCancelClose();
                    }}
                    className="px-2 py-0.5 text-[10px] font-mono text-[#6f7f9a] bg-[#131721] border border-[#2d3240] rounded hover:text-[#ece7dc] transition-colors"
                  >
                    Cancel
                  </button>
                </div>
              )}
            </div>
          ))}

          {/* Plugin view tabs */}
          {pluginViewTabs.map((pvTab) => (
            <div
              key={`plugin:${pvTab.viewId}`}
              onClick={() => {
                activatePluginViewTab(pvTab.viewId);
                onTabSwitch?.();
              }}
              className={cn(
                "group relative flex items-center gap-1.5 px-3 py-1.5 min-w-[80px] max-w-[200px] cursor-pointer select-none transition-all",
                "border-r border-[#2d3240]/50",
                pvTab.viewId === activePluginViewTabId
                  ? "bg-[#131721] text-[#ece7dc]"
                  : "bg-[#0b0d13]/60 text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#131721]/50",
              )}
            >
              {/* Active indicator -- blue for plugin tabs */}
              {pvTab.viewId === activePluginViewTabId && (
                <div className="absolute top-0 left-0 right-0 h-[3px] bg-[#7c9aef]" />
              )}

              {/* Plugin icon indicator */}
              <span className="inline-block w-2.5 h-2.5 rounded-full flex-shrink-0 bg-[#7c9aef]" />

              {/* Dirty dot */}
              {pvTab.dirty && (
                <span className="w-1.5 h-1.5 rounded-full bg-[#d4a84b] shrink-0" />
              )}

              {/* Tab label */}
              <span className="truncate text-[11px] font-mono flex-1">
                {pvTab.label}
              </span>

              {/* Close button */}
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  closePluginViewTab(pvTab.viewId);
                }}
                className={cn(
                  "shrink-0 p-1 rounded hover:bg-[#c45c5c]/20 hover:text-[#c45c5c] transition-colors",
                  pvTab.viewId === activePluginViewTabId ? "opacity-60 group-hover:opacity-100" : "opacity-0 group-hover:opacity-100",
                )}
                title="Close tab"
              >
                <IconX size={11} stroke={1.5} />
              </button>
            </div>
          ))}

          {/* New tab split button — main + dropdown caret */}
          <div ref={newTabDropdownRef} className="relative shrink-0 flex items-center">
            {/* Main button: creates a new ClawdStrike policy tab */}
            <button
              type="button"
              onClick={handleNewTab}
              disabled={!canAddTab}
              className={cn(
                "flex items-center justify-center pl-2.5 pr-1 py-1.5 transition-colors",
                canAddTab
                  ? "text-[#6f7f9a] hover:text-[#d4a84b] hover:bg-[#d4a84b]/10"
                  : "text-[#6f7f9a]/30 cursor-not-allowed",
              )}
              title={canAddTab ? "New policy tab" : "Maximum tabs reached (25)"}
            >
              <IconPlus size={13} stroke={1.5} />
            </button>

            {/* Dropdown caret */}
            <button
              type="button"
              onClick={() => setNewTabDropdownOpen((prev) => !prev)}
              disabled={!canAddTab}
              className={cn(
                "flex items-center justify-center pr-2 pl-0.5 py-1.5 transition-colors",
                canAddTab
                  ? "text-[#6f7f9a] hover:text-[#d4a84b] hover:bg-[#d4a84b]/10"
                  : "text-[#6f7f9a]/30 cursor-not-allowed",
              )}
              title="New tab from format..."
            >
              <IconChevronDown size={10} stroke={1.5} />
            </button>

            {/* Format dropdown */}
            {newTabDropdownOpen && canAddTab && (
              <div className="absolute top-full left-0 z-[100] mt-0.5 min-w-[200px] bg-[#0b0d13] border border-[#2d3240] rounded-lg shadow-lg py-1">
                {(
                  [
                    { fileType: "clawdstrike_policy" as FileType, label: "New Policy", ext: ".yaml" },
                    { fileType: "sigma_rule" as FileType, label: "New Sigma Rule", ext: ".yml" },
                    { fileType: "yara_rule" as FileType, label: "New YARA Rule", ext: ".yar" },
                    { fileType: "ocsf_event" as FileType, label: "New OCSF Event", ext: ".json" },
                  ] as const
                ).map((item) => (
                  <button
                    key={item.fileType}
                    type="button"
                    onClick={() => handleNewTabWithType(item.fileType)}
                    className="flex items-center gap-2 w-full px-3 py-1.5 text-[11px] font-mono text-[#ece7dc] hover:bg-[#131721] cursor-pointer transition-colors"
                  >
                    <span
                      className="inline-block w-2 h-2 rounded-full shrink-0"
                      style={{ backgroundColor: FILE_TYPE_REGISTRY[item.fileType].iconColor }}
                      aria-hidden="true"
                    />
                    <span className="flex-1 text-left">{item.label}</span>
                    <span className="text-[#6f7f9a]/60 text-[10px]">{item.ext}</span>
                  </button>
                ))}
                {availableEditorViews.length > 0 && (
                  <>
                    <div className="h-px bg-[#2d3240] my-1" />
                    {availableEditorViews.map((view) => (
                      <button
                        key={view.id}
                        type="button"
                        onClick={() => {
                          openPluginViewTab(view.id);
                          onTabSwitch?.();
                          setNewTabDropdownOpen(false);
                        }}
                        className="flex items-center gap-2 w-full px-3 py-1.5 text-[11px] font-mono text-[#ece7dc] hover:bg-[#131721] cursor-pointer transition-colors"
                      >
                        <span className="inline-block w-2 h-2 rounded-full shrink-0 bg-[#7c9aef]" />
                        <span className="flex-1 text-left">{view.label}</span>
                        <span className="text-[#6f7f9a]/60 text-[10px]">plugin</span>
                      </button>
                    ))}
                  </>
                )}
              </div>
            )}
          </div>
        </div>
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
