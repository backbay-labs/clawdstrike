import { useRef, useEffect, useLayoutEffect, useState } from "react";
import {
  IconFilePlus,
  IconFolderPlus,
  IconEdit,
  IconTrash,
  IconCopy,
  IconClipboard,
  IconFolderOpen,
  IconRefresh,
  IconArrowsMinimize,
  IconExternalLink,
  IconX,
  IconFile,
} from "@tabler/icons-react";
import type { ProjectFile } from "@/features/project/stores/project-store";
import { joinWorkspacePath } from "@/lib/workbench/path-utils";

// ---------------------------------------------------------------------------
// Discriminated union for context menu targets
// ---------------------------------------------------------------------------

export type ContextMenuTarget =
  | { targetType: "root"; rootPath: string; rootName: string; x: number; y: number }
  | { targetType: "file"; file: ProjectFile; rootPath: string; x: number; y: number }
  | { targetType: "folder"; file: ProjectFile; rootPath: string; x: number; y: number };

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface ExplorerContextMenuProps {
  target: ContextMenuTarget;
  onClose: () => void;
  onNewFile: (dirPath: string) => void;
  onOpen?: (file: ProjectFile) => void;
  onRename?: (file: ProjectFile) => void;
  onDelete?: (file: ProjectFile) => void;
  onRevealInFinder?: (absolutePath: string) => void;
  onRemoveRoot?: (rootPath: string) => void;
  onRefreshRoot?: (rootPath: string) => void;
  onCollapseChildren?: (rootPath: string, dirPath: string) => void;
  onNewFolder?: (dirPath: string) => void;
}

// ---------------------------------------------------------------------------
// Menu item types
// ---------------------------------------------------------------------------

type MenuItem =
  | {
      label: string;
      icon: typeof IconFilePlus;
      action: () => void;
      variant?: "danger";
      shortcut?: string;
    }
  | { type: "separator" };

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function ExplorerContextMenu({
  target,
  onClose,
  onNewFile,
  onOpen,
  onRename,
  onDelete,
  onRevealInFinder,
  onRemoveRoot,
  onRefreshRoot,
  onCollapseChildren,
  onNewFolder,
}: ExplorerContextMenuProps) {
  const ref = useRef<HTMLDivElement>(null);
  const [position, setPosition] = useState({ x: target.x, y: target.y });

  // Viewport clamping: measure the rendered menu and ensure it stays on-screen.
  useLayoutEffect(() => {
    if (!ref.current) return;
    const rect = ref.current.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const PADDING = 4;
    setPosition({
      x: Math.min(target.x, vw - rect.width - PADDING),
      y: Math.min(target.y, vh - rect.height - PADDING),
    });
  }, [target.x, target.y]);

  // Close on click outside or Escape key.
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

  // Build menu items based on target type.
  const items: MenuItem[] = buildMenuItems(target, {
    onNewFile,
    onOpen,
    onRename,
    onDelete,
    onRevealInFinder,
    onRemoveRoot,
    onRefreshRoot,
    onCollapseChildren,
    onNewFolder,
  });

  return (
    <div
      ref={ref}
      className="fixed z-[100] min-w-[160px] bg-[#131721] border border-[#2d3240] rounded-md shadow-xl py-1"
      style={{ left: position.x, top: position.y }}
    >
      {items.map((item, i) => {
        if ("type" in item && item.type === "separator") {
          return <div key={i} className="h-px bg-[#2d3240] my-1" />;
        }
        const Icon = "icon" in item ? item.icon : null;
        const isDanger = "variant" in item && item.variant === "danger";
        return (
          <button
            key={i}
            type="button"
            className={
              isDanger
                ? "flex items-center gap-2 w-full px-3 py-1.5 text-[11px] font-mono text-red-400 hover:bg-red-500/10 hover:text-red-300 transition-colors text-left"
                : "flex items-center gap-2 w-full px-3 py-1.5 text-[11px] font-mono text-[#ece7dc] hover:bg-[#d4a84b]/10 hover:text-[#d4a84b] transition-colors text-left"
            }
            onClick={() => {
              if ("action" in item) item.action();
              onClose();
            }}
          >
            {Icon && <Icon size={12} stroke={1.5} />}
            {"label" in item && item.label}
            {"shortcut" in item && item.shortcut && (
              <span className="ml-auto text-[9px] text-[#6f7f9a]/50">
                {item.shortcut}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Menu item builders per target type
// ---------------------------------------------------------------------------

function buildMenuItems(
  target: ContextMenuTarget,
  callbacks: {
    onNewFile: (dirPath: string) => void;
    onOpen?: (file: ProjectFile) => void;
    onRename?: (file: ProjectFile) => void;
    onDelete?: (file: ProjectFile) => void;
    onRevealInFinder?: (absolutePath: string) => void;
    onRemoveRoot?: (rootPath: string) => void;
    onRefreshRoot?: (rootPath: string) => void;
    onCollapseChildren?: (rootPath: string, dirPath: string) => void;
    onNewFolder?: (dirPath: string) => void;
  },
): MenuItem[] {
  switch (target.targetType) {
    case "root":
      return buildRootItems(target, callbacks);
    case "file":
      return buildFileItems(target, callbacks);
    case "folder":
      return buildFolderItems(target, callbacks);
  }
}

function buildRootItems(
  target: Extract<ContextMenuTarget, { targetType: "root" }>,
  cb: {
    onNewFile: (dirPath: string) => void;
    onRevealInFinder?: (absolutePath: string) => void;
    onRefreshRoot?: (rootPath: string) => void;
    onRemoveRoot?: (rootPath: string) => void;
  },
): MenuItem[] {
  return [
    {
      label: "New File",
      icon: IconFilePlus,
      action: () => cb.onNewFile(target.rootPath),
    },
    { type: "separator" },
    {
      label: "Open in Finder",
      icon: IconExternalLink,
      action: () => cb.onRevealInFinder?.(target.rootPath),
    },
    {
      label: "Refresh",
      icon: IconRefresh,
      action: () => cb.onRefreshRoot?.(target.rootPath),
    },
    { type: "separator" },
    {
      label: "Remove from Workspace",
      icon: IconX,
      action: () => cb.onRemoveRoot?.(target.rootPath),
      variant: "danger",
    },
  ];
}

function buildFileItems(
  target: Extract<ContextMenuTarget, { targetType: "file" }>,
  cb: {
    onOpen?: (file: ProjectFile) => void;
    onRename?: (file: ProjectFile) => void;
    onDelete?: (file: ProjectFile) => void;
    onRevealInFinder?: (absolutePath: string) => void;
  },
): MenuItem[] {
  const absPath = joinWorkspacePath(target.rootPath, target.file.path);
  return [
    {
      label: "Open",
      icon: IconFile,
      action: () => cb.onOpen?.(target.file),
    },
    { type: "separator" },
    {
      label: "Copy Path",
      icon: IconCopy,
      action: () => {
        void navigator.clipboard.writeText(absPath);
      },
    },
    {
      label: "Copy Relative Path",
      icon: IconClipboard,
      action: () => {
        void navigator.clipboard.writeText(target.file.path);
      },
    },
    { type: "separator" },
    {
      label: "Rename",
      icon: IconEdit,
      action: () => cb.onRename?.(target.file),
      shortcut: "F2",
    },
    {
      label: "Delete",
      icon: IconTrash,
      action: () => cb.onDelete?.(target.file),
      variant: "danger",
    },
    { type: "separator" },
    {
      label: "Reveal in Finder",
      icon: IconFolderOpen,
      action: () => cb.onRevealInFinder?.(absPath),
    },
  ];
}

function buildFolderItems(
  target: Extract<ContextMenuTarget, { targetType: "folder" }>,
  cb: {
    onNewFile: (dirPath: string) => void;
    onNewFolder?: (dirPath: string) => void;
    onCollapseChildren?: (rootPath: string, dirPath: string) => void;
    onRevealInFinder?: (absolutePath: string) => void;
  },
): MenuItem[] {
  const absPath = joinWorkspacePath(target.rootPath, target.file.path);
  return [
    {
      label: "New File",
      icon: IconFilePlus,
      action: () => cb.onNewFile(absPath),
    },
    {
      label: "New Folder",
      icon: IconFolderPlus,
      action: () => cb.onNewFolder?.(absPath),
    },
    { type: "separator" },
    {
      label: "Collapse All Children",
      icon: IconArrowsMinimize,
      action: () => cb.onCollapseChildren?.(target.rootPath, target.file.path),
    },
    { type: "separator" },
    {
      label: "Reveal in Finder",
      icon: IconFolderOpen,
      action: () => cb.onRevealInFinder?.(absPath),
    },
  ];
}
