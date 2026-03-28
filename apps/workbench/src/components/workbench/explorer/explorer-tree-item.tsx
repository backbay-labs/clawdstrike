import { forwardRef } from "react";
import {
  IconChevronRight,
  IconFolder,
  IconFolderOpen,
} from "@tabler/icons-react";
import { FileTypeIcon } from "@/lib/workbench/file-type-icons";
import type { ProjectFile } from "@/features/project/stores/project-store";
import { InlineNameInput } from "./inline-name-input";
import { cn } from "@/lib/utils";

// ---- Props ----

interface ExplorerTreeItemProps {
  nodeId: string;
  level: number;
  file: ProjectFile;
  isExpanded: boolean;
  onToggle: () => void;
  onOpen: () => void;
  tabIndex?: number;
  onFocus?: () => void;
  onKeyDown?: (e: React.KeyboardEvent<HTMLDivElement>) => void;
  isActive?: boolean;
  onContextMenu?: (e: React.MouseEvent) => void;
  /** Whether this item is currently being renamed inline. */
  isRenaming?: boolean;
  /** Called when the user submits the rename. */
  onRenameSubmit?: (newName: string) => void;
  /** Called when the user cancels the rename. */
  onRenameCancel?: () => void;
  /** Called to start the rename flow (e.g. F2 key). */
  onStartRename?: () => void;
  /** Whether this file has unsaved modifications. */
  isModified?: boolean;
  /** Whether this file has validation errors. */
  hasError?: boolean;
  /** Optional mutation state badge for a row affected by a pending/error mutation. */
  mutationStatus?: "pending" | "error";
  mutationLabel?: string | null;
}

// ---- Component ----

export const ExplorerTreeItem = forwardRef<HTMLDivElement, ExplorerTreeItemProps>(function ExplorerTreeItem({
  nodeId,
  level,
  file,
  isExpanded,
  onToggle,
  onOpen,
  tabIndex = -1,
  onFocus,
  onKeyDown,
  isActive,
  onContextMenu,
  isRenaming,
  onRenameSubmit,
  onRenameCancel,
  onStartRename,
  isModified,
  hasError,
  mutationStatus,
  mutationLabel,
}, ref) {
  const indent = Math.max(0, level - 1) * 16;
  const accessibilityState = file.isDirectory
    ? `${isExpanded ? "expanded" : "collapsed"} folder`
    : hasError
      ? "file with validation errors"
      : isModified
        ? "modified file"
        : "file";
  const ariaLabel = [file.name, accessibilityState, isActive ? "active" : null]
    .filter(Boolean)
    .join(", ");

  const handleClick = (e: React.MouseEvent<HTMLDivElement>) => {
    e.currentTarget.focus();
    onFocus?.();
    if (file.isDirectory) {
      onToggle();
    } else {
      onOpen();
    }
  };

  return (
    <div
      ref={ref}
      role="treeitem"
      aria-level={level}
      aria-expanded={file.isDirectory ? isExpanded : undefined}
      aria-selected={!file.isDirectory && isActive ? true : undefined}
      aria-label={ariaLabel}
      data-explorer-node-id={nodeId}
      tabIndex={tabIndex}
      onClick={handleClick}
      onFocus={onFocus}
      onKeyDown={onKeyDown}
      onContextMenu={onContextMenu}
      style={{ paddingLeft: indent + 4 }}
      className={cn(
        "w-full flex items-center gap-1.5 pr-2 py-[3px] text-left transition-colors group relative outline-none",
        "hover:bg-[#131721]/40",
        isActive && "bg-[#131721]/60",
        "focus-visible:bg-[#131721]/70 focus-visible:ring-1 focus-visible:ring-[#d4a84b]/50",
      )}
      title={file.path}
    >
      {/* Active file gold left accent */}
      {isActive && !file.isDirectory && (
        <div className="absolute left-0 top-0 bottom-0 w-[2px] bg-[#d4a84b]" />
      )}

      {/* Indent guide lines -- one vertical line per ancestor depth level */}
      {Array.from({ length: file.depth }, (_, i) => (
        <div
          key={i}
          className="absolute top-0 bottom-0 border-l border-[#2d3240]/30 indent-guide"
          style={{ left: i * 16 + 11 }}
        />
      ))}

      {/* Chevron (directories) or spacer (files) */}
      {file.isDirectory ? (
        <span
          className={cn(
            "shrink-0 transition-transform duration-150",
            isExpanded && "rotate-90",
          )}
        >
          <IconChevronRight
            size={12}
            stroke={1.5}
            className="text-[#6f7f9a]/70"
          />
        </span>
      ) : (
        <span className="shrink-0 w-3" />
      )}

      {/* Icon: folder or file-type icon */}
      {file.isDirectory ? (
        isExpanded ? (
          <IconFolderOpen
            size={14}
            stroke={1.5}
            className="shrink-0 text-[#d4a84b]/80"
          />
        ) : (
          <IconFolder
            size={14}
            stroke={1.5}
            className="shrink-0 text-[#6f7f9a]/70"
          />
        )
      ) : (
        <FileTypeIcon fileType={file.fileType} size={14} stroke={1.5} className="shrink-0" />
      )}

      {/* Name or inline rename input */}
      {isRenaming ? (
        <InlineNameInput
          defaultValue={file.name}
          onSubmit={(newName) => onRenameSubmit?.(newName)}
          onCancel={() => onRenameCancel?.()}
          className="flex-1 min-w-0"
        />
      ) : (
        <>
          <span
            className={cn(
              "text-[11px] font-mono truncate",
              file.isDirectory
                ? "text-[#ece7dc]"
                : hasError
                  ? "text-red-400"
                  : isActive
                    ? "text-[#ece7dc]"
                    : "text-[#6f7f9a]",
              !file.isDirectory && isModified && !hasError && "italic",
            )}
          >
            {file.name}
          </span>

          {mutationLabel && (
            <span
              className={cn(
                "ml-auto shrink-0 rounded border px-1.5 py-0.5 text-[8px] font-mono uppercase tracking-[0.16em]",
                mutationStatus === "pending"
                  ? "border-[#d4a84b]/35 bg-[#20180b] text-[#f1d089]"
                  : "border-[#e77b72]/35 bg-[#241012] text-[#f2b8b3]",
              )}
            >
              {mutationLabel}
            </span>
          )}

          {/* Status indicator dot (files only) */}
          {!file.isDirectory && hasError && (
            <span className="shrink-0 w-1 h-1 rounded-full bg-red-500 ml-auto" />
          )}
          {!file.isDirectory && isModified && !hasError && (
            <span className="shrink-0 w-1 h-1 rounded-full bg-[#d4a84b] ml-auto" />
          )}
        </>
      )}
    </div>
  );
});
