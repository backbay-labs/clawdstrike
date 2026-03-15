import {
  IconChevronRight,
  IconFolder,
  IconFolderOpen,
} from "@tabler/icons-react";
import { FILE_TYPE_REGISTRY } from "@/lib/workbench/file-type-registry";
import type { ProjectFile } from "@/lib/workbench/project-store";
import { cn } from "@/lib/utils";

// ---- Props ----

interface ExplorerTreeItemProps {
  file: ProjectFile;
  isExpanded: boolean;
  onToggle: () => void;
  onOpen: () => void;
  isActive?: boolean;
  style?: React.CSSProperties;
}

// ---- Component ----

export function ExplorerTreeItem({
  file,
  isExpanded,
  onToggle,
  onOpen,
  isActive,
  style,
}: ExplorerTreeItemProps) {
  const indent = file.depth * 16;
  const descriptor = FILE_TYPE_REGISTRY[file.fileType];

  const handleClick = () => {
    if (file.isDirectory) {
      onToggle();
    } else {
      onOpen();
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      handleClick();
    }
    // Arrow right: expand directory
    if (e.key === "ArrowRight" && file.isDirectory && !isExpanded) {
      e.preventDefault();
      onToggle();
    }
    // Arrow left: collapse directory
    if (e.key === "ArrowLeft" && file.isDirectory && isExpanded) {
      e.preventDefault();
      onToggle();
    }
  };

  return (
    <button
      type="button"
      onClick={handleClick}
      onKeyDown={handleKeyDown}
      style={{
        paddingLeft: indent + 4,
        ...style,
      }}
      className={cn(
        "w-full flex items-center gap-1.5 pr-2 py-[3px] text-left transition-colors group relative",
        "hover:bg-[#131721]/40",
        isActive && "bg-[#131721]/60",
      )}
      title={file.path}
    >
      {/* Active file gold left accent */}
      {isActive && !file.isDirectory && (
        <div className="absolute left-0 top-0 bottom-0 w-[2px] bg-[#d4a84b]" />
      )}

      {/* Connector line segment */}
      {file.depth > 0 && (
        <div
          className="absolute top-0 bottom-0 border-l border-[#2d3240]/30"
          style={{ left: (file.depth - 1) * 16 + 11 }}
        />
      )}

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

      {/* Icon: folder or colored dot */}
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
        <span
          className="shrink-0 w-[7px] h-[7px] rounded-full"
          style={{ backgroundColor: descriptor.iconColor }}
          aria-label={descriptor.label}
        />
      )}

      {/* Name */}
      <span
        className={cn(
          "text-[11px] font-mono truncate",
          file.isDirectory
            ? "text-[#ece7dc]"
            : isActive
              ? "text-[#ece7dc]"
              : "text-[#6f7f9a]",
        )}
      >
        {file.name}
      </span>
    </button>
  );
}
