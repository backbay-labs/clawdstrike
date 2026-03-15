import { useMemo, useCallback } from "react";
import {
  IconFolderOpen,
  IconRefresh,
  IconArrowsMaximize,
  IconArrowsMinimize,
  IconSearch,
} from "@tabler/icons-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { FILE_TYPE_REGISTRY, type FileType } from "@/lib/workbench/file-type-registry";
import type { DetectionProject, ProjectFile } from "@/lib/workbench/project-store";
import { ExplorerTreeItem } from "./explorer-tree-item";
import { cn } from "@/lib/utils";

// ---- Types ----

interface ExplorerPanelProps {
  project: DetectionProject | null;
  onToggleDir: (path: string) => void;
  onOpenFile: (file: ProjectFile) => void;
  onExpandAll: () => void;
  onCollapseAll: () => void;
  filter: string;
  onFilterChange: (filter: string) => void;
  formatFilter: FileType | null;
  onFormatFilterChange: (format: FileType | null) => void;
  onRefresh?: () => void;
  onOpenFolder?: () => void;
  activeFilePath?: string | null;
  className?: string;
}

// ---- Filter logic ----

const ALL_FILE_TYPES: FileType[] = [
  "clawdstrike_policy",
  "sigma_rule",
  "yara_rule",
  "ocsf_event",
];

/**
 * Recursively filter the file tree by text filter and format filter.
 * Directories are kept if any of their descendants match.
 */
function filterTree(
  files: ProjectFile[],
  textFilter: string,
  formatFilter: FileType | null,
): ProjectFile[] {
  const lowerFilter = textFilter.toLowerCase();

  function matches(file: ProjectFile): boolean {
    if (file.isDirectory) return false;
    const nameMatch = !lowerFilter || file.name.toLowerCase().includes(lowerFilter);
    const formatMatch = !formatFilter || file.fileType === formatFilter;
    return nameMatch && formatMatch;
  }

  function filterNodes(nodes: ProjectFile[]): ProjectFile[] {
    const result: ProjectFile[] = [];

    for (const node of nodes) {
      if (node.isDirectory) {
        const filteredChildren = node.children
          ? filterNodes(node.children)
          : [];
        // Keep directory if it has matching descendants
        if (filteredChildren.length > 0) {
          result.push({ ...node, children: filteredChildren });
        }
      } else if (matches(node)) {
        result.push(node);
      }
    }

    return result;
  }

  return filterNodes(files);
}

/**
 * Flatten the visible tree (respecting expanded directories) into a list
 * for rendering.
 */
function flattenTree(
  files: ProjectFile[],
  expandedDirs: Set<string>,
): ProjectFile[] {
  const result: ProjectFile[] = [];

  function walk(nodes: ProjectFile[]) {
    for (const node of nodes) {
      result.push(node);
      if (node.isDirectory && node.children && expandedDirs.has(node.path)) {
        walk(node.children);
      }
    }
  }

  walk(files);
  return result;
}

// ---- Format filter dot button ----

function FormatDot({
  fileType,
  active,
  onClick,
}: {
  fileType: FileType;
  active: boolean;
  onClick: () => void;
}) {
  const descriptor = FILE_TYPE_REGISTRY[fileType];

  return (
    <button
      type="button"
      onClick={onClick}
      title={`Filter: ${descriptor.shortLabel}`}
      className={cn(
        "w-[14px] h-[14px] rounded-full border transition-all shrink-0",
        active
          ? "scale-110 shadow-sm"
          : "opacity-40 hover:opacity-70",
      )}
      style={{
        backgroundColor: active ? descriptor.iconColor : "transparent",
        borderColor: descriptor.iconColor,
      }}
    />
  );
}

// ---- Component ----

export function ExplorerPanel({
  project,
  onToggleDir,
  onOpenFile,
  onExpandAll,
  onCollapseAll,
  filter,
  onFilterChange,
  formatFilter,
  onFormatFilterChange,
  onRefresh,
  onOpenFolder,
  activeFilePath,
  className,
}: ExplorerPanelProps) {
  // Apply filters to the tree
  const filteredFiles = useMemo(() => {
    if (!project) return [];
    if (!filter && !formatFilter) return project.files;
    return filterTree(project.files, filter, formatFilter);
  }, [project, filter, formatFilter]);

  // Flatten visible portion of the tree
  const visibleItems = useMemo(() => {
    if (!project) return [];
    return flattenTree(filteredFiles, project.expandedDirs);
  }, [filteredFiles, project]);

  const handleFormatClick = useCallback(
    (ft: FileType) => {
      onFormatFilterChange(formatFilter === ft ? null : ft);
    },
    [formatFilter, onFormatFilterChange],
  );

  // ---- Empty state ----
  if (!project) {
    return (
      <div
        className={cn(
          "flex flex-col h-full bg-[#05060a]",
          className,
        )}
      >
        {/* Header */}
        <div className="shrink-0 px-3 py-2.5 border-b border-[#2d3240]">
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a]">
              Explorer
            </span>
          </div>
        </div>

        {/* Empty state content */}
        <div className="flex-1 flex flex-col items-center justify-center p-4 text-center gap-3">
          <IconFolderOpen
            size={28}
            stroke={1}
            className="text-[#6f7f9a]/30"
          />
          <p className="text-[11px] font-mono text-[#6f7f9a]/70 leading-relaxed">
            No project open. Open a folder containing detection rules to browse them here.
          </p>
          {onOpenFolder && (
            <button
              type="button"
              onClick={onOpenFolder}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-mono rounded border border-[#d4a84b]/20 text-[#d4a84b] bg-[#d4a84b]/5 hover:bg-[#d4a84b]/10 transition-colors"
            >
              <IconFolderOpen size={12} stroke={1.5} />
              Open Folder
            </button>
          )}
        </div>
      </div>
    );
  }

  // ---- Active project ----
  return (
    <div
      className={cn(
        "flex flex-col h-full bg-[#05060a]",
        className,
      )}
    >
      {/* Header */}
      <div className="shrink-0 px-3 py-2.5 border-b border-[#2d3240]">
        <div className="flex items-center gap-1.5 mb-2">
          <span className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a]">
            Explorer
          </span>

          {/* Toolbar */}
          <div className="ml-auto flex items-center gap-0.5">
            {onRefresh && (
              <button
                type="button"
                onClick={onRefresh}
                title="Refresh"
                className="p-1 rounded text-[#6f7f9a]/60 hover:text-[#ece7dc] hover:bg-[#131721]/40 transition-colors"
              >
                <IconRefresh size={12} stroke={1.5} />
              </button>
            )}
            <button
              type="button"
              onClick={onExpandAll}
              title="Expand All"
              className="p-1 rounded text-[#6f7f9a]/60 hover:text-[#ece7dc] hover:bg-[#131721]/40 transition-colors"
            >
              <IconArrowsMaximize size={12} stroke={1.5} />
            </button>
            <button
              type="button"
              onClick={onCollapseAll}
              title="Collapse All"
              className="p-1 rounded text-[#6f7f9a]/60 hover:text-[#ece7dc] hover:bg-[#131721]/40 transition-colors"
            >
              <IconArrowsMinimize size={12} stroke={1.5} />
            </button>
          </div>
        </div>

        {/* Search input */}
        <div className="relative mb-2">
          <IconSearch
            size={11}
            stroke={1.5}
            className="absolute left-2 top-1/2 -translate-y-1/2 text-[#6f7f9a]/40 pointer-events-none"
          />
          <input
            type="text"
            value={filter}
            onChange={(e) => onFilterChange(e.target.value)}
            placeholder="Filter files..."
            className="w-full bg-[#0b0d13] border border-[#2d3240] rounded text-[11px] font-mono text-[#ece7dc] pl-7 pr-2 py-1 outline-none transition-colors placeholder:text-[#6f7f9a]/40 focus:border-[#d4a84b]/40"
          />
        </div>

        {/* Format filter dots */}
        <div className="flex items-center gap-2">
          <span className="text-[9px] font-mono text-[#6f7f9a]/40 uppercase tracking-wide">
            File type
          </span>
          <div className="flex items-center gap-1.5">
            {ALL_FILE_TYPES.map((ft) => (
              <FormatDot
                key={ft}
                fileType={ft}
                active={formatFilter === ft}
                onClick={() => handleFormatClick(ft)}
              />
            ))}
          </div>
          {formatFilter && (
            <button
              type="button"
              onClick={() => onFormatFilterChange(null)}
              className="text-[8px] font-mono text-[#6f7f9a]/50 hover:text-[#ece7dc] transition-colors ml-auto"
            >
              clear
            </button>
          )}
        </div>
      </div>

      {/* Project name */}
      <div className="shrink-0 px-3 py-1.5 border-b border-[#2d3240]/50">
        <span className="text-[10px] font-mono font-semibold text-[#ece7dc]/80 truncate">
          {project.name}
        </span>
      </div>

      {/* Tree */}
      <ScrollArea className="flex-1">
        <div className="py-1">
          {visibleItems.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-center">
              <p className="text-[10px] font-mono text-[#6f7f9a]/50">
                {filter || formatFilter
                  ? "No files match the current filter"
                  : "No detection files found"}
              </p>
            </div>
          ) : (
            visibleItems.map((file) => (
              <ExplorerTreeItem
                key={file.path}
                file={file}
                isExpanded={project.expandedDirs.has(file.path)}
                onToggle={() => onToggleDir(file.path)}
                onOpen={() => onOpenFile(file)}
                isActive={
                  !file.isDirectory && activeFilePath === file.path
                }
              />
            ))
          )}
        </div>
      </ScrollArea>

      {/* Footer status bar */}
      <div className="shrink-0 px-3 py-1.5 border-t border-[#2d3240] flex items-center gap-2">
        <span className="text-[9px] font-mono text-[#6f7f9a]/40">
          {countFiles(project.files)} files
        </span>
        {formatFilter && (
          <span
            className="text-[9px] font-mono"
            style={{ color: FILE_TYPE_REGISTRY[formatFilter].iconColor }}
          >
            {FILE_TYPE_REGISTRY[formatFilter].shortLabel}
          </span>
        )}
      </div>
    </div>
  );
}

/** Count total non-directory files in the tree. */
function countFiles(files: ProjectFile[]): number {
  let count = 0;
  for (const f of files) {
    if (f.isDirectory) {
      count += f.children ? countFiles(f.children) : 0;
    } else {
      count += 1;
    }
  }
  return count;
}
