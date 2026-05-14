import React, { useMemo, useCallback, useState, useRef } from "react";
import {
  IconFolderOpen,
  IconRefresh,
  IconArrowsMaximize,
  IconArrowsMinimize,
  IconSearch,
  IconFilePlus,
  IconChevronRight,
  IconFolder,
  IconPlus,
} from "@tabler/icons-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { FILE_TYPE_REGISTRY, type FileType } from "@/lib/workbench/file-type-registry";
import type { DetectionProject, ProjectFile, FileStatus } from "@/features/project/stores/project-store";
import { getProjectFileStatusKey } from "@/features/project/stores/project-store";
import { ExplorerTreeItem } from "./explorer-tree-item";
import { ExplorerContextMenu, type ContextMenuTarget } from "./explorer-context-menu";
import { DeleteConfirmDialog } from "./delete-confirm-dialog";
import { InlineNameInput } from "./inline-name-input";
import { cn } from "@/lib/utils";

// ---- Types ----

interface ExplorerPanelProps {
  /** Array of mounted workspace roots (multi-root support). */
  projects: DetectionProject[];
  onToggleDir: (rootPath: string, dirPath: string) => void;
  onOpenFile: (rootPath: string, file: ProjectFile) => void;
  onExpandAll: () => void;
  onCollapseAll: () => void;
  filter: string;
  onFilterChange: (filter: string) => void;
  formatFilter: FileType | null;
  onFormatFilterChange: (format: FileType | null) => void;
  onRefresh?: () => void;
  /** Callback to open native folder picker and mount a new root. */
  onAddFolder?: () => void;
  /** Callback to remove a mounted root from the workspace. */
  onRemoveRoot?: (rootPath: string) => void;
  activeFileKey?: string | null;
  className?: string;
  onCreateFile?: (parentPath: string, fileName: string) => void;
  onRenameFile?: (rootPath: string, file: ProjectFile, newName: string) => void;
  onDeleteFile?: (rootPath: string, file: ProjectFile) => void;
  fileStatuses?: Map<string, FileStatus>;
  onRevealInFinder?: (absolutePath: string) => void;
  onCreateFolder?: (parentPath: string, folderName: string) => void;
  onCollapseChildren?: (rootPath: string, dirPath: string) => void;
  onRefreshRoot?: (rootPath: string) => void;
}

interface DeleteTarget {
  rootPath: string;
  file: ProjectFile;
}

// ---- Filter logic ----

const ALL_FILE_TYPES: FileType[] = [
  "clawdstrike_policy",
  "sigma_rule",
  "yara_rule",
  "ocsf_event",
  "swarm_bundle",
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

// ---- Format filter toggle pill ----

function FormatToggle({
  fileType,
  active,
  count,
  onClick,
}: {
  fileType: FileType;
  active: boolean;
  count: number;
  onClick: () => void;
}) {
  const descriptor = FILE_TYPE_REGISTRY[fileType];

  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-mono leading-tight transition-all shrink-0 border",
        active
          ? "text-white shadow-sm"
          : "bg-transparent hover:opacity-80",
      )}
      style={{
        backgroundColor: active ? descriptor.iconColor : "transparent",
        borderColor: active ? descriptor.iconColor : `${descriptor.iconColor}40`,
        color: active ? "#ffffff" : descriptor.iconColor,
      }}
    >
      <span>{descriptor.shortLabel}</span>
      <span className={active ? "opacity-80" : "opacity-60"}>({count})</span>
    </button>
  );
}

// ---- Single-root tree section (extracted for reuse) ----

function RootTreeSection({
  project,
  filter,
  formatFilter,
  onToggleDir,
  onOpenFile,
  activeFileKey,
  fileStatuses,
  onCreateFile,
  onRenameFile,
  creatingInDir,
  setCreatingInDir,
  renamingFileKey,
  setRenamingFileKey,
  setContextMenu,
  setDeleteTarget,
}: {
  project: DetectionProject;
  filter: string;
  formatFilter: FileType | null;
  onToggleDir: (rootPath: string, dirPath: string) => void;
  onOpenFile: (rootPath: string, file: ProjectFile) => void;
  activeFileKey?: string | null;
  fileStatuses?: Map<string, FileStatus>;
  onCreateFile?: (parentPath: string, fileName: string) => void;
  onRenameFile?: (rootPath: string, file: ProjectFile, newName: string) => void;
  creatingInDir: string | null;
  setCreatingInDir: (dir: string | null) => void;
  renamingFileKey: string | null;
  setRenamingFileKey: (path: string | null) => void;
  setContextMenu: (menu: ContextMenuTarget | null) => void;
  setDeleteTarget: (target: DeleteTarget | null) => void;
}) {
  const filteredFiles = useMemo(() => {
    if (!filter && !formatFilter) return project.files;
    return filterTree(project.files, filter, formatFilter);
  }, [project.files, filter, formatFilter]);

  const visibleItems = useMemo(() => {
    return flattenTree(filteredFiles, project.expandedDirs);
  }, [filteredFiles, project.expandedDirs]);

  if (visibleItems.length === 0 && creatingInDir === null) {
    return (
      <div className="flex flex-col items-center justify-center py-4 text-center">
        <p className="text-[10px] font-mono text-[#6f7f9a]/50">
          {filter || formatFilter
            ? "No files match the current filter"
            : "No detection files found"}
        </p>
      </div>
    );
  }

  // Resolve creatingInDir to a relative path for matching against the tree.
  const creatingInRelDir =
    creatingInDir === null
      ? null
      : creatingInDir === project.rootPath
        ? ""
        : creatingInDir.startsWith(project.rootPath + "/")
          ? creatingInDir.slice(project.rootPath.length + 1)
          : creatingInDir;

  // Determine the depth for the inline input.
  const inputDepth = creatingInRelDir === null
    ? 0
    : creatingInRelDir === ""
      ? 0
      : creatingInRelDir.split("/").filter(Boolean).length;

  const renderInlineInput = () => (
    <div className="py-1" style={{ paddingLeft: inputDepth * 16 + 4 }}>
      <InlineNameInput
        placeholder="filename.yaml"
        onSubmit={(name) => {
          onCreateFile?.(creatingInDir!, name);
          setCreatingInDir(null);
        }}
        onCancel={() => setCreatingInDir(null)}
      />
    </div>
  );

  // For root-level creation, render input at the top.
  const isRootCreation = creatingInRelDir === "";

  const items: React.ReactNode[] = [];

  if (creatingInDir !== null && isRootCreation) {
    items.push(
      <React.Fragment key="__new-file-input">{renderInlineInput()}</React.Fragment>,
    );
  }

  for (let i = 0; i < visibleItems.length; i++) {
    const file = visibleItems[i];
    const fileKey = getProjectFileStatusKey(project.rootPath, file.path);
    const status = fileStatuses?.get(fileKey);
    items.push(
      <ExplorerTreeItem
        key={file.path}
        file={file}
        isExpanded={project.expandedDirs.has(file.path)}
        onToggle={() => onToggleDir(project.rootPath, file.path)}
        onOpen={() => onOpenFile(project.rootPath, file)}
        isActive={
          !file.isDirectory && activeFileKey === fileKey
        }
        onContextMenu={(e) => {
          e.preventDefault();
          setContextMenu({
            targetType: file.isDirectory ? "folder" : "file",
            file,
            rootPath: project.rootPath,
            x: e.clientX,
            y: e.clientY,
          });
        }}
        isRenaming={renamingFileKey === fileKey}
        onRenameSubmit={(newName) => {
          onRenameFile?.(project.rootPath, file, newName);
          setRenamingFileKey(null);
        }}
        onRenameCancel={() => setRenamingFileKey(null)}
        onStartRename={() => setRenamingFileKey(fileKey)}
        isModified={status?.modified}
        hasError={status?.hasError}
      />,
    );

    // Render inline input after the target directory's children.
    if (
      creatingInDir !== null &&
      !isRootCreation &&
      creatingInRelDir !== null
    ) {
      const isTargetOrChild =
        file.path === creatingInRelDir ||
        file.path.startsWith(creatingInRelDir + "/");
      const nextFile = visibleItems[i + 1];
      const nextIsChild =
        nextFile?.path.startsWith(creatingInRelDir + "/");

      if (isTargetOrChild && !nextIsChild) {
        items.push(
          <React.Fragment key="__new-file-input">{renderInlineInput()}</React.Fragment>,
        );
      }
    }
  }

  return <>{items}</>;
}

// ---- Component ----

export function ExplorerPanel({
  projects,
  onToggleDir,
  onOpenFile,
  onExpandAll,
  onCollapseAll,
  filter,
  onFilterChange,
  formatFilter,
  onFormatFilterChange,
  onRefresh,
  onAddFolder,
  onRemoveRoot,
  activeFileKey,
  className,
  onCreateFile,
  onRenameFile,
  onDeleteFile,
  fileStatuses,
  onRevealInFinder,
  onCreateFolder,
  onCollapseChildren,
  onRefreshRoot,
}: ExplorerPanelProps) {
  // Context menu state (discriminated union: root | file | folder)
  const [contextMenu, setContextMenu] = useState<ContextMenuTarget | null>(null);
  // Inline new-file creation state: the directory path where a file is being created.
  const [creatingInDir, setCreatingInDir] = useState<string | null>(null);
  // Inline folder creation state: the parent directory path where a folder is being created.
  const [creatingFolderInDir, setCreatingFolderInDir] = useState<string | null>(null);
  // Inline rename state: which file path is being renamed.
  const [renamingFileKey, setRenamingFileKey] = useState<string | null>(null);
  // Delete confirmation dialog state.
  const [deleteTarget, setDeleteTarget] = useState<DeleteTarget | null>(null);
  // Track which root sections are expanded (all expanded by default).
  const [expandedRoots, setExpandedRoots] = useState<Set<string>>(
    () => new Set(projects.map((p) => p.rootPath)),
  );

  // Whether initial auto-expand has already been applied.
  const autoExpandApplied = useRef(false);

  // Auto-expand all roots on the very first mount only.
  const expandedRootsResolved = useMemo(() => {
    if (!autoExpandApplied.current) {
      autoExpandApplied.current = true;
      const initial = new Set(expandedRoots);
      for (const p of projects) {
        initial.add(p.rootPath);
      }
      return initial;
    }
    return expandedRoots;
  }, [projects, expandedRoots]);

  const toggleRootExpanded = useCallback((rootPath: string) => {
    setExpandedRoots((prev) => {
      const next = new Set(prev);
      if (next.has(rootPath)) {
        next.delete(rootPath);
      } else {
        next.add(rootPath);
      }
      return next;
    });
  }, []);

  const handleFormatClick = useCallback(
    (ft: FileType) => {
      onFormatFilterChange(formatFilter === ft ? null : ft);
    },
    [formatFilter, onFormatFilterChange],
  );

  // Total file count across all roots.
  const totalFileCount = useMemo(() => {
    return projects.reduce((sum, p) => sum + countFiles(p.files), 0);
  }, [projects]);

  // File counts grouped by type across all roots.
  const fileCountsByType = useMemo(() => {
    return countFilesByType(projects);
  }, [projects]);

  // ---- Empty state ----
  if (projects.length === 0) {
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

        {/* Hero empty state */}
        <div className="flex-1 flex flex-col items-center justify-center p-6 text-center gap-4">
          <IconFolderOpen
            size={48}
            stroke={0.8}
            className="text-[#6f7f9a]/20"
          />
          <div className="space-y-1.5">
            <p className="text-[13px] font-mono text-[#ece7dc]/70 font-medium">
              No folder open
            </p>
            <p className="text-[10px] font-mono text-[#6f7f9a]/50 leading-relaxed max-w-[180px]">
              Open a folder containing detection rules to get started.
            </p>
          </div>
          {onAddFolder && (
            <button
              type="button"
              onClick={onAddFolder}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-mono text-[#6f7f9a]/60 hover:text-[#ece7dc] transition-colors"
            >
              <IconPlus size={12} stroke={1.5} />
              Add Folder to Workspace
            </button>
          )}
        </div>
      </div>
    );
  }

  // Convenience: for single root, use the first project as backward-compat reference.
  const firstProject = projects[0];
  const isMultiRoot = projects.length > 1;

  // ---- Active project(s) ----
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
            <button
              type="button"
              onClick={() => firstProject && setCreatingInDir(firstProject.rootPath)}
              title="New File"
              className="p-1 rounded text-[#6f7f9a]/60 hover:text-[#ece7dc] hover:bg-[#131721]/40 transition-colors"
            >
              <IconFilePlus size={12} stroke={1.5} />
            </button>
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

        {/* Format filter toggles */}
        <div className="flex items-center gap-1.5 flex-wrap">
          {ALL_FILE_TYPES.map((ft) => (
            <FormatToggle
              key={ft}
              fileType={ft}
              active={formatFilter === ft}
              count={fileCountsByType[ft]}
              onClick={() => handleFormatClick(ft)}
            />
          ))}
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

      {/* Single-root: collapsible project name header with item count */}
      {!isMultiRoot && (
        <div
          className="shrink-0 flex items-center gap-1.5 px-3 py-1.5 border-b border-[#2d3240]/50 cursor-pointer hover:bg-[#131721]/20"
          onClick={() => toggleRootExpanded(firstProject.rootPath)}
          onContextMenu={(e) => {
            e.preventDefault();
            setContextMenu({
              targetType: "root",
              rootPath: firstProject.rootPath,
              rootName: firstProject.name,
              x: e.clientX,
              y: e.clientY,
            });
          }}
        >
          <IconChevronRight
            size={10}
            stroke={1.5}
            className={cn(
              "text-[#6f7f9a]/60 transition-transform",
              expandedRootsResolved.has(firstProject.rootPath) && "rotate-90",
            )}
          />
          <span className="text-[10px] font-mono font-semibold text-[#ece7dc]/80 truncate">
            {firstProject.name}
          </span>
          <span className="text-[9px] font-mono text-[#6f7f9a]/40 ml-0.5">
            ({countFiles(firstProject.files)})
          </span>
        </div>
      )}

      {/* Tree */}
      <ScrollArea className="flex-1">
        <div className="py-1">
          {isMultiRoot ? (
            // Multi-root: render each root as a collapsible section
            projects.map((project) => {
              const isExpanded = expandedRootsResolved.has(project.rootPath);
              return (
                <div key={project.rootPath}>
                  {/* Root section header */}
                  <div
                    className="flex items-center gap-1.5 px-3 py-1.5 border-b border-[#2d3240]/50 cursor-pointer hover:bg-[#131721]/20"
                    onClick={() => toggleRootExpanded(project.rootPath)}
                    onContextMenu={(e) => {
                      e.preventDefault();
                      setContextMenu({
                        targetType: "root",
                        rootPath: project.rootPath,
                        rootName: project.name,
                        x: e.clientX,
                        y: e.clientY,
                      });
                    }}
                  >
                    <IconChevronRight
                      size={10}
                      stroke={1.5}
                      className={cn(
                        "text-[#6f7f9a]/60 transition-transform",
                        isExpanded && "rotate-90",
                      )}
                    />
                    <IconFolder size={12} stroke={1.5} className="text-[#6f7f9a]" />
                    <span className="text-[10px] font-mono font-semibold text-[#ece7dc]/80 truncate flex-1">
                      {project.name}
                    </span>
                    <span className="text-[9px] font-mono text-[#6f7f9a]/40">
                      ({countFiles(project.files)})
                    </span>
                  </div>
                  {/* Root section tree content */}
                  {isExpanded && (
                    <RootTreeSection
                      project={project}
                      filter={filter}
                      formatFilter={formatFilter}
                      onToggleDir={onToggleDir}
                      onOpenFile={onOpenFile}
                      activeFileKey={activeFileKey}
                      fileStatuses={fileStatuses}
                      onCreateFile={onCreateFile}
                      onRenameFile={onRenameFile}
                      creatingInDir={creatingInDir}
                      setCreatingInDir={setCreatingInDir}
                      renamingFileKey={renamingFileKey}
                      setRenamingFileKey={setRenamingFileKey}
                      setContextMenu={setContextMenu}
                      setDeleteTarget={setDeleteTarget}
                    />
                  )}
                </div>
              );
            })
          ) : (
            // Single-root: render tree only when root is expanded
            expandedRootsResolved.has(firstProject.rootPath) && (
              <RootTreeSection
                project={firstProject}
                filter={filter}
                formatFilter={formatFilter}
                onToggleDir={onToggleDir}
                onOpenFile={onOpenFile}
                activeFileKey={activeFileKey}
                fileStatuses={fileStatuses}
                onCreateFile={onCreateFile}
                onRenameFile={onRenameFile}
                creatingInDir={creatingInDir}
                setCreatingInDir={setCreatingInDir}
                renamingFileKey={renamingFileKey}
                setRenamingFileKey={setRenamingFileKey}
                setContextMenu={setContextMenu}
                setDeleteTarget={setDeleteTarget}
              />
            )
          )}
        </div>

        {/* Add Folder button at bottom of tree area */}
        {onAddFolder && (
          <button
            type="button"
            onClick={onAddFolder}
            className="flex items-center gap-1.5 w-full px-3 py-2 text-[10px] font-mono text-[#6f7f9a]/60 hover:text-[#ece7dc] hover:bg-[#131721]/40 transition-colors border-t border-[#2d3240]/30"
          >
            <IconPlus size={12} stroke={1.5} />
            Add Folder
          </button>
        )}
      </ScrollArea>

      {/* Context menu overlay */}
      {contextMenu && (
        <ExplorerContextMenu
          target={contextMenu}
          onClose={() => setContextMenu(null)}
          onNewFile={(dirPath) => {
            setCreatingInDir(dirPath);
            setContextMenu(null);
          }}
          onOpen={(file) => {
            onOpenFile(contextMenu.rootPath, file);
            setContextMenu(null);
          }}
          onRename={(file) => {
            setRenamingFileKey(getProjectFileStatusKey(contextMenu.rootPath, file.path));
            setContextMenu(null);
          }}
          onDelete={(file) => {
            setDeleteTarget({ rootPath: contextMenu.rootPath, file });
            setContextMenu(null);
          }}
          onRevealInFinder={(absPath) => {
            onRevealInFinder?.(absPath);
            setContextMenu(null);
          }}
          onRemoveRoot={(rootPath) => {
            onRemoveRoot?.(rootPath);
            setContextMenu(null);
          }}
          onRefreshRoot={(rootPath) => {
            onRefreshRoot?.(rootPath);
            setContextMenu(null);
          }}
          onCollapseChildren={(rootPath, dirPath) => {
            onCollapseChildren?.(rootPath, dirPath);
            setContextMenu(null);
          }}
          onNewFolder={(dirPath) => {
            setCreatingFolderInDir(dirPath);
            setContextMenu(null);
          }}
        />
      )}

      {/* Inline folder creation input */}
      {creatingFolderInDir && (
        <div className="fixed z-[100] top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-[#131721] border border-[#2d3240] rounded-md shadow-xl p-3 min-w-[220px]">
          <p className="text-[10px] font-mono text-[#6f7f9a] mb-2">New Folder</p>
          <InlineNameInput
            placeholder="folder-name"
            onSubmit={(name) => {
              onCreateFolder?.(creatingFolderInDir, name);
              setCreatingFolderInDir(null);
            }}
            onCancel={() => setCreatingFolderInDir(null)}
          />
        </div>
      )}

      {/* Footer status bar */}
      <div className="shrink-0 px-3 py-1.5 border-t border-[#2d3240] flex items-center gap-2">
        <span className="text-[9px] font-mono text-[#6f7f9a]/40">
          {formatFilter
            ? `${fileCountsByType[formatFilter]} ${fileCountsByType[formatFilter] === 1 ? "file" : "files"}`
            : `${totalFileCount} ${totalFileCount === 1 ? "file" : "files"}`}
        </span>
        {isMultiRoot && (
          <span className="text-[9px] font-mono text-[#6f7f9a]/30">
            {projects.length} roots
          </span>
        )}
      </div>

      {/* Delete confirmation dialog */}
      <DeleteConfirmDialog
        file={deleteTarget?.file ?? null}
        open={deleteTarget !== null}
        onConfirm={() => {
          if (deleteTarget) {
            onDeleteFile?.(deleteTarget.rootPath, deleteTarget.file);
          }
          setDeleteTarget(null);
        }}
        onCancel={() => setDeleteTarget(null)}
      />
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

/** Count files grouped by FileType across all project roots. */
function countFilesByType(projects: DetectionProject[]): Record<FileType, number> {
  const counts: Record<FileType, number> = {
    clawdstrike_policy: 0,
    sigma_rule: 0,
    yara_rule: 0,
    ocsf_event: 0,
    swarm_bundle: 0,
  };
  function walk(files: ProjectFile[]) {
    for (const f of files) {
      if (f.isDirectory) {
        if (f.children) walk(f.children);
      } else {
        counts[f.fileType] += 1;
      }
    }
  }
  for (const p of projects) {
    walk(p.files);
  }
  return counts;
}
