import React, { useMemo, useCallback, useState, useRef, useEffect } from "react";
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
import type {
  DetectionProject,
  ProjectFile,
  FileStatus,
  ProjectMutationState,
  ProjectRootStatus,
} from "@/features/project/stores/project-store";
import { getProjectFileStatusKey } from "@/features/project/stores/project-store";
import { ExplorerTreeItem } from "./explorer-tree-item";
import { ExplorerContextMenu, type ContextMenuTarget } from "./explorer-context-menu";
import { DeleteConfirmDialog } from "./delete-confirm-dialog";
import { InlineNameInput } from "./inline-name-input";
import { cn } from "@/lib/utils";
import type {
  TauriWorkspaceRootKind,
  TauriWorkspaceRootProvenance,
} from "@/lib/tauri-commands";

// ---- Types ----

interface ExplorerPanelProps {
  /** Array of mounted workspace roots (multi-root support). */
  projects: DetectionProject[];
  rootStates?: Map<string, ExplorerRootState>;
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

export interface ExplorerRootState {
  status: ProjectRootStatus;
  error: string | null;
  mutation?: ProjectMutationState | null;
  isDefault?: boolean;
  label?: string;
  kind?: TauriWorkspaceRootKind;
  provenance?: TauriWorkspaceRootProvenance;
}

interface CuratedRootSections {
  primaryFiles: ProjectFile[];
  secondaryFiles: ProjectFile[];
  secondaryUnderlyingCount: number;
}

interface RootRenderModel {
  hasActiveFilter: boolean;
  shouldUseCuratedSections: boolean;
  primaryVisibleItems: ProjectFile[];
  secondaryVisibleItems: ProjectFile[];
  primaryHiddenCount: number;
  secondaryHiddenCount: number;
  primaryUnderlyingCount: number;
  secondaryUnderlyingCount: number;
}

type ExplorerVisibleNodeKind = "root" | "directory" | "file";

interface ExplorerVisibleNode {
  id: string;
  parentId: string | null;
  rootPath: string;
  rootName: string;
  kind: ExplorerVisibleNodeKind;
  level: number;
  label: string;
  file?: ProjectFile;
  isExpanded: boolean;
  hasChildren: boolean;
}

// ---- Filter logic ----

const ALL_FILE_TYPES: FileType[] = [
  "clawdstrike_policy",
  "sigma_rule",
  "yara_rule",
  "ocsf_event",
  "swarm_bundle",
];

const DEFAULT_RENDERED_TREE_ROWS = 200;
const RENDERED_TREE_ROW_INCREMENT = 200;

function getRootStatusLabel(status: ProjectRootStatus): string | null {
  switch (status) {
    case "loading":
      return "Indexing";
    case "refreshing":
      return "Refreshing";
    case "empty":
      return "Empty";
    case "stale":
      return "Stale";
    case "error":
      return "Error";
    default:
      return null;
  }
}

function getRootEmptyMessage(
  status: ProjectRootStatus,
  hasActiveFilter: boolean,
  hasUnderlyingFiles: boolean,
): { title: string; detail?: string } {
  if (hasActiveFilter && hasUnderlyingFiles) {
    return { title: "No matching files" };
  }

  switch (status) {
    case "loading":
      return {
        title: "Indexing workspace...",
        detail: "Scanning files from disk.",
      };
    case "refreshing":
      return {
        title: "Refreshing workspace...",
        detail: "Syncing the latest filesystem state.",
      };
    case "stale":
      return {
        title: "Refresh failed",
        detail: "Showing the last successful tree.",
      };
    case "error":
      return {
        title: "Workspace unavailable",
        detail: "The initial scan did not complete.",
      };
    default:
      return { title: "No files yet" };
  }
}

function RootStatusBadge({ rootState }: { rootState?: ExplorerRootState }) {
  if (!rootState) return null;
  const label = getRootStatusLabel(rootState.status);
  if (!label) return null;

  let className = "text-[8px] font-mono uppercase tracking-[0.16em] px-1.5 py-0.5 rounded border ";
  switch (rootState.status) {
    case "loading":
    case "refreshing":
      className += "text-[#d4a84b] border-[#d4a84b]/40 bg-[#d4a84b]/10";
      break;
    case "empty":
      className += "text-[#6f7f9a] border-[#2d3240] bg-[#11151d]";
      break;
    case "stale":
      className += "text-[#f39c6b] border-[#f39c6b]/40 bg-[#f39c6b]/10";
      break;
    case "error":
      className += "text-[#e77b72] border-[#e77b72]/40 bg-[#e77b72]/10";
      break;
    default:
      return null;
  }

  return <span className={className}>{label}</span>;
}

function getRootDisplayLabel(
  project: DetectionProject,
  rootState?: ExplorerRootState,
): string {
  if (rootState?.isDefault || rootState?.kind === "default_home") {
    return "Workspace";
  }
  return rootState?.label ?? project.name;
}

function formatMutationVerb(kind: ProjectMutationState["kind"]): string {
  switch (kind) {
    case "create_file":
      return "Create";
    case "create_folder":
      return "Create folder";
    case "rename":
      return "Rename";
    case "delete":
      return "Delete";
    default:
      return "Sync";
  }
}

function getMutationBannerTitle(mutation: ProjectMutationState): string {
  const label = mutation.targetLabel || mutation.targetRelativePath || "selection";
  if (mutation.status === "pending") {
    return `${formatMutationVerb(mutation.kind)} pending for ${label}`;
  }
  return `${formatMutationVerb(mutation.kind)} needs review for ${label}`;
}

function getMutationBannerDetail(mutation: ProjectMutationState): string {
  if (mutation.message) {
    return mutation.message;
  }
  if (mutation.status === "pending") {
    return "Waiting for the next workspace refresh to confirm the filesystem state.";
  }
  return "Retry the root refresh to reconcile the explorer with disk.";
}

function getMutationRowBadge(mutation: ProjectMutationState): { label: string; tone: "pending" | "error" } {
  return mutation.status === "pending"
    ? { label: "Pending", tone: "pending" }
    : { label: "Retry", tone: "error" };
}

function getRenderSectionKey(rootPath: string, section: "primary" | "secondary"): string {
  return `${rootPath}::${section}`;
}

function resolveImportantVisibleIndex(
  project: DetectionProject,
  items: ProjectFile[],
  options: {
    activeFileKey?: string | null;
    renamingFileKey?: string | null;
    mutationRelativePath?: string | null;
  },
): number {
  let importantIndex = -1;
  for (let index = 0; index < items.length; index += 1) {
    const item = items[index];
    const itemKey = getProjectFileStatusKey(project.rootPath, item.path);
    if (
      itemKey === options.activeFileKey
      || itemKey === options.renamingFileKey
      || item.path === options.mutationRelativePath
    ) {
      importantIndex = index;
    }
  }
  return importantIndex;
}

function applyRenderBound(
  items: ProjectFile[],
  limit: number,
  importantIndex: number,
): { renderedItems: ProjectFile[]; hiddenCount: number } {
  const effectiveLimit = Math.min(
    items.length,
    Math.max(limit, importantIndex >= 0 ? importantIndex + 1 : 0),
  );
  return {
    renderedItems: items.slice(0, effectiveLimit),
    hiddenCount: Math.max(0, items.length - effectiveLimit),
  };
}

function renderShowMoreButton(
  hiddenCount: number,
  onClick: () => void,
): React.ReactNode {
  if (hiddenCount <= 0) {
    return null;
  }

  return (
    <div className="px-3 py-2">
      <button
        type="button"
        onClick={onClick}
        className="w-full rounded border border-[#2d3240] bg-[#0c1017] px-2.5 py-1.5 text-left text-[9px] font-mono uppercase tracking-[0.16em] text-[#6f7f9a]/70 transition-colors hover:border-[#d4a84b]/30 hover:text-[#ece7dc]"
      >
        Show {Math.min(hiddenCount, RENDERED_TREE_ROW_INCREMENT)} More Rows
        <span className="ml-1 text-[#6f7f9a]/45">({hiddenCount} hidden)</span>
      </button>
    </div>
  );
}

function RootBannerCard({
  toneClass,
  title,
  detail,
  rootPath,
  onRefreshRoot,
  onRevealInFinder,
}: {
  toneClass: string;
  title: string;
  detail: string;
  rootPath: string;
  onRefreshRoot?: (rootPath: string) => void;
  onRevealInFinder?: (absolutePath: string) => void;
}) {
  return (
    <div className={cn("mx-3 mt-2 rounded border px-2.5 py-2", toneClass)}>
      <div className="flex items-start gap-3">
        <div className="min-w-0 flex-1">
          <p className="text-[10px] font-mono">{title}</p>
          <p className="mt-1 text-[9px] font-mono opacity-80">{detail}</p>
        </div>
        <div className="flex shrink-0 items-center gap-1">
          {onRefreshRoot && (
            <button
              type="button"
              onClick={() => onRefreshRoot(rootPath)}
              className="rounded border border-current/20 px-1.5 py-1 text-[8px] font-mono uppercase tracking-[0.16em] opacity-80 transition-opacity hover:opacity-100"
            >
              Refresh
            </button>
          )}
          {onRevealInFinder && (
            <button
              type="button"
              onClick={() => onRevealInFinder(rootPath)}
              className="rounded border border-current/20 px-1.5 py-1 text-[8px] font-mono uppercase tracking-[0.16em] opacity-80 transition-opacity hover:opacity-100"
            >
              Reveal
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function RootStatusBanner({
  rootPath,
  rootState,
  onRefreshRoot,
  onRevealInFinder,
}: {
  rootPath: string;
  rootState?: ExplorerRootState;
  onRefreshRoot?: (rootPath: string) => void;
  onRevealInFinder?: (absolutePath: string) => void;
}) {
  if (!rootState) return null;

  const banners: React.ReactNode[] = [];

  if (rootState.mutation) {
    banners.push(
      <RootBannerCard
        key="mutation"
        rootPath={rootPath}
        onRefreshRoot={onRefreshRoot}
        onRevealInFinder={onRevealInFinder}
        toneClass={
          rootState.mutation.status === "pending"
            ? "border-[#d4a84b]/30 bg-[#20180b] text-[#f1d089]"
            : "border-[#e77b72]/30 bg-[#241012] text-[#f2b8b3]"
        }
        title={getMutationBannerTitle(rootState.mutation)}
        detail={getMutationBannerDetail(rootState.mutation)}
      />,
    );
  }

  if (rootState.status === "refreshing" || rootState.status === "stale" || rootState.status === "error") {
    let toneClass = "border-[#2d3240]/60 bg-[#10131a] text-[#6f7f9a]";
    let title = "Refreshing workspace";
    let detail = "Syncing the latest filesystem state.";

    if (rootState.status === "stale") {
      toneClass = "border-[#f39c6b]/30 bg-[#261910] text-[#f6c7a8]";
      title = "Refresh failed";
      detail = rootState.error ?? "Showing the last successful tree.";
    } else if (rootState.status === "error") {
      toneClass = "border-[#e77b72]/30 bg-[#241012] text-[#f2b8b3]";
      title = "Workspace unavailable";
      detail = rootState.error ?? "Try refreshing this root.";
    }

    banners.push(
      <RootBannerCard
        key="root-status"
        rootPath={rootPath}
        onRefreshRoot={onRefreshRoot}
        onRevealInFinder={onRevealInFinder}
        toneClass={toneClass}
        title={title}
        detail={detail}
      />,
    );
  }

  return banners.length > 0 ? <>{banners}</> : null;
}

function rebaseProjectFiles(files: ProjectFile[], depthOffset: number): ProjectFile[] {
  if (depthOffset <= 0) return files;
  return files.map((file) => ({
    ...file,
    depth: Math.max(0, file.depth - depthOffset),
    children: file.children ? rebaseProjectFiles(file.children, depthOffset) : undefined,
  }));
}

function buildCuratedRootSections(project: DetectionProject): CuratedRootSections {
  const workspaceDir = project.files.find((file) => file.isDirectory && file.path === "workspace");
  const secondaryFiles = project.files.filter((file) => file.path !== "workspace");
  return {
    primaryFiles: workspaceDir?.children ? rebaseProjectFiles(workspaceDir.children, 1) : [],
    secondaryFiles,
    secondaryUnderlyingCount: countFiles(secondaryFiles),
  };
}

function shouldUseCuratedRootSections(
  project: DetectionProject,
  rootState?: ExplorerRootState,
): boolean {
  if (!rootState?.isDefault && rootState?.kind !== "default_home") {
    return false;
  }
  return project.files.some((file) => file.isDirectory && file.path === "workspace");
}

function getRootNodeId(project: DetectionProject): string {
  return `root:${project.rootId}`;
}

function getFileNodeId(project: DetectionProject, file: ProjectFile): string {
  return `${getRootNodeId(project)}:entry:${file.path}`;
}

function buildRootRenderModel(
  project: DetectionProject,
  rootState: ExplorerRootState | undefined,
  filter: string,
  formatFilter: FileType | null,
): RootRenderModel {
  const hasActiveFilter = Boolean(filter || formatFilter);
  const shouldUseCuratedSections = shouldUseCuratedRootSections(project, rootState);
  const curatedSections = buildCuratedRootSections(project);
  const primaryFiles = shouldUseCuratedSections ? curatedSections.primaryFiles : project.files;
  const secondaryFiles = shouldUseCuratedSections
    ? (filter || formatFilter
        ? filterTree(curatedSections.secondaryFiles, filter, formatFilter)
        : curatedSections.secondaryFiles)
    : [];
  const primaryFilteredFiles = filter || formatFilter
    ? filterTree(primaryFiles, filter, formatFilter)
    : primaryFiles;
  return {
    hasActiveFilter,
    shouldUseCuratedSections,
    primaryVisibleItems: flattenTree(primaryFilteredFiles, project.expandedDirs, hasActiveFilter),
    secondaryVisibleItems: flattenTree(secondaryFiles, project.expandedDirs, hasActiveFilter),
    primaryHiddenCount: 0,
    secondaryHiddenCount: 0,
    primaryUnderlyingCount: countFiles(primaryFiles),
    secondaryUnderlyingCount: curatedSections.secondaryUnderlyingCount,
  };
}

function buildVisibleNodesForItems(
  project: DetectionProject,
  items: ProjectFile[],
  rootNodeId: string,
  depthOffset: number,
  forceExpandAll: boolean,
): ExplorerVisibleNode[] {
  const nodes: ExplorerVisibleNode[] = [];
  const directoryStack: Array<{ nodeId: string }> = [];

  for (const file of items) {
    const adjustedDepth = Math.max(0, file.depth - depthOffset);
    while (directoryStack.length > adjustedDepth) {
      directoryStack.pop();
    }
    const parentId = adjustedDepth === 0
      ? rootNodeId
      : directoryStack[directoryStack.length - 1]?.nodeId ?? rootNodeId;
    const nodeId = getFileNodeId(project, file);
    nodes.push({
      id: nodeId,
      parentId,
      rootPath: project.rootPath,
      rootName: project.name,
      kind: file.isDirectory ? "directory" : "file",
      level: adjustedDepth + 2,
      label: file.name,
      file,
      isExpanded: file.isDirectory ? (forceExpandAll || project.expandedDirs.has(file.path)) : false,
      hasChildren: Boolean(file.children?.length),
    });
    if (file.isDirectory) {
      directoryStack.push({ nodeId });
    }
  }

  return nodes;
}

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
  forceExpandAll = false,
): ProjectFile[] {
  const result: ProjectFile[] = [];

  function walk(nodes: ProjectFile[]) {
    for (const node of nodes) {
      result.push(node);
      if (node.isDirectory && node.children && (forceExpandAll || expandedDirs.has(node.path))) {
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
  rootNodeId,
  project,
  rootState,
  model,
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
  focusedNodeId,
  onFocusNode,
  onKeyDownNode,
  setTreeNodeRef,
  onShowMorePrimary,
  onRefreshRoot,
  onRevealInFinder,
}: {
  rootNodeId: string;
  project: DetectionProject;
  rootState?: ExplorerRootState;
  model: RootRenderModel;
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
  focusedNodeId: string | null;
  onFocusNode: (nodeId: string) => void;
  onKeyDownNode: (e: React.KeyboardEvent<HTMLDivElement>, nodeId: string) => void;
  setTreeNodeRef: (nodeId: string, element: HTMLDivElement | null) => void;
  onShowMorePrimary: () => void;
  onRefreshRoot?: (rootPath: string) => void;
  onRevealInFinder?: (absolutePath: string) => void;
}) {
  const {
    hasActiveFilter,
    shouldUseCuratedSections,
    primaryVisibleItems,
    primaryHiddenCount,
    primaryUnderlyingCount,
  } = model;

  // Resolve creatingInDir to a relative path for matching against the tree.
  const creatingInRelDir =
    creatingInDir === null
      ? null
      : creatingInDir === project.rootPath
        ? ""
        : creatingInDir.startsWith(project.rootPath + "/")
          ? creatingInDir.slice(project.rootPath.length + 1)
          : creatingInDir;

  const renderInlineInput = (depthOffset = 0) => {
    const rawDepth = creatingInRelDir === null
      ? 0
      : creatingInRelDir === ""
        ? 0
        : creatingInRelDir.split("/").filter(Boolean).length;
    const inputDepth = Math.max(0, rawDepth - depthOffset);

    return (
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
  };

  const buildRenderedItems = (
    visibleItems: ProjectFile[],
    depthOffset = 0,
    allowRootCreation = true,
  ): React.ReactNode[] => {
    const isRootCreation = creatingInRelDir === "";
    const items: React.ReactNode[] = [];

    if (creatingInDir !== null && isRootCreation && allowRootCreation) {
      items.push(
        <React.Fragment key={`__new-file-input-root-${depthOffset}`}>
          {renderInlineInput(depthOffset)}
        </React.Fragment>,
      );
    }

    for (let i = 0; i < visibleItems.length; i++) {
      const file = visibleItems[i];
      const fileKey = getProjectFileStatusKey(project.rootPath, file.path);
      const status = fileStatuses?.get(fileKey);
      const rowMutation = rootState?.mutation?.targetRelativePath === file.path
        ? getMutationRowBadge(rootState.mutation)
        : null;
      const nodeId = getFileNodeId(project, file);
      const treeLevel = Math.max(0, file.depth - depthOffset) + 2;
      const isExpanded = file.isDirectory ? (hasActiveFilter || project.expandedDirs.has(file.path)) : false;
      items.push(
        <ExplorerTreeItem
          key={file.path}
          ref={(node) => setTreeNodeRef(nodeId, node)}
          nodeId={nodeId}
          level={treeLevel}
          file={file}
          isExpanded={isExpanded}
          onToggle={() => onToggleDir(project.rootPath, file.path)}
          onOpen={() => onOpenFile(project.rootPath, file)}
          onFocus={() => onFocusNode(nodeId)}
          onKeyDown={(e) => onKeyDownNode(e, nodeId)}
          isActive={!file.isDirectory && activeFileKey === fileKey}
          onContextMenu={(e) => {
            e.preventDefault();
            onFocusNode(nodeId);
            setContextMenu({
              targetType: file.isDirectory ? "folder" : "file",
              file,
              rootPath: project.rootPath,
              x: e.clientX,
              y: e.clientY,
            });
          }}
          tabIndex={focusedNodeId === nodeId ? 0 : -1}
          isRenaming={renamingFileKey === fileKey}
          onRenameSubmit={(newName) => {
            onRenameFile?.(project.rootPath, file, newName);
            setRenamingFileKey(null);
          }}
          onRenameCancel={() => setRenamingFileKey(null)}
          onStartRename={() => setRenamingFileKey(fileKey)}
          isModified={status?.modified}
          hasError={status?.hasError}
          mutationStatus={rowMutation?.tone}
          mutationLabel={rowMutation?.label}
        />,
      );

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
            <React.Fragment key={`__new-file-input-${file.path}`}>
              {renderInlineInput(depthOffset)}
            </React.Fragment>,
          );
        }
      }
    }

    return items;
  };

  if (!shouldUseCuratedSections) {
    const emptyMessage = getRootEmptyMessage(
      rootState?.status ?? "ready",
      hasActiveFilter,
      primaryUnderlyingCount > 0,
    );

    if (primaryVisibleItems.length === 0 && creatingInDir === null) {
      return (
        <div className="flex flex-col items-center justify-center py-4 text-center">
          <p className="text-[10px] font-mono text-[#6f7f9a]/60">{emptyMessage.title}</p>
          {emptyMessage.detail && (
            <p className="mt-1 max-w-[220px] text-[9px] font-mono leading-relaxed text-[#6f7f9a]/40">
              {rootState?.status === "stale" || rootState?.status === "error"
                ? rootState.error ?? emptyMessage.detail
                : emptyMessage.detail}
            </p>
          )}
        </div>
      );
    }

    return (
      <>
        <RootStatusBanner
          rootPath={project.rootPath}
          rootState={rootState}
          onRefreshRoot={onRefreshRoot}
          onRevealInFinder={onRevealInFinder}
        />
        {buildRenderedItems(primaryVisibleItems)}
        {renderShowMoreButton(primaryHiddenCount, onShowMorePrimary)}
      </>
    );
  }

  const workspaceEmptyMessage = getRootEmptyMessage(
    rootState?.status ?? "ready",
    hasActiveFilter,
    primaryUnderlyingCount > 0,
  );

  return (
    <>
      <RootStatusBanner
        rootPath={project.rootPath}
        rootState={rootState}
        onRefreshRoot={onRefreshRoot}
        onRevealInFinder={onRevealInFinder}
      />

      {primaryVisibleItems.length === 0 && creatingInDir === null ? (
        <div className="flex flex-col items-center justify-center px-3 py-4 text-center">
          <p className="text-[11px] text-[#9ca9c0]">{workspaceEmptyMessage.title}</p>
          {workspaceEmptyMessage.detail && (
            <p className="mt-1 max-w-[220px] text-[10px] leading-relaxed text-[#73819a]">
              {rootState?.status === "stale" || rootState?.status === "error"
                ? rootState.error ?? workspaceEmptyMessage.detail
                : workspaceEmptyMessage.detail}
            </p>
          )}
        </div>
      ) : (
        <>
          {buildRenderedItems(primaryVisibleItems, 1)}
          {renderShowMoreButton(primaryHiddenCount, onShowMorePrimary)}
        </>
      )}
    </>
  );
}

// ---- Component ----

export function ExplorerPanel({
  projects,
  rootStates,
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
  const [sectionRenderLimits, setSectionRenderLimits] = useState<Map<string, number>>(() => new Map());

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

  const showMoreSectionRows = useCallback((rootPath: string, section: "primary" | "secondary") => {
    const sectionKey = getRenderSectionKey(rootPath, section);
    setSectionRenderLimits((prev) => {
      const next = new Map(prev);
      next.set(
        sectionKey,
        (next.get(sectionKey) ?? DEFAULT_RENDERED_TREE_ROWS) + RENDERED_TREE_ROW_INCREMENT,
      );
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
  const hasActiveFilter = Boolean(filter || formatFilter);
  const treeRef = useRef<HTMLDivElement>(null);
  const treeNodeRefs = useRef(new Map<string, HTMLDivElement>());
  const treeHasManagedFocus = useRef(false);
  const previousVisibleNodeIdsRef = useRef<string[]>([]);
  const [focusedNodeId, setFocusedNodeId] = useState<string | null>(null);

  const rootModels = useMemo(() => {
    const next = new Map<string, RootRenderModel>();
    for (const project of projects) {
      const rootState = rootStates?.get(project.rootPath);
      const rawModel = buildRootRenderModel(
        project,
        rootState,
        filter,
        formatFilter,
      );
      const primarySectionKey = getRenderSectionKey(project.rootPath, "primary");
      const secondarySectionKey = getRenderSectionKey(project.rootPath, "secondary");
      const mutationRelativePath = rootState?.mutation?.targetRelativePath ?? null;
      const primaryImportantIndex = resolveImportantVisibleIndex(project, rawModel.primaryVisibleItems, {
        activeFileKey,
        renamingFileKey,
        mutationRelativePath,
      });
      const secondaryImportantIndex = resolveImportantVisibleIndex(project, rawModel.secondaryVisibleItems, {
        activeFileKey,
        renamingFileKey,
        mutationRelativePath,
      });
      const primaryBound = applyRenderBound(
        rawModel.primaryVisibleItems,
        sectionRenderLimits.get(primarySectionKey) ?? DEFAULT_RENDERED_TREE_ROWS,
        primaryImportantIndex,
      );
      const secondaryBound = applyRenderBound(
        rawModel.secondaryVisibleItems,
        sectionRenderLimits.get(secondarySectionKey) ?? DEFAULT_RENDERED_TREE_ROWS,
        secondaryImportantIndex,
      );
      next.set(
        project.rootPath,
        {
          ...rawModel,
          primaryVisibleItems: primaryBound.renderedItems,
          secondaryVisibleItems: secondaryBound.renderedItems,
          primaryHiddenCount: primaryBound.hiddenCount,
          secondaryHiddenCount: secondaryBound.hiddenCount,
        },
      );
    }
    return next;
  }, [
    activeFileKey,
    filter,
    formatFilter,
    projects,
    renamingFileKey,
    rootStates,
    sectionRenderLimits,
  ]);

  const visibleNodes = useMemo(() => {
    const nodes: ExplorerVisibleNode[] = [];

    for (const project of projects) {
      const rootState = rootStates?.get(project.rootPath);
      const rootNodeId = getRootNodeId(project);
      const model = rootModels.get(project.rootPath);
      const isExpanded = expandedRootsResolved.has(project.rootPath);
      nodes.push({
        id: rootNodeId,
        parentId: null,
        rootPath: project.rootPath,
        rootName: getRootDisplayLabel(project, rootState),
        kind: "root",
        level: 1,
        label: getRootDisplayLabel(project, rootState),
        isExpanded,
        hasChildren: project.files.length > 0 || Boolean(model?.secondaryUnderlyingCount),
      });

      if (!isExpanded || !model) {
        continue;
      }

      nodes.push(
        ...buildVisibleNodesForItems(
          project,
          model.primaryVisibleItems,
          rootNodeId,
          model.shouldUseCuratedSections ? 1 : 0,
          model.hasActiveFilter,
        ),
      );
    }

    return nodes;
  }, [projects, rootStates, rootModels, expandedRootsResolved]);

  const visibleNodeIds = useMemo(
    () => visibleNodes.map((node) => node.id),
    [visibleNodes],
  );
  const visibleNodesById = useMemo(
    () => new Map(visibleNodes.map((node) => [node.id, node])),
    [visibleNodes],
  );

  useEffect(() => {
    setFocusedNodeId((current) => {
      if (visibleNodeIds.length === 0) {
        return null;
      }
      if (current && visibleNodeIds.includes(current)) {
        return current;
      }
      if (!current) {
        return visibleNodeIds[0];
      }

      const previousIds = previousVisibleNodeIdsRef.current;
      const previousIndex = previousIds.indexOf(current);
      if (previousIndex >= 0) {
        return visibleNodeIds[Math.min(previousIndex, visibleNodeIds.length - 1)] ?? visibleNodeIds[0];
      }
      return visibleNodeIds[0];
    });
    previousVisibleNodeIdsRef.current = visibleNodeIds;
  }, [visibleNodeIds]);

  useEffect(() => {
    if (!treeHasManagedFocus.current || !focusedNodeId) {
      return;
    }
    const element = treeNodeRefs.current.get(focusedNodeId);
    if (element && document.activeElement !== element) {
      element.focus();
    }
  }, [focusedNodeId]);

  const setTreeNodeRef = useCallback((nodeId: string, element: HTMLDivElement | null) => {
    if (element) {
      treeNodeRefs.current.set(nodeId, element);
      return;
    }
    treeNodeRefs.current.delete(nodeId);
  }, []);

  const focusNode = useCallback((nodeId: string) => {
    treeHasManagedFocus.current = true;
    setFocusedNodeId((current) => (current === nodeId ? current : nodeId));
    const element = treeNodeRefs.current.get(nodeId);
    if (element && document.activeElement !== element) {
      element.focus();
    }
  }, []);

  const activateNode = useCallback((node: ExplorerVisibleNode) => {
    if (node.kind === "root") {
      toggleRootExpanded(node.rootPath);
      return;
    }
    if (node.kind === "directory" && node.file) {
      onToggleDir(node.rootPath, node.file.path);
      return;
    }
    if (node.kind === "file" && node.file) {
      onOpenFile(node.rootPath, node.file);
    }
  }, [onOpenFile, onToggleDir, toggleRootExpanded]);

  const openContextMenuForNode = useCallback((nodeId: string) => {
    const node = visibleNodesById.get(nodeId);
    if (!node) {
      return;
    }

    const element = treeNodeRefs.current.get(nodeId);
    const rect = element?.getBoundingClientRect();
    const x = rect ? rect.left + Math.min(rect.width - 12, 64) : 120;
    const y = rect ? rect.top + rect.height / 2 : 120;

    if (node.kind === "root") {
      setContextMenu({
        targetType: "root",
        rootPath: node.rootPath,
        rootName: node.label,
        x,
        y,
      });
      return;
    }

    if (!node.file) {
      return;
    }

    setContextMenu({
      targetType: node.kind === "directory" ? "folder" : "file",
      file: node.file,
      rootPath: node.rootPath,
      x,
      y,
    });
  }, [visibleNodesById]);

  const handleNodeKeyDown = useCallback((e: React.KeyboardEvent<HTMLDivElement>, nodeId: string) => {
    const node = visibleNodesById.get(nodeId);
    if (!node) {
      return;
    }

    const currentIndex = visibleNodeIds.indexOf(nodeId);
    const nextNodeId = visibleNodeIds[currentIndex + 1];
    const previousNodeId = visibleNodeIds[currentIndex - 1];
    const firstChild = visibleNodes.find((candidate) => candidate.parentId === nodeId);

    if (e.key === "ArrowDown") {
      e.preventDefault();
      if (nextNodeId) {
        focusNode(nextNodeId);
      }
      return;
    }

    if (e.key === "ArrowUp") {
      e.preventDefault();
      if (previousNodeId) {
        focusNode(previousNodeId);
      }
      return;
    }

    if (e.key === "Home") {
      e.preventDefault();
      if (visibleNodeIds[0]) {
        focusNode(visibleNodeIds[0]);
      }
      return;
    }

    if (e.key === "End") {
      e.preventDefault();
      if (visibleNodeIds.length > 0) {
        focusNode(visibleNodeIds[visibleNodeIds.length - 1]);
      }
      return;
    }

    if (e.key === "ArrowRight") {
      if ((node.kind === "root" || node.kind === "directory") && node.hasChildren) {
        e.preventDefault();
        if (!node.isExpanded) {
          activateNode(node);
          return;
        }
        if (firstChild) {
          focusNode(firstChild.id);
        }
      }
      return;
    }

    if (e.key === "ArrowLeft") {
      if (node.kind === "root" || node.kind === "directory") {
        e.preventDefault();
        if (node.isExpanded && node.hasChildren) {
          activateNode(node);
          return;
        }
        if (node.parentId) {
          focusNode(node.parentId);
        }
        return;
      }
      if (node.parentId) {
        e.preventDefault();
        focusNode(node.parentId);
      }
      return;
    }

    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      activateNode(node);
      return;
    }

    if (e.key === "F2" && node.kind === "file" && node.file) {
      e.preventDefault();
      setRenamingFileKey(getProjectFileStatusKey(node.rootPath, node.file.path));
      return;
    }

    if (e.key === "ContextMenu" || (e.shiftKey && e.key === "F10")) {
      e.preventDefault();
      openContextMenuForNode(nodeId);
    }
  }, [activateNode, focusNode, openContextMenuForNode, setRenamingFileKey, visibleNodeIds, visibleNodes, visibleNodesById]);

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

      {/* Tree */}
      <ScrollArea className="flex-1">
        <div
          ref={treeRef}
          role="tree"
          aria-label="Workspace explorer"
          className="py-1"
          onFocusCapture={() => {
            treeHasManagedFocus.current = true;
          }}
          onBlurCapture={(e) => {
            const relatedTarget = e.relatedTarget as Node | null;
            if (!e.currentTarget.contains(relatedTarget)) {
              treeHasManagedFocus.current = false;
            }
          }}
        >
          {projects.map((project) => {
            const isExpanded = expandedRootsResolved.has(project.rootPath);
            const rootState = rootStates?.get(project.rootPath);
            const model = rootModels.get(project.rootPath);
            const rootNodeId = getRootNodeId(project);
            const rootLabel = getRootDisplayLabel(project, rootState);
            const rootAriaLabel = [
              rootLabel,
              rootState?.isDefault ? "default workspace root" : "workspace root",
              getRootStatusLabel(rootState?.status ?? "ready"),
            ].filter(Boolean).join(", ");

            return (
              <div key={project.rootPath}>
                <div
                  ref={(node) => setTreeNodeRef(rootNodeId, node)}
                  role="treeitem"
                  aria-level={1}
                  aria-expanded={isExpanded}
                  aria-label={rootAriaLabel}
                  data-explorer-node-id={rootNodeId}
                  tabIndex={focusedNodeId === rootNodeId ? 0 : -1}
                  title={project.rootPath}
                  className="flex items-center gap-1.5 px-2.5 py-1.5 cursor-pointer rounded-sm hover:bg-[#131721]/28 outline-none focus-visible:bg-[#151b25] focus-visible:ring-1 focus-visible:ring-[#334156]/80"
                  onClick={(e) => {
                    treeHasManagedFocus.current = true;
                    e.currentTarget.focus();
                    focusNode(rootNodeId);
                    toggleRootExpanded(project.rootPath);
                  }}
                  onFocus={() => focusNode(rootNodeId)}
                  onKeyDown={(e) => handleNodeKeyDown(e, rootNodeId)}
                  onContextMenu={(e) => {
                    e.preventDefault();
                    treeHasManagedFocus.current = true;
                    focusNode(rootNodeId);
                    setContextMenu({
                      targetType: "root",
                      rootPath: project.rootPath,
                      rootName: rootLabel,
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
                  {isExpanded ? (
                    <IconFolderOpen size={13} stroke={1.5} className="text-[#8fa0bb]" />
                  ) : (
                    <IconFolder size={13} stroke={1.5} className="text-[#8fa0bb]" />
                  )}
                  <span className="truncate flex-1 text-[12px] font-medium text-[#dbe3f2]">
                    {rootLabel}
                  </span>
                  <RootStatusBadge rootState={rootState} />
                </div>
                {isExpanded && model && (
                  <RootTreeSection
                    rootNodeId={rootNodeId}
                    project={project}
                  rootState={rootState}
                  model={model}
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
                    focusedNodeId={focusedNodeId}
                    onFocusNode={focusNode}
                    onKeyDownNode={handleNodeKeyDown}
                    setTreeNodeRef={setTreeNodeRef}
                    onShowMorePrimary={() => showMoreSectionRows(project.rootPath, "primary")}
                    onRefreshRoot={onRefreshRoot}
                    onRevealInFinder={onRevealInFinder}
                  />
                )}
              </div>
            );
          })}
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
