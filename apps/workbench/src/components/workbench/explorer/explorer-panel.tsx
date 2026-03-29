import React, { useMemo, useCallback, useState, useRef, useEffect, useLayoutEffect } from "react";
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
import { ExplorerTreeItem, getTreeItemPaddingLeft } from "./explorer-tree-item";
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
  onToggleDir: (rootId: string, dirPath: string) => void;
  onOpenFile: (rootId: string, file: ProjectFile) => void;
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
  onRemoveRoot?: (rootId: string) => void;
  activeFileKey?: string | null;
  className?: string;
  onCreateFile?: (parentPath: string, fileName: string) => void;
  onRenameFile?: (rootId: string, file: ProjectFile, newName: string) => void;
  onDeleteFile?: (rootId: string, file: ProjectFile) => void;
  fileStatuses?: Map<string, FileStatus>;
  onRevealInFinder?: (rootId: string, absolutePath: string) => void;
  onCreateFolder?: (parentPath: string, folderName: string) => void;
  onCollapseChildren?: (rootId: string, dirPath: string) => void;
  onRefreshRoot?: (rootId: string) => void;
}

interface DeleteTarget {
  rootId: string;
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

interface RootRenderModel {
  hasActiveFilter: boolean;
  shouldUseCuratedSections: boolean;
  effectiveExpandedDirs: Set<string>;
  forceExpandRoot: boolean;
  primaryVisibleItems: ProjectFile[];
  primaryHiddenCount: number;
  primaryUnderlyingCount: number;
}

type ExplorerVisibleNodeKind = "root" | "directory" | "file";

interface ExplorerVisibleNode {
  id: string;
  parentId: string | null;
  rootId: string;
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

function getExplorerFileKey(rootId: string, relativePath: string): string {
  return `${rootId}::${relativePath}`;
}

function parseExplorerFileKey(
  fileKey?: string | null,
): { rootId: string; relativePath: string } | null {
  if (!fileKey) {
    return null;
  }
  const separatorIndex = fileKey.indexOf("::");
  if (separatorIndex <= 0 || separatorIndex === fileKey.length - 2) {
    return null;
  }
  return {
    rootId: fileKey.slice(0, separatorIndex),
    relativePath: fileKey.slice(separatorIndex + 2),
  };
}

function collectAncestorDirs(relativePath: string): string[] {
  const segments = relativePath.split("/").filter(Boolean);
  if (segments.length <= 1) {
    return [];
  }
  const ancestors: string[] = [];
  for (let index = 1; index < segments.length; index += 1) {
    ancestors.push(segments.slice(0, index).join("/"));
  }
  return ancestors;
}

function getTreeItemLevel(fileDepth: number, depthOffset = 0): number {
  return Math.max(0, fileDepth - depthOffset) + 2;
}

function getCreationRowLevel(relativeDir: string | null, depthOffset = 0): number {
  if (!relativeDir) {
    return 2;
  }
  const directoryDepth = relativeDir.split("/").filter(Boolean).length;
  return getTreeItemLevel(directoryDepth, depthOffset);
}

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

function getRenderSectionKey(rootId: string): string {
  return `${rootId}::primary`;
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
    const itemKey = getExplorerFileKey(project.rootId, item.path);
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
  rootId,
  rootPath,
  onRefreshRoot,
  onRevealInFinder,
}: {
  toneClass: string;
  title: string;
  detail: string;
  rootId: string;
  rootPath: string;
  onRefreshRoot?: (rootId: string) => void;
  onRevealInFinder?: (rootId: string, absolutePath: string) => void;
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
              onClick={() => onRefreshRoot(rootId)}
              className="rounded border border-current/20 px-1.5 py-1 text-[8px] font-mono uppercase tracking-[0.16em] opacity-80 transition-opacity hover:opacity-100"
            >
              Refresh
            </button>
          )}
          {onRevealInFinder && (
            <button
              type="button"
              onClick={() => onRevealInFinder(rootId, rootPath)}
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
  rootId,
  rootPath,
  rootState,
  onRefreshRoot,
  onRevealInFinder,
}: {
  rootId: string;
  rootPath: string;
  rootState?: ExplorerRootState;
  onRefreshRoot?: (rootId: string) => void;
  onRevealInFinder?: (rootId: string, absolutePath: string) => void;
}) {
  if (!rootState) return null;

  const banners: React.ReactNode[] = [];

  if (rootState.mutation) {
    banners.push(
      <RootBannerCard
        key="mutation"
        rootId={rootId}
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
        rootId={rootId}
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

function getCuratedPrimaryFiles(project: DetectionProject): ProjectFile[] {
  const workspaceDir = project.files.find((file) => file.isDirectory && file.path === "workspace");
  return workspaceDir?.children ?? [];
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

function findProjectByRootIdentifier(
  projects: DetectionProject[],
  rootIdentifier: string | null | undefined,
): DetectionProject | null {
  if (!rootIdentifier) {
    return null;
  }
  return projects.find((project) =>
    project.rootId === rootIdentifier || project.rootPath === rootIdentifier)
    ?? null;
}

function buildRootRenderModel(
  project: DetectionProject,
  rootState: ExplorerRootState | undefined,
  filter: string,
  formatFilter: FileType | null,
  activeFileKey?: string | null,
  renamingFileKey?: string | null,
): RootRenderModel {
  const hasActiveFilter = Boolean(filter || formatFilter);
  const shouldUseCuratedSections = shouldUseCuratedRootSections(project, rootState);
  const primaryFiles = shouldUseCuratedSections ? getCuratedPrimaryFiles(project) : project.files;
  const renamingFile = parseExplorerFileKey(renamingFileKey);
  const relevantPaths = [
    renamingFile?.rootId === project.rootId ? renamingFile.relativePath : null,
    rootState?.mutation?.targetRelativePath ?? null,
  ].filter((path): path is string => Boolean(path));
  const effectiveExpandedDirs = new Set(project.expandedDirs);
  for (const path of relevantPaths) {
    for (const ancestor of collectAncestorDirs(path)) {
      effectiveExpandedDirs.add(ancestor);
    }
  }
  const primaryFilteredFiles = filter || formatFilter
    ? filterTree(primaryFiles, filter, formatFilter)
    : primaryFiles;
  return {
    hasActiveFilter,
    shouldUseCuratedSections,
    effectiveExpandedDirs,
    forceExpandRoot: relevantPaths.length > 0,
    primaryVisibleItems: flattenTree(primaryFilteredFiles, effectiveExpandedDirs, hasActiveFilter),
    primaryHiddenCount: 0,
    primaryUnderlyingCount: countTreeEntries(primaryFiles),
  };
}

function buildVisibleNodesForItems(
  project: DetectionProject,
  items: ProjectFile[],
  rootNodeId: string,
  depthOffset: number,
  forceExpandAll: boolean,
  effectiveExpandedDirs: Set<string>,
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
      rootId: project.rootId,
      rootPath: project.rootPath,
      rootName: project.name,
      kind: file.isDirectory ? "directory" : "file",
      level: getTreeItemLevel(file.depth, depthOffset),
      label: file.name,
      file,
      isExpanded: file.isDirectory ? (forceExpandAll || effectiveExpandedDirs.has(file.path)) : false,
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
  onToggleDir: (rootId: string, dirPath: string) => void;
  onOpenFile: (rootId: string, file: ProjectFile) => void;
  activeFileKey?: string | null;
  fileStatuses?: Map<string, FileStatus>;
  onCreateFile?: (parentPath: string, fileName: string) => void;
  onRenameFile?: (rootId: string, file: ProjectFile, newName: string) => void;
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
  onRefreshRoot?: (rootId: string) => void;
  onRevealInFinder?: (rootId: string, absolutePath: string) => void;
}) {
  const {
    hasActiveFilter,
    shouldUseCuratedSections,
    effectiveExpandedDirs,
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
    const rowLevel = getCreationRowLevel(creatingInRelDir, depthOffset);

    return (
      <div className="py-1" style={{ paddingLeft: getTreeItemPaddingLeft(rowLevel) }}>
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
      const fileKey = getExplorerFileKey(project.rootId, file.path);
      const fileStatusKey = getProjectFileStatusKey(project.rootPath, file.path);
      const status = fileStatuses?.get(fileStatusKey);
      const rowMutation = rootState?.mutation?.targetRelativePath === file.path
        ? getMutationRowBadge(rootState.mutation)
        : null;
      const nodeId = getFileNodeId(project, file);
      const treeLevel = getTreeItemLevel(file.depth, depthOffset);
      const isExpanded = file.isDirectory ? (hasActiveFilter || effectiveExpandedDirs.has(file.path)) : false;
      items.push(
        <ExplorerTreeItem
          key={file.path}
          ref={(node) => setTreeNodeRef(nodeId, node)}
          nodeId={nodeId}
          level={treeLevel}
          file={file}
          isExpanded={isExpanded}
          onToggle={() => onToggleDir(project.rootId, file.path)}
          onOpen={() => onOpenFile(project.rootId, file)}
          onFocus={() => onFocusNode(nodeId)}
          onKeyDown={(e) => onKeyDownNode(e, nodeId)}
          isActive={!file.isDirectory && activeFileKey === fileKey}
          onContextMenu={(e) => {
            e.preventDefault();
            onFocusNode(nodeId);
            setContextMenu({
              targetType: file.isDirectory ? "folder" : "file",
              file,
              rootId: project.rootId,
              rootPath: project.rootPath,
              x: e.clientX,
              y: e.clientY,
            });
          }}
          tabIndex={focusedNodeId === nodeId ? 0 : -1}
          isRenaming={renamingFileKey === fileKey}
          onRenameSubmit={(newName) => {
            onRenameFile?.(project.rootId, file, newName);
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
    const shouldShowEmptyCopy = rootState?.status !== "refreshing"
      && rootState?.status !== "stale"
      && rootState?.status !== "error";

    if (primaryVisibleItems.length === 0 && creatingInDir === null) {
      return (
        <>
          <RootStatusBanner
            rootId={project.rootId}
            rootPath={project.rootPath}
            rootState={rootState}
            onRefreshRoot={onRefreshRoot}
            onRevealInFinder={onRevealInFinder}
          />
          {shouldShowEmptyCopy && (
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
          )}
        </>
      );
    }

    return (
      <>
        <RootStatusBanner
          rootId={project.rootId}
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
        rootId={project.rootId}
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
  const lastAutoRevealedActiveFileKeyRef = useRef<string | null>(null);
  // Track which root sections are expanded (all expanded by default).
  const [expandedRoots, setExpandedRoots] = useState<Set<string>>(
    () => new Set(projects.map((p) => p.rootId)),
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
        initial.add(p.rootId);
      }
      return initial;
    }
    return expandedRoots;
  }, [projects, expandedRoots]);

  const toggleRootExpanded = useCallback((rootId: string) => {
    setExpandedRoots((prev) => {
      const next = new Set(prev);
      if (next.has(rootId)) {
        next.delete(rootId);
      } else {
        next.add(rootId);
      }
      return next;
    });
  }, []);

  const revealFilePathInTree = useCallback((project: DetectionProject, relativePath: string) => {
    setExpandedRoots((prev) => {
      if (prev.has(project.rootId)) {
        return prev;
      }
      const next = new Set(prev);
      next.add(project.rootId);
      return next;
    });

    for (const ancestor of collectAncestorDirs(relativePath)) {
      if (!project.expandedDirs.has(ancestor)) {
        onToggleDir(project.rootId, ancestor);
      }
    }
  }, [onToggleDir]);

  useLayoutEffect(() => {
    const parsedActiveFile = parseExplorerFileKey(activeFileKey);
    if (!parsedActiveFile || activeFileKey == null) {
      lastAutoRevealedActiveFileKeyRef.current = null;
      return;
    }
    if (lastAutoRevealedActiveFileKeyRef.current === activeFileKey) {
      return;
    }

    const project = findProjectByRootIdentifier(projects, parsedActiveFile.rootId);
    if (project) {
      revealFilePathInTree(project, parsedActiveFile.relativePath);
    }

    lastAutoRevealedActiveFileKeyRef.current = activeFileKey;
  }, [activeFileKey, projects, revealFilePathInTree]);

  const showMoreSectionRows = useCallback((rootId: string) => {
    const sectionKey = getRenderSectionKey(rootId);
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

  // Convenience: for single root, use the first project as backward-compat reference.
  const firstProject = projects[0];
  const isMultiRoot = projects.length > 1;
  const treeRef = useRef<HTMLDivElement>(null);
  const treeNodeRefs = useRef(new Map<string, HTMLDivElement>());
  const previousVisibleNodeIdsRef = useRef<string[]>([]);
  const [focusedNodeId, setFocusedNodeId] = useState<string | null>(null);
  const [treeIsFocused, setTreeIsFocused] = useState(false);
  const rootModels = useMemo(() => {
    const next = new Map<string, RootRenderModel>();
    for (const project of projects) {
      const rootState = rootStates?.get(project.rootId);
      const rawModel = buildRootRenderModel(
        project,
        rootState,
        filter,
        formatFilter,
        activeFileKey,
        renamingFileKey,
      );
      const primarySectionKey = getRenderSectionKey(project.rootId);
      const mutationRelativePath = rootState?.mutation?.targetRelativePath ?? null;
      const primaryImportantIndex = resolveImportantVisibleIndex(project, rawModel.primaryVisibleItems, {
        activeFileKey,
        renamingFileKey,
        mutationRelativePath,
      });
      const primaryBound = applyRenderBound(
        rawModel.primaryVisibleItems,
        sectionRenderLimits.get(primarySectionKey) ?? DEFAULT_RENDERED_TREE_ROWS,
        primaryImportantIndex,
      );
      next.set(
        project.rootId,
        {
          ...rawModel,
          primaryVisibleItems: primaryBound.renderedItems,
          primaryHiddenCount: primaryBound.hiddenCount,
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
      const rootState = rootStates?.get(project.rootId);
      const rootNodeId = getRootNodeId(project);
      const model = rootModels.get(project.rootId);
      const isExpanded = expandedRootsResolved.has(project.rootId) || Boolean(model?.forceExpandRoot);
      nodes.push({
        id: rootNodeId,
        parentId: null,
        rootId: project.rootId,
        rootPath: project.rootPath,
        rootName: getRootDisplayLabel(project, rootState),
        kind: "root",
        level: 1,
        label: getRootDisplayLabel(project, rootState),
        isExpanded,
        hasChildren: (model?.primaryUnderlyingCount ?? 0) > 0
          || Boolean(rootState?.mutation)
          || rootState?.status === "loading"
          || rootState?.status === "refreshing"
          || rootState?.status === "stale"
          || rootState?.status === "error",
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
          model.effectiveExpandedDirs,
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
    if (!treeIsFocused || !focusedNodeId) {
      return;
    }
    const element = treeNodeRefs.current.get(focusedNodeId);
    if (element && document.activeElement !== element) {
      element.focus();
    }
  }, [focusedNodeId, treeIsFocused]);

  const setTreeNodeRef = useCallback((nodeId: string, element: HTMLDivElement | null) => {
    if (element) {
      treeNodeRefs.current.set(nodeId, element);
      return;
    }
    treeNodeRefs.current.delete(nodeId);
  }, []);

  const focusNode = useCallback((nodeId: string) => {
    setTreeIsFocused(true);
    setFocusedNodeId((current) => (current === nodeId ? current : nodeId));
    const element = treeNodeRefs.current.get(nodeId);
    if (element && document.activeElement !== element) {
      element.focus();
    }
  }, []);

  const activateNode = useCallback((node: ExplorerVisibleNode) => {
    if (node.kind === "root") {
      toggleRootExpanded(node.rootId);
      return;
    }
    if (node.kind === "directory" && node.file) {
      onToggleDir(node.rootId, node.file.path);
      return;
    }
    if (node.kind === "file" && node.file) {
      onOpenFile(node.rootId, node.file);
    }
  }, [onOpenFile, onToggleDir, toggleRootExpanded]);

  const preferredCreateRootPath = useMemo(() => {
    const focusedRootId = treeIsFocused && focusedNodeId
      ? visibleNodesById.get(focusedNodeId)?.rootId ?? null
      : null;
    const activeRootId = parseExplorerFileKey(activeFileKey)?.rootId ?? null;
    const preferredRootId = focusedRootId ?? activeRootId ?? firstProject?.rootId ?? null;
    return findProjectByRootIdentifier(projects, preferredRootId)?.rootPath
      ?? firstProject?.rootPath
      ?? null;
  }, [activeFileKey, firstProject, focusedNodeId, projects, treeIsFocused, visibleNodesById]);

  const beginCreateFile = useCallback((parentPath: string) => {
    const targetProject = projects.find((project) =>
      parentPath === project.rootPath || parentPath.startsWith(`${project.rootPath}/`))
      ?? null;

    if (targetProject) {
      setExpandedRoots((prev) => {
        if (prev.has(targetProject.rootId)) {
          return prev;
        }
        const next = new Set(prev);
        next.add(targetProject.rootId);
        return next;
      });
    }

    setCreatingInDir(parentPath);
  }, [projects]);

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
        rootId: node.rootId,
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
      rootId: node.rootId,
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
      setRenamingFileKey(getExplorerFileKey(node.rootId, node.file.path));
      return;
    }

    if (e.key === "ContextMenu" || (e.shiftKey && e.key === "F10")) {
      e.preventDefault();
      openContextMenuForNode(nodeId);
    }
  }, [activateNode, focusNode, openContextMenuForNode, setRenamingFileKey, visibleNodeIds, visibleNodes, visibleNodesById]);

  // ---- Empty state ----
  if (projects.length === 0) {
    return (
      <div
        className={cn(
          "flex flex-col h-full bg-[#05060a]",
          className,
        )}
      >
        <div className="shrink-0 px-3 py-2.5 border-b border-[#2d3240]">
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a]">
              Explorer
            </span>
          </div>
        </div>

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
              onClick={() => preferredCreateRootPath && beginCreateFile(preferredCreateRootPath)}
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
      <div className="min-h-0 flex-1 flex flex-col">
      <ScrollArea className="min-h-0 flex-1">
        <div
          ref={treeRef}
          role="tree"
          aria-label="Workspace explorer"
          className="py-1"
          onFocusCapture={() => {
            setTreeIsFocused(true);
          }}
          onBlurCapture={(e) => {
            const relatedTarget = e.relatedTarget as Node | null;
            if (!e.currentTarget.contains(relatedTarget)) {
              setTreeIsFocused(false);
            }
          }}
        >
          {projects.map((project) => {
            const rootState = rootStates?.get(project.rootId);
            const model = rootModels.get(project.rootId);
            const isExpanded = expandedRootsResolved.has(project.rootId) || Boolean(model?.forceExpandRoot);
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
                  className="flex min-h-7 items-center gap-1.5 rounded-sm px-2 py-1 cursor-pointer hover:bg-[#12161f] outline-none focus-visible:bg-[#151b25] focus-visible:ring-1 focus-visible:ring-[#334156]/80"
                  onClick={(e) => {
                    setTreeIsFocused(true);
                    e.currentTarget.focus();
                    focusNode(rootNodeId);
                    toggleRootExpanded(project.rootId);
                  }}
                  onFocus={() => focusNode(rootNodeId)}
                  onKeyDown={(e) => handleNodeKeyDown(e, rootNodeId)}
                  onContextMenu={(e) => {
                    e.preventDefault();
                    setTreeIsFocused(true);
                    focusNode(rootNodeId);
                    setContextMenu({
                      targetType: "root",
                      rootId: project.rootId,
                      rootPath: project.rootPath,
                      rootName: rootLabel,
                      x: e.clientX,
                      y: e.clientY,
                    });
                  }}
                >
                  <IconChevronRight
                    size={11}
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
                  <span className="min-w-0 flex-1 truncate text-[11px] font-medium text-[#dbe3f2]">
                    {rootLabel}
                  </span>
                  <RootStatusBadge rootState={rootState} />
                </div>
                {isExpanded && creatingInDir === project.rootPath && (
                  <div className="py-1" style={{ paddingLeft: getTreeItemPaddingLeft(2) }}>
                    <InlineNameInput
                      placeholder="filename.yaml"
                      onSubmit={(name) => {
                        onCreateFile?.(project.rootPath, name);
                        setCreatingInDir(null);
                      }}
                      onCancel={() => setCreatingInDir(null)}
                    />
                  </div>
                )}
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
                    creatingInDir={creatingInDir === project.rootPath ? null : creatingInDir}
                    setCreatingInDir={setCreatingInDir}
                    renamingFileKey={renamingFileKey}
                    setRenamingFileKey={setRenamingFileKey}
                    setContextMenu={setContextMenu}
                    setDeleteTarget={setDeleteTarget}
                    focusedNodeId={focusedNodeId}
                    onFocusNode={focusNode}
                    onKeyDownNode={handleNodeKeyDown}
                    setTreeNodeRef={setTreeNodeRef}
                    onShowMorePrimary={() => showMoreSectionRows(project.rootId)}
                    onRefreshRoot={onRefreshRoot}
                    onRevealInFinder={onRevealInFinder}
                  />
                )}
              </div>
            );
          })}
        </div>
      </ScrollArea>
        {/* Add Folder button at bottom of tree area */}
        {onAddFolder && (
          <button
            type="button"
            onClick={onAddFolder}
            className="shrink-0 flex items-center gap-1.5 w-full px-3 py-2 text-[10px] font-mono text-[#6f7f9a]/60 hover:text-[#ece7dc] hover:bg-[#131721]/40 transition-colors border-t border-[#2d3240]/30"
          >
            <IconPlus size={12} stroke={1.5} />
            Add Folder
          </button>
        )}
      </div>

      {/* Context menu overlay */}
      {contextMenu && (
        <ExplorerContextMenu
          target={contextMenu}
          onClose={() => setContextMenu(null)}
          onNewFile={(dirPath) => {
            beginCreateFile(dirPath);
            setContextMenu(null);
          }}
          onOpen={(file) => {
            onOpenFile(contextMenu.rootId, file);
            setContextMenu(null);
          }}
          onRename={(file) => {
            setRenamingFileKey(getExplorerFileKey(contextMenu.rootId, file.path));
            setContextMenu(null);
          }}
          onDelete={(file) => {
            setDeleteTarget({ rootId: contextMenu.rootId, file });
            setContextMenu(null);
          }}
          onRevealInFinder={(rootId, absPath) => {
            onRevealInFinder?.(rootId, absPath);
            setContextMenu(null);
          }}
          onRemoveRoot={(rootId) => {
            onRemoveRoot?.(rootId);
            setContextMenu(null);
          }}
          onRefreshRoot={(rootId) => {
            onRefreshRoot?.(rootId);
            setContextMenu(null);
          }}
          onCollapseChildren={(rootId, dirPath) => {
            onCollapseChildren?.(rootId, dirPath);
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
            onDeleteFile?.(deleteTarget.rootId, deleteTarget.file);
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

function countTreeEntries(files: ProjectFile[]): number {
  let count = 0;
  for (const file of files) {
    count += 1;
    if (file.isDirectory && file.children) {
      count += countTreeEntries(file.children);
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
