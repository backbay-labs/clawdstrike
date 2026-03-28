import { create } from "zustand";
import { createSelectors } from "@/lib/create-selectors";
import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import type { FileType } from "@/lib/workbench/file-type-registry";
import { getFileTypeByExtension } from "@/lib/workbench/file-type-registry";
import { getDocumentIdentityStore } from "@/lib/workbench/detection-workflow/document-identity-store";
import {
  isAbsoluteWorkspacePath,
  joinWorkspacePath,
  normalizeWorkspacePath,
  relativeWorkspacePath,
} from "@/lib/workbench/path-utils";
import {
  getProjectPathBasename,
  isValidProjectBasename,
  replaceProjectPathBasename,
} from "@/features/project/utils/resolve-project-path";
import {
  addWorkspaceRootNative,
  createWorkspaceDirectoryNative,
  deleteWorkspaceEntryNative,
  readWorkspaceTreeNative,
  renameWorkspaceEntryNative,
  removeWorkspaceRootNative,
  type TauriWorkspaceTreeEntry,
  type TauriWorkspaceRegistrySnapshot,
  type TauriWorkspaceRootRecord,
} from "@/lib/tauri-commands";

// ---- Types ----

export interface ProjectFile {
  /** Relative path within the project root. */
  path: string;
  /** File name (last segment of path). */
  name: string;
  /** Detected file type (only meaningful for files, not directories). */
  fileType: FileType;
  /** Whether this entry represents a directory. */
  isDirectory: boolean;
  /** Child entries (only present for directories). */
  children?: ProjectFile[];
  /** Nesting depth (0 = root). */
  depth: number;
}

export interface DetectionProject {
  /** Backend-issued workspace root identity. */
  rootId: string;
  /** Absolute path to the project root directory. */
  rootPath: string;
  /** Human-readable project name (usually the directory basename). */
  name: string;
  /** Hierarchical file tree. */
  files: ProjectFile[];
  /** Set of directory paths currently expanded in the UI. */
  expandedDirs: Set<string>;
}

/** Per-file status flags for Explorer visual indicators. */
export interface FileStatus {
  /** File has unsaved modifications. */
  modified?: boolean;
  /** File has validation errors. */
  hasError?: boolean;
}

export type ProjectMutationKind = "create_file" | "create_folder" | "rename" | "delete";

export type ProjectMutationStatus = "pending" | "error";

export interface ProjectMutationState {
  kind: ProjectMutationKind;
  status: ProjectMutationStatus;
  rootId: string;
  rootPath: string;
  targetRelativePath: string | null;
  targetLabel: string;
  message: string | null;
  updatedAt: number;
}

export type ProjectRootStatus =
  | "idle"
  | "loading"
  | "refreshing"
  | "ready"
  | "empty"
  | "stale"
  | "error";

interface ProjectState {
  project: DetectionProject | null;
  loading: boolean;
  error: string | null;
  /** Free-text filename filter. */
  filter: string;
  /** Filter files by a specific format. */
  formatFilter: FileType | null;
  /** Per-file status map (keyed by relative file path). */
  fileStatuses: Map<string, FileStatus>;
  /** Backend-issued default workspace root identity. */
  defaultRootId: string | null;
  /** Ordered workspace root identities from the backend registry. */
  orderedRootIds: string[];
  /** Workspace root metadata keyed by rootId. */
  rootsById: Map<string, TauriWorkspaceRootRecord>;
  /** Per-root explorer status keyed by rootId. */
  rootStatusById: Map<string, ProjectRootStatus>;
  /** Per-root last error keyed by rootId. */
  rootErrorById: Map<string, string | null>;
  /** Per-root latest requested scan version keyed by rootId. */
  rootRequestedVersionById: Map<string, number>;
  /** Per-root latest committed scan version keyed by rootId. */
  rootCommittedVersionById: Map<string, number>;
  /** Per-root local mutation status keyed by rootId. */
  rootMutationById: Map<string, ProjectMutationState | null>;
  /** DetectionProject instances keyed by rootId. */
  projectsById: Map<string, DetectionProject>;
  /** Absolute paths of mounted workspace roots (multi-root support). */
  projectRoots: string[];
  /** DetectionProject instances keyed by rootPath (one per mounted root). */
  projects: Map<string, DetectionProject>;
}

export type WorkspaceConsumerState = Pick<
  ProjectState,
  | "project"
  | "defaultRootId"
  | "orderedRootIds"
  | "rootsById"
  | "rootStatusById"
  | "projectRoots"
>;

const FILE_STATUS_KEY_SEPARATOR = "::";
const TERMINAL_ROOT_STATUSES = new Set<ProjectRootStatus>(["ready", "empty", "stale", "error"]);

export interface WorkspaceRootsReadyResult {
  ready: boolean;
  pendingRootIds: string[];
  elapsedMs: number;
}

export function getProjectFileStatusKey(rootPath: string, filePath: string): string {
  const normalizedRoot = rootPath.replace(/\/+$/, "");
  const normalizedPath = filePath.replace(/^\/+/, "");
  return `${normalizedRoot}${FILE_STATUS_KEY_SEPARATOR}${normalizedPath}`;
}

function getPrimaryProject(
  orderedRootIds: string[],
  projectsById: Map<string, DetectionProject>,
): DetectionProject | null {
  const firstRootId = orderedRootIds[0];
  return firstRootId ? projectsById.get(firstRootId) ?? null : null;
}

function normalizeRootIdentityPath(path: string): string {
  const normalized = normalizeWorkspacePath(path);
  if (normalized === "/" || /^[A-Za-z]:\/$/.test(normalized)) {
    return normalized;
  }
  return normalized.replace(/\/+$/, "");
}

function hasWorkspaceRootPrefix(path: string, rootPath: string): boolean {
  if (path === rootPath) {
    return true;
  }
  if (rootPath.endsWith("/")) {
    return path.startsWith(rootPath);
  }
  return path.startsWith(`${rootPath}/`);
}

function getRootIdentityPaths(root: TauriWorkspaceRootRecord): string[] {
  const unique = new Set<string>();
  for (const candidate of [root.displayPath, root.canonicalPath, ...root.aliases]) {
    const normalized = normalizeRootIdentityPath(candidate);
    if (normalized) {
      unique.add(normalized);
    }
  }
  return [...unique];
}

function findRootRecordByExactPath(
  rootsById: Map<string, TauriWorkspaceRootRecord>,
  orderedRootIds: string[],
  path: string,
): TauriWorkspaceRootRecord | null {
  const normalizedPath = normalizeRootIdentityPath(path);
  for (const rootId of orderedRootIds) {
    const root = rootsById.get(rootId);
    if (!root) continue;
    if (getRootIdentityPaths(root).some((candidate) => candidate === normalizedPath)) {
      return root;
    }
  }
  return null;
}

function findRootRecordByIdOrPath(
  rootsById: Map<string, TauriWorkspaceRootRecord>,
  orderedRootIds: string[],
  rootIdOrPath: string | null | undefined,
): TauriWorkspaceRootRecord | null {
  if (!rootIdOrPath) {
    return null;
  }

  const byId = rootsById.get(rootIdOrPath);
  if (byId) {
    return byId;
  }

  return findRootRecordByExactPath(rootsById, orderedRootIds, rootIdOrPath);
}

function resolveRootRecordForAbsolutePath(
  rootsById: Map<string, TauriWorkspaceRootRecord>,
  orderedRootIds: string[],
  path: string,
): TauriWorkspaceRootRecord | null {
  const normalizedPath = normalizeWorkspacePath(path);
  const matches: Array<{ root: TauriWorkspaceRootRecord; score: number }> = [];

  for (const rootId of orderedRootIds) {
    const root = rootsById.get(rootId);
    if (!root) continue;
    for (const candidate of getRootIdentityPaths(root)) {
      if (hasWorkspaceRootPrefix(normalizedPath, candidate)) {
        matches.push({ root, score: candidate.length });
      }
    }
  }

  matches.sort((a, b) => b.score - a.score);
  return matches[0]?.root ?? null;
}

interface ResolvedWorkspaceConsumerOwnership {
  root: TauriWorkspaceRootRecord;
  matchedRootPath: string;
  canonicalRootPath: string;
  absolutePath: string;
  relativePath: string;
}

function resolveWorkspaceConsumerOwnership(
  state: WorkspaceConsumerState,
  path: string,
): ResolvedWorkspaceConsumerOwnership | null {
  const normalizedPath = normalizeWorkspacePath(path);
  if (!isAbsoluteWorkspacePath(normalizedPath)) {
    return null;
  }

  const matches: Array<{ root: TauriWorkspaceRootRecord; candidate: string; score: number }> = [];
  for (const rootId of state.orderedRootIds) {
    const root = state.rootsById.get(rootId);
    if (!root) continue;
    for (const candidate of getRootIdentityPaths(root)) {
      if (hasWorkspaceRootPrefix(normalizedPath, candidate)) {
        matches.push({ root, candidate, score: candidate.length });
      }
    }
  }

  matches.sort((a, b) => b.score - a.score);
  const best = matches[0];
  if (!best) {
    return null;
  }

  return {
    root: best.root,
    matchedRootPath: best.candidate,
    canonicalRootPath: best.root.displayPath,
    absolutePath: normalizedPath,
    relativePath: relativeWorkspacePath(best.candidate, normalizedPath),
  };
}

export function getDefaultWorkspaceConsumerRoot(
  state: WorkspaceConsumerState,
): TauriWorkspaceRootRecord | null {
  const defaultRoot = state.defaultRootId ? state.rootsById.get(state.defaultRootId) ?? null : null;
  if (defaultRoot) {
    return defaultRoot;
  }

  const firstRootId = state.orderedRootIds[0];
  if (firstRootId) {
    return state.rootsById.get(firstRootId) ?? null;
  }

  if (state.project?.rootPath) {
    return findRootRecordByExactPath(state.rootsById, state.orderedRootIds, state.project.rootPath);
  }

  const firstProjectRoot = state.projectRoots[0];
  return firstProjectRoot
    ? findRootRecordByExactPath(state.rootsById, state.orderedRootIds, firstProjectRoot)
    : null;
}

export function getDefaultWorkspaceConsumerRootPath(
  state: WorkspaceConsumerState,
): string | null {
  return getDefaultWorkspaceConsumerRoot(state)?.displayPath
    ?? state.project?.rootPath
    ?? state.projectRoots[0]
    ?? null;
}

export function resolveWorkspaceConsumerRoot(
  state: WorkspaceConsumerState,
  path?: string | null,
): TauriWorkspaceRootRecord | null {
  if (path) {
    const exactRoot = findRootRecordByIdOrPath(state.rootsById, state.orderedRootIds, path);
    if (exactRoot) {
      return exactRoot;
    }

    const ownedRoot = resolveWorkspaceConsumerOwnership(state, path)?.root;
    if (ownedRoot) {
      return ownedRoot;
    }
  }

  return getDefaultWorkspaceConsumerRoot(state);
}

export function canonicalizeWorkspaceConsumerPath(
  state: WorkspaceConsumerState,
  path: string,
): string {
  const trimmed = path.trim();
  if (!trimmed) {
    return path;
  }

  if (!isAbsoluteWorkspacePath(trimmed)) {
    return normalizeWorkspacePath(trimmed);
  }

  const ownership = resolveWorkspaceConsumerOwnership(state, trimmed);
  if (!ownership) {
    return normalizeWorkspacePath(trimmed);
  }

  if (!ownership.relativePath) {
    return ownership.canonicalRootPath;
  }

  const matchedRootSuffix = hasWorkspaceRootPrefix(
    ownership.matchedRootPath,
    ownership.canonicalRootPath,
  )
    ? relativeWorkspacePath(ownership.canonicalRootPath, ownership.matchedRootPath)
    : "";
  const canonicalRelativePath = matchedRootSuffix
    ? `${matchedRootSuffix}/${ownership.relativePath}`.replace(/^\/+/, "")
    : ownership.relativePath;

  return joinWorkspacePath(ownership.canonicalRootPath, canonicalRelativePath);
}

export function getCanonicalWorkspaceRootPaths(
  state: WorkspaceConsumerState,
): string[] {
  const roots = state.orderedRootIds
    .map((rootId) => state.rootsById.get(rootId)?.displayPath ?? null)
    .filter((rootPath): rootPath is string => rootPath != null);
  if (roots.length > 0) {
    return Array.from(new Set(roots));
  }

  return Array.from(new Set(state.projectRoots));
}

export function isWorkspaceConsumerRootReady(
  state: WorkspaceConsumerState,
  rootIdOrPath?: string | null,
): boolean {
  const root = resolveWorkspaceConsumerRoot(state, rootIdOrPath);
  if (!root) {
    return false;
  }

  return isTerminalRootStatus(state.rootStatusById.get(root.rootId));
}

function buildProjectSelectionPatch(
  orderedRootIds: string[],
  rootsById: Map<string, TauriWorkspaceRootRecord>,
  projectsById: Map<string, DetectionProject>,
): Pick<
  ProjectStoreState,
  "project" | "projectRoots" | "projects" | "projectsById" | "rootsById" | "orderedRootIds"
> {
  const projectRoots = orderedRootIds
    .map((rootId) => rootsById.get(rootId)?.displayPath ?? null)
    .filter((rootPath): rootPath is string => rootPath != null);
  const projects = new Map<string, DetectionProject>();

  for (const rootId of orderedRootIds) {
    const root = rootsById.get(rootId);
    const project = projectsById.get(rootId);
    if (!root || !project) continue;
    projects.set(root.displayPath, project);
  }

  return {
    orderedRootIds,
    rootsById,
    projectsById,
    projectRoots,
    project: getPrimaryProject(orderedRootIds, projectsById),
    projects,
  };
}

function applyWorkspaceRegistrySnapshot(
  state: Pick<
    ProjectStoreState,
    | "projectsById"
    | "rootStatusById"
    | "rootErrorById"
    | "rootRequestedVersionById"
    | "rootCommittedVersionById"
    | "rootMutationById"
  >,
  snapshot: TauriWorkspaceRegistrySnapshot,
): Pick<
  ProjectStoreState,
  | "defaultRootId"
  | "orderedRootIds"
  | "rootsById"
  | "rootStatusById"
  | "rootErrorById"
  | "rootRequestedVersionById"
  | "rootCommittedVersionById"
  | "rootMutationById"
  | "projectsById"
  | "projectRoots"
  | "projects"
  | "project"
> {
  const rootsById = new Map<string, TauriWorkspaceRootRecord>(
    snapshot.roots.map((root) => [root.rootId, root]),
  );
  const projectsById = new Map<string, DetectionProject>();
  const rootStatusById = new Map<string, ProjectRootStatus>();
  const rootErrorById = new Map<string, string | null>();
  const rootRequestedVersionById = new Map<string, number>();
  const rootCommittedVersionById = new Map<string, number>();
  const rootMutationById = new Map<string, ProjectMutationState | null>();

  for (const rootId of snapshot.orderedRootIds) {
    const root = rootsById.get(rootId);
    if (!root) continue;
    const existingProject = state.projectsById.get(rootId);
    projectsById.set(
      rootId,
      existingProject
        ? {
            ...existingProject,
            rootId,
            rootPath: root.displayPath,
            name: root.label,
          }
        : createSkeletonProject(root),
    );
    rootStatusById.set(rootId, state.rootStatusById.get(rootId) ?? "idle");
    rootErrorById.set(rootId, state.rootErrorById.get(rootId) ?? null);
    rootRequestedVersionById.set(rootId, state.rootRequestedVersionById.get(rootId) ?? 0);
    rootCommittedVersionById.set(rootId, state.rootCommittedVersionById.get(rootId) ?? 0);
    rootMutationById.set(rootId, state.rootMutationById.get(rootId) ?? null);
  }

  return {
    defaultRootId: snapshot.defaultRootId,
    rootStatusById,
    rootErrorById,
    rootRequestedVersionById,
    rootCommittedVersionById,
    rootMutationById,
    ...buildProjectSelectionPatch(snapshot.orderedRootIds, rootsById, projectsById),
  };
}

function isTerminalRootStatus(status: ProjectRootStatus | undefined): boolean {
  return status != null && TERMINAL_ROOT_STATUSES.has(status);
}

function formatWorkspaceError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  if (typeof error === "string") {
    return error;
  }
  return "Workspace scan failed";
}

function logWorkspaceRootEvent(
  level: "info" | "warn" | "error",
  event: string,
  detail: Record<string, unknown>,
): void {
  console[level]("[workspace-root]", {
    event,
    ...detail,
  });
}

function buildRootMetadataPatch(
  state: Pick<
    ProjectState,
    | "rootStatusById"
    | "rootErrorById"
    | "rootRequestedVersionById"
    | "rootCommittedVersionById"
  >,
  rootId: string,
  updates: {
    status?: ProjectRootStatus;
    error?: string | null;
    requestedVersion?: number;
    committedVersion?: number;
  },
): Pick<
  ProjectState,
  "rootStatusById" | "rootErrorById" | "rootRequestedVersionById" | "rootCommittedVersionById"
> {
  const rootStatusById = new Map(state.rootStatusById);
  const rootErrorById = new Map(state.rootErrorById);
  const rootRequestedVersionById = new Map(state.rootRequestedVersionById);
  const rootCommittedVersionById = new Map(state.rootCommittedVersionById);

  if ("status" in updates) {
    rootStatusById.set(rootId, updates.status ?? "idle");
  }
  if ("error" in updates) {
    rootErrorById.set(rootId, updates.error ?? null);
  }
  if ("requestedVersion" in updates) {
    rootRequestedVersionById.set(rootId, updates.requestedVersion ?? 0);
  }
  if ("committedVersion" in updates) {
    rootCommittedVersionById.set(rootId, updates.committedVersion ?? 0);
  }

  return {
    rootStatusById,
    rootErrorById,
    rootRequestedVersionById,
    rootCommittedVersionById,
  };
}

function buildRootMutationPatch(
  state: Pick<ProjectState, "rootMutationById">,
  rootId: string,
  mutation: ProjectMutationState | null,
): Pick<ProjectState, "rootMutationById"> {
  const rootMutationById = new Map(state.rootMutationById);
  rootMutationById.set(rootId, mutation);
  return { rootMutationById };
}

function createRootMutationState(
  root: TauriWorkspaceRootRecord,
  kind: ProjectMutationKind,
  status: ProjectMutationStatus,
  targetRelativePath: string | null,
  targetLabel: string,
  message: string | null,
): ProjectMutationState {
  return {
    kind,
    status,
    rootId: root.rootId,
    rootPath: root.displayPath,
    targetRelativePath,
    targetLabel,
    message,
    updatedAt: Date.now(),
  };
}

function buildMutationFailureState(
  mutation: ProjectMutationState,
  message: string,
): ProjectMutationState {
  return {
    ...mutation,
    status: "error",
    message,
    updatedAt: Date.now(),
  };
}

function resolveMutationFailureMessage(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message.trim()) {
    return error.message;
  }
  if (typeof error === "string" && error.trim()) {
    return error;
  }
  return fallback;
}

function resolveCommittedExpandedDirs(
  previousProject: DetectionProject | undefined,
  allDirs: string[],
): Set<string> {
  if (!previousProject || previousProject.files.length === 0) {
    return new Set(allDirs);
  }
  const availableDirs = new Set(allDirs);
  const preservedDirs = [...previousProject.expandedDirs].filter((dirPath) => availableDirs.has(dirPath));
  return new Set(preservedDirs);
}

function resolveOwningRootPath(state: ProjectState, path: string): string | null {
  const normalizedPath = normalizeWorkspacePath(path);
  if (!isAbsoluteWorkspacePath(normalizedPath)) {
    return state.project?.rootPath ?? state.projectRoots[0] ?? null;
  }

  return (
    resolveRootRecordForAbsolutePath(state.rootsById, state.orderedRootIds, normalizedPath)?.displayPath ??
    state.project?.rootPath ??
    null
  );
}

function getProjectForRoot(
  state: ProjectState,
  rootPath: string | null,
): DetectionProject | null {
  if (!rootPath) return null;
  const root = findRootRecordByExactPath(state.rootsById, state.orderedRootIds, rootPath);
  if (!root) {
    return state.projects.get(rootPath) ?? (state.project?.rootPath === rootPath ? state.project : null);
  }
  return state.projectsById.get(root.rootId) ?? (state.project?.rootId === root.rootId ? state.project : null);
}

function relativePathWithinRoot(rootPath: string, path: string): string {
  return relativeWorkspacePath(rootPath, path);
}

function getFileStatusKeyForPath(state: ProjectState, filePath: string): string | null {
  const rootPath = resolveOwningRootPath(state, filePath);
  if (!rootPath) {
    return filePath ? filePath.replace(/^\/+/, "") : null;
  }
  return getProjectFileStatusKey(rootPath, relativePathWithinRoot(rootPath, filePath));
}

interface ResolvedWorkspaceTarget {
  root: TauriWorkspaceRootRecord;
  rootPath: string;
  absolutePath: string;
  relativePath: string;
}

function resolveWorkspaceTarget(
  state: ProjectState,
  path: string,
): ResolvedWorkspaceTarget | null {
  const rootPath = resolveOwningRootPath(state, path);
  if (!rootPath) return null;

  const root = findRootRecordByExactPath(state.rootsById, state.orderedRootIds, rootPath)
    ?? (isAbsoluteWorkspacePath(path)
      ? resolveRootRecordForAbsolutePath(
          state.rootsById,
          state.orderedRootIds,
          normalizeWorkspacePath(path),
        )
      : null);
  if (!root) return null;

  const absolutePath = isAbsoluteWorkspacePath(path)
    ? normalizeWorkspacePath(path)
    : joinWorkspacePath(root.displayPath, path);

  return {
    root,
    rootPath: root.displayPath,
    absolutePath,
    relativePath: relativePathWithinRoot(root.displayPath, absolutePath),
  };
}

// ---------------------------------------------------------------------------
// Multi-root persistence helpers
// ---------------------------------------------------------------------------

export const LEGACY_WORKSPACE_ROOTS_STORAGE_KEY = "clawdstrike_workspace_roots";

/** Read legacy workspace roots from localStorage once for backend migration. */
export function readLegacyWorkspaceRoots(): string[] {
  try {
    const raw = localStorage.getItem(LEGACY_WORKSPACE_ROOTS_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

/** Clear the legacy localStorage roots after backend migration succeeds. */
export function clearLegacyWorkspaceRoots(): void {
  try {
    localStorage.removeItem(LEGACY_WORKSPACE_ROOTS_STORAGE_KEY);
  } catch {
    // localStorage may be unavailable in some environments.
  }
}

function workspaceTreeEntriesToPaths(entries: TauriWorkspaceTreeEntry[]): string[] {
  return entries.map((entry) => (
    entry.kind === "directory" ? `${entry.path.replace(/\/+$/, "")}/` : entry.path
  ));
}

// ---- Helpers ----

/** Collect every directory path from a file tree. */
function collectDirPaths(files: ProjectFile[]): string[] {
  const paths: string[] = [];
  for (const f of files) {
    if (f.isDirectory) {
      paths.push(f.path);
      if (f.children) {
        paths.push(...collectDirPaths(f.children));
      }
    }
  }
  return paths;
}

function createSkeletonProject(root: TauriWorkspaceRootRecord): DetectionProject {
  return {
    rootId: root.rootId,
    rootPath: root.displayPath,
    name: root.label,
    files: [],
    expandedDirs: new Set<string>(),
  };
}

// ---- Build file tree from flat paths ----

/**
 * Build a hierarchical `ProjectFile[]` tree from a flat list of relative paths.
 *
 * Paths like `["sigma/windows/proc.yml", "yara/malware.yar", "policies/strict.yaml"]`
 * produce a nested tree with proper `isDirectory`, `children`, `depth`, and
 * `fileType` detection.
 *
 * File type detection for YAML files is ambiguous without content, so the
 * heuristic uses path segments: paths containing `sigma` resolve to
 * `sigma_rule`, paths containing `policies` or `rulesets` resolve to
 * `clawdstrike_policy`, and other YAML files default to `clawdstrike_policy`.
 */
export function buildFileTree(rootPath: string, paths: string[]): ProjectFile[] {
  // Intermediate tree node used during construction.
  interface TreeNode {
    name: string;
    path: string;
    isDirectory: boolean;
    children: Map<string, TreeNode>;
    depth: number;
  }

  const root: TreeNode = {
    name: "",
    path: "",
    isDirectory: true,
    children: new Map(),
    depth: -1,
  };

  // Insert each path segment-by-segment.
  for (const relPath of paths) {
    const segments = relPath.split("/").filter(Boolean);
    let current = root;
    let accumulated = "";

    for (let i = 0; i < segments.length; i++) {
      const segment = segments[i];
      accumulated = accumulated ? `${accumulated}/${segment}` : segment;
      const isLast = i === segments.length - 1;

      if (!current.children.has(segment)) {
        current.children.set(segment, {
          name: segment,
          path: accumulated,
          isDirectory: !isLast,
          children: new Map(),
          depth: i,
        });
      } else if (!isLast) {
        // Ensure intermediate nodes are marked as directories.
        const existing = current.children.get(segment)!;
        existing.isDirectory = true;
      }

      current = current.children.get(segment)!;
    }
  }

  // Convert the intermediate tree to ProjectFile[].
  function convert(node: TreeNode): ProjectFile[] {
    const entries = Array.from(node.children.values());

    // Sort: directories first, then alphabetical.
    entries.sort((a, b) => {
      if (a.isDirectory !== b.isDirectory) return a.isDirectory ? -1 : 1;
      return a.name.localeCompare(b.name);
    });

    return entries.map((entry): ProjectFile => {
      const fileType = entry.isDirectory
        ? inferFileTypeFromPath(entry.path, entry.name)
        : inferFileTypeFromPath(entry.path, entry.name);

      const children = entry.isDirectory ? convert(entry) : undefined;

      return {
        path: entry.path,
        name: entry.name,
        fileType,
        isDirectory: entry.isDirectory,
        children,
        depth: entry.depth,
      };
    });
  }

  return convert(root);
}

// ---- Tree mutation helpers ----

/**
 * Recursively walk a ProjectFile[] tree and apply a mutator when the target
 * node is found. Returns a new tree (shallow copies along the path).
 *
 * The mutator receives the parent's children array and the index of the
 * matching node, and must return the replacement children array.
 */
function mutateTree(
  files: ProjectFile[],
  targetPath: string,
  mutator: (siblings: ProjectFile[], index: number) => ProjectFile[],
): ProjectFile[] {
  for (let i = 0; i < files.length; i++) {
    if (files[i].path === targetPath) {
      return mutator([...files], i);
    }
    if (files[i].isDirectory && files[i].children) {
      const mutated = mutateTree(files[i].children!, targetPath, mutator);
      if (mutated !== files[i].children) {
        const copy = [...files];
        copy[i] = { ...copy[i], children: mutated };
        return copy;
      }
    }
  }
  return files;
}

/** Sort children: directories first, then alphabetical by name. */
function sortChildren(children: ProjectFile[]): ProjectFile[] {
  return [...children].sort((a, b) => {
    if (a.isDirectory !== b.isDirectory) return a.isDirectory ? -1 : 1;
    return a.name.localeCompare(b.name);
  });
}

/**
 * Insert a new ProjectFile into a directory node's children. Returns new tree.
 */
function insertIntoDir(
  files: ProjectFile[],
  parentPath: string,
  newNode: ProjectFile,
): ProjectFile[] {
  for (let i = 0; i < files.length; i++) {
    if (files[i].path === parentPath && files[i].isDirectory) {
      const copy = [...files];
      const updatedChildren = sortChildren([...(copy[i].children ?? []), newNode]);
      copy[i] = { ...copy[i], children: updatedChildren };
      return copy;
    }
    if (files[i].isDirectory && files[i].children) {
      const mutated = insertIntoDir(files[i].children!, parentPath, newNode);
      if (mutated !== files[i].children) {
        const copy = [...files];
        copy[i] = { ...copy[i], children: mutated };
        return copy;
      }
    }
  }
  return files;
}

/**
 * Infer a FileType from a path string. For unambiguous extensions (.yar, .json)
 * the result is deterministic. For YAML files we use path-segment heuristics.
 */
function inferFileTypeFromPath(relPath: string, name: string): FileType {
  // .swarm bundle directories treated as leaf files
  if (name.endsWith(".swarm")) return "swarm_bundle";

  // Unambiguous by extension
  const byExt = getFileTypeByExtension(name);
  if (byExt !== null) return byExt;

  // YAML heuristic: check path segments
  const lowerPath = relPath.toLowerCase();
  if (lowerPath.includes("sigma")) return "sigma_rule";
  if (lowerPath.includes("policies") || lowerPath.includes("rulesets")) {
    return "clawdstrike_policy";
  }

  // Default for YAML
  return "clawdstrike_policy";
}

function moveFileStatus(
  fileStatuses: Map<string, FileStatus>,
  rootPath: string,
  oldRelPath: string,
  newRelPath: string,
): Map<string, FileStatus> {
  const oldKey = getProjectFileStatusKey(rootPath, oldRelPath);
  const existingStatus = fileStatuses.get(oldKey);
  if (!existingStatus) {
    return fileStatuses;
  }

  const newKey = getProjectFileStatusKey(rootPath, newRelPath);
  const next = new Map(fileStatuses);
  next.delete(oldKey);
  next.set(newKey, existingStatus);
  return next;
}

function deleteFileStatus(
  fileStatuses: Map<string, FileStatus>,
  rootPath: string,
  relPath: string,
): Map<string, FileStatus> {
  const key = getProjectFileStatusKey(rootPath, relPath);
  if (!fileStatuses.has(key)) {
    return fileStatuses;
  }

  const next = new Map(fileStatuses);
  next.delete(key);
  return next;
}

// ---- Zustand store ----

interface ProjectStoreState extends ProjectState {
  actions: {
    /** Set the current project. */
    setProject: (project: DetectionProject) => void;
    /** Clear the current project. */
    clearProject: () => void;
    /** Set the loading state. */
    setLoading: (loading: boolean) => void;
    /** Set the error state. */
    setError: (error: string | null) => void;
    /** Toggle a directory's expand/collapse state. */
    toggleDir: (path: string) => void;
    /** Set the free-text filename filter. */
    setFilter: (filter: string) => void;
    /** Set the format filter (or null to clear). */
    setFormatFilter: (format: FileType | null) => void;
    /** Expand all directories. */
    expandAll: () => void;
    /** Collapse all directories. */
    collapseAll: () => void;
    /** Create a new file in the given directory. Returns the new file path or null. */
    createFile: (parentDirPath: string, fileName: string, fileType: FileType) => Promise<string | null>;
    /** Rename a file. Returns true on success. */
    renameFile: (oldPath: string, newName: string) => Promise<boolean>;
    /** Delete a file. Returns true on success. */
    deleteFile: (filePath: string) => Promise<boolean>;
    /** Create a directory. Returns true on success. */
    createDirectory: (parentDirPath: string, folderName: string) => Promise<boolean>;
    /** Set or merge file status flags for a given file path. */
    setFileStatus: (filePath: string, status: FileStatus) => void;
    /** Clear file status for a given file path. */
    clearFileStatus: (filePath: string) => void;
    /** Hydrate the workspace registry snapshot from the backend authority. */
    hydrateWorkspaceRegistry: (snapshot: TauriWorkspaceRegistrySnapshot) => void;
    /** Add a root folder to the multi-root workspace. */
    addRoot: (rootPath: string) => Promise<void>;
    /** Remove a root folder from the multi-root workspace. */
    removeRoot: (rootPath: string) => Promise<void>;
    /** Scan a root directory and populate its DetectionProject. */
    loadRoot: (rootPath: string) => Promise<void>;
    /** Kick off scans for the currently hydrated backend workspace registry. */
    initFromWorkspaceRegistry: () => Promise<void>;
    /** Wait until the current workspace roots reach a terminal state or time out. */
    waitForRootsReady: (timeoutMs?: number) => Promise<WorkspaceRootsReadyResult>;
    /** Toggle expand/collapse for a directory within a specific root. */
    toggleDirForRoot: (rootPath: string, dirPath: string) => void;
  };
}

const useProjectStoreBase = create<ProjectStoreState>()((set, get) => ({
  project: null,
  loading: false,
  error: null,
  filter: "",
  formatFilter: null,
  fileStatuses: new Map<string, FileStatus>(),
  defaultRootId: null,
  orderedRootIds: [],
  rootsById: new Map<string, TauriWorkspaceRootRecord>(),
  rootStatusById: new Map<string, ProjectRootStatus>(),
  rootErrorById: new Map<string, string | null>(),
  rootRequestedVersionById: new Map<string, number>(),
  rootCommittedVersionById: new Map<string, number>(),
  rootMutationById: new Map<string, ProjectMutationState | null>(),
  projectsById: new Map<string, DetectionProject>(),
  projectRoots: [],
  projects: new Map<string, DetectionProject>(),

  actions: {
    setProject: (project: DetectionProject) => {
      set({ project, loading: false, error: null });
    },

    clearProject: () => {
      set({ project: null, error: null, filter: "", formatFilter: null, fileStatuses: new Map() });
    },

    setLoading: (loading: boolean) => {
      set({ loading });
    },

    setError: (error: string | null) => {
      set({ error, loading: false });
    },

    toggleDir: (path: string) => {
      const { project } = get();
      if (!project) return;
      const next = new Set(project.expandedDirs);
      if (next.has(path)) {
        next.delete(path);
      } else {
        next.add(path);
      }
      set({ project: { ...project, expandedDirs: next } });
    },

    setFilter: (filter: string) => {
      set({ filter });
    },

    setFormatFilter: (format: FileType | null) => {
      set({ formatFilter: format });
    },

    expandAll: () => {
      const state = get();
      if (state.projectsById.size > 0) {
        const nextProjectsById = new Map(state.projectsById);
        for (const [rootId, project] of state.projectsById) {
          nextProjectsById.set(rootId, {
            ...project,
            expandedDirs: new Set(collectDirPaths(project.files)),
          });
        }
        set(buildProjectSelectionPatch(state.orderedRootIds, state.rootsById, nextProjectsById));
        return;
      }

      if (!state.project) return;
      const allDirs = collectDirPaths(state.project.files);
      set({ project: { ...state.project, expandedDirs: new Set(allDirs) } });
    },

    collapseAll: () => {
      const state = get();
      if (state.projectsById.size > 0) {
        const nextProjectsById = new Map(state.projectsById);
        for (const [rootId, project] of state.projectsById) {
          nextProjectsById.set(rootId, {
            ...project,
            expandedDirs: new Set<string>(),
          });
        }
        set(buildProjectSelectionPatch(state.orderedRootIds, state.rootsById, nextProjectsById));
        return;
      }

      if (!state.project) return;
      set({ project: { ...state.project, expandedDirs: new Set<string>() } });
    },

    createFile: async (parentDirPath: string, fileName: string, fileType: FileType): Promise<string | null> => {
      const state = get();
      const rootPath = resolveOwningRootPath(state, parentDirPath);
      const project = getProjectForRoot(state, rootPath);
      const root = rootPath
        ? findRootRecordByExactPath(state.rootsById, state.orderedRootIds, rootPath)
        : null;
      if (!project || !rootPath || !root) return null;

      const trimmedName = fileName.trim();
      if (!isValidProjectBasename(trimmedName)) {
        return null;
      }

      const parentRelPath = relativePathWithinRoot(rootPath, parentDirPath);
      const optimisticRelPath = parentRelPath ? `${parentRelPath}/${trimmedName}` : trimmedName;

      let savedPath: string | null = null;
      try {
        const { createDetectionFile } = await import("@/lib/tauri-bridge");
        savedPath = await createDetectionFile(parentDirPath, trimmedName, fileType);
      } catch (error) {
        const message = resolveMutationFailureMessage(error, `Failed to create ${trimmedName}.`);
        set({
          ...buildRootMutationPatch(
            get(),
            root.rootId,
            createRootMutationState(
              root,
              "create_file",
              "error",
              optimisticRelPath,
              trimmedName,
              message,
            ),
          ),
        });
        return null;
      }
      if (!savedPath) {
        set({
          ...buildRootMutationPatch(
            get(),
            root.rootId,
            createRootMutationState(
              root,
              "create_file",
              "error",
              optimisticRelPath,
              trimmedName,
              `Failed to create ${trimmedName}.`,
            ),
          ),
        });
        return null;
      }

      const relPath = relativePathWithinRoot(rootPath, savedPath) || trimmedName;

      // Compute depth from relative path segments.
      const depth = relPath.split("/").filter(Boolean).length - 1;

      const newNode: ProjectFile = {
        path: relPath,
        name: trimmedName,
        fileType: inferFileTypeFromPath(relPath, trimmedName),
        isDirectory: false,
        depth,
      };

      // Insert into tree and auto-expand the parent directory.
      let newFiles: ProjectFile[];
      if (parentRelPath === "" || parentDirPath === project.rootPath) {
        // Inserting at root level.
        newFiles = sortChildren([...project.files, newNode]);
      } else {
        newFiles = insertIntoDir(project.files, parentRelPath, newNode);
      }

      const expandedDirs = new Set(project.expandedDirs);
      if (parentRelPath) {
        expandedDirs.add(parentRelPath);
      }

      const nextProject = { ...project, files: newFiles, expandedDirs };
      const nextProjectsById = new Map(get().projectsById);
      nextProjectsById.set(root.rootId, nextProject);
      set({
        ...buildProjectSelectionPatch(get().orderedRootIds, get().rootsById, nextProjectsById),
        ...buildRootMutationPatch(
          get(),
          root.rootId,
          createRootMutationState(root, "create_file", "pending", relPath, trimmedName, null),
        ),
      });
      // Re-scan from disk to ensure tree is in sync (catches nested dir creation, etc.)
      void get().actions.loadRoot(rootPath);
      return savedPath;
    },

    renameFile: async (oldPath: string, newName: string): Promise<boolean> => {
      const state = get();
      const target = resolveWorkspaceTarget(state, oldPath);
      const project = getProjectForRoot(state, target?.rootPath ?? null);
      if (!project || !target) return false;

      const trimmedName = newName.trim();
      if (!isValidProjectBasename(trimmedName)) {
        return false;
      }

      const oldAbsPath = target.absolutePath;
      const newAbsPath = replaceProjectPathBasename(oldAbsPath, trimmedName);
      const newRelPath = relativePathWithinRoot(target.rootPath, newAbsPath);
      let response;
      try {
        response = await renameWorkspaceEntryNative(
          target.root.rootId,
          target.relativePath,
          newRelPath,
        );
      } catch (error) {
        const message = resolveMutationFailureMessage(error, `Failed to rename ${project.name}.`);
        set({
          ...buildRootMutationPatch(
            get(),
            target.root.rootId,
            createRootMutationState(
              target.root,
              "rename",
              "error",
              target.relativePath,
              getProjectPathBasename(oldAbsPath),
              message,
            ),
          ),
        });
        return false;
      }
      if (!response?.ok) {
        if (response && !response.ok) {
          console.warn("[project-store] Failed to rename workspace entry:", response.error);
          set({
            ...buildRootMutationPatch(
              get(),
              target.root.rootId,
              createRootMutationState(
                target.root,
                "rename",
                "error",
                target.relativePath,
                getProjectPathBasename(oldAbsPath),
                response.error.message,
              ),
            ),
          });
        }
        return false;
      }

      const tabsStore = usePolicyTabsStore.getState();
      const previousName = getProjectPathBasename(oldAbsPath);
      const renamedTabIds = tabsStore.tabs
        .filter((tab) => tab.filePath === oldAbsPath)
        .map((tab) => tab.id);
      for (const tabId of renamedTabIds) {
        tabsStore.setFilePath(tabId, newAbsPath);
        const renamedTab = tabsStore.tabs.find((tab) => tab.id === tabId);
        if (renamedTab?.name === previousName) {
          tabsStore.renameTab(tabId, trimmedName);
        }
      }
      getDocumentIdentityStore().move(oldAbsPath, newAbsPath);

      const oldRelPath = target.relativePath;

      const newFiles = mutateTree(project.files, oldRelPath, (siblings, idx) => {
        siblings[idx] = {
          ...siblings[idx],
          name: trimmedName,
          path: newRelPath,
          fileType: inferFileTypeFromPath(newRelPath, trimmedName),
        };
        return sortChildren(siblings);
      });

      const fileStatuses = moveFileStatus(
        get().fileStatuses,
        target.rootPath,
        oldRelPath,
        newRelPath,
      );
      const nextProject = { ...project, files: newFiles };
      const nextProjectsById = new Map(get().projectsById);
      nextProjectsById.set(target.root.rootId, nextProject);
      set({
        ...buildProjectSelectionPatch(get().orderedRootIds, get().rootsById, nextProjectsById),
        ...buildRootMutationPatch(
          get(),
          target.root.rootId,
          createRootMutationState(target.root, "rename", "pending", newRelPath, trimmedName, null),
        ),
        fileStatuses,
      });
      // Re-scan from disk to pick up any side effects of the rename.
      void get().actions.loadRoot(target.rootPath);
      return true;
    },

    deleteFile: async (filePath: string): Promise<boolean> => {
      const state = get();
      const target = resolveWorkspaceTarget(state, filePath);
      const project = getProjectForRoot(state, target?.rootPath ?? null);
      if (!project || !target) return false;

      let response;
      try {
        response = await deleteWorkspaceEntryNative(
          target.root.rootId,
          target.relativePath,
        );
      } catch (error) {
        const message = resolveMutationFailureMessage(error, `Failed to delete ${target.relativePath}.`);
        set({
          ...buildRootMutationPatch(
            get(),
            target.root.rootId,
            createRootMutationState(
              target.root,
              "delete",
              "error",
              target.relativePath,
              getProjectPathBasename(target.absolutePath),
              message,
            ),
          ),
        });
        return false;
      }
      if (!response?.ok) {
        if (response && !response.ok) {
          console.warn("[project-store] Failed to delete workspace entry:", response.error);
          set({
            ...buildRootMutationPatch(
              get(),
              target.root.rootId,
              createRootMutationState(
                target.root,
                "delete",
                "error",
                target.relativePath,
                getProjectPathBasename(target.absolutePath),
                response.error.message,
              ),
            ),
          });
        }
        return false;
      }

      const absPath = target.absolutePath;
      const relPath = target.relativePath;

      const newFiles = mutateTree(project.files, relPath, (siblings, idx) => {
        siblings.splice(idx, 1);
        return siblings;
      });

      const tabsStore = usePolicyTabsStore.getState();
      const tabsToClose = tabsStore.tabs
        .filter((tab) => tab.filePath === absPath)
        .map((tab) => tab.id);
      for (const tabId of tabsToClose) {
        tabsStore.closeTab(tabId);
      }
      getDocumentIdentityStore().unregister(absPath);
      const fileStatuses = deleteFileStatus(get().fileStatuses, target.rootPath, relPath);
      const nextProject = { ...project, files: newFiles };
      const nextProjectsById = new Map(get().projectsById);
      nextProjectsById.set(target.root.rootId, nextProject);
      set({
        ...buildProjectSelectionPatch(get().orderedRootIds, get().rootsById, nextProjectsById),
        ...buildRootMutationPatch(
          get(),
          target.root.rootId,
          createRootMutationState(
            target.root,
            "delete",
            "pending",
            target.relativePath,
            getProjectPathBasename(target.absolutePath),
            null,
          ),
        ),
        fileStatuses,
      });
      // Re-scan from disk to ensure deleted file (and any empty parent dirs) are gone.
      void get().actions.loadRoot(target.rootPath);
      return true;
    },

    createDirectory: async (parentDirPath: string, folderName: string): Promise<boolean> => {
      const state = get();
      const target = resolveWorkspaceTarget(state, parentDirPath);
      if (!target) return false;

      const trimmedName = folderName.trim();
      if (!isValidProjectBasename(trimmedName)) {
        return false;
      }

      const relativePath = target.relativePath
        ? `${target.relativePath}/${trimmedName}`
        : trimmedName;

      let response;
      try {
        response = await createWorkspaceDirectoryNative(
          target.root.rootId,
          relativePath,
        );
      } catch (error) {
        const message = resolveMutationFailureMessage(error, `Failed to create ${trimmedName}.`);
        set({
          ...buildRootMutationPatch(
            get(),
            target.root.rootId,
            createRootMutationState(
              target.root,
              "create_folder",
              "error",
              relativePath,
              trimmedName,
              message,
            ),
          ),
        });
        return false;
      }
      if (!response?.ok) {
        if (response && !response.ok) {
          console.warn("[project-store] Failed to create workspace directory:", response.error);
          set({
            ...buildRootMutationPatch(
              get(),
              target.root.rootId,
              createRootMutationState(
                target.root,
                "create_folder",
                "error",
                relativePath,
                trimmedName,
                response.error.message,
              ),
            ),
          });
        }
        return false;
      }

      const currentProject = get().projectsById.get(target.root.rootId) ?? createSkeletonProject(target.root);
      const depth = relativePath.split("/").filter(Boolean).length - 1;
      const newNode: ProjectFile = {
        path: relativePath,
        name: trimmedName,
        fileType: inferFileTypeFromPath(relativePath, trimmedName),
        isDirectory: true,
        depth,
        children: [],
      };
      const nextFiles = target.relativePath === ""
        ? sortChildren([...currentProject.files, newNode])
        : insertIntoDir(currentProject.files, target.relativePath, newNode);
      const nextExpandedDirs = new Set(currentProject.expandedDirs);
      if (target.relativePath) {
        nextExpandedDirs.add(target.relativePath);
      }
      nextExpandedDirs.add(relativePath);
      const nextProject = { ...currentProject, files: nextFiles, expandedDirs: nextExpandedDirs };
      const nextProjectsById = new Map(get().projectsById);
      nextProjectsById.set(target.root.rootId, nextProject);
      set({
        ...buildProjectSelectionPatch(get().orderedRootIds, get().rootsById, nextProjectsById),
        ...buildRootMutationPatch(
          get(),
          target.root.rootId,
          createRootMutationState(target.root, "create_folder", "pending", relativePath, trimmedName, null),
        ),
      });
      void get().actions.loadRoot(target.rootPath);
      return true;
    },

    setFileStatus: (filePath: string, status: FileStatus) => {
      const key = getFileStatusKeyForPath(get(), filePath);
      if (!key) return;
      const next = new Map(get().fileStatuses);
      next.set(key, { ...next.get(key), ...status });
      set({ fileStatuses: next });
    },

    clearFileStatus: (filePath: string) => {
      const key = getFileStatusKeyForPath(get(), filePath);
      if (!key) return;
      const next = new Map(get().fileStatuses);
      next.delete(key);
      set({ fileStatuses: next });
    },

    hydrateWorkspaceRegistry: (snapshot: TauriWorkspaceRegistrySnapshot) => {
      set((state) => applyWorkspaceRegistrySnapshot(state, snapshot));
    },

    addRoot: async (rootPath: string) => {
      const normalizedRootPath = normalizeWorkspacePath(rootPath);
      const existingRoot = findRootRecordByExactPath(
        get().rootsById,
        get().orderedRootIds,
        normalizedRootPath,
      );
      if (existingRoot) {
        await get().actions.loadRoot(existingRoot.displayPath);
        return;
      }

      const snapshot = await addWorkspaceRootNative(normalizedRootPath);
      if (!snapshot) {
        console.warn("[project-store] Failed to add root through workspace registry:", normalizedRootPath);
        return;
      }

      set((state) => applyWorkspaceRegistrySnapshot(state, snapshot));
      const addedRoot = findRootRecordByExactPath(
        get().rootsById,
        get().orderedRootIds,
        normalizedRootPath,
      );
      if (addedRoot) {
        void get().actions.loadRoot(addedRoot.displayPath);
      }
    },

    loadRoot: async (rootPath: string) => {
      const root = findRootRecordByExactPath(get().rootsById, get().orderedRootIds, rootPath)
        ?? resolveRootRecordForAbsolutePath(get().rootsById, get().orderedRootIds, rootPath);
      if (!root) return;

      const skeletonProject = createSkeletonProject(root);
      const beforeRequest = get();
      const existingProject = beforeRequest.projectsById.get(root.rootId);
      const nextRequestedVersion = (beforeRequest.rootRequestedVersionById.get(root.rootId) ?? 0) + 1;
      const hasCommittedSnapshot = (beforeRequest.rootCommittedVersionById.get(root.rootId) ?? 0) > 0;
      const nextStatus: ProjectRootStatus = hasCommittedSnapshot ? "refreshing" : "loading";

      logWorkspaceRootEvent("info", "scan_started", {
        rootId: root.rootId,
        rootPath: root.displayPath,
        requestedVersion: nextRequestedVersion,
        previousCommittedVersion: beforeRequest.rootCommittedVersionById.get(root.rootId) ?? 0,
        status: nextStatus,
      });

      // Publish the root immediately so the Explorer shows it even if the
      // native scan is still in flight or hangs during dev reload churn.
      const initialProjectsById = new Map(beforeRequest.projectsById);
      if (!existingProject) {
        initialProjectsById.set(root.rootId, skeletonProject);
      }
      set({
        ...buildProjectSelectionPatch(get().orderedRootIds, get().rootsById, initialProjectsById),
        ...buildRootMetadataPatch(beforeRequest, root.rootId, {
          status: nextStatus,
          error: null,
          requestedVersion: nextRequestedVersion,
        }),
      });

      try {
        const response = await readWorkspaceTreeNative(root.rootId);
        const afterRead = get();
        if ((afterRead.rootRequestedVersionById.get(root.rootId) ?? 0) !== nextRequestedVersion) {
          logWorkspaceRootEvent("info", "scan_discarded_stale_result", {
            rootId: root.rootId,
            rootPath: root.displayPath,
            requestedVersion: nextRequestedVersion,
            latestRequestedVersion: afterRead.rootRequestedVersionById.get(root.rootId) ?? 0,
          });
          return;
        }

        if (!response) {
          const message = `Workspace tree read returned no response for ${root.displayPath}`;
          logWorkspaceRootEvent("warn", "scan_failed_missing_response", {
            rootId: root.rootId,
            rootPath: root.displayPath,
            requestedVersion: nextRequestedVersion,
            message,
          });
          const nextFailureStatus: ProjectRootStatus = hasCommittedSnapshot ? "stale" : "error";
          const mutation = afterRead.rootMutationById.get(root.rootId);
          set({
            ...buildRootMetadataPatch(afterRead, root.rootId, {
              status: nextFailureStatus,
              error: message,
            }),
            ...buildRootMutationPatch(
              afterRead,
              root.rootId,
              mutation?.status === "pending" ? buildMutationFailureState(mutation, message) : mutation ?? null,
            ),
          });
          return;
        }
        if (!response.ok) {
          logWorkspaceRootEvent("warn", "scan_failed_command_error", {
            rootId: root.rootId,
            rootPath: root.displayPath,
            requestedVersion: nextRequestedVersion,
            code: response.error.code,
            path: response.error.path ?? null,
            message: response.error.message,
          });
          const nextFailureStatus: ProjectRootStatus = hasCommittedSnapshot ? "stale" : "error";
          const mutation = afterRead.rootMutationById.get(root.rootId);
          set({
            ...buildRootMetadataPatch(afterRead, root.rootId, {
              status: nextFailureStatus,
              error: response.error.message,
            }),
            ...buildRootMutationPatch(
              afterRead,
              root.rootId,
              mutation?.status === "pending"
                ? buildMutationFailureState(mutation, response.error.message)
                : mutation ?? null,
            ),
          });
          return;
        }

        const paths = workspaceTreeEntriesToPaths(response.data.entries);
        const files = buildFileTree(root.displayPath, paths);
        const allDirs = collectDirPaths(files);
        const previousProject = get().projectsById.get(root.rootId);

        const dp: DetectionProject = {
          ...skeletonProject,
          files,
          expandedDirs: resolveCommittedExpandedDirs(previousProject, allDirs),
        };

        const newProjectsById = new Map(get().projectsById);
        newProjectsById.set(root.rootId, dp);
        const committedState = get();
        if ((committedState.rootRequestedVersionById.get(root.rootId) ?? 0) !== nextRequestedVersion) {
          logWorkspaceRootEvent("info", "scan_discarded_stale_commit", {
            rootId: root.rootId,
            rootPath: root.displayPath,
            requestedVersion: nextRequestedVersion,
            latestRequestedVersion: committedState.rootRequestedVersionById.get(root.rootId) ?? 0,
          });
          return;
        }
        const committedStatus = files.length === 0 ? "empty" : "ready";
        logWorkspaceRootEvent("info", "scan_committed", {
          rootId: root.rootId,
          rootPath: root.displayPath,
          requestedVersion: nextRequestedVersion,
          committedVersion: nextRequestedVersion,
          status: committedStatus,
          entryCount: response.data.entries.length,
        });
        set({
          ...buildProjectSelectionPatch(get().orderedRootIds, get().rootsById, newProjectsById),
          ...buildRootMetadataPatch(committedState, root.rootId, {
            status: committedStatus,
            error: null,
            committedVersion: nextRequestedVersion,
          }),
          ...buildRootMutationPatch(committedState, root.rootId, null),
        });
      } catch (err) {
        const failedState = get();
        if ((failedState.rootRequestedVersionById.get(root.rootId) ?? 0) !== nextRequestedVersion) {
          return;
        }
        const nextFailureStatus: ProjectRootStatus = hasCommittedSnapshot ? "stale" : "error";
        const message = formatWorkspaceError(err);
        logWorkspaceRootEvent("error", "scan_failed_exception", {
          rootId: root.rootId,
          rootPath: root.displayPath,
          requestedVersion: nextRequestedVersion,
          message,
        });
        const mutation = failedState.rootMutationById.get(root.rootId);
        set({
          ...buildRootMetadataPatch(failedState, root.rootId, {
            status: nextFailureStatus,
            error: message,
          }),
          ...buildRootMutationPatch(
            failedState,
            root.rootId,
            mutation?.status === "pending" ? buildMutationFailureState(mutation, message) : mutation ?? null,
          ),
        });
      }
    },

    removeRoot: async (rootPath: string) => {
      const root = findRootRecordByExactPath(get().rootsById, get().orderedRootIds, rootPath);
      if (!root) return;

      const snapshot = await removeWorkspaceRootNative(root.rootId);
      if (!snapshot) {
        console.warn("[project-store] Failed to remove root through workspace registry:", rootPath);
        return;
      }

      set((state) => applyWorkspaceRegistrySnapshot(state, snapshot));
    },

    initFromWorkspaceRegistry: async () => {
      const roots = get().orderedRootIds
        .map((rootId) => get().rootsById.get(rootId)?.displayPath ?? null)
        .filter((rootPath): rootPath is string => rootPath != null);
      if (roots.length === 0) return;
      // Kick scans off in the background so bootstrap can paint placeholder
      // roots immediately instead of waiting for Tauri FS round-trips.
      for (const root of roots) {
        void get().actions.loadRoot(root);
      }
    },

    waitForRootsReady: async (timeoutMs = 5_000) => {
      const targetRootIds = get().orderedRootIds.filter((rootId) => get().rootsById.has(rootId));
      if (targetRootIds.length === 0) {
        return { ready: true, pendingRootIds: [], elapsedMs: 0 };
      }

      const startedAt = Date.now();
      while (Date.now() - startedAt < timeoutMs) {
        const state = get();
        const allReady = targetRootIds.every((rootId) => {
          const status = state.rootStatusById.get(rootId);
          return isTerminalRootStatus(status);
        });
        if (allReady) {
          return { ready: true, pendingRootIds: [], elapsedMs: Date.now() - startedAt };
        }
        await new Promise((resolve) => setTimeout(resolve, 25));
      }

      const finalState = get();
      const pendingRootIds = targetRootIds.filter((rootId) => {
        const status = finalState.rootStatusById.get(rootId);
        return !isTerminalRootStatus(status);
      });
      return {
        ready: pendingRootIds.length === 0,
        pendingRootIds,
        elapsedMs: Date.now() - startedAt,
      };
    },

    toggleDirForRoot: (rootPath: string, dirPath: string) => {
      const root = findRootRecordByExactPath(get().rootsById, get().orderedRootIds, rootPath);
      if (!root) return;
      const { projectsById } = get();
      const dp = projectsById.get(root.rootId);
      if (!dp) return;
      const next = new Set(dp.expandedDirs);
      if (next.has(dirPath)) {
        next.delete(dirPath);
      } else {
        next.add(dirPath);
      }
      const updated = { ...dp, expandedDirs: next };
      const newProjectsById = new Map(projectsById);
      newProjectsById.set(root.rootId, updated);
      set(buildProjectSelectionPatch(get().orderedRootIds, get().rootsById, newProjectsById));
    },
  },
}));

export const useProjectStore = createSelectors(useProjectStoreBase);

// ---------------------------------------------------------------------------
// Backward-compatible hook
// ---------------------------------------------------------------------------

interface ProjectContextValue {
  state: ProjectState;
  dispatch: never;
  /** Toggle a directory's expand/collapse state. */
  toggleDir: (path: string) => void;
  /** Set the free-text filename filter. */
  setFilter: (filter: string) => void;
  /** Set the format filter (or null to clear). */
  setFormatFilter: (format: FileType | null) => void;
  /** Expand all directories. */
  expandAll: () => void;
  /** Collapse all directories. */
  collapseAll: () => void;
  /** Set the current project. */
  setProject: (project: DetectionProject) => void;
  /** Clear the current project. */
  clearProject: () => void;
}

/** @deprecated Use useProjectStore directly */
export function useProject(): ProjectContextValue {
  const project = useProjectStore((s) => s.project);
  const loading = useProjectStore((s) => s.loading);
  const error = useProjectStore((s) => s.error);
  const filter = useProjectStore((s) => s.filter);
  const formatFilter = useProjectStore((s) => s.formatFilter);
  const actions = useProjectStore((s) => s.actions);

  return {
    state: {
      project,
      loading,
      error,
      filter,
      formatFilter,
      fileStatuses: new Map(),
      defaultRootId: null,
      orderedRootIds: [],
      rootsById: new Map(),
      rootStatusById: new Map(),
      rootErrorById: new Map(),
      rootRequestedVersionById: new Map(),
      rootCommittedVersionById: new Map(),
      rootMutationById: new Map(),
      projectsById: new Map(),
      projectRoots: [],
      projects: new Map(),
    },
    dispatch: undefined as never,
    toggleDir: actions.toggleDir,
    setFilter: actions.setFilter,
    setFormatFilter: actions.setFormatFilter,
    expandAll: actions.expandAll,
    collapseAll: actions.collapseAll,
    setProject: actions.setProject,
    clearProject: actions.clearProject,
  };
}
