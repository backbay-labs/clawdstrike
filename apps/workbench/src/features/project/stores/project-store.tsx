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
  resolveWorkspaceRootPath,
} from "@/lib/workbench/path-utils";
import {
  getProjectPathBasename,
  isValidProjectBasename,
  replaceProjectPathBasename,
} from "@/features/project/utils/resolve-project-path";
import { getWorkbenchE2EBridge } from "@/lib/workbench/e2e-bridge";

const TAURI_FS_SPECIFIER = "@tauri-apps/plugin-fs";

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
  /** Absolute paths of mounted workspace roots (multi-root support). */
  projectRoots: string[];
  /** DetectionProject instances keyed by rootPath (one per mounted root). */
  projects: Map<string, DetectionProject>;
}

const FILE_STATUS_KEY_SEPARATOR = "::";

export function getProjectFileStatusKey(rootPath: string, filePath: string): string {
  const normalizedRoot = rootPath.replace(/\/+$/, "");
  const normalizedPath = filePath.replace(/^\/+/, "");
  return `${normalizedRoot}${FILE_STATUS_KEY_SEPARATOR}${normalizedPath}`;
}

function getPrimaryProject(
  projectRoots: string[],
  projects: Map<string, DetectionProject>,
): DetectionProject | null {
  const firstRoot = projectRoots[0];
  return firstRoot ? projects.get(firstRoot) ?? null : null;
}

function buildProjectSelectionPatch(
  projectRoots: string[],
  projects: Map<string, DetectionProject>,
): Pick<ProjectStoreState, "project" | "projects"> {
  return {
    project: getPrimaryProject(projectRoots, projects),
    projects,
  };
}

function resolveOwningRootPath(state: ProjectState, path: string): string | null {
  const normalizedPath = normalizeWorkspacePath(path);
  if (!isAbsoluteWorkspacePath(normalizedPath)) {
    return state.project?.rootPath ?? state.projectRoots[0] ?? null;
  }

  return resolveWorkspaceRootPath(state.projectRoots, normalizedPath) ?? state.project?.rootPath ?? null;
}

function getProjectForRoot(
  state: ProjectState,
  rootPath: string | null,
): DetectionProject | null {
  if (!rootPath) return null;
  return state.projects.get(rootPath) ?? (state.project?.rootPath === rootPath ? state.project : null);
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

// ---------------------------------------------------------------------------
// Multi-root persistence helpers
// ---------------------------------------------------------------------------

const STORAGE_KEY = "clawdstrike_workspace_roots";

/** Read persisted workspace roots from localStorage. */
function loadPersistedRoots(): string[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

/** Persist workspace roots to localStorage. */
function persistRoots(roots: string[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(roots));
  } catch {
    // localStorage may be unavailable in some environments.
  }
}

async function importTauriFs() {
  return import(/* @vite-ignore */ TAURI_FS_SPECIFIER);
}

async function readProjectDirEntries(dirPath: string) {
  const e2eBridge = getWorkbenchE2EBridge();
  if (e2eBridge?.readDetectionDir) {
    return e2eBridge.readDetectionDir(dirPath);
  }

  const { readDir } = await importTauriFs();
  return readDir(dirPath);
}

/**
 * Recursively scan a directory via Tauri fs readDir and collect relative paths.
 * Directories get a trailing "/" to distinguish them from files.
 */
async function scanDir(dirPath: string, basePath: string): Promise<string[]> {
  const entries = await readProjectDirEntries(dirPath);
  const paths: string[] = [];
  for (const entry of entries) {
    const fullPath = `${dirPath}/${entry.name}`;
    const relPath = fullPath.slice(basePath.length + 1);
    if (entry.isDirectory) {
      // .swarm bundle detection -- emit as leaf file, skip recursion
      if (entry.name.endsWith(".swarm")) {
        paths.push(relPath);
        continue;
      }
      paths.push(relPath + "/");
      const subPaths = await scanDir(fullPath, basePath);
      paths.push(...subPaths);
    } else {
      paths.push(relPath);
    }
  }
  return paths;
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
    /** Set or merge file status flags for a given file path. */
    setFileStatus: (filePath: string, status: FileStatus) => void;
    /** Clear file status for a given file path. */
    clearFileStatus: (filePath: string) => void;
    /** Add a root folder to the multi-root workspace. */
    addRoot: (rootPath: string) => void;
    /** Remove a root folder from the multi-root workspace. */
    removeRoot: (rootPath: string) => void;
    /** Scan a root directory and populate its DetectionProject. */
    loadRoot: (rootPath: string) => Promise<void>;
    /** Initialize the store from persisted workspace roots. */
    initFromPersistedRoots: () => Promise<void>;
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
  projectRoots: loadPersistedRoots(),
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
      if (state.projects.size > 0) {
        const nextProjects = new Map(state.projects);
        for (const [rootPath, project] of state.projects) {
          nextProjects.set(rootPath, {
            ...project,
            expandedDirs: new Set(collectDirPaths(project.files)),
          });
        }
        set(buildProjectSelectionPatch(state.projectRoots, nextProjects));
        return;
      }

      if (!state.project) return;
      const allDirs = collectDirPaths(state.project.files);
      set({ project: { ...state.project, expandedDirs: new Set(allDirs) } });
    },

    collapseAll: () => {
      const state = get();
      if (state.projects.size > 0) {
        const nextProjects = new Map(state.projects);
        for (const [rootPath, project] of state.projects) {
          nextProjects.set(rootPath, {
            ...project,
            expandedDirs: new Set<string>(),
          });
        }
        set(buildProjectSelectionPatch(state.projectRoots, nextProjects));
        return;
      }

      if (!state.project) return;
      set({ project: { ...state.project, expandedDirs: new Set<string>() } });
    },

    createFile: async (parentDirPath: string, fileName: string, fileType: FileType): Promise<string | null> => {
      const state = get();
      const rootPath = resolveOwningRootPath(state, parentDirPath);
      const project = getProjectForRoot(state, rootPath);
      if (!project || !rootPath) return null;

      const trimmedName = fileName.trim();
      if (!isValidProjectBasename(trimmedName)) {
        return null;
      }

      const { createDetectionFile } = await import("@/lib/tauri-bridge");
      const savedPath = await createDetectionFile(parentDirPath, trimmedName, fileType);
      if (!savedPath) return null;

      const relPath = relativePathWithinRoot(rootPath, savedPath) || trimmedName;
      const parentRelPath = relativePathWithinRoot(rootPath, parentDirPath);

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
      const nextProjects = new Map(get().projects);
      nextProjects.set(rootPath, nextProject);
      set(buildProjectSelectionPatch(get().projectRoots, nextProjects));
      // Re-scan from disk to ensure tree is in sync (catches nested dir creation, etc.)
      void get().actions.loadRoot(rootPath);
      return savedPath;
    },

    renameFile: async (oldPath: string, newName: string): Promise<boolean> => {
      const state = get();
      const rootPath = resolveOwningRootPath(state, oldPath);
      const project = getProjectForRoot(state, rootPath);
      if (!project || !rootPath) return false;

      const trimmedName = newName.trim();
      if (!isValidProjectBasename(trimmedName)) {
        return false;
      }

      // oldPath may be relative; resolve to absolute for Tauri APIs.
      const oldAbsPath = isAbsoluteWorkspacePath(oldPath)
        ? normalizeWorkspacePath(oldPath)
        : joinWorkspacePath(rootPath, oldPath);
      const newAbsPath = replaceProjectPathBasename(oldAbsPath, trimmedName);

      const { renameDetectionFile } = await import("@/lib/tauri-bridge");
      const ok = await renameDetectionFile(oldAbsPath, newAbsPath);
      if (!ok) return false;

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

      const oldRelPath = relativePathWithinRoot(rootPath, oldAbsPath);
      const newRelPath = relativePathWithinRoot(rootPath, newAbsPath);

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
        rootPath,
        oldRelPath,
        newRelPath,
      );
      const nextProject = { ...project, files: newFiles };
      const nextProjects = new Map(get().projects);
      nextProjects.set(rootPath, nextProject);
      set({ ...buildProjectSelectionPatch(get().projectRoots, nextProjects), fileStatuses });
      // Re-scan from disk to pick up any side effects of the rename.
      void get().actions.loadRoot(rootPath);
      return true;
    },

    deleteFile: async (filePath: string): Promise<boolean> => {
      const state = get();
      const rootPath = resolveOwningRootPath(state, filePath);
      const project = getProjectForRoot(state, rootPath);
      if (!project || !rootPath) return false;

      // filePath may be relative; resolve to absolute for Tauri APIs.
      const absPath = isAbsoluteWorkspacePath(filePath)
        ? normalizeWorkspacePath(filePath)
        : joinWorkspacePath(rootPath, filePath);

      const { deleteDetectionFile } = await import("@/lib/tauri-bridge");
      const ok = await deleteDetectionFile(absPath);
      if (!ok) return false;

      const relPath = relativePathWithinRoot(rootPath, absPath);

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
      const fileStatuses = deleteFileStatus(get().fileStatuses, rootPath, relPath);
      const nextProject = { ...project, files: newFiles };
      const nextProjects = new Map(get().projects);
      nextProjects.set(rootPath, nextProject);
      set({ ...buildProjectSelectionPatch(get().projectRoots, nextProjects), fileStatuses });
      // Re-scan from disk to ensure deleted file (and any empty parent dirs) are gone.
      void get().actions.loadRoot(rootPath);
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

    addRoot: (rootPath: string) => {
      const { projectRoots } = get();
      if (projectRoots.includes(rootPath)) return;
      const newRoots = [...projectRoots, rootPath];
      persistRoots(newRoots);
      set({ projectRoots: newRoots });
      // Trigger async scan (fire-and-forget from the synchronous action).
      get().actions.loadRoot(rootPath);
    },

    removeRoot: (rootPath: string) => {
      const { projectRoots, projects } = get();
      const newRoots = projectRoots.filter((r) => r !== rootPath);
      persistRoots(newRoots);
      const newProjects = new Map(projects);
      newProjects.delete(rootPath);
      set({
        projectRoots: newRoots,
        ...buildProjectSelectionPatch(newRoots, newProjects),
      });
    },

    loadRoot: async (rootPath: string) => {
      try {
        const paths = await scanDir(rootPath, rootPath);
        const files = buildFileTree(rootPath, paths);
        const normalizedRootPath = normalizeWorkspacePath(rootPath);
        const name = normalizedRootPath.split("/").filter(Boolean).pop() ?? "workspace";
        const allDirs = collectDirPaths(files);

        const dp: DetectionProject = {
          rootPath,
          name,
          files,
          expandedDirs: new Set(allDirs),
        };

        const newProjects = new Map(get().projects);
        newProjects.set(rootPath, dp);

        set(buildProjectSelectionPatch(get().projectRoots, newProjects));
      } catch (err) {
        console.error("[project-store] Failed to load root:", rootPath, err);
      }
    },

    initFromPersistedRoots: async () => {
      const roots = loadPersistedRoots();
      if (roots.length === 0) return;
      set({ projectRoots: roots });
      for (const root of roots) {
        await get().actions.loadRoot(root);
      }
    },

    toggleDirForRoot: (rootPath: string, dirPath: string) => {
      const { projects } = get();
      const dp = projects.get(rootPath);
      if (!dp) return;
      const next = new Set(dp.expandedDirs);
      if (next.has(dirPath)) {
        next.delete(dirPath);
      } else {
        next.add(dirPath);
      }
      const updated = { ...dp, expandedDirs: next };
      const newProjects = new Map(projects);
      newProjects.set(rootPath, updated);
      set(buildProjectSelectionPatch(get().projectRoots, newProjects));
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
    state: { project, loading, error, filter, formatFilter, fileStatuses: new Map(), projectRoots: [], projects: new Map() },
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
