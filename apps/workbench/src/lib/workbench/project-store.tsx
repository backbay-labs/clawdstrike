import {
  createContext,
  useContext,
  useReducer,
  useCallback,
  type ReactNode,
} from "react";
import type { FileType } from "./file-type-registry";
import { getFileTypeByExtension } from "./file-type-registry";

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

interface ProjectState {
  project: DetectionProject | null;
  loading: boolean;
  error: string | null;
  /** Free-text filename filter. */
  filter: string;
  /** Filter files by a specific format. */
  formatFilter: FileType | null;
}

type ProjectAction =
  | { type: "SET_PROJECT"; project: DetectionProject }
  | { type: "CLEAR_PROJECT" }
  | { type: "SET_LOADING"; loading: boolean }
  | { type: "SET_ERROR"; error: string | null }
  | { type: "TOGGLE_DIR"; path: string }
  | { type: "SET_FILTER"; filter: string }
  | { type: "SET_FORMAT_FILTER"; format: FileType | null }
  | { type: "EXPAND_ALL" }
  | { type: "COLLAPSE_ALL" };

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

/**
 * Infer a FileType from a path string. For unambiguous extensions (.yar, .json)
 * the result is deterministic. For YAML files we use path-segment heuristics.
 */
function inferFileTypeFromPath(relPath: string, name: string): FileType {
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

// ---- Reducer ----

const initialState: ProjectState = {
  project: null,
  loading: false,
  error: null,
  filter: "",
  formatFilter: null,
};

function projectReducer(state: ProjectState, action: ProjectAction): ProjectState {
  switch (action.type) {
    case "SET_PROJECT":
      return {
        ...state,
        project: action.project,
        loading: false,
        error: null,
      };

    case "CLEAR_PROJECT":
      return {
        ...state,
        project: null,
        error: null,
        filter: "",
        formatFilter: null,
      };

    case "SET_LOADING":
      return { ...state, loading: action.loading };

    case "SET_ERROR":
      return { ...state, error: action.error, loading: false };

    case "TOGGLE_DIR": {
      if (!state.project) return state;
      const next = new Set(state.project.expandedDirs);
      if (next.has(action.path)) {
        next.delete(action.path);
      } else {
        next.add(action.path);
      }
      return {
        ...state,
        project: { ...state.project, expandedDirs: next },
      };
    }

    case "SET_FILTER":
      return { ...state, filter: action.filter };

    case "SET_FORMAT_FILTER":
      return { ...state, formatFilter: action.format };

    case "EXPAND_ALL": {
      if (!state.project) return state;
      const allDirs = collectDirPaths(state.project.files);
      return {
        ...state,
        project: {
          ...state.project,
          expandedDirs: new Set(allDirs),
        },
      };
    }

    case "COLLAPSE_ALL": {
      if (!state.project) return state;
      return {
        ...state,
        project: {
          ...state.project,
          expandedDirs: new Set<string>(),
        },
      };
    }

    default:
      return state;
  }
}

// ---- Context ----

interface ProjectContextValue {
  state: ProjectState;
  dispatch: React.Dispatch<ProjectAction>;
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

const ProjectContext = createContext<ProjectContextValue | null>(null);

/** Access the project store. Must be used within a `ProjectProvider`. */
export function useProject(): ProjectContextValue {
  const ctx = useContext(ProjectContext);
  if (!ctx) throw new Error("useProject must be used within a ProjectProvider");
  return ctx;
}

// ---- Provider ----

export function ProjectProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(projectReducer, initialState);

  const toggleDir = useCallback(
    (path: string) => dispatch({ type: "TOGGLE_DIR", path }),
    [],
  );

  const setFilter = useCallback(
    (filter: string) => dispatch({ type: "SET_FILTER", filter }),
    [],
  );

  const setFormatFilter = useCallback(
    (format: FileType | null) => dispatch({ type: "SET_FORMAT_FILTER", format }),
    [],
  );

  const expandAll = useCallback(() => dispatch({ type: "EXPAND_ALL" }), []);
  const collapseAll = useCallback(() => dispatch({ type: "COLLAPSE_ALL" }), []);

  const setProject = useCallback(
    (project: DetectionProject) => dispatch({ type: "SET_PROJECT", project }),
    [],
  );

  const clearProject = useCallback(() => dispatch({ type: "CLEAR_PROJECT" }), []);

  const value: ProjectContextValue = {
    state,
    dispatch,
    toggleDir,
    setFilter,
    setFormatFilter,
    expandAll,
    collapseAll,
    setProject,
    clearProject,
  };

  return (
    <ProjectContext.Provider value={value}>
      {children}
    </ProjectContext.Provider>
  );
}
