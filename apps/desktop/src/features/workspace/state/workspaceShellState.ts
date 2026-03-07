import type {
  WorkspaceEntry,
  WorkspaceRoot,
  WorkspaceServiceErrorPayload,
  WorkspaceShellSnapshot,
} from "@/services/workspace";

export type WorkspacePaneId = "main" | "right" | "bottom" | "workspace-tree" | "terminal";

export type WorkspaceRouteSection =
  | "workspace"
  | "tree"
  | "search"
  | "git"
  | "terminal"
  | "file";

export type WorkspaceAccessState = "loading" | "ready" | "empty" | "denied";

export interface WorkspaceTabFrame {
  id: string;
  title: string;
  relativePath: string;
  kind: "file" | "preview" | "search" | "git" | "terminal";
  pinned?: boolean;
}

export interface WorkspaceRouteState {
  section: WorkspaceRouteSection;
  activeFilePath?: string;
}

export interface WorkspaceTreeState {
  expandedPaths: string[];
  selectedPath?: string;
}

export interface WorkspacePaneLayout {
  treeWidth: number;
  rightWidth: number;
  bottomHeight: number;
}

export interface WorkspaceSurfaceState {
  roots: WorkspaceRoot[];
  activeRootId?: string;
  access: WorkspaceAccessState;
  focusedPane: WorkspacePaneId;
  route: WorkspaceRouteState;
  tree: WorkspaceTreeState;
  tabs: WorkspaceTabFrame[];
  layout: WorkspacePaneLayout;
  rootTree: WorkspaceEntry[];
  lastError?: WorkspaceServiceErrorPayload;
}

const DEFAULT_LAYOUT: WorkspacePaneLayout = {
  treeWidth: 300,
  rightWidth: 320,
  bottomHeight: 180,
};

function collectDirectoryPaths(entries: WorkspaceEntry[]): string[] {
  return entries.flatMap((entry) => {
    if (entry.kind !== "directory") return [];
    return [entry.relativePath, ...collectDirectoryPaths(entry.children ?? [])];
  });
}

export function createWorkspaceSurfaceState(
  snapshot?: WorkspaceShellSnapshot,
): WorkspaceSurfaceState {
  const roots = snapshot?.roots ?? [];
  const activeRootId = snapshot?.activeRootId ?? roots[0]?.id;
  const rootTree = snapshot?.tree ?? [];
  const suggestedTabs = snapshot?.suggestedTabs ?? [];
  const expandedPaths = collectDirectoryPaths(rootTree).slice(0, 2);
  const firstTab = suggestedTabs[0];

  return {
    roots,
    activeRootId,
    access: roots.length > 0 ? "ready" : "empty",
    focusedPane: "workspace-tree",
    route: {
      section: firstTab ? "file" : "workspace",
      activeFilePath: firstTab?.relativePath,
    },
    tree: {
      expandedPaths,
      selectedPath: firstTab?.relativePath,
    },
    tabs: suggestedTabs.map((tab) => ({
      id: tab.id,
      title: tab.title,
      relativePath: tab.relativePath,
      kind: tab.kind,
    })),
    layout: DEFAULT_LAYOUT,
    rootTree,
  };
}

export function setWorkspaceAccessDenied(
  state: WorkspaceSurfaceState,
  lastError: WorkspaceServiceErrorPayload,
): WorkspaceSurfaceState {
  return {
    ...state,
    access: "denied",
    lastError,
  };
}

export function setWorkspaceActiveRoot(
  state: WorkspaceSurfaceState,
  rootId: string,
): WorkspaceSurfaceState {
  return {
    ...state,
    activeRootId: rootId,
  };
}

export function focusWorkspacePane(
  state: WorkspaceSurfaceState,
  pane: WorkspacePaneId,
): WorkspaceSurfaceState {
  return {
    ...state,
    focusedPane: pane,
  };
}

export function toggleWorkspaceTreePath(
  state: WorkspaceSurfaceState,
  relativePath: string,
): WorkspaceSurfaceState {
  const expanded = new Set(state.tree.expandedPaths);
  if (expanded.has(relativePath)) {
    expanded.delete(relativePath);
  } else {
    expanded.add(relativePath);
  }

  return {
    ...state,
    tree: {
      ...state.tree,
      expandedPaths: Array.from(expanded),
    },
  };
}

export function selectWorkspacePath(
  state: WorkspaceSurfaceState,
  relativePath: string,
): WorkspaceSurfaceState {
  return {
    ...state,
    route: {
      section: "file",
      activeFilePath: relativePath,
    },
    tree: {
      ...state.tree,
      selectedPath: relativePath,
    },
    focusedPane: "main",
  };
}

export function upsertWorkspaceTab(
  state: WorkspaceSurfaceState,
  tab: WorkspaceTabFrame,
): WorkspaceSurfaceState {
  const existing = state.tabs.find((candidate) => candidate.id === tab.id);

  return {
    ...state,
    route: {
      section: tab.kind === "file" || tab.kind === "preview" ? "file" : tab.kind,
      activeFilePath: tab.relativePath || undefined,
    },
    tabs: existing
      ? state.tabs.map((candidate) => (candidate.id === tab.id ? tab : candidate))
      : [...state.tabs, tab],
  };
}

export function closeWorkspaceTab(
  state: WorkspaceSurfaceState,
  tabId: string,
): WorkspaceSurfaceState {
  const nextTabs = state.tabs.filter((tab) => tab.id !== tabId);
  const activeTab = nextTabs[nextTabs.length - 1];

  return {
    ...state,
    tabs: nextTabs,
    route: activeTab
      ? {
          section: activeTab.kind === "file" || activeTab.kind === "preview" ? "file" : activeTab.kind,
          activeFilePath: activeTab.relativePath,
        }
      : { section: "workspace" },
  };
}

export function getWorkspaceActiveTab(state: WorkspaceSurfaceState) {
  if (state.route.section !== "file" || !state.route.activeFilePath) {
    return state.tabs[state.tabs.length - 1];
  }

  return (
    state.tabs.find((tab) => tab.relativePath === state.route.activeFilePath) ??
    state.tabs[state.tabs.length - 1]
  );
}

export function parseWorkspaceRouteState(search: string): WorkspaceRouteState {
  const params = new URLSearchParams(search.startsWith("?") ? search.slice(1) : search);
  const section = params.get("section");
  const activeFilePath = params.get("file") ?? undefined;

  if (
    section === "tree" ||
    section === "search" ||
    section === "git" ||
    section === "terminal" ||
    section === "file"
  ) {
    return { section, activeFilePath };
  }

  return activeFilePath ? { section: "file", activeFilePath } : { section: "workspace" };
}

export function serializeWorkspaceRouteState(route: WorkspaceRouteState): string {
  const params = new URLSearchParams();

  if (route.section !== "workspace") {
    params.set("section", route.section);
  }

  if (route.activeFilePath) {
    params.set("file", route.activeFilePath);
  }

  const encoded = params.toString();
  return encoded ? `?${encoded}` : "";
}
