import { create } from "zustand";
import {
  getWorkbenchRouteLabel,
  normalizeWorkbenchRoute,
} from "@/components/desktop/workbench-routes";
import {
  addViewToGroup,
  closePane as closePaneNode,
  createPaneGroup,
  findPaneGroup,
  getAdjacentPane,
  getAllPaneGroups,
  getFirstPaneGroup,
  getPaneActiveView,
  removeViewFromGroup,
  replaceNode,
  setActivePaneView,
  setPaneActiveRoute,
  splitPane as splitPaneNode,
  updatePaneSizes,
} from "./pane-tree";
import { usePolicyTabsStore, pushRecentFile } from "@/features/policy/stores/policy-tabs-store";
import { loadPaneSession, countFileViews } from "./pane-session";
import type { PaneFocusDirection, PaneGroup, PaneNode, PaneSplitDirection, PaneView } from "./pane-types";

function createPaneView(route: string): PaneView {
  const normalized = normalizeWorkbenchRoute(route);
  return {
    id: crypto.randomUUID(),
    route: normalized,
    label: getWorkbenchRouteLabel(normalized),
  };
}

function createInitialRoot(): PaneGroup {
  return createPaneGroup(createPaneView("/home"));
}

export function getActivePane(root: PaneNode, activePaneId: string): PaneGroup | null {
  return getAllPaneGroups(root).find((group) => group.id === activePaneId) ?? null;
}

export function getActivePaneRoute(root: PaneNode, activePaneId: string): string {
  const activePane = getActivePane(root, activePaneId);
  return getPaneActiveView(activePane ?? getFirstPaneGroup(root))?.route ?? "/home";
}

export interface PaneStore {
  root: PaneNode;
  activePaneId: string;
  syncRoute: (route: string) => void;
  splitPane: (paneId: string, direction: PaneSplitDirection) => void;
  closePane: (paneId: string) => void;
  setActivePane: (paneId: string) => void;
  resizeSplit: (splitId: string, sizes: [number, number]) => void;
  focusPane: (direction: PaneFocusDirection) => void;
  paneCount: () => number;
  /** Open a route as a new tab in the active pane, or focus an existing tab with that route. */
  openApp: (route: string, label?: string) => void;
  /** Close a specific view (tab) within a pane group. */
  closeView: (paneId: string, viewId: string) => void;
  /** Switch to a specific view (tab) within a pane group. */
  setActiveView: (paneId: string, viewId: string) => void;
  /** Close all views to the right of the given view in a pane group. */
  closeViewsToRight: (paneId: string, viewId: string) => void;
  /** Close all views except the active one (non-active = "saved"). */
  closeSavedViews: (paneId: string) => void;
  /** Close all views in a pane group except the one with the given viewId. */
  closeOtherViews: (paneId: string, viewId: string) => void;
  /** Open a file as a pane tab. Bridges to policy-tabs-store for content loading. */
  openFile: (filePath: string, label?: string, fileType?: string) => void;
  /** Restore pane tree from localStorage. Returns count of file views restored. */
  restoreSession: () => number;
  _reset: () => void;
}

// Attempt to restore a saved session at store creation time so the tree is
// immediately available (no flash of default Home before React hydrates).
const savedSession = loadPaneSession();
const initialRoot = savedSession?.root ?? createInitialRoot();
const initialActivePaneId = savedSession?.activePaneId ?? (initialRoot as PaneGroup).id;

export const usePaneStore = create<PaneStore>((set, get) => ({
  root: initialRoot,
  activePaneId: initialActivePaneId,

  syncRoute: (route) => {
    const normalized = normalizeWorkbenchRoute(route);
    const state = get();
    const activePane = getActivePane(state.root, state.activePaneId)
      ?? getFirstPaneGroup(state.root);

    // If the active view already shows this route, no-op.
    const activeView = getPaneActiveView(activePane);
    if (activeView && normalizeWorkbenchRoute(activeView.route) === normalized) {
      return;
    }

    // If another tab in the active pane already has this route, focus it.
    const existingView = activePane.views.find(
      (v) => normalizeWorkbenchRoute(v.route) === normalized,
    );
    if (existingView) {
      set((s) => ({
        root: setActivePaneView(s.root, s.activePaneId, existingView.id),
      }));
      return;
    }

    // Otherwise, replace the active view's route (original behavior).
    set((s) => ({
      root: setPaneActiveRoute(
        s.root,
        s.activePaneId,
        normalized,
        getWorkbenchRouteLabel(normalized),
      ),
    }));
  },

  splitPane: (paneId, direction) => {
    const current = getActivePane(get().root, paneId) ?? getFirstPaneGroup(get().root);
    const sourceView = getPaneActiveView(current) ?? createPaneView("/home");
    const sibling = createPaneGroup({
      ...sourceView,
      id: crypto.randomUUID(),
    });

    set((state) => ({
      root: splitPaneNode(state.root, paneId, direction, sibling),
      activePaneId: sibling.id,
    }));
  },

  closePane: (paneId) => {
    const nextRoot = closePaneNode(get().root, paneId);

    if (!nextRoot) {
      const fallbackRoot = createInitialRoot();
      set({
        root: fallbackRoot,
        activePaneId: fallbackRoot.id,
      });
      return;
    }

    const nextActivePane = getFirstPaneGroup(nextRoot);
    set({
      root: nextRoot,
      activePaneId: nextActivePane.id,
    });
  },

  setActivePane: (paneId) => {
    if (!getActivePane(get().root, paneId)) return;
    set({ activePaneId: paneId });
  },

  resizeSplit: (splitId, sizes) => {
    set((state) => ({
      root: updatePaneSizes(state.root, splitId, sizes),
    }));
  },

  focusPane: (direction) => {
    const adjacent = getAdjacentPane(get().root, get().activePaneId, direction);
    if (!adjacent) return;
    set({ activePaneId: adjacent.id });
  },

  paneCount: () => getAllPaneGroups(get().root).length,

  openApp: (route, label) => {
    const normalized = normalizeWorkbenchRoute(route);
    const resolvedLabel = label ?? getWorkbenchRouteLabel(normalized);

    // Search all pane groups for an existing view with this normalized route
    const allGroups = getAllPaneGroups(get().root);
    for (const group of allGroups) {
      const existing = group.views.find(
        (v) => normalizeWorkbenchRoute(v.route) === normalized,
      );
      if (existing) {
        // Focus the existing tab instead of adding a duplicate
        set((state) => ({
          activePaneId: group.id,
          root: setActivePaneView(state.root, group.id, existing.id),
        }));
        return;
      }
    }

    // Not found anywhere -- add new view to the active pane
    const view: PaneView = {
      id: crypto.randomUUID(),
      route: normalized,
      label: resolvedLabel,
    };
    set((state) => ({
      root: addViewToGroup(state.root, state.activePaneId, view),
    }));
  },

  closeView: (paneId, viewId) => {
    const { root } = get();
    const nextRoot = removeViewFromGroup(root, paneId, viewId);

    // Check if the group is now empty
    const group = findPaneGroup(nextRoot, paneId);
    if (group && group.views.length === 0) {
      const allGroups = getAllPaneGroups(nextRoot);
      if (allGroups.length === 1) {
        // Last pane -- reset to Home instead of leaving empty
        const homeView = createPaneView("/home");
        set({
          root: replaceNode(nextRoot, paneId, (node) =>
            node.type === "group"
              ? { ...node, views: [homeView], activeViewId: homeView.id }
              : node,
          ),
        });
      } else {
        // Multiple panes -- close the empty pane entirely
        get().closePane(paneId);
      }
      return;
    }

    set({ root: nextRoot });
  },

  setActiveView: (paneId, viewId) => {
    set((state) => ({
      activePaneId: paneId,
      root: setActivePaneView(state.root, paneId, viewId),
    }));
  },

  closeViewsToRight: (paneId, viewId) => {
    set((state) => {
      const group = findPaneGroup(state.root, paneId);
      if (!group) return state;
      const idx = group.views.findIndex((v) => v.id === viewId);
      if (idx < 0) return state;
      const kept = group.views.slice(0, idx + 1);
      if (kept.length === group.views.length) return state;
      const nextActiveId = kept.find((v) => v.id === group.activeViewId)
        ? group.activeViewId
        : kept[kept.length - 1]?.id ?? null;
      return {
        root: replaceNode(state.root, paneId, (node) =>
          node.type === "group"
            ? { ...node, views: kept, activeViewId: nextActiveId }
            : node,
        ),
      };
    });
  },

  closeSavedViews: (paneId) => {
    set((state) => {
      const group = findPaneGroup(state.root, paneId);
      if (!group) return state;
      const kept = group.views.filter((v) => v.id === group.activeViewId);
      if (kept.length === group.views.length) return state;
      return {
        root: replaceNode(state.root, paneId, (node) =>
          node.type === "group"
            ? { ...node, views: kept, activeViewId: group.activeViewId }
            : node,
        ),
      };
    });
  },

  closeOtherViews: (paneId, viewId) => {
    set((state) => {
      const group = findPaneGroup(state.root, paneId);
      if (!group) return state;
      const kept = group.views.filter((v) => v.id === viewId);
      if (kept.length === group.views.length) return state;
      return {
        root: replaceNode(state.root, paneId, (node) =>
          node.type === "group"
            ? { ...node, views: kept, activeViewId: viewId }
            : node,
        ),
      };
    });
  },

  openFile: (filePath, label, _fileType) => {
    const route = `/file/${filePath}`;
    get().openApp(route, label ?? filePath.split("/").pop() ?? "File");
    pushRecentFile(filePath);
  },

  restoreSession: () => {
    const session = loadPaneSession();
    if (!session) return 0;
    set({ root: session.root, activePaneId: session.activePaneId });
    return countFileViews(session.root);
  },

  _reset: () => {
    const nextRoot = createInitialRoot();
    set({
      root: nextRoot,
      activePaneId: nextRoot.id,
    });
  },
}));

// Sync dirty state from policy-tabs-store to pane views
function subscribeToDirtySync() {
  usePolicyTabsStore.subscribe((state, prevState) => {
    if (state.tabs === prevState.tabs) return;
    const tabs = state.tabs;
    const tabsByRoute = new Map<string, (typeof tabs)[number]>();
    const movedTabsByPreviousRoute = new Map<
      string,
      { nextRoute: string; nextLabel: string; tab: (typeof tabs)[number] }
    >();

    for (const tab of tabs) {
      const nextRoute = tab.filePath ? `/file/${tab.filePath}` : `/file/__new__/${tab.id}`;
      tabsByRoute.set(nextRoute, tab);

      const previousTab = prevState.tabs.find((candidate) => candidate.id === tab.id);
      if (!previousTab) {
        continue;
      }

      if (previousTab.filePath !== tab.filePath) {
        const previousRoute = previousTab.filePath
          ? `/file/${previousTab.filePath}`
          : `/file/__new__/${tab.id}`;
        movedTabsByPreviousRoute.set(previousRoute, {
          nextRoute,
          nextLabel: tab.filePath?.split("/").pop() ?? tab.name,
          tab,
        });
      }
    }

    const paneState = usePaneStore.getState();
    const allGroups = getAllPaneGroups(paneState.root);
    let changed = false;
    let nextRoot = paneState.root;

    for (const group of allGroups) {
      for (const view of group.views) {
        if (!view.route.startsWith("/file/")) continue;
        const movedTab = movedTabsByPreviousRoute.get(view.route);
        const nextRoute = movedTab?.nextRoute ?? view.route;
        const nextLabel = movedTab?.nextLabel ?? view.label;
        const tab = movedTab?.tab ?? tabsByRoute.get(nextRoute);
        const newDirty = tab?.dirty ?? false;
        const newFileType = tab?.fileType;
        if (
          view.route !== nextRoute ||
          view.label !== nextLabel ||
          view.dirty !== newDirty ||
          view.fileType !== newFileType
        ) {
          changed = true;
          nextRoot = replaceNode(nextRoot, group.id, (node) =>
            node.type === "group"
              ? {
                  ...node,
                  views: node.views.map((v) =>
                    v.id === view.id
                      ? {
                          ...v,
                          route: nextRoute,
                          label: nextLabel,
                          dirty: newDirty,
                          fileType: newFileType,
                        }
                      : v,
                  ),
                }
              : node,
          );
        }
      }
    }

    if (changed) {
      usePaneStore.setState({ root: nextRoot });
    }
  });
}

subscribeToDirtySync();
