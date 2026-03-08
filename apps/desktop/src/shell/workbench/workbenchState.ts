import type { HuntStore } from "./huntTypes";
import { createInitialHuntStore } from "./huntTypes";
import type { HuntAction } from "./huntReducer";
import { huntReducer } from "./huntReducer";

export type ShellMode = "wire" | "hunt" | "lab" | "case";

// ── Tab System Types ──────────────────────────────────────────────

export type TabKind =
  | "signal-thread" | "hunt" | "receipt" | "case" | "sandbox"
  | "artifact" | "brief" | "profile" | "policy"
  | "threat-radar" | "attack-graph" | "network-map"
  | "workflow" | "marketplace" | "operations"
  | "file" | "note" | "welcome";

export interface TabState {
  id: string;
  kind: TabKind;
  title: string;
  subtitle?: string;
  icon?: string;
  isPreview: boolean;
  isPinned: boolean;
  isDirty: boolean;
  sourceUri?: string;
  metadata?: Record<string, unknown>;
}

export interface TabGroupState {
  id: string;
  tabs: TabState[];
  activeTabId: string | null;
  tabHistory: string[];
}

export type LensId =
  | "scopes"
  | "history"
  | "files"
  | "sandboxes"
  | "entities"
  | "swarms"
  | "notes";

export type BottomPanelTabId =
  | "tape"
  | "terminal"
  | "receipts"
  | "tasks"
  | "replay"
  | "diff";

export type OpenTabMode =
  | "replace"
  | "split-right"
  | "split-below"
  | "new-tab"
  | "preview"
  | "compare";

export type InspectorTabId = "context" | "graph" | "proof" | "companion";

export type PostureMode = "observe" | "trace" | "contain" | "execute";

export interface BottomPanelState {
  activeTab: BottomPanelTabId;
  collapsed: boolean;
  height: number;
}

export interface InspectorState {
  activeTab: InspectorTabId;
  width: number;
  visible: boolean;
}

export type SelectionEntityType = "file" | "receipt" | "policy" | "agent" | "session" | "guard" | null;

export interface SelectionState {
  entityType: SelectionEntityType;
  entityId: string | null;
  metadata?: Record<string, unknown>;
}

export interface ShellLayoutMemory {
  lens: LensId;
  bottomPanel: BottomPanelState;
  inspector: InspectorState;
}

export interface WorkbenchState {
  shell: ShellMode;
  lens: LensId;
  previousLens: LensId | null;
  sidebarCollapsed: boolean;
  sidebarWidth: number;
  bottomPanel: BottomPanelState;
  inspector: InspectorState;
  selection: SelectionState;
  posture: PostureMode;
  shellMemory: Record<ShellMode, ShellLayoutMemory>;
  tabGroups: TabGroupState[];
  huntStore: HuntStore;
}

export const DEFAULT_TAB_GROUP: TabGroupState = {
  id: "main",
  tabs: [],
  activeTabId: null,
  tabHistory: [],
};

const MAX_TAB_GROUPS = 3;
const MAX_TAB_HISTORY = 100;

export const SHELL_DEFAULTS: Record<ShellMode, ShellLayoutMemory> = {
  wire: {
    lens: "scopes",
    bottomPanel: { activeTab: "tape", collapsed: true, height: 220 },
    inspector: { activeTab: "context", width: 320, visible: true },
  },
  hunt: {
    lens: "entities",
    bottomPanel: { activeTab: "terminal", collapsed: false, height: 220 },
    inspector: { activeTab: "context", width: 320, visible: true },
  },
  lab: {
    lens: "files",
    bottomPanel: { activeTab: "terminal", collapsed: false, height: 220 },
    inspector: { activeTab: "context", width: 320, visible: true },
  },
  case: {
    lens: "notes",
    bottomPanel: { activeTab: "receipts", collapsed: true, height: 220 },
    inspector: { activeTab: "context", width: 320, visible: true },
  },
};

export function createInitialWorkbenchState(): WorkbenchState {
  const shell: ShellMode = "wire";
  const defaults = SHELL_DEFAULTS[shell];

  return {
    shell,
    lens: defaults.lens,
    previousLens: null,
    sidebarCollapsed: false,
    sidebarWidth: 304,
    bottomPanel: { ...defaults.bottomPanel },
    inspector: { ...defaults.inspector },
    selection: { entityType: null, entityId: null },
    posture: "observe",
    shellMemory: {
      wire: { ...SHELL_DEFAULTS.wire, bottomPanel: { ...SHELL_DEFAULTS.wire.bottomPanel }, inspector: { ...SHELL_DEFAULTS.wire.inspector } },
      hunt: { ...SHELL_DEFAULTS.hunt, bottomPanel: { ...SHELL_DEFAULTS.hunt.bottomPanel }, inspector: { ...SHELL_DEFAULTS.hunt.inspector } },
      lab: { ...SHELL_DEFAULTS.lab, bottomPanel: { ...SHELL_DEFAULTS.lab.bottomPanel }, inspector: { ...SHELL_DEFAULTS.lab.inspector } },
      case: { ...SHELL_DEFAULTS.case, bottomPanel: { ...SHELL_DEFAULTS.case.bottomPanel }, inspector: { ...SHELL_DEFAULTS.case.inspector } },
    },
    tabGroups: [{ ...DEFAULT_TAB_GROUP, tabs: [], tabHistory: [] }],
    huntStore: createInitialHuntStore(),
  };
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

export type WorkbenchAction =
  | { type: "SET_SHELL"; payload: ShellMode }
  | { type: "SET_LENS"; payload: LensId }
  | { type: "TOGGLE_LENS" }
  | { type: "TOGGLE_SIDEBAR" }
  | { type: "SET_SIDEBAR_COLLAPSED"; payload: boolean }
  | { type: "SET_SIDEBAR_WIDTH"; payload: number }
  | { type: "TOGGLE_BOTTOM_PANEL" }
  | { type: "SET_BOTTOM_PANEL_TAB"; payload: BottomPanelTabId }
  | { type: "SET_BOTTOM_PANEL_HEIGHT"; payload: number }
  | { type: "TOGGLE_INSPECTOR" }
  | { type: "SET_INSPECTOR_TAB"; payload: InspectorTabId }
  | { type: "SET_INSPECTOR_WIDTH"; payload: number }
  | { type: "SET_POSTURE"; payload: PostureMode }
  // Tab actions
  | { type: "OPEN_TAB"; payload: { groupId: string; tab: Omit<TabState, "id">; openMode?: OpenTabMode } }
  | { type: "CLOSE_TAB"; payload: { groupId: string; tabId: string } }
  | { type: "PIN_TAB"; payload: { groupId: string; tabId: string } }
  | { type: "UNPIN_TAB"; payload: { groupId: string; tabId: string } }
  | { type: "SET_TAB_PREVIEW"; payload: { groupId: string; tabId: string } }
  | { type: "REORDER_TAB"; payload: { groupId: string; tabId: string; toIndex: number } }
  | { type: "MOVE_TAB_TO_GROUP"; payload: { fromGroupId: string; toGroupId: string; tabId: string } }
  | { type: "SET_ACTIVE_TAB"; payload: { groupId: string; tabId: string } }
  | { type: "SET_TAB_DIRTY"; payload: { groupId: string; tabId: string; dirty: boolean } }
  | { type: "NAVIGATE_TAB_BACK"; payload: { groupId: string } }
  | { type: "NAVIGATE_TAB_FORWARD"; payload: { groupId: string } }
  | { type: "CREATE_TAB_GROUP"; payload: { groupId: string } }
  | { type: "REMOVE_TAB_GROUP"; payload: { groupId: string } }
  | { type: "SET_SELECTION"; payload: SelectionState }
  // Hunt actions (delegated to huntReducer)
  | HuntAction;

function generateTabId(kind: TabKind): string {
  return `tab_${kind}_${Date.now()}`;
}

function updateTabGroup(
  groups: TabGroupState[],
  groupId: string,
  updater: (group: TabGroupState) => TabGroupState,
): TabGroupState[] {
  return groups.map((g) => (g.id === groupId ? updater(g) : g));
}

function sortTabsPinnedFirst(tabs: TabState[]): TabState[] {
  const pinned = tabs.filter((t) => t.isPinned);
  const unpinned = tabs.filter((t) => !t.isPinned);
  return [...pinned, ...unpinned];
}

function capHistory(history: string[]): string[] {
  return history.length > MAX_TAB_HISTORY ? history.slice(-MAX_TAB_HISTORY) : history;
}

function inferOpenMode(
  activeTabKind: TabKind | null,
  nextTabKind: TabKind,
): OpenTabMode {
  if (!activeTabKind) return "replace";
  if (activeTabKind === "signal-thread" && nextTabKind === "hunt") {
    return "split-right";
  }
  if (activeTabKind === "receipt" && nextTabKind === "receipt") {
    return "compare";
  }
  if (activeTabKind === "case" && nextTabKind === "note") {
    return "new-tab";
  }
  if (activeTabKind === "hunt" && nextTabKind === "file") {
    return "split-right";
  }
  return "replace";
}

function resolveOpenTargetGroup(
  groups: TabGroupState[],
  requestedGroupId: string,
  openMode: OpenTabMode,
): { tabGroups: TabGroupState[]; targetGroupId: string | null } {
  const existingRequested = groups.find((group) => group.id === requestedGroupId);
  if (!existingRequested) {
    return { tabGroups: groups, targetGroupId: null };
  }

  if (
    openMode === "replace"
    || openMode === "preview"
  ) {
    return { tabGroups: groups, targetGroupId: requestedGroupId };
  }

  const alternate = groups.find((group) => group.id !== requestedGroupId);
  if (alternate) {
    return { tabGroups: groups, targetGroupId: alternate.id };
  }

  if (groups.length >= MAX_TAB_GROUPS) {
    return { tabGroups: groups, targetGroupId: requestedGroupId };
  }

  const targetGroupId = `group-${groups.length + 1}`;
  return {
    targetGroupId,
    tabGroups: [
      ...groups,
      {
        id: targetGroupId,
        tabs: [],
        activeTabId: null,
        tabHistory: [],
      },
    ],
  };
}

export function workbenchReducer(state: WorkbenchState, action: WorkbenchAction): WorkbenchState {
  // Delegate HUNT_* actions to sub-reducer
  if (action.type.startsWith("HUNT_")) {
    const nextHuntStore = huntReducer(state.huntStore, action as HuntAction);
    if (nextHuntStore === state.huntStore) return state;
    return { ...state, huntStore: nextHuntStore };
  }

  switch (action.type) {
    case "SET_SHELL": {
      if (action.payload === state.shell) return state;

      const savedMemory: ShellLayoutMemory = {
        lens: state.lens,
        bottomPanel: { ...state.bottomPanel },
        inspector: { ...state.inspector },
      };

      const restored = state.shellMemory[action.payload];

      return {
        ...state,
        shell: action.payload,
        lens: restored.lens,
        previousLens: null,
        bottomPanel: { ...restored.bottomPanel },
        inspector: { ...restored.inspector },
        shellMemory: {
          ...state.shellMemory,
          [state.shell]: savedMemory,
        },
      };
    }

    case "SET_LENS":
      if (action.payload === state.lens) return state;
      return {
        ...state,
        lens: action.payload,
        previousLens: state.lens,
      };

    case "TOGGLE_LENS": {
      if (!state.previousLens || state.previousLens === state.lens) return state;
      return {
        ...state,
        lens: state.previousLens,
        previousLens: state.lens,
      };
    }

    case "TOGGLE_SIDEBAR":
      return { ...state, sidebarCollapsed: !state.sidebarCollapsed };

    case "SET_SIDEBAR_COLLAPSED":
      if (action.payload === state.sidebarCollapsed) return state;
      return { ...state, sidebarCollapsed: action.payload };

    case "SET_SIDEBAR_WIDTH":
      return { ...state, sidebarWidth: clamp(action.payload, 240, 400) };

    case "TOGGLE_BOTTOM_PANEL":
      return {
        ...state,
        bottomPanel: { ...state.bottomPanel, collapsed: !state.bottomPanel.collapsed },
      };

    case "SET_BOTTOM_PANEL_TAB":
      return {
        ...state,
        bottomPanel: {
          ...state.bottomPanel,
          activeTab: action.payload,
          collapsed: false,
        },
      };

    case "SET_BOTTOM_PANEL_HEIGHT":
      return {
        ...state,
        bottomPanel: {
          ...state.bottomPanel,
          height: clamp(action.payload, 120, 600),
        },
      };

    case "TOGGLE_INSPECTOR":
      return {
        ...state,
        inspector: { ...state.inspector, visible: !state.inspector.visible },
      };

    case "SET_INSPECTOR_TAB":
      return {
        ...state,
        inspector: {
          ...state.inspector,
          activeTab: action.payload,
          visible: true,
        },
      };

    case "SET_INSPECTOR_WIDTH":
      return {
        ...state,
        inspector: {
          ...state.inspector,
          width: clamp(action.payload, 240, 480),
        },
      };

    case "SET_POSTURE":
      return { ...state, posture: action.payload };

    // ── Tab Actions ─────────────────────────────────────────────

    case "OPEN_TAB": {
      const { groupId, tab } = action.payload;
      const sourceGroup = state.tabGroups.find((group) => group.id === groupId);
      if (!sourceGroup) return state;

      const activeTabKind = sourceGroup.activeTabId
        ? (sourceGroup.tabs.find((candidate) => candidate.id === sourceGroup.activeTabId)?.kind ?? null)
        : null;
      const openMode = action.payload.openMode ?? inferOpenMode(activeTabKind, tab.kind);
      const { tabGroups: resolvedGroups, targetGroupId } = resolveOpenTargetGroup(
        state.tabGroups,
        groupId,
        openMode,
      );
      if (!targetGroupId) return state;

      return {
        ...state,
        tabGroups: updateTabGroup(resolvedGroups, targetGroupId, (group) => {
          // If sourceUri provided, check for existing tab with same sourceUri
          if (tab.sourceUri) {
            const existing = group.tabs.find((t) => t.sourceUri === tab.sourceUri);
            if (existing) {
              return {
                ...group,
                activeTabId: existing.id,
                tabHistory: capHistory([...group.tabHistory.filter((id) => id !== existing.id), existing.id]),
              };
            }
          }

          const newTab: TabState = {
            ...tab,
            id: generateTabId(tab.kind),
          };

          // If the new tab is preview, replace existing preview tab
          if (tab.isPreview || openMode === "preview") {
            const previewIndex = group.tabs.findIndex((t) => t.isPreview && !t.isPinned);
            if (previewIndex !== -1) {
              const replaced = group.tabs[previewIndex];
              const tabs = [...group.tabs];
              tabs[previewIndex] = { ...newTab, isPreview: true };
              return {
                ...group,
                tabs,
                activeTabId: tabs[previewIndex].id,
                tabHistory: capHistory([...group.tabHistory.filter((id) => id !== replaced.id), newTab.id]),
              };
            }
          }

          return {
            ...group,
            tabs: sortTabsPinnedFirst([...group.tabs, newTab]),
            activeTabId: newTab.id,
            tabHistory: capHistory([...group.tabHistory, newTab.id]),
          };
        }),
      };
    }

    case "CLOSE_TAB": {
      const { groupId, tabId } = action.payload;
      let newGroups = updateTabGroup(state.tabGroups, groupId, (group) => {
        const tabs = group.tabs.filter((t) => t.id !== tabId);
        const history = group.tabHistory.filter((id) => id !== tabId);
        let activeTabId = group.activeTabId;

        if (activeTabId === tabId) {
          // Activate previous tab from history, or last tab, or null
          activeTabId = history.length > 0
            ? history[history.length - 1]
            : tabs.length > 0
              ? tabs[tabs.length - 1].id
              : null;
        }

        return { ...group, tabs, activeTabId, tabHistory: history };
      });

      // Remove empty groups (except "main")
      const closedGroup = newGroups.find((g) => g.id === groupId);
      if (closedGroup && closedGroup.tabs.length === 0 && closedGroup.id !== "main") {
        newGroups = newGroups.filter((g) => g.id !== groupId);
      }

      return { ...state, tabGroups: newGroups };
    }

    case "PIN_TAB": {
      const { groupId, tabId } = action.payload;
      return {
        ...state,
        tabGroups: updateTabGroup(state.tabGroups, groupId, (group) => ({
          ...group,
          tabs: sortTabsPinnedFirst(
            group.tabs.map((t) =>
              t.id === tabId ? { ...t, isPinned: true, isPreview: false } : t,
            ),
          ),
        })),
      };
    }

    case "UNPIN_TAB": {
      const { groupId, tabId } = action.payload;
      return {
        ...state,
        tabGroups: updateTabGroup(state.tabGroups, groupId, (group) => ({
          ...group,
          tabs: sortTabsPinnedFirst(
            group.tabs.map((t) =>
              t.id === tabId ? { ...t, isPinned: false } : t,
            ),
          ),
        })),
      };
    }

    case "SET_TAB_PREVIEW": {
      const { groupId, tabId } = action.payload;
      return {
        ...state,
        tabGroups: updateTabGroup(state.tabGroups, groupId, (group) => ({
          ...group,
          tabs: group.tabs.map((t) =>
            t.id === tabId ? { ...t, isPreview: false, isPinned: false } : t,
          ),
        })),
      };
    }

    case "REORDER_TAB": {
      const { groupId, tabId, toIndex } = action.payload;
      return {
        ...state,
        tabGroups: updateTabGroup(state.tabGroups, groupId, (group) => {
          const fromIndex = group.tabs.findIndex((t) => t.id === tabId);
          if (fromIndex === -1) return group;

          const tab = group.tabs[fromIndex];
          const tabs = [...group.tabs];
          tabs.splice(fromIndex, 1);

          const clampedIndex = Math.min(Math.max(0, toIndex), tabs.length);
          tabs.splice(clampedIndex, 0, tab);

          return { ...group, tabs: sortTabsPinnedFirst(tabs) };
        }),
      };
    }

    case "MOVE_TAB_TO_GROUP": {
      const { fromGroupId, toGroupId, tabId } = action.payload;
      const sourceGroup = state.tabGroups.find((g) => g.id === fromGroupId);
      if (!sourceGroup) return state;
      if (!state.tabGroups.find((g) => g.id === toGroupId)) return state;

      const tab = sourceGroup.tabs.find((t) => t.id === tabId);
      if (!tab) return state;

      let newGroups = updateTabGroup(state.tabGroups, fromGroupId, (group) => {
        const tabs = group.tabs.filter((t) => t.id !== tabId);
        const history = group.tabHistory.filter((id) => id !== tabId);
        const activeTabId = group.activeTabId === tabId
          ? (history.length > 0 ? history[history.length - 1] : tabs.length > 0 ? tabs[tabs.length - 1].id : null)
          : group.activeTabId;
        return { ...group, tabs, activeTabId, tabHistory: history };
      });

      newGroups = updateTabGroup(newGroups, toGroupId, (group) => ({
        ...group,
        tabs: sortTabsPinnedFirst([...group.tabs, tab]),
        activeTabId: tab.id,
        tabHistory: capHistory([...group.tabHistory, tab.id]),
      }));

      // Remove empty source group (except "main")
      const updatedSource = newGroups.find((g) => g.id === fromGroupId);
      if (updatedSource && updatedSource.tabs.length === 0 && updatedSource.id !== "main") {
        newGroups = newGroups.filter((g) => g.id !== fromGroupId);
      }

      return { ...state, tabGroups: newGroups };
    }

    case "SET_ACTIVE_TAB": {
      const { groupId, tabId } = action.payload;
      return {
        ...state,
        tabGroups: updateTabGroup(state.tabGroups, groupId, (group) => {
          if (!group.tabs.find((t) => t.id === tabId)) return group;
          return {
            ...group,
            activeTabId: tabId,
            tabHistory: capHistory([...group.tabHistory.filter((id) => id !== tabId), tabId]),
          };
        }),
      };
    }

    case "SET_TAB_DIRTY": {
      const { groupId, tabId, dirty } = action.payload;
      return {
        ...state,
        tabGroups: updateTabGroup(state.tabGroups, groupId, (group) => ({
          ...group,
          tabs: group.tabs.map((t) =>
            t.id === tabId ? { ...t, isDirty: dirty } : t,
          ),
        })),
      };
    }

    case "NAVIGATE_TAB_BACK": {
      const { groupId } = action.payload;
      return {
        ...state,
        tabGroups: updateTabGroup(state.tabGroups, groupId, (group) => {
          if (group.tabHistory.length < 2) return group;
          const currentIndex = group.activeTabId
            ? group.tabHistory.lastIndexOf(group.activeTabId)
            : group.tabHistory.length - 1;
          if (currentIndex <= 0) return group;
          const prevId = group.tabHistory[currentIndex - 1];
          return { ...group, activeTabId: prevId };
        }),
      };
    }

    case "NAVIGATE_TAB_FORWARD": {
      const { groupId } = action.payload;
      return {
        ...state,
        tabGroups: updateTabGroup(state.tabGroups, groupId, (group) => {
          if (group.tabHistory.length < 2 || !group.activeTabId) return group;
          const currentIndex = group.tabHistory.lastIndexOf(group.activeTabId);
          if (currentIndex === -1 || currentIndex >= group.tabHistory.length - 1) return group;
          const nextId = group.tabHistory[currentIndex + 1];
          return { ...group, activeTabId: nextId };
        }),
      };
    }

    case "CREATE_TAB_GROUP": {
      const { groupId } = action.payload;
      if (state.tabGroups.length >= MAX_TAB_GROUPS) return state;
      if (state.tabGroups.some((g) => g.id === groupId)) return state;
      return {
        ...state,
        tabGroups: [
          ...state.tabGroups,
          { id: groupId, tabs: [], activeTabId: null, tabHistory: [] },
        ],
      };
    }

    case "REMOVE_TAB_GROUP": {
      const { groupId } = action.payload;
      if (groupId === "main") return state;
      const group = state.tabGroups.find((g) => g.id === groupId);
      if (!group || group.tabs.length > 0) return state;
      return {
        ...state,
        tabGroups: state.tabGroups.filter((g) => g.id !== groupId),
      };
    }

    case "SET_SELECTION":
      return { ...state, selection: action.payload };

    default:
      return state;
  }
}
