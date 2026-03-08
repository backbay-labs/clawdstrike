import { createContext, useContext, useEffect, useReducer, useRef } from "react";
import type { ReactNode } from "react";
import {
  type WorkbenchState,
  type WorkbenchAction,
  type BottomPanelState,
  type InspectorState,
  type SelectionState,
  type LensId,
  type ShellMode,
  type TabState,
  type TabGroupState,
  workbenchReducer,
  createInitialWorkbenchState,
} from "./workbenchState";
import type { Hunt, HuntStore, HuntDockState, Artifact } from "./huntTypes";
import { createInitialHuntStore } from "./huntTypes";

const STORAGE_KEY = "huntronomer:workbench:state:v1";

function loadPersistedState(): Partial<WorkbenchState> | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as Partial<WorkbenchState>;
  } catch {
    return null;
  }
}

function persistState(state: WorkbenchState): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch {
    // Silently ignore quota errors
  }
}

interface WorkbenchContextValue {
  state: WorkbenchState;
  dispatch: React.Dispatch<WorkbenchAction>;
}

const WorkbenchContext = createContext<WorkbenchContextValue | null>(null);

export function WorkbenchStateProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(workbenchReducer, undefined, () => {
    const persisted = loadPersistedState();
    const initial = createInitialWorkbenchState();
    if (!persisted) return initial;
    return {
      ...initial,
      ...persisted,
      bottomPanel: { ...initial.bottomPanel, ...persisted.bottomPanel },
      inspector: { ...initial.inspector, ...persisted.inspector },
      selection: { ...initial.selection, ...persisted.selection },
      shellMemory: {
        wire: { ...initial.shellMemory.wire, bottomPanel: { ...initial.shellMemory.wire.bottomPanel, ...persisted.shellMemory?.wire?.bottomPanel }, inspector: { ...initial.shellMemory.wire.inspector, ...persisted.shellMemory?.wire?.inspector }, lens: persisted.shellMemory?.wire?.lens ?? initial.shellMemory.wire.lens },
        hunt: { ...initial.shellMemory.hunt, bottomPanel: { ...initial.shellMemory.hunt.bottomPanel, ...persisted.shellMemory?.hunt?.bottomPanel }, inspector: { ...initial.shellMemory.hunt.inspector, ...persisted.shellMemory?.hunt?.inspector }, lens: persisted.shellMemory?.hunt?.lens ?? initial.shellMemory.hunt.lens },
        lab: { ...initial.shellMemory.lab, bottomPanel: { ...initial.shellMemory.lab.bottomPanel, ...persisted.shellMemory?.lab?.bottomPanel }, inspector: { ...initial.shellMemory.lab.inspector, ...persisted.shellMemory?.lab?.inspector }, lens: persisted.shellMemory?.lab?.lens ?? initial.shellMemory.lab.lens },
        case: { ...initial.shellMemory.case, bottomPanel: { ...initial.shellMemory.case.bottomPanel, ...persisted.shellMemory?.case?.bottomPanel }, inspector: { ...initial.shellMemory.case.inspector, ...persisted.shellMemory?.case?.inspector }, lens: persisted.shellMemory?.case?.lens ?? initial.shellMemory.case.lens },
      },
      tabGroups: persisted.tabGroups ?? initial.tabGroups,
      huntStore: persisted.huntStore
        ? {
            ...createInitialHuntStore(),
            ...persisted.huntStore,
            dock: { ...createInitialHuntStore().dock, ...persisted.huntStore.dock },
          }
        : initial.huntStore,
    };
  });

  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
    }
    timerRef.current = setTimeout(() => {
      persistState(state);
      timerRef.current = null;
    }, 500);

    return () => {
      if (timerRef.current) {
        clearTimeout(timerRef.current);
      }
    };
  }, [state]);

  return (
    <WorkbenchContext.Provider value={{ state, dispatch }}>
      {children}
    </WorkbenchContext.Provider>
  );
}

export function useWorkbench(): WorkbenchContextValue {
  const context = useContext(WorkbenchContext);
  if (!context) {
    throw new Error("useWorkbench must be used within a WorkbenchStateProvider");
  }
  return context;
}

export function useShell(): ShellMode {
  return useWorkbench().state.shell;
}

export function useLens(): { lens: LensId; previousLens: LensId | null } {
  const { lens, previousLens } = useWorkbench().state;
  return { lens, previousLens };
}

export function useBottomPanel(): BottomPanelState {
  return useWorkbench().state.bottomPanel;
}

export function useContextInspector(): InspectorState {
  return useWorkbench().state.inspector;
}

export function useWorkbenchDispatch(): React.Dispatch<WorkbenchAction> {
  return useWorkbench().dispatch;
}

export function useActiveTab(): TabState | null {
  const { tabGroups } = useWorkbench().state;
  // Return the active tab in the first group that has one
  for (const group of tabGroups) {
    if (group.activeTabId) {
      const tab = group.tabs.find((t) => t.id === group.activeTabId);
      if (tab) return tab;
    }
  }
  return null;
}

export function useTabGroup(groupId: string): TabGroupState | null {
  const { tabGroups } = useWorkbench().state;
  return tabGroups.find((g) => g.id === groupId) ?? null;
}

export function useTabs(): TabState[] {
  const { tabGroups } = useWorkbench().state;
  return tabGroups.flatMap((g) => g.tabs);
}

export function useSelection(): SelectionState {
  return useWorkbench().state.selection;
}

export function useHuntStore(): HuntStore {
  return useWorkbench().state.huntStore;
}

export function useActiveHunt(): Hunt | null {
  const { huntStore } = useWorkbench().state;
  const { activeHuntId } = huntStore.dock;
  return activeHuntId ? huntStore.hunts[activeHuntId] ?? null : null;
}

export function useHuntDock(): HuntDockState {
  return useWorkbench().state.huntStore.dock;
}

export function useBucketSummaryCollapsed(): boolean {
  return useWorkbench().state.huntStore.dock.bucketSummaryCollapsed;
}

export function useHuntArtifacts(huntId: string | null): Artifact[] {
  const { huntStore } = useWorkbench().state;
  if (!huntId) return [];
  const hunt = huntStore.hunts[huntId];
  if (!hunt) return [];
  return hunt.artifactIds
    .map((id) => huntStore.artifacts[id])
    .filter(Boolean);
}
