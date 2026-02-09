/**
 * DockContext - State management for the dock/capsule system
 *
 * Ported from Origin desktop dock system.
 */
import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useReducer,
  type ReactNode,
} from "react";
import type {
  CapsuleKind,
  CapsuleTabState,
  CapsuleViewMode,
  DockCapsuleState,
  SessionItem,
  ShelfMode,
  ShelfState,
} from "./types";

interface DockState {
  capsules: DockCapsuleState[];
  shelf: ShelfState;
  sessions: SessionItem[];
  hoveredCapsuleId: string | null;
}

const initialState: DockState = {
  capsules: [],
  shelf: { isOpen: false, mode: null },
  sessions: [],
  hoveredCapsuleId: null,
};

const DEFAULT_VIEW_MODES: Partial<Record<CapsuleKind, CapsuleViewMode>> = {
  action: "compact",
  events: "compact",
  kernel_agent: "expanded",
};

function getDefaultViewMode(kind: CapsuleKind): CapsuleViewMode {
  return DEFAULT_VIEW_MODES[kind] ?? "expanded";
}

type DockAction =
  | { type: "OPEN_CAPSULE"; payload: DockCapsuleState }
  | { type: "CLOSE_CAPSULE"; payload: string }
  | { type: "MINIMIZE_CAPSULE"; payload: string }
  | { type: "RESTORE_CAPSULE"; payload: string }
  | { type: "SET_VIEW_MODE"; payload: { id: string; mode: CapsuleViewMode } }
  | { type: "UPDATE_CAPSULE"; payload: { id: string; updates: Partial<DockCapsuleState> } }
  | { type: "OPEN_SHELF"; payload: ShelfMode }
  | { type: "CLOSE_SHELF" }
  | { type: "SET_SESSIONS"; payload: SessionItem[] }
  | { type: "ADD_SESSION"; payload: SessionItem }
  | { type: "REMOVE_SESSION"; payload: string }
  | { type: "SET_HOVERED_CAPSULE"; payload: string | null };

function dockReducer(state: DockState, action: DockAction): DockState {
  switch (action.type) {
    case "OPEN_CAPSULE": {
      const existing = state.capsules.find((c) => c.id === action.payload.id);
      if (existing) {
        return {
          ...state,
          capsules: [
            ...state.capsules.filter((c) => c.id !== action.payload.id),
            { ...existing, isMinimized: false },
          ],
        };
      }
      return { ...state, capsules: [...state.capsules, action.payload] };
    }

    case "CLOSE_CAPSULE":
      return { ...state, capsules: state.capsules.filter((c) => c.id !== action.payload) };

    case "MINIMIZE_CAPSULE":
      return {
        ...state,
        capsules: state.capsules.map((c) => (c.id === action.payload ? { ...c, isMinimized: true } : c)),
      };

    case "RESTORE_CAPSULE":
      return {
        ...state,
        capsules: state.capsules.map((c) => (c.id === action.payload ? { ...c, isMinimized: false } : c)),
      };

    case "SET_VIEW_MODE":
      return {
        ...state,
        capsules: state.capsules.map((c) => (c.id === action.payload.id ? { ...c, viewMode: action.payload.mode } : c)),
      };

    case "UPDATE_CAPSULE":
      return {
        ...state,
        capsules: state.capsules.map((c) => (c.id === action.payload.id ? { ...c, ...action.payload.updates } : c)),
      };

    case "OPEN_SHELF":
      return { ...state, shelf: { isOpen: true, mode: action.payload } };

    case "CLOSE_SHELF":
      return { ...state, shelf: { isOpen: false, mode: null } };

    case "SET_SESSIONS":
      return { ...state, sessions: action.payload };

    case "ADD_SESSION": {
      const exists = state.sessions.some((s) => s.id === action.payload.id);
      if (exists) return state;
      return { ...state, sessions: [...state.sessions, action.payload] };
    }

    case "REMOVE_SESSION":
      return { ...state, sessions: state.sessions.filter((s) => s.id !== action.payload) };

    case "SET_HOVERED_CAPSULE":
      return { ...state, hoveredCapsuleId: action.payload };

    default:
      return state;
  }
}

export interface DockContextValue {
  capsules: DockCapsuleState[];
  visibleCapsules: DockCapsuleState[];
  minimizedCapsules: DockCapsuleState[];
  capsuleTabs: CapsuleTabState[];
  shelf: ShelfState;
  sessions: SessionItem[];
  hoveredCapsuleId: string | null;

  openCapsule: (
    capsule: Omit<DockCapsuleState, "viewMode" | "isMinimized" | "isPinned">,
    minimized?: boolean
  ) => void;
  closeCapsule: (id: string) => void;
  minimizeCapsule: (id: string) => void;
  restoreCapsule: (id: string) => void;
  setViewMode: (id: string, mode: CapsuleViewMode) => void;
  updateCapsule: (id: string, updates: Partial<DockCapsuleState>) => void;
  toggleCapsule: (id: string) => void;

  openShelf: (mode: ShelfMode) => void;
  closeShelf: () => void;
  toggleShelf: (mode: ShelfMode) => void;

  setSessions: (sessions: SessionItem[]) => void;
  addSession: (session: SessionItem) => void;
  removeSession: (id: string) => void;

  setHoveredCapsule: (id: string | null) => void;

  getCapsule: (id: string) => DockCapsuleState | undefined;
  hasCapsule: (id: string) => boolean;
  getCapsulesByKind: (kind: CapsuleKind) => DockCapsuleState[];
}

const DockContext = createContext<DockContextValue | null>(null);

export function DockProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(dockReducer, initialState);

  const visibleCapsules = useMemo(
    () => state.capsules.filter((c) => !c.isMinimized && c.viewMode !== "fullView"),
    [state.capsules]
  );

  const minimizedCapsules = useMemo(
    () => state.capsules.filter((c) => c.isMinimized),
    [state.capsules]
  );

  const capsuleTabs = useMemo<CapsuleTabState[]>(
    () =>
      minimizedCapsules.map((c) => ({
        id: `tab-${c.id}`,
        capsuleId: c.id,
        kind: c.kind,
        title: c.title,
        badgeCount: c.badgeCount,
        isMinimized: true,
      })),
    [minimizedCapsules]
  );

  const openCapsule = useCallback(
    (capsule: Omit<DockCapsuleState, "viewMode" | "isMinimized" | "isPinned">, minimized = false) => {
      const viewMode = getDefaultViewMode(capsule.kind);
      dispatch({
        type: "OPEN_CAPSULE",
        payload: {
          ...capsule,
          viewMode,
          isMinimized: minimized,
          isPinned: false,
        },
      });
    },
    []
  );

  const closeCapsule = useCallback((id: string) => {
    dispatch({ type: "CLOSE_CAPSULE", payload: id });
  }, []);

  const minimizeCapsule = useCallback((id: string) => {
    dispatch({ type: "MINIMIZE_CAPSULE", payload: id });
  }, []);

  const restoreCapsule = useCallback((id: string) => {
    dispatch({ type: "RESTORE_CAPSULE", payload: id });
  }, []);

  const setViewMode = useCallback((id: string, mode: CapsuleViewMode) => {
    dispatch({ type: "SET_VIEW_MODE", payload: { id, mode } });
  }, []);

  const updateCapsule = useCallback((id: string, updates: Partial<DockCapsuleState>) => {
    dispatch({ type: "UPDATE_CAPSULE", payload: { id, updates } });
  }, []);

  const toggleCapsule = useCallback(
    (id: string) => {
      const capsule = state.capsules.find((c) => c.id === id);
      if (!capsule) return;
      dispatch({ type: capsule.isMinimized ? "RESTORE_CAPSULE" : "MINIMIZE_CAPSULE", payload: id });
    },
    [state.capsules]
  );

  const openShelf = useCallback((mode: ShelfMode) => {
    dispatch({ type: "OPEN_SHELF", payload: mode });
  }, []);

  const closeShelf = useCallback(() => {
    dispatch({ type: "CLOSE_SHELF" });
  }, []);

  const toggleShelf = useCallback(
    (mode: ShelfMode) => {
      if (state.shelf.isOpen && state.shelf.mode === mode) {
        dispatch({ type: "CLOSE_SHELF" });
      } else {
        dispatch({ type: "OPEN_SHELF", payload: mode });
      }
    },
    [state.shelf]
  );

  const setSessions = useCallback((sessions: SessionItem[]) => {
    dispatch({ type: "SET_SESSIONS", payload: sessions });
  }, []);

  const addSession = useCallback((session: SessionItem) => {
    dispatch({ type: "ADD_SESSION", payload: session });
  }, []);

  const removeSession = useCallback((id: string) => {
    dispatch({ type: "REMOVE_SESSION", payload: id });
  }, []);

  const setHoveredCapsule = useCallback((id: string | null) => {
    dispatch({ type: "SET_HOVERED_CAPSULE", payload: id });
  }, []);

  const getCapsule = useCallback((id: string) => state.capsules.find((c) => c.id === id), [state.capsules]);
  const hasCapsule = useCallback((id: string) => state.capsules.some((c) => c.id === id), [state.capsules]);
  const getCapsulesByKind = useCallback((kind: CapsuleKind) => state.capsules.filter((c) => c.kind === kind), [state.capsules]);

  const value: DockContextValue = {
    capsules: state.capsules,
    visibleCapsules,
    minimizedCapsules,
    capsuleTabs,
    shelf: state.shelf,
    sessions: state.sessions,
    hoveredCapsuleId: state.hoveredCapsuleId,
    openCapsule,
    closeCapsule,
    minimizeCapsule,
    restoreCapsule,
    setViewMode,
    updateCapsule,
    toggleCapsule,
    openShelf,
    closeShelf,
    toggleShelf,
    setSessions,
    addSession,
    removeSession,
    setHoveredCapsule,
    getCapsule,
    hasCapsule,
    getCapsulesByKind,
  };

  return <DockContext.Provider value={value}>{children}</DockContext.Provider>;
}

export function useDock(): DockContextValue {
  const context = useContext(DockContext);
  if (!context) {
    throw new Error("useDock must be used within a DockProvider");
  }
  return context;
}

export function useCapsule(id: string): DockCapsuleState | undefined {
  const { getCapsule } = useDock();
  return getCapsule(id);
}

export function useCapsulesByKind(kind: CapsuleKind): DockCapsuleState[] {
  const { getCapsulesByKind } = useDock();
  return getCapsulesByKind(kind);
}

