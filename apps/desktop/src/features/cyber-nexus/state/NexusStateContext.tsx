import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useReducer,
  type ReactNode,
} from "react";
import type {
  NexusEscLayer,
  NexusLayoutMode,
  NexusSelectionState,
  NexusViewMode,
  StrikecellDomainId,
} from "../types";

export interface NexusContextMenuState {
  x: number;
  y: number;
  targetId: string;
  targetType: "strikecell" | "node";
  strikecellId?: StrikecellDomainId;
}

export interface NexusState {
  selection: NexusSelectionState;
  layoutMode: NexusLayoutMode;
  hud: {
    viewMode: NexusViewMode;
    fieldVisible: boolean;
    layoutDropdownOpen: boolean;
    detailPanelOpen: boolean;
  };
  feedOpen: boolean;
  drawerAppId: StrikecellDomainId | null;
  searchOpen: boolean;
  contextMenu: NexusContextMenuState | null;
  carouselVisible: boolean;
  carouselFocused: boolean;
  keyboardHighlightedStrikecellId: StrikecellDomainId | null;
  strikecellOrder: StrikecellDomainId[];
  pinnedStrikecells: {
    left?: StrikecellDomainId;
    right?: StrikecellDomainId;
  };
  cameraResetToken: number;
  lastEscLayer: NexusEscLayer | null;
}

export type NexusAction =
  | { type: "SYNC_STRIKECELLS"; strikecellIds: StrikecellDomainId[] }
  | { type: "SET_ACTIVE_STRIKECELL"; id: StrikecellDomainId }
  | { type: "TOGGLE_STRIKECELL_EXPANDED"; id: StrikecellDomainId }
  | { type: "SET_LAYOUT_MODE"; mode: NexusLayoutMode }
  | { type: "SET_VIEW_MODE"; mode: NexusViewMode }
  | { type: "TOGGLE_FIELD_VISIBILITY" }
  | { type: "SET_LAYOUT_DROPDOWN_OPEN"; open: boolean }
  | { type: "SET_DETAIL_PANEL_OPEN"; open: boolean }
  | { type: "TOGGLE_FEED" }
  | { type: "SET_DRAWER_APP"; appId: StrikecellDomainId | null }
  | { type: "SET_SEARCH_OPEN"; open: boolean }
  | { type: "SET_CONTEXT_MENU"; value: NexusContextMenuState | null }
  | { type: "SET_CAROUSEL_VISIBLE"; visible: boolean }
  | { type: "SET_CAROUSEL_FOCUSED"; focused: boolean }
  | { type: "NAVIGATE_CAROUSEL"; direction: "prev" | "next" }
  | { type: "SET_KEYBOARD_HIGHLIGHT"; id: StrikecellDomainId | null }
  | { type: "SET_SELECTED_NODES"; nodeIds: string[] }
  | { type: "TOGGLE_NODE_SELECTION"; nodeId: string }
  | { type: "SET_FOCUSED_NODE"; nodeId: string | null }
  | { type: "CLEAR_SELECTION" }
  | { type: "REQUEST_CAMERA_RESET" }
  | { type: "SET_LAST_ESC_LAYER"; layer: NexusEscLayer | null }
  | {
      type: "PIN_STRIKECELL";
      id: StrikecellDomainId;
      position: "left" | "right" | null;
    }
  | {
      type: "REORDER_STRIKECELL";
      id: StrikecellDomainId;
      direction: "up" | "down";
    };

export const initialNexusState: NexusState = {
  selection: {
    activeStrikecellId: null,
    selectedNodeIds: [],
    focusedNodeId: null,
    expandedStrikecellIds: [],
  },
  layoutMode: "radial",
  hud: {
    viewMode: "galaxy",
    fieldVisible: true,
    layoutDropdownOpen: false,
    detailPanelOpen: false,
  },
  feedOpen: false,
  drawerAppId: null,
  searchOpen: false,
  contextMenu: null,
  carouselVisible: false,
  carouselFocused: false,
  keyboardHighlightedStrikecellId: null,
  strikecellOrder: [],
  pinnedStrikecells: {},
  cameraResetToken: 0,
  lastEscLayer: null,
};

function cycleIndex(
  ids: StrikecellDomainId[],
  current: StrikecellDomainId | null,
  offset: number
): StrikecellDomainId | null {
  if (ids.length === 0) return null;
  if (!current) return ids[0];
  const idx = ids.indexOf(current);
  if (idx < 0) return ids[0];
  const next = (idx + offset + ids.length) % ids.length;
  return ids[next];
}

function reorder(
  ids: StrikecellDomainId[],
  id: StrikecellDomainId,
  direction: "up" | "down"
): StrikecellDomainId[] {
  const index = ids.indexOf(id);
  if (index < 0) return ids;

  const target = direction === "up" ? index - 1 : index + 1;
  if (target < 0 || target >= ids.length) return ids;

  const next = ids.slice();
  [next[index], next[target]] = [next[target], next[index]];
  return next;
}

function sameOrder<T>(left: readonly T[], right: readonly T[]) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

export function nexusReducer(state: NexusState, action: NexusAction): NexusState {
  switch (action.type) {
    case "SYNC_STRIKECELLS": {
      const filteredOrder = state.strikecellOrder.filter((id) => action.strikecellIds.includes(id));
      const missing = action.strikecellIds.filter((id) => !filteredOrder.includes(id));
      const strikecellOrder = [...filteredOrder, ...missing];
      const active =
        state.selection.activeStrikecellId && strikecellOrder.includes(state.selection.activeStrikecellId)
          ? state.selection.activeStrikecellId
          : strikecellOrder[0] ?? null;
      const expandedStrikecellIds = state.selection.expandedStrikecellIds.filter((id) =>
        strikecellOrder.includes(id)
      );
      const pinnedLeft =
        state.pinnedStrikecells.left && strikecellOrder.includes(state.pinnedStrikecells.left)
          ? state.pinnedStrikecells.left
          : undefined;
      const pinnedRight =
        state.pinnedStrikecells.right && strikecellOrder.includes(state.pinnedStrikecells.right)
          ? state.pinnedStrikecells.right
          : undefined;

      if (
        sameOrder(strikecellOrder, state.strikecellOrder) &&
        active === state.selection.activeStrikecellId &&
        sameOrder(expandedStrikecellIds, state.selection.expandedStrikecellIds) &&
        pinnedLeft === state.pinnedStrikecells.left &&
        pinnedRight === state.pinnedStrikecells.right
      ) {
        return state;
      }

      return {
        ...state,
        strikecellOrder,
        selection: {
          ...state.selection,
          activeStrikecellId: active,
          expandedStrikecellIds,
        },
        pinnedStrikecells: {
          left: pinnedLeft,
          right: pinnedRight,
        },
      };
    }

    case "SET_ACTIVE_STRIKECELL":
      return {
        ...state,
        selection: {
          ...state.selection,
          activeStrikecellId: action.id,
        },
        keyboardHighlightedStrikecellId: action.id,
      };

    case "TOGGLE_STRIKECELL_EXPANDED": {
      const exists = state.selection.expandedStrikecellIds.includes(action.id);
      const expandedStrikecellIds = exists
        ? state.selection.expandedStrikecellIds.filter((id) => id !== action.id)
        : [...state.selection.expandedStrikecellIds, action.id];

      return {
        ...state,
        selection: {
          ...state.selection,
          expandedStrikecellIds,
          activeStrikecellId: action.id,
        },
      };
    }

    case "SET_LAYOUT_MODE":
      return { ...state, layoutMode: action.mode };

    case "SET_VIEW_MODE":
      return {
        ...state,
        hud: {
          ...state.hud,
          viewMode: action.mode,
        },
      };

    case "TOGGLE_FIELD_VISIBILITY":
      return {
        ...state,
        hud: {
          ...state.hud,
          fieldVisible: !state.hud.fieldVisible,
        },
      };

    case "SET_LAYOUT_DROPDOWN_OPEN":
      return {
        ...state,
        hud: {
          ...state.hud,
          layoutDropdownOpen: action.open,
        },
      };

    case "SET_DETAIL_PANEL_OPEN":
      return {
        ...state,
        hud: {
          ...state.hud,
          detailPanelOpen: action.open,
        },
      };

    case "TOGGLE_FEED":
      return { ...state, feedOpen: !state.feedOpen };

    case "SET_DRAWER_APP":
      return { ...state, drawerAppId: action.appId };

    case "SET_SEARCH_OPEN":
      return { ...state, searchOpen: action.open };

    case "SET_CONTEXT_MENU":
      return { ...state, contextMenu: action.value };

    case "SET_CAROUSEL_VISIBLE":
      return {
        ...state,
        carouselVisible: action.visible,
        carouselFocused: action.visible ? state.carouselFocused : false,
      };

    case "SET_CAROUSEL_FOCUSED":
      return {
        ...state,
        carouselVisible: action.focused ? true : state.carouselVisible,
        carouselFocused: action.focused,
        keyboardHighlightedStrikecellId: action.focused
          ? state.keyboardHighlightedStrikecellId ?? state.selection.activeStrikecellId
          : state.keyboardHighlightedStrikecellId,
      };

    case "NAVIGATE_CAROUSEL": {
      const current = state.keyboardHighlightedStrikecellId ?? state.selection.activeStrikecellId;
      const next = cycleIndex(state.strikecellOrder, current, action.direction === "prev" ? -1 : 1);
      return {
        ...state,
        keyboardHighlightedStrikecellId: next,
      };
    }

    case "SET_KEYBOARD_HIGHLIGHT":
      return { ...state, keyboardHighlightedStrikecellId: action.id };

    case "SET_SELECTED_NODES":
      return {
        ...state,
        selection: {
          ...state.selection,
          selectedNodeIds: action.nodeIds,
        },
      };

    case "TOGGLE_NODE_SELECTION": {
      const exists = state.selection.selectedNodeIds.includes(action.nodeId);
      const selectedNodeIds = exists
        ? state.selection.selectedNodeIds.filter((id) => id !== action.nodeId)
        : [...state.selection.selectedNodeIds, action.nodeId];
      return {
        ...state,
        selection: {
          ...state.selection,
          selectedNodeIds,
        },
      };
    }

    case "SET_FOCUSED_NODE":
      return {
        ...state,
        selection: {
          ...state.selection,
          focusedNodeId: action.nodeId,
        },
      };

    case "CLEAR_SELECTION":
      return {
        ...state,
        selection: {
          ...state.selection,
          selectedNodeIds: [],
          focusedNodeId: null,
        },
      };

    case "REQUEST_CAMERA_RESET":
      return { ...state, cameraResetToken: state.cameraResetToken + 1 };

    case "SET_LAST_ESC_LAYER":
      return { ...state, lastEscLayer: action.layer };

    case "PIN_STRIKECELL": {
      if (action.position === null) {
        return {
          ...state,
          pinnedStrikecells: {
            left: state.pinnedStrikecells.left === action.id ? undefined : state.pinnedStrikecells.left,
            right: state.pinnedStrikecells.right === action.id ? undefined : state.pinnedStrikecells.right,
          },
        };
      }

      return {
        ...state,
        pinnedStrikecells: {
          ...state.pinnedStrikecells,
          [action.position]: action.id,
        },
      };
    }

    case "REORDER_STRIKECELL":
      return {
        ...state,
        strikecellOrder: reorder(state.strikecellOrder, action.id, action.direction),
      };

    default:
      return state;
  }
}

export interface NexusContextValue {
  state: NexusState;
  syncStrikecells: (ids: StrikecellDomainId[]) => void;
  setActiveStrikecell: (id: StrikecellDomainId) => void;
  toggleExpanded: (id: StrikecellDomainId) => void;
  setLayoutMode: (mode: NexusLayoutMode) => void;
  setViewMode: (mode: NexusViewMode) => void;
  toggleFieldVisibility: () => void;
  setLayoutDropdownOpen: (open: boolean) => void;
  setDetailPanelOpen: (open: boolean) => void;
  toggleFeed: () => void;
  setDrawerApp: (appId: StrikecellDomainId | null) => void;
  setSearchOpen: (open: boolean) => void;
  setContextMenu: (value: NexusContextMenuState | null) => void;
  setCarouselVisible: (visible: boolean) => void;
  setCarouselFocused: (focused: boolean) => void;
  navigateCarousel: (direction: "prev" | "next") => void;
  setKeyboardHighlight: (id: StrikecellDomainId | null) => void;
  setSelectedNodes: (nodeIds: string[]) => void;
  toggleNodeSelection: (nodeId: string) => void;
  setFocusedNode: (nodeId: string | null) => void;
  clearSelection: () => void;
  requestCameraReset: () => void;
  setLastEscLayer: (layer: NexusEscLayer | null) => void;
  pinStrikecell: (id: StrikecellDomainId, position: "left" | "right" | null) => void;
  reorderStrikecell: (id: StrikecellDomainId, direction: "up" | "down") => void;
}

const NexusStateContext = createContext<NexusContextValue | null>(null);

export function NexusStateProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(nexusReducer, initialNexusState);

  const value = useMemo<NexusContextValue>(() => {
    const action = <T extends NexusAction>(entry: T) => dispatch(entry);

    return {
      state,
      syncStrikecells: (ids) => action({ type: "SYNC_STRIKECELLS", strikecellIds: ids }),
      setActiveStrikecell: (id) => action({ type: "SET_ACTIVE_STRIKECELL", id }),
      toggleExpanded: (id) => action({ type: "TOGGLE_STRIKECELL_EXPANDED", id }),
      setLayoutMode: (mode) => action({ type: "SET_LAYOUT_MODE", mode }),
      setViewMode: (mode) => action({ type: "SET_VIEW_MODE", mode }),
      toggleFieldVisibility: () => action({ type: "TOGGLE_FIELD_VISIBILITY" }),
      setLayoutDropdownOpen: (open) => action({ type: "SET_LAYOUT_DROPDOWN_OPEN", open }),
      setDetailPanelOpen: (open) => action({ type: "SET_DETAIL_PANEL_OPEN", open }),
      toggleFeed: () => action({ type: "TOGGLE_FEED" }),
      setDrawerApp: (appId) => action({ type: "SET_DRAWER_APP", appId }),
      setSearchOpen: (open) => action({ type: "SET_SEARCH_OPEN", open }),
      setContextMenu: (value) => action({ type: "SET_CONTEXT_MENU", value }),
      setCarouselVisible: (visible) => action({ type: "SET_CAROUSEL_VISIBLE", visible }),
      setCarouselFocused: (focused) => action({ type: "SET_CAROUSEL_FOCUSED", focused }),
      navigateCarousel: (direction) => action({ type: "NAVIGATE_CAROUSEL", direction }),
      setKeyboardHighlight: (id) => action({ type: "SET_KEYBOARD_HIGHLIGHT", id }),
      setSelectedNodes: (nodeIds) => action({ type: "SET_SELECTED_NODES", nodeIds }),
      toggleNodeSelection: (nodeId) => action({ type: "TOGGLE_NODE_SELECTION", nodeId }),
      setFocusedNode: (nodeId) => action({ type: "SET_FOCUSED_NODE", nodeId }),
      clearSelection: () => action({ type: "CLEAR_SELECTION" }),
      requestCameraReset: () => action({ type: "REQUEST_CAMERA_RESET" }),
      setLastEscLayer: (layer) => action({ type: "SET_LAST_ESC_LAYER", layer }),
      pinStrikecell: (id, position) => action({ type: "PIN_STRIKECELL", id, position }),
      reorderStrikecell: (id, direction) => action({ type: "REORDER_STRIKECELL", id, direction }),
    };
  }, [state]);

  return <NexusStateContext.Provider value={value}>{children}</NexusStateContext.Provider>;
}

export function useNexusState() {
  const context = useContext(NexusStateContext);
  if (!context) {
    throw new Error("useNexusState must be used within NexusStateProvider");
  }
  return context;
}

export function useEscClosePriority() {
  const {
    state,
    setSearchOpen,
    setContextMenu,
    setLayoutDropdownOpen,
    setDrawerApp,
    setCarouselVisible,
    setCarouselFocused,
    toggleExpanded,
    setFocusedNode,
    setSelectedNodes,
    setLastEscLayer,
    clearSelection,
  } = useNexusState();

  return useCallback(() => {
    if (state.searchOpen) {
      setSearchOpen(false);
      setLastEscLayer("search");
      return true;
    }

    if (state.contextMenu) {
      setContextMenu(null);
      setLastEscLayer("context-menu");
      return true;
    }

    if (state.hud.layoutDropdownOpen) {
      setLayoutDropdownOpen(false);
      setLastEscLayer("layout-dropdown");
      return true;
    }

    if (state.drawerAppId) {
      setDrawerApp(null);
      setLastEscLayer("drawer");
      return true;
    }

    if (state.carouselVisible) {
      setCarouselFocused(false);
      setCarouselVisible(false);
      setLastEscLayer("carousel-focus");
      return true;
    }

    if (state.carouselFocused) {
      setCarouselFocused(false);
      setLastEscLayer("carousel-focus");
      return true;
    }

    if (state.selection.expandedStrikecellIds.length > 0) {
      const top = state.selection.expandedStrikecellIds[state.selection.expandedStrikecellIds.length - 1];
      if (top) {
        toggleExpanded(top);
        setLastEscLayer("expanded");
        return true;
      }
    }

    if (state.selection.focusedNodeId) {
      setFocusedNode(null);
      setLastEscLayer("selection");
      return true;
    }

    if (state.selection.selectedNodeIds.length > 0) {
      setSelectedNodes([]);
      setLastEscLayer("selection");
      return true;
    }

    clearSelection();
    setLastEscLayer(null);
    return false;
  }, [
    clearSelection,
    setCarouselFocused,
    setCarouselVisible,
    setContextMenu,
    setDrawerApp,
    setFocusedNode,
    setLastEscLayer,
    setLayoutDropdownOpen,
    setSearchOpen,
    setSelectedNodes,
    state.carouselVisible,
    state.carouselFocused,
    state.contextMenu,
    state.drawerAppId,
    state.hud.layoutDropdownOpen,
    state.searchOpen,
    state.selection.expandedStrikecellIds,
    state.selection.focusedNodeId,
    state.selection.selectedNodeIds.length,
    toggleExpanded,
  ]);
}
