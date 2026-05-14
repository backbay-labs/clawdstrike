import { create } from "zustand";
import { immer } from "zustand/middleware/immer";
import { createSelectors } from "@/lib/create-selectors";
import type { ActivityBarItemId } from "../types";

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

interface ActivityBarState {
  activeItem: ActivityBarItemId;
  sidebarVisible: boolean;
  sidebarWidth: number;
  actions: {
    setActiveItem: (id: ActivityBarItemId) => void;
    toggleItem: (id: ActivityBarItemId) => void;
    toggleSidebar: () => void;
    showPanel: (id: ActivityBarItemId) => void;
    setSidebarWidth: (width: number) => void;
    collapseSidebar: () => void;
  };
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

const useActivityBarStoreBase = create<ActivityBarState>()(
  immer((set) => ({
    activeItem: "explorer",
    sidebarVisible: true,
    sidebarWidth: 240,

    actions: {
      setActiveItem: (id: ActivityBarItemId) => {
        set((state) => {
          state.activeItem = id;
        });
      },

      toggleItem: (id: ActivityBarItemId) => {
        set((state) => {
          if (id === state.activeItem && state.sidebarVisible) {
            state.sidebarVisible = false;
          } else {
            state.activeItem = id;
            state.sidebarVisible = true;
          }
        });
      },

      toggleSidebar: () => {
        set((state) => {
          state.sidebarVisible = !state.sidebarVisible;
        });
      },

      showPanel: (id: ActivityBarItemId) => {
        set((state) => {
          state.activeItem = id;
          state.sidebarVisible = true;
        });
      },

      setSidebarWidth: (width: number) => {
        set((state) => {
          state.sidebarWidth = Math.max(120, Math.min(480, width));
        });
      },

      collapseSidebar: () => {
        set((state) => {
          state.sidebarVisible = false;
        });
      },
    },
  })),
);

export const useActivityBarStore = createSelectors(useActivityBarStoreBase);
