import { create } from "zustand";
import { immer } from "zustand/middleware/immer";
import { createSelectors } from "@/lib/create-selectors";
import type { RightSidebarPanel } from "../types";

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

interface RightSidebarState {
  visible: boolean;
  activePanel: RightSidebarPanel;
  width: number;
  actions: {
    toggle: () => void;
    show: () => void;
    hide: () => void;
    setActivePanel: (panel: RightSidebarPanel) => void;
    setWidth: (width: number) => void;
  };
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

const useRightSidebarStoreBase = create<RightSidebarState>()(
  immer((set) => ({
    visible: false,
    activePanel: "speakeasy",
    width: 320,

    actions: {
      toggle: () => {
        set((state) => {
          state.visible = !state.visible;
        });
      },

      show: () => {
        set((state) => {
          state.visible = true;
        });
      },

      hide: () => {
        set((state) => {
          state.visible = false;
        });
      },

      setActivePanel: (panel: RightSidebarPanel) => {
        set((state) => {
          state.activePanel = panel;
        });
      },

      setWidth: (width: number) => {
        set((state) => {
          state.width = Math.max(200, Math.min(480, width));
        });
      },
    },
  })),
);

export const useRightSidebarStore = createSelectors(useRightSidebarStoreBase);
