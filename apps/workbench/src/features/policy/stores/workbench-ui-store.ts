/**
 * workbench-ui-store.ts — Zustand store for UI chrome state.
 *
 * Extracted from the monolithic multi-policy-store.tsx (Phase B1).
 * Manages sidebar, editor tab, and sync direction state.
 */
import { create } from "zustand";

export interface WorkbenchUIState {
  sidebarCollapsed: boolean;
  activeEditorTab: "visual" | "yaml";
  editorSyncDirection: "visual" | "yaml" | null;
}

export interface WorkbenchUIActions {
  toggleSidebar: () => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  setActiveEditorTab: (tab: "visual" | "yaml") => void;
  setEditorSyncDirection: (direction: "visual" | "yaml" | null) => void;
  /** Reset to initial state (used by MultiPolicyProvider for test isolation). */
  _reset: () => void;
}

export type WorkbenchUIStore = WorkbenchUIState & WorkbenchUIActions;

export const useWorkbenchUIStore = create<WorkbenchUIStore>((set) => ({
  // ---- State ----
  sidebarCollapsed: false,
  activeEditorTab: "visual",
  editorSyncDirection: null,

  // ---- Actions ----
  toggleSidebar: () =>
    set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed })),

  setSidebarCollapsed: (collapsed) => set({ sidebarCollapsed: collapsed }),

  setActiveEditorTab: (tab) => set({ activeEditorTab: tab }),

  setEditorSyncDirection: (direction) =>
    set({ editorSyncDirection: direction }),

  _reset: () =>
    set({
      sidebarCollapsed: false,
      activeEditorTab: "visual",
      editorSyncDirection: null,
    }),
}));
