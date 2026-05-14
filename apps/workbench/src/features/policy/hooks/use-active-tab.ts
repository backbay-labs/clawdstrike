/**
 * Direct-store migration hooks -- replace deprecated useWorkbench()/useMultiPolicy() bridge hooks.
 *
 * These compose usePolicyTabsStore + usePolicyEditStore + useWorkbenchUIStore directly,
 * producing shapes equivalent to the old bridge hooks without the bridge layer overhead.
 *
 * Consumers that previously used `useWorkbench()` should migrate to `useActiveTabState()`.
 * Consumers that previously used `useMultiPolicy()` should migrate to `useActiveTab()`.
 * Action dispatching via `useActiveTabDispatch()` replaces both `dispatch` and `multiDispatch`.
 */
import { useMemo } from "react";
import {
  usePolicyTabsStore,
  type TabMeta,
  type SplitMode,
} from "@/features/policy/stores/policy-tabs-store";
import {
  usePolicyEditStore,
  type TabEditState,
} from "@/features/policy/stores/policy-edit-store";
import { useWorkbenchUIStore } from "@/features/policy/stores/workbench-ui-store";
import { DEFAULT_POLICY } from "@/features/policy/stores/policy-store";

// Re-export types for consumer convenience
export type { TabMeta, SplitMode } from "@/features/policy/stores/policy-tabs-store";
export type { TabEditState } from "@/features/policy/stores/policy-edit-store";

// ---------------------------------------------------------------------------
// useActiveTabState -- replaces useWorkbench().state
// ---------------------------------------------------------------------------

export function useActiveTabState() {
  const activeTabId = usePolicyTabsStore((s) => s.activeTabId);
  const tabs = usePolicyTabsStore((s) => s.tabs);
  const savedPolicies = usePolicyTabsStore((s) => s.savedPolicies);
  const editStates = usePolicyEditStore((s) => s.editStates);
  const sidebarCollapsed = useWorkbenchUIStore((s) => s.sidebarCollapsed);
  const activeEditorTab = useWorkbenchUIStore((s) => s.activeEditorTab);
  const editorSyncDirection = useWorkbenchUIStore((s) => s.editorSyncDirection);

  return useMemo(() => {
    const activeTab = tabs.find((t) => t.id === activeTabId);
    const editState = editStates.get(activeTabId);
    const policy = editState?.policy ?? DEFAULT_POLICY;
    const yaml = editState?.yaml ?? "";
    const dirty = activeTab?.dirty ?? false;
    const validation = editState?.validation;
    const nativeValidation = editState?.nativeValidation;

    return {
      activeTabId,
      activeTab,
      editState,
      policy,
      yaml,
      dirty,
      validation,
      nativeValidation,
      savedPolicies,
      sidebarCollapsed,
      activeEditorTab,
      editorSyncDirection,
    };
  }, [
    activeTabId,
    tabs,
    editStates,
    savedPolicies,
    sidebarCollapsed,
    activeEditorTab,
    editorSyncDirection,
  ]);
}

// ---------------------------------------------------------------------------
// useActiveTab -- replaces useMultiPolicy()
// ---------------------------------------------------------------------------

export function useActiveTab() {
  const tabs = usePolicyTabsStore((s) => s.tabs);
  const activeTabId = usePolicyTabsStore((s) => s.activeTabId);
  const splitMode = usePolicyTabsStore((s) => s.splitMode);
  const splitTabId = usePolicyTabsStore((s) => s.splitTabId);
  const editStates = usePolicyEditStore((s) => s.editStates);

  return useMemo(() => {
    const activeTab = tabs.find((t) => t.id === activeTabId);
    const canAddTab = tabs.length < 25;

    return {
      activeTab,
      tabs,
      editStates,
      canAddTab,
      splitMode,
      splitTabId,
    };
  }, [tabs, activeTabId, splitMode, splitTabId, editStates]);
}

// ---------------------------------------------------------------------------
// useActiveTabDispatch -- replaces dispatch + multiDispatch
// ---------------------------------------------------------------------------

export function useActiveTabDispatch() {
  return useMemo(() => ({
    // ---- Policy edit actions (operate on active tab) ----
    updatePolicy: (...args: Parameters<ReturnType<typeof usePolicyEditStore.getState>["updatePolicy"]>) =>
      usePolicyEditStore.getState().updatePolicy(...args),
    setYaml: (...args: Parameters<ReturnType<typeof usePolicyEditStore.getState>["setYaml"]>) =>
      usePolicyEditStore.getState().setYaml(...args),
    updateGuard: (...args: Parameters<ReturnType<typeof usePolicyEditStore.getState>["updateGuard"]>) =>
      usePolicyEditStore.getState().updateGuard(...args),
    toggleGuard: (...args: Parameters<ReturnType<typeof usePolicyEditStore.getState>["toggleGuard"]>) =>
      usePolicyEditStore.getState().toggleGuard(...args),
    updateSettings: (...args: Parameters<ReturnType<typeof usePolicyEditStore.getState>["updateSettings"]>) =>
      usePolicyEditStore.getState().updateSettings(...args),
    updateMeta: (...args: Parameters<ReturnType<typeof usePolicyEditStore.getState>["updateMeta"]>) =>
      usePolicyEditStore.getState().updateMeta(...args),
    updateOrigins: (...args: Parameters<ReturnType<typeof usePolicyEditStore.getState>["updateOrigins"]>) =>
      usePolicyEditStore.getState().updateOrigins(...args),
    undo: (tabId: string) => usePolicyEditStore.getState().undo(tabId),
    redo: (tabId: string) => usePolicyEditStore.getState().redo(tabId),
    setNativeValidation: (...args: Parameters<ReturnType<typeof usePolicyEditStore.getState>["setNativeValidation"]>) =>
      usePolicyEditStore.getState().setNativeValidation(...args),

    // ---- Tab lifecycle actions ----
    closeTab: (tabId: string) => usePolicyTabsStore.getState().closeTab(tabId),
    switchTab: (tabId: string) => usePolicyTabsStore.getState().switchTab(tabId),
    newTab: (...args: Parameters<ReturnType<typeof usePolicyTabsStore.getState>["newTab"]>) =>
      usePolicyTabsStore.getState().newTab(...args),
    setSplitMode: (mode: SplitMode) => usePolicyTabsStore.getState().setSplitMode(mode),
    setSplitTab: (tabId: string | null) => usePolicyTabsStore.getState().setSplitTab(tabId),
    reorderTabs: (fromIndex: number, toIndex: number) => usePolicyTabsStore.getState().reorderTabs(fromIndex, toIndex),
    duplicateTab: (tabId: string) => usePolicyTabsStore.getState().duplicateTab(tabId),
    renameTab: (tabId: string, name: string) => usePolicyTabsStore.getState().renameTab(tabId, name),
    bulkUpdateGuards: (...args: Parameters<ReturnType<typeof usePolicyTabsStore.getState>["bulkUpdateGuards"]>) =>
      usePolicyTabsStore.getState().bulkUpdateGuards(...args),
    openTabOrSwitch: (...args: Parameters<ReturnType<typeof usePolicyTabsStore.getState>["openTabOrSwitch"]>) =>
      usePolicyTabsStore.getState().openTabOrSwitch(...args),
    savePolicyToLibrary: (...args: Parameters<ReturnType<typeof usePolicyTabsStore.getState>["savePolicyToLibrary"]>) =>
      usePolicyTabsStore.getState().savePolicyToLibrary(...args),
    deleteSavedPolicy: (id: string) => usePolicyTabsStore.getState().deleteSavedPolicy(id),

    // ---- UI chrome actions ----
    toggleSidebar: () => useWorkbenchUIStore.getState().toggleSidebar(),
    setSidebarCollapsed: (collapsed: boolean) => useWorkbenchUIStore.getState().setSidebarCollapsed(collapsed),
    setActiveEditorTab: (tab: "visual" | "yaml") => useWorkbenchUIStore.getState().setActiveEditorTab(tab),
    setEditorSyncDirection: (direction: "visual" | "yaml" | null) => useWorkbenchUIStore.getState().setEditorSyncDirection(direction),
  }), []);
}
