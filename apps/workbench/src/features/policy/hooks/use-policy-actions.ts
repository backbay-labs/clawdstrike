/**
 * Policy action hooks — compose Zustand stores into convenient interfaces.
 *
 * These replace the deprecated useWorkbench() / useMultiPolicy() bridge hooks
 * that lived in multi-policy-store.tsx.
 *
 * usePolicyTabs()      — replaces useMultiPolicy()
 * useWorkbenchState()  — replaces useWorkbench()
 * policyDispatch()     — singleton action dispatcher (replaces multiDispatch / dispatch)
 */
import React, { useCallback, useMemo } from "react";
import type {
  WorkbenchPolicy,
  SavedPolicy,
  GuardId,
  GuardConfigMap,
  OriginsConfig,
} from "@/lib/workbench/types";
import {
  DEFAULT_POLICY,
  type WorkbenchState,
  type WorkbenchAction,
  type NativeValidationState,
} from "@/features/policy/stores/policy-store";
import {
  policyToYaml,
  validatePolicy,
} from "@/features/policy/yaml-utils";
import {
  getPrimaryExtension,
  isPolicyFileType,
  sanitizeFilenameStem,
} from "@/lib/workbench/file-type-registry";
import {
  isDesktop,
  openDetectionFile,
  saveDetectionFile,
  readDetectionFileByPath,
} from "@/lib/tauri-bridge";
import { getDocumentIdentityStore } from "@/lib/workbench/detection-workflow/document-identity-store";
import {
  usePolicyTabsStore,
  pushRecentFile,
} from "@/features/policy/stores/policy-tabs-store";
import {
  usePolicyEditStore,
  emptyNativeValidation,
  evaluateTabSource,
} from "@/features/policy/stores/policy-edit-store";
import { useWorkbenchUIStore } from "@/features/policy/stores/workbench-ui-store";
import {
  type PolicyTab,
  type MultiPolicyAction,
  type MultiPolicyState,
  type BulkGuardUpdate,
  reconstructPolicyTab,
} from "@/features/policy/types/policy-tab";

type OpenFileByPathOptions = {
  shouldApply?: () => boolean;
};

// ---- Singleton dispatch ----

let _dispatch: React.Dispatch<MultiPolicyAction> | null = null;

function createDispatch(): React.Dispatch<MultiPolicyAction> {
  return (action: MultiPolicyAction) => {
    const tabsStore = usePolicyTabsStore.getState();
    const editStore = usePolicyEditStore.getState();
    const uiStore = useWorkbenchUIStore.getState();
    const activeTabId = tabsStore.activeTabId;
    const activeTab = tabsStore.tabs.find((t) => t.id === activeTabId);

    switch (action.type) {
      // ---- Tab lifecycle ----
      case "NEW_TAB":
        tabsStore.newTab({
          policy: action.policy,
          filePath: action.filePath,
          fileType: action.fileType,
          yaml: action.yaml,
          documentId: action.documentId,
        });
        break;
      case "CLOSE_TAB":
        tabsStore.closeTab(action.tabId);
        break;
      case "SWITCH_TAB":
        tabsStore.switchTab(action.tabId);
        break;
      case "SET_SPLIT_MODE":
        tabsStore.setSplitMode(action.mode);
        break;
      case "SET_SPLIT_TAB":
        tabsStore.setSplitTab(action.tabId);
        break;
      case "RENAME_TAB":
        tabsStore.renameTab(action.tabId, action.name);
        break;
      case "REORDER_TABS":
        tabsStore.reorderTabs(action.fromIndex, action.toIndex);
        break;
      case "DUPLICATE_TAB":
        tabsStore.duplicateTab(action.tabId);
        break;
      case "BULK_UPDATE_GUARDS":
        tabsStore.bulkUpdateGuards(action.updates);
        break;
      case "OPEN_TAB_OR_SWITCH":
        tabsStore.openTabOrSwitch(
          action.filePath,
          action.fileType,
          action.yaml,
          action.name,
        );
        break;
      case "SET_TAB_TEST_SUITE":
        tabsStore.setTabTestSuite(action.tabId, action.yaml);
        break;
      case "RESTORE_AUTOSAVE_ENTRIES":
        tabsStore.restoreAutosaveEntries(action.entries);
        break;

      // ---- Saved policies (global) ----
      case "SAVE_POLICY":
        tabsStore.savePolicyToLibrary(action.savedPolicy);
        break;
      case "DELETE_SAVED_POLICY":
        tabsStore.deleteSavedPolicy(action.id);
        break;
      case "LOAD_SAVED_POLICIES":
        tabsStore.loadSavedPolicies(action.policies);
        break;

      // ---- UI state ----
      case "SET_SIDEBAR_COLLAPSED":
        uiStore.setSidebarCollapsed(action.collapsed);
        break;
      case "SET_EDITOR_TAB":
        uiStore.setActiveEditorTab(action.tab);
        break;

      // ---- Delegated to active tab editing ----
      case "SET_POLICY":
        if (activeTab) {
          editStore.updatePolicy(activeTabId, action.policy, activeTab.fileType);
          const newName = action.policy.name || activeTab.name;
          tabsStore.renameTab(activeTabId, newName);
          tabsStore.setDirty(activeTabId, true);
          uiStore.setEditorSyncDirection("visual");
        }
        break;
      case "SET_YAML":
        if (activeTab) {
          editStore.setYaml(
            activeTabId,
            action.yaml,
            activeTab.fileType,
            activeTab.filePath,
            activeTab.name,
          );
          const editAfterYaml = editStore.editStates.get(activeTabId);
          if (editAfterYaml) {
            const { name: derivedName } = evaluateTabSource(
              activeTab.fileType,
              action.yaml,
              editAfterYaml.policy,
              activeTab.filePath,
              activeTab.name,
            );
            tabsStore.renameTab(activeTabId, derivedName);
          }
          tabsStore.setDirty(activeTabId, true);
          uiStore.setEditorSyncDirection("yaml");
        }
        break;
      case "UPDATE_GUARD":
        if (activeTab) {
          editStore.updateGuard(
            activeTabId,
            action.guardId,
            action.config,
            activeTab.fileType,
          );
          tabsStore.setDirty(activeTabId, true);
        }
        break;
      case "TOGGLE_GUARD":
        if (activeTab) {
          editStore.toggleGuard(
            activeTabId,
            action.guardId,
            action.enabled,
            activeTab.fileType,
          );
          tabsStore.setDirty(activeTabId, true);
        }
        break;
      case "UPDATE_SETTINGS":
        if (activeTab) {
          editStore.updateSettings(
            activeTabId,
            action.settings,
            activeTab.fileType,
          );
          tabsStore.setDirty(activeTabId, true);
        }
        break;
      case "UPDATE_META":
        if (activeTab) {
          editStore.updateMeta(
            activeTabId,
            {
              name: action.name,
              description: action.description,
              version: action.version,
              extends: action.extends,
            },
            activeTab.fileType,
          );
          if (action.name !== undefined) {
            tabsStore.renameTab(activeTabId, action.name || activeTab.name);
          }
          tabsStore.setDirty(activeTabId, true);
        }
        break;
      case "UPDATE_ORIGINS":
        if (activeTab) {
          editStore.updateOrigins(
            activeTabId,
            action.origins,
            activeTab.fileType,
          );
          tabsStore.setDirty(activeTabId, true);
        }
        break;
      case "SET_FILE_PATH":
        if (activeTabId) {
          tabsStore.setFilePath(activeTabId, action.path);
        }
        break;
      case "MARK_CLEAN":
        if (activeTabId) {
          editStore.markClean(activeTabId);
          tabsStore.setDirty(activeTabId, false);
        }
        break;
      case "SET_NATIVE_VALIDATION":
        if (activeTabId) {
          editStore.setNativeValidation(activeTabId, action.payload);
        }
        break;
      case "UNDO":
        if (activeTabId) {
          editStore.undo(activeTabId);
          const afterUndo = editStore.editStates.get(activeTabId);
          if (afterUndo) {
            tabsStore.setDirty(activeTabId, editStore.isDirty(activeTabId));
          }
        }
        break;
      case "REDO":
        if (activeTabId) {
          editStore.redo(activeTabId);
          const afterRedo = editStore.editStates.get(activeTabId);
          if (afterRedo) {
            tabsStore.setDirty(activeTabId, editStore.isDirty(activeTabId));
          }
        }
        break;
      case "SET_COMPARISON":
        break;
      default:
        break;
    }
  };
}

/**
 * Get the singleton policy dispatch function.
 * Stable reference — safe to use outside React components.
 */
export function policyDispatch(): React.Dispatch<MultiPolicyAction> {
  if (!_dispatch) {
    _dispatch = createDispatch();
  }
  return _dispatch;
}

// ---------------------------------------------------------------------------
// usePolicyTabs — replaces useMultiPolicy()
// ---------------------------------------------------------------------------

export function usePolicyTabs() {
  const tabsMeta = usePolicyTabsStore((s) => s.tabs);
  const activeTabId = usePolicyTabsStore((s) => s.activeTabId);
  const splitMode = usePolicyTabsStore((s) => s.splitMode);
  const splitTabId = usePolicyTabsStore((s) => s.splitTabId);
  const savedPolicies = usePolicyTabsStore((s) => s.savedPolicies);
  const editStates = usePolicyEditStore((s) => s.editStates);
  const sidebarCollapsed = useWorkbenchUIStore((s) => s.sidebarCollapsed);
  const activeEditorTab = useWorkbenchUIStore((s) => s.activeEditorTab);
  const editorSyncDirection = useWorkbenchUIStore((s) => s.editorSyncDirection);

  const dispatch = policyDispatch();

  const tabs = useMemo(
    () =>
      tabsMeta.map((meta) =>
        reconstructPolicyTab(meta, editStates.get(meta.id)),
      ),
    [tabsMeta, editStates],
  );

  const activeTab = useMemo(
    () => tabs.find((t) => t.id === activeTabId),
    [tabs, activeTabId],
  );

  const multiState: MultiPolicyState = useMemo(
    () => ({
      tabs,
      activeTabId,
      splitMode,
      splitTabId,
      savedPolicies,
      ui: {
        sidebarCollapsed,
        activeEditorTab,
        editorSyncDirection,
      },
    }),
    [
      tabs,
      activeTabId,
      splitMode,
      splitTabId,
      savedPolicies,
      sidebarCollapsed,
      activeEditorTab,
      editorSyncDirection,
    ],
  );

  return useMemo(
    () => ({
      multiState,
      multiDispatch: dispatch,
      activeTab,
      tabs,
      canAddTab: tabsMeta.length < 25,
    }),
    [multiState, dispatch, activeTab, tabs, tabsMeta.length],
  );
}

// ---------------------------------------------------------------------------
// useWorkbenchState — replaces useWorkbench()
// ---------------------------------------------------------------------------

export function useWorkbenchState() {
  const tabsMeta = usePolicyTabsStore((s) => s.tabs);
  const activeTabId = usePolicyTabsStore((s) => s.activeTabId);
  const savedPolicies = usePolicyTabsStore((s) => s.savedPolicies);
  const editStates = usePolicyEditStore((s) => s.editStates);
  const sidebarCollapsed = useWorkbenchUIStore((s) => s.sidebarCollapsed);
  const activeEditorTab = useWorkbenchUIStore((s) => s.activeEditorTab);
  const editorSyncDirection = useWorkbenchUIStore((s) => s.editorSyncDirection);

  const dispatch = policyDispatch();

  const activeTabMeta = useMemo(
    () => tabsMeta.find((t) => t.id === activeTabId),
    [tabsMeta, activeTabId],
  );

  const currentTabEdit = useMemo(
    () => editStates.get(activeTabId),
    [editStates, activeTabId],
  );

  const currentTab = useMemo(
    () =>
      activeTabMeta
        ? reconstructPolicyTab(activeTabMeta, currentTabEdit)
        : undefined,
    [activeTabMeta, currentTabEdit],
  );

  // Build WorkbenchState from active tab
  const workbenchState: WorkbenchState = useMemo(() => {
    if (!currentTab) {
      const yaml = policyToYaml(DEFAULT_POLICY);
      return {
        activePolicy: DEFAULT_POLICY,
        yaml,
        validation: validatePolicy(DEFAULT_POLICY),
        savedPolicies,
        comparisonPolicy: null,
        comparisonYaml: "",
        filePath: null,
        dirty: false,
        nativeValidation: emptyNativeValidation(),
        _undoPast: [],
        _undoFuture: [],
        _cleanSnapshot: null,
        ui: {
          sidebarCollapsed,
          activeEditorTab,
          editorSyncDirection,
        },
      };
    }

    return {
      activePolicy: currentTab.policy,
      yaml: currentTab.yaml,
      validation: currentTab.validation,
      savedPolicies,
      comparisonPolicy: null,
      comparisonYaml: "",
      filePath: currentTab.filePath,
      dirty: currentTab.dirty,
      nativeValidation: currentTab.nativeValidation,
      _undoPast: currentTab._undoPast,
      _undoFuture: currentTab._undoFuture,
      _cleanSnapshot: currentTab._cleanSnapshot,
      ui: {
        sidebarCollapsed,
        activeEditorTab,
        editorSyncDirection,
      },
    };
  }, [
    currentTab,
    savedPolicies,
    sidebarCollapsed,
    activeEditorTab,
    editorSyncDirection,
  ]);

  const workbenchDispatch = useCallback(
    (action: WorkbenchAction) => {
      dispatch(action as MultiPolicyAction);
    },
    [dispatch],
  );

  // ---- Callback implementations ----

  const saveCurrentPolicy = useCallback(() => {
    if (!currentTab || !isPolicyFileType(currentTab.fileType)) return;
    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    const savedPolicy: SavedPolicy = {
      id,
      policy: currentTab.policy,
      yaml: currentTab.yaml,
      createdAt: now,
      updatedAt: now,
    };
    usePolicyTabsStore.getState().savePolicyToLibrary(savedPolicy);
  }, [currentTab]);

  const exportYaml = useCallback(() => {
    if (!currentTab) return;
    const blob = new Blob([currentTab.yaml], {
      type:
        currentTab.fileType === "ocsf_event"
          ? "application/json"
          : "text/plain",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const stem = sanitizeFilenameStem(
      currentTab.name || "untitled",
      "untitled",
    );
    a.download = `${stem}${getPrimaryExtension(currentTab.fileType)}`;
    a.click();
    URL.revokeObjectURL(url);
  }, [currentTab]);

  const copyYaml = useCallback(() => {
    if (!currentTab) return;
    navigator.clipboard.writeText(currentTab.yaml).catch(() => {});
  }, [currentTab]);

  const loadPolicy = useCallback(
    (policy: WorkbenchPolicy) => {
      if (currentTab && !isPolicyFileType(currentTab.fileType)) {
        dispatch({ type: "NEW_TAB", policy });
        return;
      }
      dispatch({ type: "SET_POLICY", policy });
    },
    [currentTab, dispatch],
  );

  const openFile = useCallback(async () => {
    try {
      const result = await openDetectionFile();
      if (!result) return;
      dispatch({
        type: "OPEN_TAB_OR_SWITCH",
        filePath: result.path,
        fileType: result.fileType,
        yaml: result.content,
      });
      pushRecentFile(result.path);
    } catch (err) {
      console.error("[workbench-state] Failed to open file:", err);
    }
  }, [dispatch]);

  const openFileByPath = useCallback(
    async (filePath: string, options?: OpenFileByPathOptions) => {
      try {
        const result = await readDetectionFileByPath(filePath);
        if (!result) return;
        if (options?.shouldApply && !options.shouldApply()) return;
        dispatch({
          type: "OPEN_TAB_OR_SWITCH",
          filePath: result.path,
          fileType: result.fileType,
          yaml: result.content,
        });
        pushRecentFile(result.path);
      } catch (err) {
        console.error("[workbench-state] Failed to open file by path:", err);
      }
    },
    [dispatch],
  );

  const saveFileAs = useCallback(async () => {
    if (!currentTab) return;
    try {
      if (!isDesktop()) {
        exportYaml();
        return;
      }
      const savedPath = await saveDetectionFile(
        currentTab.yaml,
        currentTab.fileType,
        null,
        currentTab.name,
      );
      if (!savedPath) return;
      getDocumentIdentityStore().register(savedPath, currentTab.documentId);
      dispatch({ type: "SET_FILE_PATH", path: savedPath });
      dispatch({ type: "MARK_CLEAN" });
      pushRecentFile(savedPath);
    } catch (err) {
      console.error("[workbench-state] Failed to save file:", err);
    }
  }, [currentTab, exportYaml, dispatch]);

  const saveFile = useCallback(async () => {
    if (!currentTab) return;
    try {
      if (!isDesktop()) {
        exportYaml();
        return;
      }
      if (currentTab.filePath) {
        await saveDetectionFile(
          currentTab.yaml,
          currentTab.fileType,
          currentTab.filePath,
          currentTab.name,
        );
        dispatch({ type: "MARK_CLEAN" });
      } else {
        await saveFileAs();
      }
    } catch (err) {
      console.error("[workbench-state] Failed to save file:", err);
    }
  }, [currentTab, saveFileAs, exportYaml, dispatch]);

  const newPolicy = useCallback(() => {
    dispatch({ type: "NEW_TAB" });
  }, [dispatch]);

  const undo = useCallback(
    () => dispatch({ type: "UNDO" }),
    [dispatch],
  );
  const redo = useCallback(
    () => dispatch({ type: "REDO" }),
    [dispatch],
  );

  const canUndo = currentTab ? currentTab._undoPast.length > 0 : false;
  const canRedo = currentTab ? currentTab._undoFuture.length > 0 : false;

  return useMemo(
    () => ({
      state: workbenchState,
      dispatch: workbenchDispatch,
      saveCurrentPolicy,
      exportYaml,
      copyYaml,
      loadPolicy,
      openFile,
      openFileByPath,
      saveFile,
      saveFileAs,
      newPolicy,
      undo,
      redo,
      canUndo,
      canRedo,
    }),
    [
      workbenchState,
      workbenchDispatch,
      saveCurrentPolicy,
      exportYaml,
      copyYaml,
      loadPolicy,
      openFile,
      openFileByPath,
      saveFile,
      saveFileAs,
      newPolicy,
      undo,
      redo,
      canUndo,
      canRedo,
    ],
  );
}
