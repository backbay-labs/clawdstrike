import React, {
  createContext,
  useContext,
  useReducer,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  type ReactNode,
} from "react";
import type {
  WorkbenchPolicy,
  ValidationResult,
  SavedPolicy,
  GuardId,
  GuardConfigMap,
  OriginsConfig,
} from "./types";
import {
  DEFAULT_POLICY,
  type WorkbenchState,
  type WorkbenchAction,
  type PolicySnapshot,
  type NativeValidationState,
} from "./policy-store";
import { policyToYaml, yamlToPolicy, validatePolicy } from "./yaml-utils";
import {
  sanitizeObjectForStorageWithMetadata,
  sanitizeYamlForStorageWithMetadata,
} from "./storage-sanitizer";
import {
  isDesktop,
  openPolicyFile,
  savePolicyFile,
  readPolicyFileByPath,
} from "@/lib/tauri-bridge";


export interface PolicyTab {
  id: string;
  name: string;
  filePath: string | null;
  dirty: boolean;
  policy: WorkbenchPolicy;
  yaml: string;
  validation: ValidationResult;
  nativeValidation: NativeValidationState;
  testSuiteYaml?: string;
  _undoPast: PolicySnapshot[];
  _undoFuture: PolicySnapshot[];
  _cleanSnapshot: PolicySnapshot | null;
}

export type SplitMode = "none" | "horizontal" | "vertical";

export interface MultiPolicyState {
  tabs: PolicyTab[];
  activeTabId: string;
  splitMode: SplitMode;
  splitTabId: string | null;
  savedPolicies: SavedPolicy[];
  ui: {
    sidebarCollapsed: boolean;
    activeEditorTab: "visual" | "yaml";
    editorSyncDirection: "visual" | "yaml" | null;
  };
}

export interface BulkGuardUpdate {
  tabId: string;
  guardId: GuardId;
  enabled: boolean;
  config?: Record<string, unknown>;
}

export type MultiPolicyAction =
  | { type: "NEW_TAB"; policy?: WorkbenchPolicy; filePath?: string | null }
  | { type: "CLOSE_TAB"; tabId: string }
  | { type: "SWITCH_TAB"; tabId: string }
  | { type: "SET_SPLIT_MODE"; mode: SplitMode }
  | { type: "SET_SPLIT_TAB"; tabId: string | null }
  | { type: "RENAME_TAB"; tabId: string; name: string }
  | { type: "REORDER_TABS"; fromIndex: number; toIndex: number }
  | { type: "DUPLICATE_TAB"; tabId: string }
  | { type: "BULK_UPDATE_GUARDS"; updates: BulkGuardUpdate[] }
  | { type: "NEW_TAB_OR_SWITCH"; policy: WorkbenchPolicy; filePath: string; fallbackYaml?: string }
  | { type: "SET_TAB_TEST_SUITE"; tabId: string; yaml: string }
  | {
    type: "RESTORE_AUTOSAVE_ENTRIES";
    entries: Array<{
      tabId?: string;
      yaml: string;
      filePath: string | null;
      timestamp: number;
      policyName: string;
    }>;
  }
  // Delegated to active tab — same as WorkbenchAction
  | { type: "SET_POLICY"; policy: WorkbenchPolicy }
  | { type: "SET_YAML"; yaml: string }
  | { type: "UPDATE_GUARD"; guardId: GuardId; config: Partial<GuardConfigMap[GuardId]> }
  | { type: "TOGGLE_GUARD"; guardId: GuardId; enabled: boolean }
  | { type: "UPDATE_SETTINGS"; settings: Partial<WorkbenchPolicy["settings"]> }
  | { type: "UPDATE_META"; name?: string; description?: string; version?: string; extends?: string }
  | { type: "UPDATE_ORIGINS"; origins: OriginsConfig | undefined }
  | { type: "SAVE_POLICY"; savedPolicy: SavedPolicy }
  | { type: "DELETE_SAVED_POLICY"; id: string }
  | { type: "LOAD_SAVED_POLICIES"; policies: SavedPolicy[] }
  | { type: "SET_COMPARISON"; policy: WorkbenchPolicy | null; yaml?: string }
  | { type: "SET_SIDEBAR_COLLAPSED"; collapsed: boolean }
  | { type: "SET_EDITOR_TAB"; tab: "visual" | "yaml" }
  | { type: "SET_FILE_PATH"; path: string | null }
  | { type: "MARK_CLEAN" }
  | { type: "SET_NATIVE_VALIDATION"; payload: NativeValidationState }
  | { type: "UNDO" }
  | { type: "REDO" };


const TABS_STORAGE_KEY = "clawdstrike_workbench_tabs";
const SAVED_POLICIES_KEY = "clawdstrike_workbench_policies";
const RECENT_FILES_KEY = "clawdstrike_recent_files";
const MAX_RECENT_FILES = 10;
const MAX_TABS = 10;
const MAX_HISTORY = 50;


function createTabId(): string {
  return crypto.randomUUID();
}

function createDefaultTab(id?: string): PolicyTab {
  const yaml = policyToYaml(DEFAULT_POLICY);
  return {
    id: id ?? createTabId(),
    name: DEFAULT_POLICY.name,
    filePath: null,
    dirty: false,
    policy: DEFAULT_POLICY,
    yaml,
    validation: validatePolicy(DEFAULT_POLICY),
    nativeValidation: {
      guardErrors: {},
      topLevelErrors: [],
      loading: false,
      valid: null,
    },
    _undoPast: [],
    _undoFuture: [],
    _cleanSnapshot: null,
  };
}

function createTabFromPolicy(policy: WorkbenchPolicy, filePath?: string | null): PolicyTab {
  const yaml = policyToYaml(policy);
  return {
    id: createTabId(),
    name: policy.name || "Untitled",
    filePath: filePath ?? null,
    dirty: false,
    policy,
    yaml,
    validation: validatePolicy(policy),
    nativeValidation: {
      guardErrors: {},
      topLevelErrors: [],
      loading: false,
      valid: null,
    },
    _undoPast: [],
    _undoFuture: [],
    _cleanSnapshot: {
      activePolicy: policy,
      yaml,
      validation: validatePolicy(policy),
    },
  };
}

function replaceTabFromOpenedFile(
  tab: PolicyTab,
  policy: WorkbenchPolicy,
  filePath: string,
  yamlFromDisk?: string,
): PolicyTab {
  const yaml = yamlFromDisk ?? policyToYaml(policy);
  const validation = validatePolicy(policy);

  return {
    ...tab,
    name: policy.name || "Untitled",
    filePath,
    yaml,
    policy,
    dirty: false,
    validation,
    nativeValidation: {
      guardErrors: {},
      topLevelErrors: [],
      loading: false,
      valid: null,
    },
    _undoPast: [],
    _undoFuture: [],
    _cleanSnapshot: {
      activePolicy: policy,
      yaml,
      validation,
    },
  };
}

function takeTabSnapshot(tab: PolicyTab): PolicySnapshot {
  return {
    activePolicy: tab.policy,
    yaml: tab.yaml,
    validation: tab.validation,
  };
}

function snapshotsEqual(a: PolicySnapshot, b: PolicySnapshot): boolean {
  return a.yaml === b.yaml;
}

function isTabDirtyVsClean(tab: PolicyTab): boolean {
  if (!tab._cleanSnapshot) return true;
  return !snapshotsEqual(takeTabSnapshot(tab), tab._cleanSnapshot);
}

function revalidate(policy: WorkbenchPolicy, yaml?: string): { yaml: string; validation: ValidationResult } {
  const y = yaml ?? policyToYaml(policy);
  return {
    yaml: y,
    validation: validatePolicy(policy),
  };
}

function applyYamlToTab(
  tab: PolicyTab,
  yaml: string,
  options?: {
    dirty?: boolean;
    filePath?: string | null;
    nameFallback?: string;
  },
): PolicyTab {
  const nextDirty = options?.dirty ?? tab.dirty;
  const nextFilePath = options?.filePath !== undefined ? options.filePath : tab.filePath;
  const [policy, errors] = yamlToPolicy(yaml);

  if (policy && errors.length === 0) {
    return {
      ...tab,
      policy,
      name: policy.name || options?.nameFallback || tab.name,
      yaml,
      filePath: nextFilePath,
      dirty: nextDirty,
      validation: validatePolicy(policy),
    };
  }

  return {
    ...tab,
    name: options?.nameFallback || tab.name,
    yaml,
    filePath: nextFilePath,
    dirty: nextDirty,
    validation: {
      valid: false,
      errors: errors.map((msg) => ({
        path: "yaml",
        message: msg,
        severity: "error" as const,
      })),
      warnings: [],
    },
  };
}

/** Actions that modify the policy and should be tracked by undo/redo. */
const POLICY_MODIFYING_ACTIONS = new Set([
  "SET_POLICY",
  "SET_YAML",
  "UPDATE_GUARD",
  "TOGGLE_GUARD",
  "UPDATE_SETTINGS",
  "UPDATE_META",
  "UPDATE_ORIGINS",
]);

/** Actions that are delegated to the active tab's policy state. */
const TAB_DELEGATED_ACTIONS = new Set([
  "SET_POLICY",
  "SET_YAML",
  "UPDATE_GUARD",
  "TOGGLE_GUARD",
  "UPDATE_SETTINGS",
  "UPDATE_META",
  "UPDATE_ORIGINS",
  "SET_FILE_PATH",
  "MARK_CLEAN",
  "SET_NATIVE_VALIDATION",
  "UNDO",
  "REDO",
]);


function tabCoreReducer(tab: PolicyTab, action: MultiPolicyAction): PolicyTab {
  switch (action.type) {
    case "SET_POLICY": {
      const rv = revalidate(action.policy);
      return {
        ...tab,
        policy: action.policy,
        name: action.policy.name || tab.name,
        dirty: true,
        ...rv,
      };
    }

    case "SET_YAML": {
      return applyYamlToTab(tab, action.yaml, { dirty: true });
    }

    case "UPDATE_GUARD": {
      const newGuards = {
        ...tab.policy.guards,
        [action.guardId]: {
          ...(tab.policy.guards[action.guardId] || {}),
          ...action.config,
        },
      };
      const newPolicy = { ...tab.policy, guards: newGuards };
      return { ...tab, policy: newPolicy, dirty: true, ...revalidate(newPolicy) };
    }

    case "TOGGLE_GUARD": {
      const existing = tab.policy.guards[action.guardId] || {};
      const newGuards = {
        ...tab.policy.guards,
        [action.guardId]: { ...existing, enabled: action.enabled },
      };
      if (!action.enabled) {
        const config = newGuards[action.guardId];
        if (config && Object.keys(config).length === 1 && "enabled" in config) {
          delete newGuards[action.guardId];
        }
      }
      const newPolicy = { ...tab.policy, guards: newGuards };
      return { ...tab, policy: newPolicy, dirty: true, ...revalidate(newPolicy) };
    }

    case "UPDATE_SETTINGS": {
      const newPolicy = {
        ...tab.policy,
        settings: { ...tab.policy.settings, ...action.settings },
      };
      return { ...tab, policy: newPolicy, dirty: true, ...revalidate(newPolicy) };
    }

    case "UPDATE_META": {
      const newPolicy = { ...tab.policy };
      if (action.name !== undefined) {
        newPolicy.name = action.name;
      }
      if (action.description !== undefined) newPolicy.description = action.description;
      if (action.version !== undefined) newPolicy.version = action.version as WorkbenchPolicy["version"];
      if (action.extends !== undefined) newPolicy.extends = action.extends || undefined;
      const rv = revalidate(newPolicy);
      return {
        ...tab,
        policy: newPolicy,
        name: newPolicy.name || tab.name,
        dirty: true,
        ...rv,
      };
    }

    case "UPDATE_ORIGINS": {
      const newPolicy = { ...tab.policy, origins: action.origins };
      return { ...tab, policy: newPolicy, dirty: true, ...revalidate(newPolicy) };
    }

    case "SET_FILE_PATH": {
      return { ...tab, filePath: action.path };
    }

    case "MARK_CLEAN": {
      return {
        ...tab,
        dirty: false,
        _cleanSnapshot: takeTabSnapshot(tab),
      };
    }

    case "SET_NATIVE_VALIDATION": {
      return { ...tab, nativeValidation: action.payload };
    }

    case "UNDO":
    case "REDO":
      return tab;

    default:
      return tab;
  }
}

function tabReducer(tab: PolicyTab, action: MultiPolicyAction): PolicyTab {
  if (action.type === "UNDO") {
    if (tab._undoPast.length === 0) return tab;
    const past = [...tab._undoPast];
    const snapshot = past.pop()!;
    const currentSnapshot = takeTabSnapshot(tab);
    const newTab: PolicyTab = {
      ...tab,
      policy: snapshot.activePolicy,
      yaml: snapshot.yaml,
      validation: snapshot.validation,
      _undoPast: past,
      _undoFuture: [currentSnapshot, ...tab._undoFuture],
    };
    newTab.dirty = isTabDirtyVsClean(newTab);
    return newTab;
  }

  if (action.type === "REDO") {
    if (tab._undoFuture.length === 0) return tab;
    const future = [...tab._undoFuture];
    const snapshot = future.shift()!;
    const currentSnapshot = takeTabSnapshot(tab);
    const newTab: PolicyTab = {
      ...tab,
      policy: snapshot.activePolicy,
      yaml: snapshot.yaml,
      validation: snapshot.validation,
      _undoPast: [...tab._undoPast, currentSnapshot].slice(-MAX_HISTORY),
      _undoFuture: future,
    };
    newTab.dirty = isTabDirtyVsClean(newTab);
    return newTab;
  }

  if (POLICY_MODIFYING_ACTIONS.has(action.type)) {
    const currentSnapshot = takeTabSnapshot(tab);
    const next = tabCoreReducer(tab, action);
    const nextSnapshot = takeTabSnapshot(next);
    if (snapshotsEqual(currentSnapshot, nextSnapshot)) return next;
    return {
      ...next,
      _undoPast: [...tab._undoPast, currentSnapshot].slice(-MAX_HISTORY),
      _undoFuture: [],
    };
  }

  return tabCoreReducer(tab, action);
}


function multiPolicyReducer(state: MultiPolicyState, action: MultiPolicyAction): MultiPolicyState {
  switch (action.type) {
    case "NEW_TAB": {
      if (state.tabs.length >= MAX_TABS) return state;
      const newTab = action.policy
        ? createTabFromPolicy(action.policy, action.filePath)
        : createDefaultTab();
      return {
        ...state,
        tabs: [...state.tabs, newTab],
        activeTabId: newTab.id,
      };
    }

    case "CLOSE_TAB": {
      const idx = state.tabs.findIndex((t) => t.id === action.tabId);
      if (idx === -1) return state;
      const newTabs = state.tabs.filter((t) => t.id !== action.tabId);

      // Don't allow closing the last tab — create a fresh default one
      if (newTabs.length === 0) {
        const freshTab = createDefaultTab();
        return {
          ...state,
          tabs: [freshTab],
          activeTabId: freshTab.id,
          splitTabId: null,
          splitMode: "none",
        };
      }

      let newActiveId = state.activeTabId;
      if (state.activeTabId === action.tabId) {
        // Switch to the tab before the closed one, or the first
        const newIdx = Math.min(idx, newTabs.length - 1);
        newActiveId = newTabs[newIdx].id;
      }

      let newSplitTabId = state.splitTabId;
      if (state.splitTabId === action.tabId) {
        newSplitTabId = null;
      }

      return {
        ...state,
        tabs: newTabs,
        activeTabId: newActiveId,
        splitTabId: newSplitTabId,
        splitMode: newSplitTabId === null && state.splitMode !== "none" ? "none" : state.splitMode,
      };
    }

    case "SWITCH_TAB": {
      if (!state.tabs.some((t) => t.id === action.tabId)) return state;
      return { ...state, activeTabId: action.tabId };
    }

    case "SET_SPLIT_MODE": {
      if (action.mode === "none") {
        return { ...state, splitMode: "none", splitTabId: null };
      }
      return { ...state, splitMode: action.mode };
    }

    case "SET_SPLIT_TAB": {
      return { ...state, splitTabId: action.tabId };
    }

    case "RENAME_TAB": {
      return {
        ...state,
        tabs: state.tabs.map((t) =>
          t.id === action.tabId ? { ...t, name: action.name } : t
        ),
      };
    }

    case "REORDER_TABS": {
      if (
        action.fromIndex < 0 ||
        action.toIndex < 0 ||
        action.fromIndex >= state.tabs.length ||
        action.toIndex >= state.tabs.length
      ) {
        return state;
      }
      const newTabs = [...state.tabs];
      const [moved] = newTabs.splice(action.fromIndex, 1);
      newTabs.splice(action.toIndex, 0, moved);
      return { ...state, tabs: newTabs };
    }

    case "DUPLICATE_TAB": {
      if (state.tabs.length >= MAX_TABS) return state;
      const source = state.tabs.find((t) => t.id === action.tabId);
      if (!source) return state;
      const duped: PolicyTab = {
        ...source,
        id: createTabId(),
        name: `${source.name} (copy)`,
        filePath: null,
        dirty: true,
        _undoPast: [],
        _undoFuture: [],
        _cleanSnapshot: null,
      };
      const idx = state.tabs.findIndex((t) => t.id === action.tabId);
      const newTabs = [...state.tabs];
      newTabs.splice(idx + 1, 0, duped);
      return {
        ...state,
        tabs: newTabs,
        activeTabId: duped.id,
      };
    }

    // Bulk guard update — applies guard changes across multiple tabs in a single
    // reducer call, avoiding the SWITCH_TAB + TOGGLE_GUARD race (#6).
    case "BULK_UPDATE_GUARDS": {
      const updatesByTab = new Map<string, BulkGuardUpdate[]>();
      for (const u of action.updates) {
        const list = updatesByTab.get(u.tabId) ?? [];
        list.push(u);
        updatesByTab.set(u.tabId, list);
      }

      const newTabs = state.tabs.map((tab) => {
        const updates = updatesByTab.get(tab.id);
        if (!updates) return tab;

        let current = tab;
        for (const u of updates) {
          // Apply toggle
          const toggleAction: MultiPolicyAction = {
            type: "TOGGLE_GUARD",
            guardId: u.guardId,
            enabled: u.enabled,
          };
          current = tabReducer(current, toggleAction);

          // Apply additional config if provided
          if (u.config && Object.keys(u.config).length > 0) {
            const configAction: MultiPolicyAction = {
              type: "UPDATE_GUARD",
              guardId: u.guardId,
              config: u.config as Partial<GuardConfigMap[GuardId]>,
            };
            current = tabReducer(current, configAction);
          }
        }

        return current;
      });

      return { ...state, tabs: newTabs };
    }

    // Atomically check if a file path is already open and switch to it, or
    // create a new tab — avoids stale closure race in async file dialogs (#31).
    case "NEW_TAB_OR_SWITCH": {
      const existing = state.tabs.find((t) => t.filePath === action.filePath);
      if (existing) {
        return {
          ...state,
          tabs: state.tabs.map((tab) =>
            tab.id === existing.id
              ? replaceTabFromOpenedFile(tab, action.policy, action.filePath, action.fallbackYaml)
              : tab,
          ),
          activeTabId: existing.id,
        };
      }
      if (state.tabs.length >= MAX_TABS) return state;
      const newTab = replaceTabFromOpenedFile(
        createTabFromPolicy(action.policy, action.filePath),
        action.policy,
        action.filePath,
        action.fallbackYaml,
      );
      return {
        ...state,
        tabs: [...state.tabs, newTab],
        activeTabId: newTab.id,
      };
    }

    // Saved policies (global, not per-tab)
    case "SAVE_POLICY": {
      const existing = state.savedPolicies.filter((p) => p.id !== action.savedPolicy.id);
      return { ...state, savedPolicies: [...existing, action.savedPolicy] };
    }

    case "DELETE_SAVED_POLICY": {
      return {
        ...state,
        savedPolicies: state.savedPolicies.filter((p) => p.id !== action.id),
      };
    }

    case "LOAD_SAVED_POLICIES": {
      return { ...state, savedPolicies: action.policies };
    }

    // UI state (global)
    case "SET_SIDEBAR_COLLAPSED": {
      return { ...state, ui: { ...state.ui, sidebarCollapsed: action.collapsed } };
    }

    case "SET_EDITOR_TAB": {
      return { ...state, ui: { ...state.ui, activeEditorTab: action.tab } };
    }

    case "SET_TAB_TEST_SUITE": {
      return {
        ...state,
        tabs: state.tabs.map((t) =>
          t.id === action.tabId ? { ...t, testSuiteYaml: action.yaml } : t
        ),
      };
    }

    case "RESTORE_AUTOSAVE_ENTRIES": {
      if (action.entries.length === 0) return state;

      let nextTabs = [...state.tabs];
      let nextActiveTabId = state.activeTabId;

      for (const entry of action.entries) {
        const existingIndex = nextTabs.findIndex((tab) => {
          if (entry.tabId && tab.id === entry.tabId) return true;
          return entry.filePath !== null && tab.filePath === entry.filePath;
        });

        if (existingIndex >= 0) {
          const existing = nextTabs[existingIndex];
          nextTabs[existingIndex] = {
            ...applyYamlToTab(existing, entry.yaml, {
              dirty: true,
              filePath: entry.filePath,
              nameFallback: entry.policyName || existing.name,
            }),
            _undoPast: [],
            _undoFuture: [],
          };
          nextActiveTabId = nextTabs[existingIndex].id;
          continue;
        }

        if (nextTabs.length >= MAX_TABS) {
          break;
        }

        const restored = applyYamlToTab(createDefaultTab(entry.tabId), entry.yaml, {
          dirty: true,
          filePath: entry.filePath,
          nameFallback: entry.policyName || "Recovered Policy",
        });
        nextTabs = [
          ...nextTabs,
          {
            ...restored,
            _undoPast: [],
            _undoFuture: [],
            _cleanSnapshot: null,
          },
        ];
        nextActiveTabId = restored.id;
      }

      return {
        ...state,
        tabs: nextTabs,
        activeTabId: nextActiveTabId,
      };
    }

    // SET_COMPARISON is a no-op in multi-policy mode (comparison lives in /compare route)
    case "SET_COMPARISON":
      return state;

    default:
      break;
  }

  // Delegate to active tab
  if (TAB_DELEGATED_ACTIONS.has(action.type)) {
    return {
      ...state,
      tabs: state.tabs.map((t) =>
        t.id === state.activeTabId ? tabReducer(t, action) : t
      ),
      // Sync UI editorSyncDirection for delegated SET_POLICY / SET_YAML
      ui: action.type === "SET_POLICY"
        ? { ...state.ui, editorSyncDirection: "visual" }
        : action.type === "SET_YAML"
        ? { ...state.ui, editorSyncDirection: "yaml" }
        : state.ui,
    };
  }

  return state;
}


function activeTab(state: MultiPolicyState): PolicyTab | undefined {
  return state.tabs.find((t) => t.id === state.activeTabId);
}

function toWorkbenchState(state: MultiPolicyState): WorkbenchState {
  const tab = activeTab(state);
  if (!tab) {
    // Should not happen, but defensive
    const yaml = policyToYaml(DEFAULT_POLICY);
    return {
      activePolicy: DEFAULT_POLICY,
      yaml,
      validation: validatePolicy(DEFAULT_POLICY),
      savedPolicies: state.savedPolicies,
      comparisonPolicy: null,
      comparisonYaml: "",
      filePath: null,
      dirty: false,
      nativeValidation: { guardErrors: {}, topLevelErrors: [], loading: false, valid: null },
      _undoPast: [],
      _undoFuture: [],
      _cleanSnapshot: null,
      ui: state.ui,
    };
  }

  return {
    activePolicy: tab.policy,
    yaml: tab.yaml,
    validation: tab.validation,
    savedPolicies: state.savedPolicies,
    comparisonPolicy: null,
    comparisonYaml: "",
    filePath: tab.filePath,
    dirty: tab.dirty,
    nativeValidation: tab.nativeValidation,
    _undoPast: tab._undoPast,
    _undoFuture: tab._undoFuture,
    _cleanSnapshot: tab._cleanSnapshot,
    ui: state.ui,
  };
}


interface PersistedTab {
  id: string;
  name: string;
  filePath: string | null;
  yaml: string;
  sensitiveFieldsStripped?: boolean;
}

interface PersistedTabState {
  tabs: PersistedTab[];
  activeTabId: string;
}

function persistTabs(state: MultiPolicyState): void {
  try {
    const persisted: PersistedTabState = {
      tabs: state.tabs.map((t) => {
        const sanitized = sanitizeYamlForStorageWithMetadata(t.yaml);
        const sensitiveFieldsStripped = sanitized.sensitiveFieldsStripped;
        return {
          id: t.id,
          name: t.name,
          filePath: sensitiveFieldsStripped ? null : t.filePath,
          yaml: sanitized.yaml,
          sensitiveFieldsStripped: sensitiveFieldsStripped || undefined,
        };
      }),
      activeTabId: state.activeTabId,
    };
    localStorage.setItem(TABS_STORAGE_KEY, JSON.stringify(persisted));
  } catch (e) {
    // TODO: surface via toast when toast system is available outside React components
    console.error("[multi-policy-store] persistTabs failed — changes may be lost on reload:", e);
  }
}

function loadPersistedTabs(): MultiPolicyState | null {
  try {
    const raw = localStorage.getItem(TABS_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    // Validate persisted data shape
    if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.tabs)) {
      console.warn("[multi-policy-store] Invalid persisted tab data, using defaults");
      return null;
    }
    const persisted = parsed as PersistedTabState;
    if (persisted.tabs.length === 0) return null;

    // Per-entry type validation (#30): skip entries with invalid shape
    const validPersistedTabs = persisted.tabs.filter((pt) =>
      typeof pt.id === "string" && typeof pt.yaml === "string"
    );
    if (validPersistedTabs.length === 0) return null;

    const tabs: PolicyTab[] = validPersistedTabs.map((pt) => {
      const [policy] = yamlToPolicy(pt.yaml);
      const pol = policy ?? DEFAULT_POLICY;
      const yaml = pt.yaml;
      const validation = validatePolicy(pol);
      const sensitiveFieldsStripped = pt.sensitiveFieldsStripped === true;
      return {
        id: pt.id,
        name: pt.name || pol.name || "Untitled",
        filePath: sensitiveFieldsStripped ? null : pt.filePath,
        dirty: sensitiveFieldsStripped,
        policy: pol,
        yaml,
        validation,
        nativeValidation: { guardErrors: {}, topLevelErrors: [], loading: false, valid: null },
        _undoPast: [],
        _undoFuture: [],
        _cleanSnapshot: sensitiveFieldsStripped
          ? null
          : { activePolicy: pol, yaml, validation },
      };
    });

    const activeTabId = tabs.some((t) => t.id === persisted.activeTabId)
      ? persisted.activeTabId
      : tabs[0].id;

    return {
      tabs,
      activeTabId,
      splitMode: "none",
      splitTabId: null,
      savedPolicies: [],
      ui: {
        sidebarCollapsed: false,
        activeEditorTab: "visual",
        editorSyncDirection: null,
      },
    };
  } catch (e) {
    console.warn("[multi-policy-store] loadPersistedTabs failed:", e);
    return null;
  }
}

function pushRecentFile(filePath: string): void {
  try {
    const stored = localStorage.getItem(RECENT_FILES_KEY);
    const parsed = stored ? JSON.parse(stored) : [];
    const files = Array.isArray(parsed) ? parsed.filter((f): f is string => typeof f === "string") : [];
    const updated = [filePath, ...files.filter((p) => p !== filePath)].slice(0, MAX_RECENT_FILES);
    localStorage.setItem(RECENT_FILES_KEY, JSON.stringify(updated));
  } catch (e) {
    console.warn("[multi-policy-store] pushRecentFile localStorage operation failed:", e);
  }
}

function sanitizeSavedPolicy(savedPolicy: SavedPolicy): SavedPolicy {
  const sanitized = sanitizeYamlForStorageWithMetadata(savedPolicy.yaml);
  const sanitizedPolicy = sanitizeObjectForStorageWithMetadata(savedPolicy.policy);
  const [parsedPolicy, errors] = yamlToPolicy(sanitized.yaml);
  const sensitiveFieldsStripped =
    sanitized.sensitiveFieldsStripped || sanitizedPolicy.sensitiveFieldsStripped;
  const storedPolicy =
    sensitiveFieldsStripped && parsedPolicy && errors.length === 0
      ? parsedPolicy
      : sanitizedPolicy.value;

  return {
    ...savedPolicy,
    yaml: sanitized.yaml,
    policy: storedPolicy,
    sensitiveFieldsStripped: sensitiveFieldsStripped || undefined,
  };
}


interface MultiPolicyContextValue {
  /** The full multi-policy state for components that need tab awareness. */
  multiState: MultiPolicyState;
  /** Dispatch for multi-policy actions. */
  multiDispatch: React.Dispatch<MultiPolicyAction>;
  /** Active tab, or undefined if no tabs exist (should never happen). */
  activeTab: PolicyTab | undefined;
  /** All open tabs. */
  tabs: PolicyTab[];
  /** Whether new tabs can be added. */
  canAddTab: boolean;
}

/**
 * Backward-compatible WorkbenchContext value — identical API to the single-policy store.
 * Components using useWorkbench() get this transparently.
 */
interface WorkbenchContextValue {
  state: WorkbenchState;
  dispatch: React.Dispatch<WorkbenchAction>;
  saveCurrentPolicy: () => void;
  exportYaml: () => void;
  copyYaml: () => void;
  loadPolicy: (policy: WorkbenchPolicy) => void;
  openFile: () => Promise<void>;
  openFileByPath: (filePath: string) => Promise<void>;
  saveFile: () => Promise<void>;
  saveFileAs: () => Promise<void>;
  newPolicy: () => void;
  undo: () => void;
  redo: () => void;
  canUndo: boolean;
  canRedo: boolean;
}

const MultiPolicyContext = createContext<MultiPolicyContextValue | null>(null);
const WorkbenchContext = createContext<WorkbenchContextValue | null>(null);


/** Access the multi-policy tab state (for tab bar, split pane, etc.). */
export function useMultiPolicy(): MultiPolicyContextValue {
  const ctx = useContext(MultiPolicyContext);
  if (!ctx) throw new Error("useMultiPolicy must be used within MultiPolicyProvider");
  return ctx;
}

/**
 * Backward-compatible hook — returns the active tab's state shaped as WorkbenchState.
 * Existing components that call useWorkbench() continue to work unchanged.
 */
export function useWorkbench(): WorkbenchContextValue {
  const ctx = useContext(WorkbenchContext);
  if (!ctx) throw new Error("useWorkbench must be used within MultiPolicyProvider");
  return ctx;
}


function getInitialState(): MultiPolicyState {
  const restored = loadPersistedTabs();
  if (restored) return restored;

  const defaultTab = createDefaultTab();
  return {
    tabs: [defaultTab],
    activeTabId: defaultTab.id,
    splitMode: "none",
    splitTabId: null,
    savedPolicies: [],
    ui: {
      sidebarCollapsed: false,
      activeEditorTab: "visual",
      editorSyncDirection: null,
    },
  };
}


export function MultiPolicyProvider({ children }: { children: ReactNode }) {
  const [multiState, multiDispatch] = useReducer(multiPolicyReducer, undefined, getInitialState);

  // Hydrate saved policies from localStorage with shape validation (#17)
  useEffect(() => {
    try {
      const stored = localStorage.getItem(SAVED_POLICIES_KEY);
      if (stored) {
        const parsed: unknown = JSON.parse(stored);
        if (!Array.isArray(parsed)) {
          console.warn("[multi-policy-store] Saved policies is not an array, skipping hydration");
          return;
        }
        const policies: SavedPolicy[] = parsed.filter((entry: unknown): entry is SavedPolicy => {
          if (!entry || typeof entry !== "object") return false;
          const e = entry as Record<string, unknown>;
          return (
            typeof e.id === "string" &&
            typeof e.policy === "object" && e.policy !== null &&
            typeof e.yaml === "string"
          );
        }).map(sanitizeSavedPolicy);
        multiDispatch({ type: "LOAD_SAVED_POLICIES", policies });
      }
    } catch (e) {
      console.warn("[multi-policy-store] hydrate saved policies failed:", e);
    }
  }, []);

  // Persist saved policies
  useEffect(() => {
    try {
      localStorage.setItem(
        SAVED_POLICIES_KEY,
        JSON.stringify(multiState.savedPolicies.map(sanitizeSavedPolicy)),
      );
    } catch (e) {
      // TODO: surface via toast when toast system is available outside React components
      console.error("[multi-policy-store] persist saved policies failed — changes may be lost on reload:", e);
    }
  }, [multiState.savedPolicies]);

  // Persist tab state on changes (debounced to avoid perf hit)
  const persistRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (persistRef.current) clearTimeout(persistRef.current);
    persistRef.current = setTimeout(() => {
      persistTabs(multiState);
    }, 500);
    return () => {
      if (persistRef.current) clearTimeout(persistRef.current);
    };
  }, [multiState.tabs, multiState.activeTabId]);

  const currentTab = activeTab(multiState);

  // Compute backward-compatible WorkbenchState, memoized to avoid creating a
  // new reference on every render when the inputs haven't changed.
  const workbenchState = useMemo(
    () => toWorkbenchState(multiState),
    [
      currentTab?.policy,
      currentTab?.yaml,
      currentTab?.validation,
      currentTab?.nativeValidation,
      currentTab?.filePath,
      currentTab?.dirty,
      currentTab?._undoPast,
      currentTab?._undoFuture,
      currentTab?._cleanSnapshot,
      multiState.savedPolicies,
      multiState.ui,
    ],
  );

  // Bridge dispatch: WorkbenchAction -> MultiPolicyAction
  // The type sets are identical, so we can forward directly
  const workbenchDispatch = useCallback(
    (action: WorkbenchAction) => {
      multiDispatch(action as MultiPolicyAction);
    },
    [multiDispatch],
  );

  // ---- Callback implementations (mirroring single-policy store) ----

  const saveCurrentPolicy = useCallback(() => {
    if (!currentTab) return;
    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    const savedPolicy = sanitizeSavedPolicy({
      id,
      policy: currentTab.policy,
      yaml: currentTab.yaml,
      createdAt: now,
      updatedAt: now,
    });
    multiDispatch({ type: "SAVE_POLICY", savedPolicy });
  }, [currentTab, multiDispatch]);

  const exportYaml = useCallback(() => {
    if (!currentTab) return;
    const blob = new Blob([currentTab.yaml], { type: "text/yaml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${currentTab.policy.name || "policy"}.yaml`;
    a.click();
    URL.revokeObjectURL(url);
  }, [currentTab]);

  const copyYaml = useCallback(() => {
    if (!currentTab) return;
    navigator.clipboard.writeText(currentTab.yaml).catch(() => {});
  }, [currentTab]);

  const loadPolicy = useCallback(
    (policy: WorkbenchPolicy) => {
      multiDispatch({ type: "SET_POLICY", policy });
    },
    [multiDispatch],
  );

  const openFile = useCallback(async () => {
    try {
      const result = await openPolicyFile();
      if (!result) return;

      const [policy] = yamlToPolicy(result.content);
      if (policy) {
        // Atomically check-and-switch-or-create inside the reducer (#31)
        multiDispatch({
          type: "NEW_TAB_OR_SWITCH",
          policy,
          filePath: result.path,
          fallbackYaml: result.content,
        });
      } else {
        // Still open but with raw yaml in current tab
        multiDispatch({ type: "SET_YAML", yaml: result.content });
        multiDispatch({ type: "SET_FILE_PATH", path: result.path });
      }
      multiDispatch({ type: "MARK_CLEAN" });
      pushRecentFile(result.path);
    } catch (err) {
      console.error("[multi-policy] Failed to open file:", err);
    }
  }, [multiDispatch]);

  const openFileByPath = useCallback(
    async (filePath: string) => {
      try {
        const result = await readPolicyFileByPath(filePath);
        if (!result) return;

        const [policy] = yamlToPolicy(result.content);
        if (policy) {
          // Atomically check-and-switch-or-create inside the reducer (#31)
          multiDispatch({
            type: "NEW_TAB_OR_SWITCH",
            policy,
            filePath: result.path,
            fallbackYaml: result.content,
          });
        } else {
          multiDispatch({ type: "SET_YAML", yaml: result.content });
          multiDispatch({ type: "SET_FILE_PATH", path: result.path });
        }
        multiDispatch({ type: "MARK_CLEAN" });
        pushRecentFile(result.path);
      } catch (err) {
        console.error("[multi-policy] Failed to open file by path:", err);
      }
    },
    [multiDispatch],
  );

  const saveFileAs = useCallback(async () => {
    if (!currentTab) return;
    try {
      if (!isDesktop()) {
        exportYaml();
        return;
      }
      const savedPath = await savePolicyFile(currentTab.yaml);
      if (!savedPath) return;
      multiDispatch({ type: "SET_FILE_PATH", path: savedPath });
      multiDispatch({ type: "MARK_CLEAN" });
      pushRecentFile(savedPath);
    } catch (err) {
      console.error("[multi-policy] Failed to save file:", err);
    }
  }, [currentTab, exportYaml, multiDispatch]);

  const saveFile = useCallback(async () => {
    if (!currentTab) return;
    try {
      if (!isDesktop()) {
        exportYaml();
        return;
      }
      if (currentTab.filePath) {
        await savePolicyFile(currentTab.yaml, currentTab.filePath);
        multiDispatch({ type: "MARK_CLEAN" });
      } else {
        await saveFileAs();
      }
    } catch (err) {
      console.error("[multi-policy] Failed to save file:", err);
    }
  }, [currentTab, saveFileAs, exportYaml, multiDispatch]);

  const newPolicy = useCallback(() => {
    multiDispatch({ type: "NEW_TAB" });
  }, [multiDispatch]);

  const undo = useCallback(() => multiDispatch({ type: "UNDO" }), [multiDispatch]);
  const redo = useCallback(() => multiDispatch({ type: "REDO" }), [multiDispatch]);

  const canUndo = currentTab ? currentTab._undoPast.length > 0 : false;
  const canRedo = currentTab ? currentTab._undoFuture.length > 0 : false;

  const multiContextValue: MultiPolicyContextValue = {
    multiState,
    multiDispatch,
    activeTab: currentTab,
    tabs: multiState.tabs,
    canAddTab: multiState.tabs.length < MAX_TABS,
  };

  const workbenchContextValue: WorkbenchContextValue = {
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
  };

  return (
    <MultiPolicyContext.Provider value={multiContextValue}>
      <WorkbenchContext.Provider value={workbenchContextValue}>
        {children}
      </WorkbenchContext.Provider>
    </MultiPolicyContext.Provider>
  );
}
