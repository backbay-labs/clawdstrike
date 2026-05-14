/**
 * policy-tabs-store.ts — Zustand store for tab lifecycle management.
 *
 * Extracted from the monolithic multi-policy-store.tsx (Phase B1).
 * Manages tabs, active tab, split mode, and saved policies.
 * localStorage persistence for tabs and saved policies.
 */
import { create } from "zustand";
import type {
  GuardConfigMap,
  GuardId,
  SavedPolicy,
  WorkbenchPolicy,
} from "@/lib/workbench/types";
import {
  DEFAULT_POLICY,
  type PolicySnapshot,
  type NativeValidationState,
} from "@/features/policy/stores/policy-store";
import {
  policyToYaml,
  yamlToPolicy,
  validatePolicy,
} from "@/features/policy/yaml-utils";
import {
  sanitizeObjectForStorageWithMetadata,
  sanitizeYamlForStorageWithMetadata,
} from "@/lib/workbench/storage-sanitizer";
import {
  FILE_TYPE_REGISTRY,
  coerceFileType,
  isPolicyFileType,
  type FileType,
} from "@/lib/workbench/file-type-registry";
import { getDocumentIdentityStore } from "@/lib/workbench/detection-workflow/document-identity-store";
import {
  evaluateTabSource,
  emptyNativeValidation,
  type TabEditState,
} from "@/features/policy/stores/policy-edit-store";
import { usePolicyEditStore } from "@/features/policy/stores/policy-edit-store";

// Re-export types that consumers depend on
export type { TabEditState } from "@/features/policy/stores/policy-edit-store";

// ---- Constants ----

const TABS_STORAGE_KEY = "clawdstrike_workbench_tabs";
const SAVED_POLICIES_KEY = "clawdstrike_workbench_policies";
const RECENT_FILES_KEY = "clawdstrike_recent_files";
const MAX_RECENT_FILES = 10;
const MAX_TABS = 25;

// ---- Tab metadata type (slim — editing data lives in policy-edit-store) ----

export interface TabMeta {
  id: string;
  /** Stable document identity — survives tab close/reopen, save, rename. */
  documentId: string;
  name: string;
  filePath: string | null;
  dirty: boolean;
  fileType: FileType;
}

export type SplitMode = "none" | "horizontal" | "vertical";

// ---- Helpers ----

function createTabId(): string {
  return crypto.randomUUID();
}

function createDocumentId(): string {
  return crypto.randomUUID();
}

function resolveDocumentId(filePath: string | null): string {
  if (!filePath) return createDocumentId();
  const store = getDocumentIdentityStore();
  const existing = store.resolve(filePath);
  if (existing) return existing;
  const newId = createDocumentId();
  store.register(filePath, newId);
  return newId;
}

function sanitizeSavedPolicy(savedPolicy: SavedPolicy): SavedPolicy {
  const sanitized = sanitizeYamlForStorageWithMetadata(savedPolicy.yaml);
  const sanitizedPolicy = sanitizeObjectForStorageWithMetadata(
    savedPolicy.policy,
  );
  const [parsedPolicy, errors] = yamlToPolicy(sanitized.yaml);
  const sensitiveFieldsStripped =
    sanitized.sensitiveFieldsStripped ||
    sanitizedPolicy.sensitiveFieldsStripped;
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

export function pushRecentFile(filePath: string): void {
  try {
    const stored = localStorage.getItem(RECENT_FILES_KEY);
    const parsed = stored ? JSON.parse(stored) : [];
    const files = Array.isArray(parsed)
      ? parsed.filter((f): f is string => typeof f === "string")
      : [];
    const updated = [filePath, ...files.filter((p) => p !== filePath)].slice(
      0,
      MAX_RECENT_FILES,
    );
    localStorage.setItem(RECENT_FILES_KEY, JSON.stringify(updated));
  } catch (e) {
    console.warn(
      "[policy-tabs-store] pushRecentFile localStorage operation failed:",
      e,
    );
  }
}

/** Create default edit state for a new tab. */
export function createDefaultEditState(
  fileType?: FileType,
): TabEditState {
  const nextFileType = coerceFileType(fileType);
  const yaml = isPolicyFileType(nextFileType)
    ? policyToYaml(DEFAULT_POLICY)
    : FILE_TYPE_REGISTRY[nextFileType].defaultContent;
  const { policy, validation } = evaluateTabSource(
    nextFileType,
    yaml,
    DEFAULT_POLICY,
    null,
    DEFAULT_POLICY.name,
  );

  return {
    policy,
    yaml,
    validation,
    nativeValidation: emptyNativeValidation(),
    undoStack: { past: [], future: [] },
    cleanSnapshot: null,
  };
}

/** Create default tab metadata + editing state, and register in the edit store. */
function createDefaultTabAndEditState(
  id?: string,
  fileType?: FileType,
  documentId?: string,
): { meta: TabMeta; editState: TabEditState } {
  const nextFileType = coerceFileType(fileType);
  const editState = createDefaultEditState(nextFileType);
  const { name } = evaluateTabSource(
    nextFileType,
    editState.yaml,
    DEFAULT_POLICY,
    null,
    DEFAULT_POLICY.name,
  );

  const meta: TabMeta = {
    id: id ?? createTabId(),
    documentId: documentId ?? createDocumentId(),
    name,
    filePath: null,
    dirty: false,
    fileType: nextFileType,
  };

  return { meta, editState };
}

// ---- Persistence types ----

interface PersistedTab {
  id: string;
  documentId?: string;
  name: string;
  filePath: string | null;
  yaml: string;
  sensitiveFieldsStripped?: boolean;
  fileType?: FileType;
}

interface PersistedTabState {
  tabs: PersistedTab[];
  activeTabId: string;
}

// ---- Persistence helpers ----

function persistTabs(tabs: TabMeta[], activeTabId: string): void {
  try {
    const editStore = usePolicyEditStore.getState();
    const persisted: PersistedTabState = {
      tabs: tabs.map((t) => {
        const editState = editStore.editStates.get(t.id);
        const yaml = editState?.yaml ?? "";
        const sanitized = sanitizeYamlForStorageWithMetadata(yaml);
        const sensitiveFieldsStripped = sanitized.sensitiveFieldsStripped;
        return {
          id: t.id,
          documentId: t.documentId,
          name: t.name,
          filePath: sensitiveFieldsStripped ? null : t.filePath,
          yaml: sanitized.yaml,
          sensitiveFieldsStripped: sensitiveFieldsStripped || undefined,
          fileType: t.fileType,
        };
      }),
      activeTabId,
    };
    localStorage.setItem(TABS_STORAGE_KEY, JSON.stringify(persisted));
  } catch (e) {
    console.error(
      "[policy-tabs-store] persistTabs failed — changes may be lost on reload:",
      e,
    );
  }
}

function loadPersistedTabs(): {
  tabs: TabMeta[];
  activeTabId: string;
  editStates: Map<string, TabEditState>;
} | null {
  try {
    const raw = localStorage.getItem(TABS_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.tabs)) {
      console.warn(
        "[policy-tabs-store] Invalid persisted tab data, using defaults",
      );
      return null;
    }
    const persisted = parsed as PersistedTabState;
    if (persisted.tabs.length === 0) return null;

    const validPersistedTabs = persisted.tabs.filter(
      (pt) => typeof pt.id === "string" && typeof pt.yaml === "string",
    );
    if (validPersistedTabs.length === 0) return null;

    const tabs: TabMeta[] = [];
    const editStates = new Map<string, TabEditState>();

    for (const pt of validPersistedTabs) {
      const fileType = coerceFileType(pt.fileType);
      const documentId = pt.documentId ?? resolveDocumentId(pt.filePath);
      const sensitiveFieldsStripped = pt.sensitiveFieldsStripped === true;

      const { policy, validation, name } = evaluateTabSource(
        fileType,
        pt.yaml,
        DEFAULT_POLICY,
        pt.filePath,
        pt.name || FILE_TYPE_REGISTRY[fileType].label,
      );

      const meta: TabMeta = {
        id: pt.id,
        documentId,
        name,
        filePath: sensitiveFieldsStripped ? null : pt.filePath,
        dirty: sensitiveFieldsStripped,
        fileType,
      };

      const editState: TabEditState = {
        policy,
        yaml: pt.yaml,
        validation,
        nativeValidation: emptyNativeValidation(),
        undoStack: { past: [], future: [] },
        cleanSnapshot: sensitiveFieldsStripped
          ? null
          : { activePolicy: policy, yaml: pt.yaml, validation },
      };

      tabs.push(meta);
      editStates.set(pt.id, editState);
    }

    const activeTabId = tabs.some((t) => t.id === persisted.activeTabId)
      ? persisted.activeTabId
      : tabs[0].id;

    return { tabs, activeTabId, editStates };
  } catch (e) {
    console.warn("[policy-tabs-store] loadPersistedTabs failed:", e);
    return null;
  }
}

// ---- Store interface ----

export interface PolicyTabsState {
  tabs: TabMeta[];
  activeTabId: string;
  splitMode: SplitMode;
  splitTabId: string | null;
  savedPolicies: SavedPolicy[];
  /** Whether persistence has been initialized. */
  _hydrated: boolean;
  /** Timer handle for debounced persistence. */
  _persistTimer: ReturnType<typeof setTimeout> | null;
}

export interface PolicyTabsActions {
  /** Create a new tab. Returns the new tab ID. */
  newTab: (options?: {
    policy?: WorkbenchPolicy;
    filePath?: string | null;
    fileType?: FileType;
    yaml?: string;
    documentId?: string;
  }) => string | null;

  /** Close a tab by ID. */
  closeTab: (tabId: string) => void;

  /** Switch to a tab by ID. */
  switchTab: (tabId: string) => void;

  /** Duplicate a tab. */
  duplicateTab: (tabId: string) => void;

  /** Rename a tab. */
  renameTab: (tabId: string, name: string) => void;

  /** Reorder tabs by index. */
  reorderTabs: (fromIndex: number, toIndex: number) => void;

  /** Set split mode. */
  setSplitMode: (mode: SplitMode) => void;

  /** Set the split pane tab. */
  setSplitTab: (tabId: string | null) => void;

  /** Set file path for the active tab. */
  setFilePath: (tabId: string, path: string | null) => void;

  /** Mark a tab as dirty or clean. */
  setDirty: (tabId: string, dirty: boolean) => void;

  /** Open a file path (switches if already open, creates tab otherwise). */
  openTabOrSwitch: (
    filePath: string,
    fileType: FileType,
    yaml: string,
    name?: string,
  ) => void;

  /** Set test suite YAML for a tab. */
  setTabTestSuite: (tabId: string, yaml: string) => void;

  /** Restore autosaved entries. */
  restoreAutosaveEntries: (
    entries: Array<{
      tabId?: string;
      yaml: string;
      filePath: string | null;
      timestamp: number;
      policyName: string;
      fileType?: FileType;
    }>,
  ) => void;

  /** Bulk update guards across multiple tabs. */
  bulkUpdateGuards: (
    updates: Array<{
      tabId: string;
      guardId: string;
      enabled: boolean;
      config?: Record<string, unknown>;
    }>,
  ) => void;

  // ---- Saved policies ----
  savePolicyToLibrary: (savedPolicy: SavedPolicy) => void;
  deleteSavedPolicy: (id: string) => void;
  loadSavedPolicies: (policies: SavedPolicy[]) => void;

  /** Hydrate saved policies from localStorage (called once on init). */
  hydrateSavedPolicies: () => void;

  /** Schedule debounced tab persistence. */
  schedulePersist: () => void;

  /** Get active tab metadata. */
  getActiveTab: () => TabMeta | undefined;

  /**
   * Reset store to fresh initial state from localStorage.
   * Used by MultiPolicyProvider for test isolation.
   */
  _reset: () => void;
}

export type PolicyTabsStore = PolicyTabsState & PolicyTabsActions;

// ---- Initial state ----

function getInitialState(): Pick<
  PolicyTabsState,
  "tabs" | "activeTabId" | "splitMode" | "splitTabId" | "savedPolicies"
> {
  const restored = loadPersistedTabs();
  if (restored) {
    // Also initialize the edit store with restored edit states
    const editStore = usePolicyEditStore.getState();
    for (const [tabId, editState] of restored.editStates) {
      editStore.initTab(tabId, editState);
    }
    return {
      tabs: restored.tabs,
      activeTabId: restored.activeTabId,
      splitMode: "none",
      splitTabId: null,
      savedPolicies: [],
    };
  }

  // Create a default tab
  const { meta, editState } = createDefaultTabAndEditState();
  usePolicyEditStore.getState().initTab(meta.id, editState);

  return {
    tabs: [meta],
    activeTabId: meta.id,
    splitMode: "none",
    splitTabId: null,
    savedPolicies: [],
  };
}

// ---- Store creation ----

export const usePolicyTabsStore = create<PolicyTabsStore>((set, get) => {
  const initial = getInitialState();

  return {
    // ---- State ----
    ...initial,
    _hydrated: false,
    _persistTimer: null,

    // ---- Actions ----

    newTab: (options) => {
      const state = get();
      if (state.tabs.length >= MAX_TABS) return null;

      const editStore = usePolicyEditStore.getState();

      let meta: TabMeta;
      let editState: TabEditState;

      if (options?.policy) {
        const policy = options.policy;
        const filePath = options.filePath ?? null;
        const fileType = options.fileType ?? "clawdstrike_policy";
        const yaml = policyToYaml(policy);
        const validation = validatePolicy(policy);

        meta = {
          id: createTabId(),
          documentId: resolveDocumentId(filePath),
          name: policy.name || "Untitled",
          filePath,
          dirty: false,
          fileType,
        };

        editState = {
          policy,
          yaml,
          validation,
          nativeValidation: emptyNativeValidation(),
          undoStack: { past: [], future: [] },
          cleanSnapshot: { activePolicy: policy, yaml, validation },
        };
      } else if (options?.yaml) {
        const fileType = coerceFileType(options.fileType);
        const { meta: defaultMeta, editState: defaultEdit } =
          createDefaultTabAndEditState(undefined, fileType, options.documentId);

        const evaluated = evaluateTabSource(
          fileType,
          options.yaml,
          defaultEdit.policy,
          null,
          FILE_TYPE_REGISTRY[fileType].label,
        );

        meta = {
          ...defaultMeta,
          name: evaluated.name,
          fileType,
        };

        editState = {
          policy: evaluated.policy,
          yaml: options.yaml,
          validation: evaluated.validation,
          nativeValidation: emptyNativeValidation(),
          undoStack: { past: [], future: [] },
          cleanSnapshot: {
            activePolicy: evaluated.policy,
            yaml: options.yaml,
            validation: evaluated.validation,
          },
        };
      } else {
        const result = createDefaultTabAndEditState(
          undefined,
          options?.fileType,
          options?.documentId,
        );
        meta = result.meta;
        editState = result.editState;
      }

      editStore.initTab(meta.id, editState);
      set({
        tabs: [...state.tabs, meta],
        activeTabId: meta.id,
      });
      get().schedulePersist();
      return meta.id;
    },

    closeTab: (tabId) => {
      const state = get();
      const idx = state.tabs.findIndex((t) => t.id === tabId);
      if (idx === -1) return;

      const editStore = usePolicyEditStore.getState();
      const newTabs = state.tabs.filter((t) => t.id !== tabId);

      if (newTabs.length === 0) {
        const { meta, editState } = createDefaultTabAndEditState();
        editStore.removeTab(tabId);
        editStore.initTab(meta.id, editState);
        set({
          tabs: [meta],
          activeTabId: meta.id,
          splitTabId: null,
          splitMode: "none",
        });
        get().schedulePersist();
        return;
      }

      let newActiveId = state.activeTabId;
      if (state.activeTabId === tabId) {
        const newIdx = Math.min(idx, newTabs.length - 1);
        newActiveId = newTabs[newIdx].id;
      }

      let newSplitTabId = state.splitTabId;
      if (state.splitTabId === tabId) {
        newSplitTabId = null;
      }

      editStore.removeTab(tabId);
      set({
        tabs: newTabs,
        activeTabId: newActiveId,
        splitTabId: newSplitTabId,
        splitMode:
          newSplitTabId === null && state.splitMode !== "none"
            ? "none"
            : state.splitMode,
      });
      get().schedulePersist();
    },

    switchTab: (tabId) => {
      const state = get();
      if (!state.tabs.some((t) => t.id === tabId)) return;
      set({ activeTabId: tabId });
    },

    duplicateTab: (tabId) => {
      const state = get();
      if (state.tabs.length >= MAX_TABS) return;
      const source = state.tabs.find((t) => t.id === tabId);
      if (!source) return;

      const editStore = usePolicyEditStore.getState();
      const sourceEdit = editStore.editStates.get(tabId);
      if (!sourceEdit) return;

      const newId = createTabId();
      const dupedMeta: TabMeta = {
        ...source,
        id: newId,
        documentId: createDocumentId(),
        name: `${source.name} (copy)`,
        filePath: null,
        dirty: true,
      };

      const dupedEdit: TabEditState = {
        ...sourceEdit,
        undoStack: { past: [], future: [] },
        cleanSnapshot: null,
      };

      editStore.initTab(newId, dupedEdit);

      const idx = state.tabs.findIndex((t) => t.id === tabId);
      const newTabs = [...state.tabs];
      newTabs.splice(idx + 1, 0, dupedMeta);

      set({
        tabs: newTabs,
        activeTabId: newId,
      });
      get().schedulePersist();
    },

    renameTab: (tabId, name) => {
      set((state) => ({
        tabs: state.tabs.map((t) =>
          t.id === tabId ? { ...t, name } : t,
        ),
      }));
      get().schedulePersist();
    },

    reorderTabs: (fromIndex, toIndex) => {
      const state = get();
      if (
        fromIndex < 0 ||
        toIndex < 0 ||
        fromIndex >= state.tabs.length ||
        toIndex >= state.tabs.length
      ) {
        return;
      }
      const newTabs = [...state.tabs];
      const [moved] = newTabs.splice(fromIndex, 1);
      newTabs.splice(toIndex, 0, moved);
      set({ tabs: newTabs });
      get().schedulePersist();
    },

    setSplitMode: (mode) => {
      if (mode === "none") {
        set({ splitMode: "none", splitTabId: null });
      } else {
        set({ splitMode: mode });
      }
    },

    setSplitTab: (tabId) => {
      set({ splitTabId: tabId });
    },

    setFilePath: (tabId, path) => {
      set((state) => ({
        tabs: state.tabs.map((t) =>
          t.id === tabId ? { ...t, filePath: path } : t,
        ),
      }));
      get().schedulePersist();
    },

    setDirty: (tabId, dirty) => {
      set((state) => ({
        tabs: state.tabs.map((t) =>
          t.id === tabId ? { ...t, dirty } : t,
        ),
      }));
      get().schedulePersist();
    },

    openTabOrSwitch: (filePath, fileType, yaml, name) => {
      const state = get();
      const editStore = usePolicyEditStore.getState();
      const existing = state.tabs.find((t) => t.filePath === filePath);

      if (existing) {
        const existingEdit = editStore.editStates.get(existing.id);
        if (
          existingEdit &&
          existingEdit.yaml === yaml &&
          existing.fileType === fileType
        ) {
          set({ activeTabId: existing.id });
          return;
        }
        // Content changed on disk — replace but preserve documentId
        const evaluated = evaluateTabSource(
          fileType,
          yaml,
          existingEdit?.policy ?? DEFAULT_POLICY,
          filePath,
          name ?? existing.name,
        );
        const newEditState: TabEditState = {
          policy: evaluated.policy,
          yaml,
          validation: evaluated.validation,
          nativeValidation: emptyNativeValidation(),
          undoStack: { past: [], future: [] },
          cleanSnapshot: {
            activePolicy: evaluated.policy,
            yaml,
            validation: evaluated.validation,
          },
        };
        editStore.replaceEditState(existing.id, newEditState);
        set((s) => ({
          tabs: s.tabs.map((tab) =>
            tab.id === existing.id
              ? {
                  ...tab,
                  name: evaluated.name || "Untitled",
                  filePath,
                  fileType,
                  dirty: false,
                }
              : tab,
          ),
          activeTabId: existing.id,
        }));
        get().schedulePersist();
        return;
      }

      if (state.tabs.length >= MAX_TABS) return;

      const resolvedDocId = resolveDocumentId(filePath);
      const { editState: defaultEdit } = createDefaultTabAndEditState(
        undefined,
        fileType,
        resolvedDocId,
      );
      const evaluated = evaluateTabSource(
        fileType,
        yaml,
        defaultEdit.policy,
        filePath,
        name,
      );
      const newId = createTabId();
      const newMeta: TabMeta = {
        id: newId,
        documentId: resolvedDocId,
        name: evaluated.name || "Untitled",
        filePath,
        dirty: false,
        fileType,
      };
      const newEditState: TabEditState = {
        policy: evaluated.policy,
        yaml,
        validation: evaluated.validation,
        nativeValidation: emptyNativeValidation(),
        undoStack: { past: [], future: [] },
        cleanSnapshot: {
          activePolicy: evaluated.policy,
          yaml,
          validation: evaluated.validation,
        },
      };
      editStore.initTab(newId, newEditState);
      set({
        tabs: [...state.tabs, newMeta],
        activeTabId: newId,
      });
      get().schedulePersist();
    },

    setTabTestSuite: (tabId, yaml) => {
      const editStore = usePolicyEditStore.getState();
      editStore.setTestSuite(tabId, yaml);
    },

    restoreAutosaveEntries: (entries) => {
      if (entries.length === 0) return;

      const state = get();
      const editStore = usePolicyEditStore.getState();
      let nextTabs = [...state.tabs];
      let nextActiveTabId = state.activeTabId;

      for (const entry of entries) {
        const existingIndex = nextTabs.findIndex((tab) => {
          if (entry.tabId && tab.id === entry.tabId) return true;
          return entry.filePath !== null && tab.filePath === entry.filePath;
        });

        if (existingIndex >= 0) {
          const existing = nextTabs[existingIndex];
          const fileType = coerceFileType(entry.fileType ?? existing.fileType);
          const evaluated = evaluateTabSource(
            fileType,
            entry.yaml,
            editStore.editStates.get(existing.id)?.policy ?? DEFAULT_POLICY,
            entry.filePath,
            entry.policyName || existing.name,
          );

          nextTabs[existingIndex] = {
            ...existing,
            name: evaluated.name,
            filePath: entry.filePath,
            dirty: true,
            fileType,
          };

          editStore.replaceEditState(existing.id, {
            policy: evaluated.policy,
            yaml: entry.yaml,
            validation: evaluated.validation,
            nativeValidation: emptyNativeValidation(),
            undoStack: { past: [], future: [] },
            cleanSnapshot: null,
          });

          nextActiveTabId = nextTabs[existingIndex].id;
          continue;
        }

        if (nextTabs.length >= MAX_TABS) break;

        const fileType = coerceFileType(entry.fileType);
        const restoredDocId = resolveDocumentId(entry.filePath);
        const tabId = entry.tabId ?? createTabId();
        const evaluated = evaluateTabSource(
          fileType,
          entry.yaml,
          DEFAULT_POLICY,
          entry.filePath,
          entry.policyName || "Recovered Policy",
        );

        const meta: TabMeta = {
          id: tabId,
          documentId: restoredDocId,
          name: evaluated.name,
          filePath: entry.filePath,
          dirty: true,
          fileType,
        };

        editStore.initTab(tabId, {
          policy: evaluated.policy,
          yaml: entry.yaml,
          validation: evaluated.validation,
          nativeValidation: emptyNativeValidation(),
          undoStack: { past: [], future: [] },
          cleanSnapshot: null,
        });

        nextTabs = [...nextTabs, meta];
        nextActiveTabId = tabId;
      }

      set({
        tabs: nextTabs,
        activeTabId: nextActiveTabId,
      });
      get().schedulePersist();
    },

    bulkUpdateGuards: (updates) => {
      const editStore = usePolicyEditStore.getState();
      const state = get();

      // Group updates by tab
      const updatesByTab = new Map<
        string,
        Array<{
          guardId: string;
          enabled: boolean;
          config?: Record<string, unknown>;
        }>
      >();
      for (const u of updates) {
        const list = updatesByTab.get(u.tabId) ?? [];
        list.push(u);
        updatesByTab.set(u.tabId, list);
      }

      for (const [tabId, tabUpdates] of updatesByTab) {
        const tab = state.tabs.find((t) => t.id === tabId);
        if (!tab) continue;

        for (const u of tabUpdates) {
          editStore.toggleGuard(
            tabId,
            u.guardId as GuardId,
            u.enabled,
            tab.fileType,
          );
          if (u.config && Object.keys(u.config).length > 0) {
            editStore.updateGuard(
              tabId,
              u.guardId as GuardId,
              u.config as Partial<GuardConfigMap[GuardId]>,
              tab.fileType,
            );
          }
        }
      }

      // Mark affected tabs as dirty
      set((s) => ({
        tabs: s.tabs.map((t) =>
          updatesByTab.has(t.id) ? { ...t, dirty: true } : t,
        ),
      }));
      get().schedulePersist();
    },

    savePolicyToLibrary: (savedPolicy) => {
      const sanitized = sanitizeSavedPolicy(savedPolicy);
      set((state) => ({
        savedPolicies: [
          ...state.savedPolicies.filter((p) => p.id !== sanitized.id),
          sanitized,
        ],
      }));
      // Persist to localStorage
      try {
        const policies = get().savedPolicies;
        localStorage.setItem(
          SAVED_POLICIES_KEY,
          JSON.stringify(policies.map(sanitizeSavedPolicy)),
        );
      } catch (e) {
        console.error(
          "[policy-tabs-store] persist saved policies failed:",
          e,
        );
      }
    },

    deleteSavedPolicy: (id) => {
      set((state) => ({
        savedPolicies: state.savedPolicies.filter((p) => p.id !== id),
      }));
      try {
        const policies = get().savedPolicies;
        localStorage.setItem(
          SAVED_POLICIES_KEY,
          JSON.stringify(policies.map(sanitizeSavedPolicy)),
        );
      } catch (e) {
        console.error(
          "[policy-tabs-store] persist saved policies failed:",
          e,
        );
      }
    },

    loadSavedPolicies: (policies) => {
      set({ savedPolicies: policies });
    },

    hydrateSavedPolicies: () => {
      if (get()._hydrated) return;
      try {
        const stored = localStorage.getItem(SAVED_POLICIES_KEY);
        if (stored) {
          const parsed: unknown = JSON.parse(stored);
          if (!Array.isArray(parsed)) {
            console.warn(
              "[policy-tabs-store] Saved policies is not an array, skipping hydration",
            );
            set({ _hydrated: true });
            return;
          }
          const policies: SavedPolicy[] = parsed
            .filter((entry: unknown): entry is SavedPolicy => {
              if (!entry || typeof entry !== "object") return false;
              const e = entry as Record<string, unknown>;
              return (
                typeof e.id === "string" &&
                typeof e.policy === "object" &&
                e.policy !== null &&
                typeof e.yaml === "string"
              );
            })
            .map(sanitizeSavedPolicy);
          set({ savedPolicies: policies, _hydrated: true });
        } else {
          set({ _hydrated: true });
        }
      } catch (e) {
        console.warn(
          "[policy-tabs-store] hydrate saved policies failed:",
          e,
        );
        set({ _hydrated: true });
      }
    },

    schedulePersist: () => {
      const state = get();
      if (state._persistTimer) clearTimeout(state._persistTimer);
      const timer = setTimeout(() => {
        const s = get();
        persistTabs(s.tabs, s.activeTabId);
      }, 500);
      set({ _persistTimer: timer });
    },

    getActiveTab: () => {
      const state = get();
      return state.tabs.find((t) => t.id === state.activeTabId);
    },

    _reset: () => {
      // Clear pending persist timer
      const timer = get()._persistTimer;
      if (timer) clearTimeout(timer);

      // Reset edit store first
      usePolicyEditStore.getState()._reset();

      // Re-read from localStorage (may have been cleared in tests)
      const restored = loadPersistedTabs();
      if (restored) {
        const editStore = usePolicyEditStore.getState();
        for (const [tabId, editState] of restored.editStates) {
          editStore.initTab(tabId, editState);
        }
        set({
          tabs: restored.tabs,
          activeTabId: restored.activeTabId,
          splitMode: "none",
          splitTabId: null,
          savedPolicies: [],
          _hydrated: false,
          _persistTimer: null,
        });
      } else {
        const { meta, editState } = createDefaultTabAndEditState();
        usePolicyEditStore.getState().initTab(meta.id, editState);
        set({
          tabs: [meta],
          activeTabId: meta.id,
          splitMode: "none",
          splitTabId: null,
          savedPolicies: [],
          _hydrated: false,
          _persistTimer: null,
        });
      }
    },
  };
});

// Hydrate saved policies on startup
usePolicyTabsStore.getState().hydrateSavedPolicies();
