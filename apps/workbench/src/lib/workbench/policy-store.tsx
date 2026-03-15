import React, {
  createContext,
  useContext,
  useReducer,
  useCallback,
  useEffect,
  type ReactNode,
} from "react";
import type {
  WorkbenchPolicy,
  ValidationResult,
  SavedPolicy,
  GuardConfigMap,
  GuardId,
  OriginsConfig,
} from "./types";
import { policyToYaml, yamlToPolicy, validatePolicy } from "./yaml-utils";
import {
  isDesktop,
  openPolicyFile,
  savePolicyFile,
  readPolicyFileByPath,
} from "@/lib/tauri-bridge";

export const DEFAULT_POLICY: WorkbenchPolicy = {
  version: "1.2.0",
  name: "My Policy",
  description: "",
  guards: {
    forbidden_path: {
      enabled: true,
      patterns: [
        "**/.ssh/**",
        "**/.aws/**",
        "**/.env",
        "**/.env.*",
        "**/.git-credentials",
        "**/.gnupg/**",
        "**/.kube/**",
        "/etc/shadow",
        "/etc/passwd",
      ],
      exceptions: [],
    },
    egress_allowlist: {
      enabled: true,
      allow: [
        "*.openai.com",
        "*.anthropic.com",
        "api.github.com",
        "registry.npmjs.org",
        "pypi.org",
        "crates.io",
      ],
      block: [],
      default_action: "block",
    },
    secret_leak: {
      enabled: true,
      patterns: [
        { name: "aws_access_key", pattern: "AKIA[0-9A-Z]{16}", severity: "critical" },
        { name: "github_token", pattern: "gh[ps]_[A-Za-z0-9]{36}", severity: "critical" },
        { name: "private_key", pattern: "-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----", severity: "critical" },
      ],
      skip_paths: ["**/test/**", "**/tests/**"],
    },
  },
  settings: {
    fail_fast: false,
    verbose_logging: false,
    session_timeout_secs: 3600,
  },
};

/** Per-guard native (Rust engine) validation errors, keyed by guard ID. */
export type NativeValidationErrors = Record<string, string[]>;

export interface NativeValidationState {
  guardErrors: NativeValidationErrors;
  topLevelErrors: string[];
  /** Non-error diagnostics (warnings/info) from native detection validation. */
  topLevelWarnings: string[];
  loading: boolean;
  valid: boolean | null;
}

/** The slice of state that undo/redo tracks. */
export interface PolicySnapshot {
  activePolicy: WorkbenchPolicy;
  yaml: string;
  validation: ValidationResult;
}

const MAX_HISTORY = 50;

export interface WorkbenchState {
  activePolicy: WorkbenchPolicy;
  yaml: string;
  validation: ValidationResult;
  savedPolicies: SavedPolicy[];
  comparisonPolicy: WorkbenchPolicy | null;
  comparisonYaml: string;
  /** Path to the currently-open file on disk (desktop only) */
  filePath: string | null;
  /** Whether in-memory state differs from the last save */
  dirty: boolean;
  /** Native Rust engine validation state (desktop only). */
  nativeValidation: NativeValidationState;
  /** Undo stack (past snapshots, most recent last). */
  _undoPast: PolicySnapshot[];
  /** Redo stack (future snapshots, most recent first). */
  _undoFuture: PolicySnapshot[];
  /** Snapshot of the state at last save/open, used to recompute dirty flag on undo/redo. */
  _cleanSnapshot: PolicySnapshot | null;
  ui: {
    sidebarCollapsed: boolean;
    activeEditorTab: "visual" | "yaml";
    editorSyncDirection: "visual" | "yaml" | null;
  };
}

export type WorkbenchAction =
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

function revalidate(policy: WorkbenchPolicy, yaml?: string): Pick<WorkbenchState, "yaml" | "validation"> {
  const y = yaml ?? policyToYaml(policy);
  return {
    yaml: y,
    validation: validatePolicy(policy),
  };
}

/** Extract the snapshot fields tracked by undo/redo. */
function takeSnapshot(state: WorkbenchState): PolicySnapshot {
  return {
    activePolicy: state.activePolicy,
    yaml: state.yaml,
    validation: state.validation,
  };
}

/** Check whether two snapshots represent the same policy content. */
function snapshotsEqual(a: PolicySnapshot, b: PolicySnapshot): boolean {
  return a.yaml === b.yaml;
}

/** Whether the current state matches the clean (last-saved) snapshot. */
function isDirtyVsClean(state: WorkbenchState): boolean {
  if (!state._cleanSnapshot) return true;
  return !snapshotsEqual(takeSnapshot(state), state._cleanSnapshot);
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

function coreReducer(state: WorkbenchState, action: WorkbenchAction): WorkbenchState {
  switch (action.type) {
    case "SET_POLICY": {
      return {
        ...state,
        activePolicy: action.policy,
        dirty: true,
        ...revalidate(action.policy),
        ui: { ...state.ui, editorSyncDirection: "visual" },
      };
    }

    case "SET_YAML": {
      const [policy, errors] = yamlToPolicy(action.yaml);
      if (policy && errors.length === 0) {
        return {
          ...state,
          activePolicy: policy,
          yaml: action.yaml,
          dirty: true,
          validation: validatePolicy(policy),
          ui: { ...state.ui, editorSyncDirection: "yaml" },
        };
      }
      return {
        ...state,
        yaml: action.yaml,
        dirty: true,
        validation: {
          valid: false,
          errors: errors.map((msg) => ({ path: "yaml", message: msg, severity: "error" as const })),
          warnings: [],
        },
        ui: { ...state.ui, editorSyncDirection: "yaml" },
      };
    }

    case "UPDATE_GUARD": {
      const newGuards = {
        ...state.activePolicy.guards,
        [action.guardId]: {
          ...(state.activePolicy.guards[action.guardId] || {}),
          ...action.config,
        },
      };
      const newPolicy = { ...state.activePolicy, guards: newGuards };
      return { ...state, activePolicy: newPolicy, dirty: true, ...revalidate(newPolicy) };
    }

    case "TOGGLE_GUARD": {
      const existing = state.activePolicy.guards[action.guardId] || {};
      const newGuards = {
        ...state.activePolicy.guards,
        [action.guardId]: { ...existing, enabled: action.enabled },
      };
      if (!action.enabled) {
        const config = newGuards[action.guardId];
        if (config && Object.keys(config).length === 1 && "enabled" in config) {
          delete newGuards[action.guardId];
        }
      }
      const newPolicy = { ...state.activePolicy, guards: newGuards };
      return { ...state, activePolicy: newPolicy, dirty: true, ...revalidate(newPolicy) };
    }

    case "UPDATE_SETTINGS": {
      const newPolicy = {
        ...state.activePolicy,
        settings: { ...state.activePolicy.settings, ...action.settings },
      };
      return { ...state, activePolicy: newPolicy, dirty: true, ...revalidate(newPolicy) };
    }

    case "UPDATE_META": {
      const newPolicy = { ...state.activePolicy };
      if (action.name !== undefined) newPolicy.name = action.name;
      if (action.description !== undefined) newPolicy.description = action.description;
      if (action.version !== undefined) newPolicy.version = action.version as WorkbenchPolicy["version"];
      if (action.extends !== undefined) newPolicy.extends = action.extends || undefined;
      return { ...state, activePolicy: newPolicy, dirty: true, ...revalidate(newPolicy) };
    }

    case "UPDATE_ORIGINS": {
      const newPolicy = { ...state.activePolicy, origins: action.origins };
      return { ...state, activePolicy: newPolicy, dirty: true, ...revalidate(newPolicy) };
    }

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

    case "SET_COMPARISON": {
      return {
        ...state,
        comparisonPolicy: action.policy,
        comparisonYaml: action.yaml ?? (action.policy ? policyToYaml(action.policy) : ""),
      };
    }

    case "SET_SIDEBAR_COLLAPSED": {
      return { ...state, ui: { ...state.ui, sidebarCollapsed: action.collapsed } };
    }

    case "SET_EDITOR_TAB": {
      return { ...state, ui: { ...state.ui, activeEditorTab: action.tab } };
    }

    case "SET_FILE_PATH": {
      return { ...state, filePath: action.path };
    }

    case "MARK_CLEAN": {
      return {
        ...state,
        dirty: false,
        _cleanSnapshot: takeSnapshot(state),
      };
    }

    case "SET_NATIVE_VALIDATION": {
      return { ...state, nativeValidation: action.payload };
    }

    // UNDO and REDO are handled in the outer `reducer` wrapper.
    // If they reach here, it means there is nothing to undo/redo.
    case "UNDO":
    case "REDO":
      return state;

    default:
      return state;
  }
}

/**
 * Outer reducer that wraps coreReducer with undo/redo history management.
 *
 * - Policy-modifying actions push the *previous* snapshot onto `_undoPast`
 *   and clear `_undoFuture`.
 * - UNDO pops from `_undoPast`, pushes current onto `_undoFuture`.
 * - REDO pops from `_undoFuture`, pushes current onto `_undoPast`.
 * - Non-policy actions pass through without touching history.
 */
function reducer(state: WorkbenchState, action: WorkbenchAction): WorkbenchState {
  if (action.type === "UNDO") {
    if (state._undoPast.length === 0) return state;
    const past = [...state._undoPast];
    const snapshot = past.pop()!;
    const currentSnapshot = takeSnapshot(state);
    const newState: WorkbenchState = {
      ...state,
      activePolicy: snapshot.activePolicy,
      yaml: snapshot.yaml,
      validation: snapshot.validation,
      _undoPast: past,
      _undoFuture: [currentSnapshot, ...state._undoFuture],
    };
    newState.dirty = isDirtyVsClean(newState);
    return newState;
  }

  if (action.type === "REDO") {
    if (state._undoFuture.length === 0) return state;
    const future = [...state._undoFuture];
    const snapshot = future.shift()!;
    const currentSnapshot = takeSnapshot(state);
    const newState: WorkbenchState = {
      ...state,
      activePolicy: snapshot.activePolicy,
      yaml: snapshot.yaml,
      validation: snapshot.validation,
      _undoPast: [...state._undoPast, currentSnapshot].slice(-MAX_HISTORY),
      _undoFuture: future,
    };
    newState.dirty = isDirtyVsClean(newState);
    return newState;
  }

  // For policy-modifying actions, push the current snapshot before applying.
  if (POLICY_MODIFYING_ACTIONS.has(action.type)) {
    const currentSnapshot = takeSnapshot(state);
    const next = coreReducer(state, action);
    // Only push to history if the snapshot actually changed.
    const nextSnapshot = takeSnapshot(next);
    if (snapshotsEqual(currentSnapshot, nextSnapshot)) return next;
    return {
      ...next,
      _undoPast: [...state._undoPast, currentSnapshot].slice(-MAX_HISTORY),
      _undoFuture: [],
    };
  }

  // Non-policy actions: pass through without touching history.
  return coreReducer(state, action);
}

interface WorkbenchContextValue {
  state: WorkbenchState;
  dispatch: React.Dispatch<WorkbenchAction>;
  saveCurrentPolicy: () => void;
  exportYaml: () => void;
  copyYaml: () => void;
  loadPolicy: (policy: WorkbenchPolicy) => void;
  /** Open a file dialog, load the YAML, and update state. Desktop only. */
  openFile: () => Promise<void>;
  /** Open a specific file by path (no dialog). Desktop only. */
  openFileByPath: (filePath: string) => Promise<void>;
  /** Save to the current filePath (or trigger Save As if none). */
  saveFile: () => Promise<void>;
  /** Always opens a Save As dialog. */
  saveFileAs: () => Promise<void>;
  /** Reset to default policy (confirms if dirty). */
  newPolicy: () => void;
  /** Undo the last policy-modifying action. */
  undo: () => void;
  /** Redo the last undone action. */
  redo: () => void;
  /** Whether there are actions to undo. */
  canUndo: boolean;
  /** Whether there are actions to redo. */
  canRedo: boolean;
}

const WorkbenchContext = createContext<WorkbenchContextValue | null>(null);

export function useWorkbench(): WorkbenchContextValue {
  const ctx = useContext(WorkbenchContext);
  if (!ctx) throw new Error("useWorkbench must be used within WorkbenchProvider");
  return ctx;
}

const STORAGE_KEY = "clawdstrike_workbench_policies";
const ACTIVE_KEY = "clawdstrike_workbench_active";
const RECENT_FILES_KEY = "clawdstrike_recent_files";
const MAX_RECENT_FILES = 10;

/** Push a file path to the recent-files list in localStorage. */
function pushRecentFile(filePath: string) {
  try {
    const stored = localStorage.getItem(RECENT_FILES_KEY);
    const existing: string[] = stored ? JSON.parse(stored) : [];
    // Remove duplicates and prepend
    const updated = [filePath, ...existing.filter((p) => p !== filePath)].slice(
      0,
      MAX_RECENT_FILES,
    );
    localStorage.setItem(RECENT_FILES_KEY, JSON.stringify(updated));
  } catch {
    // ignore
  }
}

/** Read recent file paths from localStorage. */
export function getRecentFiles(): string[] {
  try {
    const stored = localStorage.getItem(RECENT_FILES_KEY);
    return stored ? JSON.parse(stored) : [];
  } catch {
    return [];
  }
}

function getInitialState(): WorkbenchState {
  const yaml = policyToYaml(DEFAULT_POLICY);
  return {
    activePolicy: DEFAULT_POLICY,
    yaml,
    validation: validatePolicy(DEFAULT_POLICY),
    savedPolicies: [],
    comparisonPolicy: null,
    comparisonYaml: "",
    filePath: null,
    dirty: false,
    nativeValidation: {
      guardErrors: {},
      topLevelErrors: [],
      topLevelWarnings: [],
      loading: false,
      valid: null,
    },
    _undoPast: [],
    _undoFuture: [],
    _cleanSnapshot: null,
    ui: {
      sidebarCollapsed: false,
      activeEditorTab: "visual",
      editorSyncDirection: null,
    },
  };
}

export function WorkbenchProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(reducer, undefined, getInitialState);

  // Hydrate from localStorage with schema validation (Finding M13)
  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const parsed: unknown = JSON.parse(stored);
        if (!Array.isArray(parsed)) {
          console.warn("[policy-store] Saved policies is not an array, skipping hydration");
        } else {
          // Validate each entry has the expected shape before loading
          const policies: SavedPolicy[] = parsed.filter((entry: unknown): entry is SavedPolicy => {
            if (!entry || typeof entry !== "object") return false;
            const e = entry as Record<string, unknown>;
            return (
              typeof e.id === "string" &&
              typeof e.yaml === "string" &&
              typeof e.policy === "object" && e.policy !== null
            );
          });
          dispatch({ type: "LOAD_SAVED_POLICIES", policies });
        }
      }
      const activeYaml = localStorage.getItem(ACTIVE_KEY);
      if (activeYaml) {
        dispatch({ type: "SET_YAML", yaml: activeYaml });
      }
    } catch {
      // ignore
    }
  }, []);

  // Persist saved policies
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(state.savedPolicies));
    } catch {
      // ignore
    }
  }, [state.savedPolicies]);

  // Persist active policy yaml
  useEffect(() => {
    try {
      localStorage.setItem(ACTIVE_KEY, state.yaml);
    } catch {
      // ignore
    }
  }, [state.yaml]);

  const saveCurrentPolicy = useCallback(() => {
    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    const savedPolicy: SavedPolicy = {
      id,
      policy: state.activePolicy,
      yaml: state.yaml,
      createdAt: now,
      updatedAt: now,
    };
    dispatch({ type: "SAVE_POLICY", savedPolicy });
  }, [state.activePolicy, state.yaml]);

  const exportYaml = useCallback(() => {
    const blob = new Blob([state.yaml], { type: "text/yaml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${state.activePolicy.name || "policy"}.yaml`;
    a.click();
    URL.revokeObjectURL(url);
  }, [state.yaml, state.activePolicy.name]);

  const copyYaml = useCallback(() => {
    navigator.clipboard.writeText(state.yaml).catch(() => {
      // Clipboard write failed (e.g. permissions, non-secure context)
    });
  }, [state.yaml]);

  const loadPolicy = (policy: WorkbenchPolicy) => {
    dispatch({ type: "SET_POLICY", policy });
  };

  const openFile = useCallback(async () => {
    try {
      const result = await openPolicyFile();
      if (!result) return; // user cancelled

      dispatch({ type: "SET_YAML", yaml: result.content });
      dispatch({ type: "SET_FILE_PATH", path: result.path });
      dispatch({ type: "MARK_CLEAN" });
      pushRecentFile(result.path);
    } catch (err) {
      console.error("[workbench] Failed to open file:", err);
    }
  }, []);

  const openFileByPath = useCallback(async (filePath: string) => {
    try {
      const result = await readPolicyFileByPath(filePath);
      if (!result) return;

      dispatch({ type: "SET_YAML", yaml: result.content });
      dispatch({ type: "SET_FILE_PATH", path: result.path });
      dispatch({ type: "MARK_CLEAN" });
      pushRecentFile(result.path);
    } catch (err) {
      console.error("[workbench] Failed to open file by path:", err);
    }
  }, []);

  const saveFileAs = useCallback(async () => {
    try {
      if (!isDesktop()) {
                exportYaml();
        return;
      }

      const savedPath = await savePolicyFile(state.yaml);
      if (!savedPath) return; // user cancelled

      dispatch({ type: "SET_FILE_PATH", path: savedPath });
      dispatch({ type: "MARK_CLEAN" });
      pushRecentFile(savedPath);
    } catch (err) {
      console.error("[workbench] Failed to save file:", err);
    }
  }, [state.yaml, exportYaml]);

  const saveFile = useCallback(async () => {
    try {
      if (!isDesktop()) {
                exportYaml();
        return;
      }

      if (state.filePath) {
        // Save directly to existing path
        await savePolicyFile(state.yaml, state.filePath);
        dispatch({ type: "MARK_CLEAN" });
      } else {
        // No path yet -- trigger Save As
        await saveFileAs();
      }
    } catch (err) {
      console.error("[workbench] Failed to save file:", err);
    }
  }, [state.yaml, state.filePath, saveFileAs, exportYaml]);

  const newPolicy = useCallback(() => {
    if (state.dirty) {
      const confirmed = window.confirm(
        "Unsaved changes will be lost. Continue?",
      );
      if (!confirmed) return;
    }

    dispatch({ type: "SET_POLICY", policy: DEFAULT_POLICY });
    dispatch({ type: "SET_FILE_PATH", path: null });
    dispatch({ type: "MARK_CLEAN" });
  }, [state.dirty]);

  const undo = () => dispatch({ type: "UNDO" });
  const redo = () => dispatch({ type: "REDO" });

  const canUndo = state._undoPast.length > 0;
  const canRedo = state._undoFuture.length > 0;

  return (
    <WorkbenchContext.Provider
      value={{
        state,
        dispatch,
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
      }}
    >
      {children}
    </WorkbenchContext.Provider>
  );
}
