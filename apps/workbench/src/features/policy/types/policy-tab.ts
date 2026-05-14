/**
 * PolicyTab — full reconstructed tab shape.
 *
 * Combines TabMeta (from policy-tabs-store) + TabEditState (from policy-edit-store)
 * into a single object for consumers that need the full picture of a tab.
 *
 * Previously defined in multi-policy-store.tsx — now standalone.
 */
import type {
  WorkbenchPolicy,
  ValidationResult,
  SavedPolicy,
  GuardId,
  GuardConfigMap,
  OriginsConfig,
} from "@/lib/workbench/types";
import type {
  WorkbenchState,
  WorkbenchAction,
  PolicySnapshot,
  NativeValidationState,
} from "@/features/policy/stores/policy-store";
import type { FileType } from "@/lib/workbench/file-type-registry";
import type { TabMeta, SplitMode } from "@/features/policy/stores/policy-tabs-store";
import type { TabEditState } from "@/features/policy/stores/policy-edit-store";
import { DEFAULT_POLICY } from "@/features/policy/stores/policy-store";
import { policyToYaml, validatePolicy } from "@/features/policy/yaml-utils";
import { emptyNativeValidation } from "@/features/policy/stores/policy-edit-store";

// Re-export types
export type { SplitMode } from "@/features/policy/stores/policy-tabs-store";

/**
 * Full PolicyTab shape — reconstructed from TabMeta + TabEditState.
 */
export interface PolicyTab {
  id: string;
  /** Stable document identity — survives tab close/reopen, save, rename. */
  documentId: string;
  name: string;
  filePath: string | null;
  dirty: boolean;
  fileType: FileType;
  policy: WorkbenchPolicy;
  yaml: string;
  validation: ValidationResult;
  nativeValidation: NativeValidationState;
  testSuiteYaml?: string;
  _undoPast: PolicySnapshot[];
  _undoFuture: PolicySnapshot[];
  _cleanSnapshot: PolicySnapshot | null;
}

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
  | {
      type: "NEW_TAB";
      policy?: WorkbenchPolicy;
      filePath?: string | null;
      fileType?: FileType;
      yaml?: string;
      documentId?: string;
    }
  | { type: "CLOSE_TAB"; tabId: string }
  | { type: "SWITCH_TAB"; tabId: string }
  | { type: "SET_SPLIT_MODE"; mode: SplitMode }
  | { type: "SET_SPLIT_TAB"; tabId: string | null }
  | { type: "RENAME_TAB"; tabId: string; name: string }
  | { type: "REORDER_TABS"; fromIndex: number; toIndex: number }
  | { type: "DUPLICATE_TAB"; tabId: string }
  | { type: "BULK_UPDATE_GUARDS"; updates: BulkGuardUpdate[] }
  | {
      type: "OPEN_TAB_OR_SWITCH";
      filePath: string;
      fileType: FileType;
      yaml: string;
      name?: string;
    }
  | { type: "SET_TAB_TEST_SUITE"; tabId: string; yaml: string }
  | {
      type: "RESTORE_AUTOSAVE_ENTRIES";
      entries: Array<{
        tabId?: string;
        yaml: string;
        filePath: string | null;
        timestamp: number;
        policyName: string;
        fileType?: FileType;
      }>;
    }
  // Delegated to active tab — same as WorkbenchAction
  | { type: "SET_POLICY"; policy: WorkbenchPolicy }
  | { type: "SET_YAML"; yaml: string }
  | {
      type: "UPDATE_GUARD";
      guardId: GuardId;
      config: Partial<GuardConfigMap[GuardId]>;
    }
  | { type: "TOGGLE_GUARD"; guardId: GuardId; enabled: boolean }
  | { type: "UPDATE_SETTINGS"; settings: Partial<WorkbenchPolicy["settings"]> }
  | {
      type: "UPDATE_META";
      name?: string;
      description?: string;
      version?: string;
      extends?: string;
    }
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

/**
 * Reconstruct a full PolicyTab from TabMeta + TabEditState.
 */
export function reconstructPolicyTab(
  meta: TabMeta,
  editState: TabEditState | undefined,
): PolicyTab {
  const edit = editState ?? {
    policy: DEFAULT_POLICY,
    yaml: policyToYaml(DEFAULT_POLICY),
    validation: validatePolicy(DEFAULT_POLICY),
    nativeValidation: emptyNativeValidation(),
    undoStack: { past: [], future: [] },
    cleanSnapshot: null,
  };

  return {
    id: meta.id,
    documentId: meta.documentId,
    name: meta.name,
    filePath: meta.filePath,
    dirty: meta.dirty,
    fileType: meta.fileType,
    policy: edit.policy,
    yaml: edit.yaml,
    validation: edit.validation,
    nativeValidation: edit.nativeValidation,
    testSuiteYaml: edit.testSuiteYaml,
    _undoPast: edit.undoStack.past,
    _undoFuture: edit.undoStack.future,
    _cleanSnapshot: edit.cleanSnapshot,
  };
}
