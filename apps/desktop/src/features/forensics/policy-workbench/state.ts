export interface ValidationIssue {
  path: string;
  code: string;
  message: string;
}

export interface ValidationModel {
  status: "idle" | "running" | "valid" | "invalid" | "error";
  errors: ValidationIssue[];
  warnings: ValidationIssue[];
  message?: string;
  lastCheckedAt?: number;
}

export interface PolicyWorkbenchState {
  loadedYaml: string;
  loadedHash?: string;
  loadedVersion?: string;
  draftYaml: string;
  isSaving: boolean;
  loadError?: string;
  saveError?: string;
  validation: ValidationModel;
}

export const initialPolicyWorkbenchState: PolicyWorkbenchState = {
  loadedYaml: "",
  draftYaml: "",
  isSaving: false,
  validation: {
    status: "idle",
    errors: [],
    warnings: [],
  },
};

export type PolicyWorkbenchAction =
  | { type: "load_start" }
  | { type: "load_success"; yaml: string; hash?: string; version?: string }
  | { type: "load_error"; message: string }
  | { type: "edit"; yaml: string }
  | { type: "revert" }
  | { type: "validate_start" }
  | {
      type: "validate_success";
      valid: boolean;
      errors: ValidationIssue[];
      warnings: ValidationIssue[];
    }
  | { type: "validate_error"; message: string }
  | { type: "save_start" }
  | { type: "save_success"; yaml: string; hash?: string; version?: string }
  | { type: "save_success_preserve_draft"; loadedYaml: string; hash?: string; version?: string }
  | { type: "save_error"; message: string };

export function policyWorkbenchReducer(
  state: PolicyWorkbenchState,
  action: PolicyWorkbenchAction,
): PolicyWorkbenchState {
  switch (action.type) {
    case "load_start":
      return state;
    case "load_success":
      return {
        ...state,
        loadedYaml: action.yaml,
        draftYaml: action.yaml,
        loadedHash: action.hash,
        loadedVersion: action.version,
        loadError: undefined,
        saveError: undefined,
        validation: {
          ...state.validation,
          status: "idle",
          errors: [],
          warnings: [],
          message: undefined,
        },
      };
    case "load_error":
      return { ...state, loadError: action.message };
    case "edit":
      return { ...state, draftYaml: action.yaml };
    case "revert":
      return {
        ...state,
        draftYaml: state.loadedYaml,
        saveError: undefined,
      };
    case "validate_start":
      return {
        ...state,
        validation: {
          ...state.validation,
          status: "running",
          message: undefined,
        },
      };
    case "validate_success":
      return {
        ...state,
        validation: {
          status: action.valid ? "valid" : "invalid",
          errors: action.errors,
          warnings: action.warnings,
          lastCheckedAt: Date.now(),
        },
      };
    case "validate_error":
      return {
        ...state,
        validation: {
          status: "error",
          errors: [],
          warnings: [],
          message: action.message,
          lastCheckedAt: Date.now(),
        },
      };
    case "save_start":
      return { ...state, isSaving: true, saveError: undefined };
    case "save_success":
      return {
        ...state,
        isSaving: false,
        loadedYaml: action.yaml,
        draftYaml: action.yaml,
        loadedHash: action.hash ?? state.loadedHash,
        loadedVersion: action.version ?? state.loadedVersion,
        loadError: undefined,
        saveError: undefined,
      };
    case "save_success_preserve_draft":
      return {
        ...state,
        isSaving: false,
        loadedYaml: action.loadedYaml,
        loadedHash: action.hash ?? state.loadedHash,
        loadedVersion: action.version ?? state.loadedVersion,
        loadError: undefined,
        saveError: undefined,
      };
    case "save_error":
      return {
        ...state,
        isSaving: false,
        saveError: action.message,
      };
    default:
      return state;
  }
}

export function isPolicyDraftDirty(state: PolicyWorkbenchState): boolean {
  return state.draftYaml !== state.loadedYaml;
}
