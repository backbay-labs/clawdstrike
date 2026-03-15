import { useEffect, useRef, type Dispatch } from "react";
import { isDesktop } from "@/lib/tauri-bridge";
import {
  validateOcsfEventNative,
  validatePolicyNative,
  validateSigmaRuleNative,
  validateYaraRuleNative,
  type TauriDetectionDiagnostic,
  type TauriOcsfValidationResponse,
  type TauriSigmaValidationResponse,
  type TauriValidationResponse,
  type TauriYaraValidationResponse,
} from "@/lib/tauri-commands";
import { isPolicyFileType, type FileType } from "./file-type-registry";
import type { NativeValidationErrors, NativeValidationState } from "./policy-store";
import type { GuardId } from "./types";

const GUARD_IDS: readonly string[] = [
  "forbidden_path",
  "path_allowlist",
  "egress_allowlist",
  "secret_leak",
  "patch_integrity",
  "shell_command",
  "mcp_tool",
  "prompt_injection",
  "jailbreak",
  "computer_use",
  "remote_desktop_side_channel",
  "input_injection_capability",
  "spider_sense",
] satisfies readonly GuardId[];

const EMPTY_NATIVE_VALIDATION: NativeValidationState = {
  guardErrors: {},
  topLevelErrors: [],
  topLevelWarnings: [],
  loading: false,
  valid: null,
};

/** Extract guard ID from a Rust validation error path like "guards.forbidden_path.patterns[0]". */
function extractGuardId(errorPath: string): string | null {
  const match = errorPath.match(/^guards\.([a-z_]+)/);
  if (!match) return null;
  const candidate = match[1];
  return GUARD_IDS.includes(candidate) ? candidate : null;
}

function formatDetectionDiagnostic(diagnostic: TauriDetectionDiagnostic): string {
  const location = diagnostic.line != null
    ? `line ${diagnostic.line}${diagnostic.column != null ? `:${diagnostic.column}` : ""}: `
    : "";

  return `${location}${diagnostic.message}`;
}

function parsePolicyValidationResponse(
  response: TauriValidationResponse,
): Pick<NativeValidationState, "guardErrors" | "topLevelErrors" | "topLevelWarnings" | "valid"> {
  const guardErrors: NativeValidationErrors = {};
  const topLevelErrors: string[] = [];

  if (response.parse_error) {
    topLevelErrors.push(response.parse_error);
  }

  for (const err of response.errors) {
    const guardId = extractGuardId(err.path);
    if (guardId) {
      if (!guardErrors[guardId]) {
        guardErrors[guardId] = [];
      }
      guardErrors[guardId].push(err.message);
    } else {
      topLevelErrors.push(`${err.path}: ${err.message}`);
    }
  }

  return {
    guardErrors,
    topLevelErrors,
    topLevelWarnings: [],
    valid: response.valid,
  };
}

function detectionDiagnosticsToState(
  valid: boolean,
  diagnostics: TauriDetectionDiagnostic[],
): NativeValidationState {
  const topLevelErrors: string[] = [];
  const topLevelWarnings: string[] = [];

  for (const diag of diagnostics) {
    const formatted = formatDetectionDiagnostic(diag);
    if (diag.severity === "error") {
      topLevelErrors.push(formatted);
    } else {
      // "warning" and "info" go to warnings so they don't block validation
      topLevelWarnings.push(formatted);
    }
  }

  return {
    guardErrors: {},
    topLevelErrors,
    topLevelWarnings,
    loading: false,
    valid,
  };
}

async function runNativeValidation(
  fileType: FileType,
  source: string,
): Promise<NativeValidationState> {
  if (!isDesktop()) {
    return EMPTY_NATIVE_VALIDATION;
  }

  if (isPolicyFileType(fileType)) {
    const result = await validatePolicyNative(source);
    if (!result) return EMPTY_NATIVE_VALIDATION;
    const parsed = parsePolicyValidationResponse(result);
    return {
      ...parsed,
      loading: false,
    };
  }

  let result:
    | TauriSigmaValidationResponse
    | TauriYaraValidationResponse
    | TauriOcsfValidationResponse
    | null = null;

  switch (fileType) {
    case "sigma_rule":
      result = await validateSigmaRuleNative(source);
      break;
    case "yara_rule":
      result = await validateYaraRuleNative(source);
      break;
    case "ocsf_event":
      result = await validateOcsfEventNative(source);
      break;
    default:
      return EMPTY_NATIVE_VALIDATION;
  }

  if (!result) return EMPTY_NATIVE_VALIDATION;
  return detectionDiagnosticsToState(result.valid, result.diagnostics);
}

export async function triggerNativeValidation(
  fileType: FileType,
  source: string,
  dispatch: Dispatch<{ type: "SET_NATIVE_VALIDATION"; payload: NativeValidationState }>,
): Promise<void> {
  if (!isDesktop()) {
    dispatch({ type: "SET_NATIVE_VALIDATION", payload: EMPTY_NATIVE_VALIDATION });
    return;
  }

  dispatch({
    type: "SET_NATIVE_VALIDATION",
    payload: {
      ...EMPTY_NATIVE_VALIDATION,
      loading: true,
    },
  });

  try {
    const result = await runNativeValidation(fileType, source);
    dispatch({
      type: "SET_NATIVE_VALIDATION",
      payload: result,
    });
  } catch (err) {
    console.error("[native-validation] IPC call failed:", err);
    dispatch({ type: "SET_NATIVE_VALIDATION", payload: EMPTY_NATIVE_VALIDATION });
  }
}

const DEBOUNCE_MS = 800;

/** Debounced native Rust validation. No-op outside Tauri. */
export function useNativeValidation(
  source: string,
  fileType: FileType,
  dispatch: Dispatch<{ type: "SET_NATIVE_VALIDATION"; payload: NativeValidationState }>,
): void {
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const latestSourceRef = useRef(source);
  const latestFileTypeRef = useRef(fileType);

  latestSourceRef.current = source;
  latestFileTypeRef.current = fileType;

  useEffect(() => {
    if (!isDesktop()) return;

    if (debounceRef.current) {
      clearTimeout(debounceRef.current);
    }

    const capturedSource = source;
    const capturedFileType = fileType;

    debounceRef.current = setTimeout(() => {
      dispatch({
        type: "SET_NATIVE_VALIDATION",
        payload: {
          ...EMPTY_NATIVE_VALIDATION,
          loading: true,
        },
      });

      runNativeValidation(capturedFileType, capturedSource).then((result) => {
        if (
          latestSourceRef.current !== capturedSource ||
          latestFileTypeRef.current !== capturedFileType
        ) {
          return;
        }

        dispatch({
          type: "SET_NATIVE_VALIDATION",
          payload: result,
        });
      }).catch((err) => {
        console.error("[native-validation] IPC call failed:", err);
        dispatch({ type: "SET_NATIVE_VALIDATION", payload: EMPTY_NATIVE_VALIDATION });
      });
    }, DEBOUNCE_MS);

    return () => {
      if (debounceRef.current) {
        clearTimeout(debounceRef.current);
      }
    };
  }, [source, fileType, dispatch]);
}

export function countNativeErrors(state: NativeValidationState): number {
  let count = state.topLevelErrors.length;
  for (const errors of Object.values(state.guardErrors)) {
    count += errors.length;
  }
  return count;
}
