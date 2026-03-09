import { useEffect, useRef } from "react";
import { isDesktop } from "@/lib/tauri-bridge";
import { validatePolicyNative } from "@/lib/tauri-commands";
import type { TauriValidationResponse } from "@/lib/tauri-commands";
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

/** Extract guard ID from a Rust validation error path like "guards.forbidden_path.patterns[0]". */
function extractGuardId(errorPath: string): string | null {
  // Pattern: "guards.<guard_id>" or "guards.<guard_id>.<rest>"
  const match = errorPath.match(/^guards\.([a-z_]+)/);
  if (!match) return null;
  const candidate = match[1];
  return GUARD_IDS.includes(candidate) ? candidate : null;
}

function parseValidationResponse(
  response: TauriValidationResponse,
): Pick<NativeValidationState, "guardErrors" | "topLevelErrors" | "valid"> {
  const guardErrors: NativeValidationErrors = {};
  const topLevelErrors: string[] = [];

  // Parse error from the YAML parser itself
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
    valid: response.valid,
  };
}

const DEBOUNCE_MS = 800;

/** Debounced native Rust validation. No-op outside Tauri. */
export function useNativeValidation(
  yaml: string,
  dispatch: React.Dispatch<{ type: "SET_NATIVE_VALIDATION"; payload: NativeValidationState }>,
): void {
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const latestYamlRef = useRef(yaml);

  // Always keep the latest yaml in the ref so the async callback can check
  // whether a newer request has superseded it.
  latestYamlRef.current = yaml;

  useEffect(() => {
    if (!isDesktop()) return;

    if (debounceRef.current) {
      clearTimeout(debounceRef.current);
    }

    const capturedYaml = yaml;

    debounceRef.current = setTimeout(() => {
      // Mark loading only when we actually start the async validation,
      // not on every keystroke, to avoid UI flicker.
      dispatch({
        type: "SET_NATIVE_VALIDATION",
        payload: {
          guardErrors: {},
          topLevelErrors: [],
          loading: true,
          valid: null,
        },
      });

      validatePolicyNative(capturedYaml).then((result) => {
        // If yaml changed while we were waiting, discard this stale result
        if (latestYamlRef.current !== capturedYaml) return;

        if (!result) {
          // Tauri call returned null (not in desktop mode or error)
          dispatch({
            type: "SET_NATIVE_VALIDATION",
            payload: {
              guardErrors: {},
              topLevelErrors: [],
              loading: false,
              valid: null,
            },
          });
          return;
        }

        const { guardErrors, topLevelErrors, valid } = parseValidationResponse(result);
        dispatch({
          type: "SET_NATIVE_VALIDATION",
          payload: {
            guardErrors,
            topLevelErrors,
            loading: false,
            valid,
          },
        });
      }).catch((err) => {
        console.error("[native-validation] IPC call failed:", err);
        dispatch({
          type: "SET_NATIVE_VALIDATION",
          payload: { guardErrors: {}, topLevelErrors: [], loading: false, valid: null },
        });
      });
    }, DEBOUNCE_MS);

    return () => {
      if (debounceRef.current) {
        clearTimeout(debounceRef.current);
      }
    };
  }, [yaml, dispatch]);
}

export function countNativeErrors(state: NativeValidationState): number {
  let count = state.topLevelErrors.length;
  for (const errors of Object.values(state.guardErrors)) {
    count += errors.length;
  }
  return count;
}
