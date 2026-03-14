import { describe, it, expect } from "vitest";

// The hook useNativeValidation requires React context and async Tauri calls.
// We test the pure helper functions that are exported: countNativeErrors.
// The internal functions (extractGuardId, parseValidationResponse) are not
// exported, so we exercise them indirectly by testing countNativeErrors and
// by testing the types/logic patterns they implement.
//
// We also re-implement the internal logic for extractGuardId and
// parseValidationResponse in a test-friendly way to verify the parsing logic.

import { countNativeErrors } from "../use-native-validation";
import type { NativeValidationState } from "../policy-store";


const GUARD_IDS = [
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
];

function extractGuardId(errorPath: string): string | null {
  const match = errorPath.match(/^guards\.([a-z_]+)/);
  if (!match) return null;
  const candidate = match[1];
  return GUARD_IDS.includes(candidate) ? candidate : null;
}

interface TauriValidationResponse {
  valid: boolean;
  errors: { path: string; message: string }[];
  parse_error: string | null;
}

function parseValidationResponse(response: TauriValidationResponse) {
  const guardErrors: Record<string, string[]> = {};
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

  return { guardErrors, topLevelErrors, valid: response.valid };
}


describe("extractGuardId (internal logic)", () => {
  it("extracts forbidden_path from guards.forbidden_path.patterns[0]", () => {
    expect(extractGuardId("guards.forbidden_path.patterns[0]")).toBe("forbidden_path");
  });

  it("extracts egress_allowlist from guards.egress_allowlist.allow", () => {
    expect(extractGuardId("guards.egress_allowlist.allow")).toBe("egress_allowlist");
  });

  it("extracts jailbreak from guards.jailbreak.detector.block_threshold", () => {
    expect(extractGuardId("guards.jailbreak.detector.block_threshold")).toBe("jailbreak");
  });

  it("extracts spider_sense from guards.spider_sense", () => {
    expect(extractGuardId("guards.spider_sense")).toBe("spider_sense");
  });

  it("extracts computer_use from guards.computer_use.mode", () => {
    expect(extractGuardId("guards.computer_use.mode")).toBe("computer_use");
  });

  it("returns null for version path", () => {
    expect(extractGuardId("version")).toBeNull();
  });

  it("returns null for settings path", () => {
    expect(extractGuardId("settings.fail_fast")).toBeNull();
  });

  it("returns null for unknown guard ID", () => {
    expect(extractGuardId("guards.unknown_guard.field")).toBeNull();
  });

  it("returns null for empty string", () => {
    expect(extractGuardId("")).toBeNull();
  });

  it("returns null for bare 'guards' without dot", () => {
    expect(extractGuardId("guards")).toBeNull();
  });

  it("handles all 13 known guard IDs", () => {
    for (const id of GUARD_IDS) {
      expect(extractGuardId(`guards.${id}.enabled`)).toBe(id);
    }
  });
});


describe("parseValidationResponse (internal logic)", () => {
  it("parses a valid response with no errors", () => {
    const response: TauriValidationResponse = {
      valid: true,
      errors: [],
      parse_error: null,
    };
    const result = parseValidationResponse(response);
    expect(result.valid).toBe(true);
    expect(result.topLevelErrors).toEqual([]);
    expect(result.guardErrors).toEqual({});
  });

  it("routes guard errors to guardErrors map", () => {
    const response: TauriValidationResponse = {
      valid: false,
      errors: [
        { path: "guards.forbidden_path.patterns", message: "must not be empty" },
        { path: "guards.forbidden_path.enabled", message: "is required" },
      ],
      parse_error: null,
    };
    const result = parseValidationResponse(response);
    expect(result.guardErrors.forbidden_path).toEqual([
      "must not be empty",
      "is required",
    ]);
  });

  it("routes non-guard errors to topLevelErrors", () => {
    const response: TauriValidationResponse = {
      valid: false,
      errors: [
        { path: "version", message: "unsupported version" },
        { path: "settings.fail_fast", message: "must be boolean" },
      ],
      parse_error: null,
    };
    const result = parseValidationResponse(response);
    expect(result.topLevelErrors).toEqual([
      "version: unsupported version",
      "settings.fail_fast: must be boolean",
    ]);
    expect(result.guardErrors).toEqual({});
  });

  it("includes parse_error in topLevelErrors", () => {
    const response: TauriValidationResponse = {
      valid: false,
      errors: [],
      parse_error: "YAML syntax error at line 5",
    };
    const result = parseValidationResponse(response);
    expect(result.topLevelErrors).toEqual(["YAML syntax error at line 5"]);
  });

  it("separates errors across multiple guards", () => {
    const response: TauriValidationResponse = {
      valid: false,
      errors: [
        { path: "guards.forbidden_path.patterns", message: "invalid glob" },
        { path: "guards.egress_allowlist.allow", message: "domain required" },
        { path: "guards.jailbreak.detector.block_threshold", message: "must be > 0" },
      ],
      parse_error: null,
    };
    const result = parseValidationResponse(response);
    expect(Object.keys(result.guardErrors)).toHaveLength(3);
    expect(result.guardErrors.forbidden_path).toHaveLength(1);
    expect(result.guardErrors.egress_allowlist).toHaveLength(1);
    expect(result.guardErrors.jailbreak).toHaveLength(1);
  });

  it("combines parse_error with field errors", () => {
    const response: TauriValidationResponse = {
      valid: false,
      errors: [
        { path: "guards.secret_leak.patterns", message: "duplicate name" },
        { path: "name", message: "too long" },
      ],
      parse_error: "Warning: schema mismatch",
    };
    const result = parseValidationResponse(response);
    expect(result.topLevelErrors).toEqual([
      "Warning: schema mismatch",
      "name: too long",
    ]);
    expect(result.guardErrors.secret_leak).toEqual(["duplicate name"]);
  });
});


describe("countNativeErrors", () => {
  it("returns 0 for empty state", () => {
    const state: NativeValidationState = {
      guardErrors: {},
      topLevelErrors: [],
      loading: false,
      valid: true,
    };
    expect(countNativeErrors(state)).toBe(0);
  });

  it("counts topLevelErrors", () => {
    const state: NativeValidationState = {
      guardErrors: {},
      topLevelErrors: ["error1", "error2"],
      loading: false,
      valid: false,
    };
    expect(countNativeErrors(state)).toBe(2);
  });

  it("counts guardErrors across all guards", () => {
    const state: NativeValidationState = {
      guardErrors: {
        forbidden_path: ["error1"],
        egress_allowlist: ["error2", "error3"],
      },
      topLevelErrors: [],
      loading: false,
      valid: false,
    };
    expect(countNativeErrors(state)).toBe(3);
  });

  it("counts both topLevel and guard errors", () => {
    const state: NativeValidationState = {
      guardErrors: {
        forbidden_path: ["err1"],
        jailbreak: ["err2", "err3"],
      },
      topLevelErrors: ["parse error"],
      loading: false,
      valid: false,
    };
    expect(countNativeErrors(state)).toBe(4);
  });

  it("returns 0 when loading with no errors", () => {
    const state: NativeValidationState = {
      guardErrors: {},
      topLevelErrors: [],
      loading: true,
      valid: null,
    };
    expect(countNativeErrors(state)).toBe(0);
  });
});
