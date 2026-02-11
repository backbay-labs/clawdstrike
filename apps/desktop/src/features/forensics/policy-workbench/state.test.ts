import { describe, expect, it } from "vitest";

import {
  initialPolicyWorkbenchState,
  isPolicyDraftDirty,
  policyWorkbenchReducer,
} from "./state";

describe("policyWorkbenchReducer", () => {
  it("marks draft as dirty after edit and clears on revert", () => {
    const loaded = policyWorkbenchReducer(initialPolicyWorkbenchState, {
      type: "load_success",
      yaml: "version: \"1.2.0\"\nname: demo",
      hash: "abc",
      version: "1.2.0",
    });
    expect(isPolicyDraftDirty(loaded)).toBe(false);

    const edited = policyWorkbenchReducer(loaded, {
      type: "edit",
      yaml: "version: \"1.2.0\"\nname: edited",
    });
    expect(isPolicyDraftDirty(edited)).toBe(true);

    const reverted = policyWorkbenchReducer(edited, { type: "revert" });
    expect(isPolicyDraftDirty(reverted)).toBe(false);
  });

  it("tracks validation state transitions", () => {
    const running = policyWorkbenchReducer(initialPolicyWorkbenchState, { type: "validate_start" });
    expect(running.validation.status).toBe("running");

    const invalid = policyWorkbenchReducer(running, {
      type: "validate_success",
      valid: false,
      errors: [{ path: "version", code: "policy_schema_unsupported", message: "unsupported" }],
      warnings: [],
    });
    expect(invalid.validation.status).toBe("invalid");
    expect(invalid.validation.errors).toHaveLength(1);

    const errored = policyWorkbenchReducer(invalid, {
      type: "validate_error",
      message: "network failed",
    });
    expect(errored.validation.status).toBe("error");
    expect(errored.validation.message).toBe("network failed");
  });
});
