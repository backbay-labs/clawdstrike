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

  it("preserves newer draft when save completes against an older snapshot", () => {
    const loaded = policyWorkbenchReducer(initialPolicyWorkbenchState, {
      type: "load_success",
      yaml: "version: \"1.2.0\"\nname: loaded",
      hash: "h1",
      version: "1.2.0",
    });
    const edited = policyWorkbenchReducer(loaded, {
      type: "edit",
      yaml: "version: \"1.2.0\"\nname: newer",
    });
    const saving = policyWorkbenchReducer(edited, { type: "save_start" });

    const saved = policyWorkbenchReducer(saving, {
      type: "save_success_preserve_draft",
      loadedYaml: "version: \"1.2.0\"\nname: loaded",
      hash: "h2",
    });

    expect(saved.isSaving).toBe(false);
    expect(saved.loadedHash).toBe("h2");
    expect(saved.loadedYaml).toContain("name: loaded");
    expect(saved.draftYaml).toContain("name: newer");
  });

  it("clears stale loadError on save success", () => {
    const errored = policyWorkbenchReducer(initialPolicyWorkbenchState, {
      type: "load_error",
      message: "Failed to load policy",
    });
    expect(errored.loadError).toBe("Failed to load policy");

    const saved = policyWorkbenchReducer(errored, {
      type: "save_success",
      yaml: "version: \"1.2.0\"\nname: saved",
      hash: "h3",
    });
    expect(saved.loadError).toBeUndefined();

    const preserved = policyWorkbenchReducer(errored, {
      type: "save_success_preserve_draft",
      loadedYaml: "version: \"1.2.0\"\nname: saved",
      hash: "h3",
    });
    expect(preserved.loadError).toBeUndefined();
  });
});
