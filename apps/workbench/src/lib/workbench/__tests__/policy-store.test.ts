import { describe, it, expect } from "vitest";
import { policyToYaml, yamlToPolicy, validatePolicy } from "../yaml-utils";
import type {
  WorkbenchPolicy,
  SavedPolicy,
  GuardId,
} from "../types";

// Since the reducer and DEFAULT_POLICY are exported from a .tsx file that uses
// React, we import them directly. The reducer is a pure function so it can be
// tested without rendering any components.

// We replicate the state type and import the reducer + defaults.
import { DEFAULT_POLICY, type WorkbenchState, type WorkbenchAction, type PolicySnapshot } from "../policy-store";
import type { ValidationResult } from "../types";

// We need access to the reducer — it is not exported, so we reconstruct it
// locally using the same logic. To avoid this, we test through a thin wrapper.
// However, the reducer is an unexported function. We will instead test it by
// building actions and verifying the expected state transformations using
// the helper functions (policyToYaml, yamlToPolicy, validatePolicy) that the
// reducer itself uses.

/**
 * Minimal replica of the reducer for testing purposes.
 * This must stay in sync with the real reducer in policy-store.tsx.
 */
function revalidate(policy: WorkbenchPolicy, yaml?: string) {
  const y = yaml ?? policyToYaml(policy);
  return { yaml: y, validation: validatePolicy(policy) };
}

const MAX_HISTORY = 50;

function takeSnapshot(state: WorkbenchState): PolicySnapshot {
  return {
    activePolicy: state.activePolicy,
    yaml: state.yaml,
    validation: state.validation,
  };
}

function snapshotsEqual(a: PolicySnapshot, b: PolicySnapshot): boolean {
  return a.yaml === b.yaml;
}

function isDirtyVsClean(state: WorkbenchState): boolean {
  if (!state._cleanSnapshot) return true;
  return !snapshotsEqual(takeSnapshot(state), state._cleanSnapshot);
}

const POLICY_MODIFYING_ACTIONS = new Set([
  "SET_POLICY",
  "SET_YAML",
  "UPDATE_GUARD",
  "TOGGLE_GUARD",
  "UPDATE_SETTINGS",
  "UPDATE_META",
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
      return { ...state, dirty: false, _cleanSnapshot: takeSnapshot(state) };
    }
    case "UNDO":
    case "REDO":
      return state;
    default:
      return state;
  }
}

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

  if (POLICY_MODIFYING_ACTIONS.has(action.type)) {
    const currentSnapshot = takeSnapshot(state);
    const next = coreReducer(state, action);
    const nextSnapshot = takeSnapshot(next);
    if (snapshotsEqual(currentSnapshot, nextSnapshot)) return next;
    return {
      ...next,
      _undoPast: [...state._undoPast, currentSnapshot].slice(-MAX_HISTORY),
      _undoFuture: [],
    };
  }

  return coreReducer(state, action);
}


function makeInitialState(overrides?: Partial<WorkbenchState>): WorkbenchState {
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
    ...overrides,
  };
}

function makeSavedPolicy(id: string, name?: string): SavedPolicy {
  const policy: WorkbenchPolicy = {
    version: "1.2.0",
    name: name || `policy-${id}`,
    description: "",
    guards: {},
    settings: {},
  };
  return {
    id,
    policy,
    yaml: policyToYaml(policy),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
}


describe("DEFAULT_POLICY", () => {
  it("is a valid policy", () => {
    const result = validatePolicy(DEFAULT_POLICY);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("has version 1.2.0", () => {
    expect(DEFAULT_POLICY.version).toBe("1.2.0");
  });

  it("has a name", () => {
    expect(DEFAULT_POLICY.name).toBeTruthy();
  });

  it("has forbidden_path, egress_allowlist, and secret_leak guards", () => {
    expect(DEFAULT_POLICY.guards.forbidden_path).toBeDefined();
    expect(DEFAULT_POLICY.guards.egress_allowlist).toBeDefined();
    expect(DEFAULT_POLICY.guards.secret_leak).toBeDefined();
  });

  it("forbidden_path has multiple patterns", () => {
    expect(DEFAULT_POLICY.guards.forbidden_path!.patterns!.length).toBeGreaterThanOrEqual(5);
  });

  it("egress_allowlist defaults to block", () => {
    expect(DEFAULT_POLICY.guards.egress_allowlist!.default_action).toBe("block");
  });

  it("secret_leak has patterns for AWS, GitHub, and private keys", () => {
    const names = DEFAULT_POLICY.guards.secret_leak!.patterns!.map((p) => p.name);
    expect(names).toContain("aws_access_key");
    expect(names).toContain("github_token");
    expect(names).toContain("private_key");
  });
});


describe("SET_POLICY", () => {
  it("updates activePolicy and revalidates", () => {
    const state = makeInitialState();
    const newPolicy: WorkbenchPolicy = {
      version: "1.3.0",
      name: "New Policy",
      description: "fresh",
      guards: {},
      settings: {},
    };
    const next = reducer(state, { type: "SET_POLICY", policy: newPolicy });
    expect(next.activePolicy).toBe(newPolicy);
    expect(next.dirty).toBe(true);
    expect(next.yaml).toContain("New Policy");
    expect(next.validation.valid).toBe(true);
    expect(next.ui.editorSyncDirection).toBe("visual");
  });

  it("updates validation when new policy has errors", () => {
    const state = makeInitialState();
    const badPolicy: WorkbenchPolicy = {
      version: "0.0.0" as any,
      name: "",
      description: "",
      guards: {},
      settings: {},
    };
    const next = reducer(state, { type: "SET_POLICY", policy: badPolicy });
    expect(next.validation.valid).toBe(false);
    expect(next.validation.errors.length).toBeGreaterThan(0);
  });
});


describe("SET_YAML", () => {
  it("with valid YAML updates both policy and yaml", () => {
    const state = makeInitialState();
    const yaml = `version: "1.2.0"\nname: "YAML Policy"\ndescription: ""\nguards: {}\nsettings: {}\n`;
    const next = reducer(state, { type: "SET_YAML", yaml });
    expect(next.yaml).toBe(yaml);
    expect(next.activePolicy.name).toBe("YAML Policy");
    expect(next.dirty).toBe(true);
    expect(next.ui.editorSyncDirection).toBe("yaml");
  });

  it("with invalid YAML preserves yaml but adds errors", () => {
    const state = makeInitialState();
    const badYaml = "version: '1.2.0\n  broken: [";
    const next = reducer(state, { type: "SET_YAML", yaml: badYaml });
    expect(next.yaml).toBe(badYaml);
    expect(next.validation.valid).toBe(false);
    expect(next.validation.errors.length).toBeGreaterThan(0);
    // activePolicy should remain unchanged (the old one)
    expect(next.activePolicy).toBe(state.activePolicy);
  });

  it("with YAML array rejects (must be a mapping/object)", () => {
    const state = makeInitialState();
    const next = reducer(state, { type: "SET_YAML", yaml: "- just\n- a\n- list" });
    // Arrays are now rejected by yamlToPolicy validation
    expect(next.validation.valid).toBe(false);
    expect(next.validation.errors.length).toBeGreaterThan(0);
    // activePolicy should remain unchanged (the old one)
    expect(next.activePolicy).toBe(state.activePolicy);
  });
});


describe("UPDATE_GUARD", () => {
  it("merges config into existing guard", () => {
    const state = makeInitialState();
    const next = reducer(state, {
      type: "UPDATE_GUARD",
      guardId: "forbidden_path",
      config: { exceptions: ["/allowed/path"] },
    });
    expect(next.activePolicy.guards.forbidden_path!.exceptions).toEqual(["/allowed/path"]);
    // Original patterns should be preserved
    expect(next.activePolicy.guards.forbidden_path!.patterns).toEqual(
      DEFAULT_POLICY.guards.forbidden_path!.patterns
    );
    expect(next.dirty).toBe(true);
  });

  it("creates guard config if it did not exist", () => {
    const state = makeInitialState();
    const next = reducer(state, {
      type: "UPDATE_GUARD",
      guardId: "shell_command",
      config: { enabled: true, forbidden_patterns: ["rm.*-rf"] },
    });
    expect(next.activePolicy.guards.shell_command).toBeDefined();
    expect(next.activePolicy.guards.shell_command!.enabled).toBe(true);
    expect(next.activePolicy.guards.shell_command!.forbidden_patterns).toEqual(["rm.*-rf"]);
  });

  it("triggers revalidation", () => {
    const state = makeInitialState();
    const next = reducer(state, {
      type: "UPDATE_GUARD",
      guardId: "forbidden_path",
      config: { patterns: ["**/.ssh/**", ""] }, // empty pattern should cause error
    });
    expect(next.validation.errors.some((e) => e.message === "Empty pattern")).toBe(true);
  });
});


describe("TOGGLE_GUARD", () => {
  it("enables a guard", () => {
    const state = makeInitialState();
    const next = reducer(state, {
      type: "TOGGLE_GUARD",
      guardId: "jailbreak",
      enabled: true,
    });
    expect(next.activePolicy.guards.jailbreak).toBeDefined();
    expect(next.activePolicy.guards.jailbreak!.enabled).toBe(true);
  });

  it("disables a guard but keeps it if it has other config", () => {
    const state = makeInitialState();
    const next = reducer(state, {
      type: "TOGGLE_GUARD",
      guardId: "forbidden_path",
      enabled: false,
    });
    // forbidden_path has patterns etc, so it should remain (just disabled)
    expect(next.activePolicy.guards.forbidden_path).toBeDefined();
    expect(next.activePolicy.guards.forbidden_path!.enabled).toBe(false);
  });

  it("removes guard entirely if disabled and only has enabled field", () => {
    // First add a guard with only enabled: true
    let state = makeInitialState();
    state = reducer(state, { type: "TOGGLE_GUARD", guardId: "spider_sense", enabled: true });
    expect(state.activePolicy.guards.spider_sense).toBeDefined();

    // Now disable it - since only field is enabled, it should be deleted
    const next = reducer(state, { type: "TOGGLE_GUARD", guardId: "spider_sense", enabled: false });
    expect(next.activePolicy.guards.spider_sense).toBeUndefined();
  });

  it("marks state as dirty", () => {
    const state = makeInitialState();
    const next = reducer(state, {
      type: "TOGGLE_GUARD",
      guardId: "forbidden_path",
      enabled: false,
    });
    expect(next.dirty).toBe(true);
  });
});


describe("UPDATE_SETTINGS", () => {
  it("merges settings correctly", () => {
    const state = makeInitialState();
    const next = reducer(state, {
      type: "UPDATE_SETTINGS",
      settings: { verbose_logging: true },
    });
    expect(next.activePolicy.settings.verbose_logging).toBe(true);
    // Other settings preserved
    expect(next.activePolicy.settings.fail_fast).toBe(DEFAULT_POLICY.settings.fail_fast);
  });

  it("can update session_timeout_secs", () => {
    const state = makeInitialState();
    const next = reducer(state, {
      type: "UPDATE_SETTINGS",
      settings: { session_timeout_secs: 1800 },
    });
    expect(next.activePolicy.settings.session_timeout_secs).toBe(1800);
  });

  it("triggers revalidation on short timeout", () => {
    const state = makeInitialState();
    const next = reducer(state, {
      type: "UPDATE_SETTINGS",
      settings: { session_timeout_secs: 10 },
    });
    expect(next.validation.warnings.some((w) => w.path === "settings.session_timeout_secs")).toBe(true);
  });
});


describe("UPDATE_META", () => {
  it("updates name", () => {
    const state = makeInitialState();
    const next = reducer(state, { type: "UPDATE_META", name: "New Name" });
    expect(next.activePolicy.name).toBe("New Name");
    expect(next.dirty).toBe(true);
  });

  it("updates description", () => {
    const state = makeInitialState();
    const next = reducer(state, { type: "UPDATE_META", description: "A description" });
    expect(next.activePolicy.description).toBe("A description");
  });

  it("updates version", () => {
    const state = makeInitialState();
    const next = reducer(state, { type: "UPDATE_META", version: "1.3.0" });
    expect(next.activePolicy.version).toBe("1.3.0");
  });

  it("updates extends", () => {
    const state = makeInitialState();
    const next = reducer(state, { type: "UPDATE_META", extends: "strict" });
    expect(next.activePolicy.extends).toBe("strict");
  });

  it("clears extends when empty string", () => {
    let state = makeInitialState();
    state = reducer(state, { type: "UPDATE_META", extends: "strict" });
    const next = reducer(state, { type: "UPDATE_META", extends: "" });
    expect(next.activePolicy.extends).toBeUndefined();
  });

  it("only updates specified fields", () => {
    const state = makeInitialState();
    const next = reducer(state, { type: "UPDATE_META", name: "Changed" });
    expect(next.activePolicy.description).toBe(DEFAULT_POLICY.description);
    expect(next.activePolicy.version).toBe(DEFAULT_POLICY.version);
  });
});


describe("SAVE_POLICY", () => {
  it("adds to savedPolicies", () => {
    const state = makeInitialState();
    const saved = makeSavedPolicy("p1", "First Policy");
    const next = reducer(state, { type: "SAVE_POLICY", savedPolicy: saved });
    expect(next.savedPolicies).toHaveLength(1);
    expect(next.savedPolicies[0].id).toBe("p1");
  });

  it("replaces existing policy with same id", () => {
    let state = makeInitialState();
    const v1 = makeSavedPolicy("p1", "Version 1");
    state = reducer(state, { type: "SAVE_POLICY", savedPolicy: v1 });
    expect(state.savedPolicies).toHaveLength(1);

    const v2 = makeSavedPolicy("p1", "Version 2");
    state = reducer(state, { type: "SAVE_POLICY", savedPolicy: v2 });
    expect(state.savedPolicies).toHaveLength(1);
    expect(state.savedPolicies[0].policy.name).toBe("Version 2");
  });

  it("keeps other policies when replacing by id", () => {
    let state = makeInitialState();
    state = reducer(state, { type: "SAVE_POLICY", savedPolicy: makeSavedPolicy("p1") });
    state = reducer(state, { type: "SAVE_POLICY", savedPolicy: makeSavedPolicy("p2") });
    expect(state.savedPolicies).toHaveLength(2);

    state = reducer(state, { type: "SAVE_POLICY", savedPolicy: makeSavedPolicy("p1", "Updated") });
    expect(state.savedPolicies).toHaveLength(2);
    expect(state.savedPolicies.find((p) => p.id === "p1")!.policy.name).toBe("Updated");
    expect(state.savedPolicies.find((p) => p.id === "p2")).toBeDefined();
  });
});


describe("DELETE_SAVED_POLICY", () => {
  it("removes the correct policy", () => {
    let state = makeInitialState();
    state = reducer(state, { type: "SAVE_POLICY", savedPolicy: makeSavedPolicy("p1") });
    state = reducer(state, { type: "SAVE_POLICY", savedPolicy: makeSavedPolicy("p2") });
    state = reducer(state, { type: "SAVE_POLICY", savedPolicy: makeSavedPolicy("p3") });
    expect(state.savedPolicies).toHaveLength(3);

    state = reducer(state, { type: "DELETE_SAVED_POLICY", id: "p2" });
    expect(state.savedPolicies).toHaveLength(2);
    expect(state.savedPolicies.some((p) => p.id === "p2")).toBe(false);
    expect(state.savedPolicies.some((p) => p.id === "p1")).toBe(true);
    expect(state.savedPolicies.some((p) => p.id === "p3")).toBe(true);
  });

  it("no-ops when deleting non-existent id", () => {
    let state = makeInitialState();
    state = reducer(state, { type: "SAVE_POLICY", savedPolicy: makeSavedPolicy("p1") });
    const next = reducer(state, { type: "DELETE_SAVED_POLICY", id: "nonexistent" });
    expect(next.savedPolicies).toHaveLength(1);
  });
});


describe("SET_COMPARISON", () => {
  it("sets comparison policy", () => {
    const state = makeInitialState();
    const compPolicy: WorkbenchPolicy = {
      version: "1.2.0",
      name: "comparison",
      description: "",
      guards: {},
      settings: {},
    };
    const next = reducer(state, { type: "SET_COMPARISON", policy: compPolicy });
    expect(next.comparisonPolicy).toBe(compPolicy);
    expect(next.comparisonYaml).toContain("comparison");
  });

  it("clears comparison policy when null", () => {
    let state = makeInitialState();
    const compPolicy: WorkbenchPolicy = {
      version: "1.2.0",
      name: "comparison",
      description: "",
      guards: {},
      settings: {},
    };
    state = reducer(state, { type: "SET_COMPARISON", policy: compPolicy });
    expect(state.comparisonPolicy).not.toBeNull();

    state = reducer(state, { type: "SET_COMPARISON", policy: null });
    expect(state.comparisonPolicy).toBeNull();
    expect(state.comparisonYaml).toBe("");
  });

  it("uses provided yaml when given", () => {
    const state = makeInitialState();
    const compPolicy: WorkbenchPolicy = {
      version: "1.2.0",
      name: "comp",
      description: "",
      guards: {},
      settings: {},
    };
    const customYaml = "# custom yaml\nversion: '1.2.0'\n";
    const next = reducer(state, { type: "SET_COMPARISON", policy: compPolicy, yaml: customYaml });
    expect(next.comparisonYaml).toBe(customYaml);
  });
});


describe("other actions", () => {
  it("SET_SIDEBAR_COLLAPSED toggles sidebar", () => {
    const state = makeInitialState();
    const next = reducer(state, { type: "SET_SIDEBAR_COLLAPSED", collapsed: true });
    expect(next.ui.sidebarCollapsed).toBe(true);
    const next2 = reducer(next, { type: "SET_SIDEBAR_COLLAPSED", collapsed: false });
    expect(next2.ui.sidebarCollapsed).toBe(false);
  });

  it("SET_EDITOR_TAB switches tab", () => {
    const state = makeInitialState();
    const next = reducer(state, { type: "SET_EDITOR_TAB", tab: "yaml" });
    expect(next.ui.activeEditorTab).toBe("yaml");
    const next2 = reducer(next, { type: "SET_EDITOR_TAB", tab: "visual" });
    expect(next2.ui.activeEditorTab).toBe("visual");
  });

  it("SET_FILE_PATH sets file path", () => {
    const state = makeInitialState();
    const next = reducer(state, { type: "SET_FILE_PATH", path: "/tmp/policy.yaml" });
    expect(next.filePath).toBe("/tmp/policy.yaml");
  });

  it("SET_FILE_PATH can set null", () => {
    let state = makeInitialState();
    state = reducer(state, { type: "SET_FILE_PATH", path: "/tmp/policy.yaml" });
    const next = reducer(state, { type: "SET_FILE_PATH", path: null });
    expect(next.filePath).toBeNull();
  });

  it("MARK_CLEAN sets dirty to false", () => {
    let state = makeInitialState();
    state = reducer(state, { type: "UPDATE_META", name: "Changed" });
    expect(state.dirty).toBe(true);
    state = reducer(state, { type: "MARK_CLEAN" });
    expect(state.dirty).toBe(false);
  });

  it("unknown action returns state unchanged", () => {
    const state = makeInitialState();
    const next = reducer(state, { type: "UNKNOWN_ACTION" } as any);
    expect(next).toBe(state);
  });
});


describe("UNDO", () => {
  it("no-ops when history is empty", () => {
    const state = makeInitialState();
    const next = reducer(state, { type: "UNDO" });
    expect(next).toBe(state);
  });

  it("restores previous snapshot after a policy-modifying action", () => {
    let state = makeInitialState();
    const originalName = state.activePolicy.name;
    state = reducer(state, { type: "UPDATE_META", name: "Renamed" });
    expect(state.activePolicy.name).toBe("Renamed");
    expect(state._undoPast).toHaveLength(1);

    state = reducer(state, { type: "UNDO" });
    expect(state.activePolicy.name).toBe(originalName);
    expect(state._undoPast).toHaveLength(0);
    expect(state._undoFuture).toHaveLength(1);
  });

  it("can undo multiple steps", () => {
    let state = makeInitialState();
    const originalName = state.activePolicy.name;
    state = reducer(state, { type: "UPDATE_META", name: "Step 1" });
    state = reducer(state, { type: "UPDATE_META", name: "Step 2" });
    state = reducer(state, { type: "UPDATE_META", name: "Step 3" });
    expect(state._undoPast).toHaveLength(3);

    state = reducer(state, { type: "UNDO" });
    expect(state.activePolicy.name).toBe("Step 2");
    state = reducer(state, { type: "UNDO" });
    expect(state.activePolicy.name).toBe("Step 1");
    state = reducer(state, { type: "UNDO" });
    expect(state.activePolicy.name).toBe(originalName);
    expect(state._undoPast).toHaveLength(0);
  });

  it("recalculates dirty flag correctly after undo to clean state", () => {
    let state = makeInitialState();
    // Mark current state as clean
    state = reducer(state, { type: "MARK_CLEAN" });
    expect(state.dirty).toBe(false);

    // Make a change
    state = reducer(state, { type: "UPDATE_META", name: "Dirty" });
    expect(state.dirty).toBe(true);

    // Undo should restore to the clean state
    state = reducer(state, { type: "UNDO" });
    expect(state.dirty).toBe(false);
  });
});

describe("REDO", () => {
  it("no-ops when future is empty", () => {
    const state = makeInitialState();
    const next = reducer(state, { type: "REDO" });
    expect(next).toBe(state);
  });

  it("reapplies undone changes", () => {
    let state = makeInitialState();
    state = reducer(state, { type: "UPDATE_META", name: "Changed" });
    state = reducer(state, { type: "UNDO" });
    expect(state.activePolicy.name).toBe(DEFAULT_POLICY.name);
    expect(state._undoFuture).toHaveLength(1);

    state = reducer(state, { type: "REDO" });
    expect(state.activePolicy.name).toBe("Changed");
    expect(state._undoFuture).toHaveLength(0);
    expect(state._undoPast).toHaveLength(1);
  });

  it("clears future on new policy-modifying action", () => {
    let state = makeInitialState();
    state = reducer(state, { type: "UPDATE_META", name: "V1" });
    state = reducer(state, { type: "UPDATE_META", name: "V2" });
    state = reducer(state, { type: "UNDO" });
    expect(state._undoFuture).toHaveLength(1);

    // New action should clear the redo stack
    state = reducer(state, { type: "UPDATE_META", name: "V3" });
    expect(state._undoFuture).toHaveLength(0);
    expect(state.activePolicy.name).toBe("V3");
  });
});

describe("undo/redo history limits", () => {
  it("caps history at MAX_HISTORY (50) entries", () => {
    let state = makeInitialState();
    for (let i = 0; i < 60; i++) {
      state = reducer(state, { type: "UPDATE_META", name: `Step ${i}` });
    }
    expect(state._undoPast.length).toBeLessThanOrEqual(50);
  });

  it("does not push to history for UI-only actions", () => {
    let state = makeInitialState();
    state = reducer(state, { type: "SET_SIDEBAR_COLLAPSED", collapsed: true });
    expect(state._undoPast).toHaveLength(0);

    state = reducer(state, { type: "SET_EDITOR_TAB", tab: "yaml" });
    expect(state._undoPast).toHaveLength(0);
  });

  it("does not push to history for file-tracking actions", () => {
    let state = makeInitialState();
    state = reducer(state, { type: "SET_FILE_PATH", path: "/tmp/test.yaml" });
    expect(state._undoPast).toHaveLength(0);

    state = reducer(state, { type: "MARK_CLEAN" });
    expect(state._undoPast).toHaveLength(0);
  });

  it("tracks all policy-modifying action types", () => {
    let state = makeInitialState();

    state = reducer(state, { type: "UPDATE_META", name: "test" });
    expect(state._undoPast).toHaveLength(1);

    state = reducer(state, { type: "UPDATE_SETTINGS", settings: { fail_fast: true } });
    expect(state._undoPast).toHaveLength(2);

    state = reducer(state, { type: "TOGGLE_GUARD", guardId: "jailbreak", enabled: true });
    expect(state._undoPast).toHaveLength(3);

    state = reducer(state, { type: "UPDATE_GUARD", guardId: "jailbreak", config: { enabled: false } });
    expect(state._undoPast).toHaveLength(4);
  });
});
