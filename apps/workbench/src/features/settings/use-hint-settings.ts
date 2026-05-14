// Hint Settings — configurable Claude Code hint text and visibility
// Persisted to localStorage independently of the policy store.
//
// Zustand + immer store (migrated from React Context + useState).
import {
  createElement,
  createContext,
  useContext,
  useLayoutEffect,
  type ReactElement,
  type ReactNode,
} from "react";
import { create } from "zustand";
import { immer } from "zustand/middleware/immer";
import { createSelectors } from "@/lib/create-selectors";


export interface HintConfig {
  hint: string;   // Short description shown in the UI strip
  prompt: string; // Full prompt copied to clipboard
}

export type HintId =
  | "home.audit"
  | "editor.validate"
  | "simulator.scenarios"
  | "compliance.check"
  | "observe.synth"
  | "risk.assess"
  | "library.audit"
  | "library.testSuite"
  | "library.harden"
  | "library.compare";

export const HINT_LABELS: Record<HintId, string> = {
  "home.audit": "Home \u2014 Policy Audit",
  "editor.validate": "Editor \u2014 Validate & Tighten",
  "simulator.scenarios": "Simulator \u2014 Generate Scenarios",
  "compliance.check": "Compliance \u2014 Framework Check",
  "observe.synth": "Observe & Synth \u2014 Policy Synthesis",
  "risk.assess": "Risk Dashboard \u2014 Risk Assessment",
  "library.audit": "Library \u2014 Audit My Policy",
  "library.testSuite": "Library \u2014 Build Test Suite",
  "library.harden": "Library \u2014 Harden Policy",
  "library.compare": "Library \u2014 Compare Versions",
};


export const DEFAULT_HINTS: Record<HintId, HintConfig> = {
  "home.audit": {
    hint: "Ask Claude Code to audit your policy and find security gaps",
    prompt:
      "Read my active policy YAML file. Then: 1) Call workbench_validate_policy to check for errors. 2) Call workbench_guard_coverage to identify disabled guards. 3) Call workbench_compliance_check against all frameworks. 4) Call workbench_suggest_scenarios and run them with workbench_run_all_scenarios. Summarize: validation status, guard coverage %, compliance scores, test pass rate, and top 5 recommended fixes ranked by impact.",
  },
  "editor.validate": {
    hint: "Validate & tighten this policy with Claude Code",
    prompt:
      "Read the policy YAML I'm editing. Call workbench_validate_policy and fix any errors. Then call workbench_harden_policy with level 'moderate' and show me a diff of what changed. For each change, explain why it improves security.",
  },
  "simulator.scenarios": {
    hint: "Generate attack scenarios with Claude Code",
    prompt:
      "Read my policy YAML. Call workbench_suggest_scenarios to generate test cases for every enabled guard. Then call workbench_create_scenario to add 3 edge cases: a path traversal attempt (../../etc/passwd), a base64-encoded secret in a file write, and a curl command piped to bash. Run everything with workbench_run_all_scenarios. Show a pass/fail table and flag any unexpected results.",
  },
  "compliance.check": {
    hint: "Check compliance scores with Claude Code",
    prompt:
      "Read my policy YAML. Call workbench_compliance_check against HIPAA, SOC2, and PCI-DSS. For each gap found, call workbench_harden_policy with level 'aggressive' to generate a fix. Show me a table: framework | current score | gap count | specific guards to enable. Then output the hardened YAML.",
  },
  "observe.synth": {
    hint: "Synthesize a policy from agent logs with Claude Code",
    prompt:
      "I'll paste agent activity logs below as JSONL. Call workbench_synth_policy to generate a policy from these events. Then call workbench_validate_policy on the result and workbench_guard_coverage to check coverage. If coverage is below 70%, call workbench_harden_policy to strengthen it. Show me the final policy YAML with annotations explaining each guard's purpose.",
  },
  "risk.assess": {
    hint: "Ask Claude Code to assess your risk posture",
    prompt:
      "Read my policy YAML. Call workbench_guard_coverage and workbench_compliance_check against all frameworks. Calculate an overall risk score: (guard_coverage% + avg_compliance%) / 2. List every disabled guard with its risk category. For each compliance gap, show the specific guard config change needed. Output a prioritized remediation plan.",
  },
  "library.audit": {
    hint: "Audit My Policy",
    prompt:
      "Read my active policy YAML. Run this full audit: 1) workbench_validate_policy for errors 2) workbench_guard_coverage for coverage gaps 3) workbench_compliance_check against HIPAA, SOC2, PCI-DSS 4) workbench_suggest_scenarios + workbench_run_all_scenarios for testing. Output a security report with scores, test results, and a prioritized fix list.",
  },
  "library.testSuite": {
    hint: "Build Test Suite",
    prompt:
      "Read my policy YAML. Call workbench_suggest_scenarios for auto-generated tests. Then use workbench_create_scenario to build 5 additional edge cases: 1) symlink traversal to /etc/shadow, 2) DNS rebinding egress to internal IP, 3) base64-encoded AWS key in file write, 4) chained shell command with pipe to nc, 5) MCP tool call with injected args. Run all with workbench_run_all_scenarios and output the full test suite as JSON I can save.",
  },
  "library.harden": {
    hint: "Harden Policy",
    prompt:
      "Read my policy YAML. Call workbench_harden_policy with level 'aggressive'. Then call workbench_diff_policies comparing my original against the hardened version. For each change, explain the security improvement. Run workbench_compliance_check on both versions and show the score improvement. Output the hardened YAML.",
  },
  "library.compare": {
    hint: "Compare Versions",
    prompt:
      "Call workbench_list_rulesets to show available built-in policies. Then read my policy YAML and call workbench_diff_policies comparing it against the 'strict' ruleset. Show exactly which guards I'm missing and which settings are weaker. Suggest the minimum changes to match strict-level security.",
  },
};


// ---------------------------------------------------------------------------
// localStorage persistence
// ---------------------------------------------------------------------------

interface HintSettingsState {
  showHints: boolean;           // Master toggle -- show/hide all hints
  overrides: Partial<Record<HintId, Partial<HintConfig>>>; // Only non-default values stored
}

const DEFAULT_STATE: HintSettingsState = {
  showHints: true,
  overrides: {},
};


const STORAGE_KEY = "clawdstrike_hint_settings";
const HintSettingsContext = createContext(false);
let lastHintSettingsStorageSnapshot =
  typeof window === "undefined" ? null : readHintSettingsStorageSnapshot();

function readHintSettingsStorageSnapshot(): string | null {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

function loadState(): HintSettingsState {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULT_STATE;
    const parsed = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null) return DEFAULT_STATE;

    const showHints =
      typeof parsed.showHints === "boolean" ? parsed.showHints : DEFAULT_STATE.showHints;
    const overrides =
      typeof parsed.overrides === "object" && parsed.overrides !== null
        ? parsed.overrides
        : DEFAULT_STATE.overrides;

    // Validate overrides: each value must be an object with optional hint/prompt strings
    const validOverrides: Partial<Record<HintId, Partial<HintConfig>>> = {};
    for (const [key, val] of Object.entries(overrides)) {
      if (typeof val !== "object" || val === null) continue;
      const patch: Partial<HintConfig> = {};
      const v = val as Record<string, unknown>;
      if (typeof v.hint === "string" && v.hint.length > 0) patch.hint = v.hint;
      if (typeof v.prompt === "string" && v.prompt.length > 0) patch.prompt = v.prompt;
      if (Object.keys(patch).length > 0) validOverrides[key as HintId] = patch;
    }

    return { showHints, overrides: validOverrides };
  } catch {
    return DEFAULT_STATE;
  }
}

function persistState(state: HintSettingsState): void {
  try {
    const raw = JSON.stringify(state);
    localStorage.setItem(STORAGE_KEY, raw);
    lastHintSettingsStorageSnapshot = raw;
  } catch {
    // Storage full or unavailable -- ignore
  }
}


// ---------------------------------------------------------------------------
// Zustand store
// ---------------------------------------------------------------------------

export interface HintSettingsStoreState {
  showHints: boolean;
  overrides: Partial<Record<HintId, Partial<HintConfig>>>;
  actions: HintSettingsActions;
}

interface HintSettingsActions {
  setShowHints: (show: boolean) => void;
  getHint: (id: HintId) => HintConfig;
  updateHint: (id: HintId, patch: Partial<HintConfig>) => void;
  resetHint: (id: HintId) => void;
  resetAll: () => void;
  isCustomized: (id: HintId) => boolean;
}

const useHintSettingsStoreBase = create<HintSettingsStoreState>()(
  immer((set, get) => {
    const initial = loadState();

    return {
      showHints: initial.showHints,
      overrides: initial.overrides,

      actions: {
        setShowHints: (show: boolean) => {
          set((state) => {
            state.showHints = show;
          });
          const s = get();
          persistState({ showHints: s.showHints, overrides: s.overrides });
        },

        getHint: (id: HintId): HintConfig => {
          const defaults = DEFAULT_HINTS[id];
          const override = get().overrides[id];
          if (!override) return defaults;
          return {
            hint: override.hint ?? defaults.hint,
            prompt: override.prompt ?? defaults.prompt,
          };
        },

        updateHint: (id: HintId, patch: Partial<HintConfig>) => {
          set((state) => {
            const defaults = DEFAULT_HINTS[id];
            const existing = state.overrides[id] ?? {};
            const merged = { ...existing, ...patch };

            // Remove fields that match the default (only store actual overrides)
            const cleaned: Partial<HintConfig> = {};
            if (merged.hint && merged.hint !== defaults.hint) cleaned.hint = merged.hint;
            if (merged.prompt && merged.prompt !== defaults.prompt) cleaned.prompt = merged.prompt;

            if (Object.keys(cleaned).length > 0) {
              state.overrides[id] = cleaned;
            } else {
              delete state.overrides[id];
            }
          });
          const s = get();
          persistState({ showHints: s.showHints, overrides: s.overrides });
        },

        resetHint: (id: HintId) => {
          set((state) => {
            delete state.overrides[id];
          });
          const s = get();
          persistState({ showHints: s.showHints, overrides: s.overrides });
        },

        resetAll: () => {
          set((state) => {
            state.overrides = {};
          });
          const s = get();
          persistState({ showHints: s.showHints, overrides: s.overrides });
        },

        isCustomized: (id: HintId): boolean => {
          return id in get().overrides;
        },
      },
    };
  }),
);

export const useHintSettingsStore = createSelectors(useHintSettingsStoreBase);

function syncHintSettingsStoreWithStorage(force = false): void {
  const snapshot = readHintSettingsStorageSnapshot();
  if (!force && snapshot === lastHintSettingsStorageSnapshot) {
    return;
  }

  const initial = loadState();
  lastHintSettingsStorageSnapshot = snapshot;
  useHintSettingsStoreBase.setState({
    showHints: initial.showHints,
    overrides: initial.overrides,
  });
}

// ---------------------------------------------------------------------------
// Backward-compatible hook — same shape the old Context-based hook returned
// ---------------------------------------------------------------------------

interface HintSettingsContextValue {
  showHints: boolean;
  setShowHints: (show: boolean) => void;
  getHint: (id: HintId) => HintConfig;
  updateHint: (id: HintId, patch: Partial<HintConfig>) => void;
  resetHint: (id: HintId) => void;
  resetAll: () => void;
  isCustomized: (id: HintId) => boolean;
}

function useHintSettingsValue(): HintSettingsContextValue {
  useLayoutEffect(() => {
    syncHintSettingsStoreWithStorage();
  }, []);

  const showHints = useHintSettingsStore((s) => s.showHints);
  const actions = useHintSettingsStore((s) => s.actions);

  return {
    showHints,
    setShowHints: actions.setShowHints,
    getHint: actions.getHint,
    updateHint: actions.updateHint,
    resetHint: actions.resetHint,
    resetAll: actions.resetAll,
    isCustomized: actions.isCustomized,
  };
}

/** @deprecated Use useHintSettingsStore directly */
export function useHintSettings(): HintSettingsContextValue {
  const withinProvider = useContext(HintSettingsContext);
  if (!withinProvider) {
    throw new Error("useHintSettings must be used within HintSettingsProvider");
  }

  return useHintSettingsValue();
}

/**
 * Safe version that returns the hook value without requiring the legacy
 * compatibility provider.
 * @deprecated Use useHintSettingsStore directly
 */
export function useHintSettingsSafe(): HintSettingsContextValue {
  return useHintSettingsValue();
}

/**
 * @deprecated Compatibility wrapper retained for legacy callers and tests.
 */
export function HintSettingsProvider({ children }: { children: ReactNode }) {
  useLayoutEffect(() => {
    syncHintSettingsStoreWithStorage(true);
  }, []);

  return createElement(
    HintSettingsContext.Provider,
    { value: true },
    children as ReactElement,
  );
}
