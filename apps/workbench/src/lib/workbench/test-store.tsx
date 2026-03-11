import React, {
  createContext,
  useContext,
  useReducer,
  type ReactNode,
} from "react";
import { parseSuiteYaml, suiteScenariosToYaml, type SuiteScenario } from "./suite-parser";
import type { CoverageReport } from "./coverage-analyzer";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface TestResult {
  scenarioName: string;
  verdict: "allow" | "warn" | "deny";
  guard: string | null;
  passed: boolean | null; // null = no expectation
  durationMs: number;
  guardResults: Array<{ guard: string; verdict: string; message: string }>;
}

export type GuardTestStatus = "pass" | "fail" | "warn" | "none";

export interface RunHistoryEntry {
  timestamp: string;
  total: number;
  passed: number;
  failed: number;
}

export interface TestRunnerState {
  suiteYaml: string;
  scenarios: SuiteScenario[];
  parseErrors: string[];
  results: Map<string, TestResult>;
  guardResults: Map<string, GuardTestStatus>;
  isRunning: boolean;
  autoRerun: boolean;
  runHistory: RunHistoryEntry[];
  coverageReport: CoverageReport | null;
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

export type TestRunnerAction =
  | { type: "SET_SUITE_YAML"; yaml: string }
  | { type: "SET_RESULTS"; results: Map<string, TestResult> }
  | { type: "SET_RUNNING"; running: boolean }
  | { type: "TOGGLE_AUTO_RERUN" }
  | { type: "ADD_HISTORY_ENTRY"; entry: RunHistoryEntry }
  | { type: "SET_COVERAGE"; report: CoverageReport | null }
  | { type: "CLEAR_RESULTS" }
  | { type: "IMPORT_SCENARIOS"; scenarios: SuiteScenario[] };

// ---------------------------------------------------------------------------
// Guard results computation
// ---------------------------------------------------------------------------

const MAX_HISTORY = 20;

/**
 * Recompute aggregate guard test status from all results.
 *
 * For each guard exercised across all test results:
 * - "pass" if all tests involving it pass
 * - "fail" if any test involving it fails
 * - "warn" if some warn but none fail
 * - "none" if no tests touch it
 */
function computeGuardResults(results: Map<string, TestResult>): Map<string, GuardTestStatus> {
  const guardMap = new Map<string, GuardTestStatus>();

  for (const result of results.values()) {
    for (const gr of result.guardResults) {
      const existing = guardMap.get(gr.guard) ?? "none";

      if (result.passed === false) {
        // Any failure overrides everything
        guardMap.set(gr.guard, "fail");
      } else if (result.passed === null) {
        // No expectation -- keep existing unless it's "none"
        if (existing === "none") {
          guardMap.set(gr.guard, "none");
        }
      } else {
        // passed === true
        if (existing === "fail") {
          // fail sticks
        } else if (gr.verdict === "warn") {
          // Warn overrides pass and none, but not fail
          if (existing !== "warn") {
            guardMap.set(gr.guard, "warn");
          }
        } else if (existing === "none") {
          guardMap.set(gr.guard, "pass");
        }
        // If existing is "pass" or "warn" and current is pass, keep existing
      }
    }
  }

  return guardMap;
}

// ---------------------------------------------------------------------------
// Reducer
// ---------------------------------------------------------------------------

function testRunnerReducer(state: TestRunnerState, action: TestRunnerAction): TestRunnerState {
  switch (action.type) {
    case "SET_SUITE_YAML": {
      const parsed = parseSuiteYaml(action.yaml);
      return {
        ...state,
        suiteYaml: action.yaml,
        scenarios: parsed.scenarios,
        parseErrors: parsed.errors,
      };
    }

    case "SET_RESULTS": {
      const guardResults = computeGuardResults(action.results);
      return {
        ...state,
        results: action.results,
        guardResults,
      };
    }

    case "SET_RUNNING": {
      // Prevent concurrent runs at the store level
      if (action.running && state.isRunning) return state;
      return { ...state, isRunning: action.running };
    }

    case "TOGGLE_AUTO_RERUN": {
      return { ...state, autoRerun: !state.autoRerun };
    }

    case "ADD_HISTORY_ENTRY": {
      const newHistory = [action.entry, ...state.runHistory].slice(0, MAX_HISTORY);
      return { ...state, runHistory: newHistory };
    }

    case "SET_COVERAGE": {
      return { ...state, coverageReport: action.report };
    }

    case "CLEAR_RESULTS": {
      return {
        ...state,
        results: new Map(),
        guardResults: new Map(),
        runHistory: [],
      };
    }

    case "IMPORT_SCENARIOS": {
      // Merge imported scenarios into the current suite
      const merged = [...state.scenarios, ...action.scenarios];
      const yaml = suiteScenariosToYaml(merged);
      return {
        ...state,
        suiteYaml: yaml,
        scenarios: merged,
        parseErrors: [],
      };
    }

    default:
      return state;
  }
}

// ---------------------------------------------------------------------------
// Initial state
// ---------------------------------------------------------------------------

function getInitialState(): TestRunnerState {
  return {
    suiteYaml: "",
    scenarios: [],
    parseErrors: [],
    results: new Map(),
    guardResults: new Map(),
    isRunning: false,
    autoRerun: false,
    runHistory: [],
    coverageReport: null,
  };
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

interface TestRunnerContextValue {
  state: TestRunnerState;
  dispatch: React.Dispatch<TestRunnerAction>;
}

const TestRunnerContext = createContext<TestRunnerContextValue | null>(null);

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export function TestRunnerProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(testRunnerReducer, undefined, getInitialState);

  return (
    <TestRunnerContext.Provider value={{ state, dispatch }}>
      {children}
    </TestRunnerContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

/** Access the full test runner state and dispatch. */
export function useTestRunner(): { state: TestRunnerState; dispatch: React.Dispatch<TestRunnerAction> } {
  const ctx = useContext(TestRunnerContext);
  if (!ctx) throw new Error("useTestRunner must be used within TestRunnerProvider");
  return ctx;
}

/**
 * Access the test runner state and dispatch if inside a TestRunnerProvider.
 * Returns null when no provider is present (safe to call unconditionally).
 */
export function useTestRunnerOptional(): { state: TestRunnerState; dispatch: React.Dispatch<TestRunnerAction> } | null {
  return useContext(TestRunnerContext);
}

/** Get the aggregate test status for a specific guard (for guard cards). */
export function useGuardTestStatus(guardId: string): GuardTestStatus {
  const ctx = useContext(TestRunnerContext);
  if (!ctx) return "none";
  return ctx.state.guardResults.get(guardId) ?? "none";
}
