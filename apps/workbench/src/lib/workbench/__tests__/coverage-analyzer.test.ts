import { describe, it, expect } from "vitest";
import { analyzeCoverage, guardsExercisedByScenario } from "../coverage-analyzer";
import type { GuardConfigMap, GuardId, TestScenario } from "../types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeScenario(
  overrides: Partial<TestScenario> & Pick<TestScenario, "id" | "actionType" | "payload">,
): TestScenario {
  return {
    name: "Test scenario",
    description: "",
    category: "benign",
    ...overrides,
  };
}

/** All 13 guard IDs. */
const ALL_GUARD_IDS: GuardId[] = [
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

/** Full guard config with all guards enabled. */
function allGuardsEnabled(): GuardConfigMap {
  return {
    forbidden_path: { enabled: true, patterns: [] },
    path_allowlist: { enabled: true },
    egress_allowlist: { enabled: true, allow: [] },
    secret_leak: { enabled: true, patterns: [] },
    patch_integrity: { enabled: true },
    shell_command: { enabled: true },
    mcp_tool: { enabled: true },
    prompt_injection: { enabled: true },
    jailbreak: { enabled: true },
    computer_use: { enabled: true },
    remote_desktop_side_channel: { enabled: true },
    input_injection_capability: { enabled: true },
    spider_sense: { enabled: true },
  };
}

/** Auto-generated scenario IDs that target specific guards. */
function autoScenarioForGuard(guardId: GuardId, actionType: TestScenario["actionType"]): TestScenario {
  return makeScenario({
    id: `auto-${guardId}-deny-0`,
    actionType,
    payload: {},
    category: "attack",
  });
}

/** Create a set of auto-generated scenarios covering all guards. */
function fullCoverageScenarios(): TestScenario[] {
  return [
    autoScenarioForGuard("forbidden_path", "file_access"),
    autoScenarioForGuard("path_allowlist", "file_access"),
    autoScenarioForGuard("egress_allowlist", "network_egress"),
    autoScenarioForGuard("secret_leak", "file_write"),
    autoScenarioForGuard("patch_integrity", "patch_apply"),
    autoScenarioForGuard("shell_command", "shell_command"),
    autoScenarioForGuard("mcp_tool", "mcp_tool_call"),
    autoScenarioForGuard("prompt_injection", "user_input"),
    autoScenarioForGuard("jailbreak", "user_input"),
    autoScenarioForGuard("computer_use", "mcp_tool_call"),
    autoScenarioForGuard("remote_desktop_side_channel", "mcp_tool_call"),
    autoScenarioForGuard("input_injection_capability", "mcp_tool_call"),
    autoScenarioForGuard("spider_sense", "user_input"),
  ];
}

// ---------------------------------------------------------------------------
// analyzeCoverage — empty scenarios
// ---------------------------------------------------------------------------

describe("analyzeCoverage with empty scenarios", () => {
  it("reports 0% coverage when all guards are enabled but no scenarios exist", () => {
    const report = analyzeCoverage(allGuardsEnabled(), []);
    expect(report.coveragePercent).toBe(0);
    expect(report.coveredGuards).toBe(0);
    expect(report.enabledGuards).toBe(13);
  });

  it("lists all enabled guards as gaps", () => {
    const report = analyzeCoverage(allGuardsEnabled(), []);
    expect(report.gaps.length).toBe(13);
    for (const guardId of ALL_GUARD_IDS) {
      expect(report.gaps).toContain(guardId);
    }
  });

  it("marks all guards as uncovered", () => {
    const report = analyzeCoverage(allGuardsEnabled(), []);
    for (const g of report.guards) {
      expect(g.status).toBe("uncovered");
      expect(g.scenarioCount).toBe(0);
    }
  });
});

// ---------------------------------------------------------------------------
// analyzeCoverage — full coverage
// ---------------------------------------------------------------------------

describe("analyzeCoverage with full coverage", () => {
  it("reports 100% coverage when every enabled guard has a scenario", () => {
    const report = analyzeCoverage(allGuardsEnabled(), fullCoverageScenarios());
    expect(report.coveragePercent).toBe(100);
    expect(report.coveredGuards).toBe(13);
    expect(report.gaps).toHaveLength(0);
  });

  it("marks all guards as covered", () => {
    const report = analyzeCoverage(allGuardsEnabled(), fullCoverageScenarios());
    for (const g of report.guards) {
      expect(g.status).toBe("covered");
      expect(g.scenarioCount).toBeGreaterThanOrEqual(1);
    }
  });
});

// ---------------------------------------------------------------------------
// analyzeCoverage — partial coverage
// ---------------------------------------------------------------------------

describe("analyzeCoverage with partial coverage", () => {
  it("computes correct percentage for partial coverage", () => {
    // Only cover forbidden_path and shell_command out of 13 enabled guards
    const scenarios = [
      autoScenarioForGuard("forbidden_path", "file_access"),
      autoScenarioForGuard("shell_command", "shell_command"),
    ];
    const report = analyzeCoverage(allGuardsEnabled(), scenarios);
    // 2 out of 13 = ~15%
    expect(report.coveragePercent).toBe(Math.round((2 / 13) * 100));
    expect(report.coveredGuards).toBe(2);
    expect(report.gaps.length).toBe(11);
  });

  it("correctly identifies which guards are covered and which are not", () => {
    const scenarios = [
      autoScenarioForGuard("egress_allowlist", "network_egress"),
      autoScenarioForGuard("jailbreak", "user_input"),
    ];
    const report = analyzeCoverage(allGuardsEnabled(), scenarios);

    const egressGuard = report.guards.find((g) => g.guardId === "egress_allowlist");
    expect(egressGuard!.status).toBe("covered");
    expect(egressGuard!.scenarioCount).toBe(1);

    const jailbreakGuard = report.guards.find((g) => g.guardId === "jailbreak");
    expect(jailbreakGuard!.status).toBe("covered");

    const shellGuard = report.guards.find((g) => g.guardId === "shell_command");
    expect(shellGuard!.status).toBe("uncovered");
    expect(shellGuard!.scenarioCount).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Disabled guards
// ---------------------------------------------------------------------------

describe("disabled guards in coverage", () => {
  it("marks disabled guards as 'disabled' not 'uncovered'", () => {
    const configs: GuardConfigMap = {
      forbidden_path: { enabled: true, patterns: [] },
      shell_command: { enabled: false },
    };
    const scenarios = [autoScenarioForGuard("forbidden_path", "file_access")];
    const report = analyzeCoverage(configs, scenarios);

    const fpGuard = report.guards.find((g) => g.guardId === "forbidden_path");
    expect(fpGuard!.status).toBe("covered");

    const shellGuard = report.guards.find((g) => g.guardId === "shell_command");
    expect(shellGuard!.status).toBe("disabled");
  });

  it("does not count disabled guards as gaps", () => {
    const configs: GuardConfigMap = {
      forbidden_path: { enabled: true, patterns: [] },
      shell_command: { enabled: false },
    };
    const scenarios = [autoScenarioForGuard("forbidden_path", "file_access")];
    const report = analyzeCoverage(configs, scenarios);

    expect(report.gaps).not.toContain("shell_command");
    // Only enabled guards without coverage are gaps
    // All other guards (not explicitly configured) are treated as disabled
  });

  it("reports 100% when all enabled guards are covered (disabled excluded)", () => {
    const configs: GuardConfigMap = {
      forbidden_path: { enabled: true, patterns: [] },
      shell_command: { enabled: false },
    };
    const scenarios = [autoScenarioForGuard("forbidden_path", "file_access")];
    const report = analyzeCoverage(configs, scenarios);

    expect(report.enabledGuards).toBe(1);
    expect(report.coveredGuards).toBe(1);
    expect(report.coveragePercent).toBe(100);
  });

  it("reports 100% coverage when no guards are enabled (vacuous truth)", () => {
    const configs: GuardConfigMap = {};
    const report = analyzeCoverage(configs, []);
    expect(report.coveragePercent).toBe(100);
    expect(report.enabledGuards).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// guardsExercisedByScenario
// ---------------------------------------------------------------------------

describe("guardsExercisedByScenario", () => {
  it("extracts guard ID from auto-generated scenario IDs", () => {
    const scenario = makeScenario({
      id: "auto-forbidden_path-deny-0",
      actionType: "file_access",
      payload: {},
    });
    expect(guardsExercisedByScenario(scenario)).toEqual(["forbidden_path"]);
  });

  it("handles multi-word guard IDs (e.g., remote_desktop_side_channel)", () => {
    const scenario = makeScenario({
      id: "auto-remote_desktop_side_channel-deny-clipboard",
      actionType: "mcp_tool_call",
      payload: {},
    });
    expect(guardsExercisedByScenario(scenario)).toEqual(["remote_desktop_side_channel"]);
  });

  it("handles input_injection_capability guard ID", () => {
    const scenario = makeScenario({
      id: "auto-input_injection_capability-deny-type",
      actionType: "mcp_tool_call",
      payload: {},
    });
    expect(guardsExercisedByScenario(scenario)).toEqual(["input_injection_capability"]);
  });

  it("falls back to action type mapping for pre-built scenarios", () => {
    const scenario = makeScenario({
      id: "prebuilt-file-test-1",
      actionType: "file_access",
      payload: {},
    });
    const guards = guardsExercisedByScenario(scenario);
    expect(guards).toContain("forbidden_path");
    expect(guards).toContain("path_allowlist");
  });

  it("maps network_egress to egress_allowlist", () => {
    const scenario = makeScenario({
      id: "custom-network-test",
      actionType: "network_egress",
      payload: {},
    });
    expect(guardsExercisedByScenario(scenario)).toEqual(["egress_allowlist"]);
  });

  it("maps user_input to prompt_injection, jailbreak, and spider_sense", () => {
    const scenario = makeScenario({
      id: "manual-input-test",
      actionType: "user_input",
      payload: {},
    });
    const guards = guardsExercisedByScenario(scenario);
    expect(guards).toContain("prompt_injection");
    expect(guards).toContain("jailbreak");
    expect(guards).toContain("spider_sense");
  });

  it("maps shell_command to shell_command guard", () => {
    const scenario = makeScenario({
      id: "manual-shell-test",
      actionType: "shell_command",
      payload: {},
    });
    expect(guardsExercisedByScenario(scenario)).toEqual(["shell_command"]);
  });

  it("maps mcp_tool_call to mcp_tool, computer_use, side_channel, and input_injection", () => {
    const scenario = makeScenario({
      id: "manual-mcp-test",
      actionType: "mcp_tool_call",
      payload: {},
    });
    const guards = guardsExercisedByScenario(scenario);
    expect(guards).toContain("mcp_tool");
    expect(guards).toContain("computer_use");
    expect(guards).toContain("remote_desktop_side_channel");
    expect(guards).toContain("input_injection_capability");
  });

  it("maps patch_apply to patch_integrity and path_allowlist", () => {
    const scenario = makeScenario({
      id: "manual-patch-test",
      actionType: "patch_apply",
      payload: {},
    });
    const guards = guardsExercisedByScenario(scenario);
    expect(guards).toContain("patch_integrity");
    expect(guards).toContain("path_allowlist");
  });
});

// ---------------------------------------------------------------------------
// Report shape
// ---------------------------------------------------------------------------

describe("coverage report shape", () => {
  it("totalGuards is always 13", () => {
    const report = analyzeCoverage({}, []);
    expect(report.totalGuards).toBe(13);
  });

  it("includes guardName for all entries", () => {
    const report = analyzeCoverage(allGuardsEnabled(), []);
    for (const g of report.guards) {
      expect(g.guardName).toBeTruthy();
      expect(typeof g.guardName).toBe("string");
    }
  });

  it("scenarioIds array contains the IDs of mapped scenarios", () => {
    const scenario = autoScenarioForGuard("forbidden_path", "file_access");
    const report = analyzeCoverage(allGuardsEnabled(), [scenario]);

    const fpGuard = report.guards.find((g) => g.guardId === "forbidden_path");
    expect(fpGuard!.scenarioIds).toContain("auto-forbidden_path-deny-0");
  });

  it("multiple scenarios for the same guard accumulate in scenarioIds", () => {
    const scenarios = [
      makeScenario({ id: "auto-shell_command-deny-rm", actionType: "shell_command", payload: {} }),
      makeScenario({ id: "auto-shell_command-allow-safe", actionType: "shell_command", payload: {} }),
    ];
    const report = analyzeCoverage(allGuardsEnabled(), scenarios);

    const shellGuard = report.guards.find((g) => g.guardId === "shell_command");
    expect(shellGuard!.scenarioCount).toBe(2);
    expect(shellGuard!.scenarioIds).toContain("auto-shell_command-deny-rm");
    expect(shellGuard!.scenarioIds).toContain("auto-shell_command-allow-safe");
  });
});
