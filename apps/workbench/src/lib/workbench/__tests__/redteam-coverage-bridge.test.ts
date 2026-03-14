import { describe, it, expect } from "vitest";
import {
  identifyRedTeamGaps,
  generateGapFillingScenarios,
  computeRedTeamCoverage,
} from "../redteam/coverage-bridge";
import { analyzeCoverage } from "../coverage-analyzer";
import type { WorkbenchPolicy, GuardConfigMap, GuardId, TestScenario } from "../types";
import type { RedTeamScenario } from "../redteam/types";


function makePolicy(guards: GuardConfigMap): WorkbenchPolicy {
  return {
    version: "1.2.0",
    name: "test-policy",
    description: "Test policy for coverage bridge",
    guards,
    settings: {},
  };
}

function makeAutoScenario(guardId: GuardId, actionType: TestScenario["actionType"]): TestScenario {
  return {
    id: `auto-${guardId}-deny-0`,
    name: `Scenario for ${guardId}`,
    description: "",
    category: "attack",
    actionType,
    payload: {},
  };
}

function makeRedTeamScenario(guardId: GuardId, pluginId: string, index = 0): RedTeamScenario {
  return {
    id: `rt-${guardId}-${index}`,
    name: `Red team scenario for ${guardId}`,
    description: "",
    category: "attack",
    actionType: "file_access",
    payload: {},
    redteamPluginId: pluginId,
    severity: "medium",
  };
}


describe("identifyRedTeamGaps", () => {
  it("returns gaps for uncovered guards", () => {
    const guards: GuardConfigMap = {
      forbidden_path: { enabled: true, patterns: [] },
      shell_command: { enabled: true },
      jailbreak: { enabled: true },
    };
    const policy = makePolicy(guards);
    // Provide a scenario only for forbidden_path
    const scenarios = [makeAutoScenario("forbidden_path", "file_access")];
    const coverageReport = analyzeCoverage(guards, scenarios);
    const gaps = identifyRedTeamGaps(coverageReport, policy);
    // shell_command and jailbreak should be gaps
    expect(gaps.length).toBeGreaterThan(0);
    const gapGuardIds = gaps.map((g) => g.guardId);
    expect(gapGuardIds).toContain("shell_command");
    expect(gapGuardIds).toContain("jailbreak");
  });

  it("returns empty array when all guards are covered", () => {
    const guards: GuardConfigMap = {
      forbidden_path: { enabled: true, patterns: [] },
      shell_command: { enabled: true },
    };
    const policy = makePolicy(guards);
    // Provide enough scenarios: >=2 per guard so they aren't flagged as thin coverage
    const scenarios = [
      makeAutoScenario("forbidden_path", "file_access"),
      { ...makeAutoScenario("forbidden_path", "file_access"), id: "auto-forbidden_path-deny-1" },
      makeAutoScenario("shell_command", "shell_command"),
      { ...makeAutoScenario("shell_command", "shell_command"), id: "auto-shell_command-deny-1" },
    ];
    const coverageReport = analyzeCoverage(guards, scenarios);
    const gaps = identifyRedTeamGaps(coverageReport, policy);
    expect(gaps).toHaveLength(0);
  });

  it("suggests correct plugins for each uncovered guard", () => {
    const guards: GuardConfigMap = {
      jailbreak: { enabled: true },
      prompt_injection: { enabled: true },
    };
    const policy = makePolicy(guards);
    // Cover only jailbreak with 2+ scenarios
    const scenarios = [
      makeAutoScenario("jailbreak", "user_input"),
      { ...makeAutoScenario("jailbreak", "user_input"), id: "auto-jailbreak-deny-1" },
    ];
    const coverageReport = analyzeCoverage(guards, scenarios);
    const gaps = identifyRedTeamGaps(coverageReport, policy);
    // prompt_injection should be a gap
    const piGap = gaps.find((g) => g.guardId === "prompt_injection");
    expect(piGap).toBeDefined();
    expect(piGap!.suggestedPlugins.length).toBeGreaterThan(0);
  });
});


describe("generateGapFillingScenarios", () => {
  it("produces scenarios for each gap", () => {
    const guards: GuardConfigMap = {
      forbidden_path: { enabled: true, patterns: [] },
      shell_command: { enabled: true },
      egress_allowlist: { enabled: true, allow: [] },
    };
    const policy = makePolicy(guards);
    // Only cover forbidden_path
    const scenarios = [
      makeAutoScenario("forbidden_path", "file_access"),
      { ...makeAutoScenario("forbidden_path", "file_access"), id: "auto-forbidden_path-deny-1" },
    ];
    const coverageReport = analyzeCoverage(guards, scenarios);
    const gaps = identifyRedTeamGaps(coverageReport, policy);
    expect(gaps.length).toBeGreaterThan(0);
    const fillingScenarios = generateGapFillingScenarios(gaps, policy);
    expect(fillingScenarios.length).toBeGreaterThan(0);
    // Should generate scenarios related to the uncovered guards
    expect(fillingScenarios.every((s) => s.redteamPluginId != null)).toBe(true);
  });
});


describe("computeRedTeamCoverage", () => {
  it("returns 0% for empty scenarios", () => {
    const policy = makePolicy({
      forbidden_path: { enabled: true, patterns: [] },
      shell_command: { enabled: true },
    });
    const coverage = computeRedTeamCoverage(policy, []);
    expect(coverage.coveragePercent).toBe(0);
  });

  it("returns higher coverage with more scenarios", () => {
    const policy = makePolicy({
      forbidden_path: { enabled: true, patterns: [] },
      shell_command: { enabled: true },
      egress_allowlist: { enabled: true, allow: [] },
    });
    const fewScenarios = [makeRedTeamScenario("forbidden_path", "path-traversal")];
    const moreScenarios = [
      makeRedTeamScenario("forbidden_path", "path-traversal", 0),
      makeRedTeamScenario("shell_command", "shell-injection", 1),
      makeRedTeamScenario("egress_allowlist", "ssrf", 2),
    ];
    const coverageFew = computeRedTeamCoverage(policy, fewScenarios);
    const coverageMore = computeRedTeamCoverage(policy, moreScenarios);
    expect(coverageMore.coveragePercent).toBeGreaterThanOrEqual(coverageFew.coveragePercent);
  });

  it("byGuard breakdown is correct", () => {
    const policy = makePolicy({
      forbidden_path: { enabled: true, patterns: [] },
      shell_command: { enabled: true },
    });
    const scenarios = [
      makeRedTeamScenario("forbidden_path", "path-traversal", 0),
      makeRedTeamScenario("forbidden_path", "shell-injection", 1),
      makeRedTeamScenario("shell_command", "shell-injection", 2),
    ];
    const coverage = computeRedTeamCoverage(policy, scenarios);
    expect(coverage.byGuard).toBeDefined();
    // forbidden_path maps to path-traversal and shell-injection plugins
    expect(coverage.byGuard["forbidden_path"].covered).toBeGreaterThanOrEqual(1);
    // shell_command maps to shell-injection plugin
    expect(coverage.byGuard["shell_command"].covered).toBeGreaterThanOrEqual(1);
  });
});
