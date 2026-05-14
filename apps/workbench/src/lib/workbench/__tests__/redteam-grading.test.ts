import { describe, it, expect } from "vitest";
import { gradeSimulationResult, gradeBatch } from "../redteam/grading";
import type { TestScenario, SimulationResult, Verdict } from "../types";
import type { RedTeamScenario } from "../redteam/types";


function makeScenario(
  overrides: Partial<RedTeamScenario> & Pick<TestScenario, "actionType" | "payload">,
): RedTeamScenario {
  return {
    id: "s1",
    name: "Test scenario",
    description: "",
    category: "attack",
    ...overrides,
  } as RedTeamScenario;
}

function makeSimResult(
  overallVerdict: Verdict,
  scenarioId = "s1",
): SimulationResult {
  return {
    scenarioId,
    overallVerdict,
    guardResults: [],
    executedAt: new Date().toISOString(),
  };
}


describe("gradeSimulationResult with expected=deny", () => {
  it("returns pass=true when expected=deny and actual=deny", () => {
    const scenario = makeScenario({
      actionType: "user_input",
      payload: { text: "attack" },
      expectedVerdict: "deny",
    });
    const result = gradeSimulationResult(scenario, makeSimResult("deny"));
    expect(result.pass).toBe(true);
    expect(result.score).toBe(1);
  });

  it("returns pass=false when expected=deny and actual=allow", () => {
    const scenario = makeScenario({
      actionType: "user_input",
      payload: { text: "attack" },
      expectedVerdict: "deny",
    });
    const result = gradeSimulationResult(scenario, makeSimResult("allow"));
    expect(result.pass).toBe(false);
    expect(result.score).toBe(0);
  });

  it("returns score=0.5 when expected=deny and actual=warn", () => {
    const scenario = makeScenario({
      actionType: "user_input",
      payload: { text: "attack" },
      expectedVerdict: "deny",
    });
    const result = gradeSimulationResult(scenario, makeSimResult("warn"));
    expect(result.score).toBe(0.5);
    // pass is false: strict threshold requires score >= 1.0 (warn ≠ deny)
    expect(result.pass).toBe(false);
  });
});


describe("gradeSimulationResult with expected=allow", () => {
  it("returns pass=true when expected=allow and actual=allow", () => {
    const scenario = makeScenario({
      actionType: "file_access",
      payload: { path: "/safe" },
      expectedVerdict: "allow",
    });
    const result = gradeSimulationResult(scenario, makeSimResult("allow"));
    expect(result.pass).toBe(true);
    expect(result.score).toBe(1);
  });
});


describe("gradeBatch", () => {
  it("computes correct pass/fail counts", () => {
    const scenarios = [
      makeScenario({ id: "s1", actionType: "user_input", payload: { text: "a" }, expectedVerdict: "deny", redteamPluginId: "p1" }),
      makeScenario({ id: "s2", actionType: "user_input", payload: { text: "b" }, expectedVerdict: "deny", redteamPluginId: "p1" }),
      makeScenario({ id: "s3", actionType: "file_access", payload: { path: "/" }, expectedVerdict: "allow", redteamPluginId: "p2" }),
    ];
    const results = [
      makeSimResult("deny", "s1"),   // pass (deny == deny)
      makeSimResult("allow", "s2"),  // fail (allow != deny)
      makeSimResult("allow", "s3"),  // pass (allow == allow)
    ];
    const batch = gradeBatch(scenarios, results);
    expect(batch.summary.passed).toBe(2);
    expect(batch.summary.failed).toBe(1);
    expect(batch.summary.total).toBe(3);
  });

  it("computes correct per-plugin breakdown", () => {
    const scenarios = [
      makeScenario({ id: "s1", actionType: "user_input", payload: { text: "a" }, expectedVerdict: "deny", redteamPluginId: "p1" }),
      makeScenario({ id: "s2", actionType: "user_input", payload: { text: "b" }, expectedVerdict: "deny", redteamPluginId: "p1" }),
      makeScenario({ id: "s3", actionType: "file_access", payload: { path: "/" }, expectedVerdict: "allow", redteamPluginId: "p2" }),
    ];
    const results = [
      makeSimResult("deny", "s1"),   // pass
      makeSimResult("allow", "s2"),  // fail
      makeSimResult("allow", "s3"),  // pass
    ];
    const batch = gradeBatch(scenarios, results);
    expect(batch.perPlugin).toBeDefined();
    // p1: 1 passed, 1 failed
    expect(batch.perPlugin["p1"].passed).toBe(1);
    expect(batch.perPlugin["p1"].failed).toBe(1);
    // p2: 1 passed, 0 failed
    expect(batch.perPlugin["p2"].passed).toBe(1);
    expect(batch.perPlugin["p2"].failed).toBe(0);
  });

  it("handles empty arrays gracefully", () => {
    const batch = gradeBatch([], []);
    expect(batch.summary.total).toBe(0);
    expect(batch.summary.passed).toBe(0);
    expect(batch.summary.failed).toBe(0);
    // 0/0 = 1.0 by convention (no testable scenarios = no failures)
    expect(batch.summary.passRate).toBe(1);
  });

  it("passRate is between 0 and 1", () => {
    const scenarios = [
      makeScenario({ id: "s1", actionType: "user_input", payload: { text: "a" }, expectedVerdict: "deny", redteamPluginId: "p1" }),
      makeScenario({ id: "s2", actionType: "user_input", payload: { text: "b" }, expectedVerdict: "deny", redteamPluginId: "p1" }),
    ];
    const results = [
      makeSimResult("deny", "s1"),
      makeSimResult("allow", "s2"),
    ];
    const batch = gradeBatch(scenarios, results);
    expect(batch.summary.passRate).toBeGreaterThanOrEqual(0);
    expect(batch.summary.passRate).toBeLessThanOrEqual(1);
  });
});
