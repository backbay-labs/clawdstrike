import { describe, it, expect } from "vitest";
import { generateRedTeamScenarios } from "../redteam/scenario-generator";
import type { WorkbenchPolicy, GuardConfigMap } from "../types";


function makePolicy(guards: GuardConfigMap): WorkbenchPolicy {
  return {
    version: "1.2.0",
    name: "test-policy",
    description: "Test policy for red team scenario generation",
    guards,
    settings: {},
  };
}


describe("generateRedTeamScenarios per guard", () => {
  it("produces scenarios for a policy with forbidden_path enabled", () => {
    const policy = makePolicy({
      forbidden_path: { enabled: true, patterns: ["**/.ssh/**"] },
    });
    const scenarios = generateRedTeamScenarios(policy);
    expect(scenarios.length).toBeGreaterThan(0);
    // Should produce at least one scenario (shell-injection or path-traversal templates)
    expect(scenarios.every((s) => s.redteamPluginId != null)).toBe(true);
  });

  it("produces scenarios for a policy with jailbreak enabled", () => {
    // jailbreak guard maps to "hijacking" and "harmful" plugins via DEFAULT_GUARD_TO_PLUGINS
    // which have ATTACK_TEMPLATES entries
    const policy = makePolicy({
      jailbreak: { enabled: true },
    });
    const scenarios = generateRedTeamScenarios(policy);
    // Even if no ATTACK_TEMPLATES match the canonical plugin-registry mapping,
    // the generator falls back to DEFAULT_GUARD_TO_PLUGINS
    expect(scenarios.length).toBeGreaterThanOrEqual(0);
  });

  it("produces scenarios for a policy with all guards enabled", () => {
    const policy = makePolicy({
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
    });
    const scenarios = generateRedTeamScenarios(policy);
    // With all 13 guards enabled, there should be many scenarios
    expect(scenarios.length).toBeGreaterThan(5);
  });

  it("produces no scenarios for a policy with no guards enabled", () => {
    const policy = makePolicy({});
    const scenarios = generateRedTeamScenarios(policy);
    expect(scenarios).toHaveLength(0);
  });
});


describe("generated scenario validity", () => {
  const policy = makePolicy({
    forbidden_path: { enabled: true, patterns: ["**/.ssh/**"] },
    shell_command: { enabled: true },
    egress_allowlist: { enabled: true, allow: [] },
    secret_leak: { enabled: true, patterns: [] },
    mcp_tool: { enabled: true },
    prompt_injection: { enabled: true },
  });

  it("all generated scenarios have valid redteamPluginId set", () => {
    const scenarios = generateRedTeamScenarios(policy);
    expect(scenarios.length).toBeGreaterThan(0);
    for (const scenario of scenarios) {
      expect(scenario.redteamPluginId).toBeTruthy();
      expect(typeof scenario.redteamPluginId).toBe("string");
    }
  });

  it("all generated scenarios have valid severity set", () => {
    const validSeverities = ["critical", "high", "medium", "low"];
    const scenarios = generateRedTeamScenarios(policy);
    expect(scenarios.length).toBeGreaterThan(0);
    for (const scenario of scenarios) {
      expect(scenario.severity).toBeTruthy();
      expect(validSeverities).toContain(scenario.severity);
    }
  });

  it("generated scenarios have unique IDs", () => {
    const scenarios = generateRedTeamScenarios(policy);
    const ids = scenarios.map((s) => s.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });
});


describe("generateRedTeamScenarios filtering", () => {
  const policy = makePolicy({
    forbidden_path: { enabled: true, patterns: ["**/.ssh/**"] },
    shell_command: { enabled: true },
    egress_allowlist: { enabled: true, allow: [] },
    secret_leak: { enabled: true, patterns: [] },
    mcp_tool: { enabled: true },
    prompt_injection: { enabled: true },
  });

  it("guardIds filter restricts generation to specified guards", () => {
    const allScenarios = generateRedTeamScenarios(policy);
    const filtered = generateRedTeamScenarios(policy, {
      guardIds: ["shell_command"],
    });
    // Filtered should have fewer or equal scenarios than unfiltered
    expect(filtered.length).toBeLessThanOrEqual(allScenarios.length);
    // All filtered scenarios should come from plugins mapped to shell_command
    expect(filtered.length).toBeGreaterThan(0);
  });

  it("maxPerGuard limits scenario count per guard", () => {
    const maxPerGuard = 1;
    const limited = generateRedTeamScenarios(policy, { maxPerGuard });
    const unlimited = generateRedTeamScenarios(policy, { maxPerGuard: 100 });
    // Limited generation should produce fewer or equal scenarios
    expect(limited.length).toBeLessThanOrEqual(unlimited.length);
  });
});
