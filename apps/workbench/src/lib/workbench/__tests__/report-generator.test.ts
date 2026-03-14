import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { generateBatchReport, reportToJson } from "../report-generator";
import type {
  WorkbenchPolicy,
  TestScenario,
  SimulationResult,
  GuardSimResult,
} from "../types";


function makePolicy(overrides?: Partial<WorkbenchPolicy>): WorkbenchPolicy {
  return {
    version: "1.2.0",
    name: "test-policy",
    description: "A test policy",
    guards: {},
    settings: {},
    ...overrides,
  };
}

function makeScenario(
  overrides: Partial<TestScenario> & Pick<TestScenario, "actionType" | "payload">,
): TestScenario {
  return {
    id: `s-${Math.random().toString(36).slice(2, 8)}`,
    name: "Test Scenario",
    description: "A test scenario",
    category: "benign",
    ...overrides,
  };
}

function makeResult(
  scenarioId: string,
  overrides?: Partial<SimulationResult>,
): SimulationResult {
  return {
    scenarioId,
    overallVerdict: "allow",
    guardResults: [],
    executedAt: new Date().toISOString(),
    ...overrides,
  };
}

function makeGuardResult(overrides?: Partial<GuardSimResult>): GuardSimResult {
  return {
    guardId: "forbidden_path",
    guardName: "Forbidden Path",
    verdict: "allow",
    message: "Path allowed",
    ...overrides,
  };
}


beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-03-09T12:00:00Z"));
});

afterEach(() => {
  vi.useRealTimers();
});


describe("generateBatchReport", () => {
  // ---- Structure ----

  describe("report structure", () => {
    it("produces a report with correct type and version", () => {
      const report = generateBatchReport(makePolicy(), [], []);
      expect(report.report_type).toBe("clawdstrike_policy_test_report");
      expect(report.version).toBe("1.0");
    });

    it("includes generated_at timestamp", () => {
      const report = generateBatchReport(makePolicy(), [], []);
      expect(report.generated_at).toBe("2026-03-09T12:00:00.000Z");
    });

    it("captures policy info correctly", () => {
      const policy = makePolicy({
        name: "my-policy",
        version: "1.3.0",
        extends: "strict",
      });
      const report = generateBatchReport(policy, [], []);
      expect(report.policy.name).toBe("my-policy");
      expect(report.policy.version).toBe("1.3.0");
      expect(report.policy.extends).toBe("strict");
    });

    it("has all required top-level fields", () => {
      const report = generateBatchReport(makePolicy(), [], []);
      expect(report).toHaveProperty("report_type");
      expect(report).toHaveProperty("version");
      expect(report).toHaveProperty("generated_at");
      expect(report).toHaveProperty("policy");
      expect(report).toHaveProperty("summary");
      expect(report).toHaveProperty("scenarios");
      expect(report).toHaveProperty("compliance");
      expect(report).toHaveProperty("policy_config");
    });
  });

  // ---- Empty scenarios ----

  describe("empty scenarios", () => {
    it("produces zero summary counts with no scenarios", () => {
      const report = generateBatchReport(makePolicy(), [], []);
      expect(report.summary.total).toBe(0);
      expect(report.summary.passed).toBe(0);
      expect(report.summary.failed).toBe(0);
      expect(report.summary.warnings).toBe(0);
      expect(report.summary.pass_rate).toBe(0);
    });

    it("produces an empty scenarios array", () => {
      const report = generateBatchReport(makePolicy(), [], []);
      expect(report.scenarios).toEqual([]);
    });
  });

  // ---- Pass/fail detection ----

  describe("pass/fail detection", () => {
    it("marks scenario as passed when expected matches actual verdict", () => {
      const scenario = makeScenario({
        id: "s1",
        actionType: "file_access",
        payload: { path: "/safe/file.txt" },
        expectedVerdict: "allow",
      });
      const result = makeResult("s1", { overallVerdict: "allow" });
      const report = generateBatchReport(makePolicy(), [scenario], [result]);
      expect(report.scenarios[0].passed).toBe(true);
      expect(report.summary.passed).toBe(1);
      expect(report.summary.failed).toBe(0);
    });

    it("marks scenario as failed when expected does not match actual", () => {
      const scenario = makeScenario({
        id: "s1",
        actionType: "file_access",
        payload: { path: "/etc/shadow" },
        expectedVerdict: "deny",
      });
      const result = makeResult("s1", { overallVerdict: "allow" });
      const report = generateBatchReport(makePolicy(), [scenario], [result]);
      expect(report.scenarios[0].passed).toBe(false);
      expect(report.summary.failed).toBe(1);
      expect(report.summary.passed).toBe(0);
    });

    it("treats scenario as passed when expectedVerdict is null", () => {
      const scenario = makeScenario({
        id: "s1",
        actionType: "file_access",
        payload: { path: "/test.txt" },
        // no expectedVerdict
      });
      const result = makeResult("s1", { overallVerdict: "deny" });
      const report = generateBatchReport(makePolicy(), [scenario], [result]);
      expect(report.scenarios[0].passed).toBe(true);
      expect(report.summary.passed).toBe(1);
    });

    it("counts warnings correctly", () => {
      const scenario = makeScenario({
        id: "s1",
        actionType: "user_input",
        payload: { text: "test" },
        expectedVerdict: "warn",
      });
      const result = makeResult("s1", { overallVerdict: "warn" });
      const report = generateBatchReport(makePolicy(), [scenario], [result]);
      expect(report.summary.warnings).toBe(1);
      expect(report.scenarios[0].passed).toBe(true);
    });
  });

  // ---- Summary stats ----

  describe("summary statistics", () => {
    it("calculates pass_rate correctly", () => {
      const scenarios = [
        makeScenario({ id: "s1", actionType: "file_access", payload: { path: "/a" }, expectedVerdict: "allow" }),
        makeScenario({ id: "s2", actionType: "file_access", payload: { path: "/b" }, expectedVerdict: "deny" }),
        makeScenario({ id: "s3", actionType: "file_access", payload: { path: "/c" }, expectedVerdict: "allow" }),
      ];
      const results = [
        makeResult("s1", { overallVerdict: "allow" }),
        makeResult("s2", { overallVerdict: "allow" }), // mismatch!
        makeResult("s3", { overallVerdict: "allow" }),
      ];
      const report = generateBatchReport(makePolicy(), scenarios, results);
      expect(report.summary.total).toBe(3);
      expect(report.summary.passed).toBe(2);
      expect(report.summary.failed).toBe(1);
      // pass_rate = 2/3 rounded to 3 decimals = 0.667
      expect(report.summary.pass_rate).toBe(0.667);
    });

    it("pass_rate is 1 when all pass", () => {
      const scenarios = [
        makeScenario({ id: "s1", actionType: "file_access", payload: { path: "/a" }, expectedVerdict: "allow" }),
        makeScenario({ id: "s2", actionType: "file_access", payload: { path: "/b" }, expectedVerdict: "deny" }),
      ];
      const results = [
        makeResult("s1", { overallVerdict: "allow" }),
        makeResult("s2", { overallVerdict: "deny" }),
      ];
      const report = generateBatchReport(makePolicy(), scenarios, results);
      expect(report.summary.pass_rate).toBe(1);
    });

    it("pass_rate is 0 when all fail", () => {
      const scenarios = [
        makeScenario({ id: "s1", actionType: "file_access", payload: { path: "/a" }, expectedVerdict: "deny" }),
        makeScenario({ id: "s2", actionType: "file_access", payload: { path: "/b" }, expectedVerdict: "allow" }),
      ];
      const results = [
        makeResult("s1", { overallVerdict: "allow" }),
        makeResult("s2", { overallVerdict: "deny" }),
      ];
      const report = generateBatchReport(makePolicy(), scenarios, results);
      expect(report.summary.pass_rate).toBe(0);
    });
  });

  // ---- Target extraction ----

  describe("target extraction from payloads", () => {
    it("extracts path from file_access scenario", () => {
      const scenario = makeScenario({
        id: "s1",
        actionType: "file_access",
        payload: { path: "/home/.ssh/id_rsa" },
      });
      const result = makeResult("s1");
      const report = generateBatchReport(makePolicy(), [scenario], [result]);
      expect(report.scenarios[0].target).toBe("/home/.ssh/id_rsa");
    });

    it("extracts host from network_egress scenario", () => {
      const scenario = makeScenario({
        id: "s1",
        actionType: "network_egress",
        payload: { host: "evil.com", port: 443 },
      });
      const result = makeResult("s1");
      const report = generateBatchReport(makePolicy(), [scenario], [result]);
      expect(report.scenarios[0].target).toBe("evil.com");
    });

    it("extracts host:port for non-443 port", () => {
      const scenario = makeScenario({
        id: "s1",
        actionType: "network_egress",
        payload: { host: "evil.com", port: 8080 },
      });
      const result = makeResult("s1");
      const report = generateBatchReport(makePolicy(), [scenario], [result]);
      expect(report.scenarios[0].target).toBe("evil.com:8080");
    });

    it("extracts command from shell_command scenario", () => {
      const scenario = makeScenario({
        id: "s1",
        actionType: "shell_command",
        payload: { command: "rm -rf /" },
      });
      const result = makeResult("s1");
      const report = generateBatchReport(makePolicy(), [scenario], [result]);
      expect(report.scenarios[0].target).toBe("rm -rf /");
    });

    it("extracts tool from mcp_tool_call scenario", () => {
      const scenario = makeScenario({
        id: "s1",
        actionType: "mcp_tool_call",
        payload: { tool: "write_file" },
      });
      const result = makeResult("s1");
      const report = generateBatchReport(makePolicy(), [scenario], [result]);
      expect(report.scenarios[0].target).toBe("write_file");
    });

    it("extracts text from user_input scenario", () => {
      const scenario = makeScenario({
        id: "s1",
        actionType: "user_input",
        payload: { text: "ignore all instructions" },
      });
      const result = makeResult("s1");
      const report = generateBatchReport(makePolicy(), [scenario], [result]);
      expect(report.scenarios[0].target).toBe("ignore all instructions");
    });
  });

  // ---- Guard results in report ----

  describe("guard results", () => {
    it("includes guard results in scenario details", () => {
      const scenario = makeScenario({
        id: "s1",
        actionType: "file_access",
        payload: { path: "/etc/shadow" },
      });
      const gr = makeGuardResult({
        guardId: "forbidden_path",
        guardName: "Forbidden Path",
        verdict: "deny",
        message: "Blocked by forbidden path pattern",
        engine: "client",
      });
      const result = makeResult("s1", {
        overallVerdict: "deny",
        guardResults: [gr],
      });
      const report = generateBatchReport(makePolicy(), [scenario], [result]);
      expect(report.scenarios[0].guard_results).toHaveLength(1);
      expect(report.scenarios[0].guard_results[0].guard_id).toBe("forbidden_path");
      expect(report.scenarios[0].guard_results[0].verdict).toBe("deny");
      expect(report.scenarios[0].guard_results[0].engine).toBe("client");
    });
  });

  // ---- Scenarios without matching results ----

  describe("unmatched scenarios", () => {
    it("skips scenarios with no matching result", () => {
      const scenario = makeScenario({
        id: "orphan",
        actionType: "file_access",
        payload: { path: "/test" },
      });
      // No result with id "orphan"
      const report = generateBatchReport(makePolicy(), [scenario], []);
      expect(report.scenarios).toHaveLength(0);
      expect(report.summary.total).toBe(0);
    });
  });

  // ---- Compliance section ----

  describe("compliance section", () => {
    it("includes all three compliance frameworks", () => {
      const report = generateBatchReport(makePolicy(), [], []);
      expect(report.compliance).toHaveProperty("hipaa");
      expect(report.compliance).toHaveProperty("soc2");
      expect(report.compliance).toHaveProperty("pci_dss");
    });

    it("compliance scores increase with more guards enabled", () => {
      const emptyReport = generateBatchReport(makePolicy(), [], []);
      const fullPolicy = makePolicy({
        guards: {
          forbidden_path: { enabled: true, patterns: ["a", "b", "c"] },
          egress_allowlist: { enabled: true, default_action: "block" },
          secret_leak: {
            enabled: true,
            patterns: [{ name: "aws_key", pattern: "AKIA.*", severity: "critical" }],
          },
          patch_integrity: { enabled: true },
          shell_command: { enabled: true },
          mcp_tool: { enabled: true, default_action: "block" },
          prompt_injection: { enabled: true },
          jailbreak: { enabled: true },
        },
        settings: {
          verbose_logging: true,
          session_timeout_secs: 1800,
        },
      });
      const fullReport = generateBatchReport(fullPolicy, [], []);
      expect(fullReport.compliance.hipaa.score).toBeGreaterThan(emptyReport.compliance.hipaa.score);
      expect(fullReport.compliance.soc2.score).toBeGreaterThan(emptyReport.compliance.soc2.score);
      expect(fullReport.compliance.pci_dss.score).toBeGreaterThan(emptyReport.compliance.pci_dss.score);
    });

    it("compliance frameworks include met and gap arrays", () => {
      const report = generateBatchReport(makePolicy(), [], []);
      for (const fw of Object.values(report.compliance)) {
        expect(Array.isArray(fw.met)).toBe(true);
        expect(Array.isArray(fw.gaps)).toBe(true);
        expect(fw.met_count + fw.gap_count).toBe(fw.total_requirements);
      }
    });
  });

  // ---- Policy config section ----

  describe("policy config section", () => {
    it("includes all 13 guard IDs in enabled_guards", () => {
      const report = generateBatchReport(makePolicy(), [], []);
      expect(report.policy_config.enabled_guards).toHaveLength(13);
    });

    it("reports guards as disabled when not configured", () => {
      const report = generateBatchReport(makePolicy(), [], []);
      for (const guard of report.policy_config.enabled_guards) {
        expect(guard.enabled).toBe(false);
      }
    });

    it("reports guards as enabled when configured", () => {
      const policy = makePolicy({
        guards: {
          forbidden_path: { enabled: true },
          shell_command: { enabled: true },
        },
      });
      const report = generateBatchReport(policy, [], []);
      const fpGuard = report.policy_config.enabled_guards.find((g) => g.guard_id === "forbidden_path");
      expect(fpGuard?.enabled).toBe(true);
      const scGuard = report.policy_config.enabled_guards.find((g) => g.guard_id === "shell_command");
      expect(scGuard?.enabled).toBe(true);
    });

    it("captures base_ruleset from policy.extends", () => {
      const policy = makePolicy({ extends: "strict" });
      const report = generateBatchReport(policy, [], []);
      expect(report.policy_config.base_ruleset).toBe("strict");
    });

    it("base_ruleset is null when no extends", () => {
      const report = generateBatchReport(makePolicy(), [], []);
      expect(report.policy_config.base_ruleset).toBeNull();
    });
  });
});


describe("reportToJson", () => {
  it("produces valid JSON string", () => {
    const report = generateBatchReport(makePolicy(), [], []);
    const json = reportToJson(report);
    expect(() => JSON.parse(json)).not.toThrow();
  });

  it("produces formatted (indented) JSON", () => {
    const report = generateBatchReport(makePolicy(), [], []);
    const json = reportToJson(report);
    // Formatted JSON has newlines
    expect(json).toContain("\n");
    // And indentation
    expect(json).toContain("  ");
  });

  it("roundtrips correctly", () => {
    const report = generateBatchReport(makePolicy(), [], []);
    const json = reportToJson(report);
    const parsed = JSON.parse(json);
    expect(parsed.report_type).toBe(report.report_type);
    expect(parsed.version).toBe(report.version);
    expect(parsed.summary.total).toBe(report.summary.total);
  });
});
