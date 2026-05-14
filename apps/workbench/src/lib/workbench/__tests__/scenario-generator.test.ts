import { describe, it, expect } from "vitest";
import { generateScenariosFromPolicy, guardDisplayName } from "../scenario-generator";
import type { WorkbenchPolicy, GuardId, TestActionType } from "../types";


function makePolicy(guards: WorkbenchPolicy["guards"]): WorkbenchPolicy {
  return {
    version: "1.2.0",
    name: "test",
    description: "",
    guards,
    settings: {},
  };
}

/** A policy that mirrors the "default" ruleset with common guards enabled. */
function makeDefaultPolicy(): WorkbenchPolicy {
  return makePolicy({
    forbidden_path: {
      enabled: true,
      patterns: ["**/.ssh/**", "**/.aws/**", "**/.env", "/etc/shadow"],
      exceptions: ["**/.ssh/known_hosts"],
    },
    egress_allowlist: {
      enabled: true,
      allow: ["*.openai.com", "api.github.com"],
      block: ["evil.com"],
      default_action: "block",
    },
    secret_leak: {
      enabled: true,
      patterns: [
        { name: "aws_access_key", pattern: "AKIA[0-9A-Z]{16}", severity: "critical" },
        { name: "github_token", pattern: "gh[ps]_[A-Za-z0-9]{36}", severity: "critical" },
        { name: "private_key", pattern: "-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----", severity: "critical" },
      ],
      skip_paths: ["**/test/**"],
    },
    shell_command: { enabled: true },
    mcp_tool: {
      enabled: true,
      allow: ["read_file"],
      block: ["dangerous_tool"],
      require_confirmation: ["write_file"],
      default_action: "block",
    },
    patch_integrity: { enabled: true, max_additions: 500, max_deletions: 200 },
    prompt_injection: { enabled: true },
    jailbreak: { enabled: true },
    computer_use: { enabled: true, mode: "guardrail" },
    remote_desktop_side_channel: { enabled: true },
    input_injection_capability: { enabled: true },
    spider_sense: { enabled: true },
    path_allowlist: { enabled: true, file_access_allow: ["/app/**"], file_write_allow: ["/app/**"] },
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

const VALID_ACTION_TYPES: TestActionType[] = [
  "file_access",
  "file_write",
  "network_egress",
  "shell_command",
  "mcp_tool_call",
  "patch_apply",
  "user_input",
];


describe("generateScenariosFromPolicy with default policy", () => {
  const policy = makeDefaultPolicy();
  const result = generateScenariosFromPolicy(policy);

  it("produces scenarios for all enabled guards", () => {
    // All 13 guards are enabled in the default policy
    expect(result.coveredGuards.length).toBe(13);
    expect(result.disabledGuards).toHaveLength(0);
  });

  it("has no coverage gaps", () => {
    expect(result.gaps).toHaveLength(0);
  });

  it("produces a non-trivial number of scenarios", () => {
    // 13 guards, each producing at least 2 → at least 26
    expect(result.scenarios.length).toBeGreaterThanOrEqual(26);
  });

  it("all scenario IDs start with 'auto-'", () => {
    for (const s of result.scenarios) {
      expect(s.id).toMatch(/^auto-/);
    }
  });

  it("all scenarios have valid action types", () => {
    for (const s of result.scenarios) {
      expect(VALID_ACTION_TYPES).toContain(s.actionType);
    }
  });

  it("all scenarios have a name and description", () => {
    for (const s of result.scenarios) {
      expect(s.name).toBeTruthy();
      expect(s.description).toBeTruthy();
    }
  });

  it("all scenarios have a valid category", () => {
    for (const s of result.scenarios) {
      expect(["attack", "benign", "edge_case"]).toContain(s.category);
    }
  });

  it("scenario IDs are unique", () => {
    const ids = result.scenarios.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});


describe("generateScenariosFromPolicy with all guards disabled", () => {
  const policy = makePolicy({
    forbidden_path: { enabled: false },
    path_allowlist: { enabled: false },
    egress_allowlist: { enabled: false },
    secret_leak: { enabled: false },
    patch_integrity: { enabled: false },
    shell_command: { enabled: false },
    mcp_tool: { enabled: false },
    prompt_injection: { enabled: false },
    jailbreak: { enabled: false },
    computer_use: { enabled: false },
    remote_desktop_side_channel: { enabled: false },
    input_injection_capability: { enabled: false },
    spider_sense: { enabled: false },
  });
  const result = generateScenariosFromPolicy(policy);

  it("produces no scenarios", () => {
    expect(result.scenarios).toHaveLength(0);
  });

  it("lists all guards as disabled", () => {
    expect(result.disabledGuards.length).toBe(13);
  });

  it("has no covered guards", () => {
    expect(result.coveredGuards).toHaveLength(0);
  });

  it("has no gaps (disabled guards are not gaps)", () => {
    expect(result.gaps).toHaveLength(0);
  });
});


describe("generateScenariosFromPolicy with empty guard config", () => {
  const policy = makePolicy({});
  const result = generateScenariosFromPolicy(policy);

  it("treats missing configs as disabled", () => {
    expect(result.disabledGuards.length).toBe(13);
    expect(result.scenarios).toHaveLength(0);
  });
});


describe("forbidden_path scenarios reference configured patterns", () => {
  const policy = makePolicy({
    forbidden_path: {
      enabled: true,
      patterns: ["**/.ssh/**", "**/.aws/**"],
      exceptions: ["**/.ssh/known_hosts"],
    },
  });
  const result = generateScenariosFromPolicy(policy);
  const fpScenarios = result.scenarios.filter((s) => s.id.startsWith("auto-forbidden_path"));

  it("generates scenarios containing .ssh path", () => {
    const sshScenario = fpScenarios.find(
      (s) => JSON.stringify(s.payload).includes(".ssh")
    );
    expect(sshScenario).toBeDefined();
  });

  it("generates scenarios containing .aws path", () => {
    const awsScenario = fpScenarios.find(
      (s) => JSON.stringify(s.payload).includes(".aws")
    );
    expect(awsScenario).toBeDefined();
  });

  it("generates an exception scenario for configured exceptions", () => {
    const exceptionScenario = fpScenarios.find(
      (s) => s.id.includes("exception")
    );
    expect(exceptionScenario).toBeDefined();
    expect(JSON.stringify(exceptionScenario!.payload)).toContain(".ssh/known_hosts");
  });

  it("generates a traversal edge case", () => {
    const traversal = fpScenarios.find((s) => s.id.includes("traversal"));
    expect(traversal).toBeDefined();
    expect(traversal!.category).toBe("edge_case");
  });
});

describe("egress_allowlist scenarios reference configured domains", () => {
  const policy = makePolicy({
    egress_allowlist: {
      enabled: true,
      allow: ["*.openai.com"],
      block: ["evil.com"],
      default_action: "block",
    },
  });
  const result = generateScenariosFromPolicy(policy);
  const egressScenarios = result.scenarios.filter((s) => s.id.startsWith("auto-egress"));

  it("generates an allow scenario for an allowed domain", () => {
    const allowScenario = egressScenarios.find((s) => s.id.includes("allow"));
    expect(allowScenario).toBeDefined();
    expect(JSON.stringify(allowScenario!.payload)).toContain("openai.com");
  });

  it("generates a deny scenario for an unknown domain", () => {
    const denyScenario = egressScenarios.find((s) => s.id.includes("deny-unknown"));
    expect(denyScenario).toBeDefined();
    expect(denyScenario!.expectedVerdict).toBe("deny");
  });

  it("generates a deny scenario for an explicitly blocked domain", () => {
    const blockedScenario = egressScenarios.find((s) => s.id.includes("deny-blocked"));
    expect(blockedScenario).toBeDefined();
  });
});

describe("mcp_tool scenarios use configured tool lists", () => {
  const policy = makePolicy({
    mcp_tool: {
      enabled: true,
      allow: ["read_file"],
      block: ["dangerous_tool"],
      require_confirmation: ["write_file"],
      default_action: "block",
    },
  });
  const result = generateScenariosFromPolicy(policy);
  const mcpScenarios = result.scenarios.filter((s) => s.id.startsWith("auto-mcp_tool"));

  it("generates an allow scenario for an allowed tool", () => {
    const allowed = mcpScenarios.find((s) => s.id.includes("allow"));
    expect(allowed).toBeDefined();
    expect(allowed!.payload.tool).toBe("read_file");
  });

  it("generates a deny scenario for a blocked tool", () => {
    const blocked = mcpScenarios.find((s) => s.id.includes("deny-blocked"));
    expect(blocked).toBeDefined();
    expect(blocked!.payload.tool).toBe("dangerous_tool");
  });

  it("generates a warn scenario for a confirmation-required tool", () => {
    const confirm = mcpScenarios.find((s) => s.id.includes("warn-confirmation"));
    expect(confirm).toBeDefined();
    expect(confirm!.payload.tool).toBe("write_file");
    expect(confirm!.expectedVerdict).toBe("warn");
  });
});


describe("determinism", () => {
  it("same policy produces identical scenarios", () => {
    const policy = makeDefaultPolicy();
    const result1 = generateScenariosFromPolicy(policy);
    const result2 = generateScenariosFromPolicy(policy);

    expect(result1.scenarios.length).toBe(result2.scenarios.length);
    for (let i = 0; i < result1.scenarios.length; i++) {
      expect(result1.scenarios[i].id).toBe(result2.scenarios[i].id);
      expect(result1.scenarios[i].name).toBe(result2.scenarios[i].name);
      expect(result1.scenarios[i].actionType).toBe(result2.scenarios[i].actionType);
      expect(result1.scenarios[i].category).toBe(result2.scenarios[i].category);
    }
    expect(result1.coveredGuards).toEqual(result2.coveredGuards);
    expect(result1.disabledGuards).toEqual(result2.disabledGuards);
    expect(result1.gaps).toEqual(result2.gaps);
  });
});


describe("each guard generator produces at least 2 scenarios when enabled", () => {
  it.each(ALL_GUARD_IDS)("%s produces at least 2 scenarios", (guardId) => {
    // Build a policy with a reasonable config for each guard
    const configs: Record<string, object> = {
      forbidden_path: { enabled: true, patterns: ["**/.ssh/**"] },
      path_allowlist: { enabled: true, file_access_allow: ["/app/**"] },
      egress_allowlist: { enabled: true, allow: ["api.github.com"], default_action: "block" },
      secret_leak: {
        enabled: true,
        patterns: [{ name: "aws_access_key", pattern: "AKIA[0-9A-Z]{16}", severity: "critical" }],
      },
      patch_integrity: { enabled: true },
      shell_command: { enabled: true },
      mcp_tool: { enabled: true, allow: ["read_file"], default_action: "block" },
      prompt_injection: { enabled: true },
      jailbreak: { enabled: true },
      computer_use: { enabled: true, mode: "guardrail" },
      remote_desktop_side_channel: {
        enabled: true,
        clipboard_enabled: false,
        file_transfer_enabled: false,
      },
      input_injection_capability: {
        enabled: true,
        allowed_input_types: ["keyboard"],
      },
      spider_sense: { enabled: true },
    };

    const policy = makePolicy({ [guardId]: configs[guardId] } as WorkbenchPolicy["guards"]);
    const result = generateScenariosFromPolicy(policy);

    const guardScenarios = result.scenarios.filter((s) => s.id.startsWith(`auto-${guardId}`));
    expect(guardScenarios.length).toBeGreaterThanOrEqual(2);
  });
});


describe("guardDisplayName", () => {
  it("returns a human-readable name for known guards", () => {
    expect(guardDisplayName("forbidden_path")).toBe("Forbidden Path");
    expect(guardDisplayName("spider_sense")).toBe("Trustprint");
    expect(guardDisplayName("egress_allowlist")).toBe("Egress Control");
  });

  it("returns the guard ID for unknown guards", () => {
    // Cast to bypass type check for a non-existent guard
    expect(guardDisplayName("nonexistent" as GuardId)).toBe("nonexistent");
  });
});


describe("partial guard enablement", () => {
  it("only generates scenarios for enabled guards", () => {
    const policy = makePolicy({
      forbidden_path: { enabled: true, patterns: ["**/.ssh/**"] },
      shell_command: { enabled: false },
      egress_allowlist: { enabled: true, allow: ["api.github.com"], default_action: "block" },
    });
    const result = generateScenariosFromPolicy(policy);

    expect(result.coveredGuards).toContain("forbidden_path");
    expect(result.coveredGuards).toContain("egress_allowlist");
    expect(result.coveredGuards).not.toContain("shell_command");
    expect(result.disabledGuards).toContain("shell_command");

    // No shell_command scenarios
    const shellScenarios = result.scenarios.filter((s) => s.id.includes("shell_command"));
    expect(shellScenarios).toHaveLength(0);
  });
});
