import { describe, expect, it } from "vitest";

import type { WorkbenchPolicy } from "../types";
import {
  deepEqual,
  parsePolicy,
  suggestScenariosFromPolicy,
  validatePolicyYaml,
} from "../../../../mcp-server/index.ts";

function makePolicy(
  guards: WorkbenchPolicy["guards"],
): WorkbenchPolicy {
  return {
    version: "1.2.0",
    name: "mcp-test-policy",
    description: "MCP test policy",
    guards,
    settings: {},
  };
}

describe("mcp-server helpers", () => {
  it("keeps usable policies when yamlToPolicy returns non-fatal diagnostics", () => {
    const yaml = `
version: "1.2.0"
name: "warn-policy"
guards:
  egress_allowlist:
    enabled: true
    allow: "not-an-array"
`;

    const { policy, warnings } = parsePolicy(yaml);
    expect(policy.name).toBe("warn-policy");
    expect(warnings.length).toBeGreaterThan(0);
    expect(
      warnings.some((warning) => warning.includes("egress_allowlist.allow")),
    ).toBe(true);
  });

  it("treats arrays and plain objects as different in both directions", () => {
    expect(deepEqual([], {})).toBe(false);
    expect(deepEqual({}, [])).toBe(false);
  });

  it("enforces the shared policy size limit in validatePolicyYaml", () => {
    const oversizedYaml = "a".repeat(1_000_001);
    const result = validatePolicyYaml(oversizedYaml);

    expect(result.valid).toBe(false);
    expect(result.parseErrors).toEqual([
      "Policy YAML too large: 1000001 bytes (max 1000000)",
    ]);
    expect(result.errors).toEqual([]);
    expect(result.warnings).toEqual([]);
  });

  it("keeps valid true when parsePolicy returns only non-fatal diagnostics", () => {
    const yaml = `
version: "1.2.0"
name: "warn-policy"
guards:
  egress_allowlist:
    enabled: true
    allow: "not-an-array"
`;

    const result = validatePolicyYaml(yaml);

    expect(result.valid).toBe(true);
    expect(result.parseErrors.length).toBeGreaterThan(0);
    expect(
      result.parseErrors.some((warning) => warning.includes("egress_allowlist.allow")),
    ).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it("does not assume egress default_action is block when the field is absent", () => {
    const result = suggestScenariosFromPolicy(
      makePolicy({
        egress_allowlist: {
          enabled: true,
          allow: ["*.example.com"],
        },
      }),
    );

    expect(
      result.scenarios.some((scenario) => scenario.name === "Unknown domain egress (should block)"),
    ).toBe(false);
  });

  it("adds an allow scenario when egress default_action is explicitly allow", () => {
    const result = suggestScenariosFromPolicy(
      makePolicy({
        egress_allowlist: {
          enabled: true,
          allow: ["*.example.com"],
          default_action: "allow",
        },
      }),
    );

    expect(
      result.scenarios.some((scenario) => scenario.name === "Unknown domain egress (default allow)"),
    ).toBe(true);
    expect(
      result.scenarios.some((scenario) => scenario.name === "Unknown domain egress (should block)"),
    ).toBe(false);
  });

  it("treats guards without explicit enabled field as enabled (ClawdStrike default)", () => {
    const result = suggestScenariosFromPolicy(
      makePolicy({
        forbidden_path: {
          patterns: ["/tmp/secret.txt"],
        },
        egress_allowlist: {
          enabled: true,
          allow: ["*.example.com"],
        },
      }),
    );

    // Both guards should be reported as enabled — ClawdStrike treats
    // a guard as enabled whenever enabled !== false (undefined → enabled).
    expect(result.enabledGuards).toContain("forbidden_path");
    expect(result.enabledGuards).toContain("egress_allowlist");
    expect(
      result.scenarios.some((scenario) => scenario.name.startsWith("Forbidden path:")),
    ).toBe(true);
  });

  it("excludes guards that are explicitly disabled", () => {
    const result = suggestScenariosFromPolicy(
      makePolicy({
        forbidden_path: {
          enabled: false,
          patterns: ["/tmp/secret.txt"],
        },
        egress_allowlist: {
          enabled: true,
          allow: ["*.example.com"],
        },
      }),
    );

    expect(result.enabledGuards).toEqual(["egress_allowlist"]);
    expect(
      result.scenarios.some((scenario) => scenario.name.startsWith("Forbidden path:")),
    ).toBe(false);
  });
});
