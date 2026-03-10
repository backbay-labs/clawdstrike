import { describe, expect, it } from "vitest";

import type { WorkbenchPolicy } from "../types";
import { deepEqual, parsePolicy, suggestScenariosFromPolicy } from "../../../../mcp-server/index.ts";

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
});
