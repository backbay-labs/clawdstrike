import { describe, expect, it } from "vitest";

import { McpToolGuard, ToolDecision } from "../../src/guards/mcp-tool";
import { GuardAction, GuardContext } from "../../src/guards/types";

describe("McpToolGuard", () => {
  it("fails closed for unknown tools when no default action is configured", () => {
    const guard = new McpToolGuard();

    expect(guard.isAllowed("mcp__blender__execute_blender_code")).toBe(ToolDecision.Block);

    const result = guard.check(
      GuardAction.mcpTool("mcp__blender__execute_blender_code", { code: "print(1)" }),
      new GuardContext(),
    );

    expect(result.allowed).toBe(false);
    expect(result.guard).toBe("mcp_tool");
  });

  it("honors an explicit allow default action", () => {
    const guard = new McpToolGuard({ defaultAction: "allow", block: [], requireConfirmation: [] });

    expect(guard.isAllowed("mcp__blender__execute_blender_code")).toBe(ToolDecision.Allow);
    expect(
      guard.check(
        GuardAction.mcpTool("mcp__blender__execute_blender_code", { code: "print(1)" }),
        new GuardContext(),
      ).allowed,
    ).toBe(true);
  });
});
