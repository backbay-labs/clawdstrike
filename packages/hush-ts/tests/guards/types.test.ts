import { describe, it, expect } from "vitest";
import {
  Severity,
  GuardResult,
  GuardContext,
  GuardAction,
} from "../../src/guards/types";

describe("Severity", () => {
  it("has expected values", () => {
    expect(Severity.INFO).toBe("info");
    expect(Severity.WARNING).toBe("warning");
    expect(Severity.ERROR).toBe("error");
    expect(Severity.CRITICAL).toBe("critical");
  });
});

describe("GuardResult", () => {
  it("creates allow result", () => {
    const result = GuardResult.allow("test-guard");
    expect(result.allowed).toBe(true);
    expect(result.guard).toBe("test-guard");
    expect(result.severity).toBe(Severity.INFO);
  });

  it("creates block result", () => {
    const result = GuardResult.block("test-guard", Severity.ERROR, "Blocked for testing");
    expect(result.allowed).toBe(false);
    expect(result.guard).toBe("test-guard");
    expect(result.severity).toBe(Severity.ERROR);
    expect(result.message).toBe("Blocked for testing");
  });

  it("creates warn result", () => {
    const result = GuardResult.warn("test-guard", "Warning message");
    expect(result.allowed).toBe(true);
    expect(result.severity).toBe(Severity.WARNING);
    expect(result.message).toBe("Warning message");
  });

  it("adds details", () => {
    const result = GuardResult.block("test-guard", Severity.CRITICAL, "Critical issue")
      .withDetails({ path: "/etc/passwd", reason: "forbidden" });

    expect(result.details).toEqual({ path: "/etc/passwd", reason: "forbidden" });
  });
});

describe("GuardAction", () => {
  it("creates file access action", () => {
    const action = GuardAction.fileAccess("/path/to/file");
    expect(action.actionType).toBe("file_access");
    expect(action.path).toBe("/path/to/file");
  });

  it("creates file write action", () => {
    const content = new TextEncoder().encode("content");
    const action = GuardAction.fileWrite("/path/to/file", content);
    expect(action.actionType).toBe("file_write");
    expect(action.path).toBe("/path/to/file");
    expect(action.content).toBe(content);
  });

  it("creates network egress action", () => {
    const action = GuardAction.networkEgress("api.example.com", 443);
    expect(action.actionType).toBe("network_egress");
    expect(action.host).toBe("api.example.com");
    expect(action.port).toBe(443);
  });

  it("creates shell command action", () => {
    const action = GuardAction.shellCommand("ls -la");
    expect(action.actionType).toBe("shell_command");
    expect(action.command).toBe("ls -la");
  });

  it("creates MCP tool action", () => {
    const action = GuardAction.mcpTool("read_file", { path: "/etc/passwd" });
    expect(action.actionType).toBe("mcp_tool");
    expect(action.tool).toBe("read_file");
    expect(action.args).toEqual({ path: "/etc/passwd" });
  });

  it("creates patch action", () => {
    const action = GuardAction.patch("/src/file.ts", "+console.log('hi')");
    expect(action.actionType).toBe("patch");
    expect(action.path).toBe("/src/file.ts");
    expect(action.diff).toBe("+console.log('hi')");
  });

  it("creates custom action", () => {
    const action = GuardAction.custom("output", { content: "secret data" });
    expect(action.actionType).toBe("custom");
    expect(action.customType).toBe("output");
    expect(action.customData).toEqual({ content: "secret data" });
  });
});

describe("GuardContext", () => {
  it("creates with defaults", () => {
    const ctx = new GuardContext();
    expect(ctx.cwd).toBeUndefined();
    expect(ctx.sessionId).toBeUndefined();
  });

  it("creates with values", () => {
    const ctx = new GuardContext({
      cwd: "/home/user",
      sessionId: "session-123",
      agentId: "agent-456",
      metadata: { key: "value" },
    });

    expect(ctx.cwd).toBe("/home/user");
    expect(ctx.sessionId).toBe("session-123");
    expect(ctx.agentId).toBe("agent-456");
    expect(ctx.metadata).toEqual({ key: "value" });
  });
});
